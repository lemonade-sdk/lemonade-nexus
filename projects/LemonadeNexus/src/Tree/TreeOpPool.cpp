#include <LemonadeNexus/Tree/TreeOpPool.hpp>

#include <algorithm>

namespace nexus::tree {

TreeOpOutcome TreeOpTicket::wait_for(std::chrono::milliseconds timeout) {
    std::unique_lock lock(mutex_);
    cv_.wait_for(lock, timeout, [this] { return outcome_.status != TreeOpStatus::Pending; });
    return outcome_;
}

TreeOpOutcome TreeOpTicket::current() const {
    std::lock_guard lock(mutex_);
    return outcome_;
}

void TreeOpTicket::on_settled(std::function<void(const TreeOpOutcome&)> fn) {
    TreeOpOutcome settled;
    {
        std::lock_guard lock(mutex_);
        if (outcome_.status == TreeOpStatus::Pending) {
            continuations_.push_back(std::move(fn));
            return;
        }
        settled = outcome_;
    }
    fn(settled);
}

void TreeOpTicket::settle(TreeOpOutcome outcome) {
    if (outcome.status == TreeOpStatus::Pending) return;
    std::vector<std::function<void(const TreeOpOutcome&)>> run;
    {
        std::lock_guard lock(mutex_);
        if (outcome_.status != TreeOpStatus::Pending) return;
        outcome_ = std::move(outcome);
        run.swap(continuations_);
    }
    cv_.notify_all();
    // Continuations run outside the lock, so one may read the ticket.
    for (auto& fn : run) fn(outcome_);
}

TreeOpPool::Admit TreeOpPool::add(TreeOp op, std::shared_ptr<TreeOpTicket> ticket) {
    const std::string id = op_id_hex(op);
    const std::string author = canonical_principal(op.author);
    const std::string principal = canonical_principal(op.principal);
    std::lock_guard lock(mutex_);
    if (entries_.contains(id) || outcomes_.contains(id)) return Admit::Duplicate;
    if (entries_.size() >= limits_.total) return Admit::Full;
    if (per_author_[author] >= limits_.per_author) return Admit::AuthorLimit;
    if (per_principal_[principal] >= limits_.per_principal) return Admit::PrincipalLimit;
    ++per_author_[author];
    ++per_principal_[principal];
    entries_.emplace(id, Entry{std::move(op), std::move(ticket), next_sequence_++});
    return Admit::Added;
}

std::vector<TreeOp> TreeOpPool::pending() const {
    std::vector<const Entry*> ordered;
    std::lock_guard lock(mutex_);
    ordered.reserve(entries_.size());
    for (const auto& [id, entry] : entries_) ordered.push_back(&entry);
    std::sort(ordered.begin(), ordered.end(),
              [](const Entry* a, const Entry* b) { return a->sequence < b->sequence; });
    std::vector<TreeOp> out;
    out.reserve(ordered.size());
    for (const Entry* entry : ordered) out.push_back(entry->op);
    return out;
}

bool TreeOpPool::contains(const std::string& op_id) const {
    std::lock_guard lock(mutex_);
    return entries_.contains(op_id);
}

std::size_t TreeOpPool::size() const {
    std::lock_guard lock(mutex_);
    return entries_.size();
}

void TreeOpPool::remember_locked(const std::string& op_id, const TreeOpOutcome& outcome) {
    if (limits_.remembered_outcomes == 0) return;
    if (outcomes_.insert_or_assign(op_id, outcome).second) outcome_order_.push_back(op_id);
    while (outcome_order_.size() > limits_.remembered_outcomes) {
        outcomes_.erase(outcome_order_.front());
        outcome_order_.pop_front();
    }
}

void TreeOpPool::settle(const std::string& op_id, const TreeOpOutcome& outcome) {
    std::shared_ptr<TreeOpTicket> ticket;
    {
        std::lock_guard lock(mutex_);
        if (const auto it = entries_.find(op_id); it != entries_.end()) {
            const auto author = canonical_principal(it->second.op.author);
            const auto principal = canonical_principal(it->second.op.principal);
            if (--per_author_[author] == 0) per_author_.erase(author);
            if (--per_principal_[principal] == 0) per_principal_.erase(principal);
            ticket = std::move(it->second.ticket);
            entries_.erase(it);
        }
        remember_locked(op_id, outcome);
    }
    if (ticket) ticket->settle(outcome);
}

std::optional<TreeOpOutcome> TreeOpPool::status(const std::string& op_id) const {
    std::lock_guard lock(mutex_);
    if (entries_.contains(op_id)) return TreeOpOutcome{};
    if (const auto it = outcomes_.find(op_id); it != outcomes_.end()) return it->second;
    return std::nullopt;
}

}  // namespace nexus::tree
