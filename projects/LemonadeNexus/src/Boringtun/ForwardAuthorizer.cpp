#include <LemonadeNexus/Boringtun/ForwardAuthorizer.hpp>

#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <spdlog/spdlog.h>

#include <string>
#include <unordered_map>
#include <vector>

namespace nexus::boringtun {

namespace {

/// The node's tunnel address when it is one address inside `governed`.
std::optional<uint32_t> plane_address(const tree::TreeNode& node, const Cidr& governed) {
    if (node.tunnel_ip.empty()) return std::nullopt;
    auto cidr = Cidr::parse(node.tunnel_ip);
    if (!cidr || cidr->prefix_len != 32 || !governed.contains(cidr->network)) return std::nullopt;
    return cidr->network;
}

/// The connect rule of PermissionTreeService::resolve_authorized, applied to
/// the endpoint `from` (its management key is the principal) and `to`.
bool may_connect(const tree::PermissionTreeService& tree, const tree::TreeNode& from,
                 const tree::TreeNode& to) {
    if (from.id == to.id || from.parent_id.empty()) return false;
    if (!tree.is_descendant_of(to.id, from.parent_id)) return false;
    return tree.check_permission(from.mgmt_pubkey, to.id, acl::Permission::ConnectPrivate) ||
           tree.check_permission(from.mgmt_pubkey, to.id, acl::Permission::ConnectShared);
}

} // namespace

std::shared_ptr<const ForwardPolicy> build_forward_policy(
    const tree::PermissionTreeService& tree, const Cidr& governed) {
    auto policy = std::make_shared<ForwardPolicy>();
    policy->governed = governed;

    for (const auto& relay : tree.get_nodes_by_type(tree::NodeType::Relay)) {
        if (auto addr = plane_address(relay, governed)) policy->open.insert(*addr);
    }

    struct Located {
        tree::TreeNode node;
        uint32_t       addr;
    };
    std::vector<Located> endpoints;
    for (auto& node : tree.get_nodes_by_type(tree::NodeType::Endpoint)) {
        if (auto addr = plane_address(node, governed)) endpoints.push_back({std::move(node), *addr});
    }

    // A grant names a principal on the target node, so the candidate sources
    // for a target are the endpoints whose management key appears in the
    // target's assignments. may_connect then applies the full rule.
    std::unordered_map<std::string, std::vector<const Located*>> by_principal;
    for (const auto& e : endpoints) {
        if (!e.node.mgmt_pubkey.empty())
            by_principal[tree::canonical_principal(e.node.mgmt_pubkey)].push_back(&e);
    }
    for (const auto& target : endpoints) {
        for (const auto& assignment : target.node.assignments) {
            auto it = by_principal.find(tree::canonical_principal(assignment.management_pubkey));
            if (it == by_principal.end()) continue;
            for (const Located* source : it->second) {
                if (may_connect(tree, source->node, target.node))
                    policy->allowed.insert(ForwardPolicy::key(source->addr, target.addr));
            }
        }
    }
    return policy;
}

ForwardAuthorizer::ForwardAuthorizer(const tree::PermissionTreeService& tree,
                                     UserspaceDataplane& dataplane, Cidr governed,
                                     std::chrono::milliseconds poll)
    : tree_(tree), dataplane_(dataplane), governed_(governed), poll_(poll) {}

ForwardAuthorizer::~ForwardAuthorizer() {
    stop();
}

void ForwardAuthorizer::start() {
    (void)refresh(true);
    std::lock_guard lock(wait_mtx_);
    if (thread_.joinable()) return;
    stopping_ = false;
    thread_ = std::thread([this] { run(); });
}

void ForwardAuthorizer::stop() {
    {
        std::lock_guard lock(wait_mtx_);
        stopping_ = true;
    }
    wait_cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

bool ForwardAuthorizer::refresh(bool force) {
    std::lock_guard lock(refresh_mtx_);
    // Hash before the build: a change during the build gives a new hash, and
    // the next poll rebuilds.
    const auto hash = tree_.get_tree_hash();
    if (!force && built_hash_ && *built_hash_ == hash) return false;
    auto policy = build_forward_policy(tree_, governed_);
    spdlog::debug("[ForwardAuthorizer] policy rebuilt: {} allowed pairs, {} relays",
                  policy->allowed.size(), policy->open.size());
    dataplane_.set_forward_policy(std::move(policy));
    built_hash_ = hash;
    return true;
}

void ForwardAuthorizer::run() {
    std::unique_lock lock(wait_mtx_);
    while (!stopping_) {
        wait_cv_.wait_for(lock, poll_, [this] { return stopping_; });
        if (stopping_) break;
        lock.unlock();
        try {
            (void)refresh(false);
        } catch (const std::exception& e) {
            // The previous policy stays installed; it never widens on error.
            spdlog::error("[ForwardAuthorizer] policy rebuild failed: {}", e.what());
        }
        lock.lock();
    }
}

} // namespace nexus::boringtun
