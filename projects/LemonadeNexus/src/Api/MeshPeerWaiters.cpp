#include <LemonadeNexus/Api/MeshPeerWaiters.hpp>

namespace nexus::api {

MeshPeerWaiters::Slot::~Slot() {
    owner_.release(caller_);
}

std::unique_ptr<MeshPeerWaiters::Slot> MeshPeerWaiters::try_admit(const std::string& caller,
                                                                  Refusal& why) {
    std::lock_guard lock(mtx_);
    if (shutdown_) {
        why = Refusal::ShuttingDown;
        return nullptr;
    }
    if (waiting_ >= max_waiters_) {
        why = Refusal::ServerFull;
        return nullptr;
    }
    auto& held = per_caller_[caller];
    if (held >= max_per_caller_) {
        if (held == 0) per_caller_.erase(caller);
        why = Refusal::CallerFull;
        return nullptr;
    }
    ++held;
    ++waiting_;
    why = Refusal::None;
    return std::unique_ptr<Slot>(new Slot(*this, caller));
}

void MeshPeerWaiters::release(const std::string& caller) {
    std::lock_guard lock(mtx_);
    if (waiting_ > 0) --waiting_;
    if (const auto it = per_caller_.find(caller); it != per_caller_.end()) {
        if (--it->second == 0) per_caller_.erase(it);
    }
}

uint64_t MeshPeerWaiters::generation() const {
    std::lock_guard lock(mtx_);
    return generation_;
}

void MeshPeerWaiters::notify() {
    {
        std::lock_guard lock(mtx_);
        ++generation_;
    }
    cv_.notify_all();
}

uint64_t MeshPeerWaiters::wait(uint64_t seen, std::chrono::milliseconds max_wait) const {
    std::unique_lock lock(mtx_);
    cv_.wait_for(lock, max_wait, [&] { return generation_ != seen || shutdown_; });
    return generation_;
}

void MeshPeerWaiters::shutdown() {
    {
        std::lock_guard lock(mtx_);
        shutdown_ = true;
    }
    cv_.notify_all();
}

bool MeshPeerWaiters::shutting_down() const {
    std::lock_guard lock(mtx_);
    return shutdown_;
}

std::size_t MeshPeerWaiters::waiting() const {
    std::lock_guard lock(mtx_);
    return waiting_;
}

void MeshPeerWaiters::set_limits_for_testing(std::size_t max_waiters, std::size_t per_caller) {
    std::lock_guard lock(mtx_);
    max_waiters_    = max_waiters;
    max_per_caller_ = per_caller;
}

} // namespace nexus::api
