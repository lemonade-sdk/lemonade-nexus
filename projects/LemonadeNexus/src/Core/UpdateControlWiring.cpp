#include <LemonadeNexus/Core/UpdateControlWiring.hpp>

#include <LemonadeNexus/Core/Version.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityMeshService.hpp>
#include <LemonadeNexus/Security/Storage/StorageVault.hpp>
#include <LemonadeNexus/Tree/TreeConsensus.hpp>

#include <chrono>
#include <future>
#include <memory>

namespace nexus::core {
namespace {

/// Run `work` on the security io thread and wait at most `timeout`. nullopt
/// when the thread does not get to it in time (startup, shutdown).
template <typename T, typename F>
std::optional<T> on_security_thread(security::SecurityMeshService* mesh, F work,
                                    std::chrono::seconds timeout) {
    if (!mesh) return std::nullopt;
    auto promise = std::make_shared<std::promise<T>>();
    auto future = promise->get_future();
    mesh->post([promise, work = std::move(work)]() mutable { promise->set_value(work()); });
    if (future.wait_for(timeout) != std::future_status::ready) return std::nullopt;
    return future.get();
}

}  // namespace

update::UpdateControlHandlers make_update_control_handlers(UpdateStatusSources sources,
                                                           BootChainStagingInputs staging,
                                                           update::RefusingTurnGate& gate) {
    update::UpdateControlHandlers handlers;
    handlers.status = [sources] {
        update::UpdateServerStatus s;
        s.version = kVersion;
        s.release_id = sources.release_id;
        s.approval_digest_hex = sources.approval_digest_hex;
        struct Epoch {
            bool known;
            uint64_t epoch;
            bool member;
        };
        auto* mesh = sources.mesh;
        const auto self = sources.self;
        if (const auto e = on_security_thread<Epoch>(
                mesh,
                [mesh] {
                    const auto current = mesh->driver().current_epoch();
                    return Epoch{current.has_value(), current ? current->underlying() : 0,
                                 mesh->driver().is_tier1_member()};
                },
                std::chrono::seconds(2))) {
            s.epoch_known = e->known;
            s.epoch = e->epoch;
            s.tier1_member = e->member && mesh->is_current_member(self);
        }
        if (sources.vault) {
            s.storage_files_ready = sources.vault->files_ready();
            s.storage_phase = std::string(security::vault_phase_name(sources.vault->phase()));
        } else {
            s.storage_files_ready = true;
            s.storage_phase = "none";
        }
        if (const auto* tree = sources.tree ? sources.tree->load() : nullptr) {
            const auto t = tree->status_summary();
            s.tree_enabled = true;
            s.tree_healthy = t.healthy;
            s.tree_height = t.height;
            s.tree_applied_height = t.applied_height;
            s.tree_behind = t.behind;
            s.tree_held = t.held;
        }
        return s;
    };
    update::bind_turn_gate(handlers, gate);
    handlers.stage_boot_chain = [mesh = sources.mesh, staging](std::string_view approval) {
        const std::string text(approval);
        // The security thread owns the sealed directory at runtime.
        if (mesh) {
            if (auto r = on_security_thread<update::BootChainStageResult>(
                    mesh, [staging, text] { return stage_boot_chain_for_approval(staging, text); },
                    std::chrono::seconds(update::kControlDeadlineSeconds - 10))) {
                return *r;
            }
            update::BootChainStageResult timeout;
            timeout.detail = "the security thread did not run the staging in time";
            return timeout;
        }
        return stage_boot_chain_for_approval(staging, text);
    };
    return handlers;
}

}  // namespace nexus::core
