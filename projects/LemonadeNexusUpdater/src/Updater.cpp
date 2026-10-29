#include <LemonadeNexusUpdater/Updater.hpp>

#include <LemonadeNexusUpdater/FileSwap.hpp>

#include <LemonadeNexus/Security/DurableWrite.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlob.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <map>

namespace nexus::updater {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

constexpr std::size_t kMaxMetadataBytes = 1024 * 1024;
constexpr std::string_view kSealedDir = "/var/lib/lemonade-nexus/data/sealed";
constexpr std::string_view kGrubDefault = "/etc/default/grub";
constexpr std::string_view kGrubCfg = "/boot/grub/grub.cfg";
constexpr std::string_view kGrubEnv = "/boot/grub/grubenv";
constexpr std::string_view kBootId = "/proc/sys/kernel/random/boot_id";
/// GRUB reads this image for the kernel and measures it into PCR 9.
constexpr std::string_view kInitrdPrefix = "/boot/initrd.img-";

std::optional<std::string> read_file(const fs::path& path, std::size_t max_bytes) {
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > max_bytes) return std::nullopt;
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string trim(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    while (!s.empty() && s.front() == ' ') s.erase(s.begin());
    return s;
}

json packages_json(const std::vector<OsPackage>& packages) {
    json out = json::array();
    for (const auto& p : packages) {
        out.push_back({p.name, p.version, static_cast<int>(p.role)});
    }
    return out;
}

/// Where the updater keeps the measured initramfs before a package install.
fs::path initrd_backup_path(const fs::path& state_dir, const std::string& tag,
                            const std::string& initrd) {
    return state_dir / "previous" / tag / "boot" / fs::path(initrd).filename();
}

std::vector<OsPackage> packages_from(const json& j) {
    std::vector<OsPackage> out;
    for (const auto& p : j) {
        out.push_back({p.at(0).get<std::string>(), p.at(1).get<std::string>(),
                       static_cast<PackageRole>(p.at(2).get<int>())});
    }
    return out;
}

}  // namespace

std::string_view cycle_outcome_name(CycleOutcome outcome) {
    switch (outcome) {
        case CycleOutcome::NoUpdate:  return "no-update";
        case CycleOutcome::Waiting:   return "waiting";
        case CycleOutcome::Upgraded:  return "upgraded";
        case CycleOutcome::Failed:    return "failed";
        case CycleOutcome::Rebooting: return "rebooting";
        case CycleOutcome::Halted:    return "halted";
        case CycleOutcome::Refused:   return "refused";
    }
    return "unknown";
}

struct Updater::State {
    uint64_t installed_release_number{0};
    uint64_t halted_release_number{0};
    /// idle | swapping | swapped | rebooting | boot_rollback
    std::string phase{"idle"};
    std::string tag;
    uint64_t number{0};
    /// The server's health reply before the swap, as received.
    std::string baseline_line;
    std::vector<OsPackage> packages_install;
    std::vector<OsPackage> packages_previous;
    bool reboot{false};
    std::string previous_grub_entry;
    std::string boot_id;
    std::vector<std::string> staged_seal_names;
    /// The initramfs kept before the package install (kInitrdPrefix + kernel
    /// release); empty when no package install or no image.
    std::string measured_initrd;
    std::string last_result;
};

struct Updater::Release {
    VerifiedRelease verified;
    fs::path stage_dir;
    /// Asset name to staged file.
    std::map<std::string, fs::path> files;
    OsPackageLock lock;
};

Updater::Updater(UpdaterConfig config, UpdaterEnv env)
    : config_(std::move(config)), env_(std::move(env)) {}

fs::path Updater::host_path(std::string_view absolute) const {
    return config_.root / fs::path(absolute).relative_path();
}

fs::path Updater::state_dir() const { return host_path("/var/lib/nexus-updater"); }

std::optional<Updater::State> Updater::load_state() {
    const auto path = state_dir() / "state.json";
    std::error_code ec;
    if (!fs::exists(path, ec)) return State{};
    const auto text = read_file(path, kMaxMetadataBytes);
    if (!text) return std::nullopt;
    const json j = json::parse(*text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    try {
        State s;
        s.installed_release_number = j.at("installed_release_number").get<uint64_t>();
        s.halted_release_number = j.at("halted_release_number").get<uint64_t>();
        s.phase = j.at("phase").get<std::string>();
        s.tag = j.at("tag").get<std::string>();
        s.number = j.at("number").get<uint64_t>();
        s.baseline_line = j.at("baseline").get<std::string>();
        s.packages_install = packages_from(j.at("packages_install"));
        s.packages_previous = packages_from(j.at("packages_previous"));
        s.reboot = j.at("reboot").get<bool>();
        s.previous_grub_entry = j.at("previous_grub_entry").get<std::string>();
        s.boot_id = j.at("boot_id").get<std::string>();
        s.staged_seal_names = j.at("staged_seal_names").get<std::vector<std::string>>();
        // Absent in a state file written before this field existed.
        s.measured_initrd = j.value("measured_initrd", std::string());
        s.last_result = j.at("last_result").get<std::string>();
        return s;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool Updater::save_state(const State& s) {
    const json j = {
        {"installed_release_number", s.installed_release_number},
        {"halted_release_number", s.halted_release_number},
        {"phase", s.phase},
        {"tag", s.tag},
        {"number", s.number},
        {"baseline", s.baseline_line},
        {"packages_install", packages_json(s.packages_install)},
        {"packages_previous", packages_json(s.packages_previous)},
        {"reboot", s.reboot},
        {"previous_grub_entry", s.previous_grub_entry},
        {"boot_id", s.boot_id},
        {"staged_seal_names", s.staged_seal_names},
        {"measured_initrd", s.measured_initrd},
        {"last_result", s.last_result},
    };
    std::error_code ec;
    fs::create_directories(state_dir(), ec);
    fs::permissions(state_dir(), fs::perms::owner_all, fs::perm_options::replace, ec);
    if (!security::write_durable(state_dir() / "state.json", j.dump(2))) {
        spdlog::error("[updater] cannot write {}", (state_dir() / "state.json").string());
        return false;
    }
    return true;
}

uint64_t Updater::installed_release_number(const State& state) const {
    uint64_t number = state.installed_release_number;
    // The installed approval is root-owned; its tag bounds replay even when
    // the state file is lost.
    if (const auto text =
            read_file(host_path(security::kReleaseApprovalPath), kMaxMetadataBytes)) {
        std::string error;
        if (const auto bundle = security::parse_release_approval_bundle(*text, error)) {
            if (const auto tag = parse_release_tag(bundle->approval.release_id)) {
                number = std::max(number, tag->number);
            }
        }
    }
    return number;
}

std::optional<std::string> Updater::server_health_line() {
    auto line = env_.control(encode_health_request());
    if (!line || !decode_health_reply(*line)) return std::nullopt;
    return line;
}

std::optional<ServerHealth> Updater::server_health() {
    const auto line = env_.control(encode_health_request());
    return line ? decode_health_reply(*line) : std::nullopt;
}

void Updater::report(const State& state, bool upgraded, const std::string& detail) {
    const auto line = env_.control(encode_report_request(state.number, upgraded));
    spdlog::info("[updater] report {} {} to the server ({}): {}", state.tag,
                 upgraded ? "upgraded" : "failed", detail,
                 !line ? std::string("no answer")
                       : decode_ok_reply(*line) ? std::string("accepted")
                                                : "refused: " + reply_error(*line));
}

bool Updater::systemctl(const std::vector<std::string>& args, std::string& error) {
    std::vector<std::string> argv{"systemctl"};
    argv.insert(argv.end(), args.begin(), args.end());
    const auto r = env_.run(argv);
    if (r.exit_code != 0) {
        error = "systemctl " + args.front() + " failed: " + trim(r.output);
        return false;
    }
    return true;
}

std::optional<std::string> Updater::fetch_asset(const std::string& tag, const std::string& name,
                                                const std::string& url, std::string& error) {
    const auto path = state_dir() / "staged" / tag / name;
    if (auto cached = read_file(path, config_.max_asset_bytes)) return cached;
    auto body = env_.http(url, config_.max_asset_bytes, error);
    if (!body) return std::nullopt;
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (!security::write_durable(path, *body)) {
        error = "cannot stage " + path.string();
        return std::nullopt;
    }
    return body;
}

std::optional<Updater::Release> Updater::fetch_and_verify(const State& state,
                                                          std::string& error) {
    const auto doc = env_.http(latest_release_url(config_.trust.repository), kMaxMetadataBytes,
                               error);
    if (!doc) return std::nullopt;
    const auto gh = parse_github_release(*doc, config_.trust.repository, error);
    if (!gh) return std::nullopt;
    std::map<std::string, std::string> urls;
    for (const auto& a : gh->assets) urls[a.name] = a.download_url;
    auto fetch = [&](std::string_view name) -> std::optional<std::string> {
        const auto it = urls.find(std::string(name));
        if (it == urls.end()) {
            error = "the release has no asset " + std::string(name);
            return std::nullopt;
        }
        return fetch_asset(gh->tag, it->first, it->second, error);
    };

    const auto manifest = fetch(kManifestAsset);
    if (!manifest) return std::nullopt;
    const auto signature = fetch(kManifestSignatureAsset);
    if (!signature) return std::nullopt;
    const auto approval = fetch(kApprovalAsset);
    if (!approval) return std::nullopt;

    auto verified = verify_release_metadata(config_.trust, *manifest, trim(*signature), *approval,
                                            installed_release_number(state), error);
    if (!verified) return std::nullopt;
    if (verified->manifest.tag != gh->tag || verified->manifest.approval_asset != kApprovalAsset) {
        error = "the signed manifest does not describe release " + gh->tag;
        return std::nullopt;
    }

    Release release;
    release.stage_dir = state_dir() / "staged" / gh->tag;
    std::map<std::string, std::string> consumed{{std::string(kManifestAsset), *manifest},
                                                {std::string(kApprovalAsset), *approval}};
    std::vector<std::string> names{verified->manifest.os_lock_asset};
    for (const auto& f : verified->manifest.server_files) names.push_back(f.asset);
    for (const auto& name : names) {
        const auto bytes = fetch(name);
        if (!bytes) return std::nullopt;
        if (!verify_asset_hash(*verified, name, sha256_hex(*bytes), error)) return std::nullopt;
        consumed[name] = *bytes;
    }
    if (!verify_asset_hash(*verified, kApprovalAsset, sha256_hex(*approval), error)) {
        return std::nullopt;
    }
    for (const auto& [name, bytes] : consumed) {
        const auto bundle = fetch(name + std::string(kProvenanceSuffix));
        if (!bundle) {
            error = "no provenance for " + name + ": " + error;
            return std::nullopt;
        }
        std::string why;
        if (!env_.provenance(*bundle, sha256_hex(bytes), why)) {
            error = "provenance of " + name + " does not verify: " + why;
            return std::nullopt;
        }
        release.files[name] = release.stage_dir / name;
    }
    const auto lock = parse_os_package_lock(consumed[verified->manifest.os_lock_asset], error);
    if (!lock) return std::nullopt;
    release.lock = *lock;
    release.verified = std::move(*verified);
    return release;
}

CycleResult Updater::run_once() {
    try {
        auto result = cycle();
        spdlog::info("[updater] cycle: {}{}{}", cycle_outcome_name(result.outcome),
                     result.detail.empty() ? "" : ": ", result.detail);
        return result;
    } catch (const std::exception& e) {
        spdlog::error("[updater] cycle aborted: {}", e.what());
        return {CycleOutcome::Refused, std::string("internal error: ") + e.what()};
    }
}

CycleResult Updater::cycle() {
    auto state = load_state();
    if (!state) return {CycleOutcome::Refused, "the updater state file is unreadable"};
    if (state->phase != "idle") return resume(*state);

    std::string error;
    const auto doc = env_.http(latest_release_url(config_.trust.repository), kMaxMetadataBytes,
                               error);
    if (!doc) return {CycleOutcome::NoUpdate, error};
    const auto gh = parse_github_release(*doc, config_.trust.repository, error);
    if (!gh) return {CycleOutcome::NoUpdate, error};
    const auto tag = parse_release_tag(gh->tag);
    if (!tag) return {CycleOutcome::NoUpdate, "the latest release " + gh->tag + " is not a date tag"};
    if (tag->number <= installed_release_number(*state)) {
        return {CycleOutcome::NoUpdate, "release " + gh->tag + " is installed or older"};
    }
    if (tag->number <= state->halted_release_number) {
        return {CycleOutcome::Halted, "release " + gh->tag + " halted; waiting for a newer release"};
    }

    auto release = fetch_and_verify(*state, error);
    if (!release) {
        // Refetch next time: a partial or tampered download must not stick.
        std::error_code ec;
        fs::remove_all(state_dir() / "staged" / gh->tag, ec);
        return {CycleOutcome::Refused, error};
    }
    return start_update(*state, *release);
}

std::optional<TurnGate> Updater::ask_turn(uint64_t release_number) {
    const auto line = env_.control(encode_turn_request(release_number));
    return line ? decode_turn_reply(*line) : std::nullopt;
}

TurnGate Updater::await_turn(uint64_t release_number, const std::string& tag) {
    spdlog::info("[updater] {}: another server holds the upgrade turn; asking the gate every "
                 "{} s for up to {} s",
                 tag, config_.turn_poll.count(), config_.turn_wait.count());
    const auto deadline = env_.now() + config_.turn_wait;
    while (env_.now() < deadline) {
        env_.sleep(config_.turn_poll);
        const auto gate = ask_turn(release_number);
        if (gate && *gate != TurnGate::Wait) {
            spdlog::info("[updater] {}: upgrade turn: {}", tag, turn_gate_name(*gate));
            return *gate;
        }
    }
    return TurnGate::Wait;
}

CycleResult Updater::start_update(State& state, const Release& release) {
    const auto& v = release.verified;
    const uint64_t number = v.tag.number;
    // Hand the approval to the server first (Phase 4 step 4): the release
    // chain applies the signer pin and the number rule, and the server stages
    // the boot chain only for the approval it accepted.
    const auto offer_line = env_.control(encode_offer_request(v.approval_json));
    const auto offer = offer_line ? decode_offer_reply(*offer_line) : std::nullopt;
    if (!offer) {
        return {CycleOutcome::Waiting,
                "staged " + v.tag.tag + "; the server did not answer the approval offer"};
    }
    if (!offer->ok) {
        return {CycleOutcome::Refused,
                "the server refused the approval of " + v.tag.tag + ": " + offer->result};
    }
    const auto stage_line = env_.control(encode_stage_request(number));
    if (!stage_line || !decode_ok_reply(*stage_line)) {
        return {CycleOutcome::Waiting,
                "staged " + v.tag.tag + "; the server did not record the staged release"};
    }
    auto gate = ask_turn(number);
    if (!gate) {
        return {CycleOutcome::Waiting,
                "staged " + v.tag.tag + "; the turn gate did not answer"};
    }
    if (*gate == TurnGate::Wait) gate = await_turn(number, v.tag.tag);
    switch (*gate) {
        case TurnGate::Go:
            break;
        case TurnGate::Wait:
            return {CycleOutcome::Waiting,
                    "staged " + v.tag.tag + "; upgrade turn: wait (no turn within " +
                        std::to_string(config_.turn_wait.count()) + " s)"};
        case TurnGate::NotStarted:
            return {CycleOutcome::Waiting, "staged " + v.tag.tag + "; upgrade turn: " +
                                               std::string(turn_gate_name(*gate))};
        case TurnGate::Halted:
            state.halted_release_number = number;
            state.last_result = "the rollout of " + v.tag.tag + " halted";
            (void)save_state(state);
            return {CycleOutcome::Halted, state.last_result + "; waiting for a newer release"};
        case TurnGate::Done:
            // Finalized state says this server already runs the release, but
            // the installed files say otherwise. Change nothing.
            return {CycleOutcome::Refused, "the turn gate reports " + v.tag.tag +
                                               " done, but it is not installed"};
    }

    const auto baseline = server_health_line();
    if (!baseline) return {CycleOutcome::Refused, "the server health is unavailable"};

    std::string error;
    const auto installed_text =
        read_file(host_path(security::kReleaseApprovalPath), kMaxMetadataBytes);
    auto installed = installed_text
                         ? security::parse_release_approval_bundle(*installed_text, error)
                         : std::nullopt;
    if (!installed ||
        !security::verify_release_approval_bundle(*installed, config_.trust.genesis_public_key,
                                                  config_.trust.network_id, error)) {
        return {CycleOutcome::Refused, "the installed release approval does not verify"};
    }
    const bool pcrs_changed = security::boot_pcrs_from_approval(v.approval.approval) !=
                              security::boot_pcrs_from_approval(installed->approval);

    std::map<std::string, std::string> installed_versions;
    if (!release.lock.packages.empty()) {
        const auto q = env_.run(dpkg_query_argv(release.lock));
        installed_versions = parse_dpkg_query(q.output);
    }
    const auto plan = plan_os_packages(release.lock, installed_versions);
    const auto decision_reboot = decide_reboot(plan.boot_chain_changed, pcrs_changed);
    if (!decision_reboot.error.empty()) {
        state.halted_release_number = v.tag.number;
        state.last_result = v.tag.tag + " refused: " + decision_reboot.error;
        (void)save_state(state);
        return {CycleOutcome::Refused, decision_reboot.error};
    }
    if (decision_reboot.reboot != v.manifest.boot_chain_changed) {
        spdlog::warn("[updater] the manifest says boot_chain_changed={}, this host needs "
                     "reboot={}; this host was not on the previous release's package set",
                     v.manifest.boot_chain_changed, decision_reboot.reboot);
    }

    State next = state;
    next.tag = v.tag.tag;
    next.number = number;
    next.baseline_line = *baseline;
    next.packages_install = plan.install;
    next.packages_previous = plan.previous;
    next.reboot = decision_reboot.reboot;
    next.staged_seal_names.clear();
    next.previous_grub_entry.clear();
    next.measured_initrd.clear();
    if (!next.packages_install.empty() && !back_up_measured_initrd(next, error)) {
        return {CycleOutcome::Refused, error};
    }

    if (next.reboot) {
        const auto grub_default = read_file(host_path(kGrubDefault), kMaxMetadataBytes);
        if (!grub_default || !grub_default_is_saved(*grub_default)) {
            return {CycleOutcome::Refused,
                    "a boot-chain update needs GRUB_DEFAULT=saved so the previous entry can boot"};
        }
        const auto grub_cfg = read_file(host_path(kGrubCfg), 4 * kMaxMetadataBytes);
        const auto entry = grub_cfg ? grub_entry_for_kernel(*grub_cfg, env_.kernel_release())
                                    : std::nullopt;
        if (!entry) {
            return {CycleOutcome::Refused, "cannot find the GRUB entry of the running kernel"};
        }
        next.previous_grub_entry = *entry;
        const auto line = env_.control(encode_stage_boot_chain_request(v.approval_json));
        const auto staged = line ? decode_stage_boot_chain_reply(*line) : std::nullopt;
        if (!staged || !staged->ok) {
            return {CycleOutcome::Refused,
                    "the server did not stage the boot set for the new boot chain: " +
                        (staged ? staged->detail : std::string("no answer"))};
        }
        next.staged_seal_names = staged->staged;
        next.boot_id = trim(read_file(host_path(kBootId), 256).value_or(""));
    }

    next.phase = "swapping";
    if (!save_state(next)) return {CycleOutcome::Refused, "cannot record the update state"};
    state = next;
    spdlog::info("[updater] installing {} (release {}){}", state.tag, state.number,
                 state.reboot ? " with a boot-chain change" : "");

    if (!systemctl({"stop", std::string(kServerUnit), std::string(kAttestdUnit)}, error)) {
        state.phase = "idle";
        (void)save_state(state);
        std::string ignored;
        (void)systemctl({"start", std::string(kAttestdUnit), std::string(kServerUnit)}, ignored);
        return {CycleOutcome::Refused, error};
    }
    if (state.reboot) {
        // The server is stopped, so no runtime seal can drop the staged slot now.
        for (const auto& name : state.staged_seal_names) {
            std::error_code ec;
            if (!fs::exists(host_path(kSealedDir) / (name + ".next.sealed"), ec)) {
                return roll_back(state, "the staged sealed blob for " + name + " is missing",
                                 true);
            }
        }
    }

    SwapPlan swap;
    swap.release_tag = state.tag;
    swap.backup_dir = state_dir() / "previous" / state.tag;
    for (const auto& f : v.manifest.server_files) {
        swap.files.push_back({host_path(f.path), release.files.at(f.asset), f.sha256});
    }
    SwapFile approval_file{host_path(security::kReleaseApprovalPath),
                           release.files.at(std::string(kApprovalAsset)),
                           v.manifest.approval_sha256};
    approval_file.mode = fs::perms::owner_read | fs::perms::owner_write |
                         fs::perms::group_read | fs::perms::others_read;
    swap.files.push_back(approval_file);

    FileSwapper swapper(state_dir() / "swap-journal.json");
    if (!swapper.apply(swap, error)) return roll_back(state, error, true);
    state.phase = "swapped";
    (void)save_state(state);
    return resume(state);
}

CycleResult Updater::resume(State& state) {
    std::string error;
    FileSwapper swapper(state_dir() / "swap-journal.json");
    if (state.phase == "swapping") {
        spdlog::warn("[updater] resuming an interrupted swap of {}", state.tag);
        if (!swapper.resume(error)) return roll_back(state, error, true);
        state.phase = "swapped";
        if (!save_state(state)) return {CycleOutcome::Refused, "cannot record the update state"};
    }
    if (state.phase == "swapped") {
        if (!state.packages_install.empty()) {
            // The archive indexes must name the locked versions; apt verifies
            // the archive signatures.
            const auto lists = env_.run({"apt-get", "update"});
            if (lists.exit_code != 0) {
                return roll_back(state, "apt-get update failed: " + trim(lists.output), true);
            }
            const auto r = env_.run(apt_install_argv(state.packages_install));
            if (r.exit_code != 0) {
                return roll_back(state, "apt-get install failed: " + trim(r.output), true);
            }
            // The approval keeps PCR 8/9 unless the boot chain changes, so the
            // initramfs must stay the measured image. With a boot-chain
            // change, the new PCRs cover what the packages produce.
            if (!state.reboot && !restore_measured_initrd(state, error)) {
                return roll_back(state, error, true);
            }
            if (!check_library_hashes(error)) return roll_back(state, error, true);
        }
        if (!state.reboot) return finish_without_reboot(state);
        const auto unset = env_.run({"grub-editenv", host_path(kGrubEnv).string(), "unset",
                                     "saved_entry"});
        if (unset.exit_code != 0) {
            return roll_back(state, "cannot clear the saved GRUB entry: " + trim(unset.output),
                             true);
        }
        state.phase = "rebooting";
        if (!save_state(state)) return roll_back(state, "cannot record the update state", true);
        if (!systemctl({"reboot"}, error)) return roll_back(state, error, true);
        return {CycleOutcome::Rebooting, "rebooting into the boot chain of " + state.tag};
    }
    if (state.phase == "rebooting") {
        const auto boot_id = trim(read_file(host_path(kBootId), 256).value_or(""));
        if (!state.boot_id.empty() && boot_id == state.boot_id) {
            // The reboot did not happen yet; ask again rather than judge health.
            if (!systemctl({"reboot"}, error)) return roll_back(state, error, true);
            return {CycleOutcome::Rebooting, "rebooting into the boot chain of " + state.tag};
        }
        return run_health_gate(state);
    }
    if (state.phase == "boot_rollback") {
        std::string notes;
        std::vector<OsPackage> restore;
        for (const auto& p : state.packages_previous) {
            if (!p.version.empty()) restore.push_back(p);
        }
        if (!restore.empty() && env_.run(apt_install_argv(restore)).exit_code != 0) {
            notes = "; restoring the previous packages failed";
        }
        if (!restore_measured_initrd(state, error)) notes += "; " + error;
        const std::string detail = state.last_result + notes;
        report(state, false, detail);
        state.halted_release_number = state.number;
        state.phase = "idle";
        state.last_result = detail;
        swapper.clear();
        (void)save_state(state);
        return {CycleOutcome::Failed, detail};
    }
    return {CycleOutcome::Refused, "unknown updater phase " + state.phase};
}

bool Updater::back_up_measured_initrd(State& state, std::string& error) {
    state.measured_initrd.clear();
    const auto kernel = trim(env_.kernel_release());
    if (kernel.empty() || kernel.find('/') != std::string::npos || kernel == "." ||
        kernel == "..") {
        error = "cannot name the initramfs of the running kernel";
        return false;
    }
    const std::string initrd = std::string(kInitrdPrefix) + kernel;
    const auto target = host_path(initrd);
    std::error_code ec;
    if (!fs::exists(target, ec)) return true;
    const auto backup = initrd_backup_path(state_dir(), state.tag, initrd);
    fs::create_directories(backup.parent_path(), ec);
    fs::permissions(backup.parent_path(), fs::perms::owner_all, fs::perm_options::replace, ec);
    if (!install_file_atomic(target, backup, fs::status(target, ec).permissions(), error)) {
        return false;
    }
    state.measured_initrd = initrd;
    return true;
}

bool Updater::restore_measured_initrd(const State& state, std::string& error) {
    if (state.measured_initrd.empty()) return true;
    const auto target = host_path(state.measured_initrd);
    const auto backup = initrd_backup_path(state_dir(), state.tag, state.measured_initrd);
    const auto kept = sha256_file_hex(backup.string());
    if (!kept) {
        error = "the backup of the measured " + state.measured_initrd + " is missing";
        return false;
    }
    if (sha256_file_hex(target.string()) == kept) return true;
    spdlog::warn("[updater] the package install changed {}; restoring the measured image",
                 state.measured_initrd);
    std::error_code ec;
    if (!install_file_atomic(backup, target, fs::status(backup, ec).permissions(), error)) {
        return false;
    }
    if (sha256_file_hex(target.string()) != kept) {
        error = "the restored " + state.measured_initrd + " does not match its backup";
        return false;
    }
    return true;
}

bool Updater::check_library_hashes(std::string& error) {
    const auto text = read_file(host_path(security::kReleaseApprovalPath), kMaxMetadataBytes);
    std::string why;
    const auto bundle = text ? security::parse_release_approval_bundle(*text, why) : std::nullopt;
    if (!bundle) {
        error = "the installed release approval does not parse";
        return false;
    }
    for (const auto& approved : bundle->approval.approved_paths) {
        if (std::find(std::begin(kSwappablePaths), std::end(kSwappablePaths), approved.path) !=
            std::end(kSwappablePaths)) {
            continue;
        }
        const auto hash = sha256_file_hex(host_path(approved.path).string());
        if (!hash || std::find(approved.sha256.begin(), approved.sha256.end(), *hash) ==
                         approved.sha256.end()) {
            error = approved.path + " is not an approved build after the package install";
            return false;
        }
    }
    return true;
}

CycleResult Updater::finish_without_reboot(State& state) {
    std::string error;
    if (!systemctl({"start", std::string(kAttestdUnit), std::string(kServerUnit)}, error)) {
        return roll_back(state, error, true);
    }
    return run_health_gate(state);
}

CycleResult Updater::run_health_gate(State& state) {
    const auto baseline = decode_health_reply(state.baseline_line);
    if (!baseline) return roll_back(state, "the recorded baseline is unreadable", true);
    const auto deadline = env_.now() + config_.health_timeout;
    HealthResult result;
    while (true) {
        result = evaluate_health(*baseline, server_health(), state.number);
        if (result.verdict != HealthVerdict::Pending) break;
        if (env_.now() >= deadline) {
            result = {HealthVerdict::Failed, "health gate timed out: " + result.reason};
            break;
        }
        env_.sleep(config_.health_poll);
    }
    if (result.verdict == HealthVerdict::Healthy) return commit(state, result.reason);
    if (!state.reboot) return roll_back(state, result.reason, true);

    // After a reboot: restore the files and boot the previous GRUB entry.
    std::string error;
    FileSwapper swapper(state_dir() / "swap-journal.json");
    std::string notes;
    (void)systemctl({"stop", std::string(kServerUnit), std::string(kAttestdUnit)}, error);
    if (!swapper.rollback(error)) notes += "; " + error;
    const auto set = env_.run({"grub-set-default", state.previous_grub_entry});
    if (set.exit_code != 0) notes += "; grub-set-default failed: " + trim(set.output);
    state.phase = "boot_rollback";
    state.last_result = state.tag + " failed after reboot: " + result.reason + notes;
    (void)save_state(state);
    if (set.exit_code != 0 || !systemctl({"reboot"}, error)) {
        // Without the previous entry selected, a reboot would return to the
        // failed chain. Stay up on the restored files and report.
        (void)systemctl({"start", std::string(kAttestdUnit), std::string(kServerUnit)}, error);
        return resume(state);
    }
    return {CycleOutcome::Rebooting, state.last_result + "; booting the previous GRUB entry"};
}

CycleResult Updater::roll_back(State& state, const std::string& reason, bool restart_services) {
    spdlog::error("[updater] {} failed: {}; rolling back", state.tag, reason);
    std::string notes;
    std::string error;
    (void)systemctl({"stop", std::string(kServerUnit), std::string(kAttestdUnit)}, error);
    FileSwapper swapper(state_dir() / "swap-journal.json");
    if (swapper.load() && !swapper.rollback(error)) notes += "; " + error;
    // Packages change only after the swap completes ("swapped").
    if (!state.packages_install.empty() && state.phase != "swapping") {
        std::vector<OsPackage> restore;
        for (const auto& p : state.packages_previous) {
            if (!p.version.empty()) restore.push_back(p);
        }
        if (!restore.empty() && env_.run(apt_install_argv(restore)).exit_code != 0) {
            notes += "; restoring the previous packages failed";
        }
        // The previous boot chain needs its measured initramfs back.
        if (!restore_measured_initrd(state, error)) notes += "; " + error;
    }
    if (restart_services &&
        !systemctl({"start", std::string(kAttestdUnit), std::string(kServerUnit)}, error)) {
        notes += "; " + error;
    }
    const std::string detail = state.tag + " rolled back: " + reason + notes;
    report(state, false, detail);
    state.halted_release_number = state.number;
    state.phase = "idle";
    state.last_result = detail;
    swapper.clear();
    (void)save_state(state);
    return {CycleOutcome::Failed, detail};
}

CycleResult Updater::commit(State& state, const std::string& detail) {
    state.installed_release_number = state.number;
    state.phase = "idle";
    state.last_result = state.tag + " upgraded: " + detail;
    if (!save_state(state)) return {CycleOutcome::Refused, "cannot record the installed release"};
    report(state, true, detail);
    FileSwapper(state_dir() / "swap-journal.json").clear();
    // Keep only the files from before this release.
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(state_dir() / "previous", ec)) {
        if (entry.path().filename() != state.tag) fs::remove_all(entry.path(), ec);
    }
    fs::remove_all(state_dir() / "staged", ec);
    return {CycleOutcome::Upgraded, state.last_result};
}

}  // namespace nexus::updater
