#include <LemonadeNexus/Security/Storage/StorageVault.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <sstream>

namespace nexus::security {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

constexpr std::string_view kMagic = "LNXVAULT";
constexpr uint8_t kFormat = 1;
constexpr std::size_t kKeyIdSize = 16;
constexpr std::size_t kHeaderSize = kMagic.size() + 1 + kKeyIdSize;
constexpr int kStateFormat = 1;
constexpr std::string_view kStateFile = "vault-state.json";
// Domain separation of the two DEK derivations. The salt is the storage key
// role tag (design B1).
constexpr std::string_view kSalt = "LEMONADE-NEXUS-STORAGE-V1";
constexpr std::string_view kFileKeyInfo = "lemonade-nexus-storage-file-key-v1";
constexpr std::string_view kKeyIdInfo = "lemonade-nexus-storage-file-key-id-v1";

std::span<const uint8_t> as_bytes(std::string_view text) {
    return {reinterpret_cast<const uint8_t*>(text.data()), text.size()};
}

std::optional<std::string> read_whole(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream buffer;
    buffer << in.rdbuf();
    if (in.bad()) return std::nullopt;
    return std::move(buffer).str();
}

void wipe(std::string& text) {
    if (!text.empty()) sodium_memzero(text.data(), text.size());
    text.clear();
}

std::optional<VaultMode> parse_mode(std::string_view text) {
    for (auto m : {VaultMode::Plaintext, VaultMode::Migrating, VaultMode::Encrypted}) {
        if (vault_mode_name(m) == text) return m;
    }
    return std::nullopt;
}

std::optional<VaultPhase> parse_phase(std::string_view text) {
    for (auto p : {VaultPhase::Idle, VaultPhase::Staging, VaultPhase::Verifying,
                   VaultPhase::Promoting, VaultPhase::RotateStaging,
                   VaultPhase::RotateVerifying}) {
        if (vault_phase_name(p) == text) return p;
    }
    return std::nullopt;
}

}  // namespace

std::string_view vault_mode_name(VaultMode mode) {
    switch (mode) {
        case VaultMode::Plaintext: return "plaintext";
        case VaultMode::Migrating: return "migrating";
        case VaultMode::Encrypted: return "encrypted";
    }
    return "encrypted";
}

std::string_view vault_phase_name(VaultPhase phase) {
    switch (phase) {
        case VaultPhase::Idle: return "idle";
        case VaultPhase::Staging: return "staging";
        case VaultPhase::Verifying: return "verifying";
        case VaultPhase::Promoting: return "promoting";
        case VaultPhase::RotateStaging: return "rotate-staging";
        case VaultPhase::RotateVerifying: return "rotate-verifying";
    }
    return "idle";
}

StorageVault::StorageVault(fs::path data_root, fs::path state_directory,
                           crypto::SodiumCryptoService& crypto,
                           std::vector<VaultCoverage> coverage, StorageVaultOptions options)
    : data_root_(std::move(data_root).lexically_normal()),
      state_path_(std::move(state_directory) / kStateFile),
      crypto_(crypto),
      coverage_(std::move(coverage)),
      options_(options) {
    if (options_.batch == 0) options_.batch = 1;
}

std::vector<VaultCoverage> StorageVault::default_coverage() {
    return {
        {"node-identity", "identity", "keypair.enc", ""},
        {"jwt-secret", "identity", "jwt_secret.hex", ""},
        {"ddns-credentials", "identity", "ddns_credentials.enc", ""},
        {"account-replica", "account", "replica.json", ""},
        {"tree-node", "tree/nodes", "", ".json"},
        {"tree-delta", "tree/deltas", "", ".json"},
        {"tree-log", "tree/log", "", ".json"},
        // Phase 7b: TLS and ACME private keys are secret material at rest.
        // Cover the TLS private key in every FQDN directory (certs/<fqdn>/
        // privkey.pem) and the ACME account key (certs/account.key). The public
        // cert (fullchain.pem) and meta.json stay plaintext: they are not secret,
        // and the TLS listener still opens the cert by path.
        {"tls-key", "certs", "privkey.pem", ""},
        {"acme-account-key", "certs", "account.key", ""},
    };
}

// --- Classification ------------------------------------------------------------------

std::optional<StorageVault::Covered> StorageVault::classify(const fs::path& path) const {
    const auto normal = path.lexically_normal();
    const auto relative = normal.lexically_relative(data_root_);
    if (relative.empty() || relative.is_absolute()) return std::nullopt;
    const std::string rel = relative.generic_string();
    if (rel.starts_with("..")) return std::nullopt;
    const std::string directory = relative.parent_path().generic_string();
    const std::string name = relative.filename().string();
    for (const auto& c : coverage_) {
        // The file sits in `c.directory` or in any subdirectory beneath it
        // (recursive coverage). Nested FQDN cert directories (certs/<fqdn>/)
        // hold privkey.pem one level below the declared `certs` directory.
        const bool in_dir = directory == c.directory ||
            (c.directory.empty()
                 ? false
                 : (directory.size() > c.directory.size() &&
                    directory.starts_with(c.directory) &&
                    directory[c.directory.size()] == '/'));
        if (!in_dir) continue;
        const bool match = !c.name.empty() ? name == c.name
                                           : (!c.suffix.empty() && name.size() > c.suffix.size() &&
                                              name.ends_with(c.suffix));
        if (match) return Covered{normal, rel, &c};
    }
    return std::nullopt;
}

bool StorageVault::covers(const fs::path& path) const {
    return classify(path).has_value();
}

fs::path StorageVault::staged_path(const fs::path& path) {
    fs::path staged = path;
    staged += kVaultStagedSuffix;
    return staged;
}

std::vector<std::string> StorageVault::test_enumerate_relative() const {
    std::vector<std::string> out;
    for (const auto& file : enumerate()) out.push_back(file.relative);
    return out;
}

std::vector<StorageVault::Covered> StorageVault::enumerate() const {
    last_scan_ok_ = true;
    std::map<std::string, Covered> found;

    // Manual recursive walk that refuses to follow symlinks. The standard
    // recursive_directory_iterator follows symlinks to directories and can
    // loop; a manual walk lets us reject every symlink and non-regular entry
    // before descending, so a partial or unsafe list is never reported as
    // complete.
    std::function<bool(const fs::path&)> walk =
        [&](const fs::path& dir) -> bool {
        std::error_code ec;
        auto it = fs::directory_iterator(dir, ec);
        if (ec) {
            spdlog::error("[storage-vault] cannot scan {}", dir.string());
            return false;
        }
        while (it != fs::directory_iterator()) {
            const auto sstatus = it->symlink_status(ec);
            if (ec) {
                spdlog::error("[storage-vault] cannot stat {}: {}",
                               it->path().string(), ec.message());
                return false;
            }
            if (fs::is_symlink(sstatus)) {
                spdlog::error("[storage-vault] symlink in covered directory: "
                               "{}", it->path().string());
                return false;
            }
            const bool is_regular = fs::is_regular_file(sstatus);
            const bool is_dir = fs::is_directory(sstatus);
            if (!is_regular && !is_dir) {
                spdlog::error("[storage-vault] non-regular entry in covered "
                               "directory: {}", it->path().string());
                return false;
            }
            if (is_dir) {
                if (!walk(it->path())) return false;
            } else {
                // A staged copy ("<file>.vault-new") whose original is gone
                // still counts: after a rotation commit it is the only current
                // copy. Classify the path with the staged suffix stripped so
                // the original name matches; the AAD uses the original
                // relative path.
                std::string name = it->path().filename().string();
                fs::path orig = it->path();
                if (name.ends_with(kVaultStagedSuffix)) {
                    orig = orig.parent_path() /
                           name.substr(0, name.size() - kVaultStagedSuffix.size());
                }
                if (auto file = classify(orig)) {
                    found.emplace(file->relative, std::move(*file));
                }
            }
            it.increment(ec);
            if (ec) {
                spdlog::error("[storage-vault] scan of {} failed: {}",
                               dir.string(), ec.message());
                return false;
            }
        }
        return true;
    };

    for (const auto& c : coverage_) {
        const auto dir = data_root_ / c.directory;
        std::error_code ec;
        if (!fs::is_directory(dir, ec)) continue;
        if (!walk(dir)) {
            last_scan_ok_ = false;
            return {};
        }
    }
    std::vector<Covered> out;
    out.reserve(found.size());
    for (auto& [rel, file] : found) out.push_back(std::move(file));
    return out;
}

// --- Cipher --------------------------------------------------------------------------

StorageVault::KeyId StorageVault::key_id(std::span<const uint8_t> dek) const {
    const auto derived = crypto_.hkdf_sha256(dek, as_bytes(kSalt), as_bytes(kKeyIdInfo), kKeyIdSize);
    KeyId id{};
    std::copy_n(derived.begin(), std::min(derived.size(), id.size()), id.begin());
    return id;
}

bool StorageVault::has_header(std::string_view bytes) {
    return bytes.size() >= kMagic.size() && bytes.substr(0, kMagic.size()) == kMagic;
}

std::optional<StorageVault::KeyId> StorageVault::header_key_id(std::string_view object) {
    if (object.size() < kHeaderSize || !has_header(object) ||
        static_cast<uint8_t>(object[kMagic.size()]) != kFormat) {
        return std::nullopt;
    }
    KeyId id{};
    std::memcpy(id.data(), object.data() + kMagic.size() + 1, id.size());
    return id;
}

std::optional<std::string> StorageVault::seal(const Covered& file, std::span<const uint8_t> dek,
                                              std::string_view plaintext) const {
    if (dek.size() != crypto::kAeadKeySize) return std::nullopt;
    const KeyId id = key_id(dek);
    auto derived = crypto_.hkdf_sha256(dek, as_bytes(kSalt), as_bytes(kFileKeyInfo),
                                       crypto::kAeadKeySize);
    crypto::AeadKey key{};
    std::copy_n(derived.begin(), key.size(), key.begin());
    sodium_memzero(derived.data(), derived.size());
    const auto aad = crypto::aead_aad(
        crypto::aead_purpose::kStorageFileAtRest,
        {as_bytes(file.coverage->domain), as_bytes(file.relative),
         std::span<const uint8_t>(id.data(), id.size())});
    const auto blob = crypto_.aead_encrypt(key, as_bytes(plaintext), aad);
    sodium_memzero(key.data(), key.size());
    if (blob.nonce.size() != crypto::kAeadNonceSize || blob.ciphertext.empty()) {
        return std::nullopt;
    }
    std::string out;
    out.reserve(kHeaderSize + blob.nonce.size() + blob.ciphertext.size());
    out.append(kMagic);
    out.push_back(static_cast<char>(kFormat));
    out.append(reinterpret_cast<const char*>(id.data()), id.size());
    out.append(reinterpret_cast<const char*>(blob.nonce.data()), blob.nonce.size());
    out.append(reinterpret_cast<const char*>(blob.ciphertext.data()), blob.ciphertext.size());
    return out;
}

std::optional<std::string> StorageVault::open(const Covered& file, std::span<const uint8_t> dek,
                                              std::string_view object) const {
    const auto id = header_key_id(object);
    if (!id || dek.size() != crypto::kAeadKeySize ||
        object.size() < kHeaderSize + crypto::kAeadNonceSize + crypto::kAeadTagSize) {
        return std::nullopt;
    }
    const KeyId expected = key_id(dek);
    if (sodium_memcmp(id->data(), expected.data(), id->size()) != 0) return std::nullopt;
    crypto::EncryptedBlob blob;
    blob.version = crypto::kEncryptedBlobVersion;
    const auto* base = reinterpret_cast<const uint8_t*>(object.data());
    blob.nonce.assign(base + kHeaderSize, base + kHeaderSize + crypto::kAeadNonceSize);
    blob.ciphertext.assign(base + kHeaderSize + crypto::kAeadNonceSize, base + object.size());
    auto derived = crypto_.hkdf_sha256(dek, as_bytes(kSalt), as_bytes(kFileKeyInfo),
                                       crypto::kAeadKeySize);
    crypto::AeadKey key{};
    std::copy_n(derived.begin(), key.size(), key.begin());
    sodium_memzero(derived.data(), derived.size());
    const auto aad = crypto::aead_aad(
        crypto::aead_purpose::kStorageFileAtRest,
        {as_bytes(file.coverage->domain), as_bytes(file.relative),
         std::span<const uint8_t>(id->data(), id->size())});
    auto plain = crypto_.aead_decrypt(key, blob, aad);
    sodium_memzero(key.data(), key.size());
    if (!plain) return std::nullopt;
    std::string out(plain->begin(), plain->end());
    sodium_memzero(plain->data(), plain->size());
    return out;
}

std::optional<std::string> StorageVault::seal_for(const fs::path& path,
                                                  std::span<const uint8_t> dek,
                                                  std::string_view plaintext) const {
    const auto file = classify(path);
    if (!file) return std::nullopt;
    return seal(*file, dek, plaintext);
}

// --- State ---------------------------------------------------------------------------

std::optional<VaultMode> StorageVault::recorded_mode(const fs::path& state_directory) {
    const auto path = state_directory / kStateFile;
    std::error_code ec;
    if (!fs::exists(path, ec)) return std::nullopt;
    const auto text = read_whole(path);
    const json j = text ? json::parse(*text, nullptr, false) : json();
    if (!j.is_object() || !j.contains("mode") || !j["mode"].is_string()) {
        return VaultMode::Encrypted;  // damaged: fail closed
    }
    return parse_mode(j["mode"].get<std::string>()).value_or(VaultMode::Encrypted);
}

bool StorageVault::save_state() {
    json j;
    j["format"] = kStateFormat;
    j["mode"] = vault_mode_name(mode_);
    j["phase"] = vault_phase_name(phase_);
    j["key_id"] = crypto::to_hex(std::span<const uint8_t>(target_key_id_));
    j["last_rotation_ms"] = last_rotation_ms_;
    j["rotation_requested"] = rotation_requested_;
    std::error_code ec;
    fs::create_directories(state_path_.parent_path(), ec);
    if (!write_durable(state_path_, j.dump())) {
        spdlog::error("[storage-vault] cannot write {}", state_path_.string());
        return false;
    }
    return true;
}

void StorageVault::load() {
    std::lock_guard lock(mutex_);
    pending_.clear();
    pending_loaded_ = false;
    const auto text = read_whole(state_path_);
    bool damaged = false;
    if (text) {
        const json j = json::parse(*text, nullptr, false);
        std::optional<VaultMode> mode;
        std::optional<VaultPhase> phase;
        std::vector<uint8_t> id;
        if (j.is_object() && j.value("format", 0) == kStateFormat && j.contains("mode") &&
            j["mode"].is_string() && j.contains("phase") && j["phase"].is_string() &&
            j.contains("key_id") && j["key_id"].is_string()) {
            mode = parse_mode(j["mode"].get<std::string>());
            phase = parse_phase(j["phase"].get<std::string>());
            id = crypto::from_hex(j["key_id"].get<std::string>());
        }
        if (mode && phase && id.size() == target_key_id_.size()) {
            mode_ = *mode;
            phase_ = *phase;
            std::copy(id.begin(), id.end(), target_key_id_.begin());
            last_rotation_ms_ = j.value("last_rotation_ms", uint64_t{0});
            rotation_requested_ = j.value("rotation_requested", false);
        } else {
            damaged = true;
        }
    } else {
        // No state: plaintext, unless a covered file already holds the header.
        // A deleted state file must not turn encrypted files back into
        // accepted plaintext.
        mode_ = VaultMode::Plaintext;
        phase_ = VaultPhase::Idle;
        for (const auto& file : enumerate()) {
            const auto bytes = read_whole(file.path);
            if (bytes && has_header(*bytes)) {
                damaged = true;
                break;
            }
        }
    }
    if (damaged) {
        spdlog::error("[storage-vault] {} is missing or damaged and encrypted files exist; the "
                      "vault stays encrypted and refuses plaintext",
                      state_path_.string());
        mode_ = VaultMode::Encrypted;
        phase_ = VaultPhase::Idle;
        return;
    }
    if (mode_ == VaultMode::Encrypted && phase_ == VaultPhase::Promoting) {
        // The migration or rotation committed; the replacements need no key.
        promote_all(target_key_id_);
        phase_ = VaultPhase::Idle;
        (void)save_state();
    }
    spdlog::info("[storage-vault] mode {}, phase {}", vault_mode_name(mode_), vault_phase_name(phase_));
}

void StorageVault::attach(DataKeySource* source) {
    std::lock_guard lock(mutex_);
    source_ = source;
}

VaultMode StorageVault::mode() const {
    std::lock_guard lock(mutex_);
    return mode_;
}

VaultPhase StorageVault::phase() const {
    std::lock_guard lock(mutex_);
    return phase_;
}

uint64_t StorageVault::last_rotation_ms() const {
    std::lock_guard lock(mutex_);
    return last_rotation_ms_;
}

bool StorageVault::rotation_requested() const {
    std::lock_guard lock(mutex_);
    return rotation_requested_;
}

bool StorageVault::files_ready() const {
    std::lock_guard lock(mutex_);
    if (mode_ != VaultMode::Encrypted) return true;
    return source_ != nullptr && source_->data_key().has_value();
}

bool StorageVault::request_rotation() {
    std::lock_guard lock(mutex_);
    if (mode_ != VaultMode::Encrypted) return false;
    if (rotation_requested_) return true;
    rotation_requested_ = true;
    return save_state();
}

// --- Reads and writes ----------------------------------------------------------------

VaultRead StorageVault::read(const fs::path& path) const {
    const auto file = classify(path);
    if (!file) return {VaultReadStatus::Rejected, {}};
    std::lock_guard lock(mutex_);
    return read_locked(*file);
}

VaultRead StorageVault::read_locked(const Covered& file) const {
    std::error_code ec;
    const auto staged = staged_path(file.path);
    const bool have_file = fs::exists(file.path, ec);
    const bool have_staged = fs::exists(staged, ec);
    if (mode_ != VaultMode::Encrypted) {
        // Before the migration commits, the plaintext is authoritative.
        if (!have_file) return {VaultReadStatus::Missing, {}};
        auto bytes = read_whole(file.path);
        if (!bytes) return {VaultReadStatus::Rejected, {}};
        if (has_header(*bytes)) {
            spdlog::error("[storage-vault] {} is encrypted before the migration committed",
                          file.relative);
            return {VaultReadStatus::Rejected, {}};
        }
        return {VaultReadStatus::Ok, std::move(*bytes)};
    }
    if (!have_file && !have_staged) return {VaultReadStatus::Missing, {}};
    const auto dek = source_ != nullptr ? source_->data_key() : std::nullopt;
    if (!dek) return {VaultReadStatus::Locked, {}};
    const KeyId current = key_id(dek->span());
    // The candidate under the DEK in memory wins: the staged copy after a
    // rotation commit, the file itself otherwise.
    for (const auto* candidate : {&staged, &file.path}) {
        if (candidate == &staged ? !have_staged : !have_file) continue;
        auto bytes = read_whole(*candidate);
        if (!bytes) continue;
        const auto id = header_key_id(*bytes);
        if (!id || *id != current) continue;
        if (auto plain = open(file, dek->span(), *bytes)) {
            return {VaultReadStatus::Ok, std::move(*plain)};
        }
        spdlog::error("[storage-vault] {} does not authenticate", file.relative);
        return {VaultReadStatus::Rejected, {}};
    }
    spdlog::error("[storage-vault] {} is not encrypted under the current data key",
                  file.relative);
    return {VaultReadStatus::Rejected, {}};
}

bool StorageVault::write(const fs::path& path, std::string_view bytes) {
    const auto file = classify(path);
    if (!file) return false;
    std::lock_guard lock(mutex_);
    return write_locked(*file, bytes);
}

bool StorageVault::write_locked(const Covered& file, std::string_view bytes) {
    std::error_code ec;
    fs::create_directories(file.path.parent_path(), ec);
    const auto staged = staged_path(file.path);
    if (mode_ != VaultMode::Encrypted) {
        if (!write_durable(file.path, bytes)) return false;
        // A stale staged copy is re-staged before the migration commits.
        fs::remove(staged, ec);
        return true;
    }
    const auto dek = source_ != nullptr ? source_->data_key() : std::nullopt;
    if (!dek) return false;
    auto object = seal(file, dek->span(), bytes);
    if (!object) return false;
    const KeyId current = key_id(dek->span());
    // After a rotation commit and before its replacement, the staged copy is
    // the current one: write there, so no reader sees the older content.
    if (fs::exists(staged, ec)) {
        const auto existing = read_whole(staged);
        const auto id = existing ? header_key_id(*existing) : std::nullopt;
        if (id && *id == current) {
            return write_durable(staged, *object);
        }
    }
    if (!write_durable(file.path, *object)) return false;
    fs::remove(staged, ec);
    return true;
}

bool StorageVault::remove(const fs::path& path) {
    const auto file = classify(path);
    if (!file) return false;
    std::lock_guard lock(mutex_);
    std::error_code ec;
    // The staged copy goes first, so a crash never leaves it as the only copy
    // of a file the owner deleted.
    fs::remove(staged_path(file->path), ec);
    fs::remove(file->path, ec);
    return !fs::exists(file->path, ec) && !fs::exists(staged_path(file->path), ec);
}

// --- Staging, verification, and replacement ------------------------------------------

bool StorageVault::stage_one(const Covered& file, std::span<const uint8_t> source_key,
                             std::span<const uint8_t> target_key) {
    std::error_code ec;
    const auto staged = staged_path(file.path);
    if (!fs::exists(file.path, ec)) {
        fs::remove(staged, ec);
        return true;
    }
    auto bytes = read_whole(file.path);
    if (!bytes) return false;
    std::string plain;
    if (source_key.empty()) {
        if (has_header(*bytes)) return false;
        plain = std::move(*bytes);
    } else {
        auto opened = open(file, source_key, *bytes);
        if (!opened) return false;
        plain = std::move(*opened);
    }
    auto object = seal(file, target_key, plain);
    if (!object) {
        wipe(plain);
        return false;
    }
    const bool written = write_durable(staged, *object);
    // Read back what is on disk: a staged copy counts only once it decrypts.
    bool ok = false;
    if (written) {
        const auto back = read_whole(staged);
        auto reopened = back ? open(file, target_key, *back) : std::nullopt;
        ok = reopened && *reopened == plain;
        if (reopened) wipe(*reopened);
    }
    wipe(plain);
    return ok;
}

bool StorageVault::verify_scan_complete(const std::set<std::string>& original_files) const {
    for (const auto& file : enumerate()) {
        if (original_files.find(file.relative) == original_files.end()) {
            // A covered file that was not in the original scan: it appeared
            // after the scan, so the list must be repeated.
            spdlog::warn("[storage-vault] covered file {} appeared after the scan; "
                         "the scan must be repeated", file.relative);
            return false;
        }
    }
    if (!last_scan_ok_) {
        spdlog::warn("[storage-vault] scan failed; the scan must be repeated");
        return false;
    }
    return true;
}

bool StorageVault::verify_all(std::span<const uint8_t> source_key,
                              std::span<const uint8_t> target_key) {
    for (const auto& file : enumerate()) {
        std::error_code ec;
        if (!fs::exists(file.path, ec)) {
            // Only a staged copy is left. Before a commit that cannot happen
            // through write() or remove(); drop it rather than commit it.
            fs::remove(staged_path(file.path), ec);
            continue;
        }
        auto bytes = read_whole(file.path);
        if (!bytes) return false;
        std::optional<std::string> plain;
        if (source_key.empty()) {
            if (has_header(*bytes)) return false;
            plain = std::move(*bytes);
        } else {
            plain = open(file, source_key, *bytes);
        }
        if (!plain) {
            spdlog::error("[storage-vault] {} does not open before the commit", file.relative);
            return false;
        }
        const auto staged = read_whole(staged_path(file.path));
        auto reopened = staged ? open(file, target_key, *staged) : std::nullopt;
        const bool same = reopened && *reopened == *plain;
        if (reopened) wipe(*reopened);
        wipe(*plain);
        if (!same && !stage_one(file, source_key, target_key)) {
            return false;
        }
    }
    return true;
}

void StorageVault::promote_all(const KeyId& target) {
    // The staged copies were all verified before this ran; a scan failure here
    // never drops one.
    for (const auto& file : enumerate()) {
        const auto staged = staged_path(file.path);
        std::error_code ec;
        if (!fs::exists(staged, ec)) continue;
        const auto bytes = read_whole(staged);
        const auto id = bytes ? header_key_id(*bytes) : std::nullopt;
        if (!id || *id != target) {
            fs::remove(staged, ec);
            continue;
        }
        // Old content first (plaintext or old-DEK ciphertext), then the
        // atomic replacement. A crash between the two leaves the staged copy,
        // which the next pass promotes.
        overwrite_contents(file.path);
        if (!rename_durable(staged, file.path)) {
            spdlog::error("[storage-vault] cannot replace {}", file.relative);
        }
    }
}

void StorageVault::discard_staged() {
    for (const auto& file : enumerate()) {
        std::error_code ec;
        fs::remove(staged_path(file.path), ec);
    }
}

// --- Tick ----------------------------------------------------------------------------

void StorageVault::tick(uint64_t wall_ms) {
    std::lock_guard lock(mutex_);
    if (source_ == nullptr) return;
    if (mode_ == VaultMode::Encrypted) {
        tick_rotation(wall_ms);
    } else {
        tick_migration(wall_ms);
    }
}

void StorageVault::finish(uint64_t wall_ms) {
    phase_ = VaultPhase::Idle;
    last_rotation_ms_ = wall_ms;
    rotation_requested_ = false;
    pending_.clear();
    pending_loaded_ = false;
    staged_originals_.clear();
    (void)save_state();
}

void StorageVault::tick_migration(uint64_t wall_ms) {
    const auto dek = source_->data_key();
    if (!dek) return;  // B10 step 3: keep the plaintext and retry later.
    const KeyId current = key_id(dek->span());
    if (mode_ == VaultMode::Plaintext) {
        // Start only after an unlock round trip proved the wrapped DEK opens.
        if (!source_->unlock_verified()) return;
        mode_ = VaultMode::Migrating;
        phase_ = VaultPhase::Staging;
        target_key_id_ = current;
        if (!save_state()) {
            mode_ = VaultMode::Plaintext;
            phase_ = VaultPhase::Idle;
            return;
        }
        spdlog::info("[storage-vault] migration started");
    }
    if (current != target_key_id_) {
        // Another DEK than the one staging began with: start over.
        target_key_id_ = current;
        phase_ = VaultPhase::Staging;
        pending_loaded_ = false;
        (void)save_state();
    }
    if (phase_ == VaultPhase::Staging) {
        if (!pending_loaded_) {
            pending_ = enumerate();
            pending_loaded_ = true;
        }
        std::size_t done = 0;
        while (!pending_.empty() && done < options_.batch) {
            if (!stage_one(pending_.back(), {}, dek->span())) {
                spdlog::warn("[storage-vault] staging {} failed; retrying",
                             pending_.back().relative);
                return;
            }
            staged_originals_.insert(pending_.back().relative);
            pending_.pop_back();
            ++done;
        }
        if (!pending_.empty()) return;
        // A covered file that appeared after the scan, or a scan that could
        // not be repeated cleanly, must not be skipped: rescan and stage
        // before verifying.
        if (!verify_scan_complete(staged_originals_)) {
            phase_ = VaultPhase::Staging;
            pending_loaded_ = false;
            staged_originals_.clear();
            (void)save_state();
            return;
        }
        phase_ = VaultPhase::Verifying;
        if (!save_state()) return;
        // B10 step 2: a fresh round trip through the holders before any
        // plaintext goes.
        source_->request_verification();
        return;
    }
    if (phase_ != VaultPhase::Verifying || !source_->unlock_verified()) return;
    // The DEK in memory now equals what t holders unwrapped. Every staged copy
    // must decrypt under it to exactly the plaintext.
    if (!verify_all({}, dek->span())) {
        spdlog::warn("[storage-vault] migration verification failed; retrying");
        return;
    }
    mode_ = VaultMode::Encrypted;
    phase_ = VaultPhase::Promoting;
    if (!save_state()) {
        mode_ = VaultMode::Migrating;
        phase_ = VaultPhase::Verifying;
        return;
    }
    promote_all(current);
    finish(wall_ms);
    spdlog::info("[storage-vault] migration complete; plaintext removed");
}

void StorageVault::start_rotation() {
    if (!source_->begin_replacement()) return;
    const auto next = source_->replacement_key();
    if (!next) return;
    phase_ = VaultPhase::RotateStaging;
    target_key_id_ = key_id(next->span());
    pending_loaded_ = false;
    if (!save_state()) {
        source_->abort_replacement();
        phase_ = VaultPhase::Idle;
        return;
    }
    spdlog::info("[storage-vault] data key rotation started");
}

void StorageVault::abort_rotation() {
    discard_staged();
    source_->abort_replacement();
    phase_ = VaultPhase::Idle;
    pending_.clear();
    pending_loaded_ = false;
    (void)save_state();
    spdlog::info("[storage-vault] interrupted data key rotation discarded");
}

void StorageVault::tick_rotation(uint64_t wall_ms) {
    const auto dek = source_->data_key();
    if (!dek) return;
    const KeyId current = key_id(dek->span());
    if (phase_ == VaultPhase::Idle || phase_ == VaultPhase::Promoting) {
        if (phase_ == VaultPhase::Promoting) {
            promote_all(target_key_id_);
            finish(wall_ms);
            return;
        }
        if (last_rotation_ms_ == 0) {
            last_rotation_ms_ = wall_ms;
            (void)save_state();
        }
        const bool due = wall_ms >= last_rotation_ms_ &&
                         wall_ms - last_rotation_ms_ >= options_.rotation_interval_ms;
        if ((due || rotation_requested_) && source_->unlock_verified()) {
            start_rotation();
        }
        return;
    }
    if (phase_ != VaultPhase::RotateStaging && phase_ != VaultPhase::RotateVerifying) return;
    const auto next = source_->replacement_key();
    if (!next) {
        if (current == target_key_id_) {
            // The new wrapped key was committed before an interruption: the
            // staged copies are the current files.
            phase_ = VaultPhase::Promoting;
            (void)save_state();
            promote_all(current);
            finish(wall_ms);
            spdlog::info("[storage-vault] data key rotation resumed and completed");
        } else {
            abort_rotation();
        }
        return;
    }
    if (key_id(next->span()) != target_key_id_) {
        abort_rotation();
        return;
    }
    if (phase_ == VaultPhase::RotateStaging) {
        if (!pending_loaded_) {
            pending_ = enumerate();
            pending_loaded_ = true;
        }
        std::size_t done = 0;
        while (!pending_.empty() && done < options_.batch) {
            if (!stage_one(pending_.back(), dek->span(), next->span())) {
                spdlog::warn("[storage-vault] re-encrypting {} failed; retrying",
                             pending_.back().relative);
                return;
            }
            staged_originals_.insert(pending_.back().relative);
            pending_.pop_back();
            ++done;
        }
        if (!pending_.empty()) return;
        // A covered file that appeared after the scan, or a scan that could
        // not be repeated cleanly, must not be skipped: rescan and re-stage
        // before verifying.
        if (!verify_scan_complete(staged_originals_)) {
            pending_loaded_ = false;
            staged_originals_.clear();
            (void)save_state();
            return;
        }
        phase_ = VaultPhase::RotateVerifying;
        (void)save_state();
        return;
    }
    if (!source_->replacement_verified()) return;
    if (!verify_all(dek->span(), next->span())) {
        spdlog::warn("[storage-vault] rotation verification failed; retrying");
        return;
    }
    if (!source_->commit_replacement()) return;
    phase_ = VaultPhase::Promoting;
    (void)save_state();
    promote_all(target_key_id_);
    finish(wall_ms);
    spdlog::info("[storage-vault] data key rotation complete; old ciphertext removed");
}

}  // namespace nexus::security
