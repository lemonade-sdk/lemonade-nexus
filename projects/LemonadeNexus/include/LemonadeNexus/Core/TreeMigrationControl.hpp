#pragma once

// The root holder's side of the one-time tree merge (design A9,
// docs/Tree-Merge-Ceremony.md), served on the local control socket
// (UpgradeControl.hpp) to scripts/nexus-tree-migrate.
//
// The root management key and the data key exist only inside the running
// server, so every step that needs them runs here, and the script only
// carries bytes:
//
//   {"op":"tree_merge_context"}
//       The network, the configured root key, whether this server holds it,
//       this server's gossip identity, and the current Tier 1 members by
//       finalized membership with their advertised addresses.
//   {"op":"tree_merge_request","target":"ed25519:<base64>"}
//       A tree export request for that Tier 1 member, signed by the root
//       management key (tree_export_request). The member answers it on
//       POST /api/tree/merge/export with its signed export.
//   {"op":"tree_merge_export_backup","data_root":"<directory>"}
//       The signed export of a copy of this server's data directory (a backup
//       from before this server stopped holding the tree). Covered files are
//       read with the data key this server holds (StorageVault::copy_view).
//   {"op":"tree_merge_build","exports":[...],"block_time_ms":N}
//       Dry run: build_signed_merge over the exports. The reply carries the
//       review report (decisions, drops, per-server differences) and the tree
//       digest. Nothing is signed.
//   {"op":"tree_merge_sign","exports":[...],"block_time_ms":N,"tree_digest":"<base64>"}
//       Build again from the same input, refuse unless the tree digest equals
//       the reviewed one, sign the merge preimage with the root management
//       key, verify the signature, and reply with the signed commit.
//
// TreeMergeExportEndpoint is the Tier 1 side: it answers
// POST /api/tree/merge/export with this server's signed export while it
// awaits the merge.
//
// The root management key signs only two document types here: a tree export
// request for a current Tier 1 member, and the preimage of a merge that this
// server built itself from exports that verified. No request names bytes for
// the key to sign.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Tree/TreeMerge.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace nexus::crypto { class SodiumCryptoService; }

namespace nexus::core {

/// One current Tier 1 member as this server sees it.
struct TreeMigrationMember {
    std::string signer;     ///< gossip identity, "ed25519:<base64>"
    std::string address;    ///< advertised "ip:port" of its gossip socket, or empty
    uint16_t http_port = 0; ///< its public API port, or 0 when unknown
    std::string server_id;  ///< the label in its server certificate, or empty
};

/// The facts the requests are checked against.
struct TreeMigrationFacts {
    security::NetworkId network_id{};
    /// The configured root management key, "ed25519:<base64>", or empty.
    std::string root_key;
    /// This server's identity key is the configured root management key.
    bool holds_root_key = false;
    /// This server's gossip identity, "ed25519:<base64>".
    std::string signer;
    /// False until this server holds finalized membership.
    bool membership_known = false;
    std::vector<TreeMigrationMember> members;
};

/// What the handler needs from the running server. Every member must be set.
struct TreeMigrationHooks {
    /// Not owning.
    crypto::SodiumCryptoService* crypto = nullptr;
    std::function<TreeMigrationFacts()> facts;
    /// A signature by the root management key over `message`, or nullopt when
    /// this server does not hold that key.
    std::function<std::optional<crypto::Ed25519Signature>(std::span<const uint8_t> message)>
        sign_with_root_key;
    /// The signed export (sign_tree_export) of the data directory copy at
    /// `data_root`, marked as the root server export, or nullopt with `error`
    /// set.
    std::function<std::optional<nlohmann::json>(const std::filesystem::path& data_root,
                                                 std::string& error)>
        export_backup;
    /// Unix time in milliseconds.
    std::function<uint64_t()> wall_clock_ms;
    /// 16 random bytes as 32 lowercase hex digits.
    std::function<std::string()> random_nonce_hex;
};

/// What a Tier 1 member needs to answer POST /api/tree/merge/export.
struct TreeMergeExportSource {
    /// Not owning.
    crypto::SodiumCryptoService* crypto = nullptr;
    security::NetworkId network_id{};
    /// The configured root management key, "ed25519:<base64>".
    std::string root_key;
    /// This server's gossip identity, "ed25519:<base64>": the request target.
    std::string self;
    /// Signs the export. Not owning; must outlive the endpoint.
    const crypto::Ed25519Keypair* keypair = nullptr;
    /// True while the tree log awaits the merge commit.
    std::function<bool()> awaiting_merge;
    /// This server's export as it stands (tree::collect_tree_export).
    std::function<tree::TreeExport()> collect;
    /// Unix time in milliseconds.
    std::function<uint64_t()> wall_clock_ms;
};

/// Answers tree export requests on a Tier 1 member. Thread-safe.
class TreeMergeExportEndpoint {
public:
    explicit TreeMergeExportEndpoint(TreeMergeExportSource source) : source_(std::move(source)) {}

    /// The status and body for `body`: 200 with the signed export
    /// (tree::sign_tree_export); 409 when this server does not await the
    /// merge or the request was already served; 403 when the request does
    /// not verify (tree::verify_tree_export_request).
    [[nodiscard]] std::pair<int, nlohmann::json> answer(const nlohmann::json& body);

private:
    TreeMergeExportSource source_;
    std::mutex mutex_;
    tree::TreeExportNonces nonces_;
};

/// Most exports one build takes.
inline constexpr std::size_t kMaxTreeMigrationExports = 64;

/// Handle one tree_merge_* request (see the file comment) and return the
/// reply: "ok" (bool), and "error" when it is false. Runs on the security io
/// thread. Never throws.
[[nodiscard]] nlohmann::json handle_tree_migration_request(const nlohmann::json& request,
                                                           const TreeMigrationHooks& hooks);

}  // namespace nexus::core
