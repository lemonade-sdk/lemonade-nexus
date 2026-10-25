#pragma once

// Offline verification of a Sigstore build-provenance bundle.
//
// The release workflow attaches one bundle per artifact
// (actions/attest-build-provenance). The updater downloads it from the GitHub
// release beside the artifact and verifies it here against a pinned trusted
// root. Nothing is fetched from Sigstore, Rekor, or Fulcio at verification
// time.
//
// Provenance is a second check. The root of trust for a release is the
// release key that Genesis delegates; provenance adds that the bytes came
// from one workflow file, on one ref, in one repository, on a GitHub-hosted
// runner.
//
// What is verified, in order. Every step fails closed.
//   1. The bundle is a v0.3 (or v0.2) bundle with one DSSE envelope, one
//      leaf certificate, and one transparency-log entry of kind dsse 0.0.1.
//   2. The log entry: its signed entry timestamp (SET) verifies under a
//      pinned Rekor key that was valid at the integrated time. Its Merkle
//      inclusion proof reaches the root hash, and the root hash is the one in
//      a checkpoint signed by the same key.
//   3. The entry body binds this envelope: the payload hash, the signature,
//      and the signing certificate are the ones in the bundle.
//   4. The leaf certificate chains to a pinned Fulcio CA that was valid at the
//      integrated time, the leaf was valid at that time, it carries the code
//      signing usage, and it has a valid embedded SCT from a pinned CT log.
//   5. The DSSE signature verifies under the leaf key.
//   6. The statement is an in-toto v1 statement with SLSA provenance v1, and
//      one subject has the expected SHA-256.
//   7. The certificate's Fulcio identity extensions name the expected OIDC
//      issuer, repository, ref, workflow file, and a GitHub-hosted runner.
//      The provenance predicate names the same workflow.
//
// Limits. Only Rekor v1 entries with an inclusion promise are accepted. A
// bundle that relies only on an RFC 3161 timestamp, or a Rekor v2 entry, is
// refused until this verifier supports it. The trusted root is pinned in the
// package; a Sigstore key rotation needs a package update.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::updater {

/// One key with the window in which Sigstore used it. Times are Unix seconds.
struct SigstoreKey {
    /// Raw key id bytes: SHA-256 of the DER SubjectPublicKeyInfo.
    std::vector<uint8_t> key_id;
    /// DER SubjectPublicKeyInfo.
    std::vector<uint8_t> spki_der;
    std::string base_url;
    int64_t valid_from{0};
    /// INT64_MAX when the key has no end date.
    int64_t valid_until{INT64_MAX};
};

struct SigstoreCa {
    /// DER certificates, leaf-most first, self-signed root last.
    std::vector<std::vector<uint8_t>> chain;
    int64_t valid_from{0};
    int64_t valid_until{INT64_MAX};
};

/// The parts of a Sigstore trusted_root.json that bundle verification uses.
struct SigstoreTrustedRoot {
    std::vector<SigstoreKey> tlogs;
    std::vector<SigstoreKey> ctlogs;
    std::vector<SigstoreCa> certificate_authorities;
};

/// Parse application/vnd.dev.sigstore.trustedroot+json;version=0.1. nullopt
/// and a reason when the document is malformed or has no usable tlog, CT
/// log, or CA.
[[nodiscard]] std::optional<SigstoreTrustedRoot> parse_sigstore_trusted_root(
    std::string_view json_text, std::string& error);

/// The identity a release artifact must carry.
struct ProvenancePolicy {
    /// "owner/name".
    std::string repository;
    /// Path of the workflow file in the repository, ".github/workflows/x.yml".
    std::string workflow_path;
    /// Full ref, "refs/heads/main".
    std::string ref;
    std::string oidc_issuer{"https://token.actions.githubusercontent.com"};
};

/// Largest bundle accepted, checked before parsing.
inline constexpr std::size_t kMaxProvenanceBundleBytes = 1024 * 1024;

/// Verify `bundle_json` for an artifact whose SHA-256 is `subject_sha256_hex`
/// (64 lowercase hex). True only when every step above passes; otherwise
/// false with a reason in `error`. Thread-safe; no network access.
[[nodiscard]] bool verify_provenance_bundle(const SigstoreTrustedRoot& root,
                                            std::string_view bundle_json,
                                            std::string_view subject_sha256_hex,
                                            const ProvenancePolicy& policy,
                                            std::string& error);

/// RFC 3339 UTC ("2021-01-12T11:53:27Z", optional fraction) to Unix seconds.
[[nodiscard]] std::optional<int64_t> parse_rfc3339_utc(std::string_view text);

}  // namespace nexus::updater
