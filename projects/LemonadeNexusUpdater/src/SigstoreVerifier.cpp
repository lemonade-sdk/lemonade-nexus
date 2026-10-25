#include <LemonadeNexusUpdater/SigstoreVerifier.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <nlohmann/json.hpp>
#include <openssl/asn1.h>
#include <openssl/ct.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <climits>
#include <ctime>
#include <memory>

namespace nexus::updater {
namespace {

using json = nlohmann::json;
using Bytes = std::vector<uint8_t>;

struct X509Free { void operator()(X509* p) const { X509_free(p); } };
struct PkeyFree { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct StoreFree { void operator()(X509_STORE* p) const { X509_STORE_free(p); } };
struct StoreCtxFree { void operator()(X509_STORE_CTX* p) const { X509_STORE_CTX_free(p); } };
struct StackFree { void operator()(STACK_OF(X509)* p) const { sk_X509_pop_free(p, X509_free); } };
struct MdCtxFree { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
struct SctListFree { void operator()(STACK_OF(SCT)* p) const { SCT_LIST_free(p); } };
struct ObjFree { void operator()(ASN1_OBJECT* p) const { ASN1_OBJECT_free(p); } };
struct Utf8Free { void operator()(ASN1_UTF8STRING* p) const { ASN1_UTF8STRING_free(p); } };
struct BioFree { void operator()(BIO* p) const { BIO_free(p); } };

using X509Ptr = std::unique_ptr<X509, X509Free>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;

constexpr std::string_view kBundleV03 = "application/vnd.dev.sigstore.bundle.v0.3+json";
constexpr std::string_view kBundleV02 = "application/vnd.dev.sigstore.bundle+json;version=0.2";
constexpr std::string_view kStatementType = "https://in-toto.io/Statement/v1";
constexpr std::string_view kSlsaV1 = "https://slsa.dev/provenance/v1";
constexpr std::string_view kInTotoPayloadType = "application/vnd.in-toto+json";

// Fulcio certificate extensions (sigstore/fulcio docs/oid-info.md). These are
// the v2 forms, each a DER UTF8String.
constexpr const char* kOidIssuerV2 = "1.3.6.1.4.1.57264.1.8";
constexpr const char* kOidBuildSignerUri = "1.3.6.1.4.1.57264.1.9";
constexpr const char* kOidRunnerEnvironment = "1.3.6.1.4.1.57264.1.11";
constexpr const char* kOidSourceRepositoryUri = "1.3.6.1.4.1.57264.1.12";
constexpr const char* kOidSourceRepositoryRef = "1.3.6.1.4.1.57264.1.14";
constexpr const char* kOidBuildConfigUri = "1.3.6.1.4.1.57264.1.18";

Bytes sha256(std::string_view data) {
    Bytes out(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), out.data());
    return out;
}

Bytes sha256(const Bytes& data) {
    return sha256(std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
}

std::string as_string(const Bytes& b) { return std::string(b.begin(), b.end()); }

/// Strict base64: the project decoder returns empty on error, so an empty
/// result for non-empty input is a failure.
std::optional<Bytes> b64(std::string_view text) {
    if (text.empty()) return std::nullopt;
    auto out = crypto::from_base64(text);
    if (out.empty()) return std::nullopt;
    return out;
}

/// proto3 JSON writes int64 as a string; accept both forms.
std::optional<int64_t> json_int64(const json& j) {
    if (j.is_number_integer()) return j.get<int64_t>();
    if (!j.is_string()) return std::nullopt;
    const auto& s = j.get_ref<const std::string&>();
    if (s.empty() || s.size() > 19) return std::nullopt;
    int64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        v = v * 10 + (c - '0');
    }
    return v;
}

const json* field(const json& j, std::string_view key) {
    if (!j.is_object()) return nullptr;
    const auto it = j.find(std::string(key));
    return it == j.end() ? nullptr : &*it;
}

std::optional<std::string> str_field(const json& j, std::string_view key) {
    const auto* f = field(j, key);
    if (!f || !f->is_string()) return std::nullopt;
    return f->get<std::string>();
}

X509Ptr parse_cert(const Bytes& der) {
    const unsigned char* p = der.data();
    X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
    if (cert && p != der.data() + der.size()) return nullptr;  // trailing bytes
    return cert;
}

PkeyPtr parse_spki(const Bytes& der) {
    const unsigned char* p = der.data();
    PkeyPtr key(d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size())));
    if (key && p != der.data() + der.size()) return nullptr;
    return key;
}

/// ECDSA (DER signature) or Ed25519 over `message`. The digest follows the
/// key: SHA-256 for P-256, SHA-384 for P-384, none for Ed25519.
bool verify_signature(EVP_PKEY* key, std::string_view message, const Bytes& signature) {
    if (!key || signature.empty()) return false;
    std::unique_ptr<EVP_MD_CTX, MdCtxFree> ctx(EVP_MD_CTX_new());
    if (!ctx) return false;
    const EVP_MD* md = nullptr;
    const int type = EVP_PKEY_get_base_id(key);
    if (type == EVP_PKEY_EC) {
        md = EVP_PKEY_get_bits(key) > 256 ? EVP_sha384() : EVP_sha256();
    } else if (type != EVP_PKEY_ED25519) {
        return false;
    }
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, key) != 1) return false;
    return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                            reinterpret_cast<const unsigned char*>(message.data()),
                            message.size()) == 1;
}

const SigstoreKey* find_key(const std::vector<SigstoreKey>& keys, const Bytes& key_id,
                            int64_t at) {
    for (const auto& k : keys) {
        if (k.key_id == key_id && at >= k.valid_from && at <= k.valid_until) return &k;
    }
    return nullptr;
}

std::optional<std::pair<int64_t, int64_t>> parse_valid_for(const json& j) {
    const auto* vf = field(j, "validFor");
    if (!vf) return std::nullopt;
    const auto start = str_field(*vf, "start");
    if (!start) return std::nullopt;
    const auto from = parse_rfc3339_utc(*start);
    if (!from) return std::nullopt;
    int64_t until = INT64_MAX;
    if (const auto end = str_field(*vf, "end")) {
        const auto parsed = parse_rfc3339_utc(*end);
        if (!parsed) return std::nullopt;
        until = *parsed;
    }
    return std::make_pair(*from, until);
}

std::optional<SigstoreKey> parse_log_key(const json& j) {
    SigstoreKey key;
    const auto* pk = field(j, "publicKey");
    const auto* log_id = field(j, "logId");
    if (!pk || !log_id) return std::nullopt;
    const auto raw = str_field(*pk, "rawBytes");
    const auto id = str_field(*log_id, "keyId");
    if (!raw || !id) return std::nullopt;
    const auto spki = b64(*raw);
    const auto key_id = b64(*id);
    const auto window = parse_valid_for(*pk);
    if (!spki || !key_id || !window || !parse_spki(*spki)) return std::nullopt;
    key.spki_der = *spki;
    key.key_id = *key_id;
    key.base_url = str_field(j, "baseUrl").value_or("");
    key.valid_from = window->first;
    key.valid_until = window->second;
    return key;
}

/// The value of a Fulcio v2 extension: a DER UTF8String inside the extension.
std::optional<std::string> fulcio_extension(X509* cert, const char* oid) {
    std::unique_ptr<ASN1_OBJECT, ObjFree> obj(OBJ_txt2obj(oid, 1));
    if (!obj) return std::nullopt;
    const int index = X509_get_ext_by_OBJ(cert, obj.get(), -1);
    if (index < 0) return std::nullopt;
    // Exactly one occurrence: a second copy could disagree with the first.
    if (X509_get_ext_by_OBJ(cert, obj.get(), index) >= 0) return std::nullopt;
    X509_EXTENSION* ext = X509_get_ext(cert, index);
    const ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    const unsigned char* p = ASN1_STRING_get0_data(data);
    const long length = ASN1_STRING_length(data);
    std::unique_ptr<ASN1_UTF8STRING, Utf8Free> value(d2i_ASN1_UTF8STRING(nullptr, &p, length));
    if (!value || p != ASN1_STRING_get0_data(data) + length) return std::nullopt;
    return std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(value.get())),
                       static_cast<std::size_t>(ASN1_STRING_length(value.get())));
}

/// The single URI subject alternative name, or nullopt.
std::optional<std::string> san_uri(X509* cert) {
    auto* names = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (!names) return std::nullopt;
    std::optional<std::string> out;
    int uris = 0;
    for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
        if (name->type != GEN_URI) continue;
        ++uris;
        const ASN1_IA5STRING* uri = name->d.uniformResourceIdentifier;
        out = std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)),
                          static_cast<std::size_t>(ASN1_STRING_length(uri)));
    }
    GENERAL_NAMES_free(names);
    if (uris != 1) return std::nullopt;
    return out;
}

Bytes spki_of(X509* cert) {
    unsigned char* der = nullptr;
    const int len = i2d_PUBKEY(X509_get0_pubkey(cert), &der);
    if (len <= 0) return {};
    Bytes out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// RFC 6962 section 3.2 signature input for a precertificate SCT.
bool verify_embedded_scts(X509* leaf, X509* issuer, const SigstoreTrustedRoot& root,
                          std::string& error) {
    std::unique_ptr<STACK_OF(SCT), SctListFree> scts(static_cast<STACK_OF(SCT)*>(
        X509_get_ext_d2i(leaf, NID_ct_precert_scts, nullptr, nullptr)));
    if (!scts || sk_SCT_num(scts.get()) == 0) {
        error = "the signing certificate has no embedded SCT";
        return false;
    }
    // The precertificate TBS is the final TBS without the SCT list.
    X509Ptr precert(X509_dup(leaf));
    if (!precert) {
        error = "cannot copy the signing certificate";
        return false;
    }
    const int sct_index = X509_get_ext_by_NID(precert.get(), NID_ct_precert_scts, -1);
    X509_EXTENSION* removed = X509_delete_ext(precert.get(), sct_index);
    X509_EXTENSION_free(removed);
    unsigned char* tbs = nullptr;
    const int tbs_len = i2d_re_X509_tbs(precert.get(), &tbs);
    if (tbs_len <= 0) {
        error = "cannot encode the precertificate";
        return false;
    }
    const Bytes tbs_der(tbs, tbs + tbs_len);
    OPENSSL_free(tbs);
    const Bytes issuer_key_hash = sha256(spki_of(issuer));

    for (int i = 0; i < sk_SCT_num(scts.get()); ++i) {
        SCT* sct = sk_SCT_value(scts.get(), i);
        if (SCT_get_version(sct) != SCT_VERSION_V1) continue;
        unsigned char* log_id = nullptr;
        const std::size_t log_id_len = SCT_get0_log_id(sct, &log_id);
        const Bytes id(log_id, log_id + log_id_len);
        const uint64_t timestamp_ms = SCT_get_timestamp(sct);
        const auto* log = find_key(root.ctlogs, id, static_cast<int64_t>(timestamp_ms / 1000));
        if (!log) continue;
        unsigned char* ext = nullptr;
        const std::size_t ext_len = SCT_get0_extensions(sct, &ext);
        unsigned char* sig = nullptr;
        const std::size_t sig_len = SCT_get0_signature(sct, &sig);
        if (tbs_der.size() >= (1u << 24) || ext_len >= (1u << 16)) continue;

        std::string input;
        input.push_back(0);  // sct_version v1
        input.push_back(0);  // signature_type certificate_timestamp
        for (int shift = 56; shift >= 0; shift -= 8) {
            input.push_back(static_cast<char>((timestamp_ms >> shift) & 0xff));
        }
        input.push_back(0);
        input.push_back(1);  // entry_type precert_entry
        input.append(issuer_key_hash.begin(), issuer_key_hash.end());
        input.push_back(static_cast<char>((tbs_der.size() >> 16) & 0xff));
        input.push_back(static_cast<char>((tbs_der.size() >> 8) & 0xff));
        input.push_back(static_cast<char>(tbs_der.size() & 0xff));
        input.append(tbs_der.begin(), tbs_der.end());
        input.push_back(static_cast<char>((ext_len >> 8) & 0xff));
        input.push_back(static_cast<char>(ext_len & 0xff));
        if (ext_len > 0) input.append(reinterpret_cast<const char*>(ext), ext_len);

        const auto key = parse_spki(log->spki_der);
        if (verify_signature(key.get(), input, Bytes(sig, sig + sig_len))) return true;
    }
    error = "no embedded SCT verifies under a pinned CT log key";
    return false;
}

bool verify_chain(X509* leaf, const SigstoreTrustedRoot& root, int64_t at, X509Ptr& issuer_out,
                  std::string& error) {
    for (const auto& ca : root.certificate_authorities) {
        if (at < ca.valid_from || at > ca.valid_until || ca.chain.empty()) continue;
        std::unique_ptr<X509_STORE, StoreFree> store(X509_STORE_new());
        std::unique_ptr<STACK_OF(X509), StackFree> intermediates(sk_X509_new_null());
        if (!store || !intermediates) break;
        X509Ptr anchor = parse_cert(ca.chain.back());
        if (!anchor || X509_STORE_add_cert(store.get(), anchor.get()) != 1) continue;
        for (std::size_t i = 0; i + 1 < ca.chain.size(); ++i) {
            X509* cert = parse_cert(ca.chain[i]).release();
            if (!cert || sk_X509_push(intermediates.get(), cert) <= 0) {
                X509_free(cert);
                continue;
            }
        }
        std::unique_ptr<X509_STORE_CTX, StoreCtxFree> ctx(X509_STORE_CTX_new());
        if (!ctx || X509_STORE_CTX_init(ctx.get(), store.get(), leaf, intermediates.get()) != 1) {
            continue;
        }
        X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx.get());
        X509_VERIFY_PARAM_set_time(param, static_cast<time_t>(at));
        X509_VERIFY_PARAM_set_depth(param, static_cast<int>(ca.chain.size()) + 1);
        if (X509_verify_cert(ctx.get()) != 1) continue;
        STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(ctx.get());
        if (!chain || sk_X509_num(chain) < 2) continue;
        X509* issuer = sk_X509_value(chain, 1);
        X509_up_ref(issuer);
        issuer_out.reset(issuer);
        return true;
    }
    error = "the signing certificate does not chain to a pinned Fulcio CA valid at the log time";
    return false;
}

/// RFC 9162 section 2.1.3.2.
bool verify_inclusion(uint64_t index, uint64_t size, const Bytes& leaf_hash,
                      const std::vector<Bytes>& path, const Bytes& root_hash) {
    if (index >= size) return false;
    uint64_t fn = index;
    uint64_t sn = size - 1;
    Bytes r = leaf_hash;
    for (const auto& p : path) {
        if (sn == 0 || p.size() != SHA256_DIGEST_LENGTH) return false;
        std::string buf(1, '\x01');
        if ((fn & 1) || fn == sn) {
            buf.append(p.begin(), p.end());
            buf.append(r.begin(), r.end());
            r = sha256(buf);
            if (!(fn & 1)) {
                while (!(fn & 1) && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            buf.append(r.begin(), r.end());
            buf.append(p.begin(), p.end());
            r = sha256(buf);
        }
        fn >>= 1;
        sn >>= 1;
    }
    return sn == 0 && r == root_hash;
}

/// A signed note (checkpoint): body lines, a blank line, signature lines of
/// the form "— <name> <base64(4-byte key hint || signature)>".
bool verify_checkpoint(std::string_view envelope, const SigstoreKey& log, uint64_t tree_size,
                       const Bytes& root_hash, std::string& error) {
    const auto split = envelope.find("\n\n");
    if (split == std::string_view::npos) {
        error = "the checkpoint has no signature block";
        return false;
    }
    const std::string_view body = envelope.substr(0, split + 1);
    // Body: origin, tree size, base64 root hash (then optional extensions).
    std::vector<std::string_view> lines;
    for (std::size_t start = 0; start < body.size();) {
        const auto end = body.find('\n', start);
        lines.push_back(body.substr(start, end - start));
        start = end + 1;
    }
    if (lines.size() < 3) {
        error = "the checkpoint body is incomplete";
        return false;
    }
    const auto size_text = std::string(lines[1]);
    if (size_text.empty() || size_text.size() > 19 ||
        !std::all_of(size_text.begin(), size_text.end(),
                     [](char c) { return c >= '0' && c <= '9'; }) ||
        std::stoull(size_text) != tree_size) {
        error = "the checkpoint tree size does not match the inclusion proof";
        return false;
    }
    const auto checkpoint_root = b64(lines[2]);
    if (!checkpoint_root || *checkpoint_root != root_hash) {
        error = "the checkpoint root hash does not match the inclusion proof";
        return false;
    }
    const auto key = parse_spki(log.spki_der);
    static constexpr std::string_view kDash = "\xE2\x80\x94 ";
    std::string_view rest = envelope.substr(split + 2);
    while (!rest.empty()) {
        const auto end = rest.find('\n');
        const std::string_view line = rest.substr(0, end);
        rest = end == std::string_view::npos ? std::string_view{} : rest.substr(end + 1);
        if (line.substr(0, kDash.size()) != kDash) continue;
        const auto space = line.rfind(' ');
        const auto sig = b64(line.substr(space + 1));
        if (!sig || sig->size() <= 4 || log.key_id.size() < 4 ||
            !std::equal(sig->begin(), sig->begin() + 4, log.key_id.begin())) {
            continue;
        }
        if (verify_signature(key.get(), body, Bytes(sig->begin() + 4, sig->end()))) return true;
    }
    error = "the checkpoint has no valid signature from the log key";
    return false;
}

bool check_identity(X509* leaf, const json& statement, const ProvenancePolicy& policy,
                    std::string& error) {
    const std::string repo_uri = "https://github.com/" + policy.repository;
    const std::string workflow_uri = repo_uri + "/" + policy.workflow_path + "@" + policy.ref;
    const struct {
        const char* oid;
        std::string expected;
        const char* what;
    } required[] = {
        {kOidIssuerV2, policy.oidc_issuer, "OIDC issuer"},
        {kOidSourceRepositoryUri, repo_uri, "source repository"},
        {kOidSourceRepositoryRef, policy.ref, "source ref"},
        {kOidBuildConfigUri, workflow_uri, "workflow"},
        {kOidBuildSignerUri, workflow_uri, "signing workflow"},
        {kOidRunnerEnvironment, "github-hosted", "runner environment"},
    };
    for (const auto& r : required) {
        const auto value = fulcio_extension(leaf, r.oid);
        if (!value || *value != r.expected) {
            error = std::string("provenance ") + r.what + " is " +
                    (value ? "\"" + *value + "\"" : std::string("absent")) + ", expected \"" +
                    r.expected + "\"";
            return false;
        }
    }
    const auto san = san_uri(leaf);
    if (!san || *san != workflow_uri) {
        error = "the certificate identity is not the expected workflow";
        return false;
    }
    // The predicate must agree with the certificate.
    const json* workflow = nullptr;
    if (const auto* pred = field(statement, "predicate"))
        if (const auto* def = field(*pred, "buildDefinition"))
            if (const auto* ext = field(*def, "externalParameters"))
                workflow = field(*ext, "workflow");
    if (!workflow || str_field(*workflow, "repository") != repo_uri ||
        str_field(*workflow, "path") != policy.workflow_path ||
        str_field(*workflow, "ref") != policy.ref) {
        error = "the provenance predicate does not name the expected workflow";
        return false;
    }
    return true;
}

}  // namespace

std::optional<int64_t> parse_rfc3339_utc(std::string_view text) {
    // YYYY-MM-DDTHH:MM:SS[.fraction]Z
    if (text.size() < 20 || text.back() != 'Z') return std::nullopt;
    auto num = [&](std::size_t pos, std::size_t len) -> std::optional<int> {
        int v = 0;
        for (std::size_t i = pos; i < pos + len; ++i) {
            if (text[i] < '0' || text[i] > '9') return std::nullopt;
            v = v * 10 + (text[i] - '0');
        }
        return v;
    };
    if (text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' ||
        text[16] != ':') {
        return std::nullopt;
    }
    const auto y = num(0, 4), mo = num(5, 2), d = num(8, 2), h = num(11, 2), mi = num(14, 2),
               s = num(17, 2);
    if (!y || !mo || !d || !h || !mi || !s) return std::nullopt;
    if (text.size() > 20) {
        if (text[19] != '.' || text.size() < 22) return std::nullopt;
        if (!num(20, text.size() - 21)) return std::nullopt;
    }
    if (*mo < 1 || *mo > 12 || *d < 1 || *d > 31 || *h > 23 || *mi > 59 || *s > 60) {
        return std::nullopt;
    }
    // Days from civil (Howard Hinnant), independent of the local time zone.
    const int yy = *y - (*mo <= 2 ? 1 : 0);
    const int era = (yy >= 0 ? yy : yy - 399) / 400;
    const int yoe = yy - era * 400;
    const int doy = (153 * (*mo + (*mo > 2 ? -3 : 9)) + 2) / 5 + *d - 1;
    const int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const int64_t days = static_cast<int64_t>(era) * 146097 + doe - 719468;
    return days * 86400 + *h * 3600 + *mi * 60 + *s;
}

std::optional<SigstoreTrustedRoot> parse_sigstore_trusted_root(std::string_view json_text,
                                                               std::string& error) {
    const json doc = json::parse(json_text, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) {
        error = "the trusted root is not JSON";
        return std::nullopt;
    }
    const auto media = str_field(doc, "mediaType").value_or("");
    if (media.rfind("application/vnd.dev.sigstore.trustedroot+json", 0) != 0) {
        error = "the trusted root has an unknown media type";
        return std::nullopt;
    }
    SigstoreTrustedRoot root;
    for (const char* name : {"tlogs", "ctlogs"}) {
        const auto* list = field(doc, name);
        if (!list || !list->is_array()) continue;
        for (const auto& entry : *list) {
            auto key = parse_log_key(entry);
            if (!key) continue;  // an algorithm or form this verifier does not use
            (std::string_view(name) == "tlogs" ? root.tlogs : root.ctlogs)
                .push_back(std::move(*key));
        }
    }
    if (const auto* cas = field(doc, "certificateAuthorities"); cas && cas->is_array()) {
        for (const auto& entry : *cas) {
            SigstoreCa ca;
            const auto window = parse_valid_for(entry);
            const auto* chain = field(entry, "certChain");
            const auto* certs = chain ? field(*chain, "certificates") : nullptr;
            if (!window || !certs || !certs->is_array() || certs->empty()) continue;
            bool ok = true;
            for (const auto& cert : *certs) {
                const auto raw = b64(str_field(cert, "rawBytes").value_or(""));
                if (!raw || !parse_cert(*raw)) {
                    ok = false;
                    break;
                }
                ca.chain.push_back(*raw);
            }
            if (!ok) continue;
            ca.valid_from = window->first;
            ca.valid_until = window->second;
            root.certificate_authorities.push_back(std::move(ca));
        }
    }
    if (root.tlogs.empty() || root.ctlogs.empty() || root.certificate_authorities.empty()) {
        error = "the trusted root has no usable transparency log, CT log, or CA";
        return std::nullopt;
    }
    return root;
}

bool verify_provenance_bundle(const SigstoreTrustedRoot& root, std::string_view bundle_json,
                              std::string_view subject_sha256_hex,
                              const ProvenancePolicy& policy, std::string& error) {
    error.clear();
    if (bundle_json.size() > kMaxProvenanceBundleBytes) {
        error = "the provenance bundle is too large";
        return false;
    }
    if (subject_sha256_hex.size() != 64 ||
        !std::all_of(subject_sha256_hex.begin(), subject_sha256_hex.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        })) {
        error = "the artifact digest is not 64 lowercase hex";
        return false;
    }
    const json bundle = json::parse(bundle_json, nullptr, false);
    if (bundle.is_discarded() || !bundle.is_object()) {
        error = "the provenance bundle is not JSON";
        return false;
    }
    const auto media = str_field(bundle, "mediaType").value_or("");
    if (media != kBundleV03 && media != kBundleV02) {
        error = "the provenance bundle has an unsupported media type: " + media;
        return false;
    }
    const auto* material = field(bundle, "verificationMaterial");
    if (!material) {
        error = "the provenance bundle has no verification material";
        return false;
    }

    // 1. Leaf certificate.
    std::optional<Bytes> leaf_der;
    if (const auto* cert = field(*material, "certificate")) {
        leaf_der = b64(str_field(*cert, "rawBytes").value_or(""));
    } else if (const auto* chain = field(*material, "x509CertificateChain")) {
        const auto* certs = field(*chain, "certificates");
        if (certs && certs->is_array() && !certs->empty()) {
            leaf_der = b64(str_field((*certs)[0], "rawBytes").value_or(""));
        }
    }
    X509Ptr leaf = leaf_der ? parse_cert(*leaf_der) : nullptr;
    if (!leaf) {
        error = "the provenance bundle has no valid signing certificate";
        return false;
    }

    // 2. Transparency log entry.
    const auto* entries = field(*material, "tlogEntries");
    if (!entries || !entries->is_array() || entries->size() != 1) {
        error = "the provenance bundle must carry exactly one transparency log entry";
        return false;
    }
    const json& entry = (*entries)[0];
    const auto* kind = field(entry, "kindVersion");
    if (!kind || str_field(*kind, "kind") != "dsse" || str_field(*kind, "version") != "0.0.1") {
        error = "the transparency log entry is not of kind dsse 0.0.1";
        return false;
    }
    const auto log_index = field(entry, "logIndex") ? json_int64(entry["logIndex"]) : std::nullopt;
    const auto integrated =
        field(entry, "integratedTime") ? json_int64(entry["integratedTime"]) : std::nullopt;
    const auto body_b64 = str_field(entry, "canonicalizedBody");
    const auto* log_id_obj = field(entry, "logId");
    const auto log_id = log_id_obj ? b64(str_field(*log_id_obj, "keyId").value_or(""))
                                   : std::nullopt;
    if (!log_index || !integrated || !body_b64 || !log_id) {
        error = "the transparency log entry is incomplete";
        return false;
    }
    const auto* log = find_key(root.tlogs, *log_id, *integrated);
    if (!log) {
        error = "the transparency log entry is from a log that is not pinned for that time";
        return false;
    }
    const auto log_key = parse_spki(log->spki_der);
    const auto* promise = field(entry, "inclusionPromise");
    const auto set = promise ? b64(str_field(*promise, "signedEntryTimestamp").value_or(""))
                             : std::nullopt;
    if (!set) {
        error = "the transparency log entry has no inclusion promise";
        return false;
    }
    json set_payload = {{"body", *body_b64},
                        {"integratedTime", *integrated},
                        {"logID", crypto::to_hex(*log_id)},
                        {"logIndex", *log_index}};
    if (!verify_signature(log_key.get(), set_payload.dump(), *set)) {
        error = "the signed entry timestamp does not verify";
        return false;
    }
    const auto body = b64(*body_b64);
    if (!body) {
        error = "the transparency log body is not base64";
        return false;
    }
    const auto* proof = field(entry, "inclusionProof");
    if (!proof) {
        error = "the transparency log entry has no inclusion proof";
        return false;
    }
    {
        const auto proof_index = field(*proof, "logIndex") ? json_int64((*proof)["logIndex"])
                                                           : std::nullopt;
        const auto tree_size = field(*proof, "treeSize") ? json_int64((*proof)["treeSize"])
                                                         : std::nullopt;
        const auto root_hash = b64(str_field(*proof, "rootHash").value_or(""));
        const auto* hashes = field(*proof, "hashes");
        const auto* checkpoint = field(*proof, "checkpoint");
        if (!proof_index || !tree_size || !root_hash || !hashes || !hashes->is_array() ||
            hashes->size() > 64 || !checkpoint || *proof_index < 0 || *tree_size <= 0) {
            error = "the inclusion proof is incomplete";
            return false;
        }
        std::vector<Bytes> path;
        for (const auto& h : *hashes) {
            const auto decoded = h.is_string() ? b64(h.get<std::string>()) : std::nullopt;
            if (!decoded) {
                error = "the inclusion proof has an invalid hash";
                return false;
            }
            path.push_back(*decoded);
        }
        std::string leaf_input(1, '\0');
        leaf_input.append(body->begin(), body->end());
        if (!verify_inclusion(static_cast<uint64_t>(*proof_index),
                              static_cast<uint64_t>(*tree_size), sha256(leaf_input), path,
                              *root_hash)) {
            error = "the inclusion proof does not reach the root hash";
            return false;
        }
        if (!verify_checkpoint(str_field(*checkpoint, "envelope").value_or(""), *log,
                               static_cast<uint64_t>(*tree_size), *root_hash, error)) {
            return false;
        }
    }

    // 3. The entry body binds this envelope.
    const auto* envelope = field(bundle, "dsseEnvelope");
    if (!envelope) {
        error = "the provenance bundle has no DSSE envelope";
        return false;
    }
    const auto payload_type = str_field(*envelope, "payloadType");
    const auto payload = b64(str_field(*envelope, "payload").value_or(""));
    const auto* sigs = field(*envelope, "signatures");
    if (!payload_type || *payload_type != kInTotoPayloadType || !payload || !sigs ||
        !sigs->is_array() || sigs->size() != 1) {
        error = "the DSSE envelope must hold one in-toto payload and one signature";
        return false;
    }
    const auto signature = b64(str_field((*sigs)[0], "sig").value_or(""));
    if (!signature) {
        error = "the DSSE signature is not base64";
        return false;
    }
    {
        const json logged = json::parse(as_string(*body), nullptr, false);
        const auto* spec = field(logged, "spec");
        const auto* payload_hash = spec ? field(*spec, "payloadHash") : nullptr;
        const auto* logged_sigs = spec ? field(*spec, "signatures") : nullptr;
        if (logged.is_discarded() || str_field(logged, "kind") != "dsse" ||
            str_field(logged, "apiVersion") != "0.0.1" || !payload_hash ||
            str_field(*payload_hash, "algorithm") != "sha256" ||
            str_field(*payload_hash, "value") != crypto::to_hex(sha256(*payload)) ||
            !logged_sigs || !logged_sigs->is_array() || logged_sigs->size() != 1) {
            error = "the transparency log entry does not record this payload";
            return false;
        }
        const auto logged_sig = b64(str_field((*logged_sigs)[0], "signature").value_or(""));
        const auto verifier_pem = b64(str_field((*logged_sigs)[0], "verifier").value_or(""));
        if (!logged_sig || *logged_sig != *signature || !verifier_pem) {
            error = "the transparency log entry does not record this signature";
            return false;
        }
        std::unique_ptr<BIO, BioFree> bio(
            BIO_new_mem_buf(verifier_pem->data(), static_cast<int>(verifier_pem->size())));
        X509Ptr logged_cert(bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)
                                : nullptr);
        if (!logged_cert || X509_cmp(logged_cert.get(), leaf.get()) != 0) {
            error = "the transparency log entry does not record this certificate";
            return false;
        }
    }

    // 4. Certificate chain, usage, and SCT at the integrated time.
    X509Ptr issuer;
    if (!verify_chain(leaf.get(), root, *integrated, issuer, error)) return false;
    if ((X509_get_extension_flags(leaf.get()) & EXFLAG_XKUSAGE) == 0 ||
        (X509_get_extended_key_usage(leaf.get()) & XKU_CODE_SIGN) == 0) {
        error = "the signing certificate is not issued for code signing";
        return false;
    }
    if (!verify_embedded_scts(leaf.get(), issuer.get(), root, error)) return false;

    // 5. DSSE signature (pre-authentication encoding, DSSE v1).
    {
        std::string pae = "DSSEv1 " + std::to_string(payload_type->size()) + " " +
                          *payload_type + " " + std::to_string(payload->size()) + " ";
        pae.append(payload->begin(), payload->end());
        if (!verify_signature(X509_get0_pubkey(leaf.get()), pae, *signature)) {
            error = "the DSSE signature does not verify under the signing certificate";
            return false;
        }
    }

    // 6. Statement and subject.
    const json statement = json::parse(as_string(*payload), nullptr, false);
    if (statement.is_discarded() || str_field(statement, "_type") != kStatementType ||
        str_field(statement, "predicateType") != kSlsaV1) {
        error = "the payload is not an in-toto v1 SLSA provenance v1 statement";
        return false;
    }
    bool subject_found = false;
    if (const auto* subjects = field(statement, "subject"); subjects && subjects->is_array()) {
        for (const auto& s : *subjects) {
            const auto* digest = field(s, "digest");
            if (digest && str_field(*digest, "sha256") == subject_sha256_hex) {
                subject_found = true;
                break;
            }
        }
    }
    if (!subject_found) {
        error = "the provenance does not name this artifact";
        return false;
    }

    // 7. Identity.
    return check_identity(leaf.get(), statement, policy, error);
}

}  // namespace nexus::updater
