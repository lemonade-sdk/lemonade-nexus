// The TPM seal path against a TPM simulator.
//
// SIMULATOR ONLY. These tests prove the TPM 2.0 command sequence, the PCR
// policy, the seal parent, and the daemon's request path. They are not hardware
// evidence: they say nothing about the SEV-SNP SVSM vTPM, whether it keeps its
// owner seed across reboots, or what its PCR 8 and 9 contain.
//
// They run only when NEXUS_TEST_TPM_TCTI names a simulator, for example:
//
//   swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
//       --tpmstate dir=/tmp/swtpm --flags not-need-init,startup-clear
//   NEXUS_TEST_TPM_TCTI=swtpm:host=127.0.0.1,port=2321 ctest -R TpmSealSimulator
//
// They extend PCR 8, so a "device:" TCTI is refused: never point them at a TPM
// whose PCRs matter.

#include <LemonadeNexus/Core/BootSet.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlob.hpp>
#include <LemonadeNexus/Security/Sealing/TpmSeal.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexusAttestd/AttestdClient.hpp>
#include <LemonadeNexusAttestd/AttestdCodec.hpp>
#include <LemonadeNexusAttestd/AttestdFraming.hpp>
#include <LemonadeNexusAttestd/AttestdService.hpp>
#include <LemonadeNexusAttestd/AttestdSocket.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <array>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef _WIN32
#  include <grp.h>
#  include <unistd.h>
#endif

#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)
#  include <tss2/tss2_esys.h>
#  include <tss2/tss2_mu.h>
#  include <tss2/tss2_tctildr.h>
#  define NEXUS_TPM_SIMULATOR_TESTS 1
#endif

namespace crypto = nexus::crypto;
namespace attestd = nexus::attestd;
using namespace nexus::security;
using json = nlohmann::json;

namespace {

const std::vector<uint8_t> kSecret = [] {
    std::vector<uint8_t> s(crypto::kEd25519PrivateKeySize);
    for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(0xA0 + i);
    return s;
}();

std::vector<std::pair<attestd::FrameKind, std::string>> split_frames(const std::string& wire) {
    std::vector<std::pair<attestd::FrameKind, std::string>> frames;
    std::size_t at = 0;
    while (at + attestd::kFrameHeaderBytes <= wire.size()) {
        const auto* p = reinterpret_cast<const uint8_t*>(wire.data() + at);
        const std::size_t len = (std::size_t{p[0]} << 24) | (std::size_t{p[1]} << 16) |
                                (std::size_t{p[2]} << 8) | std::size_t{p[3]};
        frames.emplace_back(static_cast<attestd::FrameKind>(p[4]),
                            wire.substr(at + attestd::kFrameHeaderBytes, len));
        at += attestd::kFrameHeaderBytes + len;
    }
    return frames;
}

#ifdef NEXUS_TPM_SIMULATOR_TESTS

/// Direct ESYS access for what the production code deliberately cannot do:
/// extend a PCR, and run a trial policy session.
struct Esys {
    TSS2_TCTI_CONTEXT* tcti{nullptr};
    ESYS_CONTEXT* ctx{nullptr};
    explicit Esys(const std::string& config) {
        if (Tss2_TctiLdr_Initialize(config.c_str(), &tcti) != TSS2_RC_SUCCESS) return;
        if (Esys_Initialize(&ctx, tcti, nullptr) != TSS2_RC_SUCCESS) ctx = nullptr;
        if (ctx) (void)Esys_Startup(ctx, TPM2_SU_CLEAR);
    }
    ~Esys() {
        if (ctx) Esys_Finalize(&ctx);
        if (tcti) Tss2_TctiLdr_Finalize(&tcti);
    }
};

TPML_PCR_SELECTION selection_8_9() {
    TPML_PCR_SELECTION s{};
    s.count = 1;
    s.pcrSelections[0].hash = TPM2_ALG_SHA256;
    s.pcrSelections[0].sizeofSelect = 3;
    s.pcrSelections[0].pcrSelect[1] = 0x03;
    return s;
}

#endif

struct TpmSealSimulator : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
#ifndef NEXUS_TPM_SIMULATOR_TESTS
        GTEST_SKIP() << "needs Linux and the TPM ESYS stack";
#else
        const char* env = std::getenv("NEXUS_TEST_TPM_TCTI");
        if (!env || !*env) {
            GTEST_SKIP() << "NEXUS_TEST_TPM_TCTI is not set; these tests need a TPM simulator "
                            "and are not hardware evidence";
        }
        tcti = env;
        if (tcti.rfind("device:", 0) == 0) {
            GTEST_SKIP() << "refusing a device TCTI: these tests extend PCR 8";
        }
        esys.emplace(tcti);
        ASSERT_NE(esys->ctx, nullptr) << "no simulator answers at " << tcti;
#endif
    }

#ifdef NEXUS_TPM_SIMULATOR_TESTS
    BootPcrValues read_pcrs() {
        TPML_PCR_SELECTION sel = selection_8_9();
        UINT32 counter = 0;
        TPML_PCR_SELECTION* out_sel = nullptr;
        TPML_DIGEST* values = nullptr;
        BootPcrValues out{};
        EXPECT_EQ(Esys_PCR_Read(esys->ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &sel,
                                &counter, &out_sel, &values),
                  TSS2_RC_SUCCESS);
        if (values && values->count == 2) {
            std::memcpy(out[0].data(), values->digests[0].buffer, 32);
            std::memcpy(out[1].data(), values->digests[1].buffer, 32);
        }
        Esys_Free(out_sel);
        Esys_Free(values);
        return out;
    }

    /// Extend PCR 8 with `data` (one SHA-256 digest); returns the new value.
    PcrValue extend_pcr8(uint8_t fill) {
        const auto before = read_pcrs()[0];
        TPML_DIGEST_VALUES digests{};
        digests.count = 1;
        digests.digests[0].hashAlg = TPM2_ALG_SHA256;
        std::memset(digests.digests[0].digest.sha256, fill, 32);
        EXPECT_EQ(Esys_PCR_Extend(esys->ctx, ESYS_TR_PCR8, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                  ESYS_TR_NONE, &digests),
                  TSS2_RC_SUCCESS);
        // new = SHA-256(old || data), the extend rule the release pins rely on.
        std::array<uint8_t, 64> input{};
        std::memcpy(input.data(), before.data(), 32);
        std::memset(input.data() + 32, fill, 32);
        PcrValue expected{};
        crypto_hash_sha256(expected.data(), input.data(), input.size());
        EXPECT_EQ(read_pcrs()[0], expected);
        return expected;
    }

    Digest trial_policy(const Digest& pcr_digest) {
        TPMT_SYM_DEF sym{};
        sym.algorithm = TPM2_ALG_NULL;
        ESYS_TR session = ESYS_TR_NONE;
        EXPECT_EQ(Esys_StartAuthSession(esys->ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                        ESYS_TR_NONE, ESYS_TR_NONE, nullptr, TPM2_SE_TRIAL, &sym,
                                        TPM2_ALG_SHA256, &session),
                  TSS2_RC_SUCCESS);
        TPM2B_DIGEST digest{};
        digest.size = 32;
        std::memcpy(digest.buffer, pcr_digest.data(), 32);
        const TPML_PCR_SELECTION sel = selection_8_9();
        EXPECT_EQ(Esys_PolicyPCR(esys->ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 &digest, &sel),
                  TSS2_RC_SUCCESS);
        TPM2B_DIGEST* policy = nullptr;
        EXPECT_EQ(Esys_PolicyGetDigest(esys->ctx, session, ESYS_TR_NONE, ESYS_TR_NONE,
                                       ESYS_TR_NONE, &policy),
                  TSS2_RC_SUCCESS);
        Digest out{};
        if (policy && policy->size == 32) std::memcpy(out.data(), policy->buffer, 32);
        Esys_Free(policy);
        (void)Esys_FlushContext(esys->ctx, session);
        return out;
    }

    std::optional<Esys> esys;
#endif
    std::string tcti;
};

/// Seal the way the server does: a TPM-sealed key, then local encryption.
std::optional<std::string> seal_blob(std::string_view domain, const std::vector<uint8_t>& secret,
                                     const std::optional<BootPcrValues>& target,
                                     TpmSealStatus& status, const std::string& tcti) {
    auto sealed = tpm_seal_key(target, status, tcti.c_str());
    if (!sealed) return std::nullopt;
    return make_sealed_blob(domain, sealed->object, sealed->key.span(), secret);
}

/// Unseal the way the server does: the TPM returns the key, decryption here.
std::vector<uint8_t> unseal_bytes(std::string_view domain, const std::string& text,
                                  TpmSealStatus& status, const std::string& tcti) {
    status = {};
    const auto blob = decode_sealed_blob(text);
    if (!blob || blob->domain != domain) {
        status.error = TpmSealError::Corrupt;
        return {};
    }
    const auto key = tpm_unseal_key({blob->pcr_digest, blob->tpm_public, blob->tpm_private},
                                    status, tcti.c_str());
    if (!key) return {};
    const auto plaintext = open_sealed_blob(*blob, key->span());
    if (!plaintext) {
        status.error = TpmSealError::Corrupt;
        return {};
    }
    return {plaintext->span().begin(), plaintext->span().end()};
}

}  // namespace

#ifdef NEXUS_TPM_SIMULATOR_TESTS

TEST_F(TpmSealSimulator, ThePolicyDigestMatchesATrialSession) {
    const auto current = read_pcrs();
    EXPECT_EQ(boot_pcr_policy_digest(boot_pcr_digest(current)),
              trial_policy(boot_pcr_digest(current)));
    BootPcrValues chosen{};
    chosen[0].fill(0x5C);
    chosen[1].fill(0xC5);
    EXPECT_EQ(boot_pcr_policy_digest(boot_pcr_digest(chosen)),
              trial_policy(boot_pcr_digest(chosen)));
}

TEST_F(TpmSealSimulator, SealThenUnsealRoundTrips) {
    TpmSealStatus status;
    const auto blob = seal_blob("gossip-identity", kSecret, std::nullopt, status, tcti);
    ASSERT_TRUE(blob) << tpm_seal_error_name(status.error) << ": " << status.detail;
    const auto parsed = decode_sealed_blob(*blob);
    ASSERT_TRUE(parsed);
    EXPECT_EQ(parsed->pcr_digest, boot_pcr_digest(read_pcrs()));
    EXPECT_EQ(unseal_bytes("gossip-identity", *blob, status, tcti), kSecret)
        << tpm_seal_error_name(status.error) << ": " << status.detail;
    EXPECT_EQ(status.error, TpmSealError::None);
}

TEST_F(TpmSealSimulator, EachSealIsAFreshKey) {
    TpmSealStatus status;
    const auto a = tpm_seal_key(std::nullopt, status, tcti.c_str());
    const auto b = tpm_seal_key(std::nullopt, status, tcti.c_str());
    ASSERT_TRUE(a && b) << status.detail;
    EXPECT_NE(std::vector<uint8_t>(a->key.span().begin(), a->key.span().end()),
              std::vector<uint8_t>(b->key.span().begin(), b->key.span().end()));
    EXPECT_NE(a->object.tpm_private, b->object.tpm_private);
}

TEST_F(TpmSealSimulator, ABlobDoesNotOpenForAnotherDomain) {
    TpmSealStatus status;
    const auto blob = seal_blob("gossip-identity", kSecret, std::nullopt, status, tcti);
    ASSERT_TRUE(blob) << status.detail;
    // Relabel the domain: the TPM still unseals the key, but the AEAD binds
    // the domain, so the secret does not open.
    auto j = json::parse(*blob);
    j["domain"] = "storage-share";
    EXPECT_TRUE(unseal_bytes("storage-share", j.dump(), status, tcti).empty());
    EXPECT_EQ(status.error, TpmSealError::Corrupt);
}

TEST_F(TpmSealSimulator, TamperingIsCorrupt) {
    TpmSealStatus status;
    const auto blob = seal_blob("gossip-identity", kSecret, std::nullopt, status, tcti);
    ASSERT_TRUE(blob) << status.detail;
    const json good = json::parse(*blob);

    auto flip = [&](const char* field) {
        auto j = good;
        auto bytes = crypto::from_base64(j[field].get<std::string>());
        bytes[bytes.size() / 2] ^= 0x01;
        j[field] = crypto::to_base64(bytes);
        return j.dump();
    };
    for (const char* field : {"ciphertext", "tpm_private", "tpm_public"}) {
        EXPECT_TRUE(unseal_bytes("gossip-identity", flip(field), status, tcti).empty()) << field;
        EXPECT_EQ(status.error, TpmSealError::Corrupt) << field << ": " << status.detail;
    }
    // Rebinding the digest field to other PCR values breaks the public area.
    auto j = good;
    BootPcrValues other{};
    other[0].fill(0x01);
    j["pcr_digest"] = crypto::to_hex(boot_pcr_digest(other));
    EXPECT_TRUE(unseal_bytes("gossip-identity", j.dump(), status, tcti).empty());
    EXPECT_EQ(status.error, TpmSealError::Corrupt) << status.detail;
}

TEST_F(TpmSealSimulator, ExtendingPcr8FailsClosed) {
    TpmSealStatus status;
    const auto blob = seal_blob("gossip-identity", kSecret, std::nullopt, status, tcti);
    ASSERT_TRUE(blob) << status.detail;
    extend_pcr8(0x42);
    EXPECT_TRUE(unseal_bytes("gossip-identity", *blob, status, tcti).empty());
    EXPECT_EQ(status.error, TpmSealError::PolicyMismatch) << status.detail;
}

TEST_F(TpmSealSimulator, SealingToAnApprovedFutureStateUnsealsOnlyThere) {
    // The release-upgrade path: seal to the PCR values the next boot chain will
    // have, before it boots.
    const auto now = read_pcrs();
    std::array<uint8_t, 64> input{};
    std::memcpy(input.data(), now[0].data(), 32);
    std::memset(input.data() + 32, 0x37, 32);
    BootPcrValues future = now;
    crypto_hash_sha256(future[0].data(), input.data(), input.size());

    TpmSealStatus status;
    const auto blob = seal_blob("gossip-identity", kSecret, future, status, tcti);
    ASSERT_TRUE(blob) << status.detail;
    EXPECT_TRUE(unseal_bytes("gossip-identity", *blob, status, tcti).empty());
    EXPECT_EQ(status.error, TpmSealError::PolicyMismatch);

    ASSERT_EQ(extend_pcr8(0x37), future[0]);
    EXPECT_EQ(unseal_bytes("gossip-identity", *blob, status, tcti), kSecret) << status.detail;
}

TEST_F(TpmSealSimulator, TheTpmItselfRefusesTheWrongPcrs) {
    // Bypass the PCR pre-check in tpm_unseal_key: load the sealed object under
    // the documented seal parent and run PolicyPCR + Unseal directly after PCR 8
    // moved. The TPM must answer TPM_RC_POLICY_FAIL.
    TpmSealStatus status;
    const auto sealed = tpm_seal_key(std::nullopt, status, tcti.c_str());
    ASSERT_TRUE(sealed) << status.detail;
    extend_pcr8(0x99);

    TPM2B_PUBLIC parent_in{};
    auto& area = parent_in.publicArea;
    area.type = TPM2_ALG_ECC;
    area.nameAlg = TPM2_ALG_SHA256;
    area.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                            TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
                            TPMA_OBJECT_NODA | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
    area.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
    area.parameters.eccDetail.symmetric.keyBits.aes = 128;
    area.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    area.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    area.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    area.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    area.unique.ecc.x.size = static_cast<UINT16>(kSealParentUnique.size());
    std::memcpy(area.unique.ecc.x.buffer, kSealParentUnique.data(), kSealParentUnique.size());
    TPM2B_SENSITIVE_CREATE sensitive{};
    TPM2B_DATA outside{};
    TPML_PCR_SELECTION creation_pcr{};
    ESYS_TR parent = ESYS_TR_NONE;
    TPM2B_PUBLIC* out_public = nullptr;
    TPM2B_CREATION_DATA* creation = nullptr;
    TPM2B_DIGEST* hash = nullptr;
    TPMT_TK_CREATION* ticket = nullptr;
    ASSERT_EQ(Esys_CreatePrimary(esys->ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                 ESYS_TR_NONE, &sensitive, &parent_in, &outside, &creation_pcr,
                                 &parent, &out_public, &creation, &hash, &ticket),
              TSS2_RC_SUCCESS);
    Esys_Free(out_public);
    Esys_Free(creation);
    Esys_Free(hash);
    Esys_Free(ticket);

    TPM2B_PUBLIC in_public{};
    TPM2B_PRIVATE in_private{};
    std::size_t offset = 0;
    ASSERT_EQ(Tss2_MU_TPM2B_PUBLIC_Unmarshal(sealed->object.tpm_public.data(),
                                            sealed->object.tpm_public.size(), &offset,
                                            &in_public),
              TSS2_RC_SUCCESS);
    offset = 0;
    ASSERT_EQ(Tss2_MU_TPM2B_PRIVATE_Unmarshal(sealed->object.tpm_private.data(),
                                             sealed->object.tpm_private.size(), &offset,
                                             &in_private),
              TSS2_RC_SUCCESS);
    ESYS_TR item = ESYS_TR_NONE;
    ASSERT_EQ(Esys_Load(esys->ctx, parent, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        &in_private, &in_public, &item),
              TSS2_RC_SUCCESS)
        << "the documented parent template must load the object";

    TPMT_SYM_DEF sym{};
    sym.algorithm = TPM2_ALG_NULL;
    ESYS_TR session = ESYS_TR_NONE;
    ASSERT_EQ(Esys_StartAuthSession(esys->ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, nullptr, TPM2_SE_POLICY, &sym,
                                    TPM2_ALG_SHA256, &session),
              TSS2_RC_SUCCESS);
    TPM2B_DIGEST empty{};
    const TPML_PCR_SELECTION sel = selection_8_9();
    ASSERT_EQ(Esys_PolicyPCR(esys->ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &empty,
                             &sel),
              TSS2_RC_SUCCESS);
    TPM2B_SENSITIVE_DATA* out = nullptr;
    const TSS2_RC rc = Esys_Unseal(esys->ctx, item, session, ESYS_TR_NONE, ESYS_TR_NONE, &out);
    EXPECT_NE(rc, TSS2_RC_SUCCESS);
    EXPECT_EQ(rc & 0xBFu, TPM2_RC_POLICY_FAIL & 0xBFu) << std::hex << rc;
    EXPECT_EQ(out, nullptr);
    Esys_Free(out);
    (void)Esys_FlushContext(esys->ctx, session);
    (void)Esys_FlushContext(esys->ctx, item);
    (void)Esys_FlushContext(esys->ctx, parent);
}

TEST_F(TpmSealSimulator, TheDaemonSealsAndUnsealsOverItsRequestPath) {
    attestd::AttestdConfig config;
    config.cache_dir = ::testing::TempDir();
    config.tcti = tcti;
    attestd::AttestdService service{config};
    auto run = [&service](std::string request) {
        request.pop_back();  // the newline the socket reader strips
        std::string wire;
        service.handle_request(request, [&wire](std::string_view frame) {
            wire.append(frame);
            return true;
        });
        const auto frames = split_frames(wire);
        EXPECT_EQ(frames.size(), 1u);
        return frames.empty() ? std::pair{attestd::FrameKind::Refusal, std::string{}}
                              : frames.front();
    };

    const auto sealed = run(attestd::encode_seal_request({"gossip-identity", std::nullopt}));
    ASSERT_EQ(sealed.first, attestd::FrameKind::Result) << sealed.second;
    attestd::ResponseAssembler seal_reader;
    EXPECT_FALSE(seal_reader.offer(sealed.first, sealed.second));
    const auto object = seal_reader.result_object();
    ASSERT_TRUE(object);
    const auto key = seal_reader.take_result_key();
    ASSERT_EQ(key.size(), kSealKeyBytes);

    const auto unseal_request = attestd::encode_unseal_request({"gossip-identity", *object});
    const auto opened = run(unseal_request);
    ASSERT_EQ(opened.first, attestd::FrameKind::Result) << opened.second;
    attestd::ResponseAssembler unseal_reader;
    EXPECT_FALSE(unseal_reader.offer(opened.first, opened.second));
    const auto unsealed = unseal_reader.take_result_key();
    EXPECT_EQ(std::vector<uint8_t>(unsealed.span().begin(), unsealed.span().end()),
              std::vector<uint8_t>(key.span().begin(), key.span().end()));

    extend_pcr8(0x24);
    const auto refused = run(unseal_request);
    ASSERT_EQ(refused.first, attestd::FrameKind::Refusal);
    EXPECT_EQ(json::parse(refused.second)["code"].get<uint16_t>(),
              static_cast<uint16_t>(attestd::Refusal::SealPolicyMismatch));
}

TEST_F(TpmSealSimulator, TheBootSetMigratesAndRestartsThroughTheRealSocket) {
    // The production composition end to end: BootSet -> attestd_seal_backend
    // -> unix socket -> AttestdService -> TPM (here: the simulator).
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("nexus_sim_bootset_" +
                                                      std::to_string(::getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir / "run");

    attestd::AttestdConfig config;
    config.cache_dir = dir / "cache";
    config.tcti = tcti;
    attestd::AttestdService service{config};
    attestd::AttestdSocketConfig socket_config;
    socket_config.path = dir / "run" / "attestd.sock";
    socket_config.group = ::getgrgid(::getgid())->gr_name;
    attestd::UnixRequestSocket socket;
    std::string why;
    ASSERT_TRUE(socket.open(socket_config, &why)) << why;
    std::atomic<bool> stop{false};
    std::thread server([&] {
        socket.serve([&service](std::string_view request, const attestd::ResponseWriter& write) {
            service.handle_request(request, write);
        }, stop);
    });

    {
        nexus::storage::FileStorageService storage{dir / "data"};
        storage.start();
        std::string boot = "sim-boot-1";
        nexus::core::BootSetConfig boot_set;
        boot_set.data_root = dir / "data";
        boot_set.backend = attestd::attestd_seal_backend({socket_config.path});
        boot_set.boot_id = [&boot] { return boot; };
        std::string error;

        const auto first = nexus::core::load_gossip_identity(storage, boot_set, error);
        ASSERT_TRUE(first) << error;
        EXPECT_EQ(first->protection, nexus::core::GossipIdentityProtection::SealedPending);

        boot = "sim-boot-2";
        const auto second = nexus::core::load_gossip_identity(storage, boot_set, error);
        ASSERT_TRUE(second) << error;
        EXPECT_EQ(second->protection, nexus::core::GossipIdentityProtection::Sealed);
        EXPECT_EQ(second->keypair.public_key, first->keypair.public_key);
        EXPECT_FALSE(fs::exists(dir / "data" / "identity" / "keypair.json"));

        // Stage an approved next boot chain, move PCR 8 to it, restart.
        auto next = read_pcrs();
        std::array<uint8_t, 64> input{};
        std::memcpy(input.data(), next[0].data(), 32);
        std::memset(input.data() + 32, 0x5D, 32);
        crypto_hash_sha256(next[0].data(), input.data(), input.size());
        boot_set.next_boot_chain = next;
        ASSERT_TRUE(nexus::core::load_gossip_identity(storage, boot_set, error)) << error;
        ASSERT_EQ(extend_pcr8(0x5D), next[0]);
        boot = "sim-boot-3";
        const auto upgraded = nexus::core::load_gossip_identity(storage, boot_set, error);
        ASSERT_TRUE(upgraded) << error;
        EXPECT_EQ(upgraded->keypair.public_key, first->keypair.public_key);

        // An unapproved boot-chain change fails closed and creates nothing.
        extend_pcr8(0x6E);
        EXPECT_FALSE(nexus::core::load_gossip_identity(storage, boot_set, error));
        EXPECT_NE(error.find("PCR 8/9"), std::string::npos) << error;
        EXPECT_FALSE(fs::exists(dir / "data" / "identity" / "keypair.json"));
        storage.stop();
    }

    stop = true;
    server.join();
    socket.close();
    fs::remove_all(dir);
}

#endif  // NEXUS_TPM_SIMULATOR_TESTS

TEST_F(TpmSealSimulator, RunsOnlyAgainstASimulator) {
    // Reached only when SetUp found a simulator. Keeps the suite listed (and
    // its skip reason visible) on builds where the cases above compile out.
    SUCCEED();
}
