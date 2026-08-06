#include <LemonadeNexus/Security/PlatformProbe.hpp>

#include <LemonadeNexus/Core/TrustTypes.hpp>
#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <iterator>
#include <random>
#include <span>
#include <vector>

#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#endif

namespace nexus::security {

namespace fs = std::filesystem;

namespace {

std::vector<uint8_t> read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

bool write_file(const fs::path& p, std::span<const uint8_t> data) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    return f.good();
}

PlatformDiagnostics gather_diagnostics() {
    PlatformDiagnostics d;
    std::error_code ec;
    d.tpm_device_present = fs::exists("/dev/tpmrm0", ec) || fs::exists("/dev/tpm0", ec);
    d.sev_guest_device_present = fs::exists("/dev/sev-guest", ec);
    d.ima_measurements_present =
        fs::exists("/sys/kernel/security/ima/ascii_runtime_measurements", ec);
    return d;
}

/// VCEK is per chip and per TCB, so cache it under both.
fs::path vcek_cache_path(const fs::path& cache_dir, const SnpReport& r) {
    const auto& t = r.reported_tcb;
    return cache_dir / "vcek" /
           (r.chip_id_hex().substr(0, 32) + "-" + std::to_string(t.bootloader) + "." +
            std::to_string(t.tee) + "." + std::to_string(t.snp) + "." +
            std::to_string(t.microcode) + ".der");
}

PlatformProbeResult no(PlatformProbeResult r, std::string why) {
    r.tier1_capable = false;
    r.failure = std::move(why);
    return r;
}

}  // namespace

std::string_view evidence_profile_name(EvidenceProfile p) {
    switch (p) {
        case EvidenceProfile::SnpVtpm:   return "snp-vtpm";
        case EvidenceProfile::SnpDirect: return "snp-direct";
        case EvidenceProfile::None:      break;
    }
    return "none";
}

// ---------------------------------------------------------------------------
// Platform I/O
// ---------------------------------------------------------------------------

std::vector<uint8_t> read_hcl_nv_blob() {
#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)
    TSS2_TCTI_CONTEXT* tcti = nullptr;
    ESYS_CONTEXT* esys = nullptr;
    std::vector<uint8_t> out;

    if (Tss2_TctiLdr_Initialize(nullptr, &tcti) != TSS2_RC_SUCCESS || !tcti) {
        spdlog::debug("[probe] no TPM TCTI available");
        return out;
    }
    if (Esys_Initialize(&esys, tcti, nullptr) != TSS2_RC_SUCCESS || !esys) {
        Tss2_TctiLdr_Finalize(&tcti);
        return out;
    }
    Esys_Startup(esys, TPM2_SU_CLEAR);

    ESYS_TR handle = ESYS_TR_NONE;
    TSS2_RC rc = Esys_TR_FromTPMPublic(esys, kHclNvIndex, ESYS_TR_NONE, ESYS_TR_NONE,
                                        ESYS_TR_NONE, &handle);
    if (rc != TSS2_RC_SUCCESS) {
        spdlog::debug("[probe] NV index 0x{:08x} not present (0x{:x})", kHclNvIndex, rc);
    } else {
        TPM2B_NV_PUBLIC* pub = nullptr;
        rc = Esys_NV_ReadPublic(esys, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 &pub, nullptr);
        if (rc == TSS2_RC_SUCCESS && pub) {
            const uint16_t total = pub->nvPublic.dataSize;
            Esys_Free(pub);

            // The index is larger than a single NV_Read will return, so page it.
            out.reserve(total);
            uint16_t off = 0;
            while (off < total) {
                const uint16_t want = static_cast<uint16_t>(
                    std::min<int>(512, total - off));
                TPM2B_MAX_NV_BUFFER* chunk = nullptr;
                rc = Esys_NV_Read(esys, ESYS_TR_RH_OWNER, handle,
                                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                   want, off, &chunk);
                if (rc != TSS2_RC_SUCCESS || !chunk) {
                    spdlog::warn("[probe] NV_Read failed at offset {} (0x{:x})", off, rc);
                    out.clear();
                    break;
                }
                out.insert(out.end(), chunk->buffer, chunk->buffer + chunk->size);
                off = static_cast<uint16_t>(off + chunk->size);
                Esys_Free(chunk);
            }
        }
    }

    if (handle != ESYS_TR_NONE) Esys_TR_Close(esys, &handle);
    Esys_Finalize(&esys);
    Tss2_TctiLdr_Finalize(&tcti);
    return out;
#else
    return {};
#endif
}

std::vector<uint8_t> fetch_vcek(const fs::path& cache_dir, const SnpReport& r,
                                 const std::string& product, bool allow_network) {
    const auto cached = vcek_cache_path(cache_dir, r);
    if (auto bytes = read_file(cached); !bytes.empty()) {
        spdlog::debug("[probe] using cached VCEK {}", cached.string());
        return bytes;
    }
    if (!allow_network) return {};

    const std::string url = vcek_kds_url(r, product);
    const auto path_start = url.find('/', url.find("//") + 2);
    if (path_start == std::string::npos) return {};

    try {
        httplib::SSLClient client("kdsintf.amd.com", 443);
        client.set_connection_timeout(10);
        client.set_read_timeout(30);
        client.set_follow_location(true);
        auto res = client.Get(url.substr(path_start));
        if (!res || res->status != 200) {
            spdlog::warn("[probe] AMD KDS returned {} for the VCEK",
                          res ? std::to_string(res->status) : "no response");
            return {};
        }
        std::vector<uint8_t> der(res->body.begin(), res->body.end());
        if (!write_file(cached, der)) {
            spdlog::debug("[probe] could not cache the VCEK at {}", cached.string());
        }
        return der;
    } catch (const std::exception& e) {
        spdlog::warn("[probe] VCEK fetch failed: {}", e.what());
        return {};
    }
}

std::string fetch_amd_chain(const fs::path& cache_dir, const std::string& product,
                             bool allow_network) {
    const auto cached = cache_dir / "vcek" / (product + "-cert-chain.pem");
    if (auto bytes = read_file(cached); !bytes.empty()) {
        return std::string(bytes.begin(), bytes.end());
    }
    if (!allow_network) return {};

    try {
        httplib::SSLClient client("kdsintf.amd.com", 443);
        client.set_connection_timeout(10);
        client.set_read_timeout(30);
        client.set_follow_location(true);
        auto res = client.Get("/vcek/v1/" + product + "/cert_chain");
        if (!res || res->status != 200) {
            spdlog::warn("[probe] AMD KDS returned {} for the certificate chain",
                          res ? std::to_string(res->status) : "no response");
            return {};
        }
        std::vector<uint8_t> pem(res->body.begin(), res->body.end());
        write_file(cached, pem);
        return res->body;
    } catch (const std::exception& e) {
        spdlog::warn("[probe] AMD chain fetch failed: {}", e.what());
        return {};
    }
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

PlatformProbeResult probe_platform(const PlatformProbeConfig& cfg) {
    PlatformProbeResult out;
    out.diagnostics = gather_diagnostics();

    // Offline mode: a blob captured elsewhere, verified as far as a blob can be.
    // No quote is possible, so this can confirm the platform was genuine but can
    // never make THIS host Tier-1 capable.
    if (!cfg.hcl_blob_override.empty()) {
        const auto blob = read_file(cfg.hcl_blob_override);
        if (blob.empty()) {
            return no(std::move(out),
                      "could not read the HCL blob from " + cfg.hcl_blob_override.string());
        }
        auto hcl = parse_hcl_blob(blob);
        if (!hcl) return no(std::move(out), "the attestation blob is malformed or inconsistent");
        out.profile = EvidenceProfile::SnpVtpm;

        auto vcek = fetch_vcek(cfg.cache_dir, hcl->snp, cfg.product, cfg.allow_network);
        if (vcek.empty()) {
            return no(std::move(out), "no VCEK for this chip and TCB (AMD KDS unreachable and "
                                       "nothing cached), so the report cannot be verified");
        }
        if (pinned_amd_root(cfg.product).empty()) {
            return no(std::move(out), "no compiled-in AMD root for product '" + cfg.product + "'");
        }
        const std::string chain = fetch_amd_chain(cfg.cache_dir, cfg.product, cfg.allow_network);
        if (chain.empty()) {
            return no(std::move(out), "no AMD certificate chain available for this product");
        }
        if (auto sig = verify_snp_signature(hcl->snp, vcek, chain); !sig.ok) {
            return no(std::move(out), "AMD signature check failed: " + sig.failure);
        }
        if (auto pol = verify_snp_policy(hcl->snp, cfg.policy); !pol.ok) {
            return no(std::move(out), "platform policy check failed: " + pol.failure);
        }

        out.measurement_hex = hcl->snp.measurement_hex();
        out.chip_id_hex     = hcl->snp.chip_id_hex();
        out.tcb             = hcl->snp.reported_tcb.to_string();
        out.policy_summary  = snp_report_summary(hcl->snp);
        out.ak_pub_b64      = rsa_spki_b64(hcl->ak.modulus, hcl->ak.exponent);
        return no(std::move(out),
                  "verified a captured blob, not this host: no fresh quote was produced, so "
                  "this run grants no Tier-1 capability");
    }

    // Live: produce real evidence against a random nonce, then verify it through
    // exactly the path a remote peer would use. Anything less is detection.
    std::array<uint8_t, 32> nonce{};
    {
        std::random_device rd;
        for (auto& b : nonce) b = static_cast<uint8_t>(rd() & 0xFF);
    }

    EvidenceProduceConfig prod;
    prod.cache_dir       = cfg.cache_dir;
    prod.product         = cfg.product;
    prod.allow_network   = cfg.allow_network;
    prod.identity_pubkey = cfg.identity_pubkey;

    std::string why;
    auto evidence = produce_snp_vtpm_evidence(prod, nonce, &why);
    if (!evidence) {
        return no(std::move(out), why.empty() ? "no platform evidence source on this host" : why);
    }
    out.profile = EvidenceProfile::SnpVtpm;
    out.evidence_bytes = encode_snp_vtpm_evidence(*evidence).size();

    EvidenceRequirements req;
    req.policy                  = cfg.policy;
    req.expected_measurement_hex = cfg.policy.expected_measurement_hex;
    req.require_ima             = cfg.require_ima;

    auto verdict = verify_snp_vtpm_evidence(*evidence, nonce, cfg.identity_pubkey, req);
    out.measurement_hex = verdict.measurement_hex;
    out.ak_pub_b64      = verdict.ak_spki_b64;
    out.binary_sha256   = verdict.binary_sha256;
    out.chip_id_hex     = verdict.chip_id_hex;
    out.tcb             = verdict.tcb;
    out.policy_summary  = verdict.report_summary;
    out.ima_sha1_bank   = verdict.ima_replayed_in_sha1_bank;
    out.quote_verified  = verdict.quote_verified;
    if (!verdict.ok) return no(std::move(out), verdict.failure);

    out.binary_measured = !verdict.binary_sha256.empty();
    out.tier1_capable   = true;
    return out;
}

std::string format_probe_report(const PlatformProbeResult& r) {
    std::string s;
    s += "platform evidence: ";
    s += r.tier1_capable ? "VERIFIED" : "NOT VERIFIED";
    s += " (profile ";
    s += evidence_profile_name(r.profile);
    s += ")\n";
    if (!r.tier1_capable) s += "  reason:      " + r.failure + "\n";
    s += std::string("  fresh quote: ") + (r.quote_verified ? "yes" : "no") + "\n";
    if (!r.measurement_hex.empty()) s += "  measurement: " + r.measurement_hex + "\n";
    if (!r.ak_pub_b64.empty())      s += "  binding key: " + r.ak_pub_b64 + "\n";
    if (!r.binary_sha256.empty())   s += "  binary (IMA):" + r.binary_sha256 + "\n";
    if (r.evidence_bytes > 0) {
        s += "  evidence:    " + std::to_string(r.evidence_bytes) + " bytes";
        s += r.evidence_bytes > core::kMaxInlineEvidenceBytes
                 ? "  (OVER the inline gossip budget — needs out-of-band retrieval)\n"
                 : "\n";
    }
    if (r.ima_sha1_bank) {
        s += "  WARNING: the IMA log replays only in the SHA-1 PCR bank, so log integrity "
             "rests on SHA-1.\n           Boot the guest with ima_template_hash_algo=sha256.\n";
    }
    if (!r.chip_id_hex.empty())     s += "  chip id:     " + r.chip_id_hex + "\n";
    if (!r.tcb.empty())             s += "  tcb:         " + r.tcb + "\n";
    if (!r.policy_summary.empty())  s += "  report:      " + r.policy_summary + "\n";
    s += "  diagnostics (guest self-reported, not evidence):\n";
    s += std::string("    /dev/tpmrm0:     ") +
         (r.diagnostics.tpm_device_present ? "present" : "absent") + "\n";
    s += std::string("    /dev/sev-guest:  ") +
         (r.diagnostics.sev_guest_device_present ? "present" : "absent (expected under a paravisor)") + "\n";
    s += std::string("    IMA measurements:") +
         (r.diagnostics.ima_measurements_present ? " present" : " absent") + "\n";
    return s;
}

}  // namespace nexus::security
