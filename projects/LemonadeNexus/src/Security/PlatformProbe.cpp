#include <LemonadeNexus/Security/PlatformProbe.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <fstream>
#include <iterator>
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

/// Read the paravisor's attestation blob out of vTPM NV. Unauthenticated by design
/// on Azure — anything in the guest that can open the TPM can read it, which is
/// exactly why the blob alone is not proof of anything.
std::vector<uint8_t> read_hcl_from_nv() {
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

/// VCEK is per chip and per TCB, so cache it under both.
fs::path vcek_cache_path(const PlatformProbeConfig& cfg, const SnpReport& r) {
    const auto& t = r.reported_tcb;
    return cfg.cache_dir / "vcek" /
           (r.chip_id_hex().substr(0, 32) + "-" + std::to_string(t.bootloader) + "." +
            std::to_string(t.tee) + "." + std::to_string(t.snp) + "." +
            std::to_string(t.microcode) + ".der");
}

std::vector<uint8_t> fetch_vcek(const PlatformProbeConfig& cfg, const SnpReport& r) {
    const auto cached = vcek_cache_path(cfg, r);
    if (auto bytes = read_file(cached); !bytes.empty()) {
        spdlog::debug("[probe] using cached VCEK {}", cached.string());
        return bytes;
    }
    if (!cfg.allow_network) return {};

    const std::string url = vcek_kds_url(r, cfg.product);
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

/// ASK + ARK, cached next to the VCEK. Trust does not come from this fetch — the
/// verifier re-checks the root against the compiled-in one.
std::string fetch_amd_chain(const PlatformProbeConfig& cfg) {
    const auto cached = cfg.cache_dir / "vcek" / (cfg.product + "-cert-chain.pem");
    if (auto bytes = read_file(cached); !bytes.empty()) {
        return std::string(bytes.begin(), bytes.end());
    }
    if (!cfg.allow_network) return {};

    try {
        httplib::SSLClient client("kdsintf.amd.com", 443);
        client.set_connection_timeout(10);
        client.set_read_timeout(30);
        client.set_follow_location(true);
        auto res = client.Get("/vcek/v1/" + cfg.product + "/cert_chain");
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

PlatformProbeResult probe_platform(const PlatformProbeConfig& cfg) {
    PlatformProbeResult out;
    out.diagnostics = gather_diagnostics();

    // 1. Obtain the platform's attestation blob.
    std::vector<uint8_t> blob;
    if (!cfg.hcl_blob_override.empty()) {
        blob = read_file(cfg.hcl_blob_override);
        if (blob.empty()) {
            return no(std::move(out),
                      "could not read the HCL blob from " + cfg.hcl_blob_override.string());
        }
    } else {
        blob = read_hcl_from_nv();
        if (blob.empty()) {
            return no(std::move(out),
                      "no platform evidence source: vTPM NV index 0x01400001 is absent or "
                      "unreadable, and no /dev/sev-guest backend is implemented yet");
        }
    }

    // 2. Structure, and the AMD-signed binding to the vTPM AK.
    auto hcl = parse_hcl_blob(blob);
    if (!hcl) return no(std::move(out), "the attestation blob is malformed or inconsistent");
    out.profile = EvidenceProfile::SnpVtpm;

    // 3. The AMD signature. Until this passes we have only parsed a blob that
    //    claims to be from AMD.
    auto vcek = fetch_vcek(cfg, hcl->snp);
    if (vcek.empty()) {
        return no(std::move(out), "no VCEK for this chip and TCB (AMD KDS unreachable and "
                                   "nothing cached), so the report cannot be verified");
    }
    if (pinned_amd_root(cfg.product).empty()) {
        return no(std::move(out), "no compiled-in AMD root for product '" + cfg.product + "'");
    }
    // The ASK is an intermediate, so it is safe to transport: verify_snp_signature
    // independently requires the chain's root to be the compiled-in ARK, so a
    // spoofed KDS buys nothing.
    const std::string chain = fetch_amd_chain(cfg);
    if (chain.empty()) {
        return no(std::move(out), "no AMD certificate chain available for this product");
    }
    if (auto sig = verify_snp_signature(hcl->snp, vcek, chain); !sig.ok) {
        return no(std::move(out), "AMD signature check failed: " + sig.failure);
    }

    // 4. Guest policy: this is where "pause the VM and dump memory" is ruled out.
    if (auto pol = verify_snp_policy(hcl->snp, cfg.policy); !pol.ok) {
        return no(std::move(out), "platform policy check failed: " + pol.failure);
    }

    out.tier1_capable   = true;
    out.measurement_hex = hcl->snp.measurement_hex();
    out.chip_id_hex     = hcl->snp.chip_id_hex();
    out.tcb             = hcl->snp.reported_tcb.to_string();
    out.policy_summary  = snp_report_summary(hcl->snp);
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
    if (!r.measurement_hex.empty()) s += "  measurement: " + r.measurement_hex + "\n";
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
