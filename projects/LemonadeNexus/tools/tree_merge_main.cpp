// nexus-tree-merge: offline tree merge tooling for test data (design A9).
//
// A live mesh migrates with scripts/nexus-tree-migrate instead: its files are
// encrypted under each server's data key, which only the running server
// holds (docs/Tree-Merge-Ceremony.md). This tool reads plaintext data
// directories only.
//
//   nexus-tree-merge export   --data-root <dir> --server <label> [--root-server]
//                             --out <export.json>
//   nexus-tree-merge merge    --spec <spec.json> --out <unsigned.json>
//                             --preimage <preimage.json> [--report <report.json>]
//   nexus-tree-merge finalize --unsigned <unsigned.json> --signature <signature.b64>
//                             --out <commit.json>
//
// export reads one server's tree, IPAM records, and delta log from a data
// directory (a stopped server, or a copy). merge unions the exports by the
// rule in TreeMerge.hpp and writes the unsigned height-1 commit plus the exact
// preimage the root management key signs. With any conflict it writes only
// the report and exits with status 2. The root holder signs the preimage with
// `lemonade-nexus --sign-tree-merge <preimage> <signature-out>`. finalize
// checks the signature and writes the signed commit, which
// `lemonade-nexus --install-tree-merge <commit.json>` installs on a server.
//
// Merge spec:
//   {
//     "network_id": "<64-hex>",            // the mesh's network id
//     "root_pubkey": "<64-hex>",           // the root management key
//     "block_time_ms": 1700000000000,      // optional; default: now
//     "exports": ["a.json", "b.json"],
//     "resolutions": {"<node id>": "<server label>" | "drop"}   // optional
//   }
//
// No key material is read or written here.

#include <LemonadeNexus/Core/ApplicationRoot.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeMerge.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

using json = nlohmann::json;
namespace tree = nexus::tree;

namespace {

int fail(const std::string& reason) {
    std::fprintf(stderr, "nexus-tree-merge: %s\n", reason.c_str());
    return 1;
}

bool write_file(const std::string& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
    return static_cast<bool>(out);
}

std::optional<std::string> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

std::optional<json> read_json(const std::string& path) {
    const auto text = read_file(path);
    if (!text) return std::nullopt;
    auto doc = json::parse(*text, nullptr, false);
    if (doc.is_discarded()) return std::nullopt;
    return doc;
}

using Args = std::map<std::string, std::string>;

/// "--key value" pairs and bare "--flag" switches after the subcommand.
std::optional<Args> parse_args(int argc, char** argv, std::initializer_list<const char*> flags) {
    Args args;
    for (int i = 2; i < argc; ++i) {
        const std::string key = argv[i];
        if (!key.starts_with("--")) return std::nullopt;
        const bool is_flag = std::any_of(flags.begin(), flags.end(),
                                         [&](const char* f) { return key == f; });
        if (is_flag) {
            args[key] = "1";
        } else if (i + 1 < argc) {
            args[key] = argv[++i];
        } else {
            return std::nullopt;
        }
    }
    return args;
}

int run_export(const Args& args) {
    const auto data_root = args.find("--data-root");
    const auto server = args.find("--server");
    const auto out = args.find("--out");
    if (data_root == args.end() || server == args.end() || out == args.end()) {
        return fail("export needs --data-root, --server, and --out");
    }
    nexus::crypto::SodiumCryptoService crypto;
    crypto.start();
    nexus::storage::FileStorageService storage{std::filesystem::path(data_root->second)};
    storage.start();
    tree::PermissionTreeService tree_svc{storage, crypto};
    tree_svc.start();
    nexus::ipam::IPAMService ipam{storage};
    ipam.start();

    const auto exported = tree::collect_tree_export(server->second, args.contains("--root-server"),
                                                    tree_svc.nodes_snapshot(), ipam, storage);
    if (!write_file(out->second, tree::tree_export_to_json(exported).dump(2))) {
        return fail("cannot write " + out->second);
    }
    std::printf("exported %zu nodes from %s (%zu joined here, %zu created here)%s\n",
                exported.nodes.size(), exported.server.c_str(), exported.joined_here.size(),
                exported.created_here.size(), exported.root_server ? " [root server]" : "");
    tree_svc.stop();
    storage.stop();
    return 0;
}

int run_merge(const Args& args) {
    const auto spec_path = args.find("--spec");
    const auto out = args.find("--out");
    const auto preimage_path = args.find("--preimage");
    if (spec_path == args.end() || out == args.end() || preimage_path == args.end()) {
        return fail("merge needs --spec, --out, and --preimage");
    }
    const auto spec = read_json(spec_path->second);
    if (!spec || !spec->is_object()) return fail("spec is not valid JSON");

    nexus::security::NetworkId network_id{};
    std::string root_key;
    uint64_t block_time_ms = 0;
    std::vector<tree::TreeExport> exports;
    std::map<std::string, std::string> resolutions;
    try {
        const auto network = nexus::crypto::from_hex(spec->at("network_id").get<std::string>());
        if (network.size() != network_id.size()) return fail("network_id is not 64 hex digits");
        std::copy(network.begin(), network.end(), network_id.begin());
        const auto principal =
            nexus::core::root_principal_from_hex(spec->at("root_pubkey").get<std::string>());
        if (!principal) return fail("root_pubkey is not a 64-hex Ed25519 key");
        root_key = *principal;
        block_time_ms = spec->value(
            "block_time_ms",
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count()));
        for (const auto& path : spec->at("exports")) {
            const auto doc = read_json(path.get<std::string>());
            const auto parsed = doc ? tree::tree_export_from_json(*doc) : std::nullopt;
            if (!parsed) return fail("export is not valid: " + path.get<std::string>());
            exports.push_back(*parsed);
        }
        const json chosen = spec->value("resolutions", json::object());
        for (const auto& [id, choice] : chosen.items()) {
            resolutions[id] = choice.get<std::string>();
        }
    } catch (const std::exception& e) {
        return fail(std::string("spec field error: ") + e.what());
    }

    const auto result = tree::merge_tree_exports(exports, resolutions);
    const json report = tree::merge_report(exports, result);
    if (const auto r = args.find("--report"); r != args.end()) {
        if (!write_file(r->second, report.dump(2))) return fail("cannot write " + r->second);
    }
    for (const auto& c : result.conflicts) {
        std::string servers;
        for (const auto& s : c.servers) servers += (servers.empty() ? "" : ",") + s;
        std::printf("CONFLICT %-24s %-26s %s [%s]\n", c.node_id.c_str(), c.kind.c_str(),
                    c.detail.c_str(), servers.c_str());
    }
    for (const auto& d : result.dropped) {
        std::printf("DROPPED  %-24s %-26s %s\n", d.node_id.c_str(), d.reason.c_str(),
                    d.detail.c_str());
    }
    if (!result.conflicts.empty()) {
        std::printf("%zu conflict(s). Fix the exports or the resolutions and run merge again.\n",
                    result.conflicts.size());
        return 2;
    }
    const auto entry = tree::build_merge_entry(result.nodes, block_time_ms, network_id, root_key);
    if (!entry) return fail("the merged tree exceeds the merge body limits");
    if (!write_file(out->second, tree::tree_log_entry_to_json(*entry).dump(2)) ||
        !write_file(preimage_path->second,
                    tree::merge_preimage(*entry, network_id, result.nodes.size()))) {
        return fail("cannot write the merge output");
    }
    std::printf("merged %zu nodes from %zu exports; %zu dropped\n", result.nodes.size(),
                exports.size(), result.dropped.size());
    std::printf("state root (height 1): %s\n",
                nexus::crypto::to_base64(entry->state_root).c_str());
    std::printf("sign %s with: lemonade-nexus --sign-tree-merge %s <signature-out>\n",
                preimage_path->second.c_str(), preimage_path->second.c_str());
    return 0;
}

int run_finalize(const Args& args) {
    const auto unsigned_path = args.find("--unsigned");
    const auto signature_path = args.find("--signature");
    const auto out = args.find("--out");
    if (unsigned_path == args.end() || signature_path == args.end() || out == args.end()) {
        return fail("finalize needs --unsigned, --signature, and --out");
    }
    const auto doc = read_json(unsigned_path->second);
    auto entry = doc ? tree::tree_log_entry_from_json(*doc) : std::nullopt;
    if (!entry || entry->kind != tree::TreeLogEntryKind::Merge) {
        return fail("the unsigned commit is not a merge entry");
    }
    const auto signature_text = read_file(signature_path->second);
    if (!signature_text) return fail("cannot read " + signature_path->second);
    std::string trimmed = *signature_text;
    while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.back()))) {
        trimmed.pop_back();
    }
    std::vector<uint8_t> raw;
    try {
        raw = nexus::crypto::from_base64(trimmed);
    } catch (const std::exception&) {
        return fail("the signature is not base64");
    }
    if (raw.size() != nexus::crypto::kEd25519SignatureSize) {
        return fail("the signature is not 64 bytes");
    }
    nexus::crypto::Ed25519Signature signature{};
    std::copy(raw.begin(), raw.end(), signature.begin());
    *entry = tree::attach_merge_signature(std::move(*entry), signature);

    nexus::security::NetworkId network_id{};
    try {
        const auto network = nexus::crypto::from_hex(entry->commit.at("network_id").get<std::string>());
        if (network.size() != network_id.size()) return fail("the commit names no network");
        std::copy(network.begin(), network.end(), network_id.begin());
    } catch (const std::exception&) {
        return fail("the commit names no network");
    }
    nexus::crypto::SodiumCryptoService crypto;
    crypto.start();
    const std::string signer = entry->commit.value("signer", "");
    if (const auto refusal = tree::verify_merge_signature(crypto, *entry, network_id, signer)) {
        return fail(*refusal);
    }
    if (!write_file(out->second, tree::tree_log_entry_to_json(*entry).dump(2))) {
        return fail("cannot write " + out->second);
    }
    std::printf("signed merge commit written to %s\n", out->second.c_str());
    std::printf("install with: lemonade-nexus --install-tree-merge %s\n", out->second.c_str());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    spdlog::set_level(spdlog::level::warn);
    if (argc < 2) {
        return fail("usage: nexus-tree-merge export|merge|finalize [options]");
    }
    const std::string command = argv[1];
    const auto args = parse_args(argc, argv, {"--root-server"});
    if (!args) return fail("malformed arguments");
    if (command == "export") return run_export(*args);
    if (command == "merge") return run_merge(*args);
    if (command == "finalize") return run_finalize(*args);
    return fail("unknown command: " + command);
}
