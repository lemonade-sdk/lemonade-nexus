#include <LemonadeNexus/Client/ClientService.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>

namespace nexus::client {

using json = nlohmann::json;
namespace chrono = std::chrono;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

ClientService::ClientService(storage::FileStorageService& storage,
                               crypto::SodiumCryptoService& crypto)
    : storage_{storage}
    , crypto_{crypto}
{
}

// ---------------------------------------------------------------------------
// IService lifecycle
// ---------------------------------------------------------------------------

void ClientService::on_start() {
    load_identity();
    load_known_servers();

    spdlog::info("[{}] started (pubkey: {}, known servers: {})",
                  name(),
                  crypto::to_base64(identity_keypair_.public_key),
                  known_servers_.size());
}

void ClientService::on_stop() {
    spdlog::info("[{}] stopping...", name());

    save_known_servers();

    spdlog::info("[{}] stopped", name());
}

// ---------------------------------------------------------------------------
// Identity persistence
// ---------------------------------------------------------------------------

void ClientService::load_identity() {
    auto envelope = storage_.read_file("identity", "client_keypair.json");
    if (envelope) {
        try {
            auto j = json::parse(envelope->data);
            auto pub_bytes  = crypto::from_base64(j.value("public_key", ""));
            auto priv_bytes = crypto::from_base64(j.value("private_key", ""));

            if (pub_bytes.size() == crypto::kEd25519PublicKeySize &&
                priv_bytes.size() == crypto::kEd25519PrivateKeySize) {
                std::memcpy(identity_keypair_.public_key.data(),
                            pub_bytes.data(), crypto::kEd25519PublicKeySize);
                std::memcpy(identity_keypair_.private_key.data(),
                            priv_bytes.data(), crypto::kEd25519PrivateKeySize);
                spdlog::info("[{}] loaded client identity keypair", name());
            } else {
                spdlog::warn("[{}] stored keypair has wrong size, regenerating", name());
                identity_keypair_ = crypto_.ed25519_keygen();
                save_identity();
            }
        } catch (const std::exception& e) {
            spdlog::warn("[{}] failed to parse client keypair: {}, regenerating",
                          name(), e.what());
            identity_keypair_ = crypto_.ed25519_keygen();
            save_identity();
        }
    } else {
        identity_keypair_ = crypto_.ed25519_keygen();
        spdlog::info("[{}] generated new client Ed25519 identity", name());
        save_identity();
    }

    // Also try to restore any previously assigned node ID
    auto node_env = storage_.read_file("identity", "client_node.json");
    if (node_env) {
        try {
            auto j = json::parse(node_env->data);
            my_node_id_ = j.value("node_id", "");
            if (!my_node_id_.empty()) {
                spdlog::info("[{}] restored node ID: {}", name(), my_node_id_);
            }
        } catch (const std::exception& e) {
            spdlog::warn("[{}] failed to parse client node state: {}", name(), e.what());
        }
    }
}

void ClientService::save_identity() {
    storage::SignedEnvelope envelope;
    envelope.type = "client_identity_keypair";

    json kp_json;
    kp_json["public_key"]  = crypto::to_base64(identity_keypair_.public_key);
    kp_json["private_key"] = crypto::to_base64(identity_keypair_.private_key);
    envelope.data = kp_json.dump();
    envelope.signer_pubkey = "ed25519:" +
                              crypto::to_base64(identity_keypair_.public_key);
    envelope.timestamp = static_cast<uint64_t>(
        chrono::system_clock::to_time_t(chrono::system_clock::now()));

    auto data_bytes = std::vector<uint8_t>(envelope.data.begin(),
                                            envelope.data.end());
    auto sig = crypto_.ed25519_sign(identity_keypair_.private_key, data_bytes);
    envelope.signature = crypto::to_base64(sig);

    if (!storage_.write_file("identity", "client_keypair.json", envelope)) {
        spdlog::warn("[{}] failed to persist client keypair", name());
    }
}

// ---------------------------------------------------------------------------
// Known servers persistence
// ---------------------------------------------------------------------------

void ClientService::load_known_servers() {
    std::lock_guard lock(mutex_);
    known_servers_.clear();

    auto envelope = storage_.read_file("identity", "known_servers.json");
    if (!envelope) {
        spdlog::info("[{}] no known_servers.json found, starting with empty list", name());
        return;
    }

    try {
        auto j = json::parse(envelope->data);
        if (!j.contains("servers") || !j["servers"].is_array()) {
            spdlog::warn("[{}] known_servers.json has invalid format", name());
            return;
        }

        for (const auto& s : j["servers"]) {
            ServerEndpoint ep;
            ep.address     = s.value("address", "");
            ep.http_port   = s.value("http_port", uint16_t{9100});
            ep.udp_port    = s.value("udp_port", uint16_t{51940});
            ep.stun_port   = s.value("stun_port", uint16_t{3478});
            ep.gossip_port = s.value("gossip_port", uint16_t{9102});
            ep.pubkey      = s.value("pubkey", "");
            ep.is_central  = s.value("is_central", false);

            if (!ep.address.empty()) {
                known_servers_.push_back(std::move(ep));
            }
        }

        spdlog::info("[{}] loaded {} known servers from storage",
                      name(), known_servers_.size());

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse known_servers.json: {}", name(), e.what());
    }
}

void ClientService::save_known_servers() {
    std::lock_guard lock(mutex_);

    json j;
    json servers_array = json::array();
    for (const auto& s : known_servers_) {
        json sj;
        sj["address"]     = s.address;
        sj["http_port"]   = s.http_port;
        sj["udp_port"]    = s.udp_port;
        sj["stun_port"]   = s.stun_port;
        sj["gossip_port"] = s.gossip_port;
        sj["pubkey"]      = s.pubkey;
        sj["is_central"]  = s.is_central;
        servers_array.push_back(std::move(sj));
    }
    j["servers"] = std::move(servers_array);

    storage::SignedEnvelope envelope;
    envelope.type = "known_servers";
    envelope.data = j.dump();
    envelope.signer_pubkey = "ed25519:" +
                              crypto::to_base64(identity_keypair_.public_key);
    envelope.timestamp = static_cast<uint64_t>(
        chrono::system_clock::to_time_t(chrono::system_clock::now()));

    auto data_bytes = std::vector<uint8_t>(envelope.data.begin(),
                                            envelope.data.end());
    auto sig = crypto_.ed25519_sign(identity_keypair_.private_key, data_bytes);
    envelope.signature = crypto::to_base64(sig);

    if (storage_.write_file("identity", "known_servers.json", envelope)) {
        spdlog::debug("[{}] saved {} known servers to storage",
                       name(), known_servers_.size());
    } else {
        spdlog::warn("[{}] failed to save known servers to storage", name());
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

std::optional<json> ClientService::http_post(const ServerEndpoint& server,
                                               const std::string& path,
                                               const json& body) {
    const auto host = server.address + ":" + std::to_string(server.http_port);

    try {
        httplib::Client cli(server.address, server.http_port);
        cli.set_connection_timeout(5);   // seconds
        cli.set_read_timeout(10);        // seconds
        cli.set_write_timeout(5);        // seconds

        auto res = cli.Post(path, body.dump(), "application/json");
        if (!res) {
            spdlog::warn("[{}] HTTP POST {} to {} failed: connection error",
                          name(), path, host);
            return std::nullopt;
        }

        if (res->status < 200 || res->status >= 300) {
            spdlog::warn("[{}] HTTP POST {} to {} returned status {}",
                          name(), path, host, res->status);

            // Try to parse an error body anyway
            try {
                auto err = json::parse(res->body);
                return err;
            } catch (...) {
                json err;
                err["error"] = "HTTP " + std::to_string(res->status);
                err["body"]  = res->body;
                return err;
            }
        }

        return json::parse(res->body);

    } catch (const std::exception& e) {
        spdlog::error("[{}] HTTP POST {} to {} exception: {}",
                       name(), path, host, e.what());
        return std::nullopt;
    }
}

std::optional<json> ClientService::http_get(const ServerEndpoint& server,
                                              const std::string& path) {
    const auto host = server.address + ":" + std::to_string(server.http_port);

    try {
        httplib::Client cli(server.address, server.http_port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(10);

        auto res = cli.Get(path);
        if (!res) {
            spdlog::warn("[{}] HTTP GET {} from {} failed: connection error",
                          name(), path, host);
            return std::nullopt;
        }

        if (res->status < 200 || res->status >= 300) {
            spdlog::warn("[{}] HTTP GET {} from {} returned status {}",
                          name(), path, host, res->status);
            return std::nullopt;
        }

        return json::parse(res->body);

    } catch (const std::exception& e) {
        spdlog::error("[{}] HTTP GET {} from {} exception: {}",
                       name(), path, host, e.what());
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------
// IClientProvider — discover_servers
// ---------------------------------------------------------------------------

std::vector<ServerEndpoint>
ClientService::do_discover_servers(const std::vector<ServerEndpoint>& bootstrap_endpoints) {
    std::vector<ServerEndpoint> discovered;

    // Phase 1: probe each bootstrap endpoint with GET /api/health
    for (const auto& ep : bootstrap_endpoints) {
        spdlog::info("[{}] probing bootstrap {}:{}", name(), ep.address, ep.http_port);

        auto health = http_get(ep, "/api/health");
        if (!health) {
            spdlog::warn("[{}] bootstrap {}:{} is unreachable",
                          name(), ep.address, ep.http_port);
            continue;
        }

        spdlog::info("[{}] bootstrap {}:{} is healthy", name(), ep.address, ep.http_port);
        discovered.push_back(ep);
    }

    // Phase 2: ask reachable servers for their relay/server lists
    // Copy the currently-discovered list so we can iterate stably
    const auto reachable = discovered;
    for (const auto& ep : reachable) {
        auto relay_list = http_get(ep, "/api/relay/list");
        if (!relay_list || !relay_list->contains("relays") ||
            !(*relay_list)["relays"].is_array()) {
            continue;
        }

        for (const auto& r : (*relay_list)["relays"]) {
            ServerEndpoint new_ep;
            new_ep.address     = r.value("address", "");
            new_ep.http_port   = r.value("http_port", uint16_t{9100});
            new_ep.udp_port    = r.value("udp_port", uint16_t{51940});
            new_ep.stun_port   = r.value("stun_port", uint16_t{3478});
            new_ep.gossip_port = r.value("gossip_port", uint16_t{9102});
            new_ep.pubkey      = r.value("pubkey", "");
            new_ep.is_central  = r.value("is_central", false);

            if (new_ep.address.empty()) {
                continue;
            }

            // De-duplicate: skip if we already have this address:port
            bool already_known = std::any_of(
                discovered.begin(), discovered.end(),
                [&](const ServerEndpoint& existing) {
                    return existing.address == new_ep.address &&
                           existing.http_port == new_ep.http_port;
                });

            if (!already_known) {
                spdlog::info("[{}] discovered server {}:{} via relay list",
                              name(), new_ep.address, new_ep.http_port);
                discovered.push_back(std::move(new_ep));
            }
        }
    }

    // Merge into our persistent known-servers list
    {
        std::lock_guard lock(mutex_);
        for (const auto& d : discovered) {
            bool exists = std::any_of(
                known_servers_.begin(), known_servers_.end(),
                [&](const ServerEndpoint& existing) {
                    return existing.address == d.address &&
                           existing.http_port == d.http_port;
                });
            if (!exists) {
                known_servers_.push_back(d);
            }
        }
    }

    spdlog::info("[{}] discovery complete: {} servers found", name(), discovered.size());
    return discovered;
}

// ---------------------------------------------------------------------------
// IClientProvider — join_network
// ---------------------------------------------------------------------------

JoinResult ClientService::do_join_network(const ServerEndpoint& server,
                                            const json& credentials_json) {
    JoinResult result;

    // Step 1: authenticate
    json auth_body = credentials_json;
    auth_body["client_pubkey"] = "ed25519:" +
                                  crypto::to_base64(identity_keypair_.public_key);

    auto auth_resp = http_post(server, "/api/auth", auth_body);
    if (!auth_resp) {
        result.error_message = "authentication request failed: server unreachable";
        spdlog::error("[{}] join failed: {}", name(), result.error_message);
        return result;
    }

    if (auth_resp->contains("error")) {
        result.error_message = auth_resp->value("error", "unknown auth error");
        spdlog::error("[{}] join failed: {}", name(), result.error_message);
        return result;
    }

    if (!auth_resp->value("authenticated", false)) {
        result.error_message = auth_resp->value("error_message",
                                                 "authentication rejected");
        spdlog::error("[{}] join failed: {}", name(), result.error_message);
        return result;
    }

    const auto session_token = auth_resp->value("session_token", "");

    // Step 2: register as an endpoint node in the tree
    tree::TreeNode endpoint_node;
    endpoint_node.type       = tree::NodeType::Endpoint;
    endpoint_node.mgmt_pubkey = "ed25519:" +
                                 crypto::to_base64(identity_keypair_.public_key);

    tree::TreeDelta join_delta;
    join_delta.operation      = "create_node";
    join_delta.target_node_id = "";  // server assigns the target
    join_delta.node_data      = endpoint_node;
    join_delta.signer_pubkey  = "ed25519:" +
                                 crypto::to_base64(identity_keypair_.public_key);
    join_delta.timestamp      = static_cast<uint64_t>(
        chrono::system_clock::to_time_t(chrono::system_clock::now()));

    // Sign the delta
    auto canonical = tree::canonical_delta_json(join_delta);
    auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
    auto sig = crypto_.ed25519_sign(identity_keypair_.private_key, canonical_bytes);
    join_delta.signature = crypto::to_base64(sig);

    // Build the request body
    json delta_body;
    delta_body["delta"]         = join_delta;
    delta_body["session_token"] = session_token;

    auto delta_resp = http_post(server, "/api/tree/delta", delta_body);
    if (!delta_resp) {
        result.error_message = "tree delta submission failed: server unreachable";
        spdlog::error("[{}] join failed: {}", name(), result.error_message);
        return result;
    }

    if (!delta_resp->value("success", false)) {
        result.error_message = delta_resp->value("error",
                                                  delta_resp->value("error_message",
                                                                     "delta rejected"));
        spdlog::error("[{}] join failed: {}", name(), result.error_message);
        return result;
    }

    // Parse the server's response
    result.success        = true;
    result.node_id        = delta_resp->value("node_id", "");
    result.tunnel_ip      = delta_resp->value("tunnel_ip", "");
    result.private_subnet = delta_resp->value("private_subnet", "");

    // Persist our node ID
    my_node_id_ = result.node_id;

    storage::SignedEnvelope node_env;
    node_env.type = "client_node_state";
    json node_state;
    node_state["node_id"]        = result.node_id;
    node_state["tunnel_ip"]      = result.tunnel_ip;
    node_state["private_subnet"] = result.private_subnet;
    node_env.data = node_state.dump();
    node_env.signer_pubkey = "ed25519:" +
                              crypto::to_base64(identity_keypair_.public_key);
    node_env.timestamp = static_cast<uint64_t>(
        chrono::system_clock::to_time_t(chrono::system_clock::now()));

    auto state_bytes = std::vector<uint8_t>(node_env.data.begin(),
                                             node_env.data.end());
    auto state_sig = crypto_.ed25519_sign(identity_keypair_.private_key,
                                           state_bytes);
    node_env.signature = crypto::to_base64(state_sig);
    (void)storage_.write_file("identity", "client_node.json", node_env);

    // Add this server to known servers if not already present
    {
        std::lock_guard lock(mutex_);
        bool exists = std::any_of(
            known_servers_.begin(), known_servers_.end(),
            [&](const ServerEndpoint& existing) {
                return existing.address == server.address &&
                       existing.http_port == server.http_port;
            });
        if (!exists) {
            known_servers_.push_back(server);
        }
    }

    spdlog::info("[{}] joined network: node_id={}, tunnel_ip={}, subnet={}",
                  name(), result.node_id, result.tunnel_ip, result.private_subnet);
    return result;
}

// ---------------------------------------------------------------------------
// IClientProvider — leave_network
// ---------------------------------------------------------------------------

bool ClientService::do_leave_network() {
    if (my_node_id_.empty()) {
        spdlog::warn("[{}] leave_network called but not currently joined", name());
        return false;
    }

    // Try to notify at least one known server
    ServerEndpoint target;
    bool found_server = false;
    {
        std::lock_guard lock(mutex_);
        if (!known_servers_.empty()) {
            target = known_servers_.front();
            found_server = true;
        }
    }

    if (found_server) {
        // Build a delete_node delta
        tree::TreeDelta leave_delta;
        leave_delta.operation      = "delete_node";
        leave_delta.target_node_id = my_node_id_;
        leave_delta.signer_pubkey  = "ed25519:" +
                                      crypto::to_base64(identity_keypair_.public_key);
        leave_delta.timestamp      = static_cast<uint64_t>(
            chrono::system_clock::to_time_t(chrono::system_clock::now()));

        auto canonical = tree::canonical_delta_json(leave_delta);
        auto canonical_bytes = std::vector<uint8_t>(canonical.begin(),
                                                     canonical.end());
        auto sig = crypto_.ed25519_sign(identity_keypair_.private_key,
                                         canonical_bytes);
        leave_delta.signature = crypto::to_base64(sig);

        json body;
        body["delta"] = leave_delta;

        auto resp = http_post(target, "/api/tree/delta", body);
        if (!resp || !resp->value("success", false)) {
            spdlog::warn("[{}] leave notification to {}:{} may have failed",
                          name(), target.address, target.http_port);
        }
    }

    spdlog::info("[{}] left network (node_id was: {})", name(), my_node_id_);
    my_node_id_.clear();

    // Remove persisted node state
    storage::SignedEnvelope empty_env;
    empty_env.type = "client_node_state";
    empty_env.data = "{}";
    empty_env.signer_pubkey = "ed25519:" +
                               crypto::to_base64(identity_keypair_.public_key);
    empty_env.timestamp = static_cast<uint64_t>(
        chrono::system_clock::to_time_t(chrono::system_clock::now()));
    (void)storage_.write_file("identity", "client_node.json", empty_env);

    return true;
}

// ---------------------------------------------------------------------------
// IClientProvider — submit_delta
// ---------------------------------------------------------------------------

TreeModifyResult ClientService::do_submit_delta(const tree::TreeDelta& delta) {
    TreeModifyResult result;

    // Make a mutable copy so we can sign it
    tree::TreeDelta signed_delta = delta;
    signed_delta.signer_pubkey = "ed25519:" +
                                  crypto::to_base64(identity_keypair_.public_key);
    signed_delta.timestamp = static_cast<uint64_t>(
        chrono::system_clock::to_time_t(chrono::system_clock::now()));

    // Sign: Ed25519 over the canonical delta JSON (excludes signature field)
    auto canonical = tree::canonical_delta_json(signed_delta);
    auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
    auto sig = crypto_.ed25519_sign(identity_keypair_.private_key, canonical_bytes);
    signed_delta.signature = crypto::to_base64(sig);

    // Try to submit to any known server
    ServerEndpoint target;
    bool found_server = false;
    {
        std::lock_guard lock(mutex_);
        if (!known_servers_.empty()) {
            target = known_servers_.front();
            found_server = true;
        }
    }

    if (!found_server) {
        result.error_message = "no known servers to submit delta to";
        spdlog::error("[{}] submit_delta failed: {}", name(), result.error_message);
        return result;
    }

    json body;
    body["delta"] = signed_delta;

    auto resp = http_post(target, "/api/tree/delta", body);
    if (!resp) {
        result.error_message = "server " + target.address + ":" +
                                std::to_string(target.http_port) + " unreachable";
        spdlog::error("[{}] submit_delta failed: {}", name(), result.error_message);
        return result;
    }

    result.success        = resp->value("success", false);
    result.delta_sequence = resp->value("delta_sequence", uint64_t{0});

    if (!result.success) {
        result.error_message = resp->value("error",
                                            resp->value("error_message",
                                                         "delta rejected by server"));
        spdlog::warn("[{}] submit_delta rejected: {}", name(), result.error_message);
    } else {
        spdlog::info("[{}] delta submitted successfully (seq={})",
                      name(), result.delta_sequence);
    }

    return result;
}

// ---------------------------------------------------------------------------
// IClientProvider — create_child_node
// ---------------------------------------------------------------------------

TreeModifyResult
ClientService::do_create_child_node(const std::string& parent_id,
                                      const tree::TreeNode& child_node) {
    tree::TreeDelta delta;
    delta.operation      = "create_node";
    delta.target_node_id = parent_id;
    delta.node_data      = child_node;

    // Ensure the child knows its parent
    delta.node_data.parent_id = parent_id;

    return do_submit_delta(delta);
}

// ---------------------------------------------------------------------------
// IClientProvider — update_node
// ---------------------------------------------------------------------------

TreeModifyResult
ClientService::do_update_node(const std::string& node_id,
                                const json& updates_json) {
    tree::TreeDelta delta;
    delta.operation      = "update_node";
    delta.target_node_id = node_id;

    // Populate the node_data from the update fields.
    // The server will merge these into the existing node.
    tree::TreeNode partial;
    partial.id = node_id;

    if (updates_json.contains("tunnel_ip")) {
        partial.tunnel_ip = updates_json["tunnel_ip"].get<std::string>();
    }
    if (updates_json.contains("private_subnet")) {
        partial.private_subnet = updates_json["private_subnet"].get<std::string>();
    }
    if (updates_json.contains("private_shared_addresses")) {
        partial.private_shared_addresses =
            updates_json["private_shared_addresses"].get<std::string>();
    }
    if (updates_json.contains("shared_domain")) {
        partial.shared_domain = updates_json["shared_domain"].get<std::string>();
    }
    if (updates_json.contains("wg_pubkey")) {
        partial.wg_pubkey = updates_json["wg_pubkey"].get<std::string>();
    }
    if (updates_json.contains("listen_endpoint")) {
        partial.listen_endpoint = updates_json["listen_endpoint"].get<std::string>();
    }
    if (updates_json.contains("region")) {
        partial.region = updates_json["region"].get<std::string>();
    }
    if (updates_json.contains("capacity_mbps")) {
        partial.capacity_mbps = updates_json["capacity_mbps"].get<uint32_t>();
    }
    if (updates_json.contains("reputation_score")) {
        partial.reputation_score = updates_json["reputation_score"].get<float>();
    }
    if (updates_json.contains("expires_at")) {
        partial.expires_at = updates_json["expires_at"].get<uint64_t>();
    }
    if (updates_json.contains("assignments") && updates_json["assignments"].is_array()) {
        for (const auto& a : updates_json["assignments"]) {
            tree::Assignment assignment;
            assignment.management_pubkey = a.value("management_pubkey", "");
            if (a.contains("permissions") && a["permissions"].is_array()) {
                for (const auto& p : a["permissions"]) {
                    assignment.permissions.push_back(p.get<std::string>());
                }
            }
            partial.assignments.push_back(std::move(assignment));
        }
    }

    delta.node_data = std::move(partial);

    return do_submit_delta(delta);
}

// ---------------------------------------------------------------------------
// IClientProvider — get_available_relays
// ---------------------------------------------------------------------------

std::vector<relay::RelayNodeInfo>
ClientService::do_get_available_relays(const relay::RelaySelectionCriteria& criteria) {
    std::vector<relay::RelayNodeInfo> results;

    // Strategy 1: read relay-type nodes from our locally cached tree
    auto node_ids = storage_.list_nodes();
    for (const auto& nid : node_ids) {
        auto envelope = storage_.read_node(nid);
        if (!envelope) {
            continue;
        }

        try {
            auto j = json::parse(envelope->data);
            tree::TreeNode node;
            from_json(j, node);

            if (node.type != tree::NodeType::Relay) {
                continue;
            }

            // Apply selection criteria filters
            if (node.reputation_score < criteria.min_reputation) {
                continue;
            }
            if (node.capacity_mbps < criteria.min_capacity_mbps) {
                continue;
            }
            if (!criteria.preferred_region.empty() &&
                node.region != criteria.preferred_region) {
                continue;
            }

            relay::RelayNodeInfo info;
            info.relay_id         = node.id;
            info.public_key       = node.mgmt_pubkey;
            info.endpoint         = node.listen_endpoint;
            info.region           = node.region;
            info.capacity_mbps    = node.capacity_mbps;
            info.reputation_score = node.reputation_score;
            info.supports_relay   = true;
            info.supports_stun    = true;

            results.push_back(std::move(info));
        } catch (const std::exception& e) {
            spdlog::debug("[{}] failed to parse node {}: {}", name(), nid, e.what());
        }
    }

    // Strategy 2: if we have few local results, query a known server
    if (results.size() < criteria.max_results) {
        ServerEndpoint target;
        bool found_server = false;
        {
            std::lock_guard lock(mutex_);
            if (!known_servers_.empty()) {
                target = known_servers_.front();
                found_server = true;
            }
        }

        if (found_server) {
            auto resp = http_get(target, "/api/relay/list");
            if (resp && resp->contains("relays") && (*resp)["relays"].is_array()) {
                for (const auto& r : (*resp)["relays"]) {
                    relay::RelayNodeInfo info;
                    info.relay_id         = r.value("relay_id", "");
                    info.public_key       = r.value("public_key", "");
                    info.endpoint         = r.value("endpoint", "");
                    info.region           = r.value("region", "");
                    info.capacity_mbps    = r.value("capacity_mbps", uint32_t{0});
                    info.reputation_score = r.value("reputation_score", 0.0f);
                    info.supports_stun    = r.value("supports_stun", true);
                    info.supports_relay   = r.value("supports_relay", true);
                    info.is_central       = r.value("is_central", false);

                    // Apply criteria
                    if (info.reputation_score < criteria.min_reputation) {
                        continue;
                    }
                    if (info.capacity_mbps < criteria.min_capacity_mbps) {
                        continue;
                    }
                    if (!criteria.preferred_region.empty() &&
                        info.region != criteria.preferred_region) {
                        continue;
                    }

                    // De-duplicate against local results
                    bool duplicate = std::any_of(
                        results.begin(), results.end(),
                        [&](const relay::RelayNodeInfo& existing) {
                            return existing.relay_id == info.relay_id;
                        });

                    if (!duplicate) {
                        results.push_back(std::move(info));
                    }
                }
            }
        }
    }

    // Sort by reputation descending, then trim to max_results
    std::sort(results.begin(), results.end(),
              [](const relay::RelayNodeInfo& a, const relay::RelayNodeInfo& b) {
                  return a.reputation_score > b.reputation_score;
              });

    if (results.size() > criteria.max_results) {
        results.resize(criteria.max_results);
    }

    spdlog::info("[{}] found {} relays matching criteria", name(), results.size());
    return results;
}

// ---------------------------------------------------------------------------
// IClientProvider — get_my_permissions
// ---------------------------------------------------------------------------

std::vector<std::string>
ClientService::do_get_my_permissions(const std::string& node_id) {
    std::vector<std::string> permissions;

    const auto our_pubkey = "ed25519:" +
                             crypto::to_base64(identity_keypair_.public_key);

    // Look up the target node in local storage
    auto envelope = storage_.read_node(node_id);
    if (!envelope) {
        spdlog::debug("[{}] node {} not found in local storage", name(), node_id);
        return permissions;
    }

    try {
        auto j = json::parse(envelope->data);
        tree::TreeNode node;
        from_json(j, node);

        // Scan the node's assignment list for entries matching our pubkey
        for (const auto& assignment : node.assignments) {
            if (assignment.management_pubkey == our_pubkey) {
                permissions.insert(permissions.end(),
                                   assignment.permissions.begin(),
                                   assignment.permissions.end());
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse node {} for permission check: {}",
                      name(), node_id, e.what());
    }

    spdlog::debug("[{}] permissions on node {}: {} entries",
                   name(), node_id, permissions.size());
    return permissions;
}

} // namespace nexus::client
