#include <LemonadeNexus/Boringtun/ForwardAuthorizer.hpp>

#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Api/MeshRekey.hpp>
#include <LemonadeNexus/Tree/TreeRules.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <spdlog/spdlog.h>

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace nexus::boringtun {

namespace {

/// The node's tunnel address when it is one address inside `governed`.
std::optional<uint32_t> plane_address(const tree::TreeNode& node, const Cidr& governed) {
    if (node.tunnel_ip.empty()) return std::nullopt;
    auto cidr = Cidr::parse(node.tunnel_ip);
    if (!cidr || cidr->prefix_len != 32 || !governed.contains(cidr->network)) return std::nullopt;
    return cidr->network;
}

/// The connect rule of PermissionTreeService::resolve_authorized, applied to
/// the endpoint `from` (its management key is the principal) and `to`.
bool may_connect(const tree::PermissionTreeService& tree, const tree::TreeNode& from,
                 const tree::TreeNode& to) {
    if (from.id == to.id || from.parent_id.empty()) return false;
    if (!tree.is_descendant_of(to.id, from.parent_id)) return false;
    return tree.check_permission(from.mgmt_pubkey, to.id, acl::Permission::ConnectPrivate) ||
           tree.check_permission(from.mgmt_pubkey, to.id, acl::Permission::ConnectShared);
}

} // namespace

std::shared_ptr<const ForwardPolicy> build_forward_policy(
    const tree::PermissionTreeService& tree, const Cidr& governed, const PlanePeers& peers) {
    auto policy = std::make_shared<ForwardPolicy>();
    policy->governed = governed;

    // A node's tunnel_ip is only a claim. An address belongs to a node only
    // when the dataplane peer the server installed for that address has the
    // node's mesh key; the dataplane already binds the address to that key,
    // so a node that names another device's address gains nothing from it.
    struct Located {
        tree::TreeNode node;
        uint32_t       addr;
    };
    std::vector<Located> located;
    std::unordered_map<uint32_t, int> claims;
    for (const auto type : {tree::NodeType::Endpoint, tree::NodeType::Relay}) {
        for (auto& node : tree.get_nodes_by_type(type)) {
            const auto addr = plane_address(node, governed);
            if (!addr || node.mesh_pubkey.empty()) continue;
            const auto peer = peers.find(*addr);
            if (peer == peers.end() || api::normalize_mesh_pubkey(node.mesh_pubkey) != peer->second) {
                continue;
            }
            ++claims[*addr];
            located.push_back({std::move(node), *addr});
        }
    }
    // Two nodes that both match one peer (two spellings of one key) make the
    // owner ambiguous: the address gets no rule, so its traffic is dropped.
    std::erase_if(located, [&](const Located& l) {
        if (claims[l.addr] == 1) return false;
        spdlog::warn("[ForwardAuthorizer] {} nodes claim one tunnel address and its peer key; "
                     "forwarding for it is denied",
                     claims[l.addr]);
        return true;
    });

    // A relay forwards for the whole plane, so it is open only when a root
    // admin placed it: its management key must administer the tree root (the
    // rule that lets a writer create a relay at all).
    std::vector<const Located*> endpoints;
    std::optional<tree::rules::NodeMap> nodes;
    for (const auto& l : located) {
        if (l.node.type == tree::NodeType::Endpoint) {
            endpoints.push_back(&l);
            continue;
        }
        if (l.node.mgmt_pubkey.empty()) continue;
        if (!nodes) nodes = tree.nodes_snapshot();
        if (tree::rules::administers_root(*nodes, l.node.id, l.node.mgmt_pubkey)) {
            policy->open.insert(l.addr);
        }
    }

    // A grant names a principal on the target node, so the candidate sources
    // for a target are the endpoints whose management key appears in the
    // target's assignments. may_connect then applies the full rule.
    std::unordered_map<std::string, std::vector<const Located*>> by_principal;
    for (const Located* e : endpoints) {
        if (!e->node.mgmt_pubkey.empty())
            by_principal[tree::canonical_principal(e->node.mgmt_pubkey)].push_back(e);
    }
    for (const Located* target : endpoints) {
        for (const auto& assignment : target->node.assignments) {
            auto it = by_principal.find(tree::canonical_principal(assignment.management_pubkey));
            if (it == by_principal.end()) continue;
            for (const Located* source : it->second) {
                if (may_connect(tree, source->node, target->node))
                    policy->allowed.insert(ForwardPolicy::key(source->addr, target->addr));
            }
        }
    }
    return policy;
}

std::shared_ptr<const ForwardPolicy> deny_forward_policy() {
    auto policy = std::make_shared<ForwardPolicy>();
    policy->governed = *Cidr::parse("0.0.0.0/0");
    return policy;
}

ForwardAuthorizer::ForwardAuthorizer(const tree::PermissionTreeService& tree,
                                     UserspaceDataplane& dataplane, Cidr governed,
                                     std::chrono::milliseconds poll)
    : tree_(tree), dataplane_(dataplane), governed_(governed), poll_(poll) {}

ForwardAuthorizer::~ForwardAuthorizer() {
    stop();
}

void ForwardAuthorizer::start() {
    (void)refresh(true);
    std::lock_guard lock(wait_mtx_);
    if (thread_.joinable()) return;
    stopping_ = false;
    thread_ = std::thread([this] { run(); });
}

void ForwardAuthorizer::stop() {
    {
        std::lock_guard lock(wait_mtx_);
        stopping_ = true;
    }
    wait_cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

bool ForwardAuthorizer::refresh(bool force) {
    std::lock_guard lock(refresh_mtx_);
    // Read both inputs' versions before the build: a change during the build
    // gives a new version, and the next poll rebuilds.
    const auto hash = tree_.get_tree_hash();
    const auto generation = dataplane_.routes_generation();
    if (!force && built_hash_ && *built_hash_ == hash && built_generation_ == generation) {
        return false;
    }
    auto policy = build_forward_policy(tree_, governed_, dataplane_.primary_address_peers());
    spdlog::debug("[ForwardAuthorizer] policy rebuilt: {} allowed pairs, {} relays",
                  policy->allowed.size(), policy->open.size());
    dataplane_.set_forward_policy(std::move(policy));
    built_hash_ = hash;
    built_generation_ = generation;
    return true;
}

void ForwardAuthorizer::run() {
    std::unique_lock lock(wait_mtx_);
    while (!stopping_) {
        wait_cv_.wait_for(lock, poll_, [this] { return stopping_; });
        if (stopping_) break;
        lock.unlock();
        try {
            (void)refresh(false);
        } catch (const std::exception& e) {
            // The previous policy stays installed; it never widens on error.
            spdlog::error("[ForwardAuthorizer] policy rebuild failed: {}", e.what());
        }
        lock.lock();
    }
}

} // namespace nexus::boringtun
