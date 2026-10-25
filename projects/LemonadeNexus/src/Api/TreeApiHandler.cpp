#include <LemonadeNexus/Api/TreeApiHandler.hpp>
#include <algorithm>
#include <cctype>
#include <map>

#include <LemonadeNexus/Api/MeshRekey.hpp>
#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeOpSubmitter.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>
#include <LemonadeNexus/Tree/TreeRules.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Routing/IdentifierDerivation.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Boringtun/BoringtunService.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/ACL/Permission.hpp>

#include <spdlog/spdlog.h>

namespace nexus::api {

namespace {

// Caller-scoped JSON view of a tree node. Always redacts the wrapped management
// private key (secret key material must never leave the server). Reduces the
// assignment map to the caller's own entry unless `full_assignments` is set —
// management readers (EditNode) need the whole ACL for read-modify-write group
// edits, but lesser readers must not see every principal on the node.
nlohmann::json redact_node_for_caller(const tree::TreeNode& node,
                                      const std::string& caller_pubkey,
                                      bool full_assignments) {
    nlohmann::json j = node;
    j["wrapped_mgmt_privkey"] = ""; // keep the field present, drop the secret
    if (!full_assignments) {
        nlohmann::json own = nlohmann::json::array();
        const auto caller_canon = tree::canonical_principal(caller_pubkey);
        for (const auto& a : node.assignments) {
            if (tree::canonical_principal(a.management_pubkey) == caller_canon) own.push_back(a);
        }
        j["assignments"] = std::move(own);
    }
    return j;
}

// Private EP FQDN registered at join (private.<node_id>.ep.<base_domain>).
// Join and the delete cascade must construct this byte-identically, or the
// cascade would remove a name the join never created.
std::string client_ep_fqdn(const std::string& node_id, const std::string& base_domain) {
    return "private." + node_id + ".ep." + base_domain;
}

// Strip the "ed25519:" identity prefix (when present) so bare base64 key
// bytes can be compared.
[[nodiscard]] std::string_view strip_ed25519_prefix(std::string_view key) {
    constexpr std::string_view ed_prefix = "ed25519:";
    return key.starts_with(ed_prefix) ? key.substr(ed_prefix.size()) : key;
}

// Apply an optional JSON field to `dst`, leaving it unchanged when the key
// is absent. Mirrors the prior per-field body.contains/get chain.
template <typename T>
void apply_optional_field(const nlohmann::json& body, const char* key, T& dst) {
    if (body.contains(key)) dst = body[key].get<T>();
}

// --- Tree operations (ServerConfig::tree_ops_enabled) ---
//
// With the flag on, every tree write below builds a TreeOp and submits it
// through TreeOpSubmitter. On the server the op goes through Tier 1 consensus:
// the route waits up to kTreeOpCommitWaitMs for the commit and then answers
// 202 with the op id (answer_unfinished). Request checks that run before a
// write, and the status codes and bodies of a committed write, stay those of
// the direct paths.

/// The configured submitter, or nullptr after answering 500. The flag never
/// falls back to the direct write paths.
tree::TreeOpSubmitter* tree_op_submitter(ApiContext& ctx, httplib::Response& res) {
    if (!ctx.tree_ops) {
        spdlog::error("[TreeApi] tree_ops_enabled is set but no tree-op submitter is wired");
        error_response(res, "tree operations unavailable", 500);
    }
    return ctx.tree_ops;
}

/// Answer a submission that did not finish: 202 with the op id when the op is
/// queued but not yet committed, 503 when this server cannot order tree
/// operations (not Tier 1, halted, or a full pool). Returns true when it
/// answered.
bool answer_unfinished(httplib::Response& res, const tree::TreeOpSubmission& s) {
    if (s.pending) {
        json_response(res, {{"success", true}, {"status", "pending"}, {"op_id", s.op_id}}, 202);
        return true;
    }
    if (s.verdict.refusal == tree::TreeOpRefusal::Unavailable) {
        error_response(res, s.verdict.reason, 503);
        return true;
    }
    return false;
}

/// Run `fn` when the pending op behind `s` commits. Work a committed write
/// does after the tree changes on this server only (a join's dataplane steps)
/// must still happen when the commit arrives after the request answered.
void after_commit(const tree::TreeOpSubmission& s, std::function<void()> fn) {
    if (!s.ticket) return;
    s.ticket->on_settled([fn = std::move(fn)](const tree::TreeOpOutcome& outcome) {
        if (outcome.status == tree::TreeOpStatus::Committed) fn();
    });
}

/// Current clients send no base version, so a route reads it from the current
/// tree when it builds the op. A concurrent write between that read and the
/// commit makes the op stale; rebuilding it from the new state keeps the
/// direct paths' last-writer-wins behavior. Bounded, so a busy node cannot
/// hold a request in a loop.
constexpr int kStaleBaseAttempts = 3;

/// Submit `build()`, rebuilding and resubmitting while the result is
/// StaleBaseVersion, at most kStaleBaseAttempts times in total.
template <typename Build>
tree::TreeOpSubmission submit_rebased(tree::TreeOpSubmitter& submitter, Build&& build) {
    tree::TreeOpSubmission s;
    for (int attempt = 0; attempt < kStaleBaseAttempts; ++attempt) {
        s = submitter.submit(build());
        if (s.pending || s.verdict.refusal != tree::TreeOpRefusal::StaleBaseVersion) break;
    }
    return s;
}

/// The tree's content rules for a session write of `node` by `signer`, the
/// rules validate_op and apply_delta apply. Among them, only a root admin sets
/// a node's tunnel_ip or private_subnet or creates a relay. The direct
/// write paths call it so they enforce the same rules as tree operations.
std::optional<std::string> session_content_refusal(const tree::PermissionTreeService& tree,
                                                   std::string_view operation,
                                                   const tree::TreeNode& node,
                                                   const std::string& signer) {
    tree::TreeDelta d;
    d.operation = std::string(operation);
    d.target_node_id = node.id;
    d.node_data = node;
    d.signer_pubkey = signer;
    return tree::rules::delta_content_refusal(tree.nodes_snapshot(), d);
}

/// Wrap a client-signed delta in a TreeOp and submit it.
tree::TreeOpSubmission submit_delta_op(tree::TreeOpSubmitter& submitter,
                                       tree::PermissionTreeService& tree,
                                       const tree::TreeDelta& delta) {
    tree::TreeOp op;
    if (delta.operation == "create_node") {
        op.kind = tree::TreeOpKind::CreateNode;
        op.target = delta.node_data.id;
    } else if (delta.operation == "delete_node") {
        op.kind = tree::TreeOpKind::DeleteNode;
        op.target = delta.target_node_id;
    } else if (tree::rules::required_permission_for(delta.operation) ==
               acl::Permission::EditNode) {
        op.kind = tree::TreeOpKind::UpdateFields;
        op.target = delta.target_node_id;
    }
    if (op.target.empty()) {
        tree::TreeOpSubmission refused;
        refused.verdict = {tree::TreeOpRefusal::Malformed, "delta does not map to a tree op"};
        return refused;
    }
    // The delta's own signed time is the op's signed time. A zero timestamp
    // leaves the op unequal to its delta, so validate_op refuses it.
    op.signed_at = delta.timestamp;
    op.principal = delta.signer_pubkey;
    op.body.source = tree::TreeOpSource::Delta;
    op.body.delta = delta;
    return submit_rebased(submitter, [&] {
        if (op.kind != tree::TreeOpKind::CreateNode) {
            const auto current = tree.get_node(op.target);
            op.base_version = current ? current->version : 0;
        }
        return op;
    });
}

/// Outcome of the tree part of a join with tree operations on.
struct JoinOpResult {
    enum class State { Answered, Committed, Pending } state = State::Answered;
    tree::TreeOpSubmission submission;
    std::string tunnel_ip;      ///< the committed node's address (Committed)
    api::MeshRekeyPlan rekey;   ///< dataplane changes the join implies
    bool used_link = false;     ///< the op places a new device with the link token
};

/// A device-link token that POST /api/join consumed. The token is spent only
/// when the join uses it to place a new device. The destructor restores it
/// unless keep() or settle_with() decided otherwise, so a join that is
/// refused, fails, or places no new device does not burn the token.
class LinkTokenClaim {
public:
    LinkTokenClaim(auth::AuthService& auth, std::string token, auth::LinkTokenRecord record)
        : auth_(auth), token_(std::move(token)), record_(std::move(record)) {}
    ~LinkTokenClaim() {
        if (!decided_) (void)auth_.refund_link_token(token_, record_);
    }
    LinkTokenClaim(const LinkTokenClaim&)            = delete;
    LinkTokenClaim& operator=(const LinkTokenClaim&) = delete;

    /// The join placed the device: the token stays spent.
    void keep() { decided_ = true; }

    /// The join's op is pending: the token stays spent when the op commits
    /// and is restored when it is refused. Without a ticket no outcome
    /// arrives, and the token stays spent.
    void settle_with(const tree::TreeOpSubmission& s) {
        decided_ = true;
        if (!s.ticket) return;
        s.ticket->on_settled([auth = &auth_, token = token_,
                              record = record_](const tree::TreeOpOutcome& outcome) {
            if (outcome.status != tree::TreeOpStatus::Committed) {
                (void)auth->refund_link_token(token, record);
            }
        });
    }

private:
    auth::AuthService&    auth_;
    std::string           token_;
    auth::LinkTokenRecord record_;
    bool                  decided_ = false;
};

/// True when the link token's owner still holds add_child on (or administers)
/// the target, so the invite may still place a new device there. A token
/// whose owner lost that authority after minting places nothing.
bool link_owner_may_place(const tree::PermissionTreeService& tree,
                          const auth::LinkTokenRecord& link) {
    return tree::rules::holds_or_administers(tree.nodes_snapshot(), link.group_node_id,
                                             link.owner_pubkey, acl::Permission::AddChild);
}

/// The signed grant a tree operation carries for `link`, so that every
/// replica checks the invite and refuses a second redemption of it. nullopt
/// for a token that has no signed grant (minted without replication, or by
/// an earlier release); such an op keeps the earlier rules.
std::optional<auth::LinkTokenEvent> signed_grant(const auth::LinkTokenRecord& link) {
    if (!link.grant || link.grant->signature.empty()) return std::nullopt;
    return link.grant;
}

/// HTTP status for a refused tree operation in the membership and move routes.
int status_for_refusal(tree::TreeOpRefusal refusal) {
    using R = tree::TreeOpRefusal;
    switch (refusal) {
        case R::NotFound:         return 404;
        case R::Forbidden:        return 403;
        case R::Invalid:          return 400;
        case R::Conflict:         return 409;
        case R::StaleBaseVersion: return 409;
        case R::Unavailable:      return 503;
        default:                  return 500;
    }
}

/// HTTP status for a refused direct-write assignment, invite, or move.
int status_for_change(tree::PermissionTreeService::AssignmentChange change) {
    using Change = tree::PermissionTreeService::AssignmentChange;
    switch (change) {
        case Change::Applied:      return 200;
        case Change::NotFound:     return 404;
        case Change::Forbidden:    return 403;
        case Change::Invalid:      return 400;
        case Change::Conflict:     return 409;
        case Change::StorageError: return 500;
    }
    return 500;
}

/// Outcome of accepting an invite as a member.
struct MembershipOutcome {
    int                                   status = 500;  ///< 200 applied, 202 pending, else refused
    std::string                           error;
    std::optional<tree::TreeOpSubmission> submission;   ///< set when the op is pending
};

/// Make `invitee` a member of the invite's target with the invite's
/// permissions: a direct write, or an AcceptInvite tree operation. Both apply
/// rules::invite_acceptance_refusal, so the inviter's current authority on
/// the target bounds the grant. The invitee's own nodes never move.
MembershipOutcome accept_membership(ApiContext& ctx, const std::string& invitee,
                                    const auth::LinkTokenRecord& link) {
    MembershipOutcome out;
    if (!ctx.config.tree_ops_enabled) {
        std::string reason;
        const auto change = ctx.tree.accept_invite(link.group_node_id, invitee, link.owner_pubkey,
                                                   link.permissions, reason);
        out.status = status_for_change(change);
        out.error = std::move(reason);
        return out;
    }
    if (!ctx.tree_ops) {
        spdlog::error("[TreeApi] tree_ops_enabled is set but no tree-op submitter is wired");
        out.error = "tree operations unavailable";
        return out;
    }
    tree::TreeOp op;
    op.kind = tree::TreeOpKind::AcceptInvite;
    op.target = link.group_node_id;
    op.principal = invitee;
    op.body.source = tree::TreeOpSource::Session;
    op.body.inviter = link.owner_pubkey;
    op.body.invite_permissions = link.permissions;
    op.body.link_extension = true;
    op.body.invite_grant = signed_grant(link);
    auto s = submit_rebased(*ctx.tree_ops, [&] {
        const auto current = ctx.tree.get_node(op.target);
        op.base_version = current ? current->version : 0;
        return op;
    });
    if (s.pending) {
        out.status = 202;
        out.submission = std::move(s);
        return out;
    }
    out.status = s.verdict.ok() ? 200 : status_for_refusal(s.verdict.refusal);
    out.error = s.verdict.reason;
    return out;
}

/// The response body part that reports a membership outcome.
nlohmann::json membership_json(const MembershipOutcome& outcome,
                               const auth::LinkTokenRecord& link) {
    nlohmann::json j = {{"node_id", link.group_node_id}, {"permissions", link.permissions}};
    if (outcome.status == 200) {
        j["status"] = "member";
    } else if (outcome.status == 202 && outcome.submission) {
        j["status"] = "pending";
        j["op_id"] = outcome.submission->op_id;
    } else {
        j["status"] = "refused";
        j["error"] = outcome.error;
    }
    return j;
}

/// The tree part of POST /api/join with tree operations on: the direct path's
/// placement checks, then one Join op. The op's apply step derives the tunnel
/// address from the tree (tree::derive_tunnel_address), so every replica
/// assigns the same address and no IPAM allocation runs. Answered means an
/// error response was written.
JoinOpResult join_via_tree_op(ApiContext& ctx, httplib::Response& res,
                              const nlohmann::json& body, const std::string& node_id,
                              const std::string& norm_pubkey,
                              const std::optional<auth::LinkTokenRecord>& link,
                              const std::string& cpu_id, const std::string& net_mac,
                              const std::string& node_region, bool is_inference,
                              bool is_root_owner) {
    JoinOpResult result;
    auto* submitter = tree_op_submitter(ctx, res);
    if (!submitter) return result;

    const auto existing = ctx.tree.get_node(node_id);
    if (!existing) {
        if (link) {
            if (!ctx.tree.get_node(link->group_node_id)) {
                error_response(res, "link token group no longer exists", 409);
                return result;
            }
            if (!link_owner_may_place(ctx.tree, *link)) {
                error_response(res, "the invite is no longer valid", 403);
                return result;
            }
        } else if (!ctx.config.open_registration && !is_root_owner &&
                   !ctx.tree.get_node("customer-" + node_id)) {
            error_response(res, "registration closed — link token required", 403);
            return result;
        }
    }

    tree::TreeOp op;
    op.kind = tree::TreeOpKind::Join;
    op.target = node_id;
    op.principal = norm_pubkey;
    op.body.source = tree::TreeOpSource::Device;
    auto& js = op.body.join;
    js.device_pubkey = norm_pubkey;
    js.challenge = body.value("challenge", std::string{});
    js.challenge_signature = body.value("signature", std::string{});
    js.hostname_present = body.contains("hostname");
    if (js.hostname_present) js.hostname = body.value("hostname", std::string{});
    js.mesh_pubkey_present = body.contains("mesh_pubkey");
    js.mesh_pubkey = body.value("mesh_pubkey", std::string{});
    js.cpu_id = cpu_id;
    js.net_mac = net_mac;
    js.region = node_region;
    js.is_inference = is_inference;
    if (!existing && link) {
        js.link_group_id = link->group_node_id;
        js.link_owner_pubkey = link->owner_pubkey;
        op.body.link_extension = true;
        op.body.invite_grant = signed_grant(*link);
    }

    auto answer_refusal = [&](const tree::TreeOpVerdict& v) {
        switch (v.refusal) {
            case tree::TreeOpRefusal::Conflict:
                error_response(res, v.reason, 409);
                break;
            case tree::TreeOpRefusal::NotFound:
                error_response(res,
                    "application root not established — root initialization is unavailable",
                    409);
                break;
            case tree::TreeOpRefusal::Unavailable:
                error_response(res, v.reason, 503);
                break;
            default:
                spdlog::warn("[Join] tree op for {} refused: {}", node_id, v.reason);
                error_response(res, "tree operation refused", 500);
                break;
        }
    };

    // Same re-key decision as the direct path, made from the stored node
    // before the op (a new node "stores" the key this join carries).
    auto plan_rekey = [&](const std::optional<tree::TreeNode>& before,
                          const std::string& new_ip) {
        const std::string prev_ip = before ? before->tunnel_ip : std::string{};
        const std::string prev_mesh = before ? before->mesh_pubkey : js.mesh_pubkey;
        const std::string new_mesh = js.mesh_pubkey_present ? js.mesh_pubkey : prev_mesh;
        return api::plan_mesh_rekey(prev_ip, new_ip, prev_mesh, new_mesh);
    };

    // A returning device whose join changes nothing needs no op.
    if (existing && !existing->tunnel_ip.empty()) {
        op.base_version = existing->version;
        tree::TreeOpEffect effect;
        if (tree::plan_op(op, ctx.tree.nodes_snapshot(), effect).ok() &&
            effect.writes.empty() && effect.removals.empty()) {
            result.state = JoinOpResult::State::Committed;
            result.tunnel_ip = existing->tunnel_ip;
            result.rekey = plan_rekey(existing, existing->tunnel_ip);
            return result;
        }
    }

    for (int attempt = 0;; ++attempt) {
        // A concurrent join of the same device may have written the node
        // since the last read; the op then applies as a returning-device join.
        const auto current = attempt == 0 ? existing : ctx.tree.get_node(node_id);
        op.base_version = current ? current->version : 0;
        auto s = submitter->submit(op);
        if (s.pending) {
            result.state = JoinOpResult::State::Pending;
            result.submission = std::move(s);
            result.rekey = plan_rekey(current, {});
            result.used_link = !js.link_group_id.empty();
            return result;
        }
        if (s.verdict.ok()) {
            result.used_link = !js.link_group_id.empty();
            const auto after = ctx.tree.get_node(node_id);
            if (!after || after->tunnel_ip.empty()) {
                error_response(res, "IP allocation failed", 409);
                return result;
            }
            result.state = JoinOpResult::State::Committed;
            result.tunnel_ip = after->tunnel_ip;
            result.rekey = plan_rekey(current, after->tunnel_ip);
            result.submission = std::move(s);
            return result;
        }
        if (s.verdict.refusal != tree::TreeOpRefusal::StaleBaseVersion ||
            attempt + 1 >= kStaleBaseAttempts) {
            answer_refusal(s.verdict);
            return result;
        }
    }
}

} // namespace

// Only applied tree operations call the hook, and with tree operations off no
// operation is applied, so the direct routes' own cleanup never runs twice.
TreeApiHandler::TreeApiHandler(ApiContext& ctx) : ctx_(ctx) {
    ctx_.tree.set_removed_nodes_hook(
        [this](const std::vector<tree::TreeNode>& removed) { cleanup_removed_nodes(removed); });
}

TreeApiHandler::~TreeApiHandler() {
    ctx_.tree.set_removed_nodes_hook({});
}

void TreeApiHandler::cleanup_removed_nodes(const std::vector<tree::TreeNode>& removed) {
    for (const auto& node : removed) cascade_node_cleanup(node.id, node);
}

// Post-delete cascade shared by the direct-delete and delta-delete routes and,
// with tree operations on, by the committed-removal hook, so every path stays
// behaviorally identical. Failures follow the direct route's existing
// conventions: IPAM release results are ignored, and peer/DNS removal is
// logged on success only.
void TreeApiHandler::cascade_node_cleanup(const std::string& node_id,
                                          const std::optional<tree::TreeNode>& doomed) {
    if (!doomed) return;
    // 1. Revoke the device's Ed25519 credential so a deleted device
    //    cannot silently auto-re-register (node_id is key-deterministic).
    //    Owner-protection: an owner's key is the mgmt_pubkey of their
    //    customer group AND every sibling endpoint, so deleting ONE of
    //    their own devices must NOT blocklist that shared key. Only revoke
    //    a key that no surviving node still owns — i.e. a linked-device
    //    key, which owns only the endpoint just deleted.
    if (!doomed->mgmt_pubkey.empty() &&
        !ctx_.tree.is_mgmt_pubkey_in_use(doomed->mgmt_pubkey)) {
        ctx_.auth.revoke_ed25519(
            std::string(strip_ed25519_prefix(doomed->mgmt_pubkey)));
    }
    // 2. Release the node's IP allocations back to the pools.
    (void)ctx_.ipam.release(node_id, ipam::BlockType::Tunnel);
    (void)ctx_.ipam.release(node_id, ipam::BlockType::Private);
    (void)ctx_.ipam.release(node_id, ipam::BlockType::Shared);
    // 3. Remove the mesh peer using the join-time key conversion.
    if (ctx_.boringtun && !doomed->mesh_pubkey.empty()) {
        // Same Ed25519->Curve25519 conversion the join route performs; the
        // stored key must match the dataplane peer key byte-for-byte.
        const auto peer_mesh_key = api::normalize_mesh_pubkey(doomed->mesh_pubkey);
        if (ctx_.boringtun->remove_peer(peer_mesh_key)) {
            spdlog::info("[TreeApi] removed mesh peer for deleted node '{}'", node_id);
        }
    }
    // 4. Remove the private EP A record registered at join; otherwise the
    //    stale record keeps serving a tunnel IP IPAM has already recycled
    //    (it could resolve to a different, live node). Best-effort like the
    //    other steps: absence is fine, a failure never aborts the cascade.
    if (ctx_.dns) {
        if (ctx_.dns->remove_record(client_ep_fqdn(node_id, ctx_.config.dns_base_domain), "A")) {
            spdlog::info("[TreeApi] removed private EP DNS record for deleted node '{}'",
                         node_id);
        }
    }
    // 5. Remove the stored certificate that this server issued for the node,
    //    so the next owner of the name gets a new key. The group loopback
    //    names stop resolving with the group itself (DnsService reads the
    //    tree). A device certificate stays while another endpoint still uses
    //    the hostname.
    const auto& base_domain = ctx_.config.dns_base_domain;
    if (!base_domain.empty()) {
        if (doomed->type == tree::NodeType::Customer) {
            const auto wildcard = network::group_loopback_wildcard(doomed->id, base_domain);
            if (!wildcard.empty()) (void)ctx_.acme.remove_certificate(wildcard);
        } else if (doomed->type == tree::NodeType::Endpoint && !doomed->hostname.empty()) {
            const auto lower = [](std::string s) {
                std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                return s;
            };
            const auto hostname = lower(doomed->hostname);
            bool still_used = false;
            for (const auto& node : ctx_.tree.get_nodes_by_type(tree::NodeType::Endpoint)) {
                if (node.id != node_id && lower(node.hostname) == hostname) {
                    still_used = true;
                    break;
                }
            }
            if (!still_used) {
                (void)ctx_.acme.remove_certificate(doomed->hostname + ".capi." + base_domain);
            }
        }
    }
}

std::string TreeApiHandler::finish_join_dataplane(const std::string& node_id,
                                                  const std::string& tunnel_cidr,
                                                  const std::string& client_mesh_pubkey,
                                                  bool remove_stale_peer,
                                                  const std::string& stale_peer_key) {
    // Add the client as a mesh peer on the server interface.
    if (ctx_.boringtun && !client_mesh_pubkey.empty() && !tunnel_cidr.empty()) {
        auto peer_mesh_key = api::normalize_mesh_pubkey(client_mesh_pubkey);

        // Re-join with a rotated key: drop the stale peer first, or its
        // allowed_ips route shadows the new key and return traffic is
        // encrypted to a dead handshake.
        if (remove_stale_peer && ctx_.boringtun->remove_peer(stale_peer_key)) {
            spdlog::info("[Join] removed stale mesh peer {} for node {}",
                         stale_peer_key.substr(0, 12), node_id);
        }

        if (ctx_.boringtun->add_peer(peer_mesh_key, tunnel_cidr, "")) {
            spdlog::info("[Join] added mesh peer {} allowed_ips={}",
                         peer_mesh_key.substr(0, 12), tunnel_cidr);
        } else {
            spdlog::warn("[Join] failed to add mesh peer for node {}", node_id);
        }
    }

    // Register private DNS for this client: private.<node_id>.ep.<domain> -> tunnel IP
    std::string client_tunnel_ip_bare = tunnel_cidr;
    if (auto slash = client_tunnel_ip_bare.find('/'); slash != std::string::npos) {
        client_tunnel_ip_bare = client_tunnel_ip_bare.substr(0, slash);
    }
    std::string client_private_fqdn;
    if (ctx_.dns && !client_tunnel_ip_bare.empty()) {
        client_private_fqdn = client_ep_fqdn(node_id, ctx_.config.dns_base_domain);
        ctx_.dns->set_record(client_private_fqdn, "A", client_tunnel_ip_bare, 300);
        spdlog::info("[Join] registered DNS: {} -> {}", client_private_fqdn, client_tunnel_ip_bare);
    }
    return client_private_fqdn;
}

void TreeApiHandler::do_register_routes(httplib::Server& pub, httplib::Server& priv) {
    using nexus::auth::require_auth;
    using nexus::auth::SessionClaims;

    // ========================================================================
    // POST /api/join (PUBLIC, no auth)
    // Composite bootstrap endpoint: authenticate, create node, allocate tunnel
    // IP, return mesh config.
    // ========================================================================
    pub.Post("/api/join", [this](const httplib::Request& req, httplib::Response& res) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        // The joining device's key becomes its node's management key and every
        // permission principal, so the join must prove the device holds it.
        // Only the ed25519 method verifies body.pubkey against a challenge
        // signature; with password, passkey, or token-link, body.pubkey is
        // whatever the caller wrote.
        if (body.value("method", std::string{}) != "ed25519") {
            error_response(res,
                "joining requires the ed25519 method: sign the server challenge "
                "with the device key", 403);
            return;
        }

        auto auth_result = ctx_.auth.authenticate(body);
        if (!auth_result.authenticated) {
            error_response(res, "authentication failed", 401);
            return;
        }

        auto client_pubkey = body.value("public_key", "");
        if (client_pubkey.empty()) {
            error_response(res, "public_key required");
            return;
        }

        // public_key drives mgmt_pubkey, every ACL principal, and the
        // is_root_owner check — it MUST be the Ed25519-authenticated identity,
        // not an unverified body field. Bind it to body.pubkey (already verified
        // against the challenge signature by ctx_.auth.authenticate above).
        {
            const auto claimed_b64 = strip_ed25519_prefix(client_pubkey);
            bool matches = false;
            try {
                matches = crypto::from_base64(claimed_b64) ==
                          crypto::from_base64(body.value("pubkey", std::string{}));
            } catch (...) {
                matches = false;
            }
            if (!matches) {
                error_response(res,
                    "public_key does not match authenticated identity", 403);
                return;
            }
        }

        auto node_id = auth_result.user_id;
        if (node_id.empty()) {
            node_id = "node-" + client_pubkey.substr(0, 16);
        }

        // Normalize pubkey to "ed25519:base64..." format for tree storage
        auto norm_pubkey = normalize_pubkey(client_pubkey);

        // A mesh transport key binds to one node identity. The Ed25519 challenge
        // authenticated WHO is joining; this guard decides what that identity
        // may claim: its own identity-bound static (possession proved
        // transitively through the challenge), its previously registered key,
        // or a fresh opaque one — never a key another node registered, and
        // never another enrolled identity's bound form. Checked before any
        // tree write or dataplane change, so a hostile claim moves no route.
        if (const auto advertised = body.value("mesh_pubkey", std::string{});
            !advertised.empty()) {
            if (const auto refusal =
                    api::mesh_key_claim_refusal(ctx_.tree, advertised, node_id, norm_pubkey)) {
                error_response(res, *refusal, 409);
                return;
            }
        }

        // Optional link token (single use, minted via POST /api/link/token):
        // places a new endpoint under the token's target group, or makes an
        // existing device's identity a member of that group. Consuming it first
        // stops two concurrent joins from both using it; link_claim restores
        // it unless this join uses it.
        auto link_token = body.value("link_token", std::string{});
        std::optional<auth::LinkTokenRecord> link;
        std::optional<LinkTokenClaim> link_claim;
        if (!link_token.empty()) {
            link = ctx_.auth.consume_link_token(link_token);
            if (!link) {
                error_response(res, "invalid or expired link token", 403);
                return;
            }
            link_claim.emplace(ctx_.auth, link_token, *link);
        }

        // cpu_id/net_mac are self-reported label seeds (not security controls).
        auto cpu_id       = body.value("cpu_id", std::string{});
        auto net_mac      = body.value("net_mac", std::string{});
        auto node_region  = body.value("region", std::string{});
        bool is_inference = body.value("is_inference", false);
        auto endpoint_identifier = routing::derive_endpoint_identifier(
                node_id, node_region, cpu_id, net_mac, is_inference);

        auto stamp_endpoint_identity = [&](tree::TreeNode& n) {
            n.endpoint_identifier = endpoint_identifier;
            n.cpu_id              = cpu_id;
            n.net_mac             = net_mac;
            n.region              = node_region;
            n.is_inference        = is_inference;
        };

        // Root initialization is deferred: no public caller may create the
        // application root, and this endpoint never modifies an existing
        // root's data or assignments. Ownership below is pure validation of
        // the stored root record for the closed-registration exemption.
        const auto existing_root = ctx_.tree.get_node("root");
        if (!existing_root) {
            error_response(res,
                "application root not established — root initialization is unavailable",
                409);
            return;
        }
        const bool is_root_owner = !existing_root->mgmt_pubkey.empty() &&
            tree::canonical_principal(existing_root->mgmt_pubkey) ==
            tree::canonical_principal(norm_pubkey);

        // A device that already joined does not move: its link token is an
        // invite to become a member of the token's group. The join below then
        // runs as a returning-device join without the token. A refused
        // membership does not fail the join, and link_claim restores the token.
        std::optional<nlohmann::json> membership;
        if (link && ctx_.tree.get_node(node_id)) {
            const auto outcome = accept_membership(ctx_, norm_pubkey, *link);
            membership = membership_json(outcome, *link);
            if (outcome.status == 200) {
                link_claim->keep();
            } else if (outcome.status == 202 && outcome.submission) {
                link_claim->settle_with(*outcome.submission);
            }
            link.reset();
        }

        if (!ctx_.config.tree_ops_enabled && node_id != "root") {
            std::string customer_id;
            auto existing_endpoint = ctx_.tree.get_node(node_id);

            if (existing_endpoint) {
                // Returning device — keep its current placement (a linked device
                // must not be reparented into a fresh group of its own).
                customer_id = existing_endpoint->parent_id;
            } else if (link) {
                // Linked join — place the device under the token's target group.
                customer_id = link->group_node_id;
                if (!ctx_.tree.get_node(customer_id)) {
                    error_response(res, "link token group no longer exists", 409);
                    return;
                }
                if (!link_owner_may_place(ctx_.tree, *link)) {
                    error_response(res, "the invite is no longer valid", 403);
                    return;
                }
            } else {
                // Under closed registration a brand-new identity needs a link
                // token — except the root owner, who bootstraps their own
                // account (their key already owns root via /api/auth).
                if (!ctx_.config.open_registration && !is_root_owner &&
                    !ctx_.tree.get_node("customer-" + node_id)) {
                    error_response(res, "registration closed — link token required", 403);
                    return;
                }

                // Returning or new user — find or create their Customer group
                customer_id = "customer-" + node_id;
                auto existing_customer = ctx_.tree.get_node(customer_id);
                if (!existing_customer) {
                    tree::TreeNode customer_node;
                    customer_node.id          = customer_id;
                    customer_node.parent_id   = "root";
                    customer_node.type        = tree::NodeType::Customer;
                    customer_node.hostname    = body.value("hostname",
                                                           "group-" + node_id.substr(0, 8));
                    customer_node.mgmt_pubkey = norm_pubkey;
                    customer_node.assignments = {{
                        .management_pubkey = norm_pubkey,
                        .permissions = {"read", "write", "add_child", "delete_node",
                                        "edit_node", "admin"},
                    }};
                    ctx_.tree.insert_join_node(customer_node);
                }
            }

            // The group creator administers the group: only an admin may change
            // assignments, so an owner without it could not manage members.
            // Groups created before that rule gain it on the owner's next join.
            if (auto group = ctx_.tree.get_node(customer_id);
                group && group->type == tree::NodeType::Customer &&
                tree::canonical_principal(group->mgmt_pubkey) ==
                    tree::canonical_principal(norm_pubkey)) {
                auto upgraded = *group;
                bool changed = false;
                for (auto& a : upgraded.assignments) {
                    if (tree::canonical_principal(a.management_pubkey) !=
                        tree::canonical_principal(norm_pubkey)) continue;
                    if (std::find(a.permissions.begin(), a.permissions.end(), "admin") ==
                        a.permissions.end()) {
                        a.permissions.push_back("admin");
                        changed = true;
                    }
                }
                if (changed && ctx_.tree.update_node_direct(customer_id, upgraded)) {
                    spdlog::info("[Join] group owner now administers {}", customer_id);
                }
            }

            if (!existing_endpoint) {
                // Create Endpoint under the Customer group
                tree::TreeNode endpoint_node;
                endpoint_node.id          = node_id;
                endpoint_node.parent_id   = customer_id;
                endpoint_node.type        = tree::NodeType::Endpoint;
                endpoint_node.hostname    = body.value("hostname",
                                                       "endpoint-" + node_id.substr(0, 8));
                endpoint_node.mgmt_pubkey = norm_pubkey;
                // Explicit ACL grant for the endpoint's owner. Heartbeat authorizes
                // via ownership, but node-scoped reads (GET /api/mesh/peers/<node>,
                // /api/mesh/status/<node>) require an explicit Read permission on the
                // node; without this assignment they 403. Mirrors the Customer grant
                // so the owner has full control of their own endpoint.
                if (link) {
                    // The device manages itself; the group owner keeps control.
                    endpoint_node.assignments = {
                        {.management_pubkey = norm_pubkey,
                         .permissions = {"read", "write", "edit_node"}},
                        {.management_pubkey = link->owner_pubkey,
                         .permissions = {"read", "write", "add_child", "delete_node",
                                         "edit_node"}},
                    };
                } else {
                    endpoint_node.assignments = {{
                        .management_pubkey = norm_pubkey,
                        .permissions = {"read", "write", "add_child", "delete_node",
                                        "edit_node"},
                    }};
                }
                endpoint_node.mesh_pubkey = body.value("mesh_pubkey", std::string{});
                stamp_endpoint_identity(endpoint_node);
                if (!ctx_.tree.insert_join_node(endpoint_node)) {
                    error_response(res, "endpoint identifier conflict", 409);
                    return;
                }

                if (link) {
                    link_claim->keep();
                    // Pairwise grants so devices in the group can list and dial
                    // each other (peer reads and connects check the sibling
                    // node). A sibling's key can already hold an entry on the
                    // new device (the group owner's always does), so the grant
                    // completes that entry instead of skipping it; the same
                    // rule as the Join operation.
                    const auto grant_peer = [this](const std::string& id,
                                                   const std::string& principal) {
                        auto node = ctx_.tree.get_node(id);
                        if (node && tree::rules::grant_link_peer_access(*node, principal)) {
                            (void)ctx_.tree.update_node_direct(id, *node);
                        }
                    };
                    for (const auto& sibling : ctx_.tree.get_children(customer_id)) {
                        if (sibling.type != tree::NodeType::Endpoint ||
                            sibling.id == node_id) {
                            continue;
                        }
                        if (!sibling.mgmt_pubkey.empty()) {
                            grant_peer(node_id, sibling.mgmt_pubkey);
                        }
                        grant_peer(sibling.id, norm_pubkey);
                    }
                    // Let the device read its group node
                    ctx_.tree.grant_assignment(customer_id, {
                        .management_pubkey = norm_pubkey,
                        .permissions       = {"read"},
                    });
                    spdlog::info("[Join] linked device {} into group {} (owner {})",
                                 node_id, customer_id, link->owner_user_id);
                }
            }
        }

        ipam::Allocation alloc;
        api::MeshRekeyPlan rekey;
        if (ctx_.config.tree_ops_enabled) {
            auto joined = join_via_tree_op(ctx_, res, body, node_id, norm_pubkey, link, cpu_id,
                                           net_mac, node_region, is_inference, is_root_owner);
            if (joined.used_link) {
                if (joined.state == JoinOpResult::State::Pending) {
                    link_claim->settle_with(joined.submission);
                } else {
                    link_claim->keep();
                }
            }
            if (joined.state == JoinOpResult::State::Answered) return;
            if (joined.state == JoinOpResult::State::Pending) {
                // The tunnel address exists only once the join commits; the
                // client joins again to learn it (a returning-device join).
                // The dataplane and DNS steps run when the commit arrives.
                after_commit(joined.submission,
                             [this, node_id, mesh = body.value("mesh_pubkey", std::string{}),
                              rekey = joined.rekey] {
                                 const auto node = ctx_.tree.get_node(node_id);
                                 if (node && !node->tunnel_ip.empty()) {
                                     (void)finish_join_dataplane(node_id, node->tunnel_ip, mesh,
                                                                 rekey.remove_stale_peer,
                                                                 rekey.stale_peer_key);
                                 }
                             });
                nlohmann::json pending = {{"success", true},
                                          {"status", "pending"},
                                          {"op_id", joined.submission.op_id},
                                          {"node_id", node_id}};
                if (membership) pending["membership"] = *membership;
                json_response(res, pending, 202);
                return;
            }
            alloc.block_type = ipam::BlockType::Tunnel;
            alloc.base_network = joined.tunnel_ip;
            alloc.customer_node_id = node_id;
            rekey = joined.rekey;
        } else {
            // Allocate tunnel IP (returns existing if already allocated for this node)
            alloc = ctx_.ipam.allocate_tunnel_ip(node_id);

            // Decide what this (re)join does to the stored node and the dataplane
            // peer. On a re-join the IP is unchanged but the key may have rotated;
            // plan_mesh_rekey rewrites the node when either changed and identifies
            // the stale peer to drop below (see MeshRekey.hpp).
            if (!alloc.base_network.empty()) {
                auto existing_node = ctx_.tree.get_node(node_id);
                if (existing_node) {
                    auto new_mesh_pubkey = body.value("mesh_pubkey", existing_node->mesh_pubkey);
                    rekey = api::plan_mesh_rekey(existing_node->tunnel_ip, alloc.base_network,
                                                 existing_node->mesh_pubkey, new_mesh_pubkey);
                    if (rekey.update_node) {
                        tree::TreeNode updated = *existing_node;
                        updated.tunnel_ip = alloc.base_network;
                        updated.mesh_pubkey = new_mesh_pubkey;
                        ctx_.tree.update_node_direct(node_id, updated);
                    }
                }
            }
        }
        if (alloc.base_network.empty()) {
            error_response(res, "IP allocation failed", 409);
            return;
        }

        // Convert server's Ed25519 identity key to Curve25519 (X25519) for the mesh
        std::string mesh_server_pubkey;
        if (auto ed_pk = ctx_.key_wrapping.load_identity_pubkey()) {
            auto x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(*ed_pk);
            mesh_server_pubkey = crypto::to_base64(
                std::span<const uint8_t>(x_pk.data(), x_pk.size()));
        }

        std::string server_tunnel = ctx_.tunnel_bind_ip.empty()
                                        ? "10.64.0.1"
                                        : ctx_.tunnel_bind_ip;

        // Add the client as a mesh peer and register its private DNS name.
        const std::string client_private_fqdn =
            finish_join_dataplane(node_id, alloc.base_network,
                                  body.value("mesh_pubkey", std::string{}),
                                  rekey.remove_stale_peer, rekey.stale_peer_key);

        // Build the mesh endpoint: public_ip:udp_port
        std::string mesh_endpoint;
        if (!ctx_.server_public_ip.empty()) {
            mesh_endpoint = ctx_.server_public_ip + ":" + std::to_string(ctx_.config.udp_port);
        }

        nlohmann::json resp = {
            {"token",            auth_result.session_token},
            {"node_id",          node_id},
            {"endpoint_identifier", endpoint_identifier},
            {"tunnel_ip",        alloc.base_network},
            {"tunnel_subnet",    "10.64.0.0/10"},
            {"server_tunnel_ip", server_tunnel},
            {"server_seip_fqdn",    ctx_.server_seip_fqdn},
            {"server_private_fqdn", ctx_.server_private_fqdn},
            {"client_private_fqdn", client_private_fqdn},
            {"private_api_port", !ctx_.tunnel_bind_ip.empty()
                                     ? ctx_.config.private_http_port
                                     : ctx_.config.http_port},
            {"mesh_server_pubkey", mesh_server_pubkey},
            {"mesh_endpoint",      mesh_endpoint},
            {"dns_servers",      nlohmann::json::array({server_tunnel})},
        };
        if (membership) resp["membership"] = *membership;
        spdlog::info("[Join] node={} tunnel_ip={} mesh_endpoint={} private_fqdn={}",
                      node_id, alloc.base_network, mesh_endpoint, client_private_fqdn);
        json_response(res, resp);
    });

    // ========================================================================
    // GET /api/tree/node/{id} (PRIVATE, auth required)
    // ========================================================================
    priv.Get(R"(/api/tree/node/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto node_id = req.matches[1].str();
        auto caller_pubkey = normalize_pubkey(claims.pubkey);
        // Gate the read on an explicit Read grant scoped to this node, or on
        // administering it (admin on the node or an ancestor group).
        const bool administers = ctx_.tree.administers(caller_pubkey, node_id);
        if (!administers && !ctx_.tree.check_permission(caller_pubkey, node_id,
                                                        acl::Permission::Read)) {
            error_response(res, "no read permission", 403);
            return;
        }
        auto node = ctx_.tree.get_node(node_id);
        if (!node) {
            error_response(res, "node not found", 404);
            return;
        }
        // Management readers get the full ACL (needed for read-modify-write
        // group edits); everyone else sees only their own assignment.
        bool full_acl = administers || ctx_.tree.check_permission(caller_pubkey, node_id,
                                                                  acl::Permission::EditNode);
        json_response(res, redact_node_for_caller(*node, caller_pubkey, full_acl));
    }));

    // ========================================================================
    // POST /api/tree/delta (PRIVATE, auth required)
    // ========================================================================
    priv.Post("/api/tree/delta", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        tree::TreeDelta delta;
        try {
            delta = body.get<tree::TreeDelta>();
        } catch (...) {
            // Typed parse is the single source of truth for delta bodies;
            // anything it rejects is rejected here (fail closed).
            error_response(res, "invalid delta body", 400);
            return;
        }

        // Two-plane agreement: the authenticated session identity must be the
        // delta signer. apply_delta authorizes on delta.signer_pubkey's tree
        // assignments plus a signature the caller claims to possess, so without
        // this check any session holder could submit deltas signed with another
        // principal's key (e.g. a captured management key). Compare by key bytes
        // (canonical_principal), same as do_apply_delta.
        if (delta.signer_pubkey.empty() ||
            tree::canonical_principal(normalize_pubkey(claims.pubkey)) !=
                tree::canonical_principal(delta.signer_pubkey)) {
            spdlog::warn("[TreeApi] delta signer does not match authenticated session");
            error_response(res, "delta signer does not match session", 403);
            return;
        }

        bool ok = false;
        if (ctx_.config.tree_ops_enabled) {
            // The committed-removal hook runs the post-delete cascade on every
            // server that applies the delete (cleanup_removed_nodes).
            auto* submitter = tree_op_submitter(ctx_, res);
            if (!submitter) return;
            const auto s = submit_delta_op(*submitter, ctx_.tree, delta);
            if (answer_unfinished(res, s)) return;
            ok = s.verdict.ok();
        } else {
            // Pre-delete snapshot so the post-delete cascade (credential
            // revocation, IPAM release, mesh peer removal) has the node's
            // identity and keys.
            const std::optional<tree::TreeNode> doomed =
                (delta.operation == "delete_node" && !delta.target_node_id.empty())
                    ? ctx_.tree.get_node(delta.target_node_id)
                    : std::nullopt;
            ok = ctx_.tree.apply_delta(delta);
            if (ok && doomed) cascade_node_cleanup(delta.target_node_id, doomed);
        }
        network::DeltaResponse resp{.success = ok};
        if (!ok) resp.error = "delta rejected";
        nlohmann::json j = resp;
        json_response(res, j, ok ? 200 : 403);
    }));

    // ========================================================================
    // GET /api/tree/children/{id} (PRIVATE, auth required)
    // ========================================================================
    priv.Get(R"(/api/tree/children/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto parent_id = req.matches[1].str();
        auto caller_pubkey = normalize_pubkey(claims.pubkey);
        // Gate enumeration on a Read grant on the parent node.
        if (!ctx_.tree.check_permission(caller_pubkey, parent_id,
                                         acl::Permission::Read)) {
            error_response(res, "no read permission", 403);
            return;
        }
        nlohmann::json j = nlohmann::json::array();
        for (const auto& child : ctx_.tree.get_children(parent_id)) {
            bool full_acl = ctx_.tree.administers(caller_pubkey, child.id) ||
                            ctx_.tree.check_permission(caller_pubkey, child.id,
                                                       acl::Permission::EditNode);
            j.push_back(redact_node_for_caller(child, caller_pubkey, full_acl));
        }
        json_response(res, j);
    }));

    // ========================================================================
    // POST /api/tree/node (PRIVATE, auth required)
    // Create a child node. Server handles ID generation and persistence.
    // ========================================================================
    priv.Post("/api/tree/node", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        auto parent_id = body.value("parent_id", std::string{"root"});
        auto type_str  = body.value("type", std::string{"endpoint"});
        auto hostname  = body.value("hostname", std::string{});

        // Normalize pubkey for tree comparison (JWT stores raw base64,
        // tree assignments use "ed25519:" prefix)
        auto caller_pubkey = normalize_pubkey(claims.pubkey);

        // Check AddChild permission on the parent
        if (!ctx_.tree.check_permission(caller_pubkey, parent_id,
                                         acl::Permission::AddChild)) {
            error_response(res, "no add_child permission on parent", 403);
            return;
        }

        tree::TreeNode node;
        node.parent_id   = parent_id;
        node.mgmt_pubkey = caller_pubkey;

        if (type_str == "endpoint")  node.type = tree::NodeType::Endpoint;
        else if (type_str == "customer") node.type = tree::NodeType::Customer;
        else if (type_str == "relay")    node.type = tree::NodeType::Relay;
        else {
            error_response(res, "invalid type");
            return;
        }

        // Generate node ID from pubkey. Standard base64 can contain '/', which
        // no node file name may hold, so use the URL-safe alphabet.
        auto pubkey_short = claims.pubkey.substr(0, std::min<size_t>(claims.pubkey.size(), 16));
        for (auto& c : pubkey_short) {
            if (c == '+') c = '-';
            else if (c == '/') c = '_';
        }
        node.id = "node-" + pubkey_short;
        if (hostname.empty()) {
            hostname = type_str + "-" + node.id.substr(0, 12);
        }
        node.hostname = hostname;

        if (const auto refusal =
                session_content_refusal(ctx_.tree, "create_node", node, caller_pubkey)) {
            error_response(res, *refusal, 403);
            return;
        }

        if (ctx_.config.tree_ops_enabled) {
            auto* submitter = tree_op_submitter(ctx_, res);
            if (!submitter) return;
            tree::TreeOp op;
            op.kind = tree::TreeOpKind::CreateNode;
            op.target = node.id;
            op.principal = caller_pubkey;
            op.body.source = tree::TreeOpSource::Session;
            op.body.node = node;
            const auto s = submitter->submit(std::move(op));
            if (answer_unfinished(res, s)) return;
            const auto& v = s.verdict;
            // The direct path treats an existing node as success; keep that.
            if (!v.ok() && v.refusal != tree::TreeOpRefusal::AlreadyExists) {
                error_response(res, "node creation failed", 409);
                return;
            }
        } else if (!ctx_.tree.insert_join_node(node)) {
            error_response(res, "node creation failed", 409);
            return;
        }

        nlohmann::json resp = {
            {"success", true},
            {"node_id", node.id},
        };
        spdlog::info("[TreeApi] created node '{}' under '{}'", node.id, parent_id);
        json_response(res, resp);
    }));

    // ========================================================================
    // POST /api/tree/node/update/{id} (PRIVATE, auth required)
    // Update node fields. Server handles persistence.
    // ========================================================================
    priv.Post(R"(/api/tree/node/update/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto node_id = req.matches[1].str();
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        // Check EditNode permission (normalize pubkey format)
        if (!ctx_.tree.check_permission(normalize_pubkey(claims.pubkey), node_id,
                                         acl::Permission::EditNode)) {
            error_response(res, "no edit_node permission", 403);
            return;
        }

        auto existing = ctx_.tree.get_node(node_id);
        if (!existing) {
            error_response(res, "node not found", 404);
            return;
        }

        // Apply the partial update to a copy of a stored node. Returns the
        // mesh-key refusal, if any.
        auto apply_body = [&](tree::TreeNode& updated) -> std::optional<std::string> {
            apply_optional_field(body, "hostname", updated.hostname);
            apply_optional_field(body, "tunnel_ip", updated.tunnel_ip);
            apply_optional_field(body, "private_subnet", updated.private_subnet);
            apply_optional_field(body, "shared_domain", updated.shared_domain);
            if (body.contains("mesh_pubkey")) {
                // Same ownership rule as the join path: edit permission on this
                // node never extends to claiming a static another node holds or
                // another identity's bound form.
                const auto claimed = body.value("mesh_pubkey", std::string{});
                if (auto refusal = api::mesh_key_claim_refusal(
                        ctx_.tree, claimed, node_id, normalize_pubkey(claims.pubkey))) {
                    return refusal;
                }
                updated.mesh_pubkey = claimed;
            }
            apply_optional_field(body, "listen_endpoint", updated.listen_endpoint);
            apply_optional_field(body, "region", updated.region);
            apply_optional_field(body, "capacity_mbps", updated.capacity_mbps);
            apply_optional_field(body, "reputation_score", updated.reputation_score);
            apply_optional_field(body, "expires_at", updated.expires_at);
            return std::nullopt;
        };

        auto updated = *existing;
        if (const auto refusal = apply_body(updated)) {
            error_response(res, *refusal, 409);
            return;
        }
        // Same content rules as a tree operation: an edit_node holder that is
        // not a root admin cannot move the node's addresses.
        if (const auto refusal = session_content_refusal(ctx_.tree, "update_node", updated,
                                                         normalize_pubkey(claims.pubkey))) {
            error_response(res, *refusal, 403);
            return;
        }

        if (ctx_.config.tree_ops_enabled) {
            auto* submitter = tree_op_submitter(ctx_, res);
            if (!submitter) return;
            // A retry (stale base version) re-reads the node and re-applies
            // the request to it, as the direct path's last write would.
            tree::TreeOpSubmission s;
            auto current = existing;
            for (int attempt = 0; attempt < kStaleBaseAttempts; ++attempt) {
                if (attempt > 0) {
                    current = ctx_.tree.get_node(node_id);
                    if (!current) break;
                    updated = *current;
                    if (const auto refusal = apply_body(updated)) {
                        error_response(res, *refusal, 409);
                        return;
                    }
                }
                tree::TreeOp op;
                op.kind = tree::TreeOpKind::UpdateFields;
                op.target = node_id;
                op.base_version = current->version;
                op.principal = normalize_pubkey(claims.pubkey);
                op.body.source = tree::TreeOpSource::Session;
                op.body.node = updated;
                op.body.node.id = node_id;
                s = submitter->submit(std::move(op));
                if (s.pending || s.verdict.refusal != tree::TreeOpRefusal::StaleBaseVersion) break;
            }
            if (!current) {
                error_response(res, "node not found", 404);
                return;
            }
            if (answer_unfinished(res, s)) return;
            const auto& v = s.verdict;
            if (v.refusal == tree::TreeOpRefusal::NotFound) {
                error_response(res, "node not found", 404);
                return;
            }
            if (!v.ok()) {
                error_response(res, "update failed", 500);
                return;
            }
        } else if (!ctx_.tree.update_node_direct(node_id, updated)) {
            error_response(res, "update failed", 500);
            return;
        }

        nlohmann::json resp = {{"success", true}, {"node_id", node_id}};
        spdlog::info("[TreeApi] updated node '{}'", node_id);
        json_response(res, resp);
    }));

    // ========================================================================
    // POST /api/tree/node/assignments/{id} (PRIVATE, auth required)
    // Body: {"pubkey": "<key>", "permissions": ["read", ...]}. Sets exactly
    // those permissions for the key on the node; an empty list removes it.
    // The tree enforces who may administer and who may be granted.
    // ========================================================================
    priv.Post(R"(/api/tree/node/assignments/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto node_id = req.matches[1].str();
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        const auto principal = body.value("pubkey", std::string{});
        if (principal.empty() || !body.contains("permissions") ||
            !body["permissions"].is_array()) {
            error_response(res, "pubkey and permissions[] required");
            return;
        }
        std::vector<std::string> permissions;
        for (const auto& p : body["permissions"]) {
            if (!p.is_string()) {
                error_response(res, "permissions must be strings");
                return;
            }
            permissions.push_back(p.get<std::string>());
        }

        if (ctx_.config.tree_ops_enabled) {
            auto* submitter = tree_op_submitter(ctx_, res);
            if (!submitter) return;
            tree::TreeOp op;
            op.kind = tree::TreeOpKind::SetAssignment;
            op.target = node_id;
            op.principal = normalize_pubkey(claims.pubkey);
            op.body.source = tree::TreeOpSource::Session;
            op.body.assignment_principal = normalize_pubkey(principal);
            op.body.assignment_permissions = permissions;
            const auto s = submit_rebased(*submitter, [&] {
                const auto current = ctx_.tree.get_node(node_id);
                op.base_version = current ? current->version : 0;
                return op;
            });
            if (answer_unfinished(res, s)) return;
            const auto& v = s.verdict;
            using R = tree::TreeOpRefusal;
            switch (v.refusal) {
                case R::None:
                    json_response(res, {{"success", true}, {"node_id", node_id}});
                    return;
                case R::NotFound:         error_response(res, v.reason, 404); return;
                case R::Forbidden:        error_response(res, v.reason, 403); return;
                case R::Invalid:          error_response(res, v.reason, 400); return;
                case R::Conflict:         error_response(res, v.reason, 409); return;
                case R::StaleBaseVersion: error_response(res, v.reason, 409); return;
                case R::StorageError:     error_response(res, v.reason, 500); return;
                default:
                    error_response(res, "tree operation refused", 500);
                    return;
            }
        }

        std::string reason;
        using Change = tree::PermissionTreeService::AssignmentChange;
        switch (ctx_.tree.set_assignment(node_id, normalize_pubkey(claims.pubkey),
                                         normalize_pubkey(principal), permissions,
                                         reason)) {
            case Change::Applied:
                json_response(res, {{"success", true}, {"node_id", node_id}});
                return;
            case Change::NotFound:     error_response(res, reason, 404); return;
            case Change::Forbidden:    error_response(res, reason, 403); return;
            case Change::Invalid:      error_response(res, reason, 400); return;
            case Change::Conflict:     error_response(res, reason, 409); return;
            case Change::StorageError: error_response(res, reason, 500); return;
        }
    }));

    // ========================================================================
    // POST /api/link/accept (PRIVATE, auth required)
    // Body: {"link_token": "lnk_..."}. The session's identity, which has
    // already joined, becomes a member of the token's target group with the
    // token's permissions. Nothing the identity owns moves. A new device uses
    // the token in POST /api/join instead. The token is spent only when the
    // membership is applied (or its tree operation commits).
    // ========================================================================
    priv.Post("/api/link/accept", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        const auto token = body_opt->value("link_token", std::string{});
        if (token.empty()) {
            error_response(res, "link_token required");
            return;
        }
        const auto invitee = normalize_pubkey(claims.pubkey);
        // Only an identity that owns a node accepts as a member; its devices
        // are the ones the membership covers.
        if (!ctx_.tree.is_mgmt_pubkey_in_use(invitee)) {
            error_response(res,
                "this identity has not joined; a new device joins with the token "
                "through /api/join", 409);
            return;
        }
        auto link = ctx_.auth.consume_link_token(token);
        if (!link) {
            error_response(res, "invalid or expired link token", 403);
            return;
        }
        LinkTokenClaim claim(ctx_.auth, token, *link);
        const auto outcome = accept_membership(ctx_, invitee, *link);
        auto j = membership_json(outcome, *link);
        if (outcome.status == 200) {
            claim.keep();
            j["success"] = true;
            json_response(res, j);
            return;
        }
        if (outcome.status == 202 && outcome.submission) {
            claim.settle_with(*outcome.submission);
            j["success"] = true;
            json_response(res, j, 202);
            return;
        }
        error_response(res, outcome.error.empty() ? "invite refused" : outcome.error,
                       outcome.status);
    }));

    // ========================================================================
    // GET /api/tree/memberships (PRIVATE, auth required)
    // The groups the session's identity belongs to: "home" groups (the
    // parent group of each device it owns, and groups it owns) and "member"
    // groups (groups it entered through an invite, or where an admin gave it
    // an entry without it having joined there). Each entry carries the
    // identity's own permissions on the group, never other principals.
    // ========================================================================
    priv.Get("/api/tree/memberships", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims& claims) {
        const auto caller = normalize_pubkey(claims.pubkey);
        const auto caller_canon = tree::canonical_principal(caller);
        const auto nodes = ctx_.tree.nodes_snapshot();

        auto own_permissions = [&](const tree::TreeNode& n) {
            std::vector<std::string> perms;
            for (const auto& a : n.assignments) {
                if (tree::canonical_principal(a.management_pubkey) != caller_canon) continue;
                perms.insert(perms.end(), a.permissions.begin(), a.permissions.end());
            }
            std::sort(perms.begin(), perms.end());
            perms.erase(std::unique(perms.begin(), perms.end()), perms.end());
            return perms;
        };

        std::map<std::string, std::string> role_of;  // group id -> role, sorted
        for (const auto& [id, n] : nodes) {
            if (tree::canonical_principal(n.mgmt_pubkey) != caller_canon) continue;
            if (n.type == tree::NodeType::Customer) {
                role_of[id] = "home";
            } else if (n.type == tree::NodeType::Endpoint) {
                auto parent = nodes.find(n.parent_id);
                if (parent != nodes.end() && parent->second.type == tree::NodeType::Customer) {
                    role_of[parent->first] = "home";
                }
            }
        }
        for (const auto& [id, n] : nodes) {
            if (n.type != tree::NodeType::Customer || role_of.contains(id)) continue;
            if (own_permissions(n).empty()) continue;
            role_of[id] = tree::rules::principal_joined_under(nodes, id, caller) ? "home"
                                                                                 : "member";
        }

        nlohmann::json list = nlohmann::json::array();
        for (const auto& [id, role] : role_of) {
            const auto& n = nodes.at(id);
            list.push_back({{"node_id", id},
                            {"hostname", n.hostname},
                            {"parent_id", n.parent_id},
                            {"owner_pubkey", n.mgmt_pubkey},
                            {"role", role},
                            {"permissions", own_permissions(n)}});
        }
        json_response(res, {{"memberships", std::move(list)}});
    }));

    // ========================================================================
    // POST /api/tree/node/move/{id} (PRIVATE, auth required)
    // Body: {"parent_id": "<group>"}. Moves a device or a subgroup under
    // another group. rules::move_refusal decides; the node keeps its id,
    // tunnel address, and own assignments, and the move adds no grant.
    // ========================================================================
    priv.Post(R"(/api/tree/node/move/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto node_id = req.matches[1].str();
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        const auto new_parent = body_opt->value("parent_id", std::string{});
        if (new_parent.empty()) {
            error_response(res, "parent_id required");
            return;
        }
        const auto caller = normalize_pubkey(claims.pubkey);

        if (ctx_.config.tree_ops_enabled) {
            auto* submitter = tree_op_submitter(ctx_, res);
            if (!submitter) return;
            tree::TreeOp op;
            op.kind = tree::TreeOpKind::MoveNode;
            op.target = node_id;
            op.principal = caller;
            op.body.source = tree::TreeOpSource::Session;
            op.body.new_parent_id = new_parent;
            const auto s = submit_rebased(*submitter, [&] {
                const auto current = ctx_.tree.get_node(node_id);
                op.base_version = current ? current->version : 0;
                return op;
            });
            if (answer_unfinished(res, s)) return;
            if (!s.verdict.ok()) {
                error_response(res, s.verdict.reason, status_for_refusal(s.verdict.refusal));
                return;
            }
        } else {
            std::string reason;
            const auto change = ctx_.tree.move_node(node_id, new_parent, caller, reason);
            if (change != tree::PermissionTreeService::AssignmentChange::Applied) {
                error_response(res, reason, status_for_change(change));
                return;
            }
        }
        spdlog::info("[TreeApi] moved node '{}' under '{}'", node_id, new_parent);
        json_response(res, {{"success", true}, {"node_id", node_id}, {"parent_id", new_parent}});
    }));

    // ========================================================================
    // POST /api/tree/node/delete/{id} (PRIVATE, auth required)
    // Delete a node. Server handles cleanup.
    // ========================================================================
    priv.Post(R"(/api/tree/node/delete/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto node_id = req.matches[1].str();

        // DeleteNode on the node itself, or an admin of the node or an ancestor
        // group (a group admin removes the group's devices). The root is never
        // removed through the API.
        const auto caller = normalize_pubkey(claims.pubkey);
        if (auto target = ctx_.tree.get_node(node_id); target && target->parent_id.empty()) {
            error_response(res, "the root node cannot be deleted", 403);
            return;
        }
        if (!ctx_.tree.check_permission(caller, node_id, acl::Permission::DeleteNode) &&
            !ctx_.tree.administers(caller, node_id)) {
            error_response(res, "no delete_node permission", 403);
            return;
        }

        if (ctx_.config.tree_ops_enabled) {
            // The committed-removal hook runs the post-delete cascade on every
            // server that applies the delete (cleanup_removed_nodes).
            auto* submitter = tree_op_submitter(ctx_, res);
            if (!submitter) return;
            tree::TreeOp op;
            op.kind = tree::TreeOpKind::DeleteNode;
            op.target = node_id;
            op.principal = normalize_pubkey(claims.pubkey);
            op.body.source = tree::TreeOpSource::Session;
            const auto s = submit_rebased(*submitter, [&] {
                const auto current = ctx_.tree.get_node(node_id);
                op.base_version = current ? current->version : 0;
                return op;
            });
            if (answer_unfinished(res, s)) return;
            if (!s.verdict.ok()) {
                error_response(res, "node not found or delete failed", 404);
                return;
            }
        } else {
            // Snapshot identity/allocations before removal so we can cascade
            // cleanup.
            const auto doomed = ctx_.tree.get_node(node_id);
            if (!ctx_.tree.delete_node_direct(node_id)) {
                error_response(res, "node not found or delete failed", 404);
                return;
            }
            cascade_node_cleanup(node_id, doomed);
        }

        nlohmann::json resp = {{"success", true}};
        spdlog::info("[TreeApi] deleted node '{}'", node_id);
        json_response(res, resp);
    }));

    // ========================================================================
    // GET /api/tree/op/{op_id} (PRIVATE, auth required)
    // Status of a tree operation this server accepted: pending, committed, or
    // refused. A client that got 202 from a write polls here (design A2).
    // The answer carries no op content, only its state.
    // ========================================================================
    priv.Get(R"(/api/tree/op/([0-9a-f]{64}))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        const auto op_id = req.matches[1].str();
        const auto outcome = ctx_.tree_op_status ? ctx_.tree_op_status(op_id) : std::nullopt;
        if (!outcome) {
            error_response(res, "unknown tree operation", 404);
            return;
        }
        nlohmann::json j = {{"op_id", op_id}};
        switch (outcome->status) {
            case tree::TreeOpStatus::Pending:
                j["status"] = "pending";
                break;
            case tree::TreeOpStatus::Committed:
                j["status"] = "committed";
                j["log_height"] = outcome->log_height;
                break;
            case tree::TreeOpStatus::Refused:
                j["status"] = "refused";
                j["reason"] = outcome->verdict.reason;
                break;
        }
        json_response(res, j);
    }));

    // ========================================================================
    // POST /api/ipam/allocate (PRIVATE, auth required)
    // ========================================================================
    priv.Post("/api/ipam/allocate", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        auto ipam_req = body.get<network::IpamAllocateRequest>();

        if (ipam_req.node_id.empty()) {
            error_response(res, "node_id required");
            return;
        }

        // Ownership + authorization: the caller must administer the target node.
        // Mirrors the delta path, which maps allocate_ip to EditNode.
        if (!ctx_.tree.check_permission(normalize_pubkey(claims.pubkey),
                                         ipam_req.node_id, acl::Permission::EditNode)) {
            error_response(res, "no allocate permission on node", 403);
            return;
        }

        // Bound block size so a single request can't drain a pool. Tunnel is a
        // fixed /32 and ignores prefix_len.
        constexpr uint8_t kMinBlockPrefix = 24; // no block larger than a /24
        constexpr uint8_t kMaxBlockPrefix = 30;
        if (ipam_req.block_type == "private" || ipam_req.block_type == "shared") {
            if (ipam_req.prefix_len < kMinBlockPrefix ||
                ipam_req.prefix_len > kMaxBlockPrefix) {
                error_response(res, "prefix_len out of range (24-30)");
                return;
            }
        }

        ipam::Allocation alloc;
        if (ipam_req.block_type == "tunnel" && ctx_.config.tree_ops_enabled) {
            // With tree operations on, the committed Join op assigns tunnel
            // addresses from the tree on every replica. A local IPAM address
            // would be known to this server only and could collide with one.
            error_response(res,
                           "tunnel addresses are assigned by the tree; join to receive one", 409);
            return;
        }
        if (ipam_req.block_type == "tunnel") {
            alloc = ctx_.ipam.allocate_tunnel_ip(ipam_req.node_id);
        } else if (ipam_req.block_type == "private") {
            alloc = ctx_.ipam.allocate_private_subnet(ipam_req.node_id,
                                                       ipam_req.prefix_len);
        } else if (ipam_req.block_type == "shared") {
            alloc = ctx_.ipam.allocate_shared_block(ipam_req.node_id,
                                                     ipam_req.prefix_len);
        } else {
            error_response(res, "invalid block_type");
            return;
        }

        bool ok = !alloc.base_network.empty();
        network::IpamAllocateResponse resp{
            .success = ok,
            .network = alloc.base_network,
            .node_id = alloc.customer_node_id,
        };
        nlohmann::json j = resp;
        json_response(res, j, ok ? 200 : 409);
    }));
}

} // namespace nexus::api
