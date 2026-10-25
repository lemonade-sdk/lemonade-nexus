#include <LemonadeNexus/Api/AccountDataApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Account/AccountDataStore.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <spdlog/spdlog.h>

#include <memory>
#include <string_view>
#include <unordered_set>

namespace nexus::api {

AccountDataApiHandler::AccountDataApiHandler(ApiContext& ctx)
    : ctx_(ctx),
      store_(std::make_shared<account::AccountDataStore>(ctx.crypto, ctx.tree, ctx.storage)) {
    // Envelopes replicate to the other servers over the backbone; the store
    // re-checks each replicated envelope against this server's tree.
    store_->set_envelope_publisher([&g = ctx_.gossip](gossip::AccountEnvelopeRecord r) {
        g.broadcast_account_envelope(std::move(r));
    });
    ctx_.gossip.set_account_envelope_sink(
        [store = store_](const gossip::AccountEnvelopeRecord& r) {
            return store->apply_replicated_envelope(r);
        });
    ctx_.tree.set_account_deleted_hook(
        [this](const tree::AccountDeletion& deletion) { cleanup_deleted_account(deletion); });
}

AccountDataApiHandler::~AccountDataApiHandler() {
    ctx_.tree.set_account_deleted_hook({});
}

// Runs on every server that applies an account deletion (the committed
// DeleteAccount operation, or the direct write on the server that served it).
// The removed-nodes hook already ran the per-node cascade (TreeApiHandler::
// cascade_node_cleanup). Each step is idempotent, so a repeated deletion
// changes nothing.
void AccountDataApiHandler::cleanup_deleted_account(const tree::AccountDeletion& deletion) {
    std::vector<std::string> groups;
    std::unordered_set<std::string> removed_ids;
    for (const auto& node : deletion.removed) {
        removed_ids.insert(node.id);
        if (node.type == tree::NodeType::Customer) groups.push_back(node.id);
    }
    const auto files = store_->purge_account(groups, deletion.swept_keys);
    const auto envelopes = ctx_.gossip.forget_account_envelopes(groups, deletion.swept_keys);

    const std::unordered_set<std::string> swept(deletion.swept_keys.begin(),
                                                deletion.swept_keys.end());
    const auto tokens = ctx_.auth.revoke_link_tokens([&](const auth::LinkTokenRecord& r) {
        return r.owner_user_id == deletion.account_id || removed_ids.contains(r.group_node_id) ||
               swept.contains(tree::canonical_principal(r.owner_pubkey));
    });
    (void)ctx_.auth.remove_passkey_credentials(deletion.account_id);

    // The account key ends with the account unless it still owns a node: the
    // root owner's key keeps the root. Revocation also ends its sessions.
    if (!ctx_.tree.is_mgmt_pubkey_in_use(deletion.principal)) {
        constexpr std::string_view prefix = "ed25519:";
        std::string_view raw = deletion.principal;
        if (raw.starts_with(prefix)) raw.remove_prefix(prefix.size());
        (void)ctx_.auth.revoke_ed25519(std::string(raw));
    }
    spdlog::info("[AccountData] cleaned up deleted account '{}': {} file(s), {} envelope(s), "
                 "{} link token(s)", deletion.account_id, files, envelopes, tokens);
}

// Thin HTTP translator over account::AccountDataStore. All authorization and
// storage logic lives in the store (context-light, unit-tested); this maps
// request → store call → {status, body}. Every route is private + auth-gated.
void AccountDataApiHandler::do_register_routes(httplib::Server& /*pub*/,
                                               httplib::Server& priv) {
    using nexus::auth::require_auth;
    using nexus::auth::SessionClaims;

    auto store = store_;

    auto reply = [](httplib::Response& res, const account::Result& r) {
        json_response(res, r.body, r.status);
    };

    // --- Encrypted chat blobs ---

    priv.Post("/api/chats", require_auth(ctx_.auth,
        [store, reply](const httplib::Request& req, httplib::Response& res,
                       const SessionClaims& claims) {
        auto body = parse_body(req, res);
        if (!body) return;
        reply(res, store->create_chat(claims.user_id, claims.pubkey, *body, req.body.size()));
    }));

    priv.Get("/api/chats", require_auth(ctx_.auth,
        [store, reply](const httplib::Request&, httplib::Response& res,
                       const SessionClaims& claims) {
        reply(res, store->list_chats(claims.user_id, claims.pubkey));
    }));

    priv.Get(R"(/api/chats/([^/]+))", require_auth(ctx_.auth,
        [store, reply](const httplib::Request& req, httplib::Response& res,
                       const SessionClaims& claims) {
        reply(res, store->get_chat(claims.user_id, claims.pubkey, req.matches[1].str()));
    }));

    // Registered before /{id} so the more specific route wins.
    priv.Post(R"(/api/chats/([^/]+)/delete)", require_auth(ctx_.auth,
        [store, reply](const httplib::Request& req, httplib::Response& res,
                       const SessionClaims& claims) {
        reply(res, store->delete_chat(claims.user_id, claims.pubkey, req.matches[1].str()));
    }));

    priv.Post(R"(/api/chats/([^/]+))", require_auth(ctx_.auth,
        [store, reply](const httplib::Request& req, httplib::Response& res,
                       const SessionClaims& claims) {
        auto body = parse_body(req, res);
        if (!body) return;
        reply(res, store->update_chat(claims.user_id, claims.pubkey,
                                      req.matches[1].str(), *body, req.body.size()));
    }));

    // --- Group-key envelopes (opaque; the server never sees the key) ---

    priv.Get("/api/account/keys/envelope", require_auth(ctx_.auth,
        [store, reply](const httplib::Request&, httplib::Response& res,
                       const SessionClaims& claims) {
        reply(res, store->get_envelope(claims.user_id, claims.pubkey));
    }));

    priv.Post("/api/account/keys/envelope", require_auth(ctx_.auth,
        [store, reply](const httplib::Request& req, httplib::Response& res,
                       const SessionClaims& claims) {
        auto body = parse_body(req, res);
        if (!body) return;
        reply(res, store->put_envelope(claims.user_id, claims.pubkey, *body, req.body.size()));
    }));

    priv.Get("/api/account/keys/pending", require_auth(ctx_.auth,
        [store, reply](const httplib::Request&, httplib::Response& res,
                       const SessionClaims& claims) {
        reply(res, store->pending_envelopes(claims.user_id, claims.pubkey));
    }));
}

} // namespace nexus::api
