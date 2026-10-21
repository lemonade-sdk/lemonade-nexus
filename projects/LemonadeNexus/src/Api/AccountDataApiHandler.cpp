#include <LemonadeNexus/Api/AccountDataApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Account/AccountDataStore.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>

#include <memory>

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
