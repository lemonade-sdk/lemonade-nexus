#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

#include <memory>

namespace nexus::account { class AccountDataStore; }
namespace nexus::tree { struct AccountDeletion; }

namespace nexus::api {

/// Zero-knowledge account data sync over the PRIVATE mesh API. Stores opaque,
/// client-encrypted blobs owned by the caller's Customer group and never reads
/// their contents:
///   - group-key envelopes: /api/account/keys/envelope, /api/account/keys/pending
///   - encrypted chat blobs: /api/chats[/{id}[/delete]]
/// Ownership is structural (the on-disk category is derived from the caller's
/// own group, never from client input) and additionally gated by tree
/// Read/Write on the Customer node. All routes are private + auth-required.
/// Envelopes replicate between servers through gossip; construct the handler
/// before the gossip io loop runs, since it installs the gossip sink.
class AccountDataApiHandler : public IRequestHandler<AccountDataApiHandler> {
    friend class IRequestHandler<AccountDataApiHandler>;

public:
    /// Installs the gossip envelope sink and the tree's account-deleted hook.
    explicit AccountDataApiHandler(ApiContext& ctx);
    /// Clears the account-deleted hook.
    ~AccountDataApiHandler();
    AccountDataApiHandler(const AccountDataApiHandler&) = delete;
    AccountDataApiHandler& operator=(const AccountDataApiHandler&) = delete;

    /// The account-level cleanup of an applied account deletion on this
    /// server: the account's chat blobs and group-key envelopes (on disk and
    /// in the replicated envelope stream), the link tokens it minted or that
    /// target a removed group, its passkey credentials, and, when its key owns
    /// no node any longer, the key itself (which ends its sessions). Called by
    /// the tree's account-deleted hook. Idempotent.
    void cleanup_deleted_account(const tree::AccountDeletion& deletion);

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    ApiContext& ctx_;
    // One store for every registration (routes are re-registered when a
    // listener's certificate changes); shared with the gossip sink.
    std::shared_ptr<account::AccountDataStore> store_;
};

} // namespace nexus::api
