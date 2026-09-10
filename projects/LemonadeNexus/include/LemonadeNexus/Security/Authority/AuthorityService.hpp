#pragma once

// The per-epoch authority protocol (architecture 20 and 21).
//
// The service owns the current epoch key share and the signing sessions. It
// signs one shape only, AuthorityObject, and only after it has examined the
// finalized consensus certificate the object names. It does not decide what
// the mesh authorized; HotStuff did. Every signing nonce is created for one
// session, lives behind a FROST handle, and is consumed or destroyed — never
// persisted, never reused. At an epoch boundary the old share is destroyed
// and every open session dies with it.

#include <LemonadeNexus/Crypto/FrostProvider.hpp>
#include <LemonadeNexus/Security/Authority/AuthorityObject.hpp>
#include <LemonadeNexus/Security/Authority/DkgSession.hpp>
#include <LemonadeNexus/Security/Authority/NonceCommitmentStore.hpp>
#include <LemonadeNexus/Security/Authority/SigningSession.hpp>
#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <variant>
#include <vector>

namespace nexus::security {

struct AuthorityEpochContext {
    NetworkId network_id{};
    EpochId epoch = 0;
    std::size_t consensus_quorum = 0;
    std::size_t authority_threshold = 0;
    Tier1Set members{*Tier1Set::from_nodes({})};
    std::map<NodeId, crypto::Ed25519PublicKey> vote_keys;
};

struct SigningMessageHeader {
    NetworkId network_id{};
    EpochId epoch = 0;
    KeyGeneration key_generation = 0;
    SigningSessionId session_id = 0;
    Digest object_digest{};
    NodeId sender;
};

struct FrostCommitmentMessage {
    SigningMessageHeader header;
    std::vector<uint8_t> commitment;
};

struct FrostShareMessage {
    SigningMessageHeader header;
    std::vector<uint8_t> share;
};

struct AuthoritySignature {
    NetworkId network_id{};
    EpochId epoch = 0;
    KeyGeneration key_generation = 0;
    Digest object_digest{};
    crypto::Ed25519Signature signature{};
};

enum class SigningFailure : uint16_t {
    None,
    NoKeyShare,
    WrongNetwork,
    WrongEpoch,
    WrongKeyGeneration,
    CertificateMismatch,
    CertificateInvalid,
    SignerSetInvalid,
    SessionRepeated,
    UnknownSession,
    WrongPhase,
    UnknownSigner,
    DuplicateCommitment,
    CommitmentReplayed,
    DuplicateShare,
    ObjectMismatch,
    CryptoFailure,
};

struct SigningStart {
    std::optional<SigningSessionId> session_id;
    std::optional<FrostCommitmentMessage> commitment;
    SigningFailure failure = SigningFailure::None;
};

class AuthorityService {
public:
    AuthorityService(NodeId self, NonceCommitmentStore& commitments);

    // --- Epoch key lifecycle ---

    /// Installs the epoch group and this node's share. Refuses a DKG result
    /// for another epoch or participant set. On success the previous share is
    /// destroyed and every open session is dropped: old shares cannot sign
    /// for the new epoch (architecture 22).
    [[nodiscard]] bool install_epoch(AuthorityEpochContext context, DkgResult dkg);

    /// Destroys the share and every open session. A node that leaves the
    /// Tier 1 set keeps no authority material.
    void clear_epoch();

    [[nodiscard]] bool has_key_share() const { return share_.has_value(); }
    [[nodiscard]] std::optional<EpochId> key_epoch() const;
    [[nodiscard]] std::optional<crypto::Ed25519PublicKey> group_public_key() const;

    // --- Next-epoch DKG (one session at a time) ---

    [[nodiscard]] std::optional<DkgMessage> start_dkg(DkgConfiguration configuration);
    [[nodiscard]] DkgSession* dkg() { return dkg_.get(); }
    [[nodiscard]] const DkgSession* dkg() const { return dkg_.get(); }
    [[nodiscard]] std::optional<DkgResult> take_dkg_result();
    void abandon_dkg();

    /// Records that an authenticated sender broadcast round-1 material for a
    /// target epoch. Kept with or without a session, so every current member
    /// — ceremony participant or not — attributes a stalled DKG to the same
    /// silent participants. An observation, never an acceptance.
    void observe_round1(const DkgMessage& message);
    [[nodiscard]] std::set<NodeId> round1_seen(EpochId target_epoch) const;

    // --- Signing ---

    /// Opens a signing session as the initiator with a fresh random id.
    [[nodiscard]] SigningStart start_signing(const AuthorityObject& object,
                                             const QuorumCertificate& certificate,
                                             std::vector<NodeId> signer_set);

    /// Joins a session an initiator announced. The same checks apply; the
    /// mesh commitment record rejects a repeated id.
    [[nodiscard]] SigningStart join_signing(SigningSessionId session_id,
                                            const AuthorityObject& object,
                                            const QuorumCertificate& certificate,
                                            std::vector<NodeId> signer_set);

    /// Returns this node's signature share once every signer committed.
    [[nodiscard]] std::variant<std::monostate, FrostShareMessage, SigningFailure>
    receive_commitment(const FrostCommitmentMessage& message);

    /// Returns the aggregated authority signature once every share arrived.
    [[nodiscard]] std::variant<std::monostate, AuthoritySignature, SigningFailure>
    receive_signature_share(const FrostShareMessage& message);

    [[nodiscard]] std::optional<AuthoritySignature> result(SigningSessionId session_id) const;
    [[nodiscard]] const SigningSession* session(SigningSessionId session_id) const;

    /// Aborts a session. Its nonce is destroyed; a retry is a new session.
    void abort_signing(SigningSessionId session_id);

private:
    struct OpenSession {
        SigningSession session;
        Digest object_digest{};
        crypto::FrostPeerBytesMap commitments;
        crypto::FrostPeerBytesMap shares;
        crypto::FrostNonces nonces;
        std::optional<AuthoritySignature> signature;
    };

    [[nodiscard]] SigningStart open_session(SigningSessionId session_id,
                                            const AuthorityObject& object,
                                            const QuorumCertificate& certificate,
                                            std::vector<NodeId> signer_set);
    [[nodiscard]] SigningFailure check_header(const SigningMessageHeader& header,
                                              const OpenSession& open) const;
    [[nodiscard]] SigningMessageHeader make_header(const OpenSession& open) const;

    NodeId self_;
    NonceCommitmentStore& commitments_;

    std::optional<AuthorityEpochContext> context_;
    std::optional<crypto::FrostKeyShare> share_;
    crypto::FrostBytes public_key_package_;
    crypto::Ed25519PublicKey group_public_key_{};
    std::map<NodeId, crypto::ParticipantIndex> index_of_;

    std::unique_ptr<DkgSession> dkg_;
    /// Round-1 broadcasters per target epoch. Bounded: two epochs of history,
    /// and each set stops growing at twice the largest Tier 1 population.
    std::map<EpochId, std::set<NodeId>> round1_seen_;
    std::map<SigningSessionId, OpenSession> sessions_;
};

}  // namespace nexus::security
