#include <LemonadeNexus/Security/Authority/AuthorityService.hpp>

#include <LemonadeNexus/Security/Consensus/QuorumValidation.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>

#include <algorithm>
#include <set>

namespace nexus::security {

namespace {

SigningSessionId random_session_id() {
    SigningSessionId id = 0;
    randombytes_buf(&id, sizeof(id));
    return id;
}

}  // namespace

AuthorityService::AuthorityService(NodeId self, NonceCommitmentStore& commitments)
    : self_(self), commitments_(commitments) {}

bool AuthorityService::install_epoch(AuthorityEpochContext context, DkgResult dkg) {
    if (dkg.target_epoch != context.epoch ||
        dkg.participant_set_digest != context.members.digest() ||
        !dkg.key_share.valid() || !dkg.index_of.contains(self_)) {
        return false;
    }

    // Open sessions hold nonces for the old share; dropping them destroys the
    // nonces with the share.
    sessions_.clear();
    share_.reset();

    context_ = std::move(context);
    share_ = std::move(dkg.key_share);
    public_key_package_ = std::move(dkg.public_key_package);
    group_public_key_ = dkg.group_public_key;
    index_of_ = std::move(dkg.index_of);
    return true;
}

void AuthorityService::clear_epoch() {
    sessions_.clear();
    share_.reset();
    context_.reset();
    public_key_package_.clear();
    group_public_key_ = crypto::Ed25519PublicKey{};
    index_of_.clear();
}

std::optional<EpochId> AuthorityService::key_epoch() const {
    if (!context_.has_value() || !share_.has_value()) {
        return std::nullopt;
    }
    return context_->epoch;
}

std::optional<crypto::Ed25519PublicKey> AuthorityService::group_public_key() const {
    if (!share_.has_value()) {
        return std::nullopt;
    }
    return group_public_key_;
}

std::optional<DkgMessage> AuthorityService::start_dkg(DkgConfiguration configuration) {
    dkg_ = std::make_unique<DkgSession>(std::move(configuration));
    return dkg_->start();
}

std::optional<DkgResult> AuthorityService::take_dkg_result() {
    if (!dkg_) {
        return std::nullopt;
    }
    auto result = dkg_->take_result();
    if (result.has_value()) {
        dkg_.reset();
    }
    return result;
}

void AuthorityService::abandon_dkg() { dkg_.reset(); }

SigningStart AuthorityService::start_signing(const AuthorityObject& object,
                                             const QuorumCertificate& certificate,
                                             std::vector<NodeId> signer_set) {
    return open_session(random_session_id(), object, certificate, std::move(signer_set));
}

SigningStart AuthorityService::join_signing(SigningSessionId session_id,
                                            const AuthorityObject& object,
                                            const QuorumCertificate& certificate,
                                            std::vector<NodeId> signer_set) {
    return open_session(session_id, object, certificate, std::move(signer_set));
}

SigningStart AuthorityService::open_session(SigningSessionId session_id,
                                            const AuthorityObject& object,
                                            const QuorumCertificate& certificate,
                                            std::vector<NodeId> signer_set) {
    SigningStart start;
    const auto fail = [&start](SigningFailure failure) {
        start.failure = failure;
        return start;
    };

    if (!share_.has_value() || !context_.has_value()) {
        return fail(SigningFailure::NoKeyShare);
    }
    if (object.network_id != context_->network_id) {
        return fail(SigningFailure::WrongNetwork);
    }
    if (object.epoch != context_->epoch) {
        return fail(SigningFailure::WrongEpoch);
    }
    if (object.key_generation != context_->epoch) {
        return fail(SigningFailure::WrongKeyGeneration);
    }

    // The signer examines the finalized certificate before it creates a
    // share (architecture 20). A FROST signature never replaces one.
    if (qc_digest(certificate) != object.consensus_certificate_digest) {
        return fail(SigningFailure::CertificateMismatch);
    }
    const QcValidationContext qc_context{constants::kConsensusRulesetVersion,
                                         context_->network_id, context_->epoch,
                                         context_->consensus_quorum};
    if (validate_quorum_certificate(certificate, qc_context, context_->vote_keys).has_value()) {
        return fail(SigningFailure::CertificateInvalid);
    }

    std::sort(signer_set.begin(), signer_set.end());
    const bool distinct =
        std::adjacent_find(signer_set.begin(), signer_set.end()) == signer_set.end();
    const bool all_members = std::all_of(signer_set.begin(), signer_set.end(),
                                         [this](const NodeId& node) {
                                             return context_->members.contains(node) &&
                                                    index_of_.contains(node);
                                         });
    const bool includes_self =
        std::find(signer_set.begin(), signer_set.end(), self_) != signer_set.end();
    if (!distinct || !all_members || !includes_self ||
        signer_set.size() < context_->authority_threshold) {
        return fail(SigningFailure::SignerSetInvalid);
    }

    // A repeated session id is a replay: a restored signer that replays an
    // old session must find it already spent.
    if (!commitments_.register_session(context_->epoch, session_id) ||
        sessions_.contains(session_id)) {
        return fail(SigningFailure::SessionRepeated);
    }

    auto commit = crypto::FrostProvider::signing_commit(*share_);
    if (!commit.ok()) {
        return fail(SigningFailure::CryptoFailure);
    }

    OpenSession open;
    open.session.id = session_id;
    open.session.epoch = context_->epoch;
    open.session.key_generation = context_->epoch;
    open.session.object = object;
    open.session.signer_set = std::move(signer_set);
    open.session.phase = SigningPhase::CollectingCommitments;
    open.object_digest = authority_object_digest(object);
    open.nonces = std::move(commit.value->nonces);

    NonceCommitment record;
    record.epoch = context_->epoch;
    record.key_generation = context_->epoch;
    record.session_id = session_id;
    record.participant = self_;
    record.commitment = commit.value->commitments;
    if (!commitments_.insert(record)) {
        return fail(SigningFailure::CommitmentReplayed);
    }
    open.commitments[index_of_.at(self_)] = commit.value->commitments;

    FrostCommitmentMessage message;
    message.header = make_header(open);
    message.commitment = commit.value->commitments;

    sessions_.emplace(session_id, std::move(open));
    start.session_id = session_id;
    start.commitment = std::move(message);
    return start;
}

SigningMessageHeader AuthorityService::make_header(const OpenSession& open) const {
    SigningMessageHeader header;
    header.network_id = context_->network_id;
    header.epoch = open.session.epoch;
    header.key_generation = open.session.key_generation;
    header.session_id = open.session.id;
    header.object_digest = open.object_digest;
    header.sender = self_;
    return header;
}

SigningFailure AuthorityService::check_header(const SigningMessageHeader& header,
                                              const OpenSession& open) const {
    if (header.network_id != context_->network_id) {
        return SigningFailure::WrongNetwork;
    }
    if (header.epoch != open.session.epoch) {
        return SigningFailure::WrongEpoch;
    }
    if (header.key_generation != open.session.key_generation) {
        return SigningFailure::WrongKeyGeneration;
    }
    if (header.object_digest != open.object_digest) {
        return SigningFailure::ObjectMismatch;
    }
    const auto& signers = open.session.signer_set;
    if (std::find(signers.begin(), signers.end(), header.sender) == signers.end()) {
        return SigningFailure::UnknownSigner;
    }
    return SigningFailure::None;
}

std::variant<std::monostate, FrostShareMessage, SigningFailure>
AuthorityService::receive_commitment(const FrostCommitmentMessage& message) {
    if (!share_.has_value()) {
        return SigningFailure::NoKeyShare;
    }
    const auto it = sessions_.find(message.header.session_id);
    if (it == sessions_.end()) {
        return SigningFailure::UnknownSession;
    }
    OpenSession& open = it->second;
    if (open.session.phase != SigningPhase::CollectingCommitments) {
        return SigningFailure::WrongPhase;
    }
    if (const auto failure = check_header(message.header, open); failure != SigningFailure::None) {
        return failure;
    }
    const crypto::ParticipantIndex index = index_of_.at(message.header.sender);
    if (open.commitments.contains(index)) {
        return SigningFailure::DuplicateCommitment;
    }

    NonceCommitment record;
    record.epoch = open.session.epoch;
    record.key_generation = open.session.key_generation;
    record.session_id = open.session.id;
    record.participant = message.header.sender;
    record.commitment = message.commitment;
    // The mesh record rejects a commitment that any earlier session used
    // under this group key, even one this node never saw complete.
    if (!commitments_.insert(record)) {
        return SigningFailure::CommitmentReplayed;
    }
    open.commitments[index] = message.commitment;

    if (open.commitments.size() < open.session.signer_set.size()) {
        return std::monostate{};
    }

    auto share = crypto::FrostProvider::sign(*share_, std::move(open.nonces), open.object_digest,
                                             open.commitments);
    if (!share.ok()) {
        open.session.phase = SigningPhase::Aborted;
        return SigningFailure::CryptoFailure;
    }
    open.shares[index_of_.at(self_)] = *share.value;
    open.session.phase = SigningPhase::CollectingShares;

    FrostShareMessage out;
    out.header = make_header(open);
    out.share = *share.value;
    return out;
}

std::variant<std::monostate, AuthoritySignature, SigningFailure>
AuthorityService::receive_signature_share(const FrostShareMessage& message) {
    if (!share_.has_value()) {
        return SigningFailure::NoKeyShare;
    }
    const auto it = sessions_.find(message.header.session_id);
    if (it == sessions_.end()) {
        return SigningFailure::UnknownSession;
    }
    OpenSession& open = it->second;
    if (open.session.phase != SigningPhase::CollectingShares) {
        return SigningFailure::WrongPhase;
    }
    if (const auto failure = check_header(message.header, open); failure != SigningFailure::None) {
        return failure;
    }
    const crypto::ParticipantIndex index = index_of_.at(message.header.sender);
    if (!open.commitments.contains(index)) {
        return SigningFailure::UnknownSigner;
    }
    if (open.shares.contains(index)) {
        return SigningFailure::DuplicateShare;
    }
    open.shares[index] = message.share;

    if (open.shares.size() < open.session.signer_set.size()) {
        return std::monostate{};
    }

    auto aggregate = crypto::FrostProvider::aggregate(open.object_digest, open.commitments,
                                                      open.shares, public_key_package_);
    if (!aggregate.ok() ||
        !crypto::FrostProvider::verify(group_public_key_, open.object_digest, *aggregate.value)) {
        // The session is spent either way; a retry starts a new one.
        open.session.phase = SigningPhase::Aborted;
        return SigningFailure::CryptoFailure;
    }

    AuthoritySignature signature;
    signature.network_id = context_->network_id;
    signature.epoch = open.session.epoch;
    signature.key_generation = open.session.key_generation;
    signature.object_digest = open.object_digest;
    signature.signature = *aggregate.value;
    open.signature = signature;
    open.session.phase = SigningPhase::Complete;
    return signature;
}

std::optional<AuthoritySignature> AuthorityService::result(SigningSessionId session_id) const {
    const auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    return it->second.signature;
}

const SigningSession* AuthorityService::session(SigningSessionId session_id) const {
    const auto it = sessions_.find(session_id);
    return it == sessions_.end() ? nullptr : &it->second.session;
}

void AuthorityService::abort_signing(SigningSessionId session_id) {
    const auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return;
    }
    it->second.session.phase = SigningPhase::Aborted;
    it->second.nonces = crypto::FrostNonces{};
}

}  // namespace nexus::security
