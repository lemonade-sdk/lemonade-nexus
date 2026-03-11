#include <LemonadeNexus/Network/StunService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstring>
#include <memory>

namespace nexus::network {

namespace {

/// Return the current Unix timestamp.
uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

/// Write a uint16_t in network byte order (big-endian) to a buffer.
void write_u16(uint8_t* buf, uint16_t val) {
    buf[0] = static_cast<uint8_t>((val >> 8) & 0xFF);
    buf[1] = static_cast<uint8_t>( val       & 0xFF);
}

/// Write a uint32_t in network byte order (big-endian) to a buffer.
void write_u32(uint8_t* buf, uint32_t val) {
    buf[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((val >>  8) & 0xFF);
    buf[3] = static_cast<uint8_t>( val        & 0xFF);
}

/// Read a uint16_t from network byte order (big-endian) buffer.
uint16_t read_u16(const uint8_t* buf) {
    return static_cast<uint16_t>((static_cast<uint16_t>(buf[0]) << 8) | buf[1]);
}

} // anonymous namespace

// --- Construction ---

StunService::StunService(asio::io_context& io, uint16_t port,
                         crypto::SodiumCryptoService& crypto,
                         std::string server_id)
    : socket_(io, asio::ip::udp::endpoint{asio::ip::udp::v4(), port})
    , crypto_(crypto)
    , server_id_(std::move(server_id))
{
}

// --- IService lifecycle ---

void StunService::on_start() {
    // Generate a persistent identity keypair for signing STUN responses.
    identity_keypair_ = crypto_.ed25519_keygen();
    spdlog::info("[{}] listening on UDP port {} (server_id: '{}', pubkey: {}...)",
                  name(), socket_.local_endpoint().port(), server_id_,
                  crypto::to_hex(std::span<const uint8_t>(
                      identity_keypair_.public_key.data(), 4)));
    start_receive();
}

void StunService::on_stop() {
    spdlog::info("[{}] stopped", name());
    asio::error_code ec;
    socket_.close(ec);
}

// --- IStunProvider implementation ---

StunResponse StunService::do_handle_binding_request(const asio::ip::udp::endpoint& client,
                                                      std::span<const uint8_t> request) {
    // Validate minimum STUN header
    if (request.size() < kStunHeaderSize) {
        spdlog::warn("[{}] received undersized STUN message ({} bytes) from {}:{}",
                      name(), request.size(),
                      client.address().to_string(), client.port());
        return {};
    }

    uint16_t msg_type = read_u16(request.data());
    if (msg_type != kBindingRequest) {
        spdlog::debug("[{}] ignoring non-binding-request (type=0x{:04X}) from {}:{}",
                       name(), msg_type,
                       client.address().to_string(), client.port());
        return {};
    }

    StunResponse response;
    response.reflexive_address = client.address().to_string();
    response.reflexive_port    = client.port();
    response.server_id         = server_id_;
    response.timestamp         = now_unix();

    // Sign the response with the server's Ed25519 key
    do_sign_response(response);

    return response;
}

void StunService::do_sign_response(StunResponse& response) {
    auto signable = response_to_signable_bytes(response);

    // Sign with the server's persistent identity key (generated once on start).
    auto sig = crypto_.ed25519_sign(
        identity_keypair_.private_key,
        std::span<const uint8_t>(signable.data(), signable.size()));

    response.signature = sig;
    response.verified  = true;
}

bool StunService::do_verify_response(const StunResponse& response,
                                       std::string_view server_pubkey) const {
    auto signable = response_to_signable_bytes(response);

    // Decode the server's public key from base64
    auto pubkey_bytes = crypto::from_base64(server_pubkey);
    if (pubkey_bytes.size() != crypto::kEd25519PublicKeySize) {
        spdlog::warn("[{}] invalid server pubkey length for verification", name());
        return false;
    }

    crypto::Ed25519PublicKey pubkey{};
    std::memcpy(pubkey.data(), pubkey_bytes.data(), crypto::kEd25519PublicKeySize);

    return crypto_.ed25519_verify(
        pubkey,
        std::span<const uint8_t>(signable.data(), signable.size()),
        response.signature);
}

// --- UDP receive loop ---

void StunService::start_receive() {
    socket_.async_receive_from(
        asio::buffer(recv_buffer_), remote_endpoint_,
        [this](const asio::error_code& ec, std::size_t bytes) {
            if (!ec) {
                handle_receive(bytes);
                start_receive();
            } else if (ec != asio::error::operation_aborted) {
                spdlog::error("[{}] UDP receive error: {}", name(), ec.message());
            }
        });
}

void StunService::handle_receive(std::size_t bytes_received) {
    auto request = std::span<const uint8_t>(recv_buffer_.data(), bytes_received);

    if (bytes_received < kStunHeaderSize) {
        spdlog::debug("[{}] dropping short packet ({} bytes) from {}:{}",
                       name(), bytes_received,
                       remote_endpoint_.address().to_string(),
                       remote_endpoint_.port());
        return;
    }

    uint16_t msg_type = read_u16(request.data());
    if (msg_type != kBindingRequest) {
        spdlog::debug("[{}] ignoring non-binding-request (type=0x{:04X})", name(), msg_type);
        return;
    }

    spdlog::debug("[{}] STUN Binding Request from {}:{}",
                   name(),
                   remote_endpoint_.address().to_string(),
                   remote_endpoint_.port());

    // Build the raw STUN Binding Response.
    // Use shared_ptr to extend lifetime past the async_send_to completion.
    auto response_bytes = std::make_shared<std::vector<uint8_t>>(
        build_binding_response(remote_endpoint_, request));

    // Send response back to the client
    socket_.async_send_to(
        asio::buffer(*response_bytes), remote_endpoint_,
        [this, response_bytes](const asio::error_code& ec, std::size_t /*bytes_sent*/) {
            (void)response_bytes; // prevent premature destruction
            if (ec) {
                spdlog::error("[{}] failed to send STUN response: {}", name(), ec.message());
            }
        });
}

// --- STUN message construction ---

std::vector<uint8_t> StunService::build_binding_response(
    const asio::ip::udp::endpoint& client,
    std::span<const uint8_t> request_header) const
{
    // Extract the 12-byte transaction ID from the request (bytes 8..19)
    // Request layout: [0..1] type, [2..3] length, [4..7] magic cookie, [8..19] txn id

    // Build XOR-MAPPED-ADDRESS attribute for IPv4
    //   Family: 0x01 (IPv4)
    //   X-Port:   port XOR (magic cookie >> 16)
    //   X-Address: IPv4 XOR magic cookie
    const uint16_t x_port = client.port() ^ static_cast<uint16_t>(kMagicCookie >> 16);
    const uint32_t client_ip = client.address().to_v4().to_uint();
    const uint32_t x_addr = client_ip ^ kMagicCookie;

    // XOR-MAPPED-ADDRESS value: 1 reserved byte + 1 family + 2 port + 4 address = 8 bytes
    constexpr std::size_t kXmaValueLen = 8;
    // Attribute: 2 type + 2 length + value = 12 bytes
    constexpr std::size_t kXmaAttrLen = 4 + kXmaValueLen;

    // Total STUN message: header (20) + XOR-MAPPED-ADDRESS attribute (12)
    constexpr std::size_t kResponseLen = kStunHeaderSize + kXmaAttrLen;
    std::vector<uint8_t> buf(kResponseLen, 0);

    // --- Header ---
    write_u16(buf.data() + 0, kBindingResponse);
    write_u16(buf.data() + 2, kXmaAttrLen);           // message length (after header)
    write_u32(buf.data() + 4, kMagicCookie);

    // Copy transaction ID from request
    if (request_header.size() >= kStunHeaderSize) {
        std::memcpy(buf.data() + 8, request_header.data() + 8, 12);
    }

    // --- XOR-MAPPED-ADDRESS attribute ---
    std::size_t offset = kStunHeaderSize;
    write_u16(buf.data() + offset, kAttrXorMappedAddress);  // attribute type
    write_u16(buf.data() + offset + 2, kXmaValueLen);       // attribute value length

    buf[offset + 4] = 0x00;  // reserved
    buf[offset + 5] = 0x01;  // family: IPv4
    write_u16(buf.data() + offset + 6, x_port);
    write_u32(buf.data() + offset + 8, x_addr);

    return buf;
}

std::vector<uint8_t> StunService::response_to_signable_bytes(const StunResponse& response) {
    // Canonical byte representation for signing:
    //   reflexive_address (UTF-8) | 0x00 | port (2 bytes BE) | server_id (UTF-8) | 0x00 | timestamp (8 bytes BE)
    std::vector<uint8_t> bytes;
    bytes.reserve(response.reflexive_address.size() + 1 +
                  2 +
                  response.server_id.size() + 1 +
                  8);

    // reflexive_address
    bytes.insert(bytes.end(),
                 response.reflexive_address.begin(),
                 response.reflexive_address.end());
    bytes.push_back(0x00);

    // port (big-endian)
    bytes.push_back(static_cast<uint8_t>((response.reflexive_port >> 8) & 0xFF));
    bytes.push_back(static_cast<uint8_t>( response.reflexive_port       & 0xFF));

    // server_id
    bytes.insert(bytes.end(),
                 response.server_id.begin(),
                 response.server_id.end());
    bytes.push_back(0x00);

    // timestamp (big-endian, 8 bytes)
    for (int i = 7; i >= 0; --i) {
        bytes.push_back(static_cast<uint8_t>((response.timestamp >> (i * 8)) & 0xFF));
    }

    return bytes;
}

} // namespace nexus::network
