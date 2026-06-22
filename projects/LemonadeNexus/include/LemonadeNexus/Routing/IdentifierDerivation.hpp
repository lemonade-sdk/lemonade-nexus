#pragma once

#include <string>
#include <string_view>

namespace nexus::routing {

/// Deterministically derive a stable endpoint identifier. Pure, so the server
/// and any verifier compute the same label:
///
///   (is_inference ? "infer" : "client") + "-" +
///       base32-crockford(sha256("ln-endpoint-id:v1" ||
///           node_id|region|cpu_id|net_mac)[0..10])   // 80-bit core
///
/// The 80-bit core resists targeted-collision grinding. cpu_id/net_mac are
/// self-reported label seeds — NOT security controls; integrity comes from the
/// node signature over canonical_node_json.
[[nodiscard]] std::string derive_endpoint_identifier(std::string_view node_id,
                                                      std::string_view region,
                                                      std::string_view cpu_id,
                                                      std::string_view net_mac,
                                                      bool is_inference);

} // namespace nexus::routing
