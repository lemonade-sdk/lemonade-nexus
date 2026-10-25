#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::api {

/// Handles TLS certificate management and ACME certificate issuance endpoints.
/// All routes are private (auth required).
///
/// POST /api/certs/issue issues two kinds of certificate, selected by the
/// optional request field "scope":
///   - "device" (or absent): "<hostname>.capi.<base_domain>" for a node the
///     caller owns. The hostname must not belong to an endpoint of another key.
///   - "group_loopback": "*.<group-label>.lo.<base_domain>" for the caller's
///     group. The caller must be a joined endpoint of that group, and
///     client_pubkey must be the caller's own key.
/// A stored certificate is issued again when less than one third of its
/// lifetime remains (certificate_renewal_due). The private key goes back
/// encrypted to client_pubkey.
class CertApiHandler : public IRequestHandler<CertApiHandler> {
    friend class IRequestHandler<CertApiHandler>;

public:
    explicit CertApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    ApiContext& ctx_;
    // Serializes the stored-certificate check with the ACME order it can
    // start, so concurrent requests for one name do not start two orders.
    std::mutex issue_mutex_;
};

/// The stored device and group loopback certificates that the renewal
/// monitor must issue again at `now` (Unix seconds), sorted. A certificate is
/// listed only while its owner still exists in `tree` and its name is not
/// ambiguous: a "<hostname>.capi.<base>" name needs an endpoint with that
/// hostname and no endpoints of different keys; a "*.<label>.lo.<base>" name
/// needs exactly one group with that label. A key that the storage vault
/// cannot read yet is skipped. The server's own names are not listed.
[[nodiscard]] std::vector<std::string> device_certificates_due(
    acme::AcmeService& acme, const tree::PermissionTreeService& tree,
    std::string_view base_domain, uint64_t now);

} // namespace nexus::api
