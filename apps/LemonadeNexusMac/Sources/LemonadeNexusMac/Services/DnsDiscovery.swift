@preconcurrency import Foundation
@preconcurrency import Dispatch
import Network
private func dlog(_ msg: String) {
    NSLog("%@", msg)
}

// MARK: - DiscoveredServer

struct DiscoveredServer: Identifiable {
    let id = UUID()
    let ip: String
    let port: Int
    let latencyMs: Double
    let hostname: String?
    let scheme: String  // "https" or "http" — whichever probe succeeded
    var region: String?
    var load: Int?
    var score: Double  // latency_ms + (load * 10)

    var url: String {
        let host = hostname ?? ip
        return "\(scheme)://\(host):\(port)"
    }

    /// Display label: hostname if available, otherwise IP address. Includes region if known.
    var displayName: String {
        let base = hostname ?? ip
        if let region = region {
            return "\(base) (\(region))"
        }
        return base
    }
}

// MARK: - DnsDiscoveryService

/// Discovers SecurePunch/Lemonade-Nexus servers via the mesh DNS service.
///
/// Discovery flow (region-aware):
///  1. Bootstrap: resolve the domain via standard DNS (getaddrinfo) to find initial server IPs.
///  2. NS expansion: query each bootstrap IP for NS records of the zone.
///  3. Determine the client's own region via geo-IP lookup.
///  4. Query SEIP records for the client's region first (`<region>.seip.<domain>`).
///  5. If no servers found in region, query all SEIP regions by geographic distance.
///  6. Fallback to legacy NS-hostname-based discovery for backward compatibility.
///  7. Sort by score (latency + load penalty), return best servers first.
final class DnsDiscoveryService: @unchecked Sendable {
    private let domain: String
    private let dnsPort: UInt16 = 53
    private let defaultHttpPort: Int = 9100

    /// Per-query timeout for UDP DNS requests.
    private let queryTimeout: TimeInterval = 3.0

    /// Cached region for the current session (avoid re-detecting on every call).
    private var cachedRegion: String?
    private var regionDetected: Bool = false

    /// Cloud region codes and their approximate geographic centroids.
    private static let cloudRegions: [(code: String, lat: Double, lon: Double)] = [
        ("us-east", 39.0, -77.0),
        ("us-west", 37.4, -122.0),
        ("us-central", 41.8, -93.0),
        ("ca-central", 45.5, -73.6),
        ("eu-west", 53.3, -6.3),
        ("eu-central", 50.1, 8.7),
        ("eu-north", 59.3, 18.1),
        ("ap-south", 19.1, 72.9),
        ("ap-southeast", 1.3, 103.8),
        ("ap-northeast", 35.7, 139.7),
        ("ap-east", 22.3, 114.2),
        ("sa-east", -23.5, -46.6),
        ("af-south", -33.9, 18.4),
        ("me-south", 26.1, 50.2),
        ("oc-south", -33.9, 151.2),
    ]

    init(domain: String = "lemonade-nexus.io") {
        self.domain = domain
    }

    // MARK: - Public API

    func discoverServers() async -> [DiscoveredServer] {
        dlog("[Discovery] Starting region-aware discovery for domain: \(domain)")

        // Step 1: Bootstrap — resolve A records via system DNS.
        var bootstrapIPs = await resolveBootstrapIPs()
        dlog("[Discovery] Step 1 — Bootstrap IPs: \(bootstrapIPs)")

        // Fallback: if the base domain has no A record, resolve NS hostnames directly.
        if bootstrapIPs.isEmpty {
            dlog("[Discovery] Step 1b — No A record, trying NS hostname resolution")
            let nsIPs = await resolveBootstrapIPs(hostname: "ns1.\(domain)")
            bootstrapIPs = nsIPs
            dlog("[Discovery] Step 1b — NS fallback IPs: \(bootstrapIPs)")
        }

        guard !bootstrapIPs.isEmpty else {
            dlog("[Discovery] No bootstrap IPs found — aborting")
            return []
        }

        // Step 2: Query NS records from each bootstrap IP to discover all mesh servers.
        let nsServers = await resolveNSRecords(bootstrapIPs: bootstrapIPs)
        dlog("[Discovery] Step 2 — NS servers: \(nsServers.map { "\($0.hostname ?? "?")@\($0.ip)" })")

        // Step 3: Determine our region
        let ourRegion = await determineOwnRegion()
        dlog("[Discovery] Step 3 — Our region: \(ourRegion ?? "unknown")")

        // Step 4: Query SEIP records for our region first
        var servers: [DiscoveredServer] = []
        if let region = ourRegion {
            let regionServers = await querySEIPRegion(region: region, nameservers: nsServers)
            servers.append(contentsOf: regionServers)
            dlog("[Discovery] Step 4 — Region '\(region)' servers: \(regionServers.count)")
        }

        // Step 5: If no servers in our region, try all regions
        if servers.isEmpty {
            dlog("[Discovery] Step 5 — No regional servers, querying all SEIP regions")
            let allServers = await queryAllSEIPServers(nameservers: nsServers, clientRegion: ourRegion)
            servers.append(contentsOf: allServers)
            dlog("[Discovery] Step 5 — All-region servers: \(allServers.count)")
        }

        // Step 6: Fallback to legacy discovery (backward compat)
        if servers.isEmpty {
            dlog("[Discovery] Step 6 — Falling back to legacy discovery")
            servers = await legacyDiscovery(nsServers: nsServers, bootstrapIPs: bootstrapIPs)
            dlog("[Discovery] Step 6 — Legacy servers: \(servers.count)")
        }

        // Step 7: Sort by score (latency + load penalty)
        let sorted = servers.sorted { $0.score < $1.score }
        dlog("[Discovery] Final result: \(sorted.count) server(s) discovered")
        return sorted
    }

    // MARK: - Step 1: Bootstrap via getaddrinfo

    private func resolveBootstrapIPs(hostname: String? = nil) async -> [String] {
        let target = hostname ?? domain
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                var hints = addrinfo()
                hints.ai_family = AF_INET
                hints.ai_socktype = SOCK_STREAM

                var result: UnsafeMutablePointer<addrinfo>?
                let status = getaddrinfo(target, nil, &hints, &result)

                guard status == 0, let addrList = result else {
                    continuation.resume(returning: [])
                    return
                }

                defer { freeaddrinfo(addrList) }

                var ips: [String] = []
                var current: UnsafeMutablePointer<addrinfo>? = addrList
                while let addr = current {
                    if addr.pointee.ai_family == AF_INET {
                        var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                        if getnameinfo(
                            addr.pointee.ai_addr, addr.pointee.ai_addrlen,
                            &buf, socklen_t(buf.count),
                            nil, 0, NI_NUMERICHOST
                        ) == 0 {
                            let ip = String(cString: buf)
                            if !ips.contains(ip) {
                                ips.append(ip)
                            }
                        }
                    }
                    current = addr.pointee.ai_next
                }

                continuation.resume(returning: ips)
            }
        }
    }

    // MARK: - Step 2: Resolve NS Records

    /// Represents a nameserver discovered via an NS query's additional (glue) section.
    private struct NameserverEntry {
        let hostname: String?
        let ip: String
    }

    /// Queries bootstrap IPs for NS records and returns unique nameserver entries.
    private func resolveNSRecords(bootstrapIPs: [String]) async -> [NameserverEntry] {
        var entries: [NameserverEntry] = bootstrapIPs.map { NameserverEntry(hostname: nil, ip: $0) }
        await withTaskGroup(of: [NameserverEntry].self) { group in
            for ip in bootstrapIPs {
                group.addTask {
                    await self.queryNSRecords(serverIP: ip)
                }
            }
            for await result in group {
                for entry in result {
                    if !entries.contains(where: { $0.ip == entry.ip }) {
                        entries.append(entry)
                    }
                }
            }
        }
        return entries
    }

    /// Sends an NS query for the zone to a single server and parses NS + glue A records.
    private func queryNSRecords(serverIP: String) async -> [NameserverEntry] {
        let queryPacket = DnsPacketBuilder.buildQuery(name: domain, type: .NS)
        guard let responseData = await sendUDPQuery(packet: queryPacket, to: serverIP, port: dnsPort) else {
            return []
        }

        let parsed = DnsResponseParser.parse(data: responseData)

        // Collect NS hostnames from answer section.
        var nsHostnames: [String] = []
        for record in parsed.answers where record.type == .NS {
            nsHostnames.append(record.rdata)
        }

        // Build map of hostname -> IP from additional (glue) A records.
        var glueMap: [String: String] = [:]
        for record in parsed.additionals where record.type == .A {
            glueMap[record.name.lowercased()] = record.rdata
        }

        // Match NS hostnames to glue IPs.
        var entries: [NameserverEntry] = []
        for nsHost in nsHostnames {
            if let ip = glueMap[nsHost.lowercased()] {
                entries.append(NameserverEntry(hostname: nsHost, ip: ip))
            }
        }

        return entries
    }

    // MARK: - Step 3: Region Detection

    /// Determines the client's own cloud region by geo-IP lookup.
    /// Result is cached for the session so subsequent calls are instant.
    private func determineOwnRegion() async -> String? {
        // Return cached value if we already detected
        if regionDetected {
            return cachedRegion
        }

        let detected = await detectRegionViaGeoIP()
        cachedRegion = detected
        regionDetected = true
        return detected
    }

    /// Performs the actual geo-IP lookup and maps to the nearest cloud region.
    private func detectRegionViaGeoIP() async -> String? {
        guard let url = URL(string: "http://ip-api.com/json/?fields=lat,lon,regionName,countryCode") else {
            dlog("[Discovery] Region: invalid geo-IP URL")
            return regionFromLocale()
        }

        do {
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 5
            config.timeoutIntervalForResource = 5
            let session = URLSession(configuration: config)
            let (data, _) = try await session.data(from: url)

            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let lat = json["lat"] as? Double,
                  let lon = json["lon"] as? Double else {
                dlog("[Discovery] Region: failed to parse geo-IP response")
                return regionFromLocale()
            }

            let nearest = Self.nearestCloudRegion(lat: lat, lon: lon)
            dlog("[Discovery] Region: geo-IP lat=\(lat) lon=\(lon) -> \(nearest)")
            return nearest
        } catch {
            dlog("[Discovery] Region: geo-IP lookup failed — \(error.localizedDescription)")
            return regionFromLocale()
        }
    }

    /// Fallback: guess a rough region from the system locale.
    private func regionFromLocale() -> String? {
        guard let regionCode = Locale.current.region?.identifier.uppercased() else { return nil }
        dlog("[Discovery] Region: falling back to locale region code '\(regionCode)'")

        // Map common country codes to cloud regions
        switch regionCode {
        case "US":
            return "us-east"  // default US region
        case "CA":
            return "ca-central"
        case "GB", "IE":
            return "eu-west"
        case "DE", "FR", "NL", "BE", "AT", "CH":
            return "eu-central"
        case "SE", "NO", "FI", "DK":
            return "eu-north"
        case "IN":
            return "ap-south"
        case "SG", "MY", "ID", "TH", "VN", "PH":
            return "ap-southeast"
        case "JP", "KR":
            return "ap-northeast"
        case "HK", "TW":
            return "ap-east"
        case "BR", "AR", "CL", "CO":
            return "sa-east"
        case "ZA":
            return "af-south"
        case "AE", "SA", "BH", "QA":
            return "me-south"
        case "AU", "NZ":
            return "oc-south"
        default:
            return nil
        }
    }

    /// Finds the nearest cloud region to the given lat/lon using haversine distance.
    private static func nearestCloudRegion(lat: Double, lon: Double) -> String {
        var bestCode = cloudRegions[0].code
        var bestDist = Double.greatestFiniteMagnitude

        for region in cloudRegions {
            let dist = haversineDistance(lat1: lat, lon1: lon, lat2: region.lat, lon2: region.lon)
            if dist < bestDist {
                bestDist = dist
                bestCode = region.code
            }
        }

        return bestCode
    }

    /// Haversine distance in kilometers between two lat/lon points.
    private static func haversineDistance(lat1: Double, lon1: Double, lat2: Double, lon2: Double) -> Double {
        let R = 6371.0  // Earth radius in km
        let dLat = (lat2 - lat1) * .pi / 180.0
        let dLon = (lon2 - lon1) * .pi / 180.0
        let a = sin(dLat / 2) * sin(dLat / 2) +
                cos(lat1 * .pi / 180.0) * cos(lat2 * .pi / 180.0) *
                sin(dLon / 2) * sin(dLon / 2)
        let c = 2 * atan2(sqrt(a), sqrt(1 - a))
        return R * c
    }

    /// Returns cloud region codes sorted by geographic distance from the given coordinates.
    private static func regionCodesByDistance(fromLat lat: Double, fromLon lon: Double) -> [String] {
        return cloudRegions
            .map { (code: $0.code, dist: haversineDistance(lat1: lat, lon1: lon, lat2: $0.lat, lon2: $0.lon)) }
            .sorted { $0.dist < $1.dist }
            .map { $0.code }
    }

    // MARK: - Step 4: Query SEIP Region

    /// Queries A records for `<region>.seip.<domain>` and probes each server found.
    private func querySEIPRegion(region: String, nameservers: [NameserverEntry]) async -> [DiscoveredServer] {
        let qname = "\(region).seip.\(domain)"
        dlog("[Discovery] SEIP query: \(qname)")

        // Collect A record IPs from all nameservers for this region
        var regionIPs: [String] = []
        await withTaskGroup(of: [String].self) { group in
            for ns in nameservers {
                group.addTask {
                    let queryPacket = DnsPacketBuilder.buildQuery(name: qname, type: .A)
                    guard let responseData = await self.sendUDPQuery(packet: queryPacket, to: ns.ip, port: self.dnsPort) else {
                        return []
                    }
                    let parsed = DnsResponseParser.parse(data: responseData)
                    return parsed.answers.compactMap { $0.type == .A ? $0.rdata : nil }
                }
            }
            for await ips in group {
                for ip in ips {
                    if !regionIPs.contains(ip) {
                        regionIPs.append(ip)
                    }
                }
            }
        }

        dlog("[Discovery] SEIP region '\(region)' IPs: \(regionIPs)")
        guard !regionIPs.isEmpty else { return [] }

        // Probe each IP: get _config TXT, health check, compute score
        var servers: [DiscoveredServer] = []
        await withTaskGroup(of: DiscoveredServer?.self) { group in
            for ip in regionIPs {
                group.addTask {
                    await self.resolveAndProbe(ip: ip, hostname: nil, expectedRegion: region)
                }
            }
            for await result in group {
                if let server = result {
                    servers.append(server)
                }
            }
        }

        return servers
    }

    // MARK: - Step 5: Query All SEIP Regions

    /// Queries all known cloud regions for SEIP servers, ordered by geographic proximity
    /// to the client's detected location.
    private func queryAllSEIPServers(nameservers: [NameserverEntry], clientRegion: String?) async -> [DiscoveredServer] {
        // Order regions by distance from client
        let orderedRegions: [String]
        if let clientRegion = clientRegion,
           let regionEntry = Self.cloudRegions.first(where: { $0.code == clientRegion }) {
            orderedRegions = Self.regionCodesByDistance(fromLat: regionEntry.lat, fromLon: regionEntry.lon)
        } else {
            // No client region known — just try all in default order
            orderedRegions = Self.cloudRegions.map { $0.code }
        }

        var allServers: [DiscoveredServer] = []
        // Query all regions concurrently for speed
        await withTaskGroup(of: [DiscoveredServer].self) { group in
            for region in orderedRegions {
                group.addTask {
                    await self.querySEIPRegion(region: region, nameservers: nameservers)
                }
            }
            for await regionServers in group {
                allServers.append(contentsOf: regionServers)
            }
        }

        return allServers
    }

    // MARK: - Step 6: Legacy Discovery (Backward Compat)

    /// The original NS-hostname-based discovery flow. Used as a fallback when no SEIP
    /// records are found (e.g., servers running older versions without region support).
    private func legacyDiscovery(nsServers: [NameserverEntry], bootstrapIPs: [String]) async -> [DiscoveredServer] {
        dlog("[Discovery] Legacy: probing \(nsServers.count) NS servers")

        var results: [DiscoveredServer] = []
        await withTaskGroup(of: DiscoveredServer?.self) { group in
            for server in nsServers {
                group.addTask {
                    await self.resolveAndProbe(ip: server.ip, hostname: server.hostname, expectedRegion: nil)
                }
            }
            for await result in group {
                if let server = result {
                    dlog("[Discovery] Legacy — Server found: \(server.displayName) @ \(server.ip):\(server.port) (\(String(format: "%.0f", server.latencyMs))ms)")
                    results.append(server)
                }
            }
        }

        return results
    }

    // MARK: - Config TXT + Health Probe

    /// Parse `region=<code>` and `load=<int>` from a TXT record value.
    private static func parseRegionAndLoad(from txt: String) -> (region: String?, load: Int?) {
        var region: String?
        var load: Int?
        for part in txt.split(separator: " ") {
            let kv = part.split(separator: "=", maxSplits: 1)
            if kv.count == 2 {
                if kv[0] == "region" { region = String(kv[1]) }
                if kv[0] == "load" { load = Int(kv[1]) }
            }
        }
        return (region, load)
    }

    /// For a given server IP, optionally queries its _config TXT record to get the HTTP port,
    /// region, and load, then probes the health endpoint.
    private func resolveAndProbe(ip: String, hostname: String?, expectedRegion: String?) async -> DiscoveredServer? {
        // Try to get the HTTP port from the _config TXT record.
        var httpPort = defaultHttpPort
        var resolvedHostname = hostname
        var discoveredRegion = expectedRegion
        var discoveredLoad: Int?

        // If we have a hostname (already FQDN from NS response), query _config.<hostname>.
        if let host = hostname {
            let configName = "_config.\(host)"
            let queryPacket = DnsPacketBuilder.buildQuery(name: configName, type: .TXT)
            if let responseData = await sendUDPQuery(packet: queryPacket, to: ip, port: dnsPort) {
                let parsed = DnsResponseParser.parse(data: responseData)
                for record in parsed.answers where record.type == .TXT {
                    if let port = Self.parseHttpPort(from: record.rdata) {
                        httpPort = port
                    }
                    if let certHost = Self.parseHost(from: record.rdata) {
                        resolvedHostname = certHost
                        dlog("[Discovery]   TXT host=\(certHost) (cert FQDN)")
                    }
                    let regionLoad = Self.parseRegionAndLoad(from: record.rdata)
                    if let r = regionLoad.region { discoveredRegion = r }
                    if let l = regionLoad.load { discoveredLoad = l }
                }
            }
        }

        // If we don't have a hostname, try to discover it by querying NS records on this IP.
        if resolvedHostname == nil {
            let nsQuery = DnsPacketBuilder.buildQuery(name: domain, type: .NS)
            if let responseData = await sendUDPQuery(packet: nsQuery, to: ip, port: dnsPort) {
                let parsed = DnsResponseParser.parse(data: responseData)
                // Look through glue records to find which NS hostname maps to this IP.
                for record in parsed.additionals where record.type == .A {
                    if record.rdata == ip {
                        resolvedHostname = record.name
                        // Now try _config for this hostname (already FQDN).
                        let configName = "_config.\(record.name)"
                        let configQuery = DnsPacketBuilder.buildQuery(name: configName, type: .TXT)
                        if let configData = await sendUDPQuery(packet: configQuery, to: ip, port: dnsPort) {
                            let configParsed = DnsResponseParser.parse(data: configData)
                            for cr in configParsed.answers where cr.type == .TXT {
                                if let port = Self.parseHttpPort(from: cr.rdata) {
                                    httpPort = port
                                }
                                if let certHost = Self.parseHost(from: cr.rdata) {
                                    resolvedHostname = certHost
                                    dlog("[Discovery]   TXT host=\(certHost) (cert FQDN)")
                                }
                                let regionLoad = Self.parseRegionAndLoad(from: cr.rdata)
                                if let r = regionLoad.region { discoveredRegion = r }
                                if let l = regionLoad.load { discoveredLoad = l }
                            }
                        }
                        break
                    }
                }
            }
        }

        // Probe the server's HTTPS health endpoint.
        guard var server = await probeServer(ip: ip, port: httpPort, hostname: resolvedHostname) else {
            return nil
        }

        // Populate region + load + score
        server.region = discoveredRegion
        server.load = discoveredLoad
        server.score = server.latencyMs + Double(server.load ?? 0) * 10.0

        dlog("[Discovery]   Scored: \(server.displayName) score=\(String(format: "%.1f", server.score)) (latency=\(String(format: "%.0f", server.latencyMs))ms load=\(server.load ?? 0) region=\(server.region ?? "?"))")

        return server
    }

    /// Parse `http=<port>` from a TXT record value like "v=sp1 http=9100 udp=51940 ...".
    private static func parseHttpPort(from txt: String) -> Int? {
        let parts = txt.split(separator: " ")
        for part in parts {
            if part.hasPrefix("http=") {
                let value = part.dropFirst("http=".count)
                return Int(value)
            }
        }
        return nil
    }

    /// Parse `host=<fqdn>` from a TXT record value like "v=sp1 http=9100 host=ns1.srv.example.com ...".
    private static func parseHost(from txt: String) -> String? {
        let parts = txt.split(separator: " ")
        for part in parts {
            if part.hasPrefix("host=") {
                let value = String(part.dropFirst("host=".count))
                return value.isEmpty ? nil : value
            }
        }
        return nil
    }

    // MARK: - Health Probe (HTTPS with HTTP fallback)

    private func probeServer(ip: String, port: Int, hostname: String?) async -> DiscoveredServer? {
        // Try HTTPS first (using hostname for cert CN match), fall back to IP, then HTTP.
        let host = hostname ?? ip
        let probeTargets = hostname != nil
            ? [("https", host), ("https", ip), ("http", ip)]
            : [("https", ip), ("http", ip)]

        for (scheme, target) in probeTargets {
            let urlString = "\(scheme)://\(target):\(port)/api/health"
            guard let url = URL(string: urlString) else { continue }

            dlog("[Discovery]   Probe: \(urlString)")
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 5
            config.timeoutIntervalForResource = 8
            let delegate = InsecureSessionDelegate()
            let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)

            let start = CFAbsoluteTimeGetCurrent()
            do {
                let (_, response) = try await session.data(from: url)
                let elapsed = (CFAbsoluteTimeGetCurrent() - start) * 1000.0
                guard let httpResponse = response as? HTTPURLResponse,
                      (200..<300).contains(httpResponse.statusCode) else {
                    dlog("[Discovery]   Probe: \(scheme) returned status \((response as? HTTPURLResponse)?.statusCode ?? -1)")
                    continue
                }
                dlog("[Discovery]   Probe: \(scheme) OK — \(String(format: "%.0f", elapsed))ms")
                return DiscoveredServer(
                    ip: ip, port: port, latencyMs: elapsed, hostname: hostname, scheme: scheme,
                    region: nil, load: nil, score: elapsed
                )
            } catch {
                dlog("[Discovery]   Probe: \(scheme) failed — \(error.localizedDescription)")
                continue
            }
        }
        dlog("[Discovery]   Probe: all schemes failed for \(ip):\(port)")
        return nil
    }

    // MARK: - UDP Transport

    /// Sends a raw UDP DNS query packet to the given IP:port and waits for a response.
    /// Uses the Network framework's NWConnection for non-blocking UDP I/O.
    private func sendUDPQuery(packet: Data, to ip: String, port: UInt16) async -> Data? {
        await withCheckedContinuation { continuation in
            let host = NWEndpoint.Host(ip)
            let nwPort = NWEndpoint.Port(rawValue: port)!
            let params = NWParameters.udp
            let connection = NWConnection(host: host, port: nwPort, using: params)

            // Dedicated serial queue for this connection's events.
            let queue = DispatchQueue(label: "dns.udp.\(ip).\(port)", qos: .userInitiated)

            // Guard against double-resumption via a simple atomic flag.
            let completed = LockedFlag()

            // Timeout: cancel the connection if no reply arrives in time.
            let timeoutItem = DispatchWorkItem { [weak connection] in
                if completed.testAndSet() {
                    connection?.cancel()
                    continuation.resume(returning: nil)
                }
            }
            queue.asyncAfter(deadline: .now() + queryTimeout, execute: timeoutItem)

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    // Connection is ready — send the query.
                    connection.send(content: packet, completion: .contentProcessed { sendError in
                        if sendError != nil {
                            timeoutItem.cancel()
                            if completed.testAndSet() {
                                connection.cancel()
                                continuation.resume(returning: nil)
                            }
                            return
                        }
                        // Receive the response (DNS responses fit within a single UDP datagram).
                        connection.receiveMessage { content, _, _, recvError in
                            timeoutItem.cancel()
                            if completed.testAndSet() {
                                connection.cancel()
                                if recvError != nil || content == nil {
                                    continuation.resume(returning: nil)
                                } else {
                                    continuation.resume(returning: content)
                                }
                            }
                        }
                    })
                case .failed, .cancelled:
                    timeoutItem.cancel()
                    if completed.testAndSet() {
                        continuation.resume(returning: nil)
                    }
                default:
                    break
                }
            }

            connection.start(queue: queue)
        }
    }
}

// MARK: - Thread-Safe Flag

/// A simple mutex-protected boolean flag to prevent double-completion of continuations.
private final class LockedFlag: @unchecked Sendable {
    private var _value = false
    private let lock = NSLock()

    /// Atomically tests the flag. Returns `true` if the flag was previously `false` (and sets it
    /// to `true`). Returns `false` if it was already `true`.
    func testAndSet() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if _value { return false }
        _value = true
        return true
    }
}

// MARK: - DNS Packet Builder (RFC 1035)

/// Builds minimal DNS query packets in standard wire format.
private enum DnsPacketBuilder {

    enum QueryType: UInt16 {
        case A    = 1
        case NS   = 2
        case TXT  = 16
    }

    /// Build a single-question DNS query packet.
    static func buildQuery(name: String, type: QueryType) -> Data {
        var packet = Data()

        // Header (12 bytes)
        let id = UInt16.random(in: 1...UInt16.max)
        packet.appendUInt16(id)          // ID
        packet.appendUInt16(0x0100)      // Flags: standard query, recursion desired
        packet.appendUInt16(1)           // QDCOUNT = 1
        packet.appendUInt16(0)           // ANCOUNT
        packet.appendUInt16(0)           // NSCOUNT
        packet.appendUInt16(0)           // ARCOUNT

        // Question section: QNAME
        packet.appendDnsName(name)

        // QTYPE
        packet.appendUInt16(type.rawValue)

        // QCLASS = IN
        packet.appendUInt16(1)

        return packet
    }
}

// MARK: - DNS Response Parser (RFC 1035)

/// Parses DNS response packets, extracting answer and additional resource records.
private enum DnsResponseParser {

    enum RecordType: UInt16 {
        case A    = 1
        case NS   = 2
        case TXT  = 16
        case unknown = 0xFFFF

        init(raw: UInt16) {
            self = RecordType(rawValue: raw) ?? .unknown
        }
    }

    struct ResourceRecord {
        let name: String
        let type: RecordType
        let rdata: String
        let ttl: UInt32
    }

    struct ParsedResponse {
        let id: UInt16
        let responseCode: UInt8
        let answers: [ResourceRecord]
        let authorities: [ResourceRecord]
        let additionals: [ResourceRecord]
    }

    static func parse(data: Data) -> ParsedResponse {
        var reader = DnsReader(data: data)

        // Header
        let id = reader.readUInt16() ?? 0
        let flags = reader.readUInt16() ?? 0
        let rcode = UInt8(flags & 0x0F)
        let qdcount = reader.readUInt16() ?? 0
        let ancount = reader.readUInt16() ?? 0
        let nscount = reader.readUInt16() ?? 0
        let arcount = reader.readUInt16() ?? 0

        // Skip question section
        for _ in 0..<qdcount {
            _ = reader.readDnsName()  // QNAME
            _ = reader.readUInt16()   // QTYPE
            _ = reader.readUInt16()   // QCLASS
        }

        // Parse answer section
        let answers = parseRecords(count: Int(ancount), reader: &reader)
        let authorities = parseRecords(count: Int(nscount), reader: &reader)
        let additionals = parseRecords(count: Int(arcount), reader: &reader)

        return ParsedResponse(
            id: id,
            responseCode: rcode,
            answers: answers,
            authorities: authorities,
            additionals: additionals
        )
    }

    private static func parseRecords(count: Int, reader: inout DnsReader) -> [ResourceRecord] {
        var records: [ResourceRecord] = []
        for _ in 0..<count {
            let name = reader.readDnsName() ?? ""
            let typeRaw = reader.readUInt16() ?? 0
            _ = reader.readUInt16()  // CLASS
            let ttl = reader.readUInt32() ?? 0
            let rdlength = reader.readUInt16() ?? 0

            let rdataStart = reader.offset
            let recordType = RecordType(raw: typeRaw)

            var rdata = ""
            switch recordType {
            case .A:
                rdata = reader.readIPv4Address() ?? ""
            case .NS:
                rdata = reader.readDnsName() ?? ""
            case .TXT:
                rdata = reader.readTxtData(length: Int(rdlength)) ?? ""
            default:
                break
            }

            // Ensure we advance past the full RDATA regardless of what we consumed.
            reader.offset = rdataStart + Int(rdlength)

            records.append(ResourceRecord(name: name, type: recordType, rdata: rdata, ttl: ttl))
        }
        return records
    }
}

// MARK: - DNS Wire Format Reader

/// Low-level reader for DNS wire format with support for label compression (RFC 1035 section 4.1.4).
private struct DnsReader {
    let data: Data
    var offset: Int = 0

    mutating func readUInt16() -> UInt16? {
        guard offset + 2 <= data.count else { return nil }
        let value = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        offset += 2
        return value
    }

    mutating func readUInt32() -> UInt32? {
        guard offset + 4 <= data.count else { return nil }
        let value = UInt32(data[offset]) << 24
                  | UInt32(data[offset + 1]) << 16
                  | UInt32(data[offset + 2]) << 8
                  | UInt32(data[offset + 3])
        offset += 4
        return value
    }

    /// Reads a DNS domain name, handling label compression pointers.
    mutating func readDnsName() -> String? {
        var labels: [String] = []
        var jumped = false
        var currentOffset = offset
        var maxJumps = 20  // safety limit to prevent infinite loops

        while currentOffset < data.count {
            let length = Int(data[currentOffset])

            if length == 0 {
                // End of name.
                if !jumped {
                    offset = currentOffset + 1
                }
                return labels.joined(separator: ".")
            }

            // Check for compression pointer (top 2 bits set).
            if length & 0xC0 == 0xC0 {
                guard currentOffset + 1 < data.count else { return nil }
                let pointer = (Int(data[currentOffset]) & 0x3F) << 8 | Int(data[currentOffset + 1])
                if !jumped {
                    offset = currentOffset + 2
                    jumped = true
                }
                currentOffset = pointer
                maxJumps -= 1
                if maxJumps <= 0 { return nil }
                continue
            }

            // Regular label.
            currentOffset += 1
            guard currentOffset + length <= data.count else { return nil }
            let labelData = data[currentOffset..<(currentOffset + length)]
            if let label = String(data: labelData, encoding: .utf8) {
                labels.append(label)
            }
            currentOffset += length
        }

        if !jumped {
            offset = currentOffset
        }
        return labels.isEmpty ? nil : labels.joined(separator: ".")
    }

    /// Reads a 4-byte IPv4 address and returns it as a dotted-decimal string.
    mutating func readIPv4Address() -> String? {
        guard offset + 4 <= data.count else { return nil }
        let a = data[offset]
        let b = data[offset + 1]
        let c = data[offset + 2]
        let d = data[offset + 3]
        offset += 4
        return "\(a).\(b).\(c).\(d)"
    }

    /// Reads TXT record data. TXT records contain one or more length-prefixed strings.
    mutating func readTxtData(length: Int) -> String? {
        let end = offset + length
        guard end <= data.count else { return nil }

        var parts: [String] = []
        var pos = offset

        while pos < end {
            let strLen = Int(data[pos])
            pos += 1
            guard pos + strLen <= end else { break }
            let strData = data[pos..<(pos + strLen)]
            if let str = String(data: strData, encoding: .utf8) {
                parts.append(str)
            }
            pos += strLen
        }

        // Do NOT advance offset here — the caller (parseRecords) resets it via rdataStart + rdlength.
        return parts.joined()
    }
}

// MARK: - Data Helpers

private extension Data {
    /// Appends a 16-bit value in network (big-endian) byte order.
    mutating func appendUInt16(_ value: UInt16) {
        var big = value.bigEndian
        append(UnsafeBufferPointer(start: &big, count: 1))
    }

    /// Encodes a domain name as a sequence of DNS labels (length-prefixed).
    mutating func appendDnsName(_ name: String) {
        let labels = name.split(separator: ".", omittingEmptySubsequences: true)
        for label in labels {
            let utf8 = Array(label.utf8)
            append(UInt8(utf8.count))
            append(contentsOf: utf8)
        }
        append(0) // Root label terminator.
    }
}
