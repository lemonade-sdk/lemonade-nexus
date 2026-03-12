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

    var url: String { "https://\(ip):\(port)" }

    /// Display label: hostname if available, otherwise IP address.
    var displayName: String { hostname ?? ip }
}

// MARK: - DnsDiscoveryService

/// Discovers SecurePunch/Lemonade-Nexus servers via the mesh DNS service.
///
/// Discovery flow:
///  1. Bootstrap: resolve the domain via standard DNS (getaddrinfo) to find initial server IPs.
///  2. NS expansion: query each bootstrap IP on port 5353 for NS records of the zone, which
///     returns all Tier 1 nameservers with glue A records (their public IPs).
///  3. Config lookup: query `_config.<hostname>` TXT records on port 5353 to learn the HTTP port.
///  4. Health probe: hit `/api/health` over HTTPS on each discovered server to measure latency.
///  5. Return servers sorted by ascending latency (closest first).
final class DnsDiscoveryService: @unchecked Sendable {
    private let domain: String
    private let dnsPort: UInt16 = 53
    private let defaultHttpPort: Int = 9100

    /// Per-query timeout for UDP DNS requests.
    private let queryTimeout: TimeInterval = 3.0

    init(domain: String = "lemonade-nexus.io") {
        self.domain = domain
    }

    // MARK: - Public API

    func discoverServers() async -> [DiscoveredServer] {
        dlog("[Discovery] Starting discovery for domain: \(domain)")

        // Step 1: Bootstrap — resolve A records via system DNS.
        let bootstrapIPs = await resolveBootstrapIPs()
        dlog("[Discovery] Step 1 — Bootstrap IPs: \(bootstrapIPs)")
        guard !bootstrapIPs.isEmpty else {
            dlog("[Discovery] No bootstrap IPs found — aborting")
            return []
        }

        // Step 2: Query NS records from each bootstrap IP to discover all mesh servers.
        var allServers: [(hostname: String?, ip: String)] = bootstrapIPs.map { (nil, $0) }
        let nsResults = await queryNSRecordsFromPeers(peerIPs: bootstrapIPs)
        dlog("[Discovery] Step 2 — NS results: \(nsResults.map { "\($0.hostname)=\($0.ip)" })")
        for entry in nsResults {
            if !allServers.contains(where: { $0.ip == entry.ip }) {
                allServers.append((entry.hostname, entry.ip))
            }
        }
        dlog("[Discovery] All servers to probe: \(allServers.map { "\($0.hostname ?? "?")@\($0.ip)" })")

        // Step 3: Query _config TXT records to discover HTTP ports, then probe health.
        var results: [DiscoveredServer] = []
        await withTaskGroup(of: DiscoveredServer?.self) { group in
            for server in allServers {
                group.addTask {
                    await self.resolveAndProbe(ip: server.ip, hostname: server.hostname)
                }
            }
            for await result in group {
                if let server = result {
                    dlog("[Discovery] Step 4 — Server found: \(server.displayName) @ \(server.ip):\(server.port) (\(String(format: "%.0f", server.latencyMs))ms)")
                    results.append(server)
                } else {
                    dlog("[Discovery] Step 4 — A probe returned nil")
                }
            }
        }

        dlog("[Discovery] Final result: \(results.count) server(s) discovered")
        return results.sorted { $0.latencyMs < $1.latencyMs }
    }

    // MARK: - Step 1: Bootstrap via getaddrinfo

    private func resolveBootstrapIPs() async -> [String] {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async { [domain] in
                var hints = addrinfo()
                hints.ai_family = AF_INET
                hints.ai_socktype = SOCK_STREAM

                var result: UnsafeMutablePointer<addrinfo>?
                let status = getaddrinfo(domain, nil, &hints, &result)

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

    // MARK: - Step 2: Query NS records from bootstrap peers

    /// Represents a nameserver discovered via an NS query's additional (glue) section.
    private struct NameserverEntry {
        let hostname: String
        let ip: String
    }

    /// Queries multiple peer IPs for NS records concurrently. Returns unique nameserver entries.
    private func queryNSRecordsFromPeers(peerIPs: [String]) async -> [NameserverEntry] {
        var entries: [NameserverEntry] = []
        await withTaskGroup(of: [NameserverEntry].self) { group in
            for ip in peerIPs {
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

    // MARK: - Step 3: Config TXT + Health Probe

    /// For a given server IP, optionally queries its _config TXT record to get the HTTP port,
    /// then probes the health endpoint.
    private func resolveAndProbe(ip: String, hostname: String?) async -> DiscoveredServer? {
        // Try to get the HTTP port from the _config TXT record.
        var httpPort = defaultHttpPort
        var resolvedHostname = hostname

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
                            }
                        }
                        break
                    }
                }
            }
        }

        // Step 4: Probe the server's HTTPS health endpoint.
        return await probeServer(ip: ip, port: httpPort, hostname: resolvedHostname)
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

    // MARK: - Step 4: Health Probe (HTTPS with HTTP fallback)

    private func probeServer(ip: String, port: Int, hostname: String?) async -> DiscoveredServer? {
        // Try HTTPS first, fall back to HTTP if the server doesn't have a TLS cert yet.
        for scheme in ["https", "http"] {
            let urlString = "\(scheme)://\(ip):\(port)/api/health"
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
                return DiscoveredServer(ip: ip, port: port, latencyMs: elapsed, hostname: hostname)
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
