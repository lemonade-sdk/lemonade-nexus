import Foundation

struct DiscoveredServer: Identifiable {
    let id = UUID()
    let ip: String
    let port: Int
    let latencyMs: Double

    var url: String { "https://\(ip):\(port)" }
}

final class DnsDiscoveryService: @unchecked Sendable {
    private let domain: String
    private let defaultPort: Int = 9100

    init(domain: String = "lemonade-nexus.io") {
        self.domain = domain
    }

    func discoverServers() async -> [DiscoveredServer] {
        let ips = await resolveARecords()
        guard !ips.isEmpty else { return [] }

        var servers: [DiscoveredServer] = []
        await withTaskGroup(of: DiscoveredServer?.self) { group in
            for ip in ips {
                group.addTask { [defaultPort] in
                    await self.probeServer(ip: ip, port: defaultPort)
                }
            }
            for await result in group {
                if let server = result {
                    servers.append(server)
                }
            }
        }

        return servers.sorted { $0.latencyMs < $1.latencyMs }
    }

    // MARK: - DNS Resolution

    private func resolveARecords() async -> [String] {
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
                        var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                        if getnameinfo(
                            addr.pointee.ai_addr, addr.pointee.ai_addrlen,
                            &hostname, socklen_t(hostname.count),
                            nil, 0, NI_NUMERICHOST
                        ) == 0 {
                            let ip = String(cString: hostname)
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

    // MARK: - Server Probing

    private func probeServer(ip: String, port: Int) async -> DiscoveredServer? {
        let urlString = "https://\(ip):\(port)/api/health"
        guard let url = URL(string: urlString) else { return nil }

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
                return nil
            }
            return DiscoveredServer(ip: ip, port: port, latencyMs: elapsed)
        } catch {
            return nil
        }
    }
}
