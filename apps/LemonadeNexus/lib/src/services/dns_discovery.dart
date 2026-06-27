/// DNS-based server auto-discovery for Lemonade Nexus.
///
/// A faithful Dart port of the macOS `DnsDiscovery.swift` service.
///
/// Discovery flow (region-aware):
///  1. Bootstrap: resolve the base domain via standard DNS to find initial server IPs.
///  2. NS expansion: query each bootstrap IP for NS records of the zone.
///  3. Determine the client's own region via geo-IP lookup (locale fallback).
///  4. Query SEIP records for the client's region first (`<region>.seip.<domain>`).
///  5. If no servers found in region, query all SEIP regions by geographic distance.
///  6. Fallback to legacy NS-hostname-based discovery for backward compatibility.
///  7. Sort by score (latency + load penalty), return best servers first.
///
/// IMPLEMENTATION NOTE: Unlike the Swift original which speaks raw UDP DNS via
/// `NWConnection`, this port performs all DNS lookups over DNS-over-HTTPS (DoH)
/// against `https://dns.google/resolve`. This is cross-platform, works inside the
/// macOS app sandbox, and avoids hand-rolling RFC 1035 wire packets. The semantics
/// of the queries (A / NS / TXT) and the parsing of answers/glue are preserved.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:http/http.dart' as http;

// ignore: avoid_print
void _dlog(String msg) => print(msg);

// =============================================================================
// DiscoveredServer
// =============================================================================

/// A server discovered via the mesh DNS service.
///
/// Mirrors the Swift `DiscoveredServer` struct.
class DiscoveredServer {
  final String ip;
  final int port;
  final double latencyMs;
  final String? hostname;

  /// "https" or "http" — whichever probe succeeded.
  final String scheme;

  String? region;
  int? load;

  /// latency_ms + (load * 10)
  double score;

  /// Host to connect to (the cert's CN) when it differs from the display
  /// `hostname`. Not populated by the DoH/HTTP port (no TLS delegate to observe
  /// the cert CN), kept for API parity with the Swift struct.
  String? connectHost;

  DiscoveredServer({
    required this.ip,
    required this.port,
    required this.latencyMs,
    this.hostname,
    required this.scheme,
    this.region,
    this.load,
    required this.score,
    this.connectHost,
  });

  /// Host to connect to (the cert's CN) when it differs from the display
  /// `hostname`, otherwise the hostname, otherwise the IP.
  String get url {
    final host = connectHost ?? hostname ?? ip;
    return '$scheme://$host:$port';
  }

  /// Display label: hostname if available, otherwise IP address. Includes
  /// region if known.
  String get displayName {
    final base = hostname ?? ip;
    if (region != null) {
      return '$base ($region)';
    }
    return base;
  }

  @override
  bool operator ==(Object other) =>
      other is DiscoveredServer &&
      other.ip == ip &&
      other.port == port &&
      other.scheme == scheme &&
      other.hostname == hostname;

  @override
  int get hashCode => Object.hash(ip, port, scheme, hostname);

  @override
  String toString() =>
      'DiscoveredServer($displayName @ $ip:$port score=${score.toStringAsFixed(1)})';
}

// =============================================================================
// DnsDiscoveryService
// =============================================================================

/// Discovers Lemonade-Nexus servers via the mesh DNS service.
class DnsDiscoveryService {
  final String domain;
  final int defaultHttpPort;

  /// Per-query timeout for DoH requests.
  final Duration queryTimeout;

  /// Cached region for the current session (avoid re-detecting on every call).
  String? _cachedRegion;
  bool _regionDetected = false;

  /// A human-readable description of the most recent discovery outcome,
  /// suitable for surfacing in the UI as a status message.
  String? lastMessage;

  /// Cloud region codes and their approximate geographic centroids.
  ///
  /// Preserved exactly from the Swift source.
  static const List<_CloudRegion> _cloudRegions = [
    _CloudRegion('us-east', 39.0, -77.0),
    _CloudRegion('us-west', 37.4, -122.0),
    _CloudRegion('us-central', 41.8, -93.0),
    _CloudRegion('ca-central', 45.5, -73.6),
    _CloudRegion('eu-west', 53.3, -6.3),
    _CloudRegion('eu-central', 50.1, 8.7),
    _CloudRegion('eu-north', 59.3, 18.1),
    _CloudRegion('ap-south', 19.1, 72.9),
    _CloudRegion('ap-southeast', 1.3, 103.8),
    _CloudRegion('ap-northeast', 35.7, 139.7),
    _CloudRegion('ap-east', 22.3, 114.2),
    _CloudRegion('sa-east', -23.5, -46.6),
    _CloudRegion('af-south', -33.9, 18.4),
    _CloudRegion('me-south', 26.1, 50.2),
    _CloudRegion('oc-south', -33.9, 151.2),
  ];

  DnsDiscoveryService({
    this.domain = 'lemonade-nexus.io',
    this.defaultHttpPort = 9100,
    this.queryTimeout = const Duration(seconds: 3),
  });

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /// Runs the full region-aware discovery flow and returns servers best-first.
  ///
  /// Never throws; returns an empty list on total failure. Inspect [lastMessage]
  /// for a human-readable description of the outcome.
  Future<List<DiscoveredServer>> discoverServers() async {
    try {
      _dlog('[Discovery] Starting region-aware discovery for domain: $domain');

      // Step 1: Bootstrap — resolve A records via DoH.
      var bootstrapIPs = await _resolveBootstrapIPs();
      _dlog('[Discovery] Step 1 — Bootstrap IPs: $bootstrapIPs');

      // Fallback: if the base domain has no A record, resolve NS hostnames directly.
      if (bootstrapIPs.isEmpty) {
        _dlog('[Discovery] Step 1b — No A record, trying NS hostname resolution');
        bootstrapIPs = await _resolveBootstrapIPs(hostname: 'ns1.$domain');
        _dlog('[Discovery] Step 1b — NS fallback IPs: $bootstrapIPs');
      }

      if (bootstrapIPs.isEmpty) {
        _dlog('[Discovery] No bootstrap IPs found — aborting');
        lastMessage = 'No servers found for $domain';
        return [];
      }

      // Step 2: Query NS records to discover all mesh servers.
      final nsServers = await _resolveNSRecords(bootstrapIPs: bootstrapIPs);
      _dlog('[Discovery] Step 2 — NS servers: '
          '${nsServers.map((e) => '${e.hostname ?? '?'}@${e.ip}').toList()}');

      // Step 3: Determine our region.
      final ourRegion = await _determineOwnRegion();
      _dlog('[Discovery] Step 3 — Our region: ${ourRegion ?? 'unknown'}');

      // Step 4: Query SEIP records for our region first.
      final servers = <DiscoveredServer>[];
      if (ourRegion != null) {
        final regionServers =
            await _querySEIPRegion(region: ourRegion, nameservers: nsServers);
        servers.addAll(regionServers);
        _dlog("[Discovery] Step 4 — Region '$ourRegion' servers: "
            '${regionServers.length}');
      }

      // Step 5: If no servers in our region, try all regions.
      if (servers.isEmpty) {
        _dlog('[Discovery] Step 5 — No regional servers, querying all SEIP regions');
        final allServers = await _queryAllSEIPServers(
          nameservers: nsServers,
          clientRegion: ourRegion,
        );
        servers.addAll(allServers);
        _dlog('[Discovery] Step 5 — All-region servers: ${allServers.length}');
      }

      // Step 6: Fallback to legacy discovery (backward compat).
      if (servers.isEmpty) {
        _dlog('[Discovery] Step 6 — Falling back to legacy discovery');
        final legacy =
            await _legacyDiscovery(nsServers: nsServers, bootstrapIPs: bootstrapIPs);
        servers.addAll(legacy);
        _dlog('[Discovery] Step 6 — Legacy servers: ${servers.length}');
      }

      // Step 7: Sort by score (latency + load penalty).
      servers.sort((a, b) => a.score.compareTo(b.score));
      _dlog('[Discovery] Final result: ${servers.length} server(s) discovered');

      if (servers.isEmpty) {
        lastMessage = 'No reachable servers found for $domain';
      } else {
        lastMessage = 'Found ${servers.length} server'
            '${servers.length == 1 ? '' : 's'} (best: ${servers.first.displayName})';
      }
      return servers;
    } catch (e) {
      _dlog('[Discovery] Discovery failed with error: $e');
      lastMessage = 'Discovery failed: $e';
      return [];
    }
  }

  // ---------------------------------------------------------------------------
  // Step 1: Bootstrap (A records)
  // ---------------------------------------------------------------------------

  Future<List<String>> _resolveBootstrapIPs({String? hostname}) async {
    final target = hostname ?? domain;
    final answers = await _doh.query(name: target, type: _DnsType.a);
    final ips = <String>[];
    for (final a in answers) {
      if (a.type == _DnsType.a && !ips.contains(a.data)) {
        ips.add(a.data);
      }
    }
    return ips;
  }

  // ---------------------------------------------------------------------------
  // Step 2: Resolve NS records
  // ---------------------------------------------------------------------------

  Future<List<_NameserverEntry>> _resolveNSRecords({
    required List<String> bootstrapIPs,
  }) async {
    final entries = <_NameserverEntry>[
      for (final ip in bootstrapIPs) _NameserverEntry(hostname: null, ip: ip),
    ];

    // With DoH there is no per-server querying; a single zone NS query resolves
    // the nameserver hostnames, which we then resolve to glue IPs. This is the
    // DoH-equivalent of the Swift per-bootstrap-IP NS query + glue parsing.
    final results = await _queryNSRecords();
    for (final entry in results) {
      if (!entries.any((e) => e.ip == entry.ip)) {
        entries.add(entry);
      }
    }
    return entries;
  }

  /// Queries NS records for the zone and resolves each NS hostname to an IP
  /// (the DoH analogue of reading glue A records from the additional section).
  Future<List<_NameserverEntry>> _queryNSRecords() async {
    final nsAnswers = await _doh.query(name: domain, type: _DnsType.ns);
    final nsHostnames = <String>[
      for (final r in nsAnswers)
        if (r.type == _DnsType.ns) _stripTrailingDot(r.data),
    ];

    final entries = <_NameserverEntry>[];
    await Future.wait(nsHostnames.map((nsHost) async {
      final aAnswers = await _doh.query(name: nsHost, type: _DnsType.a);
      for (final a in aAnswers) {
        if (a.type == _DnsType.a) {
          entries.add(_NameserverEntry(hostname: nsHost, ip: a.data));
          break; // one IP per NS hostname, matching glue-map behaviour
        }
      }
    }));
    return entries;
  }

  // ---------------------------------------------------------------------------
  // Step 3: Region detection
  // ---------------------------------------------------------------------------

  /// Determines the client's own cloud region by geo-IP lookup.
  /// Result is cached for the session.
  Future<String?> _determineOwnRegion() async {
    if (_regionDetected) {
      return _cachedRegion;
    }
    final detected = await _detectRegionViaGeoIP();
    _cachedRegion = detected;
    _regionDetected = true;
    return detected;
  }

  Future<String?> _detectRegionViaGeoIP() async {
    final uri = Uri.parse('http://ip-api.com/json/?fields=lat,lon,regionName,countryCode');
    try {
      final resp = await http.get(uri).timeout(const Duration(seconds: 5));
      final json = jsonDecode(resp.body);
      if (json is! Map<String, dynamic>) {
        _dlog('[Discovery] Region: failed to parse geo-IP response');
        return _regionFromLocale();
      }
      final lat = _asDouble(json['lat']);
      final lon = _asDouble(json['lon']);
      if (lat == null || lon == null) {
        _dlog('[Discovery] Region: failed to parse geo-IP response');
        return _regionFromLocale();
      }
      final nearest = _nearestCloudRegion(lat, lon);
      _dlog('[Discovery] Region: geo-IP lat=$lat lon=$lon -> $nearest');
      return nearest;
    } catch (e) {
      _dlog('[Discovery] Region: geo-IP lookup failed — $e');
      return _regionFromLocale();
    }
  }

  /// Fallback: guess a rough region from the system locale.
  String? _regionFromLocale() {
    final regionCode = _localeCountryCode();
    if (regionCode == null) return null;
    _dlog("[Discovery] Region: falling back to locale region code '$regionCode'");

    switch (regionCode) {
      case 'US':
        return 'us-east'; // default US region
      case 'CA':
        return 'ca-central';
      case 'GB':
      case 'IE':
        return 'eu-west';
      case 'DE':
      case 'FR':
      case 'NL':
      case 'BE':
      case 'AT':
      case 'CH':
        return 'eu-central';
      case 'SE':
      case 'NO':
      case 'FI':
      case 'DK':
        return 'eu-north';
      case 'IN':
        return 'ap-south';
      case 'SG':
      case 'MY':
      case 'ID':
      case 'TH':
      case 'VN':
      case 'PH':
        return 'ap-southeast';
      case 'JP':
      case 'KR':
        return 'ap-northeast';
      case 'HK':
      case 'TW':
        return 'ap-east';
      case 'BR':
      case 'AR':
      case 'CL':
      case 'CO':
        return 'sa-east';
      case 'ZA':
        return 'af-south';
      case 'AE':
      case 'SA':
      case 'BH':
      case 'QA':
        return 'me-south';
      case 'AU':
      case 'NZ':
        return 'oc-south';
      default:
        return null;
    }
  }

  /// Extracts an uppercased ISO country code from `Platform.localeName`
  /// (e.g. "en_US.UTF-8" -> "US", "de-DE" -> "DE").
  String? _localeCountryCode() {
    final locale = Platform.localeName; // e.g. en_US.UTF-8
    if (locale.isEmpty) return null;
    // Strip any encoding suffix (".UTF-8") then split on '_' or '-'.
    final base = locale.split('.').first;
    final parts = base.split(RegExp(r'[_-]'));
    if (parts.length < 2) return null;
    final code = parts[1].trim().toUpperCase();
    return code.isEmpty ? null : code;
  }

  /// Finds the nearest cloud region to the given lat/lon using haversine distance.
  static String _nearestCloudRegion(double lat, double lon) {
    var bestCode = _cloudRegions[0].code;
    var bestDist = double.maxFinite;
    for (final region in _cloudRegions) {
      final dist = _haversineDistance(lat, lon, region.lat, region.lon);
      if (dist < bestDist) {
        bestDist = dist;
        bestCode = region.code;
      }
    }
    return bestCode;
  }

  /// Haversine distance in kilometers between two lat/lon points.
  static double _haversineDistance(
      double lat1, double lon1, double lat2, double lon2) {
    const r = 6371.0; // Earth radius in km
    final dLat = (lat2 - lat1) * math.pi / 180.0;
    final dLon = (lon2 - lon1) * math.pi / 180.0;
    final a = math.sin(dLat / 2) * math.sin(dLat / 2) +
        math.cos(lat1 * math.pi / 180.0) *
            math.cos(lat2 * math.pi / 180.0) *
            math.sin(dLon / 2) *
            math.sin(dLon / 2);
    final c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a));
    return r * c;
  }

  /// Returns cloud region codes sorted by geographic distance from the coords.
  static List<String> _regionCodesByDistance(double lat, double lon) {
    final scored = _cloudRegions
        .map((r) => (
              code: r.code,
              dist: _haversineDistance(lat, lon, r.lat, r.lon),
            ))
        .toList()
      ..sort((a, b) => a.dist.compareTo(b.dist));
    return scored.map((e) => e.code).toList();
  }

  // ---------------------------------------------------------------------------
  // Step 4: Query SEIP region
  // ---------------------------------------------------------------------------

  /// Queries A records for `<region>.seip.<domain>` and probes each server.
  Future<List<DiscoveredServer>> _querySEIPRegion({
    required String region,
    required List<_NameserverEntry> nameservers,
  }) async {
    final qname = '$region.seip.$domain';
    _dlog('[Discovery] SEIP query: $qname');

    // Collect A record IPs for this region. Over DoH, one authoritative resolve
    // returns the same set the Swift code aggregated across all nameservers.
    final regionIPs = <String>[];
    final answers = await _doh.query(name: qname, type: _DnsType.a);
    for (final a in answers) {
      if (a.type == _DnsType.a && !regionIPs.contains(a.data)) {
        regionIPs.add(a.data);
      }
    }

    _dlog("[Discovery] SEIP region '$region' IPs: $regionIPs");
    if (regionIPs.isEmpty) return [];

    // Probe each IP concurrently.
    final results = await Future.wait(regionIPs.map(
      (ip) => _resolveAndProbe(ip: ip, hostname: null, expectedRegion: region),
    ));
    return results.whereType<DiscoveredServer>().toList();
  }

  // ---------------------------------------------------------------------------
  // Step 5: Query all SEIP regions
  // ---------------------------------------------------------------------------

  Future<List<DiscoveredServer>> _queryAllSEIPServers({
    required List<_NameserverEntry> nameservers,
    required String? clientRegion,
  }) async {
    List<String> orderedRegions;
    _CloudRegion? regionEntry;
    if (clientRegion != null) {
      for (final r in _cloudRegions) {
        if (r.code == clientRegion) {
          regionEntry = r;
          break;
        }
      }
    }
    if (regionEntry != null) {
      orderedRegions = _regionCodesByDistance(regionEntry.lat, regionEntry.lon);
    } else {
      // No client region known — just try all in default order.
      orderedRegions = _cloudRegions.map((r) => r.code).toList();
    }

    // Query all regions concurrently for speed.
    final perRegion = await Future.wait(orderedRegions.map(
      (region) => _querySEIPRegion(region: region, nameservers: nameservers),
    ));
    return perRegion.expand((e) => e).toList();
  }

  // ---------------------------------------------------------------------------
  // Step 6: Legacy discovery (backward compat)
  // ---------------------------------------------------------------------------

  Future<List<DiscoveredServer>> _legacyDiscovery({
    required List<_NameserverEntry> nsServers,
    required List<String> bootstrapIPs,
  }) async {
    _dlog('[Discovery] Legacy: probing ${nsServers.length} NS servers');

    final results = await Future.wait(nsServers.map(
      (server) => _resolveAndProbe(
        ip: server.ip,
        hostname: server.hostname,
        expectedRegion: null,
      ),
    ));

    final out = <DiscoveredServer>[];
    for (final s in results) {
      if (s != null) {
        _dlog('[Discovery] Legacy — Server found: ${s.displayName} @ '
            '${s.ip}:${s.port} (${s.latencyMs.toStringAsFixed(0)}ms)');
        out.add(s);
      }
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Config TXT + health probe
  // ---------------------------------------------------------------------------

  /// Parse `region=<code>` and `load=<int>` from a TXT record value.
  static ({String? region, int? load}) _parseRegionAndLoad(String txt) {
    String? region;
    int? load;
    for (final part in txt.split(' ')) {
      final kv = part.split('=');
      if (kv.length >= 2) {
        final key = kv[0];
        final value = kv.sublist(1).join('=');
        if (key == 'region') region = value;
        if (key == 'load') load = int.tryParse(value);
      }
    }
    return (region: region, load: load);
  }

  /// Parse `http=<port>` from a TXT value like "v=sp1 http=9100 udp=51940 ...".
  static int? _parseHttpPort(String txt) {
    for (final part in txt.split(' ')) {
      if (part.startsWith('http=')) {
        return int.tryParse(part.substring('http='.length));
      }
    }
    return null;
  }

  /// Parse `host=<fqdn>` from a TXT value like "v=sp1 http=9100 host=ns1...".
  static String? _parseHost(String txt) {
    for (final part in txt.split(' ')) {
      if (part.startsWith('host=')) {
        final value = part.substring('host='.length);
        return value.isEmpty ? null : value;
      }
    }
    return null;
  }

  /// For a given server IP, optionally queries its `_config` TXT record to get
  /// the HTTP port, region, load and cert host, then probes the health endpoint.
  Future<DiscoveredServer?> _resolveAndProbe({
    required String ip,
    required String? hostname,
    required String? expectedRegion,
  }) async {
    var httpPort = defaultHttpPort;
    var resolvedHostname = hostname;
    var discoveredRegion = expectedRegion;
    int? discoveredLoad;

    // If we have a hostname (FQDN from NS response), query _config.<hostname>.
    if (hostname != null) {
      final configName = '_config.$hostname';
      final answers = await _doh.query(name: configName, type: _DnsType.txt);
      for (final record in answers) {
        if (record.type != _DnsType.txt) continue;
        final txt = record.data;
        final port = _parseHttpPort(txt);
        if (port != null) httpPort = port;
        final certHost = _parseHost(txt);
        if (certHost != null) {
          resolvedHostname = certHost;
          _dlog('[Discovery]   TXT host=$certHost (cert FQDN)');
        }
        final regionLoad = _parseRegionAndLoad(txt);
        if (regionLoad.region != null) discoveredRegion = regionLoad.region;
        if (regionLoad.load != null) discoveredLoad = regionLoad.load;
      }
    }

    // Probe the server's health endpoint.
    final probed =
        await _probeServer(ip: ip, port: httpPort, hostname: resolvedHostname);
    if (probed == null) return null;

    // Populate region + load + score.
    probed.region = discoveredRegion;
    probed.load = discoveredLoad;
    probed.score = probed.latencyMs + (probed.load ?? 0) * 10.0;

    _dlog('[Discovery]   Scored: ${probed.displayName} '
        'score=${probed.score.toStringAsFixed(1)} '
        '(latency=${probed.latencyMs.toStringAsFixed(0)}ms '
        'load=${probed.load ?? 0} region=${probed.region ?? '?'})');

    return probed;
  }

  // ---------------------------------------------------------------------------
  // Health probe (HTTPS with HTTP fallback)
  // ---------------------------------------------------------------------------

  Future<DiscoveredServer?> _probeServer({
    required String ip,
    required int port,
    required String? hostname,
  }) async {
    // Try HTTPS first (using hostname for cert CN match), fall back to IP, then HTTP.
    final host = hostname ?? ip;
    final probeTargets = hostname != null
        ? <(String, String)>[('https', host), ('https', ip), ('http', ip)]
        : <(String, String)>[('https', ip), ('http', ip)];

    for (final (scheme, target) in probeTargets) {
      final uri = Uri.tryParse('$scheme://$target:$port/api/health');
      if (uri == null) continue;

      // Raw HttpClient so we can read the peer (leaf) certificate after the
      // response. The SDK does strict TLS verification, so it must connect by
      // the cert's hostname (CN) rather than the bare IP (which fails to verify).
      final inner = HttpClient()
        ..connectionTimeout = const Duration(seconds: 5)
        ..badCertificateCallback = (cert, h, p) => true;

      _dlog('[Discovery]   Probe: $uri');
      final stopwatch = Stopwatch()..start();
      try {
        final req = await inner.getUrl(uri).timeout(const Duration(seconds: 8));
        final resp = await req.close().timeout(const Duration(seconds: 8));
        final elapsed = stopwatch.elapsedMicroseconds / 1000.0;
        // Leaf certificate of the peer (NOT a CA in the chain); its CN is the
        // server's real FQDN.
        final certCn =
            resp.certificate != null ? _cnOf(resp.certificate!.subject) : null;
        await resp.drain<void>();
        if (resp.statusCode < 200 || resp.statusCode >= 300) {
          _dlog('[Discovery]   Probe: $scheme returned status ${resp.statusCode}');
          inner.close();
          continue;
        }
        // The leaf CN is the server's real hostname. Use it as the DISPLAY host
        // when DNS gave us none (our DoH path can't read the server's per-IP
        // _config TXT), and as the CONNECT host when it differs from the display
        // host — the SDK does strict TLS verification, so it must connect by a
        // cert-matching name, not the bare IP.
        final certHost = (scheme == 'https' &&
                certCn != null &&
                certCn.contains('.') &&
                certCn != ip &&
                certCn != target)
            ? certCn
            : null;
        final displayHost = hostname ?? certHost;
        final connectHost =
            (certHost != null && certHost != displayHost) ? certHost : null;
        _dlog('[Discovery]   Probe: $scheme OK — ${elapsed.toStringAsFixed(0)}ms'
            '${displayHost != null ? ' (host $displayHost)' : ''}');
        inner.close();
        return DiscoveredServer(
          ip: ip,
          port: port,
          latencyMs: elapsed,
          hostname: displayHost,
          scheme: scheme,
          region: null,
          load: null,
          score: elapsed,
          connectHost: connectHost,
        );
      } catch (e) {
        _dlog('[Discovery]   Probe: $scheme failed — $e');
        inner.close();
        continue;
      }
    }
    _dlog('[Discovery]   Probe: all schemes failed for $ip:$port');
    return null;
  }

  // ---------------------------------------------------------------------------
  // Shared HTTP clients
  // ---------------------------------------------------------------------------

  late final _doh = _DohResolver(queryTimeout: queryTimeout);

  /// HTTP client used for health probes. Wraps a `dart:io` [HttpClient] that
  /// accepts self-signed / mismatched certificates — the Dart analogue of the
  /// Swift `InsecureSessionDelegate` — since discovered servers commonly present
  /// certs that don't match the bare IP. Exposed through the `http` package API.
  /// Releases the underlying HTTP clients. Call when discovery is no longer used.
  void close() {
    _doh.close();
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  static double? _asDouble(Object? v) {
    if (v is double) return v;
    if (v is int) return v.toDouble();
    if (v is String) return double.tryParse(v);
    return null;
  }

  static String _stripTrailingDot(String s) =>
      s.endsWith('.') ? s.substring(0, s.length - 1) : s;

  /// Common Name from an X.509 subject string (e.g. "...CN=host.example...").
  static String? _cnOf(String subject) {
    final m = RegExp(r'CN=([^,/]+)').firstMatch(subject);
    return m?.group(1)?.trim();
  }
}

// =============================================================================
// Internal types
// =============================================================================

class _CloudRegion {
  final String code;
  final double lat;
  final double lon;
  const _CloudRegion(this.code, this.lat, this.lon);
}

/// A nameserver discovered via an NS query (hostname + resolved IP).
class _NameserverEntry {
  final String? hostname;
  final String ip;
  const _NameserverEntry({required this.hostname, required this.ip});
}

// =============================================================================
// DNS-over-HTTPS resolver
// =============================================================================

enum _DnsType {
  a(1),
  ns(2),
  txt(16);

  final int code;
  const _DnsType(this.code);

  static _DnsType? fromCode(int code) {
    for (final t in _DnsType.values) {
      if (t.code == code) return t;
    }
    return null;
  }
}

/// A single DoH answer record (already normalised: A=IP string, NS=hostname,
/// TXT=concatenated character-strings with surrounding quotes stripped).
class _DohAnswer {
  final String name;
  final _DnsType type;
  final String data;
  const _DohAnswer({required this.name, required this.type, required this.data});
}

/// Resolves DNS records over DNS-over-HTTPS (`https://dns.google/resolve`).
///
/// This replaces the Swift code's raw UDP transport + RFC 1035 packet builder
/// and response parser. The DoH JSON API returns the same logical answer set.
class _DohResolver {
  final Duration queryTimeout;
  final http.Client _client = http.Client();

  _DohResolver({required this.queryTimeout});

  Future<List<_DohAnswer>> query({
    required String name,
    required _DnsType type,
  }) async {
    final typeName = switch (type) {
      _DnsType.a => 'A',
      _DnsType.ns => 'NS',
      _DnsType.txt => 'TXT',
    };
    final uri = Uri.https('dns.google', '/resolve', {
      'name': name,
      'type': typeName,
    });

    try {
      final resp = await _client
          .get(uri, headers: const {'accept': 'application/dns-json'})
          .timeout(queryTimeout);
      if (resp.statusCode != 200) {
        return const [];
      }
      final json = jsonDecode(resp.body);
      if (json is! Map<String, dynamic>) return const [];
      final answerList = json['Answer'];
      if (answerList is! List) return const [];

      final out = <_DohAnswer>[];
      for (final entry in answerList) {
        if (entry is! Map<String, dynamic>) continue;
        final typeCode = entry['type'];
        if (typeCode is! int) continue;
        final recType = _DnsType.fromCode(typeCode);
        if (recType == null) continue;
        final rawData = entry['data'];
        if (rawData is! String) continue;
        final recName = (entry['name'] as String?) ?? '';

        out.add(_DohAnswer(
          name: _stripDot(recName),
          type: recType,
          data: _normaliseData(recType, rawData),
        ));
      }
      return out;
    } catch (_) {
      return const [];
    }
  }

  /// Normalises DoH `data` to match what the Swift parser produced:
  ///  - A: dotted-decimal IPv4 (already in that form)
  ///  - NS: hostname without a trailing dot
  ///  - TXT: character-strings joined, with the surrounding quotes the DoH API
  ///    wraps each string in stripped.
  static String _normaliseData(_DnsType type, String data) {
    switch (type) {
      case _DnsType.a:
        return data;
      case _DnsType.ns:
        return _stripDot(data);
      case _DnsType.txt:
        return _decodeTxt(data);
    }
  }

  /// DoH presents TXT records as one or more double-quoted character-strings,
  /// e.g. `"v=sp1 http=9100" "region=us-east"`. Concatenate them (matching the
  /// Swift `readTxtData` which joins the length-prefixed strings) after stripping
  /// the surrounding quotes and unescaping `\"`.
  static String _decodeTxt(String data) {
    final parts = <String>[];
    var i = 0;
    final buf = StringBuffer();
    var inQuotes = false;
    while (i < data.length) {
      final ch = data[i];
      if (ch == '\\' && i + 1 < data.length) {
        buf.write(data[i + 1]);
        i += 2;
        continue;
      }
      if (ch == '"') {
        if (inQuotes) {
          parts.add(buf.toString());
          buf.clear();
        }
        inQuotes = !inQuotes;
        i += 1;
        continue;
      }
      if (inQuotes) {
        buf.write(ch);
      }
      i += 1;
    }
    if (parts.isEmpty) {
      // No quoting present — return as-is.
      return data;
    }
    return parts.join();
  }

  static String _stripDot(String s) =>
      s.endsWith('.') ? s.substring(0, s.length - 1) : s;

  void close() => _client.close();
}
