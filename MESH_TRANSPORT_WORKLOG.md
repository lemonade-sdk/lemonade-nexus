# Work log — userspace mesh transport (private API over the pump)

Goal: the client must reach the server's private API (`/api/mesh/peers/:node_id`,
`/api/trust/status`, `/api/relay/list`) by speaking HTTP **through the userspace
boringtun/smoltcp socket** to the tier-1 node it connected to — not via OS-routed
`httplib` to a tunnel IP (which has no route and 404s on the public fallback).

## Decisions (from owner)
- Transport seam lives in `projects/LemonadeNexusSDK/src/LemonadeNexusClient.cpp`.
- The lingering WireGuard/TUN tunnel functions in the SDK were meant to be removed
  earlier — remove them; they keep causing divergences.
- **One pump only** on macOS (and any client). No separate TUN tunnel.
- Approach **A**: couple `ln_client` → `ln_pump` (route private HTTP through
  `ln_pump_tcp_egress`); do not duplicate the netstack.

## Architecture (from code map)
- Server (`projects/LemonadeNexus`): userspace-only, boringtun + smoltcp; private
  httplib on `127.0.0.1:9101`, surfaced on tunnel IP via smoltcp `add_tcp_forward`.
  Private routes are JWT-gated and exist only there. **No server change needed.**
- `ln_pump` (`PacketPump.cpp`): has the client-side smoltcp netstack + boringtun
  session + `ln_pump_tcp_egress(dstIp,port) -> 127.0.0.1:<port>`. Was dead code
  (`PumpTunnelController` never instantiated).
- `ln_client` (`LemonadeNexusClient.cpp`): TUN-based `BoringTunBackend`, no netstack;
  `private_http_get/post` (lines ~248-332) dial `SSLClient` to the tunnel IP → 404.

## Planned commits (rough order — align later, don't over-optimize)
1. SDK: remove dead WireGuard/TUN tunnel surface from the client (wg_tunnel,
   tunnel_up/down/status, ln_tunnel_*), keeping WG *config*/keypair gen needed by the pump.
2. SDK: refactor `private_http_get/post` into one `do_private_request`; add an egress
   hook + `ln_client_set_private_egress(client, pump)` C API; plain-HTTP over loopback.
3. SDK: verify pump server-peer `allowed_ips` covers server tunnel IP / private subnet.
4. App: create the pump on macOS, bind egress into the client before first private call,
   gate on `ln_pump_status` readiness; revive `PumpTunnelController`; drop dead Dart WG.
5. Build: rebuild the native dylib consumed by the Flutter FFI; run + verify mesh peers.

## Status
- [in progress] Mapped the full WireGuard surface. Scope is larger than the
  transport seam — see the dataplane finding below.

## KEY FINDING — there are TWO userspace boringtun dataplanes
- `WireGuardTunnel` (+ `BoringTunBackend`, `ITunnelBackend`): TUN-based (utun on
  macOS). **This is what the mesh actually runs on today.** `MeshOrchestrator`
  takes a `WireGuardTunnel&` and calls `tunnel_.sync_peers()` / `mesh_status()` /
  `remove_peer()` (MeshOrchestrator.cpp:44,128,165). `enable_mesh` builds the
  orchestrator with `impl_->wg_tunnel` (LemonadeNexusClient.cpp:1866); `mesh_status`
  reads it. `get_mesh_peers` (the 404) is the orchestrator's private_http_get.
- `UserspaceDataplane` (+ `PacketPump` / `ln_pump_*`): netstack-based, **no TUN**,
  has `ln_pump_sync_peers` / `ln_pump_status` / `ln_pump_tcp_egress`. Pump is
  independent of the WG types. **Currently dead code** (never instantiated).

So "remove WireGuard" is really **consolidate the mesh dataplane onto the pump**:
- Config type: `WireGuardConfig` (Types.hpp:285) -> rename **`BoringtunConfig`**.
- `WireGuardTunnel::generate_keypair` (WireGuardTunnel.cpp:434) -> move to
  `BoringtunConfig` / free fn (join + ln_wg_generate_keypair use it).
- `MeshOrchestrator` must sync peers to the pump (`dp.add_peer`/`ln_pump_sync_peers`)
  and read status from the pump (`dp.snapshot_peers`/`ln_pump_status`) instead of
  `WireGuardTunnel`.
- Client: own a pump (UserspaceDataplane) instead of `wg_tunnel`; store the
  `BoringtunConfig` for `get_boringtun_config_json`; route private HTTP via the
  pump egress (the original transport-seam change).
- Remove: `WireGuardTunnel.{hpp,cpp}`, `BoringTunBackend.{hpp,cpp}`,
  `ITunnelBackend.hpp`, `ln_tunnel_up/down/status`, `ln_get_wg_config` (CMake too).
- CApi/header: drop ln_tunnel_*, rename ln_get_wg_config_json -> boringtun, add
  `ln_client_set_private_egress` (or fold the pump into the client so it is implicit).
- Dart: `WgConfig` -> `BoringtunConfig`, `getWgConfigJson` -> boringtun, drop
  ln_tunnel_* bindings, create/own the pump, bind egress before enable_mesh.

## Notes / running log
- Build: dylib via `cmake --build build --target LemonadeNexusSDKShared` ->
  `build/projects/LemonadeNexusSDK/liblemonade_nexus_sdk.dylib`; Xcode Run phase
  copies+codesigns it into the app. CMake GLOBs src/*.cpp so adding/deleting
  files needs `cmake -S . -B build` reconfigure before build.

### Phase 1 — DONE (SDK consolidated, builds clean, 0 errors)
- New `BoringtunConfig` (Types.hpp, was WireGuardConfig).
- New `BoringtunMesh` ({hpp,cpp}): client-owned UserspaceDataplane + smoltcp
  netstack. start/stop/tcp_egress/sync_peers/remove_peer/mesh_status +
  static generate_keypair. (Folds in the old PacketPump logic.)
- `LemonadeNexusClient`: Impl owns `meshplane` (+ stored `boringtun_config`);
  join brings the dataplane up; `private_http_get/post` egress through it
  (plain HTTP to a netstack loopback port) before any legacy fallback; removed
  tunnel_up/down/status + get_wireguard_config*; added is_mesh_active.
- `MeshOrchestrator`: now takes `BoringtunMesh&` (sync_peers/mesh_status/
  remove_peer unchanged signatures).
- `CApi` + header: removed ln_tunnel_*, ln_get_wg_config*, ln_pump_*;
  ln_wg_generate_keypair -> ln_generate_keypair.
- Deleted: WireGuardTunnel.{hpp,cpp}, BoringTunBackend.{hpp,cpp},
  ITunnelBackend.hpp, PacketPump.cpp; Dart tunnel_controller.dart.
- Deferred to Phase 2: server `nexus::wireguard`->`nexus::boringtun`,
  `WgPeer`->`BoringtunPeer`, `WireGuard/` dir; the `wg_pubkey` JSON key + struct
  fields (server contract); dead Dart FFI bindings (ln_tunnel_*/ln_pump_*) +
  WgConfig/WgKeypair models (unused, lazy-resolved — harmless until cleaned).

### Phase 1 test #1 — dataplane up, but private API still 404
- `[BoringtunMesh] dataplane up: mesh_ip=10.64.0.19` ✓ ; refreshMeshStatus up=true ✓.
- BUT `/api/mesh/peers` still 404. Server logs: our peer added with
  `endpoint=<roaming>` (server received NO packet from us) and the client issued
  a DNS query for `private.server-...seip... -> 10.64.0.1` (the legacy FQDN path).
- Root cause: join response sets `server_private_fqdn` but NOT `server_tunnel_ip`,
  so `mesh_request` (egress target = server_tunnel_ip) was SKIPPED and fell through
  to the FQDN SSLClient path (no OS route -> public 404). The egress never ran, so
  no boringtun handshake (hence <roaming>).
- Fix: at join, resolve `server_private_fqdn` -> IPv4 (the authoritative DNS maps
  it to the server's mesh IP 10.64.0.1) and store as `server_tunnel_ip`, so
  `mesh_request` egresses to 10.64.0.1:9101 over the dataplane. Added `resolve_ipv4`
  + info-level `private(mesh)` logging to confirm.

### TODO next
- Rebuild + run: expect `[LemonadeNexusClient] server mesh IP 10.64.0.1` at join,
  then `private(mesh) GET /api/mesh/peers -> HTTP 200`, peers sync, card populates.
