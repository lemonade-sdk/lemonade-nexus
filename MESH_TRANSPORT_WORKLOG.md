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

### Phase 1 test #2/#3 — dataplane works; private API was HTTPS, we spoke plain HTTP
- Fixed `mesh_request` egress target: resolve `server_private_fqdn` -> server mesh
  IP (10.64.0.1); egress now runs.
- Dataplane fully works: boringtun handshake completes (server learns our endpoint,
  no longer <roaming>), TCP 3-way handshake to 10.64.0.1:9101 completes bidirec-
  tionally, data flows both ways. Confirmed on BOTH ends via dataplane tx logging.
- BUT request died: `Failed to read connection` ~140ms, server `[private-http]`
  never logged, server sent only small ACKs (no HTTP response body).
- ROOT CAUSE: the private API is **HTTPS** (carries the private.<server> cert —
  server log: "Private API on virtual 10.64.0.1:9101 (HTTPS) via tcp:127.0.0.1:9101",
  "HttpServer (HTTPS) listening on 127.0.0.1:9101"). `mesh_request` used
  `httplib::Client` (plain HTTP) -> TLS listener reset the connection -> never
  routed -> no [private-http] log. The "plain on loopback" assumption from the
  code map was wrong for a deployment with the private cert present.
- FIX: `mesh_request` now uses `httplib::SSLClient` with cert verification
  disabled (cert is for the FQDN not 127.0.0.1; confidentiality already from the
  mesh + loopback). Client-only change; server unchanged.

### Phase 1 test #4 — transport SOLVED; was an HTTPS + ACL gap
- HTTPS fix worked: `private(mesh) POST /api/mesh/heartbeat -> HTTP 200`, mesh
  `up=true`. Transport + dataplane + TLS all working end to end.
- Remaining: `GET /api/mesh/peers/<node> -> HTTP 403` (heartbeat 200, same token).
- Server proved the token is node-scoped (JWT subject == node id), so NOT a token
  issue. The two routes differ: `/heartbeat` authorizes by ownership; `/peers`
  requires `check_permission(caller, node, Read)` (MeshApiHandler.cpp:107).
- Root cause: at join, the Customer node gets an explicit owner assignment
  (read/write/add_child/delete_node/edit_node) but the Endpoint node got NONE, so
  the owner had no Read on its own endpoint -> /peers + /status 403.
- FIX (server, owner-confirmed "explicit behaviour"): the join endpoint node now
  gets the same explicit owner assignment (TreeApiHandler.cpp, both join sites).
  Only applies to NEW joins -> needs server rebuild + fresh client login.

### Phase 1 test #5 — DONE. Transport + ACL fully working end to end.
- Server fix was `MeshApiHandler.cpp`: `/peers` + `/status` checked
  `check_permission` with `normalize_pubkey(claims.user_id)`, but assignments are
  keyed by **pubkey** (`claims.user_id` is a hash-derived node id, not the pubkey).
  Switched both to `normalize_pubkey(claims.pubkey)` (commit a9d1ff2).
- Fresh client login (node f207bdad…): `private(mesh) GET /api/mesh/peers/<node>
  -> HTTP 200`, `[MeshOrchestrator] peer refresh: 0 peers synced`,
  `refreshMeshStatus: up=true peers=0 meshIp=10.64.0.27`. P2P Mesh card populates.
- `peers=0` is correct: single endpoint in the mesh. The fetch->sync mechanism is
  proven; a second endpoint joining would show as a peer row.

### Cleanup pass — DONE (temp diagnostics stripped; diagnostics kept gated)
- main.cpp: removed the `[private-http]` request logger (pure session diagnostic).
- UserspaceDataplane.cpp: removed per-packet `tx`/`encap`/`tick` debug spam; kept
  the lifecycle logs (started/stopped/added peer/added session/dropped spoofed).
- LemonadeNexusClient.cpp `mesh_request`: success logs (egress, HTTP status) ->
  `debug`; failure logs (SKIP, NO RESPONSE, EXCEPTION) -> `warn`. Comment de-WG'd.
- CApi.cpp: **kept** the `LN_DEBUG` env gate (clean off-by-default toggle, not
  noise) — deviation from the original TODO, flagged to owner.
- Dart app_state.dart: `_log` now gated on `kDebugMode` (compiles out in release;
  still visible under `flutter run`) — mirrors the native LN_DEBUG philosophy.
- Verified: SDK dylib + server app both rebuild clean (exit 0).
- Server-side edits (main.cpp, UserspaceDataplane.cpp) need a pull+rebuild+restart
  to take effect on the running host.

### TODO next
- Phase 2: rename server `nexus::wireguard`->`nexus::boringtun`, `WgPeer`->
  `BoringtunPeer`, the `WireGuard/` dir, and the `wg_pubkey` JSON contract key.
  Also clean dead Dart FFI bindings (ln_tunnel_*/ln_pump_*) + WgConfig/WgKeypair.
- Deferred: contract test harness; `doOperation(sdkOps.X, args)` FFI simplification.
