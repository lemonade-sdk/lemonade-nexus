# Sidecar mesh integration test: nexus server + owner sidecar + linked sidecar.
# Verifies closed-registration join gating, device link-token mint/join, the
# token-gated control API (incl. no/wrong-bearer 401), and private-API
# reachability over the userspace mesh.
#
# Everything runs over verified HTTPS against a REAL, publicly-trusted ACME cert
# on the forced SEIP FQDN — there is NO manual/self-signed cert path (the mesh
# only ever uses ACME-issued public-CA certificates). This is a LOCAL-run
# template, not a self-contained CI job; it needs real infrastructure:
#
#   1. A domain you control, passed as -Domain (or $env:LN_TEST_DOMAIN). The
#      server obtains a real cert for its <node>.<region>.seip.<domain> FQDN via
#      ACME dns-01 — set SP_ACME_PROVIDER=letsencrypt, SP_DNS_PROVIDER=cloudflare
#      and CLOUDFLARE_API_TOKEN in the environment before running.
#   2. A hosts entry mapping the derived SEIP + private.<seip> FQDNs to 127.0.0.1
#      so the sidecars (and curl) reach the local server by its cert FQDN. The
#      public cert still verifies against the system trust store — split-horizon
#      DNS, not verification-off. (This is why --server-addr/--ca-cert are gone:
#      trust is the real public CA; the address comes from DNS/hosts.)
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\sidecar-mesh-test.ps1 -Domain <your-domain> [-BuildDir <path>]
param(
    [string]$BuildDir = "$PSScriptRoot\..\build",
    [string]$Domain   = $(if ($env:LN_TEST_DOMAIN) { $env:LN_TEST_DOMAIN } else { "" })
)
$ErrorActionPreference = "Continue"
if (-not $Domain) {
    Write-Host "ERROR: -Domain (a domain you control, with ACME dns-01 configured) is required."
    Write-Host "       Manual/self-signed certs are no longer supported; the server needs a real ACME cert."
    exit 2
}
$bin  = "$BuildDir\projects"
$srv  = "$bin\LemonadeNexus\Release\lemonade-nexus.exe"
$sc   = "$bin\LemonadeNexusSidecar\Release\lemonade-nexus-sidecar.exe"
$PRIV   = 19101   # private API port; NOT 9101 — VS Code may hold 127.0.0.1:9101
$TOK    = "localtesttoken"   # sidecar control-API bearer (every control endpoint requires it)
$REGION = "eu-west"
$root = "$env:TEMP\nexus-mesh-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $root | Out-Null
Write-Host "root=$root"

# Assertion tracking: fail (exit 1) if any expected security property does not
# hold, not merely print a diagnostic.
$script:fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "  ok:   $msg" } else { Write-Host "  FAIL: $msg"; $script:fail++ }
}

# curl, not Invoke-WebRequest: PS 5.1 IWR drops the Authorization header.
function CtlGet($port, $path) {
    curl.exe -s -H "Authorization: Bearer $TOK" "http://127.0.0.1:$port$path" | ConvertFrom-Json
}

$procs = @()
function Cleanup {
    foreach ($p in $procs) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {} }
    Get-Job | Stop-Job -EA SilentlyContinue; Get-Job | Remove-Job -EA SilentlyContinue
}
trap { Write-Host "ERROR: $_"; Cleanup; exit 1 }

# Clear stragglers: leftover listeners + SO_REUSEADDR let ghosts answer on the ports.
Get-Process lemonade-nexus,lemonade-nexus-sidecar -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2

# 1. init the server and derive its SEIP/private FQDNs.
#    node-id = "server-" + first 16 hex of the identity pubkey (resolve_server_node_id).
& $srv --first-run --data-root "$root\server" *> "$root\init.log"
$pubhex   = (Get-Content "$root\server\identity\keypair.pub" -Raw).Trim()
$nodeId   = "server-" + $pubhex.Substring(0, 16)
$SEIP     = "$nodeId.$REGION.seip.$Domain"
$PRIVFQDN = "private.$SEIP"
Write-Host "SEIP=$SEIP"
Write-Host "NOTE: add a hosts entry mapping '$SEIP' and '$PRIVFQDN' to 127.0.0.1,"
Write-Host "      and ensure ACME dns-01 is configured (SP_ACME_PROVIDER / SP_DNS_PROVIDER / CLOUDFLARE_API_TOKEN)."

# start the server: verified HTTPS only (ACME public CA), closed registration.
# The cert is issued automatically for the SEIP + private.<seip> FQDNs; no
# manual cert is supplied.
$procs += Start-Process $srv -PassThru -WindowStyle Hidden `
    -ArgumentList @("--data-root","$root\server","--public-ip","127.0.0.1","--region",$REGION,
                    "--closed-registration","--private-http-port",$PRIV) `
    -RedirectStandardOutput "$root\server.log" -RedirectStandardError "$root\server.err"
# ACME dns-01 issuance can take a while on first run; wait for the cert to land.
Start-Sleep 20
# Sanity: the server's published SEIP must match what we built the FQDN for.
$logged = (Select-String -Path "$root\server.log" -Pattern "SEIP: published (\S+) ->").Matches.Groups[1].Value | Select-Object -First 1
if ($logged -and $logged -ne $SEIP) { Write-Host "WARN: server SEIP '$logged' != computed '$SEIP' (region mismatch?)" }
# Public listener serves the real ACME cert; verify against the SYSTEM trust store.
$health = curl.exe -s -m8 --resolve "${SEIP}:9100:127.0.0.1" "https://${SEIP}:9100/api/health"
Write-Host "server health: $health"
Check ($health -match "ok|healthy|status") "public listener serves a valid ACME cert on the SEIP FQDN"

# Flags every sidecar uses to reach the server by its cert FQDN. The SEIP FQDN
# must resolve to the server (hosts entry -> 127.0.0.1 for a local run); trust is
# the system/public CA, so no --ca-cert / --server-addr.
$tls = @("--server","${SEIP}:9100","--pin-server")

# 2. a fake local 'lemond' HTTP service the owner exposes to the mesh
Start-Job -Name svc {
    $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:11434/"); $l.Start()
    while($l.IsListening){ $c=$l.GetContext(); $b=[Text.Encoding]::UTF8.GetBytes("hello-from-lemond"); $c.Response.OutputStream.Write($b,0,$b.Length); $c.Response.Close() }
} | Out-Null
Start-Sleep 1

# 3. owner sidecar (first identity -> root owner) exposing 8080 -> 11434
$procs += Start-Process $sc -PassThru -WindowStyle Hidden `
    -ArgumentList (@("--data-root","$root\owner","--control-port","9110","--control-token",$TOK,"--expose","8080:11434") + $tls) `
    -RedirectStandardOutput "$root\owner.log" -RedirectStandardError "$root\owner.err"
Start-Sleep 8
$o = CtlGet 9110 "/status"
Write-Host "OWNER    status=$($o.status) node=$($o.node_id) ip=$($o.tunnel_ip) mesh_up=$($o.mesh_up)"
Check ($null -ne $o.node_id) "owner sidecar reachable with a valid bearer token"

# Negative auth: every control endpoint requires the bearer (commit af9585c).
# A missing or wrong token MUST be rejected (401), or the control plane is open.
$noauth  = curl.exe -s -o NUL -w "%{http_code}" "http://127.0.0.1:9110/status"
$badauth = curl.exe -s -o NUL -w "%{http_code}" -H "Authorization: Bearer wrong-token" "http://127.0.0.1:9110/status"
Write-Host "CONTROL AUTH: no-bearer=$noauth wrong-bearer=$badauth (expect 401 each)"
Check ($noauth  -eq "401") "control API rejects a missing bearer (401)"
Check ($badauth -eq "401") "control API rejects a wrong bearer (401)"

# 4. mint a device link token via the owner control API
'{"ttl_sec":600}' | Out-File "$root\mint.json" -Encoding ascii
$linkResp = (curl.exe -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data "@$root\mint.json" http://127.0.0.1:9110/link-token) | ConvertFrom-Json
Write-Host "LINK TOKEN group=$($linkResp.group_node_id) token=$($linkResp.link_token.Substring(0,16))..."

# 5. an un-tokened identity must be rejected under closed registration
$procs += Start-Process $sc -PassThru -WindowStyle Hidden `
    -ArgumentList (@("--data-root","$root\intruder","--control-port","9112","--control-token",$TOK) + $tls) `
    -RedirectStandardOutput "$root\intruder.log" -RedirectStandardError "$root\intruder.err"
Start-Sleep 6
$intr = CtlGet 9112 "/status"
Write-Host "INTRUDER status=$($intr.status) join_failures=$($intr.join_failures) (expect degraded, failures>0)"
Check ([int]$intr.join_failures -gt 0) "un-tokened intruder rejected under closed registration"

# 6. linked sidecar WITH the token joins the owner's account/group
$procs += Start-Process $sc -PassThru -WindowStyle Hidden `
    -ArgumentList (@("--data-root","$root\phone","--control-port","9111","--control-token",$TOK,"--link-token",$linkResp.link_token) + $tls) `
    -RedirectStandardOutput "$root\phone.log" -RedirectStandardError "$root\phone.err"
Start-Sleep 8
$phone = CtlGet 9111 "/status"
Write-Host "PHONE    status=$($phone.status) node=$($phone.node_id) ip=$($phone.tunnel_ip) mesh_up=$($phone.mesh_up)"

# 7. reachability: from the phone, egress to the server private API over the mesh,
#    then reach it over verified HTTPS by the private.<seip> FQDN (verified against
#    the SYSTEM trust store — the private listener presents its own real ACME cert).
#    HTTP 401 proves the mesh path reached the JWT-gated private API.
('{"ip":"10.64.0.1","port":' + $PRIV + '}') | Out-File "$root\eg.json" -Encoding ascii
$eg = (curl.exe -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data "@$root\eg.json" http://127.0.0.1:9111/egress) | ConvertFrom-Json
if (-not $eg.loopback_port) {
    Write-Host "PRIVATE API via mesh: EGRESS FAILED ($($eg | ConvertTo-Json -Compress))"
    Check $false "phone egressed to the server private API over the mesh"
} else {
    $lp = $eg.loopback_port
    $code = curl.exe -s -m8 -o NUL -w "%{http_code}" --resolve "${PRIVFQDN}:${lp}:127.0.0.1" "https://${PRIVFQDN}:${lp}/api/trust/status"
    Write-Host "PRIVATE API via mesh: HTTP $code (401 = reached JWT-gated private API, cert verified = SUCCESS)"
    Check ($code -eq "401") "private API reached over mesh + real cert verified (JWT gate returns 401)"
}

Write-Host "`n--- server join log ---"
Select-String -Path "$root\server.log" -Pattern "Join\]|linked device|registration closed" | Select-Object -Last 6 | ForEach-Object { $_.Line }
Cleanup
if ($script:fail -gt 0) {
    Write-Host "`n$($script:fail) CHECK(S) FAILED. Logs in $root"
    exit 1
}
Write-Host "`nALL CHECKS PASSED. Logs in $root"
