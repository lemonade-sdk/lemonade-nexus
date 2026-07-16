# Sidecar mesh integration test: nexus server + owner sidecar + linked sidecar.
# Verifies closed-registration join gating, device link-token mint/join, the
# token-gated control API, and private-API reachability over the userspace mesh.
#
# TODO(tls): this script still assumes plain HTTP (--no-auto-tls). Mesh HTTP is
# now verified-HTTPS-only (no plaintext, no verify-off), so this needs porting to
# the TLS flow: serve a cert for a dev FQDN, trust it (CurrentUser Root store or a
# real Cloudflare dns-01 cert), and point the sidecar at that FQDN. See
# .idea/local-dev.md §3-4. Until then it will not pass against a current server.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\sidecar-mesh-test.ps1 [-BuildDir <path>]
param([string]$BuildDir = "$PSScriptRoot\..\build")
$ErrorActionPreference = "Stop"
$bin  = "$BuildDir\projects"
$srv  = "$bin\LemonadeNexus\Release\lemonade-nexus.exe"
$sc   = "$bin\LemonadeNexusSidecar\Release\lemonade-nexus-sidecar.exe"
$PRIV = 19101   # private API port; NOT 9101 — VS Code may hold 127.0.0.1:9101
$TOK  = "localtesttoken"   # sidecar control-API bearer (every control endpoint requires it)
$root = "$env:TEMP\nexus-mesh-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $root | Out-Null
Write-Host "root=$root"

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

# 1. init + start the nexus server (closed registration, no ACME, free private port)
& $srv --first-run --data-root "$root\server" *> "$root\init.log"
$procs += Start-Process $srv -PassThru -WindowStyle Hidden `
    -ArgumentList @("--data-root","$root\server","--public-ip","127.0.0.1","--no-auto-tls",
                    "--closed-registration","--private-http-port",$PRIV) `
    -RedirectStandardOutput "$root\server.log" -RedirectStandardError "$root\server.err"
Start-Sleep 5
Write-Host "server health: $((Invoke-WebRequest 'http://127.0.0.1:9100/api/health' -UseBasicParsing).Content)"

# 2. a fake local 'lemond' HTTP service the owner exposes to the mesh
Start-Job -Name svc {
    $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:11434/"); $l.Start()
    while($l.IsListening){ $c=$l.GetContext(); $b=[Text.Encoding]::UTF8.GetBytes("hello-from-lemond"); $c.Response.OutputStream.Write($b,0,$b.Length); $c.Response.Close() }
} | Out-Null
Start-Sleep 1

# 3. owner sidecar (first identity -> root owner) exposing 8080 -> 11434
$procs += Start-Process $sc -PassThru -WindowStyle Hidden `
    -ArgumentList @("--server","127.0.0.1:9100","--data-root","$root\owner","--control-port","9110","--control-token",$TOK,"--expose","8080:11434") `
    -RedirectStandardOutput "$root\owner.log" -RedirectStandardError "$root\owner.err"
Start-Sleep 8
$o = CtlGet 9110 "/status"
Write-Host "OWNER    status=$($o.status) node=$($o.node_id) ip=$($o.tunnel_ip) mesh_up=$($o.mesh_up)"

# 4. mint a device link token via the owner control API
'{"ttl_sec":600}' | Out-File "$root\mint.json" -Encoding ascii
$linkResp = (curl.exe -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data "@$root\mint.json" http://127.0.0.1:9110/link-token) | ConvertFrom-Json
Write-Host "LINK TOKEN group=$($linkResp.group_node_id) token=$($linkResp.link_token.Substring(0,16))..."

# 5. an un-tokened identity must be rejected under closed registration
$procs += Start-Process $sc -PassThru -WindowStyle Hidden `
    -ArgumentList @("--server","127.0.0.1:9100","--data-root","$root\intruder","--control-port","9112","--control-token",$TOK) `
    -RedirectStandardOutput "$root\intruder.log" -RedirectStandardError "$root\intruder.err"
Start-Sleep 6
$intr = CtlGet 9112 "/status"
Write-Host "INTRUDER status=$($intr.status) join_failures=$($intr.join_failures) (expect degraded, failures>0)"

# 6. linked sidecar WITH the token joins the owner's account/group
$procs += Start-Process $sc -PassThru -WindowStyle Hidden `
    -ArgumentList @("--server","127.0.0.1:9100","--data-root","$root\phone","--control-port","9111","--control-token",$TOK,"--link-token",$linkResp.link_token) `
    -RedirectStandardOutput "$root\phone.log" -RedirectStandardError "$root\phone.err"
Start-Sleep 8
$phone = CtlGet 9111 "/status"
Write-Host "PHONE    status=$($phone.status) node=$($phone.node_id) ip=$($phone.tunnel_ip) mesh_up=$($phone.mesh_up)"

# 7. reachability: from the phone, egress to the server private API over the mesh.
#    HTTP 401 proves the mesh path reached the JWT-gated private API.
('{"ip":"10.64.0.1","port":' + $PRIV + '}') | Out-File "$root\eg.json" -Encoding ascii
$eg = (curl.exe -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data "@$root\eg.json" http://127.0.0.1:9111/egress) | ConvertFrom-Json
if (-not $eg.loopback_port) {
    Write-Host "PRIVATE API via mesh: EGRESS FAILED ($($eg | ConvertTo-Json -Compress))"
} else {
    $code = curl.exe -s -m8 -o NUL -w "%{http_code}" "http://127.0.0.1:$($eg.loopback_port)/api/trust/status"
    Write-Host "PRIVATE API via mesh: HTTP $code (401 = reached JWT-gated private API = SUCCESS)"
}

Write-Host "`n--- server join log ---"
Select-String -Path "$root\server.log" -Pattern "Join\]|linked device|registration closed" | Select-Object -Last 6 | ForEach-Object { $_.Line }
Cleanup
Write-Host "`nDONE. Logs in $root"
