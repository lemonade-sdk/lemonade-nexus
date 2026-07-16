# Sidecar mesh integration test: nexus server + owner sidecar + linked sidecar.
# Verifies closed-registration join gating, device link-token mint/join, the
# token-gated control API, and private-API reachability over the userspace mesh.
#
# Everything runs over verified HTTPS (the mesh has no plaintext path). The
# server serves a self-signed cert covering its derived SEIP + private.<seip>
# FQDNs; the sidecars reach it by the SEIP FQDN, mapped to 127.0.0.1 and trusted
# via --ca-cert (split-horizon, exactly like a real deployment where the SEIP
# name resolves to the node). Requires openssl (git ships one).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\sidecar-mesh-test.ps1 [-BuildDir <path>]
param([string]$BuildDir = "$PSScriptRoot\..\build")
$ErrorActionPreference = "Continue"   # openssl writes keygen progress to stderr
$bin  = "$BuildDir\projects"
$srv  = "$bin\LemonadeNexus\Release\lemonade-nexus.exe"
$sc   = "$bin\LemonadeNexusSidecar\Release\lemonade-nexus-sidecar.exe"
$ossl = "C:\Program Files\Git\usr\bin\openssl.exe"
if (-not (Test-Path $ossl)) { $ossl = (Get-Command openssl -EA SilentlyContinue).Source }
$PRIV   = 19101   # private API port; NOT 9101 — VS Code may hold 127.0.0.1:9101
$TOK    = "localtesttoken"   # sidecar control-API bearer (every control endpoint requires it)
$REGION = "eu-west"
$DOMAIN = "lemonade-nexus.io"
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

# 1. init the server, derive its SEIP/private FQDNs, and mint a cert covering both.
#    node-id = "server-" + first 16 hex of the identity pubkey (resolve_server_node_id).
& $srv --first-run --data-root "$root\server" *> "$root\init.log"
$pubhex   = (Get-Content "$root\server\identity\keypair.pub" -Raw).Trim()
$nodeId   = "server-" + $pubhex.Substring(0, 16)
$SEIP     = "$nodeId.$REGION.seip.$DOMAIN"
$PRIVFQDN = "private.$SEIP"
Write-Host "SEIP=$SEIP"
$cert = "$root\cert.pem"; $key = "$root\key.pem"
& $ossl req -x509 -newkey rsa:2048 -nodes -keyout $key -out $cert -days 2 `
    -subj "/CN=$SEIP" -addext "subjectAltName=DNS:$SEIP,DNS:$PRIVFQDN" 2>"$root\ossl.log" | Out-Null

# start the server: verified HTTPS only, manual public + private certs, closed registration
$procs += Start-Process $srv -PassThru -WindowStyle Hidden `
    -ArgumentList @("--data-root","$root\server","--public-ip","127.0.0.1","--region",$REGION,
                    "--no-auto-tls","--tls-cert-path",$cert,"--tls-key-path",$key,
                    "--private-tls-cert-path",$cert,"--private-tls-key-path",$key,
                    "--closed-registration","--private-http-port",$PRIV) `
    -RedirectStandardOutput "$root\server.log" -RedirectStandardError "$root\server.err"
Start-Sleep 5
# Sanity: the server's published SEIP must match what we built the cert for.
$logged = (Select-String -Path "$root\server.log" -Pattern "SEIP: published (\S+) ->").Matches.Groups[1].Value | Select-Object -First 1
if ($logged -and $logged -ne $SEIP) { Write-Host "WARN: server SEIP '$logged' != computed '$SEIP' (region mismatch?)" }
$health = curl.exe -s -m8 --resolve "${SEIP}:9100:127.0.0.1" --cacert $cert "https://${SEIP}:9100/api/health"
Write-Host "server health: $health"

# TLS flags every sidecar uses to reach the server by its cert FQDN over loopback.
$tls = @("--server","${SEIP}:9100","--server-addr","127.0.0.1","--ca-cert",$cert,"--pin-server")

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

# 6. linked sidecar WITH the token joins the owner's account/group
$procs += Start-Process $sc -PassThru -WindowStyle Hidden `
    -ArgumentList (@("--data-root","$root\phone","--control-port","9111","--control-token",$TOK,"--link-token",$linkResp.link_token) + $tls) `
    -RedirectStandardOutput "$root\phone.log" -RedirectStandardError "$root\phone.err"
Start-Sleep 8
$phone = CtlGet 9111 "/status"
Write-Host "PHONE    status=$($phone.status) node=$($phone.node_id) ip=$($phone.tunnel_ip) mesh_up=$($phone.mesh_up)"

# 7. reachability: from the phone, egress to the server private API over the mesh,
#    then reach it over verified HTTPS by the private.<seip> FQDN. HTTP 401 proves
#    the mesh path reached the JWT-gated private API.
('{"ip":"10.64.0.1","port":' + $PRIV + '}') | Out-File "$root\eg.json" -Encoding ascii
$eg = (curl.exe -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data "@$root\eg.json" http://127.0.0.1:9111/egress) | ConvertFrom-Json
if (-not $eg.loopback_port) {
    Write-Host "PRIVATE API via mesh: EGRESS FAILED ($($eg | ConvertTo-Json -Compress))"
} else {
    $lp = $eg.loopback_port
    $code = curl.exe -s -m8 -o NUL -w "%{http_code}" --resolve "${PRIVFQDN}:${lp}:127.0.0.1" --cacert $cert "https://${PRIVFQDN}:${lp}/api/trust/status"
    Write-Host "PRIVATE API via mesh: HTTP $code (401 = reached JWT-gated private API over verified TLS = SUCCESS)"
}

Write-Host "`n--- server join log ---"
Select-String -Path "$root\server.log" -Pattern "Join\]|linked device|registration closed" | Select-Object -Last 6 | ForEach-Object { $_.Line }
Cleanup
Write-Host "`nDONE. Logs in $root"
