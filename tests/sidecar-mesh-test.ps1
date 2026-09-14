# Sidecar mesh integration test: nexus server + owner sidecar + linked sidecar.
# Verifies closed-registration join gating, device link-token mint/join, the
# token-gated control API (incl. no/wrong-bearer 401), and private-API
# reachability over the userspace mesh.
#
# Hermetic TLS with NO manual-cert production surface: the harness mints a test
# CA, issues certs for the derived SEIP + private.<seip> FQDNs, and drops them
# into <data-root>/certs/<fqdn>/ — the ACME cache the server already reads. The
# server is started with no cert flags at all (they don't exist). Clients verify
# against the system trust store, so the harness installs the test CA there and
# points both FQDNs at 127.0.0.1 via hosts.
#
# Requires admin (trust store + hosts) and openssl (git ships one).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\sidecar-mesh-test.ps1 [-BuildDir <path>]
param([string]$BuildDir = "$PSScriptRoot\..\build")
$ErrorActionPreference = "Continue"   # openssl writes progress to stderr

$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host "ERROR: must run elevated (installs a test CA and edits hosts)."
    exit 2
}

$bin  = "$BuildDir\projects"
$srv  = "$bin\LemonadeNexus\Release\lemonade-nexus.exe"
$sc   = "$bin\LemonadeNexusSidecar\Release\lemonade-nexus-sidecar.exe"
$ossl = "C:\Program Files\Git\usr\bin\openssl.exe"
if (-not (Test-Path $ossl)) { $ossl = (Get-Command openssl -EA SilentlyContinue).Source }
$PRIV   = 19101   # private API port; NOT 9101 — VS Code may hold 127.0.0.1:9101
$TOK    = "localtesttoken"   # sidecar control-API bearer
$REGION = "eu-west"
$DOMAIN = "lemonade-nexus.io"
$HOSTS  = "$env:SystemRoot\System32\drivers\etc\hosts"
$root = "$env:TEMP\nexus-mesh-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $root | Out-Null
Write-Host "root=$root"

# Fail (exit 1) if any expected security property does not hold.
$script:fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "  ok:   $msg" } else { Write-Host "  FAIL: $msg"; $script:fail++ }
}

# curl on Windows is Schannel-backed and hard-fails a chain whose CA publishes no
# CRL ("revocation status is unknown"), which a test CA never does. This disables
# ONLY the revocation lookup — chain and hostname verification still fail closed.
$REVOKE = "--ssl-revoke-best-effort"

# Poll instead of sleeping a fixed interval: a cold CI runner is much slower than
# a dev box, and a fixed sleep silently turns "slow" into "broken".
function Wait-Url($url, $caFile, $pattern, $timeoutSec) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
        $r = curl.exe -s -m5 $REVOKE --cacert $caFile $url 2>$null
        if ($r -match $pattern) { return @{ ok = $true; secs = [int]$sw.Elapsed.TotalSeconds; body = $r } }
        Start-Sleep -Milliseconds 500
    }
    return @{ ok = $false; secs = [int]$sw.Elapsed.TotalSeconds; body = "" }
}

# curl, not Invoke-WebRequest: PS 5.1 IWR drops the Authorization header.
function CtlGet($port, $path) {
    curl.exe -s -H "Authorization: Bearer $TOK" "http://127.0.0.1:$port$path" | ConvertFrom-Json
}

$procs = @()
$script:caThumb = $null
function Cleanup {
    foreach ($p in $procs) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {} }
    # -Force: the svc job blocks in GetContext(), so a plain Stop-Job stalls for minutes.
    Get-Job | Remove-Job -Force -EA SilentlyContinue
    if ($script:caThumb) {
        Remove-Item "Cert:\LocalMachine\Root\$($script:caThumb)" -Force -EA SilentlyContinue
    }
    # Strip the hosts lines this run added.
    try {
        (Get-Content $HOSTS) | Where-Object { $_ -notmatch "# nexus-mesh-test$" } |
            Set-Content $HOSTS -Encoding ascii
    } catch {}
}
trap { Write-Host "ERROR: $_"; Cleanup; exit 1 }

# Clear stragglers: leftover listeners + SO_REUSEADDR let ghosts answer.
Get-Process lemonade-nexus,lemonade-nexus-sidecar -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2

# 1. init the server and derive its SEIP/private FQDNs.
#    node-id = "server-" + first 16 hex of the identity pubkey.
& $srv --first-run --data-root "$root\server" *> "$root\init.log"
$pubhex   = (Get-Content "$root\server\identity\keypair.pub" -Raw).Trim()
$nodeId   = "server-" + $pubhex.Substring(0, 16)

# A normal start now requires both trust anchors. root_pubkey is this genesis's own
# identity; the release key is a throwaway — the harness never exercises Tier 1, so
# the server stays Tier 2 with an unapproved binary, which is the correct outcome.
& $ossl genpkey -algorithm ED25519 -out "$root\relsign.pem" 2>"$root\ossl-rel.log" | Out-Null
& $ossl pkey -in "$root\relsign.pem" -pubout -outform DER -out "$root\relsign.der" 2>>"$root\ossl-rel.log" | Out-Null
$RELPUB = [Convert]::ToBase64String(([IO.File]::ReadAllBytes("$root\relsign.der"))[12..43])
$SEIP     = "$nodeId.$REGION.seip.$DOMAIN"
$PRIVFQDN = "private.$SEIP"
Write-Host "SEIP=$SEIP"

# 2. mint a test CA and seed the ACME cache with a cert per listener FQDN.
#    Long validity so the renewal thread never tries to re-issue.
$ca = "$root\ca.pem"; $cak = "$root\ca.key"
& $ossl req -x509 -newkey rsa:2048 -nodes -keyout $cak -out $ca -days 3650 `
    -subj "/CN=Lemonade Nexus Test CA" 2>"$root\ossl-ca.log" | Out-Null

function New-SeededCert($fqdn) {
    $key = "$root\$fqdn.key"; $csr = "$root\$fqdn.csr"; $crt = "$root\$fqdn.crt"
    $ext = "$root\$fqdn.ext"
    "subjectAltName=DNS:$fqdn" | Out-File $ext -Encoding ascii
    & $ossl req -newkey rsa:2048 -nodes -keyout $key -out $csr -subj "/CN=$fqdn" 2>>"$root\ossl.log" | Out-Null
    & $ossl x509 -req -in $csr -CA $ca -CAkey $cak -CAcreateserial -out $crt -days 3650 `
        -extfile $ext 2>>"$root\ossl.log" | Out-Null
    $dir = "$root\server\certs\$fqdn"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Get-Content $crt, $ca | Set-Content "$dir\fullchain.pem" -Encoding ascii
    Copy-Item $key "$dir\privkey.pem" -Force
}
New-SeededCert $SEIP
New-SeededCert $PRIVFQDN

# 3. trust the CA machine-wide and resolve both FQDNs to loopback.
$script:caThumb = (Import-Certificate -FilePath $ca -CertStoreLocation Cert:\LocalMachine\Root).Thumbprint
Add-Content $HOSTS "127.0.0.1 $SEIP # nexus-mesh-test" -Encoding ascii
Add-Content $HOSTS "127.0.0.1 $PRIVFQDN # nexus-mesh-test" -Encoding ascii

# 4. start the server: no cert flags exist — it picks up the seeded ACME cache.
$procs += Start-Process $srv -PassThru -WindowStyle Hidden `
    -ArgumentList @("--data-root","$root\server","--public-ip","127.0.0.1","--region",$REGION,
                    "--closed-registration","--private-http-port",$PRIV,
                    "--root-pubkey",$pubhex,"--release-signing-pubkey",$RELPUB) `
    -RedirectStandardOutput "$root\server.log" -RedirectStandardError "$root\server.err"
$h = Wait-Url "https://${SEIP}:9100/api/health" $ca "ok|healthy|status" 60
$m = (Select-String -Path "$root\server.log" -Pattern "SEIP: published (\S+) ->" -EA SilentlyContinue | Select-Object -First 1)
if ($m) {
    $logged = $m.Matches[0].Groups[1].Value
    if ($logged -ne $SEIP) { Write-Host "WARN: server SEIP '$logged' != computed '$SEIP'" }
}
Write-Host "server health after $($h.secs)s: $($h.body)"
Check $h.ok "public listener serves the seeded cert on the SEIP FQDN"

# Sidecars reach the server by its cert FQDN via hosts + the system trust store.
$tls = @("--server","${SEIP}:9100","--pin-server")

# 5. a fake local 'lemond' HTTP service the owner exposes to the mesh
Start-Job -Name svc {
    $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:11434/"); $l.Start()
    while($l.IsListening){ $c=$l.GetContext(); $b=[Text.Encoding]::UTF8.GetBytes("hello-from-lemond"); $c.Response.OutputStream.Write($b,0,$b.Length); $c.Response.Close() }
} | Out-Null
Start-Sleep 1

# 6. owner sidecar (first identity -> root owner) exposing 8080 -> 11434
$procs += Start-Process $sc -PassThru -WindowStyle Hidden `
    -ArgumentList (@("--data-root","$root\owner","--control-port","9110","--control-token",$TOK,"--expose","8080:11434") + $tls) `
    -RedirectStandardOutput "$root\owner.log" -RedirectStandardError "$root\owner.err"
Start-Sleep 8
$o = CtlGet 9110 "/status"
Write-Host "OWNER    status=$($o.status) node=$($o.node_id) ip=$($o.tunnel_ip) mesh_up=$($o.mesh_up)"
Check ($null -ne $o.node_id) "owner sidecar joined over verified TLS"

# Negative auth: every control endpoint requires the bearer.
$noauth  = curl.exe -s -o NUL -w "%{http_code}" "http://127.0.0.1:9110/status"
$badauth = curl.exe -s -o NUL -w "%{http_code}" -H "Authorization: Bearer wrong-token" "http://127.0.0.1:9110/status"
Write-Host "CONTROL AUTH: no-bearer=$noauth wrong-bearer=$badauth (expect 401 each)"
Check ($noauth  -eq "401") "control API rejects a missing bearer (401)"
Check ($badauth -eq "401") "control API rejects a wrong bearer (401)"

# 7. mint a device link token via the owner control API
'{"ttl_sec":600}' | Out-File "$root\mint.json" -Encoding ascii
$linkResp = (curl.exe -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data "@$root\mint.json" http://127.0.0.1:9110/link-token) | ConvertFrom-Json
Write-Host "LINK TOKEN group=$($linkResp.group_node_id) token=$($linkResp.link_token.Substring(0,16))..."

# 8. an un-tokened identity must be rejected under closed registration
$procs += Start-Process $sc -PassThru -WindowStyle Hidden `
    -ArgumentList (@("--data-root","$root\intruder","--control-port","9112","--control-token",$TOK) + $tls) `
    -RedirectStandardOutput "$root\intruder.log" -RedirectStandardError "$root\intruder.err"
Start-Sleep 6
$intr = CtlGet 9112 "/status"
Write-Host "INTRUDER status=$($intr.status) join_failures=$($intr.join_failures) (expect degraded, failures>0)"
Check ([int]$intr.join_failures -gt 0) "un-tokened intruder rejected under closed registration"

# 9. linked sidecar WITH the token joins the owner's account/group
$procs += Start-Process $sc -PassThru -WindowStyle Hidden `
    -ArgumentList (@("--data-root","$root\phone","--control-port","9111","--control-token",$TOK,"--link-token",$linkResp.link_token) + $tls) `
    -RedirectStandardOutput "$root\phone.log" -RedirectStandardError "$root\phone.err"
Start-Sleep 8
$phone = CtlGet 9111 "/status"
Write-Host "PHONE    status=$($phone.status) node=$($phone.node_id) ip=$($phone.tunnel_ip) mesh_up=$($phone.mesh_up)"

# 10. from the phone, egress to the server private API over the mesh and reach it
#     by the private.<seip> FQDN. 401 = the mesh path hit the JWT-gated API.
('{"ip":"10.64.0.1","port":' + $PRIV + '}') | Out-File "$root\eg.json" -Encoding ascii
$eg = (curl.exe -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data "@$root\eg.json" http://127.0.0.1:9111/egress) | ConvertFrom-Json
if (-not $eg.loopback_port) {
    Write-Host "PRIVATE API via mesh: EGRESS FAILED ($($eg | ConvertTo-Json -Compress))"
    Check $false "phone egressed to the server private API over the mesh"
} else {
    $lp = $eg.loopback_port
    $code = curl.exe -s -m8 $REVOKE -o NUL -w "%{http_code}" --resolve "${PRIVFQDN}:${lp}:127.0.0.1" --cacert $ca "https://${PRIVFQDN}:${lp}/api/trust/status"
    Write-Host "PRIVATE API via mesh: HTTP $code (401 = reached JWT-gated private API)"
    Check ($code -eq "401") "private API reached over mesh with its own verified cert"
}

Write-Host "`n--- server join log ---"
Select-String -Path "$root\server.log" -Pattern "Join\]|linked device|registration closed" -EA SilentlyContinue |
    Select-Object -Last 6 | ForEach-Object { $_.Line }

# On failure the CI temp dir is discarded with the runner, so print enough to
# diagnose the listeners without reproducing locally.
if ($script:fail -gt 0) {
    Write-Host "`n--- server TLS / listener log ---"
    Select-String -Path "$root\server.log" -Pattern "Auto-TLS|Private API|HttpServer|TLS enabled|listening" -EA SilentlyContinue |
        Select-Object -Last 20 | ForEach-Object { $_.Line }
    Write-Host "`n--- server.err ---"
    Get-Content "$root\server.err" -Tail 20 -EA SilentlyContinue
    Write-Host "`n--- curl version (TLS backend) ---"
    curl.exe -V | Select-Object -First 1
}

Cleanup
if ($script:fail -gt 0) {
    Write-Host "`n$($script:fail) CHECK(S) FAILED. Logs in $root"
    exit 1
}
Write-Host "`nALL CHECKS PASSED. Logs in $root"
