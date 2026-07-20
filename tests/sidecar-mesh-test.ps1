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

# curl, not Invoke-WebRequest: PS 5.1 IWR drops the Authorization header.
function CtlGet($port, $path) {
    curl.exe -s -H "Authorization: Bearer $TOK" "http://127.0.0.1:$port$path" | ConvertFrom-Json
}

$procs = @()
$script:caThumb = $null
function Cleanup {
    foreach ($p in $procs) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {} }
    Get-Job | Stop-Job -EA SilentlyContinue; Get-Job | Remove-Job -EA SilentlyContinue
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
                    "--closed-registration","--private-http-port",$PRIV) `
    -RedirectStandardOutput "$root\server.log" -RedirectStandardError "$root\server.err"
Start-Sleep 5
$logged = (Select-String -Path "$root\server.log" -Pattern "SEIP: published (\S+) ->").Matches.Groups[1].Value | Select-Object -First 1
if ($logged -and $logged -ne $SEIP) { Write-Host "WARN: server SEIP '$logged' != computed '$SEIP'" }
$health = curl.exe -s -m8 --cacert $ca "https://${SEIP}:9100/api/health"
Write-Host "server health: $health"
Check ($health -match "ok|healthy|status") "public listener serves the seeded cert on the SEIP FQDN"

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
    $code = curl.exe -s -m8 -o NUL -w "%{http_code}" --resolve "${PRIVFQDN}:${lp}:127.0.0.1" --cacert $ca "https://${PRIVFQDN}:${lp}/api/trust/status"
    Write-Host "PRIVATE API via mesh: HTTP $code (401 = reached JWT-gated private API)"
    Check ($code -eq "401") "private API reached over mesh with its own verified cert"
}

Write-Host "`n--- server join log ---"
Select-String -Path "$root\server.log" -Pattern "Join\]|linked device|registration closed" | Select-Object -Last 6 | ForEach-Object { $_.Line }
Cleanup
if ($script:fail -gt 0) {
    Write-Host "`n$($script:fail) CHECK(S) FAILED. Logs in $root"
    exit 1
}
Write-Host "`nALL CHECKS PASSED. Logs in $root"
