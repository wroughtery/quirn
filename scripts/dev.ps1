# dev.ps1 — one-command visibility loop for improving quirn (Windows).
#
# Builds, vets, tests with coverage, then dogfoods quirn against the local
# mockllm target and prints EVERY report format. Run after any change to see
# real end-to-end behavior, not just unit results.
#
#   pwsh scripts/dev.ps1
#
# Throws (non-zero exit) if build/vet/test fail, so it doubles as a CI gate.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

function Section($t) { Write-Host "`n== $t ==" -ForegroundColor Cyan }

Section 'build'; go build ./...; if ($LASTEXITCODE) { exit 1 }
Section 'vet';   go vet ./...;   if ($LASTEXITCODE) { exit 1 }
Section 'test (coverage)'
go test -cover ./...; if ($LASTEXITCODE) { exit 1 }

$bin = Join-Path ([System.IO.Path]::GetTempPath()) ("quirn-dev-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $bin | Out-Null
$quirn = Join-Path $bin 'quirn.exe'
$mock  = Join-Path $bin 'mockllm.exe'
go build -o $quirn .;             if ($LASTEXITCODE) { exit 1 }
go build -o $mock ./cmd/mockllm;  if ($LASTEXITCODE) { exit 1 }

$addr = '127.0.0.1:8749'
$proc = Start-Process -FilePath $mock -ArgumentList $addr -PassThru -NoNewWindow
try {
    foreach ($_ in 1..50) {
        try { Invoke-WebRequest "http://$addr/" -TimeoutSec 1 -UseBasicParsing | Out-Null; break }
        catch { Start-Sleep -Milliseconds 100 }
    }

    $target = "http://$addr"
    function Scan($fmtArgs) {
        & $quirn scan --target $target --api-key sk-dev @fmtArgs
        Write-Host "  -> exit $LASTEXITCODE"
    }

    Section 'scan: text (default)'; Scan @()
    Section 'scan: json envelope';  Scan @('--format','json')
    Section 'scan: markdown';       Scan @('--format','markdown')
    Section 'scan: sarif (head)';   (& $quirn scan --target $target --api-key sk-dev --format sarif) | Select-Object -First 40
    Section 'list-probes';          & $quirn scan --list-probes
    Section 'done'
}
finally {
    if ($proc -and -not $proc.HasExited) { $proc.Kill() }
    Remove-Item -Recurse -Force $bin -ErrorAction SilentlyContinue
}
