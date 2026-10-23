# GUARDRAIL-X launcher — stops any previous instance, then serves the app.
# Usage:  .\run.ps1 [-Port 8899]
param(
    [int]$Port = 8899
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

# free the port if a previous instance (or anything else) holds it
$listeners = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
foreach ($l in $listeners) {
    $p = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
    if ($p -and $p.ProcessName -in @("python", "uvicorn")) {
        Write-Host "Stopping previous instance (pid $($p.Id))..."
        Stop-Process -Id $p.Id -Force
        Start-Sleep -Seconds 1
    } elseif ($p) {
        Write-Warning "Port $Port is used by '$($p.ProcessName)' (pid $($p.Id)) - not stopping it. Choose another port: .\run.ps1 -Port 9000"
        exit 1
    }
}

$env:GX_DATA_DIR = Join-Path $root "data"
$env:PYTHONPATH  = $root

Write-Host "Starting GUARDRAIL-X on http://127.0.0.1:$Port  (Ctrl+C to stop)"
Write-Host "API docs: http://127.0.0.1:$Port/api/docs"
python -m uvicorn app.main:app --port $Port
