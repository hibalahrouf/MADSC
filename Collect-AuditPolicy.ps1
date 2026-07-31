<#
.SYNOPSIS
    Collecteur MADSC - politique d'audit avancee de securite (LECTURE SEULE).

.DESCRIPTION
    Lit la politique d'audit de securite active (auditpol.exe) et produit un snapshot JSON.
    GARANTIE : 100 % LECTURE SEULE (auditpol.exe /get). AUCUNE modification de la politique.

.PARAMETER OutDir   Dossier de sortie du snapshot JSON (defaut : dossier courant).
.PARAMETER PostUrl  URL MADSC pour envoi HTTP direct (ex. http://192.168.10.1:8700/ingest).

.EXAMPLE
    .\Collect-AuditPolicy.ps1 -PostUrl http://192.168.10.1:8700/ingest
#>
[CmdletBinding()]
param(
    [string]$OutDir = ".",
    [string]$PostUrl
)

$ErrorActionPreference = 'Stop'

# Role de l'hote (ProductType : 1=poste, 2=DC, 3=serveur membre)
$pt   = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
$role = switch ($pt) { 2 { 'DC' } 3 { 'MEMBER' } default { 'WORKSTATION' } }

$controls = @()

try {
    # Lecture seule via auditpol.exe (format CSV)
    $lines = auditpol.exe /get /category:* /r
    $activeSubcats = @()
    
    foreach ($line in $lines) {
        if (-not $line -or $line -like 'Node Name*') { continue }
        $parts = $line.Split(',')
        if ($parts.Count -ge 5) {
            $subcat = $parts[2].Trim()
            $setting = $parts[4].Trim()
            if ($setting -and $setting -ne 'No Auditing' -and $setting -ne 'Pas d’audit' -and $setting -ne 'Aucun audit') {
                $activeSubcats += "$subcat=$setting"
            }
        }
    }

    $sorted = @($activeSubcats | Sort-Object)
    $controls += [pscustomobject]@{
        control_id = 'AUDIT-ADVANCED-POLICY'
        observed   = @{
            subcategories_active = $sorted.Count
            active_policy        = ($sorted -join '; ')
        }
        raw        = 'auditpol.exe /get /category:* /r'
    }
} catch {
    Write-Host "[MADSC] AUDIT-ADVANCED-POLICY : erreur de lecture auditpol" -ForegroundColor Yellow
}

# Generation du snapshot JSON
$snapshot = [pscustomobject]@{
    host              = $env:COMPUTERNAME
    role              = $role
    collector         = 'Collect-AuditPolicy'
    collector_version = '1.0'
    collected_at      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    controls          = $controls
}

$json = $snapshot | ConvertTo-Json -Depth 6

# 1) Ecriture fichier (preuve locale)
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$file  = Join-Path $OutDir ("snapshot-{0}-audit-{1}.json" -f $env:COMPUTERNAME, $stamp)
$json | Out-File -FilePath $file -Encoding ASCII
Write-Host "[MADSC] Snapshot ecrit : $file" -ForegroundColor Green
Write-Host "[MADSC] Role detecte    : $role" -ForegroundColor Cyan

# 2) Envoi DIRECT a MADSC (mode live, SANS partage) si -PostUrl fourni
if ($PostUrl) {
    try {
        Invoke-RestMethod -Method Post -Uri $PostUrl -Body $json -ContentType 'application/json; charset=utf-8' -TimeoutSec 15 | Out-Null
        Write-Host "[MADSC] POST OK -> $PostUrl" -ForegroundColor Green
    } catch {
        Write-Host "[MADSC] POST ECHEC ($PostUrl) : $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "        (le fichier reste disponible pour ingestion)" -ForegroundColor Yellow
    }
}
