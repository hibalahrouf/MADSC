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

# auditpol.exe ecrit dans la page de codes OEM. Si la console est sur une autre page (UTF-8
# par exemple), les accents sont decodes de travers et finissent en caracteres de
# remplacement jusque dans la base et le rapport. On aligne l'encodage le temps de l'appel.
$prevEnc = $null
try {
    $prevEnc = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(
        [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
} catch {
    $prevEnc = $null   # pas de console rattachee (tache planifiee) : on garde le defaut
}

# Colonnes de `auditpol /r` :
#   0=Machine  1=Policy Target  2=Subcategory  3=Subcategory GUID
#   4=Inclusion Setting (TEXTE LOCALISE)      5=Exclusion Setting   6=Setting Value (NUMERIQUE)
# On decide sur la colonne 6, numerique : 0=aucun audit, 1=succes, 2=echec, 3=succes+echec.
# Filtrer sur le libelle localise de la colonne 4 est fragile (langue, apostrophe typographique,
# encodage) et laissait passer TOUTES les sous-categories, y compris celles sans audit.
$SETTING_LABEL = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }

try {
    $lines = auditpol.exe /get /category:* /r   # LECTURE SEULE

    $audited = @()
    $parsed  = 0
    foreach ($line in $lines) {
        if (-not $line) { continue }
        $parts = $line.Split(',')
        if ($parts.Count -lt 7) { continue }

        $value = 0
        # Non numerique => ligne d'en-tete (dans n'importe quelle langue) : ignoree.
        if (-not [int]::TryParse($parts[6].Trim(), [ref]$value)) { continue }
        $parsed++

        if ($value -le 0) { continue }   # 0 = aucun audit -> exclu du perimetre audite
        $audited += ("{0}={1}" -f $parts[2].Trim(), $SETTING_LABEL[$value])
    }

    $sorted = @($audited | Sort-Object)
    $controls += [pscustomobject]@{
        control_id = 'AUDIT-ADVANCED-POLICY'
        observed   = @{
            subcategories_audited = $sorted.Count
            subcategories_total   = $parsed
            active_policy         = ($sorted -join '; ')
        }
        raw        = 'auditpol.exe /get /category:* /r (colonne Setting Value, numerique)'
    }
    Write-Host "[MADSC] Audit : $($sorted.Count) sous-categorie(s) auditee(s) sur $parsed" -ForegroundColor Cyan
} catch {
    Write-Host "[MADSC] AUDIT-ADVANCED-POLICY : erreur de lecture auditpol" -ForegroundColor Yellow
} finally {
    if ($prevEnc) { try { [Console]::OutputEncoding = $prevEnc } catch {} }
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
$json | Out-File -FilePath $file -Encoding utf8   # utf8 : ASCII detruisait les accents des libelles
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
