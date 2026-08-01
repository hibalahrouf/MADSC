<#
.SYNOPSIS
    Collecteur MADSC - configuration Active Directory et Services (LECTURE SEULE).

.DESCRIPTION
    Lit les parametres de securite AD et services sensibles (MachineAccountQuota, Print Spooler DC, Corbeille AD).
    GARANTIE : 100 % LECTURE SEULE (Get-*, lectura ADSI/registre/services). AUCUNE modification de l'AD ou du systeme.

.PARAMETER OutDir   Dossier de sortie du snapshot JSON (defaut : dossier courant).
.PARAMETER PostUrl  URL MADSC pour envoi HTTP direct (ex. http://192.168.10.1:8700/ingest).

.EXAMPLE
    .\Collect-ADConfig.ps1 -PostUrl http://192.168.10.1:8700/ingest
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

# 1. MachineAccountQuota (DC uniquement)
if ($role -eq 'DC') {
    try {
        $rootDse  = [ADSI]"LDAP://RootDSE"
        $domainDN = $rootDse.defaultNamingContext
        $domain   = [ADSI]"LDAP://$domainDN"
        $maqVal   = $domain.Properties['ms-DS-MachineAccountQuota'].Value
        if ($maqVal -eq $null) { $maqVal = 10 }

        $controls += [pscustomobject]@{
            control_id = 'AD-MAQ'
            observed   = @{ 'ms-DS-MachineAccountQuota' = [int]$maqVal }
            raw        = "ADSI: LDAP://$domainDN (ms-DS-MachineAccountQuota)"
        }
    } catch {
        Write-Host "[MADSC] AD-MAQ : erreur d'evaluation ADSI" -ForegroundColor Yellow
    }
}

# 2. Print Spooler (DC uniquement)
if ($role -eq 'DC') {
    try {
        $spoolerStart = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Spooler' -Name 'Start' -ErrorAction Stop).Start
        # Windows Service StartType: 4 = Disabled, 2 = Automatic, 3 = Manual
        $startTypeStr = switch ($spoolerStart) { 4 { 'Disabled' } 2 { 'Automatic' } 3 { 'Manual' } default { "Unknown($spoolerStart)" } }

        $controls += [pscustomobject]@{
            control_id = 'SVC-PRINT-SPOOLER-DC'
            observed   = @{ StartType = $startTypeStr }
            raw        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Spooler\Start'
        }
    } catch {
        Write-Host "[MADSC] SVC-PRINT-SPOOLER-DC : erreur de lecture registre" -ForegroundColor Yellow
    }
}

# 3. Corbeille AD (DC uniquement)
if ($role -eq 'DC') {
    $isEnabled = $false
    try {
        $feat = Get-ADOptionalFeature -Identity 'Recycle Bin Feature' -ErrorAction Stop
        $isEnabled = ($feat.EnabledScopes.Count -gt 0)
    } catch {
        try {
            $rootDse = [ADSI]"LDAP://RootDSE"
            $configDN = $rootDse.configurationNamingContext
            $partObj = [ADSI]"LDAP://CN=Partitions,$configDN"
            $enabledFeats = $partObj.Properties['msDS-EnabledFeature']
            if ($enabledFeats) {
                foreach ($f in $enabledFeats) {
                    if ($f -like '*Recycle Bin*') { $isEnabled = $true; break }
                }
            }
        } catch { $isEnabled = $false }
    }

    $controls += [pscustomobject]@{
        control_id = 'AD-RECYCLE-BIN'
        observed   = @{ RecycleBinEnabled = [bool]$isEnabled }
        raw        = 'Get-ADOptionalFeature / ADSI Partitions'
    }
}

# Generation du snapshot JSON
$snapshot = [pscustomobject]@{
    host              = $env:COMPUTERNAME
    role              = $role
    collector         = 'Collect-ADConfig'
    collector_version = '1.0'
    collected_at      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    controls          = $controls
}

$json = $snapshot | ConvertTo-Json -Depth 6

# 1) Ecriture fichier (preuve locale)
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$file  = Join-Path $OutDir ("snapshot-{0}-adconfig-{1}.json" -f $env:COMPUTERNAME, $stamp)
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
