<#
.SYNOPSIS
    Collecteur MADSC - durcissement protocolaire (LECTURE SEULE).

.DESCRIPTION
    Lit l'etat de durcissement des protocoles (LDAP/SMB/NTLM/LLMNR) et produit un
    snapshot JSON consommable par le backend MADSC.

    GARANTIE : ce script est 100 % LECTURE. Il n'utilise que Get-* et des lectures
    de registre. Aucune ecriture AD / registre / GPO. Executable sans risque sur DC-01,
    PMS-01 ou WS-01. (Ne depend PAS du service EventLog : fonctionne meme sur PMS-01.)

.PARAMETER OutDir
    Dossier de sortie du snapshot JSON (defaut : dossier courant).

.EXAMPLE
    .\Collect-Protocols.ps1 -OutDir C:\MADSC-out
    # puis copier le .json vers MADSC\data\snapshots\ sur le host de dev
#>
[CmdletBinding()]
param(
    [string]$OutDir = ".",
    [string]$PostUrl   # ex. http://192.168.10.1:8700/ingest  -> envoi DIRECT a MADSC (sans partage de fichiers)
)

function Get-RegVal {
    param($Path, $Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

# Rôle de l'hôte (ProductType : 1=poste, 2=DC, 3=serveur membre)
$pt   = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
$role = switch ($pt) { 2 { 'DC' } 3 { 'MEMBER' } default { 'WORKSTATION' } }

# SMBv1 (cmdlet lecture seule)
$smb1 = $null
try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}

$controls = @()

# LDAP signing : DC uniquement
if ($role -eq 'DC') {
    $controls += [pscustomobject]@{
        control_id = 'PROTO-LDAP-SIGNING'
        observed   = @{ LDAPServerIntegrity = (Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity') }
        raw        = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
    }
}

$controls += [pscustomobject]@{
    control_id = 'PROTO-SMB-SIGNING-SERVER'
    observed   = @{ RequireSecuritySignature = (Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature') }
    raw        = 'HKLM\...\LanmanServer\Parameters\RequireSecuritySignature'
}
$controls += [pscustomobject]@{
    control_id = 'PROTO-SMB-SIGNING-CLIENT'
    observed   = @{ RequireSecuritySignature = (Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature') }
    raw        = 'HKLM\...\LanmanWorkstation\Parameters\RequireSecuritySignature'
}
$controls += [pscustomobject]@{
    control_id = 'PROTO-SMBv1-DISABLED'
    observed   = @{ EnableSMB1Protocol = $smb1 }
    raw        = 'Get-SmbServerConfiguration.EnableSMB1Protocol'
}
$controls += [pscustomobject]@{
    control_id = 'PROTO-NTLMv2-ONLY'
    observed   = @{ LmCompatibilityLevel = (Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel') }
    raw        = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
}
$controls += [pscustomobject]@{
    control_id = 'PROTO-NOLMHASH'
    observed   = @{ NoLMHash = (Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash') }
    raw        = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash'
}
$controls += [pscustomobject]@{
    control_id = 'PROTO-LLMNR-DISABLED'
    observed   = @{ EnableMulticast = (Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') }
    raw        = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'
}

$snapshot = [pscustomobject]@{
    host              = $env:COMPUTERNAME
    role              = $role
    collector         = 'Collect-Protocols'
    collector_version = '1.0'
    collected_at      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    controls          = $controls
}

$json = $snapshot | ConvertTo-Json -Depth 6

# 1) Ecriture fichier (preuve locale + mode fichier / auto-scan)
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$file  = Join-Path $OutDir ("snapshot-{0}-protocols-{1}.json" -f $env:COMPUTERNAME, $stamp)
$json | Out-File -FilePath $file -Encoding utf8
Write-Host "[MADSC] Snapshot ecrit : $file" -ForegroundColor Green
Write-Host "[MADSC] Role detecte    : $role" -ForegroundColor Cyan

# 2) Envoi DIRECT a MADSC (mode live, SANS partage) si -PostUrl fourni
if ($PostUrl) {
    try {
        Invoke-RestMethod -Method Post -Uri $PostUrl -Body $json -ContentType 'application/json; charset=utf-8' -TimeoutSec 15 | Out-Null
        Write-Host "[MADSC] POST OK -> $PostUrl" -ForegroundColor Green
    } catch {
        Write-Host "[MADSC] POST ECHEC ($PostUrl) : $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "        (le fichier reste disponible pour ingestion via auto-scan)" -ForegroundColor Yellow
    }
}
