<#
.SYNOPSIS
    Collecteur MADSC — composition des groupes privilégiés (LECTURE SEULE, sur le DC).

.DESCRIPTION
    Lit les membres EFFECTIFS (récursifs) des groupes privilégiés Tier 0 et produit un snapshot JSON.
    Résolution par SID/RID (indépendant de la localisation FR/EN). Toute modification de composition
    ressort en DÉRIVE (CHANGED) côté MADSC — ces contrôles sont « baseline-only » (pas de valeur fixe).

    GARANTIE : 100 % LECTURE (Get-ADGroupMember / Get-ADDomain). Aucun écrit AD.
    Requiert le module ActiveDirectory (présent sur un DC ou via RSAT).

.PARAMETER OutDir   Dossier de sortie du snapshot JSON (défaut : dossier courant).
.PARAMETER PostUrl  URL MADSC pour envoi HTTP direct (ex. http://192.168.10.1:8700/ingest).

.EXAMPLE
    .\Collect-PrivilegedGroups.ps1 -PostUrl http://192.168.10.1:8700/ingest
#>
[CmdletBinding()]
param(
    [string]$OutDir = ".",
    [string]$PostUrl
)

Import-Module ActiveDirectory -ErrorAction Stop

$pt   = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
$role = switch ($pt) { 2 { 'DC' } 3 { 'MEMBER' } default { 'WORKSTATION' } }

$domainSid = (Get-ADDomain).DomainSID.Value
try { $rootSid = (Get-ADDomain (Get-ADForest).RootDomain).DomainSID.Value } catch { $rootSid = $domainSid }

# Membres effectifs (récursifs) d'un groupe -> chaîne triée "a, b, c" (comparaison de dérive fiable)
function Get-GroupControl {
    param($ControlId, $Identity)
    try {
        $names = Get-ADGroupMember -Identity $Identity -Recursive -ErrorAction Stop |
                 Select-Object -ExpandProperty SamAccountName
    } catch { return $null }
    $sorted = @($names | Sort-Object)
    return [pscustomobject]@{
        control_id = $ControlId
        observed   = @{ members = ($sorted -join ', '); count = $sorted.Count }
        raw        = "Get-ADGroupMember -Recursive $Identity"
    }
}

$targets = @(
    @{ cid = 'PRIV-DOMAIN-ADMINS';     id = "$domainSid-512" },
    @{ cid = 'PRIV-ENTERPRISE-ADMINS'; id = "$rootSid-519" },
    @{ cid = 'PRIV-SCHEMA-ADMINS';     id = "$rootSid-518" },
    @{ cid = 'PRIV-BUILTIN-ADMINS';    id = 'S-1-5-32-544' },
    @{ cid = 'PRIV-GG-T0-ADMINS';      id = 'GG_T0_Admins' }
)

$controls = @()
foreach ($t in $targets) {
    $c = Get-GroupControl -ControlId $t.cid -Identity $t.id
    if ($c) { $controls += $c }
    else    { Write-Host "[MADSC] $($t.cid) : groupe introuvable/erreur, ignore" -ForegroundColor Yellow }
}

$snapshot = [pscustomobject]@{
    host              = $env:COMPUTERNAME
    role              = $role
    collector         = 'Collect-PrivilegedGroups'
    collector_version = '1.0'
    collected_at      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    controls          = $controls
}

$json = $snapshot | ConvertTo-Json -Depth 6

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$file  = Join-Path $OutDir ("snapshot-{0}-privgroups-{1}.json" -f $env:COMPUTERNAME, $stamp)
$json | Out-File -FilePath $file -Encoding utf8
Write-Host "[MADSC] Snapshot ecrit : $file" -ForegroundColor Green

if ($PostUrl) {
    try {
        Invoke-RestMethod -Method Post -Uri $PostUrl -Body $json -ContentType 'application/json; charset=utf-8' -TimeoutSec 15 | Out-Null
        Write-Host "[MADSC] POST OK -> $PostUrl" -ForegroundColor Green
    } catch {
        Write-Host "[MADSC] POST ECHEC ($PostUrl) : $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
