<#
.SYNOPSIS
    Collecteur MADSC — composition des groupes privilégiés (LECTURE SEULE, sur le DC).

.DESCRIPTION
    Lit les membres EFFECTIFS (récursifs) des groupes privilégiés Tier 0 via LDAP direct (ADSI).
    Résolution par SID/RID (indépendant de la localisation FR/EN).

    ┌─ POURQUOI ADSI/LDAP et PAS le module ActiveDirectory ─────────────────────────────┐
    │ Le module ActiveDirectory (Get-AD*) dépend du service ADWS (port 9389). Si ADWS    │
    │ est arrêté, tous les Get-AD* échouent. ADSI interroge le DC en LDAP (389), qui est  │
    │ indépendant d'ADWS -> ce collecteur fonctionne même sans ADWS et SANS aucun module. │
    └────────────────────────────────────────────────────────────────────────────────────┘

    GARANTIE : 100 % LECTURE (RootDSE + DirectorySearcher). Aucun écrit AD.
    Membres récursifs via la règle LDAP IN_CHAIN (1.2.840.113556.1.4.1941).

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

# Contextes de nommage via RootDSE (LDAP, ne dépend PAS d'ADWS)
$rootDSE      = [ADSI]"LDAP://RootDSE"
$domainDN     = [string]$rootDSE.defaultNamingContext
$rootDomainDN = [string]$rootDSE.rootDomainNamingContext

# SID du domaine (pour construire les RID) et du domaine racine de forêt
function ConvertTo-SidString($obj) {
    $bytes = $obj.Properties["objectSid"][0]
    return (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value
}
$domainSid = ConvertTo-SidString ([ADSI]"LDAP://$domainDN")
try { $rootSid = ConvertTo-SidString ([ADSI]"LDAP://$rootDomainDN") } catch { $rootSid = $domainSid }

$pt   = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
$role = switch ($pt) { 2 { 'DC' } 3 { 'MEMBER' } default { 'WORKSTATION' } }

function Get-GroupDN {
    param([string]$Sid, [string]$Name)
    if ($Sid) {
        try {
            $g  = [ADSI]"LDAP://<SID=$Sid>"
            $dn = [string]$g.Properties["distinguishedName"][0]
            if ($dn) { return $dn }
        } catch {}
        return $null
    }
    $s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainDN")
    $s.Filter = "(&(objectClass=group)(sAMAccountName=$Name))"
    [void]$s.PropertiesToLoad.Add("distinguishedName")
    $r = $s.FindOne()
    if ($r) { return [string]$r.Properties["distinguishedname"][0] }
    return $null
}

# Membres effectifs (récursifs) via IN_CHAIN -> comptes personnes uniquement
function Get-EffectiveMembers {
    param([string]$GroupDN)
    $s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainDN")
    $s.PageSize = 1000
    $s.Filter   = "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$GroupDN))"
    [void]$s.PropertiesToLoad.Add("sAMAccountName")
    $names = @()
    foreach ($r in $s.FindAll()) { $names += [string]$r.Properties["samaccountname"][0] }
    return @($names | Sort-Object -Unique)
}

function New-GroupControl {
    param([string]$ControlId, [string]$Sid, [string]$Name)
    $dn = Get-GroupDN -Sid $Sid -Name $Name
    if (-not $dn) { return $null }
    $members = @(Get-EffectiveMembers -GroupDN $dn)
    return [pscustomobject]@{
        control_id = $ControlId
        observed   = @{ members = ($members -join ', '); count = $members.Count }
        raw        = "LDAP IN_CHAIN memberOf ($dn)"
    }
}

$targets = @(
    @{ cid = 'PRIV-DOMAIN-ADMINS';     sid = "$domainSid-512"; name = $null },
    @{ cid = 'PRIV-ENTERPRISE-ADMINS'; sid = "$rootSid-519";   name = $null },
    @{ cid = 'PRIV-SCHEMA-ADMINS';     sid = "$rootSid-518";   name = $null },
    @{ cid = 'PRIV-BUILTIN-ADMINS';    sid = 'S-1-5-32-544';   name = $null },
    @{ cid = 'PRIV-GG-T0-ADMINS';      sid = $null;            name = 'GG_T0_Admins' }
)

$controls = @()
foreach ($t in $targets) {
    $c = New-GroupControl -ControlId $t.cid -Sid $t.sid -Name $t.name
    if ($c) { $controls += $c }
    else    { Write-Host "[MADSC] $($t.cid) : groupe introuvable/erreur, ignore" -ForegroundColor Yellow }
}

$snapshot = [pscustomobject]@{
    host              = $env:COMPUTERNAME
    role              = $role
    collector         = 'Collect-PrivilegedGroups'
    collector_version = '1.1'
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
