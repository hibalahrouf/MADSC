<#
.SYNOPSIS
    Collecteur MADSC - modele de l'annuaire pour ChangeGuard (LECTURE SEULE).

.DESCRIPTION
    GARANTIE : ce script est 100 % LECTURE. Il n'utilise que des cmdlets Get-* du module
    ActiveDirectory. Il n'ecrit RIEN : ni objet, ni attribut, ni permission, ni registre.
    La liste exacte des operations executees est affichee avant de les lancer (-Preview),
    pour que ce soit verifiable et non promis.

    Ce qu'il ne fait JAMAIS : New-AD*, Set-AD*, Remove-AD*, Add-ADGroupMember,
    Move-ADObject, et surtout PAS gpupdate.

    ---------------- CE QUI EST COLLECTE, ET POURQUOI ----------------
    Ce collecteur n'emet AUCUN controle. Il ne juge rien et ne se compare a aucune baseline :
    il decrit le DECOR dans lequel les controles se lisent. Sa charge utile part dans le champ
    `topology` du snapshot, pas dans `controls` - voir backend/models.py pour le raisonnement.

    ORDINATEURS   Nom, DN et systeme d'exploitation de chaque machine du domaine.
                  C'est ce qui permet a ChangeGuard de repondre a « QUELLES machines ce lien
                  de GPO toucherait-il ? ». Sans cet inventaire, la portee d'un lien n'est pas
                  vide : elle est INCONNUE, et doit s'afficher comme telle.

                  Le DN, pas le nom. La machine Tier 2 du laboratoire s'appelle
                  DESKTOP-0LKLBTR alors que sa GPO et son groupe portent « WS01 » : le nom
                  d'hote ne dit rien du tier, seul l'emplacement dans l'annuaire le dit.

    GROUPES       SID, nom et PORTEE (DomainLocal / Global / Universal) de chaque groupe.
                  La portee est la seule facon de VERIFIER la chaine AGDLP au lieu de la
                  presumer : rien dans un SID ne dit qu'un principal est un groupe de domaine
                  local. Sans cet inventaire, ChangeGuard classe par convention de nommage
                  (prefixe DL_) et le dit ; avec lui, il mesure.

                  La COMPLETUDE de cette liste est ce qui rend l'ABSENCE informative : un SID
                  qui n'y figure pas n'est pas un groupe, donc c'est un compte nomme
                  directement. D'ou le drapeau `groupes_complets` ci-dessous - un inventaire
                  partiel ferait dire a cette absence le contraire de ce qu'elle vaut.

    UNITES        DN de chaque unite d'organisation. Une unite sans machine existe : c'est le
                  cas de Tier0 sur ce domaine. Ne pas la connaitre ferait confondre « aucune
                  machine ici » avec « unite inconnue ».
    ------------------------------------------------------------------

    ECHEC BRUYANT (regle n.2 du projet) : si le module ActiveDirectory est absent, AUCUNE
    topologie n'est emise et la raison est affichee. Emettre un domaine vide ressemblerait a
    un domaine sans machines, alors que la realite est « je n'ai rien pu lire ».

.PARAMETER Preview
    Affiche chaque operation de lecture ET son resultat, sans rien ecrire ni envoyer.

.PARAMETER OutDir
    Dossier de sortie du snapshot JSON. Ignore en -Preview.

.PARAMETER PostUrl
    Envoi a MADSC. ABSENT PAR DEFAUT : ce collecteur n'envoie rien tant qu'on ne le demande pas.

.EXAMPLE
    .\Collect-ADTopology.ps1 -Preview

.EXAMPLE
    .\Collect-ADTopology.ps1 -OutDir C:\MADSC-out
#>
[CmdletBinding()]
param(
    [string]$OutDir = ".",
    [string]$PostUrl,
    [switch]$Preview
)

$ErrorActionPreference = 'Stop'

$READ_OPERATIONS = @(
    "Get-ADDomain                                    DN, SID et nom DNS du domaine",
    "Get-ADComputer -Filter *                        nom, DN et OS de chaque machine",
    "Get-ADGroup -Filter *                           SID, nom et PORTEE de chaque groupe",
    "Get-ADOrganizationalUnit -Filter *              DN de chaque unite d'organisation"
)

Write-Host ""
Write-Host "=== Collect-ADTopology - LECTURE SEULE ===" -ForegroundColor Cyan
Write-Host "Operations qui vont etre executees :" -ForegroundColor Cyan
foreach ($op in $READ_OPERATIONS) { Write-Host "    $op" }
Write-Host "Aucune ecriture : ni objet, ni attribut, ni permission, ni gpupdate." -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------- prerequis
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "[X] Module ActiveDirectory absent : AUCUNE topologie emise." -ForegroundColor Red
    Write-Host "    Present d'office sur un controleur de domaine ; ailleurs, RSAT-AD-PowerShell." -ForegroundColor Yellow
    Write-Host "    Emettre un domaine vide ressemblerait a un domaine sans machines." -ForegroundColor Yellow
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

$pt   = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
$role = switch ($pt) { 2 { 'DC' } 3 { 'MEMBER' } default { 'WORKSTATION' } }

function Show-Step($label) {
    if ($Preview) { Write-Host "--> $label" -ForegroundColor Gray }
}

Show-Step "Get-ADDomain"
$domain = $null
try { $domain = Get-ADDomain -ErrorAction Stop } catch {}
if (-not $domain) {
    Write-Host "[X] Domaine illisible : AUCUNE topologie emise." -ForegroundColor Red
    exit 1
}

Write-Host "[i] Domaine : $($domain.DNSRoot)  ($($domain.DistinguishedName))"
Write-Host ""

# ---------------------------------------------------------------- 1. ordinateurs
Show-Step "Get-ADComputer -Filter * -Properties OperatingSystem"
$computers = @()
$computersComplets = $true
try {
    foreach ($c in (Get-ADComputer -Filter * -Properties OperatingSystem -ErrorAction Stop)) {
        $computers += [pscustomobject]@{
            Name              = $c.Name
            DistinguishedName = $c.DistinguishedName
            OperatingSystem   = $c.OperatingSystem
            Enabled           = [bool]$c.Enabled
        }
    }
} catch {
    $computersComplets = $false
    Write-Host "[!] Ordinateurs illisibles : $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------- 2. groupes
# La PORTEE est le seul champ qui compte ici : elle transforme la verification AGDLP d'une
# presomption de nommage en une mesure.
Show-Step "Get-ADGroup -Filter * -Properties GroupScope,GroupCategory"
$groups = @()
$groupesComplets = $true
try {
    foreach ($g in (Get-ADGroup -Filter * -Properties GroupScope, GroupCategory -ErrorAction Stop)) {
        $groups += [pscustomobject]@{
            sid       = $g.SID.Value
            nom       = $g.Name
            portee    = [string]$g.GroupScope      # DomainLocal | Global | Universal
            categorie = [string]$g.GroupCategory   # Security | Distribution
            dn        = $g.DistinguishedName
        }
    }
} catch {
    # DRAPEAU DECISIF. Un inventaire partiel ferait conclure a tort « ce SID n'est pas un
    # groupe » pour tout groupe manquant, donc a un contournement AGDLP inexistant.
    $groupesComplets = $false
    Write-Host "[!] Groupes illisibles : $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    ChangeGuard retombera sur la convention de nommage, et le dira." -ForegroundColor Yellow
}

# ---------------------------------------------------------------- 3. unites d'organisation
Show-Step "Get-ADOrganizationalUnit -Filter *"
$ous = @()
try {
    foreach ($o in (Get-ADOrganizationalUnit -Filter * -ErrorAction Stop)) {
        $ous += [pscustomobject]@{ nom = $o.Name; dn = $o.DistinguishedName }
    }
} catch {
    Write-Host "[!] Unites d'organisation illisibles : $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------- 4. rapport de GPO
# Le rapport XML BRUT, tel que le GPMC le rend. Il est transmis SANS INTERPRETATION : la
# lecture des reglages vit dans backend/gposettings.py, cote serveur.
#
# Pourquoi ici plutot que dans Collect-GPO.ps1 : celui-ci emet des CONTROLES, evalues et
# compares a une baseline approuvee. Y ajouter le rapport changerait la forme d'un controle
# deja approuve et ferait deriver la baseline pour une raison purement technique. La topologie
# n'a pas ce probleme - c'est du decor, pas un verdict.
#
# Volume : environ 500 Ko sur ce domaine. La table ad_topology est bornee cote serveur (voir
# db.init_db) ; sans cette borne, deux collectes par jour ajouteraient ~1 Mo par jour.
$gpoReport = $null
if (Get-Module -ListAvailable -Name GroupPolicy) {
    Show-Step "Get-GPOReport -All -ReportType Xml"
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpoReport = Get-GPOReport -All -ReportType Xml -ErrorAction Stop
    } catch {
        Write-Host "[!] Rapport de GPO illisible : $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] Module GroupPolicy absent : aucun rapport de GPO." -ForegroundColor Yellow
    Write-Host "    ChangeGuard n'aura aucune strategie a analyser, et le dira." -ForegroundColor Yellow
}

# ---------------------------------------------------------------- restitution
Write-Host ""
Write-Host "=== Ce qui a ete LU ===" -ForegroundColor Cyan
Write-Host ("  ORDINATEURS : {0}{1}" -f $computers.Count,
            $(if (-not $computersComplets) { "  (INCOMPLET)" } else { "" }))
foreach ($c in $computers) {
    Write-Host ("                  - {0}  [{1}]" -f $c.Name, $c.DistinguishedName) -ForegroundColor DarkGray
}
Write-Host ("  GROUPES     : {0}{1}" -f $groups.Count,
            $(if (-not $groupesComplets) { "  (INCOMPLET - classification AGDLP par convention)" } else { "" }))
$domainLocal = @($groups | Where-Object { $_.portee -eq 'DomainLocal' })
Write-Host ("                  dont {0} de portee DomainLocal (le « DL » d'AGDLP)" -f $domainLocal.Count) -ForegroundColor DarkGray
Write-Host ("  UNITES      : {0}" -f $ous.Count)
foreach ($o in $ous) { Write-Host ("                  - {0}" -f $o.dn) -ForegroundColor DarkGray }
Write-Host ("  RAPPORT GPO : {0}" -f $(if ($gpoReport) { "{0:N0} caracteres" -f $gpoReport.Length }
                                       else { "NON LU" }))

$topology = [pscustomobject]@{
    domaine            = [pscustomobject]@{
        dns_root = $domain.DNSRoot
        dn       = $domain.DistinguishedName
        sid      = $domain.DomainSID.Value
    }
    computers          = @($computers)
    groups             = @($groups)
    ous                = @($ous)
    gpo_report_xml     = $gpoReport
    computers_complets = $computersComplets
    groupes_complets   = $groupesComplets
    lu_le              = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# `controls` reste VIDE et c'est voulu : ce collecteur ne produit aucun verdict, donc rien qui
# doive etre evalue, compare a une baseline ou compte dans un score.
$snapshot = [pscustomobject]@{
    host              = $env:COMPUTERNAME
    role              = $role
    collector         = 'Collect-ADTopology'
    collector_version = '1.0'
    collected_at      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    controls          = @()
    topology          = $topology
}

Write-Host ""
if ($Preview) {
    Write-Host "=== MODE PREVIEW : rien n'a ete ecrit, rien n'a ete envoye ===" -ForegroundColor Green
    Write-Host "Charge utile qui SERAIT produite :" -ForegroundColor Cyan
    $snapshot | ConvertTo-Json -Depth 8
    return
}

$json = $snapshot | ConvertTo-Json -Depth 8
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$file  = Join-Path $OutDir ("snapshot-{0}-adtopology-{1}.json" -f $env:COMPUTERNAME, $stamp)
$json | Out-File -FilePath $file -Encoding utf8
Write-Host "[MADSC] Snapshot ecrit : $file" -ForegroundColor Green

if ($PostUrl) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $headers = @{}
        if ($env:MADSC_API_KEY) { $headers['X-MADSC-Key'] = $env:MADSC_API_KEY }
        $null = Invoke-RestMethod -Method Post -Uri $PostUrl -Body $json -ContentType 'application/json; charset=utf-8' -TimeoutSec 30 -Headers $headers
        Write-Host "[MADSC] POST OK -> $PostUrl" -ForegroundColor Green
    } catch {
        Write-Host "[MADSC] POST ECHEC ($PostUrl) : $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[i] Aucun -PostUrl : rien n'a ete envoye." -ForegroundColor Cyan
}
