<#
.SYNOPSIS
    Lance TOUS les collecteurs MADSC applicables a cet hote, en serie (LECTURE SEULE).

.DESCRIPTION
    Detecte le role de la machine (DC / serveur membre / poste) et execute la liste de
    collecteurs correspondante, l'une apres l'autre, puis verifie aupres de MADSC que la
    campagne a bien ete enregistree.

    GARANTIE : ce script n'ecrit RIEN. Il ne fait qu'appeler les collecteurs existants, qui
    sont eux-memes 100 % lecture (Get-*, lecture de registre, auditpol /backup).

    ---------------- POURQUOI EN SERIE, ET EN UN SEUL PASSAGE ----------------
    MADSC regroupe les collectes proches en CAMPAGNES (backend/db.py, SCAN_WINDOW_MINUTES
    = 10 min) pour que chaque point de tendance porte sur le meme perimetre de controles.
    Des collecteurs lances en parallele, ou etales sur plus de 10 minutes, produiraient
    DEUX campagnes partielles la ou une seule collecte a eu lieu : `posture_history()` les
    marquerait `partial` et la courbe de tendance se lirait comme un effondrement de la
    posture. Les executer en serie, d'affilee, les garde dans une seule campagne.
    ---------------------------------------------------------------------------

.PARAMETER PostUrl
    Endpoint d'ingestion MADSC (ex. http://192.168.10.1:8700/ingest). Envoi direct, sans
    partage de fichiers. Si absent, les snapshots restent dans -OutDir pour ingestion par
    auto-scan.

.PARAMETER MadscUrl
    Racine du serveur MADSC (ex. http://192.168.10.1:8700). Si fourni :
      - les collecteurs sont RAFRAICHIS depuis /collectors avant execution (une VM restauree
        depuis un vieux snapshot ne tourne alors pas avec un collecteur perime) ;
      - la campagne est VERIFIEE apres coup via /health.
    Deduit de -PostUrl quand celui-ci se termine par /ingest.

.PARAMETER OutDir
    Dossier de depot des snapshots JSON (preuve locale). Defaut : C:\MADSC-out

.PARAMETER Role
    Force le role (DC / MEMBER / WORKSTATION) au lieu de le detecter. Pour tests uniquement.

.PARAMETER ApiKey
    Cle d'API MADSC. A defaut, la variable d'environnement MADSC_API_KEY est utilisee.
    Sans cle, le serveur refuse l'ingestion (401) : la collecte s'arrete de facon VISIBLE
    plutot que d'enregistrer une posture non authentifiee.

.PARAMETER NoDownload
    N'essaie pas de rafraichir les collecteurs, meme si -MadscUrl est fourni.

.EXAMPLE
    # Collecte complete, envoi direct, collecteurs rafraichis, campagne verifiee
    .\Invoke-MadscCollection.ps1 -MadscUrl http://192.168.10.1:8700

.EXAMPLE
    # Depot fichier seul (mode partage / auto-scan)
    .\Invoke-MadscCollection.ps1 -OutDir \\HOST-MADSC\snapshots
#>
[CmdletBinding()]
param(
    [string]$PostUrl,
    [string]$MadscUrl,
    [string]$OutDir = "C:\MADSC-out",
    [ValidateSet("DC", "MEMBER", "WORKSTATION")]
    [string]$Role,
    [string]$ApiKey,
    [switch]$NoDownload
)

$ErrorActionPreference = 'Stop'

# TLS 1.2 AVANT tout appel reseau. Windows PowerShell 5.1 / .NET Framework negocie TLS 1.0 par
# defaut ; le serveur Python exige TLS 1.2+, et l'echec de poignee de main se presente comme
# « la connexion sous-jacente a ete fermee : une erreur inattendue s'est produite lors de
# l'envoi ». Ce message evoque le reseau ou le certificat, jamais la version du protocole :
# c'est ce qui rend la panne longue a diagnostiquer. `-bor` ajoute sans rien retirer.
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# La cle est posee dans l'ENVIRONNEMENT du processus : les collecteurs appeles avec `&`
# tournent dans ce meme processus et l'y trouvent. Elle ne figure donc dans aucune ligne de
# commande enfant, ou n'importe quel utilisateur local pourrait la lire.
if ($ApiKey) { $env:MADSC_API_KEY = $ApiKey }

# Fenetre de campagne cote serveur (backend/db.py). Sert d'alerte, pas de limite : depasser
# ne casse rien, mais la collecte sera comptee comme deux campagnes partielles.
$CampaignWindowMinutes = 10

# ---------------------------------------------------------------- URLs
if (-not $MadscUrl -and $PostUrl -match '^(.*)/ingest/?$') { $MadscUrl = $Matches[1] }
if (-not $PostUrl  -and $MadscUrl) { $PostUrl = "$($MadscUrl.TrimEnd('/'))/ingest" }

# Une URL collee depuis un Markdown rendu vaut "[https://x](https://x)" et produit une erreur
# "unknown url type" tres loin de sa cause. On la refuse tout de suite, en le disant.
foreach ($pair in @(@{n='PostUrl'; v=$PostUrl}, @{n='MadscUrl'; v=$MadscUrl})) {
    if ($pair.v -and $pair.v -notmatch '^https?://') {
        Write-Host "[X] -$($pair.n) invalide : '$($pair.v)'" -ForegroundColor Red
        Write-Host "    Attendu une URL brute (http://...). Une URL copiee depuis un Markdown" -ForegroundColor Yellow
        Write-Host "    RENDU contient des crochets et des parentheses : la coller en TEXTE BRUT." -ForegroundColor Yellow
        exit 1
    }
}

# ---------------------------------------------------------------- Role
if (-not $Role) {
    # ProductType : 1 = poste, 2 = controleur de domaine, 3 = serveur membre. Meme detection
    # que dans les collecteurs eux-memes, pour que le role annonce ici soit celui qu'ils
    # inscriront dans leurs snapshots.
    $pt = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
    $Role = switch ($pt) { 2 { 'DC' } 3 { 'MEMBER' } default { 'WORKSTATION' } }
}

# Listes alignees sur LAUNCH_GUIDE section 8.5 (inventaire des collecteurs par portee).
# Les collecteurs a portee DOMAINE (ADConfig, PrivilegedGroups, Delegation, PasswordPolicy)
# ne tournent que sur le DC : leur donnee est repliquee, la collecter depuis chaque hote
# reviendrait a enregistrer N fois la meme mesure.
#
# ORDRE SIGNIFICATIF POUR UN SEUL COUPLE : Collect-ADTopology suit IMMEDIATEMENT
# Collect-PrivilegedGroups. Les deux observent la meme chose - la population effective des
# groupes privilegies - par deux mecanismes independants (LDAP IN_CHAIN d'un cote,
# member;range + fermeture transitive de l'autre), et backend/corroboration.py les compare.
# Cette comparaison n'a de sens que si les deux relevés sont CONTEMPORAINS : deux lectures
# separees de vingt heures peuvent etre toutes deux exactes tout en decrivant deux etats
# differents, et l'ecart se lirait comme un desaccord de mesure. Les executer cote a cote
# ramene l'ecart a quelques secondes ; $CampaignWindowMinutes (10 min) borne deja la campagne
# entiere, soit six fois moins que la fenetre de corroboration par defaut (1 h).
$CollectorsByRole = @{
    'DC' = @(
        'Collect-Protocols.ps1', 'Collect-AuditPolicy.ps1', 'Collect-DetectionSensors.ps1',
        'Collect-PowerShellLogging.ps1', 'Collect-LAPS.ps1', 'Collect-PrivilegedGroups.ps1',
        'Collect-ADTopology.ps1',
        'Collect-ADConfig.ps1', 'Collect-Delegation.ps1', 'Collect-PasswordPolicy.ps1',
        'Collect-GPO.ps1'
    )
    'MEMBER' = @(
        'Collect-Protocols.ps1', 'Collect-AuditPolicy.ps1', 'Collect-DetectionSensors.ps1',
        'Collect-PowerShellLogging.ps1', 'Collect-LAPS.ps1', 'Collect-LocalAdmins.ps1',
        'Collect-TierBoundaries.ps1'
    )
}
$CollectorsByRole['WORKSTATION'] = $CollectorsByRole['MEMBER']
$Collectors = $CollectorsByRole[$Role]

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

Write-Host ""
Write-Host "=== MADSC - campagne de collecte (LECTURE SEULE) ===" -ForegroundColor Cyan
Write-Host "    Hote        : $env:COMPUTERNAME"
Write-Host "    Role detecte: $Role"
Write-Host "    Collecteurs : $($Collectors.Count)"
Write-Host "    Depot       : $OutDir"
Write-Host "    Envoi       : $(if ($PostUrl) { $PostUrl } else { '(fichier seul)' })"
Write-Host "    Cle d'API   : $(if ($env:MADSC_API_KEY) { 'presente' } else { 'ABSENTE' })"
if ($PostUrl -and -not $env:MADSC_API_KEY) {
    # Dit AVANT la collecte : tous les collecteurs vont tourner puis echouer un par un a
    # l'envoi, et la cause serait noyee dans autant de messages d'erreur identiques.
    Write-Host "[!] Aucune cle d'API : le serveur refusera l'ingestion (401)." -ForegroundColor Yellow
    Write-Host "    Poser -ApiKey ou `$env:MADSC_API_KEY. Les snapshots resteront dans $OutDir." -ForegroundColor Yellow
}
Write-Host ""

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

# ---------------------------------------------------------------- Rafraichissement
if ($MadscUrl -and -not $NoDownload) {
    foreach ($name in $Collectors) {
        try {
            Invoke-WebRequest "$($MadscUrl.TrimEnd('/'))/collectors/$name" `
                -OutFile (Join-Path $ScriptDir $name) -UseBasicParsing -TimeoutSec 20
        } catch {
            # Pas bloquant : la copie locale existante fera l'affaire, mais il faut le DIRE,
            # sinon on croira collecter avec la derniere version du catalogue.
            Write-Host "[!] $name non rafraichi ($($_.Exception.Message)) - copie locale utilisee" -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------- Cibles de collecte
#
# QUELS OBJETS MESURER SUR CE SITE. Trois collecteurs en ont besoin, et jusqu'ici ils ne le
# recevaient jamais : cette boucle ne leur passait que -OutDir et -PostUrl, donc leurs
# parametres de cible prenaient TOUJOURS leur valeur par defaut. Ces valeurs par defaut
# etaient celles de Mogador, appliquees en silence sur n'importe quel annuaire.
#
# LA REPARTITION DES ROLES EST VOULUE : Python lit et VALIDE la declaration de site, HTTP
# transporte des valeurs deja validees, PowerShell recoit des PARAMETRES EXPLICITES. Aucun
# collecteur n'analyse de TOML : il y aurait alors deux lecteurs du meme fichier, et le second
# finirait par le lire autrement.
#
# Sans -MadscUrl, aucune cible n'est recuperee. Les collecteurs concernes emettent alors leurs
# controles SANS valeur observee, et MADSC les rend NON EVALUES. C'est exact et visible — bien
# plus que de mesurer les objets d'un autre domaine.
$Cibles = $null
if ($MadscUrl) {
    try {
        $entetes = @{}
        if ($env:MADSC_API_KEY) { $entetes['X-MADSC-Key'] = $env:MADSC_API_KEY }
        $Cibles = (Invoke-RestMethod -Uri "$($MadscUrl.TrimEnd('/'))/api/collecte" `
                                     -Headers $entetes -TimeoutSec 10).cibles
        Write-Host "[MADSC] Cibles de collecte recuperees depuis le profil de site." -ForegroundColor Gray
    } catch {
        Write-Host "[!] /api/collecte injoignable ($($_.Exception.Message))" -ForegroundColor Yellow
        Write-Host "    Les controles qui en dependent seront NON EVALUES." -ForegroundColor Yellow
    }
}

function Get-ArgumentsDeCollecte {
    <#
      Parametres supplementaires d'UN collecteur, d'apres les cibles du site.

      Table EXPLICITE et fermee : trois collecteurs, trois besoins reels. Pas de convention
      implicite entre un nom de cible et un nom de parametre — une convention se lit dans le
      code des deux cotes, et se casse en silence quand l'un des deux bouge.
    #>
    param([string]$Nom, $Cibles)
    $parametres = @{}
    if (-not $Cibles) { return $parametres }

    switch ($Nom) {
        'Collect-PrivilegedGroups.ps1' {
            $g = $Cibles.groupes_privilegies
            if ($g) {
                if ($g.groupe_t0_sid) { $parametres['GroupeT0Sid'] = [string]$g.groupe_t0_sid }
                if ($g.groupe_t0_nom) { $parametres['GroupeT0Nom'] = [string]$g.groupe_t0_nom }
            }
        }
        'Collect-LAPS.ps1' {
            $l = $Cibles.laps
            if ($l -and $l.ous_gerees) { $parametres['ManagedOUs'] = [string[]]$l.ous_gerees }
        }
        'Collect-PasswordPolicy.ps1' {
            $m = $Cibles.mots_de_passe
            if ($m -and $m.pso_tier0) { $parametres['PsoName'] = [string]$m.pso_tier0 }
        }
    }
    return $parametres
}

# ---------------------------------------------------------------- Etat AVANT
$snapshotsBefore = $null
if ($MadscUrl) {
    try {
        $snapshotsBefore = (Invoke-RestMethod -Uri "$($MadscUrl.TrimEnd('/'))/health" -TimeoutSec 10).snapshots
    } catch {
        Write-Host "[!] /health injoignable avant collecte - verification finale impossible" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------- Execution en serie
$started = Get-Date
$ran = @(); $failed = @()

foreach ($name in $Collectors) {
    $path = Join-Path $ScriptDir $name
    if (-not (Test-Path $path)) {
        Write-Host "[X] $name introuvable dans $ScriptDir" -ForegroundColor Red
        $failed += $name
        continue
    }
    Write-Host "--> $name" -ForegroundColor Gray
    try {
        $supplementaires = Get-ArgumentsDeCollecte -Nom $name -Cibles $Cibles
        if ($supplementaires.Count -gt 0) {
            Write-Host "    cibles : $($supplementaires.Keys -join ', ')" -ForegroundColor DarkGray
        }
        if ($PostUrl) { & $path -OutDir $OutDir -PostUrl $PostUrl @supplementaires }
        else          { & $path -OutDir $OutDir @supplementaires }
        $ran += $name
    } catch {
        # Un collecteur qui echoue ne doit pas emporter la campagne : les autres portent des
        # controles differents, et une posture partielle vaut mieux qu'aucune posture.
        Write-Host "[X] $name a echoue : $($_.Exception.Message)" -ForegroundColor Red
        $failed += $name
    }
}

$elapsed = (Get-Date) - $started

# ---------------------------------------------------------------- Bilan
Write-Host ""
Write-Host "=== Bilan ===" -ForegroundColor Cyan
Write-Host "    Executes : $($ran.Count) / $($Collectors.Count)"
Write-Host "    Duree    : $([int]$elapsed.TotalSeconds) s"

if ($failed.Count -gt 0) {
    Write-Host "    ECHECS   : $($failed -join ', ')" -ForegroundColor Red
}

if ($elapsed.TotalMinutes -ge $CampaignWindowMinutes) {
    Write-Host "[!] Collecte etalee sur plus de $CampaignWindowMinutes min : MADSC la comptera comme" -ForegroundColor Yellow
    Write-Host "    PLUSIEURS campagnes partielles, non comparables entre elles dans la tendance." -ForegroundColor Yellow
}

# ---------------------------------------------------------------- Verification
# Un POST peut renvoyer 200 sans que rien ne soit enregistre, et un POST en echec laisse le
# fichier sur CETTE machine - que l'auto-scan de MADSC ne regarde pas. On ne se fie donc pas
# aux codes de retour : on verifie que les snapshots ont bien ATTERRI cote serveur.
$exitCode = if ($failed.Count -gt 0) { 1 } else { 0 }

if ($PostUrl -and $null -ne $snapshotsBefore) {
    try {
        $after   = (Invoke-RestMethod -Uri "$($MadscUrl.TrimEnd('/'))/health" -TimeoutSec 10).snapshots
        $landed  = $after - $snapshotsBefore
        if ($landed -ge $ran.Count) {
            Write-Host "[OK] $landed snapshot(s) enregistre(s) cote MADSC." -ForegroundColor Green
        } else {
            Write-Host "[X] $landed snapshot(s) enregistre(s) cote MADSC pour $($ran.Count) collecteur(s) executes." -ForegroundColor Red
            Write-Host "    Les collectes manquantes ne sont PAS perdues : leurs fichiers sont dans $OutDir." -ForegroundColor Yellow
            Write-Host "    Les deposer dans data\snapshots\ du serveur, ou relancer la campagne." -ForegroundColor Yellow
            $exitCode = 1
        }
    } catch {
        Write-Host "[!] Verification finale impossible ($($_.Exception.Message))" -ForegroundColor Yellow
    }
}

Write-Host ""
exit $exitCode
