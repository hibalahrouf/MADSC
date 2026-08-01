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

# `auditpol /get /category:*` EXIGE l'elevation : sans elle il renvoie « A required privilege
# is not held by the client » et AUCUNE ligne CSV exploitable.
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[MADSC] ATTENTION : PowerShell NON ELEVE -> auditpol va echouer." -ForegroundColor Red
    Write-Host "        Relancer dans une console 'Executer en tant qu'administrateur'." -ForegroundColor Red
}

# Format de `auditpol /r` : ...,Subcategory,Subcategory GUID,Inclusion,Exclusion,Setting Value
# On ne code EN DUR AUCUN indice de colonne : on localise le GUID (la sous-categorie est juste
# avant) et on prend comme valeur le dernier champ numerique de la ligne. C'est insensible a la
# langue, au nombre de colonnes et aux virgules dans les libelles.
# La valeur est numerique : 0=aucun audit, 1=succes, 2=echec, 3=succes+echec. Filtrer sur le
# libelle localise etait fragile (langue, apostrophe typographique, encodage) et laissait passer
# TOUTES les sous-categories, en-tete comprise.
$SETTING_LABEL = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
$GUID_RE       = '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$'

try {
    $lines = @(auditpol.exe /get /category:* /r 2>&1)   # LECTURE SEULE

    $audited = @()
    $parsed  = 0
    foreach ($line in $lines) {
        if (-not $line) { continue }
        $parts = [string]$line -split ','
        if ($parts.Count -lt 4) { continue }

        # Colonne GUID -> ancre de la ligne (absente sur l'en-tete, qui est donc ignoree).
        $guidIdx = -1
        for ($i = 0; $i -lt $parts.Count; $i++) {
            if ($parts[$i].Trim() -match $GUID_RE) { $guidIdx = $i; break }
        }
        if ($guidIdx -lt 1) { continue }

        # Valeur = dernier champ numerique de la ligne (apres le GUID).
        $value = $null
        for ($i = $parts.Count - 1; $i -gt $guidIdx; $i--) {
            $n = 0
            if ([int]::TryParse($parts[$i].Trim(), [ref]$n)) { $value = $n; break }
        }
        if ($null -eq $value) { continue }
        $parsed++

        if ($value -le 0) { continue }   # 0 = aucun audit -> hors perimetre audite
        $audited += ("{0}={1}" -f $parts[$guidIdx - 1].Trim(), $SETTING_LABEL[$value])
    }

    if ($parsed -eq 0) {
        # Collecte en echec : on n'emet AUCUN controle. Emettre 0/0 reviendrait a presenter
        # une mesure inexistante comme un resultat -> le contrôle doit rester NON COLLECTE.
        Write-Host "[MADSC] AUDIT-ADVANCED-POLICY : aucune ligne exploitable -> controle NON emis." -ForegroundColor Red
        Write-Host "        Sortie brute d'auditpol (1re ligne) : $($lines | Select-Object -First 1)" -ForegroundColor Yellow
        if (-not $isAdmin) { Write-Host "        Cause probable : console non elevee." -ForegroundColor Yellow }
    } else {
        $sorted = @($audited | Sort-Object)
        $controls += [pscustomobject]@{
            control_id = 'AUDIT-ADVANCED-POLICY'
            observed   = @{
                subcategories_audited = $sorted.Count
                subcategories_total   = $parsed
                active_policy         = ($sorted -join '; ')
            }
            raw        = 'auditpol.exe /get /category:* /r (valeur numerique Setting Value)'
        }
        Write-Host "[MADSC] Audit : $($sorted.Count) sous-categorie(s) auditee(s) sur $parsed" -ForegroundColor Cyan
    }
} catch {
    Write-Host "[MADSC] AUDIT-ADVANCED-POLICY : erreur de lecture auditpol -> $($_.Exception.Message)" -ForegroundColor Yellow
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
