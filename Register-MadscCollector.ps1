<#
.SYNOPSIS
    Enregistre (ou retire) le collecteur MADSC en TÂCHE PLANIFIÉE Windows — collecte automatique.

.DESCRIPTION
    Crée une tâche planifiée qui exécute périodiquement un collecteur MADSC (LECTURE SEULE),
    de sorte que l'administrateur n'ait RIEN à lancer à la main. La tâche s'exécute en compte
    SYSTEM (accès lecture au registre HKLM) et dépose un snapshot JSON dans -OutDir.

    ┌─ IMPORTANT — nature du changement ────────────────────────────────────────────────┐
    │ • Le CODE exécuté par la tâche est 100 % LECTURE (Get-*, lecture registre). Aucun   │
    │   écrit dans l'Active Directory.                                                    │
    │ • Le SEUL changement local est la CRÉATION d'une tâche planifiée sur cet hôte.      │
    │   C'est bénin et ENTIÈREMENT RÉVERSIBLE :  .\Register-MadscCollector.ps1 -Remove    │
    │   (ou via le Planificateur de tâches). Ce script ne modifie ni GPO, ni AD.          │
    └────────────────────────────────────────────────────────────────────────────────────┘

.PARAMETER OutDir
    Dossier où déposer les snapshots. En exploitation, pointer vers un partage que le host
    MADSC surveille (ex. \\HOST-MADSC\snapshots) pour une chaîne 100 % automatique.

.PARAMETER IntervalHours
    Fréquence de collecte en heures (défaut 12).

.PARAMETER CollectorPath
    Chemin du collecteur (défaut : Collect-Protocols.ps1 à côté de ce script).

.PARAMETER TaskName
    Nom de la tâche (défaut : MADSC-Collect-Protocols).

.PARAMETER Remove
    Supprime la tâche planifiée (rollback) et sort.

.EXAMPLE
    # Enregistrer : collecte toutes les 12 h, dépôt dans C:\MADSC-out
    .\Register-MadscCollector.ps1 -OutDir C:\MADSC-out -IntervalHours 12

.EXAMPLE
    # Retirer (rollback complet)
    .\Register-MadscCollector.ps1 -Remove
#>
[CmdletBinding()]
param(
    [string]$OutDir = "C:\MADSC-out",
    [int]$IntervalHours = 12,
    [string]$CollectorPath = (Join-Path $PSScriptRoot 'Collect-Protocols.ps1'),
    [string]$TaskName = "MADSC-Collect-Protocols",
    [string]$PostUrl,   # ex. http://192.168.10.1:8700/ingest -> envoi direct a MADSC (sans partage)
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

# Élévation requise (Register/Unregister-ScheduledTask)
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "[X] Executer en PowerShell ELEVE (administrateur)." -ForegroundColor Red; exit 1 }

if ($Remove) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[OK] Tache '$TaskName' supprimee (rollback)." -ForegroundColor Green
    } else {
        Write-Host "[i] Aucune tache '$TaskName' a supprimer." -ForegroundColor Yellow
    }
    return
}

if (-not (Test-Path $CollectorPath)) { Write-Host "[X] Collecteur introuvable : $CollectorPath" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

$argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$CollectorPath`" -OutDir `"$OutDir`""
if ($PostUrl) { $argLine += " -PostUrl `"$PostUrl`"" }   # envoi direct a MADSC (sans partage)
$action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argLine

# Déclencheur : première exécution dans 2 min, puis répétition toutes les N heures, indéfiniment
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2)
$trigger.Repetition.Interval = "PT${IntervalHours}H"
$trigger.Repetition.Duration = ""     # vide = indéfiniment

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description "MADSC — collecte de posture AD (LECTURE SEULE)" -Force | Out-Null

Write-Host "[OK] Tache planifiee '$TaskName' enregistree." -ForegroundColor Green
Write-Host "     Collecteur : $CollectorPath"
Write-Host "     Sortie     : $OutDir"
Write-Host "     Frequence  : toutes les $IntervalHours h (compte SYSTEM, lecture seule)"
Write-Host "     Rollback   : .\Register-MadscCollector.ps1 -Remove" -ForegroundColor Cyan

# Premiere collecte immediate (produit un premier snapshot tout de suite)
Start-ScheduledTask -TaskName $TaskName
Write-Host "[i] Premiere collecte lancee. Verifie $OutDir dans quelques secondes." -ForegroundColor Cyan
