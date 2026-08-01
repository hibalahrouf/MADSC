<#
.SYNOPSIS
    Enregistre (ou retire) le collecteur MADSC en TACHE PLANIFIEE Windows - collecte automatique.

.DESCRIPTION
    Cree une tache planifiee qui execute periodiquement un collecteur MADSC (LECTURE SEULE),
    de sorte que l'administrateur n'ait RIEN a lancer a la main. La tache s'execute en compte
    SYSTEM (acces lecture au registre HKLM) et depose un snapshot JSON dans -OutDir.

    ---------------- IMPORTANT - nature du changement ----------------
    - Le CODE execute par la tache est 100 % LECTURE (Get-*, lecture registre). Aucun
      ecrit dans l'Active Directory.
    - Le SEUL changement local est la CREATION d'une tache planifiee sur cet hote.
      C'est benin et ENTIEREMENT REVERSIBLE :  .\Register-MadscCollector.ps1 -Remove
      (ou via le Planificateur de taches). Ce script ne modifie ni GPO, ni AD.
    ------------------------------------------------------------------

.PARAMETER OutDir
    Dossier ou deposer les snapshots. En exploitation, pointer vers un partage que le host
    MADSC surveille (ex. \\HOST-MADSC\snapshots) pour une chaine 100 % automatique.

.PARAMETER IntervalHours
    Frequence de collecte en heures (defaut 12).

.PARAMETER CollectorPath
    Chemin du collecteur (defaut : Collect-Protocols.ps1 a cote de ce script).

.PARAMETER TaskName
    Nom de la tache (defaut : MADSC-Collect-Protocols).

.PARAMETER Remove
    Supprime la tache planifiee (rollback) et sort.

.EXAMPLE
    # Enregistrer : collecte toutes les 12 h, depot dans C:\MADSC-out
    .\Register-MadscCollector.ps1 -OutDir C:\MADSC-out -IntervalHours 12

.EXAMPLE
    # Retirer (rollback complet)
    .\Register-MadscCollector.ps1 -Remove
#>
[CmdletBinding()]
param(
    [string]$OutDir = "C:\MADSC-out",
    [int]$IntervalHours = 12,
    [string]$CollectorPath = "",
    [string]$TaskName = "MADSC-Collect-Protocols",
    [string]$PostUrl,   # ex. http://192.168.10.1:8700/ingest -> envoi direct a MADSC (sans partage)
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

if (-not $CollectorPath) {
    if ($PSScriptRoot) {
        $CollectorPath = Join-Path $PSScriptRoot 'Collect-Protocols.ps1'
    } else {
        $CollectorPath = '.\Collect-Protocols.ps1'
    }
}

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

# Declencheur : premiere execution dans 2 min, puis repetition toutes les N heures, indefiniment
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Hours $IntervalHours)

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description "MADSC - collecte de posture AD (LECTURE SEULE)" -Force | Out-Null

Write-Host "[OK] Tache planifiee '$TaskName' enregistree." -ForegroundColor Green
Write-Host "     Collecteur : $CollectorPath"
Write-Host "     Sortie     : $OutDir"
Write-Host "     Frequence  : toutes les $IntervalHours h (compte SYSTEM, lecture seule)"
Write-Host "     Rollback   : .\Register-MadscCollector.ps1 -Remove" -ForegroundColor Cyan

# Premiere collecte immediate (produit un premier snapshot tout de suite)
Start-ScheduledTask -TaskName $TaskName
Write-Host "[i] Premiere collecte lancee. Verifie $OutDir dans quelques secondes." -ForegroundColor Cyan
