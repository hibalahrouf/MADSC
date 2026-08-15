<#
.SYNOPSIS
    Fait CONFIANCE au certificat MADSC sur cette VM, pour que les collecteurs parlent en TLS.

.DESCRIPTION
    Importe madsc.crt dans le magasin des autorites racines de confiance de la MACHINE, afin
    que les collecteurs joignent MADSC en https sans desactiver la moindre verification.

    ---------------- POURQUOI CE CHOIX PLUTOT QU'UN CONTOURNEMENT ----------------
    Windows PowerShell 5.1 — celui des VM du laboratoire — n'a pas de
    `Invoke-RestMethod -SkipCertificateCheck` : ce parametre n'existe qu'a partir de
    PowerShell 6. La seule alternative serait de neutraliser la validation TLS dans les
    collecteurs (`ServerCertificateValidationCallback = { $true }`), ce qui donnerait le
    CHIFFREMENT sans l'AUTHENTIFICATION : n'importe quel hote du segment pourrait se faire
    passer pour MADSC et recolter la cle d'API au premier envoi. Autrement dit, exactement
    l'attaque contre laquelle TLS est mis en place.

    Faire confiance a un certificat precis est plus sur ET plus honnete : la confiance est
    declaree une fois, visible dans le magasin, et revocable.
    ------------------------------------------------------------------------------

    ---------------- NATURE DU CHANGEMENT ----------------
    Ce script MODIFIE le magasin de certificats de la machine. C'est le seul script du projet
    qui ne soit pas en lecture seule, et il ne touche ni l'AD, ni une GPO, ni une ACL.
    Il porte sur UN certificat, identifie par son empreinte, et il est reversible :
        .\Install-MadscCertificate.ps1 -Remove
    Le certificat installe est une feuille (CA:FALSE) : il ne peut signer aucun autre
    certificat. Le faire approuver n'autorise donc que MADSC lui-meme.
    ------------------------------------------------------

.PARAMETER CertPath
    Chemin de madsc.crt (le certificat SEUL ; la cle privee ne quitte jamais le host MADSC).

.PARAMETER Remove
    Retire le certificat MADSC du magasin (rollback) et sort.

.EXAMPLE
    .\Install-MadscCertificate.ps1 -CertPath .\madsc.crt
    .\Install-MadscCertificate.ps1 -Remove
#>
[CmdletBinding()]
param(
    [string]$CertPath = ".\madsc.crt",
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$store = "Cert:\LocalMachine\Root"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "[X] Executer en PowerShell ELEVE (administrateur)." -ForegroundColor Red; exit 1 }

if ($Remove) {
    $found = Get-ChildItem $store | Where-Object { $_.Subject -like "*CN=MADSC*" }
    if (-not $found) { Write-Host "[i] Aucun certificat MADSC dans $store." -ForegroundColor Yellow; return }
    foreach ($c in $found) {
        Remove-Item -Path (Join-Path $store $c.Thumbprint) -Force
        Write-Host "[OK] Retire : $($c.Thumbprint)" -ForegroundColor Green
    }
    Write-Host "[i] Les collecteurs echoueront desormais en https tant que rien n'est reinstalle." -ForegroundColor Yellow
    return
}

if (-not (Test-Path $CertPath)) {
    Write-Host "[X] Certificat introuvable : $CertPath" -ForegroundColor Red
    Write-Host "    Le copier depuis le host MADSC (certs\madsc.crt). NE PAS copier madsc.key." -ForegroundColor Yellow
    exit 1
}

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (Resolve-Path $CertPath)

# Refus net si on presente autre chose qu'un certificat de serveur : importer une AUTORITE
# dans le magasin racine lui permettrait de signer n'importe quel certificat, pour n'importe
# quel site. Ce n'est pas ce qu'on veut approuver ici.
$basic = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
if ($basic -and $basic.CertificateAuthority) {
    Write-Host "[X] Ce certificat est une AUTORITE (CA:TRUE) : import refuse." -ForegroundColor Red
    Write-Host "    Approuver une AC lui permettrait de signer n'importe quel certificat." -ForegroundColor Yellow
    exit 1
}

$existing = Get-ChildItem $store | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if ($existing) {
    Write-Host "[i] Deja approuve (empreinte $($cert.Thumbprint))." -ForegroundColor Yellow
} else {
    Import-Certificate -FilePath (Resolve-Path $CertPath) -CertStoreLocation $store | Out-Null
    Write-Host "[OK] Certificat MADSC approuve sur cette machine." -ForegroundColor Green
}

Write-Host "     Sujet     : $($cert.Subject)"
Write-Host "     Empreinte : $($cert.Thumbprint)"
Write-Host "     Expire le : $($cert.NotAfter)"
Write-Host "     Rollback  : .\Install-MadscCertificate.ps1 -Remove" -ForegroundColor Cyan
Write-Host ""
Write-Host "Verifier depuis cette VM :" -ForegroundColor Cyan
Write-Host "  Invoke-RestMethod https://192.168.10.1:8700/health"
Write-Host "  (doit repondre sans erreur TLS, avec scheme = https)"
