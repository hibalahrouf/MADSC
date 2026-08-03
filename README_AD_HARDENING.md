# Durcissement Active Directory — Projet PFA Mogador

**Domaine :** `mogador.local`  
**Périmètre :** architecture AD, contrôle des privilèges, durcissement des protocoles, journalisation et validation des chemins d’attaque  
**État du document :** synthèse technique consolidée au 28 juillet 2026  
**Source de vérité associée :** `PROJECT_CONTEXT.md`

> Ce document décrit l’implémentation réellement validée dans le laboratoire. Il ne constitue ni une certification ISO/IEC 27001, ni une architecture de production complète.

## 1. Règles de lecture

### Niveaux de confiance

- **Élevé :** contrôle directement confirmé par une sortie, un rapport GPO, un événement, un test fonctionnel ou un outil d’audit.
- **Moyen :** information cohérente avec plusieurs éléments, mais dont la preuve brute complète n’est pas conservée ici.
- **Faible :** hypothèse nécessitant une nouvelle vérification. Aucun contrôle final n’est présenté comme acquis avec ce niveau.

### Séparation des informations

- **Faits du laboratoire :** état réellement observé et validé.
- **Décisions d’architecture :** choix retenus pour le PFA.
- **Limites :** éléments acceptables dans un laboratoire mais insuffisants en production.
- **Travaux futurs :** détection, SIEM et scénarios de validation encore à réaliser.

## 2. Objectif du projet

Le projet vise à transformer un domaine Active Directory volontairement faible en une architecture administrativement cloisonnée, mesurable et défendable.

La démarche ne consiste pas seulement à « appliquer des GPO ». Elle cherche à démontrer :

1. l’existence initiale d’un risque ou d’un chemin d’attaque ;
2. la mise en œuvre d’un traitement technique précis ;
3. l’application effective du contrôle ;
4. l’absence de rupture des fonctions légitimes ;
5. la réduction mesurable du risque ;
6. la conservation des limites et risques résiduels.

### Périmètre actuel

- Active Directory et DNS intégrés à AD ;
- architecture Tier 0 / Tier 1 / Tier 2 ;
- séparation des comptes administratifs ;
- RBAC et AGDLP ;
- groupes privilégiés et ACL AD ;
- stratégies de mots de passe et FGPP ;
- LAPS Legacy ;
- SMB, LDAP, NTLM, LLMNR et synchronisation horaire ;
- mise à jour et réduction de surface du contrôleur de domaine ;
- Advanced Audit Policy et journalisation PowerShell ;
- analyse PingCastle et BloodHound ;
- alignement avec une démarche de traitement des risques ISO/IEC 27001.

### Hors périmètre

- test d’intrusion de l’application PMS ;
- audit de code ou test web du PMS ;
- certification ISO/IEC 27001 ;
- déploiement complet d’un SOC de production ;
- haute disponibilité AD ;
- PKI/AD CS, MFA, PAW et Microsoft Defender for Identity.

`PMS-01` est uniquement traité comme un serveur membre Tier 1.

## 3. Architecture du laboratoire

### 3.1 Topologie

| Système | Rôle | Tier | Adresse principale | Système |
|---|---|---:|---|---|
| `DC-01` | Contrôleur de domaine, DNS, catalogue global, rôles FSMO | 0 | `192.168.10.10` | Windows Server 2016 |
| `PMS-01` | Serveur membre métier vide | 1 | `192.168.10.21` | Windows Server 2016 |
| `DESKTOP-0LKLBTR` / `WS-01` | Poste utilisateur et administration Tier 2 | 2 | `192.168.10.20` | Windows 10 |
| `KALI-01` | Analyse offensive, BloodHound et tests contrôlés | Hors domaine | `192.168.10.40` | Kali Linux |

Le réseau AD actif est `192.168.10.0/24`. Le laboratoire est hébergé sous VMware Workstation. GNS3 et un routeur Cisco ont été utilisés pour la topologie et l’apprentissage réseau.

### 3.2 Particularité multihoming de `DC-01`

`DC-01` possède aussi une interface NAT `192.168.43.222` nécessaire à l’accès Internet du laboratoire.

Traitement appliqué :

- conservation de l’interface NAT ;
- désactivation de son enregistrement DNS ;
- suppression de l’ancien enregistrement A `192.168.43.222` ;
- conservation du seul enregistrement AD utile `DC-01.mogador.local -> 192.168.10.10` ;
- création du subnet AD `192.168.10.0/24` dans `Default-First-Site-Name`.

Le service DNS écoute encore sur plusieurs interfaces. Cette situation est acceptée comme contrainte de laboratoire, mais n’est pas recommandée pour un DC de production.

## 4. Architecture logique Active Directory

### 4.1 Modèle d’OU

```text
DC=mogador,DC=local
├── OU=Domain Controllers
│   └── DC-01
├── OU=Tier0
│   ├── OU=Users_T0
│   ├── OU=Groups_T0
│   └── OU=Computers_T0
├── OU=Tier1
│   ├── OU=Users_T1
│   ├── OU=Groups_T1
│   └── OU=Computers_T1
└── OU=Tier2
    ├── OU=Users_T2
    ├── OU=Groups_T2
    └── OU=Computers_T2
```

Le compte ordinateur du DC a été replacé dans l’OU intégrée `Domain Controllers`. Cette OU est la portée correcte des stratégies spécifiques aux contrôleurs de domaine.

Les anciennes OU départementales vides `Direction`, `RH` et `HouseKeeping` ont été retirées après vérification :

- aucun utilisateur, ordinateur, groupe ou sous-OU ;
- aucun lien GPO ;
- aucune délégation personnalisée utile ;
- sauvegarde des métadonnées et ACL avant suppression.

Toutes les OU restantes sont protégées contre la suppression accidentelle.

### 4.2 Deux dimensions indépendantes

Le modèle distingue :

1. **le niveau de confiance administratif**, représenté par Tier 0, Tier 1 et Tier 2 ;
2. **le rôle métier**, représenté par des groupes départementaux.

Un groupe métier ne confère aucun droit administratif. Cette séparation évite qu’une réorganisation fonctionnelle modifie implicitement les privilèges techniques.

## 5. Modèle administratif et RBAC

### 5.1 Comptes

| Identité | Fonction | Niveau | État |
|---|---|---:|---|
| `Administrateur` | compte intégré de secours / break-glass | 0 | Activé, exception documentée |
| `adm_t0_oussama` | administration AD et DC | 0 | Actif |
| `adm_t1_oussama` | administration des serveurs membres | 1 | Actif |
| `adm_t2_oussama` | administration des postes | 2 | Actif |
| comptes métier | usage quotidien | 2 | Actifs selon besoin |
| `svc-plurihotel` | ancien compte de service | 1 | Désactivé |

Les comptes d’administration sont séparés des usages quotidiens. Les comptes privilégiés `Administrateur`, `adm_t0_oussama`, `adm_t1_oussama` et `adm_t2_oussama` ont l’attribut **Account is sensitive and cannot be delegated**.

### 5.2 Groupes privilégiés intégrés

État final :

- `Admins du domaine` contient directement `Administrateur` et le groupe `GG_T0_Admins` ;
- `adm_t0_oussama` obtient son privilège via `GG_T0_Admins`, et non par adhésion directe ;
- `Administrateurs du schéma` est vide ;
- `Administrateurs de l’entreprise` est vide ;
- les groupes opérateurs examinés sont vides ;
- `svc-plurihotel` a été retiré de `Opérateurs de serveur`.

Le compte `Administrateur` est conservé comme compte de secours. Il ne doit pas être utilisé pour l’administration quotidienne.

### 5.3 AGDLP sélectif

Le modèle retenu est :

```text
Accounts -> Global role group -> Domain Local resource group -> Permission
```

Chemins d’administration :

```text
adm_t1_oussama
  -> GG_T1_Server_Admins
  -> DL_PMS01_LocalAdmins
  -> Administrateurs local de PMS-01

adm_t2_oussama
  -> GG_T2_WS_Admins
  -> DL_WS01_LocalAdmins
  -> Administrateurs local de WS-01
```

Les groupes globaux représentent les rôles. Les groupes Domain Local représentent l’autorisation sur une ressource précise.

Les User Rights Assignments utilisent directement les groupes globaux de Tier. Ajouter une couche Domain Local aux droits de connexion n’apporterait pas de séparation de ressource utile et compliquerait l’audit.

## 6. Méthodologie de durcissement

### 6.1 Cycle utilisé

```text
Baseline
  -> analyse du risque
  -> sauvegarde et rollback
  -> création du contrôle avec lien désactivé
  -> revue du rapport GPO
  -> déploiement pilote
  -> validation technique
  -> validation fonctionnelle
  -> déploiement élargi
  -> comparaison avant/après
  -> risque résiduel
```

### 6.2 Ordre de déploiement

Pour les politiques susceptibles de casser l’authentification ou les communications :

1. `WS-01` ;
2. `PMS-01` ;
3. `DC-01`.

Cette séquence a été utilisée pour SMB signing, NTLMv2, LLMNR et les contrôles de journalisation.

### 6.3 Porte de validation

Un contrôle n’est considéré comme terminé qu’après collecte de plusieurs preuves :

- `hostname` pour confirmer la machine ;
- `whoami` et `whoami /groups` pour confirmer le jeton ;
- `gpresult /scope computer /r` ou rapport HTML RSOP ;
- lecture du registre ou de la configuration effective ;
- test positif du fonctionnement légitime ;
- test négatif du comportement interdit ;
- événement Windows lorsque pertinent ;
- sauvegarde avant changement ;
- capture d’écran exploitable dans le rapport.

### 6.4 Principes de sécurité appliqués

- moindre privilège ;
- séparation des tâches ;
- administration par groupe et non par utilisateur ;
- portée minimale des GPO ;
- défense en profondeur ;
- réduction des protocoles hérités ;
- compatibilité testée avant enforcement ;
- changements réversibles ;
- mesure avant/après ;
- acceptation explicite des risques résiduels.

## 7. Inventaire consolidé des GPO

### 7.1 GPO actives

| GPO | Portée | Configuration principale | Validation |
|---|---|---|---|
| `Default Domain Policy` | Domaine | politique de mot de passe et verrouillage du domaine | `Get-ADDefaultDomainPasswordPolicy` |
| `Default Domain Controllers Policy` | `Domain Controllers` | paramètres DC par défaut, sans duplication LDAP finale | RSOP et rapport GPO |
| `GPO_T1_PMS01_LocalAdmins` | `Computers_T1` | ajoute `DL_PMS01_LocalAdmins` au groupe local Administrateurs | groupe local + jeton `adm_t1` |
| `GPO_T2_WS01_LocalAdmins` | `Computers_T2` | ajoute `DL_WS01_LocalAdmins` au groupe local Administrateurs | groupe local + jeton `adm_t2` |
| `GPO_T1_Deny_T0_Logon` | `Computers_T1` | interdit cinq types de connexion aux identités Tier 0 | secedit + test négatif |
| `GPO_T2_Deny_T0_T1_Logon` | `Computers_T2` | interdit cinq types de connexion aux identités Tier 0 et Tier 1 | secedit + événement 4625 |
| `GPO_LegacyLAPS_ManagedComputers` | `Computers_T1`, `Computers_T2` | mot de passe local aléatoire, longueur 20, âge 30 jours, complexité 4 | attributs LAPS + tests ACL |
| `GPO_DC_Disable_PrintSpooler` | `Domain Controllers` | service Spooler désactivé | `Stopped/Disabled` |
| `GPO_SMB_Signing_Required` | DC, Tier 1, Tier 2 | signature SMB obligatoire client et serveur | SMB 3.1.1 `Signed=True` |
| `GPO_DC_LDAP_Signing_Required` | `Domain Controllers` | signature LDAP exigée, `LDAPServerIntegrity=2` | simple bind non signé rejeté |
| `GPO_DC_NTLM_Audit` | `Domain Controllers` | audit NTLM domaine, entrant et sortant | événements NTLM 8002 |
| `GPO_Member_NTLM_Audit` | `Computers_T1`, `Computers_T2` | audit NTLM entrant et sortant | événement NTLM 8001 |
| `GPO_Authentication_NTLMv2_Only` | DC, Tier 1, Tier 2 | `LmCompatibilityLevel=5`, `NoLMHash=1` | événement 4624 NTLM V2 |
| `GPO_Member_Time_DomainHierarchy` | `Computers_T1`, `Computers_T2` | `Type=NT5DS` | source `DC-01.mogador.local` |
| `GPO_Disable_LLMNR` | DC, Tier 1, Tier 2 | `EnableMulticast=0` | aucun listener UDP/5355 |
| `GPO_DC_Advanced_Audit` | `Domain Controllers` | audit avancé DC, Security log 512 MB, ligne de commande | `auditpol`, 4688, RSOP |
| `GPO_Member_Advanced_Audit` | `Computers_T1`, `Computers_T2` | audit avancé membres, Security log 256 MB, ligne de commande | `auditpol`, 4688, RSOP |
| `GPO_PowerShell_Logging` | DC, Tier 1, Tier 2 | Script Block Logging et Module Logging `*` | événements 4103 et 4104 |

### 7.2 GPO retirées ou désactivées

| GPO | Décision | Motif |
|---|---|---|
| `T1_AddAdmin_PMS` | lien désactivé | Restricted Groups ajoutait directement `adm_t1_oussama` et contournait AGDLP |
| `T0_RestrictLogon` | liens désactivés | ancienne stratégie remplacée par deux GPO explicites Tier 1 et Tier 2 |
| `T0_LAPS_Config` | lien désactivé / stratégie retirée | LAPS ne doit pas gérer le DC ; configuration initiale incorrectement liée à Tier 0 |
| `T0_PasswordPolicy` | lien désactivé après sauvegarde | une GPO liée à une OU ne crée pas une politique de mot de passe distincte pour les comptes du domaine |

## 8. Détail des contrôles GPO

### 8.1 Administration locale Tier 1

`GPO_T1_PMS01_LocalAdmins` utilise Group Policy Preferences :

- groupe cible : groupe local intégré `Administrateurs`, identifié et vérifié sur l’OS français ;
- action : `Update` ;
- membre ajouté : `MOGADOR\DL_PMS01_LocalAdmins` ;
- suppression globale des utilisateurs : désactivée ;
- suppression globale des groupes : désactivée.

État final sur `PMS-01` :

```text
PMS-01\Administrateur
MOGADOR\Admins du domaine
MOGADOR\DL_PMS01_LocalAdmins
```

La présence de `Admins du domaine` est un accès Tier 0 implicite aux serveurs membres. Dans ce PFA, sa connexion effective sur Tier 1 est bloquée par User Rights Assignment. En production, l’administration de secours et les droits locaux des Domain Admins doivent être traités dans une architecture de niveau entreprise.

### 8.2 Administration locale Tier 2

État final sur `WS-01` :

```text
DESKTOP-0LKLBTR\Administrateur
MOGADOR\DL_WS01_LocalAdmins
```

Ont été retirés :

- `MOGADOR\adm_t1_oussama` ;
- `MOGADOR\Admins du domaine` ;
- le compte local `Win 10`.

Le compte local `Win 10` a été désactivé. Ses tâches OneDrive ont également été désactivées. Son profil a été conservé pour éviter une suppression destructive non nécessaire.

### 8.3 Cloisonnement de connexion

`GPO_T1_Deny_T0_Logon` refuse aux groupes Tier 0 :

- `SeDenyNetworkLogonRight` ;
- `SeDenyInteractiveLogonRight` ;
- `SeDenyRemoteInteractiveLogonRight` ;
- `SeDenyBatchLogonRight` ;
- `SeDenyServiceLogonRight`.

Principaux SID appliqués :

- Domain Admins : RID `-512` ;
- `GG_T0_Admins` : SID finissant par `-1118`.

`GPO_T2_Deny_T0_T1_Logon` applique les mêmes cinq interdictions à :

- Domain Admins ;
- `GG_T0_Admins` ;
- `GG_T1_Server_Admins` ;
- `GG_T1_SvcAccounts`.

Test négatif réalisé :

- tentative de connexion de `adm_t1_oussama` sur `WS-01` ;
- message : méthode d’ouverture de session non autorisée ;
- événement Security `4625` ;
- statut `0xC000015B` ;
- type de connexion `7`.

Tests positifs :

- `adm_t1_oussama` conserve l’administration sur `PMS-01` ;
- `adm_t2_oussama` conserve l’administration sur `WS-01`.

### 8.4 LAPS Legacy

Configuration :

```text
AdmPwdEnabled     = 1
PasswordComplexity = 4
PasswordLength     = 20
PasswordAgeDays    = 30
```

Portée :

- `Computers_T1` ;
- `Computers_T2` ;
- exclusion volontaire de `DC-01`.

Groupes de lecture et réinitialisation :

- `DL_LAPS_T1_Operators` contient le rôle Tier 1 ;
- `DL_LAPS_T2_Operators` contient le rôle Tier 2.

Validations :

- les mots de passe LAPS sont générés sur `PMS-01` et `WS-01` ;
- `adm_t1_oussama` lit le secret Tier 1 mais pas celui de Tier 2 ;
- `adm_t2_oussama` lit le secret Tier 2 ;
- les anciennes ACE LAPS erronées sur `Computers_T0` ont été retirées ;
- les SDDL avant/après ont été conservés.

### 8.5 SMB

Mesures :

- mise à jour complète du DC avant suppression ;
- audit de compatibilité SMBv1 ;
- désactivation du runtime SMBv1 ;
- suppression de la fonctionnalité `FS-SMB1` ;
- signature SMB obligatoire.

Résultats :

- SMBv1 absent ;
- SMB2/3 actif ;
- accès à `SYSVOL` et `NETLOGON` fonctionnel ;
- dialecte négocié `3.1.1` ;
- `Signed=True` sur les connexions testées ;
- services AD et diagnostic MachineAccount fonctionnels.

### 8.6 LDAP signing

Déploiement :

- activation temporaire du diagnostic LDAP ;
- création d’un compte de test à faible privilège ;
- preuve qu’un simple bind LDAP non signé était initialement accepté ;
- création de `GPO_DC_LDAP_Signing_Required` ;
- détection d’un conflit dans `Default Domain Controllers Policy` ;
- priorité donnée à la GPO dédiée ;
- suppression du paramètre dupliqué après sauvegarde.

État final :

```text
LDAPServerIntegrity = 2
```

Le bind LDAP simple en clair est rejeté avec une erreur d’authentification forte requise. La découverte du domaine et les secure channels de `PMS-01` et `WS-01` restent fonctionnels.

Le channel binding LDAP n’est pas encore enforced.

### 8.7 NTLM

La méthode a séparé observation et enforcement.

Phase d’audit :

- audit NTLM sortant sur les membres ;
- audit NTLM entrant sur le DC ;
- connexion SMB par adresse IP pour provoquer un fallback NTLM contrôlé ;
- événement `8001` côté client ;
- événement `8002` côté DC.

Phase d’enforcement :

```text
LmCompatibilityLevel = 5
NoLMHash              = 1
```

Conséquences :

- LM refusé ;
- NTLMv1 refusé ;
- NTLMv2 encore autorisé pour compatibilité.

Un événement Security `4624`, type `3`, a confirmé :

```text
AuthenticationPackage = NTLM
LmPackageName         = NTLM V2
```

Le projet ne prétend donc pas avoir supprimé NTLM.

### 8.8 LLMNR

Configuration :

```text
HKLM\Software\Policies\Microsoft\Windows NT\DNSClient
EnableMulticast = 0
```

Validations :

- registre effectif à `0` ;
- aucun listener UDP `5355` ;
- résolution DNS du domaine fonctionnelle ;
- secure channels membres fonctionnels ;
- diagnostic DC fonctionnel.

### 8.9 Temps du domaine

Sur les membres :

```text
Type = NT5DS
Source = DC-01.mogador.local
```

Le PDC Emulator `DC-01` utilise `time.windows.com`.

Cette architecture est correcte pour le laboratoire. En production, le PDC devrait utiliser plusieurs sources NTP approuvées et supervisées.

### 8.10 Advanced Audit Policy

Paramètres communs :

```text
SCENoApplyLegacyAuditPolicy = 1
ProcessCreationIncludeCmdLine_Enabled = 1
Retention = overwrite as needed
AutoBackupLogFiles = 0
```

Capacité :

- DC : Security log `512 MB` ;
- Tier 1 et Tier 2 : Security log `256 MB`.

Catégories DC implémentées :

- Account Logon ;
- Logon/Logoff ;
- Kerberos Authentication Service ;
- Kerberos Service Ticket Operations ;
- Credential Validation ;
- Sensitive Privilege Use ;
- Process Creation ;
- Audit Policy Change ;
- Authentication Policy Change ;
- User Account Management ;
- Security Group Management ;
- Computer Account Management ;
- Directory Service Access ;
- Directory Service Changes ;
- DPAPI Activity, succès ;
- Security System Extension, succès.

Les catégories très bruyantes suivantes n’ont pas été activées globalement :

- File System ;
- Registry ;
- Filtering Platform ;
- Handle Manipulation ;
- Detailed Directory Service Replication.

Ce choix évite de saturer un petit laboratoire sans SIEM encore opérationnel.

### 8.11 Journalisation PowerShell

Configuration :

```text
EnableScriptBlockLogging = 1
EnableModuleLogging      = 1
ModuleNames              = *
```

Validations sur `DC-01`, `PMS-01` et `WS-01` :

- événement `4104` généré ;
- événement `4103` généré ;
- GPO présente dans le RSOP ;
- journaux PowerShell activés.

La transcription et l’invocation logging restent volontairement désactivés. La transcription peut exposer des données sensibles et impose une stratégie de stockage et d’accès qui n’est pas encore définie.

## 9. Contrôles non-GPO

### 9.1 MachineAccountQuota

Valeur initiale :

```text
ms-DS-MachineAccountQuota = 10
```

Valeur finale :

```text
ms-DS-MachineAccountQuota = 0
```

Le changement empêche un utilisateur standard de joindre arbitrairement de nouveaux ordinateurs au domaine via le quota par défaut.

### 9.2 AD Recycle Bin

La corbeille Active Directory est activée. Elle améliore la récupération logique d’objets supprimés, mais ne remplace pas une sauvegarde système fiable.

### 9.3 Délégation Kerberos

Les audits ont confirmé :

- aucune délégation non contrainte sur les serveurs membres ou postes ;
- aucune délégation contrainte configurée ;
- aucune RBCD configurée ;
- aucun compte utilisateur délégué ;
- le statut attendu du DC n’a pas été interprété comme une faiblesse de serveur membre.

### 9.4 ACL Tier 0

Les ACL des OU suivantes ont été sauvegardées et nettoyées :

- `Tier0` ;
- `Users_T0` ;
- `Groups_T0` ;
- `Computers_T0`.

Les ACE explicites des groupes intégrés `Account Operators` et `Print Operators` ont été retirées de ces OU après validation de leur absence de membres.

Les ACL LAPS erronées sur `Computers_T0` ont également été retirées :

- ACE utilisateur `Administrateur` ;
- ACE `SELF` liées aux attributs Legacy LAPS ;
- attribut d’expiration LAPS résiduel sur `DC-01`.

Les propriétaires restent `MOGADOR\Admins du domaine`. Les SDDL avant/après sont conservés sous `C:\Evidence\ACL-Backups`.

### 9.5 AdminSDHolder et adminCount

`Hibalahrouf` et `adm_t1_oussama` avaient conservé :

- `adminCount=1` ;
- héritage ACL désactivé ;
- propriétaire Domain Admins ;
- ACL héritée d’un ancien statut privilégié.

Après vérification qu’ils n’appartenaient plus à un groupe protégé :

- export complet des objets ;
- sauvegarde SDDL ;
- suppression de `adminCount` ;
- réactivation de l’héritage ;
- revue des ACE explicites restantes ;
- test positif de l’administration Tier 1.

Aucun trustee personnalisé ou SID non résolu n’a été trouvé dans les ACE restantes.

### 9.6 Compte `svc-plurihotel`

État initial :

- compte activé ;
- mot de passe non expirant ;
- membre de `Server Operators` ;
- SPN `MSSQLSvc/PMS-01.mogador.local:1433` ;
- chemin Kerberoasting ;
- connexions interactives historiques ;
- tâche Google Updater exécutée sous ce compte.

État final actuel :

- retiré de `Server Operators` ;
- retiré de `GG_T1_SvcAccounts` ;
- SPN supprimé ;
- tâche désactivée et exportée ;
- compte désactivé ;
- données de rollback conservées.

Le serveur étant vide, le compte n’est pas nécessaire actuellement. Toute réactivation future exige une nouvelle analyse du service, des SPN, des droits de connexion et, idéalement, une migration vers gMSA si compatible.

### 9.7 Mise à jour de `DC-01`

État final validé :

```text
Windows Server 2016
Build 14393.9339
KB5099542
KB5099535
```

Après redémarrage :

- aucun reboot CBS en attente ;
- aucun reboot Windows Update en attente ;
- aucune opération de renommage de fichier en attente ;
- `NTDS`, `DNS`, `Netlogon` et `KDC` actifs ;
- test MachineAccount réussi.

### 9.8 Print Spooler

Avant désactivation :

- aucune imprimante physique partagée ;
- seulement Microsoft Print to PDF et XPS ;
- aucun job ;
- aucun partage d’impression.

Le Spooler est maintenant `Stopped` et `Disabled` sur `DC-01`.

## 10. Politique de mots de passe

### 10.1 Politique par défaut du domaine

| Paramètre | Valeur finale |
|---|---:|
| Complexité | Activée |
| Longueur minimale | 14 |
| Historique | 24 |
| Âge minimal | 1 jour |
| Âge maximal | 90 jours |
| Seuil de verrouillage | 10 |
| Fenêtre d’observation | 15 minutes |
| Durée de verrouillage | 15 minutes |
| Chiffrement réversible | Désactivé |

Les comptes métier actifs ont eu `PasswordNeverExpires` désactivé.

### 10.2 FGPP Tier 0

`PSO_T0_Privileged_Admins` :

| Paramètre | Valeur |
|---|---:|
| Precedence | 10 |
| Complexité | Activée |
| Longueur minimale | 16 |
| Historique | 24 |
| Âge minimal | 1 jour |
| Âge maximal | 90 jours |
| Seuil de verrouillage | 5 |
| Fenêtre d’observation | 15 minutes |
| Durée de verrouillage | 15 minutes |
| Chiffrement réversible | Désactivé |

Le PSO est appliqué à `GG_T0_Admins`. Les tests `Get-ADUserResultantPasswordPolicy` confirment son application à `Administrateur` et `adm_t0_oussama`.

Le compte intégré `Administrateur` conserve `PasswordNeverExpires=True` comme exception break-glass documentée. Cette exception est un risque résiduel.

## 11. Validation par outils d’audit

### 11.1 PingCastle

| Mesure | Baseline | État final |
|---|---:|---:|
| Score global | 100/100 | 25/100 |
| Collecteur | PingCastle 3.5.1.33 | même lignée d’outil |

Les familles de problèmes éliminées comprennent :

- SMBv1 et dette MS17-010 ;
- LDAP signing absent ;
- Print Spooler sur DC ;
- LAPS absent ;
- Schema Admins non vide ;
- groupes opérateurs ;
- Recycle Bin désactivée ;
- MachineAccountQuota ;
- faiblesse LM/NTLMv1 ;
- délégation et exposition de comptes de service ;
- audit DC insuffisant ;
- subnet AD absent ;
- LLMNR ;
- anciennes anomalies AdminSDHolder.

Le score n’est pas utilisé comme unique critère de réussite. Certains contrôles pertinents ne sont pas correctement représentés par un score global.

### 11.2 BloodHound

La collecte finale a été importée dans une base Neo4j/BloodHound Legacy nettoyée.

Résultats :

- aucun utilisateur Kerberoastable actif ;
- aucun utilisateur AS-REP Roastable ;
- aucun chemin Kerberoastable vers Domain Admins ;
- aucun chemin `HIBALAHROUF -> ADMINS DU DOMAINE` ;
- aucun chemin `ADM_T1_OUSSAMA -> ADMINS DU DOMAINE` ;
- DCSync limité à `DC-01` et aux groupes Tier 0 intégrés légitimes.

L’objectif n’est pas de supprimer toutes les relations privilégiées, ce qui rendrait AD inutilisable, mais de supprimer les chemins non autorisés depuis Tier 1, Tier 2 et les utilisateurs métier.

## 12. Preuves et captures à conserver

Pour chaque contrôle, le dossier de preuve devrait contenir :

```text
00-Baseline
01-Backup
02-GPO-Staged
03-RSOP
04-Effective-State
05-Negative-Test
06-Positive-Control
07-Events
08-Rollback
09-After
```

Captures prioritaires pour la soutenance :

1. diagramme réseau et tiers ;
2. arborescence OU finale ;
3. groupes AGDLP et membres récursifs ;
4. groupe Administrateurs local avant/après ;
5. événement `4625 / 0xC000015B` ;
6. LAPS autorisé dans le bon Tier et refusé entre Tiers ;
7. LDAP simple bind accepté avant puis rejeté après ;
8. SMB 3.1.1 signé et SMBv1 absent ;
9. événement `4624` avec `NTLM V2` ;
10. événements PowerShell `4103/4104` ;
11. événements process creation `4688` ;
12. scores PingCastle `100` puis `25` ;
13. BloodHound « Path not found » ;
14. DCSync limité aux identités légitimes.

Ne jamais afficher :

- mot de passe LAPS ;
- mot de passe de compte de test ;
- secrets, hashes ou tickets ;
- informations inutiles sur le poste hôte.

## 13. Scripts d’automatisation conservés

| Script | Fonction |
|---|---|
| `scripts/Collect-AuditBaseline.ps1` | collecte auditpol, RSOP, journaux et métadonnées avant changement |
| `scripts/New-MogadorAuditGpos.ps1` | création idempotente des GPO Advanced Audit avec liens initialement désactivés |
| `scripts/Test-MogadorAuditPolicy.ps1` | validation GPO, taille Security log, override, ligne de commande et Event 4688 |
| `scripts/New-MogadorPowerShellLoggingGpo.ps1` | création idempotente de la GPO PowerShell Logging |
| `scripts/Test-MogadorPowerShellLogging.ps1` | validation des paramètres et événements 4103/4104 |

Les scripts de création ne doivent pas remplacer la revue manuelle du rapport GPO et le déploiement progressif.

## 14. Alignement ISO/IEC 27001

L’ISO est utilisé comme cadre de gouvernance, pas comme catalogue de paramètres Windows.

| Risque traité | Traitement technique | Preuve d’efficacité |
|---|---|---|
| compromission d’un compte privilégié | comptes séparés, RBAC, tiering, FGPP | jetons, groupes, RSOP |
| propagation d’identifiants locaux | LAPS | rotation et tests de lecture |
| mouvement latéral entre tiers | deny logon, groupes locaux dédiés | 4625 et tests positifs |
| modification AD non détectée | Advanced Audit Policy | événements Security |
| scripts PowerShell malveillants | 4103/4104 | événements contrôlés |
| interception SMB | signature obligatoire | connexions signées |
| bind LDAP non protégé | LDAP signing | bind rejeté |
| protocoles anciens | SMBv1 retiré, NTLMv1 refusé, LLMNR désactivé | état protocolaire |
| création abusive de comptes machine | MachineAccountQuota 0 | attribut de domaine |
| suppression accidentelle | Recycle Bin et protection des OU | configuration AD |
| chemins d’escalade | ACL cleanup et comptes de service | BloodHound avant/après |

La matrice détaillée de traitement des risques ISO/IEC 27001 doit rester séparée de ce README afin de distinguer :

- la documentation d’implémentation technique ;
- le registre de risques ;
- la Déclaration d’Applicabilité ;
- les risques résiduels et leur acceptation.

## 15. Risques résiduels

### Élevés en production, acceptés dans le PFA

- un seul contrôleur de domaine ;
- absence de redondance DNS/AD ;
- absence de sauvegarde/restauration AD de niveau production ;
- Windows Server 2016 et Windows 10 en fin de cycle ou anciens ;
- multihoming du DC pour l’accès Internet du laboratoire.

### Moyens

- Legacy LAPS au lieu de Windows LAPS moderne ;
- NTLMv2 encore autorisé ;
- LDAP channel binding non enforced ;
- compte break-glass non expirant ;
- une seule source NTP externe ;
- absence actuelle de SIEM opérationnel ;
- rétention locale limitée des journaux ;
- pas de MFA, PAW ou Defender for Identity.

### Faibles ou documentaires

- anciens fichiers de baseline pouvant être confondus avec l’état final ;
- anciens documents mentionnant le pentest PMS annulé ;
- documentation historique d’une architecture `192.168.56.0/24` à six VM ;
- références BloodHound CE/Docker alors que la validation finale utilise Legacy/Neo4j.

## 16. Production versus PFA

### PFA

Le périmètre actuel est techniquement suffisant et avancé pour un projet de quatrième année :

- architecture de privilèges ;
- mesures défensives ;
- tests de compatibilité ;
- scénarios avant/après ;
- preuves d’efficacité ;
- analyse de risque ;
- limites explicitement assumées.

### Production hôtelière

Une architecture réelle devrait ajouter :

- au moins deux DC ;
- segmentation réseau appliquée par firewall ;
- PAW ou postes d’administration dédiés ;
- MFA pour les opérations privilégiées ;
- Windows LAPS moderne ;
- gMSA pour les services compatibles ;
- EDR et Defender for Identity ;
- sauvegardes AD testées ;
- SIEM central et rétention conforme ;
- plusieurs sources NTP ;
- gestion des correctifs industrialisée ;
- processus formel de recertification des accès ;
- PKI si nécessaire ;
- supervision de la réplication, DNS, comptes privilégiés et GPO.

## 17. Étape suivante

Le durcissement AD principal est terminé.

> **✅ Mise à jour (31 juillet 2026) — la phase détection est RÉALISÉE.** SIEM retenu : **Wazuh**. **15 détections AD validées en live** (Sysmon sur DC-01/WS-01), alerting e-mail HTML coloré vers Outlook, latence de détection ~0,64 s et 0 faux positif mesurés. Détail complet : `COMPTE_RENDU_DETECTION_PHASE_D.md`. Les étapes et scénarios listés ci-dessous ont été implémentés et validés.

La démarche initialement prévue était :

1. choisir le SIEM cible ;
2. déployer la collecte des journaux Security et PowerShell ;
3. préserver les événements nécessaires ;
4. créer un petit nombre de règles à forte valeur ;
5. valider trois scénarios de sécurité avant/après ;
6. mesurer la visibilité, les faux positifs et le temps de détection ;
7. alimenter la matrice ISO avec les preuves et risques résiduels.

Scénarios PFA recommandés :

- utilisation d’un compte Tier 1 sur une machine Tier 2 ;
- tentative de modification d’un groupe privilégié ou d’une GPO ;
- activité Kerberos/NTLM ou réplication AD anormale dans un scénario contrôlé.

## 18. Commandes de vérification essentielles

```powershell
Get-ADGroupMember -Identity "$((Get-ADDomain).DomainSID.Value)-512" -Recursive
Get-ADGroupMember -Identity "$((Get-ADDomain).DomainSID.Value)-518"
Get-ADGroupMember -Identity "$((Get-ADDomain).DomainSID.Value)-519"
Get-ADDefaultDomainPasswordPolicy
Get-ADUserResultantPasswordPolicy -Identity "adm_t0_oussama"
Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" | Select-Object Name,EnabledScopes
Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties "ms-DS-MachineAccountQuota"
Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion | Where-Object {!$_.ProtectedFromAccidentalDeletion}
```

Sur les membres :

```powershell
hostname
whoami
whoami /groups
gpresult /scope computer /r
Get-LocalGroupMember -Group (Get-LocalGroup -SID "S-1-5-32-544")
Test-ComputerSecureChannel -Verbose
Get-SmbConnection | Select-Object ServerName,ShareName,Dialect,Signed,Encrypted
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel,NoLMHash
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast
w32tm /query /source
```

Sur le DC :

```powershell
Get-Service NTDS,DNS,Netlogon,KDC
dcdiag /test:MachineAccount
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name LDAPServerIntegrity
Get-WindowsFeature FS-SMB1
Get-Service Spooler
auditpol /get /category:*
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 20
```

## 19. Conclusion

Le projet a remplacé une administration directe et peu cloisonnée par un modèle par rôles et par tiers, supprimé plusieurs protocoles et services hérités, renforcé les politiques d’authentification, nettoyé des chemins ACL et comptes de service, et déployé une journalisation exploitable.

La réussite est démontrée par :

- un score PingCastle passé de `100/100` à `25/100` ;
- l’absence de chemins BloodHound non autorisés vers Domain Admins ;
- le maintien des accès administratifs légitimes par Tier ;
- des tests négatifs et événements Windows ;
- des validations de compatibilité après chaque enforcement.

Le domaine n’est pas présenté comme « sécurisé à 100 % ». Il est présenté comme un laboratoire durci, mesuré et techniquement défendable, avec des risques résiduels explicitement documentés.
