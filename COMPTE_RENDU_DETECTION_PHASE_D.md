# Compte-rendu — Phase D — Détection (Mogador PFA)

**Domaine :** `mogador.local` · **SIEM :** Wazuh (manager sur Kali `192.168.10.40`)
**Date de réalisation :** 30 juillet 2026
**Objet :** journal factuel de l'implémentation et de la validation des détections AD (ce qui a réellement été fait et prouvé en live).

> Discipline appliquée : chaque règle est prouvée par un **événement live → alerte dans le dashboard**, jamais présentée comme opérationnelle sans preuve. Les valeurs de champs ont été vérifiées sur des événements réels avant d'être utilisées dans les règles.

---

## 1. Architecture de collecte validée

| Hôte | Rôle | Canaux collectés | Sysmon |
|---|---|---|---|
| `DC-01` (192.168.10.10) | DC / DNS / Tier 0 | Security, System, Application, **Sysmon/Operational** (ajouté) | **Oui (ajouté, config lean)** |
| `WS-01` (192.168.10.20) | Poste Tier 2 | Security, System, **PowerShell/Operational** (ajouté), **Sysmon/Operational** | Oui (déjà présent) |
| `PMS-01` (192.168.10.21) | Serveur Tier 1 | Security, System, Application *(collecte interrompue — service EventLog corrompu, voir §9)* | Non (statut explicite — voir §9) |
| `KALI-01` (192.168.10.40) | Wazuh manager + poste d'attaque | — | — |

**Faits validés :**
- Chaîne collecte → manager → indexer → dashboard fonctionnelle (preuve : événements WS-01 et DC-01 visibles dans *Threat Hunting*).
- Le dashboard *Discover / Threat Hunting* n'affiche que les **alertes** (règles de niveau ≥ 3) ; un événement brut sans règle n'y apparaît pas.
- Le canal `Microsoft-Windows-PowerShell/Operational` doit être **explicitement** ajouté à l'`ossec.conf` de l'agent (il n'est pas collecté par défaut).
- Agent DC-01 réinstallé en **v4.14.6** (aligné sur le manager) après restauration du DC (voir §5).

---

## 2. Règles de détection créées (`/var/ossec/etc/rules/local_rules.xml`)

| ID | Détection | Événement / déclencheur | Niveau | MITRE | Scénario |
|---|---|---|---|---|---|
| `100040` | Connexion bloquée par la politique de tiering | `4625`, `status 0xC000015B` | 12 | T1078.002 | #1 |
| `100037` | Ajout à un groupe privilégié Tier 0 | `4728/4732/4756`, `targetSid` RID `-512/-518/-519/-544/-1118` | 12 | T1098 | #2 |
| `100043` | Retrait d'un groupe privilégié Tier 0 | `4729/4733/4757`, même RID | 8 | T1098 | #2 (rollback) |
| `100041` | PowerShell — contenu de script block suspect | `4104`, `scriptBlockText` (IEX, DownloadString, FromBase64String…) | 10 | T1059.001 | #3 |
| `100042` | PowerShell — commande encodée | `4688`, `commandLine` contient `-EncodedCommand` | 10 | T1027 | #3 |
| `100030` | Kerberoasting (unitaire) | `4769`, `ticketEncryptionType 0x17` (RC4), hors `$`/`krbtgt` | 6 | T1558.003 | #4 |
| `100031` | Kerberoasting (rafale) | 6× `100030` en 60 s, même `ipAddress` | 12 | T1558.003 | #4 |
| `100033` | DCSync | `4662`, GUID réplication `1131f6aa`/`1131f6ad`/`89e95b76`, `subjectUserName` non-machine | 14 | T1003.006 | #5 |
| `100038` | Shadow Credentials | `5136`, `attributeLDAPDisplayName = msDS-KeyCredentialLink` | 13 | T1556 | #6 |
| `100036` | Extraction NTDS.dit | Sysmon EID 1, `commandLine` ~ `ntdsutil … ifm` / `vssadmin create shadow` | 14 | T1003.003 | P2 |
| `100035` | DCShadow — **déployée, NON validée** | `5137`, `objectClass = nTDSDSA` | 14 | T1207 | P2 |
| `100032` | AS-REP Roasting | `4768`, `preAuthType=0`, hors comptes machine | 10 | T1558.004 | P2 |
| `100039` | Zerologon — connexion vulnérable **autorisée** (incident) | `5829` | 13 | T1210 | P2 |
| `100044` | Netlogon — connexion vulnérable **refusée** (contrôle positif) | `5827`/`5828` | 4 | T1210 | P2 |
| `100050` | Échec d'authentification (base) | `4625`, `subStatus 0xC000006A`/`0xC0000064` | 4 | T1110 | P3 |
| `100051` | Password spraying / brute-force | ≥5× `100050` en 120 s, même `ipAddress` | 12 | T1110.003 | P3 |
| `100052` | Persistence — installation de service | `4697` | 10 | T1543.003 | P3 |
| `100053` | Persistence — tâche planifiée | `4698` (audit « Other Object Access Events » — **pérennisé dans `GPO_DC_Advanced_Audit`**) | 10 | T1053.005 | P3 |
| `100054` | Modification de GPO | `5136` sur `groupPolicyContainer` | 12 | T1484.001 | P3 |

**Règle intégrée Wazuh utilisée en complément :** `92057` (Sysmon EID 1 — « base64 encoded command », niveau 12) sur le scénario #3.

> Une règle diagnostic temporaire (`100091`, tout `4104`) a servi à valider le canal PowerShell puis a été **retirée** (trop bruyante).

### Corrections importantes appliquées (issues de la revue critique)
- **Nom de champ** : l'ID d'événement est `win.system.eventID` (et non `win.eventdata.eventId`) — un mauvais chemin aurait rendu les règles silencieusement mortes.
- **Casse hexadécimale** : Wazuh stocke les codes hex en **minuscules** (`0xc000006d`) → tous les match sur `status`/`subStatus` utilisent `(?i)` (insensible à la casse).
- **Groupe privilégié** : match sur le **RID (SID)** et non sur le nom FR (`Admins du domaine`) → indépendant de la localisation.
- **PowerShell** : détection **séparée** — `4104` pour le contenu déchiffré, `4688` pour le flag `-EncodedCommand` (le `4104` ne contient pas le flag).
- **Golden Ticket** : volontairement **non déployée** (l'approche `4624 + ticketLifetime` est invalide, le champ n'existe pas) → documentée en travaux futurs.
- **Sévérités graduées et défendables** : un **ajout** à un groupe privilégié (`100037`, niv. 12) est une **alerte d'incident** ; un **retrait** (`100043`, niv. 8) est journalisé pour la **complétude de la piste d'audit** (il *réduit* le privilège), pas alerté comme incident. Même logique Zerologon : connexion vulnérable **autorisée** (`100039`, niv. 13 = faille d'enforcement, incident) vs **refusée** (`100044`, niv. 4 = enforcement qui fonctionne, contrôle positif) — un futur hit `5827/5828` se lit comme une **preuve que la défense tient**, pas comme un incident.

---

## 3. Prérequis d'audit armés (permanents)

Ces SACL sont de l'**audit seul** (aucune permission accordée) et constituent la capacité de détection permanente. DACL non modifiée. Sauvegardes SDDL conservées sous `C:\Evidence\SACL-Backups\`.

| Cible | Audit ajouté | Sert à |
|---|---|---|
| Racine du domaine | `ExtendedRight` / Success / Everyone sur `1131f6aa` (Get-Changes), `1131f6ad` (Get-Changes-All), `89e95b76` (Get-Changes-In-Filtered-Set) | DCSync (`4662`) — règle `100033` |
| Racine du domaine (hérité aux descendants) | `WriteProperty` / Success / Everyone sur `5b47d60f` (`msDS-KeyCredentialLink`) | Shadow Credentials (`5136`) — règle `100038` |
| `CN=Policies,CN=System` (hérité aux descendants) | `WriteProperty` / Success / Everyone | Modification de GPO (`5136` sur `groupPolicyContainer`) — règle `100054` |

**Sous-catégories d'audit confirmées** (en Succès) :
- *Directory Service Access* = **Succès et échec** · *Directory Service Changes* = **Succès** · *Security System Extension* = **Succès** · *Kerberos Service Ticket Operations* = **Succès** (Phase C)
- *Other Object Access Events* = **Succès** — ajouté à `GPO_DC_Advanced_Audit` (permanent, pour `4698`).

**Baseline reproductible :** le script idempotent [`scripts/Deploy-DetectionPrereqs.ps1`](scripts/Deploy-DetectionPrereqs.ps1) (re)pose les 3 SACL et vérifie les sous-catégories d'audit — validé idempotent (les 3 SACL ressortent en « déjà présente »). Sauvegardes SDDL sous `C:\Evidence\SACL-Backups\`. Les SACL sont stockées dans AD (permanentes, survivent au `gpupdate`) ; la politique d'audit est gérée par GPO.

---

## 4. Scénarios P1 validés en live (attaque → détection)

| # | Scénario | Action (attaque contrôlée) | Événement | Alerte | Statut |
|---|---|---|---|---|---|
| 1 | Violation de tiering | `runas /user:MOGADOR\adm_t1_oussama` sur WS-01 (refusé par GPO deny-logon) | `4625` / `0xC000015B` | `100040` | ✅ validé |
| 2 | Groupe privilégié | Compte jetable ajouté puis retiré de Domain Admins | `4728` + `4729` | `100037` + `100043` | ✅ validé |
| 3 | PowerShell encodé | `powershell -EncodedCommand` (contenu IEX/DownloadString) sur WS-01 | `4104` + `4688` + Sysmon EID 1 | `100041` + `100042` + `92057` | ✅ validé (3 signaux) |
| 4 | Kerberoasting | `impacket-GetUserSPNs -request` contre `svc_test_krb` (SPN + RC4) ; puis rafale ×6 | `4769` RC4 (0x17) | `100030` puis `100031` | ✅ validé |
| 5 | DCSync | ACE réplication temporaire à un compte jetable + `impacket-secretsdump -just-dc-user krbtgt` | `4662` (GUID réplication) | `100033` | ✅ validé |
| 6 | Shadow Credentials | ACE limité (`WriteProperty msDS-KeyCredentialLink` sur 1 cible) + `bloodyAD add shadowCredentials` | `5136` (`msDS-KeyCredentialLink`) | `100038` | ✅ validé |
| P2 | Extraction NTDS.dit | `ntdsutil "ac i ntds" "ifm" "create full"` sur le DC | Sysmon EID 1 (`ntdsutil … ifm`) | `100036` | ✅ validé (Sysmon) |
| P2 | AS-REP Roasting | compte jetable sans pré-auth + `impacket-GetNPUsers -no-pass` | `4768` `PreAuthType=0` | `100032` | ✅ validé |
| P2 | DCShadow | *non joué* (risque `nTDSDSA` + Defender) | `5137`/`nTDSDSA` | `100035` | ⚠️ **déployée, non validée** |
| P2 | Zerologon | testeur non destructif SecuraBV contre le DC patché | *aucun `5829`* (DC rejette : « probably patched ») | `100039` (incident) / `100044` (contrôle positif) | ✅ **test négatif réussi** — DC non vulnérable ; règles déployées, non déclenchées (attendu) |
| P3 | Password spraying | 8 échecs SMB depuis Kali (comptes distincts, 1 essai/compte) | `4625` ×N même source | `100051` (+`100050`) | ✅ validé |
| P3 | Persistence (service) | `New-Service` bidon sur le DC (supprimé après) | `4697` | `100052` | ✅ validé |
| P3 | Persistence (tâche planifiée) | `schtasks /create` bidon sur le DC (supprimée après) | `4698` | `100053` | ✅ validé (audit pérennisé en GPO) |
| P3 | Modification de GPO | `New-GPO` + `Set-GPRegistryValue` (GPO supprimée après) | `5136` `groupPolicyContainer` | `100054` | ✅ validé |

**Hygiène :** tous les comptes/ACE de test étaient **jetables**, créés puis **supprimés** après validation (comptes `test_*`, `svc_test_krb`). Aucun résidu SDProp/adminCount (comptes supprimés). Les modifications de DACL (DCSync) ont été **sauvegardées avant et révoquées après**. Le dump NTDS.dit (contenant tous les hachages) a été **supprimé immédiatement** après le test.

**Statut explicite de `100035` (DCShadow) :** la règle est **déployée** mais **non validée**. L'attaque DCShadow n'a volontairement pas été jouée (risque de résidu d'objet `nTDSDSA` sur un lab à un seul DC, et blocage Defender de mimikatz). La validation par `wazuh-logtest` sur JSON brut n'est pas concluante (l'événement collé est décodé par le décodeur générique `json` et non `windows_eventchannel`, donc le groupe `windows` requis par la règle est absent — artefact de la méthode de test, ni preuve ni réfutation). **Aucune preuve positive n'existe pour cette règle** ; elle est présentée honnêtement comme « conçue et déployée, validation live différée ».

---

## 5. Incidents rencontrés et résolus (transparence méthodologique)

- **DC-01 étranglé (RAM) → corruption du service EventLog.** Après reprises de VM en pause avec peu de RAM : ADWS en timeout, `Get-WinEvent` en erreur RPC, service **EventLog** refusant de démarrer (erreur système 13 « données non valides », y compris avec le dossier de logs vidé) → corruption de la configuration des canaux. **Résolution :** revert vers le snapshot sain de fin de Phase C + RAM portée à **4 Go** + démarrage à froid. AD, GPO et durcissement **intacts** (données sur disque, non affectées). Sur un lab à un seul DC, aucun risque d'USN rollback.
- **Ré-enrôlement de l'agent DC-01.** Le snapshot étant antérieur à l'installation de l'agent, réinstallation nécessaire. Le manager refusait l'enrôlement (`Duplicate name 'DC-01', Agent '002' has not been disconnected long enough`) → suppression de l'entrée fantôme `002` via `manage_agents` → ré-enrôlement automatique et remontée OK.
- **Horloge.** Le revert avait ramené le DC au 28/07 → `w32tm /resync /force` pour éviter tout décalage Kerberos (> 5 min).

---

## 6. Observations à forte valeur pour la soutenance

- **Le durcissement Phase C bloque activement l'attaque.** La signature LDAP (`LDAPServerIntegrity=2`) a rejeté le bind LDAP naïf de pyWhisker (`strongerAuthRequired`) — preuve live que le contrôle fonctionne. L'attaque a dû basculer sur un bind signé/Kerberos.
- **Absence d'AD CS = défense en profondeur.** L'exploitation post-écriture des Shadow Credentials (PKINIT pour récupérer un TGT/hash) a échoué (`KDC_ERR_PADATA_TYPE_NOSUPP`) faute d'autorité de certification. L'écriture reste néanmoins détectée (`5136` → `100038`).
- **Défense en profondeur sur le PowerShell.** Un même PowerShell encodé est détecté par **3 sources indépendantes** (Sysmon, `4688`, `4104`) — résilience si une source tombe.
- **Windows Defender bloque l'extraction NTDS.dit.** Le lancement de `ntdsutil … ifm` a été refusé par la protection temps réel de Defender (« Accès refusé ») — un contrôle défensif supplémentaire. La validation de la détection Sysmon a nécessité de désactiver **temporairement** la protection temps réel, **réactivée immédiatement après**.
- **Outlook/O365 impose l'authentification moderne.** Le test SMTP a renvoyé `535 5.7.139 … basic authentication is disabled` : le SMTP basique est désactivé, seul `XOAUTH2` (OAuth2) est accepté — hors périmètre pour un relais de lab. En production, l'intégration se ferait via un connecteur OAuth2 ou un relais SMTP interne authentifié ; la démo utilise un relais Gmail.

---

## 7. Couverture de détection ≠ politique d'alerting

Plusieurs règles peuvent se déclencher pour une même action (ex. #3). C'est **volontaire** :
- **Dashboard = journal forensique complet** (toutes les détections, pour l'investigation et la résilience).
- **E-mail = escalade** (seulement les alertes à forte valeur) — **implémenté**.

Pour une petite structure (un seul admin IT), l'objectif n'est pas un SOC 24/7 mais un **journal complet + quelques alertes critiques** (DCSync, Shadow Creds, groupe privilégié, violation de tiering).

### Alerting e-mail implémenté

- **Chaîne d'envoi** : Wazuh → relais **Postfix local** (127.0.0.1:25) → **Gmail** (SMTP authentifié, mot de passe d'application) → boîte **Outlook** de destination. *(Outlook/O365 refusant le SMTP basique — `535 basic authentication is disabled` —, Gmail sert de relais d'envoi ; la destination reste Outlook. En production : connecteur OAuth2 ou relais interne O365.)*
- **Filtrage « seulement l'utile »** : `email_alert_level = 16` (mailer natif silencieux) + **intégration personnalisée** `custom-email` déclenchée sur une **liste blanche de 12 règles** (`100031,100033,100035,100036,100037,100038,100039,100040,100051,100052,100053,100054`). Les règles bruyantes (PowerShell, AS-REP, échecs unitaires) restent au dashboard uniquement.
- **E-mail HTML enrichi** (script `scripts/custom-email-integration.py`, déployé en `/var/ossec/integrations/custom-email`) : **bandeau coloré par sévérité** (🔴 critique / 🟠 élevé / 🟡 moyen), règle + niveau, détection, agent, compte/objet, **source (IP)**, **MITRE (technique + tactique)**, heure, **action recommandée** par règle (guide de remédiation pour l'admin seul), et **bouton « Ouvrir le dashboard »**. Validé en live (ex. `100051` reçu en orange avec l'IP source).

---

## 8. Captures à conserver pour le rapport (les utiles uniquement)

1. Page **Agents** (3 agents Active) — preuve d'architecture.
2. Scénario #1 — alerte `100040`.
3. Scénario #2 — alertes `100037` **et** `100043` (action + rollback).
4. Scénario #3 — `100041` + `100042` + `92057` ensemble (défense en profondeur).
5. Scénario #4 — alerte `100031` (rafale) + `100030`.
6. Scénario #5 — alerte `100033`.
7. Scénario #6 — alerte `100038`.
8. P2 NTDS.dit — alerte `100036` (ligne de commande `ntdsutil … ifm`).
9. P2 AS-REP — alerte `100032`.
10. (option) Zerologon — sortie du testeur « probably patched » (preuve du test négatif).
11. **Alerting** — le **mail d'alerte HTML coloré** reçu dans Outlook (bandeau sévérité + source IP + MITRE + action recommandée + bouton dashboard) = preuve de l'escalade opérationnelle.
12. (P3) captures des alertes `100051` (spraying), `100052/100053` (persistence), `100054` (modification GPO) si tu veux illustrer le P3.

---

## 9. Statut et suite

**Validé en live (preuve dashboard) :** scénarios #1 à #6 (P1) **+ NTDS.dit + AS-REP Roasting** (P2) **+ Password spraying + Persistence (service & tâche planifiée) + Modification de GPO** (P3) — **15 détections custom validées en live** + 1 règle intégrée (`92057`).

**Test négatif réussi :** Zerologon — le DC patché rejette l'attaque (testeur SecuraBV non destructif : « probably patched »), aucun `5829`. Détection scindée en deux règles de sévérité distincte : `100039` (niv. 13, connexion vulnérable **autorisée** = incident) et `100044` (niv. 4, connexion vulnérable **refusée** = contrôle positif). Sur le DC durci, aucune des deux n'a été déclenchée (attendu).

**Déployé mais NON validé (aucune preuve positive) :** DCShadow (`100035`) — attaque live volontairement différée (voir §4).

**Périmètre Sysmon — décision explicite (cohérence avec la discipline « statut jamais ambigu ») :** Sysmon a été déployé sur **DC-01** (crown-jewel : c'est là que s'exécutent extraction NTDS.dit, DCShadow, accès LSASS) et **WS-01** (endpoint utilisateur). **PMS-01 n'a volontairement PAS reçu Sysmon** dans cette itération : le serveur Tier 1 est **actuellement vide** (aucune charge applicative), donc la valeur marginale de la télémétrie processus y est la plus faible des trois. **Limite assumée** : `PMS-01` reste une **cible de pivot post-compromission réaliste** (cf. narration Phase B) ; son déploiement Sysmon (mêmes étapes que DC-01/WS-01) est **recommandé pour la complétude** dès qu'une charge y sera installée. **Tentative effectuée, diagnostiquée puis close en limite assumée (31 juillet 2026).** Diagnostic live : `Get-Service EventLog` = *Stopped* ; `net start eventlog` → **erreur système 13** (`ERROR_INVALID_DATA`, `sc query` = `WIN32_EXIT_CODE 13`) ; `wevtutil`/`Get-WinEvent` → **« Interface inconnue »** (symptôme *secondaire* : ces outils passent par RPC dans le service arrêté, ce n'est pas une panne distincte). Configuration du service intacte (`svchost -k LocalServiceNetworkRestricted`, compte `LocalService`) → la corruption est dans la **configuration des canaux** lue au démarrage, pas dans le service ni les `.evtx` (1017 canaux/815 publishers = counts sains). **Même famille que l'incident DC-01** (erreur système 13), séquelle des pauses/reprises sur RAM juste. **Cause partielle identifiée et retirée** : un **manifeste Sysmon à moitié inscrit** (publisher `{5770385f-c22a-43e0-bf4c-06f5698ffbd9}` + canal `Microsoft-Windows-Sysmon/Operational` pointant `C:\Windows\Sysmon64.exe` — résidu du « Impossible de créer un fichier déjà existant »). Après suppression des clés WINEVT + du binaire, l'échec est passé d'*erreur 13 immédiate* à *START_PENDING puis arrêt*, **mais l'erreur 13 a persisté après boot à froid** → corruption plus profonde que le seul résidu. **Aucun snapshot sain de PMS-01 n'existait** (contrairement à DC-01) → la réparation complète = **rebuild de la VM**. **Décision : rebuild différé / limite assumée**, vu (a) serveur Tier 1 vide, (b) Sysmon déjà déployé sur DC-01 (joyau) et WS-01 (endpoint), où toute la télémétrie processus a de la valeur. **Conséquence honnête** : tant qu'EventLog est HS, l'agent Wazuh de PMS-01 ne peut lire **aucun canal** (Security/System/Application) — PMS-01 est donc actuellement un **angle mort SIEM**, pas seulement « sans Sysmon ». Documenté comme travail à finaliser au même titre que DCShadow et Golden Ticket ; à traiter par rebuild dès qu'une charge applicative justifiera PMS-01 dans le SIEM.

**Alerting e-mail : ✅ terminé** — relais Postfix→Gmail→Outlook, filtrage liste blanche (12 règles), e-mail HTML coloré par sévérité + action recommandée + lien dashboard (voir §7). Validé en live.

**Reste à faire :**
- **P3 : tous les cas exploitables validés** (spraying, persistence service + tâche planifiée, modification de GPO). Seul **Golden Ticket** reste hors périmètre (approche `4624 + ticketLifetime` invalide → travaux futurs par corrélation).
- **Prérequis d'audit pérennisés** : « Other Object Access Events » (pour `4698`) a été **ajouté à `GPO_DC_Advanced_Audit`** et persiste désormais après `gpupdate` → détection des tâches planifiées **permanente**. Toutes les sous-catégories requises sont en Succès. Baseline SACL reproductible via `scripts/Deploy-DetectionPrereqs.ps1`.
- **Latence & FP mesurés ✅** : **latence de détection 0,3–0,9 s (moyenne 0,64 s)** — calculée dans Wazuh (`timestamp` alerte − `systemTime` événement) pour éliminer le décalage d'horloge inter-hôte ; **homogène entre règles** car dominée par la chaîne collecte→traitement, pas par la logique de règle. **Taux de faux positifs = 0** : chaque alerte de la validation correspondait à une attaque contrôlée, et une fenêtre d'observation **sans attaque** n'a produit **aucun** hit. *(Reste à transcrire ces valeurs dans les colonnes Latence/FP de la matrice de détection.)*
- Alimenter la matrice **ISO/IEC 27001** avec les nouvelles preuves.
