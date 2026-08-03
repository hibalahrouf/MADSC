# MADSC — Mogador Active Directory Security Center

> **Document de handoff.** Ce README est conçu pour qu'un développeur — ou une autre IA/chat — reprenne le
> projet **sans contexte préalable**. Il décrit le pourquoi, l'architecture, le contrat de données, l'état
> actuel et la feuille de route. Lis-le en entier avant de coder.

> 📖 **Procédure étape-par-étape complète :** voir [LAUNCH_GUIDE.md](LAUNCH_GUIDE.md) pour le relancement complet du lab (host MADSC + VMs DC-01/WS-01/PMS-01 + Wazuh Kali).
>
> 🏗️ **Architecture, décisions de conception et travaux futurs :** voir
> [README_ARCHITECTURE.md](README_ARCHITECTURE.md) — ce que fait MADSC, **pourquoi** il est
> construit ainsi, les résultats vérifiés et la feuille de route. C'est le document à lire pour
> le rapport PFA ; le présent README reste le guide de prise en main.

---

## 0. Quickstart (nouveau PC Windows)

> ⚠️ **Ne copie jamais le dossier `.venv`** d'un autre PC : un virtualenv contient des chemins absolus en
> dur, il n'est **pas portable**. Recrée-le. `sqlite3` est intégré à Python : **aucune base à installer**.

```powershell
# Prérequis : Python 3.11+  (vérifier : python --version)
cd MADSC
powershell -ExecutionPolicy Bypass -File .\setup.ps1   # recrée le venv + installe les dépendances
.\.venv\Scripts\Activate.ps1
uvicorn backend.main:app --host 0.0.0.0 --port 8700 --reload
```

Ouvre **http://127.0.0.1:8700** (dashboard) et **http://127.0.0.1:8700/docs** (API interactive).
Un échantillon est fourni : `POST /ingest/scan` pour l'ingérer.

**À installer sur un PC vierge :** seulement **Python 3.11+**. Le reste (`fastapi`, `uvicorn[standard]`,
`requests`, `pydantic`) vient de `pip install -r requirements.txt` (fait par `setup.ps1`).

---

## 1. Contexte du projet (PFA Mogador)

MADSC est la **vision finale** d'un PFA (projet de fin d'année) cybersécurité de type **Purple Team** sur un
domaine Active Directory fictif : `mogador.local` (un hôtel fictif). Le PFA a déjà réalisé, en amont :

- **Durcissement AD** : modèle en tiers (Tier 0/1/2), RBAC/AGDLP, Legacy LAPS, durcissement des protocoles
  (SMB/LDAP/NTLM/LLMNR), correctifs. Résultat : score **PingCastle 100/100 → 25/100**, aucun chemin
  d'élévation non autorisé dans **BloodHound**.
- **Détection (Phase D)** : SIEM **Wazuh** (manager sur Kali `192.168.10.40`, agents sur DC-01/WS-01/PMS-01),
  **16 règles de détection** AD custom (`100030`→`100054`) + Sysmon, **15 validées en live**, alerting e-mail.
- **Alignement ISO/IEC 27001:2022** : une matrice de traitement des risques (`R-01`→`R-19`) reliant chaque
  risque à un traitement, une preuve et un contrôle Annexe A. Voir `../MATRICE_ISO27001_MOGADOR.md`.

**MADSC opérationnalise tout ça** pour l'utilisateur réel visé : **l'administrateur unique d'une PME/hôtel**,
qui n'a pas de SOC 24/7 mais a besoin de savoir *« mon AD est-il toujours dans l'état durci validé, ou a-t-il
dérivé ? »* et *« qu'est-ce qui mérite mon attention en priorité ? »*.

### Topologie du lab (contexte, non requis pour faire tourner MADSC)
| Hôte | IP | Rôle | OS |
|---|---|---|---|
| DC-01 | 192.168.10.10 | Contrôleur de domaine / DNS / Tier 0 | Windows Server 2016 FR |
| PMS-01 | 192.168.10.21 | Serveur membre Tier 1 (vide) | Windows Server 2016 FR |
| WS-01 | 192.168.10.20 | Poste Tier 2 | Windows 10 FR |
| KALI-01 | 192.168.10.40 | Wazuh manager + poste d'attaque | Kali |

---

## 2. Ce que MADSC EST / N'EST PAS

**EST** : une console légère, self-hosted, **preuve-first**, qui **relie** des outils existants (Wazuh,
PingCastle, BloodHound, audits) dans une vue d'exploitation quotidienne : posture, dérives, alertes
prioritaires, preuves, rapports.

**N'EST PAS** :
- ❌ un remplaçant de Wazuh / PingCastle / BloodHound (il les consomme, ne les refait pas) ;
- ❌ un lanceur d'attaques (aucun DCSync/Kerberoasting déclenché depuis le web) ;
- ❌ un outil qui écrit dans l'AD (**100 % lecture seule**) ;
- ❌ un faux « temps réel » pour la posture (les contrôles de config sont **périodiques / à la demande** ;
  le vrai temps réel concerne les **alertes**, qui viennent du connecteur Wazuh — **phase 3 terminée**).

---

## 3. Persona & cas d'usage

- **Administrateur IT (utilisateur principal)** : voit la dérive de posture, enquête sur les alertes, corrige.
- **Direction / RSSI** : voit le risque, les priorités et les progrès **sans jargon** (rapport de synthèse).

Dashboard actuel (**5 onglets, thème CLAIR / light mode**, data-viz SVG générée côté serveur via `charts.py`) :
- **📊 Vue d'ensemble** (page d'accueil) : KPIs, **donut de conformité**, **donut de couverture Purple Team**, **barre de répartition** des statuts, **Top 3 actions prioritaires** + **risque métier** (phase 4a), **cartes de synthèse par hôte**.
- **🛡️ Posture détaillée** : les 16 contrôles avec lignes cliquables (détail, preuve, hash SHA-256, remédiation expandables).
- **🚨 Wazuh** : santé des agents (`SAIN`/`DÉGRADÉ`/`NON SURVEILLÉ`) + alertes MITRE ATT&CK.
- **🔍 Preuves ISO 27001** : vue audit (contrôle → risque → source de preuve → hash → remédiation).
- **🟣 Purple Team** : registre des 15 scénarios (statut de validation, règle Wazuh, occurrences live) + **heatmap MITRE ATT&CK** par tactique (phase 4b).

Deux rapports **PDF** téléchargeables (pied de page) : direction (jauge + KPIs + barres, sans jargon) et technique (tableau par hôte + détail + registre Purple Team) — phase 5.

---

## 4. Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│  HÔTES AD (DC-01 / WS-01 / PMS-01)         [ VM — LECTURE SEULE ]        │
│  Collecteurs PowerShell  (Get-*, lecture registre)                       │
│        │  produisent des snapshots JSON horodatés                        │
└────────┼─────────────────────────────────────────────────────────────────┘
         │  mode fichier : data/snapshots/  |  mode live : POST /ingest
         ▼
┌────────────────────────────────────────────────────────────────────────┐
│  BACKEND MADSC (host Windows, 0.0.0.0:8700)  — FastAPI + SQLite          │
│   • /ingest, /ingest/scan  → évaluation vs baseline (controls.py)         │
│   • stockage snapshots + résultats (SQLite)                              │
│   • /api/posture, /api/proofs, /api/baseline                             │
│   • ✅ connecteur Wazuh API (lecture seule) : /api/wazuh/*               │
│     └→ JWT auto-renew, fallback /manager/stats, catalogue MITRE          │
└────────┼─────────────────────────────────────────────────────────────────┘
         │                        ┌─────────────────────────────────────┐
         │    Phase 3 (terminée)  │  WAZUH MANAGER (Kali 192.168.10.40)│
         │◄──── API REST 55000 ──│  4 agents · 19 règles custom        │
         │      (lecture seule)   │  Authentification JWT (wazuh-wui)  │
         ▼                       └─────────────────────────────────────┘
      Dashboard light-mode (5 onglets : Vue d'ensemble · Posture · Wazuh · Preuves ISO · Purple Team)
```

**Flux de données (2 modes simultanés) :**
1. **Mode fichier** : collecteur PowerShell → `snapshot-*.json` → `data/snapshots/` → auto-scan.
2. **Mode live (HTTP)** : collecteur avec `-PostUrl` → `POST /ingest` directement depuis la VM.
3. **Wazuh live** : `backend/wazuh.py` interroge l'API REST Wazuh (`/agents`, `/manager/stats`) → santé des agents + synthèse des alertes MITRE ATT&CK.
4. Le dashboard (`GET /`) affiche les 3 onglets : posture, Wazuh, preuves ISO.

---

## 5. Stack technique & prérequis

| Élément | Choix | Raison |
|---|---|---|
| Langage backend | Python 3.11+ | déjà utilisé dans le projet ; portable |
| API web | **FastAPI** | léger, typé (pydantic v2), `/docs` auto |
| Serveur ASGI | **uvicorn[standard]** | dev (`--reload`) et prod |
| Persistance | **SQLite** (module `sqlite3` intégré) | zéro serveur DB, fichier unique `data/madsc.db` |
| Collecteurs | **PowerShell** (lecture seule) | natif Windows, `Get-*`/registre |
| Validation | **pydantic v2** | schéma `Snapshot` strict |

**Empreinte mémoire** : minime (~50–100 Mo) — co-localisable sur Kali (4 Go) à côté de Wazuh si besoin.

---

## 6. Installation détaillée (nouveau PC)

1. **Installer Python 3.11+** (python.org ou Microsoft Store). Vérifier : `python --version`.
2. **Copier le dossier `MADSC/`** (sans le `.venv` — le `.gitignore` l'exclut déjà si versionné via git).
3. **Bootstrap** :
   ```powershell
   cd MADSC
   powershell -ExecutionPolicy Bypass -File .\setup.ps1
   ```
   `setup.ps1` : supprime tout `.venv` copié, recrée un venv propre, installe `requirements.txt`.
4. **Lancer** :
   ```powershell
   .\.venv\Scripts\Activate.ps1
   uvicorn backend.main:app --reload --port 8700
   ```

> Sans `setup.ps1` (manuel) : `python -m venv .venv` → `.\.venv\Scripts\Activate.ps1` →
> `pip install -r requirements.txt`.

La base `data/madsc.db` est créée automatiquement au démarrage. Elle est **portable** (tu peux la copier ou
la supprimer pour repartir de zéro).

---

## 7. Utilisation

| Action | Commande |
|---|---|
| Lancer le serveur | `uvicorn backend.main:app --reload --host 0.0.0.0 --port 8700` |
| Dashboard (3 onglets) | http://127.0.0.1:8700 |
| API interactive | http://127.0.0.1:8700/docs |
| Ingérer les JSON du dossier | `Invoke-RestMethod -Method Post http://127.0.0.1:8700/ingest/scan` |
| **Figer la baseline** (référence de dérive) | `Invoke-RestMethod -Method Post http://127.0.0.1:8700/baseline/approve` |
| Posture courante (JSON) | `Invoke-RestMethod http://127.0.0.1:8700/api/posture` |
| Preuves & remédiations (JSON) | `Invoke-RestMethod http://127.0.0.1:8700/api/proofs` |
| Santé agents Wazuh (JSON) | `Invoke-RestMethod http://127.0.0.1:8700/api/wazuh/agents` |
| Alertes Wazuh MITRE (JSON) | `Invoke-RestMethod http://127.0.0.1:8700/api/wazuh/alerts` |
| Statut API Wazuh | `Invoke-RestMethod http://127.0.0.1:8700/api/wazuh/status` |

> **Workflow dérive** : ingère une première collecte (état durci validé) → `POST /baseline/approve` fige cette
> référence → à chaque collecte suivante, tout écart ressort en **CHANGÉ** (avant → après). C'est le cœur
> « surveillance de la dérive » : l'admin voit immédiatement *ce qui a bougé* depuis l'état approuvé.

**Cycle manuel (dev/test) avec une VM :**
```powershell
# sur la VM (DC-01/WS-01/PMS-01) — LECTURE SEULE, ne dépend pas d'EventLog
.\Collect-Protocols.ps1 -OutDir C:\MADSC-out
# puis copier le .json vers MADSC\data\snapshots\ sur le host (l'auto-scan l'ingère seul)
```

### Automatisation (mode exploitation — hands-off)  ⭐

Le mode manuel ci-dessus sert au **test**. En exploitation, l'administrateur ne fait **rien** au quotidien.
Deux façons de livrer les snapshots des VM vers MADSC — **A recommandé (aucun partage, pas de VMware Tools)** :

**A. Envoi HTTP direct** ⭐ (le collecteur POST le JSON à `/ingest` — rien à partager)

1. Exposer MADSC sur le LAN (host, une fois — réversible) :
   ```powershell
   New-NetFirewallRule -DisplayName "MADSC 8700" -Direction Inbound -Protocol TCP -LocalPort 8700 -Action Allow
   uvicorn backend.main:app --host 0.0.0.0 --port 8700
   ```
2. Trouver l'IP du host joignable par les VM : `ipconfig` → adaptateur *VMware Network Adapter* sur
   `192.168.10.x` (souvent `192.168.10.1`). Vérifier depuis une VM : `Test-NetConnection <ip-host> -Port 8700`.
3. Planifier la collecte sur la VM avec envoi direct :
   ```powershell
   # PowerShell ELEVÉ, sur la VM
   .\Register-MadscCollector.ps1 -PostUrl http://192.168.10.1:8700/ingest -IntervalHours 12
   # test ponctuel : .\Collect-Protocols.ps1 -PostUrl http://192.168.10.1:8700/ingest
   ```

**B. Fichier + auto-scan** (si un dossier est accessible des deux côtés : partage, USB…)

1. Collecte planifiée : `.\Register-MadscCollector.ps1 -OutDir <dossier> -IntervalHours 12`
2. MADSC scanne `data/snapshots/` tout seul :
   ```powershell
   $env:MADSC_SCAN_INTERVAL = "300"   # secondes (défaut 300 ; 0 = désactivé)
   uvicorn backend.main:app --port 8700
   ```

> **Rollback collecte** : `.\Register-MadscCollector.ps1 -Remove`. Le seul changement local est une tâche
> planifiée (bénin, réversible) ; le code reste **100 % lecture**, **aucun écrit AD**.

→ Résultat : **collecte + ingestion sans intervention**. L'admin ouvre le dashboard par exception
(dérive ou, en phase 3, alerte Wazuh critique). Effort quotidien ≈ **zéro**.

---

## 8. Contrat de données — schéma du snapshot JSON  ⚠️ (à respecter pour toute extension)

Un collecteur produit **un fichier JSON par exécution**, conforme au modèle `backend/models.py::Snapshot` :

```json
{
  "host": "DC-01",
  "role": "DC",                       // "DC" | "MEMBER" | "WORKSTATION"
  "collector": "Collect-Protocols",
  "collector_version": "1.0",
  "collected_at": "2026-07-31T12:00:00Z",   // ISO 8601 UTC
  "controls": [
    {
      "control_id": "PROTO-LDAP-SIGNING",     // doit exister dans backend/controls.py::CATALOG
      "observed": { "LDAPServerIntegrity": 2 },// clés = celles de `expected` du catalogue
      "raw": "HKLM\\...\\LDAPServerIntegrity"  // optionnel : provenance/preuve
    }
  ]
}
```

**Règles :**
- `observed` porte des **valeurs brutes** (int/bool/string). L'évaluation (PASS/FAIL) est **centralisée dans
  le backend** (`controls.py` définit `expected`) — le collecteur reste « bête » et ne juge pas.
- Les **clés de `observed`** doivent correspondre exactement aux clés de `expected` du contrôle.
- Une valeur absente → mettre `null` (le backend classera `NON ÉVALUÉ`).
- `collected_at` en **UTC ISO 8601** (`yyyy-MM-ddTHH:mm:ssZ`).

---

## 9. Catalogue de contrôles (`backend/controls.py`)

Chaque contrôle est relié à la **matrice ISO 27001** du projet (`risk_ref = R-xx`) et à un contrôle Annexe A.

| control_id | Contrôle | ISO | risk_ref | expected |
|---|---|---|---|---|
| PROTO-LDAP-SIGNING | Signature LDAP requise (DC) | A.8.5, A.8.20 | R-07 | `LDAPServerIntegrity=2` |
| PROTO-SMB-SIGNING-SERVER | Signature SMB serveur | A.8.20/21 | R-06 | `RequireSecuritySignature=1` |
| PROTO-SMB-SIGNING-CLIENT | Signature SMB client | A.8.20/21 | R-06 | `RequireSecuritySignature=1` |
| PROTO-SMBv1-DISABLED | SMBv1 désactivé | A.8.8, A.8.20 | R-06 | `EnableSMB1Protocol=false` |
| PROTO-NTLMv2-ONLY | NTLMv2 uniquement | A.5.17, A.8.5 | R-08 | `LmCompatibilityLevel=5` |
| PROTO-NOLMHASH | Hash LM désactivé | A.5.17, A.8.5 | R-08 | `NoLMHash=1` |
| PROTO-LLMNR-DISABLED | LLMNR désactivé | A.8.20/21/22 | R-11 | `EnableMulticast=0` |
| PRIV-DOMAIN-ADMINS | Membres Admins du domaine (RID 512) | A.5.15, A.8.2 | R-01 | *baseline-only* |
| PRIV-ENTERPRISE-ADMINS | Membres Admins de l'entreprise (RID 519) | A.5.15, A.8.2 | R-01 | *baseline-only* |
| PRIV-SCHEMA-ADMINS | Membres Admins du schéma (RID 518) | A.5.15, A.8.2 | R-01 | *baseline-only* |
| PRIV-BUILTIN-ADMINS | Membres Administrateurs intégré (S-1-5-32-544) | A.5.15, A.8.2 | R-01 | *baseline-only* |
| PRIV-GG-T0-ADMINS | Membres GG_T0_Admins | A.5.15, A.8.2, A.5.18 | R-01 | *baseline-only* |
| AD-MAQ | MachineAccountQuota = 0 | A.5.15, A.8.2 | R-14 | `ms-DS-MachineAccountQuota=0` |
| SVC-PRINT-SPOOLER-DC | Print Spooler désactivé (DC) | A.8.20, A.8.8 | R-09 | `StartType=Disabled` |
| AD-RECYCLE-BIN | Corbeille AD activée | A.8.14, A.8.24 | R-13 | `RecycleBinEnabled=true` |
| AUDIT-ADVANCED-POLICY | Politique d'audit avancée | A.8.15, A.8.16 | R-10 | *baseline-only* |

> **Contrôles baseline-only** (`expected=None`, ex. composition de groupes) : pas de valeur attendue fixe.
> Après `POST /baseline/approve`, toute modification de composition ressort en **CHANGÉ** (ex. un membre
> ajouté aux Admins du domaine — miroir de la règle de détection Wazuh `100037`). Sans baseline : `NON ÉVALUÉ`.

Structure d'une entrée du catalogue :
```python
"PROTO-LDAP-SIGNING": {
    "name": "...", "category": "Protocoles",
    "iso": "A.8.5, A.8.20", "risk_ref": "R-07", "severity": "Élevé",
    "applies_to": "dc",                 # "dc" (DC only) | "all"
    "expected": {"LDAPServerIntegrity": 2},
    "remediation": "GPO_DC_LDAP_Signing_Required ...",
}
```

---

## 10. Moteur d'évaluation & statuts (`backend/evaluate.py`)

Pour chaque contrôle du snapshot : recherche dans `CATALOG`, compare `observed` à `expected`.

| Statut | Sens |
|---|---|
| `PASS` (CONFORME) | toutes les valeurs observées = attendues |
| `FAIL` (DÉRIVE) | au moins une valeur ≠ attendue |
| `CHANGED` (CHANGÉ) | la valeur a **dérivé** depuis la baseline approuvée (affiche avant → après) |
| `NOT_EVALUATED` | valeur non collectée / absente |
| `NOT_APPLICABLE` | contrôle non applicable à cet hôte (ex. `applies_to="dc"` sur un membre) |

---

## 11. Endpoints API (`backend/main.py`)

| Méthode | Route | Rôle |
|---|---|---|
| GET | `/health` | état + nombre de snapshots |
| POST | `/ingest` | ingère **un** snapshot (corps = schéma `Snapshot`) |
| POST | `/ingest/scan` | ingère tous les JSON **nouveaux** de `data/snapshots/` (mode fichier, idempotent) |
| POST | `/baseline/approve` | fige la posture courante comme **baseline approuvée** (référence de dérive) |
| GET | `/api/baseline` | baseline approuvée (JSON) |
| GET | `/api/posture` | posture courante (JSON) : dernier résultat par (hôte, contrôle) |
| GET | `/api/proofs` | preuves + remédiations par contrôle, hash SHA-256 (phase 2c) |
| GET | `/api/wazuh/status` · `/agents` · `/alerts` | connecteur Wazuh lecture seule (phase 3) |
| GET | `/api/priorities` | Top 3 actions + risques métier (phase 4a) |
| GET | `/api/purpleteam` | registre Purple Team + occurrences live (phase 4b) |
| GET | `/report/direction` · `/report/technique` | rapports PDF direction/technique (phase 5) |
| GET | `/` | dashboard HTML — vue via `?view=` (`dashboard`, `compliance`, `purple`, `mitre`, `wazuh`, `alerts`, `reports`) |
| GET | `/dashboard/api/data` | payload JSON complet du dashboard (mêmes données que `/`) |

---

## 12. Structure des fichiers

```
MADSC/
├─ README.md                 ← ce document (handoff)
├─ requirements.txt          ← dépendances pip (Python 3.11+)
├─ setup.ps1                 ← bootstrap venv + install (nouveau PC)
├─ .gitignore
├─ backend/
│   ├─ __init__.py
│   ├─ main.py               ← FastAPI : endpoints + dashboard HTML (4 onglets)
│   ├─ models.py             ← schéma pydantic Snapshot / ControlObservation
│   ├─ controls.py           ← CATALOGUE des contrôles (mapping ISO R-xx)
│   ├─ evaluate.py           ← moteur PASS/FAIL/CHANGED/NON ÉVALUÉ/N-A + hash SHA-256
│   ├─ db.py                 ← SQLite (snapshots, control_results, baseline, ingested_files)
│   ├─ wazuh.py              ← connecteur API Wazuh lecture seule (phase 3)
│   ├─ priorities.py         ← Top 3 actions + risque métier (phase 4a)
│   ├─ purpleteam.py         ← registre Purple Team + couverture MITRE (phase 4b)
│   ├─ report.py             ← génération PDF direction/technique via fpdf2 (phase 5)
│   └─ charts.py             ← graphiques SVG (donut, barre) générés côté serveur, sans dépendance
├─ collectors/
│   ├─ Collect-Protocols.ps1        ← LECTURE SEULE : protocoles (LDAP/SMB/NTLM/LLMNR)
│   ├─ Collect-PrivilegedGroups.ps1 ← LECTURE SEULE : groupes privilégiés (DC, ADSI/LDAP, sans ADWS)
│   ├─ Collect-ADConfig.ps1         ← LECTURE SEULE : MAQ, Print Spooler, Corbeille AD (DC, ADSI)
│   ├─ Collect-AuditPolicy.ps1      ← LECTURE SEULE : politique d'audit (auditpol /backup, colonne numérique)
│   ├─ Collect-TierBoundaries.ps1   ← LECTURE SEULE : 5 droits SeDeny*LogonRight (secedit, par SID)
│   ├─ Collect-LocalAdmins.ps1      ← LECTURE SEULE : administrateurs locaux / chaîne AGDLP (ADSI WinNT)
│   ├─ Collect-LAPS.ps1             ← LECTURE SEULE : CSE, politique, rotation (le secret n'est JAMAIS lu)
│   ├─ Collect-PasswordPolicy.ps1   ← LECTURE SEULE : politique domaine, PSO Tier 0, non-expiration (DC)
│   ├─ Collect-Delegation.ps1       ← LECTURE SEULE : délégation Kerberos, SPN utilisateur, adminCount (DC)
│   ├─ Collect-PowerShellLogging.ps1← LECTURE SEULE : Script Block + Module Logging
│   └─ Register-MadscCollector.ps1  ← enregistre un collecteur en tâche planifiée (auto, réversible -Remove)
├─ dashboard/
│   ├─ controllers/dashboard_controller.py ← rendu des vues (dont la page Compliance)
│   ├─ services/dashboard_service.py       ← agrégation (score, conformité, MITRE, Wazuh)
│   ├─ data/                               ← catégories de score + contrôles prévus non instrumentés
│   └─ static/css|js/                      ← dashboard.css + compliance.css / compliance.js (page Compliance)
└─ data/
    ├─ madsc.db              ← base SQLite (auto-créée ; ignorée par git)
    ├─ snapshots/            ← les JSON à ingérer atterrissent ici (auto-scan)
    │   ├─ sample-DC-01.json ← échantillon DC (protocoles)
    │   ├─ sample-DC-01-adconfig.json ← échantillon config AD
    │   ├─ sample-DC-01-audit.json    ← échantillon politique d'audit
    │   └─ sample-WS-01.json ← échantillon poste
    └─ baseline/             ← (phase 2) baseline approuvée pour le diff
```

---

## 13. Comment étendre (pour un dev ou une IA)

### Ajouter un CONTRÔLE
1. Ajouter une entrée dans `backend/controls.py::CATALOG` (avec `expected`, `iso`, `risk_ref`, `applies_to`).
2. Faire en sorte qu'un collecteur émette `control_id` + `observed` (mêmes clés que `expected`).
3. Rien d'autre : l'évaluation et l'affichage sont génériques.

> **Contrôle baseline-only** : mettre `expected: None`. La conformité est alors jugée par la **dérive** vs
> baseline (sans baseline → `NON ÉVALUÉ` ; égal à la baseline → `CONFORME` ; différent → `CHANGÉ`). Pour les
> valeurs de type liste (membres), le collecteur doit émettre une valeur **déterministe** (ex. liste **triée**
> jointe en chaîne) pour éviter les fausses dérives dues à l'ordre.

### Ajouter un COLLECTEUR (nouvelle famille de contrôles)
1. Créer `collectors/Collect-<Famille>.ps1`, **lecture seule uniquement** (`Get-*`, lecture registre/AD).
2. Émettre le schéma snapshot (§8) avec les `control_id` de la nouvelle famille.
3. Exécuter sur la VM → copier le JSON dans `data/snapshots/` → `POST /ingest/scan` (ou `-PostUrl`).

> **Règle d'or : aucun collecteur ni le backend ne doit JAMAIS écrire dans l'AD.** Uniquement des lectures.
> Interdits : `Set-*`, `Remove-*`, `New-AD*`, `dsacls` en écriture, modification de GPO/registre.

> ⚠️ **Éviter le module `ActiveDirectory` (`Get-AD*`)** : il dépend du service **ADWS** (port 9389), souvent
> arrêté/instable sur ce lab (constaté sur DC-01). Pour interroger l'AD, préférer **ADSI/LDAP** (`[ADSI]`,
> `System.DirectoryServices.DirectorySearcher`) — port 389, **indépendant d'ADWS et sans aucun module**.
> Modèle de référence : `Collect-PrivilegedGroups.ps1` (résolution par SID, membres récursifs via IN_CHAIN).

---

## 14. Feuille de route détaillée

| Phase | Contenu | Statut |
|---|---|---|
| **1 — Socle posture** | Backend FastAPI + SQLite, moteur d'évaluation, dashboard, ingestion fichier, collecteur protocoles (7 contrôles), échantillon. | ✅ **FAIT & testé** |
| **1.5 — Automatisation** | Auto-scan du dossier snapshots (tâche de fond, `MADSC_SCAN_INTERVAL`) + `Register-MadscCollector.ps1` (tâche planifiée lecture seule, réversible). Modèle hands-off : l'admin n'agit que par exception. | ✅ **FAIT & testé** |
| **2a — Moteur de dérive** | Baseline approuvée (`POST /baseline/approve`, table SQLite `baseline`) + détection **`CHANGED`** (avant → après) à chaque collecte. | ✅ **FAIT & testé** |
| **2b — Catalogue étendu** | 16 contrôles. **Fait :** groupes privilégiés (`R-01`, `Collect-PrivilegedGroups.ps1`), config AD & services (`AD-MAQ` `R-14`, `SVC-PRINT-SPOOLER-DC` `R-09`, `AD-RECYCLE-BIN` `R-13`, `Collect-ADConfig.ps1`), politique d'audit avancée (`AUDIT-ADVANCED-POLICY` `R-10`, `Collect-AuditPolicy.ps1`). | ✅ **FAIT & testé** |
| **2c — Centralisation des preuves & remédiation** | Vue « preuve » par contrôle : hôte, source (`raw`), date (`collected_at`), commande de collecte, valeur observée, **action de remédiation** (`remediation` du catalogue) ; chaîne **contrôle → risque ISO → preuve → recommandation** ; API `/api/proofs` ; empreinte SHA-256 d'intégrité. | ✅ **FAIT & testé** |
| **3 — Connecteur Wazuh (temps réel alertes)** | Client **lecture seule** de l'API Wazuh (`https://192.168.10.40:55000`, user `wazuh-wui`). Santé des agents (`SAIN`/`DÉGRADÉ`/`NON SURVEILLÉ`), synthèse alertes via `/manager/stats` (fallback `/alerts` 404). Enrichissement MITRE ATT&CK (19 règles custom mappées `100030`→`100054` + Sysmon/intégrées). JWT auto-renew + tolérance aux pannes + bandeau de secours. | ✅ **FAIT & testé** |
| **UI — Refonte light mode (v0.4)** | Interface **thème clair** professionnelle + onglet **Vue d'ensemble** (data-viz **SVG** générée côté serveur via `charts.py` : donuts conformité & Purple Team, barres de répartition, cartes par hôte). 5 onglets, lignes dépliables, sans dépendance externe (marche hors-ligne). *(A remplacé une v1 glassmorphism dark jugée peu lisible.)* | ✅ **FAIT & testé** |
| **4a — Risque métier & Top 3 actions** | En tête de l'onglet Posture : **Top 3 actions prioritaires** (classées par sévérité, avec remédiation) + **risque métier** (impact hôtel par `risk_ref`). Module `backend/priorities.py` ; API `/api/priorities`. | ✅ **FAIT & testé** |
| **4b — Registre Purple Team & MITRE** | 4e onglet : **registre des 15 scénarios** attaque ↔ règle Wazuh ↔ MITRE ↔ statut (validé live / test négatif / déployé non validé / hors périmètre) + **heatmap MITRE ATT&CK** par tactique + **occurrences live** (compteurs Wazuh). Module `backend/purpleteam.py` ; API `/api/purpleteam`. Registre, **pas** un lanceur d'attaques. | ✅ **FAIT & testé** |
| **5 — Rapports PDF** | Rapport **direction** (synthèse sans jargon : conformité, Top 3, risque métier, couverture) et rapport **technique** (contrôles, observé/attendu, preuve+hash, registre Purple Team). Génération **PDF** via `fpdf2` (`backend/report.py`) ; endpoints `/report/direction` et `/report/technique` (liens en pied de dashboard). | ✅ **FAIT & testé** |

### Besoins fonctionnels (Vision Finale) → phases

Vérification que **rien de la vision n'est oublié** :

| Besoin fonctionnel (Vision Finale) | Phase(s) | Statut |
|---|---|---|
| 1. Collecter l'état de sécurité (PowerShell lecture seule → JSON) | 1, 2b | ✅ fait |
| 2. Détecter la dérive (baseline ; PASS / FAIL / CHANGÉ) | 2a | ✅ fait |
| 3. Centraliser les preuves (contrôle → risque ISO → preuve → recommandation ; source/date/commande/valeur/hash) | 1, 2c | ✅ fait |
| 4. Exploiter Wazuh (API lecture seule, santé agents, contexte MITRE) | 3 | ✅ fait |
| 5. Suivre la validation Purple Team (registre + matrice MITRE) | **4b** | ✅ fait |
| 6. Rapporter (direction + technique, PDF) | 5 | ✅ fait |

**Hors périmètre** (repris de la Vision Finale, à ne jamais implémenter) : aucun DCSync/Kerberoasting lancé
depuis le web ; pas de remplacement de Wazuh/PingCastle/BloodHound ; pas de faux « temps réel » sur les
contrôles AD ; pas de score opaque (conformité / couverture / télémétrie restent séparées).

**MVP à démontrer (jury)** : dashboard glassmorphism 3 onglets (posture/Wazuh/preuves ISO) + catalogue 16 contrôles
**avec preuves & remédiation** + ingestion JSON live + connecteur Wazuh lecture seule avec MITRE ATT&CK
+ rapport PDF de synthèse.

---

## 15. Principes de conception & contraintes (à ne pas violer)

1. **Lecture seule totale.** Aucun écrit dans l'AD, jamais. C'est la garantie « sans rien casser ».
2. **Pas de faux temps réel sur la posture.** Les contrôles de config sont périodiques/à la demande ; seul le
   flux d'**alertes Wazuh** est temps réel.
3. **Preuve-first.** Chaque contrôle porte sa provenance (`raw`), son mapping ISO et sa valeur observée.
4. **Pas de score opaque.** Garder conformité / couverture / télémétrie **séparées**.
5. **Dev sur host, test sur VM.** On développe sur le PC de dev ; les VM ne font que produire des snapshots.
6. **Contrainte RAM du lab** (Kali 4 Go) : garder MADSC léger ; API Wazuh en lecture seule, pas de charge.
7. **Statuts honnêtes** (repris de la discipline du projet) : ne jamais afficher « OK » sans preuve.

---

## 16. État actuel (au 1er août 2026)

**Toutes les phases sont construites et testées sur le host** (1, 1.5, 2a, 2b, 2c, 3, 3.5, 4a, 4b, 5) :
- ✅ Socle (posture, auto-scan, dérive baseline) ; 16 contrôles (protocoles, groupes privilégiés, config AD, audit).
- ✅ Preuves + hash SHA-256 + remédiation (`/api/proofs`).
- ✅ Connecteur Wazuh lecture seule (agents + alertes MITRE), tolérant aux pannes.
- ✅ Rapports PDF direction + technique (`/report/*`).

### Sprint 0 — fiabilité (fait, 1er août 2026)

Correctifs et nettoyages appliqués, tous vérifiés :

- ✅ **`Collect-AuditPolicy.ps1` — le contrôle d'audit ne prouvait rien.** Le filtre « pas d'audit »
  comparait un libellé localisé avec une apostrophe typographique (`’`) et ne skippait que l'en-tête
  anglais `Node Name*` : **toutes** les sous-catégories étaient comptées comme auditées, en-tête
  comprise. La décision se prend désormais sur la colonne **`Setting Value` numérique**
  (0/1/2/3) — indépendante de la langue, de l'apostrophe et de l'encodage. Vérifié sur jeux FR et EN.
- ✅ **Dérive figée après ré-approbation de baseline.** La dérive est une fonction de
  (observé, baseline *courante*) : elle est maintenant **résolue à la lecture**
  (`evaluate.resolve_drift` + `db.latest_posture`) et non plus gelée à l'ingestion. Trois faux
  positifs permanents ont disparu. La ligne stockée reste intacte comme piste d'audit.
- ✅ **Tendance du score non comparable.** `posture_history` groupait par horodatage exact, donc
  **un point par collecteur** (calculé tantôt sur 1 contrôle, tantôt sur 7). Regroupement par
  **campagne de collecte** (fenêtre de 10 min, dernier statut par hôte/contrôle).
- ✅ **Encodage.** `-Encoding ASCII` → `utf8` (`Collect-ADConfig`, `Collect-AuditPolicy`) et
  alignement de `[Console]::OutputEncoding` sur la page OEM le temps de l'appel `auditpol`
  (les accents finissaient en caractères de remplacement jusque dans la base et le PDF).
- ✅ **Secret retiré du code.** Plus aucun mot de passe en dur ni repli `admin/admin` :
  `WAZUH_PASSWORD` est **requis**, sinon message explicite. Supprime aussi la rafale de 401
  envoyée au manager Wazuh à chaque démarrage — et rend `/` instantané quand Wazuh est
  injoignable (plus de boucle de fallbacks × timeout).
- ✅ **TLS explicite.** `WAZUH_VERIFY_TLS` (défaut `0`) : l'exception de laboratoire
  (certificat auto-signé) est déclarée et activable, plus silencieuse.
- ✅ **Compteurs ≠ alertes.** `/manager/stats` renvoie des **compteurs cumulés** sans date ni
  agent : ils ne sont plus affichés comme des « dernières alertes » horodatées avec un agent
  inventé (`kind="rule_counter"`, panneau et KPI renommés).
- 🧹 **Code mort supprimé** : ~410 lignes d'ancienne UI dans `main.py`, routes `/legacy` et
  `/dashboard`, stubs `dashboard/data/{alerts,purple_validation}.json`. Les helpers SVG sont
  regroupés dans **un seul** module `backend/charts.py` (`ring` / `trend` / `radar`).

**Restes connus :**
- 🔴 **Rotation** du compte Wazuh utilisé jusqu'ici : son mot de passe est **dans l'historique git**
  (commit initial). Le retirer du code ne le retire pas de l'historique.
- 🟠 `PMS-01` n'est pas encore collecté alors que les collecteurs (registre + LDAP) **ne dépendent
  pas du service EventLog** corrompu : c'est l'angle mort SIEM `RR-08` que MADSC peut couvrir.
- 🟠 Les contrôles `LAPS`, `PowerShell logging`, `Protected Users` sont affichés `N/A` alors qu'ils
  sont **déployés et prouvés** en Phase C → collecteurs à écrire (Sprint 1).
- 🟠 Le **score composite** (`dashboard_service.get_security_score`) contredit le principe §15.4
  « pas de score opaque » et il est **de polarité inverse à PingCastle** (86/100 = bien ici,
  25/100 = bien là-bas) : à afficher avec sa formule, ou à retirer.
- 🟡 `WS-01` : la posture affichée provient encore de l'**échantillon** livré, pas d'une collecte réelle.
- ⏳ Aucun test automatisé (`pytest`) : le défaut de dérive ci-dessus aurait été détecté par un test.

---

## 17. Liens avec les autres livrables du projet

Dans le dossier parent (`../`) :
- `PROJECT_CONTEXT.md` — source de vérité de tout le projet.
- `COMPTE_RENDU_DETECTION_PHASE_D.md` — détail du SIEM Wazuh + 16 règles (base du connecteur phase 3).
- `MATRICE_ISO27001_MOGADOR.md` — matrice de risques `R-01`→`R-19` (sourc