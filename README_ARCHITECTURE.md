# MADSC — Architecture, évolution et travaux futurs

**Projet :** Mogador Active Directory Security Center — PFA Purple Team, domaine `mogador.local`
**Objet :** ce qui a été construit, **pourquoi** l'architecture est ainsi, et ce qui reste à faire.
**État du document :** 2 août 2026 — état vérifié en laboratoire sur les trois hôtes réels.
**Reprise du projet :** voir [`HANDOFF.md`](HANDOFF.md) pour repartir sans contexte préalable.
**Documents liés :** [`README.md`](README.md) (prise en main), `../PROJECT_CONTEXT.md` (source de vérité du projet), `../MATRICE_ISO27001_MOGADOR.md` (registre de risques `R-01`→`R-19`).

> Ce document complète le README de prise en main. Le README dit *comment lancer* MADSC ;
> celui-ci dit *ce qu'il fait, pourquoi il est construit ainsi, et ce qu'il ne fait pas encore*.

---

## 1. Ce que MADSC est — et n'est pas

Le durcissement (Phase C) et la détection (Phase D) répondent à la question *« l'annuaire est-il
sécurisé aujourd'hui ? »*. Ils n'y répondent qu'**une fois**, le jour de la validation.

MADSC répond à la question suivante, celle qui compte pour l'administrateur unique d'un hôtel :

> **« Mon Active Directory est-il toujours dans l'état durci qui a été validé, ou a-t-il dérivé ? »**

| MADSC **est** | MADSC **n'est pas** |
|---|---|
| une console de posture et de dérive, 100 % lecture | un remplaçant de Wazuh / PingCastle / BloodHound |
| un consommateur d'outils existants (Wazuh en lecture seule) | un lanceur d'attaques |
| une chaîne de preuve : contrôle → risque ISO → preuve → remédiation | un outil qui écrit dans l'AD |
| un état périodique, à la demande | un faux « temps réel » sur la configuration |

**Complémentarité avec la Phase D :** Wazuh détecte un **événement** (« quelqu'un vient d'ajouter
un compte aux Admins du domaine », règle `100037`). MADSC constate un **état** (« la composition
du groupe diffère de la référence approuvée »). Une attaque manquée par le SIEM — agent arrêté,
canal non collecté, machine hors ligne au mauvais moment — laisse malgré tout une trace de
configuration que MADSC voit à la collecte suivante. C'est l'argument de défense en profondeur :
`PMS-01` est un angle mort SIEM assumé (`RR-08`, service EventLog corrompu), **mais MADSC le
couvre**, car ses collecteurs lisent le registre et LDAP, pas le journal d'événements.

---

## 2. Point de départ — l'audit du 1er août 2026

Avant les travaux décrits ici, MADSC était fonctionnel mais présentait des défauts qui
**contredisaient la discipline du projet** (« ne jamais afficher OK sans preuve ») :

| # | Défaut constaté | Conséquence réelle |
|---|---|---|
| 1 | `Collect-AuditPolicy.ps1` filtrait le libellé localisé « Pas d'audit » avec une apostrophe typographique (`’`) et ne sautait que l'en-tête anglais | **Toutes** les sous-catégories comptées comme auditées, en-tête comprise (« 61 actives » au lieu de 23). Le seul contrôle de `R-10` affichait CONFORME sans rien prouver. |
| 2 | La dérive était figée à l'ingestion | Ré-approuver la baseline ne nettoyait pas les `CHANGED` : **3 faux positifs permanents**, sur un projet dont l'indicateur phare est « FP = 0 ». |
| 3 | `posture_history` groupait sur l'horodatage exact | Chaque collecteur produisait son propre point de tendance, calculé tantôt sur 1 contrôle tantôt sur 7 → **courbe non comparable**. |
| 4 | Mot de passe Wazuh en dur + repli `admin/admin`, `wazuh/wazuh` | Secret dans le code **et dans l'historique git** ; rafale de 401 vers le manager à chaque démarrage ; `/` très lent quand Wazuh est injoignable. |
| 5 | `/manager/stats` présenté comme des « dernières alertes » | Horodatage et agent **inventés** (`now`, `"DC-01 / WS-01"`) pour des compteurs cumulés. |
| 6 | Encodage `ASCII` + page de codes console | Accents détruits jusque dans la base, le tableau de bord et le PDF — donc dans l'empreinte SHA-256 censée garantir l'intégrité. |
| 7 | Le tableau de bord lisait une liste d'IDs figée | **SMBv1, tiering, administration locale invisibles** de la page d'accueil. |
| 8 | Agrégation : tout ce qui n'était ni FAIL ni CHANGED → PASS | Un contrôle **jamais collecté** s'affichait CONFORME. |
| 9 | ~410 lignes d'ancienne interface morte dans `main.py` | Dette de lecture pour un dépôt destiné à être repris. |

---

## 3. Sprint 0 — fiabilité

Objectif : **rien de faux à l'écran**. Aucun ajout de fonctionnalité.

- **Analyse d'audit robuste.** `auditpol /get /r` est *localisé* et, en français, ne comporte
  **que six colonnes, sans valeur numérique**. Bascule sur `auditpol /backup`, format d'échange
  machine qui expose la colonne numérique `Setting Value` (0/1/2/3). Décision insensible à la
  langue, à l'apostrophe et à l'encodage. *(Le fichier CSV temporaire est supprimé après lecture.)*
- **Dérive résolue à la lecture** (§5.1).
- **Tendance par campagne de collecte** (fenêtre de 10 min, dernier statut par hôte/contrôle).
- **Aucun secret dans le code.** `WAZUH_PASSWORD` requis, message explicite si absent, plus
  aucun repli. Effet de bord mesuré : quand Wazuh est injoignable, `/` se rend en **0,016 s** au
  lieu de subir la boucle d'identifiants × délai d'expiration (4 essais × 8 s au pire).
- **TLS explicite.** `WAZUH_VERIFY_TLS` (défaut `0`) : l'exception de laboratoire est déclarée
  et activable, plus silencieuse.
- **Compteurs ≠ alertes.** `kind="rule_counter"`, `timestamp=None`, `agent=None` ; le panneau se
  renomme « Compteurs de règles (cumul) ».
- **Nettoyage.** ~410 lignes d'UI morte, routes `/legacy` et `/dashboard`, deux fichiers JSON
  orphelins ; les aides SVG regroupées dans un **seul** `backend/charts.py`.
- **Hôte fantôme supprimé.** Le poste réel se déclare `DESKTOP-0LKLBTR` ; les lignes `WS-01`
  provenaient du **fichier d'échantillon** livré avec le dépôt et se seraient retrouvées figées
  dans la baseline. Base sauvegardée avant suppression.

## 4. Sprint 1 — couverture

Six collecteurs, seize contrôles, quatre risques du registre ISO passés de *non surveillés* à
*vérifiés en continu* (**R-02, R-03, R-04, R-05**).

| Collecteur | Contrôles | Risque | Ce qu'il rend visible |
|---|---|---|---|
| `Collect-TierBoundaries.ps1` | `TIER-DENY-LOGON-COVERAGE`, `TIER-DENY-LOGON-PRINCIPALS` | **R-03** | les cinq droits `SeDeny*LogonRight` effectifs, par SID |
| `Collect-LocalAdmins.ps1` | `LOCAL-ADMINS-MEMBERS`, `LOCAL-ADMINS-NO-DIRECT-USERS` | **R-02** | la chaîne AGDLP tient-elle encore sur chaque machine |
| `Collect-LAPS.ps1` | `LAPS-CSE-INSTALLED`, `LAPS-POLICY-EFFECTIVE`, `LAPS-MANAGED-COVERAGE` | **R-02** | LAPS *configuré* **et** *réellement en train de tourner* |
| `Collect-PasswordPolicy.ps1` | `PWD-DOMAIN-POLICY`, `PWD-PSO-T0`, `PWD-NO-NEVER-EXPIRES` | **R-04** | politique du domaine, PSO Tier 0, comptes sans expiration |
| `Collect-Delegation.ps1` | `DELEG-UNCONSTRAINED`, `DELEG-CONSTRAINED`, `KRB-USER-SPN`, `ADMINCOUNT-RESIDUAL` | **R-05**, R-14, R-01 | délégation Kerberos et surface Kerberoasting |
| `Collect-PowerShellLogging.ps1` | `LOG-PS-SCRIPTBLOCK`, `LOG-PS-MODULE` | **R-10** | les sources qui alimentent les règles Wazuh `100041` / `4103` |
| `Collect-DetectionSensors.ps1` | `SENSOR-EVENTLOG`, `SENSOR-WAZUH-AGENT`, `SENSOR-SYSMON`, `SENSOR-AUDIT-SACL` | **R-18** | si les capteurs du SIEM sont encore vivants (voir §5.12) |

Deux points de conception valent d'être signalés :

- **`PWD-PSO-T0` vérifie un PSO, pas une GPO.** Une GPO liée à une OU ne crée pas de politique de
  mot de passe distincte pour des comptes du domaine — c'était le défaut de l'ancienne
  `T0_PasswordPolicy`, remplacée en Phase C par `PSO_T0_Privileged_Admins`.
- **`LOG-PS-*` protège la détection elle-même.** Si la journalisation PowerShell retombe, la règle
  Wazuh `100041` devient muette **sans qu'aucune alerte ne le signale**. Un contrôle de posture est
  le seul moyen de voir un capteur s'éteindre.

---

## 4bis. Refonte de la page Compliance (présentation uniquement)

La page listait les contrôles à plat, machine après machine : impossible de comparer un même
contrôle entre les trois hôtes, ni de répondre d'un coup d'œil à « qu'est-ce qui ne va pas, et
où ? ». Elle a été refondue en **matrice contrôles × hôtes**, sans toucher à la logique métier.

- **Indicateurs globaux** (score, hôtes, conformes, écarts, baseline avec date d'approbation).
- **Une carte par hôte** : rôle, pourcentage, compteurs, dernière collecte, état de santé.
  Un clic filtre la matrice ; un second clic annule le filtre.
- **Matrice triable** à en-tête figé : une ligne par contrôle, une colonne par hôte.
- **Recherche, filtre par catégorie, filtre par hôte** — entièrement côté client, sans rechargement.
- **Tiroir de détail** : valeur observée/attendue, baseline, collecteur, source de preuve,
  empreinte SHA-256, risque métier, recommandation, référence ISO et **historique de statut**.

Trois choix de conception méritent d'être notés :

1. **Les lignes sont rendues par le serveur**, le JavaScript ne fait que masquer, réordonner et
   détailler. La page reste lisible sans JavaScript, et aucune donnée n'est fabriquée côté client.
2. **Le détail est embarqué dans la page** sous forme de bloc JSON : pas de nouvel endpoint d'API,
   pas d'appel réseau au clic.
3. **Feuille de style dédiée et préfixée `cmp-`** : `dashboard.css` n'est pas modifié, donc aucune
   autre vue ne peut être affectée par cette refonte.

Le champ « niveau de confiance » demandé par la maquette de référence est affiché
**« Non disponible »** : aucun collecteur ne produit un tel indicateur, et en fabriquer un
contredirait la règle qui structure tout le projet.

## 5. Décisions d'architecture — et leur justification

### 5.1 La dérive est calculée à la LECTURE, pas figée à l'ingestion

La dérive n'est pas une propriété du snapshot : c'est une fonction de **(valeur observée,
baseline courante)**. Figée à l'ingestion, elle survivait à une ré-approbation de baseline et se
transformait en faux positif permanent.

`evaluate.resolve_drift()` est appliqué à chaque lecture dans `db.latest_posture()`. La ligne
stockée reste **intacte** : elle constitue la piste d'audit de ce qui était vrai au moment de la
collecte. Conséquence pratique : approuver une baseline nettoie l'écran **immédiatement**, sans
attendre une nouvelle collecte.

### 5.2 Deux contrôles par thème : attente fixe + baseline

C'est la décision la plus structurante. Pour chaque sujet sensible, MADSC pose **deux** contrôles :

| Type | Exemple | Détecte |
|---|---|---|
| **attente fixe** (`expected` défini) | `TIER-DENY-LOGON-COVERAGE = 5` | la disparition du contrôle, **même sans baseline approuvée** |
| **baseline seule** (`expected = None`) | `TIER-DENY-LOGON-PRINCIPALS` | la modification fine de l'état approuvé |

**Pourquoi les deux sont nécessaires** — démontré en test : retirer les groupes Tier 1 de la liste
de refus d'une machine Tier 2 laisse la couverture à un rassurant **5/5**. Seul le contrôle des
principaux voit la régression. Inversement, sur une installation neuve sans baseline, seul le
contrôle à attente fixe peut encore dire NON CONFORME. Un seul des deux serait aveugle la moitié
du temps.

### 5.3 Comparaison par SID, jamais par nom

Le domaine est en français : `Admins du domaine`, `Administrateurs (intégré)`. Les noms changent
d'une langue à l'autre et un groupe peut être renommé (le projet l'a fait : `Admins_T1` →
`GG_T1_Server_Admins`). Tous les contrôles d'appartenance et de droits comparent des **SID**, et
les groupes locaux intégrés sont ouverts par SID (`S-1-5-32-544`) puis traduits. C'est la même
discipline que l'analyse BloodHound du projet.

### 5.4 Applicabilité par rôle : `dc` / `member` / `all`

Un contrôleur de domaine ne doit **pas** refuser la connexion aux identités Tier 0 ; son groupe
« local » Administrateurs **est** le groupe intégré du domaine et contient légitimement le compte
`Administrateur` en direct. Sans la notion `member`, ces contrôles auraient produit des NON
CONFORME permanents et faux sur le DC. Le statut `NOT_APPLICABLE`, jusque-là inutilisé, porte
désormais une information : *« ce contrôle a été pensé pour cet hôte, et il ne s'y applique pas »*.

### 5.5 Le collecteur ne juge pas

Les scripts PowerShell renvoient des **valeurs brutes** ; toute l'évaluation (PASS / FAIL /
CHANGED) vit dans `backend/controls.py` et `backend/evaluate.py`. Ajouter un contrôle = une entrée
de catalogue + un collecteur qui émet la bonne clé. Rien d'autre à modifier.

### 5.6 Échec bruyant : ne jamais émettre une mesure inexistante

Règle appliquée à tous les collecteurs : **si la lecture échoue, aucun contrôle n'est émis**, et le
script affiche pourquoi (code retour, nombre de lignes, première ligne brute).

Cette règle a été écrite après une erreur réelle : la première version du collecteur d'audit
émettait `0 auditées / 0 total` quand `auditpol` ne renvoyait rien. Or « 0 sous-catégorie auditée »
ressemble à une catastrophe de sécurité, alors que la réalité était « je n'ai rien pu mesurer ».
Même logique pour `LOCAL-ADMINS` (un groupe Administrateurs vide est impossible en pratique) et
pour `LAPS-MANAGED-COVERAGE` (« 0 machine en retard » sur un périmètre vide serait un faux
CONFORME).

### 5.7 Le secret LAPS n'est jamais lu

`Collect-LAPS.ps1` lit **uniquement** `ms-Mcs-AdmPwdExpirationTime` (métadonnée non
confidentielle). L'attribut `ms-Mcs-AdmPwd` — le mot de passe administrateur local en clair —
n'est **même pas demandé au serveur** : il n'apparaît pas dans `PropertiesToLoad`, uniquement dans
les commentaires qui expliquent son exclusion.

Prouver que la rotation fonctionne n'exige pas de manipuler le secret. La Phase C avait justement
détecté une lecture inter-tier sur cet attribut précis : une console de supervision n'a aucune
raison de pouvoir le voir, même compromise.

### 5.8 Une date d'expiration, pas une simple présence

`LAPS-MANAGED-COVERAGE` n'exige pas qu'une valeur existe, mais qu'elle soit **dans le futur**.
Une expiration passée signifie que la machine a cessé de faire tourner son mot de passe : GPO qui
ne s'applique plus, extension absente, hôte hors ligne depuis longtemps. *Configuré* et *qui
fonctionne* sont deux affirmations différentes.

### 5.9 Le tableau de bord dérive du catalogue

Les contrôles affichés sont **construits à partir de `CATALOG`**. Auparavant, une liste d'IDs
maintenue à la main dans `compliance.json` décidait de ce qui apparaissait : SMBv1 n'y figurait
pas, et l'échec réel de `PMS-01` du 1er août n'est jamais apparu sur la page d'accueil. Désormais,
ajouter un contrôle au catalogue le rend visible automatiquement — il n'existe plus de second
endroit à tenir à jour. `get_security_score()` expose en outre `unmapped_controls` : tout contrôle
oublié d'une catégorie de pondération est signalé au lieu de peser silencieusement zéro.

### 5.10 Statuts honnêtes dans l'agrégation

`NOT_EVALUATED` devient **UNKNOWN**, jamais PASS. `NOT_APPLICABLE` est **neutre** entre hôtes (le
N/A du DC ne masque pas le résultat réel d'un membre). Un contrôle du catalogue jamais collecté
s'affiche *« Jamais collecté — collecteur non déployé ? »*. C'est la transposition à l'agrégation
de la discipline « statut jamais ambigu » de la Phase D.

### 5.11 La péremption ne peut que RETIRER de la confiance

Une mesure vieille de plusieurs jours ne prouve plus rien. Au-delà d'un seuil
(`MADSC_STALE_AFTER_HOURS`, 72 h par défaut — six cycles manqués avec la collecte planifiée
toutes les 12 h), la règle est **asymétrique et volontairement conservatrice** :

| État mesuré | Périmé devient | Pourquoi |
|---|---|---|
| CONFORME | **NON ÉVALUÉ** | on ne peut plus affirmer la conformité |
| NON CONFORME / DÉRIVE | **inchangé** | un écart reste un écart tant que rien ne prouve sa correction |
| N/A | **inchangé** | dépend du rôle de l'hôte, pas du temps |

Blanchir un écart parce que la donnée a vieilli serait le pire des comportements. Comme la
dérive, la fraîcheur est calculée **à la lecture** : elle dépend de l'instant présent, pas de
l'instant de la collecte. Un horodatage dans le futur (les instantanés de VM ont fait reculer
l'horloge du lab) est borné à un âge nul plutôt que traité comme anormal.

### 5.12 Un SIEM ne peut pas détecter sa propre cécité

C'est l'argument conceptuel le plus fort du projet, et il justifie à lui seul l'existence de MADSC
à côté de Wazuh.

> Si le paramètre qui alimente une règle de détection est désactivé, Wazuh ne dit pas « attention,
> je ne vois plus rien » : il **se tait**. Et ce silence ressemble exactement à « tout va bien ».
> Un administrateur qui ne voit aucune alerte pense que tout est sous contrôle, alors qu'en réalité
> le capteur est mort. **Wazuh lui-même ne peut pas faire la différence entre ces deux situations,
> puisque c'est précisément lui qui est aveugle.**

Un SIEM raisonne sur ce qu'il **reçoit**. Il n'a aucun moyen de raisonner sur ce qu'il **aurait dû**
recevoir. « Zéro alerte » a deux causes possibles — *rien ne s'est passé* et *je ne vois plus rien* —
et aucune donnée d'un SIEM ne les distingue. Seule une **vérification de configuration**, menée par
un canal indépendant, le peut.

Exemples mesurés dans ce laboratoire :

| Capteur coupé | Règles rendues muettes | Ce que Wazuh affiche |
|---|---|---|
| Service `EventLog` (cas réel de `PMS-01`) | **toutes**, sur cet hôte | rien d'anormal |
| Sous-catégorie *Other Object Access Events* | `100053` (tâches planifiées) | rien d'anormal |
| Script Block Logging | `100041` (PowerShell suspect) | rien d'anormal |
| SACL de réplication | `100033` (DCSync) | rien d'anormal |

`Collect-DetectionSensors.ps1` instrumente ces capteurs (service EventLog, agent Wazuh, Sysmon,
les trois SACL de la Phase D) et la page **Santé de la détection** en tire un verdict par hôte :
*Peut détecter* / *Partiellement aveugle* / *Aveugle*. C'est la seule page de la plateforme qui
répond à « puis-je encore détecter quoi que ce soit ? » plutôt qu'à « suis-je conforme ? ».

Conséquence sur la notation : la catégorie *Detection & Response* du score était calculée sur le
**taux de validation Purple Team** — un nombre figé dans le code, identique quel que soit l'état
réel du système. Elle est désormais calculée sur la **santé mesurée des capteurs**. Un capteur qui
tombe fait donc réellement baisser le score.

### 5.13 Distribution des collecteurs par HTTP

MADSC sert `collectors/` en lecture seule sur `/collectors`. Une VM récupère la version courante
d'un script en une commande, au lieu d'une copie manuelle sur trois machines. Motivation concrète :
le DC a été restauré depuis un ancien instantané et tournait avec des collecteurs périmés. Ces
scripts ne contiennent aucun secret et sont eux-mêmes 100 % lecture.

---

## 6. Résultats vérifiés

**État au 2 août 2026 — 36 contrôles, 3 hôtes, 70 lignes de posture : 64 CONFORME, 4 N/A,
2 NON CONFORME (capteurs de `PMS-01`, voir ci-dessous), 0 DÉRIVE.**

| Indicateur | Avant | Après |
|---|---:|---:|
| Contrôles au catalogue | 16 | **36** |
| Lignes de posture surveillées | 22 | **70** |
| Hôtes réels | 2 *(dont un issu d'un échantillon)* | **3** |
| Collecteurs | 4 | **11** |
| Risques ISO couverts | 9 | **14** *(+ R-02, R-03, R-04, R-05, R-18)* |
| Conformité affichée en page d'accueil | 6 / 10 | **32 / 32**, dérivée du catalogue |

### Corroboration croisée avec les preuves de Phase C

MADSC mesure indépendamment ce que le rapport de durcissement affirme — les deux concordent :

| Contrôle MADSC | Mesure live | Preuve Phase C correspondante |
|---|---|---|
| `TIER-DENY-LOGON-PRINCIPALS` (PMS-01) | refus de `-512` + `-1118` sur les 5 droits | `GPO_T1_Deny_T0_Logon` |
| `TIER-DENY-LOGON-PRINCIPALS` (WS) | refus de `-512`, `-1118`, `-1117`, `-1121` | `GPO_T2_Deny_T0_T1_Logon` |
| `LOCAL-ADMINS-MEMBERS` (PMS-01) | `DL_PMS01_LocalAdmins` **SID `-1122`** | identique dans `PROJECT_CONTEXT.md` |
| `LAPS-CSE-INSTALLED` | `AdmPwd.dll` **version 6.2.0.0** | inventaire LAPS du 23 juillet |
| `AUDIT-ADVANCED-POLICY` (DC) | 23 sous-catégories auditées / 60 | `GPO_DC_Advanced_Audit` |

Deux points méritent d'être soulignés pour la soutenance :

- **Les cinq droits de refus portent des principaux identiques** sur les deux membres. C'était un
  défaut corrigé en cours de Phase C (`Admins du domaine` manquait sur un seul des cinq droits) ;
  la correction est confirmée indépendamment.
- **La frontière de tiering et LAPS ont survécu à la restauration d'instantané du DC.** Les GPO
  vivent dans AD et SYSVOL sur le contrôleur restauré : leur vérification n'était pas acquise.

### Prérequis de détection : question tranchée

La restauration d'instantané du contrôleur de domaine faisait planer un doute sur les trois SACL
d'audit de la Phase D, qui vivent **dans AD** et non sur disque. `SENSOR-AUDIT-SACL` a répondu :

```
DCSync 3/3 · msDS-KeyCredentialLink True · CN=Policies True   -> CONFORME
```

Les règles `100033` (DCSync), `100038` (Shadow Credentials) et `100054` (modification de GPO) ont
donc conservé leur capacité de détection. Ce point ne se vérifie plus à la main après chaque
restauration : c'est désormais un contrôle surveillé en continu.

### Ce que MADSC a trouvé que l'audit manuel avait manqué

> **`PROTO-SMBv1-DISABLED = NON CONFORME` sur `PMS-01`** (`EnableSMB1Protocol: True`).

La Phase C a retiré la fonctionnalité `FS-SMB1` **sur `DC-01` uniquement** ; `PMS-01` et `WS-01`
n'y figurent que comme *clients* du test de compatibilité. Le risque `R-06` est pourtant marqué
« Traité / validé » dans la matrice ISO. Le serveur SMBv1 de `PMS-01` n'avait jamais été désactivé.

Cycle complet, tracé dans l'outil : **détection → remédiation → confirmation**. C'est un argument
plus fort qu'un tableau de bord vert dès le premier jour, et il justifie une précision de périmètre
sur `R-06` dans la matrice.

### `PMS-01` déclare lui-même sa cécité

Les deux seuls écarts restants sont sur `PMS-01` : `SENSOR-EVENTLOG` (service arrêté) et
`SENSOR-SYSMON` (absent). La page *Santé de la détection* en tire le verdict **AVEUGLE**.

L'intérêt n'est pas de découvrir `RR-08` — il était déjà documenté — mais que **l'outil l'énonce
de lui-même, en continu**, au lieu qu'il vive en note de bas de page. Wazuh, lui, affiche cet agent
comme *connecté et sain* : l'agent tourne réellement, il n'a simplement plus rien à lire. Un SIEM ne
peut pas voir cela (§5.12).

---

## 7. Limites assumées

- **Aucune authentification.** MADSC expose la posture AD, la composition des groupes privilégiés
  et des conseils de remédiation sur `0.0.0.0:8700` sans contrôle d'accès. Acceptable en
  laboratoire ; **à documenter comme risque résiduel** (candidat `RR-09`). `/ingest` accepte de
  même tout POST se déclarant sous n'importe quel nom d'hôte.
- **Vérification TLS désactivée par défaut** vers le manager Wazuh (certificat auto-signé) —
  désormais explicite et activable, mais toujours désactivée en configuration par défaut.
- **Score composite.** `get_security_score()` agrège conformité et couverture Purple Team en un
  nombre unique, ce qui est en tension avec le principe « pas de score opaque » du README. Il est
  en outre **de polarité inverse à PingCastle** (98/100 = bon ici, 25/100 = bon là-bas) : à
  afficher avec sa formule, ou à retirer.
- **Le tableau de bord principal affiche des compteurs**, pas les libellés ; le détail par contrôle
  vit dans l'onglet *Compliance Checker*.
- **Poids de la page Compliance :** ~106 Ko pour 32 contrôles × 3 hôtes, le détail et le journal
  étant embarqués dans la page. La croissance est linéaire ; au-delà de quelques centaines de
  contrôles, il faudrait charger le détail à la demande. Sans JavaScript, la matrice et le journal
  restent lisibles, mais les filtres, le tri et le tiroir sont inactifs.
- **Couverture de tests partielle.** 39 tests couvrent le moteur d'évaluation, la dérive, la
  fraîcheur et le journal des changements. Les collecteurs PowerShell, le client Wazuh et le
  rendu HTML ne sont pas testés automatiquement.
- **Le journal des changements n'a pas de rétention.** Il relit l'intégralité de
  `control_results` à chaque affichage ; acceptable à cette échelle, à borner en production.

## 8. Points ouverts hors code

1. **Rotation du compte Wazuh** utilisé jusqu'ici : son mot de passe reste **dans l'historique
   git** (commit initial). Le retirer du code ne le retire pas de l'historique.
2. **Prérequis de détection Phase D** après la restauration d'instantané du DC : les trois SACL
   d'audit (droits de réplication DCSync, `msDS-KeyCredentialLink`, `CN=Policies`) vivent **dans
   AD**. Rejouer `Deploy-DetectionPrereqs.ps1` (idempotent) pour confirmer qu'elles ont survécu ;
   `[+]` au lieu de `[=]` signifierait que les règles `100033`, `100038` et `100054` sont déployées
   mais **aveugles**.

---

## 9. Travaux futurs

### 9.1 Sprint 1 — terminé (6 collecteurs sur 6)

Les six collecteurs prévus sont écrits et testés. `KRB-USER-SPN` mérite une mention : c'est le
**miroir de configuration** de la règle Wazuh `100030` (Kerberoasting). Wazuh voit l'attaque — une
demande de ticket RC4 ; MADSC voit la **cible réapparaître**. C'est le premier point de contact
concret entre les deux outils, et la base de la corrélation décrite en 9.2.

**Contrôles restants non instrumentés :** Protected Users, inventaire/liens de GPO, protection des
OU contre la suppression, source de temps (`R-12`).

**Ajout hors plan initial :** `Collect-DetectionSensors.ps1` — né de la refonte de la page Purple
Team en page *Santé de la détection* (§5.12). Il instrumente enfin les trois SACL de la Phase D,
qui devaient jusque-là être revérifiées à la main après chaque restauration d'instantané du DC.

### 9.2 Sprint 2 — ce qui ferait de MADSC autre chose qu'un tableau de bord

> **Correction d'une version antérieure de ce document.** Cette section affirmait que *« chaque
> règle de Phase D a un pendant de configuration »* et qu'*« aucune nouvelle source de données
> n'est nécessaire »*. La réalisation des collecteurs et du client Wazuh a montré que **les deux
> affirmations sont fausses** ; elles sont corrigées ci-dessous. C'est précisément le genre
> d'écart qu'un registre de preuves doit faire ressortir.

**a. Carte de couverture posture × détection — ✅ FAIT.** MADSC détient deux observations indépendantes de
la même réalité — Wazuh voit des **événements**, MADSC voit des **états** — et ne les croise
jamais. Le croisement donne quatre cas :

|  | Dérive de configuration | Aucune dérive |
|---|---|---|
| **Alerte déclenchée** | ✅ **Corroboré** — les deux canaux concordent | 🟠 Tentative bloquée ou annulée |
| **Aucune alerte** | 🔴 **Dérive silencieuse → lacune de détection** | ⚪ Rien ne s'est produit |

Le quadrant rouge est le seul moyen de mesurer des **faux négatifs**, ce que la Phase D ne peut
structurellement pas faire : elle démontre `FP = 0` et une latence de 0,64 s, mais ne dit rien de
ce que les règles **manquent**.

**Trois limites à assumer explicitement — elles bornent ce qui est réellement livrable :**

1. **`/alerts` renvoie 404 sur ce manager.** MADSC ne dispose que de **compteurs cumulés depuis le
   démarrage**, sans horodatage : une corrélation par fenêtre temporelle est donc impossible en
   l'état. Contournement retenu : enregistrer les compteurs à chaque interrogation et calculer les
   **deltas** — un delta positif entre deux relevés signifie « la règle a sonné dans l'intervalle ».
   Cela exige une petite table supplémentaire : c'est bien une modification du backend.
2. **La plupart des règles n'ont AUCUN pendant de configuration.** Un PowerShell encodé, un DCSync
   ou des Shadow Credentials ne laissent pas de trace dans l'état de configuration. Seuls quelques
   couples sont réellement corrélables aujourd'hui :

   | Règle Wazuh | Contrôle MADSC | Force du couple |
   |---|---|---|
   | `100037` / `100043` | dérive `PRIV-*` | forte |
   | `100030` / `100031` | `KRB-USER-SPN` | forte |
   | `100037` (4732) | `LOCAL-ADMINS-MEMBERS` | partielle |
   | `100040` | `TIER-DENY-LOGON-*` | sémantique différente : l'alerte prouve que la frontière **a tenu** |
   | `100054` | inventaire de GPO **non instrumenté** | à construire |

3. **Asymétrie d'échantillonnage.** La posture est périodique, les alertes sont continues. Un
   changement effectué puis annulé entre deux collectes est invisible de MADSC : « aucune dérive »
   signifie donc « aucun changement **persistant** », pas « rien ne s'est passé ».

**Livrable honnête :** non pas « MADSC détecte les faux négatifs », mais une **carte de
couverture** — pour chaque technique du registre Purple Team, y a-t-il deux témoins indépendants,
un seul, ou aucun ? Deux témoins = corroboration possible ; un seul = point de défaillance unique ;
aucun = angle mort assumé. C'est défendable, nouveau pour le rapport, et sans surenchère.

**b. Chronologie des dérives — ✅ FAIT.** `db.drift_events()` reconstitue les transitions de
valeur entre deux collectes successives (comparaison APRÈS désérialisation : l'ordre des clés
d'une table de hachage PowerShell n'est pas garanti et créerait de faux changements). Deux vues
en découlent : un **journal des changements** en bas de la page Compliance, avec valeur avant →
après et transition de statut, et une **chronologie par contrôle** dans le tiroir de détail, où
les collectes ayant modifié la valeur sont marquées. Sur le laboratoire, ce journal restitue de
lui-même l'historique réel de la remédiation : `EnableSMB1Protocol true → false` sur `PMS-01`,
`cse_installed false → true` sur les deux membres, politique d'audit `0 → 60` sous-catégories.

**c. Garde-fou de fraîcheur — ✅ FAIT.** Voir §5.11 pour la règle appliquée. Un indicateur
« Mesures périmées » et une pastille par hôte rendent l'arrêt d'un collecteur immédiatement
visible. *(Texte d'origine conservé ci-dessous pour mémoire du besoin.)* Si un collecteur cesse
de tourner, le tableau de bord affiche
indéfiniment la dernière posture connue **en vert**. Dans un modèle où l'administrateur ne regarde
que par exception, la mort silencieuse d'un collecteur est le pire mode de défaillance :
`collected_at` au-delà de N heures → statut `STALE`.

**d. Tests — ✅ FAIT.** 39 cas `pytest` (`tests/`) sur la conformité, la dérive, la fraîcheur,
les identifiants de contrôle inconnus et le journal des changements. Les tests d'intégration
utilisent une base jetable : `data/madsc.db` n'est jamais touché.
`.venv\Scripts\python.exe -m pytest tests -q`

**e. Résultat mesuré sur le laboratoire** (`backend/coverage.py`, onglet *Purple Team*) :

| Verdict | Nombre | Lecture |
|---|---:|---|
| **Deux témoins indépendants** | **3** | tiering, groupes privilégiés, Kerberoasting — corroboration possible |
| **Détection seule** | **10** | l'action ne laisse aucun état persistant : le SIEM est le seul témoin |
| **Aucun témoin actif** | **2** | DCShadow (déployée non validée) et Golden Ticket (hors périmètre) |
| **Posture seule** | **23** | contrôles durcis qu'**aucune règle Wazuh ne surveille** |

La ligne la plus parlante est la dernière : **23 contrôles de durcissement n'ont aucune règle de
détection associée**. Retirer la signature SMB, affaiblir la politique de mot de passe ou couper
LAPS ne déclencherait **aucune alerte** — seule la collecte suivante de MADSC le verrait. C'est
la justification chiffrée de l'existence de l'outil, et elle sort d'une mesure, pas d'un argument.

Les compteurs Wazuh sont mémorisés à chaque relevé (`wazuh_rule_counters`) pour permettre le
calcul d'un **écart entre deux relevés** — la seule granularité temporelle atteignable avec une
API qui n'expose que des cumuls. Un compteur qui recule est interprété comme un redémarrage du
manager, pas comme un écart négatif.

**Reste de Sprint 2 :** rien. Les cinq points sont livrés.

### 9.3 Au-delà du PFA

- Authentification et HTTPS sur MADSC lui-même ; `/ingest` authentifié par hôte.
- Collecteurs additionnels : inventaire/liens de GPO, protection des OU contre la suppression,
  source de temps, Protected Users.
- Export de preuves aligné sur la matrice (`R-xx` → contrôle → preuve → empreinte → date).
- Migration vers Windows LAPS lors de la modernisation des OS (`RR-07`).

---

## 10. Annexe — inventaire des contrôles

| Famille | Contrôles | Risque(s) | Portée |
|---|---|---|---|
| Protocoles | LDAP signing, SMB signing client/serveur, SMBv1, NTLMv2, NoLMHash, LLMNR | R-06, R-07, R-08, R-11 | dc / all |
| Groupes privilégiés | Admins du domaine, entreprise, schéma, intégré, `GG_T0_Admins` | R-01 | dc |
| Tiering | couverture et principaux des 5 droits de refus ; membres et absence d'utilisateur direct en admin local | R-02, R-03 | member |
| LAPS | extension client, politique effective, couverture de rotation | R-02 | member / dc |
| Mots de passe | politique du domaine, PSO Tier 0, comptes sans expiration | R-04 | dc |
| Délégation | non contrainte, contrainte/transition/RBCD, SPN utilisateur, `adminCount` | R-01, R-05, R-14 | dc |
| Active Directory | MachineAccountQuota, Corbeille AD | R-13, R-14 | dc |
| Services système | Spouleur d'impression sur DC | R-09 | dc |
| Télémétrie & Audit | politique d'audit avancée, Script Block Logging, Module Logging | R-10 | all |

**Risques du registre non encore instrumentés :** R-12 (synchronisation horaire), R-15 à R-19
(résilience, fin de vie des OS, réseau/DNS, SIEM, anti-malware).

> **Nuance connue :** une valeur de registre *absente* produit `NON ÉVALUÉ`, pas `NON CONFORME`
> (convention du moteur depuis la phase 1, commune à tous les contrôles de registre). Pour la
> journalisation PowerShell, « absente » signifie en pratique « non activée » ; le statut reste
> néanmoins distinct de CONFORME, donc sans fausse assurance.

---

*Document de travail PFA — 2 août 2026. Les chiffres cités proviennent de collectes réelles sur
`DC-01`, `PMS-01` et `DESKTOP-0LKLBTR` ; aucun n'est estimé.*
