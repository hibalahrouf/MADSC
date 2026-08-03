# Matrice de traitement des risques — Alignement ISO/IEC 27001:2022

**Projet :** Durcissement et surveillance de l'Active Directory `mogador.local` (laboratoire hôtelier fictif Mogador — PFA Purple Team)
**Périmètre :** `DC-01` (contrôleur de domaine / DNS, Tier 0), `PMS-01` (serveur Tier 1), `WS-01` (poste Tier 2), `KALI-01` (manager Wazuh + poste d'attaque)
**Version :** 1.1 — 31 juillet 2026 *(supersède la v1.0 du 28/07, antérieure à la fin de la Phase D — Détection)*
**Classification :** Interne — PFA
**Propriétaire du risque :** *[à nommer dans le rapport]* · **Approbateur :** *[encadrant / jury / RSSI fictif]*

---

## 0. Positionnement et avertissement

Ce document démontre un **alignement ciblé** avec l'ISO/IEC 27001:2022 pour le périmètre Active Directory de Mogador. Il **ne constitue pas** :
- une certification ISO 27001 ;
- un Système de Management de la Sécurité de l'Information (SMSI) complet et opéré dans la durée ;
- une Déclaration d'applicabilité (SoA) exhaustive sur les 93 contrôles de l'Annexe A.

Les **faits techniques** proviennent de `PROJECT_CONTEXT.md`, du `README_AD_HARDENING.md` et du `COMPTE_RENDU_DETECTION_PHASE_D.md` (preuves live du laboratoire). Les **niveaux de risque** sont des appréciations d'architecte proposées pour le PFA et devraient, en contexte réel, être validés par un propriétaire du risque désigné. Les intitulés de contrôles ISO sont **volontairement abrégés** ; tout usage contractuel/réglementaire doit repartir des textes ISO sous licence.

---

## 1. Ce que couvre le cadre ISMS ISO 27001 (clauses 4 → 10) — lecture honnête

L'ISO 27001 ne se résume pas à l'Annexe A : le cœur normatif, ce sont les **clauses 4 à 10** (le système de management). Le PFA en couvre une partie de façon « allégée » ; le reste est explicitement hors périmètre.

| Clause | Exigence | Ce que le PFA Mogador fournit | Écart assumé |
|---|---|---|---|
| **4. Contexte** | Périmètre, enjeux, parties intéressées | Périmètre AD défini (4 VM, domaine `mogador.local`), contexte hôtelier fictif | Analyse formelle des parties intéressées non produite |
| **5. Leadership** | Engagement direction, politique, rôles | Rôles Tier 0/1/2 et RBAC comme politique d'accès technique | Pas de politique SSI signée par une direction réelle |
| **6.1 Appréciation & traitement du risque** | Méthode, critères, plan de traitement | **Sections 3 et 4** de ce document (registre R-01→R-19) | Échelle qualitative (pas de scoring numérique validé) |
| **6.1.3 SoA** | Déclaration d'applicabilité | **Section 5** (SoA scoped, A.5/A.8) | Thèmes A.6/A.7 déclarés hors périmètre, pas détaillés |
| **6.2 Objectifs SSI** | Objectifs mesurables | Réduction PingCastle, 0 chemin BloodHound non autorisé, détection < 1 s | Pas de tableau d'objectifs pluriannuel |
| **7. Support** | Compétences, documentation | Runbooks, scripts idempotents, guides techniques versionnés (**A.5.37**) | — |
| **8. Opération** | Mise en œuvre du traitement | Tout le durcissement + détection déployés et **prouvés en live** | — |
| **9.1 Mesure d'efficacité** | Surveillance, mesure | **Section 7** : PingCastle 100→25, BloodHound propre, latence 0,64 s, FP = 0 | Pas d'audit interne formel (9.2) ni revue de direction (9.3) |
| **10. Amélioration** | Correctifs, amélioration continue | Résiduels + feuille de route production (**Section 6**) | Cycle d'amélioration non rejoué (PFA ponctuel) |

> **À retenir pour la soutenance :** on revendique un **alignement sur 6.1 / 6.1.3 / 8 / 9.1**, avec des lacunes assumées sur 5, 9.2 et 9.3 — ce qui est cohérent avec un PFA et bien plus défendable qu'une prétention de conformité totale.

---

## 2. Actifs primaires protégés (vue métier hôtel)

| Actif | Pourquoi il compte pour l'hôtel |
|---|---|
| Annuaire Active Directory (`DC-01`) | Cœur de confiance : authentifie tout le personnel, porte les stratégies de sécurité. Sa compromission = compromission totale. |
| Identités privilégiées (Tier 0) | Un vol de compte administrateur du domaine donne les clés de toute l'infrastructure. |
| Serveur applicatif Tier 1 (`PMS-01`) | Hébergera le futur Property Management System (données clients, réservations, facturation). |
| Postes de travail (Tier 2) | Points d'entrée réalistes (phishing, poste réception) vers le SI. |
| Journaux et capacité de détection | Sans traçabilité, une intrusion reste invisible : obligation de moyen pour protéger les données clients. |

---

## 3. Méthode d'appréciation des risques

- **Échelle proposée :** vraisemblance × impact, chacun de 1 à 5. Seuils : 1–4 *Faible*, 5–9 *Modéré*, 10–16 *Élevé*, 17–25 *Critique*.
- **Version employée :** niveaux **qualitatifs** (Faible/Modéré/Élevé/Critique) afin de ne pas fabriquer de valeurs numériques non approuvées par un propriétaire du risque.
- **Critères d'acceptation :** un risque *Faible* est accepté avec contrôle périodique ; *Modéré* nécessite justification + échéance ; *Élevé/Critique* exige une réduction démontrée **ou** une acceptation formelle documentée (cas des contraintes de laboratoire).
- **Règle de preuve :** aucun contrôle n'est marqué « validé » sans preuve reproductible (commande, RSOP, événement Windows, rapport d'outil, ou test fonctionnel). Les éléments non démontrés restent « planifié » / « non prouvé » / « à valider ».

**Options de traitement :** *Réduire* (mesures de sécurité), *Éviter* (supprimer la source), *Accepter* (risque résiduel documenté), *Transférer* (non utilisé — pas de tiers/assurance en labo).

---

## 4. Registre et plan de traitement des risques

> Source de vérité technique : `PROJECT_CONTEXT.md`, `README_AD_HARDENING.md`, `COMPTE_RENDU_DETECTION_PHASE_D.md`. Les références ISO indiquent les contrôles Annexe A les plus directement liés (pas une SoA complète).

| ID | Actif / Scénario de risque | Init. | Résid. | Mesures de traitement (résumé) | Contrôles ISO 27001:2022 | Preuves vérifiées (clés) | Statut |
|---|---|---|---|---|---|---|---|
| **R-01** | Identités privilégiées Tier 0 — élévation par appartenance excessive / ACL abusives / chemins indirects vers Admins du domaine | Critique | Faible | Modèle Tier 0/1/2, comptes séparés, RBAC/AGDLP, nettoyage groupes privilégiés, remise en héritage AdminSDHolder, nettoyage ACL Tier 0 | A.5.15, A.5.16, A.5.18, A.8.2, A.8.3 | Groupes `GG_/DL_`, vérifs récursives, SDDL avant/après, **BloodHound final sans chemin `Hiba`/`adm_t1` → Domain Admins** | Traité / validé |
| **R-02** | Admin local `PMS-01`/`WS-01` — réutilisation/exposition de mots de passe admin local (mouvement latéral) | Élevé | Faible | Legacy LAPS sur Tier 1/2, délégation lecture/reset par groupes `DL` dédiés, retrait des accès croisés | A.5.17, A.5.18, A.8.2, A.8.5 | `GPO_LegacyLAPS_ManagedComputers`, `ms-Mcs-AdmPwd` présent, tests lecture autorisée/refusée, ACL LAPS tier-isolées | Traité / validé |
| **R-03** | Frontières Tier 0/1/2 — connexion d'un compte supérieur sur machine inférieure, exposition de secrets | Critique | Faible | GPO deny-logon (réseau/local/RDP/batch/service) par niveau, admin local limité aux groupes de ressource | A.5.15, A.5.18, A.8.2, A.8.3, A.8.5 | RSOP, `secedit` USER_RIGHTS, connexion refusée, **événement 4625 `0xC000015B`** | Traité / validé |
| **R-04** | Comptes du domaine — politique de mot de passe faible / pas de verrouillage / non-expiration | Élevé | Modéré | Politique domaine 14 car., historique 24, complexité, verrouillage 10/15 min ; PSO Tier 0 16 car./seuil 5 ; correction `PasswordNeverExpires` | A.5.17, A.5.18, A.8.5 | `Get-ADDefaultDomainPasswordPolicy`, `PSO_T0_Privileged_Admins`, inventaire `PasswordNeverExpires` | Traité / exception documentée (break-glass) |
| **R-05** | Compte de service `svc-plurihotel` — Kerberoasting / privilèges excessifs / usage interactif | Critique | Faible | Retrait groupes opérateurs, rollback sauvegardé, **compte désactivé + SPN supprimé** tant qu'aucune appli déployée | A.5.16, A.5.18, A.8.2, A.8.5, A.8.9 | `Enabled=False`, SPN absent, `GG_T1_SvcAccounts` vide, **BloodHound sans user Kerberoastable** | Traité ; réévaluation avant réactivation |
| **R-06** | Services SMB du domaine — SMBv1/MS17-010, sessions non signées | Critique | Faible | Correctifs DC, retrait `FS-SMB1`, désactivation SMBv1, **signature SMB requise** client/serveur | A.8.7, A.8.8, A.8.9, A.8.20, A.8.21 | Build DC **14393.9339**, KB5099542/KB5099535, `FS-SMB1` absent, **SMB 3.1.1 `Signed=True`**, `GPO_SMB_Signing_Required` | Traité / validé |
| **R-07** | Service LDAP de `DC-01` — interception/relais par bind non signé | Élevé | Modéré | Audit des binds, résolution conflit précédence GPO, **exigence de signature LDAP** | A.8.5, A.8.20, A.8.21, A.8.24 | `LDAPServerIntegrity=2`, `GPO_DC_LDAP_Signing_Required`, **bind clair rejeté** (`strongerAuthRequired`) | Traité ; channel binding hors périmètre |
| **R-08** | Authentification Windows — LM/NTLMv1 (cassage, relais, downgrade) | Élevé | Modéré | Audit NTLM entrant/sortant puis `LmCompatibilityLevel=5` + `NoLMHash=1` sur DC/T1/T2 | A.5.17, A.8.5, A.8.15, A.8.16 | GPO audit NTLM, événements 8001/8002, `GPO_Authentication_NTLMv2_Only`, 4624 `NTLM V2` | Traité partiellement ; NTLMv2 conservé |
| **R-09** | `DC-01` — surface d'attaque du Spouleur d'impression | Élevé | Faible | Vérif absence de dépendance puis arrêt + désactivation par GPO dédiée | A.8.7, A.8.8, A.8.9 | `GPO_DC_Disable_PrintSpooler`, service `Stopped/Disabled`, santé NTDS/DNS/KDC/Netlogon | Traité / validé |
| **R-10** | Traçabilité AD & endpoints — audit insuffisant des actions privilégiées / PowerShell | Élevé | Faible | Advanced Audit Policy dédiée, Security log 512/256 Mo, ligne de commande 4688, PowerShell ScriptBlock+Module | A.8.15, A.8.16, A.8.17 | `GPO_DC_Advanced_Audit`, `GPO_Member_Advanced_Audit`, `SCENoApplyLegacyAuditPolicy=1`, événements **4688/4103/4104** | Traité / validé *(sources consommées par le SIEM — voir R-18)* |
| **R-11** | Résolution de noms locale — empoisonnement LLMNR, capture/relais d'identifiants | Élevé | Faible | Désactivation LLMNR sur DC/T1/T2 par GPO dédiée | A.8.20, A.8.21, A.8.22 | `EnableMulticast=0`, pas d'écoute UDP/5355, découverte DNS OK | Traité / validé |
| **R-12** | Cohérence temporelle — dérive horaire (Kerberos, corrélation d'événements) | Élevé | Modéré | Hiérarchie `NT5DS` pour les membres ; PDC synchronisé source externe | A.8.15, A.8.17 | `GPO_Member_Time_DomainHierarchy`, `Type=NT5DS`, sources PMS/WS = `DC-01` | Traité ; source externe unique acceptée en labo |
| **R-13** | Objets & structure AD — suppression accidentelle d'OU / restauration | Élevé | Modéré | Corbeille AD, protection anti-suppression de toutes les OU, retrait OU obsolètes | A.8.9, A.8.13 | `Recycle Bin EnabledScopes`, inventaire OU sans `ProtectedFromAccidentalDeletion=False` | Traité ; sauvegarde système distincte requise en prod |
| **R-14** | Création de machines & délégation Kerberos — ajout non autorisé / abus de délégation | Élevé | Faible | `MachineAccountQuota=0`, inventaire délégation classique/RBCD, `AccountNotDelegated` sur comptes admin | A.5.16, A.5.18, A.8.2, A.8.9 | `ms-DS-MachineAccountQuota=0`, aucune délégation inattendue, comptes admin `AccountNotDelegated=True` | Traité / validé |
| **R-15** | Résilience du service d'annuaire — indispo/perte de données sur DC unique | Critique | Élevé | Contrainte PFA documentée ; snapshots labo pour rollback. Prod : 2e DC, System State isolé, tests de restauration | A.5.29, A.5.30, A.8.13, A.8.14 | Architecture actuelle : **un seul DC** ; pas d'archi de sauvegarde AD résiliente démontrée | **Résiduel accepté (PFA)** |
| **R-16** | Plateformes Windows — fin de cycle / vulnérabilités futures | Élevé | Élevé | MAJ DC au niveau dispo en labo ; feuille de route migration OS supportés | A.8.8, A.8.9, A.8.19 | `DC-01` WS2016 `14393.9339`, `WS-01` Win10 19045 ; migration non réalisée | **Résiduel / feuille de route prod** |
| **R-17** | Réseau & DNS de `DC-01` — publication de l'interface NAT dans DNS | Élevé | Modéré | Déclaration sous-réseau AD, désactivation enregistrement DNS sur NAT, suppression enreg. A NAT | A.8.20, A.8.21, A.8.22 | DNS ne publie que `192.168.10.10` ; multihoming documenté | Traité partiellement / contrainte labo |
| **R-18** | Supervision centralisée & détection — événements non corrélés, absence d'alerte consolidée | Élevé | **Faible** | **SIEM Wazuh déployé** (manager Kali, agents DC/WS/PMS), **16 règles** AD custom + intégrée `92057`, prérequis SACL, alerting e-mail par sévérité | **A.5.7, A.5.24, A.5.25, A.5.26, A.5.28, A.8.15, A.8.16** | **15/16 règles validées live** (scénarios #1–6 + P2/P3), SACL via `Deploy-DetectionPrereqs.ps1`, alerting HTML (liste blanche 12 règles), **latence 0,64 s / FP 0** | **Traité / validé** *(nouveau v1.1)* |
| **R-19** | Exécution de code malveillant sur hôtes AD (vol d'identifiants, extraction NTDS) | Élevé | Modéré | Protection anti-malware active (Defender), détection Sysmon/EDR-like des outils d'attaque | A.8.7, A.5.25 | **Defender a bloqué `ntdsutil … ifm` et mimikatz** (preuve live, §6 compte-rendu) ; règles `100036`/`92057` détectent les tentatives | Traité ; couverture Sysmon partielle (PMS-01, voir RR-08) |

**Hygiène de test (transversal) :** tous les comptes/ACE de validation étaient **jetables** (`test_*`, `svc_test_krb`), créés puis **supprimés** ; DACL sauvegardées avant et **révoquées après** ; le dump NTDS.dit a été **supprimé immédiatement**. → contrôles **A.8.34** (protection pendant les tests) et **A.8.10** (suppression de l'information).

---

## 5. Déclaration d'applicabilité (SoA) — périmètre scoped

**Thèmes hors périmètre déclarés :**
- **A.6 (Personnes)** — screening, contrats, sensibilisation, télétravail : **hors périmètre** (labo technique sans organisation RH réelle). *Exception : A.6.8 (signalement d'événements) est couvert techniquement par l'alerting.*
- **A.7 (Physique)** — accès physique, câblage, maintenance : **N/A** (infrastructure virtualisée VMware). En production hôtelière réelle : à traiter (salles serveurs, badges).

**Contrôles applicables (A.5 Organisationnels & A.8 Technologiques) :**

| Contrôle | Intitulé abrégé | Applicabilité | État Mogador |
|---|---|---|---|
| A.5.7 | Renseignement sur les menaces | Applicable | Règles de détection mappées **MITRE ATT&CK** (technique + tactique) |
| A.5.15 | Contrôle d'accès | Applicable | Cadre Tier 0/1/2 + règles de connexion |
| A.5.16 | Gestion des identités | Applicable | Comptes séparés, groupes de rôle, cycle de vie |
| A.5.17 | Informations d'authentification | Applicable | Politique MDP, PSO, LAPS |
| A.5.18 | Droits d'accès | Applicable | AGDLP, revues, délégations, retrait d'accès |
| A.5.24 | Planification gestion des incidents | Applicable / satisfait | Cas de détection conçus, alerting déployé, actions recommandées par règle |
| A.5.25 | Appréciation & décision sur les événements | Applicable / satisfait | **Règles à sévérité graduée** (niveau 3→14), liste blanche d'escalade |
| A.5.26 | Réponse aux incidents | Applicable / partiel | Alerting e-mail + guide de remédiation par règle ; pas de SOC 24/7 (mono-admin assumé) |
| A.5.28 | Collecte de preuves | Applicable / satisfait | Structure `Evidence/<scenario>/`, sauvegardes SDDL, logtest, événements bruts JSON |
| A.5.29 | Sécurité pendant une perturbation | Applicable / non satisfait | Un seul DC ; continuité non résiliente (R-15) |
| A.5.30 | Préparation TIC à la continuité | Applicable / non satisfait | 2e DC + restauration AD à prévoir en prod |
| A.5.37 | Procédures documentées | Applicable | Guides techniques, runbooks, script idempotent `Deploy-DetectionPrereqs.ps1` |
| A.8.2 | Droits d'accès privilégiés | Applicable | Groupes Tier, comptes d'admin dédiés, moindre privilège |
| A.8.3 | Restriction d'accès à l'information | Applicable | Deny-logon inter-tiers, accès locaux ciblés |
| A.8.5 | Authentification sécurisée | Applicable | FGPP, LDAP signing, NTLMv2-only, restrictions de délégation |
| A.8.7 | Protection contre les malwares | Applicable | **Defender a bloqué extraction NTDS + mimikatz** (preuve live) |
| A.8.8 | Gestion des vulnérabilités techniques | Applicable | Correctifs DC, retrait SMBv1, réduction de services |
| A.8.9 | Gestion de la configuration | Applicable | GPO dédiées, états avant/après, rollback |
| A.8.10 | Suppression de l'information | Applicable | Dump NTDS supprimé, comptes/ACE de test nettoyés |
| A.8.13 | Sauvegarde de l'information | Applicable / partiel | Corbeille AD ; System State résilient non démontré |
| A.8.14 | Redondance des moyens de traitement | Applicable / non satisfait | Un seul contrôleur de domaine |
| A.8.15 | Journalisation | Applicable | Advanced Audit Policy, Security logs, PowerShell logging |
| A.8.16 | Activités de surveillance | Applicable / satisfait | **SIEM Wazuh opérationnel**, 16 règles, dashboard + alerting *(v1.1)* |
| A.8.17 | Synchronisation des horloges | Applicable | Hiérarchie NT5DS, PDC source externe |
| A.8.19 | Installation de logiciels | Applicable | MAJ et composants gérés ; migration OS planifiée |
| A.8.20 | Sécurité des réseaux | Applicable | SMB signing, LLMNR désactivé, DNS AD corrigé |
| A.8.21 | Sécurité des services réseau | Applicable | SMB/LDAP/DNS durcis et testés |
| A.8.22 | Séparation des réseaux | Applicable / partiel | Sous-réseau AD déclaré ; segmentation physique limitée en labo |
| A.8.24 | Utilisation de la cryptographie | Applicable / partiel | Signature LDAP/SMB ; chiffrement SMB non exigé globalement |
| A.8.34 | Protection des SI pendant les tests d'audit | Applicable | Comptes jetables, rollback, sauvegarde avant chaque modification |

---

## 6. Risques résiduels prioritaires

| ID | Risque résiduel | Niveau | Action recommandée | Horizon |
|---|---|---|---|---|
| **RR-01** | Un seul contrôleur de domaine | Élevé | 2e DC, sauvegarde System State isolée, procédure + test de restauration | Production |
| **RR-02** | WS2016 / Win10 en fin de cycle | Élevé | Plan de migration vers versions supportées + validation applicative | Production |
| **RR-03** | ~~Absence de SIEM/forwarding finalisé~~ **RÉSOLU** | ~~Élevé~~ → **Faible** | SIEM Wazuh déployé et validé (Phase D). Reste : transcrire latence/FP dans la matrice de détection | *Clos (PFA)* |
| **RR-04** | NTLMv2 encore autorisé | Modéré | Mesurer les dépendances puis réduire NTLM par exceptions contrôlées | Production |
| **RR-05** | LDAP channel binding non imposé | Modéré | Audit de compatibilité + déploiement progressif | Production |
| **RR-06** | DC multihomé (interface NAT) | Modéré | Séparer routage et rôle DC en production | PFA accepté |
| **RR-07** | Legacy LAPS (vs Windows LAPS) | Modéré | Migrer vers Windows LAPS lors de la modernisation OS | Production |
| **RR-08** | **`PMS-01` : angle mort SIEM** *(nouveau v1.1)* | Modéré | Service EventLog corrompu (erreur 13, famille DC-01) ; sans snapshot → **rebuild VM** différé (serveur Tier 1 vide). Tant qu'il est HS, l'agent Wazuh de `PMS-01` ne collecte aucun canal. À traiter dès qu'une charge applicative justifiera PMS-01 dans le SIEM | PFA accepté / à finaliser |

---

## 7. Mesure d'efficacité (clause 9.1)

| Indicateur | Résultat | Interprétation |
|---|---|---|
| **PingCastle** (même collecteur 3.5.1.33) | **100/100 → 25/100** | Réduction majeure du risque technique ; les constats restants sont traités en résiduels |
| **BloodHound — Kerberoasting / AS-REP** | Aucun résultat | Les comptes exploitables du scénario initial ont disparu de la collecte finale |
| **BloodHound — chemins vers Domain Admins** | Aucun chemin `Hiba`/`adm_t1` | Les chemins d'élévation non autorisés ciblés ont disparu |
| **BloodHound — DCSync** | Tier 0 légitime uniquement | Droits de réplication limités à `DC-01` + groupes intégrés |
| **Détection — règles** *(v1.1)* | **16 règles custom + 1 intégrée ; 15 validées en live** | Couverture MITRE : accès aux identifiants, mouvement latéral, persistance, escalade, exfiltration AD |
| **Détection — latence** *(v1.1)* | **≈ 0,64 s** (0,3–0,9 s, calculée dans Wazuh) | Chaîne collecte→alerte quasi temps réel |
| **Détection — faux positifs** *(v1.1)* | **Taux = 0** | Chaque alerte de validation = attaque contrôlée ; fenêtre sans attaque = aucun hit |

> **Statuts honnêtes conservés :** Zerologon = test négatif réussi (DC patché rejette) ; DCShadow = règle déployée **non** validée (attaque différée) ; Golden Ticket = hors périmètre (approche invalide) ; `PMS-01` Sysmon = limite assumée (RR-08).

---

## 8. Ce que l'on présente — deux publics, deux niveaux

### 8.1 Dans le **rapport PFA** (jury / lecteur technique)
Présenter **l'intégralité** de ce document comme le **chapitre « Traitement des risques & alignement ISO 27001 »** :
- La **lecture ISMS clauses 4→10** (Section 1) — montre qu'on sait que 27001 ≠ Annexe A, et on assume les lacunes.
- Le **registre R-01→R-19** (Section 4) — le cœur : chaque risque relié à une mesure **et à une preuve live**.
- La **SoA scoped** (Section 5) avec thèmes A.6/A.7 explicitement hors périmètre.
- Les **résiduels** (Section 6) et la **mesure d'efficacité** (Section 7) — le « avant/après » chiffré (PingCastle 100→25, BloodHound propre, détection 0,64 s / FP 0).
- **Message clé de soutenance :** *« alignement démontré et prouvé, pas certification revendiquée »* — la posture honnête est un atout, pas une faiblesse.

### 8.2 À la **direction de l'hôtel** (public non technique)
Une **synthèse d'une page** (extraite de ce document), en langage métier :
- **Ce qu'on a réduit :** « le niveau de risque de notre annuaire est passé de 100/100 à 25/100 ; les chemins qui permettaient à un attaquant de prendre le contrôle total ont été supprimés. »
- **Ce qu'on protège :** données clients (futur PMS), réservations, facturation, réputation, et la **capacité à détecter une intrusion en moins d'une seconde**.
- **Ce qui reste à financer (résiduels) :** un **2e contrôleur de domaine** (pour ne pas tout perdre en cas de panne), la **migration des systèmes en fin de vie**, et l'extension de la supervision au serveur applicatif quand il sera en service.
- **Ton :** pas de jargon ; risque = impact business (indisponibilité, fuite de données clients, atteinte à la réputation).

---

## 9. Références et limites

- ISO/IEC 27001:2022 — exigences SMSI et Annexe A.
- ISO/IEC 27002:2022 — lignes directrices des mesures de sécurité.
- `PROJECT_CONTEXT.md`, `README_AD_HARDENING.md`, `COMPTE_RENDU_DETECTION_PHASE_D.md` — sources de vérité techniques du projet.
- Rapports PingCastle (référence + final) ; collecte finale Legacy BloodHound/Neo4j.
- Preuves GPO, RSOP, journaux Windows, commandes PowerShell et sauvegardes SDDL conservées dans les dossiers `Evidence/` du laboratoire.

> **Limite :** les intitulés ISO sont abrégés ; les niveaux de risque sont des appréciations d'architecte à valider par un propriétaire du risque. Toute utilisation contractuelle, réglementaire ou de certification doit être revue à partir des textes ISO sous licence et par un auditeur qualifié.

---

*Version 1.1 — 31 juillet 2026. Supersède la v1.0 (28/07) en intégrant la Phase D — Détection (SIEM Wazuh) et la limite `PMS-01`. Document de travail PFA — alignement ISO/IEC 27001:2022, sans revendication de certification.*
