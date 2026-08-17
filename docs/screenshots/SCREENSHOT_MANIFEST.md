# DocGuard — Manifeste des captures d'écran (rapport / soutenance)

Captured from: **DocGuard v1.1.1**
Release commit: `48b08fba2f1125c79c4f595fd18d5c8378c0523d`
Policy: **1.0.2** (fingerprint `c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b`)
Controlled revalidation: Phase 11D, corpus 59 cas synthétiques, toutes les métriques de décision/détection/CDR reproduites.

Toutes les captures ont été produites via `scripts/report_screenshots/capture.py` (Playwright/Chromium) contre une instance DocGuard locale, réelle et non modifiée, avec authentification réelle (aucune injection de cookie) et des données **entièrement synthétiques et contrôlées** — aucune donnée réelle de client, de CIN, de RIB ou de facture n'a été utilisée. Voir `capture.py`/`seed_data.py` pour la méthode exacte.

Viewport desktop : 1440×900 (facteur d'échelle 2, soit des captures à ~2880 px de large). Mobile (optionnel) : 375×812. `prefers-reduced-motion: reduce` actif pour des captures déterministes.

---

## 01_landing_hero.png

- **Route** : `/` (page d'accueil publique, non authentifiée)
- **État montré** : bannière d'accueil — wordmark DocGuard, titre principal, texte explicatif, CTA de connexion, visuel « document non fiable → inspection isolée → décision de politique »
- **Objectif** : présenter le produit et son principe en une seule image
- **Chapitre suggéré** : Introduction / Présentation du produit
- **Légende (FR)** : *Figure X.X – Page d'accueil de DocGuard présentant le principe général d'inspection des documents non fiables.*

## 02_security_architecture.png

- **Route** : `/` (section architecture, capture d'élément)
- **État montré** : diagramme zone de confiance (FastAPI, Authentification/CSRF, moteur de politique, SQLite, audit, autorisation des artefacts) vs. travailleur non fiable jetable (analyseur PDF/Office/ZIP, règles YARA, secours lexical, moteur CDR), séparés par la frontière de confiance (« JSON versionné uniquement ») et les contraintes (aucun réseau, ressources bornées)
- **Objectif** : figure la plus importante du rapport — démontre la séparation réelle entre zone de confiance et travailleur isolé
- **Chapitre suggéré** : Architecture de sécurité
- **Légende (FR)** : *Figure X.X – Architecture de sécurité de DocGuard mettant en évidence la séparation entre la zone de confiance et le travailleur d'analyse isolé.*

## 03_operator_login.png

- **Route** : `/login`
- **État montré** : formulaire de connexion opérateur, champs vides (aucun identifiant ni mot de passe visible)
- **Objectif** : montrer le point d'entrée authentifié du produit
- **Chapitre suggéré** : Authentification / Modèle de sécurité
- **Légende (FR)** : *Figure X.X – Page de connexion de l'opérateur DocGuard, accès réservé aux comptes autorisés.*

## 04_dashboard.png

- **Route** : `/app` (authentifié)
- **État montré** : tableau de bord opérateur — zone de dépôt de documents, activité des décisions (Allow/Review/Quarantine/Block), liste « à traiter » avec des scans synthétiques contrôlés
- **Objectif** : illustrer le poste de travail quotidien de l'opérateur
- **Chapitre suggéré** : Interface opérateur / Flux de travail
- **Légende (FR)** : *Figure X.X – Tableau de bord opérateur affichant l'activité des décisions et les documents nécessitant une attention.*

## 05_multi_file_queue.png

- **Route** : `/app` (file d'analyse multi-fichiers, après complétion réelle)
- **État montré** : file de 4 documents synthétiques réellement analysés indépendamment — 2 ALLOW, 1 QUARANTINE, 1 BLOCK
- **Objectif** : démontrer l'analyse indépendante par lot, sans état simulé ni délai artificiel
- **Chapitre suggéré** : Interface opérateur / Analyse multi-documents
- **Légende (FR)** : *Figure X.X – File d'analyse multi-documents montrant des décisions réelles et indépendantes (ALLOW, QUARANTINE, BLOCK) pour un lot synthétique.*

## 06_documents_list.png

- **Route** : `/app/scans`
- **État montré** : liste des scans contrôlés (type détecté, décision, score de risque, date)
- **Objectif** : vue d'ensemble opérationnelle des documents traités
- **Chapitre suggéré** : Interface opérateur
- **Légende (FR)** : *Figure X.X – Liste des documents analysés avec leurs décisions et scores de risque respectifs.*

## 07_allow_decision.png

- **Fichier synthétique** : `rapport-annuel-2026.pdf` (PDF bénin généré)
- **Route** : `/app/scans/{scan_id}`
- **État montré** : décision **ALLOW**, résumé d'analyse, formulation prudente (« n'est pas une preuve que le document est bénin »)
- **Objectif** : montrer une décision ALLOW réelle sans sur-interprétation (jamais « sûr » ni « sans malware »)
- **Chapitre suggéré** : Politique de décision / Résultats
- **Légende (FR)** : *Figure X.X – Exemple d'une décision ALLOW, avec rappel explicite qu'elle ne constitue pas une preuve d'innocuité du document.*

## 08_quarantine_decision.png

- **Fichier synthétique** : `document-partiel-endommage.pdf` (PDF structurellement endommagé, généré)
- **Route** : `/app/scans/{scan_id}`
- **État montré** : décision **QUARANTINE** déclenchée par une analyse structurelle incomplète (statut d'analyse `FAILED`, `Release eligible: No`) — comportement *fail-closed*
- **Objectif** : démontrer que DocGuard ne libère jamais un document dont l'analyse a échoué ou est incomplète — particulièrement utile pour le jury
- **Chapitre suggéré** : Comportement fail-closed / Gestion des erreurs d'analyse
- **Légende (FR)** : *Figure X.X – Exemple d'une décision de mise en quarantaine déclenchée par une analyse documentaire incomplète (comportement « fail-closed »).*

## 09_fallback_evidence.png

- **Même scan que 08** (`document-partiel-endommage.pdf`)
- **Route** : `/app/scans/{scan_id}` (section preuves)
- **État montré** : trois constats — deux preuves structurelles (« Malformed PDF structure », « PDF analysis was incomplete ») et un constat lexical borné explicitement étiqueté **BOUNDED LEXICAL EVIDENCE**, avec un texte explicite indiquant qu'il s'agit d'un indice non confirmé par une analyse structurelle complète
- **Objectif** : montrer la distinction visuelle et textuelle entre une preuve structurelle confirmée et une preuve lexicale bornée (`PDF_FALLBACK_INDICATOR`)
- **Chapitre suggéré** : Explicabilité / Preuve de secours lexicale
- **Légende (FR)** : *Figure X.X – Distinction entre une preuve structurelle confirmée et un indice lexical borné (PDF_FALLBACK_INDICATOR), signalé explicitement comme non équivalent à une confirmation structurelle.*

## 10_block_decision.png

- **Fichier synthétique** : `piece-jointe-executable.pdf` (exécutable Windows inerte, masquerading en PDF)
- **Route** : `/app/scans/{scan_id}`
- **État montré** : décision **BLOCK**, motifs explicites (incohérence de type MIME, contenu exécutable présenté comme document métier), mention explicite que BLOCK ne peut pas être contourné par un opérateur ; aucune action de déblocage/CDR visible
- **Objectif** : montrer une règle de blocage matérielle et sa justification
- **Chapitre suggéré** : Politique de décision / Règles de blocage strict
- **Légende (FR)** : *Figure X.X – Exemple d'une décision BLOCK déclenchée par une règle de sécurité stricte, non contournable par l'opérateur.*

## 11_cdr_lineage.png

- **Scan source** : `facture-fournisseur.pdf` (PDF avec JavaScript, décision source QUARANTINE)
- **Route** : `/app/scans/{source_scan_id}` (section lignage CDR, capture d'élément)
- **État montré** : « Original source » (QUARANTINE, inchangé) → « Derived sanitized artifact » (ALLOW, ré-analysé indépendamment)
- **Objectif** : démontrer que la reconstruction CDR ne modifie jamais la décision du document source — seul un nouvel artefact dérivé, entièrement ré-analysé, peut atteindre ALLOW
- **Chapitre suggéré** : Content Disarm and Reconstruction (CDR)
- **Légende (FR)** : *Figure X.X – Chaîne de reconstruction CDR distinguant le document source de l'artefact dérivé réanalysé indépendamment ; la décision de la source reste inchangée.*

## 12_evidence_report.png

- **Même scan que 11 (source)** : `facture-fournisseur.pdf`
- **Route** : `/app/scans/{scan_id}/report`
- **État montré** : rapport de preuve HTML — identité du document (nom, empreinte SHA-256), décision, identité de la politique (version et empreinte), justification de la décision, deux constats réels avec détails techniques
- **Objectif** : illustrer le rapport de preuve imprimable destiné à un usage interne (aperçu HTML, pas l'aperçu d'impression natif)
- **Chapitre suggéré** : Rapport de preuve / Traçabilité
- **Légende (FR)** : *Figure X.X – Aperçu du rapport de preuve de sécurité d'un document, incluant son identité, la décision, l'identité de la politique appliquée et les constats détaillés.*

## 13_audit_trail.png

- **Route** : `/app/audit`
- **État montré** : événements d'audit réels générés par le flux de travail synthétique — téléversements, connexion, téléchargement d'artefact approuvé, approbation et ré-analyse CDR
- **Objectif** : montrer la traçabilité opérationnelle append-only, sans exposer de jeton de session, de secret CSRF ni de mot de passe
- **Chapitre suggéré** : Journal d'audit / Traçabilité
- **Légende (FR)** : *Figure X.X – Journal d'audit illustrant la traçabilité des actions opérateur (téléversement, connexion, reconstruction CDR, téléchargement d'artefact).*

## 14_mobile_dashboard.png *(optionnel)*

- **Route** : `/app` — viewport 375×812
- **État montré** : tableau de bord opérateur en disposition mobile
- **Objectif** : illustrer la réactivité de l'interface (figure secondaire, non indispensable)
- **Chapitre suggéré** : Annexe / Interface responsive
- **Légende (FR)** : *Figure X.X (annexe) – Tableau de bord opérateur en disposition mobile (375×812).*

---

## Reproduction

```bash
# Server (fresh, local instance — see .report-venv/instance.env for override paths)
PYTHONPATH=.python-deps:.worker-deps python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8010 --workers 1

# Seed synthetic controlled data (once, against a fresh database)
PYTHONPATH=.python-deps:.worker-deps .report-venv/bin/python scripts/report_screenshots/seed_data.py

# Capture the curated set
PYTHONPATH=.python-deps:.worker-deps .report-venv/bin/python scripts/report_screenshots/capture.py
```

Credentials are read only from `DOCGUARD_SCREENSHOT_BASE_URL`, `DOCGUARD_SCREENSHOT_USERNAME`,
`DOCGUARD_SCREENSHOT_PASSWORD` — never hardcoded, never printed, never committed.
