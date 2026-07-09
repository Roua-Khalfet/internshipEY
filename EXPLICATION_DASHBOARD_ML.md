# 🧠 Comment le Dashboard et la Base de Données servent ton modèle de Machine Learning (ML) ?

Ce document explique comment la base de connaissances et le tableau de bord interactif que nous avons mis en place vont directement t'aider à concevoir, entraîner et surveiller ton modèle de détection d'anomalies réseau.

---

## 1. Analyse Exploratoire des Données (EDA — Exploratory Data Analysis)
Avant de concevoir n'importe quel modèle ML, il est crucial de comprendre tes données. Le dashboard Streamlit remplit ce rôle en fournissant une visualisation immédiate de la structure de ta base :

*   **Déséquilibre des classes (Class Imbalance)** : Le dashboard montre, par exemple, que le protocole `HTTP` représente ~84% des templates, alors que `DNS` ou `TCP` représentent moins de 1%. Pour ton modèle de détection réseau, cela indique un fort déséquilibre. Tu devras utiliser des techniques spécifiques (comme le sur-échantillonnage, le sous-échantillonnage ou des fonctions de perte pondérées) pour éviter que ton modèle ne devienne biaisé en faveur de HTTP.
*   **Distribution des sévérités** : Savoir qu'une grande partie des templates est classée en `Info` ou `High`/`Critical` te permet de filtrer ton dataset d'entraînement pour te focaliser uniquement sur les menaces ayant un réel impact réseau (ex: ignorer les infos/low pour l'entraînement initial).

---

## 2. Feature Engineering & Encodage des Variables
La table `templates` de la base [nuclei_kb.db](file:///c:/Users/rarou/Desktop/internship/data/nuclei_kb.db) contient des colonnes qui serviront de caractéristiques (*features*) pour alimenter ton modèle de classification ou de détection :

*   **Protocole (`protocol`)** : C'est une variable catégorielle clé. Tu peux la transformer en vecteurs numériques exploitables par ton algorithme en utilisant le **One-Hot Encoding** (pour des modèles comme XGBoost/Random Forest) ou des **Embeddings** (pour des réseaux de neurones).
*   **Sévérité (`severity`)** : C'est une variable catégorielle ordonnée. Tu peux lui appliquer un **Ordinal Encoding** (`info` = 0, `low` = 1, `medium` = 2, `high` = 3, `critical` = 4) pour donner une notion d'importance numérique à chaque flux ou alerte.
*   **Score CVSS (`cvss_score`)** : C'est une caractéristique numérique continue idéale (valeur entre 0.0 et 10.0) pour pondérer la criticité de l'anomalie détectée par ton modèle.
*   **CWE-ID (`cwe_id`)** : Les CWE regroupent les vulnérabilités par famille logique (ex: CWE-79 pour les XSS, CWE-89 pour les injections SQL). Tu peux t'en servir pour faire du **regroupement thématique (Clustering)** ou pour catégoriser les prédictions de ton modèle.
*   **Tags (`tags`)** : En appliquant du traitement de texte (NLP) simple comme **TF-IDF** ou en utilisant des **Sentence Embeddings** (modèles de langage comme BERT), tu peux transformer la liste de tags en un espace vectoriel dense représentant la signature logique de la vulnérabilité.

---

## 3. Labellisation et Vérité Terrain (Ground Truth)
Dans un projet ML supervisé pour la sécurité réseau, le plus difficile est d'avoir des données correctement labellisées (savoir exactement à quelle attaque correspond un flux réseau).

*   **Création de trafic labellisé** : Le **Générateur de commande Nuclei** du dashboard te permet de sélectionner des vulnérabilités spécifiques par tags (ex: `dns`, `rce`). En lançant ces scans ciblés dans un environnement de test contrôlé (sandbox) et en capturant le trafic (fichiers `.pcap`), tu obtiens des flux d'attaques réels et propres. 
*   **Association flux/alertes** : Grâce aux identifiants uniques des templates (`template_id`), tu peux associer de manière déterministe les paquets réseau capturés à leur étiquette réelle (Label) : *« Ce flux réseau correspond au template X, qui exploite la CVE-Y »*.

---

## 4. Gestion du Concept Drift (Dérive de Concept)
Les menaces réseau évoluent constamment (nouvelles vulnérabilités 0-day, nouveaux protocoles ciblés). Un modèle de ML entraîné en 2026 peut devenir obsolète en 2027 : c'est ce qu'on appelle le **Concept Drift**.

*   **Surveillance des flux de menaces** : L'historique des changements du dashboard (`change_log`) et le suivi des nouveaux templates ajoutés chaque semaine te permettent de voir en temps réel si de nouvelles familles de menaces apparaissent.
*   **Déclencheur de réentraînement automatique** : Tu peux configurer ton pipeline pour qu'il déclenche automatiquement un réentraînement de ton modèle ML (Retraining pipeline) si le nombre de nouveaux templates réseau critiques dépasse un certain seuil dans la base SQLite.

---

## 5. Synthèse des correspondances Données ➡️ Modèle

| Donnée brute (Dashboard / DB) | Rôle pour le modèle de Machine Learning | Type de Feature / Utilisation |
| :--- | :--- | :--- |
| **`severity`** | Cible (Label) de classification ou poids de la perte | Ordinal Feature (`0` à `4`) |
| **`protocol`** | Contexte de transport de l'attaque | Categorical Feature (One-Hot Encoded) |
| **`cvss_score`** | Score d'importance ou d'anomalie attendu | Numerical Feature (0.0 à 10.0) |
| **`tags`** & **`description`** | Représentation sémantique de l'attaque | Text Embeddings / TF-IDF |
| **`change_log`** | Détection de dérive (Concept Drift) | Indicateur temporel pour réentraînement |
| **Générateur CLI** | Capture et enregistrement de trafic réseau réel | Outil de génération de dataset d'entraînement |
