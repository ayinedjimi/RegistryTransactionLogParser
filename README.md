# 🚀 RegistryTransactionLogParser


**WinToolsSuite Serie 3 - Forensics Tool #20**

## 📋 Description

RegistryTransactionLogParser est un outil forensique avancé permettant de parser et analyser les fichiers de transaction logs du registre Windows (`.LOG`, `.LOG1`, `.LOG2`). Il permet la reconstruction des modifications registry ante-mortem (avant crash/shutdown brutal) et la détection de modifications malveillantes non commitées.


## ✨ Fonctionnalités

### Parsing de Transaction Logs
- **Fichiers supportés** : `C:\Windows\System32\config\*.LOG` (SYSTEM.LOG, SOFTWARE.LOG, SAM.LOG, SECURITY.LOG, etc.)
- **Format analysé** :
  - Base block (header REGF)
  - Dirty pages (modifications non commitées)
  - Log entries (séquences de transactions)
  - Signatures : `HvLE` (Hive Log Entry), `hknh` (Hive Key Node Header)

### Reconstruction de Modifications
- **Extraction des données** :
  - Key path (chemin de clé registry)
  - Value name (nom de la valeur modifiée)
  - Data before/after (données avant/après modification)
  - Timestamp de transaction
  - Transaction ID (numéro de séquence)
  - Offset dans le fichier
- **Cas d'usage** :
  - Crash système brutal (perte d'électricité)
  - Shutdown forcé avant commit
  - Malware modifiant le registre puis crashant le système

### Comparaison avec Hive Actuel
- Comparaison des modifications dans le log avec l'état actuel du registre
- Détection de divergences (modifications non appliquées)
- Identification de clés/valeurs restaurées après incident

### Interface Graphique
- **ListView 7 colonnes** :
  - **Timestamp** : Horodatage de la transaction (avec numéro de séquence)
  - **Hive File** : Nom du hive (SYSTEM, SOFTWARE, etc.)
  - **Key Path** : Chemin de la clé modifiée
  - **Value Name** : Nom de la valeur
  - **Data Before** : Données avant modification
  - **Data After** : Données après modification (format hex si binaire)
  - **TxID** : Identifiant de transaction (séquence)

- **Contrôles** :
  - Champ de texte + bouton "Parcourir" pour sélectionner le fichier LOG
  - Bouton "Charger LOG" : Valide et charge le fichier
  - Bouton "Parser Transactions" : Analyse le log en background thread
  - Bouton "Comparer avec Hive" : Comparaison avec registre actuel
  - Bouton "Exporter CSV" : Export des résultats

### Export et Logging
- **Export CSV UTF-8** avec BOM
- **Colonnes** : Timestamp, HiveFile, KeyPath, ValueName, DataBefore, DataAfter, TxID
- **Logging automatique** : `RegistryTransactionLogParser.log` (opérations, erreurs, statistiques)


## Architecture Technique

### APIs Utilisées
- **File I/O** : `CreateFile`, `ReadFile` pour parsing binaire des logs
- **advapi32.lib** : APIs Registry (pour comparaison future)
- **comctl32.lib** : ListView et contrôles common controls
- **shlwapi.lib** : `PathFileExists`, `PathRemoveFileSpec`, `PathFindFileName`

### Structures de Données

#### REGF_HEADER (Header de Hive)
```cpp
struct REGF_HEADER {
    DWORD signature;      // "regf" (0x66676572)
    DWORD sequence1;      // Numéro de séquence primaire
    DWORD sequence2;      // Numéro de séquence secondaire
    FILETIME timestamp;   // Dernière écriture
    DWORD majorVersion;
    DWORD minorVersion;
    DWORD type;
    DWORD format;
    DWORD rootCellOffset;
    DWORD hiveSize;
    // ...
};
```

#### LOG_ENTRY_HEADER (Dirty Page Entry)
```cpp
struct LOG_ENTRY_HEADER {
    DWORD signature;      // "HvLE" (0x656C7648)
    DWORD size;           // Taille de l'entrée
    DWORD offset;         // Offset dans le hive
    DWORD sequenceNumber; // Numéro de séquence
    BYTE data[1];         // Données variables
};
```

### Algorithme de Parsing

1. **Ouverture du fichier LOG**
   - Validation de l'existence
   - Lecture complète en mémoire (buffer)

2. **Recherche de signatures**
   - Scan séquentiel pour trouver `HvLE` (0x656C7648)
   - Validation de la taille d'entrée

3. **Extraction de métadonnées**
   - Récupération du nom du hive depuis le chemin
   - Extraction du numéro de séquence (TxID)
   - Conversion de l'offset

4. **Extraction de key path**
   - Heuristique : recherche de strings Unicode dans les données
   - Filtrage de caractères imprimables (32-126)
   - Fallback : affichage de l'offset si pas de string trouvée

5. **Affichage dans ListView**
   - Tri par ordre chronologique (séquence)
   - Formatage des données binaires en hexadécimal

### Threading
- **Worker thread** pour le parsing (opération I/O intensive)
- **UI thread** reste réactive pendant l'analyse
- **Communication** : `WM_USER + 1` pour signaler fin de parsing
- **Synchronisation** : `volatile bool stopProcessing` pour arrêt propre

### RAII
- **FileHandle** : Wrapper RAII pour `HANDLE` de fichier
  - Fermeture automatique dans le destructeur
  - Méthode `valid()` pour vérification


## 🚀 Utilisation

### Scénario 1 : Analyse Forensique Post-Crash

1. **Récupération des logs** :
   ```
   C:\Windows\System32\config\SYSTEM.LOG
   C:\Windows\System32\config\SOFTWARE.LOG1
   ```

2. **Chargement dans l'outil** :
   - Cliquer sur "Parcourir"
   - Sélectionner le fichier LOG
   - Cliquer "Charger LOG"

3. **Parsing** :
   - Cliquer "Parser Transactions"
   - Attendre la fin de l'analyse (status bar)

4. **Analyse des résultats** :
   - Trier par timestamp pour chronologie
   - Chercher des clés suspectes (Run, Services, etc.)
   - Identifier les modifications non commitées

5. **Export** :
   - Cliquer "Exporter CSV"
   - Analyse ultérieure dans Excel/Python

### Scénario 2 : Détection de Malware Furtif

1. **Contexte** : Malware qui modifie le registre puis crash volontairement le système pour éviter la détection

2. **Analyse** :
   - Charger `SOFTWARE.LOG1` et `SOFTWARE.LOG2`
   - Parser les transactions
   - Comparer avec hive actuel

3. **Recherche de divergences** :
   - Clés présentes dans le LOG mais absentes du hive actuel
   - Valeurs modifiées puis restaurées

4. **Clés à surveiller** :
   - `Software\Microsoft\Windows\CurrentVersion\Run`
   - `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
   - `Software\Classes\exefile\shell\open\command`

### Scénario 3 : Timeline de Modifications Système

1. **Parser plusieurs logs** :
   - SYSTEM.LOG (configuration système)
   - SOFTWARE.LOG (applications)
   - SAM.LOG (comptes utilisateurs)

2. **Reconstruction chronologique** :
   - Trier par séquence/timestamp
   - Corréler avec événements système (Event Logs)

3. **Détection d'anomalies** :
   - Modifications à des heures inhabituelles
   - Transactions multiples sur des clés sensibles
   - Patterns de modification suspects


## 🚀 Cas d'Usage Forensique

### 1. Attaque par Ransomware
- **Observation** : Modifications massives de clés de démarrage
- **Transaction logs** : Montrent les modifications avant chiffrement
- **Utilité** : Reconstruction de l'état avant attaque

### 2. Rootkit Mode Utilisateur
- **Observation** : Modifications de `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
- **Transaction logs** : Révèlent le debugger malveillant configuré
- **Utilité** : Même si le rootkit nettoie après lui

### 3. Persistence APT
- **Observation** : Ajouts dans `Run`, `Services`, `Scheduled Tasks`
- **Transaction logs** : Timestamps précis d'installation
- **Utilité** : Corrélation avec network logs pour attribution

### 4. Incident Response
- **Observation** : Système crashé avant finalisation d'une attaque
- **Transaction logs** : Modifications en cours non commitées
- **Utilité** : Comprendre l'intention de l'attaquant


## Format des Transaction Logs

### Structure Générale
```
[REGF Header] (optionnel selon version)
[LOG Entry 1]
  - Signature: HvLE
  - Size: 0x1000
  - Offset: 0x00023000
  - Sequence: 42
  - Data: [dirty page content]
[LOG Entry 2]
  ...
```

### Dirty Pages
- **Définition** : Pages de registre modifiées mais non encore écrites sur disque
- **Commit** : Lors d'un flush registry, les dirty pages sont appliquées au hive principal
- **Perte** : Si crash avant commit, les modifications sont perdues
- **Forensics** : Les logs contiennent ces modifications perdues !

### Séquences de Transaction
- **Numéro de séquence** : Monotone croissant
- **Ordre d'application** : Les logs doivent être appliqués dans l'ordre des séquences
- **Rollback** : En cas d'erreur, les transactions peuvent être annulées

### Fichiers LOG Multiples
- **LOG** : Transaction log principal
- **LOG1** : Ancien log (après rotation)
- **LOG2** : Très ancien log (après double rotation)
- **Stratégie** : Analyser tous les fichiers pour timeline complète


## Limitations et Évolutions Futures

### Limitations Actuelles
1. **Parsing heuristique** : Extraction de key path approximative
2. **Comparaison simulée** : Nécessite implémentation complète avec APIs Registry
3. **Support limité** : Certaines structures avancées non parsées
4. **Pas de reconstruction** : Pas d'application réelle des transactions

### Évolutions Futures
1. **Parser complet** :
   - Support de toutes les versions Windows (XP à 11)
   - Décodage complet des structures hive (hbin, nk, vk, sk)

2. **Reconstruction active** :
   - Appliquer les transactions à un hive de test
   - Comparaison byte-à-byte avec hive actuel

3. **Détection avancée** :
   - Signatures de malware connus dans les modifications
   - Machine learning pour détecter anomalies

4. **Visualisation** :
   - Timeline graphique des modifications
   - Graph de dépendances entre clés

5. **Integration** :
   - Export vers outils SIEM
   - API pour automation


## Compilation

### Prérequis
- Visual Studio 2019 ou supérieur
- Windows SDK 10.0 ou supérieur
- Architecture : x86 ou x64

### Build
```batch
go.bat
```

### Fichiers Générés
- `RegistryTransactionLogParser.exe` (exécutable principal)
- `RegistryTransactionLogParser.log` (fichier de log au runtime)


## Références Techniques

### Documentation Microsoft
- [Registry Hive File Format](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md)
- [Transaction Log Format](https://github.com/msuhanov/regf/blob/master/Dirty%20pages%20and%20transaction%20logs.md)

### Outils Similaires
- **regripper** : Perl-based registry parser
- **Registry Decoder** : Log2Timeline integration
- **Zimmerman's Registry Explorer** : GUI pour analyse complète

### Structures Registry
- **Base Block** : Header du hive
- **Hbin** : Allocation bin (4KB aligned)
- **Cell** : Unité de données (nk, vk, sk, lf, lh)
- **nk** : Named Key (clé)
- **vk** : Value Key (valeur)
- **sk** : Security Key (ACL)


## 🔒 Sécurité et Bonnes Pratiques

### Permissions Requises
- **Lecture** : Accès aux fichiers `C:\Windows\System32\config\*.LOG`
- **Recommandation** : Exécuter en tant qu'Administrateur
- **Alternative** : Copier les fichiers LOG vers un emplacement accessible

### Analyse Hors-Ligne
1. **Boot forensique** : Démarrer sur un CD/USB live
2. **Copie des logs** : Extraire les fichiers LOG vers média externe
3. **Analyse sur poste dédié** : Parser sans risque de contamination

### Chain of Custody
- **Hash** : Calculer SHA-256 des fichiers LOG avant analyse
- **Log** : Toutes les opérations sont loggées avec timestamp
- **Export** : CSV signé pour preuve légale


## 🔧 Troubleshooting

### Erreur : "Impossible d'ouvrir le fichier LOG"
- **Cause** : Permissions insuffisantes ou fichier verrouillé
- **Solution** : Exécuter en tant qu'Administrateur ou copier le fichier

### Erreur : "Fichier LOG vide ou invalide"
- **Cause** : Fichier corrompu ou mauvais format
- **Solution** : Vérifier la taille du fichier (doit être > 512 bytes)

### Erreur : "Aucune transaction trouvée"
- **Cause** : Fichier LOG sans dirty pages (système proprement arrêté)
- **Solution** : Normal, essayer un autre fichier LOG

### Performance : Parsing très lent
- **Cause** : Fichier LOG volumineux (> 100 MB)
- **Solution** : Attendre, le parsing est fait en thread background


## 📄 Licence

MIT License - WinToolsSuite Project


## 👤 Auteur

WinToolsSuite Development Team


## 📝 Changelog

### Version 1.0 (2025)
- Version initiale
- Parsing de base des transaction logs
- Support .LOG, .LOG1, .LOG2
- Export CSV UTF-8
- Interface graphique française
- Logging complet


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>