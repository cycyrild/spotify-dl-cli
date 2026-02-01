## Faisabilité d'une réimplémentation Rust

Cette évaluation synthétise les éléments du projet Python actuel (`playplay_emulator`) et les implications d’une réimplémentation en Rust.

### Portée fonctionnelle existante
- **Récupération et déchiffrement audio** : `main.py` orchestre la récupération (HTTP), la résolution d’URL, l’obtention d’une clé obfusquée et le déchiffrement des chunks Ogg puis la reconstruction du flux (`ogg_parser.py`).
- **Interopérabilité binaire** : `playplay_emulator/playplay_keygen.py` charge un binaire PE (`bin.exe`) et reproduit sa logique via Unicorn (`KeyEmu`) et des offsets/constants extraits du binaire.
- **Clients réseau** : `clients/*` utilise `requests` et des messages protobuf générés (`proto/*.proto`).

### Équivalents Rust disponibles
- **HTTP / streaming** : `reqwest` (asynchrone ou bloquant) couvre les fonctionnalités `requests`.
- **Protobuf** : `prost` (ou `protobuf` crate) pour générer les messages depuis les `.proto`.
- **PE parsing** : crates comme `goblin` ou `pelite` permettent d’extraire sections/ RVA/ données brutes (remplacement de `pefile`).
- **Émulation Unicorn** : bindings Rust `unicorn-engine` existent ; la logique `KeyEmu` peut être transposée en encapsulant les appels FFI et la mémoire (l’approche et les offsets resteront identiques).
- **Parsing Ogg** : la logique actuelle est simple (découpe de pages). On peut soit la porter telle quelle, soit s’appuyer sur `lewton`/`ogg` pour gérer les pages.

### Points d’attention / risques
- **Stabilité FFI Unicorn** : bien supporté en Rust mais nécessite une gestion manuelle des mappings mémoire et des callbacks (similaire à l’implémentation Python).
- **Manipulation du binaire PE** : garantir une lecture identique des offsets utilisés pour le token/playplay (préserver `ADDR`/`SIZES`). Des tests de non-régression seront nécessaires.
- **Gestion des flux et backpressure** : le streaming chunk par chunk devra conserver l’ordre et la taille (`CHUNK_SIZE`) pour rester compatible avec la reconstruction Ogg.
- **Interop avec le binaire fourni** : si `bin.exe` reste nécessaire, l’API côté Rust doit reproduire les accès mémoire attendus ; sinon, il faudrait recompiler ou extraire la logique, ce qui augmente l’effort.

### Estimation de complexité
- **Faible à modérée** : clients HTTP, protobuf, parsing Ogg.
- **Modérée à élevée** : portage du keygen/émulateur (FFI Unicorn, lecture PE, gestion des états de chiffrement).

### Plan minimal de portage
1) Générer les messages protobuf avec `prost` ; implémenter les clients HTTP (`reqwest`).
2) Porter `ogg_parser.py` en Rust (tests sur des fixtures de pages pour vérifier la continuité).
3) Reproduire `PlayPlayKeygen` : chargement PE (`goblin`/`pelite`), extraction du token, intégration Unicorn via FFI, reproduction des fonctions `obfuscatedInitializeWithKey`, `decryptBufferInPlace`, etc.
4) Rebrancher le flux principal (équivalent de `main.py`) et ajouter des tests d’intégration sur un échantillon chiffré connu (ou fixtures unitaires sur chaque étape).

### Conclusion
La réimplémentation en Rust est **faisable** : l’écosystème fournit des alternatives pour chaque dépendance critique (HTTP, protobuf, parsing PE, Unicorn). Le risque principal réside dans la parité fonctionnelle du moteur d’émulation/déchiffrement. Une phase de tests différentiels (Python vs Rust) sur des fixtures binaires est recommandée pour valider la fidélité du portage.
