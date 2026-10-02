# LanShare

Échange de fichiers/dossiers en LAN, débit maximal, chiffrement optionnel (TLS 1.3).

- `daemon/` — **lanshared** (Rust, tokio, rustls) : découverte UDP, association, transferts.
- `app/` — **lanshare** (Python + PySide6) : systray, zone de dépôt, fenêtre de config, menus contextuels.
- `tests/` — `e2e.py` (deux daemons en loopback), `resume.py` (coupure `kill -9`, pause/reprise, dossier, annulation), `ui_smoke.py` (UI headless). `LANSHARE_THROTTLE=<octets/s>` ralentit l'expéditeur, pour les tests.

## Installation

```sh
cd daemon && cargo build --release          # Windows : toolchain MSVC (ring compile du C)
cd ../app && pip install -e .               # PySide6 (Qt 6)
mkdir -p lanshare/bin && cp ../daemon/target/release/lanshared* lanshare/bin/   # optionnel (sinon trouvé dans target/ ou le PATH)
lanshare                                    # systray ; le daemon est lancé automatiquement
lanshare install-integration                # menus contextuels (par utilisateur, sans admin)
```

Ports : UDP 47652 (découverte), TCP 47653 (échange). À autoriser dans le pare-feu (Windows le propose au 1er lancement).

## Fonctionnement

**Découverte / association.** Avec *Broadcast* activé, la machine annonce sa présence toutes les 3 s. « Rechercher » envoie un `search` : chaque machine en broadcast répond et *propose d'ajouter* le chercheur (notification). Chaque côté clique « Associer » (vérifier l'empreinte affichée). Quand les deux se sont ajoutés, ils échangent un **JWT EdDSA** (pas de x509) : chacun émet pour l'autre un jeton signé de sa clé, que l'autre présentera à chaque connexion. L'identité d'une machine est sa clé publique ed25519 (= son id). L'association transporte `os`, `uid`, `gid`.

**Authentification.** À chaque connexion : JWT + preuve de possession de clé (signatures croisées sur des nonces). Un jeton sniffé est donc inutilisable seul.

**Chiffrement.** « Exiger le chiffrement » est un réglage local. Si au moins un des deux le demande → TLS 1.3 (rustls), sinon flux en clair. Le certificat TLS est dérivé de la clé ed25519 et **épinglé** sur la clé publique du pair (pas de CA).
Un client qui exige le chiffrement refuse de continuer si le pair répond « en clair ».

**Transfert.** Trame de métadonnées (`nom`, `file|dir`, `taille` optionnelle, mode, uid, gid) → le destinataire est notifié, **choisit la destination** (boîte « Enregistrer sous » de l'OS) → flux brut (fichier) ou suite d'enregistrements binaires (dossier : en-tête compact d'environ 30 octets par élément — tar en impose 512 — puis ses octets ; les petits fichiers ≤ 128 Ko sont groupés avec leur en-tête dans un seul write, sans flush par élément), tampons 1 Mo, pipeline disque/réseau, sockets 4 Mo. Symlinks ignorés à l'envoi ; setuid retiré, chemins `..`/absolus/`:` refusés à la réception.

**Reprise.** Chaque transfert a un identifiant stable (`tid`). Le destinataire garde le fichier partiel et un enregistrement persistant (`transfers.json`, survit à un redémarrage du daemon). Sur coupure réseau, l'expéditeur réessaie seul (backoff 1→15 s, abandon après 10 min sans succès, puis « échec » réessayable à la main) et le destinataire répond avec l'offset qu'il possède : le fichier courant reprend au dernier octet reçu, sans nouvelle demande à l'utilisateur. Pour un dossier, les éléments terminés sont sautés et l'élément courant reprend à son offset. **Pause / Reprendre / Annuler** sont disponibles des deux côtés (onglet Transferts) ; si le destinataire met en pause, l'expéditeur attend et reprend dès que le destinataire relance. Si la source a changé entre-temps, le transfert passe en échec plutôt que de produire un fichier incohérent. Un redémarrage du daemon laisse les transferts « interrompus » : l'expéditeur les relance via Reprendre.

**uid/gid.** Table de remapping par client (fenêtre de config). Appliquée à la réception sous Unix seulement et si le process a le droit de `chown`. Sous Windows l'utilisateur est toujours annoncé `1000:1000` (admin ou non) ; les fichiers reçus appartiennent à l'utilisateur local et héritent des ACL du dossier choisi. Aucune élévation (pas de service SYSTEM, pas d'UAC).

**Services.** Menu systray : Broadcast / Échange (listener TCP) / Quitter tout. Fenêtre de config : clients (bloquer, retirer, mapper), découverte, transferts, paramètres.

## Limites connues

- **Glisser-déposer sur l'icône du systray : impossible.** Ni Qt, ni Windows, ni les barres Linux (SNI) ne transmettent les drops à une icône de notification. À la place : une **zone de dépôt** flottante (menu systray → « Zone de dépôt ») qui ouvre le choix du destinataire.
- Les notifications Qt n'ont pas de boutons : on **clique** sur la notification (ou sur « Réceptions en attente » du menu) pour choisir la destination.
- Le mode « en clair » n'authentifie que l'établissement de la connexion, pas le flux (choix voulu : c'est le mode sans chiffrement).
- Testé sous Linux uniquement (daemon + UI headless). Windows (registre HKCU, ACL) et macOS (Quick Action Automator) : écrits mais non testés.
- Plusieurs éléments déposés ensemble = autant de demandes de réception.
