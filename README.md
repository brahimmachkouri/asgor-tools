# asgor-tools

Outils pour les développeurs, à utiliser avec les rapports d'[ASGOR](https://github.com/brahimmachkouri/asgor) (*Automated Security Grading Of Repositories*).

| Outil | Rôle |
|---|---|
| [`corriger_dependances.py`](corriger_dependances.py) | lit un rapport JSON exporté depuis ASGOR et met à jour les dépendances vulnérables du dépôt analysé, sur une branche Git à part (npm, pnpm, Composer) |

---

## Avertissement

**`corriger_dependances.py` modifie le dépôt sur lequel il est lancé** : fichiers de dépendances (`package.json`, `package-lock.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `composer.lock`), `node_modules/` et `vendor/`. Il exécute des commandes (npm, pnpm, Composer) et les tests du projet, donc du code du projet.

**Une mise à jour de dépendance peut casser l'application**, même si les tests réussissent. La branche Git créée par le script ne protège pas `node_modules/` ni `vendor/`, qui ne sont pas suivis par Git.

Avant de l'utiliser :

- sauvegardez vos données et travaillez de préférence sur une **copie isolée** du dépôt ;
- affichez d'abord le plan, sans rien modifier (`--plan`) ;
- relisez les changements et vérifiez l'application avant de les fusionner. La décision de fusionner revient à l'utilisateur.

Les rapports d'ASGOR peuvent être incomplets ou comporter des erreurs. Ce logiciel est fourni « tel quel », sans garantie d'aucune sorte (voir [`LICENSE`](LICENSE)). Les exclusions de garantie et limitations de responsabilité de la licence s'appliquent dans les limites autorisées par le droit applicable.

---

## corriger_dependances.py

### Prérequis

- Python 3 (bibliothèque standard seulement, rien à installer) ;
- Git, et selon le projet : npm, pnpm ou Composer ;
- un rapport JSON exporté depuis ASGOR (bouton « JSON » de la page du rapport), pour le même dépôt et le même commit.

### Utilisation

```bash
# Voir ce qui serait fait, sans rien modifier
python3 corriger_dependances.py rapport.json --plan --depot ~/mon-projet

# Appliquer (une confirmation est demandée)
python3 corriger_dependances.py rapport.json --depot ~/mon-projet
```

Le dépôt doit être propre (aucune modification non enregistrée dans Git), sinon le script refuse de continuer.

### Ce que fait le script

Pour chaque dossier qui contient un `package-lock.json`, un `pnpm-lock.yaml` ou un `composer.lock` cité par le rapport :

1. Il regroupe les paquets vulnérables, garde pour chacun la plus haute version corrigée et signale les changements de version majeure.
2. Il affiche ce plan et attend votre confirmation.
3. Il crée une branche Git (`asgor/corrections-<date>`).
4. Il met à jour les dépendances :
   - **npm** : `npm audit fix` (jamais `--force`), puis des « overrides » dans `package.json` pour les dépendances indirectes encore vulnérables, seulement sans changement de version majeure, et limités à la série installée (exemple : `"debug@>=2.0.0 <2.6.9": "^2.6.9"`, qui ne touche pas aux copies 3.x et 4.x). Le script compare ensuite le verrou avant et après : il signale chaque paquet resté à la même version qui reçoit une autre version majeure d'une de ses dépendances. npm le permet sans `--force` quand la plage demandée est `*`. C'est le principal risque de casse, et le script indique comment garder l'ancienne version.
   - **pnpm** : `pnpm audit --fix` (« overrides » dans `pnpm-workspace.yaml`), puis `pnpm install`. Le script signale les overrides qui font changer une dépendance installée de version majeure, et un `pnpm-lock.yaml` déjà périmé avant la correction.
   - **Composer** : `composer update <paquets> --with-all-dependencies`. Si une contrainte de `composer.json` empêche toute version corrigée, le script le dit et passe à la suite : élargir la contrainte est votre décision. Si Composer refuse la mise à jour groupée, le script essaie les paquets un par un. Il fait ensuite un second passage pour les paquets que `composer audit` signale encore et qui ne sont bloqués par rien.
   - **`composer.lock` périmé** (il ne correspond plus à `composer.json`) : le script ne régénère pas le verrou. Il simule un `composer update` complet et affiche les changements de version majeure : c'est à vous de décider.
5. Il relance `npm audit`, `pnpm audit` ou `composer audit`, puis les tests du projet une fois tous les dossiers traités, et affiche ce qui reste.

### Ce qu'il ne fait pas

- Il ne pousse rien vers GitHub et ne crée pas de « pull request » : vous relisez la branche, puis vous décidez.
- Il n'exécute pas les scripts des paquets (npm et pnpm `--ignore-scripts`, Composer `--no-scripts --no-plugins`), sauf avec `--avec-scripts`.
- Il ne corrige pas un paquet pour lequel aucune version corrigée n'est publiée : il le signale.
- Il ne traite pas yarn, poetry, uv et pipenv : ils sont listés dans le plan, avec la commande à lancer à la main.
- Il ne peut rien installer sans ce que le projet exige (jeton d'un registre npm privé, paquet Composer chargé depuis un dossier local) : le plan signale ces cas avant toute modification.

### Options

| Option | Effet |
|---|---|
| `--plan` | affiche le plan seulement, ne modifie rien |
| `--depot <dossier>` | racine du dépôt analysé (par défaut : dossier courant) |
| `--oui` | ne demande pas de confirmation |
| `--sans-branche` | ne crée pas de branche Git |
| `--sans-tests` | ne lance pas les tests du projet |
| `--avec-scripts` | autorise les scripts des paquets (npm, pnpm, Composer) |
| `--forcer` | accepte un dépôt qui a des modifications non enregistrées dans Git |

`--oui`, `--sans-branche`, `--forcer` et `--avec-scripts` retirent une partie des protections : à utiliser en connaissance de cause.

### Tests

```bash
python3 -m unittest discover -p "test_*.py"
```

Les tests utilisent de faux npm, pnpm et Composer : ils ne touchent à aucun vrai dépôt.

---

## Licence

[MIT](LICENSE) © 2026 BM
