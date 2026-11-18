#!/usr/bin/env python3
"""Corrige les dépendances vulnérables listées dans un rapport JSON d'ASGOR.

AVERTISSEMENT : ce script MODIFIE le dépôt (fichiers de dépendances, node_modules/,
vendor/) et exécute des commandes (npm, pnpm, Composer, tests du projet). Une mise à
jour de dépendance peut CASSER L'APPLICATION, même si les tests réussissent.
Sauvegardez vos données, travaillez sur une copie isolée du dépôt, lancez d'abord
--plan, relisez les changements avant de les fusionner. Fourni « tel quel », sans
garantie (licence MIT). Source : https://github.com/brahimmachkouri/asgor-tools

À lancer sur le poste du développeur, dans le dépôt analysé (pas sur la VM).

    python3 corriger_dependances.py rapport.json --plan          # afficher le plan seulement
    python3 corriger_dependances.py rapport.json --depot ~/projet  # appliquer, après confirmation

Pour chaque dossier qui contient un fichier de verrouillage cité par le rapport :

1. regroupe les paquets vulnérables, garde la plus haute version corrigée de chacun,
   signale les changements de version majeure ;
2. affiche le plan et demande confirmation ;
3. crée une branche Git ;
4. npm : `npm audit fix` (jamais --force), puis des « overrides » dans package.json
   pour les dépendances indirectes encore vulnérables, seulement sans changement de
   version majeure ;
   Composer : `composer update <paquets> --with-all-dependencies` (respecte composer.json ;
   si une contrainte de composer.json bloque toute version corrigée, le script le dit
   et passe à la suite : élargir la contrainte est une décision du développeur), puis
   un second passage pour les paquets que `composer audit` signale encore sans qu'ils
   soient bloqués. Si composer.lock est périmé (il ne correspond plus à composer.json),
   le script ne le régénère pas : il simule un `composer update` complet et en affiche
   les changements de version majeure, pour que le développeur décide ;
   pnpm : `pnpm audit --fix` (overrides), puis `pnpm install`, en signalant les overrides
   qui imposent un changement de version majeure et un pnpm-lock.yaml déjà périmé ;
5. relance `npm audit` / `composer audit` / `pnpm audit`, puis les tests de chaque dossier
   une fois tous les dossiers traités (les tests d'un dossier peuvent avoir besoin des
   dépendances d'un autre), et affiche ce qui reste.

Par défaut, les scripts des paquets ne sont pas exécutés (npm et pnpm --ignore-scripts,
composer --no-scripts --no-plugins) : option --avec-scripts pour les autoriser.

Les autres gestionnaires (yarn, pip…) sont listés dans le plan, à traiter à la main.
Bibliothèque standard de Python uniquement.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

ECOSYSTEMES = {
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "composer.lock": "composer",
}
NON_GERES = {
    "yarn.lock": "yarn (essayer : yarn up <paquet>)",
    "poetry.lock": "poetry (poetry update <paquet>)",
    "uv.lock": "uv (uv lock --upgrade-package <paquet>)",
    "Pipfile.lock": "pipenv (pipenv update <paquet>)",
}

_NOM_NPM = re.compile(r"(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")
_NOM_COMPOSER = re.compile(r"[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*")
_VERSION = re.compile(r"v?[0-9][0-9A-Za-z.+-]{0,60}")
_NUMERIQUE = re.compile(r"v?(\d+(?:\.\d+)*)")


# ------------------------------------------------------------------- versions

def cle_version(version: str) -> tuple:
    """(1, 13, 2) pour « 1.13.2 » ; préversion (« 2.0.0-beta ») classée avant la finale."""
    m = _NUMERIQUE.match(version or "")
    if not m:
        return ((), 0)
    parties = tuple(int(x) for x in m.group(1).split("."))
    while len(parties) > 1 and parties[-1] == 0:
        parties = parties[:-1]
    finale = 1 if re.fullmatch(r"v?\d+(\.\d+)*", version) else 0
    return (parties, finale)


def plus_haute(versions) -> str:
    return max(versions, key=cle_version)


def majeure(version: str) -> tuple:
    """Partie « compatible » au sens semver : (1,) pour 1.x ; (0, 4) pour 0.4.x."""
    parties = cle_version(version)[0]
    if not parties:
        return ()
    if parties[0] == 0 and len(parties) > 1:
        return parties[:2]
    return parties[:1]


def changement_majeur(installee: str, cible: str) -> bool:
    if not installee or not cible:
        return False
    a, b = majeure(installee), majeure(cible)
    return bool(a) and bool(b) and a != b


# -------------------------------------------------------------------- le plan

@dataclass
class Paquet:
    nom: str
    installee: str = ""
    cible: str = ""
    gravite: str = ""
    identifiants: set = field(default_factory=set)

    @property
    def majeur(self) -> bool:
        return changement_majeur(self.installee, self.cible)


@dataclass
class Dossier:
    chemin: str                 # relatif à la racine du dépôt ("" = racine)
    verrou: str                 # nom du fichier de verrouillage
    ecosysteme: str             # npm, composer, ou "" (non géré)
    paquets: dict = field(default_factory=dict)
    refuses: list = field(default_factory=list)   # noms ou versions de forme inattendue
    perime: bool = False        # le rapport signale un verrou qui ne correspond plus au manifeste


RANG = {"Critique": 0, "Élevée": 1, "Moyenne": 2, "Faible": 3, "Information": 4}


def lire_rapport(chemin: str) -> dict:
    with open(chemin, encoding="utf-8") as f:
        rapport = json.load(f)
    if not isinstance(rapport, dict) or not isinstance(rapport.get("problemes"), list):
        raise ValueError("ce fichier n'est pas un rapport JSON d'ASGOR")
    return rapport


REGLE_VERROU_PERIME = "composer-lock-perime"   # problème écrit par le moteur ASGOR


def construire_plan(rapport: dict) -> list:
    dossiers = {}
    for p in rapport["problemes"]:
        if not isinstance(p, dict) or p.get("domaine") != "dependances":
            continue
        fichier, nom = p.get("fichier"), p.get("paquet")
        if not isinstance(fichier, str) or not fichier:
            continue
        if fichier.startswith("/") or ".." in fichier.split("/"):
            continue  # chemin anormal : ignoré
        perime = p.get("regle") == REGLE_VERROU_PERIME
        if not perime and (not isinstance(nom, str) or not nom):
            continue
        dossier, verrou = os.path.split(fichier)
        ecosysteme = ECOSYSTEMES.get(verrou, "")
        cle = (dossier, verrou)
        if cle not in dossiers:
            dossiers[cle] = Dossier(chemin=dossier, verrou=verrou, ecosysteme=ecosysteme)
        d = dossiers[cle]
        if perime:
            d.perime = True
            continue
        motif = _NOM_NPM if ecosysteme == "npm" else _NOM_COMPOSER if ecosysteme == "composer" else None
        cible = p.get("version_corrigee") or ""
        if motif is not None and not motif.fullmatch(nom):
            d.refuses.append(nom)
            continue
        if cible and not _VERSION.fullmatch(cible):
            d.refuses.append(f"{nom} (version « {cible[:30]} »)")
            continue
        paquet = d.paquets.setdefault(nom, Paquet(nom=nom))
        if isinstance(p.get("version"), str) and _VERSION.fullmatch(p["version"]):
            paquet.installee = paquet.installee or p["version"]
        if cible:
            paquet.cible = plus_haute([v for v in (paquet.cible, cible) if v])
        g = p.get("gravite", "")
        if not paquet.gravite or RANG.get(g, 9) < RANG.get(paquet.gravite, 9):
            paquet.gravite = g
        paquet.identifiants.update(i for i in p.get("identifiants") or [] if isinstance(i, str))
    ordre = {"composer": 0, "npm": 1, "pnpm": 1}
    return sorted(dossiers.values(),
                  key=lambda d: (d.ecosysteme == "", d.chemin, ordre.get(d.ecosysteme, 2), d.verrou))


def afficher_plan(plan: list, rapport: dict, racine_plan: str = "") -> None:
    depot = rapport.get("depot", {})
    print(f"Rapport : {depot.get('url', '?')} — commit {str(depot.get('commit', ''))[:10]}")
    for d in plan:
        emplacement = os.path.join(d.chemin, d.verrou) if d.chemin else d.verrou
        gestion = d.ecosysteme or NON_GERES.get(d.verrou, "gestionnaire non reconnu")
        print(f"\n== {emplacement} ({gestion}) : {len(d.paquets)} paquet(s)")
        if not d.ecosysteme:
            print("   À traiter à la main.")
        if d.perime:
            print(f"   ⚠ {d.verrou} PÉRIMÉ : il ne correspond plus au manifeste du dossier "
                  "(voir le bilan)")
        for paquet in sorted(d.paquets.values(), key=lambda q: (RANG.get(q.gravite, 9), q.nom)):
            cible = paquet.cible or "aucune version corrigée connue"
            alerte = "   ⚠ CHANGEMENT DE VERSION MAJEURE" if paquet.majeur else ""
            print(f"   {paquet.gravite:<9} {paquet.nom:<40} {paquet.installee or '?':>12} -> {cible}{alerte}")
        for refus in d.refuses:
            print(f"   ignoré (forme inattendue) : {refus}")
        if d.ecosysteme == "npm" and racine_plan:
            for registre in registres_prives(os.path.join(racine_plan, d.chemin), d.verrou):
                print(f"   ⚠ registre privé : {registre} — npm demandera un jeton d'accès")
        if d.ecosysteme == "composer" and racine_plan:
            for chemin in depots_locaux_absents(os.path.join(racine_plan, d.chemin)):
                print(f"   ⚠ composer.json charge un paquet depuis {chemin}, absent de ce poste : "
                      "composer update et composer install échoueront")


# --------------------------------------------------------------- application

class Arret(Exception):
    pass


def lancer(commande, dossier, accepter=(0,), capturer=False):
    print(f"   $ {' '.join(commande)}   (dans {dossier})")
    resultat = subprocess.run(commande, cwd=dossier, text=True,
                              capture_output=capturer, stdin=subprocess.DEVNULL)
    if resultat.returncode not in accepter:
        raise Arret(f"la commande a échoué (code {resultat.returncode}) : {' '.join(commande)}")
    return resultat


def verifier_git(racine: str, forcer: bool) -> None:
    """Les chemins du rapport partent de la racine du dépôt : --depot doit être cette racine."""
    r = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=racine, text=True,
                       capture_output=True)
    if r.returncode != 0:
        raise Arret(f"{racine} n'est pas dans un dépôt Git")
    if os.path.realpath(r.stdout.strip()) != os.path.realpath(racine):
        raise Arret(f"--depot doit être la racine du dépôt : {r.stdout.strip()}")
    etat = subprocess.run(["git", "status", "--porcelain"], cwd=racine, text=True,
                          capture_output=True, check=True).stdout
    if etat.strip():
        if not forcer:
            raise Arret("le dépôt a des modifications non enregistrées : faites un commit ou "
                        "un « git stash » d'abord (ou --forcer)")
        print("Attention : le dépôt a des modifications non enregistrées (--forcer).")


def creer_branche(racine: str) -> str:
    nom = "asgor/corrections-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    lancer(["git", "switch", "-c", nom], racine)
    return nom


def audit_npm(dossier: str) -> dict:
    r = lancer(["npm", "audit", "--json"], dossier, accepter=(0, 1), capturer=True)
    try:
        return json.loads(r.stdout or "{}").get("vulnerabilities", {}) or {}
    except ValueError:
        return {}


def audit_composer(dossier: str) -> dict:
    r = lancer(["composer", "audit", "--locked", "--format=json", "--no-interaction"],
               dossier, accepter=tuple(range(0, 8)), capturer=True)
    try:
        avis = json.loads(r.stdout or "{}").get("advisories", {}) or {}
    except ValueError:
        return {}
    return avis if isinstance(avis, dict) else {}


def ajouter_overrides(dossier: str, overrides: dict) -> None:
    """Ajoute des « overrides » à package.json en gardant l'ordre des clés."""
    chemin = os.path.join(dossier, "package.json")
    with open(chemin, encoding="utf-8") as f:
        texte = f.read()
    donnees = json.loads(texte)
    existants = donnees.get("overrides") or {}
    if not isinstance(existants, dict):
        raise Arret("la clé « overrides » de package.json a une forme inattendue")
    existants.update(overrides)
    donnees["overrides"] = existants
    retrait = 4 if texte.startswith("{\n    ") else 2
    with open(chemin, "w", encoding="utf-8") as f:
        f.write(json.dumps(donnees, indent=retrait, ensure_ascii=False) + "\n")


SECTIONS_NPM = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def dependances_directes(dossier: str) -> set:
    with open(os.path.join(dossier, "package.json"), encoding="utf-8") as f:
        donnees = json.load(f)
    return {nom for section in SECTIONS_NPM for nom in (donnees.get(section) or {})}


def chemins_vendor(dossier: str) -> list:
    """Dépendances npm qui pointent vers vendor/ (Symfony UX : fournies par Composer)."""
    with open(os.path.join(dossier, "package.json"), encoding="utf-8") as f:
        donnees = json.load(f)
    chemins = []
    for section in SECTIONS_NPM:
        for valeur in (donnees.get(section) or {}).values():
            if isinstance(valeur, str) and valeur.startswith("file:") and "vendor/" in valeur:
                chemins.append(valeur[len("file:"):])
    return chemins


def preparer_vendor(dossier: str, avec_scripts: bool) -> str:
    """Installe les dépendances Composer si package.json en a besoin et qu'elles manquent."""
    manquants = [c for c in chemins_vendor(dossier)
                 if not os.path.exists(os.path.join(dossier, c))]
    if not manquants:
        return ""
    if not os.path.isfile(os.path.join(dossier, "composer.lock")) or shutil.which("composer") is None:
        raise Arret(f"package.json utilise {manquants[0]}, fourni par Composer : lancer d'abord "
                    "« composer install » dans ce dossier")
    scripts = [] if avec_scripts else ["--no-scripts", "--no-plugins"]
    r = lancer(["composer", "install", "--no-interaction", *scripts], dossier,
               accepter=tuple(range(0, 256)), capturer=True)
    if r.returncode != 0:
        raise Arret(f"package.json utilise {manquants[0]}, fourni par Composer, mais « composer "
                    f"install » a échoué (code {r.returncode}) : "
                    + dernieres_lignes((r.stdout or "") + (r.stderr or "")))
    return f"composer install lancé d'abord : package.json utilise {len(manquants)} paquet(s) de vendor/"


def depots_locaux_absents(dossier: str) -> list:
    """Dépôts Composer de type « path » introuvables sur ce poste.

    Exemple réel : {"type": "path", "url": "/Users/dev/Web/TableBundle"},
    le dossier du mainteneur : Composer ne peut rien installer ailleurs.
    """
    try:
        with open(os.path.join(dossier, "composer.json"), encoding="utf-8") as f:
            depots = json.load(f).get("repositories") or []
    except (OSError, ValueError, AttributeError):
        return []
    if isinstance(depots, dict):
        depots = list(depots.values())
    absents = []
    for depot in depots if isinstance(depots, list) else []:
        if isinstance(depot, dict) and depot.get("type") == "path" and isinstance(depot.get("url"), str):
            url = depot["url"][:300]
            # Composer accepte un motif (« ../paquets/* ») : on regarde le dossier avant le motif.
            base = url.split("*", 1)[0]
            if not os.path.exists(os.path.join(dossier, os.path.expanduser(base))):
                absents.append(url)
    return absents


_REGISTRE = re.compile(r'"resolved":\s*"(https?://[^/"]+)')


def registres_prives(dossier: str, verrou: str = "package-lock.json") -> list:
    """Registres autres que registry.npmjs.org (ex. npm.fontawesome.com : jeton nécessaire)."""
    try:
        with open(os.path.join(dossier, verrou), encoding="utf-8") as f:
            texte = f.read()
    except OSError:
        return []
    return sorted({r for r in _REGISTRE.findall(texte) if r != "https://registry.npmjs.org"})


def erreurs_npm(sortie: str) -> str:
    """Lignes d'erreur de npm (« npm error … » ou « npm ERR! … »), en bref."""
    lignes = [l.split(" ", 2)[-1].strip() for l in (sortie or "").splitlines()
              if l.startswith(("npm error", "npm ERR!"))]
    lignes = [l for l in lignes if l and not l.startswith(("A complete log", "/"))]
    return " | ".join(dict.fromkeys(lignes))[:400]


SECTIONS_VERROU = ("dependencies", "optionalDependencies")


def liens_npm(texte: str) -> dict:
    """{(parent, version du parent, dépendance): {versions reçues}} de package-lock.json v2/v3.

    La version reçue est celle que Node charge : node_modules du parent, puis ceux des
    dossiers au-dessus. Verrou v1 (sans « packages ») : {} (non géré).
    """
    try:
        paquets = json.loads(texte or "{}").get("packages")
    except (ValueError, AttributeError):
        return {}
    if not isinstance(paquets, dict):
        return {}
    liens = {}
    for chemin, p in paquets.items():
        if not isinstance(p, dict):
            continue
        parent = chemin.split("node_modules/")[-1] if chemin else "(racine)"
        version = p.get("version", "") if chemin else ""
        sections = SECTIONS_VERROU + (("devDependencies",) if not chemin else ())
        noms = {n for s in sections for n in (p.get(s) or {})}
        for nom in noms:
            dossier = chemin
            while True:
                candidat = f"{dossier}/node_modules/{nom}" if dossier else f"node_modules/{nom}"
                if candidat in paquets:
                    v = (paquets[candidat] or {}).get("version")
                    if isinstance(v, str):
                        liens.setdefault((parent, version, nom), set()).add(v)
                    break
                if not dossier:
                    break
                coupe = dossier.rfind("/node_modules/")
                dossier = dossier[:coupe] if coupe >= 0 else ""
    return liens


def changements_de_serie(avant: str, apres: str) -> list:
    """[(parent@version, dépendance, versions avant, versions après)].

    Un paquet resté à la même version reçoit une autre série majeure d'une de ses
    dépendances : c'est là que l'application peut casser. Exemple réel (nodejs-goof) :
    connect-busboy 0.0.2 (qui accepte « * ») reçoit busboy 1.6.0 au lieu de 0.3.1 après
    « npm audit fix » : « Busboy is not a constructor ». Une dépendance qui change parce
    que son parent a été mis à jour n'est pas comptée : c'est attendu.
    """
    liens_avant, liens_apres = liens_npm(avant), liens_npm(apres)
    changes = []
    for cle in sorted(set(liens_avant) & set(liens_apres)):
        if {majeure(v) for v in liens_avant[cle]} != {majeure(v) for v in liens_apres[cle]}:
            parent, version, nom = cle
            changes.append((f"{parent}@{version}" if version else parent, nom,
                            sorted(liens_avant[cle], key=cle_version),
                            sorted(liens_apres[cle], key=cle_version)))
    return changes


def cle_override(paquet: Paquet) -> str:
    """« debug@>=2.0.0 <2.6.9 » : l'override ne touche que la série majeure installée.

    Sans plage, npm l'applique à toutes les copies du paquet (nodejs-goof : ansi-regex
    5.0.0 remplacé par 3.0.1).
    """
    cible = paquet.cible.lstrip("v")
    serie = majeure(paquet.installee) or majeure(cible)
    base = ".".join(str(x) for x in (serie + (0, 0, 0))[:3]) if serie else "0.0.0"
    return f"{paquet.nom}@>={base} <{cible}"


def corriger_npm(dossier: str, d: Dossier, avec_scripts: bool) -> list:
    if not os.path.isfile(os.path.join(dossier, "package.json")):
        raise Arret(f"package.json absent dans {dossier}")
    scripts = [] if avec_scripts else ["--ignore-scripts"]
    prealable = preparer_vendor(dossier, avec_scripts)
    directes = dependances_directes(dossier)
    verrou_avant = lire_si_present(os.path.join(dossier, d.verrou)) or ""
    avant = audit_npm(dossier)
    notes = []
    for registre in registres_prives(dossier, d.verrou):
        notes.append(f"registre privé dans {d.verrou} : {registre} (jeton nécessaire pour npm install)")
    r = lancer(["npm", "audit", "fix", *scripts], dossier, accepter=tuple(range(0, 256)),
               capturer=True)
    erreur = erreurs_npm((r.stdout or "") + (r.stderr or ""))
    if r.returncode not in (0, 1) or erreur:
        # npm renvoie aussi 1 quand il reste des failles : on regarde ses lignes d'erreur.
        notes.append(f"npm audit fix a échoué : {erreur or f'code {r.returncode}'}")
    restants = audit_npm(dossier)
    overrides = {}
    for nom, info in sorted(restants.items()):
        paquet = d.paquets.get(nom)
        direct = nom in directes or (isinstance(info, dict) and info.get("isDirect"))
        if paquet is None or not paquet.cible:
            notes.append(f"{nom} : encore vulnérable, pas de version corrigée connue dans le rapport")
        elif direct:
            notes.append(f"{nom} : dépendance directe, à mettre à jour dans package.json "
                         f"(version corrigée : {paquet.cible})")
        elif paquet.majeur:
            notes.append(f"{nom} : dépendance indirecte, correction en version majeure "
                         f"({paquet.installee} -> {paquet.cible}) : mettre à jour le paquet qui l'utilise")
        else:
            overrides[cle_override(paquet)] = f"^{paquet.cible.lstrip('v')}"
    if overrides:
        print(f"   overrides ajoutés à package.json : {overrides}")
        chemin = os.path.join(dossier, "package.json")
        with open(chemin, encoding="utf-8") as f:
            original = f.read()
        ajouter_overrides(dossier, overrides)
        r = lancer(["npm", "install", *scripts], dossier, accepter=tuple(range(0, 256)),
                   capturer=True)
        if r.returncode != 0:
            # Retour à l'état d'avant : package.json ne doit pas rester incohérent avec le verrou.
            with open(chemin, "w", encoding="utf-8") as f:
                f.write(original)
            raison = erreurs_npm((r.stdout or "") + (r.stderr or "")) or f"code {r.returncode}"
            notes.append(f"overrides annulés, npm install a échoué : {raison}")
        if r.returncode == 0:
            notes.append(f"overrides ajoutés pour {len(overrides)} dépendance(s) indirecte(s) : "
                         + ", ".join(sorted(k.split("@>=")[0] for k in overrides)))
    final = audit_npm(dossier)
    notes.insert(0, f"npm audit : {len(avant)} paquet(s) vulnérable(s) avant, {len(final)} après")
    series = changements_de_serie(verrou_avant,
                                  lire_si_present(os.path.join(dossier, d.verrou)) or "")
    if series:
        notes.append(f"{len(series)} paquet(s) non mis à jour reçoivent une AUTRE VERSION MAJEURE "
                     "d'une dépendance (npm l'accepte quand la plage demandée est « * » ou très "
                     "large) : risque de casse, à vérifier en lançant l'application :")
        for parent, nom, v_avant, v_apres in series:
            notes.append(f"    {parent} -> {nom} : {', '.join(v_avant)} -> {', '.join(v_apres)}")
            if parent != "(racine)":
                # Vérifié sur nodejs-goof : l'application refonctionne, au prix des failles
                # de l'ancienne version (busboy 0.3.1 et dicer).
                ancienne = max(v_avant, key=cle_version)
                notes.append(f"      si l'application casse : garder l'ancienne version avec "
                             f"« \"overrides\": {{\"{parent.rsplit('@', 1)[0]}\": {{\"{nom}\": "
                             f"\"^{ancienne}\"}}}} » dans package.json, puis npm install ; ou mettre "
                             f"à jour le paquet direct qui utilise {parent.rsplit('@', 1)[0]}")
    if prealable:
        notes.insert(0, prealable)
    return notes


# ----------------------------------------------------------------------- pnpm

FICHIERS_OVERRIDES_PNPM = ("pnpm-workspace.yaml", "package.json")   # pnpm 10+ / avant
# « '@vitest/mocker@>=2.1.0 <4.1.11': ^4.1.11 » (YAML) ou « "axios@<1.20.0": "^1.20.0", » (JSON)
_OVERRIDE = re.compile(r"""^\s*["']?(?P<paquet>@?[^@"'\s:][^@"':]*)@(?P<plage>[^"':]+)["']?\s*:"""
                       r"""\s*["']?(?P<cible>[^"',\s]+)["']?,?\s*$""")
_BORNE_BASSE = re.compile(r">=?\s*v?(\d+(?:\.\d+)*)")


def lire_si_present(chemin: str):
    try:
        with open(chemin, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


def overrides_ajoutes(avant: dict, apres: dict) -> list:
    """[(paquet, plage, cible)] des lignes d'override ajoutées, tous fichiers confondus."""
    ajoutes = []
    for nom, texte in apres.items():
        anciennes = set((avant.get(nom) or "").splitlines())
        for ligne in (texte or "").splitlines():
            m = _OVERRIDE.match(ligne)
            if m and ligne not in anciennes:
                ajoutes.append((m["paquet"], m["plage"].strip(), m["cible"]))
    return ajoutes


def versions_pnpm(verrou: str, paquet: str) -> set:
    """Versions de « paquet » dans pnpm-lock.yaml (« glob@13.0.6: », « '@vitest/mocker@4.1.7': »)."""
    motif = re.compile(rf"^\s+'?{re.escape(paquet)}@(v?\d[^:'(\s]*)", re.M)
    return set(motif.findall(verrou or ""))


def override_majeur(paquet: str, plage: str, cible: str, d: Dossier, verrou: str = "") -> bool:
    """Vrai si l'override fait passer une version installée à une autre version majeure.

    D'abord les versions installées, lues dans pnpm-lock.yaml avant la correction.
    Exemple réel : « glob@>=9.0.0 <=14.0.1 » -> « ^14.0.2 » avec glob 13.0.6
    installé : changement majeur ; « brace-expansion@>=4.0.0 <5.0.10 » -> « ^5.0.10 » avec
    5.0.6 installé : non. Paquet absent du verrou : borne basse de la plage et version du
    rapport.
    """
    cible = cible.lstrip("^~=v")
    m = _BORNE_BASSE.search(plage)
    installees = versions_pnpm(verrou, paquet)
    if installees:
        return any(changement_majeur(v, cible) and cle_version(v) < cle_version(cible)
                   and (not m or cle_version(v) >= cle_version(m.group(1)))
                   for v in installees)
    if m and changement_majeur(m.group(1), cible):
        return True
    connu = d.paquets.get(paquet)
    return bool(connu and changement_majeur(connu.installee, cible))


def audit_pnpm(dossier: str) -> dict:
    """{identifiant de l'avis: avis} de « pnpm audit --json »."""
    r = lancer(["pnpm", "audit", "--json"], dossier, accepter=(0, 1), capturer=True)
    try:
        avis = json.loads(r.stdout or "{}").get("advisories", {}) or {}
    except ValueError:
        return {}
    return avis if isinstance(avis, dict) else {}


def corriger_pnpm(dossier: str, d: Dossier, avec_scripts: bool) -> list:
    if not os.path.isfile(os.path.join(dossier, "package.json")):
        raise Arret(f"package.json absent dans {dossier}")
    scripts = [] if avec_scripts else ["--ignore-scripts"]
    notes = []
    # Verrou déjà périmé : pnpm install le régénère, une partie de son diff ne vient pas des
    # corrections (cas réel : projet packages/message-bundle absent de pnpm-lock.yaml).
    r = lancer(["pnpm", "install", "--frozen-lockfile", "--lockfile-only", *scripts], dossier,
               accepter=tuple(range(0, 256)), capturer=True)
    if r.returncode != 0:
        notes.append("pnpm-lock.yaml était déjà PÉRIMÉ (ou pnpm install échoue) : une partie des "
                     "changements du verrou ne vient pas des corrections. Réponse de pnpm : "
                     + dernieres_lignes((r.stdout or "") + (r.stderr or "")))
    avant = audit_pnpm(dossier)
    chemins = {nom: os.path.join(dossier, nom) for nom in FICHIERS_OVERRIDES_PNPM}
    originaux = {nom: lire_si_present(c) for nom, c in chemins.items()}
    verrou = lire_si_present(os.path.join(dossier, d.verrou)) or ""
    r = lancer(["pnpm", "audit", "--fix"], dossier, accepter=tuple(range(0, 256)), capturer=True)
    if r.returncode != 0:
        notes.append(f"pnpm audit --fix a échoué (code {r.returncode}) : "
                     + dernieres_lignes((r.stdout or "") + (r.stderr or "")))
    ajoutes = overrides_ajoutes(originaux, {nom: lire_si_present(c) for nom, c in chemins.items()})
    if ajoutes:
        r = lancer(["pnpm", "install", *scripts], dossier, accepter=tuple(range(0, 256)),
                   capturer=True)
        if r.returncode != 0:
            # Retour à l'état d'avant : les overrides ne doivent pas rester sans verrou à jour.
            for nom, texte in originaux.items():
                if texte is not None:
                    with open(chemins[nom], "w", encoding="utf-8") as f:
                        f.write(texte)
                elif os.path.exists(chemins[nom]):
                    os.remove(chemins[nom])
            notes.append(f"overrides annulés, pnpm install a échoué (code {r.returncode}) : "
                         + dernieres_lignes((r.stdout or "") + (r.stderr or "")))
        else:
            notes.append(f"pnpm audit --fix : {len(ajoutes)} override(s) ajouté(s), pnpm install réussi")
            majeurs = [(p, pl, c) for p, pl, c in ajoutes if override_majeur(p, pl, c, d, verrou)]
            if majeurs:
                notes.append(f"{len(majeurs)} override(s) imposent un CHANGEMENT DE VERSION "
                             "MAJEURE, à vérifier (git diff, tests) :")
                for paquet, plage, cible in sorted(majeurs):
                    notes.append(f"    {paquet}@{plage} -> {cible}")
    final = audit_pnpm(dossier)
    notes.insert(0, f"pnpm audit : {len(avant)} avis avant, {len(final)} après")
    sans_correctif = sorted({str(a.get("module_name")) for a in final.values()
                             if isinstance(a, dict) and a.get("patched_versions") in (None, "", "<0.0.0")})
    if sans_correctif:
        notes.append("aucune version corrigée publiée sur le registre npm (remplacer le paquet "
                     "ou changer sa source) : " + ", ".join(sans_correctif))
    autres = sorted({str(a.get("module_name")) for a in final.values() if isinstance(a, dict)}
                    - set(sans_correctif))
    if autres:
        notes.append("encore concernés : " + ", ".join(autres))
    return notes


# ------------------------------------------------------------------- Composer

_CONTRAINTE_RACINE = re.compile(r"Root composer\.json requires (\S+) ([^\s,]+)")
# « … but the package is fixed to v7.4.8 (lock file version) by a partial update » :
# composer.lock ne respecte plus composer.json (extrait réel).
_MISE_A_JOUR_PARTIELLE = "(lock file version) by a partial update"
_CHANGEMENT = re.compile(r"^\s*- (Upgrading|Downgrading) (\S+) \((\S+) => (\S+)\)", re.M)
_OPERATION = re.compile(r"^\s*- (?:Upgrading|Downgrading|Locking|Removing) (\S+)", re.M)


_ECARTEES_AVIS = "affected by security advisories"


def contraintes_bloquantes(sortie: str) -> dict:
    """Lit « Root composer.json requires symfony/yaml 8.0.*, found … but these were not
    loaded, because they are affected by security advisories » dans la réponse de Composer.

    Seules ces lignes comptent : la contrainte de composer.json n'admet que des versions
    qui ont un avis. Les autres lignes « Root composer.json requires … » ne bloquent rien
    (« … -> satisfiable by … », par exemple « exemple/table-bundle * »), et
    « … (lock file version) by a partial update » signale un composer.lock périmé.
    """
    bloquantes = {}
    for ligne in (sortie or "").splitlines():
        if _ECARTEES_AVIS in ligne and _MISE_A_JOUR_PARTIELLE not in ligne:
            bloquantes.update(_CONTRAINTE_RACINE.findall(ligne))
    return bloquantes


def verrou_perime(sortie: str) -> bool:
    return _MISE_A_JOUR_PARTIELLE in (sortie or "")


def mettre_a_jour_composer(dossier: str, noms: list, scripts: list):
    r = lancer(["composer", "update", *noms, "--with-all-dependencies", "--no-interaction",
                *scripts], dossier, accepter=tuple(range(0, 256)), capturer=True)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


_BLOC_EXCEPTION = re.compile(r"^\s*In \S+ line \d+:\s*$")        # « In PathRepository.php line 163: »
_AIDE_UTILISATION = re.compile(r"^\s*[a-z][\w-]* \[-")             # « update [--with WITH] … »


def dernieres_lignes(sortie: str) -> str:
    """La raison d'un échec de Composer, npm ou pnpm, en une ligne.

    Composer termine souvent par son aide d'utilisation : la vraie raison est dans
    le bloc « In … line N: » (exemple réel : « The `url` supplied for the
    path (/Users/dev/Web/TableBundle) repository does not exist »), ou dans les
    lignes « - … » d'un « Problem N ».
    """
    lignes = (sortie or "").splitlines()
    for i, ligne in enumerate(lignes):
        if _BLOC_EXCEPTION.match(ligne):
            bloc = []
            for suite in lignes[i + 1:]:
                if _AIDE_UTILISATION.match(suite) or _BLOC_EXCEPTION.match(suite):
                    break
                if suite.strip():
                    bloc.append(suite.strip())
                elif bloc:
                    break
            if bloc:
                return " ".join(bloc)[:400]
    problemes = [l.strip() for l in lignes if l.strip().startswith("- ")
                 and not re.match(r"\s*- (Installing|Downloading|Upgrading|Locking|Removing) ", l)]
    if any("Problem " in l for l in lignes) and problemes:
        return " | ".join(problemes[:3])[:400]
    utiles = [l.strip() for l in lignes if l.strip() and not _AIDE_UTILISATION.match(l)]
    return " | ".join(utiles[-2:])[:400]


def simuler_update_complet(dossier: str, scripts: list) -> list:
    """composer.lock périmé : simule « composer update » complet, sans rien modifier.

    Régénérer le verrou change souvent beaucoup de paquets, parfois en version
    majeure : c'est au développeur de décider. Le script affiche seulement ce qui
    changerait.
    """
    notes = ["composer.lock PÉRIMÉ : il ne correspond plus à composer.json, une mise à jour "
             "ciblée est impossible. Le script ne le régénère pas."]
    r = lancer(["composer", "update", "--dry-run", "--no-interaction", *scripts], dossier,
               accepter=tuple(range(0, 256)), capturer=True)
    sortie = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        notes.append(f"    la simulation d'un « composer update » complet échoue aussi "
                     f"(code {r.returncode}) : {dernieres_lignes(sortie)}")
        return notes
    changements = {}
    for _, nom, avant, apres in _CHANGEMENT.findall(sortie):
        changements.setdefault(nom, (avant, apres))
    majeurs = sorted((n, a, b) for n, (a, b) in changements.items() if changement_majeur(a, b))
    operations = set(_OPERATION.findall(sortie))
    notes.append(f"    « composer update » complet (simulé) : {len(operations)} paquet(s) changent, "
                 f"dont {len(majeurs)} en version majeure" + (" :" if majeurs else ""))
    for nom, avant, apres in majeurs:
        notes.append(f"        {nom} : {avant} -> {apres}")
    notes.append("    à faire par le développeur : « composer update » dans ce dossier, relire les "
                 "changements, lancer les tests")
    return notes


def corriger_composer(dossier: str, d: Dossier, avec_scripts: bool) -> list:
    if not os.path.isfile(os.path.join(dossier, "composer.json")):
        raise Arret(f"composer.json absent dans {dossier}")
    scripts = [] if avec_scripts else ["--no-scripts", "--no-plugins"]
    avant = audit_composer(dossier)
    noms = sorted(n for n, q in d.paquets.items() if q.cible)
    notes, bloquantes, perime, echec = [], {}, False, False
    if noms:
        code, sortie = mettre_a_jour_composer(dossier, noms, scripts)
        restants = noms
        if code != 0:
            perime = verrou_perime(sortie)
            bloquantes = contraintes_bloquantes(sortie)
            restants = [n for n in noms if n not in bloquantes]
            if not perime and bloquantes and restants and restants != noms:
                # Nouvel essai sans les paquets bloqués par composer.json.
                code, sortie = mettre_a_jour_composer(dossier, restants, scripts)
                perime = verrou_perime(sortie)
                bloquantes.update(contraintes_bloquantes(sortie))
        if code == 0:
            notes.append(f"composer update réussi pour {len(restants)} paquet(s) du rapport")
        elif not perime:
            notes.append(f"composer update refusé (code {code}) même sans les paquets "
                         f"bloqués : {dernieres_lignes(sortie)}")
            if len(restants) > 1 and "Problem " in sortie:
                # Un seul paquet en conflit fait refuser tout le groupe : paquet par paquet,
                # ceux qui ne dépendent pas d'un paquet bloqué passent.
                reussis, refuses = [], {}
                for nom in restants:
                    code_seul, sortie_seul = mettre_a_jour_composer(dossier, [nom], scripts)
                    if code_seul == 0:
                        reussis.append(nom)
                    else:
                        bloquantes.update(contraintes_bloquantes(sortie_seul))
                        refuses[nom] = dernieres_lignes(sortie_seul)
                notes.append(f"paquet par paquet : {len(reussis)} mis à jour"
                             + (" (" + ", ".join(reussis) + ")" if reussis else "")
                             + f", {len(refuses)} refusé(s)")
                for nom, raison in sorted(refuses.items()):
                    if nom not in bloquantes:
                        notes.append(f"    {nom} : {raison[:200]}")
                echec = not reussis
            else:
                echec = True
    if not perime and not echec:
        # Second passage : paquets que composer audit signale encore, absents du rapport
        # (rapport d'une ancienne version d'ASGOR, base d'avis plus récente…).
        supplementaires = sorted(n for n in audit_composer(dossier)
                                 if _NOM_COMPOSER.fullmatch(n) and n not in noms
                                 and n not in bloquantes)
        if supplementaires:
            code, sortie = mettre_a_jour_composer(dossier, supplementaires, scripts)
            perime = verrou_perime(sortie)
            bloquantes.update(contraintes_bloquantes(sortie))
            if code == 0:
                notes.append(f"second passage : {len(supplementaires)} paquet(s) signalé(s) par "
                             "composer audit mais absent(s) du rapport, mis à jour : "
                             + ", ".join(supplementaires))
            elif not perime:
                echec = True
                notes.append(f"second passage refusé (code {code}) pour "
                             f"{', '.join(supplementaires)} : {dernieres_lignes(sortie)}")
    if perime or d.perime:
        # Verrou périmé : Composer cite des contraintes du composer.json qui ne bloquent rien
        # (« Root composer.json requires symfony/http-kernel ^8.1 -> satisfiable by … »).
        bloquantes = {}
    if bloquantes:
        notes.append("composer.json limite ces paquets à des versions qui ont toutes un avis "
                     "de sécurité. Élargir la contrainte (par exemple Symfony 8.0.* -> 8.1.*), "
                     "après décision et tests :")
        for nom, contrainte in sorted(bloquantes.items()):
            cible = d.paquets[nom].cible if nom in d.paquets else ""
            notes.append(f"    {nom} : contrainte {contrainte}"
                         + (f", version corrigée {cible}" if cible else ""))
    if perime or d.perime:
        notes.extend(simuler_update_complet(dossier, scripts))
    final = audit_composer(dossier)
    notes.insert(0, f"composer audit : {len(avant)} paquet(s) concerné(s) avant, {len(final)} après")
    autres = sorted(n for n in final if n not in bloquantes)
    if autres:
        raison = ("composer.lock périmé, voir ci-dessus" if perime or d.perime
                  else "composer update a échoué, voir ci-dessus" if echec
                  else "contrainte de composer.json ou dépendance d'un paquet bloqué")
        notes.append(f"encore concernés ({raison}) : " + ", ".join(autres))
    return notes


def lancer_tests(dossier: str, ecosysteme: str) -> str:
    if ecosysteme in ("npm", "pnpm"):
        with open(os.path.join(dossier, "package.json"), encoding="utf-8") as f:
            if "test" not in (json.load(f).get("scripts") or {}):
                return "pas de script « test » dans package.json"
        commande = [ecosysteme, "test"]
    else:
        with open(os.path.join(dossier, "composer.json"), encoding="utf-8") as f:
            if "test" not in (json.load(f).get("scripts") or {}):
                return "pas de script « test » dans composer.json"
        commande = ["composer", "test"]
    r = subprocess.run(commande, cwd=dossier, stdin=subprocess.DEVNULL)
    return "tests réussis" if r.returncode == 0 else f"TESTS EN ÉCHEC (code {r.returncode})"


AVERTISSEMENT = (
    "\nAVERTISSEMENT : ce script va MODIFIER le dépôt (fichiers de dépendances, node_modules/,\n"
    "vendor/) et exécuter des commandes (npm, pnpm, Composer, tests du projet).\n"
    "Une mise à jour de dépendance peut CASSER L'APPLICATION, même si les tests réussissent.\n"
    "Sauvegardez vos données et travaillez sur une copie isolée du dépôt. Relisez les\n"
    "changements avant de les fusionner. Fourni « tel quel », sans garantie (licence MIT).")


def appliquer(plan: list, racine: str, options) -> int:
    geres = [d for d in plan if d.ecosysteme and (d.paquets or d.perime)]
    if not geres:
        print("\nRien à corriger automatiquement.")
        return 0
    for outil in sorted({d.ecosysteme for d in geres}):
        if shutil.which(outil) is None:
            raise Arret(f"{outil} est introuvable sur ce poste")
    for d in geres:
        dossier = os.path.join(racine, d.chemin)
        if not os.path.isfile(os.path.join(dossier, d.verrou)):
            raise Arret(f"{os.path.join(d.chemin, d.verrou) or d.verrou} est absent de {racine} : "
                        "est-ce bien le même dépôt, au même commit ?")
    verifier_git(racine, options.forcer)
    print(AVERTISSEMENT)
    if not options.oui:
        reponse = input("\nAppliquer ce plan sur une nouvelle branche Git ? [o/N] ").strip().lower()
        if reponse not in ("o", "oui"):
            print("Abandon : rien n'a été modifié.")
            return 1
    branche = None if options.sans_branche else creer_branche(racine)
    bilan = []
    for d in geres:
        dossier = os.path.join(racine, d.chemin)
        print(f"\n== {os.path.join(d.chemin, d.verrou) if d.chemin else d.verrou}")
        corriger = {"npm": corriger_npm, "pnpm": corriger_pnpm}.get(d.ecosysteme, corriger_composer)
        try:
            notes = corriger(dossier, d, options.avec_scripts)
            arrete = False
        except Arret as e:
            notes, arrete = [f"ARRÊT pour ce dossier : {e}"], True
        bilan.append((d, notes, arrete))
    if not options.sans_tests:
        # Les tests une fois tous les dossiers traités : ceux de la racine peuvent charger
        # les dépendances d'un sous-dossier (par exemple back/vendor/autoload.php).
        print("\n================ Tests ================")
        for d, notes, arrete in bilan:
            if not arrete:
                notes.append(lancer_tests(os.path.join(racine, d.chemin), d.ecosysteme))
    print("\n================ Bilan ================")
    if branche:
        print(f"Branche : {branche}")
    for d, notes, _ in bilan:
        print(f"\n{os.path.join(d.chemin, d.verrou) if d.chemin else d.verrou}")
        for note in notes:
            print(f"   - {note}")
    print("\nÀ faire : relire les changements (git diff), vérifier l'application, puis faire "
          "un commit. Relancer ensuite une analyse ASGOR.")
    return 0


def main(arguments=None) -> int:
    o = argparse.ArgumentParser(description="Corrige les dépendances vulnérables d'un rapport ASGOR.",
                                epilog=AVERTISSEMENT.strip(),
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    o.add_argument("rapport", help="rapport JSON exporté depuis ASGOR")
    o.add_argument("--depot", default=".", help="racine du dépôt analysé (par défaut : dossier courant)")
    o.add_argument("--plan", action="store_true", help="afficher le plan seulement, ne rien modifier")
    o.add_argument("--oui", action="store_true", help="ne pas demander de confirmation")
    o.add_argument("--sans-branche", action="store_true", help="ne pas créer de branche Git")
    o.add_argument("--sans-tests", action="store_true", help="ne pas lancer les tests du projet")
    o.add_argument("--avec-scripts", action="store_true",
                   help="autoriser les scripts des paquets (npm, Composer)")
    o.add_argument("--forcer", action="store_true",
                   help="accepter un dépôt qui a des modifications non enregistrées")
    options = o.parse_args(arguments)

    chemin_rapport = os.path.abspath(options.rapport)   # avant tout changement de dossier
    racine = os.path.abspath(options.depot)
    try:
        rapport = lire_rapport(chemin_rapport)
        plan = construire_plan(rapport)
        if not plan:
            print("Le rapport ne contient aucune dépendance vulnérable.")
            return 0
        afficher_plan(plan, rapport, racine if os.path.isdir(racine) else "")
        if options.plan:
            return 0
        return appliquer(plan, racine, options)
    except (OSError, ValueError, Arret) as e:
        print(f"\nArrêt : {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
