"""Tests de corriger_dependances.py (sur le Mac, sans npm ni Composer réels).

    python3 -m unittest discover -p "test_*.py"     # depuis le dossier du dépôt
"""

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import corriger_dependances as cd  # noqa: E402


def probleme(paquet, fichier="package-lock.json", version="1.0.0", cible="1.0.1", gravite="Élevée"):
    return {"domaine": "dependances", "paquet": paquet, "fichier": fichier, "version": version,
            "version_corrigee": cible, "gravite": gravite, "identifiants": [f"CVE-{paquet}"]}


class Versions(unittest.TestCase):
    def test_ordre_numerique(self):
        self.assertEqual(cd.plus_haute(["1.9.0", "1.13.2", "1.10.0"]), "1.13.2")
        self.assertEqual(cd.plus_haute(["3.1.3", "3.1.9", "3.1.10"]), "3.1.10")
        self.assertEqual(cd.plus_haute(["2.0.0-beta1", "2.0.0"]), "2.0.0")
        self.assertEqual(cd.plus_haute(["v8.0.13", "8.1.0"]), "8.1.0")

    def test_changement_majeur(self):
        self.assertTrue(cd.changement_majeur("8.3.2", "11.1.1"))
        self.assertFalse(cd.changement_majeur("v8.0.13", "8.1.0"))
        self.assertTrue(cd.changement_majeur("0.4.2", "0.5.0"))     # semver : 0.x
        self.assertFalse(cd.changement_majeur("0.7.4", "0.7.5"))
        self.assertFalse(cd.changement_majeur("", "1.0.0"))


class Plan(unittest.TestCase):
    def test_regroupement_par_fichier_et_ecosysteme(self):
        rapport = {"problemes": [
            probleme("fast-uri", cible="3.1.3"), probleme("fast-uri", cible="3.1.9"),
            probleme("@hotwired/turbo", version="7.3.0", cible="8.0.21", gravite="Faible"),
            probleme("symfony/yaml", fichier="composer.lock", version="v8.0.13", cible="8.1.0"),
            probleme("symfony/yaml", fichier="back/composer.lock", cible="8.1.0"),
            probleme("axios", fichier="front/pnpm-lock.yaml"),
            probleme("axios", fichier="autre/yarn.lock"),
            {"domaine": "code", "paquet": "x", "fichier": "package-lock.json"},
        ]}
        plan = {(d.chemin, d.verrou): d for d in cd.construire_plan(rapport)}
        self.assertEqual(set(plan), {("", "package-lock.json"), ("", "composer.lock"),
                                     ("back", "composer.lock"), ("front", "pnpm-lock.yaml"),
                                     ("autre", "yarn.lock")})
        npm = plan[("", "package-lock.json")]
        self.assertEqual(npm.ecosysteme, "npm")
        self.assertEqual(npm.paquets["fast-uri"].cible, "3.1.9")
        self.assertTrue(npm.paquets["@hotwired/turbo"].majeur)
        self.assertEqual(plan[("", "composer.lock")].ecosysteme, "composer")
        self.assertEqual(plan[("front", "pnpm-lock.yaml")].ecosysteme, "pnpm")
        self.assertEqual(plan[("autre", "yarn.lock")].ecosysteme, "")   # à la main

    def test_verrou_perime_signale_par_le_rapport(self):
        """Problème « composer-lock-perime » du moteur (sans paquet) : retenu dans le plan."""
        rapport = {"problemes": [
            {"domaine": "dependances", "regle": "composer-lock-perime", "gravite": "Moyenne",
             "fichier": "packages/intranet-bundle/composer.lock"},
            {"domaine": "dependances", "regle": "autre", "fichier": "composer.lock"},  # sans paquet
        ]}
        plan = {(d.chemin, d.verrou): d for d in cd.construire_plan(rapport)}
        self.assertEqual(set(plan), {("packages/intranet-bundle", "composer.lock")})
        d = plan[("packages/intranet-bundle", "composer.lock")]
        self.assertTrue(d.perime)
        self.assertEqual(d.paquets, {})

    def test_formes_refusees(self):
        rapport = {"problemes": [
            probleme("--registry=http://pirate", cible="1.0.0"),
            probleme("Symfony/Yaml", fichier="composer.lock"),
            probleme("axios", cible="1.0.0; rm -rf /"),
            probleme("ok", fichier="../dehors/package-lock.json"),
            probleme("ok", fichier="/etc/package-lock.json"),
        ]}
        plan = cd.construire_plan(rapport)
        self.assertEqual(sum(len(d.paquets) for d in plan), 0)
        self.assertEqual(sum(len(d.refuses) for d in plan), 3)
        self.assertNotIn("dehors", [d.chemin for d in plan])


FAUX_NPM = r"""#!/usr/bin/env python3
# Faux npm : « audit --json » lit audit-N.json (N = nombre d'audits déjà faits).
import json, os, sys
journal = os.path.join(os.getcwd(), "npm-appels.txt")
with open(journal, "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
if sys.argv[1:3] == ["audit", "--json"]:
    n = sum(1 for l in open(journal) if l.startswith("audit --json"))
    fichier = os.path.join(os.getcwd(), f"audit-{n}.json")
    print(open(fichier).read() if os.path.exists(fichier) else '{"vulnerabilities": {}}')
    sys.exit(1)
if sys.argv[1] == "install" and os.environ.get("FAUX_NPM_INSTALL_ECHEC"):
    sys.exit(254)
sys.exit(0)
"""


class CorrectionNpm(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.depot = os.path.join(tmp.name, "depot")
        os.makedirs(self.depot)
        bin_ = os.path.join(tmp.name, "bin")
        os.makedirs(bin_)
        with open(os.path.join(bin_, "npm"), "w") as f:
            f.write(FAUX_NPM)
        os.chmod(os.path.join(bin_, "npm"), stat.S_IRWXU)
        ancien = os.environ["PATH"]
        os.environ["PATH"] = bin_ + os.pathsep + ancien
        self.addCleanup(os.environ.__setitem__, "PATH", ancien)
        with open(os.path.join(self.depot, "package.json"), "w") as f:
            f.write('{\n  "name": "essai",\n  "dependencies": {\n    "express": "^4.0.0"\n  },\n'
                    '  "devDependencies": {\n    "vite": "^8.0.0",\n'
                    '    "@symfony/ux-live-component": "file:vendor/symfony/ux-live-component/assets"\n  }\n}\n')
        os.makedirs(os.path.join(self.depot, "vendor/symfony/ux-live-component/assets"))
        open(os.path.join(self.depot, "package-lock.json"), "w").close()
        vulnerables = {"proxy-addr": {"isDirect": False}, "uuid": {"isDirect": False},
                       "express": {"isDirect": True}, "inconnu": {"isDirect": False},
                       "vite": {"isDirect": False}}   # npm audit peut se tromper sur « direct »
        # audit 1 (avant) et audit 2 (après « audit fix ») : 4 paquets ; audit 3 (final) : 2
        for n, v in ((1, vulnerables), (2, vulnerables),
                     (3, {"uuid": {}, "express": {}})):
            with open(os.path.join(self.depot, f"audit-{n}.json"), "w") as f:
                json.dump({"vulnerabilities": v}, f)

    def test_overrides_et_refus_des_changements_majeurs(self):
        rapport = {"problemes": [
            probleme("proxy-addr", version="2.0.7", cible="2.0.8"),
            probleme("uuid", version="8.3.2", cible="11.1.1"),
            probleme("express", version="4.21.0", cible="4.22.0"),
            probleme("vite", version="8.0.14", cible="8.1.6"),
        ]}
        d, = cd.construire_plan(rapport)
        notes = cd.corriger_npm(self.depot, d, avec_scripts=False)
        with open(os.path.join(self.depot, "package.json")) as f:
            paquet = json.load(f)
        # Seule la dépendance indirecte sans changement majeur reçoit un override, limité à
        # sa série majeure (sinon npm l'applique à toutes les copies du paquet).
        self.assertEqual(paquet["overrides"], {"proxy-addr@>=2.0.0 <2.0.8": "^2.0.8"})
        self.assertEqual(list(paquet), ["name", "dependencies", "devDependencies", "overrides"])
        self.assertIn("vite : dépendance directe", "\n".join(notes))   # jamais d'override
        with open(os.path.join(self.depot, "npm-appels.txt")) as f:
            appels = f.read().splitlines()
        self.assertIn("audit fix --ignore-scripts", appels)
        self.assertIn("install --ignore-scripts", appels)
        self.assertNotIn("--force", " ".join(appels))
        texte = "\n".join(notes)
        self.assertIn("5 paquet(s) vulnérable(s) avant, 2 après", texte)
        self.assertIn("uuid : dépendance indirecte, correction en version majeure", texte)
        self.assertIn("express : dépendance directe", texte)
        self.assertIn("overrides ajoutés pour 1 dépendance(s) indirecte(s) : proxy-addr", texte)
        self.assertIn("inconnu : encore vulnérable", texte)


FAUX_COMPOSER = r"""#!/usr/bin/env python3
# Faux composer : « audit » répond avant puis après la mise à jour.
import json, os, sys
journal = os.path.join(os.getcwd(), "composer-appels.txt")
with open(journal, "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
if sys.argv[1] == "audit":
    n = sum(1 for l in open(journal) if l.startswith("audit"))
    avis = {"symfony/yaml": [{}], "guzzlehttp/guzzle": [{}]} if n == 1 else {"guzzlehttp/guzzle": [{}]}
    print(json.dumps({"advisories": avis}))
    sys.exit(1)
sys.exit(0)
"""


class CorrectionComposer(unittest.TestCase):
    def test_update_avec_dependances_sans_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            depot, bin_ = os.path.join(tmp, "depot"), os.path.join(tmp, "bin")
            os.makedirs(depot)
            os.makedirs(bin_)
            with open(os.path.join(bin_, "composer"), "w") as f:
                f.write(FAUX_COMPOSER)
            os.chmod(os.path.join(bin_, "composer"), stat.S_IRWXU)
            ancien = os.environ["PATH"]
            os.environ["PATH"] = bin_ + os.pathsep + ancien
            try:
                with open(os.path.join(depot, "composer.json"), "w") as f:
                    f.write('{"require": {"symfony/yaml": "^8.0"}}')
                rapport = {"problemes": [
                    probleme("symfony/yaml", fichier="composer.lock", version="v8.0.13", cible="8.1.0"),
                    probleme("guzzlehttp/guzzle", fichier="composer.lock", version="7.11.1", cible="7.15.2")]}
                d, = cd.construire_plan(rapport)
                notes = cd.corriger_composer(depot, d, avec_scripts=False)
                with open(os.path.join(depot, "composer-appels.txt")) as f:
                    appels = f.read().splitlines()
            finally:
                os.environ["PATH"] = ancien
        self.assertIn("update guzzlehttp/guzzle symfony/yaml --with-all-dependencies --no-interaction "
                      "--no-scripts --no-plugins", appels)
        texte = "\n".join(notes)
        self.assertIn("2 paquet(s) concerné(s) avant, 1 après", texte)
        self.assertIn("encore concernés", texte)
        self.assertIn("guzzlehttp/guzzle", texte)


class SeriesMajeuresNpm(unittest.TestCase):
    """Cas réels de nodejs-goof."""

    AVANT = json.dumps({"lockfileVersion": 2, "packages": {
        "": {"name": "goof", "dependencies": {"express-fileupload": "0.0.5"},
             "devDependencies": {"snyk": "^1.0.0"}},
        "node_modules/express-fileupload": {"version": "0.0.5",
                                            "dependencies": {"connect-busboy": "0.0.2"}},
        "node_modules/connect-busboy": {"version": "0.0.2", "dependencies": {"busboy": "*"}},
        "node_modules/busboy": {"version": "0.3.1"},
        # strip-ansi mis à jour 5.2.0 -> 6.0.1 : son ansi-regex change, c'est attendu
        "node_modules/strip-ansi": {"version": "5.2.0", "dependencies": {"ansi-regex": "^4.1.0"}},
        "node_modules/ansi-regex": {"version": "4.1.0"},
        # dépendance imbriquée : chalk garde sa copie de ansi-styles
        "node_modules/chalk": {"version": "2.4.2", "dependencies": {"ansi-styles": "^3.2.1"}},
        "node_modules/chalk/node_modules/ansi-styles": {"version": "3.2.1"},
        "node_modules/ansi-styles": {"version": "4.3.0"},
        "node_modules/snyk": {"version": "1.0.0"}}})
    APRES = json.dumps({"lockfileVersion": 2, "packages": {
        "": {"name": "goof", "dependencies": {"express-fileupload": "0.0.5"},
             "devDependencies": {"snyk": "^1.0.0"}},
        "node_modules/express-fileupload": {"version": "0.0.5",
                                            "dependencies": {"connect-busboy": "0.0.2"}},
        "node_modules/connect-busboy": {"version": "0.0.2", "dependencies": {"busboy": "*"}},
        "node_modules/busboy": {"version": "1.6.0"},
        "node_modules/strip-ansi": {"version": "6.0.1", "dependencies": {"ansi-regex": "^5.0.1"}},
        "node_modules/ansi-regex": {"version": "5.0.1"},
        "node_modules/chalk": {"version": "2.4.2", "dependencies": {"ansi-styles": "^3.2.1"}},
        "node_modules/chalk/node_modules/ansi-styles": {"version": "3.2.1"},
        "node_modules/ansi-styles": {"version": "4.3.0"},
        "node_modules/snyk": {"version": "1.0.0"}}})

    def test_seul_le_parent_inchange_est_signale(self):
        self.assertEqual(cd.changements_de_serie(self.AVANT, self.APRES),
                         [("connect-busboy@0.0.2", "busboy", ["0.3.1"], ["1.6.0"])])

    def test_resolution_comme_node(self):
        liens = cd.liens_npm(self.AVANT)
        self.assertEqual(liens[("chalk", "2.4.2", "ansi-styles")], {"3.2.1"})   # copie imbriquée
        self.assertEqual(liens[("(racine)", "", "snyk")], {"1.0.0"})            # devDependencies
        self.assertEqual(cd.liens_npm(json.dumps({"lockfileVersion": 1, "dependencies": {}})), {})
        self.assertEqual(cd.liens_npm("pas du json"), {})

    def test_cle_override(self):
        self.assertEqual(cd.cle_override(cd.Paquet(nom="debug", installee="2.2.0", cible="2.6.9")),
                         "debug@>=2.0.0 <2.6.9")
        self.assertEqual(cd.cle_override(cd.Paquet(nom="minimist", installee="0.0.10", cible="0.0.11")),
                         "minimist@>=0.0.0 <0.0.11")
        self.assertEqual(cd.cle_override(cd.Paquet(nom="@a/b", installee="", cible="v1.4.1")),
                         "@a/b@>=1.0.0 <1.4.1")

    def test_signale_dans_le_bilan(self):
        with tempfile.TemporaryDirectory() as tmp:
            depot, bin_ = os.path.join(tmp, "depot"), os.path.join(tmp, "bin")
            os.makedirs(depot)
            os.makedirs(bin_)
            with open(os.path.join(bin_, "npm"), "w") as f:
                f.write("#!/usr/bin/env python3\nimport sys\n"
                        "if sys.argv[1:3] == ['audit', 'fix']:\n"
                        f"    open('package-lock.json', 'w').write({self.APRES!r})\n"
                        "if sys.argv[1:3] == ['audit', '--json']:\n"
                        "    print('{\"vulnerabilities\": {}}')\n")
            os.chmod(os.path.join(bin_, "npm"), stat.S_IRWXU)
            with open(os.path.join(depot, "package.json"), "w") as f:
                f.write('{"name": "goof"}')
            with open(os.path.join(depot, "package-lock.json"), "w") as f:
                f.write(self.AVANT)
            ancien = os.environ["PATH"]
            os.environ["PATH"] = bin_ + os.pathsep + ancien
            try:
                d, = cd.construire_plan({"problemes": [probleme("busboy", version="0.3.1", cible="1.6.0")]})
                texte = "\n".join(cd.corriger_npm(depot, d, avec_scripts=False))
            finally:
                os.environ["PATH"] = ancien
        self.assertIn("1 paquet(s) non mis à jour reçoivent une AUTRE VERSION MAJEURE", texte)
        self.assertIn("    connect-busboy@0.0.2 -> busboy : 0.3.1 -> 1.6.0", texte)
        self.assertIn('« "overrides": {"connect-busboy": {"busboy": "^0.3.1"}} »', texte)


class RetourArriere(CorrectionNpm):
    def test_package_json_restaure_si_npm_install_echoue(self):
        chemin = os.path.join(self.depot, "package.json")
        with open(chemin) as f:
            original = f.read()
        os.environ["FAUX_NPM_INSTALL_ECHEC"] = "1"
        self.addCleanup(os.environ.pop, "FAUX_NPM_INSTALL_ECHEC", None)
        d, = cd.construire_plan({"problemes": [probleme("proxy-addr", version="2.0.7", cible="2.0.8")]})
        notes = cd.corriger_npm(self.depot, d, avec_scripts=False)
        with open(chemin) as f:
            self.assertEqual(f.read(), original)
        self.assertTrue(any(n.startswith("overrides annulés") for n in notes))

    def test_registre_prive_et_erreurs_npm(self):
        with open(os.path.join(self.depot, "package-lock.json"), "w") as f:
            f.write('{"packages": {"a": {"resolved": "https://registry.npmjs.org/a/-/a-1.tgz"},'
                    ' "b": {"resolved": "https://npm.fontawesome.com/b/-/b-1.tgz"}}}')
        self.assertEqual(cd.registres_prives(self.depot), ["https://npm.fontawesome.com"])
        sortie = ("npm error code E401\nnpm error Incorrect or missing password.\n"
                  "npm error A complete log of this run can be found in: /x.log\n")
        self.assertEqual(cd.erreurs_npm(sortie), "code E401 | Incorrect or missing password.")

    def test_overrides_et_refus_des_changements_majeurs(self):
        pass  # déjà couvert par la classe parente

    def test_chemins_vendor(self):
        self.assertEqual(cd.chemins_vendor(self.depot), ["vendor/symfony/ux-live-component/assets"])
        self.assertEqual(cd.preparer_vendor(self.depot, False), "")   # dossier présent : rien à faire
        import shutil as sh
        sh.rmtree(os.path.join(self.depot, "vendor"))
        with self.assertRaises(cd.Arret):                             # pas de composer.lock
            cd.preparer_vendor(self.depot, False)


class ContraintesBloquantes(unittest.TestCase):
    def test_lecture_de_la_reponse_de_composer(self):
        # Extrait réel
        sortie = ("  Problem 8\n    - Root composer.json requires symfony/yaml 8.0.*, found "
                  "symfony/yaml[v8.0.0, ..., v8.0.15] but these were not loaded, because they are "
                  "affected by security advisories\n    - Root composer.json requires "
                  "easycorp/easyadmin-bundle 5.* -> satisfiable by ...\n")
        # « easyadmin-bundle 5.* -> satisfiable by » ne bloque rien (« exemple/table-bundle * »
        # était compté à tort comme bloquant).
        self.assertEqual(cd.contraintes_bloquantes(sortie), {"symfony/yaml": "8.0.*"})
        self.assertFalse(cd.verrou_perime(sortie))

    def test_verrou_perime_n_est_pas_une_contrainte(self):
        self.assertNotIn("symfony/framework-bundle", cd.contraintes_bloquantes(SORTIE_PERIME))
        self.assertTrue(cd.verrou_perime(SORTIE_PERIME))


# Extrait réel (packages/intranet-bundle)
SORTIE_PERIME = (
    "Your requirements could not be resolved to an installable set of packages.\n"
    "  Problem 1\n    - Root composer.json requires symfony/framework-bundle ^8.1, found "
    "symfony/framework-bundle[v8.1.0, ..., v8.1.11] but the package is fixed to v7.4.8 (lock file "
    "version) by a partial update and that version does not match. Make sure you list it as an "
    "argument for the update command.\n"
    "  Problem 2\n    - Root composer.json requires symfony/http-kernel ^8.1 -> satisfiable by "
    "symfony/http-kernel[v8.1.11].\n")
SIMULATION_COMPLETE = (
    "Lock file operations: 0 installs, 3 updates, 0 removals\n"
    "  - Upgrading symfony/cache (v8.0.8 => v8.1.11)\n"
    "  - Upgrading symfony/framework-bundle (v7.4.8 => v8.1.11)\n"
    "  - Upgrading symfony/http-kernel (v7.4.8 => v8.1.11)\n"
    "Package operations: 3 installs, 0 updates, 0 removals\n"
    "  - Installing symfony/cache (v8.1.11)\n")

FAUX_COMPOSER_SCENARIO = r"""#!/usr/bin/env python3
# Faux composer piloté par scenario.json : réponses d'audit successives et réponses d'update.
import json, os, sys
journal = os.path.join(os.getcwd(), "composer-appels.txt")
with open(journal, "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
s = json.load(open(os.path.join(os.getcwd(), "scenario.json")))
if sys.argv[1] == "audit":
    n = sum(1 for l in open(journal) if l.startswith("audit"))
    audits = s["audits"]
    print(json.dumps({"advisories": {p: [{}] for p in audits[min(n, len(audits)) - 1]}}))
    sys.exit(1)
if sys.argv[1] == "update":
    if "--dry-run" in sys.argv:
        print(s.get("simulation", ""))
        sys.exit(s.get("code_simulation", 0))
    print(s.get("sortie_update", ""), file=sys.stderr)
    sys.exit(s.get("code_update", 0))
sys.exit(0)
"""


class OutilFactice(unittest.TestCase):
    """Dossier temporaire avec un faux outil en tête du PATH."""

    def installer(self, nom, script):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.depot = os.path.join(tmp.name, "depot")
        bin_ = os.path.join(tmp.name, "bin")
        os.makedirs(self.depot)
        os.makedirs(bin_)
        with open(os.path.join(bin_, nom), "w") as f:
            f.write(script)
        os.chmod(os.path.join(bin_, nom), stat.S_IRWXU)
        ancien = os.environ["PATH"]
        os.environ["PATH"] = bin_ + os.pathsep + ancien
        self.addCleanup(os.environ.__setitem__, "PATH", ancien)

    def ecrire(self, nom, contenu):
        with open(os.path.join(self.depot, nom), "w", encoding="utf-8") as f:
            f.write(contenu if isinstance(contenu, str) else json.dumps(contenu))

    def appels(self, nom):
        with open(os.path.join(self.depot, nom)) as f:
            return f.read().splitlines()


class ComposerPerimeEtSecondPassage(OutilFactice):
    def setUp(self):
        self.installer("composer", FAUX_COMPOSER_SCENARIO)
        self.ecrire("composer.json", {"require": {"symfony/framework-bundle": "^8.1"}})

    def test_verrou_perime_simulation_sans_conseil_d_elargir(self):
        self.ecrire("scenario.json", {
            "audits": [["symfony/cache", "symfony/http-kernel"]],
            "code_update": 2, "sortie_update": SORTIE_PERIME,
            "simulation": SIMULATION_COMPLETE})
        d, = cd.construire_plan({"problemes": [
            probleme("symfony/cache", fichier="composer.lock", version="v8.0.8", cible="8.0.12"),
            probleme("symfony/http-kernel", fichier="composer.lock", version="v7.4.8", cible="7.4.12")]})
        texte = "\n".join(cd.corriger_composer(self.depot, d, avec_scripts=False))
        self.assertIn("composer.lock PÉRIMÉ", texte)
        self.assertIn("3 paquet(s) changent, dont 2 en version majeure", texte)
        self.assertIn("symfony/framework-bundle : v7.4.8 -> v8.1.11", texte)
        self.assertNotIn("Élargir", texte)
        self.assertIn("encore concernés (composer.lock périmé", texte)
        appels = self.appels("composer-appels.txt")
        self.assertIn("update --dry-run --no-interaction --no-scripts --no-plugins", appels)
        # Le vrai composer.lock n'est jamais régénéré : un seul update réel (ciblé).
        self.assertEqual([a for a in appels if a.startswith("update") and "--dry-run" not in a],
                         ["update symfony/cache symfony/http-kernel --with-all-dependencies "
                          "--no-interaction --no-scripts --no-plugins"])

    def test_echec_sans_contrainte_pas_de_second_passage(self):
        """Dépôt « path » du mainteneur absent, tout update échoue."""
        self.ecrire("scenario.json", {
            "audits": [["symfony/yaml", "symfony/config"]],
            "code_update": 1, "sortie_update": SORTIE_DEPOT_LOCAL})
        d, = cd.construire_plan({"problemes": [
            probleme("symfony/yaml", fichier="composer.lock", version="v8.1.10", cible="8.1.11")]})
        texte = "\n".join(cd.corriger_composer(self.depot, d, avec_scripts=False))
        self.assertIn("composer update refusé (code 1) même sans les paquets bloqués : The `url` "
                      "supplied for the path (/Users/dev/Web/TableBundle) repository does not exist",
                      texte)
        self.assertIn("encore concernés (composer update a échoué, voir ci-dessus)", texte)
        updates = [a for a in self.appels("composer-appels.txt") if a.startswith("update")]
        self.assertEqual(len(updates), 1)

    def test_second_passage_pour_les_paquets_absents_du_rapport(self):
        """Sous-dossier back/ : symfony/config absent du rapport (ancienne fusion d'ASGOR)."""
        self.ecrire("scenario.json", {
            "audits": [["symfony/config", "symfony/yaml"], ["symfony/config"], []]})
        d, = cd.construire_plan({"problemes": [
            probleme("symfony/yaml", fichier="composer.lock", version="v8.1.10", cible="8.1.11")]})
        texte = "\n".join(cd.corriger_composer(self.depot, d, avec_scripts=False))
        self.assertIn("update symfony/config --with-all-dependencies --no-interaction "
                      "--no-scripts --no-plugins", self.appels("composer-appels.txt"))
        self.assertIn("second passage : 1 paquet(s) signalé(s) par composer audit", texte)
        self.assertIn("2 paquet(s) concerné(s) avant, 0 après", texte)
        self.assertNotIn("encore concernés", texte)


FAUX_PNPM = r"""#!/usr/bin/env python3
# Faux pnpm 12 : verrou périmé, audit avant/après, « audit --fix » écrit pnpm-workspace.yaml.
import json, os, sys
journal = os.path.join(os.getcwd(), "pnpm-appels.txt")
with open(journal, "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if args[:1] == ["install"] and "--frozen-lockfile" in args:
    print('ERR_PNPM_PACKAGE_MANAGER_NO_IMPORTER\nCannot install with "frozen-lockfile" because '
          'pnpm-lock.yaml has no `importers["packages/message-bundle"]` entry.')
    sys.exit(1)
if args[:2] == ["audit", "--json"]:
    n = sum(1 for l in open(journal) if l.startswith("audit --json"))
    xlsx = {"module_name": "xlsx", "patched_versions": None}
    avis = ({"1": {"module_name": "vitest", "patched_versions": ">=4.1.11"}, "2": xlsx}
            if n == 1 else {"2": xlsx})
    print(json.dumps({"advisories": avis}))
    sys.exit(1)
if args[:2] == ["audit", "--fix"]:
    with open("pnpm-workspace.yaml", "a") as f:
        f.write("overrides:\n  '@vitest/mocker@>=2.1.0 <4.1.11': ^4.1.11\n"
                "  axios@<1.20.0: ^1.20.0\n  vite@<=6.4.2: ^6.4.3\n")
    sys.exit(0)
if args[:1] == ["install"] and os.environ.get("FAUX_PNPM_INSTALL_ECHEC"):
    sys.exit(1)
sys.exit(0)
"""


class CorrectionPnpm(OutilFactice):
    def setUp(self):
        self.installer("pnpm", FAUX_PNPM)
        self.ecrire("package.json", {"name": "essai", "scripts": {"test": "vitest run"}})
        self.ecrire("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\nallowBuilds:\n"
                                           "  '@parcel/watcher': true\n")
        self.ecrire("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n"
                                      "  '@vitest/mocker@4.1.7':\n    resolution: {}\n\n"
                                      "  axios@0.9.0:\n    resolution: {}\n")
        self.plan, = cd.construire_plan({"problemes": [
            probleme("vite", fichier="pnpm-lock.yaml", version="4.5.0", cible="6.4.3")]})

    def test_audit_fix_puis_install_sans_scripts(self):
        texte = "\n".join(cd.corriger_pnpm(self.depot, self.plan, avec_scripts=False))
        appels = self.appels("pnpm-appels.txt")
        self.assertEqual(appels[0], "install --frozen-lockfile --lockfile-only --ignore-scripts")
        self.assertIn("audit --fix", appels)
        self.assertIn("install --ignore-scripts", appels)
        self.assertIn("pnpm-lock.yaml était déjà PÉRIMÉ", texte)
        self.assertIn("pnpm audit : 2 avis avant, 1 après", texte)
        self.assertIn("3 override(s) ajouté(s), pnpm install réussi", texte)
        # Versions du verrou : @vitest/mocker 4.1.7 -> 4.1.11 non (malgré la borne basse 2.1.0),
        # axios 0.9.0 -> 1.20.0 oui ; vite absent du verrou : version du rapport, 4.5.0 -> 6.4.3.
        self.assertIn("2 override(s) imposent un CHANGEMENT DE VERSION MAJEURE", texte)
        self.assertIn("axios@<1.20.0 -> ^1.20.0", texte)
        self.assertIn("vite@<=6.4.2 -> ^6.4.3", texte)
        self.assertNotIn("@vitest/mocker@>=2.1.0 <4.1.11 -> ", texte)
        self.assertIn("aucune version corrigée publiée sur le registre npm (remplacer le paquet "
                      "ou changer sa source) : xlsx", texte)

    def test_overrides_annules_si_pnpm_install_echoue(self):
        with open(os.path.join(self.depot, "pnpm-workspace.yaml")) as f:
            original = f.read()
        os.environ["FAUX_PNPM_INSTALL_ECHEC"] = "1"
        self.addCleanup(os.environ.pop, "FAUX_PNPM_INSTALL_ECHEC", None)
        notes = cd.corriger_pnpm(self.depot, self.plan, avec_scripts=False)
        with open(os.path.join(self.depot, "pnpm-workspace.yaml")) as f:
            self.assertEqual(f.read(), original)
        self.assertTrue(any(n.startswith("overrides annulés, pnpm install a échoué") for n in notes))

    def test_lecture_des_overrides_yaml_et_json(self):
        avant = {"pnpm-workspace.yaml": "packages:\n  - 'a/*'\n", "package.json": "{}"}
        apres = {"pnpm-workspace.yaml": "packages:\n  - 'a/*'\noverrides:\n"
                                        "  '@faker-js/faker@<=10.4.0': ^10.5.0\n",
                 "package.json": '{"pnpm": {"overrides": {\n    "axios@<1.20.0": "^1.20.0",\n'
                                 '    "undici@>=7.0.0 <7.28.0": "^7.28.0"\n}}}'}
        self.assertEqual(cd.overrides_ajoutes(avant, apres), [
            ("@faker-js/faker", "<=10.4.0", "^10.5.0"),
            ("axios", "<1.20.0", "^1.20.0"), ("undici", ">=7.0.0 <7.28.0", "^7.28.0")])

    def test_versions_du_verrou(self):
        verrou = ("packages:\n  glob@13.0.6:\n    x\n  '@vitest/mocker@4.1.7(vite@6.4.2)':\n"
                  "  globby@1.0.0:\n")
        self.assertEqual(cd.versions_pnpm(verrou, "glob"), {"13.0.6"})
        self.assertEqual(cd.versions_pnpm(verrou, "@vitest/mocker"), {"4.1.7"})
        d = cd.Dossier(chemin="", verrou="pnpm-lock.yaml", ecosysteme="pnpm")
        self.assertTrue(cd.override_majeur("glob", ">=9.0.0 <=14.0.1", "^14.0.2", d, verrou))
        self.assertFalse(cd.override_majeur("@vitest/mocker", ">=2.1.0 <4.1.11", "^4.1.11", d, verrou))


class TestsApresTousLesDossiers(unittest.TestCase):
    def test_ordre(self):
        """Monorepo : les tests de la racine chargent back/vendor, installé après la racine."""
        evenements = []
        originaux = (cd.corriger_composer, cd.lancer_tests, cd.verifier_git, cd.creer_branche)
        self.addCleanup(lambda: (setattr(cd, "corriger_composer", originaux[0]),
                                 setattr(cd, "lancer_tests", originaux[1]),
                                 setattr(cd, "verifier_git", originaux[2]),
                                 setattr(cd, "creer_branche", originaux[3])))
        cd.corriger_composer = lambda dossier, d, s: evenements.append(("corriger", d.chemin)) or []
        cd.lancer_tests = lambda dossier, e: evenements.append(("tests", dossier)) or "tests réussis"
        cd.verifier_git = lambda racine, forcer: None
        cd.creer_branche = lambda racine: "branche"
        with tempfile.TemporaryDirectory() as racine:
            for chemin in ("", "back"):
                os.makedirs(os.path.join(racine, chemin), exist_ok=True)
                open(os.path.join(racine, chemin, "composer.lock"), "w").close()
            plan = cd.construire_plan({"problemes": [
                probleme("a/a", fichier="composer.lock"), probleme("b/b", fichier="back/composer.lock")]})
            options = argparse.Namespace(
                oui=True, sans_branche=False, sans_tests=False, avec_scripts=False, forcer=False)
            saved = cd.shutil.which
            cd.shutil.which = lambda outil: "/bin/" + outil
            try:
                cd.appliquer(plan, racine, options)
            finally:
                cd.shutil.which = saved
        self.assertEqual([e[0] for e in evenements], ["corriger", "corriger", "tests", "tests"])


# Extraits réels : Composer termine par son aide d'utilisation.
SORTIE_DEPOT_LOCAL = (
    "Loading composer repositories with package information\n\n"
    "In PathRepository.php line 163:\n"
    "                                                                               \n"
    "  The `url` supplied for the path (/Users/dev/Web/TableBundle) repository   \n"
    "  does not exist                                                               \n"
    "                                                                               \n\n"
    "update [--with WITH] [--prefer-source] [--prefer-dist] [--dry-run] [--] [<packages>...]\n")
SORTIE_INSTALL_LOCAL = (
    "Package operations: 211 installs, 0 updates, 0 removals\n"
    "  - Installing twig/twig (v3.23.0)\n"
    "In PathDownloader.php line 51:\n"
    "  Source path \"/Users/dev/Web/TableBundle\" is not found for package exempl  \n"
    "  e/table-bundle                                                           \n\n"
    "install [--prefer-source] [--prefer-dist] [--dry-run] [--] [<packages>...]\n")


class MessagesDErreur(unittest.TestCase):
    def test_bloc_exception_de_composer(self):
        self.assertEqual(cd.dernieres_lignes(SORTIE_DEPOT_LOCAL),
                         "The `url` supplied for the path (/Users/dev/Web/TableBundle) "
                         "repository does not exist")
        self.assertIn('Source path "/Users/dev/Web/TableBundle" is not found',
                      cd.dernieres_lignes(SORTIE_INSTALL_LOCAL))

    def test_problemes_de_composer(self):
        texte = cd.dernieres_lignes(SORTIE_PERIME + "\nupdate [--with WITH] [--]\n")
        self.assertTrue(texte.startswith("- Root composer.json requires symfony/framework-bundle ^8.1"))
        self.assertIn(" | - Root composer.json requires symfony/http-kernel ^8.1", texte)
        self.assertNotIn("[--with", texte)

    def test_sans_bloc_l_aide_est_ignoree(self):
        self.assertEqual(cd.dernieres_lignes("erreur A\nerreur B\nupdate [--with WITH] [--]\n"),
                         "erreur A | erreur B")


FAUX_COMPOSER_CONFLIT = r"""#!/usr/bin/env python3
# Faux composer : symfony/mime bloqué par « 7.0.* », symfony/cache en dépend ;
# guzzle et twig se mettent à jour seuls.
import json, os, sys
journal = os.path.join(os.getcwd(), "composer-appels.txt")
with open(journal, "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if args[0] == "audit":
    print(json.dumps({"advisories": {}}))
    sys.exit(0)
paquets = [a for a in args[1:] if "/" in a]
if "symfony/mime" in paquets:
    print("  Problem 1\n    - Root composer.json requires symfony/mime 7.0.*, found symfony/mime"
          "[v7.0.0, ..., v7.0.9] but these were not loaded, because they are affected by security "
          "advisories\n    - Root composer.json requires exemple/table-bundle * -> satisfiable "
          "by exemple/table-bundle[v1.0.2].", file=sys.stderr)
    sys.exit(2)
if "symfony/cache" in paquets:
    print("  Problem 1\n    - symfony/cache v7.1.0 requires symfony/mime ^7.1 -> found "
          "symfony/mime[v7.0.9] but it does not match.", file=sys.stderr)
    sys.exit(2)
sys.exit(0)
"""


class ComposerPaquetParPaquet(OutilFactice):
    def test_les_paquets_independants_passent(self):
        self.installer("composer", FAUX_COMPOSER_CONFLIT)
        self.ecrire("composer.json", {"require": {"symfony/mime": "7.0.*"}})
        d, = cd.construire_plan({"problemes": [
            probleme(n, fichier="composer.lock", version="v7.0.8", cible="7.1.0")
            for n in ("guzzlehttp/guzzle", "symfony/cache", "symfony/mime", "twig/twig")]})
        texte = "\n".join(cd.corriger_composer(self.depot, d, avec_scripts=False))
        updates = [a.split(" --")[0] for a in self.appels("composer-appels.txt")
                   if a.startswith("update")]
        self.assertEqual(updates, [
            "update guzzlehttp/guzzle symfony/cache symfony/mime twig/twig",   # groupé
            "update guzzlehttp/guzzle symfony/cache twig/twig",                # sans le bloqué
            "update guzzlehttp/guzzle", "update symfony/cache", "update twig/twig"])
        self.assertIn("paquet par paquet : 2 mis à jour (guzzlehttp/guzzle, twig/twig), "
                      "1 refusé(s)", texte)
        self.assertIn("    symfony/cache : - symfony/cache v7.1.0 requires symfony/mime ^7.1", texte)
        self.assertIn("    symfony/mime : contrainte 7.0.*, version corrigée 7.1.0", texte)
        self.assertNotIn("exemple/table-bundle : contrainte", texte)


class DepotsLocaux(OutilFactice):
    def setUp(self):
        self.installer("composer", "#!/bin/sh\nexit 0\n")

    def test_depot_path_absent_signale(self):
        os.makedirs(os.path.join(self.depot, "paquets", "a"))
        self.ecrire("composer.json", {"repositories": [
            {"type": "path", "url": "/Users/dev/Web/TableBundle"},
            {"type": "path", "url": "paquets/*"},          # présent : rien à signaler
            {"type": "vcs", "url": "https://github.com/x/y"}]})
        self.assertEqual(cd.depots_locaux_absents(self.depot), ["/Users/dev/Web/TableBundle"])

    def test_composer_json_absent_ou_illisible(self):
        self.assertEqual(cd.depots_locaux_absents(self.depot), [])
        self.ecrire("composer.json", "pas du json")
        self.assertEqual(cd.depots_locaux_absents(self.depot), [])

    def test_echec_de_composer_install_avant_npm(self):
        self.installer("composer", "#!/bin/sh\ncat <<'FIN' >&2\n" + SORTIE_INSTALL_LOCAL + "FIN\nexit 1\n")
        self.ecrire("package.json", {"devDependencies": {
            "@symfony/ux-chartjs": "file:vendor/symfony/ux-chartjs/assets"}})
        self.ecrire("composer.lock", "{}")
        with self.assertRaises(cd.Arret) as e:
            cd.preparer_vendor(self.depot, avec_scripts=False)
        self.assertIn("« composer install » a échoué (code 1)", str(e.exception))
        self.assertIn("/Users/dev/Web/TableBundle", str(e.exception))


class Git(unittest.TestCase):
    def test_depot_modifie_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            open(os.path.join(d, "fichier"), "w").close()
            with self.assertRaises(cd.Arret):
                cd.verifier_git(d, forcer=False)
            cd.verifier_git(d, forcer=True)            # accepté avec --forcer
            os.makedirs(os.path.join(d, "sous"))
            with self.assertRaises(cd.Arret):
                cd.verifier_git(os.path.join(d, "sous"), forcer=True)   # pas la racine


class Ligne_de_commande(unittest.TestCase):
    def test_sans_argument(self):
        r = subprocess.run([sys.executable, cd.__file__], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("usage", r.stderr.lower())

    def test_avertissement_dans_l_aide(self):
        r = subprocess.run([sys.executable, cd.__file__, "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("CASSER L'APPLICATION", r.stdout)
        self.assertIn("sans garantie", r.stdout)

    def test_chemin_relatif_du_rapport(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "r.json"), "w") as f:
                json.dump({"problemes": [probleme("axios")]}, f)
            r = subprocess.run([sys.executable, cd.__file__, "r.json", "--plan"], cwd=d,
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("axios", r.stdout)


if __name__ == "__main__":
    unittest.main()
