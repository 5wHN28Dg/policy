"""Tests for tools/policy_check.py. Run: python3 -m unittest discover -s tools/tests"""

import datetime
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import policy_check as pc  # noqa: E402

EXAMPLE_BUDGETS = (pc.POLICY_ROOT / "templates" / "budgets.example.json").read_text()
SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
DIGEST = "sha256:" + "a" * 64


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def compliant_project(root: Path, tier: str = "T2", types: str = "native") -> None:
    write(root, "README.md", f"# Demo\n\nTier: {tier}\nPolicy: v1.1\nType: {types}\n")
    write(root, "SECURITY.md", "Report to ...\n")
    write(root, "docs/threat-model.md", "# Threat model\n")
    write(root, "docs/capability-matrix.md", "# Matrix\nChecked: 2026-10-05\n")
    write(root, "license-allowlist.txt", "MIT\nApache-2.0\n")
    write(root, "budgets.json", EXAMPLE_BUDGETS)
    write(root, ".github/workflows/ci.yml", f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA} # v7\n")
    if "web" in types:
        write(root, "index.html", "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self'; object-src 'none'; base-uri 'none'\">\n")


def commit_backdated(root: Path, days: int = 3, message: str = "x") -> None:
    """Commit everything in root (making it a git repo if needed) with author and committer dates `days` ago."""
    if not (root / ".git").exists():
        subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
    when = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S+0000")
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when}
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", message, "--allow-empty"], check=True, env=env)


def rules(problems):
    return sorted({p.rule for p in problems})


class HeaderTests(unittest.TestCase):
    def test_parses_plain_and_bold_lines(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "README.md", "**Tier:** T3\n*Policy:* `v1.1`\nType: web, Firmware\nUsers: none\n")
            h = pc.read_header(Path(d))
            self.assertEqual((h.tier, h.policy, h.types, h.users), ("T3", "v1.1", ["web", "firmware"], "none"))

    def test_header_ignores_code_blocks_and_later_sections(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "README.md", "# App\n\nTier: T2\nPolicy: [v1.1](https://x/y)\nType: web\n\n```yaml\nusers: none\n```\n\n## Usage\n\nType: anything you like\nUsers: none\n")
            h = pc.read_header(Path(d))
            self.assertEqual((h.tier, h.policy, h.types, h.users, h.lighter_t2), ("T2", "v1.1", ["web"], None, False))

    def test_tier_with_label(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "README.md", "Tier: T2 (Public)\n")
            self.assertEqual(pc.read_header(Path(d)).tier, "T2")

    def test_lighter_t2_only_for_t2(self):
        self.assertTrue(pc.Header(tier="T2", users="none").lighter_t2)
        self.assertFalse(pc.Header(tier="T3", users="none").lighter_t2)
        self.assertFalse(pc.Header(tier="T2", users="12").lighter_t2)

    def test_missing_lines_are_reported(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "README.md", "# Nothing here\n")
            self.assertEqual(rules(pc.check_header(Path(d), pc.read_header(Path(d)))), ["Gov §1", "README index"])

    def test_bad_values(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "README.md", "Tier: T5\nPolicy: 1.0\nType: desktop\n")
            msgs = " ".join(p.message for p in pc.check_header(Path(d), pc.read_header(Path(d))))
            self.assertIn("T5", msgs)
            self.assertIn("vX.Y", msgs)
            self.assertIn("desktop", msgs)

    def test_t0_needs_only_tier(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "README.md", "Tier: T0\n")
            self.assertEqual(pc.conformance(Path(d), None, {}), [])


class ConformanceTests(unittest.TestCase):
    def setUp(self):
        os.environ["POLICY_SKIP_BROWSERSLIST"] = "1"

    def test_compliant_t2_passes(self):
        with tempfile.TemporaryDirectory() as d:
            compliant_project(Path(d))
            self.assertEqual(pc.conformance(Path(d), None, {}), [])

    def test_t2_missing_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            compliant_project(root)
            for f in ("SECURITY.md", "docs/threat-model.md", "docs/capability-matrix.md", "license-allowlist.txt", "budgets.json"):
                (root / f).unlink()
            self.assertEqual(rules(pc.conformance(root, None, {})), ["Gov §1", "Gov §4", "Gov §5 (license allowlist)", "NAT-3", "NAT-7"])

    def test_t1_does_not_need_t2_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            compliant_project(root, tier="T1")
            for f in ("docs/threat-model.md", "license-allowlist.txt", "budgets.json"):
                (root / f).unlink()
            self.assertEqual(pc.conformance(root, None, {}), [])

    def test_lighter_t2_defers_budgets_and_threat_model(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            compliant_project(root)
            write(root, "README.md", "Tier: T2\nPolicy: v1.1\nType: native\nUsers: none\n")
            for f in ("docs/threat-model.md", "license-allowlist.txt", "budgets.json"):
                (root / f).unlink()
            self.assertEqual(pc.conformance(root, None, {}), [])

    def test_security_md_in_github_dir(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            compliant_project(root)
            (root / "SECURITY.md").rename(root / "docs" / "SECURITY.md")
            self.assertEqual(pc.conformance(root, None, {}), [])

    def test_matrix_needs_checked_date(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            compliant_project(root, types="web, firmware")
            write(root, "docs/capability-matrix.md", "# Matrix\n")
            self.assertEqual([p.rule for p in pc.conformance(root, None, {})], ["WEB-1"])

    def test_invalid_budgets(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            compliant_project(root, types="service")
            data = json.loads(EXAMPLE_BUDGETS)
            del data["custom"][0]["measuredWhere"]
            write(root, "budgets.json", json.dumps(data))
            problems = pc.conformance(root, None, {})
            self.assertEqual([p.rule for p in problems], ["OTH-5"])
            self.assertIn("measuredWhere", problems[0].message)

    def test_budgets_not_json(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            compliant_project(root)
            write(root, "budgets.json", "{nope")
            self.assertIn("not valid JSON", pc.conformance(root, None, {})[0].message)


class PinTests(unittest.TestCase):
    def check(self, files):
        with tempfile.TemporaryDirectory() as d:
            for rel, text in files.items():
                write(Path(d), rel, text)
            return pc.check_pins(Path(d))

    def test_workflow_uses(self):
        problems = self.check({".github/workflows/a.yml": "\n".join([
            "steps:",
            f"  - uses: actions/checkout@{SHA} # v7",
            "  - uses: actions/setup-java@v6",
            "  - uses: ./local-action",
            f"  - uses: docker://alpine@{DIGEST}",
            "  - uses: docker://alpine:3.20",
            "  - uses: 'gradle/actions/setup-gradle@v6'",
            "jobs:",
            "  x:",
            "    uses: owner/repo/.github/workflows/w.yml@main",
        ])})
        self.assertEqual([p.line for p in problems], [3, 6, 7, 10])
        self.assertTrue(all(p.rule == "DEP-7" for p in problems))

    def test_container_images(self):
        problems = self.check({".github/workflows/a.yml": f"container: node:20\nservices:\n  db:\n    image: postgres@{DIGEST}\n  cache:\n    image: redis:7\n"})
        self.assertEqual([p.line for p in problems], [1, 6])

    def test_expression_images_are_skipped(self):
        self.assertEqual(self.check({".github/workflows/a.yml": "container: ${{ matrix.image }}\n"}), [])

    def test_dockerfile_stages_and_scratch(self):
        problems = self.check({"deploy/Dockerfile": "\n".join([
            "FROM python:3.13 AS build",
            f"FROM python@{DIGEST} AS ok",
            "FROM build",
            "FROM scratch",
            "FROM --platform=linux/amd64 debian:12",
            "FROM ${BASE}",
        ])})
        self.assertEqual([p.line for p in problems], [1, 5, 6])
        self.assertIn("no default", problems[2].message)

    def test_dockerfile_variants_args_and_stage_case(self):
        problems = self.check({
            "deploy/Dockerfile.prod": "ARG BASE=ubuntu:22.04\nFROM ${BASE} AS Build\nFROM build\n",
            "Containerfile.dev": f"ARG BASE=debian@{DIGEST}\nFROM $BASE\n",
        })
        self.assertEqual([(p.file, p.line) for p in problems], [("deploy/Dockerfile.prod", 2)])
        self.assertIn("ubuntu:22.04", problems[0].message)

    def test_kubernetes_manifest(self):
        problems = self.check({"k8s/app.yaml": f"apiVersion: apps/v1\nkind: Deployment\nspec:\n  containers:\n    - image: app:1.2\n    - image: app@{DIGEST}\n",
                               "config/settings.yaml": "image: not-a-manifest\n"})
        self.assertEqual([(p.file, p.line) for p in problems], [("k8s/app.yaml", 5)])

    def test_compose(self):
        problems = self.check({"docker-compose.yml": f"services:\n  a:\n    image: nginx:1.27\n  b:\n    image: nginx@{DIGEST}\n"})
        self.assertEqual([p.line for p in problems], [3])


class BudgetLooseningTests(unittest.TestCase):
    def repo(self, d: Path, old: dict, new: dict) -> str:
        subprocess.run(["git", "init", "-q", "-b", "main", str(d)], check=True)
        write(d, "budgets.json", json.dumps(old))
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        subprocess.run(["git", "-C", str(d), "add", "."], check=True)
        subprocess.run(["git", "-C", str(d), "commit", "-qm", "base"], check=True, env=env)
        write(d, "budgets.json", json.dumps(new))
        return "HEAD"

    def test_raised_max_needs_reason(self):
        old = json.loads(EXAMPLE_BUDGETS)
        new = json.loads(EXAMPLE_BUDGETS)
        new["web"]["bundles"][0]["maxKB"] += 50
        new["custom"][1]["min"] -= 10
        with tempfile.TemporaryDirectory() as d:
            base = self.repo(Path(d), old, new)
            problems = pc.check_budget_loosening(Path(d), base, {"pull_request": {"body": "Adds a chart."}})
            self.assertEqual(len(problems), 1)
            self.assertIn("maxKB: 100 -> 150", problems[0].message)
            self.assertIn("free heap after boot", problems[0].message)
            ok = pc.check_budget_loosening(Path(d), base, {"pull_request": {"body": "Budget change: the chart library, see DEP record"}})
            self.assertEqual(ok, [])

    def test_removed_or_moved_out_of_ci_counts(self):
        old = json.loads(EXAMPLE_BUDGETS)
        new = json.loads(EXAMPLE_BUDGETS)
        del new["native"]["linux"]
        new["custom"][0]["measuredWhere"] = "release-test"
        with tempfile.TemporaryDirectory() as d:
            base = self.repo(Path(d), old, new)
            msg = pc.check_budget_loosening(Path(d), base, {})[0].message
            self.assertIn("native.linux@ci.startupMs: removed", msg)
            self.assertIn("firmware flash used]@ci.max: removed", msg)

    def test_tightening_is_fine(self):
        old = json.loads(EXAMPLE_BUDGETS)
        new = json.loads(EXAMPLE_BUDGETS)
        new["web"]["lab"]["lcpMs"] -= 500
        with tempfile.TemporaryDirectory() as d:
            base = self.repo(Path(d), old, new)
            self.assertEqual(pc.check_budget_loosening(Path(d), base, {}), [])

    def test_no_base_no_check(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(pc.check_budget_loosening(Path(d), None, {}), [])


class BrowserslistTests(unittest.TestCase):
    def test_missing_declaration(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root, "package.json", "{}")
            problems = pc.check_browserslist(root, pc.Header(tier="T1", types=["web"]))
            self.assertEqual([p.rule for p in problems], ["WEB-2"])

    def test_recorded_list_parsing(self):
        with tempfile.TemporaryDirectory() as d:
            m = Path(d) / "m.md"
            m.write_text("Checked: x\nResolved browser list (web only):\n\n```\nchrome 140\nsafari 26.0\n```\n")
            self.assertEqual(pc.recorded_browsers(m), {"chrome 140", "safari 26.0"})
            m.write_text("Resolved browser list (web only): <output of npx browserslist>\n")
            self.assertIsNone(pc.recorded_browsers(m))

    def test_differs_both_ways(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root, ".browserslistrc", "defaults\n")
            write(root, "docs/capability-matrix.md", "Resolved browser list:\n```\nchrome 140\nie 11\n```\n")
            fake = root / "bin" / "npx"
            write(root, "bin/npx", "#!/bin/sh\nprintf 'chrome 140\\nfirefox 143\\n'\n")
            fake.chmod(0o755)
            old_path = os.environ["PATH"]
            os.environ["PATH"] = f"{root / 'bin'}:{old_path}"
            try:
                problems = pc.check_browserslist(root, pc.Header(tier="T1", types=["web"]))
            finally:
                os.environ["PATH"] = old_path
            self.assertEqual(len(problems), 1)
            self.assertIn("now includes firefox 143", problems[0].message)
            self.assertIn("no longer includes ie 11", problems[0].message)

    def test_not_web(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(pc.check_browserslist(Path(d), pc.Header(tier="T1", types=["native"])), [])


class CliTests(unittest.TestCase):
    def test_tier_and_header_commands(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "README.md", "Tier: T1\nPolicy: v1.1\nType: service\n")
            script = str(pc.POLICY_ROOT / "tools" / "policy_check.py")
            out = subprocess.run([sys.executable, script, "tier", "--root", d], capture_output=True, text=True, check=True).stdout
            self.assertEqual(out.strip(), "T1")
            out = subprocess.run([sys.executable, script, "header", "--root", d], capture_output=True, text=True, check=True).stdout
            self.assertEqual(json.loads(out)["types"], ["service"])

    def test_annotations_in_actions(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "README.md", "Tier: T1\n")
            env = {**os.environ, "GITHUB_ACTIONS": "true", "POLICY_SKIP_BROWSERSLIST": "1"}
            env.pop("GITHUB_EVENT_PATH", None)
            env.pop("GITHUB_STEP_SUMMARY", None)
            r = subprocess.run([sys.executable, str(pc.POLICY_ROOT / "tools" / "policy_check.py"), "conformance", "--root", d],
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 1)
            self.assertIn("::error file=README.md::Gov §1:", r.stdout)


if __name__ == "__main__":
    unittest.main()


class VulnGateTests(unittest.TestCase):
    REPORT = {"results": [{"source": {"path": "/x/package-lock.json"}, "packages": [
        {"package": {"name": "a", "version": "1"}, "groups": [{"ids": ["GHSA-1"], "max_severity": "9.8"}]},
        {"package": {"name": "b", "version": "2"}, "groups": [{"ids": ["GHSA-2"], "max_severity": "5.3"}]},
        {"package": {"name": "c", "version": "3"}, "groups": [{"ids": ["GHSA-3"], "max_severity": ""}]},
    ]}]}

    def gate(self, tier):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "osv.json"
            p.write_text(json.dumps(self.REPORT))
            return pc.vuln_gate(p, tier)

    def test_t1_only_warns(self):
        blocking, warnings = self.gate("T1")
        self.assertEqual((len(blocking), len(warnings)), (0, 3))

    def test_t2_blocks_high_and_critical(self):
        blocking, warnings = self.gate("T2")
        # a: CVSS 9.8; c: no score and no database rating, so assumed severe
        self.assertEqual([b.message.split()[2] for b in blocking], ["a", "c"])
        self.assertEqual(len(warnings), 1)

    def test_t3_blocks_every_severity(self):
        blocking, warnings = self.gate("T3")
        self.assertEqual((len(blocking), len(warnings)), (3, 0))

    def test_database_severity_fallback(self):
        report = {"results": [{"source": {"path": "/x/go.sum"}, "packages": [
            {"package": {"name": "h", "version": "1"}, "groups": [{"ids": ["GO-1"], "max_severity": ""}],
             "vulnerabilities": [{"id": "GO-1", "database_specific": {"severity": "HIGH"}}]},
            {"package": {"name": "m", "version": "1"}, "groups": [{"ids": ["GO-2"], "max_severity": ""}],
             "vulnerabilities": [{"id": "GO-2", "database_specific": {"severity": "MODERATE"}}]},
        ]}]}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "osv.json"
            p.write_text(json.dumps(report))
            blocking, warnings = pc.vuln_gate(p, "T2")
        self.assertEqual([b.message.split()[2] for b in blocking], ["h"])
        self.assertIn("severity MODERATE", warnings[0].message)

    def test_real_osv_report(self):
        fixture = Path(__file__).parent / "fixtures" / "osv-licenses-and-vulns.json"
        blocking, warnings = pc.vuln_gate(fixture, "T2")
        self.assertEqual(len(blocking), 1)  # lodash GHSA-35jh, CVSS 8.1
        self.assertEqual(len(warnings), 2)
        self.assertEqual(pc.vuln_gate(fixture, "T1")[0], [])


class LicenseGateTests(unittest.TestCase):
    def test_violations_only(self):
        fixture = Path(__file__).parent / "fixtures" / "osv-licenses-and-vulns.json"
        problems = pc.license_gate(fixture)
        self.assertEqual(len(problems), 1)
        self.assertIn("left-pad 1.3.0 has license WTFPL", problems[0].message)

    def test_missing_report_is_clean(self):
        self.assertEqual(pc.vuln_gate(Path("/nonexistent.json"), "T3"), ([], []))


class BaselineTests(unittest.TestCase):
    def setUp(self):
        os.environ["POLICY_SKIP_BROWSERSLIST"] = "1"

    def project(self, root, baseline):
        compliant_project(root)
        write(root, "README.md", f"Tier: T2\nPolicy: v1.2\nType: native\nBaseline: {baseline}\n")
        for f in ("docs/threat-model.md", "budgets.json"):
            (root / f).unlink()

    def test_active_baseline_turns_missing_artifacts_into_warnings(self):
        until = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.project(root, f"until {until}")
            write(root, ".github/workflows/x.yml", "steps:\n  - uses: actions/checkout@v7\n")
            problems = pc.conformance(root, None, {})
            errors = [p.rule for p in problems if p.level == "error"]
            warnings = sorted(p.rule for p in problems if p.level == "warning")
            self.assertEqual(errors, ["DEP-7"])  # not an artifact: still blocks
            self.assertEqual(warnings, ["Gov §1", "Gov §4", "NAT-7"])

    def test_expired_or_too_long_baseline_blocks(self):
        past = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        far = (datetime.date.today() + datetime.timedelta(days=120)).isoformat()
        for value, text in ((f"until {past}", "ended"), (f"until {far}", "more than 90"), ("soon", "form")):
            with tempfile.TemporaryDirectory() as d:
                root = Path(d)
                self.project(root, value)
                problems = pc.conformance(root, None, {})
                self.assertTrue(any(text in p.message and p.level == "error" for p in problems), value)
                self.assertTrue(all(p.level == "error" for p in problems if p.artifact), value)


class LockfileTests(unittest.TestCase):
    def check(self, files, tier="T2"):
        with tempfile.TemporaryDirectory() as d:
            for rel, text in files.items():
                write(Path(d), rel, text)
            return pc.check_lockfiles(Path(d), pc.Header(tier=tier, types=["native"]))

    def test_gradle_and_npm_without_lockfiles(self):
        problems = self.check({"android/app/build.gradle.kts": "plugins {}\ndependencies {\n  implementation(\"a:b:1\")\n}\n",
                               "web/package.json": '{"dependencies": {"x": "1"}}',
                               "ok/package.json": '{"dependencies": {"x": "1"}}', "ok/package-lock.json": "{}",
                               "empty/package.json": '{"name": "no-deps"}'})
        self.assertEqual(sorted(p.file for p in problems), ["android/app/build.gradle.kts", "web/package.json"])
        self.assertTrue(all(p.level == "error" and not p.artifact for p in problems))

    def test_gradle_lockfile_anywhere_counts(self):
        self.assertEqual(self.check({"android/app/build.gradle.kts": "x", "android/gradle.lockfile": "x"}), [])

    def test_unpinned_requirements(self):
        problems = self.check({"requirements-dev.txt": "pytest\nrequests==2.32.0\n# comment\n-r other.txt\nblack>=24\n"})
        self.assertEqual([p.line for p in problems], [1, 5])

    def test_t1_warns(self):
        problems = self.check({"build.gradle": "dependencies {\n}\n"}, tier="T1")
        self.assertEqual([p.level for p in problems], ["warning"])


class PinnedSourcesTests(unittest.TestCase):
    def check(self, bom):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "pinned-sources.cdx.json", json.dumps(bom))
            return pc.check_pinned_sources(Path(d))

    def test_complete_component_passes(self):
        good = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{
            "name": "zlib", "version": "1.3.1", "licenses": [{"license": {"id": "Zlib"}}],
            "externalReferences": [{"type": "distribution", "url": "https://zlib.net/zlib-1.3.1.tar.gz",
                                    "hashes": [{"alg": "SHA-256", "content": "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"}]}]}]}
        self.assertEqual(self.check(good), [])

    def test_commit_as_version_counts_as_pin(self):
        bom = {"bomFormat": "CycloneDX", "components": [{"name": "emsdk", "version": "a" * 40,
               "licenses": [{"license": {"id": "MIT"}}], "externalReferences": [{"url": "https://github.com/x/y"}]}]}
        self.assertEqual(self.check(bom), [])

    def test_missing_fields(self):
        problems = self.check({"bomFormat": "CycloneDX", "components": [{"name": "sqlite", "version": "3.46"}]})
        self.assertEqual(len(problems), 1)
        for word in ("URL", "SHA-256", "licenses"):
            self.assertIn(word, problems[0].message)

    def test_not_cyclonedx(self):
        self.assertIn("CycloneDX", self.check({"components": []})[0].message)


class CspTests(unittest.TestCase):
    def check(self, files, tier="T2", types=("web",)):
        with tempfile.TemporaryDirectory() as d:
            for rel, text in files.items():
                write(Path(d), rel, text)
            return pc.check_csp(Path(d), pc.Header(tier=tier, types=list(types)))

    def test_no_csp_at_t2(self):
        self.assertEqual([p.rule for p in self.check({"index.html": "<p>hi</p>"})], ["WEB-8"])
        self.assertEqual(self.check({"index.html": "<p>hi</p>"}, tier="T1"), [])
        self.assertEqual(self.check({"main.kt": "x"}, types=("native",)), [])

    def test_unsafe_inline_in_script_directive(self):
        problems = self.check({"server/headers.py": 'HEADERS = {"Content-Security-Policy": "default-src \'self\'; script-src \'self\' \'unsafe-inline\'"}\n'})
        self.assertEqual([(p.rule, p.line) for p in problems], [("WEB-7", 1)])

    def test_unsafe_inline_only_in_style_is_fine(self):
        problems = self.check({"index.html": "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self'; style-src 'self' 'unsafe-inline'\">"})
        self.assertEqual(problems, [])

    def test_default_src_counts_when_no_script_src(self):
        problems = self.check({"_headers": "Content-Security-Policy: default-src 'self' 'unsafe-eval'\n"})
        self.assertEqual([p.rule for p in problems], ["WEB-7"])

    def test_markdown_mentions_are_ignored(self):
        self.assertEqual([p.rule for p in self.check({"docs/csp.md": "never use script-src 'unsafe-inline'"})], ["WEB-8"])


class GitleaksConfigTests(unittest.TestCase):
    def test_must_extend_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), ".gitleaks.toml", "[allowlist]\npaths = ['''ref/vectors/''']\n")
            self.assertIn("useDefault", pc.check_gitleaks_config(Path(d), None, {})[0].message)
            write(Path(d), ".gitleaks.toml", "[extend]\nuseDefault = true\n\n[allowlist]\npaths = ['''ref/vectors/''']\n")
            self.assertEqual(pc.check_gitleaks_config(Path(d), None, {}), [])

    def test_pr_change_needs_reason(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subprocess.run(["git", "init", "-q", "-b", "main", d], check=True)
            env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
            write(root, "README.md", "x")
            subprocess.run(["git", "-C", d, "add", "."], check=True)
            subprocess.run(["git", "-C", d, "commit", "-qm", "base"], check=True, env=env)
            base = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
            write(root, ".gitleaks.toml", "[extend]\nuseDefault = true\n")
            subprocess.run(["git", "-C", d, "add", "."], check=True)
            subprocess.run(["git", "-C", d, "commit", "-qm", "config"], check=True, env=env)
            problems = pc.check_gitleaks_config(root, base, {"pull_request": {"body": "Adds vectors."}})
            self.assertIn("Secrets config change", problems[0].message)
            self.assertEqual(pc.check_gitleaks_config(root, base, {"pull_request": {"body": "Secrets config change: test vectors"}}), [])
            write(root, "app.py", f"KEY = 'x'  # {pc.ALLOW_MARKER}\n")
            subprocess.run(["git", "-C", d, "add", "."], check=True)
            subprocess.run(["git", "-C", d, "commit", "-qm", "allow"], check=True, env=env)
            problems = pc.check_gitleaks_config(root, base, {"pull_request": {"body": "x"}})
            self.assertIn(pc.ALLOW_MARKER, problems[0].message)

    def test_toml_forms(self):
        for text, ok in (("extend.useDefault = true\n", True), ("[extend] # defaults\nuseDefault = true\n", True),
                         ("extend = { useDefault = true }\n", True), ("[extend]\nuseDefault = false\n", False),
                         ("[extend\n", None)):
            with tempfile.TemporaryDirectory() as d:
                write(Path(d), ".gitleaks.toml", text)
                problems = pc.check_gitleaks_config(Path(d), None, {})
                if ok:
                    self.assertEqual(problems, [], text)
                elif ok is False:
                    self.assertIn("useDefault", problems[0].message, text)
                else:
                    self.assertIn("not valid TOML", problems[0].message, text)


class InlineScriptTests(unittest.TestCase):
    PAGE = ("<html>\n<head><script src=\"app.js\"></script>\n<script type=\"application/ld+json\">{\"a\": 1}</script>\n"
            "</head>\n<body onclick=\"go()\">\n<script>\nconst x = 1;\nel.innerHTML = data;\n</script>\n"
            "<script type=module>\nlocation.href = next;\n</script>\n</body></html>\n")

    def test_keeps_line_numbers_and_only_inline_js(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            write(Path(d), "admin.html", self.PAGE)
            mapping = pc.extract_inline(Path(d), Path(out))
            (copy, orig), = mapping.items()
            self.assertEqual(orig, "admin.html")
            lines = Path(copy).read_text().splitlines()
            self.assertEqual(len(lines), len(self.PAGE.splitlines()))
            self.assertEqual(lines[7].strip(), "el.innerHTML = data;")
            self.assertEqual(lines[10].strip(), "location.href = next;")
            text = Path(copy).read_text()
            self.assertNotIn("onclick", text)
            self.assertNotIn('"a": 1', text)
            self.assertNotIn("app.js", text)

    def test_files_without_inline_scripts_are_skipped(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            write(Path(d), "a.html", "<p>no scripts</p>")
            self.assertEqual(pc.extract_inline(Path(d), Path(out)), {})


class SastGateTests(unittest.TestCase):
    def report(self, d, results):
        p = Path(d) / f"r{len(list(Path(d).iterdir()))}.json"
        p.write_text(json.dumps({"results": results}))
        return p

    def result(self, check_id, path, line, severity, **meta):
        return {"check_id": check_id, "path": path, "start": {"line": line},
                "extra": {"message": "msg", "severity": severity, "metadata": meta}}

    def test_levels(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.report(d, [
                self.result("semgrep.web-9-html-sink-assignment", "a.js", 1, "ERROR", **{"policy-rule": "WEB-9"}),
                self.result("semgrep.web-7-inline-event-handler", "a.html", 2, "WARNING", **{"policy-rule": "WEB-7"}),
                self.result("javascript.lang.security.detect-insecure-websocket", "x.nim", 3, "ERROR",
                            confidence="LOW", subcategory=["audit"]),
                self.result("python.lang.security.audit.eval", "y.py", 4, "ERROR", confidence="HIGH", subcategory=["vuln"]),
                self.result("generic.secrets.thing", "z", 5, "WARNING", confidence="HIGH"),
            ])
            problems = pc.sast_gate([r])
            self.assertEqual([(p.rule, p.level) for p in problems], [
                ("WEB-9", "error"), ("WEB-7", "warning"), ("Gov §5 (detect-insecure-websocket)", "warning"),
                ("Gov §5 (eval)", "error"), ("Gov §5 (thing)", "warning")])

    def test_inline_paths_map_back_and_dedupe(self):
        with tempfile.TemporaryDirectory() as d:
            copy = str(Path(d) / "admin.html.inline.js")
            Path(copy).write_text("")
            r1 = self.report(d, [self.result("x.web-9-html-sink-assignment", copy, 9, "ERROR", **{"policy-rule": "WEB-9"})])
            r2 = self.report(d, [self.result("x.web-9-html-sink-assignment", copy, 9, "ERROR", **{"policy-rule": "WEB-9"})])
            problems = pc.sast_gate([r1, r2], {copy: "admin.html"})
            self.assertEqual([(p.file, p.line) for p in problems], [("admin.html", 9)])


class ReviewFixTests(unittest.TestCase):
    """Behaviour added after the PR #2 review."""

    def git(self, d, *args):
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        return subprocess.run(["git", "-C", d, *args], check=True, capture_output=True, text=True, env=env).stdout.strip()

    def test_baseline_cannot_be_added_late_or_extended(self):
        soon = (datetime.date.today() + datetime.timedelta(days=20)).isoformat()
        later = (datetime.date.today() + datetime.timedelta(days=60)).isoformat()
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", "-b", "main", d], check=True)
            write(Path(d), "README.md", "Tier: T2\nPolicy: v2.0\nType: native\n")
            self.git(d, "add", "."); self.git(d, "commit", "-qm", "adopted")
            base = self.git(d, "rev-parse", "HEAD")
            write(Path(d), "README.md", f"Tier: T2\nPolicy: v2.0\nType: native\nBaseline: until {soon}\n")
            msg = pc.check_baseline_change(Path(d), base, pc.read_header(Path(d)))[0].message
            self.assertIn("already follows", msg)
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", "-b", "main", d], check=True)
            write(Path(d), "README.md", f"Tier: T2\nPolicy: v2.0\nType: native\nBaseline: until {soon}\n")
            self.git(d, "add", "."); self.git(d, "commit", "-qm", "adopted")
            base = self.git(d, "rev-parse", "HEAD")
            write(Path(d), "README.md", f"Tier: T2\nPolicy: v2.0\nType: native\nBaseline: until {later}\n")
            self.assertIn("never moved later", pc.check_baseline_change(Path(d), base, pc.read_header(Path(d)))[0].message)
        with tempfile.TemporaryDirectory() as d:  # the adoption PR itself: no Policy line before
            subprocess.run(["git", "init", "-q", "-b", "main", d], check=True)
            write(Path(d), "README.md", "# App\n")
            self.git(d, "add", "."); self.git(d, "commit", "-qm", "before")
            base = self.git(d, "rev-parse", "HEAD")
            write(Path(d), "README.md", f"Tier: T2\nPolicy: v2.0\nType: native\nBaseline: until {soon}\n")
            self.assertEqual(pc.check_baseline_change(Path(d), base, pc.read_header(Path(d))), [])

    def test_suppression_markers_need_policy_fp_or_exception(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "a.js", "\n".join([
                "el.innerHTML = x; // nosemgrep",
                "el.innerHTML = y; // nosemgrep: web-9-html-sink-assignment -- policy-fp: constant markup (https://github.com/o/r/pull/3#r1)",
                "el.innerHTML = z; // nosemgrep -- exception: https://github.com/o/r/issues/9",
                f"const k = 'x'; // {pc.ALLOW_MARKER}",
            ]))
            write(Path(d), "docs/notes.md", "use // nosemgrep sparingly\n")
            # line 3 names an exception link, but no entry in force has it
            self.assertEqual([p.line for p in pc.check_markers(Path(d))], [1, 3, 4])
            ex = pc.Exception_("EX-9", "WEB-9", ["a.js"], datetime.date.today(), datetime.date.today(), "https://github.com/o/r/issues/9")
            self.assertEqual([p.line for p in pc.check_markers(Path(d), [ex])], [1, 4])
            elsewhere = pc.Exception_("EX-9", "WEB-9", ["src/*.js"], datetime.date.today(), datetime.date.today(), "https://github.com/o/r/issues/9")
            self.assertEqual([p.line for p in pc.check_markers(Path(d), [elsewhere])], [1, 3, 4])

    def test_lockfile_in_ancestor_and_pyproject_without_deps(self):
        with tempfile.TemporaryDirectory() as d:
            for rel, text in {"package-lock.json": "{}", "packages/a/package.json": '{"dependencies": {"x": "1"}}',
                              "pyproject.toml": "[tool.ruff]\nline-length = 100\n",
                              "svc/pyproject.toml": "[project]\nname = 'x'\ndependencies = ['requests']\n",
                              "requirements.txt": "a==1.2\nb==2.*\nc @ https://x/c.whl\n"}.items():
                write(Path(d), rel, text)
            problems = pc.check_lockfiles(Path(d), pc.Header(tier="T2", types=["service"]))
            self.assertEqual(sorted((p.file, p.line) for p in problems),
                             [("requirements.txt", 2), ("svc/pyproject.toml", None)])
        with tempfile.TemporaryDirectory() as d:  # unparsable JSON doesn't crash, and still needs a lockfile
            write(Path(d), "web/package.json", "{ // jsonc\n}")
            self.assertEqual([p.file for p in pc.check_lockfiles(Path(d), pc.Header(tier="T2"))], ["web/package.json"])

    def test_csp_threat_model_line_comments_and_default_src(self):
        def check(files):
            with tempfile.TemporaryDirectory() as d:
                for rel, text in files.items():
                    write(Path(d), rel, text)
                return [p.rule for p in pc.check_csp(Path(d), pc.Header(tier="T2", types=["web"]))]
        self.assertEqual(check({"docs/threat-model.md": "- CSP: set by the Cloudflare _headers of the host\n"}), [])
        self.assertEqual(check({"a.js": "const h = 'Content-Security-Policy';\n// never use script-src 'unsafe-inline'\n"}), [])
        self.assertEqual(check({"a.js": "csp = ['Content-Security-Policy',\n \"default-src 'self' 'unsafe-inline'\",\n \"script-src 'self'\"]\n"}), [])
        self.assertEqual(check({"s.js": "helmet({ contentSecurityPolicy: { directives: { scriptSrc: [\"'self'\", \"'unsafe-eval'\"] } } })\n"}), ["WEB-7"])
        self.assertEqual(check({"a.js": "// mentions script-src only\n"}), ["WEB-8"])

    def test_inline_copies_follow_semgrepignore_and_data_attributes(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            write(Path(d), ".semgrepignore", "docs/\n")
            write(Path(d), "docs/x.html", "<script>el.innerHTML = a;</script>")
            write(Path(d), "app/y.html", "<script data-src=\"z\" data-type=\"q\">el.innerHTML = b;</script>")
            self.assertEqual(list(pc.extract_inline(Path(d), Path(out)).values()), ["app/y.html"])
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            write(Path(d), "tests/t.html", "<script>el.innerHTML = a;</script>")  # Semgrep's defaults skip tests/
            self.assertEqual(pc.extract_inline(Path(d), Path(out)), {})

    def test_new_severity_scale_and_missing_report(self):
        with tempfile.TemporaryDirectory() as d:
            r = Path(d) / "r.json"
            r.write_text(json.dumps({"results": [
                {"check_id": "a.b.rule", "path": "x.py", "start": {"line": 1},
                 "extra": {"message": "m", "severity": "HIGH", "metadata": {"confidence": "MEDIUM"}}},
                {"check_id": "a.b.rule2", "path": "x.py", "start": {"line": 2},
                 "extra": {"message": "m", "severity": "MEDIUM", "metadata": {"confidence": "HIGH"}}}]}))
            problems = pc.sast_gate([r, Path(d) / "missing.json"])
            self.assertEqual([p.level for p in problems], ["error", "warning", "error"])
            self.assertIn("missing", problems[2].message)

    def test_release_test_to_ci_is_not_loosening(self):
        old = json.loads(EXAMPLE_BUDGETS)
        new = json.loads(EXAMPLE_BUDGETS)
        new["native"]["android"]["measuredWhere"] = "ci"
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", "-b", "main", d], check=True)
            write(Path(d), "budgets.json", json.dumps(old))
            self.git(d, "add", "."); self.git(d, "commit", "-qm", "b")
            write(Path(d), "budgets.json", json.dumps(new))
            self.assertEqual(pc.check_budget_loosening(Path(d), "HEAD", {}), [])


class ReReviewTests(unittest.TestCase):
    def test_hash_pinned_requirements_are_pinned(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "requirements.txt", "annotated-types==0.8.0 \\\n    --hash=sha256:" + "a" * 64 + " \\\n"
                  "    --hash=sha256:" + "b" * 64 + "\n    # via pydantic\nfoo==1.0 --hash=sha256:" + "c" * 64 + "\nbar>=2\n")
            problems = pc.check_lockfiles(Path(d), pc.Header(tier="T2"))
            self.assertEqual([p.line for p in problems], [6])
        own = pc.POLICY_ROOT / "tools" / "requirements-sast.txt"
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "requirements.txt", own.read_text())
            self.assertEqual(pc.check_lockfiles(Path(d), pc.Header(tier="T2")), [])

    def test_csp_other_directives_on_the_same_line(self):
        def rules(text):
            with tempfile.TemporaryDirectory() as d:
                write(Path(d), "a.js", "// Content-Security-Policy\n" + text)
                return [p.rule for p in pc.check_csp(Path(d), pc.Header(tier="T2", types=["web"]))]
        self.assertEqual(rules('const csp = ["script-src \'self\'", "style-src \'unsafe-inline\'"].join("; ");\n'), [])
        self.assertEqual(rules('helmet({contentSecurityPolicy: {directives: {scriptSrc: ["\'self\'"], styleSrc: ["\'unsafe-inline\'"]}}});\n'), [])
        self.assertEqual(rules('"script-src \'self\' \'unsafe-inline\'; style-src \'self\'"\n'), ["WEB-7"])
        self.assertEqual(rules('{scriptSrc: ["\'self\'", "\'unsafe-eval\'"], styleSrc: ["\'self\'"]}\n'), ["WEB-7"])

    def test_marker_forms(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "a.js", "\n".join([
                "x(); // nosemgrep -- no exception handling needed, see https://example.com",
                "x(); // nosemgrep -- exception: https://github.com/o/r/issues/4",
                'const help = "add a nosemgrep comment";',
            ]))
            write(Path(d), "notes.md", f"token = abc {pc.ALLOW_MARKER}\n")
            self.assertEqual(sorted((p.file, p.line) for p in pc.check_markers(Path(d))), [("a.js", 1), ("a.js", 2), ("notes.md", 1)])
            ex = pc.Exception_("EX-4", "WEB-9", [], datetime.date.today(), datetime.date.today(), "https://github.com/o/r/issues/4")
            self.assertEqual(sorted((p.file, p.line) for p in pc.check_markers(Path(d), [ex])),
                             [("a.js", 1), ("notes.md", 1)])

    def test_unresolvable_base_fails(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", "-b", "main", d], check=True)
            write(Path(d), ".gitleaks.toml", "[extend]\nuseDefault = true\n")
            write(Path(d), "README.md", "Tier: T2\nPolicy: v2.0\nType: native\nBaseline: until 2099-01-01\n")
            self.assertIn("not available", pc.check_gitleaks_config(Path(d), "origin/nope", {})[0].message)
            self.assertIn("not available", pc.check_baseline_change(Path(d), "origin/nope", pc.read_header(Path(d)))[0].message)


class ExceptionTests(unittest.TestCase):
    TODAY = datetime.date.today()

    def entry(self, **kw):
        d = lambda n: (self.TODAY + datetime.timedelta(days=n)).isoformat()
        e = {"id": "EX-1", "rule": "WEB-8", "finding": "No CSP yet", "reason": "70 inline handlers to move first",
             "compensatingControl": "WEB-9 sinks reviewed by hand", "acceptedBy": "@owner", "written": d(-3),
             "accepted": d(-2), "expires": d(60), "renewals": 0, "link": "https://github.com/o/r/issues/1"}
        e.update(kw)
        return e

    def load(self, entries, raw=None, commit=True):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "policy-exceptions.json", raw if raw is not None else json.dumps({"schemaVersion": 1, "exceptions": entries}))
            if commit:
                commit_backdated(Path(d))
            return pc.load_exceptions(Path(d))

    def test_valid_exception_turns_error_into_warning(self):
        active, problems = self.load([self.entry()])
        self.assertEqual((len(active), problems), (1, []))
        p = [pc.Problem("WEB-8", "no CSP"), pc.Problem("WEB-9", "sink", "a.js", 3)]
        pc.apply_exceptions(p, active)
        self.assertEqual([x.level for x in p], ["warning", "error"])
        self.assertIn("excepted by EX-1 until", p[0].message)

    def test_files_scope(self):
        active, _ = self.load([self.entry(id="EX-2", rule="WEB-9", files=["admin.html", "src/*.js"])])
        p = [pc.Problem("WEB-9", "s", "admin.html", 1), pc.Problem("WEB-9", "s", "src/a.js", 2),
             pc.Problem("WEB-9", "s", "index.html", 3), pc.Problem("WEB-9", "s")]
        pc.apply_exceptions(p, active)
        self.assertEqual([x.level for x in p], ["warning", "warning", "error", "error"])

    def test_combined_rule_labels(self):
        active, _ = self.load([self.entry(rule="NAT-7")])
        p = [pc.Problem("WEB-15/NAT-7/OTH-5", "budgets.json is missing")]
        self.assertEqual(pc.apply_exceptions(p, active)[0].level, "warning")

    def test_invalid_entries(self):
        cases = {
            "lacks": self.entry(reason=""),
            "more than 90 days": self.entry(expires=(self.TODAY + datetime.timedelta(days=120)).isoformat()),
            "is not a rule ID": self.entry(rule="secrets"),
            "without \"files\"": self.entry(rule="Gov §5"),
            "whole number": self.entry(renewals="none"),
            "not YYYY-MM-DD": self.entry(expires="soon"),
        }
        for text, e in cases.items():
            active, problems = self.load([e])
            self.assertEqual(active, [], text)
            self.assertIn(text, problems[0].message, text)
            self.assertFalse(problems[0].exceptable)

    def test_expired_exception_stops_applying(self):
        past = lambda n: (self.TODAY - datetime.timedelta(days=n)).isoformat()
        active, problems = self.load([self.entry(written=past(80), accepted=past(70), expires=past(1))])
        self.assertEqual(active, [])
        self.assertIn("expired on", problems[0].message)

    def test_bad_file(self):
        self.assertIn("not valid JSON", self.load(None, raw="{")[1][0].message)
        self.assertIn("schemaVersion", self.load(None, raw='{"exceptions": []}')[1][0].message)

    def test_policy_controls_and_critical_are_not_exceptable(self):
        active, _ = self.load([self.entry(id="EX-3", rule="Gov §5 (GHSA-1)", files=["package-lock.json"])])
        crit = pc.Problem("Gov §5 (GHSA-1)", "critical vuln", "package-lock.json", exceptable=False)
        high = pc.Problem("Gov §5 (GHSA-1)", "high vuln", "package-lock.json")
        marker = pc.Problem("Gov §5", "bare nosemgrep", "a.js", 1, exceptable=False)
        pc.apply_exceptions([crit, high, marker], active)
        self.assertEqual([crit.level, high.level, marker.level], ["error", "warning", "error"])

    def test_conformance_reads_the_file(self):
        os.environ["POLICY_SKIP_BROWSERSLIST"] = "1"
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            compliant_project(root, types="web")
            (root / "index.html").unlink()  # no CSP: WEB-8
            self.assertEqual([p.rule for p in pc.conformance(root, None, {}) if p.level == "error"], ["WEB-8"])
            write(root, "policy-exceptions.json", json.dumps({"schemaVersion": 1, "exceptions": [self.entry()]}))
            commit_backdated(root)
            self.assertEqual([p.rule for p in pc.conformance(root, None, {}) if p.level == "error"], [])

    def test_vuln_gate_critical_is_not_exceptable(self):
        report = {"results": [{"source": {"path": "/x/package-lock.json"}, "packages": [
            {"package": {"name": "a", "version": "1"}, "groups": [{"ids": ["G-1"], "max_severity": "9.8"}]},
            {"package": {"name": "b", "version": "1"}, "groups": [{"ids": ["G-2"], "max_severity": "7.5"}]}]}]}
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "osv.json"
            path.write_text(json.dumps(report))
            blocking, _ = pc.vuln_gate(path, "T2")
        self.assertEqual([b.exceptable for b in blocking], [False, True])

    def test_the_template_example_is_valid(self):
        import shutil
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(pc.POLICY_ROOT / "templates" / "policy-exceptions.example.json", Path(d) / "policy-exceptions.json")
            commit_backdated(Path(d))
            active, problems = pc.load_exceptions(Path(d), today=datetime.date(2026, 10, 10))
            self.assertEqual(([e.id for e in active], problems), (["EX-1", "EX-2"], []))


class ExceptionReviewTests(unittest.TestCase):
    """The PR #3 review: scope, renewal, the 24-hour wait and line-level links."""
    entry = ExceptionTests.entry
    TODAY = ExceptionTests.TODAY

    def test_globs_stay_in_their_segment_and_broad_ones_are_refused(self):
        self.assertTrue(pc.glob_regex("src/*").match("src/a.js"))
        self.assertFalse(pc.glob_regex("src/*").match("src/a/b.js"))
        self.assertTrue(pc.glob_regex("src/**").match("src/a/b.js"))
        self.assertTrue(pc.glob_regex("src/**/*.html").match("src/index.html"))
        self.assertTrue(pc.glob_regex(".github/workflows/x.yml").match(".github/workflows/x.yml"))
        for g in ("*", "**", "**/*", "*.*", "./*", "**/*.js", "*/*/*/*", "[a-z]*/x"):
            self.assertTrue(pc.too_broad(g), g)
        for g in ("admin.html", "src/*.js", "src/**/*.html", "android/app2/build.gradle.kts", "./docs/x.md", ".github/workflows/x.yml"):
            self.assertFalse(pc.too_broad(g), g)

    def test_governance_rules_match_exactly(self):
        self.assertTrue(pc.rule_matches("Gov §5 (GHSA-1)", "Gov §5 (GHSA-1)"))
        self.assertFalse(pc.rule_matches("Gov §5 (GHSA-1)", "Gov §5"))
        self.assertFalse(pc.rule_matches("Gov §5 (eval)", "Gov §5"))
        self.assertTrue(pc.rule_matches("WEB-15/NAT-7/OTH-5", "NAT-7"))

    def test_broad_entry_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "policy-exceptions.json", json.dumps({"schemaVersion": 1, "exceptions": [
                self.entry(rule="Gov §5 (GHSA-1)", files=["*"])]}))
            commit_backdated(Path(d))
            active, problems = pc.load_exceptions(Path(d))
        self.assertEqual(active, [])
        self.assertIn("would match any file", problems[0].message)

    def test_same_day_acceptance_is_a_warning_not_a_refusal(self):
        today = self.TODAY.isoformat()
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "policy-exceptions.json", json.dumps({"schemaVersion": 1, "exceptions": [
                self.entry(written=today, accepted=today)]}))
            active, problems = pc.load_exceptions(Path(d))
        self.assertEqual(len(active), 1)  # Section 11's wait is for solo developers; CI can't tell, so it only warns
        self.assertEqual([(p.rule, p.level) for p in problems], [("Gov §11", "warning")])

    def test_dot_paths_are_kept(self):
        ex = pc.Exception_("EX-1", "DEP-7", [".github/workflows/arm64.yml"], self.TODAY, self.TODAY, "https://x")
        p = [pc.Problem("DEP-7", "unpinned", ".github/workflows/arm64.yml", 109)]
        self.assertEqual(pc.apply_exceptions(p, [ex])[0].level, "warning")

    def test_budget_rules_per_section_and_loosening_not_exceptable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            data = json.loads(EXAMPLE_BUDGETS)
            del data["native"]["linux"]["runs"]
            write(root, "budgets.json", json.dumps(data))
            problems = pc.check_budgets(root, pc.Header(tier="T2", types=["web", "native"]))
            self.assertEqual({p.rule for p in problems}, {"NAT-7"})

    def test_pr_changes_must_be_named_counted_and_not_re_added(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root, "policy-exceptions.json", json.dumps({"schemaVersion": 1, "exceptions": [self.entry()]}))
            commit_backdated(root, days=10)
            base = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            later = (self.TODAY + datetime.timedelta(days=80)).isoformat()
            # renewal without counting it
            write(root, "policy-exceptions.json", json.dumps({"schemaVersion": 1, "exceptions": [self.entry(expires=later)]}))
            msgs = " ".join(p.message for p in pc.check_exception_changes(root, base, {}))
            self.assertIn("renewals count", msgs)
            self.assertIn("Exception change: EX-1", msgs)
            ok = pc.check_exception_changes(root, base, {"pull_request": {"body": "Exception change: EX-1 (re-decided)"}})
            self.assertIn("renewals count", ok[0].message)
            write(root, "policy-exceptions.json", json.dumps({"schemaVersion": 1, "exceptions": [self.entry(expires=later, renewals=1)]}))
            self.assertEqual(pc.check_exception_changes(root, base, {"pull_request": {"body": "Exception change: EX-1"}}), [])
            # the same rule under a new id, with the same files or a wider glob
            write(root, "policy-exceptions.json", json.dumps({"schemaVersion": 1, "exceptions": [self.entry(id="EX-9")]}))
            msgs = " ".join(p.message for p in pc.check_exception_changes(root, base, {"pull_request": {"body": "Exception change: EX-9"}}))
            self.assertIn("replaces EX-1", msgs)
            write(root, "policy-exceptions.json", json.dumps({"schemaVersion": 1, "exceptions": [self.entry(id="EX-8", files=["src/*.js"])]}))
            msgs = " ".join(p.message for p in pc.check_exception_changes(root, base, {"pull_request": {"body": "Exception change: EX-8"}}))
            self.assertIn("replaces EX-1", msgs)

    def test_allow_marker_never_rests_on_an_exception(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "k.py", f"KEY = 'AKIA...'  # {pc.ALLOW_MARKER} exception: https://github.com/o/r/issues/1\n")
            ex = pc.Exception_("EX-1", "WEB-9", [], datetime.date.today(), datetime.date.today(), "https://github.com/o/r/issues/1")
            problems = pc.check_markers(Path(d), [ex])
            self.assertIn("rotated", problems[0].message)

    def test_missing_files_can_be_excepted_by_path(self):
        p = [pc.Problem("Gov §4", "docs/threat-model.md is missing", "docs/threat-model.md")]
        ex = pc.Exception_("EX-1", "Gov §4", ["docs/threat-model.md"], self.TODAY, self.TODAY, "https://x")
        self.assertEqual(pc.apply_exceptions(p, [ex])[0].level, "warning")

    def test_malformed_file_does_not_crash(self):
        for raw in ("[]", '{"schemaVersion": 1, "exceptions": [1, "x"]}'):
            with tempfile.TemporaryDirectory() as d:
                write(Path(d), "policy-exceptions.json", raw)
                active, problems = pc.load_exceptions(Path(d))
                self.assertEqual(active, [])
                self.assertTrue(problems)


class CommandWiringTests(unittest.TestCase):
    """Each command that reads policy-exceptions.json applies it (a revert of the wiring fails these)."""

    def project_with_exception(self, d, rule, files):
        e = ExceptionTests.entry(ExceptionTests, rule=rule, files=files)
        write(Path(d), "README.md", "Tier: T2\nPolicy: v2.1\nType: web\n")
        write(Path(d), "policy-exceptions.json", json.dumps({"schemaVersion": 1, "exceptions": [e]}))
        commit_backdated(Path(d))

    def run_cmd(self, d, *args):
        env = {**os.environ, "POLICY_SKIP_BROWSERSLIST": "1"}
        env.pop("GITHUB_ACTIONS", None)
        env.pop("GITHUB_STEP_SUMMARY", None)
        return subprocess.run([sys.executable, str(pc.POLICY_ROOT / "tools" / "policy_check.py"), *args],
                              cwd=d, capture_output=True, text=True, env=env)

    def test_sast(self):
        with tempfile.TemporaryDirectory() as d:
            self.project_with_exception(d, "WEB-9", ["app.js"])
            Path(d, "r.json").write_text(json.dumps({"results": [{"check_id": "x.web-9", "path": "app.js", "start": {"line": 1},
                "extra": {"message": "m", "severity": "ERROR", "metadata": {"policy-rule": "WEB-9"}}}]}))
            r = self.run_cmd(d, "sast", "--report", "r.json")
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn("excepted by EX-1", r.stdout)

    def test_licenses(self):
        with tempfile.TemporaryDirectory() as d:
            self.project_with_exception(d, "Gov §5 (license left-pad)", ["package-lock.json"])
            Path(d, "l.json").write_text(json.dumps({"results": [{"source": {"path": str(Path(d) / "package-lock.json")},
                "packages": [{"package": {"name": "left-pad", "version": "1"}, "license_violations": ["WTFPL"]}]}]}))
            r = self.run_cmd(d, "licenses", "--report", "l.json")
            self.assertEqual(r.returncode, 0, r.stdout)

    def test_vulns(self):
        with tempfile.TemporaryDirectory() as d:
            self.project_with_exception(d, "Gov §5 (GHSA-2)", ["package-lock.json"])
            Path(d, "v.json").write_text(json.dumps({"results": [{"source": {"path": str(Path(d) / "package-lock.json")},
                "packages": [{"package": {"name": "a", "version": "1"}, "groups": [{"ids": ["GHSA-2"], "max_severity": "7.5"}]},
                             {"package": {"name": "b", "version": "1"}, "groups": [{"ids": ["GHSA-3"], "max_severity": "9.8"}]}]}]}))
            r = self.run_cmd(d, "vulns", "--root", ".", "--report", "v.json")
            self.assertEqual(r.returncode, 1, r.stdout)  # GHSA-3 is Critical: no exception covers it
            self.assertIn("excepted by EX-1", r.stdout)
            self.assertIn("1 blocking", r.stdout)
