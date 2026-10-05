"""Tests for tools/policy_check.py. Run: python3 -m unittest discover -s tools/tests"""

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
            self.assertEqual(rules(pc.conformance(root, None, {})), ["Gov §1", "Gov §4", "Gov §5", "NAT-3", "NAT-7"])

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
            self.assertIn("native.linux.startupMs: removed", msg)
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
