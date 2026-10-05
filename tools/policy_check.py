#!/usr/bin/env python3
"""Check a project against the parts of the policy that a file or a diff can prove.

Usage:
    policy_check.py conformance [--root DIR] [--base REF] [--event FILE]
    policy_check.py tier [--root DIR]
    policy_check.py header [--root DIR]
    policy_check.py vulns --report FILE [--root DIR]
    policy_check.py licenses --report FILE
    policy_check.py pins [--root DIR]

`conformance` prints one line per problem, as GitHub annotations when run in
Actions, and exits 1 if any rule fails. `tier` prints the declared tier
(T0-T3). `header` prints the parsed README header as JSON. `vulns` applies the
Section 5 gate to an osv-scanner JSON report: warnings on T1, failure on High
or Critical (CVSS 7.0 and up) on T2, failure on any severity on T3. `licenses` fails on license violations in an
osv-scanner report made with --licenses. `pins` runs only the DEP-7 check.

Each problem names the rule it comes from, so a finding can cite it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

POLICY_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = POLICY_ROOT / "templates" / "budgets.schema.json"

TYPES = {"web", "native", "service", "firmware", "webview", "engine-bundling"}
WEB_UI_TYPES = {"web", "webview", "engine-bundling"}

SHA_RE = re.compile(r"@[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


@dataclass
class Header:
    tier: str | None = None
    policy: str | None = None
    types: list[str] = field(default_factory=list)
    users: str | None = None

    @property
    def tier_num(self) -> int:
        return int(self.tier[1]) if self.tier else -1

    @property
    def lighter_t2(self) -> bool:
        """Section 11: a solo T2 project with no external users yet."""
        return self.tier == "T2" and (self.users or "").lower() == "none"


@dataclass
class Problem:
    rule: str
    message: str
    file: str | None = None
    line: int | None = None


def read_header(root: Path) -> Header:
    """Parse the `Tier:`, `Policy:`, `Type:` and `Users:` lines from the README."""
    header = Header()
    readme = root / "README.md"
    if not readme.is_file():
        return header
    in_fence = False
    for raw in readme.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if re.match(r"^#{2,}\s", raw):
            break  # the header lines belong at the top, before the first section
        line = raw.strip().strip("*_").strip()
        m = re.match(r"(?i)^(tier|policy|type|users)\s*:\s*\**\s*(.+?)\s*\**$", line)
        if not m:
            continue
        key = m.group(1).lower()
        value = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", m.group(2)).strip("`* ")
        if key == "tier" and header.tier is None:
            t = re.match(r"(?i)^T([0-3])\b", value)
            header.tier = f"T{t.group(1)}" if t else value
        elif key == "policy" and header.policy is None:
            header.policy = value
        elif key == "type" and not header.types:
            header.types = [v.strip().lower() for v in value.split(",") if v.strip()]
        elif key == "users" and header.users is None:
            header.users = value
    return header


def check_header(root: Path, h: Header) -> list[Problem]:
    problems = []
    if not (root / "README.md").is_file():
        return [Problem("Gov §1", "README.md is missing; it must state the tier and policy version")]
    if h.tier is None:
        problems.append(Problem("Gov §1", "README has no `Tier: T0|T1|T2|T3` line", "README.md"))
    elif not re.fullmatch(r"T[0-3]", h.tier):
        problems.append(Problem("Gov §1", f"README tier `{h.tier}` is not one of T0, T1, T2, T3", "README.md"))
    if h.tier != "T0":
        if h.policy is None:
            problems.append(Problem("Gov §1", "README has no `Policy: vX.Y` line naming the policy version", "README.md"))
        elif not re.fullmatch(r"v\d+\.\d+", h.policy):
            problems.append(Problem("Gov §1", f"README policy version `{h.policy}` is not in the form vX.Y", "README.md"))
        if not h.types:
            problems.append(Problem("README index", "README has no `Type:` line (web, native, service, firmware, webview, engine-bundling)", "README.md"))
        for t in h.types:
            if t not in TYPES:
                problems.append(Problem("README index", f"README type `{t}` is not one of {', '.join(sorted(TYPES))}", "README.md"))
    return problems


def check_files(root: Path, h: Header) -> list[Problem]:
    problems = []
    n = h.tier_num
    if n >= 1 and not any((root / d / "SECURITY.md").is_file() for d in (".", ".github", "docs")):
        problems.append(Problem("Gov §1", "SECURITY.md is missing (how to report a vulnerability)"))
    if n >= 2 and not h.lighter_t2 and not (root / "docs" / "threat-model.md").is_file():
        problems.append(Problem("Gov §4", "docs/threat-model.md is missing (required from T2)"))
    if n >= 1:
        matrix = root / "docs" / "capability-matrix.md"
        rule = "/".join(r for t, r in (("web", "WEB-1"), ("native", "NAT-3")) if t in h.types) or "OTH-2"
        if not matrix.is_file():
            problems.append(Problem(rule, "docs/capability-matrix.md is missing"))
        elif not re.search(r"(?im)^\s*Checked:\s*\S", matrix.read_text(encoding="utf-8", errors="replace")):
            problems.append(Problem(rule, "the capability matrix has no `Checked:` date", "docs/capability-matrix.md"))
    if n >= 2 and not h.lighter_t2 and not (root / "license-allowlist.txt").is_file():
        problems.append(Problem("Gov §5", "license-allowlist.txt is missing (the written license policy: one allowed SPDX id per line)"))
    return problems


def check_budgets(root: Path, h: Header) -> list[Problem]:
    path = root / "budgets.json"
    if h.tier_num < 2 or h.lighter_t2:
        if not path.is_file():
            return []
    elif not path.is_file():
        return [Problem(budget_rule(h), "budgets.json is missing (required from T2)")]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [Problem(budget_rule(h), f"budgets.json is not valid JSON: {e.msg}", "budgets.json", e.lineno)]
    try:
        import jsonschema
    except ImportError:
        return [Problem(budget_rule(h), "cannot validate budgets.json: the jsonschema package is not installed", "budgets.json")]
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    return [
        Problem(budget_rule(h), f"budgets.json: {'/'.join(map(str, err.absolute_path)) or '(root)'}: {err.message}", "budgets.json")
        for err in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    ]


def budget_rule(h: Header) -> str:
    rules = [r for t, r in (("web", "WEB-15"), ("native", "NAT-7")) if t in h.types]
    if set(h.types) - {"web", "native"}:
        rules.append("OTH-5")
    return "/".join(rules) or "OTH-5"


def thresholds(data: dict) -> dict[str, tuple[str, float]]:
    """Flatten budgets.json into {path: (direction, value)}; direction is 'max' or 'min'.

    A custom metric measured in CI is keyed separately from one measured in a release test, so moving a metric out
    of CI shows up as a removed CI threshold."""
    out: dict[str, tuple[str, float]] = {}
    web = data.get("web", {})
    for b in web.get("bundles", []):
        out[f"web.bundles[{b.get('name')}].maxKB"] = ("max", b.get("maxKB"))
    for section in ("lab", "field"):
        for k, v in web.get(section, {}).items():
            if k.endswith(("Ms", "KB")) or k == "cls":
                out[f"web.{section}.{k}"] = ("max", v)
    for platform, m in data.get("native", {}).items():
        for k in ("startupMs", "memoryMB", "installedSizeMB"):
            if k in m:
                out[f"native.{platform}.{k}"] = ("max", m[k])
    for c in data.get("custom", []):
        where = c.get("measuredWhere", "ci")
        for d in ("max", "min"):
            if d in c:
                out[f"custom[{c.get('name')}]@{where}.{d}"] = (d, c[d])
    return out


def check_budget_loosening(root: Path, base: str | None, event: dict) -> list[Problem]:
    """D5: a PR that loosens a threshold states the reason (a `Budget change:` line in the PR body)."""
    if not base or not (root / "budgets.json").is_file():
        return []
    try:
        old_text = subprocess.run(
            ["git", "-C", str(root), "show", f"{base}:./budgets.json"],
            check=True, capture_output=True, text=True,
        ).stdout
        old, new = json.loads(old_text), json.loads((root / "budgets.json").read_text(encoding="utf-8"))
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return []
    loosened = []
    new_t = thresholds(new)
    for key, (direction, old_v) in thresholds(old).items():
        if key not in new_t:
            loosened.append(f"{key}: removed")
            continue
        if not isinstance(old_v, (int, float)):
            continue
        new_v = new_t[key][1]
        if not isinstance(new_v, (int, float)):
            continue
        if (direction == "max" and new_v > old_v) or (direction == "min" and new_v < old_v):
            loosened.append(f"{key}: {old_v} -> {new_v}")
    body = ((event.get("pull_request") or {}).get("body") or "")
    if loosened and not re.search(r"(?im)^\s*Budget change:\s*\S", body):
        return [Problem("Budgets", "this PR loosens " + "; ".join(loosened)
                        + ". Add a `Budget change: <reason>` line to the PR description", "budgets.json")]
    return []


def iter_files(root: Path, patterns: list[str]):
    seen = set()
    for pattern in patterns:
        for p in sorted(root.glob(pattern)):
            if p in seen:
                continue
            seen.add(p)
            if p.is_file() and ".git" not in p.parts and "node_modules" not in p.parts:
                yield p


def check_pins(root: Path) -> list[Problem]:
    """DEP-7: third-party actions pinned by commit SHA, container images by digest."""
    problems = []
    for wf in iter_files(root, [".github/workflows/*.yml", ".github/workflows/*.yaml",
                                "**/action.yml", "**/action.yaml"]):
        rel = str(wf.relative_to(root))
        for i, raw in enumerate(wf.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            line = raw.split(" #")[0].strip()
            m = re.match(r"^-?\s*uses:\s*['\"]?([^'\"\s]+)", line)
            if m:
                ref = m.group(1)
                if ref.startswith("./"):
                    continue
                if ref.startswith("docker://"):
                    if not DIGEST_RE.search(ref):
                        problems.append(Problem("DEP-7", f"`{ref}` is not pinned by @sha256: digest", rel, i))
                elif not SHA_RE.search(ref):
                    problems.append(Problem("DEP-7", f"`{ref}` is not pinned to a full commit SHA", rel, i))
                continue
            m = re.match(r"^-?\s*(?:image|container):\s*['\"]?([^'\"\s{}]+)['\"]?$", line)
            if m and not DIGEST_RE.search(m.group(1)):
                problems.append(Problem("DEP-7", f"container image `{m.group(1)}` is not pinned by @sha256: digest", rel, i))
    for df in iter_files(root, ["**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile", "**/Containerfile", "**/Containerfile.*"]):
        rel = str(df.relative_to(root))
        stages: set[str] = set()
        args: dict[str, str] = {}
        for i, raw in enumerate(df.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            a = re.match(r"(?i)^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", raw)
            if a:
                args[a.group(1)] = a.group(2).strip("'\"")
                continue
            m = re.match(r"(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", raw)
            if not m:
                continue
            image = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", lambda v: args.get(v.group(1), v.group(0)), m.group(1))
            stage = m.group(2)
            if image.lower() == "scratch" or image.lower() in stages or DIGEST_RE.search(image):
                pass
            elif "$" in image:
                problems.append(Problem("DEP-7", f"base image `{image}` comes from a build argument with no default; "
                                                 "give the ARG a digest-pinned default", rel, i))
            else:
                problems.append(Problem("DEP-7", f"base image `{image}` is not pinned by @sha256: digest", rel, i))
            if stage:
                stages.add(stage.lower())
    manifests = []
    for f in iter_files(root, ["**/*.yml", "**/*.yaml"]):
        if f.parts[len(root.parts):][:2] == (".github", "workflows") or f.name in ("action.yml", "action.yaml"):
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        is_compose = re.match(r"(docker-)?compose", f.name) is not None
        is_k8s = re.search(r"(?m)^apiVersion:", text) and re.search(r"(?m)^kind:", text)
        if is_compose or is_k8s:
            manifests.append((f, text))
    for cf, text in manifests:
        rel = str(cf.relative_to(root))
        for i, raw in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*-?\s*image:\s*['\"]?([^'\"\s]+)", raw)
            if m and "$" not in m.group(1) and "{{" not in m.group(1) and not DIGEST_RE.search(m.group(1)):
                problems.append(Problem("DEP-7", f"deployment image `{m.group(1)}` is not pinned by @sha256: digest", rel, i))
    return problems


def check_browserslist(root: Path, h: Header) -> list[Problem]:
    """WEB-1: the browser list browserslist resolves to is recorded in the capability matrix."""
    if "web" not in h.types or h.tier_num < 1:
        return []
    pkg = root / "package.json"
    has_config = (root / ".browserslistrc").is_file() or (
        pkg.is_file() and "browserslist" in json.loads(pkg.read_text(encoding="utf-8") or "{}"))
    if not has_config:
        return [Problem("WEB-2", "no browserslist declaration (.browserslistrc or the `browserslist` key in package.json)")]
    version = os.environ.get("BROWSERSLIST_VERSION", "4.29.3")
    try:
        out = subprocess.run(["npx", "--yes", f"browserslist@{version}"], cwd=root,
                             check=True, capture_output=True, text=True, timeout=300).stdout
    except (OSError, subprocess.SubprocessError) as e:
        return [Problem("WEB-1", f"could not resolve the browser list with npx browserslist: {e}")]
    resolved = {l.strip() for l in out.splitlines() if l.strip()}
    recorded = recorded_browsers(root / "docs" / "capability-matrix.md")
    if recorded is None:
        return [Problem("WEB-1", "the capability matrix has no resolved browser list (a fenced block after the "
                                  "`Resolved browser list` line)", "docs/capability-matrix.md")]
    added, dropped = sorted(resolved - recorded), sorted(recorded - resolved)
    if added or dropped:
        def show(xs):
            return ", ".join(xs[:8]) + (f" and {len(xs) - 8} more" if len(xs) > 8 else "")
        parts = ([f"now includes {show(added)}"] if added else []) + ([f"no longer includes {show(dropped)}"] if dropped else [])
        return [Problem("WEB-1", "the resolved browser list differs from the one in the capability matrix: it "
                                  + "; it ".join(parts) + ". Re-check the matrix and record the new list",
                        "docs/capability-matrix.md")]
    return []


def recorded_browsers(matrix: Path) -> set[str] | None:
    """The fenced block that follows the `Resolved browser list` line in the capability matrix."""
    if not matrix.is_file():
        return None
    lines = matrix.read_text(encoding="utf-8", errors="replace").splitlines()
    for i, line in enumerate(lines):
        if re.match(r"(?i)^\s*\**resolved browser list", line):
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith(("```", "~~~")):
                if lines[j].strip() and not lines[j].lstrip().startswith(("<", "(")):
                    return None
                j += 1
            block = []
            for line2 in lines[j + 1:]:
                if line2.strip().startswith(("```", "~~~")):
                    return {b.strip() for b in block if b.strip()}
                block.append(line2)
            return None
    return None


def conformance(root: Path, base: str | None, event: dict) -> list[Problem]:
    h = read_header(root)
    problems = check_header(root, h)
    if h.tier is None or h.tier == "T0" or not re.fullmatch(r"T[0-3]", h.tier):
        return problems
    problems += check_files(root, h)
    problems += check_budgets(root, h)
    problems += check_budget_loosening(root, base, event)
    problems += check_pins(root)
    if os.environ.get("POLICY_SKIP_BROWSERSLIST") != "1":
        problems += check_browserslist(root, h)
    return problems


def vuln_gate(report_path: Path, tier: str | None) -> tuple[list[Problem], list[Problem]]:
    """Section 5, known-vulnerable dependencies. Returns (blocking, warnings)."""
    data = json.loads(report_path.read_text(encoding="utf-8")) if report_path.is_file() else {}
    blocking, warnings = [], []
    n = int(tier[1]) if tier and re.fullmatch(r"T[0-3]", tier) else 2
    for result in data.get("results", []):
        source = (result.get("source") or {}).get("path", "")
        rel = os.path.relpath(source) if source else None
        for pkg in result.get("packages", []):
            info = pkg.get("package", {})
            for group in pkg.get("groups", []):
                ids = ", ".join(group.get("aliases") or group.get("ids") or [])
                raw = group.get("max_severity") or ""
                try:
                    high = float(raw) >= 7.0
                    shown = f"CVSS {raw}"
                except ValueError:
                    levels = {str((v.get("database_specific") or {}).get("severity", "")).upper()
                              for v in pkg.get("vulnerabilities", []) if v.get("id") in set(group.get("ids", []))}
                    levels.discard("")
                    # No CVSS score: use the advisory database's rating; with no rating at all, assume the worst.
                    high = bool(levels & {"HIGH", "CRITICAL"}) or not levels
                    shown = f"severity {', '.join(sorted(levels)) or 'unknown'}"
                p = Problem("Gov §5", f"known-vulnerable dependency {info.get('name')} {info.get('version')}: {ids} ({shown})", rel)
                # Section 5: High and Critical block from T2; on T3 every known vulnerability blocks.
                if n >= 3 or (n >= 2 and high):
                    blocking.append(p)
                else:
                    warnings.append(p)
    return blocking, warnings


def license_gate(report_path: Path) -> list[Problem]:
    """Section 5, license compliance: every package license outside license-allowlist.txt."""
    data = json.loads(report_path.read_text(encoding="utf-8")) if report_path.is_file() else {}
    problems = []
    for result in data.get("results", []):
        source = (result.get("source") or {}).get("path", "")
        rel = os.path.relpath(source) if source else None
        for pkg in result.get("packages", []):
            bad = pkg.get("license_violations") or []
            if bad:
                info = pkg.get("package", {})
                problems.append(Problem("Gov §5", f"{info.get('name')} {info.get('version')} has license "
                                                   f"{', '.join(bad)}, which license-allowlist.txt does not allow", rel))
    return problems


def report(problems: list[Problem], level: str = "error") -> None:
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    for p in problems:
        if in_actions:
            loc = ",".join(x for x in (f"file={p.file}" if p.file else "", f"line={p.line}" if p.line else "") if x)
            print(f"::{level} {loc}::{p.rule}: {p.message}" if loc else f"::{level} ::{p.rule}: {p.message}")
        else:
            where = f"{p.file}:{p.line}: " if p.file and p.line else f"{p.file}: " if p.file else ""
            print(f"{where}{p.rule}: {p.message}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and level == "error":
        with open(summary, "a", encoding="utf-8") as f:
            f.write("## Policy conformance\n\n")
            if problems:
                f.write("| Rule | Problem | Where |\n| --- | --- | --- |\n")
                for p in problems:
                    where = f"`{p.file}:{p.line}`" if p.file and p.line else f"`{p.file}`" if p.file else ""
                    f.write(f"| {p.rule} | {p.message.replace('|', '/')} | {where} |\n")
            else:
                f.write("All checked rules pass.\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["conformance", "tier", "header", "vulns", "licenses", "pins"])
    ap.add_argument("--report", type=Path, help="osv-scanner JSON report, for `vulns`")
    ap.add_argument("--root", default=".", type=Path)
    ap.add_argument("--base", help="git ref of the PR base, to detect loosened budgets")
    ap.add_argument("--event", type=Path, default=os.environ.get("GITHUB_EVENT_PATH"),
                    help="GitHub event JSON (defaults to $GITHUB_EVENT_PATH)")
    args = ap.parse_args(argv)
    root = args.root.resolve()

    if args.command == "tier":
        print(read_header(root).tier or "")
        return 0
    if args.command == "header":
        h = read_header(root)
        print(json.dumps({"tier": h.tier, "policy": h.policy, "types": h.types,
                          "users": h.users, "lighter_t2": h.lighter_t2}))
        return 0

    if args.command == "pins":
        problems = check_pins(root)
        report(problems)
        return 1 if problems else 0
    if args.command == "licenses":
        problems = license_gate(args.report)
        report(problems)
        return 1 if problems else 0
    if args.command == "vulns":
        h = read_header(root)
        blocking, warnings = vuln_gate(args.report, "T1" if h.lighter_t2 else h.tier)
        report(warnings, level="warning")
        report(blocking)
        print(f"{len(blocking)} blocking, {len(warnings)} warning")
        return 1 if blocking else 0

    event = {}
    if args.event and Path(args.event).is_file():
        event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    problems = conformance(root, args.base, event)
    report(problems)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
