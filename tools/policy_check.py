#!/usr/bin/env python3
"""Check a project against the parts of the policy that a file or a diff can prove.

Usage:
    policy_check.py conformance [--root DIR] [--base REF] [--event FILE]
    policy_check.py tier [--root DIR]
    policy_check.py header [--root DIR]
    policy_check.py vulns --report FILE [--root DIR]
    policy_check.py licenses --report FILE
    policy_check.py pins [--root DIR]
    policy_check.py secrets-config [--root DIR] [--base REF]
    policy_check.py extract-inline --root DIR --out DIR
    policy_check.py sast --report FILE [--report FILE] [--map FILE]

`conformance` prints one line per problem, as GitHub annotations when run in
Actions, and exits 1 if any rule fails. `tier` prints the declared tier
(T0-T3). `header` prints the parsed README header as JSON. `vulns` applies the
Section 5 gate to an osv-scanner JSON report: warnings on T1, failure on High
or Critical (CVSS 7.0 and up) on T2, failure on any severity on T3. `licenses` fails on license violations in an
osv-scanner report made with --licenses. `pins` runs only the DEP-7 check.
`secrets-config` checks a project's .gitleaks.toml. `extract-inline` copies the
inline <script> blocks of HTML files out for Semgrep, and `sast` gates Semgrep
JSON reports.

Each problem names the rule it comes from, so a finding can cite it.
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
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
    baseline: str | None = None

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
    level: str = "error"     # "error" fails the check; "warning" is reported only
    artifact: bool = False   # a missing artifact, which a Baseline period turns into a warning (Section 1)


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
        m = re.match(r"(?i)^(tier|policy|type|users|baseline)\s*:\s*\**\s*(.+?)\s*\**$", line)
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
        elif key == "baseline" and header.baseline is None:
            header.baseline = value
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
        problems.append(Problem("Gov §4", "docs/threat-model.md is missing (required from T2)", artifact=True))
    if n >= 1:
        matrix = root / "docs" / "capability-matrix.md"
        rule = "/".join(r for t, r in (("web", "WEB-1"), ("native", "NAT-3")) if t in h.types) or "OTH-2"
        if not matrix.is_file():
            problems.append(Problem(rule, "docs/capability-matrix.md is missing", artifact=True))
        elif not re.search(r"(?im)^\s*Checked:\s*\S", matrix.read_text(encoding="utf-8", errors="replace")):
            problems.append(Problem(rule, "the capability matrix has no `Checked:` date", "docs/capability-matrix.md"))
    if n >= 2 and not h.lighter_t2 and not (root / "license-allowlist.txt").is_file():
        problems.append(Problem("Gov §5", "license-allowlist.txt is missing (the written license policy: one allowed SPDX id per line)",
                                artifact=True))
    return problems


def check_budgets(root: Path, h: Header) -> list[Problem]:
    path = root / "budgets.json"
    if h.tier_num < 2 or h.lighter_t2:
        if not path.is_file():
            return []
    elif not path.is_file():
        return [Problem(budget_rule(h), "budgets.json is missing (required from T2)", artifact=True)]
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
        where = m.get("measuredWhere", "ci")
        for k in ("startupMs", "memoryMB"):
            if k in m:
                out[f"native.{platform}@{where}.{k}"] = ("max", m[k])
        if "installedSizeMB" in m:
            out[f"native.{platform}.installedSizeMB"] = ("max", m["installedSizeMB"])
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
            if "@release-test." in key and key.replace("@release-test.", "@ci.") in new_t:
                continue  # moving a metric into CI is tightening
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
    # In CI, the conformance action installs the policy's lockfile-pinned browserslist and sets BROWSERSLIST_BIN.
    # Locally, fall back to npx with the same version (not integrity-checked).
    binary = os.environ.get("BROWSERSLIST_BIN")
    cmd = [binary] if binary else ["npx", "--yes", "browserslist@4.29.3"]
    try:
        out = subprocess.run(cmd, cwd=root, check=True, capture_output=True, text=True, timeout=300).stdout
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


def tracked_files(root: Path) -> list[Path]:
    """Files git tracks under root, or every file when root is not a git work tree."""
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--", "."], check=True,
                             capture_output=True, text=True).stdout
        files = [root / f for f in out.split("\0") if f]
        if files:
            return [f for f in files if f.is_file()]
    except (OSError, subprocess.CalledProcessError):
        pass
    return [p for p in root.rglob("*") if p.is_file() and ".git" not in p.relative_to(root).parts]


# (manifest pattern, lockfiles that pin it, ecosystem)
LOCKFILES = [
    ("package.json", ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"), "npm"),
    ("build.gradle", ("gradle.lockfile",), "Gradle"),
    ("build.gradle.kts", ("gradle.lockfile",), "Gradle"),
    ("pyproject.toml", ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.txt"), "Python"),
    ("Pipfile", ("Pipfile.lock",), "Python"),
    ("Cargo.toml", ("Cargo.lock",), "Cargo"),
    ("go.mod", ("go.sum",), "Go"),
    ("Gemfile", ("Gemfile.lock",), "Bundler"),
    ("composer.json", ("composer.lock",), "Composer"),
    ("*.nimble", ("nimble.lock",), "Nimble"),
]


def skipped_path(rel: str) -> bool:
    """Paths that are not the project's own manifests: vendored code, installed packages, test fixtures."""
    parts = rel.split("/")
    return any(p in ("node_modules", "vendor", "fixtures", "test", "tests", "__tests__") for p in parts[:-1])


def declares_dependencies(f: Path, eco: str) -> bool:
    """False for manifests that declare nothing to lock, which would only produce noise."""
    text = f.read_text(encoding="utf-8", errors="replace")
    if eco == "npm":
        try:
            data = json.loads(text or "{}")
        except json.JSONDecodeError:
            return True  # can't tell; let the lockfile question stand
        return bool(data.get("dependencies") or data.get("devDependencies") or data.get("optionalDependencies"))
    if eco == "Python" and f.name == "pyproject.toml":
        return bool(re.search(r"(?m)^\s*(dependencies\s*=|\[project\.optional-dependencies\]|\[dependency-groups\]|"
                              r"\[tool\.poetry\.(dev-)?dependencies\]|\[tool\.poetry\.group\.)", text))
    if eco == "Gradle":
        return re.search(r"(?m)^\s*dependencies\s*\{", text) is not None
    return True


def check_lockfiles(root: Path, h: Header) -> list[Problem]:
    """Section 5: dependencies are pinned by lockfile. A manifest without its lockfile is neither pinned nor scanned."""
    problems = []
    level = "error" if h.tier_num >= 2 and not h.lighter_t2 else "warning"
    files = tracked_files(root)
    names_by_dir: dict[Path, set[str]] = {}
    for f in files:
        names_by_dir.setdefault(f.parent, set()).add(f.name)

    def lock_found(f: Path, locks: tuple[str, ...], eco: str) -> bool:
        # npm, pnpm, Yarn and Cargo workspaces lock at an ancestor; every other ecosystem locks beside the manifest.
        d = f.parent
        while True:
            if any(l in names_by_dir.get(d, set()) for l in locks):
                return True
            if eco not in ("npm", "Cargo") or d == root or root not in d.parents:
                return False
            d = d.parent

    for f in files:
        rel = str(f.relative_to(root))
        if skipped_path(rel):
            continue
        for pattern, locks, eco in LOCKFILES:
            if not fnmatch.fnmatch(f.name, pattern) or lock_found(f, locks, eco) or not declares_dependencies(f, eco):
                continue
            hint = "enable dependency locking (`./gradlew dependencies --write-locks`)" if eco == "Gradle" else \
                   f"commit its lockfile ({', '.join(locks[:2])})"
            problems.append(Problem("Gov §5", f"{eco} manifest without a lockfile: its dependencies are neither pinned "
                                              f"nor scanned; {hint}", rel, level=level))
    for f in files:
        rel = str(f.relative_to(root))
        if not re.fullmatch(r"requirements[\w.-]*\.txt", f.name) or skipped_path(rel):
            continue
        for i, raw in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            line = raw.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            exact = re.search(r"===?\s*[^\s*,;]+(\s*;.*)?$", line) and "*" not in line
            if exact or " @ " in line:
                continue
            problems.append(Problem("Gov §5", f"`{line}` is not pinned to an exact version (`==`); the scanner skips "
                                              "unpinned requirements", rel, i, level=level))
    return problems


def check_pinned_sources(root: Path) -> list[Problem]:
    """DEP-8: pinned-sources.cdx.json lists third-party code that no lockfile can express."""
    path = root / "pinned-sources.cdx.json"
    if not path.is_file():
        return []
    rel = "pinned-sources.cdx.json"
    try:
        bom = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [Problem("DEP-8", f"not valid JSON: {e.msg}", rel, e.lineno)]
    problems = []
    if bom.get("bomFormat") != "CycloneDX":
        problems.append(Problem("DEP-8", 'not a CycloneDX file ("bomFormat": "CycloneDX" is missing)', rel))
    for i, c in enumerate(bom.get("components") or []):
        name = c.get("name") or f"component {i + 1}"
        missing = [k for k in ("name", "version") if not c.get(k)]
        refs = c.get("externalReferences") or []
        if not any(r.get("url") for r in refs):
            missing.append("the URL it is fetched from (externalReferences[].url)")
        hashes = (c.get("hashes") or []) + [h for r in refs for h in (r.get("hashes") or [])]
        strong = [x for x in hashes if str(x.get("alg", "")).upper() in STRONG_HASHES
                  and re.fullmatch(r"[0-9a-fA-F]{64,128}", str(x.get("content", "")))]
        if not strong and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(c.get("version", ""))):
            missing.append("a pinned SHA-256 or stronger hash (hashes) or a full commit as version")
        if not c.get("licenses"):
            missing.append("licenses")
        if missing:
            problems.append(Problem("DEP-8", f"`{name}` lacks {', '.join(missing)}", rel))
    if not bom.get("components"):
        problems.append(Problem("DEP-8", "lists no components", rel))
    return problems


STRONG_HASHES = {"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2B-256", "BLAKE2B-384",
                 "BLAKE2B-512", "BLAKE3"}

CSP_SOURCE_EXT = {".html", ".htm", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".py", ".nim", ".go",
                  ".rs", ".kt", ".java", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".dart", ".rb", ".php",
                  ".json", ".json5", ".toml", ".yaml", ".yml", ".conf", ".cfg", ".ini", ".xml"}
CSP_MARKER = re.compile(r"(?i)content-security-policy|contentSecurityPolicy|[\"']csp[\"']\s*:")
COMMENT_LINE = re.compile(r"^\s*(//|#|\*|/\*|<!--|--|;)")
CSP_SOURCE_NAMES = {"_headers", ".htaccess", "nginx.conf", "Caddyfile", "vercel.json", "netlify.toml"}


def check_csp(root: Path, h: Header) -> list[Problem]:
    """WEB-7 and WEB-8, as far as the repository shows them: a CSP exists, and no script directive allows inline or
    eval. CSPs set outside the repository can't be seen here; the PR review and the release audit check those."""
    if not WEB_UI_TYPES & set(h.types):
        return []
    found = False
    problems = []
    tm = root / "docs" / "threat-model.md"
    if tm.is_file() and re.search(r"(?im)^\s*[-*]?\s*CSP:\s*set by\s+\S", tm.read_text(encoding="utf-8", errors="replace")):
        found = True  # set outside the repository; the review and the audit check it where the threat model says
    for f in tracked_files(root):
        if f.suffix.lower() not in CSP_SOURCE_EXT and f.name not in CSP_SOURCE_NAMES:
            continue
        rel = str(f.relative_to(root))
        if skipped_path(rel):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not CSP_MARKER.search(text):
            continue
        found = True
        has_script_src = re.search(r"(?i)script-src|scriptSrc", text) is not None
        for i, line in enumerate(text.splitlines(), 1):
            if COMMENT_LINE.match(line):
                continue
            for name, rest in re.findall(r"(?i)\b(script-src(?:-elem|-attr)?|scriptSrc(?:Elem|Attr)?|default-src|defaultSrc)\b"
                                         r"([^;]*)", line):
                bad = [k for k in ("'unsafe-inline'", "'unsafe-eval'") if k in rest.lower()]
                if bad and (not name.lower().startswith("default") or not has_script_src):
                    problems.append(Problem("WEB-7", f"a script directive allows {' and '.join(bad)}", rel, i))
    if not found and h.tier_num >= 2:
        problems.append(Problem("WEB-8", "no Content-Security-Policy found in the repository (a meta tag, server code or "
                                         "hosting config). If it is set outside the repository, add a line "
                                         "`CSP: set by <where>` to docs/threat-model.md"))
    return problems


def check_baseline_change(root: Path, base: str | None, h: Header) -> list[Problem]:
    """Section 1: the baseline date is set once, by the adoption PR, and never moved later."""
    if not base or not h.baseline:
        return []
    old = subprocess.run(["git", "-C", str(root), "show", f"{base}:./README.md"], capture_output=True, text=True)
    if old.returncode != 0:
        return []
    with tempfile.TemporaryDirectory() as d:
        Path(d, "README.md").write_text(old.stdout, encoding="utf-8")
        before = read_header(Path(d))
    if before.baseline is None and before.policy:
        return [Problem("Gov §1", "this PR adds a `Baseline:` line to a project that already follows the policy; the "
                                  "baseline period is only for the adoption PR", "README.md")]
    old_date = re.search(r"\d{4}-\d{2}-\d{2}", before.baseline or "")
    new_date = re.search(r"\d{4}-\d{2}-\d{2}", h.baseline)
    if old_date and new_date and new_date.group(0) > old_date.group(0):
        return [Problem("Gov §1", f"this PR moves the baseline date from {old_date.group(0)} to {new_date.group(0)}; "
                                  "the date is never moved later", "README.md")]
    return []


MARKER_RE = re.compile(r"nosemgrep|gitleaks:allow")
MARKER_OK = re.compile(r"policy-fp:\s*\S.*\(\s*https?://\S+\s*\)|exception\b.*https?://\S+", re.I)


def check_markers(root: Path) -> list[Problem]:
    """Section 5: every suppression marker carries either a `policy-fp: <reason> (<link>)` or a link to its exception."""
    problems = []
    for f in tracked_files(root):
        rel = str(f.relative_to(root))
        if skipped_path(rel) or f.suffix.lower() in (".md", ".lock") or f.stat().st_size > 2_000_000:
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if not MARKER_RE.search(text):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if MARKER_RE.search(line) and not MARKER_OK.search(line):
                problems.append(Problem("Gov §5", "a suppression without `policy-fp: <reason> (<link to the review that "
                                                  "confirmed it>)` or a link to its Section 10 exception", rel, i))
    return problems


def baseline_state(h: Header, today: datetime.date | None = None) -> tuple[bool, list[Problem]]:
    """Section 1: until the Baseline date, missing artifacts are warnings. Returns (active, problems)."""
    if not h.baseline:
        return False, []
    today = today or datetime.date.today()
    m = re.match(r"(?i)^until\s+(\d{4}-\d{2}-\d{2})$", h.baseline.strip())
    if not m:
        return False, [Problem("Gov §1", f"README `Baseline: {h.baseline}` is not in the form `Baseline: until YYYY-MM-DD`", "README.md")]
    try:
        until = datetime.date.fromisoformat(m.group(1))
    except ValueError:
        return False, [Problem("Gov §1", f"README baseline date `{m.group(1)}` is not a valid date", "README.md")]
    if until < today:
        return False, [Problem("Gov §1", f"the baseline period ended on {until}: complete the baseline audit, remove the "
                                         "`Baseline:` line, and fix the missing artifacts", "README.md")]
    if (until - today).days > 90:
        return False, [Problem("Gov §1", f"the baseline date {until} is more than 90 days ahead", "README.md")]
    return True, [Problem("Gov §1", f"baseline period until {until}: missing artifacts are reported as warnings",
                          "README.md", level="warning")]


def conformance(root: Path, base: str | None, event: dict) -> list[Problem]:
    h = read_header(root)
    problems = check_header(root, h)
    if h.tier is None or h.tier == "T0" or not re.fullmatch(r"T[0-3]", h.tier):
        return problems
    in_baseline, baseline_problems = baseline_state(h)
    problems += baseline_problems
    problems += check_baseline_change(root, base, h)
    problems += check_files(root, h)
    problems += check_budgets(root, h)
    problems += check_budget_loosening(root, base, event)
    problems += check_pins(root)
    problems += check_lockfiles(root, h)
    problems += check_pinned_sources(root)
    problems += check_csp(root, h)
    problems += check_markers(root)
    if os.environ.get("POLICY_SKIP_BROWSERSLIST") != "1":
        problems += check_browserslist(root, h)
    if in_baseline:
        for p in problems:
            if p.artifact:
                p.level = "warning"
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


def check_gitleaks_config(root: Path, base: str | None, event: dict) -> list[Problem]:
    """Section 5 secrets scan: a project's .gitleaks.toml must extend the default rules, and a PR that changes it says
    why (the scan reads the config from the PR itself)."""
    path = root / ".gitleaks.toml"
    problems = []
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            import tomllib
            use_default = (tomllib.loads(text).get("extend") or {}).get("useDefault") is True
        except ImportError:
            extend = re.search(r"(?ms)^\s*\[extend\][^\n]*$(.*?)(?=^\s*\[|\Z)", text)
            use_default = bool(extend and re.search(r"(?m)^\s*useDefault\s*=\s*true\b", extend.group(1))) or \
                bool(re.search(r"(?m)^\s*extend\.useDefault\s*=\s*true\b", text))
        except Exception as e:  # tomllib.TOMLDecodeError
            return [Problem("Gov §5", f"`.gitleaks.toml` is not valid TOML: {e}", ".gitleaks.toml")]
        if not use_default:
            problems.append(Problem("Gov §5", "`.gitleaks.toml` does not extend the default rules, so it switches every "
                                              "one of them off. Add `[extend]` with `useDefault = true`", ".gitleaks.toml"))
    if base:
        changed = subprocess.run(["git", "-C", str(root), "diff", "--name-only", f"{base}...HEAD", "--",
                                  ".gitleaks.toml", ".gitleaksignore"], capture_output=True, text=True).stdout.split()
        added = subprocess.run(["git", "-C", str(root), "diff", "-U0", f"{base}...HEAD"], capture_output=True,
                               text=True).stdout
        allows = [l for l in added.splitlines() if l.startswith("+") and "gitleaks:allow" in l]
        body = ((event.get("pull_request") or {}).get("body") or "")
        if (changed or allows) and not re.search(r"(?im)^\s*Secrets config change:\s*\S", body):
            what = ", ".join([f"`{c}`" for c in changed] + (["`gitleaks:allow` comments"] if allows else []))
            problems.append(Problem("Gov §5", f"this PR changes what the secrets scan ignores ({what}), and that scan "
                                              "runs on this same PR. Add a `Secrets config change: <reason>` line to "
                                              "the PR description", changed[0] if changed else None))
    return problems


# Semgrep's built-in ignore list, used when a project has no .semgrepignore of its own.
SEMGREP_DEFAULT_IGNORES = ["node_modules/", "build/", "dist/", "vendor/", ".env/", ".venv/", ".tox/", ".npm/",
                           "test/", "tests/", "*_test.go", "*.min.js", ".semgrep", ".semgrep_logs/"]


def semgrep_ignored(root: Path):
    """A matcher for the project's .semgrepignore (gitignore syntax, simplified), so that inline-script copies are
    skipped exactly where Semgrep would skip the HTML file itself."""
    path = root / ".semgrepignore"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.is_file() else SEMGREP_DEFAULT_IGNORES
    patterns = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(":include"):
            continue
        negate = line.startswith("!")
        patterns.append((negate, line.lstrip("!")))

    def ignored(rel: str) -> bool:
        result = False
        parts = rel.split("/")
        for negate, pat in patterns:
            anchored = pat.startswith("/")
            pat = pat.strip("/") if pat.endswith("/") else pat.lstrip("/")
            dir_only = pat != pat.rstrip("/") or raw_dir(pat, lines)
            if anchored:
                hit = fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*") or rel.startswith(pat + "/")
            else:
                hit = any(fnmatch.fnmatch(p, pat) for p in parts[:-1]) or (not dir_only and fnmatch.fnmatch(parts[-1], pat)) \
                    or fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*")
            if hit:
                result = not negate
        return result
    return ignored


def raw_dir(pat: str, lines: list[str]) -> bool:
    return any(l.strip().lstrip("!").lstrip("/") == pat + "/" for l in lines)


SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.I | re.S)
JS_TYPES = {"", "text/javascript", "application/javascript", "module", "text/ecmascript", "application/ecmascript"}


def extract_inline(root: Path, out: Path) -> dict[str, str]:
    """Copy the inline <script> blocks of each tracked HTML file to <out>/<path>.inline.js, with everything outside
    them blanked and newlines kept, so that a finding's line number is the line in the HTML file. Returns
    {copy path: original relative path}."""
    mapping = {}
    ignored = semgrep_ignored(root)
    for f in tracked_files(root):
        if f.suffix.lower() not in (".html", ".htm") or ignored(str(f.relative_to(root))):
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        keep = [False] * len(text)
        any_block = False
        for m in SCRIPT_RE.finditer(text):
            attrs = m.group(1)
            if re.search(r"(?i)(?<![\w-])src\s*=", attrs):
                continue
            t = re.search(r"(?i)(?<![\w-])type\s*=\s*[\"']?([^\"'\s>]+)", attrs)
            if (t.group(1).lower() if t else "") not in JS_TYPES:
                continue
            any_block = True
            for i in range(m.start(2), m.end(2)):
                keep[i] = True
        if not any_block:
            continue
        blanked = "".join(c if keep[i] or c == "\n" else " " for i, c in enumerate(text))
        rel = str(f.relative_to(root))
        dest = out / (rel + ".inline.js")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(blanked, encoding="utf-8")
        mapping[str(dest)] = rel
    return mapping


def sast_gate(reports: list[Path], mapping: dict[str, str] | None = None) -> list[Problem]:
    """Section 5 static analysis and WEB-9/WEB-10. The policy's own ERROR rules block. A registry ERROR result blocks
    unless the rule rates itself low-confidence or an audit rule (a lead for a reviewer, not a defect); everything
    else is a warning."""
    mapping = {os.path.realpath(k): v for k, v in (mapping or {}).items()}
    problems, seen = [], set()
    for path in reports:
        if not path.is_file():
            problems.append(Problem("Gov §5", f"the Semgrep report {path} is missing, so nothing was checked"))
            continue
        for r in json.loads(path.read_text(encoding="utf-8")).get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            file = r.get("path", "")
            file = mapping.get(os.path.realpath(file), file)
            line = (r.get("start") or {}).get("line")
            rule_id = r.get("check_id", "").split(".")[-1]
            key = (file, line, rule_id)
            if key in seen:
                continue
            seen.add(key)
            severity = str(extra.get("severity", "")).upper()
            blocking_severity = severity in ("ERROR", "HIGH", "CRITICAL")
            confidence = str(meta.get("confidence", "")).upper()
            subcategory = [str(x).lower() for x in (meta.get("subcategory") or [])]
            policy_rule = meta.get("policy-rule")
            if policy_rule:
                level = "error" if blocking_severity else "warning"
            else:
                level = "error" if blocking_severity and confidence != "LOW" and "audit" not in subcategory else "warning"
            message = " ".join(str(extra.get("message", "")).split())
            if policy_rule and message.startswith(f"{policy_rule}:"):
                message = message[len(policy_rule) + 1:].strip()
            label = policy_rule or f"Gov §5 ({rule_id})"
            problems.append(Problem(label, message if policy_rule else f"{message} [{rule_id}]", file, line, level=level))
    return problems


def report(problems: list[Problem], level: str | None = None, title: str = "Policy conformance") -> int:
    """Print problems (as GitHub annotations in Actions) and return the number of errors.

    `level` overrides every problem's own level."""
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    errors = 0
    for p in problems:
        lv = level or p.level
        errors += lv == "error"
        if in_actions:
            loc = ",".join(x for x in (f"file={p.file}" if p.file else "", f"line={p.line}" if p.line else "") if x)
            print(f"::{lv} {loc}::{p.rule}: {p.message}" if loc else f"::{lv} ::{p.rule}: {p.message}")
        else:
            where = f"{p.file}:{p.line}: " if p.file and p.line else f"{p.file}: " if p.file else ""
            print(f"{where}{'warning: ' if lv == 'warning' else ''}{p.rule}: {p.message}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"## {title}\n\n")
            if problems:
                f.write("| | Rule | Problem | Where |\n| --- | --- | --- | --- |\n")
                for p in problems:
                    where = f"`{p.file}:{p.line}`" if p.file and p.line else f"`{p.file}`" if p.file else ""
                    mark = "error" if (level or p.level) == "error" else "warning"
                    f.write(f"| {mark} | {p.rule} | {p.message.replace('|', '/')} | {where} |\n")
            else:
                f.write("All checked rules pass.\n")
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["conformance", "tier", "header", "vulns", "licenses", "pins",
                                        "secrets-config", "extract-inline", "sast"])
    ap.add_argument("--report", type=Path, action="append", default=[],
                    help="a JSON report: osv-scanner for `vulns`/`licenses`, Semgrep for `sast` (repeatable)")
    ap.add_argument("--out", type=Path, help="output directory, for `extract-inline`")
    ap.add_argument("--map", type=Path, help="inline-script map written by `extract-inline`, for `sast`")
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
        print(json.dumps({"tier": h.tier, "policy": h.policy, "types": h.types, "users": h.users,
                          "lighter_t2": h.lighter_t2, "baseline": baseline_state(h)[0]}))
        return 0

    event = {}
    if args.event and Path(args.event).is_file():
        event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    if args.command == "secrets-config":
        return 1 if report(check_gitleaks_config(root, args.base, event), title="Secrets scan configuration") else 0
    if args.command == "extract-inline":
        mapping = extract_inline(root, args.out.resolve())
        (args.out / "inline-map.json").write_text(json.dumps(mapping), encoding="utf-8")
        print(f"{len(mapping)} HTML file(s) with inline scripts")
        return 0
    if args.command == "sast":
        mapping = json.loads(args.map.read_text(encoding="utf-8")) if args.map and args.map.is_file() else {}
        problems = sast_gate(args.report, mapping)
        errors = report(problems, title="Static analysis")
        print(f"{errors} blocking, {len(problems) - errors} warning")
        return 1 if errors else 0
    if args.command == "pins":
        return 1 if report(check_pins(root), title="DEP-7 pins") else 0
    if args.command == "licenses":
        return 1 if report(license_gate(args.report[0]), title="Licenses") else 0
    if args.command == "vulns":
        h = read_header(root)
        blocking, warnings = vuln_gate(args.report[0], "T1" if h.lighter_t2 else h.tier)
        for w in warnings:
            w.level = "warning"
        data = json.loads(args.report[0].read_text(encoding="utf-8")) if args.report[0].is_file() else {}
        scanned = sum(len(r.get("packages", [])) for r in data.get("results", []))
        if scanned == 0:
            warnings.append(Problem("Gov §5", "the scan matched no packages at all, so a pass here says nothing. Check "
                                              "that every manifest has a lockfile, and list fetched sources in "
                                              "pinned-sources.cdx.json (DEP-8)", level="warning"))
        if (root / "pinned-sources.cdx.json").is_file():
            warnings.append(Problem("DEP-8", "OSV matches few C and C++ sources; check the advisories of every source in "
                                             "pinned-sources.cdx.json by hand at each release audit",
                                    "pinned-sources.cdx.json", level="warning"))
        errors = report(warnings + blocking, title="Known-vulnerable dependencies")
        print(f"{errors} blocking, {len(warnings)} warning, {scanned} package(s) scanned")
        return 1 if errors else 0

    return 1 if report(conformance(root, args.base, event)) else 0


if __name__ == "__main__":
    sys.exit(main())
