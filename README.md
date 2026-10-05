# Engineering policy

The policy every software project here follows. It has three layers:

- **Governance** says *how* work is checked: risk tiers, CI checks, review, audits, findings, exceptions. [governance/review-audit.md](governance/review-audit.md)
- **Standards** say *what* good looks like. Each rule has an ID, a minimum tier and a check. Reviews, audits and automation cite rules by ID. [standards/](standards/)
- **Guides** explain *why*. They are not checked; where a guide and a standard differ, the standard wins. [guides/](guides/)

[templates/](templates/) holds the files a project copies in.

## Which documents apply

Every project follows the governance document and [standards/dependencies.md](standards/dependencies.md). Then add the standard for its type:

| Project type | Standard | Guide |
| --- | --- | --- |
| Web app or site, delivered to a browser | [standards/web.md](standards/web.md) | [guides/web-rationale.md](guides/web-rationale.md) |
| Native desktop or mobile app | [standards/native.md](standards/native.md) | [guides/native-rationale.md](guides/native-rationale.md) |
| Cross-platform app with its own engine (React Native, Flutter) | [standards/native.md](standards/native.md); the framework fails `NAT-1` test 3, so it needs a dependency record | [guides/native-rationale.md](guides/native-rationale.md) |
| Backend script or service (for example a Telegram bot) | [standards/other-targets.md](standards/other-targets.md), class Service | [guides/native-rationale.md](guides/native-rationale.md#the-decision-procedure) |
| Microcontroller firmware (for example ESP32 with ESPHome) | [standards/other-targets.md](standards/other-targets.md), class Firmware | as above |
| App rendering in a system webview (for example Tauri) | [standards/other-targets.md](standards/other-targets.md), class Webview app, which pulls in parts of `native.md` and `web.md` | both guides |
| App bundling its own browser engine (for example Electron) | [standards/other-targets.md](standards/other-targets.md), class Engine-bundling app, which pulls in parts of `native.md` and `web.md` | both guides |

Tiers: T0 projects follow only the governance rules for T0 (a secrets scan); the standards start at T1. Firmware or a service that controls physical equipment is T3. "Release" means a tagged version ([governance Section 2](governance/review-audit.md#2-definitions)); untagged deploys don't count.

## Adopting the policy in a project

1. Do the adoption checklist in [governance/review-audit.md Section 1](governance/review-audit.md#1-purpose-and-scope): state the tier and the policy version in the README, add `SECURITY.md`, the CI checks, branch protection, and the threat model and findings register where the tier needs them. Write the README statement as these lines, so that the conformance check can read them:

   ```
   Tier: T2
   Policy: v1.2
   Type: web, native
   Users: none
   Baseline: until 2026-12-31
   ```

   `Type:` lists every project type from the table above that applies (`web`, `native`, `service`, `firmware`, `webview`, `engine-bundling`). `Users: none` is optional: it marks a solo T2 project with no external users yet, which gets the [Section 11](governance/review-audit.md#11-solo-developer-adaptations) lighter-T2 relief. Remove it at the first release others install or depend on, or when the project adds a network-facing service, whichever comes first. `Baseline: until <date>` is for an existing project adopting the policy: until that date (at most 90 days ahead), missing artifacts are warnings instead of failures ([Section 1](governance/review-audit.md#1-purpose-and-scope)).
2. Find the project's type in the table above. Its standard says what else the README must declare: target browsers (`browserslist`), OS versions, or the runtime.
3. Write `docs/capability-matrix.md` from [the template](templates/capability-matrix.md), before choosing the stack in a new project.
4. From T2: add `budgets.json` (validate it against [the schema](templates/budgets.schema.json); start from [the example](templates/budgets.example.json) but set your own numbers) and the CI jobs that read it.
5. From T2: write a [dependency record](templates/dependency-record.md) for each direct dependency, as [`DEP-2`](standards/dependencies.md#dep-2) requires, including the ones the project already has.
6. Existing project: run the baseline audit ([Section 7](governance/review-audit.md#7-release-audit)) against the governance document and the applicable standards.

## Automation

The policy ships the CI that checks it. A project copies [templates/ci/policy.yml](templates/ci/policy.yml) into `.github/workflows/`, replaces `POLICY_SHA` with the commit of the policy version it follows, and makes the jobs required for merge. Each job is a composite action in [`actions/`](actions/), pinned by SHA (`DEP-7`), with its tools pinned and checksum-verified:

| Action | What it checks | Blocks |
| --- | --- | --- |
| [conformance](actions/conformance/action.yml) | README header and baseline period; required files per tier; `budgets.json` against the schema; loosened budgets without a `Budget change:` line in the PR; `DEP-7` pins; manifests without lockfiles and unpinned requirements (Section 5); `pinned-sources.cdx.json` (`DEP-8`); a CSP exists and allows no inline or eval scripts, as far as the repository shows (`WEB-7`, `WEB-8`); the `WEB-1` resolved browser list | Yes; missing artifacts are warnings during a baseline period |
| [secrets](actions/secrets/action.yml) | Section 5 secrets in code and history (gitleaks). A project's `.gitleaks.toml` must extend the default rules, and a PR that changes it needs a `Secrets config change:` line | Yes, every tier |
| [vulns](actions/vulns/action.yml) | Section 5 known-vulnerable dependencies and licenses (osv-scanner, against `license-allowlist.txt`), including the sources in `pinned-sources.cdx.json`. Says so when it matched nothing | Every severity on T3; High and Critical on T2; warnings on T1 |
| [sast](actions/sast/action.yml) | `WEB-9` and `WEB-10` sink rules ([semgrep/](semgrep/)) for HTML UIs from T1, in `.js`/`.ts` files and in the inline `<script>` blocks of HTML files; inline event handlers as `WEB-7` warnings; Semgrep's default ruleset from full T2 | The policy's rules; default-ruleset results rated High confidence or above that are not audit rules. Everything else is a warning |
| [sbom](actions/sbom/action.yml) | Section 5 SBOM (Syft, CycloneDX) on release tags | No; uploads an artifact |
| [claude-review](actions/claude-review/action.yml) | A fresh-context Claude review of each PR against Section 6 and the standards, with inline comments and one summary comment | No; advisory |

Everything else a rule's Check names (records, matrices, manual checks, threat-model content) is for the PR review and the release audit.

Known limits:

- OSV matches few C and C++ sources, so `DEP-8` sources get their advisories checked by hand at each release audit, whatever the scan says.
- The CSP check sees only what is in the repository. A CSP set by hosting outside it is checked by the PR review and the release audit.
- Inline event handlers (`onclick=`) are flagged as `WEB-7` warnings, but the JavaScript inside them is not scanned for `WEB-9`/`WEB-10` sinks.
- Semgrep's `p/default` ruleset, used from full T2, is fetched from the Semgrep registry at run time and is not versioned, so a registry update can fail a build with no change in the project. Treat such a failure as a new finding, not a broken build.

**PR review (Claude, in CI).** Needs a repository secret `CLAUDE_CODE_OAUTH_TOKEN`: run `claude setup-token` (Claude Pro or Max), then `gh secret set CLAUDE_CODE_OAUTH_TOKEN` in the project. It runs only for PRs from the project's own branches, never from forks. The review is a blind pass (Section 11): `CLAUDE.md`, `CLAUDE.local.md`, `.claude/` and `docs/decisions/` (change the list with the `hide` input) are deleted from its checkout and denied to Claude's file tools, and in-repo Claude settings are not loaded. Claude can read the checkout, the policy and the PR's diff, post inline comments, and nothing else: no shell, no writes, no web. Treat everything in a PR as untrusted, including its description; the summary is scrubbed of anything token-shaped before it is posted. Its output is leads, not findings.

**Release audit (Claude, on your machine).** Run [tools/audit.sh](tools/audit.sh) from a clone of this repo:

```
tools/audit.sh --scope "the sync protocol" ~/code/my-project
```

It audits a copy of the project's last commit, without its git history (commit messages are rationale too), in one new Claude Code session with your customizations off. Pass 1 is blind: the rationale paths (default `CLAUDE.md .claude docs/decisions`, change them with `--rationale`) are removed. Only committed files are audited, so gitignored notes such as `CLAUDE.local.md` are never shown to the auditor. Pass 2 resumes the same session with the rationale added and attacks it. Claude can only read, search and list files. Check out the policy version the project declares first; the script warns if they differ. The reports land next to the project in `<name>-audit-<date>/`. Confirm each finding before recording it, and keep the final report with the release (Section 7).

## Changing the policy

A change to this repo is reviewed like code. Rule IDs are stable: a removed rule's ID is not reused, and a reworded rule keeps its ID unless its meaning changes. A deliberate departure in one project is an exception under [Section 10](governance/review-audit.md#10-exceptions-and-risk-acceptance), not an edit here.

**Versions.** Each release of this repo is a git tag (`v1.0`, `v1.1`, `v2.0`). A major version adds, tightens or removes a MUST; a minor version clarifies wording, or adds SHOULDs and template fields. Each project states the version it follows in its README, and each audit report records the version it applied. A new or tightened MUST takes effect for a project when it moves to that version, which is a reviewed change in the project. A breaking change to `templates/budgets.schema.json` also bumps its `schemaVersion`.
