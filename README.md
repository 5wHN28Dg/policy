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
   Policy: v1.1
   Type: web, native
   Users: none
   ```

   `Type:` lists every project type from the table above that applies (`web`, `native`, `service`, `firmware`, `webview`, `engine-bundling`). `Users: none` is optional: it marks a solo T2 project with no external users yet, which gets the [Section 11](governance/review-audit.md#11-solo-developer-adaptations) lighter-T2 relief. Remove it at the first release others install or depend on.
2. Find the project's type in the table above. Its standard says what else the README must declare: target browsers (`browserslist`), OS versions, or the runtime.
3. Write `docs/capability-matrix.md` from [the template](templates/capability-matrix.md), before choosing the stack in a new project.
4. From T2: add `budgets.json` (validate it against [the schema](templates/budgets.schema.json); start from [the example](templates/budgets.example.json) but set your own numbers) and the CI jobs that read it.
5. From T2: write a [dependency record](templates/dependency-record.md) for each direct dependency, as [`DEP-2`](standards/dependencies.md#dep-2) requires, including the ones the project already has.
6. Existing project: run the baseline audit ([Section 7](governance/review-audit.md#7-release-audit)) against the governance document and the applicable standards.

## Automation

The policy ships the CI that checks it. A project copies [templates/ci/policy.yml](templates/ci/policy.yml) into `.github/workflows/`, replaces `POLICY_SHA` with the commit of the policy version it follows, and makes the jobs required for merge. Each job is a composite action in [`actions/`](actions/), pinned by SHA (`DEP-7`), with its tools pinned and checksum-verified:

| Action | What it checks | Blocks |
| --- | --- | --- |
| [conformance](actions/conformance/action.yml) | README header; required files per tier; `budgets.json` against the schema; loosened budgets without a `Budget change:` line in the PR; `DEP-7` pins; the `WEB-1` resolved browser list | Yes |
| [secrets](actions/secrets/action.yml) | Section 5 secrets in code and history (gitleaks) | Yes, every tier |
| [vulns](actions/vulns/action.yml) | Section 5 known-vulnerable dependencies and licenses (osv-scanner, against `license-allowlist.txt`) | High and Critical from T2; warnings on T1 |
| [sast](actions/sast/action.yml) | `WEB-9` and `WEB-10` sink rules ([semgrep/](semgrep/)) for HTML UIs from T1; Semgrep's default ruleset from full T2 | Yes |
| [sbom](actions/sbom/action.yml) | Section 5 SBOM (Syft, CycloneDX) on release tags | No; uploads an artifact |
| [claude-review](actions/claude-review/action.yml) | A fresh-context Claude review of each PR against Section 6 and the standards, with inline comments and one summary comment | No; advisory |

Everything else a rule's Check names (records, matrices, manual checks, threat-model content) is for the PR review and the release audit.

**PR review (Claude, in CI).** Needs a repository secret `CLAUDE_CODE_OAUTH_TOKEN`: run `claude setup-token` (Claude Pro or Max), then `gh secret set CLAUDE_CODE_OAUTH_TOKEN` in the project. It runs only for PRs from the project's own branches, never from forks. Before Claude starts, the action removes `CLAUDE.md`, `CLAUDE.local.md` and `.claude/` from its checkout, so the review is a blind pass (Section 11). Its output is leads, not findings.

**Release audit (Claude, on your machine).** Run [tools/audit.sh](tools/audit.sh) from a clone of this repo:

```
tools/audit.sh --scope "the sync protocol" ~/code/my-project
```

It audits a copy of the project's last commit, never the working tree, in one new Claude Code session with your customizations off. Pass 1 is blind: the rationale paths (default `CLAUDE.md CLAUDE.local.md .claude docs/decisions`, change them with `--rationale`) are removed. Pass 2 resumes the same session with the rationale added and attacks it. Claude can only read files and run read-only git commands. The reports land next to the project in `<name>-audit-<date>/`. Confirm each finding before recording it, and keep the final report with the release (Section 7).

## Changing the policy

A change to this repo is reviewed like code. Rule IDs are stable: a removed rule's ID is not reused, and a reworded rule keeps its ID unless its meaning changes. A deliberate departure in one project is an exception under [Section 10](governance/review-audit.md#10-exceptions-and-risk-acceptance), not an edit here.

**Versions.** Each release of this repo is a git tag (`v1.0`, `v1.1`, `v2.0`). A major version adds, tightens or removes a MUST; a minor version clarifies wording, or adds SHOULDs and template fields. Each project states the version it follows in its README, and each audit report records the version it applied. A new or tightened MUST takes effect for a project when it moves to that version, which is a reviewed change in the project. A breaking change to `templates/budgets.schema.json` also bumps its `schemaVersion`.
