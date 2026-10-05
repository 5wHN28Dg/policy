# Standard: dependencies

The single rule for adding third-party code to a project. Every other document in this repo points here for dependency criteria. The reasoning is in [guides/native-rationale.md](../guides/native-rationale.md#dependencies) and [guides/web-rationale.md](../guides/web-rationale.md#the-dependency-question).

## How to read this standard

- **MUST**, **SHOULD** and **MAY** are used as in RFC 2119. A SHOULD that is not followed needs its reason written where the rule's check looks (the PR description or the record).
- **Tier** is the lowest risk tier ([governance/review-audit.md Section 3](../governance/review-audit.md#3-risk-tiers)) a rule applies to; it applies to every tier above as well. T0 projects are exempt from this standard.
- **Check** says what proves compliance. Reviews and audits cite rules by ID. A check applies at its rule's tier even where [Section 5](../governance/review-audit.md#5-continuous-automated-checks) does not require that kind of check for the tier.
- A departure from a MUST is a finding, rated by impact under [Section 8](../governance/review-audit.md#8-findings-severity-and-deadlines). If it is still open at the next audit, it must be fixed or excepted before that audit's release decision, whatever its severity. The only way to depart from a rule on purpose is a written exception under [Section 10](../governance/review-audit.md#10-exceptions-and-risk-acceptance).

## Rules

### DEP-0
**Tier T1. MUST.** Reviewers treat as a dependency any third-party code the project ships, or that its build runs: packages from a registry, vendored or copied source, scripts loaded from a CDN, polyfills, firmware components fetched from outside the project, and dev-only tools such as test runners and linters. Third-party CI actions are covered by `DEP-7` only. Container images are pinned under `DEP-7`, and an image that is not platform-provided under `OTH-0` is also a dependency. Not a dependency: what the applicable standard defines as platform-provided ([`NAT-1`](native.md#nat-1), [`WEB-3`](web.md#web-3), [`OTH-0`](other-targets.md#oth-0)). Platform-provided code is still covered by the automated scans in Section 5.
*Check:* every direct entry in a manifest (the packages the project itself declares), every non-official base image, and every vendored third-party directory either is platform-provided under the applicable definition or has the justification or record required by `DEP-1` and `DEP-2`.

### DEP-1
**Tier T1. MUST.** There is no presumption for or against a dependency. A new direct dependency is added when, on total cost, it beats the alternatives: what the platform provides, and a custom implementation, counting the security-sensitive work custom code would mean owning. The transitive tree is part of that cost. On T1, one or two sentences in the PR description that name the alternatives are enough; from T2, the record in `DEP-2` is the evidence.
*Check:* every PR that adds an entry to a manifest or lockfile as a new direct dependency, or adds vendored third-party code, contains that justification (T1) or a complete record (T2+).

### DEP-2
**Tier T2. MUST.** Each direct dependency has a dependency record from [templates/dependency-record.md](../templates/dependency-record.md), in the PR description or in `docs/dependencies/<name>.md`, with every field filled in: purpose; the platform alternative checked and why it falls short; the custom implementation considered; transitive dependency count and how it was counted; license; maintenance signals; size impact; replacement cost. A new dependency gets its record in the PR that adds it. A project that adopts this policy at T2 or above writes records for its existing direct dependencies during the baseline audit; a project that moves up to T2 writes them before its first T2 release audit. A family of dev-only packages from one source that never ship (for example `@types/*` type definitions) MAY share one record that lists every package.
*Check:* the record exists, is linked from the PR (or, for existing dependencies, from the baseline or first T2 audit report), and no field is blank. The transitive count can be re-derived from the lockfile.

### DEP-3
**Tier T1. MUST.** Maintenance signals are weighed as evidence, not applied as a pass/fail gate. No single signal, including having only one maintainer, disqualifies a dependency on its own; a weak signal is answered in the justification (T1) or the record's Decision field (T2+). From T2, the record states all four signals: recent releases, a findable security response history, the number of active maintainers, and age across major versions.
*Check:* a review comment that rejects a dependency cites the total-cost case, not one signal. On T2+, all four signals are present in the record.

### DEP-4
**Tier T1. MUST.** A polyfill is a dependency and meets `DEP-1` to `DEP-3` like any other. It is added only when the documented fallback for the missing feature is unacceptable to users, and the justification or record says why.
*Check:* each polyfill in the manifest, lockfile or source has a justification or record that states why the fallback was rejected.

### DEP-5
**Tier T2. MUST.** The record is kept current. It is updated when the dependency changes major version or license. A record kept only in a PR description is moved to `docs/dependencies/<name>.md` the first time it needs an update. Each release audit checks that every direct dependency has a current record, and re-checks its maintenance signals and license; a dependency whose signals have weakened since the record (no releases, unanswered security reports, maintainers gone) is a finding.
*Check:* a PR that bumps a direct dependency's major version updates its record in `docs/dependencies/`. A license change shows in the Section 5 license scanner's output, which the audit compares against the records. The audit report lists dependencies without a current record, and those with weakened signals, as findings.

### DEP-6
**Tier T2. SHOULD.** Before adding a dependency, prefer the one with the smaller transitive tree when two candidates are otherwise comparable.
*Check:* when the record names an alternative package, it gives both transitive counts.

### DEP-7
**Tier T1. MUST.** Every CI action or reusable workflow not defined in the project's own repository, including vendor-owned ones such as `actions/*` and the policy repo's own workflows, is pinned to a full commit SHA, with the version in a trailing comment. Every container image a CI job or the deployment uses (`container:`, `services:`, `docker://`, `FROM`, compose files, Kubernetes manifests) is pinned by digest (`@sha256:`). A `FROM` that names an earlier build stage, or `scratch`, needs no digest. Updates arrive as their own reviewed changes; automated update PRs (Dependabot, Renovate) are fine. No dependency record is needed.
*Check:* every `uses:` in `.github/workflows/` (or the equivalent in another CI) that is not a local path ends in a 40-character hex SHA or, for `docker://`, an `@sha256:` digest; every image reference in workflows, Dockerfiles and deployment manifests carries an `@sha256:` digest, except `FROM` lines naming a build stage or `scratch`.

## Scanning, pinning and licenses

Lockfile pinning, known-vulnerability scanning, license compliance and the SBOM are governed by [governance/review-audit.md Section 5](../governance/review-audit.md#5-continuous-automated-checks). This standard does not repeat or change those rules. A dependency that touches the network, the filesystem or native code also triggers a threat model update under [Section 4](../governance/review-audit.md#4-threat-model-design-time).
