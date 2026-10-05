# Standard: native

Normative rules for native desktop and mobile applications. The reasoning is in [guides/native-rationale.md](../guides/native-rationale.md). Apps that ship their own browser engine, or render in a system webview, follow [other-targets.md](other-targets.md), which applies this standard in part.

Also applies: [dependencies.md](dependencies.md) for every dependency.

## How to read this standard

- **MUST**, **SHOULD** and **MAY** are used as in RFC 2119. A SHOULD that is not followed needs its reason written where the rule's check looks.
- **Tier** is the lowest risk tier ([governance/review-audit.md Section 3](../governance/review-audit.md#3-risk-tiers)) a rule applies to; it applies to every tier above as well. T0 projects are exempt.
- **Check** says what proves compliance. Reviews and audits cite rules by ID. A check applies at its rule's tier even where [Section 5](../governance/review-audit.md#5-continuous-automated-checks) does not require that kind of check for the tier.
- Solo T2 projects with no external users yet may defer `NAT-7` and `NAT-8` until full T2 applies; see [Section 11, Lighter T2 before users](../governance/review-audit.md#11-solo-developer-adaptations).
- A departure from a MUST is a finding, rated by impact under [Section 8](../governance/review-audit.md#8-findings-severity-and-deadlines). If it is still open at the next audit, it must be fixed or excepted before that audit's release decision, whatever its severity. Deliberate departures need a [Section 10](../governance/review-audit.md#10-exceptions-and-risk-acceptance) exception.
- This standard contains no platform support data. Support facts live in each project's capability matrix, checked against vendor documentation when it is written.

## Rules

### NAT-1
**Tier T1. MUST.** Reviewers treat a capability as platform-provided, and so exempt from [dependencies.md](dependencies.md), only if tests 1 to 3 hold; test 4 is recorded, not required. Otherwise it is a dependency. ([rationale](../guides/native-rationale.md#what-counts-as-platform-provided))

1. **Vendor-supported for app development.** The OS vendor documents it as part of how apps are built for the platform: in the OS, a system framework, or a vendor SDK or library. Published by the vendor for another purpose, or merely present on devices, does not count. A component that is optional on target devices counts only where the matrix shows it present on all of them.
2. **Available on the declared targets.** It works on every OS version declared under `NAT-2`.
3. **No duplicate runtime.** It does not bring its own runtime, rendering engine or script engine that duplicates one the platform already provides. Cross-platform frameworks that bring their own engine (React Native, Flutter) fail this test, so they are dependencies and need a record.
4. **Established.** Whether it has been the vendor's documented path through at least one major OS release. A newer vendor framework MAY be used as platform-provided, but its matrix row says that it is new and names the churn risk.

On Linux there is no single vendor stack. The project names its target desktop stack (for example GTK with portals and D-Bus, or Qt) in the README, and that stack counts as the platform.
*Check:* for each matrix cell marked `provided`, its row names the vendor facility, it passes tests 1 to 3, and the row's Established column records test 4; anything else in the manifest has a dependency justification or record.

### NAT-2
**Tier T1. MUST.** The README declares each target platform and the minimum (and, if any, maximum) OS version supported, and the Linux desktop stack if Linux is a target.
*Check:* the README has a Targets section with these values.

### NAT-3
**Tier T1. MUST.** The project keeps a capability matrix in `docs/capability-matrix.md`, from [templates/capability-matrix.md](../templates/capability-matrix.md), with one column per target platform, a check date and a source per row. It is written before the architecture is chosen, and rebuilt when a target platform or OS version range changes, or when a feature needs a capability that is not yet a row in the matrix. ([rationale](../guides/native-rationale.md#build-a-capability-matrix-before-choosing-architecture))
*Check:* the file exists with a date and sources. For new projects, it is committed before the first UI toolkit or cross-platform framework dependency. A PR that changes the README Targets section, or adds use of a platform capability with no matrix row, also updates the matrix.

### NAT-4
**Tier T1. MUST.** Where the matrix shows a platform-provided control or dialog (file picker, print dialog, text field, notifications and similar), the app uses it. A custom replacement is merged only with keyboard-only and screen reader test evidence for each target platform in the PR: which assistive technology, the steps, and the result.
*Check:* a PR that adds a custom version of a capability the matrix marks `provided` includes the reason and that evidence.

### NAT-5
**Tier T1. MUST.** The project does not weaken, bypass or disable a platform security mechanism to remove a dependency or simplify the implementation. This covers app sandboxing and entitlements or permissions, code signing and notarization, the platform credential store, and transport security settings.
*Check:* any PR that changes entitlements, manifest permissions, sandbox settings, signing configuration or transport security exceptions states why; the reviewer blocks it without a Section 10 exception.

### NAT-6
**Tier T2. MUST.** Business logic lives in modules that do not import platform UI or system APIs, and its tests run without the platform (no device, emulator or OS UI). The platform layer is a thin adapter. On T1 this is a SHOULD. ([rationale](../guides/native-rationale.md#a-cost-this-approach-imposes))
*Check:* the core modules are named in the README; a lint or build rule forbids platform imports in them; their tests run in a plain CI job.

### NAT-7
**Tier T2. MUST.** `budgets.json`, valid against [templates/budgets.schema.json](../templates/budgets.schema.json), sets startup time, steady-state memory and installed size for each target platform in its `native` section, with the scenario each is measured in. CI measures them on each platform, takes the median of the number of runs the file states, keeps the results for each run, and fails when a value passes its threshold. Where only a real device gives meaningful startup and memory numbers (phones, low-end laptops), a platform MAY set `"measuredWhere": "release-test"` and name the device in `measuredOn`: its startup and memory are then measured on that device before each release, recorded in the release notes, and a value past its threshold blocks the release unless excepted under Section 10. Installed size is always measured in CI. A PR that loosens a threshold states the reason in its description. ([rationale](../guides/native-rationale.md#universal-principles))
*Check:* the file validates and lists every platform from `NAT-2`; the CI job reads it, stores results as artifacts, and is required for merge; each release's notes record every `release-test` value, each within its threshold or excepted; a diff that raises a threshold, or moves a platform out of CI, has a stated reason in its PR.

### NAT-8
**Tier T2. MUST.** CI builds and runs the test suite on each target OS from `NAT-2` (a runner, emulator or simulator for that OS), and every OS's job is required for merge.
*Check:* the CI config has a job per target OS, listed as required in branch protection.

### NAT-9
**Tier T1. MUST.** If the project exposes an extension or plugin API, the README declares its shape: in-process, protocol, or sandboxed. A change from one shape to another is a breaking change and is called out in the release notes. ([rationale](../guides/native-rationale.md#the-reverse-dependency))
*Check:* the README has an Extension API section when one exists; the extension point is also a trust boundary in the threat model on T2+.

### NAT-10
**Tier T2. MUST.** Before each release, a manual accessibility check is done on each target platform and recorded: the platform's screen reader, keyboard only (or switch access on mobile), the largest system text size, a high-contrast or increased-contrast mode, and reduced motion. ([rationale](../guides/native-rationale.md#universal-principles))
*Check:* the release notes or `docs/accessibility-checks.md` hold a dated entry for the version, per platform, with the tool and result for each of the five items.
