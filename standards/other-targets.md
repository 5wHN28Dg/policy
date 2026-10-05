# Standard: other targets

Normative rules for projects that are neither a browser-delivered web app ([web.md](web.md)) nor a plain native app ([native.md](native.md)). It applies the same method: the four questions from the guides, the dependency rule, and budgets. The reasoning is the [decision procedure in the native guide](../guides/native-rationale.md#the-decision-procedure).

Also applies: [dependencies.md](dependencies.md) for every dependency.

## Target classes

| Class | Examples | Also applies |
| --- | --- | --- |
| **Service** | A backend script or long-running service: a Telegram bot, a webhook receiver, a scheduled job | This standard only |
| **Firmware** | Microcontroller firmware, including ESPHome configurations for ESP32 | This standard only |
| **Webview app** | A desktop or mobile shell that renders its UI in the OS's system webview (Tauri, WebView2, WKWebView or WebKitGTK wrappers) | [native.md](native.md) for the shell; [web.md](web.md) `WEB-3`, `WEB-4`, `WEB-6` to `WEB-14` and `WEB-16` for the UI |
| **Engine-bundling app** | An app that ships its own browser engine (Electron) | [native.md](native.md) for the shell; [web.md](web.md) `WEB-3`, `WEB-4`, `WEB-6` to `WEB-14` and `WEB-16` for the renderer, with the bundled engine as the only declared browser |

For controls in the HTML UI of a webview or engine-bundling app, `WEB-12` applies instead of `NAT-4`; `NAT-4` still applies to dialogs and services the OS provides to the shell (a custom HTML file picker in place of the OS one needs `NAT-4` evidence). `WEB-7` and `WEB-8` are checked against the CSP the app actually applies: the shell's config (for Tauri, the `security.csp` setting) or the CSP the app sets for its renderer, where there are no HTTP response headers to fetch.

## How to read this standard

- **MUST**, **SHOULD** and **MAY** are used as in RFC 2119. A SHOULD that is not followed needs its reason written where the rule's check looks.
- **Tier** is the lowest risk tier a rule applies to; it applies to every tier above as well. T0 projects are exempt.
- **Check** says what proves compliance. Reviews and audits cite rules by ID. A check applies at its rule's tier even where [Section 5](../governance/review-audit.md#5-continuous-automated-checks) does not require that kind of check for the tier.
- Solo T2 projects with no external users yet may defer `OTH-5`, and for webview and engine-bundling apps `NAT-7`, `NAT-8` (through `OTH-6`) and `WEB-13`, until full T2 applies; see [Section 11, Lighter T2 before users](../governance/review-audit.md#11-solo-developer-adaptations).
- A departure from a MUST is a finding, rated by impact under [Section 8](../governance/review-audit.md#8-findings-severity-and-deadlines). If it is still open at the next audit, it must be fixed or excepted before that audit's release decision, whatever its severity. Deliberate departures need a [Section 10](../governance/review-audit.md#10-exceptions-and-risk-acceptance) exception.
- This standard contains no platform support data. Config keys named in parentheses are examples of where a protection lives today; the rule is the protection, not the key name.

## What counts as platform-provided

### OTH-0
**Tier T1. MUST.** Reviewers treat a capability as platform-provided, and so exempt from [dependencies.md](dependencies.md), only as follows. Anything else is a dependency.

- **Service:** the language runtime and its standard library at the declared version; the OS, or an official runtime or distribution container image (published by the language or distribution project) at the declared version, and its service manager; and the documented API of the external service the project integrates with (for a Telegram bot, the Bot API). Anything a project's own image adds on top of the official base is a dependency.
- **Firmware:** the declared framework and its built-in components at the declared version (for ESPHome, components that ship with ESPHome itself), and the chip vendor's SDK at the version the framework uses. External components, custom components and third-party libraries are dependencies.
- **Webview app:** the shell side follows [`NAT-1`](native.md#nat-1); the UI side follows [`WEB-3`](web.md#web-3), with the system webview on each target OS as the browser.
- **Engine-bundling app:** the shell side follows [`NAT-1`](native.md#nat-1), and the bundled engine fails its "no duplicate runtime" test, so it needs a dependency record; the renderer side follows [`WEB-3`](web.md#web-3), with the bundled engine as the browser.

*Check:* each capability matrix cell marked `provided` names a facility that fits the list for the project's class; every other direct manifest entry, and anything a non-official image adds, has a dependency justification or record.

## Rules

### OTH-1
**Tier T1. MUST.** The README declares the target class and its runtime: for a service, the language runtime version and where it runs; for firmware, the board, the framework and its version; for a webview app, each target OS with its minimum version and the webview engine it provides; for an engine-bundling app, each target OS and the bundled engine version. Firmware that controls physical equipment, and a service that can operate that equipment (such as a bot that sends commands to home automation), declare tier T3, as [governance Section 3](../governance/review-audit.md#3-risk-tiers) requires.
*Check:* the README has a Targets section with these values; a project whose code or config drives equipment outputs, or sends commands to a system that does, declares T3.

### OTH-2
**Tier T1. MUST.** The project keeps a capability matrix in `docs/capability-matrix.md`, from [templates/capability-matrix.md](../templates/capability-matrix.md), that answers the four questions for each requirement against the declared runtime. For a webview app it has one column per target OS's webview. It is written before the architecture is chosen and rebuilt when a target or runtime version is added or changed, or when a feature needs a capability that is not yet a row in the matrix.
*Check:* the file exists with a date and sources; a PR that changes the README Targets section, or adds use of a platform capability with no matrix row, also updates it.

### OTH-3
**Tier T1. MUST.** The project does not weaken or disable a security mechanism its platform provides, to make a dependency work or simplify the implementation. In particular: firmware keeps the framework's network API encrypted wherever the API is used (for ESPHome, `api: encryption:`), and requires authentication for OTA updates wherever OTA is enabled (for ESPHome, an OTA password); a service authenticates every inbound webhook with the mechanism the sender offers (for Telegram, the `secret_token` set with `setWebhook`); an engine-bundling app keeps the engine's renderer isolation defaults (for Electron, `contextIsolation` and `sandbox` on, `nodeIntegration` off).
*Check:* for firmware and engine-bundling apps, a CI step reads the config and fails if any of these is off. For a service, a test sends a webhook request with a missing or wrong secret and expects it to be rejected. A PR that changes any of them is a review blocker without a Section 10 exception.

### OTH-4
**Tier T1. MUST.** Secrets (bot tokens, Wi-Fi passwords, API and encryption keys) are kept out of the repository and out of logs, and loaded from the environment or an untracked secrets file (for ESPHome, `secrets.yaml` listed in `.gitignore`).
*Check:* the secrets scan from [Section 5](../governance/review-audit.md#5-continuous-automated-checks) passes; the secrets file is ignored by git; the reviewer checks every new log statement under [Section 6](../governance/review-audit.md#6-code-review-every-change) item 5.

### OTH-5
**Tier T2. MUST.** `budgets.json`, valid against [templates/budgets.schema.json](../templates/budgets.schema.json), sets the thresholds that matter for the class: flash used and minimum free heap for firmware; memory and, where users wait on it, response time for a service; the `native` section for webview and engine-bundling apps. Metrics marked `"measuredWhere": "ci"` are measured in CI, as the median of the runs the file states, and CI fails when a value passes its threshold. Metrics that need real hardware are marked `"release-test"` and measured on the device before each release, with the result recorded in the release notes; a value past its threshold blocks the release unless it is excepted under Section 10. A PR that loosens a threshold states the reason in its description.
*Check:* the file validates; a CI job reads it and is required for merge; each release's notes record every `release-test` value, each within its threshold or excepted; a diff that raises a `max` or lowers a `min` has a stated reason in its PR.

### OTH-6
**Tier T1. MUST.** CI builds the project for its declared runtime: firmware is compiled from its config (for ESPHome, `esphome config` and `esphome compile`); a service's tests run on the declared runtime version; a webview or engine-bundling app meets [`NAT-8`](native.md#nat-8) from T2.
*Check:* the CI job exists and is required for merge.

### OTH-7
**Tier T3. MUST.** Firmware that controls physical equipment declares a safe state for each output, and goes to it on boot, on loss of network or controller connection, and on watchdog reset. The threat model records each output's safe state and failure modes.
*Check:* the threat model's Failure behavior section lists every output; the config's restore modes and its automations for lost connection (for ESPHome, `restore_mode` and `on_client_disconnected` or interval checks) match it; a test on a real board (cut the network, reboot) is recorded before each release.

### OTH-8
**Tier T2. MUST.** In a webview or engine-bundling app, the commands and APIs the shell or main process exposes to the UI are an explicit allowlist, scoped per window, and each is a trust boundary in the threat model. For Tauri this is the capabilities and permissions files; for Electron, the functions a preload script exposes through `contextBridge` and the `ipcMain` handlers they reach. No exposed function passes through a raw IPC channel, a Node module or a filesystem path chosen by the UI.
*Check:* the allowlist config or preload file exists and contains no wildcard grants or generic pass-through functions; every exposed command or handler appears in the threat model.

### OTH-9
**Tier T1. MUST.** Firmware meets [Section 5](../governance/review-audit.md#5-continuous-automated-checks) through these equivalents, which count as meeting it without a Section 10 exception. Other classes run Section 5 as written.

| Section 5 check | Firmware equivalent |
| --- | --- |
| Secrets in code and history | As written |
| Build, lint, formatting | `esphome config` (or the framework's config validation) and `esphome compile` (`OTH-6`) |
| Unit and integration tests | Unit tests for custom C/C++ code, if any. For YAML-only firmware: `esphome config` and `esphome compile` below T3, plus the release-time board test (`OTH-7`) at T3 |
| Known-vulnerable dependencies | The framework is pinned in a lockfile or requirements file that the vulnerability scanner reads (ESPHome is a Python package); external components are pinned to a commit and their advisories are checked at each release audit |
| Static security analysis | Runs on custom C/C++ code; not applicable to the YAML config |
| License compliance | The license field of each external component's dependency record |
| Software bill of materials | The framework version and each external component with its commit, listed in the release notes |
| Test coverage on changed lines | Not applicable to the YAML config |

*Check:* the firmware's CI and release notes show each equivalent; where the table says "not applicable", nothing further is needed.

### OTH-10
**Tier T3. SHOULD.** A service that sends commands to physical equipment fails closed: when it loses its connection to the device or the controller, or cannot confirm a command's result, it stops sending commands and reports the failure instead of retrying blindly. The threat model's Failure behavior section records what the service does in each case.
*Check:* the Failure behavior section covers the service; a test cuts the device connection and asserts that no further commands are sent.
