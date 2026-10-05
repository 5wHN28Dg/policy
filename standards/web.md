# Standard: web

Normative rules for web applications and websites delivered over HTTP to a browser. The reasoning is in [guides/web-rationale.md](../guides/web-rationale.md). Apps that ship their own browser engine, or render in a system webview, follow [other-targets.md](other-targets.md), which applies parts of this standard to their UI.

Also applies: [dependencies.md](dependencies.md) for every dependency, including frameworks and polyfills.

## How to read this standard

- **MUST**, **SHOULD** and **MAY** are used as in RFC 2119. A SHOULD that is not followed needs its reason written where the rule's check looks.
- **Tier** is the lowest risk tier ([governance/review-audit.md Section 3](../governance/review-audit.md#3-risk-tiers)) a rule applies to; it applies to every tier above as well. T0 projects are exempt.
- **Check** says what proves compliance. Reviews and audits cite rules by ID. A check applies at its rule's tier even where [Section 5](../governance/review-audit.md#5-continuous-automated-checks) does not require that kind of check for the tier.
- Solo T2 projects with no external users yet may defer `WEB-5`, `WEB-13` and `WEB-15` until full T2 applies; see [Section 11, Lighter T2 before users](../governance/review-audit.md#11-solo-developer-adaptations).
- A departure from a MUST is a finding, rated by impact under [Section 8](../governance/review-audit.md#8-findings-severity-and-deadlines). If it is still open at the next audit, it must be fixed or excepted before that audit's release decision, whatever its severity. Deliberate departures need a [Section 10](../governance/review-audit.md#10-exceptions-and-risk-acceptance) exception.
- This standard contains no browser support data. Support facts live in each project's capability matrix, checked against MDN or caniuse when it is written.

## Platform and support

### WEB-1
**Tier T1. MUST.** The project keeps a capability matrix in `docs/capability-matrix.md`, from [templates/capability-matrix.md](../templates/capability-matrix.md), with a check date, a source link for each row, and the browser list that `browserslist` resolves to at that date. It is written before the framework, bundler or deployment model is chosen, and rebuilt when the resolved browser list changes or a feature needs a capability that is not yet a row in the matrix. ([rationale](../guides/web-rationale.md#build-a-capability-matrix-before-choosing-a-stack))
*Check:* the file exists with a date and sources. For new projects, it is committed no later than the first framework or bundler dependency. CI resolves the browser list (for example `npx browserslist`) and fails if it differs from the list recorded in the matrix, which catches changes from a `caniuse-lite` update as well as edits to the query. A PR that adds use of a platform capability with no matrix row also updates the matrix.

### WEB-2
**Tier T1. MUST.** Supported browsers are declared in `browserslist` (a `.browserslistrc` file or the `browserslist` key in `package.json`), and the build tooling reads it.
*Check:* the declaration exists; the build config (transpiler, CSS tooling) does not override it with a different target list.

### WEB-3
**Tier T1. MUST.** A feature counts as platform-provided only if it is a standard Web Platform feature (HTML, CSS, or a Web API on a standards track) that is supported in every browser declared under `WEB-2`, or that has a fallback meeting `WEB-4`. Vendor-prefixed features, features behind flags, and origin trials are not platform-provided. Anything else is a dependency or custom code. ([rationale](../guides/web-rationale.md#what-counts-as-platform-provided))
*Check:* each matrix cell marked `provided` is backed by a source, cited in its row, showing support in that browser.

### WEB-4
**Tier T1. MUST.** Any feature not supported in every declared browser is feature-detected at run time, and its fallback is documented in the matrix's Gaps table. A polyfill instead of a fallback is a dependency under [DEP-4](dependencies.md#dep-4).
*Check:* each `partial` or `missing` cell in the matrix has a Gaps row; the code using the feature has a detection branch. On T2+, a test exercises the fallback path.

### WEB-5
**Tier T2. MUST.** The test suite runs in CI against all three engines (Chromium, WebKit, Gecko), for example with Playwright projects for each, and every engine's job is required for merge.
*Check:* the CI config has a job or matrix entry per engine, and branch protection lists them as required.

## Security

### WEB-6
**Tier T1. MUST.** The project does not weaken, bypass or disable a browser security mechanism to make a dependency work or to simplify the implementation. This covers Content Security Policy, the same-origin policy and CORS, HTTPS, subresource integrity, iframe sandboxing, and cookie security attributes.
*Check:* the PR description states whether the change alters any of these; a change that does is a review blocker without a Section 10 exception.

### WEB-7
**Tier T1. MUST.** No Content Security Policy the app serves contains `'unsafe-inline'` or `'unsafe-eval'` in any directive that governs scripts: `script-src`, `script-src-elem` and `script-src-attr`, and `default-src` whenever `script-src` is absent. Inline scripts are allowed only through nonces or hashes.
*Check:* CI or a test fetches the deployed or preview response headers and `<meta>` CSP and fails if either keyword is present. (Webview and engine-bundling apps read the CSP from where the app applies it; see [other-targets.md](other-targets.md#target-classes).)

### WEB-8
**Tier T2. MUST.** The app serves a CSP that restricts `script-src` (by nonce, hash, `'self'`, or an explicit list of hosts) and sets `object-src 'none'` and `base-uri`. No script directive allows `*` or a bare scheme such as `https:` or `data:`.
*Check:* the same header test as `WEB-7` asserts that these directives are present and that no script directive contains `*` or a scheme-only source.

### WEB-9
**Tier T1. MUST.** Text is inserted with `textContent` or framework text interpolation. HTML is inserted only after a maintained sanitizer has processed it. Every HTML sink (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc`) and every framework escape hatch (`dangerouslySetInnerHTML`, `v-html`, `{@html}`, Angular's `bypassSecurityTrust*`) is a review blocker unless its value comes from the sanitizer. ([rationale](../guides/web-rationale.md#a-cost-this-approach-imposes))
*Check:* a static-analysis rule (Semgrep or similar) flags each sink and escape hatch; every flagged site passes through the sanitizer or carries a Section 10 suppression.

### WEB-10
**Tier T1. MUST.** A URL that comes from user input or external data, used in `href`, `src`, `action`, `formaction`, `location`, or a redirect, is parsed and checked against an allowlist of schemes before use. `javascript:` and `data:` URLs from such sources are a review blocker.
*Check:* a static-analysis rule flags these assignments; each one routes through a URL validation helper that has unit tests for `javascript:` and `data:` input.

### WEB-11
**Tier T2. SHOULD.** Trusted Types are enforced (`require-trusted-types-for 'script'` in the CSP) where the capability matrix shows that the declared browsers support them.
*Check:* the CSP header test asserts the directive, or the PR or matrix records why not.

## Accessibility

### WEB-12
**Tier T1. MUST.** Controls use native HTML elements (`<button>`, `<a>`, `<input>` with `<label>`, `<select>`, `<dialog>`, `<details>`) by default. A custom replacement for a native control is merged only with keyboard-only and screen reader test evidence in the PR: which screen reader and browser, the steps, and the result. ([rationale](../guides/web-rationale.md#accessibility))
*Check:* a PR that adds an interactive element with an ARIA widget role (`role="button"`, `role="combobox"` and similar) or a click handler on a non-interactive element includes that evidence.

### WEB-13
**Tier T2. MUST.** Automated accessibility checks (axe or equivalent) run in CI against the main pages or components and fail the build on violations.
*Check:* the CI job exists and is required for merge.

### WEB-14
**Tier T2. MUST.** Before each release, a manual accessibility check is done and recorded: a screen reader, keyboard only, 200% zoom, a high-contrast or forced-colors mode, and `prefers-reduced-motion`.
*Check:* the release notes or `docs/accessibility-checks.md` hold a dated entry for the version, with the tool and result for each of the five items.

## Performance and structure

### WEB-15
**Tier T2. MUST.** `budgets.json`, valid against [templates/budgets.schema.json](../templates/budgets.schema.json), sets thresholds in its `web` section for bundle size and for lab metrics (LCP, CLS and Total Blocking Time, measured in a stated device and network profile). CI takes the median of the number of runs the file states, and fails when a value passes its threshold. Where the app has real-user data, the `field` thresholds (including INP, which lab runs cannot measure) are compared at each release, and a breach is recorded as a finding rather than blocking a merge. A PR that loosens a threshold states the reason in its description. ([rationale](../guides/web-rationale.md#measurement))
*Check:* the file validates against the schema; a CI job reads it and is required for merge; each release audit or release note records the field values against their thresholds; a diff that raises a threshold has a stated reason in its PR.

### WEB-16
**Tier T1. MUST.** An app uses at most one UI framework. ([rationale](../guides/web-rationale.md#the-framework-question))
*Check:* the manifest lists at most one UI framework or component runtime (React, Vue, Svelte, Solid, Angular, Preact, Lit and similar), counting component libraries that bring their own.

### WEB-17
**Tier T1. MUST.** If the app exposes an extension, plugin, userscript or theme API, the README declares its shape: in-process (extensions run with the app's globals, DOM or origin), protocol, or sandboxed. A change from one shape to another is a breaking change and is called out in the release notes. ([rationale](../guides/web-rationale.md#reverse-dependencies-and-when-your-app-becomes-a-platform))
*Check:* the README has an Extension API section when one exists; on T2+, the extension point is also a trust boundary in the threat model.
