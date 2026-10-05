# Evidence-first web engineering

The reasoning behind building web software that uses what the browser platform actually provides, and adds only what it doesn't.

> **This is a guide, not the standard.** It explains why. The rules that reviews and audits check are in [standards/web.md](../standards/web.md) and [standards/dependencies.md](../standards/dependencies.md), and are cited by rule ID. Where this guide and a standard differ, the standard wins.

## What this is

This is the web companion to the [native guide](./native-rationale.md). Read that document first. The principles are the same. The platform is different, and the differences are large enough to need their own document.

The web is not another native platform. It has no install step, so size is paid per visit rather than once. Its platform is the browser, which is fragmented by rendering engine rather than operating system. Its failure mode is the npm dependency tree rather than the bundled runtime. And its measurement regime is Core Web Vitals on real networks rather than installed size and steady-state memory.

The core instinct is the same as the native document. A mature platform is a library of already-solved problems, and a small application is one that orchestrates those problems instead of reimplementing them. The browser is a mature platform. It provides more than most developers realize, and it has provided it consistently for years.

## Scope

This guide covers web applications and websites delivered over HTTP to a browser. It does not cover Electron apps, apps that render in a system webview, or anything that ships a browser engine; those are covered by [standards/other-targets.md](../standards/other-targets.md), which applies parts of the native and web standards to them. React Native and Flutter apps are native apps built with a framework that brings its own engine; they follow [standards/native.md](../standards/native.md).

This guide assumes the target is a browser, and the browser is the platform. Everything below follows from that.

## Universal principles

**Investigate the browser before bundling.** For every feature, ask what the browser platform provides. File picker, modal dialog, date picker, clipboard, notifications, storage, offline mode, camera, geolocation, fonts, text layout, form validation, animation, layout. Most of these have a browser API or an HTML element that already does the job. Find out before you import a library.

**Distinguish orchestration from implementation.** Calling `showModal()` on a `<dialog>` element is orchestration. Writing a modal library is implementation. The ratio of implement-to-orchestrate is what you want to minimize. On the web this ratio is often spectacularly bad, because the platform provides so much and developers reach for libraries anyway.

**Accessibility is the argument that ends most debates.** The browser's form controls, link elements, and landmark elements are the strongest accessibility default you can get: keyboard behavior, screen reader semantics, focus management, high-contrast compatibility, and assistive technology integration are built in. They are a default, not a guarantee. Native controls have known gaps; `<input type="date">` is the usual example, with inconsistent screen reader and keyboard behavior across browsers. Testing with real assistive technology is the actual rule. But a `<div>` with `role="button"` starts from nothing, and so does a custom date picker. Reaching for a library is often a way of avoiding the harder question of whether the platform element would work, and the cost is paid by users who depend on assistive technology. This applies even when the platform element is uglier or less flexible. ([`WEB-12`](../standards/web.md#web-12))

**Measure on the target.** Real devices, real networks, real users. Your development machine on fiber is not a target. Core Web Vitals, bundle size, parse time, and time to interactive. The numbers are per-visit, not per-install, and they matter more here than on native because the user pays them repeatedly.

**Measurement needs a decision rule, or it is trivia.** Before you start measuring, decide what counts as a regression. The thresholds go in the project's `budgets.json`, not in prose, so that CI can check them ([`WEB-15`](../standards/web.md#web-15), [schema](../templates/budgets.schema.json)). Pick thresholds that fit the project. A marketing site and a collaborative editor have different tolerances.

**Good code serves its constraints.** Duplication wins when the constraint is bundle size and the compressor cannot deduplicate. Abstraction wins when the constraint is maintainability. Neither is universal. The web frequently gets this backwards, adding abstraction to save bytes and adding bytes to save keystrokes.

**The dependency tree is the platform you are shipping.** A library is not a single thing. It is a tree of transitive dependencies, each with its own license, maintenance status, and supply chain risk. The npm ecosystem has demonstrated repeatedly that a single compromised package can affect millions of builds. Treat every dependency addition as a decision about the entire tree, not about the top-level package. That is why the transitive count is a required field in the [dependency record](../templates/dependency-record.md).

**Prefer in order, and justify each step.** The browser platform first. A small focused library second. A framework third. A meta-framework fourth. Each step needs a reason that the step below it cannot satisfy. This is not a rule about what is allowed. It is an ordering that forces the justification to be explicit.

**Do not weaken, bypass, or replace platform security mechanisms merely to eliminate a dependency or simplify implementation.** This means Content Security Policy, same-origin policy, HTTPS, subresource integrity, and browser sandboxing. Do not disable CSP to make a library work. Never add `'unsafe-inline'` or `'unsafe-eval'` to the CSP's script sources; if a script has to be inline, allow it with a nonce or a hash. Do not bypass the same-origin policy with a proxy when the API supports CORS. The platform's security model exists because the web is hostile territory, and working around it is how users get compromised. ([`WEB-6`](../standards/web.md#web-6), [`WEB-7`](../standards/web.md#web-7))

**If you publish an extension API, you are a platform, and this guide applies to you from the other side.** Reverse dependencies have the same cost structure as forward dependencies, except you cannot fix them yourself. Design extension APIs as though you will one day be the vendor whose stability you are currently pricing into your own decisions. The full section on this is below.

## What counts as platform-provided

The checkable version of this definition is [`WEB-3`](../standards/web.md#web-3).

Platform-provided on the web means functionality supplied by the browser's rendering engine and standard Web Platform APIs, available in every browser the application claims to support, with a documented fallback path for browsers that lack it.

Four constraints keep this definition from becoming a loophole.

The feature must be available in every browser the app claims to support, or have a graceful fallback. "Available in Chrome" is not "available in the browser platform." A feature that only works in Blink is not platform-provided if you claim to support Safari and Firefox.

The feature must be standardized or on a standards track. Vendor-specific APIs behind flags are not platform-provided. Origin trials are a preview, not a guarantee. The question is not "does this work in the newest Chrome" but "will this work in the browsers my users actually have, for the next several years."

The library must not ship its own rendering engine or virtual DOM that duplicates what the browser already does. React ships a runtime and a reconciliation layer. Preact ships a smaller one. Svelte compiles components at build time and ships a small runtime alongside them. These are different tradeoffs, and the runtime cost is paid on every first visit. A UI framework is not automatically forbidden, but it is not platform-provided either. It is a dependency that needs justification, and the justification is specific: the browser does not provide efficient state-to-DOM binding at scale, and writing that yourself is a security-sensitive job (see "A cost this approach imposes" below).

Vendor guidance has a churn rate, and you should weigh it. React was the answer. Then Next.js was the answer. Then Server Components were the answer. Then whatever the current recommendation is. Treat framework guidance the way the native document treats platform vendor guidance: as a signal that may be replaced within a few years, and price that risk into the decision.

**Graceful degradation is a fallback. A polyfill is an implementation.** This distinction matters because it is the exact place the definition above gets gamed. A fallback is code that detects a missing platform feature and does something simpler or lesser. A polyfill is code that implements the missing platform feature yourself and ships it to every user who lacks it. Under a careless reading, a polyfill makes any feature platform-provided, since you can always polyfill. That is not what this guide means. A polyfill is a dependency that happens to implement a web standard instead of a proprietary API, and it goes through the same dependency rule as any other ([`DEP-4`](../standards/dependencies.md#dep-4)). Prefer graceful degradation.

Under this definition, these are all legitimate platform facilities:

- HTML elements (`<dialog>`, `<details>`, `<input type="date">`, `<input type="file">`, `<video>`, `<canvas>`)
- CSS features (Grid, Flexbox, custom properties, container queries, `:has()`)
- Web APIs (Fetch, Clipboard, Notifications, Storage, IndexedDB, Service Workers, Web Animations, Web Crypto)
- Built-in accessibility on native elements
- Browser-provided form validation

The question is not "can I find an npm package for this." The question is "does the browser already provide this, in the browsers I support, with a fallback I can live with."

## The decision procedure

For every feature, for every target browser, answer four questions.

1. Does the browser platform provide this, in every browser the app claims to support, with a documented fallback for the ones that don't?
2. What is the missing functionality or limitation that prevents the browser feature from being sufficient?
3. What is the smallest library or custom implementation that closes the gap?
4. What is the full cost of that choice, and of replacing it later? Answer this one with the record in [standards/dependencies.md](../standards/dependencies.md).

Then weigh the answers against the project's actual constraints. How much state the app has. How many routes. Whether search engine visibility matters. Whether server rendering is required. Familiarity with the tools. Expected lifespan. A static marketing site and a collaborative document editor will reach very different conclusions from the same investigation.

When the browser provides ninety percent of what you need, use the browser feature and write the missing ten percent yourself. When the browser provides nothing and a library provides the whole thing, use the library and justify it in writing. When the browser provides the whole thing and you are importing a library out of habit, stop and use the browser feature.

## Build a capability matrix before choosing a stack

Before selecting a framework or a bundler, construct a capability matrix for each feature the app requires ([`WEB-1`](../standards/web.md#web-1), [template](../templates/capability-matrix.md)). Check current support at [caniuse.com](https://caniuse.com) or [MDN's browser compatibility tables](https://developer.mozilla.org/en-US/docs/Web) rather than trusting memory.

**Illustrative example only.** The cells below show the shape of a matrix. They were not checked when this guide was written and will drift; re-check every row against MDN or caniuse for your declared browsers.

| Requirement            | Blink (Chrome, Edge) | WebKit (Safari, iOS) | Gecko (Firefox) | Notes                             |
| ---------------------- | -------------------- | -------------------- | --------------- | --------------------------------- |
| File picker            | Yes                  | Yes                  | Yes             |                                   |
| File System Access     | Yes                  | Partial              | No              | Fallback required                 |
| Modal dialog           | Yes                  | Yes                  | Yes             |                                   |
| Popover API            | Yes                  | Yes                  | Yes             | Feature-detect for older versions |
| Native form validation | Yes                  | Yes                  | Yes             |                                   |
| Web Animations         | Yes                  | Yes                  | Yes             |                                   |
| View Transitions       | Yes                  | Partial              | Partial         | Fallback required                 |
| Container queries      | Yes                  | Yes                  | Yes             | Feature-detect for older versions |
| Storage (IndexedDB)    | Yes                  | Yes                  | Yes             |                                   |
| Service Workers        | Yes                  | Yes                  | Yes             | Feature-detect for older versions |
| WebGPU                 | Yes                  | Partial              | Partial         | Fallback required                 |

Do not choose the framework, the bundler, or the deployment model until this matrix exists.

The point is not the specific cells. Browser support changes. The point is that the architecture is an output of the investigation, not an input. You find out what the browsers give you, and the stack falls out of the gaps.

Rebuild the matrix per project.

## Browser and engine reality

The browser is the platform, and the browser is not one thing. It is three engines with different release cadences, different leadership, and different constraints.

**Blink (Chrome, Edge, Brave, Opera, and most Chromium derivatives).** Origin trials for experimental features. The largest market share, which means the ecosystem often assumes Blink behavior as the default. This is a trap. A feature that works in Chrome is not a web feature. It is a Chrome feature.

**WebKit (Safari on macOS, and effectively every browser on iOS).** Ships with the operating system. Historically slower to adopt new web platform features. More conservative about privacy and battery. Every browser distributed through the iOS App Store has used WebKit, including Chrome, Firefox, and Edge, so Safari compatibility has meant iOS compatibility for essentially every user. If your app does not work in Safari, assume it does not work on iOS.

**Gecko (Firefox).** Independent engine with strong standards adherence. Smaller market share. Occasionally the only engine that implements a feature correctly, and occasionally the last to ship something everyone else has. Worth testing on because it catches assumptions baked into Blink-only code.

> **Dated note (carried over from the original guide, not re-verified; check before relying on it).** Release cadence: Chrome ships a major release roughly every four weeks; Safari ships major releases roughly annually with the OS, with point releases between. iOS engines: since iOS 17.4, the EU's Digital Markets Act allows alternative browser engines on iOS in the EU; at the time the original guide was written this was described as not yet meaningful in practice.

The practical implications:

Test on all three engines. A CI pipeline that only runs headless Chromium is not testing the web. Use Playwright or similar to run the same suite against Blink, WebKit, and Gecko ([`WEB-5`](../standards/web.md#web-5)).

Treat Safari as a first-class target, not an afterthought. On iOS it has been the only engine in practice, and on macOS it has meaningful share. If your browser support matrix does not include Safari, your support matrix is a Chrome support matrix with extra steps.

Do not use a feature that is missing in any of your declared browsers without a fallback. Features arrive in the three engines at different times, and some newer APIs have stayed Blink-only for years; the File System Access API is a long-standing example. Others, such as the Popover API, have since shipped in all three engines but are still missing in older browser versions you may declare. Check the matrix, feature-detect, and do not assume ([`WEB-4`](../standards/web.md#web-4)).

## The dependency question

The npm ecosystem is the web's failure mode the way the bundled runtime is native's failure mode.

A single library can pull in a hundred transitive dependencies. Each is a supply chain risk, a maintenance burden, a potential security vulnerability, and a byte on the wire. The npm registry has demonstrated repeatedly that a compromised transitive dependency can affect millions of builds. Fewer dependencies and better review are the defense.

That does not make custom code automatically cheaper. The next sections show why: skipping a framework means owning HTML escaping, and replacing a library means owning whatever security-sensitive work it did. The honest comparison is total cost, both ways. The questions to answer, and the record that holds the answers, are in [standards/dependencies.md](../standards/dependencies.md); it is the single source for dependency criteria. On the web, take the transitive tree especially seriously: a library with 50 transitive dependencies is not a library, it is a small civilization.

## The framework question

Frameworks are not forbidden. They are also not platform-provided. They are dependencies, and they go through the dependency rule like everything else.

The decision is driven by the shape of the application, not by what is fashionable.

For a static site, a blog, or a marketing page, the browser and a build step may be all you need. Astro, Eleventy, or hand-written HTML with a CSS preprocessor. No runtime, minimal JavaScript, fast by default.

For a small interactive widget or a progressive enhancement on an existing page, a small library like Preact, lit, or Alpine.js may be the right call. Or htmx if the interaction is mostly server-driven. These ship a fraction of the runtime cost of a full framework and handle most cases.

For a real application with client-side state, routing, and a user session, a framework like React, Vue, Svelte, or Solid is a legitimate choice. Pick the one you know. The differences between them matter less than the differences between using one and not using one. Their baseline runtimes do differ, from a few kilobytes compressed for the smallest to tens of kilobytes for React with React DOM, but in a real application your own code and the libraries around the framework often outweigh the framework itself. Measure the built bundle rather than trusting published sizes.

For an application that needs server rendering, routing, data fetching, and a build pipeline, a meta-framework like Next.js, Nuxt, SvelteKit, Remix, or Astro is often the right answer. These bundle a lot, and the justification is that they replace a lot of custom code you would otherwise write yourself.

The key distinction is how much runtime the framework ships and when it runs. React ships a runtime that runs on every page load. Preact ships a much smaller one. Svelte and Solid compile components ahead of time and ship small runtimes. These are different tradeoffs, and the tradeoff matters more on the web than on native because it is paid on every visit.

The honest conclusion: for anything with meaningful client-side state, a framework is the expected endpoint. The browser provides declarative state management in the sense of custom elements and the platform's rendering model, but it does not provide efficient state-to-UI binding at scale, and writing that yourself is a security-sensitive job (see below). The framework question is not whether to use one, but which one and how much runtime you accept. Say that plainly instead of pretending the browser provides an alternative it doesn't.

Pick one. Do not pick two. A React app with a Vue component library inside it is a sign that someone lost an argument. ([`WEB-16`](../standards/web.md#web-16))

## Reverse dependencies, and when your app becomes a platform

The native guide has a [full section on this](./native-rationale.md#the-reverse-dependency). Read it. What follows is the web-specific part.

Every web app that ships an extension API, a plugin system, a userscript surface, or a theme format is publishing a platform. The moment someone writes code against it, the reverse dependency exists, and this guide applies to you from the other side.

The web has a unique failure mode here: the extension surface is usually JavaScript running in the same process as your app, with access to the same globals, the same network stack, and often the same origin. That is the in-process ecosystem shape, and it is the hardest form of lock-in. Browser extensions are the exception because the browser sandbox defines the boundary for you.

If you want to preserve the option of changing the implementation later, define the extension surface as a protocol or a sandboxed capability set. If you expose the DOM, the runtime, or your internal modules, you have chosen the in-process shape and you should say so in the README so future maintainers know what they are inheriting ([`WEB-17`](../standards/web.md#web-17)).

If your integrations are server-side, over HTTP APIs and webhooks, you are not locked to a client engine. Do not claim otherwise to justify a stack choice you would make anyway.

## Progressive web apps

The browser's answer to native application capabilities is the installable web app: a manifest, a service worker, and the platform's install and offline behaviors. These are platform facilities. Treat them the way you treat the rest of the browser platform.

A service worker is not a bundler. It is the browser's mechanism for offline behavior, background sync, and push notifications. If your app needs any of those, the service worker is the platform's answer and you should use it before reaching for a library.

Installability is a real capability with real limits. On iOS, installable web apps have historically had less capability than native apps and less than the same web app on Android. Notification support arrived late. Background execution is constrained. These limits are part of the matrix and should be in it, checked at the time you write it.

Do not treat the PWA as a replacement for a native app in every case. Treat it as the web platform's native-app story, evaluate it against the same four questions, and let the constraints of the project decide.

## Accessibility

The web platform's accessible elements are the strongest default you have. Use them.

Use `<button>` for buttons. Use `<a>` for links. Use `<input>` and `<label>` for form fields. Use `<dialog>` for modal dialogs. Use semantic landmarks (`<header>`, `<nav>`, `<main>`, `<aside>`, `<footer>`) for page structure. Use heading levels for hierarchy. Use `<details>` and `<summary>` for disclosures.

Each of these comes with built-in keyboard behavior, screen reader semantics, focus management, and browser-level accessibility integration. That is a strong default, not a guarantee: some native controls, `<input type="date">` most often, behave inconsistently with assistive technology across browsers. A `<div>` replacement, though, starts with none of it.

The specific trap: reach for a library that promises a "polished" custom control, then discover it is a `<div>` with ARIA roles and JavaScript event handlers, and it does not work with a screen reader, does not focus correctly, and does not respond to keyboard input. This is common. The library often replaces the platform element because the platform element "looks bad." The accessibility cost is invisible until someone complains, and by then it is expensive to fix.

Test with a screen reader. Test with keyboard only. Test at 200 percent zoom. Test with high-contrast mode. Test with `prefers-reduced-motion` enabled. Testing with real assistive technology is the rule, whether the control is native or custom. The standard makes this concrete: automated checks in CI ([`WEB-13`](../standards/web.md#web-13)) and the manual checklist before each release ([`WEB-14`](../standards/web.md#web-14)).

## Measurement

The measurement regime on the web is Core Web Vitals on real devices and real networks.

Largest Contentful Paint (LCP) measures loading. Interaction to Next Paint (INP) measures responsiveness. Cumulative Layout Shift (CLS) measures visual stability. Google publishes "good" thresholds for each at the 75th percentile, which also feed its search ranking signals. They are not laws of physics, but they are a useful starting point. The project's actual thresholds live in `budgets.json` ([`WEB-15`](../standards/web.md#web-15); the [example](../templates/budgets.example.json) starts from Google's published values).

INP needs real interactions, so a lab run that only loads the page cannot measure it. That is why the budgets split in two: lab metrics (LCP, CLS and Total Blocking Time, which tracks the main-thread work behind poor INP) gate every merge, and field metrics from real users, INP included, are compared at each release. A field breach becomes a finding to fix, not a blocked merge, because field data describes code that has already shipped.

Measure with real user monitoring, not just lab data. Lighthouse on your laptop is not the same as a mid-range Android phone on a slow network. Use the Chrome User Experience Report (CrUX) if your site has enough traffic. Use a synthetic testing service like WebPageTest or Calibre for controlled comparisons.

Bundle size matters. Every kilobyte of JavaScript is parsed, compiled, and executed on every first visit. Set the bundle budget per route or entry point in `budgets.json`, from a measurement of the project, and track it in CI. A pull request that pushes the bundle past its budget fails, and raising the budget is a reviewed change with a stated reason.

Measure on a mid-range Android device, not a high-end one. The median user's phone is slower than your development machine.

## A cost this approach imposes

The native guide has a section on testing cost. The web has a different one, and it is more serious.

If you skip the framework and write your own rendering, you own HTML escaping. This is the classic web security problem and it has bitten almost every project that has tried to roll its own templating. A single unescaped user-supplied string in an `innerHTML` assignment is a cross-site scripting vulnerability. Frameworks like React, Vue, and Angular escape text interpolation by default, which is one of the strongest arguments for using one.

That default covers text interpolation only. It does not cover the HTML sinks every framework still offers (`dangerouslySetInnerHTML` in React, `v-html` in Vue, `{@html}` in Svelte, Angular's `bypassSecurityTrust*`), and it does not cover URL attributes: a user-controlled `href` set to `javascript:...` runs script in every one of them. Those are where framework apps get XSS, and the standard treats each as a review blocker unless sanitized ([`WEB-9`](../standards/web.md#web-9), [`WEB-10`](../standards/web.md#web-10)).

The browser has its own XSS defenses, and they work with or without a framework. A strict Content Security Policy stops injected scripts from running even when escaping fails ([`WEB-7`](../standards/web.md#web-7), [`WEB-8`](../standards/web.md#web-8)). Trusted Types make the browser reject strings passed to HTML sinks unless they come from a policy you defined, which turns the sink audit from a search into an enforced rule ([`WEB-11`](../standards/web.md#web-11)).

This does not mean you must use a framework. It means the choice to skip one is a choice to own a security-sensitive job, and that job has a specific name, a specific failure mode, and a specific set of known mistakes. If you write your own templating, use `textContent` instead of `innerHTML` by default, sanitize with a maintained library when you must insert HTML, and audit every place you concatenate user data into markup.

The same reasoning applies to URL construction, redirect handling, and anything that parses user input. The framework is not just a convenience. It is often a security boundary you are choosing to build yourself.

Do not pretend this cost is zero. Budget for security review and a testing regime that exercises injection paths. If you cannot sustain that, the framework is not optional. It is the cheaper choice, and the preference ladder has to bend to that reality.

## Enforcement

Enforcement scales with the project's risk tier (T0 to T3 in [governance/review-audit.md Section 3](../governance/review-audit.md#3-risk-tiers)), not with team size. Each rule in [standards/web.md](../standards/web.md) and [standards/dependencies.md](../standards/dependencies.md) states its minimum tier and how it is checked.

In all cases the goal is the same. Make the investigation happen. Make the resulting decision visible. Make it possible to revisit later when the browser platform changes underneath you.

## Closing

The browser is the most widely deployed, most consistently updated, and most universally available platform in the world. It provides more than most developers realize. It has provided it for years, and it will continue to provide it for years.

The web's failure mode is not a bundled runtime. It is a dependency tree nobody audited, a `<div>` where a `<button>` belonged, a framework chosen because it was fashionable, and a bundle that grows every quarter without anyone noticing.

The approach is the same as the native document. Investigate the platform. Measure what you build. Let the constraints of the specific project decide the stack. On the web the platform is the browser, the constraints are different, and the discipline is the same.
