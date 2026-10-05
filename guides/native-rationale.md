# Evidence-first platform engineering

The reasoning behind building software that uses what the target platform actually provides, and adds only what it doesn't.

> **This is a guide, not the standard.** It explains why. The rules that reviews and audits check are in [standards/native.md](../standards/native.md) and [standards/dependencies.md](../standards/dependencies.md), and are cited by rule ID. Where this guide and a standard differ, the standard wins.

## What this is

Most software ships more than it needs. A text editor that carries a browser engine. A utility that bundles a runtime the operating system already has. A tool that reimplements a file picker, a print dialog, a font renderer, because nobody checked whether the platform provides one.

This guide describes a procedure for avoiding that. It is not a rule about what counts as native. It is not a size budget. It is a set of questions to ask before building or importing anything, a set of platform-specific facts you need in order to answer those questions honestly, and the reasons behind the enforcement in the standards.

The core instinct comes from [Dave Plummer's 2.6K Notepad video](https://www.youtube.com/watch?v=OG91c7xsNMc), where he builds a working Windows text editor in about 2.6 KB by leaning on Win32 as hard as possible. The lesson this guide takes from it is not that small is good. It is that a mature platform is a library of already-solved problems, and a small application is one that orchestrates those problems instead of reimplementing them. The video frames its byte budget as an experiment, not a target for real software, which still needs maintainability, tests, diagnostics, accessibility, localization, and security hardening. This guide takes both halves of that seriously. Nothing in the standards rests on the video; it is the inspiration, not the evidence.

## Scope

This guide covers native desktop and mobile applications. The web browser is out of scope. The browser is its own platform with its own rules, and the tradeoffs there (download size vs. install size, session lifetime vs. persistent state, cross-browser compatibility vs. single-vendor APIs) are different enough to need their own document. See the [web guide](./web-rationale.md) for the companion. If you are building a web app, treat the browser as a platform in the sense of this guide's definition, but do not import the specific platform notes below. Apps that render in a system webview or bundle a browser engine are covered by [standards/other-targets.md](../standards/other-targets.md).

## Universal principles

These apply on every platform.

**Investigate before implementing or bundling.** For every feature, ask what the target platform provides through documented, supported interfaces. File picker, print dialog, font renderer, text surface, notification system, credential store, background scheduler. Most platforms have some version of these. Find out before you write or import one.

**Distinguish orchestration from implementation.** Wiring your app to the platform's file picker is orchestration. Writing a file picker is implementation. The ratio of implement-to-orchestrate is the thing you want to minimize. That ratio depends entirely on what the platform provides, and it varies across operating systems.

**Accessibility is the argument that ends most debates.** Platform primitives are the strongest starting point for accessibility you can get: screen reader support, keyboard navigation, high-contrast modes, focus management, input method support, and assistive technology integration are built in and maintained by the vendor. They are not a guarantee. Native controls have known gaps, and which gaps varies by platform and version, so testing with real assistive technology is the actual rule. But a custom text renderer or file picker starts from nothing. It does not just cost bytes. It costs the entire accessibility stack, and retrofitting that later is far more expensive than using the platform's widget from the start. When someone proposes reimplementing a platform control to save a dependency or match a design, the accessibility cost is the first question, not the last. This applies even when the platform control is uglier or less flexible than the custom version. ([`NAT-4`](../standards/native.md#nat-4); the release-time check is [`NAT-10`](../standards/native.md#nat-10).)

**Measure on the target.** Installed size, memory, startup time, battery draw, package size, disk footprint after updates. Measure on a clean device without development tools. The build-measure-rebuild loop from the video is the method. The numbers differ per platform. The discipline does not.

**Measurement needs a decision rule, or it is trivia.** Before you start measuring, decide what counts as a regression. The thresholds go in the project's `budgets.json`, not in prose, so that CI can check them ([`NAT-7`](../standards/native.md#nat-7), [schema](../templates/budgets.schema.json)). Pick thresholds that fit the project. A text editor and a video editor have different tolerances. The point is to have a number that forces a conversation when it is crossed, not to have the perfect number.

**Good code serves its constraints.** Copy-paste wins when the constraint is compressed size. Abstraction wins when the constraint is maintainability. Neither is universal. A byte-budget experiment is a science experiment with a sharp object, not an architecture to copy into production code.

**Do not treat defaults as laws of physics.** Linker output, framework choice, deployment model. All negotiable. Question them.

**Do not weaken, bypass, or replace platform security mechanisms merely to eliminate a dependency or simplify implementation.** The principle is not "never implement security yourself." Sometimes the platform does not provide the mechanism you need and you have to add one. The principle is: do not work around the platform's security boundary just because working with it is inconvenient. ([`NAT-5`](../standards/native.md#nat-5))

**If you publish an extension API, you are a platform, and this guide applies to you from the other side.** Reverse dependencies have the same cost structure as forward dependencies, except you cannot fix them yourself. Design extension APIs as though you will one day be the vendor whose stability you are currently pricing into your own decisions. The full section on this comes later.

## Dependencies

Dependencies are not free, and they are not automatically worse than your own code either. A well-maintained library like SQLite or libcurl often has fewer bugs and better security than a custom implementation built on platform primitives, because it has had more eyes and more years. So the comparison is always total cost, not provenance.

The policy therefore takes no stance either way and asks for an honest written comparison instead. The criteria, and the record that holds the comparison, are in [standards/dependencies.md](../standards/dependencies.md); this guide does not restate them.

## What counts as platform-provided

This definition matters more than any other part of the guide, because it decides what you are allowed to use without justification. The checkable version is [`NAT-1`](../standards/native.md#nat-1).

Platform-provided means functionality supplied through the vendor's supported platform stack for the application's declared target versions, whether that capability resides in the OS, a system framework, or a vendor-supported SDK or library.

Four constraints keep this definition from becoming a loophole.

The capability must be vendor-supported for application development, not merely available on the device or published by the vendor for some other purpose. Google Play Services is vendor-published and vendor-supported, but it is an optional dependency with its own availability constraints, not a guaranteed part of the Android development model.

The capability must be appropriate for the application's declared target versions. A library that only works on the newest OS version is not platform-provided if you claim to support older versions.

The capability must not carry its own runtime that duplicates something the platform already guarantees. A UI toolkit that ships as a library and depends only on the framework is platform-provided. A UI toolkit that ships a JavaScript engine, a rendering engine, and an IPC layer to run on top of the framework is not, because it is supplying its own platform.

Vendor guidance has a churn rate, and you should weigh it. Google moved Android's recommended UI toolkit from the View system to Jetpack Compose, and deprecated once-recommended APIs such as `AsyncTask`. Microsoft pushed UWP hard and then walked it back toward WinUI 3 and the Windows App SDK. Apple pushed Catalyst and later SwiftUI. Vendor guidance is a signal, not a mandate. Prefer guidance that has survived at least one major OS release, and give more weight the longer it has lasted. Treat newly announced frameworks with the assumption that they may be replaced within five years, and price that risk into the decision.

Under this definition, these are all legitimate platform facilities:

- Win32, WinUI 3, and the Windows App SDK on Windows
- AppKit and SwiftUI on macOS
- The Android framework APIs and Jetpack, including Compose, where appropriate
- UIKit and SwiftUI on iOS
- GTK, Qt, portals, and D-Bus as the relevant Linux desktop stack, when that stack is explicitly the target

This definition also stops the guide from becoming absurdly literal about where the bytes physically reside. Compose is not in the Android system image. It is still part of Android's supported development model. WinUI 3 ships a runtime. It is still Microsoft's recommended path for new Windows desktop applications. SwiftUI is bundled with the OS. It is still a moving target whose API surface changes yearly.

The question is not "where does this code live." The question is "is this part of how the vendor expects you to build for this platform, and has that expectation survived long enough to trust."

## The decision procedure

For every feature, for every target platform, answer four questions.

1. What does the platform provide directly, through documented and supported interfaces, under the definition above?
2. What does it provide through optional components, and how reliably are those present on the target systems?
3. What is genuinely missing?
4. For what is missing, is a small custom implementation maintainable, or is a well-maintained dependency the smaller total cost? Answer this one with the record in [standards/dependencies.md](../standards/dependencies.md).

Then weigh the answers against the project's actual constraints. Number of target platforms. How much the interface needs to differ per platform to feel correct. How long the software has to live. How often the platform breaks its own APIs. How much maintenance capacity there is. A solo developer shipping a Windows utility and a five-person team shipping on five platforms will reach different conclusions from the same investigation.

When a platform vendor's own guidance points to a library as the expected development model, treat that library as part of the platform's model, not as an external dependency to be justified away. Compose on Android and SwiftUI on iOS are not deviations from the platform. They are the platform's current answer, even though they ship inside your package.

## Build a capability matrix before choosing architecture

Before selecting an architecture, construct a capability matrix for each target platform ([`NAT-3`](../standards/native.md#nat-3), [template](../templates/capability-matrix.md)). This forces the investigation to happen before the design, not after.

**Example only.** The cells below illustrate the shape of a matrix. They are not checked data; build your own from current vendor documentation.

| Requirement        | Windows                    | macOS    | Linux/GNOME                | Android                | iOS               |
| ------------------ | -------------------------- | -------- | -------------------------- | ---------------------- | ----------------- |
| File picker        | Native                     | Native   | Portal/toolkit             | System document picker | UIDocumentPicker  |
| Clipboard          | Native                     | Native   | Toolkit/display stack      | Framework              | UIKit             |
| Notifications      | Native                     | Native   | Desktop notification stack | Framework              | UserNotifications |
| Secure credentials | Credential Manager / DPAPI | Keychain | Secret Service/portal/etc. | Keystore               | Keychain          |
| Printing           | Native                     | AppKit   | Desktop/portal stack       | Print framework        | AirPrint          |
| Background tasks   | Task Scheduler / Services  | Launchd  | systemd user units         | WorkManager            | BGTaskScheduler   |

Do not choose the shared architecture until this matrix exists.

The point is not the specific cells. Those go stale. The point is that the architecture becomes an output of investigation rather than an input. You find out what each platform gives you, and the design falls out of the gaps.

Rebuild the matrix per project. A snapshot from last year is not evidence.

## Platform-specific reality

These notes are background for the investigation, not a substitute for it. They describe the platforms as the original guide found them; check the current vendor documentation before relying on any detail.

### Windows

Win32 is a stable C ABI that Microsoft has refused to break for three decades. CreateWindowEx, the common dialogs, the edit and rich edit controls, the printer subsystem, the message pump. All present, all documented, all backward compatible. A small native program can call into this machinery and behave like a real application. The 2.6K Notepad is possible because of this stability.

Modern Microsoft guidance points to WinUI 3 through the Windows App SDK for new desktop applications. The Windows App SDK can be deployed framework-dependently, sharing an installed runtime, or self-contained, where the application carries its dependencies. Microsoft treats the framework-dependent model as the default and intends it to reduce deployment size and allow the framework to be serviced independently. Win32 remains an older and exceptionally stable foundation.

This is a deployment and architectural tradeoff, not a question of whether one approach is native. Do not reject WinUI merely because it is not a 2.6 KB executable.

### macOS

AppKit is the mature framework. Stable, documented, ships with the OS. Foundation provides the non-UI plumbing. For a text editor, NSTextView is the rich edit control equivalent, plus the standard file dialogs, font panels, print panels, and menu bar integration.

SwiftUI is Apple's current push. It ships with the OS since macOS 10.15, so it is not a bundled library in the Android sense. But its API surface changes every year, and Apple deprecates and replaces pieces of it on a schedule.

Weighing SwiftUI against AppKit is a real decision, not a foregone conclusion. Use SwiftUI when the expected lifespan of the app is short to medium, when most of the UI is standard controls and system patterns, and when you can absorb per-OS-version rework. Use AppKit when the app has a long expected lifespan, when the UI is heavily custom, or when you cannot afford to chase annual API changes. A hybrid is common and legitimate. SwiftUI for new screens, AppKit for the parts that need to be stable across a decade.

Universal binaries matter. Code signing and notarization are mandatory for distribution. The Mac App Store adds sandboxing constraints. Measure memory and energy, not just disk size.

### Linux

There is no single OS-provided GUI stack comparable to Win32, AppKit, UIKit, or the Android framework. The effective platform is usually the kernel plus a chosen desktop environment, toolkit, and system stack.

The kernel provides DRM/KMS for display hardware access and evdev for input devices. Wayland and X11 are display protocols, not toolkits. The client libraries for those protocols, libwayland-client and Xlib, give you a surface and a way to draw on it. They do not give you a button, a text field, a file dialog, a font renderer, or a menu.

GTK and Qt are userland libraries. They ship with some distributions and not others. GTK4 and GTK3 are different toolkits with different rendering models. Native on Linux means whatever the desktop environment happens to use, which varies. Flatpak and AppImage exist because the dependency situation is fragmented.

The Linux platform is a stack: kernel, display and input protocols, desktop environment, toolkit, application. GNOME, KDE, wlroots-based environments, X11, Wayland, GTK, Qt, portals, D-Bus, and systemd live at different layers with different scopes. For a GNOME application, GTK may effectively be part of the target platform. For a KDE application, Qt may be. For a deliberately environment-agnostic application, you may choose something else.

This makes Linux the best stress test for the approach. It does not say "use the OS." It says determine what the actual target platform provides. On Linux that answer is a stack, not a monolith, and you have to name the stack explicitly ([`NAT-1`](../standards/native.md#nat-1), [`NAT-2`](../standards/native.md#nat-2)).

System integration that does exist and should be used: D-Bus for interprocess communication, portals for sandboxed file access and printing through the desktop environment, systemd user units for service management where applicable. These are real platform facilities. The GUI layer is not, unless your chosen toolkit is treated as the platform.

### Android

The Android framework provides a UI toolkit, system services, and intents. The View system (android.view, android.widget) ships in the system image. Button, TextView, EditText are framework classes. System intents open the document picker, the print dialog, the share sheet. Notifications, clipboard, and background scheduling are framework APIs. That is orchestration, and the platform provides it.

The framework is tied to API levels and fragmented across devices and OEM customizations. AndroidX exists partly to provide APIs and behavior independently of the platform release cycle, including backward-compatible functionality. Google's recommended UI toolkit is now Jetpack Compose, which is not in the system image. It is a set of AndroidX libraries that you bundle in your APK. The Android developer documentation describes the platform as Compose-first.

The NDK does not provide a UI toolkit. There is no native widget system in C or C++. NativeActivity is a wrapper that still expects you to call Java methods for UI.

On Android, use the platform's orchestration surfaces directly: intents, services, permissions, lifecycle. Use Compose for the UI layer. Compose is not violating this approach merely because it is packaged into the APK. It is part of Android's current supported development model.

### iOS and iPadOS

UIKit is stable and ships with the OS. It provides the view hierarchy, text controls, navigation, and the standard system integration points. SwiftUI ships with the OS and is Apple's current push, but its API surface changes yearly, and Apple regularly replaces pieces of it. UIKit remains the mature, stable choice for complex interfaces. SwiftUI is the right choice for simpler interfaces where Apple's direction matters more than API stability.

The same rubric that applies on macOS applies here. SwiftUI for short-to-medium lifespan apps dominated by standard controls. UIKit for long-lived apps with heavily custom UI. Hybrid is fine.

App Store rules constrain what you can bundle and how you update. Memory and battery constraints are stricter than on desktop. Code size matters less than runtime memory. The platform provides strong system integration: document picker, share sheet, notifications, credential storage, background tasks. Use those directly.

## A cost this approach imposes

Orchestration-heavy code can be harder to unit test than self-contained code. When business logic lives inside platform callbacks, you cannot run those callbacks in a test harness without the platform. This is a real tradeoff, not a minor nuisance.

Mitigate it by keeping business logic in pure functions and platform-independent modules, and treating the platform integration layer as a thin adapter that gets tested on the platform, not in isolation ([`NAT-6`](../standards/native.md#nat-6)). If a piece of logic is hard to test because it is tangled with platform callbacks, that is a signal to separate it, not a reason to abandon the approach.

Do not pretend this cost is zero. Budget time for integration tests and platform-specific test infrastructure. On mobile, budget for device farms. On desktop, budget for CI runners on each target OS ([`NAT-8`](../standards/native.md#nat-8)).

## The reverse dependency

Everything above assumes the dependency arrow points inward. You depend on the platform. You depend on libraries. You audit both, and you can swap them when they stop being good.

An extension API inverts the arrow. Third parties depend on you. You publish an interface, other people write code against it, and the moment their code ships, your internals become a public contract. You can no longer audit, upgrade, or remove the things that depend on you. Breaking them has the same cost as breaking a forward dependency, except you cannot fix it yourself.

This is the same problem the guide already tells you to weigh, pointed the other way. The guide says to treat platform API stability as a cost and prefer guidance that has survived at least one major OS release. When you publish an extension API, you become the vendor whose stability someone else is pricing into their decision.

Design the API as though you will one day be the vendor whose stability you are currently complaining about, because the moment it achieves adoption, you are.

The choice is not made at rewrite time. It is made at API-publish time. When you design an extension API, you decide, usually without realizing it, whether it exposes your implementation or abstracts it. That decision is often a one-way door. That is why [`NAT-9`](../standards/native.md#nat-9) requires the shape to be declared.

**In-process ecosystems** run extensions inside the host, against the runtime and the DOM. VS Code's extension host exposes Node. Obsidian's plugins run against the app's internals and the DOM. The API surface is the implementation. A native rewrite genuinely breaks them, because maintaining the API would mean shipping the runtime. This is the hardest form of lock-in, and it is nearly irreversible once adoption is meaningful.

**Protocol ecosystems** run integrations server-side, over HTTP APIs, webhooks, or a documented protocol. Slack's app directory is this shape. The apps do not care what engine the client uses. Slack could rewrite its client in AppKit tomorrow without breaking a single app. The lock-in here is contractual and commercial, not architectural. The client engine remains a free choice.

**Sandboxed, language-neutral ecosystems** sit in between. A plugin runs in a defined sandbox with a documented capability surface. The host can change implementation as long as the sandbox contract holds. This is the shape that keeps the rewrite option alive, and it is rare because it is more work to design up front.

The practical rule: if your ecosystem is in-process, the client engine is no longer a technical choice. If your ecosystem is protocol-based, the engine is still yours to choose, and "our ecosystem forces us to bundle a browser" is not a real constraint. Be honest about which one you have.

One counterexample is worth naming. Firefox's XUL extensions were in-process and deeply coupled to the browser's internals. Mozilla broke them anyway with the WebExtensions migration, and it worked, but only because the migration target had its own gravity. Chrome's extension API existed, was widely adopted, and enough of the ecosystem could port. You do not get to count on that condition. It is the exception, not the pattern.

## Enforcement

Enforcement scales with the project's risk tier (T0 to T3 in [governance/review-audit.md Section 3](../governance/review-audit.md#3-risk-tiers)), not with team size. Each rule in [standards/native.md](../standards/native.md) and [standards/dependencies.md](../standards/dependencies.md) states its minimum tier and how it is checked.

In all cases, the goal is the same. Make the investigation happen. Make the resulting decision visible. Make it possible to revisit later when the platform changes underneath you.

## Closing

The original instinct behind this guide was correct. Reuse the platform. Do not bundle a duplicate civilization. But the platform is not always a coherent thing with a single native stack, and what it provides varies enormously across operating systems. Windows has a stable C ABI for UI. macOS has two frameworks with different lifetimes. Linux has no single OS-provided GUI stack at all. Android and iOS each have a stable option and a moving option, and their vendors push you toward the moving one.

So the approach cannot be "reuse the OS." It has to be: investigate the platform, measure what you build, and let the constraints of the specific project decide the architecture. The investigation method comes from the video. The answer depends on which operating system you are standing on.
