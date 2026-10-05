# Dependency record: <package> <version>

Write this in the pull request description, or copy it to `docs/dependencies/<package>.md`. Required by `DEP-2` in [standards/dependencies.md](../standards/dependencies.md). Every field must be filled in; write "none" or "not applicable" rather than leaving one blank.

Added: <date>   Pull request: <link>   Recorded by: <name>
Kind: <runtime / build-time / dev-only / polyfill>
Packages covered: <this package only, or, for a grouped record of dev-only packages from one source (DEP-2), every package by name>

## Purpose
<What this dependency does for the project, in one or two sentences.>

## Platform alternative checked
<What the platform provides for this (link to the capability matrix row), and why it falls short. "None exists" is an answer, with the source you checked.>

## Custom implementation considered
<What writing the missing part yourself would take, including any security-sensitive work it would mean owning (escaping, parsing, crypto, auth). Why that costs more than this dependency.>

## Transitive dependencies
Count: <number of packages this adds to the lockfile>   How counted: <command, e.g. `npm ls --all <package>`, `cargo tree -p <package>`>

## License
<SPDX identifier of the package, and of any transitive license that the license policy marks "review-needed".>

## Maintenance signals
Evidence to weigh, not a pass/fail gate.

- Recent releases: <date of last release; release cadence>
- Security response: <link to a security policy, advisories, or past CVE fixes and how fast they shipped; "none found" if so>
- Active maintainers: <number, and who>
- Age across major versions: <first release; major versions survived>

## Size impact
<Bundle bytes compressed, installed size, or firmware flash/RAM added, measured; "none (dev-only)" for tools that never ship.>

## Replacement cost
<What removing or replacing it later would take: how many call sites, whether it shapes the architecture, whether data or formats depend on it.>

## Decision
<Why, on total cost, this beats the platform and a custom implementation (DEP-1).>
