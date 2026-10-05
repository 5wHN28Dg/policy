# Capability matrix: <project>

Copy to `docs/capability-matrix.md`. Required by `NAT-3`, `WEB-1` and `OTH-2`.

Checked: <date>   Checked by: <name or method>
Declared targets: <OS versions from the README, or runtime/board versions>
Sources: <MDN, caniuse, vendor docs, with links; memory is not a source>

Resolved browser list (web only): the output of `npx browserslist` on the check date. CI compares it with the current output in both directions (WEB-1).

```
<one browser and version per line, e.g. chrome 140>
```

Write this before choosing the stack or architecture. Rebuild it, with a new date, when a target is added or changed (a browser in the resolved list, an OS, an OS version range, a board, a runtime version), or when a feature needs a capability that is not yet a row.

## Matrix

One row per requirement. One column per declared target (browser engine, OS or runtime). In each target cell write one of: `provided`, `optional` (present only with an optional component; say which), `partial`, `missing`.

- **Facility:** the platform facility that provides it (for example `<dialog>`, `UIDocumentPickerViewController`, WorkManager, the ESPHome `switch` component). Required for every row with a `provided` cell (`NAT-1`, `WEB-3`, `OTH-0`). If the facility differs per target, name one per target (`iOS: UIDocumentPickerViewController; Android: Storage Access Framework`).
- **Established (native, and the shell of webview and engine-bundling apps):** whether the facility has been the vendor's documented path through at least one major OS release; if not, write `new` and the churn risk (`NAT-1` test 4).

| Requirement | Facility | <target 1> | <target 2> | <target 3> | Established | Source | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| <e.g. file picker> | <facility> | | | | <yes / new: risk> | <link> | <platform / fallback / custom / dependency> |

## Gaps

For every cell that is not `provided`:

| Requirement | Target | Gap | Decision | Fallback or dependency |
| --- | --- | --- | --- | --- |
| <requirement> | <target> | <what is missing> | <graceful fallback / custom code / dependency> | <how the fallback works, or a link to the dependency record> |

## Resulting architecture

<Two or three sentences: what the matrix led you to choose, and why.>
