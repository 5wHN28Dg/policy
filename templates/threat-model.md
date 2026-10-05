# Threat model: <project>
Tier: <T1/T2/T3>   Last reviewed: <date>   Reviewer: <name>

## Assets
- <what must be protected and why>

## Actors
| Actor | Trusted? | Allowed to |
| --- | --- | --- |

## Data flow and trust boundaries
<diagram or list: entry points, stores, external services>

## Threats and mitigations
| Boundary | Threat | Mitigation | Status |
| --- | --- | --- | --- |

## Failure behavior
Required for firmware and services that control equipment (OTH-7, OTH-10); write "not applicable" otherwise.

| Output or command | Safe state | On boot | On lost connection | On watchdog reset or crash | Failure modes |
| --- | --- | --- | --- | --- | --- |

## Out of scope
- <what this project does not defend against>
