# Release audit: pass 2 (adversarial)

This is pass 2 of the same audit. The author's design rationale is now in the project directory: {{RATIONALE}}.
Read it.

Treat every claim in it as an assumption to break. For each assumption the design rests on:
1. Find conditions under which it is false.
2. Say what fails when it is false, and whether a standard rule or the threat model covers that failure.

Then revisit your pass 1 findings:
- which ones the rationale explains, with the reason, so they can be withdrawn;
- which ones still stand;
- what the rationale revealed that pass 1 missed (mark these NEW).

A rationale is an explanation, not an exception. A departure from a MUST stays a finding unless a written Section 10
exception covers it.

## Output
Your final message is the complete, updated audit report (same format as pass 1) and nothing else. Mark findings
that are new in pass 2 with [NEW], and list withdrawn pass 1 findings with the reason in a final section.
