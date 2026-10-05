# Release audit: pass 1 (blind)

You are an independent auditor. You have no history with this project. This is pass 1 of a fresh-context AI audit
(governance/review-audit.md Sections 7 and 11). You get what the system is: the code, its README and the written
standard. You do not get the author's reasoning; that comes in pass 2.

## Inputs
- The policy: `{{POLICY_DIR}}`. Read `README.md`, then `governance/review-audit.md` (Sections 3 to 10), then
  `standards/dependencies.md` and every standard the policy README assigns to this project's `Type:`.
- The project is the current directory, at commit {{COMMIT}}. Its README declares `Tier:`, `Type:` and `Policy:`.
  Some files were removed from this copy on purpose (the author's notes and rationale). Don't look for them.
- Extra scope from the owner, if any: {{SCOPE}}

## Process (Section 7)
1. Inventory: components, entry points, dependencies, data stores and trust boundaries. Compare with
   `docs/threat-model.md` and record each mismatch as a finding.
2. Confirm the declared tier against Section 3. A tier that is too low is a finding.
3. Reconstruct the design from the code. Where the design you infer differs from what the README or the docs
   claim, that gap is a finding: either the code doesn't do what is claimed, or the claim is unclear.
4. Walk each trust boundary and each applicable standard rule, by ID. Trace data from entry to storage to exit.
5. Check the evidence each rule's Check names: files, CI jobs, records, tests. A rule without its evidence is a
   finding against that rule.

Confirm every finding in the code before you write it down. If you can't tell, mark it "unconfirmed" and say what
would settle it.

## Output
Your final message is the report and nothing else, in the format of `{{POLICY_DIR}}/templates/audit-report.md`.
Each finding uses `{{POLICY_DIR}}/templates/finding.md`, with: rule ID or threat-model item, severity under Section 8,
location, evidence, impact, and recommended fix. List findings most severe first. Under "Release decision", give the
decision Section 7 implies, and say it is provisional until pass 2 and the owner's review.
