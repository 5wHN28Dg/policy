#!/usr/bin/env bash
# Two-pass fresh-context AI audit (governance/review-audit.md Sections 7 and 11), run on your own machine.
#
#   tools/audit.sh [options] <project-dir>
#
#   -r, --rationale PATHS  space-separated paths holding the design rationale, hidden in pass 1 and shown in pass 2
#                          (default: "CLAUDE.md CLAUDE.local.md .claude docs/decisions")
#   -s, --scope TEXT       extra scope for the auditor, e.g. "the sync protocol and the relay"
#   -o, --out DIR          where the reports go (default: <project-dir>/../<name>-audit-<date>)
#   -m, --model MODEL      Claude model (default: your Claude Code default)
#       --pass1-only       stop after the blind pass
#
# The audit runs on a copy of the committed tree (git archive HEAD), so uncommitted work is not audited and the
# project is never modified. Both passes run in one new Claude Code session with customizations off (--safe-mode):
# pass 1 without the rationale, pass 2 resumed in the same session with it. Claude can only read files and run
# read-only git commands. Treat the result as leads, not findings: confirm each one before recording it.
set -euo pipefail

policy_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rationale="CLAUDE.md CLAUDE.local.md .claude docs/decisions"
scope="none"
out=""
model=()
pass1_only=false

while [[ $# -gt 0 ]]; do
  case $1 in
    -r|--rationale) rationale=$2; shift 2 ;;
    -s|--scope) scope=$2; shift 2 ;;
    -o|--out) out=$2; shift 2 ;;
    -m|--model) model=(--model "$2"); shift 2 ;;
    --pass1-only) pass1_only=true; shift ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) project=$1; shift ;;
  esac
done
[[ -n ${project:-} ]] || { echo "usage: tools/audit.sh [options] <project-dir>" >&2; exit 2; }
project=$(cd "$project" && pwd)
git -C "$project" rev-parse --is-inside-work-tree >/dev/null
command -v claude >/dev/null || { echo "claude (Claude Code) is not on PATH" >&2; exit 1; }

name=$(basename "$project")
commit=$(git -C "$project" rev-parse --short HEAD)
stamp=$(date +%Y-%m-%d)
out=${out:-"$(dirname "$project")/$name-audit-$stamp"}
mkdir -p "$out"
out=$(cd "$out" && pwd)

if [[ -n $(git -C "$project" status --porcelain) ]]; then
  echo "note: $name has uncommitted changes; the audit covers commit $commit only" >&2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/policy-audit.XXXXXX")
trap 'rm -rf "$work"' EXIT
git -C "$project" archive --format=tar HEAD | tar -x -C "$work"
hidden=()
for p in $rationale; do
  if [[ -e $work/$p ]]; then hidden+=("$p"); rm -rf -- "${work:?}/$p"; fi
done
echo "auditing $name at $commit in $work (hidden for pass 1: ${hidden[*]:-nothing})" >&2

render() {
  POLICY_DIR=$policy_dir COMMIT=$commit SCOPE=$scope RATIONALE="${hidden[*]:-none}" python3 -c '
import os, sys
text = open(sys.argv[1], encoding="utf-8").read()
for k in ("POLICY_DIR", "COMMIT", "SCOPE", "RATIONALE"):
    text = text.replace("{{" + k + "}}", os.environ[k])
print(text)' "$1"
}

tools="Read,Glob,Grep,Bash(git log:*),Bash(git diff:*),Bash(git show:*),Bash(git ls-files:*)"
common=(--print --safe-mode --permission-mode dontAsk --allowedTools "$tools" --add-dir "$policy_dir" "${model[@]}")

echo "pass 1 (blind)..." >&2
(cd "$work" && git init -q && git add -A && git -c user.name=audit -c user.email=audit@localhost commit -qm "audit snapshot of $commit")
(cd "$work" && claude "${common[@]}" --output-format json "$(render "$policy_dir/prompts/audit-blind.md")") > "$out/pass1.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); open(sys.argv[2],"w").write(d.get("result",""))' \
  "$out/pass1.json" "$out/pass1-blind.md"
session=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["session_id"])' "$out/pass1.json")
echo "pass 1 report: $out/pass1-blind.md (session $session)" >&2

if $pass1_only || [[ ${#hidden[@]} -eq 0 ]]; then
  [[ ${#hidden[@]} -eq 0 ]] && echo "no rationale paths found; skipping pass 2" >&2
  exit 0
fi

for p in "${hidden[@]}"; do
  mkdir -p "$work/$(dirname "$p")"
  git -C "$project" archive --format=tar HEAD -- "$p" | tar -x -C "$work"
done

echo "pass 2 (adversarial)..." >&2
(cd "$work" && claude "${common[@]}" --output-format json --resume "$session" \
  "$(render "$policy_dir/prompts/audit-adversarial.md")") > "$out/pass2.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); open(sys.argv[2],"w").write(d.get("result",""))' \
  "$out/pass2.json" "$out/pass2-adversarial.md"
echo "pass 2 report: $out/pass2-adversarial.md" >&2
