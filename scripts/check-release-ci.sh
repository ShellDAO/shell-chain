#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "release CI check failed: $1" >&2
    exit 1
}

COMMIT="${1:-}"
if [[ ! "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    fail "expected a full 40-character commit SHA"
fi

GH_BIN="${GH_BIN:-gh}"
command -v "$GH_BIN" >/dev/null 2>&1 || fail "GitHub CLI is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

CHECK_RUNS_FILE=$(mktemp)
trap 'rm -f "$CHECK_RUNS_FILE"' EXIT

if ! "$GH_BIN" api \
    -H 'Accept: application/vnd.github+json' \
    "/repos/ShellDAO/shell-chain/commits/${COMMIT}/check-runs?filter=latest&per_page=100" \
    > "$CHECK_RUNS_FILE"; then
    fail "could not load hosted checks for ${COMMIT}"
fi

python3 - "$COMMIT" "$CHECK_RUNS_FILE" <<'PY'
import json
import sys

commit, path = sys.argv[1:]
required = (
    "Check & Lint",
    "Test",
    "Supply Chain Security",
    "Analyze (actions)",
    "Analyze (python)",
    "Analyze (rust)",
)

try:
    with open(path, encoding="utf-8") as source:
        payload = json.load(source)
except (OSError, json.JSONDecodeError) as error:
    print(f"release CI check failed: invalid check-run response: {error}", file=sys.stderr)
    raise SystemExit(1)

runs = payload.get("check_runs")
if not isinstance(runs, list):
    print("release CI check failed: response has no check_runs array", file=sys.stderr)
    raise SystemExit(1)

errors = []
for name in required:
    matches = [run for run in runs if run.get("name") == name]
    if not matches:
        errors.append(f"required check '{name}' is missing")
        continue
    for run in matches:
        if run.get("head_sha") != commit:
            errors.append(f"required check '{name}' is associated with another commit")
        app = run.get("app")
        owner = app.get("owner") if isinstance(app, dict) else None
        if (
            not isinstance(app, dict)
            or app.get("slug") != "github-actions"
            or not isinstance(owner, dict)
            or owner.get("login") != "github"
        ):
            errors.append(f"required check '{name}' is from an untrusted app")
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            errors.append(
                f"required check '{name}' has not succeeded "
                f"(status={run.get('status')}, conclusion={run.get('conclusion')})"
            )

if errors:
    for error in errors:
        print(f"release CI check failed: {error}", file=sys.stderr)
    raise SystemExit(1)

print(f"hosted release checks passed for {commit}")
PY
