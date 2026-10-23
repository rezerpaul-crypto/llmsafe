#!/usr/bin/env bash
# Local validation of the current checkout. Does not fetch, switch, commit, or push.
set -euo pipefail
task_root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$task_root"
task_check_only=0
case "${1:-}" in
  "") ;;
  --check-only) task_check_only=1 ;;
  --help|-h)
    printf '%s\n' 'Usage: bash scripts/mac-research-check.sh [--check-only]'
    printf '%s\n' 'First run installs the existing project dev dependencies into .venv.'
    printf '%s\n' 'Set LLMSAFE_PYTHON to an existing Python 3.12-3.14 executable if needed.'
    exit 0 ;;
  *) printf '%s\n' 'Unknown option. Use --help.' >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
  printf '%s\n' 'Only one option is accepted.' >&2
  exit 2
fi
task_python="${LLMSAFE_PYTHON:-}"
if [ -z "$task_python" ]; then
  for task_candidate in python3.12 python3.13 python3.14 python3; do
    if command -v "$task_candidate" >/dev/null 2>&1 &&
       "$task_candidate" -c 'import sys; raise SystemExit(not ((3, 12) <= sys.version_info[:2] <= (3, 14)))'
    then
      task_python="$task_candidate"
      break
    fi
  done
fi
if [ -z "$task_python" ] ||
   ! "$task_python" -c 'import sys; raise SystemExit(not ((3, 12) <= sys.version_info[:2] <= (3, 14)))'
then
  printf '%s\n' 'Python 3.12-3.14 is required for this handoff. LLMSafe itself still supports 3.9+.' >&2
  printf '%s\n' 'Set LLMSAFE_PYTHON to the path of an installed interpreter.' >&2
  exit 2
fi
task_output="$task_root/build/research/2026-10-23"
mkdir -p "$task_output"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git rev-parse HEAD > "$task_output/checkout-commit.txt"
  git status --porcelain > "$task_output/working-tree.txt"
  if [ -s "$task_output/working-tree.txt" ]; then
    printf '%s\n' 'Local changes are present; checks will describe this working tree.'
  fi
else
  printf '%s\n' 'No Git metadata: this is a source snapshot.' > "$task_output/checkout-commit.txt"
fi
task_venv="$task_root/.venv"
task_dev_args=(--venv "$task_venv")
if [ "$task_check_only" -eq 1 ]; then task_dev_args+=(--check-only); fi
printf '%s\n' 'Running the existing contributor quality gate.'
"$task_python" scripts/dev.py "${task_dev_args[@]}" 2>&1 | tee "$task_output/quality.log"
task_runtime="$task_venv/bin/python"
printf '%s\n' 'Reproducing focused gaps (discovery mode; known gaps do not fail this command).'
"$task_runtime" scripts/research_gaps.py --output "$task_output/gaps.json" |
  tee "$task_output/gaps.txt"
"$task_runtime" -m benchmarks.performance --modules 500 --budget-seconds 2 |
  tee "$task_output/performance.json"
printf '%s\n' "Results: $task_output"
printf '%s\n' 'Read docs/research/2026-10-23/MAC_CODEX_HANDOFF.md for implementation.'
