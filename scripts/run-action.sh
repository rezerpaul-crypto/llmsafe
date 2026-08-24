#!/usr/bin/env bash

set -u

status=0
scan_args=(
  "${LLMSAFE_INPUT_PATH:-.}"
  --format sarif
  --output "${LLMSAFE_INPUT_SARIF:-llmsafe.sarif}"
  --fail-on "${LLMSAFE_INPUT_FAIL_ON:-high}"
)

if [[ -n "${LLMSAFE_INPUT_CONFIG:-}" ]]; then
  scan_args+=(--config "$LLMSAFE_INPUT_CONFIG")
fi
if [[ -n "${LLMSAFE_INPUT_BASELINE:-}" ]]; then
  scan_args+=(--baseline "$LLMSAFE_INPUT_BASELINE")
fi

python -m llmsafe "${scan_args[@]}" || status=$?

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  sarif_output=""
  if [[ -f "${LLMSAFE_INPUT_SARIF:-llmsafe.sarif}" ]]; then
    sarif_output="${LLMSAFE_INPUT_SARIF:-llmsafe.sarif}"
  fi
  printf '%s\n' "sarif-file=$sarif_output" >> "$GITHUB_OUTPUT"
  printf '%s\n' "exit-code=$status" >> "$GITHUB_OUTPUT"
fi

exit "$status"
