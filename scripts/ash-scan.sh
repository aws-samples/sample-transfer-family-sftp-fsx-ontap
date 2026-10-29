#!/usr/bin/env bash
# Run Automated Security Helper (ASH) v3 over the repository and over the
# synthesized CloudFormation templates. Suppressions with reasons live in
# .ash/.ash.yaml. Requires: ash (v3, local mode), Node.js, npm ci done.
#
#   pip install "automated-security-helper @ https://github.com/awslabs/automated-security-helper/archive/refs/tags/v3.7.1.tar.gz"
#   scripts/ash-scan.sh [-c account=... -c region=...]
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${ASH_OUTPUT_DIR:-$root/.ash/ash_output}"
cfg="$root/.ash/.ash.yaml"
templates="$out/templates"

rm -rf "$out"
mkdir -p "$templates"

echo "== ASH: repository"
repo_rc=0
ash --mode local --source-dir "$root" --output-dir "$out/repo" --config "$cfg" || repo_rc=$?

echo "== ASH: synthesized CloudFormation templates"
(cd "$root" && npx cdk synth --all --quiet -o "$out/cdk.out" "$@" >/dev/null)
cp "$out"/cdk.out/*.template.json "$templates/"
cfn_rc=0
ash --mode local --source-dir "$templates" --output-dir "$out/templates-report" --config "$cfg" || cfn_rc=$?

echo "repository scan exit code: $repo_rc, template scan exit code: $cfn_rc"
echo "reports: $out/repo/reports and $out/templates-report/reports"
[ "$repo_rc" -eq 0 ] && [ "$cfn_rc" -eq 0 ]
