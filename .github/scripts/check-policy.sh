#!/usr/bin/env bash
# The rules that keep kovyr-edr's public CI and repo safe. The "policy" CI
# job runs this on every run; to run it yourself, from the repo root:
#
#   .github/scripts/check-policy.sh
#
# kovyr-edr is public, so anyone's pull request runs its workflows.
#  1. Every action is pinned to a full commit SHA, with its version as a
#     comment (uses: owner/repo@<40 hex digits> # vX.Y.Z). A tag can be
#     moved to other code; a commit can't. Dependabot keeps the pins
#     current.
#  2. Every checkout sets persist-credentials: false, so the job's GitHub
#     token is not left in .git/config for later steps.
#  3. setup-go in the installer jobs sets cache: false: the agent in the
#     MSI is compiled from scratch, never from a restored build cache.
#  4. Exactly one job uploads the test kit (kovyr-protection-alarm-test-kit),
#     and it runs only for a push to main or a manual run on main, never
#     for a pull request.
#  5. No pull_request_target or workflow_run trigger: those run code from
#     a fork with the repo's write token and secrets.
#  6. .gitignore keeps build output, local agent state and key files out
#     of commits, and ignores no tracked file.
#  7. go.mod keeps `godebug x509sslcertoverrideplatform=0`. Since Go 1.27
#     an SSL_CERT_FILE or SSL_CERT_DIR environment variable replaces the
#     Windows certificate store; with this line the agent keeps trusting
#     only the Windows store, whatever another program set on the PC.
set -euo pipefail
cd "$(dirname "$0")/../.."

kit=kovyr-protection-alarm-test-kit
guard="github.ref == 'refs/heads/main' && (github.event_name == 'push' || github.event_name == 'workflow_dispatch')"
fail=0
bad() {
	echo "::error::$*"
	fail=1
}

shopt -s nullglob
workflows=(.github/workflows/*.yml .github/workflows/*.yaml)
[ ${#workflows[@]} -gt 0 ] || bad "no workflow files in .github/workflows"

kit_jobs=0
for f in "${workflows[@]}"; do
	# 1. Pinned actions. Local actions (./path) are part of this repo.
	while IFS= read -r line; do
		bad "$f:$line: pin the action to a commit SHA with a '# vX.Y.Z' comment"
	done < <(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:' "$f" |
		grep -vE 'uses:[[:space:]]*(\./[^[:space:]]+|[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]+v[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*$' || true)

	# 5. Dangerous triggers (comments stripped first).
	if sed 's/#.*//' "$f" | grep -qE '(^|[^A-Za-z_])(pull_request_target|workflow_run)([^A-Za-z_]|$)'; then
		bad "$f: uses a pull_request_target or workflow_run trigger"
	fi

	# 2, 3 and 4 look at each step, and at the job it belongs to. The awk
	# below splits the jobs: section into jobs and steps by indentation
	# and prints one line per problem ("bad ...") and per job that uploads
	# the test kit ("kit <job> <job's if:>").
	while IFS=$'\t' read -r kind job rest; do
		case $kind in
		bad) bad "$f: job $job: $rest" ;;
		kit)
			kit_jobs=$((kit_jobs + 1))
			if [ "$rest" != "$guard" ]; then
				bad "$f: job $job uploads $kit but its if: is '$rest', not: $guard"
			fi
			;;
		esac
	done < <(awk -v kit="$kit" '
		function ind(s) { match(s, /^ */); return RLENGTH }
		function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
		function endstep() {
			if (step == "") return
			if (step ~ /uses:[ \t]*actions\/checkout@/ && step !~ /\n[ \t]*persist-credentials:[ \t]*false[ \t]*\n/)
				printf "bad\t%s\tactions/checkout without persist-credentials: false\n", job
			if (job ~ /^installer/ && step ~ /uses:[ \t]*actions\/setup-go@/ && step !~ /\n[ \t]*cache:[ \t]*false[ \t]*\n/)
				printf "bad\t%s\tactions/setup-go without cache: false\n", job
			if (step ~ /uses:[ \t]*actions\/upload-artifact@/ && step ~ ("\n[ \t]*name:[ \t]*\"?" kit "\"?[ \t]*\n"))
				kitjob[job] = 1
			step = ""
		}
		/^[ \t]*(#|$)/ { next }
		{ i = ind($0) }
		i == 0 { endstep(); injobs = ($0 ~ /^jobs:[ \t]*$/); job = ""; next }
		!injobs { next }
		i == 2 { endstep(); job = trim($0); sub(/:.*/, "", job); steps = 0; next }
		steps && i <= stepsind { endstep(); steps = 0 }
		i == 4 && /^    if:/ { v = trim(substr($0, 9)); sub(/^\$\{\{[ \t]*/, "", v); sub(/[ \t]*\}\}$/, "", v); jobif[job] = v; next }
		/^[ ]*steps:[ \t]*$/ { steps = 1; stepsind = i; itemind = -1; next }
		steps && /^[ ]*- / && (itemind < 0 || i == itemind) { endstep(); itemind = i; step = "\n" $0 "\n"; next }
		steps { step = step $0 "\n" }
		END {
			endstep()
			for (j in kitjob) printf "kit\t%s\t%s\n", j, jobif[j]
		}
	' "$f")
done
[ "$kit_jobs" -eq 1 ] || bad "$kit must be uploaded by exactly one job; found $kit_jobs"

# 6. .gitignore.
must_ignore=(
	dist/kovyr-agent.exe kit/kovyr-protection-alarm-x64.msi rebuild/kovyr-protection-alarm-x64.msi
	kovyr-agent kovyr-receiver-dev winci kovyr-agent.exe kovyr-protection-alarm-x64.msi
	internal/agent/agent.test cover.out cpu.prof
	devices.json kovyr-receiver-dev.jsonl
	device-key.json state/device-key.json chain-state.json agent-config.json state/logs/agent.log
	scanner.key.json release.key receiver-tls.pem codesign.pfx codesign.p12
	.env .env.local .DS_Store docs/.DS_Store
)
for p in "${must_ignore[@]}"; do
	git check-ignore -q --no-index -- "$p" || bad ".gitignore does not ignore $p"
done
tracked=$(git ls-files -ci --exclude-standard)
[ -z "$tracked" ] || bad ".gitignore ignores tracked files: $tracked"

# 7. The agent's TLS trust.
grep -qE '^godebug[[:space:]]+x509sslcertoverrideplatform=0[[:space:]]*$' go.mod ||
	bad "go.mod lacks 'godebug x509sslcertoverrideplatform=0' (the agent must trust only the Windows certificate store)"

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "policy: ok (${#workflows[@]} workflow file(s))"
