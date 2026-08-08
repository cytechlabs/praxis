#!/usr/bin/env bash
# Agent release lifecycle smoke: build, install, update, roll back, uninstall.
#
# Exercises the operator procedure documented in agent/packaging/README.md
# against real release tarballs, so a packaging change that breaks install or
# rollback fails here instead of on a customer host.
#
# Everything runs inside disposable containers built from agent/Dockerfile.dev.
# Nothing is installed on, or removed from, the machine running this script,
# and nothing is published. systemd is out of scope (containers have no init),
# so the installer and uninstaller run with --no-systemd; the systemd branches
# are covered by their --dry-run tests in
# backend/tests/packaging/.
#
# Usage:
#   scripts/test-agent-release-smoke.sh
#
# Requires: docker, and network access the first time (to build the dev image).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

IMAGE="praxis-agent-dev"
# A synthetic older release so the rollback step has somewhere to go back to.
PREVIOUS_VERSION="v0.0.0-smoke"

green() { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
info()  { printf '\n\033[1m%s\033[0m\n' "$1"; }

command -v docker >/dev/null 2>&1 || {
    echo "docker is required" >&2
    exit 1
}

info "Building the agent dev image"
docker build -q -f agent/Dockerfile.dev -t "${IMAGE}" agent >/dev/null
green "${IMAGE} ready"

info "Running the release lifecycle in a disposable container"

# The whole lifecycle runs in one container so the "already installed" state
# carries between steps the way it does on a real host.
docker run --rm -v "${ROOT}:/src" -w /src/agent "${IMAGE}" bash -euo pipefail -c "
git config --global --add safe.directory /src

ok() { printf '  \033[32mOK\033[0m   %s\n' \"\$1\"; }
step() { printf '\n\033[1m%s\033[0m\n' \"\$1\"; }

VERSION=\"v\$(tr -d '[:space:]' < VERSION)\"
PREVIOUS='${PREVIOUS_VERSION}'

step \"Building \$VERSION and \$PREVIOUS release tarballs\"
make clean >/dev/null
make package >/dev/null
make package VERSION=\"\$PREVIOUS\" >/dev/null
ls dist/*.tar.gz
ok 'both releases packaged'

WORK=\$(mktemp -d)
tar -C \"\$WORK\" -xzf \"dist/praxis-agent-\$VERSION-linux-amd64.tar.gz\"
tar -C \"\$WORK\" -xzf \"dist/praxis-agent-\$PREVIOUS-linux-amd64.tar.gz\"
NEW_DIR=\"\$WORK/praxis-agent-\$VERSION-linux-amd64\"
OLD_DIR=\"\$WORK/praxis-agent-\$PREVIOUS-linux-amd64\"

step 'Tarball contents'
tar -tzf \"dist/praxis-agent-\$VERSION-linux-amd64.tar.gz\"
for f in praxis-agent install.sh uninstall.sh praxis-agent.service README.md LICENSE; do
    test -e \"\$NEW_DIR/\$f\" || { echo \"missing \$f in tarball\" >&2; exit 1; }
done
ok 'tarball carries the binary, both scripts, the unit, README, and LICENSE'

CONFIG_DIR=/etc/praxis-agent
BIN=/usr/local/bin/praxis-agent

step 'Clean install from the previous release'
bash \"\$OLD_DIR/install.sh\" --no-systemd --binary \"\$OLD_DIR/praxis-agent\" \\
    --broker-url wss://broker.example.com:8443 \\
    --backend-url https://praxis.example.com \\
    --system-id 42
test -x \"\$BIN\" || { echo 'binary not installed' >&2; exit 1; }
test -f \"\$CONFIG_DIR/config.json\" || { echo 'config not written' >&2; exit 1; }
\"\$BIN\" version
\"\$BIN\" version --json | grep -q \"\\\"version\\\": \\\"\$PREVIOUS\\\"\" \\
    || { echo 'installed binary reports the wrong version' >&2; exit 1; }
ok \"installed \$PREVIOUS and it reports its own version\"

# Prove the update path preserves operator-owned state, not just the file.
echo '{\"marker\":\"operator-owned\"}' > \"\$CONFIG_DIR/config.json\"
printf 'fake-key\n' > \"\$CONFIG_DIR/agent.key\"
chmod 0600 \"\$CONFIG_DIR/agent.key\"

step \"Operator-triggered update to \$VERSION\"
bash \"\$NEW_DIR/install.sh\" --no-systemd --binary \"\$NEW_DIR/praxis-agent\"
\"\$BIN\" version --json | grep -q \"\\\"version\\\": \\\"\$VERSION\\\"\" \\
    || { echo 'update did not replace the binary' >&2; exit 1; }
grep -q 'operator-owned' \"\$CONFIG_DIR/config.json\" \\
    || { echo 'update overwrote config.json' >&2; exit 1; }
grep -q 'fake-key' \"\$CONFIG_DIR/agent.key\" \\
    || { echo 'update overwrote agent.key' >&2; exit 1; }
ok \"updated to \$VERSION with config and identity preserved\"

step 'Re-running the installer is a no-op'
OUT=\$(bash \"\$NEW_DIR/install.sh\" --no-systemd --binary \"\$NEW_DIR/praxis-agent\")
echo \"\$OUT\" | grep -q 'binary unchanged' \\
    || { echo 'idempotent re-install still replaced the binary' >&2; exit 1; }
ok 'installer is idempotent'

step \"Rollback to \$PREVIOUS\"
bash \"\$OLD_DIR/install.sh\" --no-systemd --binary \"\$OLD_DIR/praxis-agent\"
\"\$BIN\" version --json | grep -q \"\\\"version\\\": \\\"\$PREVIOUS\\\"\" \\
    || { echo 'rollback did not restore the previous binary' >&2; exit 1; }
grep -q 'operator-owned' \"\$CONFIG_DIR/config.json\" \\
    || { echo 'rollback overwrote config.json' >&2; exit 1; }
ok 'rolled back with identity intact, no re-enrollment needed'

step 'Uninstall keeps identity material'
bash \"\$OLD_DIR/uninstall.sh\" --no-systemd
test ! -e \"\$BIN\" || { echo 'binary survived uninstall' >&2; exit 1; }
test -f \"\$CONFIG_DIR/agent.key\" || { echo 'uninstall deleted identity material' >&2; exit 1; }
ok 'binary removed, /etc/praxis-agent preserved'

step 'Uninstall --purge removes identity material'
bash \"\$OLD_DIR/uninstall.sh\" --no-systemd --purge
test ! -d \"\$CONFIG_DIR\" || { echo 'purge left the config dir behind' >&2; exit 1; }
ok 'purge removed the config dir'

step 'Uninstall is idempotent on an already-clean host'
bash \"\$OLD_DIR/uninstall.sh\" --no-systemd --purge >/dev/null
ok 'second uninstall exits clean'

rm -rf \"\$WORK\"
make clean >/dev/null
"

info "Agent release lifecycle smoke passed"
green "install, update, rollback, uninstall, and purge all verified"
echo
echo "This script does NOT tag, sign, or publish anything."
