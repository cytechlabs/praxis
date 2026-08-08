# Praxis Fleet Agent

Thin agent that connects this host to a Praxis backend over a long-lived
mTLS WebSocket. Written in Go, single static binary, Linux-only.

## Quickstart

```sh
tar xzf praxis-agent-*.tar.gz
cd praxis-agent-*-linux-*
sudo ./install.sh \
    --broker-url wss://broker.example.com:8443 \
    --backend-url https://praxis.example.com \
    --system-id 42
```

This installs `/usr/local/bin/praxis-agent`, `/etc/systemd/system/praxis-agent.service`,
and writes initial config to `/etc/praxis-agent/config.json`. It does **not**
start the service or generate identity material.

## Identity bootstrap

Enrollment binds this host to a pre-registered `system_id` and gets it a
signed agent certificate. The agent's URI SAN (`praxis://system/<id>`) is
minted by the backend — nothing the host supplies in the CSR can change its
identity — so trust comes from **how the CSR is authorized**, not from the
CSR itself. Two authorization paths ship in 1.0.

### Path A — activation token (default)

An admin mints a single-use, scoped, time-limited activation token in the UI
(**Settings → Activation Tokens**) or via the API. The token is redeemed
against `POST /agent/enroll`, which signs the CSR and returns the cert +
CA chain. The redemption is done by the operator/tooling on the host (the
agent binary generates the key + CSR; it does not itself call `/agent/enroll`):

```sh
sudo praxis-agent gen-keypair
sudo praxis-agent gen-csr > agent.csr          # PKCS#10 CSR (public)

# Fetch the anonymous CA bundle the agent needs to trust the broker:
curl -fsS https://praxis.example.com/agent/ca-bundle -o ca-bundle.json
#   -> {"agent_ca": "<PEM>", "broker_ca": "<PEM>"}

# Redeem the activation token, sending the CSR. host_fingerprint makes the
# redemption idempotent per host (re-runs don't burn a second use).
curl -fsS -X POST https://praxis.example.com/agent/enroll \
    -H "X-Praxis-Activation-Token: praxis_XXXXXXXX..." \
    -H "Content-Type: application/json" \
    -d @- <<JSON > enroll-response.json
{
  "system_id": 42,
  "host_fingerprint": "$(cat /etc/machine-id)",
  "csr_pem": $(jq -Rs . < agent.csr),
  "hostname": "$(hostname -f)"
}
JSON
# enroll-response.json -> {certificate, ca_chain, serial_number, ...}

# Split the signed cert out of the response for install-cert:
jq -r .certificate enroll-response.json > agent.crt

sudo praxis-agent install-cert \
    --cert agent.crt \
    --bundle ca-bundle.json \
    --backend-url https://praxis.example.com \
    --broker-url  wss://broker.example.com:8443 \
    --system-id   42
```

### Path B — admin SSH-once bootstrap (alternative)

For hosts Praxis already reaches over SSH, an admin can prove host identity
by posting the CSR to `POST /agent/bootstrap/{system_id}` (admin-JWT-gated).
The backend opens an SSH session to the host as proof, signs the CSR, and
returns the same cert + CA-chain shape. Feed the returned `agent.crt` into
the same `install-cert` step above. No activation token is involved.

`install-cert` validates that the cert's public key matches the local
`agent.key` **before** writing anything, then transactionally writes the cert
+ both CAs into `/etc/praxis-agent/` and finalises `config.json`.

Then start the service:

```sh
sudo systemctl enable --now praxis-agent
sudo systemctl status praxis-agent
```

Confirm the tunnel is up from the control plane: `GET /agent/status/<id>`
reports `agent_status: active` and `agent_liveness: online` once the agent
has dialed the broker and completed the mTLS handshake.

## Files

| Path | Purpose |
|---|---|
| `/usr/local/bin/praxis-agent` | binary |
| `/etc/praxis-agent/config.json` | broker URL, backend URL, system_id |
| `/etc/praxis-agent/agent.key` | private key (mode 0600) |
| `/etc/praxis-agent/agent.crt` | agent certificate |
| `/etc/praxis-agent/broker-ca.crt` | broker CA bundle |
| `/etc/systemd/system/praxis-agent.service` | systemd unit |

## Checking what is installed

```sh
praxis-agent version
#   praxis-agent v1.0.0 (commit 00fdd4df026d, linux/amd64, go1.26.5)

praxis-agent version --json
```

The JSON form reports `version`, `commit`, `go_version`, `os`, `arch`, and
`stamped`. The human-readable line abbreviates the commit; the JSON form
carries the full 40-character SHA, which is the identifier to quote in a bug
report. A `stamped` of `false` means the binary is a local build rather than
a published release artifact. There is no build timestamp: release builds are
reproducible, so the version, commit, and Go toolchain fully identify the
binary.

## Updating to a new release

Updates are operator-triggered. The agent never updates itself.

```sh
# 1. Download and verify the new release (see "Verifying the download").
tar xzf praxis-agent-<new>-linux-<arch>.tar.gz
cd praxis-agent-<new>-linux-<arch>

# 2. Install over the existing deployment. Config and identity are kept.
sudo ./install.sh

# 3. Confirm the new binary is live.
praxis-agent version
sudo systemctl status praxis-agent
```

`install.sh` is idempotent. It replaces the binary only if it changed,
reloads systemd only if the unit file changed, and restarts the service
only if it was already active. Existing `config.json`, `agent.key`,
`agent.crt`, and `broker-ca.crt` are never overwritten, so an update does
not re-enroll the host.

The agent reconnects to the broker on restart, so a routine update shows up
as a brief liveness gap in the control plane rather than a re-enrollment.

## Rolling back

Rollback is the same operation against the older tarball. Keep the previous
release's tarball on the host (or re-download and re-verify it) before
updating, so the rollback path does not depend on network access:

```sh
cd praxis-agent-<previous>-linux-<arch>
sudo ./install.sh
praxis-agent version      # confirm the previous version is back
```

Because identity material is preserved across install, update, and
rollback, moving between agent versions never requires a new activation
token. Rolling back does not undo control-plane state; if the newer agent
completed work, that work stands.

## Uninstalling

```sh
# Stop and remove the service and the binary, keeping identity material
# so the host can be reinstalled without re-enrolling:
sudo ./uninstall.sh

# Preview without changing anything:
sudo ./uninstall.sh --dry-run

# Also delete /etc/praxis-agent (config, key, cert). Irreversible; the
# host must be re-enrolled to come back:
sudo ./uninstall.sh --purge
```

Removing the agent from a host does not revoke its certificate. Revoke the
system in the control plane as a separate step when decommissioning.

## Verifying the download

Each release ships a `checksums.txt` covering the per-arch tarballs and their
CycloneDX SBOMs, plus a keyless cosign signature over `checksums.txt`. Each
architecture has its own SBOM, since the dependency set is resolved per
target. Two-step verification:

```sh
# 1. cosign anchors trust to the GitHub Actions identity that built
#    this release.
cosign verify-blob \
    --certificate checksums.txt.pem \
    --signature   checksums.txt.sig \
    --certificate-identity-regexp '^https://github.com/cytechlabs/praxis/.github/workflows/agent-release.yml@refs/tags/agent-v.*$' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    checksums.txt

# 2. sha256 anchors the tarballs and the SBOMs to checksums.txt.
sha256sum -c checksums.txt
```

The cosign identity must match the repository that produced the
release. The regex above pins to `cytechlabs/praxis`; verifying a
release built from a different repo means swapping the org/repo
segment to match — same trust model, different signing identity.

Verify before extracting. A tarball that fails either check should be
discarded, not installed.
