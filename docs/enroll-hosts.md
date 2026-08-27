---
title: Enroll hosts
description: Register hosts over SSH, or install and enroll the thin agent for hosts the control plane cannot reach.
---

A host becomes managed in two steps: it is **registered** in Praxis, which
creates its record and its credential binding, and it is **reachable** over at
least one transport.

Decide the transport first. [Transports](transports.md) states what each one
supports; the short version is that SSH is the default and is required for
interactive terminal sessions, and the agent exists for hosts the control plane
cannot reach inbound.

## Register a host over SSH

Open **Operate > Add System**. The guided setup connects to the host, proves the
credential works, and reads what the host is, before anything is written to the
inventory. You give the address and the credential; Praxis works out the
distribution, and the group and SSH policy default to All Systems and the
Default policy.

A host that cannot be reached, or whose credential is refused, is reported with
a specific reason rather than saved as an unreachable record. Nothing is created
and no licence capacity is used until the last step succeeds.

Host keys are approved explicitly. On first contact the offered fingerprint is
shown for you to compare against the host, and it is pinned for the rest of the
setup; a key that changes mid-setup stops it.

You may proceed without verifying. The host is then added as **Inactive** with a
**Pending** connection state, which is an accurate record of a host Praxis has
never reached, not a working one.

For the full walkthrough, including every verification reason code, see
[add your first system](guide-add-first-system.md).

After the setup finishes the host appears under **Operate > All Systems** and the
first inventory scan begins.

### Add many hosts

Use the bulk registration form or a CSV import for the rest of the fleet.
Register a handful first and confirm they are reachable and inventoried before
importing the whole estate; a credential or escalation mistake is much cheaper
to find on three hosts than on three hundred.

### Deploy certificate-based identity

Once a host is reachable you can stop using passwords for it. On the host's
detail page choose **Deploy CA Trust**. Praxis installs the signing CA public
key, adds `TrustedUserCAKeys` to the SSH daemon configuration, and reloads it.
From then on each connection is authorised by a freshly signed short-lived
certificate. Password authentication keeps working as a fallback.

See [SSH and security](ssh-and-security.md) for rotation and revocation.

## Enroll a host with the thin agent

The agent is a single static Go binary that dials **out** to the broker over a
long-lived mTLS WebSocket. Use it for hosts behind NAT or a firewall that the
control plane cannot reach.

### Install the binary

Download the release tarball for the host architecture and
[verify it](verify-release-artifacts.md) before extracting. Then:

```sh
tar xzf praxis-agent-*.tar.gz
cd praxis-agent-*-linux-*
sudo ./install.sh \
    --broker-url wss://broker.example.com:8443 \
    --backend-url https://praxis.example.com \
    --system-id 42
```

`--system-id` is the ID of a host you have **already registered** in Praxis.
Install does not start the service and does not create identity material.

### Give the host an identity

The agent's identity is minted by the backend, not supplied by the host, so
trust comes from how the certificate request is authorised. There are two
paths.

**Activation token.** An administrator mints a single-use, scoped,
time-limited token under **Settings > Activation Tokens**. On the host,
generate a key and request, fetch the CA bundle, redeem the token, and install
the returned certificate:

```sh
sudo praxis-agent gen-keypair
sudo praxis-agent gen-csr > agent.csr

curl -fsS https://praxis.example.com/agent/ca-bundle -o ca-bundle.json

curl -fsS -X POST https://praxis.example.com/agent/enroll \
    -H "X-Praxis-Activation-Token: praxis_XXXXXXXX..." \
    -H "Content-Type: application/json" \
    -d "{\"system_id\": 42,
         \"host_fingerprint\": \"$(cat /etc/machine-id)\",
         \"csr_pem\": $(jq -Rs . < agent.csr),
         \"hostname\": \"$(hostname -f)\"}" \
    > enroll-response.json

jq -r .certificate enroll-response.json > agent.crt

sudo praxis-agent install-cert \
    --cert agent.crt \
    --bundle ca-bundle.json \
    --backend-url https://praxis.example.com \
    --broker-url  wss://broker.example.com:8443 \
    --system-id   42
```

Sending `host_fingerprint` makes redemption idempotent for that host, so a
re-run does not consume a second use of the token.

**Bootstrap over SSH.** For a host Praxis can already reach, an administrator
posts the certificate request to `POST /agent/bootstrap/{system_id}`. The
backend opens an SSH session to the host as proof of identity and returns the
same signed certificate, with no activation token involved. Feed that
certificate into the same `install-cert` step.

`install-cert` checks the certificate against the local private key before it
writes anything, then writes the certificate and both CAs transactionally.

### Start it

```sh
sudo systemctl enable --now praxis-agent
sudo systemctl status praxis-agent
```

Confirm from the control plane that the tunnel is up: the host reports
`agent_status: active` and `agent_liveness: online` once the agent has dialled
the broker and completed the handshake.

### What lands on the host

| Path | Purpose |
|---|---|
| `/usr/local/bin/praxis-agent` | The binary. |
| `/etc/praxis-agent/config.json` | Broker URL, backend URL, system ID. |
| `/etc/praxis-agent/agent.key` | Private key, mode 0600. |
| `/etc/praxis-agent/agent.crt` | Agent certificate. |
| `/etc/praxis-agent/broker-ca.crt` | Broker CA bundle. |
| `/etc/systemd/system/praxis-agent.service` | The service unit. |

### Updating the agent

Updates are operator-triggered; the agent never updates itself. Verify and
extract the new tarball, then run `sudo ./install.sh` over the existing
deployment. Configuration and identity material are preserved, so an update
does not re-enroll the host and shows up as a brief liveness gap rather than a
new enrollment. Rolling back is the same operation against the older tarball.

## Confirm enrollment worked

For any host, whichever transport it uses:

1. **Operate > All Systems** shows it as Active.
2. Its detail page lists packages after the first inventory scan.
3. `Last audited` advances after the next health check.

A host that registers but never inventories is usually an escalation problem
rather than a connectivity one. Work through
[troubleshooting](troubleshooting.md).

## Next

- Organise the fleet with groups and rule-based targeting in
  [fleet and hosts](fleet-and-hosts.md).
- Take the tour in [getting started](getting-started.md).
- Ship your first patch with
  [respond to a critical update](guide-critical-updates.md).
