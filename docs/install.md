---
title: Install Praxis
description: Deploy the Praxis control plane with Docker Compose, either from the published images or from source.
---

This installs the control plane. It does not enroll any hosts; that is
[enroll hosts](enroll-hosts.md), after [first run](first-run.md).

Check [requirements](requirements.md) first. Most failed installs are a missing
prerequisite rather than a bad configuration.

## Two ways to install

| Path | Choose it when | What it runs |
|---|---|---|
| **Published images** (recommended) | You are deploying Praxis to use it. | The exact images the project built and signed for a release tag. |
| **From source** | You are developing Praxis or reviewing a change. | The same images, built from your working tree. |

Both paths use the same prerequisites, the same `.env`, the same Compose files,
the same startup checks, and the same health checks. They differ in one command,
under [start the stack](#start-the-stack). Only the published-image path can be
verified against the project's attestations, which is why it is the one to
deploy.

## Get the deployment files

The container images are published to a registry, but the Compose files and the
environment template live in the source repository, so both paths start with a
clone:

```sh
git clone https://github.com/cytechlabs/praxis.git
cd praxis
```

On the published-image path, check out the release you intend to run. The
Compose files change between releases, so a checkout that does not match the
images can start a stack the release was never tested as:

```sh
git checkout v1.0.1
```

On the source path, stay on the branch you are working on.

## Configure the environment

Copy the template and fill in the values that have no safe default:

```sh
cp .env.example .env
```

At minimum, set:

| Variable | Why |
|---|---|
| `SECRET_KEY` | Signs application tokens. Generate a long random value. Startup refuses a weak or empty key in production. |
| `POSTGRES_PASSWORD` | Bundled database password. The stack refuses to start on the retired default. |
| `ADMIN_PASSWORD` | Initial administrator password. Set a strong value before first boot; a fresh production deployment fails closed when it is empty. Praxis does not generate or print this credential. It is read only while the deployment is still being initialized, so clear it once the first administrator has signed in. |
| `PUBLIC_BASE_URL` | The external URL browsers use, for example `https://praxis.example.com`. Redirect flows and single sign-on depend on it. |
| `PRAXIS_DOMAIN` | The hostname Caddy answers on. |
| `PRAXIS_TLS_MODE` | `internal`, `acme`, or `byo`. See TLS below. |
| `PRAXIS_VERSION` | The release to run, for example `1.0.0`. Pin it; do not run `latest` in production. A source build overrides the image, so this only labels what you built. |

Keep `.env` out of version control and readable only by the account that runs
the stack. `ENVIRONMENT=production` enables the startup hardening checks; do not
promote a deployment that still says `development`.

## Choose a deployment shape

**Bundled** runs PostgreSQL and the OpenBao secrets service inside the stack.
This is the supported single-node shape and the right default.

**External services** points at a database and a Vault-compatible secrets
service you already run. Remove `bundled` from `COMPOSE_PROFILES` and set
`DATABASE_URL`, `VAULT_ADDR`, and `VAULT_TOKEN`.

Both shapes, and the constraints on each, are covered in
[production hardening](production-hardening.md).

## TLS

`PRAXIS_TLS_MODE` selects how Caddy obtains a certificate:

- `internal` self-signs. Browsers warn until you trust Caddy's local root.
  Fine for evaluation, not for anything real.
- `acme` uses Let's Encrypt. Requires `PRAXIS_DOMAIN` to resolve publicly and
  port 443 to be reachable. Set `PRAXIS_ACME_EMAIL` as well.
- `byo` uses a certificate and key you mount at `/certs/`.

## Start the stack

`--profile bundled` runs the database and the secrets service inside the stack.
`--profile proxy` starts Caddy, which is the only public ingress: without it the
backend and frontend publish no host ports and the stack is deliberately
unreachable from a browser. Omit `proxy` only when you are fronting the stack
with your own reverse proxy on the Docker network.

### Published images

Pull the pinned images, then bring the stack up:

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy pull

docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy up -d
```

### From source

`--build` replaces the pull. It rebuilds the production images from the working
tree using the same Dockerfiles, entrypoints, topology, volumes, health checks,
and environment validation the published images use, so what you get is the
release shape rather than a development mode:

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy up -d --build
```

Every toolchain the build needs is inside the Dockerfiles, so the host needs
nothing beyond Docker. It does need build-time network access to fetch
dependencies, and it takes noticeably longer than a pull. A disconnected site
should follow [airgap export and import](airgap.md) rather than build on the
isolated host.

## Confirm it came up

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy ps
```

Every service should report healthy. Then check the application answers:

```sh
curl -fsS https://praxis.example.com/api/backend/health
```

If the secrets service reports sealed, unseal it before going further;
credentials cannot be read while it is sealed. See
[production hardening](production-hardening.md).

## Verify what you deployed

Before you put a deployment into service, confirm the images you are running are
the ones the project published, by digest and by attestation. See
[verify release artifacts](verify-release-artifacts.md).

There is nothing to verify against on the source path, because the images are
yours rather than the project's. That is the reason it is a development path
rather than a deployment one.

## Next

Continue to [first run](first-run.md) to secure the administrator account and
apply a licence if you have one.
