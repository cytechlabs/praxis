# Vault Integration

> **Bundled runtime note (PRA-311):** the bundled secrets service is now **OpenBao
> 2.6.1**, a drop-in for HashiCorp Vault driven via the `bao` CLI. For 1.0 the Docker
> service name (`vault`), the `/vault/*` paths, the `vault_data`/`vault_recovery`
> volumes, and `VAULT_ADDR`/`VAULT_TOKEN` are intentionally kept for compatibility, so
> the "Vault" naming below still applies to the running service. External HashiCorp
> Vault deployments remain supported through the same `VAULT_ADDR`/`VAULT_TOKEN` contract.

This document describes the bundled secrets (Vault/OpenBao) integration for secure credential management in the Praxis system.

## Overview

The bundled **OpenBao** (a Vault-compatible secrets service) is used to securely store and manage sensitive credentials, such as API keys, passwords, and certificates. The integration provides a secure foundation for remote system operations, enabling safe credential storage and reliable system connectivity. Operators who prefer to run their own secrets service can point Praxis at an external OpenBao or HashiCorp Vault cluster via `VAULT_ADDR`/`VAULT_TOKEN` (the API is identical).

## Architecture

The Vault integration consists of the following components:

1. **Vault Server**: A production-grade Vault server running in a Docker container.
2. **Vault Service**: A backend service for managing Vault connectivity.
3. **Vault API**: REST API endpoints for managing Vault configurations.
4. **Vault Settings UI**: A frontend interface for configuring Vault connections.

## Configuration Options

The system supports two Vault configuration modes:

1. **Internal Vault**: Uses the built-in Vault container that comes with the system.
2. **External Vault**: Connects to an external Vault server.

## Setup

### Internal Vault

The internal Vault server is configured as a Docker container in the `docker-compose.yml` file. When using the internal Vault, you only need to provide the backend service token, which can be retrieved using:

```bash
docker compose exec vault cat /vault/data/backend-token
```

### External Vault

To use an external Vault server, you need to provide:

1. The server URL (e.g., https://vault.example.com:8200)
2. An authentication token with appropriate permissions

## Usage

### Configuring Vault

1. Navigate to the Settings page in the web interface
2. Select the "Vault Settings" tab
3. Click "Configure Vault"
4. Choose between internal or external Vault
5. Provide the required information
6. Click "Save Configuration"

### Health Check

The Vault integration includes a health check feature that verifies:

- Connection to the Vault server
- Authentication status
- Vault server status (initialized, sealed, etc.)

### API Endpoints

The following API endpoints are available for Vault management:

- `GET /vault/config`: List all Vault configurations
- `POST /vault/config`: Create a new Vault configuration
- `GET /vault/config/active`: Get the active Vault configuration
- `PUT /vault/config/{config_id}`: Update a Vault configuration
- `POST /vault/config/{config_id}/activate`: Activate a Vault configuration
- `DELETE /vault/config/{config_id}`: Delete a Vault configuration
- `GET /vault/health`: Check the health of the Vault connection

## Security Considerations

- **Runtime vs. recovery material (PRA-241).** Bundled Vault splits its on-disk
  material across two volumes. `vault_data` (mounted read-only into backend and
  agent-broker) holds only the scoped backend service token
  (`/vault/data/backend-token`) and public cert material. The **root token and
  unseal keys** live on the separate `vault_recovery` volume
  (`/vault/recovery/{root-token,init-keys.json}`), mounted **only** into the Vault
  container — backend and agent-broker cannot read them. Read access to
  `vault_data` therefore yields scoped service credentials, not root or unseal
  material.
- The root token is operator recovery material — it should only be used for
  administrative tasks (from inside the Vault container) and kept on the
  operator-only `vault_recovery` volume, which must be backed up off-host.
- The backend service token has limited permissions (the `backend-service`
  policy) and is what all backend operations use.
- For production deployments, prefer external Vault or Vault's auto-unseal
  mechanisms integrated with a cloud KMS/HSM, so no long-lived root token is
  stored on disk.

## Troubleshooting

### Vault is Sealed

If Vault becomes sealed, you can manually unseal it using:

```bash
docker compose exec vault vault operator unseal <unseal-key>
```

You'll need to run this command three times with different unseal keys.

### Retrieving Unseal Keys

Unseal keys are operator recovery material and live on the `vault_recovery`
volume (mounted only into the Vault container — PRA-241). Retrieve them from
inside that container:

```bash
docker compose exec vault cat /vault/recovery/init-keys.json
```

### Resetting Vault

To completely reset Vault, remove **both** its volumes (runtime + recovery) and
restart. This destroys all secrets, PKI roots, and unseal keys — irreversible:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy down
docker volume rm praxis_vault_data praxis_vault_recovery
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy up -d
```
