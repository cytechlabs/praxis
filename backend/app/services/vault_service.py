"""
Vault service for managing HashiCorp Vault connectivity.
"""

import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

import hvac
from sqlalchemy.orm import Session

from ..db.models import VaultConfig

logger = logging.getLogger(__name__)

# Allowed path prefixes for Vault operations
ALLOWED_PATH_PREFIXES = ["praxis/"]
# Regex to validate path components (no traversal)
PATH_COMPONENT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-/]*$")


def _get_vault_token() -> Optional[str]:
    """Read Vault token from VAULT_TOKEN env var."""
    return os.getenv("VAULT_TOKEN")


def _validate_path(path: str) -> str:
    """Validate and sanitize a Vault path to prevent traversal."""
    if not path:
        raise VaultSecretError("Empty path")
    if ".." in path:
        raise VaultSecretError("Path traversal not allowed")
    if not PATH_COMPONENT_RE.match(path):
        raise VaultSecretError(f"Invalid path characters: {path}")
    if not any(
        path == prefix.rstrip("/") or path.startswith(prefix)
        for prefix in ALLOWED_PATH_PREFIXES
    ):
        raise VaultSecretError(f"Path must start with one of: {ALLOWED_PATH_PREFIXES}")
    return path


def _split_path(path: str):
    """Split a vault path into mount_point and secret_path."""
    if "/" in path:
        parts = path.split("/", 1)
        return parts[0], parts[1] if len(parts) > 1 else None
    return path, None


class VaultConnectionError(Exception):
    """Exception raised for Vault connection errors."""


class VaultSecretError(Exception):
    """Exception raised for Vault secret operations errors."""


class VaultService:
    """Service for managing HashiCorp Vault connectivity."""

    def __init__(self, db: Session):
        """Initialize the Vault service."""
        self.db = db
        self._client = None
        self._config = None
        self._last_health_check = None

    def get_active_config(self) -> Optional[VaultConfig]:
        """Get the active Vault configuration."""
        return (
            self.db.query(VaultConfig).filter(VaultConfig.is_active.is_(True)).first()
        )

    def initialize_client(self) -> bool:
        """Initialize the Vault client using active config + VAULT_TOKEN env var."""
        config = self.get_active_config()
        if not config:
            logger.warning("No active Vault configuration found")
            return False

        token = _get_vault_token()
        if not token:
            logger.error("VAULT_TOKEN environment variable not set")
            self._config = config
            self._update_health_status("no_token")
            return False

        self._config = config
        try:
            if config.is_internal:
                self._client = hvac.Client(url="http://vault:8200", token=token)
            else:
                self._client = hvac.Client(url=config.server_url, token=token)

            if not self._client.is_authenticated():
                logger.error("Failed to authenticate with Vault")
                self._update_health_status("authentication_failed")
                return False

            self._update_health_status("healthy")
            return True
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Error initializing Vault client: %s", str(e))
            self._update_health_status("connection_error")
            return False

    def _update_health_status(self, status: str) -> None:
        """Update the health status of the Vault configuration."""
        if self._config:
            self._config.health_status = status
            self._config.last_health_check = datetime.utcnow()
            self.db.commit()

    def get_client(self) -> Optional[hvac.Client]:
        """Get the Vault client, initializing it if necessary."""
        if not self._client:
            if not self.initialize_client():
                return None
        return self._client

    def check_health(self) -> Dict[str, Union[bool, str]]:
        """Check the health of the Vault connection."""
        client = self.get_client()
        if not client:
            return {"healthy": False, "status": "no_client"}

        try:
            health = client.sys.read_health_status(method="GET")
            self._last_health_check = datetime.utcnow()
            self._update_health_status("healthy")
            return {
                "healthy": True,
                "status": "healthy",
                "initialized": health["initialized"],
                "sealed": health["sealed"],
                "version": health["version"],
            }
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Error checking Vault health: %s", str(e))
            self._update_health_status("health_check_failed")
            return {"healthy": False, "status": str(e)}

    def create_config(
        self, is_internal: bool, server_url: Optional[str], user_id: Optional[int]
    ) -> VaultConfig:
        """Create a new Vault configuration."""
        # Deactivate any existing active configurations
        active_configs = (
            self.db.query(VaultConfig).filter(VaultConfig.is_active.is_(True)).all()
        )
        for config in active_configs:
            config.is_active = False
        self.db.commit()

        new_config = VaultConfig(
            is_internal=is_internal,
            server_url=server_url if not is_internal else None,
            is_active=True,
            created_by=user_id,
        )
        self.db.add(new_config)
        self.db.commit()
        self.db.refresh(new_config)

        self._client = None
        self._config = None
        self.initialize_client()

        return new_config

    def update_config(
        self, config_id: int, is_internal: bool, server_url: Optional[str]
    ) -> Optional[VaultConfig]:
        """Update an existing Vault configuration."""
        config = self.db.query(VaultConfig).filter(VaultConfig.id == config_id).first()
        if not config:
            return None

        config.is_internal = is_internal
        config.server_url = server_url if not is_internal else None
        config.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(config)

        if config.is_active:
            self._client = None
            self._config = None
            self.initialize_client()

        return config

    def activate_config(self, config_id: int) -> Optional[VaultConfig]:
        """Activate a specific Vault configuration."""
        active_configs = (
            self.db.query(VaultConfig).filter(VaultConfig.is_active.is_(True)).all()
        )
        for config in active_configs:
            config.is_active = False
        self.db.commit()

        config = self.db.query(VaultConfig).filter(VaultConfig.id == config_id).first()
        if not config:
            return None

        config.is_active = True
        config.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(config)

        self._client = None
        self._config = None
        self.initialize_client()

        return config

    def delete_config(self, config_id: int) -> bool:
        """Delete a Vault configuration."""
        config = self.db.query(VaultConfig).filter(VaultConfig.id == config_id).first()
        if not config:
            return False

        if config.is_active:
            self._client = None
            self._config = None

        self.db.delete(config)
        self.db.commit()
        return True

    def list_configs(self) -> List[VaultConfig]:
        """List all Vault configurations."""
        return self.db.query(VaultConfig).all()

    def get_config(self, config_id: int) -> Optional[VaultConfig]:
        """Get a specific Vault configuration."""
        return self.db.query(VaultConfig).filter(VaultConfig.id == config_id).first()

    def read_secret(self, path: str) -> Optional[Dict]:
        """Read a secret from Vault."""
        path = _validate_path(path)
        client = self.get_client()
        if not client:
            raise VaultConnectionError("No Vault client available")

        try:
            mount_point, secret_path = _split_path(path)
            if not secret_path:
                logger.error("No secret path provided in: %s", path)
                return None

            response = client.secrets.kv.v2.read_secret_version(
                path=secret_path, mount_point=mount_point
            )
            return response["data"]["data"]
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Error reading secret from Vault: %s", str(e))
            return None

    def write_secret(self, path: str, data: Dict) -> bool:
        """Write a secret to Vault."""
        path = _validate_path(path)
        client = self.get_client()
        if not client:
            raise VaultConnectionError("No Vault client available")

        try:
            mount_point, secret_path = _split_path(path)
            if not secret_path:
                logger.error("No secret path provided in: %s", path)
                return False

            client.secrets.kv.v2.create_or_update_secret(
                path=secret_path, secret=data, mount_point=mount_point
            )
            return True
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Error writing secret to Vault: %s", str(e))
            return False

    def delete_secret(self, path: str) -> bool:
        """Delete a secret from Vault."""
        path = _validate_path(path)
        client = self.get_client()
        if not client:
            raise VaultConnectionError("No Vault client available")

        try:
            mount_point, secret_path = _split_path(path)
            if not secret_path:
                logger.error("No secret path provided in: %s", path)
                return False

            client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=secret_path, mount_point=mount_point
            )
            return True
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Error deleting secret from Vault: %s", str(e))
            return False

    def list_kv_stores(self) -> List[str]:
        """List all KV stores in Vault."""
        client = self.get_client()
        if not client:
            raise VaultConnectionError("No Vault client available")

        return ["praxis"]

    def list_secrets(self, path: str) -> List[str]:
        """List secrets at a specific path in Vault."""
        path = _validate_path(path)
        client = self.get_client()
        if not client:
            raise VaultConnectionError("No Vault client available")

        try:
            mount_point, subfolder_path = _split_path(path)

            if subfolder_path:
                response = client.secrets.kv.v2.list_secrets(
                    path=subfolder_path, mount_point=mount_point
                )
            else:
                response = client.secrets.kv.v2.list_secrets(
                    path="", mount_point=mount_point
                )

            if not response or "data" not in response or "keys" not in response["data"]:
                return []

            return response["data"]["keys"]
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Error listing secrets in Vault: %s", str(e))
            return []

    def read_secret_metadata(self, path: str) -> Optional[Dict[str, Any]]:
        """Read metadata for a secret from Vault."""
        path = _validate_path(path)
        client = self.get_client()
        if not client:
            raise VaultConnectionError("No Vault client available")

        try:
            mount_point, secret_path = _split_path(path)
            if not secret_path:
                logger.error("No secret path provided in: %s", path)
                return None

            response = client.secrets.kv.v2.read_secret_metadata(
                path=secret_path, mount_point=mount_point
            )
            return response["data"]
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Error reading secret metadata from Vault: %s", str(e))
            return None

    def read_secret_version(self, path: str, version: int) -> Optional[Dict]:
        """Read a specific version of a secret from Vault."""
        path = _validate_path(path)
        client = self.get_client()
        if not client:
            raise VaultConnectionError("No Vault client available")

        try:
            mount_point, secret_path = _split_path(path)
            if not secret_path:
                logger.error("No secret path provided in: %s", path)
                return None

            response = client.secrets.kv.v2.read_secret_version(
                path=secret_path, version=version, mount_point=mount_point
            )
            return response["data"]["data"]
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Error reading secret version from Vault: %s", str(e))
            return None

    def update_secret_password(
        self, path: str, username: str, new_password: str
    ) -> bool:
        """Update the password for a specific username in a secret."""
        existing_secret = self.read_secret(path)
        if existing_secret is None:
            logger.error("Cannot update password: Secret not found at path: %s", path)
            return False

        updated_secret = dict(existing_secret)

        if username in updated_secret:
            updated_secret[username] = new_password
        elif "username" in updated_secret and "password" in updated_secret:
            if updated_secret["username"] == username:
                updated_secret["password"] = new_password
            else:
                logger.error("Username %s does not match", username)
                return False
        else:
            password_updated = False
            for key in updated_secret:
                if (
                    isinstance(updated_secret[key], dict)
                    and "username" in updated_secret[key]
                    and "password" in updated_secret[key]
                ):
                    if updated_secret[key]["username"] == username:
                        updated_secret[key]["password"] = new_password
                        password_updated = True
                        break

            if not password_updated:
                logger.error("Could not find password field for %s", username)
                return False

        return self.write_secret(path, updated_secret)

    # ---------- PRA-44: SSH CA operations ----------

    def get_ssh_ca_public_key(self) -> Optional[str]:
        """Return the SSH CA public key registered at ssh-client-signer/config/ca."""
        if not self._client and not self.initialize_client():
            raise VaultConnectionError("Vault client not available")
        try:
            resp = self._client.read("ssh-client-signer/config/ca")
            if not resp or "data" not in resp:
                return None
            return resp["data"].get("public_key")
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Failed to read SSH CA public key: %s", e)
            raise VaultSecretError(f"Failed to read CA public key: {e}") from e

    def rotate_ssh_ca(self) -> Optional[str]:
        """Regenerate the SSH CA keypair at ssh-client-signer/config/ca (PRA-128).

        Issues a new signing key by re-writing the CA config with
        generate_signing_key=True. Returns the new CA public key.
        """
        if not self._client and not self.initialize_client():
            raise VaultConnectionError("Vault client not available")
        try:
            # Deleting first ensures a fresh keypair rather than an update
            # that keeps the old key.
            try:
                self._client.delete("ssh-client-signer/config/ca")
            except Exception:  # pylint: disable=broad-except
                # Some Vault versions return 404 when config is missing — ignore.
                pass
            self._client.write("ssh-client-signer/config/ca", generate_signing_key=True)
            resp = self._client.read("ssh-client-signer/config/ca")
            if not resp or "data" not in resp:
                raise VaultSecretError("Vault returned no CA data after rotation")
            return resp["data"].get("public_key")
        except VaultSecretError:
            raise
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Failed to rotate SSH CA: %s", e)
            raise VaultSecretError(f"Failed to rotate CA: {e}") from e

    def sign_ssh_user_cert(
        self,
        public_key: str,
        principal: str,
        ttl_seconds: int = 300,
        key_id: Optional[str] = None,
    ) -> str:
        """Sign an SSH user public key via the praxis-user role.

        Returns the signed certificate as an OpenSSH-format string.
        """
        if not self._client and not self.initialize_client():
            raise VaultConnectionError("Vault client not available")
        try:
            payload = {
                "public_key": public_key,
                "valid_principals": principal,
                "ttl": f"{ttl_seconds}s",
                "cert_type": "user",
            }
            if key_id:
                payload["key_id"] = key_id
            resp = self._client.write("ssh-client-signer/sign/praxis-user", **payload)
            if not resp or "data" not in resp or "signed_key" not in resp["data"]:
                raise VaultSecretError("Vault returned no signed_key")
            return resp["data"]["signed_key"]
        except VaultSecretError:
            raise
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Failed to sign SSH user cert: %s", e)
            raise VaultSecretError(f"Failed to sign cert: {e}") from e

    # ---------- PRA-150: Agent PKI operations ----------

    def sign_agent_csr(
        self,
        csr_pem: str,
        common_name: str,
        uri_san: str,
        ttl_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """Sign an agent CSR via the praxis-agent-ca/sign/agent role.

        Returns the signed cert plus metadata (serial, expiration, CA chain).
        Caller is responsible for enforcing System.agent_status policy; this
        method only talks to Vault.
        """
        if not self._client and not self.initialize_client():
            raise VaultConnectionError("Vault client not available")
        try:
            payload = {
                "csr": csr_pem,
                "common_name": common_name,
                "uri_sans": uri_san,
                "ttl": f"{ttl_seconds}s",
                "format": "pem",
            }
            resp = self._client.write("praxis-agent-ca/sign/agent", **payload)
            if not resp or "data" not in resp:
                raise VaultSecretError("Vault returned no data when signing agent CSR")
            data = resp["data"]
            for required in ("certificate", "serial_number", "expiration"):
                if required not in data:
                    raise VaultSecretError(
                        f"Agent CSR response missing field: {required}"
                    )
            ca_chain = data.get("ca_chain") or []
            if not ca_chain and data.get("issuing_ca"):
                ca_chain = [data["issuing_ca"]]
            ca_chain = [c for c in ca_chain if c]  # drop None entries
            return {
                "certificate": data["certificate"],
                "serial_number": data["serial_number"],
                "expiration": data["expiration"],
                "ca_chain": ca_chain,
                "issuing_ca": data.get("issuing_ca"),
            }
        except VaultSecretError:
            raise
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Failed to sign agent CSR: %s", e)
            raise VaultSecretError(f"Failed to sign agent CSR: {e}") from e

    def get_agent_ca_bundle(self) -> Optional[str]:
        """Return the agent CA root certificate (PEM)."""
        if not self._client and not self.initialize_client():
            raise VaultConnectionError("Vault client not available")
        try:
            resp = self._client.read("praxis-agent-ca/cert/ca")
            if not resp or "data" not in resp:
                return None
            return resp["data"].get("certificate")
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Failed to read agent CA cert: %s", e)
            raise VaultSecretError(f"Failed to read agent CA cert: {e}") from e

    def retry_operation(self, operation, *args, max_retries=3, **kwargs):
        """Retry an operation with exponential backoff."""
        retries = 0
        while retries < max_retries:
            try:
                return operation(*args, **kwargs)
            except Exception as e:  # pylint: disable=broad-except
                retries += 1
                if retries >= max_retries:
                    raise e
                wait_time = 2**retries
                logger.warning(
                    "Operation failed, retrying in %s seconds. Error: %s",
                    wait_time,
                    str(e),
                )
                time.sleep(wait_time)
        return None
