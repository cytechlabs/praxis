"""PRA-154 #1f: minimal Python stand-in for the host side of bootstrap.

Generates an EC P-256 keypair + PKCS#10 CSR using the same crypto
primitives the real Go agent uses (RFC 5915 / 5280), so the
backend's CSR signing path sees a wire-shape-realistic input. The
real agent's runtime behavior is covered by its own Go tests;
``FakeAgent`` exists only to validate the **control plane's**
plumbing.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import CertificateSigningRequestBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID


class FakeAgent:
    """One-shot fake host: holds a freshly-minted EC keypair and emits
    a CSR with the placeholder CN the real agent uses.

    The real agent's CN is overwritten by the backend during signing
    (use_csr_common_name=false on the Vault role), so the placeholder
    just has to be a valid DN.
    """

    def __init__(self, system_id: int, fingerprint: str = "fake-machine-id") -> None:
        self.system_id = system_id
        self.fingerprint = fingerprint
        self._key = ec.generate_private_key(ec.SECP256R1())

    @property
    def csr_pem(self) -> str:
        cn = f"system-{self.system_id}.agent.praxis.internal"
        csr = (
            CertificateSigningRequestBuilder()
            .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, cn)]))
            .sign(self._key, hashes.SHA256())
        )
        return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def enroll_body(
        self,
        *,
        hostname: str = "fake-host.example.com",
        facts: dict | None = None,
    ) -> dict:
        body = {
            "system_id": self.system_id,
            "host_fingerprint": self.fingerprint,
            "csr_pem": self.csr_pem,
            "hostname": hostname,
        }
        if facts is not None:
            body["facts"] = facts
        return body
