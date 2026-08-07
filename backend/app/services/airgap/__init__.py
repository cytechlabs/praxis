"""Airgap export/import services (PRA-160).

Slice #1 ships:
  * ``schema`` — bundle descriptor body (canonical-bytes serializable).
  * ``signing_key_service`` — Vault-backed bundle signing key.
  * ``descriptor_signer`` — canonical-bytes JSON + detached signature.
  * ``planner`` — resolves profile→channel→mirror, validates byte
    selection, returns a fully-populated ``BundleDescriptor`` or a
    structured refusal.
  * ``orchestrator`` — wires planner + signer + DB row into the
    descriptor-ready end state.

Slice #2 will add the tar payload assembler, bundle byte path,
descriptor re-sign, and final ``ok`` status transition. Slice #3 will
add the importer. Slice #4 will add delta bundles. Slice #5 closes
out cold-rebuild + docs + CLI polish.
"""
