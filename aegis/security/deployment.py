"""Explicit production prerequisites; development retains local operation."""

import os
import sys


def production() -> bool:
    profile = os.environ.get("AEGIS_SECURITY_PROFILE", "development")
    if profile not in {"development", "production"}:
        raise RuntimeError("AEGIS_SECURITY_PROFILE must be development or production")
    return profile == "production"


def validate() -> dict[str, object]:
    if not production():
        return {"profile": "development", "production_ready": False}
    if not sys.platform.startswith("linux"):
        raise RuntimeError(
            "Native production services require Linux; Windows/macOS operators must use the isolated VM backend (see VM_DEPLOYMENT.md)"
        )
    if os.geteuid() == 0:
        raise RuntimeError("Production API must run under its restricted OS identity, never root")
    if os.environ.get("AEGIS_ENABLE_DEMO_ENDPOINTS") == "1":
        raise RuntimeError("Production cannot enable demo identities or endpoints")
    required = (
        "AEGIS_KEY_BROKER_SOCKET",
        "AEGIS_KEY_BROKER_UID",
        "AEGIS_AUDIT_WITNESS_SOCKET",
        "AEGIS_AUDIT_WITNESS_UID",
        "AEGIS_INSTALLATION_ID",
        "AEGIS_PROVIDER_TRUST_POLICY",
        "AEGIS_ATTESTOR_SOCKET",
        "AEGIS_ATTESTOR_UID",
    )
    if any(not os.environ.get(name) for name in required):
        raise RuntimeError(
            "Production requires separately provisioned custody, witness and attestor configuration"
        )
    try:
        key_uid = int(os.environ["AEGIS_KEY_BROKER_UID"])
        witness_uid = int(os.environ["AEGIS_AUDIT_WITNESS_UID"])
        attestor_uid = int(os.environ["AEGIS_ATTESTOR_UID"])
    except ValueError:
        raise RuntimeError("Production custody identities must be numeric UIDs") from None
    if (
        key_uid <= 0
        or witness_uid <= 0
        or key_uid == witness_uid
        or os.geteuid() in {key_uid, witness_uid}
        or attestor_uid != 0
    ):
        raise RuntimeError(
            "Production requires separate unprivileged key/witness identities and the root attestor"
        )
    from aegis.security.key_custody import remote

    custody = remote({"operation": "status"})
    if custody.get("version") != 2 or custody.get("key_export") is not False:
        raise RuntimeError("Production requires versioned, non-exporting key custody")
    from aegis.control import store

    if not store.verify_chain(record_failure=False)["is_valid"]:
        raise RuntimeError("Production requires a valid independently anchored ledger")
    return {
        "profile": "production",
        "production_ready": True,
        "scope": "Custody and witness verified; each live provider still requires independent isolation evidence",
    }
