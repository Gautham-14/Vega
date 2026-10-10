"""Host-admin custody of independently verified offline bundles."""

import time

from aegis.control import store
from aegis.security import offline_bundle
from aegis.security.private_files import no_links


def record(directory, trust_policy):
    root, trust = no_links(directory), no_links(trust_policy)
    verified = offline_bundle.verify_bundle(root, trust)
    value = {
        "id": store.uid("BUNDLE"),
        "directory": str(root),
        "trust_policy": str(trust),
        "verification": verified,
        "created_at": time.time(),
        "status": "RECORDED",
    }
    with store.LOCK:
        store.receipt(
            "BUNDLE_CUSTODY_RECORDED",
            "host-administrator",
            bundle_record_id=value["id"],
            manifest_sha256=verified["manifest_sha256"],
        )
        store.put(
            "bundle-custody", value["id"], {**value, "seal": store.sign(value, "bundle-custody-v1")}
        )
    return {key: item for key, item in value.items() if key not in {"directory", "trust_policy"}}


def revalidate(identity):
    with store.LOCK:
        value = store.require("bundle-custody", identity)
        body = {key: item for key, item in value.items() if key != "seal"}
        if (
            body.get("id") != identity
            or not isinstance(value.get("seal"), str)
            or not store.verify_signature(body, "bundle-custody-v1", value["seal"])
        ):
            raise store.Denied(
                "BUNDLE_CUSTODY_INTEGRITY_FAILURE", "Bundle custody record changed", identity
            )
        if value["status"] != "RECORDED" or store.get("bundle-revocation", identity):
            raise store.Denied("BUNDLE_REVOKED", "Bundle custody was revoked", identity)
        current = offline_bundle.verify_bundle(value["directory"], value["trust_policy"])
        # Policy changes require a new custody record and provider profile.
        if current != value["verification"]:
            raise store.Denied(
                "BUNDLE_CUSTODY_CHANGED", "Bundle files or trust policy changed", identity
            )
        return body


def revoke(identity):
    with store.LOCK:
        value = store.require("bundle-custody", identity)
        store.receipt("BUNDLE_CUSTODY_REVOKED", "host-administrator", bundle_record_id=identity)
        store.put("bundle-revocation", identity, {"revoked_at": time.time()})
    return {"id": value["id"], "status": "REVOKED"}
