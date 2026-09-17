"""Temporary task folders with application-level access checks, not an OS sandbox."""
import hashlib
import shutil
from pathlib import Path
from typing import Any

from vega.config import WORKSPACES_DIR
from vega.knowledge.policy import rejection_reason
from vega.security.firewall import ContextFirewall
from vega.storage.paths import contained_file, safe_filename


class EphemeralEnclave:
    def __init__(self, task_id: str, department: str, equipment_id: str,
                 operator_role: str = "Engineer", user_clearance: str = "INTERNAL"):
        safe_filename(task_id)
        self.task_id = task_id
        self.department = department
        self.equipment_id = equipment_id
        self.operator_role = operator_role
        self.user_clearance = user_clearance
        self.enclave_dir = contained_file(WORKSPACES_DIR, f"enclave_{task_id}")
        self.mounted_files: list[dict[str, Any]] = []
        self.blocked_files: list[dict[str, Any]] = []
        self.network_disabled = False
        self._initialized = False

    def initialize(self) -> Path:
        # Never delete or reuse an existing workspace, even for a repeated task ID.
        self.enclave_dir.mkdir(parents=True, exist_ok=False)
        self._initialized = True
        return self.enclave_dir

    def mount_document(self, doc: dict) -> bool:
        if not self._initialized:
            raise RuntimeError("Enclave is not initialized")
        filename = doc.get("filename", "")
        reason = rejection_reason(doc, self.department, self.equipment_id, self.user_clearance)
        try:
            target = contained_file(self.enclave_dir, filename)
        except ValueError as exc:
            reason = str(exc)
        content = doc.get("content", "")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if not reason and doc.get("sha256") != digest:
            reason = "Document content hash mismatch or missing hash"
        if not reason and not ContextFirewall().scan_document(doc)["is_safe"]:
            reason = "Context Firewall QUARANTINE"
        if reason:
            self.blocked_files.append({"filename": filename, "reason": f"BLOCKED: {reason}"})
            return False
        with target.open("xb") as stream:
            stream.write(content.encode("utf-8"))
        self.mounted_files.append({
            "filename": filename, "revision": doc["revision"], "sha256": digest,
            "path": str(target), "department": doc["department"], "equipment_id": doc["equipment_id"]
        })
        return True

    def export_artifact(self, filename: str, content: str) -> Path:
        artifact_path = contained_file(self.enclave_dir, filename)
        with artifact_path.open("xb") as stream:
            stream.write(content.encode("utf-8"))
        return artifact_path

    def cleanup(self) -> None:
        if self._initialized:
            target = contained_file(WORKSPACES_DIR, f"enclave_{self.task_id}")
            if target != self.enclave_dir or target.is_symlink():
                raise ValueError("Refusing cleanup outside the task workspace")
            shutil.rmtree(target)
            self._initialized = False

    def get_summary(self) -> dict:
        return {
            "task_id": self.task_id, "enclave_path": str(self.enclave_dir),
            "network_disabled": False, "isolation_scope": "APPLICATION_FOLDER_POLICY",
            "mounted_files_count": len(self.mounted_files), "mounted_files": self.mounted_files,
            "blocked_files_count": len(self.blocked_files), "blocked_files": self.blocked_files
        }
