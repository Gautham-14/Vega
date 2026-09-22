"""Keep synthetic demonstration actions off the operator API by default."""

import os

from fastapi import HTTPException


def require_demo_mode() -> None:
    if os.environ.get("AEGIS_ENABLE_DEMO_ENDPOINTS") != "1":
        raise HTTPException(status_code=404, detail="Demonstration endpoint is disabled")
