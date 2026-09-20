"""
Vega Sovereign AI Runtime - FastAPI Server
Assembles all sovereign runtime endpoints and mounts the lightweight industrial UI.
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from urllib.parse import urlsplit
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from vega.config import FRONTEND_DIR
from vega.storage.database import init_db

from vega.api.routes.dashboard import router as dashboard_router
from vega.api.routes.models import router as models_router
from vega.api.routes.hardware import router as hardware_router
from vega.api.routes.knowledge import router as knowledge_router
from vega.api.routes.security import router as security_router
from vega.api.routes.tasks import router as tasks_router
from vega.api.routes.receipts import router as receipts_router
from vega.api.routes.control import router as control_router
from vega.control.store import init_control, Denied
import asyncio
import contextlib
import logging

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize empty local storage on server start."""
    init_db()
    init_control()
    async def retention_worker():
        from vega.control.artifacts import sweep
        while True:
            try:
                await asyncio.to_thread(sweep)
            except Exception:
                logging.getLogger("vega.retention").error("Retention sweep failed; inspect the local security ledger")
            await asyncio.sleep(30)
    worker = asyncio.create_task(retention_worker()) if os.environ.get("VEGA_ENABLE_DEMO_ENDPOINTS") == "1" else None
    try:
        yield
    finally:
        if worker:
            worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await worker

app = FastAPI(
    title="Vega Sovereign AI Runtime",
    description="Self-Defending Sovereign Industrial AI Runtime Environment",
    version="1.0.0-prototype",
    lifespan=lifespan
)

allowed_hosts = {
    host.strip().lower().removeprefix("[").removesuffix("]")
    for host in os.environ.get("VEGA_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")
}
vercel_preview = bool(os.environ.get("VERCEL"))


@app.middleware("http")
async def protect_local_mutations(request: Request, call_next):
    if vercel_preview and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        return JSONResponse({"detail": "This hosted preview is read-only. Run Vega locally to store private records."}, status_code=403)
    # Parse bracketed IPv6 correctly; accept exact configured hosts only.
    hosts = request.headers.getlist("host")
    try:
        host = urlsplit("//" + hosts[0]) if len(hosts) == 1 else None
        valid_host = (host is not None and host.hostname in allowed_hosts
                      and host.username is None and not (host.path or host.query or host.fragment)
                      and (host.port is None or 0 < host.port <= 65535))
    except ValueError:
        valid_host = False
    if not valid_host and not vercel_preview:
        return JSONResponse({"detail": "Invalid host header"}, status_code=400)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        same_origin = True
        if origin:
            try:
                parsed = urlsplit(origin)
                same_origin = (parsed.scheme, parsed.netloc) == (request.url.scheme, request.url.netloc)
            except ValueError:
                same_origin = False
        if not same_origin or request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-origin mutations are not allowed"}, status_code=403)
    return await call_next(request)

# Register API Routers
app.include_router(dashboard_router)
app.include_router(models_router)
app.include_router(hardware_router)
app.include_router(knowledge_router)
app.include_router(security_router)
app.include_router(tasks_router)
app.include_router(receipts_router)
app.include_router(control_router)


@app.exception_handler(Denied)
async def control_denied(request: Request, exc: Denied):
    return JSONResponse(status_code=403, content={"detail": str(exc), "code": exc.code, "event_id": exc.event_id})


@app.exception_handler(ValueError)
async def invalid_control_request(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})

@app.get("/health")
def health_check():
    return {
        "system": "VEGA",
        "status": "OPERATIONAL",
        "mode": "SIMULATION",
        "egress": "SIMULATED COUNTERS ONLY; OS EGRESS NOT VERIFIED",
        "deployment_mode": "HOSTED_PREVIEW" if vercel_preview else "LOCAL"
    }

# Mount static frontend assets
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def serve_frontend_index():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "Vega UI not built yet. Access /docs for API schema."}
