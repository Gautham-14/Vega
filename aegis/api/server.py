"""
Aegis Sovereign AI Runtime - FastAPI Server
Assembles all sovereign runtime endpoints and mounts the lightweight industrial UI.
"""
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.exceptions import RequestValidationError
from urllib.parse import urlsplit
import ipaddress
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from aegis.config import FRONTEND_DIR
from aegis.storage.database import init_db

from aegis.api.routes.dashboard import router as dashboard_router
from aegis.api.routes.models import router as models_router
from aegis.api.routes.hardware import router as hardware_router
from aegis.api.routes.knowledge import router as knowledge_router
from aegis.api.routes.security import router as security_router
from aegis.api.routes.tasks import router as tasks_router
from aegis.api.routes.receipts import router as receipts_router
from aegis.api.routes.control import router as control_router
from aegis.api.routes.coding import router as coding_router
from aegis.api.routes.auth import router as auth_router
from aegis.api.routes.providers import router as providers_router
from aegis.api.routes.telemetry import router as telemetry_router
from aegis.api.routes.media import router as media_router
from aegis.api.limits import RequestBodyLimit
from aegis.security import auth
from aegis import telemetry
from aegis.control.store import init_control, Denied
import asyncio
import contextlib
import logging
import time

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize empty local storage on server start."""
    init_db()
    init_control()
    auth.init_auth()
    telemetry.init_telemetry()
    async def retention_worker():
        from aegis.control.artifacts import sweep
        from aegis.coding.service import sweep as sweep_coding
        from aegis.media.service import sweep as sweep_media
        while True:
            try:
                await asyncio.to_thread(sweep)
                await asyncio.to_thread(sweep_coding)
                await asyncio.to_thread(sweep_media)
            except Exception:
                logging.getLogger("aegis.retention").error("Retention sweep failed; inspect the local security ledger")
            await asyncio.sleep(30)
    async def telemetry_worker():
        while True:
            try:
                await asyncio.to_thread(telemetry.sample)
            except Exception:
                logging.getLogger("aegis.telemetry").error("Local telemetry sampling failed")
            await asyncio.sleep(3)
    workers = [asyncio.create_task(retention_worker()), asyncio.create_task(telemetry_worker())]
    try:
        yield
    finally:
        for worker in workers:
            worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await worker

app = FastAPI(
    title="Aegis Sovereign AI Runtime",
    description="Self-Defending Sovereign Industrial AI Runtime Environment",
    version="1.0.0-prototype",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan
)
app.add_middleware(RequestBodyLimit)

allowed_hosts = {
    host.strip().lower().removeprefix("[").removesuffix("]")
    for host in os.environ.get("AEGIS_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")
}
@app.middleware("http")
async def protect_local_mutations(request: Request, call_next):
    peer = request.client.host if request.client else ""
    try:
        loopback_peer = ipaddress.ip_address(peer).is_loopback
    except ValueError:
        # Starlette's in-process TestClient has no network peer.
        loopback_peer = peer == "testclient"
    if not loopback_peer:
        return JSONResponse({"detail": "Aegis accepts local clients only"}, status_code=403)
    # Parse bracketed IPv6 correctly; accept exact configured hosts only.
    hosts = request.headers.getlist("host")
    try:
        host = urlsplit("//" + hosts[0]) if len(hosts) == 1 else None
        valid_host = (host is not None and host.hostname in allowed_hosts
                      and host.username is None and not (host.path or host.query or host.fragment)
                      and (host.port is None or 0 < host.port <= 65535))
    except ValueError:
        valid_host = False
    if not valid_host:
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
    path = request.url.path
    public_status = {"/api/auth/status", "/api/auth/login", "/api/control/status", "/api/coding/status"}
    if path.startswith("/api/") and path not in public_status:
        try:
            await asyncio.to_thread(auth.authenticate, request)
            await asyncio.to_thread(auth.authorize_legacy, request)
        except HTTPException as error:
            return JSONResponse({"detail": error.detail}, status_code=error.status_code,
                                headers={"Cache-Control": "no-store"})
        except Denied as error:
            return JSONResponse({"detail": str(error), "code": error.code}, status_code=403)
    started = time.monotonic()
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = ("default-src 'self'; connect-src 'self'; "
        "script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        # Store only route templates, never path arguments, queries or request bodies.
        route = getattr(request.scope.get("route"), "path", None)
        if route and not path.startswith("/api/telemetry/"):
            try:
                await asyncio.to_thread(telemetry.init_telemetry)
                await asyncio.to_thread(telemetry.event, request.method, route, response.status_code,
                                        (time.monotonic() - started) * 1000)
            except Exception:
                logging.getLogger("aegis.telemetry").error("Local request metrics unavailable")
    return response

# Register API Routers
app.include_router(dashboard_router)
app.include_router(models_router)
app.include_router(hardware_router)
app.include_router(knowledge_router)
app.include_router(security_router)
app.include_router(tasks_router)
app.include_router(receipts_router)
app.include_router(control_router)
app.include_router(coding_router)
app.include_router(auth_router)
app.include_router(providers_router)
app.include_router(telemetry_router)
app.include_router(media_router)


@app.get("/api/endpoints", tags=["Operations"])
def endpoints(identity=Depends(auth.principal)):
    return {"endpoints": [{"path": route.path, "methods": sorted(route.methods),
                           "summary": getattr(route, "summary", None) or route.name}
                          for route in app.routes if getattr(route, "path", "").startswith("/api/")
                          and getattr(route, "methods", None)]}


@app.exception_handler(Denied)
async def control_denied(request: Request, exc: Denied):
    return JSONResponse(status_code=403, content={"detail": str(exc), "code": exc.code, "event_id": exc.event_id})


@app.exception_handler(ValueError)
async def invalid_control_request(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(RequestValidationError)
async def invalid_schema(request: Request, exc: RequestValidationError):
    # FastAPI's default includes rejected input values, which can contain a
    # password, source text, or credentials. Return field/error descriptions only.
    return JSONResponse(status_code=422, content={"detail": [
        {"loc": list(item["loc"]), "type": item["type"], "msg": item["msg"]}
        for item in exc.errors()]})

@app.get("/health")
def health_check():
    return {
        "system": "AEGIS",
        "status": "OPERATIONAL",
        "mode": "SIMULATION",
        "egress": "SIMULATED COUNTERS ONLY; OS EGRESS NOT VERIFIED",
        "deployment_mode": "LOCAL"
    }

# Mount static frontend assets
@app.get("/docs", include_in_schema=False, response_class=HTMLResponse)
def offline_docs():
    return '<!doctype html><html><head><meta charset="utf-8"><title>Aegis local API</title></head><body><h1>Aegis local API</h1><p><a href="/openapi.json">OpenAPI schema</a></p><p>Use the authenticated local CLI for operations. This documentation loads no external assets.</p></body></html>'


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def serve_frontend_index():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "Aegis UI not built yet. Access /docs for API schema."}
