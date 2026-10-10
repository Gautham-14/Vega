"""
Aegis Sovereign AI Runtime - FastAPI Server
Assembles all sovereign runtime endpoints and mounts the lightweight industrial UI.
"""

import asyncio
import contextlib
import ipaddress
import logging
import os
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse

from aegis import __version__, telemetry
from aegis.api.limits import RequestBodyLimit
from aegis.api.routes.advisory import router as advisory_router
from aegis.api.routes.auth import router as auth_router
from aegis.api.routes.chat import router as chat_router
from aegis.api.routes.coding import router as coding_router
from aegis.api.routes.control import router as control_router
from aegis.api.routes.dashboard import router as dashboard_router
from aegis.api.routes.hardware import router as hardware_router
from aegis.api.routes.knowledge import router as knowledge_router
from aegis.api.routes.media import router as media_router
from aegis.api.routes.models import router as models_router
from aegis.api.routes.providers import router as providers_router
from aegis.api.routes.receipts import router as receipts_router
from aegis.api.routes.security import router as security_router
from aegis.api.routes.tasks import router as tasks_router
from aegis.api.routes.telemetry import router as telemetry_router
from aegis.control.store import Denied, init_control
from aegis.security import auth
from aegis.storage.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize empty local storage under an exclusive runtime lock."""
    from aegis.security.quiescence import exclusive

    with exclusive("starting another runtime"):
        init_db()
        init_control()
        auth.init_auth()
        telemetry.init_telemetry()
        from aegis.security.deployment import validate

        validate()

        async def retention_worker():
            from aegis.advisory.service import sweep as sweep_advisory
            from aegis.coding.service import sweep as sweep_coding
            from aegis.control.artifacts import sweep
            from aegis.media.service import sweep as sweep_media

            while True:
                try:
                    await asyncio.to_thread(sweep)
                    await asyncio.to_thread(sweep_coding)
                    await asyncio.to_thread(sweep_media)
                    await asyncio.to_thread(sweep_advisory)
                    from aegis.security.availability import maintenance

                    await asyncio.to_thread(maintenance)
                except Exception:
                    logging.getLogger("aegis.retention").error(
                        "Retention sweep failed; inspect the local security ledger"
                    )
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
    version=__version__,
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
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
        valid_host = (
            host is not None
            and host.hostname in allowed_hosts
            and host.username is None
            and not (host.path or host.query or host.fragment)
            and (host.port is None or 0 < host.port <= 65535)
        )
    except ValueError:
        valid_host = False
    if not valid_host:
        return JSONResponse({"detail": "Invalid host header"}, status_code=400)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origins = request.headers.getlist("origin")
        origin = origins[0] if len(origins) == 1 else None
        same_origin = True
        if origin:
            try:
                parsed = urlsplit(origin)
                same_origin = (
                    (parsed.scheme, parsed.netloc) == (request.url.scheme, request.url.netloc)
                    and not (parsed.path or parsed.query or parsed.fragment)
                    and parsed.username is None
                    and parsed.password is None
                )
            except ValueError:
                same_origin = False
        if (
            len(origins) > 1
            or not same_origin
            or request.headers.get("sec-fetch-site") == "cross-site"
        ):
            return JSONResponse(
                {"detail": "Cross-origin mutations are not allowed"}, status_code=403
            )
    path = request.url.path
    public_status = {
        "/api/auth/status",
        "/api/auth/login",
        "/api/control/status",
        "/api/coding/status",
    }
    if path.startswith("/api/") and path not in public_status:
        try:
            await asyncio.to_thread(auth.authenticate, request)
            await asyncio.to_thread(auth.authorize_legacy, request)
            await asyncio.to_thread(auth.require_step_up, request)
        except HTTPException as error:
            return JSONResponse(
                {"detail": error.detail},
                status_code=error.status_code,
                headers={"Cache-Control": "no-store"},
            )
        except Denied as error:
            return JSONResponse({"detail": str(error), "code": error.code}, status_code=403)
    started = time.monotonic()
    from aegis.security.availability import actor_context, admit

    token = actor_context.set(getattr(request.state, "actor", "anonymous"))
    admission = admit("http", actor_context.get())
    try:
        await asyncio.to_thread(admission.__enter__)
    except HTTPException as error:
        actor_context.reset(token)
        return JSONResponse(
            {"detail": error.detail}, status_code=error.status_code, headers=error.headers
        )
    try:
        response = await call_next(request)
    finally:
        try:
            await asyncio.to_thread(admission.__exit__, None, None, None)
        finally:
            actor_context.reset(token)
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        # Store only route templates, never path arguments, queries or request bodies.
        route = getattr(request.scope.get("route"), "path", None)
        if route and not path.startswith("/api/telemetry/"):
            try:
                await asyncio.to_thread(telemetry.init_telemetry)
                await asyncio.to_thread(
                    telemetry.event,
                    request.method,
                    route,
                    response.status_code,
                    (time.monotonic() - started) * 1000,
                )
            except Exception:
                logging.getLogger("aegis.telemetry").error("Local request metrics unavailable")
    return response


@app.middleware("http")
async def secure_response_headers(request: Request, call_next):
    # Outermost middleware covers early authentication, host and body rejections.
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; connect-src 'self'; "
        "script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    if request.scope.get("path", "").startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
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
app.include_router(chat_router)
app.include_router(providers_router)
app.include_router(telemetry_router)
app.include_router(media_router)
app.include_router(advisory_router)


@app.get("/api/endpoints", tags=["Operations"])
def endpoints(identity=Depends(auth.principal)):
    return {
        "endpoints": [
            {
                "path": route.path,
                "methods": sorted(route.methods),
                "summary": getattr(route, "summary", None) or route.name,
            }
            for route in app.routes
            if getattr(route, "path", "").startswith("/api/") and getattr(route, "methods", None)
        ]
    }


@app.exception_handler(Denied)
async def control_denied(request: Request, exc: Denied):
    return JSONResponse(
        status_code=403, content={"detail": str(exc), "code": exc.code, "event_id": exc.event_id}
    )


@app.exception_handler(ValueError)
async def invalid_control_request(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(RequestValidationError)
async def invalid_schema(request: Request, exc: RequestValidationError):
    # FastAPI's default includes rejected input values, which can contain a
    # password, source text, or credentials. Return field/error descriptions only.
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"loc": list(item["loc"]), "type": item["type"], "msg": item["msg"]}
                for item in exc.errors()
            ]
        },
    )


@app.get("/health")
def health_check():
    return {
        "system": "AEGIS",
        "status": "OPERATIONAL",
        "mode": "SIMULATION",
        "egress": "SIMULATED COUNTERS ONLY; OS EGRESS NOT VERIFIED",
        "deployment_mode": "LOCAL",
    }


# Mount static frontend assets
@app.get("/docs", include_in_schema=False, response_class=HTMLResponse)
def offline_docs():
    return '<!doctype html><html><head><meta charset="utf-8"><title>Aegis local API</title></head><body><h1>Aegis local API</h1><p><a href="/openapi.json">OpenAPI schema</a></p><p>Use the authenticated local CLI for operations. This documentation loads no external assets.</p></body></html>'


# (Frontend removed; CLI only)
