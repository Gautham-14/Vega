from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from aegis.security import auth
from aegis.control import policy

router = APIRouter(prefix="/api/auth", tags=["Local authentication"])


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


@router.get("/status")
def status():
    return {"configured": auth.configured(), "demo": auth.demo_identity_enabled(),
            "session_seconds": auth.SESSION_SECONDS, "provisioning": "Local administrator CLI only"}


@router.post("/login")
def login(body: Login, request: Request, response: Response):
    result = auth.login(body.username, body.password, request.client.host if request.client else "local")
    response.set_cookie("aegis_session", result["access_token"], max_age=auth.SESSION_SECONDS,
                        httponly=True, samesite="strict", secure=request.url.scheme == "https", path="/api")
    response.headers["Cache-Control"] = "no-store"
    return result


@router.get("/me")
def me(identity=Depends(auth.principal)):
    return policy.actor(identity)


@router.post("/logout")
def logout(request: Request, response: Response, identity=Depends(auth.principal)):
    if token := getattr(request.state, "session_token", None):
        auth.logout(token)
    response.delete_cookie("aegis_session", path="/api")
    return {"signed_out": True}
