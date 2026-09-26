"""Bound JSON bodies and their receive time before parsing request objects."""
import asyncio
from starlette.responses import JSONResponse


class RequestBodyLimit:
    read_timeout = 15
    max_readers = 4

    def __init__(self, app):
        self.app = app
        self.readers = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            return await self.app(scope, receive, send)
        limit = 12_000_000 if scope.get("path", "").startswith("/api/media/") else 4_000_000
        lengths = [value for key, value in scope.get("headers", []) if key.lower() == b"content-length"]
        try:
            if len(lengths) > 1 or lengths and (not lengths[0].isdigit() or int(lengths[0]) < 0):
                raise ValueError
            if lengths and int(lengths[0]) > limit:
                return await JSONResponse({"detail": "Request body exceeds the limit"}, status_code=413)(scope, receive, send)
        except ValueError:
            return await JSONResponse({"detail": "Invalid content length"}, status_code=400)(scope, receive, send)
        if self.readers >= self.max_readers:
            return await JSONResponse({"detail": "Too many uploads; retry shortly"}, status_code=429,
                                      headers={"Retry-After": "1"})(scope, receive, send)
        self.readers += 1
        body = bytearray()
        try:
            async with asyncio.timeout(self.read_timeout):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    block = message.get("body", b"")
                    if len(body) + len(block) > limit:
                        return await JSONResponse({"detail": "Request body exceeds the limit"}, status_code=413)(scope, receive, send)
                    body.extend(block)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            return await JSONResponse({"detail": "Request body receive deadline exceeded"}, status_code=408)(scope, receive, send)
        finally:
            # Slots cover uploads, not long-running inference, so incident commands
            # are not excluded just because model jobs are running.
            self.readers -= 1
        if lengths and len(body) != int(lengths[0]):
            return await JSONResponse({"detail": "Content length does not match body"}, status_code=400)(scope, receive, send)
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            payload = bytes(body)
            body.clear()
            return {"type": "http.request", "body": payload, "more_body": False}

        await self.app(scope, bounded_receive, send)
