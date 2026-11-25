"""Root FastAPI entrypoint for Vercel zero-config deployment and local ASGI runners."""
from demo.server import app

__all__ = ["app"]
