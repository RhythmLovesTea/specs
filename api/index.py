"""Vercel serverless entrypoint for the FastAPI application."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = str(Path(__file__).resolve().parent.parent)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from demo.server import app  # noqa: E402, F401
