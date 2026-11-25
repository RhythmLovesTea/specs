"""Append-only, hash-chained JSONL audit log (tamper-evident)."""
import hashlib
import json
import threading
from pathlib import Path
from typing import Optional, Tuple

from src.models import AuditRecord

GENESIS_HASH = "0" * 64


def _digest(body: dict) -> str:
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, log_path: str = "logs/audit_log.jsonl") -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        last = GENESIS_HASH
        if self.log_path.exists():
            with self.log_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last = json.loads(line)["hash"]
        return last

    def write(self, record: AuditRecord) -> AuditRecord:
        """Chain the record to its predecessor and append it to the file."""
        with self._lock:
            body = record.model_dump(mode="json", exclude={"hash"})
            body["prev_hash"] = self._last_hash
            body["hash"] = _digest(body)
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(body, ensure_ascii=False) + "\n")
            self._last_hash = body["hash"]
            return AuditRecord(**body)

    @staticmethod
    def verify_chain(log_path: str) -> Tuple[bool, Optional[int]]:
        """Return (True, None) if intact, else (False, first bad line no.)."""
        prev = GENESIS_HASH
        with open(log_path, "r", encoding="utf-8") as fh:
            for number, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    body = json.loads(line)
                except json.JSONDecodeError:
                    return False, number
                claimed = body.pop("hash", None)
                if body.get("prev_hash") != prev or _digest(body) != claimed:
                    return False, number
                prev = claimed
        return True, None
