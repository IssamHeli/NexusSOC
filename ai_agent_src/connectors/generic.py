import uuid
from typing import Any
from .base import SIEMConnector


class GenericConnector(SIEMConnector):
    """Passthrough connector — accepts any dict with at least title + description.
    Use for custom integrations or pre-normalized payloads."""

    @property
    def source_name(self) -> str:
        return "generic"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        if not raw.get("title"):
            raise ValueError("Generic connector requires 'title' field")
        if not raw.get("description"):
            raise ValueError("Generic connector requires 'description' field")

        out = dict(raw)
        if not out.get("sourceRef"):
            out["sourceRef"] = f"GENERIC-{str(uuid.uuid4())[:8].upper()}"
        if not out.get("source"):
            out["source"] = "SIEM"
        return out
