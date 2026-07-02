from __future__ import annotations

import json
from typing import Any

try:
    from pydantic import BaseModel, Field
except Exception:  # pragma: no cover - lightweight runtime fallback
    def Field(default: Any = None, **_: Any) -> Any:
        return default

    class BaseModel:
        def __init__(self, **data: Any) -> None:
            annotations = getattr(self, "__annotations__", {})
            for key, value in annotations.items():
                if key in data:
                    setattr(self, key, data[key])
                elif hasattr(self.__class__, key):
                    default = getattr(self.__class__, key)
                    setattr(self, key, default.copy() if isinstance(default, (list, dict)) else default)
                else:
                    setattr(self, key, None)
            for key, value in data.items():
                if key not in annotations:
                    setattr(self, key, value)

        def model_dump(self) -> dict[str, Any]:
            return {key: _dump(value) for key, value in self.__dict__.items()}

        def model_dump_json(self, indent: int | None = None) -> str:
            return json.dumps(self.model_dump(), ensure_ascii=False, indent=indent)


def _dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, list):
        return [_dump(item) for item in value]
    if isinstance(value, dict):
        return {key: _dump(item) for key, item in value.items()}
    return value
