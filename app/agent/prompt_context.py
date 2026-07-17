from __future__ import annotations

import re
from typing import Any


class PromptContextSanitizer:
    """Bound and redact source context before it reaches an LLM or report."""

    _assignment = re.compile(
        r"(?i)(\b(?:api[_-]?key|access[_-]?key|token|password|passwd|private[_-]?key|client[_-]?secret|secret)\b\s*[:=]\s*)(['\"])(.*?)(\2)"
    )
    _unquoted_assignment = re.compile(
        r"(?i)(\b(?:api[_-]?key|access[_-]?key|token|password|passwd|private[_-]?key|client[_-]?secret|secret)\b\s*[:=]\s*)(?!<redacted>)[^\s,;]+"
    )
    _bearer = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/-]+=*")
    _private_key = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.DOTALL)
    _known_tokens = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,})\b")

    def __init__(self, max_lines: int = 80, max_chars: int = 12_000) -> None:
        self.max_lines = max_lines
        self.max_chars = max_chars

    def redact_text(self, text: str) -> str:
        value = str(text or "")
        value = self._private_key.sub("<redacted-private-key>", value)
        value = self._assignment.sub(r"\1\2<redacted>\4", value)
        value = self._unquoted_assignment.sub(r"\1<redacted>", value)
        value = self._bearer.sub(r"\1<redacted>", value)
        value = self._known_tokens.sub("<redacted>", value)
        return value

    def sanitize_code(self, text: str) -> str:
        lines = self.redact_text(text).splitlines()[: self.max_lines]
        value = "\n".join(lines)
        if len(value) > self.max_chars:
            value = value[: self.max_chars] + "\n<truncated>"
        return value

    def sanitize_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {key: self.sanitize_value(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.sanitize_value(item) for item in value]
        return value


DEFAULT_SANITIZER = PromptContextSanitizer()


def redact_sensitive_text(text: str) -> str:
    return DEFAULT_SANITIZER.redact_text(text)
