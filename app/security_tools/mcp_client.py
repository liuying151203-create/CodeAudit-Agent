from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = {MCP_PROTOCOL_VERSION, "2025-06-18"}
MAX_MCP_MESSAGE_CHARS = 2_000_000
BASE_ENV_KEYS = {
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
}


class MCPClientError(RuntimeError):
    pass


@dataclass(frozen=True)
class MCPServerConfig:
    name: str
    command: str
    args: tuple[str, ...] = ()
    enabled: bool = True
    timeout_seconds: int = 30
    env_passthrough: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    defaults: dict[str, Any] = field(default_factory=dict)


class StdioMCPClient:
    """Small synchronous MCP stdio client for discovery and bounded tool calls."""

    def __init__(self, config: MCPServerConfig, cwd: Path | None = None):
        self.config = config
        self.cwd = cwd
        self.process: subprocess.Popen[str] | None = None
        self._messages: queue.Queue[dict[str, Any] | Exception] = queue.Queue()
        self._request_id = 0
        self.protocol_version = MCP_PROTOCOL_VERSION

    def __enter__(self) -> "StdioMCPClient":
        env_keys = {key.upper() for key in BASE_ENV_KEYS | set(self.config.env_passthrough)}
        env = {key: value for key, value in os.environ.items() if key.upper() in env_keys}
        self.process = subprocess.Popen(
            [self.config.command, *self.config.args],
            cwd=str(self.cwd) if self.cwd else None,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            shell=False,
            env=env,
        )
        threading.Thread(target=self._read_messages, name=f"mcp-{self.config.name}", daemon=True).start()
        try:
            result = self.request(
                "initialize",
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "CodeAudit-Agent", "version": "0.1.0"},
                },
            )
            version = str(result.get("protocolVersion") or "")
            if version not in SUPPORTED_PROTOCOL_VERSIONS:
                raise MCPClientError(f"Unsupported MCP protocol version: {version or 'missing'}")
            self.protocol_version = version
            self.notify("notifications/initialized")
            return self
        except Exception:
            self.close()
            raise

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        process = self.process
        if process is None:
            return
        if process.stdin and not process.stdin.closed:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        for stream in (process.stdin, process.stdout):
            if stream is not None and not stream.closed:
                stream.close()
        self.process = None

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(20):
            result = self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(item for item in result.get("tools") or [] if isinstance(item, dict))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._request_id += 1
        request_id = self._request_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            try:
                message = self._messages.get(timeout=self.config.timeout_seconds)
            except queue.Empty as exc:
                raise MCPClientError(f"MCP request timed out: {method}") from exc
            if isinstance(message, Exception):
                raise MCPClientError(str(message)) from message
            if message.get("id") == request_id:
                if "error" in message:
                    error = message.get("error") or {}
                    raise MCPClientError(str(error.get("message") or "MCP protocol error"))
                result = message.get("result")
                if not isinstance(result, dict):
                    raise MCPClientError(f"MCP response for {method} has no object result")
                return result
            if message.get("id") is not None and message.get("method"):
                self._send(
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {"code": -32601, "message": "Client-side MCP requests are not supported"},
                    }
                )

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def _send(self, message: dict[str, Any]) -> None:
        process = self.process
        if process is None or process.stdin is None or process.poll() is not None:
            raise MCPClientError("MCP server is not running")
        process.stdin.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
        process.stdin.flush()

    def _read_messages(self) -> None:
        process = self.process
        if process is None or process.stdout is None:
            return
        try:
            for line in process.stdout:
                if not line.strip():
                    continue
                if len(line) > MAX_MCP_MESSAGE_CHARS:
                    self._messages.put(MCPClientError("MCP response exceeded the configured output limit"))
                    continue
                message = json.loads(line)
                if isinstance(message, dict):
                    self._messages.put(message)
            if process.poll() not in (None, 0):
                self._messages.put(MCPClientError(f"MCP server exited with code {process.returncode}"))
        except Exception as exc:
            self._messages.put(exc)
