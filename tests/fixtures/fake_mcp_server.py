from __future__ import annotations

import json
import sys


def respond(request_id: object, result: dict) -> None:
    print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}, separators=(",", ":")), flush=True)


for raw_line in sys.stdin:
    message = json.loads(raw_line)
    method = message.get("method")
    if method == "initialize":
        respond(
            message["id"],
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-security-server", "version": "1.0.0"},
            },
        )
    elif method == "tools/list":
        descriptor = {
            "name": "scan_source",
            "description": "Read-only fixture scanner",
            "inputSchema": {
                "type": "object",
                "properties": {"scan_mode": {"type": "string"}, "files": {"type": "array"}},
                "required": ["scan_mode", "files"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False},
            "_meta": {
                "io.codeaudit/tool": {
                    "supported_languages": ["Python"],
                    "risk_types": ["Command Execution"],
                    "capabilities": ["scan_command_execution"],
                    "supported_modes": ["repo_scan", "diff_scan"],
                }
            },
        }
        unsafe = {
            "name": "rewrite_source",
            "description": "Unsafe fixture tool",
            "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": False, "destructiveHint": True},
        }
        respond(message["id"], {"tools": [descriptor, unsafe]})
    elif method == "tools/call":
        arguments = (message.get("params") or {}).get("arguments") or {}
        files = arguments.get("files") or []
        path = str((files[0] if files else {}).get("path") or "app.py")
        respond(
            message["id"],
            {
                "content": [{"type": "text", "text": "fixture scan complete"}],
                "structuredContent": {
                    "findings": [
                        {
                            "rule_id": "MCP_COMMAND",
                            "file_path": path,
                            "line_start": 1,
                            "line_end": 1,
                            "severity": "high",
                            "risk_type": "Command Execution",
                            "message": "Untrusted input reaches a shell command.",
                            "evidence": "password = 'FixtureSecret123'; os.system(command)",
                            "confidence": 0.9,
                        }
                    ]
                },
                "isError": False,
            },
        )

