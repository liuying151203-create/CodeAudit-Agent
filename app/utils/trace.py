from collections.abc import Callable
from time import perf_counter
from typing import Any

from app.schemas.report import AgentTrace


def trace_tool(state: dict[str, Any], node_name: str, tool_name: str, input_summary: str, fn: Callable[[], Any]) -> Any:
    start = perf_counter()
    status = "success"
    try:
        result = fn()
        return result
    except Exception as exc:  # pragma: no cover - defensive trace path
        status = "error"
        state.setdefault("errors", []).append(f"{node_name}: {exc}")
        raise
    finally:
        elapsed_ms = int((perf_counter() - start) * 1000)
        traces = state.setdefault("traces", [])
        traces.append(
            AgentTrace(
                node_name=node_name,
                tool_name=tool_name,
                input_summary=input_summary,
                output_summary="completed" if status == "success" else "failed",
                elapsed_ms=elapsed_ms,
                status=status,
            )
        )
