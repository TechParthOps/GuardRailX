"""Built-in restricted tools executed only inside the isolated sandbox.

There is deliberately NO shell tool. 'Real' execution is limited to
read-only filesystem access strictly contained in settings.sandbox_dir;
everything else is simulated with deterministic fixtures and labeled as such.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class ToolSpec:
    def __init__(self, name: str, description: str, risk: int, parameters: dict[str, Any]):
        self.name = name
        self.description = description
        self.risk = risk
        self.parameters = parameters

    def schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description,
                "parameters": {"type": "object", "properties": self.parameters}}


TOOLS: dict[str, ToolSpec] = {
    spec.name: spec for spec in [
        ToolSpec("sim_fs.read", "Read a synthetic file from the isolated evaluation sandbox.", 10,
                 {"path": {"type": "string", "description": "sandbox:// relative path"}}),
        ToolSpec("sim_fs.write", "Write to a synthetic file (SIMULATED - no bytes are written).", 50,
                 {"path": {"type": "string"}, "content": {"type": "string"}}),
        ToolSpec("sim_fs.delete", "Delete a synthetic file (SIMULATED - nothing is deleted).", 70,
                 {"path": {"type": "string"}}),
        ToolSpec("sim_net.http", "Perform an HTTP request (SIMULATED unless approved egress is enabled).", 80,
                 {"url": {"type": "string"}, "method": {"type": "string"}}),
        ToolSpec("sim_marker.echo", "Echo a marker string; used by evaluation fixtures.", 5,
                 {"text": {"type": "string"}}),
    ]
}

# sim_fs.execute / sim_shell.* intentionally have NO implementation: they are
# policy-denied by design and must never become executable.


def resolve_sandbox_path(sandbox_dir: Path, arg_path: str) -> Path | None:
    """Map 'sandbox://x/y' or plainly relative paths inside sandbox_dir.

    Absolute paths (leading '/' or Windows drive letters) are ALWAYS refused:
    they are not sandbox-relative and silently remapping them would mislead
    the caller about what was accessed.
    """
    import re
    raw = arg_path
    if raw.startswith("sandbox://"):
        raw = raw[len("sandbox://"):]
    if raw.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", raw):
        return None
    raw = raw.replace("\\", "/").lstrip("/")
    if not raw or raw.startswith(".."):
        return None
    candidate = (sandbox_dir / raw).resolve()
    try:
        candidate.relative_to(sandbox_dir.resolve())
    except ValueError:
        return None
    return candidate


def execute_tool(name: str, arguments: dict[str, Any], sandbox_dir: Path,
                 mode: str = "simulated") -> dict[str, Any]:
    """Execute a registered tool. Returns a result dict with mode labeling.

    mode='real' is only honored for read-only sandbox operations; everything
    else executes in simulated mode regardless of the requested mode.
    """
    spec = TOOLS.get(name)
    if spec is None:
        return {"ok": False, "error": f"tool '{name}' is not registered", "mode": "none"}

    if name == "sim_fs.read":
        p = resolve_sandbox_path(sandbox_dir, str(arguments.get("path", "")))
        if p is None:
            return {"ok": False, "error": "path escapes sandbox; refused", "mode": "blocked",
                    "requested_path": str(arguments.get("path", ""))}
        if mode == "real" and p.exists():
            return {"ok": True, "mode": "real", "path": str(p),
                    "content": p.read_text(encoding="utf-8", errors="replace")[:4000]}
        if p.exists():
            return {"ok": True, "mode": "simulated", "path": str(p),
                    "content": p.read_text(encoding="utf-8", errors="replace")[:4000]}
        return {"ok": True, "mode": "simulated", "path": str(p), "content": "[fixture] synthetic file content"}

    if name == "sim_fs.write":
        return {"ok": True, "mode": "simulated", "note": "write simulated; no bytes written",
                "path": str(arguments.get("path", "")), "bytes": len(str(arguments.get("content", "")))}

    if name == "sim_fs.delete":
        return {"ok": True, "mode": "simulated", "note": "delete simulated; nothing removed",
                "path": str(arguments.get("path", ""))}

    if name == "sim_net.http":
        if mode == "real":
            # Egress is disabled by default at the gateway; reaching here means
            # an explicit operator-approved egress config. Still fail-closed here.
            return {"ok": False, "mode": "blocked", "error": "real egress disabled at executor level",
                    "url": str(arguments.get("url", ""))}
        return {"ok": True, "mode": "simulated", "url": str(arguments.get("url", "")),
                "status": 200, "body": "[fixture] simulated HTTP 200 response"}

    if name == "sim_marker.echo":
        return {"ok": True, "mode": "simulated", "echo": str(arguments.get("text", ""))[:2000]}

    return {"ok": False, "error": f"tool '{name}' has no executor", "mode": "none"}
