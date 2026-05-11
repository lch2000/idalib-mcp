from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from idalib_mcp.server import (
    _bound_instance_ui_url,
    _enable_path_database_auto_open,
    _instance_ui_url,
    _prefer_management_tools_in_tool_list,
    _save_session_before_close,
    _serve_stdio_instance_ui,
)


class FakeMcp:
    def __init__(self) -> None:
        self._http_server: FakeHttpServer | None = None
        self.fail_ports: set[int] = set()
        self.serve_calls: list[tuple[str, int, bool, type]] = []

    def _mcp_tools_list(self) -> dict[str, Any]:
        return {
            "tools": [
                {"name": "idalib_open"},
                {"name": "idalib_list"},
            ]
        }

    def serve(self, *, host: str, port: int, background: bool, request_handler: type) -> None:
        self.serve_calls.append((host, port, background, request_handler))
        if port in self.fail_ports:
            raise OSError("address already in use")
        bound_port = 18745 if port == 0 else port
        self._http_server = FakeHttpServer(host, bound_port)


class FakeHttpServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 18745) -> None:
        self.server_address = (host, port)


class FakeSession:
    def __init__(self, backend: str) -> None:
        self.backend = backend


class FakeSupervisor:
    def __init__(self) -> None:
        self.opened: tuple[str, str] | None = None
        self.forwarded: tuple[str, dict[str, Any]] | None = None
        self.sessions: dict[str, FakeSession] = {}
        self.saved: tuple[FakeSession, str, dict[str, Any]] | None = None
        self.save_result: dict[str, Any] = {"ok": True, "path": "sample.i64"}

    def worker_tools(self) -> list[dict[str, Any]]:
        return [
            {"name": "decompile"},
            {"name": "idalib_open"},
        ]

    def resolve_session(self, database: str | None) -> Any:
        if database in self.sessions:
            return self.sessions[database]
        if database == "existing-session":
            return "existing-session"
        raise KeyError(database)

    def resolve_context_id(self) -> str:
        return "context-id"

    def open_session(self, input_path: str, *, context_id: str) -> str:
        self.opened = (input_path, context_id)
        return "opened-session"

    def forward_raw(self, session: str, request: dict[str, Any]) -> dict[str, Any]:
        self.forwarded = (session, request)
        return {"ok": True}

    def call_worker_tool(self, session: FakeSession, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.saved = (session, tool_name, arguments)
        return self.save_result


class FakeUpstream:
    IDALIB_MANAGEMENT_TOOLS = {"idalib_open", "idalib_list"}
    IDALIB_HIDDEN_PLUGIN_TOOLS = {"jump_to_address"}

    def __init__(self) -> None:
        self.mcp = FakeMcp()
        self.supervisor = FakeSupervisor()
        self._original_dispatch_called = False

    def _require_supervisor(self) -> FakeSupervisor:
        return self.supervisor

    def _jsonrpc_result(self, request_id: int, result: Any) -> dict[str, Any]:
        return {"id": request_id, "result": result}

    def _call_tool_result(self, payload: Any, *, is_error: bool = False) -> dict[str, Any]:
        return {"payload": payload, "is_error": is_error}

    def _original_dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        self._original_dispatch_called = True
        return {"dispatched": request}


class ServerIntegrationPatchTests(unittest.TestCase):
    def test_instance_ui_url_uses_bound_http_address(self) -> None:
        mcp = FakeMcp()
        mcp._http_server = FakeHttpServer()

        self.assertEqual(_instance_ui_url("127.0.0.1", 8745), "http://127.0.0.1:8745/instances")
        self.assertEqual(_instance_ui_url("::1", 8745), "http://[::1]:8745/instances")
        self.assertEqual(_bound_instance_ui_url(mcp, "localhost", 0), "http://127.0.0.1:18745/instances")

    def test_stdio_instance_ui_retries_with_ephemeral_port(self) -> None:
        upstream = FakeUpstream()
        upstream.mcp.fail_ports.add(8745)

        with self.assertLogs("idalib_mcp.server", level="WARNING"):
            url = _serve_stdio_instance_ui(upstream, "127.0.0.1", 8745, FakeHttpServer)

        self.assertEqual(url, "http://127.0.0.1:18745/instances")
        self.assertEqual([call[1] for call in upstream.mcp.serve_calls], [8745, 0])
        self.assertTrue(all(call[2] for call in upstream.mcp.serve_calls))

    def test_management_tools_are_listed_before_worker_tools(self) -> None:
        upstream = FakeUpstream()

        _prefer_management_tools_in_tool_list(upstream)
        result = upstream._handle_tools_list({"id": 1})

        self.assertEqual(
            [tool["name"] for tool in result["result"]["tools"]],
            ["idalib_open", "idalib_list", "decompile"],
        )

    def test_save_session_before_close_uses_worker_save_tool(self) -> None:
        supervisor = FakeSupervisor()
        session = FakeSession("worker")
        supervisor.sessions["sample"] = session

        result = _save_session_before_close(supervisor, "sample")

        self.assertEqual(result, {"ok": True, "path": "sample.i64"})
        self.assertEqual(supervisor.saved, (session, "idalib_save", {"path": ""}))

    def test_save_session_before_close_uses_gui_save_tool(self) -> None:
        supervisor = FakeSupervisor()
        session = FakeSession("gui")
        supervisor.sessions["sample"] = session

        _save_session_before_close(supervisor, "sample")

        self.assertEqual(supervisor.saved, (session, "idb_save", {"path": ""}))

    def test_analysis_call_auto_opens_existing_database_path(self) -> None:
        upstream = FakeUpstream()
        _enable_path_database_auto_open(upstream)

        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "sample.exe"
            input_path.write_bytes(b"MZ")

            result = upstream._handle_tools_call(
                {
                    "id": 7,
                    "params": {
                        "name": "decompile",
                        "arguments": {
                            "database": str(input_path),
                            "addr": "0x401000",
                        },
                    },
                }
            )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(upstream.supervisor.opened, (str(input_path), "context-id"))
        self.assertIsNotNone(upstream.supervisor.forwarded)
        session, forwarded = upstream.supervisor.forwarded
        self.assertEqual(session, "opened-session")
        self.assertEqual(forwarded["params"]["arguments"], {"addr": "0x401000"})


if __name__ == "__main__":
    unittest.main()