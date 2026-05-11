# Plan

## Index

- Scope
- Approach
- Steps
- Notes

## Scope

Build a fresh headless idalib MCP package in this workspace. Use the upstream `ida-pro-mcp` package as the API provider so the MCP tools stay aligned with the example project, while this project owns command-line IDA path selection and instance management UI.

## Approach

Use a supervisor process that imports upstream `ida_pro_mcp.idalib_supervisor`, replaces its worker spawning with this project's worker wrapper, and serves MCP plus a small local web UI. Worker processes configure `idapro` with a process-local config rooted at `--ida-home` before importing upstream `ida_pro_mcp.idalib_server`.

## Steps

- [x] Initialize git baseline and feature branch.
- [x] Inspect upstream idalib supervisor/worker behavior and local IDA installation layout.
- [x] Create package metadata and documentation.
- [x] Add process-local IDA home configuration helper.
- [x] Add worker wrapper that configures idalib before importing `idapro` through upstream code.
- [x] Add supervisor wrapper with multi-worker spawning and instance web UI.
- [x] Add upstream-style MCP client install/config commands for the future `nyaoouo/idalib-mcp` repository.
- [x] Add dependency-free unit tests for local configuration helpers.
- [x] Add MCP tool-list/path auto-open regression tests from live VS Code testing.
- [x] Start the instance web UI as a local sidecar when MCP runs over stdio.
- [x] Ask whether to save the IDB before closing an instance from the web UI.
- [x] Run syntax and unit checks.
- [x] Run full IDA/idapro smoke test after dependency installation approval.

## Notes

- `--ida-home` should not modify the user's real Hex-Rays idalib config file.
- Debugger tools come from upstream `api_debug.py`; use `--unsafe` and `?ext=dbg` to expose them.
- Multi-instance debugging is handled by one idalib worker process per open database/session.
- Smoke test on port `18745` loaded `D:\tools\IDA_PRO_9.1\idalib.dll`, returned 94 MCP tools including `idalib_open`, `idalib_close`, `dbg_start`, and `decompile`, opened a writable copy of `notepad.exe`, listed it through `/api/instances`, then closed it through the web API.
- VS Code/Copilot may cap or reorder visible MCP tools. The supervisor now lists management tools before worker tools and allows analysis calls to auto-open an existing filesystem path passed as the `database` selector.
- Stdio mode starts the instance manager on the configured HTTP host/port, falls back to an ephemeral port if needed, and reports the `/instances` URL on stderr so stdout remains valid MCP JSON-RPC.
- Web UI close can save first by calling the upstream worker save tool (`idalib_save` for idalib workers, `idb_save` for GUI-backed sessions), then closing the session.
