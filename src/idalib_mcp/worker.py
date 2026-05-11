from __future__ import annotations

import argparse
import importlib
import os
import sys
from pathlib import Path

from .config import configure_idalib_environment, default_ida_home_from_env


def split_worker_args(argv: list[str]) -> tuple[Path | None, Path | None, list[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--ida-home", type=Path, default=default_ida_home_from_env())
    parser.add_argument("--ida-config-root", type=Path, default=None, help=argparse.SUPPRESS)
    args, remaining = parser.parse_known_args(argv)
    return args.ida_home, args.ida_config_root, remaining


def main() -> None:
    ida_home, config_root, remaining = split_worker_args(sys.argv[1:])

    try:
        configure_idalib_environment(ida_home, config_root=config_root)
    except Exception as exc:
        raise SystemExit(f"Failed to configure IDA home for idalib: {exc}") from exc

    sys.argv = [sys.argv[0], *remaining]

    try:
        upstream_server = importlib.import_module("ida_pro_mcp.idalib_server")
    except ImportError as exc:
        raise SystemExit(
            "Missing dependency 'ida-pro-mcp'. Install this project with its "
            "dependencies, then retry."
        ) from exc

    os.environ.setdefault("IDA_MCP_WORKER", "1")
    upstream_server.main()


if __name__ == "__main__":
    main()
