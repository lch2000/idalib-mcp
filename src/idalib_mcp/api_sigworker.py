"""MCP tools exposing the NySigWorker2 extended signature engine.

These tools are registered into the upstream ``MCP_SERVER`` at worker
import time (see ``idalib_mcp.worker``), and run alongside the upstream
``api_sigmaker`` tools. The pattern syntax supports:

- ``?``  wildcard byte (non-storing)
- ``*``  jump capture (stores the relative target)
- ``^``  bytes capture (stores raw bytes)
- ``[xx:yy]``  byte range, ``[xx|yy|zz]``  byte alternation
- ``(...)``  non-storing group, ``<...>``  storing group
- ``<* * * *: <sub-pattern>>``  nested deref match
- ``?{n}`` / ``?{n:m}``  repeat counts
- trailing ``+0xN``  result offset
"""

from __future__ import annotations

from typing import Annotated, Any, NotRequired, TypedDict

import idaapi

from ida_pro_mcp.ida_mcp.rpc import tool
from ida_pro_mcp.ida_mcp.sync import idasync
from ida_pro_mcp.ida_mcp.utils import parse_address

from . import sig_worker as _sw


def _resolve_addr(addr: str) -> int:
    """Resolve an address string or name to an effective address.

    Mirrors ``api_sigmaker._resolve_addr``: numeric/hex form first, then
    fall back to symbol resolution.
    """
    try:
        return parse_address(addr)
    except Exception:
        ea = idaapi.get_name_ea(idaapi.BADADDR, addr)
        if ea == idaapi.BADADDR:
            raise ValueError(f"Cannot resolve address or name: {addr}")
        return ea


class MakeSigAdvancedCandidate(TypedDict):
    worker_addr: str
    signature: str
    idb_count: int
    compare_count: NotRequired[int | None]


class MakeSigAdvancedResult(TypedDict):
    query: str
    addr: str
    candidates: list[MakeSigAdvancedCandidate]
    log: list[str]


class SearchSigAdvancedMatch(TypedDict):
    addr: str
    match_addr: str
    offset: str
    captures: str


class SearchSigAdvancedResult(TypedDict):
    pattern: str
    offset: str
    matches: list[SearchSigAdvancedMatch]
    log: list[str]


@tool
@idasync
def make_signature_advanced(
    addr: Annotated[
        str,
        "Target address or symbol name (e.g. '0x140001000' or 'main')",
    ],
    compare_exe: Annotated[
        str,
        "Optional path (on the worker filesystem) to a comparison binary; "
        "candidates report match counts against this image too",
    ] = "",
    max_workers: Annotated[
        int,
        "Maximum parallel xref-anchored walker count (default: 500)",
    ] = 500,
    max_found: Annotated[
        int,
        "Maximum candidate signatures to return (default: 10)",
    ] = 10,
    max_steps: Annotated[
        int,
        "Walk steps per worker before giving up (default: 50)",
    ] = 50,
    nested_enabled: Annotated[
        bool,
        "Enable nested-ref validation (deref captures, default: true)",
    ] = True,
    nested_depth: Annotated[
        int,
        "Maximum nested deref depth when validating (default: 2)",
    ] = 2,
    nested_max_instructions: Annotated[
        int,
        "Sub-pattern instruction cap per nested deref (default: 8)",
    ] = 8,
    follow_nested_refs: Annotated[
        bool,
        "Follow operand refs while building nested sub-patterns (default: true)",
    ] = True,
    validate_limit: Annotated[
        int,
        "Match cap used by the post-hoc uniqueness validator (default: 20)",
    ] = 20,
) -> MakeSigAdvancedResult:
    """Generate NySigWorker2 candidate signatures for an address.

    Walks forward/backward from each candidate xref site, validates with
    the upstream native AOB scanner, and (when ``nested_enabled``) folds
    in nested deref captures (``<* * * *: sub-pattern>``) to disambiguate
    siblings. Returns one or more signature candidates plus an
    informational log."""
    ea = _resolve_addr(addr)
    options = _sw.SignatureOptions(
        max_workers=max_workers,
        max_found=max_found,
        max_steps=max_steps,
        nested_enabled=nested_enabled,
        nested_depth=nested_depth,
        nested_max_instructions=nested_max_instructions,
        follow_nested_refs=follow_nested_refs,
        validate_limit=validate_limit,
    )
    logs: list[str] = []
    results = _sw.make_sig(ea, compare_exe or None, options, logs.append)
    candidates: list[MakeSigAdvancedCandidate] = []
    for r in results:
        entry: MakeSigAdvancedCandidate = {
            "worker_addr": _sw.format_ea(r.worker_ea),
            "signature": r.signature,
            "idb_count": r.idb_count,
            "compare_count": r.compare_count,
        }
        candidates.append(entry)
    return {
        "query": addr,
        "addr": _sw.format_ea(ea),
        "candidates": candidates,
        "log": logs,
    }


@tool
@idasync
def search_signature_advanced(
    signature: Annotated[
        str,
        "Pattern in NySigWorker2 extended syntax; may carry a "
        "trailing '+0xN' result offset",
    ],
    limit: Annotated[
        int,
        "Maximum matches to return (default: 100)",
    ] = 100,
) -> SearchSigAdvancedResult:
    """Search the current IDB with the extended pattern engine.

    Supports byte ranges, alternations, jump captures, bytes captures,
    storing/non-storing groups, and nested deref matches. Each result
    reports both the raw match address and the effective address after
    the trailing ``+0xN`` offset (if any)."""
    logs: list[str] = []
    raw = _sw.search_sig(signature, limit, _sw.DEFAULT_LANGUAGE, logs.append)
    pattern, offset = _sw.split_signature_offset(signature)
    matches: list[SearchSigAdvancedMatch] = []
    for match_addr, args in raw:
        matches.append(
            {
                "addr": _sw.format_ea(match_addr + offset),
                "match_addr": _sw.format_ea(match_addr),
                "offset": f"0x{offset:x}",
                "captures": _sw.format_match_args(args),
            }
        )
    return {
        "pattern": pattern,
        "offset": f"0x{offset:x}",
        "matches": matches,
        "log": logs,
    }
