#!/usr/bin/env python3
#
# Copyright 2026 Rubicon Communications, LLC (Netgate)
#
# SPDX-License-Identifier: Apache-2.0
#

"""Generate Python type stubs for vpp_papi VAPI methods.

This script runs at build time, parsing .api files via vppapigen as a library
and producing:
  - src/vpp-api/python/vpp_papi/vapi_types.pyi: type stubs for
    VppApiDynamicMethodHolder
  - test/vpp_papi_provider.pyi: type stubs for VppPapiProvider (test framework)

Each .api file is parsed in process; an in-memory descriptor is built from the
parsed AST (no .python.json files written) and the two stubs are emitted from
the aggregated descriptors.
"""

import argparse
import os
import pathlib
import subprocess
import sys
from typing import Any

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_vpp_root() -> str:
    """Locate the VPP source checkout root.

    Resolved from this script's own location (not the caller's CWD) so it works
    whether we run as the in-tree copy under src/tools/vppapigen or as an
    installed copy that lives inside the same checkout (e.g. under
    build-root/install-*). Out-of-tree plugin builds invoke the installed copy;
    deriving the root this way lets a single invocation re-scan the full in-tree
    .api set and fold the plugin's own .api files on top.
    """
    return (
        subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=SCRIPT_DIR)
        .strip()
        .decode()
    )


BASE_DIR = _find_vpp_root()

# vppapigen lives in the source tree even when this script runs from an
# installed copy (the installed share/vpp copy has no vppapigen.py), so import
# it from the source tree rather than from SCRIPT_DIR.
sys.path.insert(0, os.path.join(BASE_DIR, "src", "tools", "vppapigen"))

import vppapigen  # noqa: E402

# Top-level subdirectories of src/ that contain .api files.
API_SEARCH_ROOTS = ("plugins", "vlibmemory", "vnet", "vlib", "vpp")

# Internal VPP API fields excluded from method signatures
INTERNAL_FIELDS = {"_vl_msg_id", "client_index", "context"}

# Quiet mode silences routine progress output (set by --quiet). Errors are
# always emitted regardless.
QUIET = False


def info(msg: str) -> None:
    if not QUIET:
        print(msg)


# ---------------------------------------------------------------------------
# Descriptor building from vppapigen's parsed AST.
#
# The descriptor is the intermediate representation the stub generator
# consumes. It used to be produced by a separate vppapigen plugin
# (vppapigen_python.py) that wrote .python.json files; this script now builds
# it in memory.
# ---------------------------------------------------------------------------

# VPP base type -> Python type annotation
BASE_TYPE_MAP = {
    "u8": "int",
    "i8": "int",
    "u16": "int",
    "i16": "int",
    "u32": "int",
    "i32": "int",
    "u64": "int",
    "i64": "int",
    "f64": "float",
    "bool": "bool",
    "string": "str",
}

# VPP types with special Python input type mappings
SPECIAL_INPUT_TYPES = {
    "vl_api_ip4_address_t": ["ipaddress.IPv4Address", "str"],
    "vl_api_ip6_address_t": ["ipaddress.IPv6Address", "str"],
    "vl_api_ip4_prefix_t": ["ipaddress.IPv4Network", "str"],
    "vl_api_ip6_prefix_t": ["ipaddress.IPv6Network", "str"],
    "vl_api_address_t": ["ipaddress.IPv4Address", "ipaddress.IPv6Address", "str"],
    "vl_api_prefix_t": ["ipaddress.IPv4Network", "ipaddress.IPv6Network", "str"],
    "vl_api_address_with_prefix_t": [
        "ipaddress.IPv4Interface",
        "ipaddress.IPv6Interface",
        "str",
    ],
    "vl_api_ip4_address_with_prefix_t": ["ipaddress.IPv4Interface", "str"],
    "vl_api_ip6_address_with_prefix_t": ["ipaddress.IPv6Interface", "str"],
    "vl_api_mac_address_t": ["MACAddress", "str"],
    "vl_api_timestamp_t": ["datetime.datetime"],
}

# VPP types that vpp_papi *unpacks* into a richer Python type at decode time
# (vpp_format.py:conversion_unpacker_table). The input mapping above accepts
# the same types plus `str` as a convenience for callers; output positions are
# tighter — vpp_papi never returns a bare `str` for these.
SPECIAL_OUTPUT_TYPES = {
    "vl_api_ip4_address_t": ["ipaddress.IPv4Address"],
    "vl_api_ip6_address_t": ["ipaddress.IPv6Address"],
    "vl_api_ip4_prefix_t": ["ipaddress.IPv4Network"],
    "vl_api_ip6_prefix_t": ["ipaddress.IPv6Network"],
    "vl_api_address_t": ["ipaddress.IPv4Address", "ipaddress.IPv6Address"],
    "vl_api_prefix_t": ["ipaddress.IPv4Network", "ipaddress.IPv6Network"],
    "vl_api_address_with_prefix_t": [
        "ipaddress.IPv4Interface",
        "ipaddress.IPv6Interface",
    ],
    "vl_api_ip4_address_with_prefix_t": ["ipaddress.IPv4Interface"],
    "vl_api_ip6_address_with_prefix_t": ["ipaddress.IPv6Interface"],
    "vl_api_mac_address_t": ["MACAddress"],
    "vl_api_timestamp_t": ["datetime.datetime"],
}


def _make_type_name(name: str) -> str:
    """Convert a VPP type/message name to vl_api_<name>_t."""
    return f"vl_api_{name}_t"


def _vpp_type_to_python_annotation(
    vpp_type: str,
    all_types: dict[str, Any],
    all_enums: dict[str, Any],
    all_unions: dict[str, Any],
    all_aliases: dict[str, Any],
    output: bool = False,
) -> str:
    """Map a VPP type name to a Python type annotation string.

    `output=True` selects the tighter SPECIAL_OUTPUT_TYPES (no `str` fallback)
    and emits a `_nt` suffix for typedef/union refs (the NamedTuple twin).
    """
    if vpp_type in BASE_TYPE_MAP:
        return BASE_TYPE_MAP[vpp_type]

    table = SPECIAL_OUTPUT_TYPES if output else SPECIAL_INPUT_TYPES
    if vpp_type in table:
        return " | ".join(table[vpp_type])

    if vpp_type in all_enums:
        return f"VppEnum.{vpp_type}"

    if vpp_type in all_types or vpp_type in all_unions:
        return f"{vpp_type}_nt" if output else vpp_type

    if vpp_type in all_aliases:
        return vpp_type

    if vpp_type.startswith("vl_api_") and vpp_type.endswith("_t"):
        return "Any"

    return "Any"


def _walk_block_to_fields(
    block: Any,
    all_types: dict[str, Any],
    all_enums: dict[str, Any],
    all_unions: dict[str, Any],
    all_aliases: dict[str, Any],
) -> list[dict[str, Any]]:
    """Walk a block of Field/Array AST objects and produce annotated field list."""
    fields = []
    for item in block:
        if item.__class__.__name__ == "Option":
            continue

        field_name = item.fieldname
        if field_name in INTERNAL_FIELDS:
            continue

        if item.__class__.__name__ == "Array":
            field_type = item.fieldtype
            if field_type == "string":
                fields.append(
                    {
                        "name": field_name,
                        "type": "str",
                        "output_type": "str",
                        "is_array": False,
                    }
                )
            else:
                elem_in = _vpp_type_to_python_annotation(
                    field_type, all_types, all_enums, all_unions, all_aliases
                )
                elem_out = _vpp_type_to_python_annotation(
                    field_type,
                    all_types,
                    all_enums,
                    all_unions,
                    all_aliases,
                    output=True,
                )
                fields.append(
                    {
                        "name": field_name,
                        "type": f"list[{elem_in}]",
                        "output_type": f"list[{elem_out}]",
                        "is_array": True,
                        "array_element_type": elem_in,
                        "length": item.length,
                        "lengthfield": item.lengthfield,
                    }
                )
        else:
            field_type = item.fieldtype
            py_type = _vpp_type_to_python_annotation(
                field_type, all_types, all_enums, all_unions, all_aliases
            )
            out_type = _vpp_type_to_python_annotation(
                field_type,
                all_types,
                all_enums,
                all_unions,
                all_aliases,
                output=True,
            )
            fields.append(
                {
                    "name": field_name,
                    "output_type": out_type,
                    "type": py_type,
                    "is_array": False,
                }
            )

    return fields


def _format_crc(crc: Any) -> str:
    """Format CRC value as hex string, handling both int and bytes."""
    if isinstance(crc, bytes):
        return "0x" + crc.hex()
    return f"0x{crc:08x}"


def _process_alias(
    a: Any,
    all_types: dict[str, Any],
    all_enums: dict[str, Any],
    all_unions: dict[str, Any],
    all_aliases: dict[str, Any],
) -> dict[str, Any]:
    full_name = _make_type_name(a.name)
    underlying = a.alias.get("type")
    length = a.alias.get("length")
    if length:
        if underlying == "u8":
            python_type = "bytes"
        else:
            elem = _vpp_type_to_python_annotation(
                underlying, all_types, all_enums, all_unions, all_aliases
            )
            python_type = f"list[{elem}]"
    else:
        python_type = _vpp_type_to_python_annotation(
            underlying, all_types, all_enums, all_unions, all_aliases
        )
    return {
        "name": a.name,
        "full_name": full_name,
        "alias": a.alias,
        "kind": "alias",
        "python_type": python_type,
        "in_special_input": full_name in SPECIAL_INPUT_TYPES,
    }


def _process_service(svc: Any, messages_by_name: dict[str, Any]) -> dict[str, Any]:
    reply = svc.reply
    is_stream = svc.stream
    stream_msg = svc.stream_message
    events = svc.events

    caller_msg = messages_by_name.get(svc.caller)
    params = caller_msg.get("fields", []) if caller_msg else []

    return_type = None
    return_kind = "single"

    if reply != "null":
        reply_full = _make_type_name(reply)
        if is_stream and stream_msg:
            stream_full = _make_type_name(stream_msg)
            return_type = {
                "kind": "stream_modern",
                "reply_type": reply_full,
                "details_type": stream_full,
            }
            return_kind = "stream_modern"
        elif is_stream:
            return_type = {
                "kind": "stream_legacy",
                "details_type": reply_full,
            }
            return_kind = "stream_legacy"
        else:
            return_type = {
                "kind": "single",
                "reply_type": reply_full,
            }
            return_kind = "single"

    return {
        "name": svc.caller,
        "params": params,
        "return_type": return_type,
        "return_kind": return_kind,
        "reply": reply,
        "is_stream": is_stream,
        "stream_msg": stream_msg,
        "events": events,
    }


def parse_api_file(api_file: pathlib.Path, includedirs: list[str]) -> dict[str, Any]:
    """Parse a single .api file and return vppapigen's processed `s` dict.

    Mirrors the parser pipeline in vppapigen.run_vppapigen for the
    process_imports=True case (which is what the old plugin opted into):
    parse, process imports + own definitions into one merged `s`, then run
    add_msg_id and foldup_crcs.
    """
    # vppapigen keeps state in module-level globals; reset between files so
    # results don't leak across .api files.
    vppapigen.dirlist.clear()
    vppapigen.global_types.clear()
    vppapigen.seen_imports.clear()
    vppapigen.dirlist_add(includedirs)

    parser = vppapigen.VPPAPI(debug=False, filename=str(api_file), logger=vppapigen.log)
    parsed_objects = parser.parse_filename(str(api_file))

    result = parser.process_imports(parsed_objects, False, [])
    s = parser.process(result)

    s["Define"] = vppapigen.add_msg_id(s["Define"])
    vppapigen.foldup_crcs(s["Define"])

    return s


def build_descriptor(api_file: pathlib.Path, s: dict[str, Any]) -> dict[str, Any]:
    """Transform a parsed `s` AST into a stub-generator descriptor dict."""
    basename = api_file.name
    filename = api_file.stem

    all_types: dict[str, Any] = {}
    all_enums: dict[str, Any] = {}
    all_unions: dict[str, Any] = {}
    all_aliases: dict[str, Any] = {}

    def register(type_list: list[Any]) -> None:
        for t in type_list:
            full_name = _make_type_name(t.name)
            cls_name = t.__class__.__name__
            if cls_name == "Typedef":
                all_types[full_name] = True
            elif cls_name == "Union":
                all_unions[full_name] = True
            elif cls_name in ("Enum", "EnumFlag"):
                all_enums[full_name] = True
            elif cls_name == "Using":
                all_aliases[full_name] = True

    register(s.get("types", []))
    register(s.get("imported", {}).get("types", []))

    messages_by_name: dict[str, Any] = {}
    for msg in s.get("Define", []):
        messages_by_name[msg.name] = {
            "fields": _walk_block_to_fields(
                msg.block, all_types, all_enums, all_unions, all_aliases
            ),
        }

    typedefs = []
    unions = []
    enums = []
    aliases = []
    for t in s.get("types", []):
        cls = t.__class__.__name__
        if cls == "Typedef":
            typedefs.append(
                {
                    "name": t.name,
                    "full_name": _make_type_name(t.name),
                    "fields": _walk_block_to_fields(
                        t.block, all_types, all_enums, all_unions, all_aliases
                    ),
                    "kind": "typedef",
                }
            )
        elif cls == "Union":
            unions.append(
                {
                    "name": t.name,
                    "full_name": _make_type_name(t.name),
                    "fields": _walk_block_to_fields(
                        t.block, all_types, all_enums, all_unions, all_aliases
                    ),
                    "kind": "union",
                }
            )
        elif cls in ("Enum", "EnumFlag"):
            enums.append(
                {
                    "name": t.name,
                    "full_name": _make_type_name(t.name),
                    "entries": [
                        {"id": entry[0], "value": entry[1]} for entry in t.block
                    ],
                    "enumtype": t.enumtype,
                    "kind": "enumflag" if cls == "EnumFlag" else "enum",
                }
            )
        elif cls == "Using":
            aliases.append(
                _process_alias(t, all_types, all_enums, all_unions, all_aliases)
            )

    msgs = []
    for msg in s.get("Define", []):
        msgs.append(
            {
                "name": msg.name,
                "full_name": _make_type_name(msg.name),
                "fields": _walk_block_to_fields(
                    msg.block, all_types, all_enums, all_unions, all_aliases
                ),
                "crc": _format_crc(msg.crc),
                "options": msg.options,
                "comment": msg.comment or "",
            }
        )

    services = [_process_service(svc, messages_by_name) for svc in s.get("Service", [])]

    return {
        "source_file": basename,
        "module": filename,
        "typedefs": typedefs,
        "unions": unions,
        "enums": enums,
        "aliases": aliases,
        "messages": msgs,
        "services": services,
        "options": s.get("Option", {}),
        "file_crc": _format_crc(s.get("file_crc", 0)),
    }


def find_api_files(
    src_dir: pathlib.Path, extra_files: list[pathlib.Path] | None = None
) -> list[pathlib.Path]:
    """Find all in-tree .api files, plus any explicit extra .api files.

    extra_files are out-of-tree plugin .api files passed via --extra-api-file;
    they are folded in alongside the in-tree scan so the generated stubs cover
    both in one shot.
    """
    info(f"Searching '{src_dir.as_posix()}' for .api files.")
    globs: list[pathlib.Path] = []
    for root in API_SEARCH_ROOTS:
        globs.extend(src_dir.glob(f"{root}/**/*.api"))
    for extra in extra_files or []:
        if not extra.is_file():
            print(
                f"Warning: --extra-api-file '{extra}' is not a file; skipping.",
                file=sys.stderr,
            )
            continue
        globs.append(extra)
    return sorted(globs)


def _normalize_type(type_str: str) -> str:
    """Normalize a type string for use in stubs.

    Strips 'VppEnum.' prefix since enum types are standalone IntEnum classes
    in the generated stub, not attributes of a VppEnum class.
    """
    return type_str.replace("VppEnum.", "")


def _widen_input_type(
    type_str: str, typedef_union_names: set[str], enum_names: set[str]
) -> str:
    """Widen a type for use in an input position (parameter or TypedDict field).

    - typedef / union refs become `T | Mapping[str, Any]`, so callers may pass
      either a literal-key dict or a programmatically-built mapping
    - enum refs become `T | int`, since vpp_papi accepts plain integers at
      runtime and existing test code commonly uses numeric literals
    - `list[T]` becomes `Sequence[<widened T>]`. Sequence rather than list
      because list is invariant: pyright would refuse `list[str]` where
      `list[IPv4Network | str]` is declared. Sequence is covariant.
    """
    if type_str.startswith("list[") and type_str.endswith("]"):
        inner = type_str[5:-1]
        if inner in typedef_union_names:
            return f"Sequence[{inner} | Mapping[str, Any]]"
        if inner in enum_names:
            return f"Sequence[{inner} | int]"
        return f"Sequence[{inner}]"
    if type_str in typedef_union_names:
        return f"{type_str} | Mapping[str, Any]"
    if type_str in enum_names:
        return f"{type_str} | int"
    return type_str


def generate_field_annotation(
    field: dict[str, Any],
    typedef_union_names: set[str] | None = None,
    enum_names: set[str] | None = None,
    output_mode: bool = False,
) -> str:
    """Generate a field annotation string.

    - `output_mode=True`: use the field's `output_type` (already resolved by the
      plugin to use NamedTuple twins for typedef refs and tighter SPECIAL_OUTPUT
      types — no `str` fallback that vpp_papi never returns at decode time).
    - `typedef_union_names`/`enum_names` provided (and not output_mode): widen
      typedef/union refs to accept Mapping[str, Any] and enum refs to accept
      int (used for input-position TypedDict fields and method parameters).
    - Neither: leave the type as-is."""
    if output_mode:
        field_type = _normalize_type(field.get("output_type", field.get("type", "Any")))
    else:
        field_type = _normalize_type(field.get("type", "Any"))
        if typedef_union_names is not None:
            field_type = _widen_input_type(
                field_type, typedef_union_names, enum_names or set()
            )
    return f"{field['name']}: {field_type}"


def generate_typeddict_class(
    name: str,
    fields: list[dict[str, Any]],
    typedef_union_names: set[str],
    enum_names: set[str],
    comment: str = "",
    total: bool = True,
) -> str:
    """Generate a TypedDict class definition for a typedef/union."""
    lines = []
    if comment:
        lines.append(f'    """{comment}"""')
    else:
        lines.append(f'    """Auto-generated TypedDict for {name}."""')

    if not fields:
        lines.append("    pass")
    else:
        for field in fields:
            lines.append(
                f"    {generate_field_annotation(field, typedef_union_names, enum_names)}"
            )

    body = "\n".join(lines)
    header = (
        f"class {name}(TypedDict)" if total else f"class {name}(TypedDict, total=False)"
    )
    return f"{header}:\n{body}\n"


def generate_namedtuple_class(
    name: str,
    fields: list[dict[str, Any]],
    comment: str = "",
) -> str:
    """Generate a NamedTuple class definition. Used for reply messages and for
    the `_nt` NamedTuple twins of typedefs/unions. Each field's `output_type`
    (precomputed by the plugin) is used so typedef/union refs point at their
    `_nt` twins and special types drop the `str` input alternative."""
    lines = []
    if comment:
        lines.append(f'    """{comment}"""')
    else:
        lines.append(f'    """Auto-generated NamedTuple for {name}."""')

    if not fields:
        lines.append("    pass")
    else:
        for field in fields:
            lines.append(f"    {generate_field_annotation(field, output_mode=True)}")

    body = "\n".join(lines)
    return f"class {name}(NamedTuple):\n{body}\n"


def generate_enum_class(enum: dict[str, Any]) -> str:
    """Generate an IntEnum class definition."""
    name = enum["full_name"]
    entries = enum.get("entries", [])

    lines = [f"class {name}(IntEnum):"]
    if not entries:
        lines.append("    pass")
    else:
        for entry in entries:
            lines.append(f"    {entry['id']} = {entry['value']}")

    return "\n".join(lines) + "\n"


def generate_method_signature(
    svc: dict[str, Any],
    typedef_union_names: set[str],
    enum_names: set[str],
    defaulted_params: set[str] | None = None,
) -> tuple[str, str]:
    """Generate a method signature and return type annotation.

    `defaulted_params`, if given, names parameters with runtime-supplied
    defaults (from the provider's defaultmapping table). Once any parameter
    in declaration order has a default, all subsequent parameters get `= ...`
    too — Python forbids required parameters after defaulted ones, so we
    cascade rather than reorder (which would break positional callers).

    Returns:
        (method_line, return_type_name_or_None)
    """
    name = svc["name"]
    params = svc.get("params", [])
    return_info = svc.get("return_type")
    defaulted_params = defaulted_params or set()

    # Build parameter list (excluding internal fields). Method parameters are an
    # input position: typedef/union refs are widened to also accept Mapping,
    # and enum refs to accept int.
    param_parts = []
    after_default = False
    for p in params:
        if p["name"] in INTERNAL_FIELDS:
            continue
        ptype = _widen_input_type(
            _normalize_type(p["type"]), typedef_union_names, enum_names
        )
        if p["name"] in defaulted_params:
            after_default = True
        suffix = " = ..." if after_default else ""
        param_parts.append(f"{p['name']}: {ptype}{suffix}")

    params_str = ", ".join(param_parts)

    # Build return type
    if return_info:
        kind = return_info["kind"]
        if kind == "single":
            ret_type = _normalize_type(return_info["reply_type"])
        elif kind == "stream_modern":
            ret_type = f"tuple[{_normalize_type(return_info['reply_type'])}, list[{_normalize_type(return_info['details_type'])}]]"
        elif kind == "stream_legacy":
            ret_type = f"list[{_normalize_type(return_info['details_type'])}]"
        else:
            ret_type = "Any"
    else:
        ret_type = "Any"

    method_line = f"    def {name}(self, {params_str}) -> {ret_type}: ..."
    return method_line, ret_type


def generate_vapi_types(descriptors: list[Any], output_path: str) -> None:
    """Generate vapi_types.py from collected descriptors."""

    # Collect all types across all files for cross-reference resolution
    all_messages = {}  # name -> message descriptor
    all_types = {}  # full_name -> typedef descriptor
    all_enums = {}  # full_name -> enum descriptor
    all_unions = {}  # full_name -> union descriptor
    all_aliases = {}  # full_name -> alias descriptor
    all_services = []  # list of service descriptors

    for desc in descriptors:
        for msg in desc.get("messages", []):
            all_messages[msg["name"]] = msg
        for tdef in desc.get("typedefs", []):
            all_types[tdef["full_name"]] = tdef
        for enum in desc.get("enums", []):
            all_enums[enum["full_name"]] = enum
        for union in desc.get("unions", []):
            all_unions[union["full_name"]] = union
        for alias in desc.get("aliases", []):
            all_aliases[alias["full_name"]] = alias
        for svc in desc.get("services", []):
            all_services.append(svc)

        # Build output
    lines = [
        "# Auto-generated type hints for vpp_papi VAPI methods.",
        "# Generated by generate_python_stubs.py at build time.",
        "#",
        "# Usage:",
        "#     from vpp_papi.vapi_types import VppApiDynamicMethodHolder",
        "#     def foo(api: VppApiDynamicMethodHolder) -> None:",
        "#         api.bfd_udp_add(sw_if_index=1, ...)  # type-checked!",
        "",
        "from __future__ import annotations",
        "",
        "import datetime",
        "import ipaddress",
        "from collections.abc import Mapping, Sequence",
        "from enum import IntEnum",
        "from typing import Any, NamedTuple, TypeAlias, TypedDict",
        "",
        "from . import MACAddress",
        "",
    ]

    typedef_union_names = set(all_types.keys()) | set(all_unions.keys())
    enum_names = set(all_enums.keys())

    # Generate TypeAlias declarations for Using nodes (e.g. typedef u32 interface_index).
    # Skip aliases whose name is in SPECIAL_INPUT_TYPES — references to those names
    # are rewritten to the special union type before reaching the alias.
    emitted_aliases = [
        alias for alias in all_aliases.values() if not alias.get("in_special_input")
    ]
    if emitted_aliases:
        lines.append("# Type aliases")
        for alias in sorted(emitted_aliases, key=lambda a: a["full_name"]):
            lines.append(f"{alias['full_name']}: TypeAlias = {alias['python_type']}")
        lines.append("")

    # Generate TypedDict classes for typedefs (used as dict parameters)
    if all_types:
        lines.append("# Type definitions")
        for full_name in sorted(all_types.keys()):
            tdef = all_types[full_name]
            lines.append(
                generate_typeddict_class(
                    full_name,
                    tdef.get("fields", []),
                    typedef_union_names,
                    enum_names,
                    comment=f"TypedDict for {tdef['name']}",
                )
            )
        lines.append("")

    # Generate TypedDict classes for unions (used as dict parameters)
    if all_unions:
        lines.append("# Union types")
        for full_name in sorted(all_unions.keys()):
            union = all_unions[full_name]
            lines.append(
                generate_typeddict_class(
                    full_name,
                    union.get("fields", []),
                    typedef_union_names,
                    enum_names,
                    comment=f"TypedDict for union {union['name']}",
                    total=False,
                )
            )
        lines.append("")

    # Generate NamedTuple twins for typedefs / unions. The same .api typedef can
    # flow into both directions (e.g. set_parameters takes a parameters typedef
    # as input; get_parameters returns it inside a reply). The TypedDict form is
    # for input (literal-key dict construction); this `_nt` NamedTuple form is
    # what callers see when reading replies, where attribute access is the
    # natural style and matches what vpp_papi decodes typedefs into at runtime
    # (collections.namedtuple).
    if all_types or all_unions:
        lines.append("# NamedTuple twins for typedefs/unions (decoded reply form)")
        for full_name in sorted(all_types.keys()):
            tdef = all_types[full_name]
            lines.append(
                generate_namedtuple_class(
                    f"{full_name}_nt",
                    tdef.get("fields", []),
                    comment=f"NamedTuple twin of {tdef['name']} (decoded form)",
                )
            )
        for full_name in sorted(all_unions.keys()):
            union = all_unions[full_name]
            lines.append(
                generate_namedtuple_class(
                    f"{full_name}_nt",
                    union.get("fields", []),
                    comment=f"NamedTuple twin of union {union['name']} (decoded form)",
                )
            )
        lines.append("")

    # Generate NamedTuple classes for reply messages
    # First, determine which messages are used as return types
    reply_types = set()
    for svc in all_services:
        ret = svc.get("return_type")
        if ret:
            if ret["kind"] == "single":
                reply_types.add(ret["reply_type"])
            elif ret["kind"] == "stream_modern":
                reply_types.add(ret["reply_type"])
                reply_types.add(ret["details_type"])
            elif ret["kind"] == "stream_legacy":
                reply_types.add(ret["details_type"])

    if reply_types:
        lines.append("# Reply message types")
        for full_name in sorted(reply_types):
            # Find the message by stripping vl_api_ prefix and _t suffix
            msg_name = full_name.removeprefix("vl_api_").removesuffix("_t")
            msg = all_messages.get(msg_name)
            if msg:
                lines.append(
                    generate_namedtuple_class(
                        full_name,
                        msg.get("fields", []),
                        comment=f"Reply message type for {msg_name}",
                    )
                )
            else:
                # Message not found (might be in imported types)
                lines.append(f"class {full_name}(NamedTuple):\n    pass\n")
        lines.append("")

    # Generate enum classes
    if all_enums:
        lines.append("# Enum types")
        for full_name in sorted(all_enums.keys()):
            enum = all_enums[full_name]
            lines.append(generate_enum_class(enum))
        lines.append("")

    # Generate VppApiDynamicMethodHolder class
    lines.append("")
    lines.append("class VppApiDynamicMethodHolder:")
    lines.append('    """Type hints for dynamically created VAPI methods."""')
    lines.append("")

    # Sort services by name for consistent output
    sorted_services = sorted(all_services, key=lambda s: s["name"])
    for svc in sorted_services:
        method_line, _ = generate_method_signature(svc, typedef_union_names, enum_names)
        lines.append(method_line)
        lines.append("")

    stub_content = "\n".join(lines)

    with open(output_path, "w", encoding="UTF-8") as f:
        f.write(stub_content)

    info(f"Generated: {output_path} ({len(sorted_services)} methods)")


def _strip_generics(type_str: str) -> str:
    """Strip generic parameters from a type string.

    E.g. 'list[vl_api_acl_rule_t]' -> 'list'
         'tuple[vl_api_reply_t, list[vl_api_detail_t]]' -> 'tuple'
    """
    bracket_pos = type_str.find("[")
    if bracket_pos != -1:
        return type_str[:bracket_pos]
    return type_str


def _split_union_type(type_str: str) -> list[str]:
    """Split a union type string on ' | ', respecting bracket depth."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    tokens = type_str.split(" ")
    for token in tokens:
        if token == "|" and depth == 0:
            part = " ".join(current).strip()
            if part:
                parts.append(part)
            current = []
        else:
            current.append(token)
            depth += token.count("[")
            depth -= token.count("]")
    part = " ".join(current).strip()
    if part:
        parts.append(part)
    return parts


def _collect_used_types(all_services: list[dict[str, Any]]) -> set[str]:
    """Collect all type names referenced in method signatures."""
    types: set[str] = set()
    for svc in all_services:
        for p in svc.get("params", []):
            if p["name"] not in INTERNAL_FIELDS:
                types.add(_normalize_type(p["type"]))
        ret = svc.get("return_type")
        if ret:
            kind = ret["kind"]
            if kind == "single":
                types.add(_normalize_type(ret["reply_type"]))
            elif kind == "stream_modern":
                types.add(_normalize_type(ret["reply_type"]))
                types.add(_normalize_type(ret["details_type"]))
            elif kind == "stream_legacy":
                types.add(_normalize_type(ret["details_type"]))
    return types


def parse_defaultmapping(provider_path: pathlib.Path) -> dict[str, set[str]]:
    """Parse the `defaultmapping` dict in test/vpp_papi_provider.py and return
    a mapping from method name to the set of parameter names with runtime
    defaults. The values themselves don't matter for stub generation — some
    entries use non-literal expressions like `os.getpid()` so we walk the AST
    and pull out only the keys."""
    import ast

    if not provider_path.is_file():
        return {}

    with open(provider_path, "r", encoding="UTF-8") as f:
        tree = ast.parse(f.read())

    result: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id != "defaultmapping":
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        for k, v in zip(node.value.keys, node.value.values):
            if not isinstance(k, ast.Constant) or not isinstance(k.value, str):
                continue
            if not isinstance(v, ast.Dict):
                continue
            params: set[str] = set()
            for pk in v.keys:
                if isinstance(pk, ast.Constant) and isinstance(pk.value, str):
                    params.add(pk.value)
            result[k.value] = params
        break
    return result


def generate_provider_stub(
    descriptors: list[Any],
    output_path: str,
    defaultmapping: dict[str, set[str]] | None = None,
    vapi_types_module: str = "vpp_papi.vapi_types",
) -> None:
    """Generate vpp_papi_provider.pyi for the test framework.

    vapi_types_module is the module the generated stub imports the vl_api_*_t /
    enum names from. In-tree this is the package path `vpp_papi.vapi_types`. For
    out-of-tree plugin output the combined vapi_types.pyi is written next to the
    provider stub, so a bare top-level `vapi_types` is used instead.
    """

    defaultmapping = defaultmapping or {}

    # Collect all services and the typedef/union/enum name sets used to widen
    # input-position references.
    all_services = []
    typedef_union_names: set[str] = set()
    enum_names: set[str] = set()
    for desc in descriptors:
        for svc in desc.get("services", []):
            all_services.append(svc)
        for tdef in desc.get("typedefs", []):
            typedef_union_names.add(tdef["full_name"])
        for union in desc.get("unions", []):
            typedef_union_names.add(union["full_name"])
        for enum in desc.get("enums", []):
            enum_names.add(enum["full_name"])

    # Methods already explicitly declared
    explicit_methods = {"cli", "ppcli", "cli_return_response", "api"}

    # Collect all types used in method signatures and determine imports
    all_types = _collect_used_types(all_services)
    # Filter to only types defined in vapi_types (vl_api_*_t and VppEnum)
    importable_types: set[str] = set()
    for type_str in all_types:
        for part in _split_union_type(type_str):
            # Strip generic params (list[X] -> list) then get base name
            stripped = _strip_generics(part)
            base = stripped.split(".")[0] if "." in stripped else stripped
            # Import top-level names from vapi_types
            # (vl_api_*_t NamedTuples, IntEnums, etc.)
            # Skip built-ins and stdlib types
            if base not in (
                "int",
                "str",
                "bool",
                "float",
                "list",
                "dict",
                "tuple",
                "set",
                "frozenset",
                "bytes",
                "bytearray",
                "None",
                "datetime",
                "ipaddress",
                "Any",
                "Callable",
                "Mapping",
                "NamedTuple",
                "Sequence",
            ):
                importable_types.add(base)

    # Build import lines
    import_lines: list[str] = []
    if importable_types:
        sorted_types = sorted(importable_types)
        # Format as multi-line import for readability
        import_lines.append(f"from {vapi_types_module} import (")
        for t in sorted_types:
            import_lines.append(f"    {t},")
        import_lines.append(")")
        import_lines.append("")

    lines = [
        "# Auto-generated type hints for VppPapiProvider.",
        "# Generated by generate_python_stubs.py at build time.",
        "#",
        "# This .pyi stub makes basedpyright understand self.vapi",
        "# in test cases, which dynamically forwards to vpp_papi.",
        "",
        "from __future__ import annotations",
        "",
        "import datetime",
        "import ipaddress",
        "from collections.abc import Mapping, Sequence",
        "from typing import Any, Callable, NamedTuple",
        "",
    ]
    lines.extend(import_lines)
    lines.extend(
        [
            "class VppApiResult(NamedTuple):",
            '    """Base type for VAPI API results."""',
            "    retval: int",
            "",
            "",
            "class VppPapiProvider:",
            '    """Type hints for VppPapiProvider."""',
            "    vpp: Any",
            "    papi: Any",
            "    hook: Any",
            "    name: str",
            "    test_class: Any",
            "",
            "    def __init__(self, name: str, test_class: Any, read_timeout: int) -> None: ...",
            "    def __enter__(self) -> 'VppPapiProvider': ...",
            "    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None: ...",
            "    def assert_negative_api_retval(self) -> 'VppPapiProvider': ...",
            "    def assert_zero_api_retval(self) -> 'VppPapiProvider': ...",
            "    def register_hook(self, hook: Any) -> None: ...",
            "    def collect_events(self) -> list: ...",
            "    def wait_for_event(self, timeout: float, name: str | None = ...) -> Any: ...",
            "    def connect(self) -> None: ...",
            "    def disconnect(self) -> None: ...",
            "    def cli(self, cli: str, strip_ansi_escapes: bool = ...) -> str: ...",
            "    def ppcli(self, cli: str) -> str: ...",
            "    def cli_return_response(self, cli: str) -> Any: ...",
            "    def api(self, api_fn: Any, api_args: Any, expected_retval: int = ...) -> Any: ...",
            "",
        ]
    )

    sorted_services = sorted(all_services, key=lambda s: s["name"])
    for svc in sorted_services:
        if svc["name"] in explicit_methods:
            continue
        method_line, _ = generate_method_signature(
            svc,
            typedef_union_names,
            enum_names,
            defaulted_params=defaultmapping.get(svc["name"]),
        )
        lines.append(method_line)
        lines.append("")

    stub_content = "\n".join(lines)

    with open(output_path, "w", encoding="UTF-8") as f:
        f.write(stub_content)

    info(
        f"Generated: {output_path} ({len(sorted_services)} methods, "
        f"{len(importable_types)} type imports)"
    )


def main():
    cliparser = argparse.ArgumentParser(
        description="Generate Python type stubs for vpp_papi"
    )
    cliparser.add_argument(
        "--srcdir",
        action="store",
        default=f"{BASE_DIR}/src",
        help="Source directory containing .api files",
    )
    cliparser.add_argument(
        "--stubs-output",
        action="store",
        help=(
            "Directory for final stub files (vapi_types.pyi, provider.pyi). "
            "When set, both stubs are written here as self-contained top-level "
            "modules; used for out-of-tree plugin builds."
        ),
    )
    cliparser.add_argument(
        "--extra-api-file",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Additional .api file to fold into the stubs (repeatable). Used by "
            "out-of-tree plugin builds to add plugin .api files on top of the "
            "in-tree scan."
        ),
    )
    cliparser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress routine progress output (errors still printed)",
    )

    args = cliparser.parse_args()
    global QUIET
    QUIET = args.quiet

    src_dir = pathlib.Path(args.srcdir)
    extra_files = [pathlib.Path(p) for p in args.extra_api_file]

    api_files = find_api_files(src_dir, extra_files)
    info(f"Found {len(api_files)} .api files")

    if not api_files:
        print("No .api files found. Exiting.", file=sys.stderr)
        sys.exit(1)

    info("Parsing .api files...")
    descriptors: list[dict[str, Any]] = []
    for api_file in api_files:
        # Resolve imports against the in-tree src and the file's own directory
        # (the latter lets a plugin .api import sibling plugin .api files).
        s = parse_api_file(api_file, [str(src_dir), str(api_file.parent)])
        descriptors.append(build_descriptor(api_file, s))
    info(f"Built {len(descriptors)} descriptors")

    # The defaultmapping table always comes from the in-tree provider; only the
    # output location differs between in-tree and plugin (--stubs-output) runs.
    defaultmapping = parse_defaultmapping(
        pathlib.Path(f"{BASE_DIR}/test/vpp_papi_provider.py")
    )

    if args.stubs_output:
        # Plugin build: both stubs are self-contained in one directory, so the
        # provider stub imports types from a sibling top-level `vapi_types`.
        out_dir = pathlib.Path(args.stubs_output)
        out_dir.mkdir(parents=True, exist_ok=True)
        types_out = out_dir / "vapi_types.pyi"
        provider_out = out_dir / "vpp_papi_provider.pyi"
        vapi_types_module = "vapi_types"
    else:
        # In-tree build: vapi_types.pyi lives in the vpp_papi package and the
        # provider stub imports it as vpp_papi.vapi_types.
        types_dir = pathlib.Path(f"{BASE_DIR}/src/vpp-api/python/vpp_papi")
        types_dir.mkdir(parents=True, exist_ok=True)
        types_out = types_dir / "vapi_types.pyi"
        provider_out = pathlib.Path(f"{BASE_DIR}/test/vpp_papi_provider.pyi")
        vapi_types_module = "vpp_papi.vapi_types"

    generate_vapi_types(descriptors, str(types_out))
    generate_provider_stub(
        descriptors,
        str(provider_out),
        defaultmapping=defaultmapping,
        vapi_types_module=vapi_types_module,
    )

    info("Done.")


if __name__ == "__main__":
    main()
