#
# Copyright 2026 Rubicon Communications, LLC (Netgate)
#
# SPDX-License-Identifier: Apache-2.0
#

"""
vppapigen plugin for generating Python type stubs.

Generates a JSON descriptor per .api file containing all type information
needed to produce vapi_types.py with complete method signatures and return
type annotations.
"""

import json
import os
import sys
from typing import Any

process_imports = True

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

# Internal VPP API fields excluded from method signatures
INTERNAL_FIELDS = {"_vl_msg_id", "client_index", "context"}


def _make_type_name(name: str) -> str:
    """Convert a VPP type/message name to vl_api_<name>_t."""
    return f"vl_api_{name}_t"


def vpp_type_to_python_annotation(
    vpp_type: str,
    all_types: dict[str, Any],
    all_enums: dict[str, Any],
    all_unions: dict[str, Any],
    all_aliases: dict[str, Any],
    output: bool = False,
) -> str:
    """Map a VPP type name to a Python type annotation string.

    Args:
        vpp_type: The VPP type name (e.g. 'u32', 'vl_api_ip4_address_t')
        all_types: Dict of typedef full names -> True
        all_enums: Dict of enum full names -> True
        all_unions: Dict of union full names -> True
        all_aliases: Dict of alias full names -> True
        output: True for output (decoded reply) positions — uses
            SPECIAL_OUTPUT_TYPES (no `str` fallback) and emits a `_nt` suffix
            for typedef/union refs (the NamedTuple twin). False for input.

    Returns:
        Python type annotation string.
    """
    # Base types
    if vpp_type in BASE_TYPE_MAP:
        return BASE_TYPE_MAP[vpp_type]

    # Special types (from conversion_table)
    table = SPECIAL_OUTPUT_TYPES if output else SPECIAL_INPUT_TYPES
    if vpp_type in table:
        return " | ".join(table[vpp_type])

    # Enum types -> use the enum class name
    if vpp_type in all_enums:
        return f"VppEnum.{vpp_type}"

    # Typedef / union types -> TypedDict class for input, NamedTuple twin for
    # output (attribute access on decoded replies)
    if vpp_type in all_types or vpp_type in all_unions:
        return f"{vpp_type}_nt" if output else vpp_type

    # Alias types -> resolve to underlying type
    if vpp_type in all_aliases:
        return vpp_type

    # Unknown complex type
    if vpp_type.startswith("vl_api_") and vpp_type.endswith("_t"):
        return "Any"

    return "Any"


def walk_block_to_fields(
    block: Any,
    all_types: dict[str, Any],
    all_enums: dict[str, Any],
    all_unions: dict[str, Any],
    all_aliases: dict[str, Any],
) -> list[dict[str, Any]]:
    """Walk a block of Field/Array objects and produce Python-annotated field list.

    Returns list of dicts with keys: name, type, is_array, ...
    """
    fields = []
    for item in block:
        if item.__class__.__name__ == "Option":
            continue

        field_name = item.fieldname
        if field_name in INTERNAL_FIELDS:
            continue

        if item.__class__.__name__ == "Array":
            field_type = item.fieldtype
            # String arrays are special
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
                elem_in = vpp_type_to_python_annotation(
                    field_type, all_types, all_enums, all_unions, all_aliases
                )
                elem_out = vpp_type_to_python_annotation(
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
            # Field
            field_type = item.fieldtype
            py_type = vpp_type_to_python_annotation(
                field_type, all_types, all_enums, all_unions, all_aliases
            )
            out_type = vpp_type_to_python_annotation(
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


def process_typedef(
    t: Any,
    all_types: dict[str, Any],
    all_enums: dict[str, Any],
    all_unions: dict[str, Any],
    all_aliases: dict[str, Any],
) -> dict[str, Any]:
    """Process a Typedef AST object."""
    full_name = _make_type_name(t.name)
    fields = walk_block_to_fields(
        t.block, all_types, all_enums, all_unions, all_aliases
    )
    return {
        "name": t.name,
        "full_name": full_name,
        "fields": fields,
        "kind": "typedef",
    }


def process_union(
    u: Any,
    all_types: dict[str, Any],
    all_enums: dict[str, Any],
    all_unions: dict[str, Any],
    all_aliases: dict[str, Any],
) -> dict[str, Any]:
    """Process a Union AST object."""
    full_name = _make_type_name(u.name)
    fields = walk_block_to_fields(
        u.block, all_types, all_enums, all_unions, all_aliases
    )
    return {
        "name": u.name,
        "full_name": full_name,
        "fields": fields,
        "kind": "union",
    }


def process_enum(e: Any) -> dict[str, Any]:
    """Process an Enum/EnumFlag AST object."""
    full_name = _make_type_name(e.name)
    entries = [{"id": entry[0], "value": entry[1]} for entry in e.block]
    return {
        "name": e.name,
        "full_name": full_name,
        "entries": entries,
        "enumtype": e.enumtype,
        "kind": "enumflag" if e.__class__.__name__ == "EnumFlag" else "enum",
    }


def process_alias(
    a: Any,
    all_types: dict[str, Any],
    all_enums: dict[str, Any],
    all_unions: dict[str, Any],
    all_aliases: dict[str, Any],
) -> dict[str, Any]:
    """Process a Using (alias) AST object."""
    full_name = _make_type_name(a.name)
    underlying = a.alias.get("type")
    length = a.alias.get("length")
    if length:
        if underlying == "u8":
            python_type = "bytes"
        else:
            elem = vpp_type_to_python_annotation(
                underlying, all_types, all_enums, all_unions, all_aliases
            )
            python_type = f"list[{elem}]"
    else:
        python_type = vpp_type_to_python_annotation(
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


def _format_crc(crc) -> str:
    """Format CRC value as hex string, handling both int and bytes."""
    if isinstance(crc, bytes):
        return "0x" + crc.hex()
    return f"0x{crc:08x}"


def process_message(
    msg: Any,
    all_types: dict[str, Any],
    all_enums: dict[str, Any],
    all_unions: dict[str, Any],
    all_aliases: dict[str, Any],
) -> dict[str, Any]:
    """Process a Define (message) AST object."""
    full_name = _make_type_name(msg.name)
    fields = walk_block_to_fields(
        msg.block, all_types, all_enums, all_unions, all_aliases
    )
    return {
        "name": msg.name,
        "full_name": full_name,
        "fields": fields,
        "crc": _format_crc(msg.crc),
        "options": msg.options,
        "comment": msg.comment or "",
    }


def process_service(svc: Any, messages_by_name: dict[str, Any]) -> dict[str, Any]:
    """Process a Service AST object into a method descriptor."""
    reply = svc.reply
    is_stream = svc.stream
    stream_msg = svc.stream_message
    events = svc.events

    # Get caller message fields
    caller_msg = messages_by_name.get(svc.caller)
    params = caller_msg.get("fields", []) if caller_msg else []

    # Determine return type
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


def run(output_dir: str, apifilename: str, s: dict[str, Any]) -> str:
    """Plugin entry point.

    Generates a JSON descriptor containing all type information from this .api file.

    Args:
        output_dir: Directory to write output files.
        apifilename: Path to the input .api file.
        s: Parsed API structure from vppapigen.

    Returns:
        Empty string (output is written to file).
    """
    if not output_dir:
        sys.stderr.write("Missing --outputdir argument\n")
        return ""

    basename = os.path.basename(apifilename)
    filename, _ = os.path.splitext(basename)

    # Collect all type names for cross-reference resolution
    all_types = {}
    all_enums = {}
    all_unions = {}
    all_aliases = {}

    def _register_types(type_list):
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

    # Types from this file and imports
    _register_types(s.get("types", []))
    imported = s.get("imported", {})
    _register_types(imported.get("types", []))

    # Build messages dict for service resolution
    messages_by_name = {}
    for msg in s.get("Define", []):
        messages_by_name[msg.name] = {
            "fields": walk_block_to_fields(
                msg.block, all_types, all_enums, all_unions, all_aliases
            ),
        }

    # Process typedefs
    typedefs = []
    for t in s.get("types", []):
        if t.__class__.__name__ == "Typedef":
            typedefs.append(
                process_typedef(t, all_types, all_enums, all_unions, all_aliases)
            )

    # Process unions
    unions = []
    for t in s.get("types", []):
        if t.__class__.__name__ == "Union":
            unions.append(
                process_union(t, all_types, all_enums, all_unions, all_aliases)
            )

    # Process enums
    enums = []
    for t in s.get("types", []):
        if t.__class__.__name__ in ("Enum", "EnumFlag"):
            enums.append(process_enum(t))

    # Process aliases (Using)
    aliases = []
    for t in s.get("types", []):
        if t.__class__.__name__ == "Using":
            aliases.append(
                process_alias(t, all_types, all_enums, all_unions, all_aliases)
            )

    # Process messages (Define)
    msgs = []
    for msg in s.get("Define", []):
        msgs.append(process_message(msg, all_types, all_enums, all_unions, all_aliases))

    # Process services
    services = []
    for svc in s.get("Service", []):
        services.append(process_service(svc, messages_by_name))

    # Build descriptor
    descriptor = {
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

    # Serialize to JSON
    json_content = json.dumps(descriptor, indent=2)

    # Write JSON descriptor
    output_path = os.path.join(output_dir, f"{filename}.python.json")
    with open(output_path, "w", encoding="UTF-8") as f:
        f.write(json_content)

    # Return JSON content so vppapigen writes it to --output file
    return json_content
