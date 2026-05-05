# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Meter, Inc.
#
# vppapigen plugin: emit vapi C bindings (.vapi.h) from the vppapigen AST.
#
# This file collapses what used to be two layers in src/vpp-api/vapi/:
#   - vapi_json_parser.py: parsed .api.json into a Field/Type/Message tree
#   - vapi_c_gen.py:       walked that tree to emit .vapi.h
# We now consume vppapigen's typed AST (s["types"], s["Define"], ...) directly
# and skip the JSON round-trip, so schema additions like [discriminator=type]
# don't require teaching a separate parser to ignore them.

import inspect
import os

# ---------------------------------------------------------------------------
# Type / field model used by the emitter.
#
# The emitter calls .get_c_name() / .get_c_def() / .get_swap_to_*_code() on
# these objects; behavior is identical to the previous vapi_json_parser.py +
# vapi_c_gen.py classes. The constructors now take native Python args because
# the AST walker has already resolved everything.
# ---------------------------------------------------------------------------

magic_prefix = "vl_api_"
magic_suffix = "_t"


def remove_magic(what):
    if what.startswith(magic_prefix) and what.endswith(magic_suffix):
        return what[len(magic_prefix) : -len(magic_suffix)]
    return what


class Field(object):
    def __init__(
        self,
        field_name,
        field_type,
        array_len=None,
        nelem_field=None,
        discriminator=None,
    ):
        self.name = field_name
        self.type = field_type
        self.len = array_len
        self.nelem_field = nelem_field
        # Name of a sibling field whose value selects which Union arm is
        # live. Set only when this field's vppapigen `[discriminator=X]`
        # option was present. Drives the switch dispatch in the parent
        # type's hton/ntoh helpers.
        self.discriminator = discriminator

    def is_vla(self):
        return self.nelem_field is not None

    def has_vla(self):
        return self.is_vla() or self.type.has_vla()

    def get_c_name(self):
        return "vapi_type_%s" % self.name

    def get_c_def(self):
        if self.type.get_c_name() == "string":
            if self.len:
                return "u8 %s[%d];" % (self.name, self.len)
            else:
                return "vl_api_string_t %s;" % (self.name)
        else:
            if self.len is not None:
                return "%s %s[%d];" % (self.type.get_c_name(), self.name, self.len)
            else:
                return "%s %s;" % (self.type.get_c_name(), self.name)

    def get_swap_to_be_code(self, struct, var):
        if self.discriminator is not None:
            return self._discriminator_switch_code(struct, var, to_net=True)
        if self.len is not None:
            if self.len > 0:
                return (
                    "do { unsigned i; for (i = 0; i < %d; ++i) { %s } }"
                    " while(0);"
                    % (self.len, self.type.get_swap_to_be_code(struct, "%s[i]" % var))
                )
            else:
                if self.nelem_field.needs_byte_swap():
                    nelem_field = "%s(%s%s)" % (
                        self.nelem_field.type.get_swap_to_host_func_name(),
                        struct,
                        self.nelem_field.name,
                    )
                else:
                    nelem_field = "%s%s" % (struct, self.nelem_field.name)
                return (
                    "do { unsigned i; for (i = 0; i < %s; ++i) { %s } }"
                    " while(0);"
                    % (
                        nelem_field,
                        self.type.get_swap_to_be_code(struct, "%s[i]" % var),
                    )
                )
        return self.type.get_swap_to_be_code(struct, "%s" % var)

    def get_swap_to_host_code(self, struct, var):
        if self.discriminator is not None:
            return self._discriminator_switch_code(struct, var, to_net=False)
        if self.len is not None:
            if self.len > 0:
                return (
                    "do { unsigned i; for (i = 0; i < %d; ++i) { %s } }"
                    " while(0);"
                    % (self.len, self.type.get_swap_to_host_code(struct, "%s[i]" % var))
                )
            else:
                # nelem_field already swapped to host here...
                return (
                    "do { unsigned i; for (i = 0; i < %s%s; ++i) { %s } }"
                    " while(0);"
                    % (
                        struct,
                        self.nelem_field.name,
                        self.type.get_swap_to_host_code(struct, "%s[i]" % var),
                    )
                )
        return self.type.get_swap_to_host_code(struct, "%s" % var)

    def needs_byte_swap(self):
        # Discriminated-union fields always need the switch dispatch even
        # when the union itself reports needs_byte_swap=False, because each
        # arm may have arm-type-specific swapping.
        if self.discriminator is not None:
            return True
        return self.type.needs_byte_swap()

    def _discriminator_switch_code(self, struct, var, to_net):
        """Emit a switch over the snapshot of the discriminator field,
        dispatching each Union arm to its arm-type endian helper. Mirrors
        endianfun_tagged_union() in vppapigen_c.py — same wire-format
        guarantees, so a vapi client and an in-process VPP plugin agree
        on which arm bytes get swapped.

        Caller (parent struct's swap function) is responsible for emitting
        the `_disc_<name>` snapshot at the top of the function body."""
        union = self.type
        lines = ["switch (_disc_%s) {" % self.discriminator]
        # Union.type_pairs entries are 3-tuples (arm_type, arm_name, case_val)
        # for discriminated unions. Older 2-tuple entries fall through here
        # only if a typedef field is mistakenly tagged with discriminator
        # against a non-tagged Union, which would already be a parse error.
        for entry in union.type_pairs:
            arm_type, arm_name = entry[0], entry[1]
            case_val = entry[2] if len(entry) >= 3 else None
            if case_val is None:
                continue
            lines.append("  case %s:" % case_val)
            if arm_type.needs_byte_swap():
                arm_var = "%s.%s" % (var, arm_name)
                if to_net:
                    code = arm_type.get_swap_to_be_code(struct, arm_var)
                else:
                    code = arm_type.get_swap_to_host_code(struct, arm_var)
                lines.append("    %s" % code)
            lines.append("    break;")
        lines.append("  default: break;")
        lines.append("  }")
        return "\n  ".join(lines)

    def get_vla_parameter_name(self, path):
        return "%s_%s_array_size" % ("_".join(path), self.name)

    def get_vla_field_name(self, path):
        return ".".join(path + [self.nelem_field.name])

    def get_alloc_vla_param_names(self, path):
        if self.is_vla():
            result = [self.get_vla_parameter_name(path)]
        else:
            result = []
        if self.type.has_vla():
            t = self.type.get_alloc_vla_param_names(path + [self.name])
            result.extend(t)
        return result

    def get_vla_calc_size_code(self, prefix, path, is_alloc):
        if self.is_vla():
            result = [
                "sizeof(%s.%s[0]) * %s"
                % (
                    ".".join([prefix] + path),
                    self.name,
                    (
                        self.get_vla_parameter_name(path)
                        if is_alloc
                        else "%s.%s" % (prefix, self.get_vla_field_name(path))
                    ),
                )
            ]
        else:
            result = []
        if self.type.has_vla():
            t = self.type.get_vla_calc_size_code(prefix, path + [self.name], is_alloc)
            result.extend(t)
        return result

    def get_vla_assign_code(self, prefix, path):
        result = []
        if self.is_vla():
            result.append(
                "%s.%s = %s"
                % (
                    ".".join([prefix] + path),
                    self.nelem_field.name,
                    self.get_vla_parameter_name(path),
                )
            )
        if self.type.has_vla():
            t = self.type.get_vla_assign_code(prefix, path + [self.name])
            result.extend(t)
        return result


class Alias(Field):
    def get_c_name(self):
        return "vapi_type_%s" % self.name

    def get_c_def(self):
        if self.len is not None:
            return "typedef %s vapi_type_%s[%d];" % (
                self.type.get_c_name(),
                self.name,
                self.len,
            )
        else:
            return "typedef %s vapi_type_%s;" % (self.type.get_c_name(), self.name)


class Type(object):
    def __init__(self, name):
        self.name = name


class SimpleType(Type):
    swap_to_be_dict = {
        "i16": "htobe16",
        "u16": "htobe16",
        "i32": "htobe32",
        "u32": "htobe32",
        "i64": "htobe64",
        "u64": "htobe64",
    }

    swap_to_host_dict = {
        "i16": "be16toh",
        "u16": "be16toh",
        "i32": "be32toh",
        "u32": "be32toh",
        "i64": "be64toh",
        "u64": "be64toh",
    }

    __packed = "__attribute__((packed))"
    pack_dict = {
        "i8": __packed,
        "u8": __packed,
        "i16": __packed,
        "u16": __packed,
    }

    def has_vla(self):
        return False

    def get_c_name(self):
        return self.name

    def get_swap_to_be_func_name(self):
        return self.swap_to_be_dict[self.name]

    def get_swap_to_host_func_name(self):
        return self.swap_to_host_dict[self.name]

    def get_packed_string(self):
        return self.pack_dict[self.name]

    def get_swap_to_be_code(self, struct, var, cast=None):
        x = "%s%s" % (struct, var)
        return "%s = %s%s(%s);" % (
            x,
            "(%s)" % cast if cast else "",
            self.get_swap_to_be_func_name(),
            x,
        )

    def get_swap_to_host_code(self, struct, var, cast=None):
        x = "%s%s" % (struct, var)
        return "%s = %s%s(%s);" % (
            x,
            "(%s)" % cast if cast else "",
            self.get_swap_to_host_func_name(),
            x,
        )

    def needs_byte_swap(self):
        try:
            self.get_swap_to_host_func_name()
            return True
        except KeyError:
            pass
        return False

    def get_packed(self):
        return self.pack_dict.get(self.name, "")


class Enum(SimpleType):
    def __init__(self, name, value_pairs, enumtype):
        super(Enum, self).__init__(name)
        self.type = enumtype
        self.value_pairs = value_pairs

    def get_c_name(self):
        return "vapi_enum_%s" % self.name

    def get_c_def(self):
        return "typedef enum {\n%s\n} %s %s;" % (
            "\n".join(["  %s = %s," % (i, j) for i, j in self.value_pairs]),
            self.type.get_packed(),
            self.get_c_name(),
        )

    def needs_byte_swap(self):
        return self.type.needs_byte_swap()

    def get_swap_to_be_code(self, struct, var):
        return self.type.get_swap_to_be_code(struct, var, self.get_c_name())

    def get_swap_to_host_code(self, struct, var):
        return self.type.get_swap_to_host_code(struct, var, self.get_c_name())


class Union(Type):
    def __init__(self, name, type_pairs, crc):
        # Each entry is (arm_type, arm_name) for legacy untagged unions
        # or (arm_type, arm_name, case_value) for discriminated unions.
        # Stored as tuples so 2-element vs 3-element form is preserved
        # for downstream consumers.
        Type.__init__(self, name)
        self.crc = crc
        self.type_pairs = type_pairs
        self.depends = [entry[0] for entry in self.type_pairs]

    def has_vla(self):
        return False

    def get_c_name(self):
        return "vapi_union_%s" % self.name

    def get_c_def(self):
        return "typedef union {\n%s\n} %s;" % (
            "\n".join(
                ["  %s %s;" % (entry[0].get_c_name(), entry[1]) for entry in self.type_pairs]
            ),
            self.get_c_name(),
        )

    def needs_byte_swap(self):
        # The Union itself never emits its own swap helper — the parent
        # typedef's discriminator-aware switch dispatches to per-arm
        # types directly. Returning False here keeps the parent's "skip
        # this field" path active for non-discriminated (legacy) unions.
        return False


class Struct(object):
    def __init__(self, name, fields):
        self.name = name
        self.fields = fields
        self.field_names = [n.name for n in self.fields]
        self.depends = [f.type for f in self.fields]

    def has_vla(self):
        for f in self.fields:
            if f.has_vla():
                return True
        return False

    def get_c_def(self):
        return "\n".join(
            [
                "typedef struct __attribute__((__packed__)) {\n%s"
                % ("\n".join(["  %s" % x.get_c_def() for x in self.fields])),
                "} %s;" % self.get_c_name(),
            ]
        )

    def get_vla_assign_code(self, prefix, path):
        return [
            x
            for f in self.fields
            if f.has_vla()
            for x in f.get_vla_assign_code(prefix, path)
        ]

    def get_alloc_vla_param_names(self, path):
        return [
            x
            for f in self.fields
            if f.has_vla()
            for x in f.get_alloc_vla_param_names(path)
        ]

    def get_vla_calc_size_code(self, prefix, path, is_alloc):
        return [
            x
            for f in self.fields
            if f.has_vla()
            for x in f.get_vla_calc_size_code(prefix, path, is_alloc)
        ]


def _discriminator_snapshot_lines(fields, struct_prefix, to_net):
    """Emit the `<type> _disc_<name> = <prefix><name>;` snapshots that
    discriminator-aware Field._discriminator_switch_code() reads from.
    For ntoh (to_net=False) the snapshot needs to be converted from net
    to host order before being switched on, since the field hasn't been
    swapped yet at function entry."""
    lines = []
    seen = set()
    for f in fields:
        disc = getattr(f, "discriminator", None)
        if not disc or disc in seen:
            continue
        seen.add(disc)
        disc_field = next((x for x in fields if x.name == disc), None)
        if disc_field is None:
            continue
        disc_c = disc_field.type.get_c_name()
        lines.append(
            "  %s _disc_%s = %s%s;" % (disc_c, disc, struct_prefix, disc)
        )
        # On ntoh the snapshot is in network byte order; convert to host
        # before the switch reads it. Skip when the discriminator type is
        # already byte-oriented (u8 enum, bool).
        if not to_net and disc_field.type.needs_byte_swap():
            conv = disc_field.type.get_swap_to_host_code("", "_disc_%s" % disc)
            lines.append("  %s" % conv)
    return lines


class StructType(Type, Struct):
    def __init__(self, name, fields, crc=None):
        Type.__init__(self, name)
        Struct.__init__(self, name, fields)
        self.crc = crc

    def has_field(self, name):
        return name in self.field_names

    def get_c_name(self):
        if self.name == "vl_api_string_t":
            return "vl_api_string_t"
        return "vapi_type_%s" % self.name

    def get_swap_to_be_func_name(self):
        return "%s_hton" % self.get_c_name()

    def get_swap_to_host_func_name(self):
        return "%s_ntoh" % self.get_c_name()

    def get_swap_to_be_func_decl(self):
        return "void %s(%s *msg)" % (self.get_swap_to_be_func_name(), self.get_c_name())

    def get_swap_to_be_func_def(self):
        snap = _discriminator_snapshot_lines(self.fields, "msg->", to_net=True)
        body = snap + [
            "  %s" % p.get_swap_to_be_code("msg->", "%s" % p.name)
            for p in self.fields
            if p.needs_byte_swap()
        ]
        return "%s\n{\n%s\n}" % (
            self.get_swap_to_be_func_decl(),
            "\n".join(body),
        )

    def get_swap_to_host_func_decl(self):
        return "void %s(%s *msg)" % (
            self.get_swap_to_host_func_name(),
            self.get_c_name(),
        )

    def get_swap_to_host_func_def(self):
        snap = _discriminator_snapshot_lines(self.fields, "msg->", to_net=False)
        body = snap + [
            "  %s" % p.get_swap_to_host_code("msg->", "%s" % p.name)
            for p in self.fields
            if p.needs_byte_swap()
        ]
        return "%s\n{\n%s\n}" % (
            self.get_swap_to_host_func_decl(),
            "\n".join(body),
        )

    def get_swap_to_be_code(self, struct, var):
        return "%s(&%s%s);" % (self.get_swap_to_be_func_name(), struct, var)

    def get_swap_to_host_code(self, struct, var):
        return "%s(&%s%s);" % (self.get_swap_to_host_func_name(), struct, var)

    def needs_byte_swap(self):
        for f in self.fields:
            if f.needs_byte_swap():
                return True
        return False


class Message(object):
    """Message type. Constructed by the AST walker once header detection,
    field translation, and service-classification have already been done."""

    def __init__(self, name, fields, header, crc, is_reply, is_event, is_stream):
        self.name = name
        self.fields = fields
        self.header = header
        self.crc = crc
        self.is_reply = is_reply
        self.is_event = is_event
        self.is_stream = is_stream
        self.request = None
        self.depends = [f.type for f in self.fields]
        self.payload_members = [
            "  %s" % p.get_c_def() for p in self.fields if p.type != self.header
        ]

    def has_payload(self):
        return len(self.payload_members) > 0

    def get_msg_id_name(self):
        return "vapi_msg_id_%s" % self.name

    def get_c_name(self):
        return "vapi_msg_%s" % self.name

    def get_payload_struct_name(self):
        return "vapi_payload_%s" % self.name

    def get_alloc_func_name(self):
        return "vapi_alloc_%s" % self.name

    def get_alloc_vla_param_names(self):
        return [
            x
            for f in self.fields
            if f.has_vla()
            for x in f.get_alloc_vla_param_names([])
        ]

    def get_alloc_func_decl(self):
        return "%s* %s(struct vapi_ctx_s *ctx%s)" % (
            self.get_c_name(),
            self.get_alloc_func_name(),
            "".join([", size_t %s" % n for n in self.get_alloc_vla_param_names()]),
        )

    def get_alloc_func_def(self):
        extra = []
        if self.header.has_field("client_index"):
            extra.append("  msg->header.client_index = vapi_get_client_index(ctx);")
        if self.header.has_field("context"):
            extra.append("  msg->header.context = 0;")
        return "\n".join(
            [
                "%s" % self.get_alloc_func_decl(),
                "{",
                "  %s *msg = NULL;" % self.get_c_name(),
                "  const size_t size = sizeof(%s)%s;"
                % (
                    self.get_c_name(),
                    "".join(
                        [
                            " + %s" % x
                            for f in self.fields
                            if f.has_vla()
                            for x in f.get_vla_calc_size_code(
                                "msg->payload", [], is_alloc=True
                            )
                        ]
                    ),
                ),
                "  /* cast here required to play nicely with C++ world ... */",
                "  msg = (%s*)vapi_msg_alloc(ctx, size);" % self.get_c_name(),
                "  if (!msg) {",
                "    return NULL;",
                "  }",
            ]
            + extra
            + [
                "  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, %s);"
                % self.get_msg_id_name(),
                "".join(
                    [
                        "  %s;\n" % line
                        for f in self.fields
                        if f.has_vla()
                        for line in f.get_vla_assign_code("msg->payload", [])
                    ]
                ),
                "  return msg;",
                "}",
            ]
        )

    def get_calc_msg_size_func_name(self):
        return "vapi_calc_%s_msg_size" % self.name

    def get_calc_msg_size_func_decl(self):
        return "uword %s(%s *msg)" % (
            self.get_calc_msg_size_func_name(),
            self.get_c_name(),
        )

    def get_calc_msg_size_func_def(self):
        return "\n".join(
            [
                "%s" % self.get_calc_msg_size_func_decl(),
                "{",
                "  return sizeof(*msg)%s;"
                % "".join(
                    [
                        " + %s" % x
                        for f in self.fields
                        if f.has_vla()
                        for x in f.get_vla_calc_size_code(
                            "msg->payload", [], is_alloc=False
                        )
                    ]
                ),
                "}",
            ]
        )

    def get_verify_msg_size_func_name(self):
        return f"vapi_verify_{self.name}_msg_size"

    def get_verify_msg_size_func_decl(self):
        return "int %s(%s *msg, uword buf_size)" % (
            self.get_verify_msg_size_func_name(),
            self.get_c_name(),
        )

    def get_verify_msg_size_func_def(self):
        return inspect.cleandoc(f"""
            {self.get_verify_msg_size_func_decl()}
            {{
              if (sizeof({self.get_c_name()}) > buf_size)
                {{
                  VAPI_ERR("Truncated '{self.name}' msg received, received %lu"
                    "bytes, expected %lu bytes.", buf_size,
                    sizeof({self.get_c_name()}));
                  return -1;
                }}
              if ({self.get_calc_msg_size_func_name()}(msg) > buf_size)
                {{
                  VAPI_ERR("Truncated '{self.name}' msg received, received %lu"
                    "bytes, expected %lu bytes.", buf_size,
                    {self.get_calc_msg_size_func_name()}(msg));
                  return -1;
                }}
              return 0;
            }}
        """)

    def get_c_def(self):
        if self.has_payload():
            return "\n".join(
                [
                    "typedef struct __attribute__ ((__packed__)) {",
                    "%s " % "\n".join(self.payload_members),
                    "} %s;" % self.get_payload_struct_name(),
                    "",
                    "typedef struct __attribute__ ((__packed__)) {",
                    (
                        "  %s %s;" % (self.header.get_c_name(), self.fields[0].name)
                        if self.header is not None
                        else ""
                    ),
                    "  %s payload;" % self.get_payload_struct_name(),
                    "} %s;" % self.get_c_name(),
                ]
            )
        else:
            return "\n".join(
                [
                    "typedef struct __attribute__ ((__packed__)) {",
                    (
                        "  %s %s;" % (self.header.get_c_name(), self.fields[0].name)
                        if self.header is not None
                        else ""
                    ),
                    "} %s;" % self.get_c_name(),
                ]
            )

    def get_swap_payload_to_host_func_name(self):
        return "%s_payload_ntoh" % self.get_c_name()

    def get_swap_payload_to_be_func_name(self):
        return "%s_payload_hton" % self.get_c_name()

    def get_swap_payload_to_host_func_decl(self):
        return "void %s(%s *payload)" % (
            self.get_swap_payload_to_host_func_name(),
            self.get_payload_struct_name(),
        )

    def get_swap_payload_to_be_func_decl(self):
        return "void %s(%s *payload)" % (
            self.get_swap_payload_to_be_func_name(),
            self.get_payload_struct_name(),
        )

    def get_swap_payload_to_be_func_def(self):
        payload_fields = [p for p in self.fields if p.type != self.header]
        snap = _discriminator_snapshot_lines(
            payload_fields, "payload->", to_net=True
        )
        body = snap + [
            "  %s" % p.get_swap_to_be_code("payload->", "%s" % p.name)
            for p in payload_fields
            if p.needs_byte_swap()
        ]
        return "%s\n{\n%s\n}" % (
            self.get_swap_payload_to_be_func_decl(),
            "\n".join(body),
        )

    def get_swap_payload_to_host_func_def(self):
        payload_fields = [p for p in self.fields if p.type != self.header]
        snap = _discriminator_snapshot_lines(
            payload_fields, "payload->", to_net=False
        )
        body = snap + [
            "  %s" % p.get_swap_to_host_code("payload->", "%s" % p.name)
            for p in payload_fields
            if p.needs_byte_swap()
        ]
        return "%s\n{\n%s\n}" % (
            self.get_swap_payload_to_host_func_decl(),
            "\n".join(body),
        )

    def get_swap_to_host_func_name(self):
        return "%s_ntoh" % self.get_c_name()

    def get_swap_to_be_func_name(self):
        return "%s_hton" % self.get_c_name()

    def get_swap_to_host_func_decl(self):
        return "void %s(%s *msg)" % (
            self.get_swap_to_host_func_name(),
            self.get_c_name(),
        )

    def get_swap_to_be_func_decl(self):
        return "void %s(%s *msg)" % (self.get_swap_to_be_func_name(), self.get_c_name())

    def get_swap_to_be_func_def(self):
        return "\n".join(
            [
                "%s" % self.get_swap_to_be_func_decl(),
                "{",
                (
                    '  VAPI_DBG("Swapping `%s\'@%%p to big endian", msg);'
                    % self.get_c_name()
                ),
                (
                    "  %s(&msg->header);" % self.header.get_swap_to_be_func_name()
                    if self.header is not None
                    else ""
                ),
                (
                    "  %s(&msg->payload);" % self.get_swap_payload_to_be_func_name()
                    if self.has_payload()
                    else ""
                ),
                "}",
            ]
        )

    def get_swap_to_host_func_def(self):
        return "\n".join(
            [
                "%s" % self.get_swap_to_host_func_decl(),
                "{",
                (
                    '  VAPI_DBG("Swapping `%s\'@%%p to host byte order", msg);'
                    % self.get_c_name()
                ),
                (
                    "  %s(&msg->header);" % self.header.get_swap_to_host_func_name()
                    if self.header is not None
                    else ""
                ),
                (
                    "  %s(&msg->payload);" % self.get_swap_payload_to_host_func_name()
                    if self.has_payload()
                    else ""
                ),
                "}",
            ]
        )

    def get_op_func_name(self):
        return "vapi_%s" % self.name

    def get_op_func_decl(self):
        stream_param_lines = []
        if self.has_stream_msg:
            stream_param_lines = [
                "vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx",
                "                                 void *callback_ctx",
                "                                 vapi_error_e rv",
                "                                 bool is_last",
                "                                 %s *details)"
                % self.stream_msg.get_payload_struct_name(),
                "void *details_callback_ctx",
            ]

        return "vapi_error_e %s(%s)" % (
            self.get_op_func_name(),
            ",\n  ".join(
                [
                    "struct vapi_ctx_s *ctx",
                    "%s *msg" % self.get_c_name(),
                    "vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx",
                    "                               void *callback_ctx",
                    "                               vapi_error_e rv",
                    "                               bool is_last",
                    "                               %s *reply)"
                    % self.reply.get_payload_struct_name(),
                ]
                + [
                    "void *reply_callback_ctx",
                ]
                + stream_param_lines
            ),
        )

    def get_op_func_def(self):
        param_check_lines = ["  if (!msg || !reply_callback) {"]
        store_request_lines = [
            "    vapi_store_request(ctx, req_context, %s, %s,"
            % (
                self.reply.get_msg_id_name(),
                "VAPI_REQUEST_DUMP" if self.reply_is_stream else "VAPI_REQUEST_REG",
            ),
            "                       (vapi_cb_t)reply_callback, reply_callback_ctx);",
        ]
        need_store_requests = 1
        if self.has_stream_msg:
            param_check_lines = [
                "  if (!msg || !reply_callback || !details_callback) {"
            ]
            store_request_lines = [
                f"    vapi_store_request(ctx, req_context, {self.stream_msg.get_msg_id_name()}, VAPI_REQUEST_STREAM,",
                "                       (vapi_cb_t)details_callback, details_callback_ctx);",
                f"    vapi_store_request(ctx, req_context, {self.reply.get_msg_id_name()}, VAPI_REQUEST_REG,",
                "                       (vapi_cb_t)reply_callback, reply_callback_ctx);",
            ]
            need_store_requests = 2

        return "\n".join(
            [
                "%s" % self.get_op_func_decl(),
                "{",
            ]
            + param_check_lines
            + [
                "    return VAPI_EINVAL;",
                "  }",
                "  if (vapi_is_nonblocking(ctx) && vapi_get_request_count(ctx) + %s > vapi_get_max_request_count(ctx)) {"
                % need_store_requests,
                "    return VAPI_EAGAIN;",
                "  }",
                "  vapi_error_e rv;",
                "  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {",
                "    return rv;",
                "  }",
                "  u32 req_context = vapi_gen_req_context(ctx);",
                "  msg->header.context = req_context;",
                "  %s(msg);" % self.get_swap_to_be_func_name(),
                (
                    "  if (VAPI_OK == (rv = vapi_send_with_control_ping "
                    "(ctx, msg, req_context))) {"
                    if (self.reply_is_stream and not self.has_stream_msg)
                    else "  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {"
                ),
            ]
            + store_request_lines
            + [
                "    if (VAPI_OK != vapi_producer_unlock (ctx)) {",
                "      abort (); /* this really shouldn't happen */",
                "    }",
                "    if (vapi_is_nonblocking(ctx)) {",
                "      rv = VAPI_OK;",
                "    } else {",
                "      rv = vapi_dispatch(ctx);",
                "    }",
                "  } else {",
                "    %s(msg);" % self.get_swap_to_host_func_name(),
                "    if (VAPI_OK != vapi_producer_unlock (ctx)) {",
                "      abort (); /* this really shouldn't happen */",
                "    }",
                "  }",
                "  return rv;",
                "}",
                "",
            ]
        )

    def get_event_cb_func_decl(self):
        if not self.is_reply and not self.is_event:
            raise Exception("Cannot register event callback for non-reply message")
        if self.has_payload():
            return "\n".join(
                [
                    "void vapi_set_%s_event_cb (" % self.get_c_name(),
                    "  struct vapi_ctx_s *ctx, ",
                    (
                        "  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, "
                        "void *callback_ctx, %s *payload),"
                        % self.get_payload_struct_name()
                    ),
                    "  void *callback_ctx)",
                ]
            )
        else:
            return "\n".join(
                [
                    "void vapi_set_%s_event_cb (" % self.get_c_name(),
                    "  struct vapi_ctx_s *ctx, ",
                    "  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, "
                    "void *callback_ctx),",
                    "  void *callback_ctx)",
                ]
            )

    def get_event_cb_func_def(self):
        if not self.is_reply and not self.is_event:
            raise Exception("Cannot register event callback for non-reply function")
        return "\n".join(
            [
                "%s" % self.get_event_cb_func_decl(),
                "{",
                (
                    "  vapi_set_event_cb(ctx, %s, (vapi_event_cb)callback, "
                    "callback_ctx);" % self.get_msg_id_name()
                ),
                "}",
            ]
        )

    def get_c_metadata_struct_name(self):
        return "__vapi_metadata_%s" % self.name

    def get_c_constructor(self):
        has_context = False
        if self.header is not None:
            has_context = self.header.has_field("context")
        return "\n".join(
            [
                "static void __attribute__((constructor)) __vapi_constructor_%s()"
                % self.name,
                "{",
                '  static const char name[] = "%s";' % self.name,
                '  static const char name_with_crc[] = "%s_%s";'
                % (self.name, self.crc[2:]),
                "  static vapi_message_desc_t %s = {"
                % self.get_c_metadata_struct_name(),
                "    name,",
                "    sizeof(name) - 1,",
                "    name_with_crc,",
                "    sizeof(name_with_crc) - 1,",
                "    true," if has_context else "    false,",
                (
                    "    offsetof(%s, context)," % self.header.get_c_name()
                    if has_context
                    else "    0,"
                ),
                (
                    ("    offsetof(%s, payload)," % self.get_c_name())
                    if self.has_payload()
                    else "    VAPI_INVALID_MSG_ID,"
                ),
                "    (verify_msg_size_fn_t)%s," % self.get_verify_msg_size_func_name(),
                "    (generic_swap_fn_t)%s," % self.get_swap_to_be_func_name(),
                "    (generic_swap_fn_t)%s," % self.get_swap_to_host_func_name(),
                "    VAPI_INVALID_MSG_ID,",
                "  };",
                "",
                "  %s = vapi_register_msg(&%s);"
                % (self.get_msg_id_name(), self.get_c_metadata_struct_name()),
                '  VAPI_DBG("Assigned msg id %%d to %s", %s);'
                % (self.name, self.get_msg_id_name()),
                "}",
            ]
        )


# ---------------------------------------------------------------------------
# Parser registry — drop-in replacement for the public surface of
# JsonParser used by the C/C++ emitters.
# ---------------------------------------------------------------------------

# The two header layouts vapi pattern-matched out of JSON. Reused here as
# StructTypes so the existing emitter keeps calling .has_field / .get_c_name /
# .get_swap_to_*_func_name on them unchanged.
def _make_msg_headers(parser):
    u16 = parser.types["u16"]
    u32 = parser.types["u32"]
    h1 = StructType(
        "msg_header1_t",
        [
            Field("_vl_msg_id", u16),
            Field("context", u32),
        ],
    )
    h2 = StructType(
        "msg_header2_t",
        [
            Field("_vl_msg_id", u16),
            Field("client_index", u32),
            Field("context", u32),
        ],
    )
    return [h1, h2]


class Parser(object):
    """Holds the same registries the JSON-driven JsonParser exposed; built
    from vppapigen AST objects rather than from a JSON file."""

    def __init__(self, logger):
        self.logger = logger
        self.services = {}
        self.replies = set()
        self.events = set()
        self.streams = set()
        self.messages = {}
        self.enums = {}
        self.enumflags = {}
        self.unions = {}
        self.aliases = {}
        self.types = {
            x: SimpleType(x)
            for x in (
                "i8",
                "i16",
                "i32",
                "i64",
                "u8",
                "u16",
                "u32",
                "u64",
                "f64",
                "bool",
            )
        }
        self.types["string"] = SimpleType("u8")
        # vl_api_string_t is its own VLA u8-with-length blob; emit it once
        # (with the legacy crc=None) so the swap helpers exist.
        length = Field("length", self.types["u32"])
        self.types["vl_api_string_t"] = StructType(
            "vl_api_string_t",
            [
                length,
                Field("buf", self.types["u8"], array_len=0, nelem_field=length),
            ],
        )
        self.exceptions = []
        # Locally-declared types/enums/unions/aliases/messages — i.e. those
        # defined in the .api file we're generating from, not pulled in via
        # `import`. The emitter uses these to decide which types to emit a
        # full definition for vs. leave to the importing-side header.
        self.local_types = []
        self.local_enums = []
        self.local_unions = []
        self.local_aliases = []
        self.local_messages = {}

    def lookup_type_like_id(self, name):
        mundane = remove_magic(name)
        for table in (
            self.types,
            self.enums,
            self.enumflags,
            self.unions,
            self.aliases,
        ):
            if name in table:
                return table[name]
            if mundane in table:
                return table[mundane]
        raise KeyError(
            "Could not find type, enum or union by magic name `%s' nor by "
            "mundane name `%s'" % (name, mundane)
        )

    def is_reply(self, name):
        return name in self.replies

    def is_event(self, name):
        return name in self.events

    def is_stream(self, name):
        return name in self.streams

    def has_stream_msg(self, message):
        return (
            message.name in self.services
            and "stream_msg" in self.services[message.name]
        )

    def get_stream_msg(self, message):
        if not self.has_stream_msg(message):
            return None
        return self.messages[self.services[message.name]["stream_msg"]]

    def get_reply(self, message):
        return self.messages[self.services[message]["reply"]]


# ---------------------------------------------------------------------------
# AST walker — translate vppapigen AST objects into Parser registry entries.
# ---------------------------------------------------------------------------


def _format_crc(crc):
    """Match the JSON path's CRC formatting: hex with 0x prefix, 8 digits.
    Only Define messages have an int CRC at plugin-run time (foldup_crcs()
    runs before plugins). Typedef / Union / Enum still have the bytes-form
    CRC vppapigen sets at parse time; vapi only consumes Message CRCs, so
    return None for those rather than crashing the formatter."""
    if isinstance(crc, int):
        return "{0:#0{1}x}".format(crc, 10)
    return None


def _field_from_ast(b, parser, parent_block_fields, parent_name):
    """Translate a single vppapigen Field/Array AST node into a vapi Field
    instance. parent_block_fields is the list of already-translated fields
    in the same struct, used to find VLA length-of references."""
    cls = b.__class__.__name__
    if cls == "Field":
        ftype = parser.lookup_type_like_id(b.fieldtype)
        # Carry forward the [discriminator=<sibling>] option so the parent
        # struct's hton/ntoh can emit the proper switch dispatch over the
        # union arms. Other limit dict entries (e.g. default values) are
        # still ignored — they don't affect wire layout.
        disc = None
        if b.limit and isinstance(b.limit, dict):
            disc = b.limit.get("discriminator")
        return Field(b.fieldname, ftype, discriminator=disc)
    if cls == "Array":
        # `string` arrays decay: a length-0 string field in a typedef is
        # only valid for vl_api_string_t (length-prefixed blob); elsewhere
        # vppapigen only emits length-0 for the `string`-with-VLA-length case
        # which is handled by the lengthfield branch.
        if b.fieldtype == "string":
            if b.length == 0 and not b.lengthfield:
                # Bare `string foo[];` — treat as vl_api_string_t.
                ftype = parser.lookup_type_like_id("vl_api_string_t")
                return Field(b.fieldname, ftype)
            if b.lengthfield:
                ftype = parser.lookup_type_like_id("vl_api_string_t")
                # Match JSON path: emit as scalar Field of vl_api_string_t,
                # not as an array. (vppapigen_json.py emits 4-element form
                # only for non-string arrays.)
                # vapi_json_parser.py l == 3 branch with field[2] == 0 and
                # field[0] == "string" wraps as a scalar vl_api_string_t.
                return Field(b.fieldname, ftype)
            # length>0 string: u8 buffer
            ftype = parser.lookup_type_like_id("u8")
            return Field(b.fieldname, ftype, array_len=b.length)
        ftype = parser.lookup_type_like_id(b.fieldtype)
        if b.lengthfield:
            nelem = None
            for f in parent_block_fields:
                if f.name == b.lengthfield:
                    nelem = f
                    break
            if nelem is None:
                raise ValueError(
                    "VLA `%s.%s' references missing length field `%s'"
                    % (parent_name, b.fieldname, b.lengthfield)
                )
            return Field(b.fieldname, ftype, array_len=b.length, nelem_field=nelem)
        return Field(b.fieldname, ftype, array_len=b.length)
    if cls == "Option":
        return None  # handled by caller
    raise ValueError("Unknown AST node in struct/message block: %r" % b)


def _build_typedef(t, parser):
    fields = []
    for b in t.block:
        if b.__class__.__name__ == "Option":
            continue
        f = _field_from_ast(b, parser, fields, t.name)
        if f is not None:
            fields.append(f)
    return StructType(t.name, fields, crc=_format_crc(getattr(t, "crc", None)))


def _build_union(u, parser):
    arms = []
    for b in u.block:
        if b.__class__.__name__ == "Option":
            continue
        # Union arms are Fields (no array length expected at this layer).
        arm_type = parser.lookup_type_like_id(b.fieldtype)
        case_val = None
        if getattr(b, "limit", None) and isinstance(b.limit, dict):
            case_val = b.limit.get("case")
        if case_val is not None:
            arms.append((arm_type, b.fieldname, case_val))
        else:
            arms.append((arm_type, b.fieldname))
    return Union(u.name, arms, crc=_format_crc(getattr(u, "crc", None)))


def _build_enum(e, parser, is_flag):
    # vppapigen Enum.block is a list of [name, value] pairs.
    value_pairs = list(e.block)
    enumtype = parser.types[e.enumtype]
    return Enum(e.name, value_pairs, enumtype)


def _build_alias(u, parser):
    # vppapigen Using has .alias = {"type": ..., ["length": N]}
    base = parser.lookup_type_like_id(u.alias["type"])
    array_len = u.alias.get("length")
    return Alias(u.name, base, array_len=array_len)


def _detect_header(define, headers):
    """Pick which message header layout (msg_header1_t / msg_header2_t)
    appears at the start of a Define's block, or None if neither matches.
    Mirrors vapi_json_parser.py is_part_of_def."""
    block = define.block
    for hdr in headers:
        if len(block) < len(hdr.fields):
            continue
        ok = True
        for i, hf in enumerate(hdr.fields):
            b = block[i]
            if getattr(b, "fieldname", None) != hf.name:
                ok = False
                break
            if getattr(b, "fieldtype", None) != hf.type.name:
                ok = False
                break
        if ok:
            return hdr
    return None


def _build_message(m, parser, headers):
    is_reply = parser.is_reply(m.name)
    is_event = parser.is_event(m.name)
    is_stream = parser.is_stream(m.name)
    header = _detect_header(m, headers)
    fields = []
    if header is not None:
        fields.append(Field("header", header))
    skip_count = len(header.fields) if header is not None else 0
    for idx, b in enumerate(m.block):
        if idx < skip_count and header is not None:
            # skip header fields that already collapsed into the header
            # placeholder above
            continue
        if b.__class__.__name__ == "Option":
            continue
        f = _field_from_ast(b, parser, fields, m.name)
        if f is None:
            continue
        # Don't double-add header fields (e.g. when client_index appears in
        # block but the matched header didn't include it).
        if header is not None and header.has_field(f.name):
            continue
        fields.append(f)
    if header is None and not (is_reply or is_event):
        raise ValueError(
            "While parsing message `%s': could not find all common header fields"
            % m.name
        )
    return Message(
        name=m.name,
        fields=fields,
        header=header,
        crc=_format_crc(getattr(m, "crc", None)),
        is_reply=is_reply,
        is_event=is_event,
        is_stream=is_stream,
    )


def parser_from_ast(s, apifilename, logger):
    """Build a Parser registry from vppapigen's AST output (`s` dict).

    Imports are flattened into s["types"] thanks to process_imports=True; the
    resulting .vapi.h is self-contained (with #ifdef guards on every type
    definition to handle the multiple-include case). Imported types end up
    in parser.{types,enums,unions,aliases} but NOT in the corresponding
    parser.local_* lists — the emitter uses local_* to decide which types
    to emit a full definition for vs. leave to the importing-side header."""

    parser = Parser(logger)

    # Services first so message classification works during build_message.
    for svc in s["Service"]:
        d = {"reply": svc.reply}
        if svc.stream:
            d["stream"] = True
        if svc.stream_message:
            d["stream_msg"] = svc.stream_message
        parser.services[svc.caller] = d
        if svc.reply and svc.reply != "null":
            parser.replies.add(svc.reply)
        for ev in svc.events:
            parser.events.add(ev)
        if svc.stream_message:
            parser.streams.add(svc.stream_message)

    # Enums (no dependencies). Imports are flattened into s["types"] so the
    # same type can appear multiple times when one .api imports the same
    # transitive dependency from multiple paths; dedupe by name.
    for o in s["types"]:
        cls = o.__class__.__name__
        if cls == "Enum":
            if o.name in parser.enums:
                continue
            e = _build_enum(o, parser, is_flag=False)
            parser.enums[e.name] = e
            parser.local_enums.append(e)
        elif cls == "EnumFlag":
            if o.name in parser.enums:
                continue
            e = _build_enum(o, parser, is_flag=True)
            parser.enums[e.name] = e
            parser.enumflags[e.name] = e
            parser.local_enums.append(e)

    # Aliases / Typedefs / Unions: forward refs across these are possible
    # (a typedef can reference a union, a union can reference a typedef, an
    # alias can reference a typedef). Multi-pass with progress check, like
    # the JSON path's retry loop. Dedupe by name in case the same import
    # was pulled in via multiple transitive paths.
    pending = []
    seen_names = set()
    for o in s["types"]:
        if o.name in seen_names:
            continue
        cls = o.__class__.__name__
        if cls == "Using":
            pending.append(("alias", o))
            seen_names.add(o.name)
        elif cls == "Typedef":
            pending.append(("type", o))
            seen_names.add(o.name)
        elif cls == "Union":
            pending.append(("union", o))
            seen_names.add(o.name)

    while pending:
        progress = False
        next_round = []
        for kind, o in pending:
            try:
                if kind == "alias":
                    a = _build_alias(o, parser)
                    parser.aliases[a.name] = a
                    parser.local_aliases.append(a)
                elif kind == "type":
                    t = _build_typedef(o, parser)
                    parser.types[t.name] = t
                    parser.local_types.append(t)
                elif kind == "union":
                    u = _build_union(o, parser)
                    parser.unions[u.name] = u
                    parser.local_unions.append(u)
                progress = True
            except KeyError:
                next_round.append((kind, o))
        if not progress:
            # Surface the first unresolved type for the diagnostic.
            kind, o = next_round[0]
            raise ValueError(
                "Cannot resolve dependencies for %s `%s' in %s"
                % (kind, o.name, apifilename)
            )
        pending = next_round

    # Messages last — all type references must resolve by now. Messages
    # whose fields don't match either header layout (e.g. memclnt_delete,
    # rx_thread_exit) are skipped; the JSON path also dropped these. They
    # are VPP-internal mailbox messages that don't carry the standard vapi
    # client headers, so vapi can't bind them anyway.
    # Dedupe by name on the off-chance a message appears twice via
    # transitive imports (rare but possible).
    headers = _make_msg_headers(parser)
    for m in s["Define"]:
        if m.name in parser.messages:
            continue
        try:
            msg = _build_message(m, parser, headers)
        except ValueError as e:
            parser.exceptions.append(e)
            continue
        parser.messages[msg.name] = msg
        parser.local_messages[msg.name] = msg

    # Match JsonParser.finalize_parsing: only surface accumulated parse
    # errors if nothing parsed at all. Otherwise the user gets noise about
    # the headerless internal messages on every build.
    if not parser.messages:
        for e in parser.exceptions:
            logger.warning(str(e))

    # Link request → reply / stream metadata, mirroring JsonParser.finalize.
    for n, m in list(parser.messages.items()):
        if not m.is_reply and not m.is_event and not m.is_stream:
            try:
                m.reply = parser.get_reply(n)
                m.reply_is_stream = parser.services[n].get("stream", False)
                m.has_stream_msg = parser.has_stream_msg(m)
                if m.has_stream_msg:
                    m.stream_msg = parser.get_stream_msg(m)
                m.reply.request = m
            except KeyError:
                # Service entry missing — only really expected for the
                # synthetic memclnt_create / control_ping pair handled
                # specially by vapi.h. Drop the message from emission so
                # the unified header still builds.
                parser.local_messages.pop(n, None)
                parser.messages.pop(n, None)

    return parser


# ---------------------------------------------------------------------------
# Header emission — copy of gen_json_unified_header() / emit_definition() from
# vapi_c_gen.py, lightly adapted to use Parser instead of JsonParser.
# ---------------------------------------------------------------------------


def _emit_definition(parser, emitted, o, write):
    if o in emitted:
        return
    if o.name in ("msg_header1_t", "msg_header2_t"):
        return
    if hasattr(o, "depends"):
        for x in o.depends:
            _emit_definition(parser, emitted, x, write)
    if hasattr(o, "reply") and o.reply is not None:
        _emit_definition(parser, emitted, o.reply, write)
    if hasattr(o, "stream_msg") and o.stream_msg is not None:
        _emit_definition(parser, emitted, o.stream_msg, write)
    if hasattr(o, "get_c_def"):
        if (
            o not in parser.local_enums
            and o not in parser.local_types
            and o not in parser.local_unions
            and o.name not in parser.local_messages
            and o not in parser.local_aliases
        ):
            return
        type_guard = "__vapi_def_defined_%s" % o.get_c_name()
        write("#ifndef %s\n" % type_guard)
        write("#define %s\n" % type_guard)
        write("%s\n" % o.get_c_def())
        write("\n")
        write("#ifndef VAPI_EMIT_TYPES_ONLY\n")
        code_guard = "__vapi_code_defined_%s" % o.get_c_name()
        write("#ifndef %s\n" % code_guard)
        write("#define %s\n" % code_guard)
        function_attrs = "static inline "
        if o.name in parser.local_messages:
            if o.has_payload():
                write("%s%s\n" % (function_attrs, o.get_swap_payload_to_be_func_def()))
                write("\n")
                write(
                    "%s%s\n" % (function_attrs, o.get_swap_payload_to_host_func_def())
                )
                write("\n")
            write("%s%s\n" % (function_attrs, o.get_swap_to_be_func_def()))
            write("\n")
            write("%s%s\n" % (function_attrs, o.get_swap_to_host_func_def()))
            write("\n")
            write("%s%s\n" % (function_attrs, o.get_calc_msg_size_func_def()))
            write("\n")
            write("%s%s\n" % (function_attrs, o.get_verify_msg_size_func_def()))
            if not o.is_reply and not o.is_event and not o.is_stream:
                write("\n")
                write("%s%s\n" % (function_attrs, o.get_alloc_func_def()))
                write("\n")
                write("%s%s\n" % (function_attrs, o.get_op_func_def()))
            write("\n")
            write("%s\n" % o.get_c_constructor())
            if (o.is_reply or o.is_event) and not o.is_stream:
                write("\n")
                write("%s%s;\n" % (function_attrs, o.get_event_cb_func_def()))
        elif hasattr(o, "get_swap_to_be_func_def"):
            write("%s%s\n" % (function_attrs, o.get_swap_to_be_func_def()))
            write("\n")
            write("%s%s\n" % (function_attrs, o.get_swap_to_host_func_def()))
        write("#endif\n")  # code_guard
        write("#endif\n")  # VAPI_EMIT_TYPES_ONLY
        write("#endif\n")
        write("\n")
    emitted.append(o)


def _munged_filename_token(f):
    return (
        f.replace(".", "_")
        .replace("/", "_")
        .replace("-", "_")
        .replace("+", "_")
        .replace("@", "_")
    )


def write_vapi_h(parser, apifilename, name, out):
    """Write the unified .vapi.h to file-like `out` (must support .write())."""
    # Match the old generator's include-guard / DEFINE_VAPI_MSG_IDS_*
    # naming, which is what consumers (vapi.c, vapi_c_test.c, vapi_cpp_test.cpp)
    # spell. Those names hash the legacy `<module>.api.json` filename, not the
    # `.api` we're driven from now, so keep the `.json` suffix for the token.
    f = os.path.basename(apifilename)
    if not f.endswith(".json"):
        f = f + ".json"
    include_guard = "__included_%s" % _munged_filename_token(f)
    out.write("#ifndef %s\n" % include_guard)
    out.write("#define %s\n" % include_guard)
    out.write("\n")
    out.write("#include <stdlib.h>\n")
    out.write("#include <stddef.h>\n")
    out.write("#include <arpa/inet.h>\n")
    out.write("#include <vapi/vapi_internal.h>\n")
    out.write("#include <vapi/vapi.h>\n")
    out.write("#include <vapi/vapi_dbg.h>\n")
    out.write("\n")
    out.write("#ifdef __cplusplus\n")
    out.write('extern "C" {\n')
    out.write("#endif\n")

    out.write("#ifndef __vl_api_string_swap_fns_defined__\n")
    out.write("#define __vl_api_string_swap_fns_defined__\n")
    out.write("\n")
    out.write("#include <vlibapi/api_types.h>\n")
    out.write("\n")
    function_attrs = "static inline "
    string_t = parser.types["vl_api_string_t"]
    out.write("%s%s\n" % (function_attrs, string_t.get_swap_to_be_func_def()))
    out.write("\n")
    out.write("%s%s\n" % (function_attrs, string_t.get_swap_to_host_func_def()))
    out.write("\n")
    out.write("#endif //__vl_api_string_swap_fns_defined__\n")

    if name == "memclnt.api.vapi.h":
        out.write("\n")
        out.write("#ifndef VAPI_EMIT_TYPES_ONLY\n")
        out.write(
            "static inline vapi_error_e vapi_send_with_control_ping "
            "(vapi_ctx_t ctx, void * msg, u32 context);\n"
        )
        out.write("#endif\n")
    elif name == "vlib.api.vapi.h":
        out.write("#include <vapi/memclnt.api.vapi.h>\n")
    else:
        out.write("#include <vapi/vlib.api.vapi.h>\n")
    out.write("\n")
    for m in parser.local_messages.values():
        out.write("extern vapi_msg_id_t %s;\n" % m.get_msg_id_name())
    out.write("\n")
    out.write(
        "#define DEFINE_VAPI_MSG_IDS_%s\\\n" % _munged_filename_token(f).upper()
    )
    out.write(
        "\\\n".join(
            [
                "  vapi_msg_id_t %s;" % m.get_msg_id_name()
                for m in parser.local_messages.values()
            ]
        )
    )
    out.write("\n")
    out.write("\n")
    out.write("\n")
    emitted = []
    for e in parser.local_enums:
        _emit_definition(parser, emitted, e, out.write)
    for u in parser.local_unions:
        _emit_definition(parser, emitted, u, out.write)
    for t in parser.local_types:
        _emit_definition(parser, emitted, t, out.write)
    for a in parser.local_aliases:
        _emit_definition(parser, emitted, a, out.write)
    for m in parser.local_messages.values():
        _emit_definition(parser, emitted, m, out.write)

    out.write("\n")

    if name == "vlib.api.vapi.h":
        vapi_send_with_control_ping_function = """
static inline vapi_error_e
vapi_send_with_control_ping (vapi_ctx_t ctx, void *msg, u32 context)
{
  vapi_msg_control_ping *ping = vapi_alloc_control_ping (ctx);
  if (!ping)
    {
      return VAPI_ENOMEM;
    }
  ping->header.context = context;
  vapi_msg_control_ping_hton (ping);
  return vapi_send2 (ctx, msg, ping);
}
"""
        out.write("#ifndef VAPI_EMIT_TYPES_ONLY\n")
        out.write("%s\n" % vapi_send_with_control_ping_function)
        out.write("#endif\n")
        out.write("\n")

    out.write("#ifdef __cplusplus\n")
    out.write("}\n")
    out.write("#endif\n")
    out.write("\n")
    out.write("#endif\n")
