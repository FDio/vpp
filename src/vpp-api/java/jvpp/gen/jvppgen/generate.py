#!/usr/bin/env python3
import json
import os
import sys

vapi_header = "vapi_gen.h"
vapi_code = "vapi_gen.c"

msg_header1_fields = [
    ('u16', '_vl_msg_id'), ('u32', 'context')]
msg_header1_field_names = [n for t, n in msg_header1_fields]

msg_header2_fields = [
    ('u16', '_vl_msg_id'), ('u32', 'client_index'), ('u32', 'context')]
msg_header2_field_names = [n for t, n in msg_header2_fields]

msg_header_defs = [
    {
        'name': 'vapi_msg_header1_t',
        'fields': msg_header1_fields,
        'field_names': msg_header1_field_names,
    },
    {
        'name': 'vapi_msg_header2_t',
        'fields': msg_header2_fields,
        'field_names': msg_header2_field_names,
    },
]


def msg_is_reply_only(name):
    return name.endswith('_reply') or name.endswith('_details')\
        or name.endswith('_event') or name.endswith('_counters')


class ParseError(Exception):
    pass


def apply_magic(what):
    return "vl_api_%s_t" % what


def is_header_present(name, definition, header_fields):
    for idx in range(len(header_fields)):
        field = definition[idx]
        t, n = header_fields[idx]
        if field[1] != n:
            return False
        if field[0] != t:
            raise ParseError("Unexpected field type `%s' (should be `%s'), "
                             "while parsing msg/def/field `%s/%s/%s'" % (
                                 field[0], t, name, definition, field))
    return True


class Parameter:

    def __init__(self, param_name, param_type, array_len=None,
                 nelem_param=None):
        self.name = param_name
        self.type = param_type
        self.len = array_len
        self.nelem_param = nelem_param

    def get_c_def(self):
        if self.len is not None:
            return "%s %s[%s]" % (self.type, self.name, self.len)
        else:
            return "%s %s" % (self.type, self.name)


class Struct:

    def __init__(self, name, parameters):
        self.name = name
        self.parameters = parameters

    def get_c_def(self):
        return "typedef struct __attribute__((__packed__)) {\n%s;\n} %s;" % (
            ";\n".join(["  %s" % x.get_c_def() for x in self.parameters]),
            self.get_struct_name()
        )


class Message(Struct):

    def __init__(self, definition, typedict, swap_to_be_dict,
                 swap_to_host_dict):
        self.swap_to_be_dict = swap_to_be_dict
        self.swap_to_host_dict = swap_to_host_dict
        m = definition
        name = m[0]
        ignore = True
        self.header = None
        for header in msg_header_defs:
            if is_header_present(name, m[1:], header['fields']):
                self.header = header
                ignore = False
                break
        if ignore and not msg_is_reply_only(name):
            raise ParseError("while parsing message `%s': could not find all "
                             "common header fields" % name)
        parameters = []
        for field in m[1:]:
            if len(field) == 1 and 'crc' in field:
                self.crc = field['crc']
                continue
            elif len(field) == 2:
                p = Parameter(param_name=field[1],
                              param_type=typedict[field[0]])
            elif len(field) == 3:
                if field[2] == 0:
                    raise ParseError(
                        "while parsing message `%s': variable length "
                        "array `%s' doesn't have reference to member "
                        "containing the actual length" %
                        (name, field[1]))
                p = Parameter(param_name=field[1],
                              param_type=typedict[field[0]],
                              array_len=field[2])
            elif len(field) == 4:
                p = Parameter(param_name=field[1],
                              param_type=typedict[field[0]],
                              array_len=field[2], nelem_param=field[3])
            else:
                raise Exception("Don't know how to parse message definition "
                                "for message `%s': `%s'" (m, m[1:]))
            parameters.append(p)
        super().__init__(name, parameters)

    def is_dump(self):
        return self.name.endswith('_dump')

    def is_reply_only(self):
        return msg_is_reply_only(self.name)

    def get_enum_name(self):
        return "__vapi_msg_%s" % self.name

    def get_struct_name(self):
        return "vapi_msg_%s" % self.name

    def get_payload_struct_name(self):
        return "vapi_payload_%s" % self.name

    def get_init_func_name(self):
        return "vapi_msg_init_%s" % self.name

    def get_init_func_decl(self):
        return "void %s(struct vapi_ctx_s *ctx, %s *msg)" % (
            self.get_init_func_name(), self.get_struct_name())

    def get_op_func_name(self):
        return "vapi_%s" % self.name

    def get_op_func_decl(self):
        return "vapi_error_e %s(%s)" % (
            self.get_op_func_name(),
            ",\n  ".join([
                'struct vapi_ctx_s *ctx',
                ('vapi_error_e (*callback)(struct vapi_ctx_s *ctx, '
                 'void *callback_ctx, vapi_error_e rv, bool is_last, '
                 '%s *reply)' %
                 self.reply.get_payload_struct_name()),
                'void *callback_ctx'] +
                [p.get_c_def() for p in self.parameters
                    if p.name not in self.header['field_names']
                 ])
        )

    def get_c_def(self):
        return "\n".join([
            "typedef struct __attribute__ ((__packed__)) {",
            "%s; " % ";\n".join([
                "  %s" % p.get_c_def()
                for p in self.parameters
                if self.header is None or
                p.name not in self.header['field_names']]),
            "} %s;" % self.get_payload_struct_name(),
            ""
            "typedef struct {",
            ("  %s header;" % self.header['name']
                if self.header is not None else ""),
            "  %s payload;" % self.get_payload_struct_name(),
            "}  %s;" % self.get_struct_name(),
        ])

    def get_init_func_def(self):
        if 'client_index' in self.header['field_names']:
            extra = "  msg->header.client_index = api_main.my_client_index;"
        return "%s\n{\n  msg->header._vl_msg_id = htons(ctx->enum_to_id[%s]);"\
            "\n%s\n}" % (self.get_init_func_decl(),
                         self.get_enum_name(), extra)

    def get_swap_to_host_func_name(self):
        return "vapi_%s_swap_to_host" % self.get_payload_struct_name()

    def get_swap_to_be_func_name(self):
        return "vapi_%s_swap_to_be" % self.get_payload_struct_name()

    def get_swap_to_host_func_decl(self):
        return "void %s(%s *payload)" % (self.get_swap_to_host_func_name(),
                                         self.get_payload_struct_name())

    def get_swap_to_be_func_decl(self):
        return "void %s(%s *payload)" % (self.get_swap_to_be_func_name(),
                                         self.get_payload_struct_name())

    def get_swap_to_be_func_def(self):
        return "%s\n{\n%s\n}" % (
            self.get_swap_to_be_func_decl(),
            "\n".join([
                "  payload->%s = %s(payload->%s);" %
                (p.name, self.swap_to_be_dict[p.type], p.name)
                for p in self.parameters
                if (self.header is None or
                    p.name not in self.header['field_names']) and
                p.type in self.swap_to_be_dict and p.len is None
            ]),
        )

    def get_swap_to_host_func_def(self):
        return "%s\n{\n%s\n}" % (
            self.get_swap_to_host_func_decl(),
            "\n".join([
                "  payload->%s = %s(payload->%s);" %
                (p.name, self.swap_to_be_dict[p.type], p.name)
                for p in self.parameters
                if (self.header is None or
                    p.name not in self.header['field_names']) and
                p.type in self.swap_to_be_dict and p.len is None
            ]),
        )

    def get_op_func_def(self):
        param_string = "\n  ".join([
            "msg->payload.%s = %s;" % (p.name, p.name)
            if p.len is None else
            "memcpy(&msg->payload.%s, %s, sizeof(*%s) * %s);" % (
                p.name, p.name, p.name, p.len)
            if p.len > 0 else
            "memcpy(&msg->payload.%s, %s, sizeof(*%s) * %s);" % (
                p.name, p.name, p.name, p.nelem_param)
            for p in self.parameters
            if p.name not in self.header['field_names']])
        return "\n".join(
            [
                "%s" % self.get_op_func_decl(),
                "{",
                "  if (!callback) {",
                "    return VAPI_EINVAL;",
                "  }",
                ("  if (VAPI_MODE_NONBLOCKING == ctx->mode && "
                    "vapi_requests_full(ctx)) {"),
                "    return VAPI_EAGAIN;",
                "  }",
                "  const bool is_dump = %s;" % (
                    "true" if self.is_dump() else "false"),
                ("  if (is_dump && "
                    "vapi_get_request_count(ctx) + 1 >= ctx->requests_size) {"
                 ),
                "    return VAPI_EAGAIN;",
                "  }",
                "  %s *msg;" % self.get_struct_name(),
                "  msg = vapi_msg_alloc (sizeof(*msg));",
                "  if (!msg) {",
                "    return VAPI_ENOMEM;",
                "  }",
                "  vapi_msg_control_ping *ping = NULL;",
                "  if (is_dump && !(ping = vapi_msg_alloc (sizeof(*ping)))) {",
                "    vapi_msg_free(msg);",
                "    return VAPI_ENOMEM;",
                "  }",
                "  %s (ctx, msg);" % self.get_init_func_name(),
                "  %s" % param_string,
                "  u32 req_context = vapi_get_context(ctx);",
                "  msg->header.context = req_context;",
                "  %s(&msg->payload);" % self.get_swap_to_be_func_name(),
                "  vapi_error_e rv = vapi_send(ctx, msg);",
                "  if (VAPI_OK == rv) {",
                ("    vapi_send_control_ping(ctx, ping, req_context);"
                    if self.is_dump() else ""),
                ("      vapi_store_request(ctx, req_context, is_dump, "
                    "(vapi_cb_t)callback, callback_ctx);"),
                "    if (VAPI_MODE_NONBLOCKING == ctx->mode) {",
                "      return VAPI_OK;",
                "    }",
                "    rv = vapi_dispatch(ctx);",
                "  }",
                "  return rv;",
                "}",
                "",
            ]
        )


class Type(Struct):

    def __init__(self, definition, typedict):
        t = definition
        name = t[0]
        parameters = []
        for field in t[1:]:
            if len(field) == 1 and 'crc' in field:
                self.crc = field['crc']
                continue
            elif len(field) == 2:
                p = Parameter(param_name=field[1],
                              param_type=typedict[field[0]])
            elif len(field) == 3:
                if field[2] == 0:
                    raise ParseError("while parsing type `%s': array `%s' has "
                                     "variable length" % (name, field[1]))
                p = Parameter(param_name=field[1],
                              param_type=typedict[field[0]],
                              array_len=field[2])
            else:
                raise ParseError("Don't know how to parse type definition for "
                                 "type `%s': `%s'" (t, t[1:]))
            parameters.append(p)
        super().__init__(name, parameters)

    def get_enum_name(self):
        return "__vapi_type_%s" % self.name

    def get_struct_name(self):
        return "vapi_type_%s" % self.name


class ParserContext:
    typedict = {x: x for x in ['u8', 'u16', 'u32', 'u64', 'f64', 'i8', 'i16', 'i32', 'i64' ]}

    swap_to_be_dict = {
        'u16': 'htobe16',
        'i16': 'htobe16',
        'u32': 'htobe32',
        'i32': 'htobe32',
        'u64': 'htobe64',
        'i64': 'htobe64',
    }

    swap_to_host_dict = {
        'u16': 'be16toh',
        'i16': 'be16toh',
        'u32': 'be32toh',
        'i32': 'be32toh',
        'u64': 'be64toh',
        'i64': 'be64toh',
    }

    def __init__(self):
        self.messages = {}
        self.types = {}
        self.exceptions = []
        self.msg_count = 0

    def parse_json_file(self, path):
        print("Found api file: `%s'" % path)
        with open(path) as f:
            j = json.load(f)
            for t in j['types']:
                try:
                    type_ = Type(t, self.typedict)
                    if type_.name in self.types:
                        raise ParseError("Duplicate type `%s'" % type_.name)
                except ParseError as e:
                    self.exceptions.append(e)
                    continue
                self.types[type_.name] = type_
                self.typedict[apply_magic(type_.name)] =\
                    type_.get_struct_name()
            for m in j['messages']:
                try:
                    msg = Message(m, self.typedict, self.swap_to_be_dict,
                                  self.swap_to_host_dict)
                    if msg.name in self.messages:
                        raise ParseError("Duplicate message `%s'" % msg.name)
                except ParseError as e:
                    self.exceptions.append(e)
                    continue
                self.messages[msg.name] = msg
            self.msg_count += len(j['messages'])

    def get_reply(self, message):
        if self.messages[message].is_dump():
            return self.messages["%s_details" % message[:-len("_dump")]]
        return self.messages["%s_reply" % message]

    def validate_json_data(self):
        if len(self.messages) == 0:
            raise Exception("No messages parsed.")
        remove = []
        for n, m in self.messages.items():
            try:
                if not m.is_reply_only():
                    try:
                        m.reply = self.get_reply(n)
                    except:
                        raise ParseError("cannot find reply for message `%s'" %
                                         n)
            except ParseError as e:
                self.exceptions.append(e)
                remove.append(n)

        self.messages = {k: v for k, v in self.messages.items()
                         if k not in remove}

    def gen_header(self, io):
        orig_stdout = sys.stdout
        sys.stdout = io
        include_guard = "included_%s" % vapi_header.replace(".", "_")
        print("#ifndef %s" % include_guard)
        print("#define %s" % include_guard)
        print("")
        print("#include <stdint.h>")
        print("")
        print("struct vapi_ctx_s;")
        print("")
        for header in msg_header_defs:
            print("typedef struct __attribute__((__packed__)) {")
            for t, v in header['fields']:
                print("  %s %s;" % (self.typedict[t], v))
            print("} %s;" % header['name'])
            print("")
        print("typedef enum {")
        for t, v in self.types.items():
            print("  %s," % v.get_enum_name())
        print("} vapi_type_id_e;")
        print("")
        print("typedef enum {")
        for n, m in self.messages.items():
            print("  %s," % m.get_enum_name())
        print("} vapi_msg_id_e;")
        print("")
        print("#define VAPI_MSG_COUNT (%s)" % self.msg_count)
        print("")
        for n, t in self.types.items():
            print("%s" % t.get_c_def())
            print("")
        for n, m in self.messages.items():
            print("%s" % m.get_c_def())
            print("")
        for n, m in self.messages.items():
            if not m.is_reply_only():
                print("%s;" % m.get_init_func_decl())
                print("%s;" % m.get_op_func_decl())
            print("%s;" % m.get_swap_to_host_func_decl())
            print("%s;" % m.get_swap_to_be_func_decl())
            print("")

        print("#endif")
        sys.stdout = orig_stdout

    def get_swap_to_host_func_table(self):
        return (
            "static void (*__vapi_swap_to_host_func_table[])(void*) = "
            "{\n%s\n};" %
            "\n".join(["[%s] = (void(*)(void*))%s," %
                       (m.get_enum_name(), m.get_swap_to_host_func_name())
                       for n, m in self.messages.items()
                       ])
        )

    def get_swap_to_be_func_table(self):
        return (
            "static void (*__vapi_swap_to_be_func_table[])(void*) = "
            "{\n%s\n};" %
            "\n".join(["[%s] = (void(*)(void*))%s," %
                       (m.get_enum_name(), m.get_swap_to_be_func_name())
                       for n, m in self.messages.items()
                       ])
        )

    def gen_code(self, io):
        orig_stdout = sys.stdout
        sys.stdout = io
        print("#include <%s>" % vapi_header)
        print("#include <stdlib.h>")
        print("#include <arpa/inet.h>")
        print("u32 __vapi_type__crcs[] = {")
        for t, v in self.types.items():
            print("  [%s] = %s, " % (v.get_enum_name(), v.crc))
        print("};")
        print("")
        print("u32 __vapi_msg_crcs[] = {")
        for n, m in self.messages.items():
            print("  [%s] = %s, " % (m.get_enum_name(), m.crc))
        print("};")
        print("")
        print("const char * __vapi_msg_names[] = {")
        for n, m in self.messages.items():
            print("  [%s] = \"%s\", " % (m.get_enum_name(), m.name))
        print("};")
        print("")
        for n, m in self.messages.items():
            print("%s" % m.get_swap_to_be_func_def())
            print("")
            print("%s" % m.get_swap_to_host_func_def())
            print("")
        for n, m in self.messages.items():
            if m.is_reply_only():
                continue
            print("%s" % m.get_init_func_def())
            print("")
            print("%s" % m.get_op_func_def())
        print("")
        print("%s" % self.get_swap_to_host_func_table())
        print("")
        # print("%s" % self.get_swap_to_be_func_table())
        # print("")
        print("static void __vapi_discover_msg_ids(u32 *ids,"
              " unsigned ids_size){")
        print("  if (%s > ids_size) {" % len(self.messages))
        print("    abort();")
        print("  }")
        for n, m in self.messages.items():
            enum = m.get_enum_name()
            crc = m.crc
            print("  ids[%s] = vl_api_get_msg_index((u8*)\"%s_%s\");" %
                  (enum, n, crc[2:]))
        print("}")
        print("static bool __vapi_msg_is_with_context[] = {")
        for n, m in self.messages.items():
            print("  [%s] = true," % m.get_enum_name())
        print("};")
        print("")
        print("static int __vapi_msg_id_to_context_offset[] = {")
        for n, m in self.messages.items():
            if m.header is None:
                continue
            print("  [%s] = offsetof(%s, context)," %
                  (m.get_enum_name(), m.header['name']))
        print("};")
        print("")
        print("static size_t __vapi_msg_id_to_msg_size[] = {")
        for n, m in self.messages.items():
            print("  [%s] = sizeof(%s)," %
                  (m.get_enum_name(), m.get_struct_name()))
        print("};")
        print("")
        # print("static vapi_msg_id_e __vapi_msg_id_to_reply_enum[] = {")
        # for n, m in self.messages.items():
        #     if m.is_reply_only():
        #         continue
        #     print("  [%s] = %s," % (m.get_enum_name(),
        #                             self.get_reply(n).get_enum_name()))
        # print("};")
        # print("")
        print("static int __vapi_msg_id_to_payload_offset[] = {")
        for n, m in self.messages.items():
            print("  [%s] = offsetof(%s, payload)," % (
                m.get_enum_name(), m.get_struct_name()))
        print("};")
        sys.stdout = orig_stdout


if __name__ == '__main__':
    path = os.getenv("VPP_API_JSON_PATH")
    if path is None:
        path = "/usr/share/vpp/api"
        print("Using default path: `%s'" % path)

    ctx = ParserContext()

    print("Walking path(s): `%s'" % path)

    for dir_path in path.split(":"):
        if not os.path.isdir(dir_path):
            raise ParseError("Invalid API dir path: `%s'" % dir_path)

        for root, dirs, files in os.walk(dir_path):
            for f in files:
                if not f.endswith(".api.json"):
                    continue
                with_path = os.path.join(root, f)
                ctx.parse_json_file(with_path)

    ctx.validate_json_data()

    io = open(vapi_header, "w")
    ctx.gen_header(io)
    io = open(vapi_code, "w")
    ctx.gen_code(io)

    for e in ctx.exceptions:
        print(e)
