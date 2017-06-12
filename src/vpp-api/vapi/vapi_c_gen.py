#!/usr/bin/env python3

import argparse
import os
import sys
import logging
from vapi_json_parser import Field, Struct, Message, JsonParser,\
    SimpleType, StructType


class CField(Field):
    def __init__(
            self,
            field_name,
            field_type,
            array_len=None,
            nelem_field=None):
        super().__init__(field_name, field_type, array_len, nelem_field)

    def get_c_def(self):
        if self.len is not None:
            return "%s %s[%d]" % (self.type.get_c_name(), self.name, self.len)
        else:
            return "%s %s" % (self.type.get_c_name(), self.name)

    def get_swap_to_be_code(self, struct, var):
        if self.len is not None:
            if self.len > 0:
                return "do { unsigned i; for (i = 0; i < %d; ++i) { %s } }"\
                    " while(0);" % (
                        self.len,
                        self.type.get_swap_to_be_code(struct, "%s[i]" % var))
            else:
                if self.nelem_field.needs_byte_swap():
                    nelem_field = "%s(%s%s)" % (
                        self.nelem_field.type.get_swap_to_host_func_name(),
                        struct, self.nelem_field.name)
                else:
                    nelem_field = "%s%s" % (struct, self.nelem_field.name)
                return (
                    "do { unsigned i; for (i = 0; i < %s; ++i) { %s } }"
                    " while(0);" %
                    (nelem_field, self.type.get_swap_to_be_code(
                        struct, "%s[i]" % var)))
        return self.type.get_swap_to_be_code(struct, "%s" % var)

    def get_swap_to_host_code(self, struct, var):
        if self.len is not None:
            if self.len > 0:
                return "do { unsigned i; for (i = 0; i < %d; ++i) { %s } }"\
                    " while(0);" % (
                        self.len,
                        self.type.get_swap_to_host_code(struct, "%s[i]" % var))
            else:
                # nelem_field already swapped to host here...
                return (
                    "do { unsigned i; for (i = 0; i < %s%s; ++i) { %s } }"
                    " while(0);" %
                    (struct, self.nelem_field.name,
                     self.type.get_swap_to_host_code(
                         struct, "%s[i]" % var)))
        return self.type.get_swap_to_host_code(struct, "%s" % var)

    def needs_byte_swap(self):
        return self.type.needs_byte_swap()


class CStruct(Struct):
    def __init__(self, name, fields):
        super().__init__(name, fields)

    def get_c_def(self):
        return "\n".join([
            "typedef struct __attribute__((__packed__)) {",
            "%s;" % ";\n".join(["  %s" % x.get_c_def()
                                for x in self.fields]),
            "} %s;" % self.get_c_name()])


class CSimpleType (SimpleType):

    swap_to_be_dict = {
        'i16': 'htobe16', 'u16': 'htobe16',
        'i32': 'htobe32', 'u32': 'htobe32',
        'i64': 'htobe64', 'u64': 'htobe64',
    }

    swap_to_host_dict = {
        'i16': 'be16toh', 'u16': 'be16toh',
        'i32': 'be32toh', 'u32': 'be32toh',
        'i64': 'be64toh', 'u64': 'be64toh',
    }

    def __init__(self, name):
        super().__init__(name)

    def get_c_name(self):
        return self.name

    def get_swap_to_be_func_name(self):
        return self.swap_to_be_dict[self.name]

    def get_swap_to_host_func_name(self):
        return self.swap_to_host_dict[self.name]

    def get_swap_to_be_code(self, struct, var):
        x = "%s%s" % (struct, var)
        return "%s = %s(%s);" % (x, self.get_swap_to_be_func_name(), x)

    def get_swap_to_host_code(self, struct, var):
        x = "%s%s" % (struct, var)
        return "%s = %s(%s);" % (x, self.get_swap_to_host_func_name(), x)

    def needs_byte_swap(self):
        try:
            self.get_swap_to_host_func_name()
            return True
        except:
            pass
        return False


class CStructType (StructType, CStruct):
    def __init__(self, definition, typedict, field_class):
        super().__init__(definition, typedict, field_class)

    def get_c_name(self):
        return "vapi_type_%s" % self.name

    def get_swap_to_be_func_name(self):
        return "%s_hton" % self.get_c_name()

    def get_swap_to_host_func_name(self):
        return "%s_ntoh" % self.get_c_name()

    def get_swap_to_be_func_decl(self):
        return "void %s(%s *msg)" % (
            self.get_swap_to_be_func_name(), self.get_c_name())

    def get_swap_to_be_func_def(self):
        return "%s\n{\n%s\n}" % (
            self.get_swap_to_be_func_decl(),
            "\n".join([
                "  %s" % p.get_swap_to_be_code("msg->", "%s" % p.name)
                for p in self.fields if p.needs_byte_swap()]),
        )

    def get_swap_to_host_func_decl(self):
        return "void %s(%s *msg)" % (
            self.get_swap_to_host_func_name(), self.get_c_name())

    def get_swap_to_host_func_def(self):
        return "%s\n{\n%s\n}" % (
            self.get_swap_to_host_func_decl(),
            "\n".join([
                "  %s" % p.get_swap_to_host_code("msg->", "%s" % p.name)
                for p in self.fields if p.needs_byte_swap()]),
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


class CMessage (Message):
    def __init__(self, logger, definition, typedict,
                 struct_type_class, simple_type_class, field_class):
        super().__init__(logger, definition, typedict, struct_type_class,
                         simple_type_class, field_class)
        self.payload_members = [
            "  %s" % p.get_c_def()
            for p in self.fields
            if p.type != self.header
        ]

    def has_payload(self):
        return len(self.payload_members) > 0

    def get_msg_id_name(self):
        return "vapi_msg_id_%s" % self.name

    def get_c_name(self):
        return "vapi_msg_%s" % self.name

    def get_payload_struct_name(self):
        return "vapi_payload_%s" % self.name

    def get_alloc_func_vla_field_length_name(self, field):
        return "%s_array_size" % field.name

    def get_alloc_func_name(self):
        return "vapi_alloc_%s" % self.name

    def get_alloc_vla_param_names(self):
        return [self.get_alloc_func_vla_field_length_name(f)
                for f in self.fields
                if f.nelem_field is not None]

    def get_alloc_func_decl(self):
        return "%s* %s(struct vapi_ctx_s *ctx%s)" % (
            self.get_c_name(),
            self.get_alloc_func_name(),
            "".join([", size_t %s" % n for n in
                     self.get_alloc_vla_param_names()]))

    def get_alloc_func_def(self):
        extra = []
        if self.header.has_field('client_index'):
            extra.append(
                "  msg->header.client_index = vapi_get_client_index(ctx);")
        if self.header.has_field('context'):
            extra.append("  msg->header.context = 0;")
        return "\n".join([
            "%s" % self.get_alloc_func_decl(),
            "{",
            "  %s *msg = NULL;" % self.get_c_name(),
            "  const size_t size = sizeof(%s)%s;" % (
                self.get_c_name(),
                "".join([
                    " + sizeof(msg->payload.%s[0]) * %s" % (
                        f.name,
                        self.get_alloc_func_vla_field_length_name(f))
                    for f in self.fields
                    if f.nelem_field is not None
                ])),
            "  /* cast here required to play nicely with C++ world ... */",
            "  msg = (%s*)vapi_msg_alloc(ctx, size);" % self.get_c_name(),
            "  if (!msg) {",
            "    return NULL;",
            "  }",
        ] + extra + [
            "  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, %s);" %
            self.get_msg_id_name(),
            "\n".join(["  msg->payload.%s = %s;" % (
                f.nelem_field.name,
                self.get_alloc_func_vla_field_length_name(f))
                for f in self.fields
                if f.nelem_field is not None]),
            "  return msg;",
            "}"])

    def get_calc_msg_size_func_name(self):
        return "vapi_calc_%s_msg_size" % self.name

    def get_calc_msg_size_func_decl(self):
        return "uword %s(%s *msg)" % (
            self.get_calc_msg_size_func_name(),
            self.get_c_name())

    def get_calc_msg_size_func_def(self):
        return "\n".join([
            "%s" % self.get_calc_msg_size_func_decl(),
            "{",
            "  return sizeof(*msg)%s;" %
            "".join(["+ msg->payload.%s * sizeof(msg->payload.%s[0])" % (
                    f.nelem_field.name,
                    f.name)
                for f in self.fields
                if f.nelem_field is not None
            ]),
            "}",
        ])

    def get_c_def(self):
        if self.has_payload():
            return "\n".join([
                "typedef struct __attribute__ ((__packed__)) {",
                "%s; " %
                ";\n".join(self.payload_members),
                "} %s;" % self.get_payload_struct_name(),
                "",
                "typedef struct __attribute__ ((__packed__)) {",
                ("  %s %s;" % (self.header.get_c_name(),
                               self.fields[0].name)
                    if self.header is not None else ""),
                "  %s payload;" % self.get_payload_struct_name(),
                "} %s;" % self.get_c_name(), ])
        else:
            return "\n".join([
                "typedef struct __attribute__ ((__packed__)) {",
                ("  %s %s;" % (self.header.get_c_name(),
                               self.fields[0].name)
                    if self.header is not None else ""),
                "} %s;" % self.get_c_name(), ])

    def get_swap_payload_to_host_func_name(self):
        return "%s_payload_ntoh" % self.get_c_name()

    def get_swap_payload_to_be_func_name(self):
        return "%s_payload_hton" % self.get_c_name()

    def get_swap_payload_to_host_func_decl(self):
        return "void %s(%s *payload)" % (
            self.get_swap_payload_to_host_func_name(),
            self.get_payload_struct_name())

    def get_swap_payload_to_be_func_decl(self):
        return "void %s(%s *payload)" % (
            self.get_swap_payload_to_be_func_name(),
            self.get_payload_struct_name())

    def get_swap_payload_to_be_func_def(self):
        return "%s\n{\n%s\n}" % (
            self.get_swap_payload_to_be_func_decl(),
            "\n".join([
                "  %s" % p.get_swap_to_be_code("payload->", "%s" % p.name)
                for p in self.fields
                if p.needs_byte_swap() and p.type != self.header]),
        )

    def get_swap_payload_to_host_func_def(self):
        return "%s\n{\n%s\n}" % (
            self.get_swap_payload_to_host_func_decl(),
            "\n".join([
                "  %s" % p.get_swap_to_host_code("payload->", "%s" % p.name)
                for p in self.fields
                if p.needs_byte_swap() and p.type != self.header]),
        )

    def get_swap_to_host_func_name(self):
        return "%s_ntoh" % self.get_c_name()

    def get_swap_to_be_func_name(self):
        return "%s_hton" % self.get_c_name()

    def get_swap_to_host_func_decl(self):
        return "void %s(%s *msg)" % (
            self.get_swap_to_host_func_name(), self.get_c_name())

    def get_swap_to_be_func_decl(self):
        return "void %s(%s *msg)" % (
            self.get_swap_to_be_func_name(), self.get_c_name())

    def get_swap_to_be_func_def(self):
        return "\n".join([
            "%s" % self.get_swap_to_be_func_decl(),
            "{",
            ("  VAPI_DBG(\"Swapping `%s'@%%p to big endian\", msg);" %
                self.get_c_name()),
            "  %s(&msg->header);" % self.header.get_swap_to_be_func_name()
            if self.header is not None else "",
            "  %s(&msg->payload);" % self.get_swap_payload_to_be_func_name()
            if self.has_payload() else "",
            "}",
        ])

    def get_swap_to_host_func_def(self):
        return "\n".join([
            "%s" % self.get_swap_to_host_func_decl(),
            "{",
            ("  VAPI_DBG(\"Swapping `%s'@%%p to host byte order\", msg);" %
                self.get_c_name()),
            "  %s(&msg->header);" % self.header.get_swap_to_host_func_name()
            if self.header is not None else "",
            "  %s(&msg->payload);" % self.get_swap_payload_to_host_func_name()
            if self.has_payload() else "",
            "}",
        ])

    def get_op_func_name(self):
        return "vapi_%s" % self.name

    def get_op_func_decl(self):
        if self.reply.has_payload():
            return "vapi_error_e %s(%s)" % (
                self.get_op_func_name(),
                ",\n  ".join([
                    'struct vapi_ctx_s *ctx',
                    '%s *msg' % self.get_c_name(),
                    'vapi_error_e (*callback)(struct vapi_ctx_s *ctx',
                    '                         void *callback_ctx',
                    '                         vapi_error_e rv',
                    '                         bool is_last',
                    '                         %s *reply)' %
                    self.reply.get_payload_struct_name(),
                    'void *callback_ctx',
                ])
            )
        else:
            return "vapi_error_e %s(%s)" % (
                self.get_op_func_name(),
                ",\n  ".join([
                    'struct vapi_ctx_s *ctx',
                    '%s *msg' % self.get_c_name(),
                    'vapi_error_e (*callback)(struct vapi_ctx_s *ctx',
                    '                         void *callback_ctx',
                    '                         vapi_error_e rv',
                    '                         bool is_last)',
                    'void *callback_ctx',
                ])
            )

    def get_op_func_def(self):
        return "\n".join([
            "%s" % self.get_op_func_decl(),
            "{",
            "  if (!msg || !callback) {",
            "    return VAPI_EINVAL;",
            "  }",
            "  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {",
            "    return VAPI_EAGAIN;",
            "  }",
            "  vapi_error_e rv;",
            "  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {",
            "    return rv;",
            "  }",
            "  u32 req_context = vapi_gen_req_context(ctx);",
            "  msg->header.context = req_context;",
            "  %s(msg);" % self.get_swap_to_be_func_name(),
            ("  if (VAPI_OK == (rv = vapi_send_with_control_ping "
                "(ctx, msg, req_context))) {"
                if self.is_dump() else
                "  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {"
             ),
            ("    vapi_store_request(ctx, req_context, %s, "
             "(vapi_cb_t)callback, callback_ctx);" %
             ("true" if self.is_dump() else "false")),
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
        ])

    def get_event_cb_func_decl(self):
        if not self.is_reply():
            raise Exception(
                "Cannot register event callback for non-reply message")
        if self.has_payload():
            return "\n".join([
                "void vapi_set_%s_event_cb (" %
                self.get_c_name(),
                "  struct vapi_ctx_s *ctx, ",
                ("  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, "
                 "void *callback_ctx, %s *payload)," %
                 self.get_payload_struct_name()),
                "  void *callback_ctx)",
            ])
        else:
            return "\n".join([
                "void vapi_set_%s_event_cb (" %
                self.get_c_name(),
                "  struct vapi_ctx_s *ctx, ",
                "  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, "
                "void *callback_ctx),",
                "  void *callback_ctx)",
            ])

    def get_event_cb_func_def(self):
        if not self.is_reply():
            raise Exception(
                "Cannot register event callback for non-reply function")
        return "\n".join([
            "%s" % self.get_event_cb_func_decl(),
            "{",
            ("  vapi_set_event_cb(ctx, %s, (vapi_event_cb)callback, "
             "callback_ctx);" %
             self.get_msg_id_name()),
            "}"])

    def get_c_metadata_struct_name(self):
        return "__vapi_metadata_%s" % self.name

    def get_c_constructor(self):
        has_context = False
        if self.header is not None:
            has_context = self.header.has_field('context')
        return '\n'.join([
            'static void __attribute__((constructor)) __vapi_constructor_%s()'
            % self.name,
            '{',
            '  static const char name[] = "%s";' % self.name,
            '  static const char name_with_crc[] = "%s_%s";'
            % (self.name, self.crc[2:]),
            '  static vapi_message_desc_t %s = {' %
            self.get_c_metadata_struct_name(),
            '    name,',
            '    sizeof(name) - 1,',
            '    name_with_crc,',
            '    sizeof(name_with_crc) - 1,',
            '    true,' if has_context else '    false,',
            '    offsetof(%s, context),' % self.header.get_c_name()
            if has_context else '    0,',
            ('    offsetof(%s, payload),' % self.get_c_name())
            if self.has_payload() else '    ~0,',
            '    sizeof(%s),' % self.get_c_name(),
            '    (generic_swap_fn_t)%s,' % self.get_swap_to_be_func_name(),
            '    (generic_swap_fn_t)%s,' % self.get_swap_to_host_func_name(),
            '    ~0,',
            '  };',
            '',
            '  %s = vapi_register_msg(&%s);' %
            (self.get_msg_id_name(), self.get_c_metadata_struct_name()),
            '  VAPI_DBG("Assigned msg id %%d to %s", %s);' %
            (self.name, self.get_msg_id_name()),
            '}',
        ])


vapi_send_with_control_ping = """
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


def gen_json_unified_header(parser, logger, j, io, name):
    logger.info("Generating header `%s'" % name)
    orig_stdout = sys.stdout
    sys.stdout = io
    include_guard = "__included_%s" % (
        j.replace(".", "_").replace("/", "_").replace("-", "_"))
    print("#ifndef %s" % include_guard)
    print("#define %s" % include_guard)
    print("")
    print("#include <stdlib.h>")
    print("#include <stddef.h>")
    print("#include <arpa/inet.h>")
    print("#include <vapi/vapi_internal.h>")
    print("#include <vapi/vapi.h>")
    print("#include <vapi/vapi_dbg.h>")
    print("")
    print("#ifdef __cplusplus")
    print("extern \"C\" {")
    print("#endif")
    if name == "vpe.api.vapi.h":
        print("")
        print("static inline vapi_error_e vapi_send_with_control_ping "
              "(vapi_ctx_t ctx, void * msg, u32 context);")
    else:
        print("#include <vapi/vpe.api.vapi.h>")
    print("")
    for m in parser.messages_by_json[j].values():
        print("extern vapi_msg_id_t %s;" % m.get_msg_id_name())
    print("")
    print("#define DEFINE_VAPI_MSG_IDS_%s\\" %
          j.replace(".", "_").replace("/", "_").replace("-", "_").upper())
    print("\\\n".join([
        "  vapi_msg_id_t %s;" % m.get_msg_id_name()
        for m in parser.messages_by_json[j].values()
    ]))
    print("")
    print("")
    for t in parser.types_by_json[j].values():
        try:
            print("%s" % t.get_c_def())
            print("")
        except:
            pass
    for m in parser.messages_by_json[j].values():
        print("%s" % m.get_c_def())
        print("")

    print("")
    function_attrs = "static inline "
    for t in parser.types_by_json[j].values():
        print("%s%s" % (function_attrs, t.get_swap_to_be_func_def()))
        print("")
        print("%s%s" % (function_attrs, t.get_swap_to_host_func_def()))
        print("")
    for m in parser.messages_by_json[j].values():
        if m.has_payload():
            print("%s%s" % (function_attrs,
                            m.get_swap_payload_to_be_func_def()))
            print("")
            print("%s%s" % (function_attrs,
                            m.get_swap_payload_to_host_func_def()))
            print("")
        print("%s%s" % (function_attrs, m.get_calc_msg_size_func_def()))
        print("")
        print("%s%s" % (function_attrs, m.get_swap_to_be_func_def()))
        print("")
        print("%s%s" % (function_attrs, m.get_swap_to_host_func_def()))
        print("")
    for m in parser.messages_by_json[j].values():
        if m.is_reply():
            continue
        print("%s%s" % (function_attrs, m.get_alloc_func_def()))
        print("")
        print("%s%s" % (function_attrs, m.get_op_func_def()))
        print("")
    print("")
    for m in parser.messages_by_json[j].values():
        print("%s" % m.get_c_constructor())
        print("")
    print("")
    for m in parser.messages_by_json[j].values():
        if not m.is_reply():
            continue
        print("%s%s;" % (function_attrs, m.get_event_cb_func_def()))
        print("")
    print("")

    if name == "vpe.api.vapi.h":
        print("%s" % vapi_send_with_control_ping)
        print("")

    print("#ifdef __cplusplus")
    print("}")
    print("#endif")
    print("")
    print("#endif")
    sys.stdout = orig_stdout


def json_to_c_header_name(json_name):
    if json_name.endswith(".json"):
        return "%s.vapi.h" % os.path.splitext(json_name)[0]
    raise Exception("Unexpected json name `%s'!" % json_name)


def gen_c_unified_headers(parser, logger, prefix):
    if prefix == "" or prefix is None:
        prefix = ""
    else:
        prefix = "%s/" % prefix
    for j in parser.json_files:
        with open('%s%s' % (prefix, json_to_c_header_name(j)), "w") as io:
            gen_json_unified_header(
                parser, logger, j, io, json_to_c_header_name(j))


if __name__ == '__main__':
    try:
        verbose = int(os.getenv("V", 0))
    except:
        verbose = 0

    if verbose >= 2:
        log_level = 10
    elif verbose == 1:
        log_level = 20
    else:
        log_level = 40

    logging.basicConfig(stream=sys.stdout, level=log_level)
    logger = logging.getLogger("VAPI C GEN")
    logger.setLevel(log_level)

    argparser = argparse.ArgumentParser(description="VPP C API generator")
    argparser.add_argument('files', metavar='api-file', action='append',
                           type=str, help='json api file'
                           '(may be specified multiple times)')
    argparser.add_argument('--prefix', action='store', default=None,
                           help='path prefix')
    args = argparser.parse_args()

    jsonparser = JsonParser(logger, args.files,
                            simple_type_class=CSimpleType,
                            struct_type_class=CStructType,
                            field_class=CField,
                            message_class=CMessage)

    # not using the model of having separate generated header and code files
    # with generated symbols present in shared library (per discussion with
    # Damjan), to avoid symbol version issues in .so
    # gen_c_headers_and_code(jsonparser, logger, args.prefix)

    gen_c_unified_headers(jsonparser, logger, args.prefix)

    for e in jsonparser.exceptions:
        logger.error(e)
