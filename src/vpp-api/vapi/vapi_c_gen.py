#!/usr/bin/env python3

import argparse
import os
import sys
import logging
from vapi_json_parser import Parameter, Struct, Message, JsonParser,\
    SimpleType, StructType


class CParameter(Parameter):
    def __init__(
            self,
            param_name,
            param_type,
            array_len=None,
            nelem_param=None):
        super().__init__(param_name, param_type, array_len, nelem_param)

    def get_c_def(self):
        if self.len is not None:
            return "%s %s[%s]" % (self.type.get_c_name(), self.name, self.len)
        else:
            return "%s %s" % (self.type.get_c_name(), self.name)


class CStruct(Struct):
    def __init__(self, name, parameters):
        super().__init__(name, parameters)

    def get_c_def(self):
        return "\n".join([
            "typedef struct __attribute__((__packed__)) {",
            "%s;" % ";\n".join(["  %s" % x.get_c_def()
                                for x in self.parameters]),
            "} %s;" % self.get_c_name()])


class CMessage (Message):
    def __init__(self, definition, typedict, swap_to_be_dict,
                 swap_to_host_dict, param_class=CParameter):
        super().__init__(definition, typedict,
                         swap_to_be_dict, swap_to_host_dict, param_class)

    def get_msg_id_name(self):
        return "vapi_msg_id_%s" % self.name

    def get_c_name(self):
        return "vapi_msg_%s" % self.name

    def get_payload_struct_name(self):
        return "vapi_payload_%s" % self.name

    def get_init_func_name(self):
        return "vapi_msg_init_%s" % self.name

    def get_init_func_decl(self):
        return "void %s(struct vapi_ctx_s *ctx, %s *msg)" % (
            self.get_init_func_name(), self.get_c_name())

    def get_op_func_name(self):
        return "vapi_%s" % self.name

    def get_op_func_decl(self):
        return "vapi_error_e %s(%s)" % (
            self.get_op_func_name(),
            ",\n  ".join([
                'struct vapi_ctx_s *ctx',
                'vapi_error_e (*callback)(struct vapi_ctx_s *ctx',
                '                         void *callback_ctx',
                '                         vapi_error_e rv',
                '                         bool is_last',
                '                         %s *reply)' %
                self.reply.get_payload_struct_name(),
                'void *callback_ctx'] + [
                p.get_c_def()
                for p in self.parameters
                if not self.header.has_field(p.name)]))

    def get_c_def(self):
        return "\n".join([
            "typedef struct __attribute__ ((__packed__)) {",
            "%s; " %
            ";\n".join([
                "  %s" % p.get_c_def()
                for p in self.parameters
                if self.header is None or
                not self.header.has_field(p.name)]),
            "} %s;" % self.get_payload_struct_name(),
            "",
            "typedef struct {",
            ("  %s header;" % self.header.name
                if self.header is not None else ""),
            "  %s payload;" % self.get_payload_struct_name(),
            "} %s;" % self.get_c_name(), ])

    def get_init_func_def(self):
        if self.header.has_field('client_index'):
            extra = "  msg->header.client_index = vapi_get_client_index(ctx);"
        return "\n".join([
            "%s" % self.get_init_func_decl(),
            "{",
            "  if (!msg) {",
            "    return;",
            "  }",
            "  msg->header._vl_msg_id = "
            "htobe16(vapi_lookup_vl_msg_id(ctx, %s));" %
            self.get_msg_id_name(),
            "",
            "%s" % extra,
            "}"])

    def get_swap_to_host_func_name(self):
        return "vapi_%s_swap_to_host" % self.get_payload_struct_name()

    def get_swap_to_be_func_name(self):
        return "vapi_%s_swap_to_be" % self.get_payload_struct_name()

    def get_swap_to_host_func_decl(self):
        return "void %s(%s *payload)" % (
            self.get_swap_to_host_func_name(), self.get_payload_struct_name())

    def get_swap_to_be_func_decl(self):
        return "void %s(%s *payload)" % (
            self.get_swap_to_be_func_name(), self.get_payload_struct_name())

    def get_swap_to_be_func_def(self):
        return "%s\n{\n%s\n}" % (
            self.get_swap_to_be_func_decl(),
            "\n".join([
                "  payload->%s = %s(payload->%s);" %
                (p.name, self.swap_to_be_dict[p.type], p.name)
                for p in self.parameters
                if (self.header is None or
                    not self.header.has_field(p.name)) and
                p.type in self.swap_to_be_dict and p.len is None
            ]
            ),
        )

    def get_swap_to_host_func_def(self):
        return "%s\n{\n%s\n}" % (
            self.get_swap_to_host_func_decl(),
            "\n".join([
                "  payload->%s = %s(payload->%s);" % (
                    p.name, self.swap_to_be_dict[p.type], p.name)
                for p in self.parameters
                if (self.header is None or
                    not self.header.has_field(p.name)) and
                p.type in self.swap_to_be_dict and p.len is None
            ]
            ),
        )

    def get_op_func_def(self):
        param_string = "\n  ".join([
            "msg->payload.%s = %s;" % (p.name, p.name)
            if p.len is None else
            "memcpy(&msg->payload.%s, %s, sizeof(*%s) * %s);" %
            (p.name, p.name, p.name, p.len)
            if p.len > 0 else
            "memcpy(&msg->payload.%s, %s, sizeof(*%s) * %s);" %
            (p.name, p.name, p.name, p.nelem_param)
            for p in self.parameters
            if not self.header.has_field(p.name)])
        return "\n".join([
            "%s" % self.get_op_func_decl(),
            "{",
            "  if (!callback) {",
            "    return VAPI_EINVAL;",
            "  }",
            "  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {",
            "    return VAPI_EAGAIN;",
            "  }",
            "  const bool is_dump = %s;" %
            ("true" if self.is_dump() else "false"),
            ("  if (is_dump && vapi_get_request_count(ctx) + 1 >= "
                "vapi_get_max_request_count(ctx)) {"),
            "    return VAPI_EAGAIN;",
            "  }",
            "  %s *msg;" % self.get_c_name(),
            "  msg = vapi_msg_alloc (ctx, sizeof(*msg));",
            "  if (!msg) {",
            "    return VAPI_ENOMEM;",
            "  }",
            "  vapi_msg_control_ping *ping = NULL;",
            ("  if (is_dump && "
             "!(ping = vapi_msg_alloc (ctx, sizeof(*ping)))) {"),
            "    vapi_msg_free(ctx, msg);",
            "    return VAPI_ENOMEM;",
            "  }",
            "  %s (ctx, msg);" % self.get_init_func_name(),
            "  %s" % param_string,
            "  u32 req_context = vapi_gen_req_context(ctx);",
            "  msg->header.context = req_context;",
            "  %s(&msg->payload);" % self.get_swap_to_be_func_name(),
            "  vapi_error_e rv = vapi_send(ctx, msg);",
            "  if (VAPI_OK == rv) {",
            ("    vapi_send_control_ping(ctx, ping, req_context);"
                if self.is_dump() else ""),
            ("    vapi_store_request(ctx, req_context, is_dump, "
             "(vapi_cb_t)callback, callback_ctx);"),
            "    if (vapi_is_nonblocking(ctx)) {",
            "      return VAPI_OK;",
            "    }",
            "    rv = vapi_dispatch(ctx);",
            "  }",
            "  return rv;",
            "}",
            "",
        ])

    def get_event_cb_func_decl(self):
        if not self.is_reply_only():
            raise Exception(
                "Cannot register event callback for non-reply function")
        return "\n".join(
            [
                "void vapi_set_%s_event_cb (" %
                self.get_c_name(),
                "  struct vapi_ctx_s *ctx, ",
                ("  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, "
                 "void *callback_ctx, %s *payload)," %
                 self.get_payload_struct_name()),
                "  void *callback_ctx)",
            ])

    def get_event_cb_func_def(self):
        if not self.is_reply_only():
            raise Exception(
                "Cannot register event callback for non-reply function")
        return "\n".join([
            "%s" % self.get_event_cb_func_decl(),
            "{",
            ("  vapi_set_event_cb(ctx, %s, (vapi_generic_event_cb)callback, "
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
            '    offsetof(%s, context),' % self.header.name if has_context
            else '    0,',
            '    offsetof(%s, payload),' % self.get_c_name(),
            '    sizeof(%s),' % self.get_c_name(),
            '    (generic_swap_fn_t)%s,' % self.get_swap_to_be_func_name(),
            '    (generic_swap_fn_t)%s,' % self.get_swap_to_host_func_name(),
            '  };',
            '',
            '  %s = vapi_register_msg(&%s);' %
            (self.get_msg_id_name(), self.get_c_metadata_struct_name()),
            '  VAPI_DBG("Assigned msg id %%d to %s", %s);' %
            (self.name, self.get_msg_id_name()),
            '}',
        ])


class CSimpleType (SimpleType):

    def __init__(self, name):
        super().__init__(name)

    def get_c_name(self):
        return self.name


class CStructType (StructType, CStruct):
    def __init__(self, definition, typedict, param_class=CParameter):
        super().__init__(definition, typedict, param_class)

    def get_c_name(self):
        return "vapi_type_%s" % self.name


def gen_json_header(parser, logger, j, io):
    logger.info("Generating %s" % io.name)
    orig_stdout = sys.stdout
    sys.stdout = io
    include_guard = "included_%s" % (
        j.replace(".", "_").replace("/", "_").replace("-", "_"))
    print("#ifndef %s" % include_guard)
    print("#define %s" % include_guard)
    print("")
    print("#include <vapi_internal.h>")
    print("")
    for m in parser.messages_by_json[j].values():
        print("extern vapi_msg_id_t %s;" % m.get_msg_id_name())
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
    for m in parser.messages_by_json[j].values():
        if not m.is_reply_only():
            print("%s;" % m.get_init_func_decl())
            print("%s;" % m.get_op_func_decl())
        print("%s;" % m.get_swap_to_host_func_decl())
        print("%s;" % m.get_swap_to_be_func_decl())
        print("")
    for m in parser.messages_by_json[j].values():
        if not m.is_reply_only():
            continue
        print("%s;" % m.get_event_cb_func_decl())
        print("")

    print("#endif")
    sys.stdout = orig_stdout


def gen_json_code(parser, logger, j, io):
    logger.error("Generating %s" % io.name)
    orig_stdout = sys.stdout
    sys.stdout = io
    print("#include <%s>" % json_to_header_name(j))
    print("#include <stdlib.h>")
    print("#include <stddef.h>")
    print("#include <arpa/inet.h>")
    print("#include <vapi_internal.h>")
    print("#include <vapi_dbg.h>")
    print("")
    for n, m in parser.messages_by_json[j].items():
        print("%s" % m.get_swap_to_be_func_def())
        print("")
        print("%s" % m.get_swap_to_host_func_def())
        print("")
    for n, m in parser.messages_by_json[j].items():
        if m.is_reply_only():
            continue
        print("%s" % m.get_init_func_def())
        print("")
        print("%s" % m.get_op_func_def())
        print("")
    print("")
    for m in parser.messages_by_json[j].values():
        print("%s" % m.get_c_constructor())
        print("")
    print("")
    for m in parser.messages_by_json[j].values():
        if not m.is_reply_only():
            continue
        print("%s;" % m.get_event_cb_func_def())
        print("")
    print("")
    for m in parser.messages_by_json[j].values():
        print("vapi_msg_id_t %s;" % m.get_msg_id_name())
    sys.stdout = orig_stdout


def json_to_header_name(json_name):
    if json_name.endswith(".json"):
        return "%s.vapi.h" % os.path.splitext(json_name)[0]
    raise Exception("Unexpected json name `%s'!" % json_name)


def json_to_code_name(json_name):
    if json_name.endswith(".json"):
        return "%s.vapi.c" % os.path.splitext(json_name)[0]
    raise Exception("Unexpected json name `%s'!" % json_name)


def gen_c_headers_and_code(parser, logger, prefix):
    if prefix == "" or prefix is None:
        prefix = ""
    else:
        prefix = "%s/" % prefix
    for j in parser.json_files:
        with open('%s%s' % (prefix, json_to_header_name(j)), "w") as io:
            gen_json_header(parser, logger, j, io)
        with open('%s%s' % (prefix, json_to_code_name(j)), "w") as io:
            gen_json_code(parser, logger, j, io)


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

    logger = logging.getLogger("logger")
    logger.setLevel(log_level)

    argparser = argparse.ArgumentParser(description="VPP JSON API parser")
    argparser.add_argument('files', metavar='N', action='append', type=str,
                           help='json api file'
                           '(may be specified multiple times)')
    argparser.add_argument('--prefix', action='store', default=None,
                           help='path prefix')
    args = argparser.parse_args()

    jsonparser = JsonParser(logger, args.files,
                            simple_type_class=CSimpleType,
                            struct_type_class=CStructType,
                            message_class=CMessage)

    gen_c_headers_and_code(jsonparser, logger, args.prefix)

    for e in jsonparser.exceptions:
        logger.error(e)
