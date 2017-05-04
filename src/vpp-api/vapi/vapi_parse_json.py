#!/usr/bin/env python3

import json
import argparse
import os
import sys
import logging
from abc import abstractmethod, ABCMeta

msg_header1_fields = [('u16', '_vl_msg_id'), ('u32', 'context')]

msg_header1_field_names = [n for t, n in msg_header1_fields]

msg_header2_fields = [
    ('u16', '_vl_msg_id'),
    ('u32', 'client_index'),
    ('u32', 'context')
]

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
    return name.endswith('_reply') or name.endswith('_details') \
        or name.endswith('_event') or name.endswith('_counters')


class ParseError (Exception):
    pass


magic_prefix = "vl_api_"
magic_suffix = "_t"


def apply_magic(what):
    return "%s%s%s" % (magic_prefix, what, magic_suffix)


def remove_magic(what):
    if what.startswith(magic_prefix) and what.endswith(magic_suffix):
        return what[len(magic_prefix): - len(magic_suffix)]
    return what


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

    def __init__(
            self,
            param_name,
            param_type,
            array_len=None,
            nelem_param=None):
        self.name = param_name
        self.type = param_type
        self.len = array_len
        self.nelem_param = nelem_param

    def get_c_def(self):
        if self.len is not None:
            return "%s %s[%s]" % (self.type.get_c_name(), self.name, self.len)
        else:
            return "%s %s" % (self.type.get_c_name(), self.name)


class Struct:

    def __init__(self, name, parameters):
        self.name = name
        self.parameters = parameters

    def get_c_def(self):
        return "\n".join([
            "typedef struct __attribute__((__packed__)) {",
            "%s;" % ";\n".join(["  %s" % x.get_c_def()
                                for x in self.parameters]),
            "} %s;" % self.get_c_name()])


class Message (Struct):

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
            else:
                param_type = field[0]
                if param_type in typedict:
                    param_type = typedict[param_type]
                else:
                    param_type = typedict[remove_magic(param_type)]
                if len(field) == 2:
                    p = Parameter(param_name=field[1],
                                  param_type=param_type)
                elif len(field) == 3:
                    if field[2] == 0:
                        raise ParseError(
                            "while parsing message `%s': variable length "
                            "array `%s' doesn't have reference to member "
                            "containing the actual length" % (
                                name, field[1]))
                    p = Parameter(
                        param_name=field[1],
                        param_type=param_type,
                        array_len=field[2])
                elif len(field) == 4:
                    p = Parameter(
                        param_name=field[1],
                        param_type=param_type,
                        array_len=field[2],
                        nelem_param=field[3])
                else:
                    raise Exception("Don't know how to parse message "
                                    "definition for message `%s': `%s'" %
                                    (m, m[1:]))
                parameters.append(p)
        super().__init__(name, parameters)

    def is_dump(self):
        return self.name.endswith('_dump')

    def is_reply_only(self):
        return msg_is_reply_only(self.name)

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
                if p.name not in self.header['field_names']]))

    def get_c_def(self):
        return "\n".join([
            "typedef struct __attribute__ ((__packed__)) {",
            "%s; " %
            ";\n".join([
                "  %s" % p.get_c_def()
                for p in self.parameters
                if self.header is None or
                p.name not in self.header['field_names']]),
            "} %s;" % self.get_payload_struct_name(),
            "",
            "typedef struct {",
            ("  %s header;" % self.header['name']
                if self.header is not None else ""),
            "  %s payload;" % self.get_payload_struct_name(),
            "} %s;" % self.get_c_name(), ])

    def get_init_func_def(self):
        if 'client_index' in self.header['field_names']:
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
                    p.name not in self.header['field_names']) and
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
                    p.name not in self.header['field_names']) and
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
            if p.name not in self.header['field_names']])
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
            has_context = 'context' in self.header['field_names']
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
            '    offsetof(%s, context),' % self.header['name'] if has_context
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


class Type:
    __metaclass__ = ABCMeta

    def __init__(self, name):
        self.name = name

    @abstractmethod
    def get_c_name(self):
        raise Exception("DOH!")


class SimpleType (Type):

    def __init__(self, name):
        super().__init__(name)

    def get_c_name(self):
        return self.name


class StructType (Type, Struct):

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
                raise ParseError(
                    "Don't know how to parse type definition for "
                    "type `%s': `%s'" % (t, t[1:]))
            parameters.append(p)
        Type.__init__(self, name)
        Struct.__init__(self, name, parameters)

    def get_msg_id_name(self):
        return "__vapi_type_%s" % self.name

    def get_c_name(self):
        return "vapi_type_%s" % self.name


class JsonParser:
    swap_to_be_dict = {
        'u16': 'htobe16', 'u32': 'htobe32', 'i32': 'htobe32', 'u64': 'htobe64',
    }

    swap_to_host_dict = {
        'u16': 'be16toh',
        'u32': 'be32toh',
        'i32': 'be32toh',
        'u64': 'be64toh',
    }

    def __init__(self, vapi_header, logger, prefix):
        self.messages = {}
        self.types = {
            x: SimpleType(x) for x in ['u8', 'u16', 'u32', 'u64', 'f64', 'i32']
        }

        self.exceptions = []
        self.msg_count = 0
        self.vapi_header = vapi_header
        self.json_files = []
        self.types_by_json = {}
        self.messages_by_json = {}
        self.logger = logger
        if prefix == "" or prefix is None:
            self.prefix = ""
        else:
            self.prefix = "%s/" % prefix

    def parse_json_file(self, path):
        self.logger.info("Parsing json api file: `%s'" % path)
        self.json_files.append(path)
        self.types_by_json[path] = {}
        self.messages_by_json[path] = {}
        with open(path) as f:
            j = json.load(f)
            for t in j['types']:
                try:
                    type_ = StructType(t, self.types)
                    if type_.name in self.types:
                        raise ParseError("Duplicate type `%s'" % type_.name)
                except ParseError as e:
                    self.exceptions.append(e)
                    continue
                self.types[type_.name] = type_
                self.types_by_json[path][type_.name] = type_
            for m in j['messages']:
                try:
                    msg = Message(m, self.types, self.swap_to_be_dict,
                                  self.swap_to_host_dict)
                    if msg.name in self.messages:
                        raise ParseError("Duplicate message `%s'" % msg.name)
                except ParseError as e:
                    self.exceptions.append(e)
                    continue
                self.messages[msg.name] = msg
                self.messages_by_json[path][msg.name] = msg
            self.msg_count += len(j['messages'])

    def get_reply(self, message):
        if self.messages[message].is_dump():
            return self.messages["%s_details" % message[:-len("_dump")]]
        return self.messages["%s_reply" % message]

    def validate_json_data(self):
        if len(self.messages) == 0:
            raise Exception("No messages parsed.")
        for jn, j in self.messages_by_json.items():
            remove = []
            for n, m in j.items():
                try:
                    if not m.is_reply_only():
                        try:
                            m.reply = self.get_reply(n)
                        except:
                            raise ParseError(
                                "cannot find reply to message `%s'" % n)
                except ParseError as e:
                    self.exceptions.append(e)
                    remove.append(n)

            self.messages_by_json[jn] = {
                k: v for k, v in j.items() if k not in remove}

    def json_to_header_name(self, json_name):
        if json_name.endswith(".json"):
            return "%s.vapi.h" % os.path.splitext(json_name)[0]
        raise Exception("Unexpected json name `%s'!" % json_name)

    def json_to_code_name(self, json_name):
        if json_name.endswith(".json"):
            return "%s.vapi.c" % os.path.splitext(json_name)[0]
        raise Exception("Unexpected json name `%s'!" % json_name)

    def gen_c_headers_and_code(self):
        for j in self.json_files:
            with open('%s%s' % (self.prefix, self.json_to_header_name(j)),
                      "w") as io:
                self.gen_json_header(j, io)
            with open('%s%s' % (self.prefix, self.json_to_code_name(j)),
                      "w") as io:
                self.gen_json_code(j, io)

    def gen_json_header(self, j, io):
        logger.error("Generating %s" % io.name)
        orig_stdout = sys.stdout
        sys.stdout = io
        include_guard = "included_%s" % (
            j.replace(".", "_").replace("/", "_").replace("-", "_"))
        print("#ifndef %s" % include_guard)
        print("#define %s" % include_guard)
        print("")
        print("#include <vapi_internal.h>")
        print("")
        for m in self.messages_by_json[j].values():
            print("extern vapi_msg_id_t %s;" % m.get_msg_id_name())
        print("")
        for t in self.types_by_json[j].values():
            try:
                print("%s" % t.get_c_def())
                print("")
            except:
                pass
        for m in self.messages_by_json[j].values():
            print("%s" % m.get_c_def())
            print("")
        for m in self.messages_by_json[j].values():
            if not m.is_reply_only():
                print("%s;" % m.get_init_func_decl())
                print("%s;" % m.get_op_func_decl())
            print("%s;" % m.get_swap_to_host_func_decl())
            print("%s;" % m.get_swap_to_be_func_decl())
            print("")
        for m in self.messages_by_json[j].values():
            if not m.is_reply_only():
                continue
            print("%s;" % m.get_event_cb_func_decl())

        print("#endif")
        sys.stdout = orig_stdout

    def gen_json_code(self, j, io):
        logger.error("Generating %s" % io.name)
        orig_stdout = sys.stdout
        sys.stdout = io
        print("#include <%s>" % self.json_to_header_name(j))
        print("#include <stdlib.h>")
        print("#include <stddef.h>")
        print("#include <arpa/inet.h>")
        print("#include <vapi_internal.h>")
        print("#include <vapi_dbg.h>")
        print("")
        for n, m in self.messages_by_json[j].items():
            print("%s" % m.get_swap_to_be_func_def())
            print("")
            print("%s" % m.get_swap_to_host_func_def())
            print("")
        for n, m in self.messages_by_json[j].items():
            if m.is_reply_only():
                continue
            print("%s" % m.get_init_func_def())
            print("")
            print("%s" % m.get_op_func_def())
        print("")
        for m in self.messages_by_json[j].values():
            print("%s" % m.get_c_constructor())
            print("")
        print("")
        for m in self.messages_by_json[j].values():
            if not m.is_reply_only():
                continue
            print("%s;" % m.get_event_cb_func_def())
        print("")
        for m in self.messages_by_json[j].values():
            print("vapi_msg_id_t %s;" % m.get_msg_id_name())
        sys.stdout = orig_stdout


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

    parser = argparse.ArgumentParser(description="VPP JSON API parser")
    parser.add_argument('files', metavar='N', action='append', type=str,
                        help='json api file'
                             '(may be specified multiple times)')
    parser.add_argument('--prefix', action='store', default=None,
                        help='path prefix')
    args = parser.parse_args()
    ctx = JsonParser(vapi_header="vapi_gen.h",
                     logger=logger, prefix=args.prefix)

    for f in args.files:
        ctx.parse_json_file(f)

    ctx.validate_json_data()
    ctx.gen_c_headers_and_code()

    for e in ctx.exceptions:
        logger.error(e)
