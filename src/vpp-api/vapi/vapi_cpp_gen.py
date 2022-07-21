#!/usr/bin/env python3

import argparse
import os
import sys
import logging
from vapi_c_gen import (
    CField,
    CEnum,
    CStruct,
    CSimpleType,
    CStructType,
    CMessage,
    json_to_c_header_name,
    CAlias,
)
from vapi_json_parser import JsonParser


class CppField(CField):
    pass


class CppStruct(CStruct):
    pass


class CppEnum(CEnum):
    pass


class CppAlias(CAlias):
    pass


class CppSimpleType(CSimpleType):
    pass


class CppStructType(CStructType, CppStruct):
    pass


class CppMessage(CMessage):
    def get_swap_to_be_template_instantiation(self):
        return "\n".join(
            [
                "template <> inline void vapi_swap_to_be<%s>(%s *msg)"
                % (self.get_c_name(), self.get_c_name()),
                "{",
                "  %s(msg);" % self.get_swap_to_be_func_name(),
                "}",
            ]
        )

    def get_swap_to_host_template_instantiation(self):
        return "\n".join(
            [
                "template <> inline void vapi_swap_to_host<%s>(%s *msg)"
                % (self.get_c_name(), self.get_c_name()),
                "{",
                "  %s(msg);" % self.get_swap_to_host_func_name(),
                "}",
            ]
        )

    def get_alloc_template_instantiation(self):
        return "\n".join(
            [
                "template <> inline %s* vapi_alloc<%s%s>"
                "(Connection &con%s)"
                % (
                    self.get_c_name(),
                    self.get_c_name(),
                    ", size_t" * len(self.get_alloc_vla_param_names()),
                    "".join(
                        [", size_t %s" % n for n in self.get_alloc_vla_param_names()]
                    ),
                ),
                "{",
                "  %s* result = %s(con.vapi_ctx%s);"
                % (
                    self.get_c_name(),
                    self.get_alloc_func_name(),
                    "".join([", %s" % n for n in self.get_alloc_vla_param_names()]),
                ),
                "#if VAPI_CPP_DEBUG_LEAKS",
                "  con.on_shm_data_alloc(result);",
                "#endif",
                "  return result;",
                "}",
            ]
        )

    def get_cpp_name(self):
        return "%s%s" % (self.name[0].upper(), self.name[1:])

    def get_req_template_name(self):
        if self.has_stream_msg:
            return "Stream<%s, %s, %s>" % (
                self.get_c_name(),
                self.reply.get_c_name(),
                self.stream_msg.get_c_name(),
            )

        if self.reply_is_stream:
            template = "Dump"
        else:
            template = "Request"

        return "%s<%s, %s%s>" % (
            template,
            self.get_c_name(),
            self.reply.get_c_name(),
            "".join([", size_t"] * len(self.get_alloc_vla_param_names())),
        )

    def get_req_template_instantiation(self):
        return "template class %s;" % self.get_req_template_name()

    def get_type_alias(self):
        return "using %s = %s;" % (self.get_cpp_name(), self.get_req_template_name())

    def get_reply_template_name(self):
        return "Msg<%s>" % (self.get_c_name())

    def get_reply_type_alias(self):
        return "using %s = %s;" % (self.get_cpp_name(), self.get_reply_template_name())

    def get_msg_class_instantiation(self):
        return "template class Msg<%s>;" % self.get_c_name()

    def get_get_msg_id_t_instantiation(self):
        return "\n".join(
            [
                (
                    "template <> inline vapi_msg_id_t vapi_get_msg_id_t<%s>()"
                    % self.get_c_name()
                ),
                "{",
                "  return ::%s; " % self.get_msg_id_name(),
                "}",
                "",
                (
                    "template <> inline vapi_msg_id_t "
                    "vapi_get_msg_id_t<Msg<%s>>()" % self.get_c_name()
                ),
                "{",
                "  return ::%s; " % self.get_msg_id_name(),
                "}",
            ]
        )

    def get_cpp_constructor(self):
        return "\n".join(
            [
                (
                    "static void __attribute__((constructor)) "
                    "__vapi_cpp_constructor_%s()" % self.name
                ),
                "{",
                (
                    "  vapi::vapi_msg_set_msg_id<%s>(%s);"
                    % (self.get_c_name(), self.get_msg_id_name())
                ),
                "}",
            ]
        )


def gen_json_header(parser, logger, j, io, gen_h_prefix, add_debug_comments):
    logger.info("Generating header `%s'" % io.name)
    orig_stdout = sys.stdout
    sys.stdout = io
    d, f = os.path.split(j)
    include_guard = "__included_hpp_%s" % (
        f.replace(".", "_").replace("/", "_").replace("-", "_").replace("@", "_")
    )
    print("#ifndef %s" % include_guard)
    print("#define %s" % include_guard)
    print("")
    print("#include <vapi/vapi.hpp>")
    print("#include <%s%s>" % (gen_h_prefix, json_to_c_header_name(f)))
    print("")
    print("namespace vapi {")
    print("")
    for m in parser.messages_by_json[j].values():
        # utility functions need to go first, otherwise internal instantiation
        # causes headaches ...
        if add_debug_comments:
            print("/* m.get_swap_to_be_template_instantiation() */")
        print("%s" % m.get_swap_to_be_template_instantiation())
        print("")
        if add_debug_comments:
            print("/* m.get_swap_to_host_template_instantiation() */")
        print("%s" % m.get_swap_to_host_template_instantiation())
        print("")
        if add_debug_comments:
            print("/* m.get_get_msg_id_t_instantiation() */")
        print("%s" % m.get_get_msg_id_t_instantiation())
        print("")
        if add_debug_comments:
            print("/* m.get_cpp_constructor() */")
        print("%s" % m.get_cpp_constructor())
        print("")
        if not m.is_reply and not m.is_event and not m.is_stream:
            if add_debug_comments:
                print("/* m.get_alloc_template_instantiation() */")
            print("%s" % m.get_alloc_template_instantiation())
            print("")
        if add_debug_comments:
            print("/* m.get_msg_class_instantiation() */")
        print("%s" % m.get_msg_class_instantiation())
        print("")
        if m.is_reply or m.is_event:
            if add_debug_comments:
                print("/* m.get_reply_type_alias() */")
            print("%s" % m.get_reply_type_alias())
            continue
        if m.is_stream:
            continue
        if add_debug_comments:
            print("/* m.get_req_template_instantiation() */")
        print("%s" % m.get_req_template_instantiation())
        print("")
        if add_debug_comments:
            print("/* m.get_type_alias() */")
        print("%s" % m.get_type_alias())
        print("")
    print("}")  # namespace vapi

    print("#endif")
    sys.stdout = orig_stdout


def json_to_cpp_header_name(json_name):
    if json_name.endswith(".json"):
        return "%s.vapi.hpp" % os.path.splitext(json_name)[0]
    raise Exception("Unexpected json name `%s'!" % json_name)


def gen_cpp_headers(
    parser, logger, prefix, gen_h_prefix, remove_path, add_debug_comments=False
):
    if prefix == "" or prefix is None:
        prefix = ""
    else:
        prefix = "%s/" % prefix
    if gen_h_prefix is None:
        gen_h_prefix = ""
    else:
        gen_h_prefix = "%s/" % gen_h_prefix
    for j in parser.json_files:
        if remove_path:
            d, f = os.path.split(j)
        else:
            f = j
        with open("%s%s" % (prefix, json_to_cpp_header_name(f)), "w") as io:
            gen_json_header(parser, logger, j, io, gen_h_prefix, add_debug_comments)


if __name__ == "__main__":
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
    logger = logging.getLogger("VAPI CPP GEN")
    logger.setLevel(log_level)

    argparser = argparse.ArgumentParser(description="VPP C++ API generator")
    argparser.add_argument(
        "files",
        metavar="api-file",
        action="append",
        type=str,
        help="json api file" "(may be specified multiple times)",
    )
    argparser.add_argument("--prefix", action="store", default=None, help="path prefix")
    argparser.add_argument(
        "--gen-h-prefix", action="store", default=None, help="generated C header prefix"
    )
    argparser.add_argument(
        "--remove-path", action="store_true", help="remove path from filename"
    )
    args = argparser.parse_args()

    jsonparser = JsonParser(
        logger,
        args.files,
        simple_type_class=CppSimpleType,
        struct_type_class=CppStructType,
        field_class=CppField,
        enum_class=CppEnum,
        message_class=CppMessage,
        alias_class=CppAlias,
    )

    gen_cpp_headers(
        jsonparser, logger, args.prefix, args.gen_h_prefix, args.remove_path
    )

    for e in jsonparser.exceptions:
        logger.warning(e)
