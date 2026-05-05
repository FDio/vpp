# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Meter, Inc.
#
# vppapigen plugin: emit vapi C++ bindings (.vapi.hpp) from the vppapigen AST.
#
# Supersedes src/vpp-api/vapi/vapi_cpp_gen.py. Reuses the type model from
# vppapigen_vapi_c — the C++ output is mostly extra template instantiations
# that wrap the C header, so we extend Message with the CppMessage helpers
# and reuse parser_from_ast() unchanged.

import os

from vppapigen_vapi_c import (
    Message as _CMessage,
    parser_from_ast,
)


class CppMessage(_CMessage):
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


def _munged_filename_token(f):
    return (
        f.replace(".", "_")
        .replace("/", "_")
        .replace("-", "_")
        .replace("@", "_")
        .replace("+", "_")
    )


def _json_to_c_header_name(json_name):
    return "%s.vapi.h" % os.path.splitext(json_name)[0]


def write_vapi_hpp(parser, apifilename, out, gen_h_prefix="vapi/"):
    """Write the .vapi.hpp file. `parser` is a Parser whose Message instances
    are CppMessage (so the template-instantiation helpers exist)."""
    # See note in vppapigen_vapi_c.write_vapi_h: keep `.json` suffix in the
    # token-derived include guard for consumer compatibility.
    f = os.path.basename(apifilename)
    if not f.endswith(".json"):
        f = f + ".json"
    include_guard = "__included_hpp_%s" % _munged_filename_token(f)
    out.write("#ifndef %s\n" % include_guard)
    out.write("#define %s\n" % include_guard)
    out.write("\n")
    out.write("#include <vapi/vapi.hpp>\n")
    out.write("#include <%s%s>\n" % (gen_h_prefix, _json_to_c_header_name(f)))
    out.write("\n")
    out.write("namespace vapi {\n")
    out.write("\n")
    for m in parser.local_messages.values():
        # utility functions need to go first, otherwise internal instantiation
        # causes headaches ...
        out.write("%s\n" % m.get_swap_to_be_template_instantiation())
        out.write("\n")
        out.write("%s\n" % m.get_swap_to_host_template_instantiation())
        out.write("\n")
        out.write("%s\n" % m.get_get_msg_id_t_instantiation())
        out.write("\n")
        out.write("%s\n" % m.get_cpp_constructor())
        out.write("\n")
        if not m.is_reply and not m.is_event and not m.is_stream:
            out.write("%s\n" % m.get_alloc_template_instantiation())
            out.write("\n")
        out.write("%s\n" % m.get_msg_class_instantiation())
        out.write("\n")
        if m.is_reply or m.is_event:
            out.write("%s\n" % m.get_reply_type_alias())
            continue
        if m.is_stream:
            continue
        out.write("%s\n" % m.get_req_template_instantiation())
        out.write("\n")
        out.write("%s\n" % m.get_type_alias())
        out.write("\n")
    out.write("}\n")  # namespace vapi

    out.write("#endif\n")


def parser_from_ast_cpp(s, apifilename, logger):
    """Same as parser_from_ast() but with CppMessage instances so the
    .vapi.hpp emitter's template helpers are available."""
    # parser_from_ast builds Message instances; we patch them to CppMessage
    # by post-processing. Cheaper than threading a class kwarg through every
    # builder helper and there's no behavioral divergence — Message and
    # CppMessage have identical state.
    parser = parser_from_ast(s, apifilename, logger)
    for k, m in list(parser.messages.items()):
        if isinstance(m, CppMessage):
            continue
        cpp = CppMessage.__new__(CppMessage)
        cpp.__dict__.update(m.__dict__)
        parser.messages[k] = cpp
    # Rebuild local_messages with the new instances.
    for k in list(parser.local_messages.keys()):
        parser.local_messages[k] = parser.messages[k]
    # request/reply backrefs may still point at the old Message instance —
    # rewire them.
    for m in parser.messages.values():
        if hasattr(m, "reply") and m.reply is not None:
            m.reply = parser.messages.get(m.reply.name, m.reply)
            m.reply.request = m
        if hasattr(m, "stream_msg") and m.stream_msg is not None:
            m.stream_msg = parser.messages.get(m.stream_msg.name, m.stream_msg)
    return parser
