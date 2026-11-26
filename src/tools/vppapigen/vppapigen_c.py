#
# Copyright (c) 2020 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
This module creates C code for core VPP, VPP plugins and client side VAT and
VAT2 tests.
"""

import datetime
import logging
import re
import itertools
import os
import time
import sys
from io import StringIO
import shutil


def _global_types():
    """Resolve the global type table at call time.

    vppapigen.py runs as __main__ when invoked as a script, so a plain
    `from vppapigen import global_types` at module load time either fails
    (vppapigen not on sys.path under that name) or imports a fresh, empty
    copy. Look it up lazily from __main__ first, falling back to an
    explicit import for the case where vppapigen is imported as a library.
    """
    import sys

    main = sys.modules.get("__main__")
    if main is not None and hasattr(main, "global_types"):
        return main.global_types
    try:
        import vppapigen  # noqa: WPS433

        return vppapigen.global_types
    except ImportError:
        return {}


class _GlobalTypesProxy:
    """Dict-like view that always reflects the live global type table."""

    def __getitem__(self, key):
        return _global_types()[key]

    def get(self, key, default=None):
        return _global_types().get(key, default)

    def __contains__(self, key):
        return key in _global_types()


global_types = _GlobalTypesProxy()

process_imports = False


###############################################################################
###############################################################################


DATESTRING = datetime.datetime.utcfromtimestamp(
    int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
)
TOP_BOILERPLATE = """\
/*
 * VLIB API definitions {datestring}
 * Input file: {input_filename}
 * Automatically generated: please edit the input file NOT this file!
 */

#include <stdbool.h>
#if defined(vl_msg_id)||defined(vl_union_id) \\
    || defined(vl_printfun) \\
    || defined(vl_api_version)||defined(vl_typedefs) \\
    || defined(vl_msg_name)||defined(vl_msg_name_crc_list) \\
    || defined(vl_api_version_tuple)
/* ok, something was selected */
#else
#warning no content included from {input_filename}
#endif

#define VL_API_PACKED(x) x __attribute__ ((packed))

/*
 * Note: VL_API_MAX_ARRAY_SIZE is set to an arbitrarily large limit.
 *
 * However, any message with a ~2 billion element array is likely to break the
 * api handling long before this limit causes array element endian issues.
 *
 * Applications should be written to create reasonable api messages.
 */
#define VL_API_MAX_ARRAY_SIZE 0x7fffffff

"""

BOTTOM_BOILERPLATE = """\
/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version({input_filename}, {file_crc:#08x})

#endif
"""


def msg_ids(s):
    """Generate macro to map API message id to handler"""
    output = """\

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
"""

    for t in s["Define"]:
        output += "vl_msg_id(VL_API_%s, vl_api_%s_t_handler)\n" % (
            t.name.upper(),
            t.name,
        )
    output += "#endif"

    return output


def msg_names(s):
    """Generate calls to name mapping macro"""
    output = """\

/****** Message names ******/

#ifdef vl_msg_name
"""

    for t in s["Define"]:
        dont_trace = 0 if t.dont_trace else 1
        output += "vl_msg_name(vl_api_%s_t, %d)\n" % (t.name, dont_trace)
    output += "#endif"

    return output


def msg_name_crc_list(s, suffix):
    """Generate list of names to CRC mappings"""
    output = """\

/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
"""
    output += "#define foreach_vl_msg_name_crc_%s " % suffix

    for t in s["Define"]:
        output += "\\\n_(VL_API_%s, %s, %08x) " % (t.name.upper(), t.name, t.crc)
    output += "\n#endif"

    return output


def api2c(fieldtype):
    """Map between API type names and internal VPP type names"""
    mappingtable = {
        "string": "vl_api_string_t",
    }
    if fieldtype in mappingtable:
        return mappingtable[fieldtype]
    return fieldtype


def typedefs(filename):
    """Include in the main files to the types file"""
    output = """\

/****** Typedefs ******/

#ifdef vl_typedefs
#include "{include}.api_types.h"
#endif
""".format(include=filename)
    return output


FORMAT_STRINGS = {
    "u8": "%u",
    "bool": "%u",
    "i8": "%d",
    "u16": "%u",
    "i16": "%d",
    "u32": "%u",
    "i32": "%ld",
    "u64": "%llu",
    "i64": "%lld",
    "f64": "%.2f",
}


class Printfun:
    """Functions for pretty printing VPP API messages"""

    _dispatch = {}
    noprint_fields = {"_vl_msg_id": None, "client_index": None, "context": None}

    def __init__(self, stream):
        self.stream = stream

    @staticmethod
    def print_string(o, stream):
        """Pretty print a vl_api_string_t"""
        write = stream.write
        if o.modern_vla:
            write("    if (vl_api_string_len(&a->{f}) > 0) {{\n".format(f=o.fieldname))
            write(
                '        s = format(s, "\\n%U{f}: %U", '
                "format_white_space, indent, "
                "vl_api_format_string, (&a->{f}));\n".format(f=o.fieldname)
            )
            write("    } else {\n")
            write(
                '        s = format(s, "\\n%U{f}:", '
                "format_white_space, indent);\n".format(f=o.fieldname)
            )
            write("    }\n")
        else:
            write(
                '    s = format(s, "\\n%U{f}: %s", '
                "format_white_space, indent, a->{f});\n".format(f=o.fieldname)
            )

    def print_field(self, o, stream):
        """Pretty print API field"""
        write = stream.write
        if o.fieldname in self.noprint_fields:
            return
        if o.fieldtype in FORMAT_STRINGS:
            f = FORMAT_STRINGS[o.fieldtype]
            write(
                '    s = format(s, "\\n%U{n}: {f}", '
                "format_white_space, indent, a->{n});\n".format(n=o.fieldname, f=f)
            )
        else:
            write(
                '    s = format(s, "\\n%U{n}: %U", '
                "format_white_space, indent, "
                "format_{t}, &a->{n}, indent);\n".format(n=o.fieldname, t=o.fieldtype)
            )

    _dispatch["Field"] = print_field

    def print_array(self, o, stream):
        """Pretty print API array"""
        write = stream.write

        forloop = """\
    for (i = 0; i < {lfield}; i++) {{
        s = format(s, "\\n%U{n}: %U",
                   format_white_space, indent, format_{t}, &a->{n}[i], indent);
    }}
"""

        forloop_format = """\
    for (i = 0; i < {lfield}; i++) {{
        s = format(s, "\\n%U{n}: {t}",
                   format_white_space, indent, a->{n}[i]);
    }}
"""

        if o.fieldtype == "string":
            self.print_string(o, stream)
            return

        if o.fieldtype == "u8":
            if o.lengthfield:
                write(
                    '    s = format(s, "\\n%U{n}: %U", format_white_space, '
                    "indent, format_hex_bytes, a->{n}, a->{lfield});\n".format(
                        n=o.fieldname, lfield=o.lengthfield
                    )
                )
            else:
                write(
                    '    s = format(s, "\\n%U{n}: %U", format_white_space, '
                    "indent, format_hex_bytes, a, {lfield});\n".format(
                        n=o.fieldname, lfield=o.length
                    )
                )
            return

        lfield = "a->" + o.lengthfield if o.lengthfield else o.length
        if o.fieldtype in FORMAT_STRINGS:
            write(
                forloop_format.format(
                    lfield=lfield, t=FORMAT_STRINGS[o.fieldtype], n=o.fieldname
                )
            )
        else:
            write(forloop.format(lfield=lfield, t=o.fieldtype, n=o.fieldname))

    _dispatch["Array"] = print_array

    @staticmethod
    def print_alias(k, v, stream):
        """Pretty print type alias"""
        write = stream.write
        if "length" in v.alias and v.alias["length"] and v.alias["type"] == "u8":
            write(
                '    return format(s, "%U", format_hex_bytes, a, {});\n'.format(
                    v.alias["length"]
                )
            )
        elif v.alias["type"] in FORMAT_STRINGS:
            write(
                '    return format(s, "{}", *a);\n'.format(
                    FORMAT_STRINGS[v.alias["type"]]
                )
            )
        else:
            write('    return format(s, "{} (print not implemented)");\n'.format(k))

    @staticmethod
    def print_enum(o, stream):
        """Pretty print API enum"""
        write = stream.write
        write("    switch(*a) {\n")
        for b in o:
            write("    case %s:\n" % b[1])
            write('        return format(s, "{}");\n'.format(b[0]))
        write("    }\n")

    _dispatch["Enum"] = print_enum
    _dispatch["EnumFlag"] = print_enum

    def print_obj(self, o, stream):
        """Entry point"""
        write = stream.write

        if o.type in self._dispatch:
            self._dispatch[o.type](self, o, stream)
        else:
            write(
                '    s = format(s, "\\n{} {} {} (print not implemented");\n'.format(
                    o.type, o.fieldtype, o.fieldname
                )
            )


def printfun_types(objs, stream, modulename):
    """Pretty print API types"""
    write = stream.write
    pp = Printfun(stream)

    h = """\
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_{module}_printfun_types
#define included_{module}_printfun_types

"""
    h = h.format(module=modulename)
    write(h)

    signature = """\
static inline u8 *format_vl_api_{name}_t (u8 *s, va_list * args)
{{
    vl_api_{name}_t *a = va_arg (*args, vl_api_{name}_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
"""

    for t in objs:
        if t.__class__.__name__ == "Enum" or t.__class__.__name__ == "EnumFlag":
            write(signature.format(name=t.name))
            pp.print_enum(t.block, stream)
            write("    return s;\n")
            write("}\n\n")
            continue

        if t.manual_print:
            write("/***** manual: vl_api_%s_t_format *****/\n\n" % t.name)
            continue

        if t.__class__.__name__ == "Using":
            write(signature.format(name=t.name))
            pp.print_alias(t.name, t, stream)
            write("}\n\n")
            continue

        write(signature.format(name=t.name))
        for o in t.block:
            pp.print_obj(o, stream)

        write("    return s;\n")
        write("}\n\n")

    write("\n#endif")
    write("\n#endif /* vl_printfun_types */\n")


def generate_imports(imports):
    """Add #include matching the API import statements"""
    output = "/* Imported API files */\n"
    output += "#ifndef vl_api_version\n"

    for i in imports:
        s = i.filename.replace("plugins/", "")
        output += "#include <{}.h>\n".format(s)
    output += "#endif\n"
    return output


NO_ENDIAN_CONVERSION = {"client_index": None}


def version_tuple(s, module):
    """Generate semantic version string"""
    output = """\
/****** Version tuple *****/

#ifdef vl_api_version_tuple

"""
    if "version" in s["Option"]:
        v = s["Option"]["version"]
        major, minor, patch = v.split(".")
        output += "vl_api_version_tuple(%s, %s, %s, %s)\n" % (
            module,
            major,
            minor,
            patch,
        )

    output += "\n#endif /* vl_api_version_tuple */\n\n"

    return output


def generate_include_enum(s, module, stream):
    """Generate <name>.api_enum.h"""
    write = stream.write

    if "Define" in s:
        write("typedef enum {\n")
        for t in s["Define"]:
            write("   VL_API_{},\n".format(t.name.upper()))
        write("   VL_MSG_{}_LAST\n".format(module.upper()))
        write("}} vl_api_{}_enum_t;\n".format(module))


def generate_include_counters(s, stream):
    """Include file for the counter data model types."""
    write = stream.write

    for counters in s:
        csetname = counters.name
        write("typedef enum {\n")
        for c in counters.block:
            write("   {}_ERROR_{},\n".format(csetname.upper(), c["name"].upper()))
        write("   {}_N_ERROR\n".format(csetname.upper()))
        write("}} vl_counter_{}_enum_t;\n".format(csetname))

        write("extern vlib_error_desc_t {}_error_counters[];\n".format(csetname))


def generate_include_types(s, module, stream):
    """Generate separate API _types file."""
    write = stream.write

    write("#ifndef included_{module}_api_types_h\n".format(module=module))
    write("#define included_{module}_api_types_h\n".format(module=module))

    if "version" in s["Option"]:
        v = s["Option"]["version"]
        major, minor, patch = v.split(".")
        write(
            "#define VL_API_{m}_API_VERSION_MAJOR {v}\n".format(
                m=module.upper(), v=major
            )
        )
        write(
            "#define VL_API_{m}_API_VERSION_MINOR {v}\n".format(
                m=module.upper(), v=minor
            )
        )
        write(
            "#define VL_API_{m}_API_VERSION_PATCH {v}\n".format(
                m=module.upper(), v=patch
            )
        )

    if "Import" in s:
        write("/* Imported API files */\n")
        for i in s["Import"]:
            filename = i.filename.replace("plugins/", "")
            write("#include <{}_types.h>\n".format(filename))

    for o in itertools.chain(s["types"], s["Define"]):
        tname = o.__class__.__name__
        if tname == "Using":
            if "length" in o.alias:
                write(
                    "typedef %s vl_api_%s_t[%s];\n"
                    % (o.alias["type"], o.name, o.alias["length"])
                )
            else:
                write("typedef %s vl_api_%s_t;\n" % (o.alias["type"], o.name))
        elif tname == "Enum" or tname == "EnumFlag":
            if o.enumtype == "u32":
                write("typedef enum {\n")
            else:
                write("typedef enum __attribute__((packed)) {\n")

            for b in o.block:
                write("    %s = %s,\n" % (b[0], b[1]))
            write("} vl_api_%s_t;\n" % o.name)
            if o.enumtype != "u32":
                size1 = "sizeof(vl_api_%s_t)" % o.name
                size2 = "sizeof(%s)" % o.enumtype
                err_str = "size of API enum %s is wrong" % o.name
                write('STATIC_ASSERT(%s == %s, "%s");\n' % (size1, size2, err_str))
        else:
            if tname == "Union":
                write("typedef union __attribute__ ((packed)) _vl_api_%s {\n" % o.name)
            else:
                write(
                    ("typedef struct __attribute__ ((packed)) _vl_api_%s {\n") % o.name
                )
            for b in o.block:
                if b.type == "Option":
                    continue
                if b.type == "Field":
                    write("    %s %s;\n" % (api2c(b.fieldtype), b.fieldname))
                elif b.type == "Array":
                    if b.lengthfield:
                        write("    %s %s[0];\n" % (api2c(b.fieldtype), b.fieldname))
                    else:
                        # Fixed length strings decay to nul terminated u8
                        if b.fieldtype == "string":
                            if b.modern_vla:
                                write(
                                    "    {} {};\n".format(
                                        api2c(b.fieldtype), b.fieldname
                                    )
                                )
                            else:
                                write("    u8 {}[{}];\n".format(b.fieldname, b.length))
                        else:
                            write(
                                "    %s %s[%s];\n"
                                % (api2c(b.fieldtype), b.fieldname, b.length)
                            )
                else:
                    raise ValueError(
                        "Error in processing type {} for {}".format(b, o.name)
                    )

            write("} vl_api_%s_t;\n" % o.name)
            write(
                f"#define VL_API_{o.name.upper()}_IS_CONSTANT_SIZE ({0 if o.vla else 1})\n\n"
            )

    for t in s["Define"]:
        write(
            '#define VL_API_{ID}_CRC "{n}_{crc:08x}"\n'.format(
                n=t.name, ID=t.name.upper(), crc=t.crc
            )
        )

    write("\n#endif\n")


def generate_c_boilerplate(s, services, defines, counters, file_crc, module, stream):
    """VPP side plugin."""
    write = stream.write
    define_hash = {d.name: d for d in defines}

    hdr = """\
/* instantiate all the print functions we know about */
#define vl_printfun
#include "{module}.api.h"
#undef vl_printfun

#include "{module}.api_json.h"
"""

    write(hdr.format(module=module))
    if len(defines) > 0:
        write(
            "extern const vl_api_desc_file_t {}_api_desc "
            '__attribute__ ((visibility ("hidden")));\n'.format(module)
        )
        write("static u16\n")
        write("setup_message_id_table (void) {\n")
        write("   api_main_t *am = my_api_main;\n")
        write("   vl_msg_api_msg_config_t c;\n")
        write(
            '   u16 msg_id_base = vl_msg_api_get_msg_ids ("{}_{crc:08x}", '
            "VL_MSG_{m}_LAST);\n".format(module, crc=file_crc, m=module.upper())
        )
        write(f"   vec_add1(am->json_api_repr, (u8 *)json_api_repr_{module});\n")
        write(f"   vl_api_desc_register (am, &{module}_api_desc, msg_id_base);\n")

    for d in defines:
        write(
            '   vl_msg_api_add_msg_name_crc (am, "{n}_{crc:08x}",\n'
            "                                VL_API_{ID} + msg_id_base);\n".format(
                n=d.name, ID=d.name.upper(), crc=d.crc
            )
        )
    for s in services:
        d = define_hash[s.caller]
        write(
            "   c = (vl_msg_api_msg_config_t) "
            " {{.id = VL_API_{ID} + msg_id_base,\n"
            '   .name = "{n}",\n'
            "   .handler = vl_api_{n}_t_handler,\n"
            "   .traced = 1,\n"
            "   .replay = 1,\n"
            "   .is_autoendian = {auto}}};\n".format(
                n=s.caller, ID=s.caller.upper(), auto=d.autoendian
            )
        )
        write("   vl_msg_api_config (&c);\n")
        try:
            d = define_hash[s.reply]
            write(
                "   c = (vl_msg_api_msg_config_t) "
                "{{.id = VL_API_{ID} + msg_id_base,\n"
                '  .name = "{n}",\n'
                "  .handler = 0,\n"
                "  .traced = 1,\n"
                "  .replay = 1,\n"
                "  .is_autoendian = {auto}}};\n".format(
                    n=s.reply, ID=s.reply.upper(), auto=d.autoendian
                )
            )
            write("   vl_msg_api_config (&c);\n")
        except KeyError:
            pass

        try:
            if s.stream:
                d = define_hash[s.stream_message]
                write(
                    "   c = (vl_msg_api_msg_config_t) "
                    "{{.id = VL_API_{ID} + msg_id_base,\n"
                    '  .name = "{n}",\n'
                    "  .handler = 0,\n"
                    "  .traced = 1,\n"
                    "  .replay = 1,\n"
                    "  .is_autoendian = {auto}}};\n".format(
                        n=s.stream_message,
                        ID=s.stream_message.upper(),
                        auto=d.autoendian,
                    )
                )
                write("   vl_msg_api_config (&c);\n")
        except KeyError:
            pass
    if len(defines) > 0:
        write("   return msg_id_base;\n")
        write("}\n")

    severity = {
        "error": "VL_COUNTER_SEVERITY_ERROR",
        "info": "VL_COUNTER_SEVERITY_INFO",
        "warn": "VL_COUNTER_SEVERITY_WARN",
    }

    for cnt in counters:
        csetname = cnt.name
        write("vlib_error_desc_t {}_error_counters[] = {{\n".format(csetname))
        for c in cnt.block:
            write("  {\n")
            write('   .name = "{}",\n'.format(c["name"]))
            write('   .desc = "{}",\n'.format(c["description"]))
            write("   .severity = {},\n".format(severity[c["severity"]]))
            write("  },\n")
        write("};\n")


def generate_c_test_boilerplate(services, defines, file_crc, module, plugin, stream):
    """Generate code for legacy style VAT. To be deleted."""
    write = stream.write

    define_hash = {d.name: d for d in defines}

    hdr = """\
/* instantiate all the print functions we know about */
#define vl_printfun
#include "{module}.api.h"
#undef vl_printfun

/* the API descriptors of the file */
#include <vlibapi/api_desc.h>
#include "{module}.api_desc.c"

"""

    write(hdr.format(module=module))
    for s in services:
        try:
            d = define_hash[s.reply]
        except KeyError:
            continue
        if d.manual_print:
            write(
                "/*\n"
                " * Manual definition requested for: \n"
                " * vl_api_{n}_t_handler()\n"
                " */\n".format(n=s.reply)
            )
            continue
        if not define_hash[s.caller].autoreply:
            write(
                "/* Generation not supported (vl_api_{n}_t_handler()) */\n".format(
                    n=s.reply
                )
            )
            continue
        write("#ifndef VL_API_{n}_T_HANDLER\n".format(n=s.reply.upper()))
        write("static void\n")
        write("vl_api_{n}_t_handler (vl_api_{n}_t * mp) {{\n".format(n=s.reply))
        write("   vat_main_t * vam = {}_test_main.vat_main;\n".format(module))
        write("   i32 retval = ntohl(mp->retval);\n")
        write("   if (vam->async_mode) {\n")
        write("      vam->async_errors += (retval < 0);\n")
        write("   } else {\n")
        write("      vam->retval = retval;\n")
        write("      vam->result_ready = 1;\n")
        write("   }\n")
        write("}\n")
        write("#endif\n")

        for e in s.events:
            if define_hash[e].manual_print:
                continue
            write("static void\n")
            write("vl_api_{n}_t_handler (vl_api_{n}_t * mp) {{\n".format(n=e))
            write('    vlib_cli_output(0, "{n} event called:");\n'.format(n=e))
            write(
                '    u8 *s = vl_api_desc_file_format(0, &{m}_api_desc, "{n}", mp);\n'.format(
                    m=module, n=e
                )
            )
            write('    vlib_cli_output(0, "%v", s);\n')
            write("    vec_free(s);\n")
            write("}\n")

    write("static void\n")
    write("setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {\n")
    if len(defines) > 0:
        # vpp has the descriptors of the files of its plugins
        write("#if VPP_API_TEST_BUILTIN == 0\n")
        write(
            "   vl_api_desc_register (vlibapi_get_main (), &{}_api_desc, msg_id_base);\n".format(
                module
            )
        )
        write("#endif\n")
    for s in services:
        write(
            "   vl_msg_api_config (&(vl_msg_api_msg_config_t){{\n"
            "    .id = VL_API_{ID} + msg_id_base,\n"
            '    .name = "{n}",\n'
            "    .handler = vl_api_{n}_t_handler,\n"
            "    .size = sizeof(vl_api_{n}_t),\n"
            "    .traced = 1,\n"
            "   }});".format(n=s.reply, ID=s.reply.upper())
        )
        write(
            '   hash_set_mem (vam->function_by_name, "{n}", api_{n});\n'.format(
                n=s.caller
            )
        )
        try:
            write(
                '   hash_set_mem (vam->help_by_name, "{n}", "{help}");\n'.format(
                    n=s.caller, help=define_hash[s.caller].options["vat_help"]
                )
            )
        except KeyError:
            pass

        # Events
        for e in s.events:
            write(
                "   vl_msg_api_config (&(vl_msg_api_msg_config_t){{\n"
                "    .id = VL_API_{ID} + msg_id_base,\n"
                '    .name = "{n}",\n'
                "    .handler = vl_api_{n}_t_handler,\n"
                "    .size = sizeof(vl_api_{n}_t),\n"
                "    .traced = 1,\n"
                "   }});".format(n=e, ID=e.upper())
            )

    write("}\n")
    write("clib_error_t * vat_plugin_register (vat_main_t *vam)\n")
    write("{\n")
    write("   {n}_test_main_t * mainp = &{n}_test_main;\n".format(n=module))
    write("   mainp->vat_main = vam;\n")
    write(
        "   mainp->msg_id_base = vl_client_get_first_plugin_msg_id "
        '                       ("{n}_{crc:08x}");\n'.format(n=module, crc=file_crc)
    )
    write("   if (mainp->msg_id_base == (u16) ~0)\n")
    write(
        '      return clib_error_return (0, "{} plugin not loaded...");\n'.format(
            module
        )
    )
    write("   setup_message_id_table (vam, mainp->msg_id_base);\n")
    write("#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE\n")
    write("    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);\n")
    write("#endif\n")
    write("   return 0;\n")
    write("}\n")


def apifunc(func):
    """Check if a method is generated already."""

    def _f(module, d, processed, *args):
        if d.name in processed:
            return None
        processed[d.name] = True
        return func(module, d, *args)

    return _f


def c_test_api_service(s, dump, module, stream):
    """Generate JSON code for a service."""
    write = stream.write

    req_reply_template = """\
static cJSON *
api_{n} (cJSON *o)
{{
  vl_api_{n}_t *mp;
  int len;
  if (!o) return 0;
  mp = vat2_json_to_msg(&{module}_api_desc, "{n}", o, &len);
  if (!mp) {{
    fprintf(stderr, "Failed converting JSON to API\\n");
    return 0;
  }}

  mp->_vl_msg_id = vac_get_msg_index(VL_API_{N}_CRC);
  vl_api_desc_file_endian(&{module}_api_desc, "{n}", mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_{R}_CRC)) {{
    fprintf(stderr, "Mismatched reply\\n");
    vac_free(p);
    return 0;
  }}
  vl_api_{r}_t *rmp = (vl_api_{r}_t *)p;
  vl_api_desc_file_endian(&{module}_api_desc, "{r}", rmp, 0);
  cJSON *json = vat2_msg_to_json(&{module}_api_desc, "{r}", rmp);
  vac_free(p);
  return json;
}}

"""
    dump_details_template = """\
static cJSON *
api_{n} (cJSON *o)
{{
  u16 msg_id = vac_get_msg_index(VL_API_{N}_CRC);
  int len;
  if (!o) return 0;
  vl_api_{n}_t *mp = vat2_json_to_msg(&{module}_api_desc, "{n}", o, &len);
  if (!mp) {{
      fprintf(stderr, "Failed converting JSON to API\\n");
      return 0;
  }}
  mp->_vl_msg_id = msg_id;
  vl_api_desc_file_endian(&{module}_api_desc, "{n}", mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_{R}_CRC);

  while (1) {{
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout
    if (p == 0 || l == 0) {{
      cJSON_free(reply);
      return 0;
    }}

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 reply_msg_id = ntohs(*((u16 *)p));
    if (reply_msg_id == ping_reply_msg_id) {{
        vac_free(p);
        break;
    }}

    if (reply_msg_id == details_msg_id) {{
        if (l < sizeof(vl_api_{r}_t)) {{
            vac_free(p);
            cJSON_free(reply);
            return 0;
        }}
        vl_api_{r}_t *rmp = (vl_api_{r}_t *)p;
        vl_api_desc_file_endian(&{module}_api_desc, "{r}", rmp, 0);
        cJSON_AddItemToArray(reply, vat2_msg_to_json(&{module}_api_desc, "{r}", rmp));
    }}
    vac_free(p);
  }}
  return reply;
}}

"""
    gets_details_reply_template = """\
static cJSON *
api_{n} (cJSON *o)
{{
    u16 msg_id = vac_get_msg_index(VL_API_{N}_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_{n}_t *mp = vat2_json_to_msg(&{module}_api_desc, "{n}", o, &len);
  if (!mp) {{
    fprintf(stderr, "Failed converting JSON to API\\n");
    return 0;
  }}
  mp->_vl_msg_id = msg_id;

  vl_api_desc_file_endian(&{module}_api_desc, "{n}", mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_{R}_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_{D}_CRC);

  while (1) {{
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 msg_id = ntohs(*((u16 *)p));
    if (msg_id == reply_msg_id) {{
        vl_api_{r}_t *rmp = (vl_api_{r}_t *)p;
        vl_api_desc_file_endian(&{module}_api_desc, "{r}", rmp, 0);
        cJSON_AddItemToArray(reply, vat2_msg_to_json(&{module}_api_desc, "{r}", rmp));
        vac_free(p);
        break;
    }}

    if (msg_id == details_msg_id) {{
        vl_api_{d}_t *rmp = (vl_api_{d}_t *)p;
        vl_api_desc_file_endian(&{module}_api_desc, "{d}", rmp, 0);
        cJSON_AddItemToArray(reply, vat2_msg_to_json(&{module}_api_desc, "{d}", rmp));
    }}
    vac_free(p);
  }}
  return reply;
}}

"""

    if dump:
        if s.stream_message:
            write(
                gets_details_reply_template.format(
                    n=s.caller,
                    r=s.reply,
                    N=s.caller.upper(),
                    module=module,
                    R=s.reply.upper(),
                    d=s.stream_message,
                    D=s.stream_message.upper(),
                )
            )
        else:
            write(
                dump_details_template.format(
                    n=s.caller,
                    r=s.reply,
                    N=s.caller.upper(),
                    R=s.reply.upper(),
                    module=module,
                )
            )
    else:
        write(
            req_reply_template.format(
                n=s.caller,
                r=s.reply,
                N=s.caller.upper(),
                R=s.reply.upper(),
                module=module,
            )
        )


def generate_c_test2_boilerplate(services, defines, module, stream):
    """Generate code for VAT2 plugin."""
    write = stream.write

    define_hash = {d.name: d for d in defines}
    # replies = {}

    hdr = """\
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip_format_fns.h>
#include <vnet/ethernet/ethernet_format_fns.h>

#define vl_typedefs             /* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#include <vlibmemory/vlib.api_types.h>
#include <vlibmemory/vlib.api.h>
#undef vl_typedefs

#include "{module}.api_enum.h"
#include "{module}.api_types.h"

#define vl_printfun
#include "{module}.api.h"
#undef vl_printfun

#include <vpp-api/client/vppapiclient.h>
#include <vlibapi/api_desc.h>

/* the API descriptors of the file */
#include "{module}.api_desc.c"

#include <vat2/vat2_helpers.h>

"""

    write(hdr.format(module=module))

    for s in services:
        if s.reply not in define_hash:
            continue
        c_test_api_service(s, s.stream, module, stream)
        write(
            "static cJSON *\n"
            "tojson_{n} (void *mp)\n"
            "{{\n"
            '  return vat2_msg_to_json (&{m}_api_desc, "{n}", mp);\n'
            "}}\n\n".format(n=s.caller, m=module)
        )

    write(
        "void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);\n"
    )
    # write('__attribute__((constructor))')
    write("clib_error_t *\n")
    write("vat2_register_plugin (void);\n")
    write("clib_error_t *\n")
    write("vat2_register_plugin (void) {\n")
    for s in services:
        if s.reply not in define_hash:
            continue
        crc = define_hash[s.caller].crc
        write(
            '   vat2_register_function("{n}", api_{n}, tojson_{n}, 0x{crc:08x});\n'.format(
                n=s.caller, crc=crc
            )
        )
    write("   return 0;\n")
    write("}\n")


###############################################################################
# API descriptors
#
# A const, self contained description of the messages and types of a file,
# registered with vlibapi at startup. It carries the binary layout (offsets,
# sizes, array and VLA rules) and the metadata of the .api file (CRCs,
# options, services...), so that generic code can convert messages to and from
# JSON and render the .api.json text on demand. Types from other files which
# are used here are included in the table too, so it does not depend on the
# other files being loaded. See vlibapi/api_desc.h.
###############################################################################
_DESC_BASE = {
    "u8": ("U8", 1),
    "i8": ("I8", 1),
    "u16": ("U16", 2),
    "i16": ("I16", 2),
    "u32": ("U32", 4),
    "i32": ("I32", 4),
    "u64": ("U64", 8),
    "i64": ("I64", 8),
    "f64": ("F64", 8),
    "bool": ("BOOL", 1),
}


def _c_str(text):
    """C string literal, or 0"""
    if text is None:
        return "0"
    out = ['"']
    for ch in str(text).encode("utf-8"):
        c = chr(ch)
        if c == "\\":
            out.append("\\\\")
        elif c == '"':
            out.append('\\"')
        elif c == "\n":
            out.append("\\n")
        elif ch < 0x20 or ch >= 0x7F:
            # octal escapes are at most 3 digits, so no ambiguity with what follows
            out.append("\\%03o" % ch)
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def _parse_comment(text):
    """The brief and the descriptions of the parameters of a comment

    The comment of a message is "/** \\brief text" followed by lines
    "@param name - description". The text of a description goes on up to the next
    tag. A comment without a tag is a brief."""
    if not text:
        return None, {}
    body = re.sub(r"^\s*/\*+", "", text)
    body = re.sub(r"\*+/\s*$", "", body)
    lines = [re.sub(r"^\s*\*?\s?", "", l) for l in body.split("\n")]
    brief = None
    params = {}
    cur = None  # [kind, name, [text]]
    entries = []
    for l in lines:
        m = re.match(r"\s*[@\\](\w+)\s*(.*)$", l)
        if m:
            cur = [m.group(1), None, [m.group(2)]]
            if m.group(1) == "param":
                pm = re.match(r"([^\s-]+)\s*-?\s*(.*)$", m.group(2))
                if pm:
                    cur = ["param", pm.group(1), [pm.group(2)]]
            entries.append(cur)
        elif cur is None:
            cur = ["brief", None, [l]]
            entries.append(cur)
        else:
            cur[2].append(l)
    for kind, name, parts in entries:
        text = " ".join(" ".join(parts).split())
        if not text:
            continue
        if kind == "brief" and brief is None:
            brief = text
        elif kind == "param" and name and name not in params:
            params[name] = text
    return brief, params


class DescBuilder:
    """Builds the descriptor tables for one .api file"""

    def __init__(self, module, s):
        self.module = module
        self.s = s
        self.emitted = {}  # id(obj) -> C symbol
        self.out = StringIO()
        self.own = {id(o) for o in s["types"]}
        self.svc = {e.caller: e for e in s["Service"]}
        self.defines = {d.name: d for d in s["Define"]}
        # the descriptors of the messages and of the types are arrays
        # a type which is imported through more than one file is in the list twice
        self.type_list = []
        self.type_index = {}
        for o in s["imported"]["types"]:
            if id(o) not in self.type_index:
                self.type_index[id(o)] = len(self.type_list)
                self.type_list.append(o)
        self.msg_index = {d.name: i for i, d in enumerate(s["Define"])}
        self.structs = {}  # (is a message, index) -> the initializer
        # the fields, the values of the enums and the options of all the types
        # of the file are in an array each, the options of the file are the first
        self.field_entries = []
        self.value_entries = []
        self.option_entries = []
        self.n_file_options = self.add_options(s["Option"])[1]

    def expr(self, o):
        """The value of a reference to a message or a type, the index in the
        messages or the types of the file plus one, 0 is no reference"""
        if o.__class__.__name__ == "Define":
            return self.msg_index[o.name] + 1
        if id(o) not in self.type_index:
            raise ValueError("%s is not in the types of %s" % (o.name, self.module))
        return self.type_index[id(o)] + 1

    def add_struct(self, o, lines):
        is_msg = o.__class__.__name__ == "Define"
        idx = self.msg_index[o.name] if is_msg else self.type_index[id(o)]
        self.structs[(is_msg, idx)] = "".join(lines)

    def msg_sym(self, name):
        """The reference to a message of the file"""
        if name not in self.defines:
            raise ValueError("%s is not a message of %s" % (name, self.module))
        return self.expr(self.defines[name])

    # ---- layout
    def size_of(self, t):
        if t in _DESC_BASE:
            return _DESC_BASE[t][1]
        return self.size_of_obj(global_types[t])

    def size_of_obj(self, o):
        cls = o.__class__.__name__
        if cls == "Using":
            sz = self.size_of(o.alias["type"])
            return sz * o.alias["length"] if "length" in o.alias else sz
        if cls in ("Enum", "EnumFlag"):
            return _DESC_BASE[o.enumtype][1]
        sizes = [self.field_size(b) for b in o.block if b.type != "Option"]
        if cls == "Union":
            return max(sizes) if sizes else 0
        return sum(sizes)

    def field_size(self, b):
        if b.type == "Field":
            return self.size_of(b.fieldtype)
        if b.fieldtype == "string":
            # vl_api_string_t header or a fixed, nul terminated u8 array
            return 4 if b.modern_vla else b.length
        if b.lengthfield:
            return 0
        return self.size_of(b.fieldtype) * b.length

    def kind_of(self, t):
        """(kind, referenced object or None) of a field type"""
        if t in _DESC_BASE:
            return "VL_API_DK_" + _DESC_BASE[t][0], None
        if t == "string":
            return "VL_API_DK_STRING", None
        o = global_types[t]
        cls = o.__class__.__name__
        if cls == "Using":
            if "length" not in o.alias and o.alias["type"] in _DESC_BASE:
                return "VL_API_DK_" + _DESC_BASE[o.alias["type"]][0], o
            return "VL_API_DK_NAMED", o
        if cls == "Enum":
            return "VL_API_DK_ENUM", o
        if cls == "EnumFlag":
            return "VL_API_DK_ENUMFLAG", o
        if cls == "Union":
            return "VL_API_DK_UNION", o
        return "VL_API_DK_STRUCT", o

    # ---- emission
    def sym(self, o, prefix):
        return "%s_%s_%s" % (self.module, prefix, o.name)

    def emit_type(self, o):
        """Emit o and everything it refers to, returns the C symbol"""
        key = id(o)
        if key in self.emitted:
            return self.emitted[key]
        cls = o.__class__.__name__
        w = self.out.write
        prefix = "m" if cls == "Define" else "d"
        name = self.sym(o, prefix)

        if cls in ("Enum", "EnumFlag"):
            first_value = len(self.value_entries)
            for b in o.block:
                self.value_entries.append(
                    "  [%d] = { %s, %dLL },\n"
                    % (len(self.value_entries), _c_str(b[0]), b[1])
                )
            w(
                'STATIC_ASSERT (sizeof (vl_api_%s_t) == %d, "API descriptor size of %s");\n'
                % (o.name, self.size_of_obj(o), o.name)
            )
            buf = []
            sw = buf.append
            sw("  .name = %s,\n" % _c_str(o.name))
            sw(
                "  .kind = %s,\n"
                % ("VL_API_DT_ENUM" if cls == "Enum" else "VL_API_DT_ENUMFLAG")
            )
            sw("  .base = VL_API_DK_%s,\n" % _DESC_BASE[o.enumtype][0])
            sw("  .size = %d,\n" % self.size_of_obj(o))
            sw("  .n_fields = %d,\n" % len(o.block))
            sw("  .first = %d,\n" % first_value)
            sw("  .imported = %d,\n" % (0 if key in self.own else 1))
            self.add_struct(o, buf)
            self.emitted[key] = self.expr(o)
            return self.emitted[key]

        if cls == "Using":
            # make sure what it points to is available to the interpreter
            if o.alias["type"] not in _DESC_BASE:
                self.emit_type(global_types[o.alias["type"]])
            w(
                'STATIC_ASSERT (sizeof (vl_api_%s_t) == %d, "API descriptor size of %s");\n'
                % (o.name, self.size_of_obj(o), o.name)
            )
            buf = []
            sw = buf.append
            sw("  .name = %s,\n" % _c_str(o.name))
            sw("  .kind = VL_API_DT_ALIAS,\n")
            sw("  .flags = %s,\n" % self.type_flags(o))
            sw("  .size = %d,\n" % self.size_of_obj(o))
            sw("  .alias_type = %s,\n" % _c_str(o.alias["type"]))
            sw("  .alias_length = %d,\n" % o.alias.get("length", 0))
            sw("  .imported = %d,\n" % (0 if key in self.own else 1))
            self.add_struct(o, buf)
            self.emitted[key] = self.expr(o)
            return self.emitted[key]

        # Typedef, Union, Define
        fields = [b for b in o.block if b.type != "Option"]
        refs = []
        for b in fields:
            _, ro = self.kind_of(b.fieldtype)
            if ro is not None:
                refs.append(self.emit_type(ro))
            else:
                refs.append(None)

        brief, params = _parse_comment(getattr(o, "comment", None))
        # the description of a field which does not exist is a typo
        if key in self.own or cls == "Define":
            names = [b.fieldname for b in fields]
            for pname in params:
                if pname not in names:
                    logging.getLogger("vppapigen").warning(
                        "%s.api: %s: '@param %s' is not a field, the fields are: %s"
                        % (self.module, o.name, pname, ", ".join(names))
                    )
        offset = 0
        first_field = len(self.field_entries)
        for idx, (b, ref) in enumerate(zip(fields, refs)):
            kind, _ = self.kind_of(b.fieldtype)
            flags = []
            length = 0
            len_field = None
            default = None
            size = self.field_size(b)
            if b.type == "Field":
                if b.limit:
                    for k in b.limit:
                        if k not in ("default", "discriminator", "case"):
                            raise ValueError("unknown field option %s" % k)
                    default = b.limit.get("default")
                elem = size
            else:
                length = b.length
                if b.fieldtype == "string":
                    # fixed strings are an array of u8 in C, variable ones
                    # are a vl_api_string_t
                    if b.modern_vla:
                        flags.append("VL_API_DF_MODERN_VLA")
                        elem = 4
                    else:
                        kind = "VL_API_DK_FSTRING"
                        elem = 1
                    flags.append("VL_API_DF_ARRAY")
                else:
                    flags.append("VL_API_DF_ARRAY")
                    elem = self.size_of(b.fieldtype)
                    if b.lengthfield:
                        flags.append("VL_API_DF_VLA")
                        len_field = b.lengthfield
            if getattr(b, "is_lengthfield", False):
                flags.append("VL_API_DF_LENGTH")
            related = 0
            case_value = 0
            limit = getattr(b, "limit", None) if b.type == "Field" else None
            if b.type == "Field" and b.fieldname in NO_ENDIAN_CONVERSION:
                flags.append("VL_API_DF_NO_ENDIAN")
            if limit and "discriminator" in limit:
                flags.append("VL_API_DF_TAGGED")
                related = [x.fieldname for x in fields].index(limit["discriminator"])
            if len_field:
                related = [x.fieldname for x in fields].index(len_field)
            if limit and "case" in limit:
                flags.append("VL_API_DF_CASE")
                case_value = self.enum_value(limit["case"])
            ebuf = []
            ew = ebuf.append
            ew("    .name = %s,\n" % _c_str(b.fieldname))
            ew("    .kind = %s,\n" % kind)
            ew("    .flags = %s,\n" % (" | ".join(flags) if flags else "0"))
            ew("    .offset = %d,\n" % offset)
            ew("    .size = %d,\n" % elem)
            ew("    .length = %d,\n" % length)
            if default is not None:
                # the parser gives the booleans as words
                if b.fieldtype == "bool" and default in ("true", "false"):
                    default = default == "true"
                kind_name, value = self.default_c(default)
                ew("    .default_kind = %s,\n" % kind_name)
                ew("    .default_value = { %s },\n" % value)
            if limit and "case" in limit:
                ew("    .case_name = %s,\n" % _c_str(limit["case"]))
            if ref:
                ew("    .ref = %d,\n" % ref)
            if b.fieldname in params:
                ew("    .description = %s,\n" % _c_str(params[b.fieldname]))
            if related:
                ew("    .related = %d,\n" % related)
            if case_value:
                ew("    .case_value = %dLL,\n" % case_value)
            self.field_entries.append(
                "  [%d] = {\n%s  },\n" % (len(self.field_entries), "".join(ebuf))
            )
            if cls != "Union":
                offset += size

        # the compiler checks the layout the descriptor is based on
        ctype = "vl_api_%s_t" % o.name
        w(
            'STATIC_ASSERT (sizeof (%s) == %d, "API descriptor size of %s");\n'
            % (ctype, self.size_of_obj(o), o.name)
        )
        off = 0
        for b in fields:
            w(
                'STATIC_ASSERT (offsetof (%s, %s) == %d, "API descriptor offset of %s.%s");\n'
                % (ctype, b.fieldname, off, o.name, b.fieldname)
            )
            if cls != "Union":
                off += self.field_size(b)
        first_option, options = self.add_options(o.options if cls == "Define" else {})
        # the reply, the details and the events of a service are messages of the file
        svc = self.svc.get(o.name) if cls == "Define" else None
        extra_flags = []
        if svc:
            extra_flags.append("VL_API_DTF_SERVICE")
            if svc.stream:
                extra_flags.append("VL_API_DTF_STREAM")
        buf = []
        sw = buf.append
        sw("  .name = %s,\n" % _c_str(o.name))
        if cls == "Define":
            sw("  .kind = VL_API_DT_MESSAGE,\n")
            sw("  .id = VL_API_%s,\n" % o.name.upper())
            sw("  .crc = 0x%08x,\n" % o.crc)
            if options:
                sw("  .first_option = %d,\n" % first_option)
                sw("  .n_options = %d,\n" % options)
            if svc:
                if svc.reply != "null":
                    sw("  .reply = %d,\n" % self.msg_sym(svc.reply))
                if svc.stream_message:
                    sw("  .details = %d,\n" % self.msg_sym(svc.stream_message))
        else:
            sw(
                "  .kind = %s,\n"
                % ("VL_API_DT_UNION" if cls == "Union" else "VL_API_DT_TYPEDEF")
            )
        flags = self.type_flags(o)
        if extra_flags:
            flags = " | ".join(([flags] if flags != "0" else []) + extra_flags)
        sw("  .flags = %s,\n" % flags)
        sw("  .size = %d,\n" % self.size_of_obj(o))
        sw("  .n_fields = %d,\n" % len(fields))
        sw("  .first = %d,\n" % first_field)
        if brief:
            sw("  .brief = %s,\n" % _c_str(brief))
        sw("  .imported = %d,\n" % (0 if key in self.own or cls == "Define" else 1))
        self.add_struct(o, buf)
        self.emitted[key] = self.expr(o)
        return self.emitted[key]

    def default_c(self, value):
        """(kind, initializer) of the default value of a field"""
        if isinstance(value, bool):
            return "VL_API_DD_BOOL", ".i = %d" % int(value)
        if isinstance(value, int):
            return "VL_API_DD_INT", ".i = %dLL" % value
        if isinstance(value, float):
            return "VL_API_DD_FLOAT", ".f = %r" % value
        if isinstance(value, str):
            return "VL_API_DD_STRING", ".s = %s" % _c_str(value)
        raise ValueError("unknown type of the default value %r" % (value,))

    def add_options(self, opts):
        """Adds options to the array of the options of the file, returns the
        index of the first and the number of them. vat_help was the text of
        the vpp_api_test command."""
        opts = {k: v for k, v in opts.items() if k != "vat_help"}
        first = len(self.option_entries)
        for k, v in opts.items():
            if v is not None and not isinstance(v, str):
                raise ValueError("option %s is not a string" % k)
            self.option_entries.append(
                "  [%d] = { %s, %s },\n"
                % (len(self.option_entries), _c_str(k), _c_str(v))
            )
        return first, len(opts)

    def enum_value(self, name):
        """The value of an enum constant, the names of them are unique"""
        for o in _global_types().values():
            if o.__class__.__name__ in ("Enum", "EnumFlag"):
                for b in o.block:
                    if b[0] == name:
                        return b[1]
        raise ValueError("no enum value %s" % name)

    def type_flags(self, o):
        f = []
        if getattr(o, "manual_print", False):
            f.append("VL_API_DTF_MANUAL_PRINT")
        if getattr(o, "manual_endian", False):
            f.append("VL_API_DTF_MANUAL_ENDIAN")
        if getattr(o, "vla", False):
            f.append("VL_API_DTF_VLA")
        if getattr(o, "dont_trace", False):
            f.append("VL_API_DTF_DONT_TRACE")
        if getattr(o, "autoendian", 0):
            f.append("VL_API_DTF_AUTOENDIAN")
        return " | ".join(f) if f else "0"

    def build(self):
        s = self.s
        w = self.out.write
        # all types, imported ones included, in the order of the .api.json
        types = [self.emit_type(o) for o in self.type_list]
        msgs = [self.emit_type(o) for o in s["Define"]]

        m = self.module
        # the indices of the descriptors are 16 bit
        for n in (
            len(self.field_entries),
            len(self.value_entries),
            len(self.option_entries),
        ):
            if n > 0xFFFF:
                raise ValueError("%s has too many descriptor entries" % m)
        for name, ctype, entries in (
            ("fields", "vl_api_desc_field_t", self.field_entries),
            ("values", "vl_api_desc_enum_val_t", self.value_entries),
            ("options", "vl_api_desc_option_t", self.option_entries),
        ):
            if entries:
                w(
                    "static const %s %s_desc_%s[%d] = {\n"
                    % (ctype, m, name, len(entries))
                )
                w("".join(entries))
                w("};\n")

        for is_msg, name, count in (
            (False, "types", len(types)),
            (True, "msgs", len(msgs)),
        ):
            if not count:
                continue
            w(
                "static const vl_api_desc_type_t %s_desc_%s[%d] = {\n"
                % (self.module, name, count)
            )
            for i in range(count):
                body = "".join(
                    "  " + l + "\n"
                    for l in self.structs[(is_msg, i)].rstrip("\n").split("\n")
                )
                w("  [%d] = {\n%s  },\n" % (i, body))
            w("};\n")
        w(
            "const vl_api_desc_file_t %s_api_desc "
            '__attribute__ ((visibility ("hidden"))) = {\n' % self.module
        )
        w("  .module = %s,\n" % _c_str(self.module))
        # the CRC the .api.json file has, it covers the imported files too
        w("  .file_crc = 0x%x,\n" % s["imported"]["file_crc"])
        if types:
            w("  .n_types = %d,\n" % len(types))
            w("  .types = %s_desc_types,\n" % self.module)
        if msgs:
            w("  .n_msgs = %d,\n" % len(msgs))
            w("  .msgs = %s_desc_msgs,\n" % self.module)
        m = self.module
        if self.field_entries:
            w("  .fields = %s_desc_fields,\n" % m)
        if self.value_entries:
            w("  .values = %s_desc_values,\n" % m)
        if self.option_entries:
            w("  .options = %s_desc_options,\n" % m)
        w("  .n_options = %d,\n" % self.n_file_options)
        w("};\n\n")
        return self.out.getvalue()


def generate_desc(s, module, stream):
    """Write the API descriptor tables of a file to a source file which is
    compiled into the plugin or the library of the file, only files with messages
    have them"""
    stream.write(
        "/* API descriptors of {}.api, generated by vppapigen */\n\n".format(module)
    )
    if len(s["Define"]) > 0:
        stream.write("#include <stddef.h>\n")
        stream.write("#include <stdbool.h>\n")
        stream.write("#include <vlib/vlib.h>\n")
        stream.write("#include <vlibapi/api_types.h>\n")
        stream.write("#include <vlibapi/api_desc.h>\n")
        stream.write('#include "{}.api_enum.h"\n'.format(module))
        stream.write('#include "{}.api_types.h"\n\n'.format(module))
        stream.write(DescBuilder(module, s).build())
    else:
        # a source file has to have a declaration
        stream.write("typedef int {}_api_has_no_messages;\n".format(module))


#
# Plugin entry point
#
def run(output_dir, apifilename, s):
    """Main plugin entry point."""
    stream = StringIO()

    if not output_dir:
        sys.stderr.write("Missing --outputdir argument")
        return None

    basename = os.path.basename(apifilename)
    filename, _ = os.path.splitext(basename)
    modulename = filename.replace(".", "_")
    filename_enum = os.path.join(output_dir + "/" + basename + "_enum.h")
    filename_types = os.path.join(output_dir + "/" + basename + "_types.h")
    filename_c = os.path.join(output_dir + "/" + basename + ".c")
    filename_desc = os.path.join(output_dir + "/" + basename + "_desc.c")
    filename_c_test = os.path.join(output_dir + "/" + basename + "_test.c")
    filename_c_test2 = os.path.join(output_dir + "/" + basename + "_test2.c")

    # Generate separate types file
    st = StringIO()
    generate_include_types(s, modulename, st)
    with open(filename_types, "w") as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()

    # Generate separate enum file
    st = StringIO()
    st.write("#ifndef included_{}_api_enum_h\n".format(modulename))
    st.write("#define included_{}_api_enum_h\n".format(modulename))
    generate_include_enum(s, modulename, st)
    generate_include_counters(s["Counters"], st)
    st.write("#endif\n")
    with open(filename_enum, "w") as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()

    # Generate separate C file
    st = StringIO()
    generate_c_boilerplate(
        s, s["Service"], s["Define"], s["Counters"], s["file_crc"], modulename, st
    )
    with open(filename_c, "w") as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()

    # Generate the API descriptors
    st = StringIO()
    generate_desc(s, modulename, st)
    with open(filename_desc, "w") as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()

    # Generate separate C test file
    st = StringIO()
    plugin = bool("plugin" in apifilename)
    generate_c_test_boilerplate(
        s["Service"], s["Define"], s["file_crc"], modulename, plugin, st
    )
    with open(filename_c_test, "w") as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()

    # Fully autogenerated VATv2 C test file
    st = StringIO()
    generate_c_test2_boilerplate(s["Service"], s["Define"], modulename, st)
    with open(filename_c_test2, "w") as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()  #

    output = TOP_BOILERPLATE.format(datestring=DATESTRING, input_filename=basename)
    output += generate_imports(s["Import"])
    output += msg_ids(s)
    output += msg_names(s)
    output += msg_name_crc_list(s, filename)
    output += typedefs(modulename)
    printfun_types(s["types"], stream, modulename)
    output += stream.getvalue()
    stream.close()
    output += version_tuple(s, basename)
    output += BOTTOM_BOILERPLATE.format(input_filename=basename, file_crc=s["file_crc"])

    return output
