# C generation
import datetime
import os
import shutil
import sys
import time
from io import StringIO

datestring = datetime.datetime.utcfromtimestamp(
    int(os.environ.get('SOURCE_DATE_EPOCH', time.time())))
input_filename = 'inputfil'
top_boilerplate = '''\
/*
 * VLIB API definitions {datestring}
 * Input file: {input_filename}
 * Automatically generated: please edit the input file NOT this file!
 */

#include <stdbool.h>
#if defined(vl_msg_id)||defined(vl_union_id) \\
    || defined(vl_printfun) ||defined(vl_endianfun) \\
    || defined(vl_api_version)||defined(vl_typedefs) \\
    || defined(vl_msg_name)||defined(vl_msg_name_crc_list) \\
    || defined(vl_api_version_tuple)
/* ok, something was selected */
#else
#warning no content included from {input_filename}
#endif

#define VL_API_PACKED(x) x __attribute__ ((packed))
'''

bottom_boilerplate = '''\
/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version({input_filename}, {file_crc:#08x})

#endif
'''


def msg_ids(s):
    output = '''\

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
'''

    for t in s['Define']:
        output += "vl_msg_id(VL_API_%s, vl_api_%s_t_handler)\n" % \
                  (t.name.upper(), t.name)
    output += "#endif"

    return output


def msg_names(s):
    output = '''\

/****** Message names ******/

#ifdef vl_msg_name
'''

    for t in s['Define']:
        dont_trace = 0 if t.dont_trace else 1
        output += "vl_msg_name(vl_api_%s_t, %d)\n" % (t.name, dont_trace)
    output += "#endif"

    return output


def msg_name_crc_list(s, suffix):
    output = '''\

/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
'''
    output += "#define foreach_vl_msg_name_crc_%s " % suffix

    for t in s['Define']:
        output += "\\\n_(VL_API_%s, %s, %08x) " % \
                   (t.name.upper(), t.name, t.crc)
    output += "\n#endif"

    return output


def api2c(fieldtype):
    mappingtable = {'string': 'vl_api_string_t', }
    if fieldtype in mappingtable:
        return mappingtable[fieldtype]
    return fieldtype


def typedefs(filename):

    output = '''\

/****** Typedefs ******/

#ifdef vl_typedefs
#include "{include}.api_types.h"
#endif
'''.format(include=filename)
    return output


format_strings = {'u8': '%u',
                  'bool': '%u',
                  'i8': '%d',
                  'u16': '%u',
                  'i16': '%d',
                  'u32': '%u',
                  'i32': '%ld',
                  'u64': '%llu',
                  'i64': '%llu',
                  'f64': '%.2f'}

noprint_fields = {'_vl_msg_id': None,
                  'client_index': None,
                  'context': None}


class Printfun():
    _dispatch = {}

    def __init__(self, stream):
        self.stream = stream

    def print_string(self, o, stream):
        write = stream.write
        if o.modern_vla:
            write('    if (vl_api_string_len(&a->{f}) > 0) {{\n'
                  .format(f=o.fieldname))
            write('        s = format(s, "\\n%U{f}: %.*s", '
                  'format_white_space, indent, '
                  'vl_api_string_len(&a->{f}) - 1, '
                  'vl_api_from_api_string(&a->{f}));\n'.format(f=o.fieldname))
            write('    } else {\n')
            write('        s = format(s, "\\n%U{f}:", '
                  'format_white_space, indent);\n'.format(f=o.fieldname))
            write('    }\n')
        else:
            write('    s = format(s, "\\n%U{f}: %s", '
                  'format_white_space, indent, a->{f});\n'
                  .format(f=o.fieldname))

    def print_field(self, o, stream):
        write = stream.write
        if o.fieldname in noprint_fields:
            return
        if o.fieldtype in format_strings:
            f = format_strings[o.fieldtype]
            write('    s = format(s, "\\n%U{n}: {f}", '
                  'format_white_space, indent, a->{n});\n'
                  .format(n=o.fieldname, f=f))
        else:
            write('    s = format(s, "\\n%U{n}: %U", '
                  'format_white_space, indent, '
                  'format_{t}, &a->{n}, indent);\n'
                  .format(n=o.fieldname, t=o.fieldtype))

    _dispatch['Field'] = print_field

    def print_array(self, o, stream):
        write = stream.write

        forloop = '''\
    for (i = 0; i < {lfield}; i++) {{
        s = format(s, "\\n%U{n}: %U",
                   format_white_space, indent, format_{t}, &a->{n}[i], indent);
    }}
'''

        forloop_format = '''\
    for (i = 0; i < {lfield}; i++) {{
        s = format(s, "\\n%U{n}: {t}",
                   format_white_space, indent, a->{n}[i]);
    }}
'''

        if o.fieldtype == 'string':
            return self.print_string(o, stream)

        if o.fieldtype == 'u8':
            if o.lengthfield:
                write('    s = format(s, "\\n%U{n}: %U", format_white_space, '
                      'indent, format_hex_bytes, a->{n}, a->{lfield});\n'
                      .format(n=o.fieldname, lfield=o.lengthfield))
            else:
                write('    s = format(s, "\\n%U{n}: %U", format_white_space, '
                      'indent, format_hex_bytes, a, {lfield});\n'
                      .format(n=o.fieldname, lfield=o.length))
            return

        lfield = 'a->' + o.lengthfield if o.lengthfield else o.length
        if o.fieldtype in format_strings:
            write(forloop_format.format(lfield=lfield,
                                        t=format_strings[o.fieldtype],
                                        n=o.fieldname))
        else:
            write(forloop.format(lfield=lfield, t=o.fieldtype, n=o.fieldname))

    _dispatch['Array'] = print_array

    def print_alias(self, k, v, stream):
        write = stream.write
        if ('length' in v.alias and v.alias['length'] and
                v.alias['type'] == 'u8'):
            write('    return format(s, "%U", format_hex_bytes, a, {});\n'
                  .format(v.alias['length']))
        elif v.alias['type'] in format_strings:
            write('    return format(s, "{}", *a);\n'
                  .format(format_strings[v.alias['type']]))
        else:
            write('    return format(s, "{} (print not implemented)");\n'
                  .format(k))

    def print_enum(self, o, stream):
        write = stream.write
        write("    switch(*a) {\n")
        for b in o:
            write("    case %s:\n" % b[1])
            write('        return format(s, "{}");\n'.format(b[0]))
        write('    }\n')

    _dispatch['Enum'] = print_enum

    def print_obj(self, o, stream):
        write = stream.write

        if o.type in self._dispatch:
            self._dispatch[o.type](self, o, stream)
        else:
            write('    s = format(s, "\\n{} {} {} (print not implemented");\n'
                  .format(o.type, o.fieldtype, o.fieldname))


def printfun(objs, stream, modulename):
    write = stream.write

    h = '''\
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_{module}_printfun
#define included_{module}_printfun

#ifdef LP64
#define _uword_fmt \"%lld\"
#define _uword_cast (long long)
#else
#define _uword_fmt \"%ld\"
#define _uword_cast long
#endif

'''

    signature = '''\
static inline void *vl_api_{name}_t_print (vl_api_{name}_t *a, void *handle)
{{
    u8 *s = 0;
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
'''

    h = h.format(module=modulename)
    write(h)

    pp = Printfun(stream)
    for t in objs:
        if t.manual_print:
            write("/***** manual: vl_api_%s_t_print  *****/\n\n" % t.name)
            continue
        write(signature.format(name=t.name))
        write('    /* Message definition: vl_api_{}_t: */\n'.format(t.name))
        write("    s = format(s, \"vl_api_%s_t:\");\n" % t.name)
        for o in t.block:
            pp.print_obj(o, stream)
        write('    vec_add1(s, 0);\n')
        write('    vl_print (handle, (char *)s);\n')
        write('    vec_free (s);\n')
        write('    return handle;\n')
        write('}\n\n')

    write("\n#endif")
    write("\n#endif /* vl_printfun */\n")

    return ''


def printfun_types(objs, stream, modulename):
    write = stream.write
    pp = Printfun(stream)

    h = '''\
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_{module}_printfun_types
#define included_{module}_printfun_types

'''
    h = h.format(module=modulename)
    write(h)

    signature = '''\
static inline u8 *format_vl_api_{name}_t (u8 *s, va_list * args)
{{
    vl_api_{name}_t *a = va_arg (*args, vl_api_{name}_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
'''

    for t in objs:
        if t.__class__.__name__ == 'Enum':
            write(signature.format(name=t.name))
            pp.print_enum(t.block, stream)
            write('    return s;\n')
            write('}\n\n')
            continue

        if t.manual_print:
            write("/***** manual: vl_api_%s_t_print  *****/\n\n" % t.name)
            continue

        if t.__class__.__name__ == 'Using':
            write(signature.format(name=t.name))
            pp.print_alias(t.name, t, stream)
            write('}\n\n')
            continue

        write(signature.format(name=t.name))
        for o in t.block:
            pp.print_obj(o, stream)

        write('    return s;\n')
        write('}\n\n')

    write("\n#endif")
    write("\n#endif /* vl_printfun_types */\n")


def imports(imports):
    output = '/* Imported API files */\n'
    output += '#ifndef vl_api_version\n'

    for i in imports:
        s = i.filename.replace('plugins/', '')
        output += '#include <{}.h>\n'.format(s)
    output += '#endif\n'
    return output


endian_strings = {
    'u16': 'clib_net_to_host_u16',
    'u32': 'clib_net_to_host_u32',
    'u64': 'clib_net_to_host_u64',
    'i16': 'clib_net_to_host_u16',
    'i32': 'clib_net_to_host_u32',
    'i64': 'clib_net_to_host_u64',
    'f64': 'clib_net_to_host_u64',
}


def endianfun_array(o):
    forloop = '''\
    for (i = 0; i < {length}; i++) {{
        a->{name}[i] = {format}(a->{name}[i]);
    }}
'''

    forloop_format = '''\
    for (i = 0; i < {length}; i++) {{
        {type}_endian(&a->{name}[i]);
    }}
'''

    output = ''
    if o.fieldtype == 'u8' or o.fieldtype == 'string':
        output += '    /* a->{n} = a->{n} (no-op) */\n'.format(n=o.fieldname)
    else:
        lfield = 'a->' + o.lengthfield if o.lengthfield else o.length
        if o.fieldtype in endian_strings:
            output += (forloop
                       .format(length=lfield,
                               format=endian_strings[o.fieldtype],
                               name=o.fieldname))
        else:
            output += (forloop_format
                       .format(length=lfield, type=o.fieldtype,
                               name=o.fieldname))
    return output


def endianfun_obj(o):
    output = ''
    if o.type == 'Array':
        return endianfun_array(o)
    elif o.type != 'Field':
        output += ('    s = format(s, "\\n{} {} {} (print not implemented");\n'
                   .format(o.type, o.fieldtype, o.fieldname))
        return output
    if o.fieldtype in endian_strings:
        output += ('    a->{name} = {format}(a->{name});\n'
                   .format(name=o.fieldname,
                           format=endian_strings[o.fieldtype]))
    elif o.fieldtype.startswith('vl_api_'):
        output += ('    {type}_endian(&a->{name});\n'
                   .format(type=o.fieldtype, name=o.fieldname))
    else:
        output += '    /* a->{n} = a->{n} (no-op) */\n'.format(n=o.fieldname)

    return output


def endianfun(objs, modulename):
    output = '''\

/****** Endian swap functions *****/\n\
#ifdef vl_endianfun
#ifndef included_{module}_endianfun
#define included_{module}_endianfun

#undef clib_net_to_host_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#endif

'''
    output = output.format(module=modulename)

    signature = '''\
static inline void vl_api_{name}_t_endian (vl_api_{name}_t *a)
{{
    int i __attribute__((unused));
'''

    for t in objs:
        if t.__class__.__name__ == 'Enum':
            output += signature.format(name=t.name)
            if t.enumtype in endian_strings:
                output += ('    *a = {}(*a);\n'
                           .format(endian_strings[t.enumtype]))
            else:
                output += ('    /* a->{name} = a->{name} (no-op) */\n'
                           .format(name=t.name))

            output += '}\n\n'
            continue

        if t.manual_endian:
            output += "/***** manual: vl_api_%s_t_endian  *****/\n\n" % t.name
            continue


        if t.__class__.__name__ == 'Using':
            output += signature.format(name=t.name)
            if ('length' in t.alias and t.alias['length'] and
                    t.alias['type'] == 'u8'):
                output += ('    /* a->{name} = a->{name} (no-op) */\n'
                           .format(name=t.name))
            elif t.alias['type'] in format_strings:
                output += ('    *a = {}(*a);\n'
                           .format(endian_strings[t.alias['type']]))
            else:
                output += '    /* Not Implemented yet {} */'.format(t.name)
            output += '}\n\n'
            continue

        output += signature.format(name=t.name)

        for o in t.block:
            output += endianfun_obj(o)
        output += '}\n\n'

    output += "\n#endif"
    output += "\n#endif /* vl_endianfun */\n\n"

    return output


def version_tuple(s, module):
    output = '''\
/****** Version tuple *****/

#ifdef vl_api_version_tuple

'''
    if 'version' in s['Option']:
        v = s['Option']['version']
        (major, minor, patch) = v.split('.')
        output += "vl_api_version_tuple(%s, %s, %s, %s)\n" % \
                  (module, major, minor, patch)

    output += "\n#endif /* vl_api_version_tuple */\n\n"

    return output


def generate_include_enum(s, module, stream):
    write = stream.write

    if len(s['Define']):
        write('typedef enum {\n')
        for t in s['Define']:
            write('   VL_API_{},\n'.format(t.name.upper()))
        write('   VL_MSG_FIRST_AVAILABLE\n')
        write('}} vl_api_{}_enum_t;\n'.format(module))

#
# Generate separate API _types file.
#
def generate_include_types(s, module, stream):
    write = stream.write

    write('#ifndef included_{module}_api_types_h\n'.format(module=module))
    write('#define included_{module}_api_types_h\n'.format(module=module))

    if len(s['Import']):
        write('/* Imported API files */\n')
        for i in s['Import']:
            filename = i.filename.replace('plugins/', '')
            write('#include <{}_types.h>\n'.format(filename))

    for o in s['types'] + s['Define']:
        tname = o.__class__.__name__
        if tname == 'Using':
            if 'length' in o.alias:
                write('typedef %s vl_api_%s_t[%s];\n' % (o.alias['type'], o.name, o.alias['length']))
            else:
                write('typedef %s vl_api_%s_t;\n' % (o.alias['type'], o.name))
        elif tname == 'Enum':
            if o.enumtype == 'u32':
                write("typedef enum {\n")
            else:
                write("typedef enum __attribute__((packed)) {\n")

            for b in o.block:
                write("    %s = %s,\n" % (b[0], b[1]))
            write('} vl_api_%s_t;\n' % o.name)
            if o.enumtype != 'u32':
                size1 = 'sizeof(vl_api_%s_t)' % o.name
                size2 = 'sizeof(%s)' % o.enumtype
                err_str = 'size of API enum %s is wrong' % o.name
                write('STATIC_ASSERT(%s == %s, "%s");\n'
                      % (size1, size2, err_str))
        else:
            if tname == 'Union':
                write("typedef union __attribute__ ((packed)) _vl_api_%s {\n" % o.name)
            else:
                write(("typedef struct __attribute__ ((packed)) _vl_api_%s {\n")
                           % o.name)
            for b in o.block:
                if b.type == 'Option':
                    continue
                if b.type == 'Field':
                      write("    %s %s;\n" % (api2c(b.fieldtype),
                                              b.fieldname))
                elif b.type == 'Array':
                    if b.lengthfield:
                      write("    %s %s[0];\n" % (api2c(b.fieldtype),
                                                 b.fieldname))
                    else:
                        # Fixed length strings decay to nul terminated u8
                        if b.fieldtype == 'string':
                            if b.modern_vla:
                                write('    {} {};\n'
                                      .format(api2c(b.fieldtype),
                                              b.fieldname))
                            else:
                                write('    u8 {}[{}];\n'
                                      .format(b.fieldname, b.length))
                        else:
                            write("    %s %s[%s];\n" %
                                  (api2c(b.fieldtype), b.fieldname,
                                   b.length))
                else:
                    raise ValueError("Error in processing type {} for {}"
                                     .format(b, o.name))

            write('} vl_api_%s_t;\n' % o.name)

    write("\n#endif\n")


def generate_c_boilerplate(services, defines, file_crc, module, stream):
    write = stream.write

    hdr = '''\
#define vl_endianfun		/* define message structures */
#include "{module}.api.h"
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include "{module}.api.h"
#undef vl_printfun

'''

    write(hdr.format(module=module))
    write('static u16\n')
    write('setup_message_id_table (void) {\n')
    write('   api_main_t *am = &api_main;\n')
    write('   u16 msg_id_base = vl_msg_api_get_msg_ids ("{}_{crc:08x}", VL_MSG_FIRST_AVAILABLE);\n'
          .format(module, crc=file_crc))


    for d in defines:
        write('   vl_msg_api_add_msg_name_crc (am, "{n}_{crc:08x}",\n'
              '                                VL_API_{ID} + msg_id_base);\n'
              .format(n=d.name, ID=d.name.upper(), crc=d.crc))
    for s in services:
        write('   vl_msg_api_set_handlers(VL_API_{ID} + msg_id_base, "{n}",\n'
              '                           vl_api_{n}_t_handler, vl_noop_handler,\n'
              '                           vl_api_{n}_t_endian, vl_api_{n}_t_print,\n'
              '                           sizeof(vl_api_{n}_t), 1);\n'
              .format(n=s.caller, ID=s.caller.upper()))

    write('   return msg_id_base;\n')
    write('}\n')


def generate_c_test_plugin_boilerplate(services, defines, file_crc, module, stream):
    write = stream.write

    define_hash = {d.name:d for d in defines}
    replies = {}

    hdr = '''\
#define vl_endianfun		/* define message structures */
#include "{module}.api.h"
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include "{module}.api.h"
#undef vl_printfun

'''

    write(hdr.format(module=module))
    for s in services:
        try:
            d = define_hash[s.reply]
        except:
            continue
        if d.manual_print:
            write('/* Manual definition requested for: vl_api_{n}_t_hander() */\n'
                  .format(n=s.reply))
            continue
        if not define_hash[s.caller].autoreply:
            write('/* Only autoreply is supported (vl_api_{n}_t_hander()) */\n'
                  .format(n=s.reply))
            continue
        write('#ifndef VL_API_{n}_T_HANLDER\n'.format(n=s.reply.upper()))
        write('static void\n')
        write('vl_api_{n}_t_handler (vl_api_{n}_t * mp) {{\n'.format(n=s.reply))
        write('   vat_main_t * vam = {}_test_main.vat_main;\n'.format(module))
        write('   i32 retval = ntohl(mp->retval);\n')
        write('   if (vam->async_mode) {\n')
        write('      vam->async_errors += (retval < 0);\n')
        write('   } else {\n')
        write('      vam->retval = retval;\n')
        write('      vam->result_ready = 1;\n')
        write('   }\n')
        write('}\n')
        write('#endif\n')

        for e in s.events:
            if define_hash[e].manual_print:
                continue
            write('static void\n')
            write('vl_api_{n}_t_handler (vl_api_{n}_t * mp) {{\n'.format(n=e))
            write('    vl_print(0, "{n} event called:");\n'.format(n=e))
            write('    vl_api_{n}_t_print(mp, 0);\n'.format(n=e))
            write('}\n')

    write('static void\n')
    write('setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {\n')
    for s in services:
        write('   vl_msg_api_set_handlers(VL_API_{ID} + msg_id_base, "{n}",\n'
              '                           vl_api_{n}_t_handler, vl_noop_handler,\n'
              '                           vl_api_{n}_t_endian, vl_api_{n}_t_print,\n'
              '                           sizeof(vl_api_{n}_t), 1);\n'
              .format(n=s.reply, ID=s.reply.upper()))
        write('   hash_set_mem (vam->function_by_name, "{n}", api_{n});\n'.format(n=s.caller))
        try:
            write('   hash_set_mem (vam->help_by_name, "{n}", "{help}");\n'
                  .format(n=s.caller, help=define_hash[s.caller].options['vat_help']))
        except:
            pass

        # Events
        for e in s.events:
            write('   vl_msg_api_set_handlers(VL_API_{ID} + msg_id_base, "{n}",\n'
                  '                           vl_api_{n}_t_handler, vl_noop_handler,\n'
                  '                           vl_api_{n}_t_endian, vl_api_{n}_t_print,\n'
                  '                           sizeof(vl_api_{n}_t), 1);\n'
                  .format(n=e, ID=e.upper()))

    write('}\n')

    write('clib_error_t * vat_plugin_register (vat_main_t *vam)\n')
    write('{\n')
    write('   {n}_test_main_t * mainp = &{n}_test_main;\n'.format(n=module))
    write('   mainp->vat_main = vam;\n')
    write('   mainp->msg_id_base = vl_client_get_first_plugin_msg_id ("{n}_{crc:08x}");\n'
          .format(n=module, crc=file_crc))
    write('   if (mainp->msg_id_base == (u16) ~0)\n')
    write('      return clib_error_return (0, "{} plugin not loaded...");\n'.format(module))
    write('   setup_message_id_table (vam, mainp->msg_id_base);\n')
    write('#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE\n')
    write('    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);\n')
    write('#endif\n')
    write('   return 0;\n')
    write('}\n')


#
# Plugin entry point
#
def run(args, input_filename, s):
    stream = StringIO()

    if not args.outputdir:
        sys.stderr.write('Missing --outputdir argument')
        return None

    basename = os.path.basename(input_filename)
    filename, file_extension = os.path.splitext(basename)
    modulename = filename.replace('.', '_')
    filename_enum = os.path.join(args.outputdir + '/' + basename + '_enum.h')
    filename_types = os.path.join(args.outputdir + '/' + basename + '_types.h')
    filename_c = os.path.join(args.outputdir + '/' + basename + '.c')
    filename_c_test = os.path.join(args.outputdir + '/' + basename + '_test.c')

    # Generate separate types file
    st = StringIO()
    generate_include_types(s, modulename, st)
    with open (filename_types, 'w') as fd:
        st.seek (0)
        shutil.copyfileobj (st, fd)
    st.close()

    # Generate separate enum file
    st = StringIO()
    generate_include_enum(s, modulename, st)
    with open (filename_enum, 'w') as fd:
        st.seek (0)
        shutil.copyfileobj (st, fd)
    st.close()

    # Generate separate C file
    st = StringIO()
    generate_c_boilerplate(s['Service'], s['Define'], s['file_crc'],
                           modulename, st)
    with open (filename_c, 'w') as fd:
        st.seek (0)
        shutil.copyfileobj(st, fd)
    st.close()

    # Generate separate C test file
    # This is only supported for plugins at the moment
    st = StringIO()
    generate_c_test_plugin_boilerplate(s['Service'], s['Define'], s['file_crc'],
                                       modulename, st)
    with open (filename_c_test, 'w') as fd:
        st.seek (0)
        shutil.copyfileobj(st, fd)
    st.close()

    output = top_boilerplate.format(datestring=datestring,
                                    input_filename=basename)
    output += imports(s['Import'])
    output += msg_ids(s)
    output += msg_names(s)
    output += msg_name_crc_list(s, filename)
    output += typedefs(modulename)
    printfun_types(s['types'], stream, modulename)
    printfun(s['Define'], stream, modulename)
    output += stream.getvalue()
    stream.close()
    output += endianfun(s['types'] + s['Define'], modulename)
    output += version_tuple(s, basename)
    output += bottom_boilerplate.format(input_filename=basename,
                                        file_crc=s['file_crc'])

    return output
