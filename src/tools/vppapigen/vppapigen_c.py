# C generation
import datetime
import os
import time

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


def typedefs(objs, aliases, filename):
    name = filename.replace('.', '_')
    output = '''\


/****** Typedefs ******/

#ifdef vl_typedefs
#ifndef included_{module}_typedef
#define included_{module}_typedef
'''
    output = output.format(module=name)

    for k, v in aliases.items():
        if 'length' in v.alias:
            output +=  'typedef %s vl_api_%s_t[%s];\n' % (v.alias['type'], k, v.alias['length'])
        else:
            output += 'typedef %s vl_api_%s_t;\n' % (v.alias['type'], k)

    for o in objs:
        tname = o.__class__.__name__
        if tname == 'Enum':
            if o.enumtype == 'u32':
                output += "typedef enum {\n"
            else:
                output += "typedef enum __attribute__((__packed__)) {\n"

            for b in o.block:
                output += "    %s = %s,\n" % (b[0], b[1])
            output += '} vl_api_%s_t;\n' % o.name
            if o.enumtype != 'u32':
                size1 = 'sizeof(vl_api_%s_t)' % o.name
                size2 = 'sizeof(%s)' % o.enumtype
                err_str = 'size of API enum %s is wrong' % o.name
                output += 'STATIC_ASSERT(%s == %s, "%s");\n' % (size1, size2, err_str)
        else:
            if tname == 'Union':
                output += "typedef VL_API_PACKED(union _vl_api_%s {\n" % o.name
            else:
                output += "typedef VL_API_PACKED(struct _vl_api_%s {\n" % o.name
            for b in o.block:
                if b.type == 'Option': continue
                if b.type == 'Field':
                    output += "    %s %s;\n" % (api2c(b.fieldtype), b.fieldname)
                elif b.type == 'Array':
                    if b.lengthfield:
                        output += "    %s %s[0];\n" % (api2c(b.fieldtype), b.fieldname)
                    else:
                        output += "    %s %s[%s];\n" % (api2c(b.fieldtype), b.fieldname,
                                                        b.length)
                else:
                    raise ValueError("Error in processing type {} for {}".format(b, o.name))

            output += '}) vl_api_%s_t;\n' % o.name

    output += "\n#endif"
    output += "\n#endif\n\n"

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
                  'f64': '%.2f',
                  'string': {'format': '%U',
                             'func': 'vl_api_format_string'},
}


def printfun(objs, modulename):
    output = '''\
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

    output = output.format(module=modulename)

    signature = '''\
static inline void *vl_api_{name}_t_print (vl_api_{name}_t *a, void *handle)
{{
    u8 *s = 0;
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
'''

    #output += "#include <vppinfra/format.h>\n"

    for t in objs:
        if t.manual_print:
            output += "/***** manual: vl_api_%s_t_print  *****/\n\n" % t.name
            ### output += "void * vl_api_{}_t_print (vl_api_{}_t *, void *);\n".format(t.name, t.name)
            continue
        output += signature.format(name=t.name)
        output += '    /* Message definition: vl_api_{}_t: */\n'.format(t.name)
        output += "    s = format(s, \"vl_api_%s_t:\");\n" % t.name
        for o in t.block:
            output += printfun_obj(o)

        output += '    vl_print (handle, (char *)s);\n'
        output += '    vec_free (s);\n'
        output += '    return handle;\n'
        output += '}\n\n'

    output += "\n#endif"
    output += "\n#endif /* vl_printfun */\n"

    return output

def printfun_array(o):
    forloop = '''\
    for (i = 0; i < {length}; i++) {{
        s = format(s, "\\n%U{name}: %U", format_white_space, indent, format_{type}, &a->{name}[i], indent);
    }}
'''

    forloop_format = '''\
    for (i = 0; i < {length}; i++) {{
        s = format(s, "\\n%U{name}: {type}", format_white_space, indent, &a->{name}[i], indent);
    }}
'''

    output = ''
    if o.fieldtype == 'u8':
        if o.lengthfield:
            output += ('    s = format(s, "\\n%U{name}: %U", format_white_space, '
                       'indent, format_hex_bytes, a->{name}, a->{length});\n').format(name=o.fieldname, length=o.lengthfield)
        else:
            output += ('    s = format(s, "\\n%U{}: %U", format_white_space, '
                       'indent, format_hex_bytes, a, {});\n').format(o.fieldname, o.length)
    else:
        l = 'a->' + o.lengthfield if o.lengthfield else o.length
        if o.fieldtype in format_strings:
            output += forloop_format.format(length=l, type=format_strings[o.fieldtype], name=o.fieldname)
        else:
            output += forloop.format(length=l, type=o.fieldtype, name=o.fieldname)
    return output


def printfun_obj(o):
    output = ''
    if o.type == 'Array':
        return printfun_array(o)
    elif o.type != 'Field':
        output += '    s = format(s, "\\n{} {} {} (print not implemented");\n'.format(o.type, o.fieldtype, o.fieldname)
        return output
    if o.fieldtype in format_strings:
        if type(format_strings[o.fieldtype]) is dict:
            output += ('    s = format(s, "\\n%U{}: {}", format_white_space, '
                       'indent, {}, &a->{});\n').format(o.fieldname, format_strings[o.fieldtype]['format'],
                                                        format_strings[o.fieldtype]['func'], o.fieldname)
        else:
            try:
                if o.vla_len:
                    return output
            except AttributeError:
                pass

            output += '    s = format(s, "\\n%U{}: {}", format_white_space, indent, a->{});\n'.format(o.fieldname, format_strings[o.fieldtype],
                                                                          o.fieldname)
    else:
        output += '    s = format(s, "\\n%U{name}: %U", format_white_space, indent, format_{type}, &a->{name}, indent);\n'.format(name=o.fieldname, type=o.fieldtype)
    return output

def printfun_types(objs, aliases, modulename):
    output = '''\
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_{module}_printfun_types
#define included_{module}_printfun_types

'''
    output = output.format(module=modulename)

    signature = '''\
static inline u8 *format_vl_api_{name}_t (u8 *s, va_list * args)
{{
    vl_api_{name}_t *a = va_arg (*args, vl_api_{name}_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
'''

    for k, v in aliases.items():
        if v.manual_print:
            output += "/***** manual: vl_api_%s_t_print  *****/\n\n" % k
            ### output += "u8 * format_vl_api_{}_t (u8 *, va_list *args);\n".format(t.name)
            continue

        output += signature.format(name=k)
        if 'length' in v.alias and v.alias['length'] and v.alias['type'] == 'u8':
            output += '    return format(s, "%U", format_hex_bytes, a, {});\n'.format(v.alias['length'])
        elif v.alias['type'] in format_strings:
            output += '    return format(s, "{}", *a);\n'.format(format_strings[v.alias['type']])
        else:
            output += '    return format(s, "{} (print not implemented)"'.format(k)
        output += '}\n\n'


    for t in objs:
        if t.__class__.__name__ == 'Enum':
            output += signature.format(name=t.name)
            output += "    switch(*a) {\n"
            for b in t.block:
                output += "    case %s:\n" % b[1]
                output += '        return format(s, "{}");\n'.format(b[0])
            output += '    }\n'
            output += '    return s;\n'
            output += '}\n\n'

            continue

        if t.manual_print:
            output += "/***** manual: vl_api_%s_t_print  *****/\n\n" % t.name
            continue

        output += signature.format(name=t.name)
        for o in t.block:
            output += printfun_obj(o)

        output += '    return s;\n'
        output += '}\n\n'


    output += "\n#endif"
    output += "\n#endif /* vl_printfun */\n"

    return output


def imports(imports):
    output = '/* Imported API files */\n'
    output += '#ifndef vl_api_version\n'

    for i in imports:
        s = i.filename.replace('plugins/','')
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
        {format}(a->{name}[i]);
    }}
'''

    forloop_format = '''\
    for (i = 0; i < {length}; i++) {{
        {type}_endian(&a->{name}[i]);
    }}
'''

    output = ''
    if o.fieldtype == 'u8':
        output += '    /* a->{n} = a->{n} (no-op) */\n'.format(n=o.fieldname)
    else:
        l = 'a->' + o.lengthfield if o.lengthfield else o.length
        if o.fieldtype in endian_strings:
            output += forloop.format(length=l, format=endian_strings[o.fieldtype], name=o.fieldname)
        else:
            output += forloop_format.format(length=l, type=o.fieldtype, name=o.fieldname)
    return output


def endianfun_obj(o):
    output = ''
    if o.type == 'Array':
        return endianfun_array(o)
    elif o.type != 'Field':
        output += '    s = format(s, "\\n{} {} {} (print not implemented");\n'.format(o.type, o.fieldtype, o.fieldname)
        return output
    if o.fieldtype in endian_strings:
        try:
            if o.vla_len:
                return output
        except AttributeError:
            pass
        output += '    a->{name} = {format}(a->{name});\n'.format(name=o.fieldname, format=endian_strings[o.fieldtype])
    elif o.fieldtype.startswith('vl_api_'):
        output += '    {type}_endian(&a->{name});\n'.format(type=o.fieldtype, name=o.fieldname)
    else:
        output += '    /* a->{n} = a->{n} (no-op) */\n'.format(n=o.fieldname)

    return output


def endianfun(objs, aliases, modulename):
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

    for k, v in aliases.items():
        if v.manual_endian:
            output += "/***** manual: vl_api_%s_t_endian  *****/\n\n" % k
            ### output += "u8 * format_vl_api_{}_t (u8 *, va_list *args);\n".format(t.name)
            continue

        output += signature.format(name=k)
        if 'length' in v.alias and v.alias['length'] and v.alias['type'] == 'u8':
            output += '    /* a->{name} = a->{name} (no-op) */\n'.format(name=k)
        elif v.alias['type'] in format_strings:
            output += '    *a = {}(*a);\n'.format(endian_strings[v.alias['type']])
        else:
            output += '    /* Not Implemented yet {} */'.format(k)
        output += '}\n\n'


    for t in objs:
        if t.__class__.__name__ == 'Enum':
            output += signature.format(name=t.name)
            if t.enumtype in endian_strings:
                output += '    *a = {}(*a);\n'.format(endian_strings[t.enumtype])
            else:
                output += '    /* a->{name} = a->{name} (no-op) */\n'.format(name=t.name)

            output += '}\n\n'
            continue

        if t.manual_endian:
            output += "/***** manual: vl_api_%s_t_endian  *****/\n\n" % t.name
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


#
# Plugin entry point
#
def run(input_filename, s):
    basename = os.path.basename(input_filename)
    filename, file_extension = os.path.splitext(basename)
    modulename = filename.replace('.', '_')

    output = top_boilerplate.format(datestring=datestring,
                                    input_filename=basename)
    output += imports(s['Import'])
    output += msg_ids(s)
    output += msg_names(s)
    output += msg_name_crc_list(s, filename)
    output += typedefs(s['types'] + s['Define'], s['Alias'], filename + file_extension)
    output += printfun_types(s['types'], s['Alias'], modulename)
    output += printfun(s['Define'], modulename)
    output += endianfun(s['types'] + s['Define'], s['Alias'],  modulename)
    output += version_tuple(s, basename)
    output += bottom_boilerplate.format(input_filename=basename,
                                        file_crc=s['file_crc'])

    return output
