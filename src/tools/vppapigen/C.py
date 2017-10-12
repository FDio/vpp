# C generation

import datetime
import os

datestring = datetime.datetime.now()
input_filename = 'inputfil'
top_boilerplate = '''\
/*
 * VLIB API definitions {datestring}
 * Input file: {input_filename}
 * Automatically generated: please edit the input file NOT this file!
 */

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

    for t in s['defines']:
        output += "vl_msg_id(VL_API_%s, vl_api_%s_t_handler)\n" % \
                  (t.name.upper(), t.name)
    output += "#endif"

    return output


def msg_names(s):
    output = '''\

/****** Message names ******/

#ifdef vl_msg_name
'''

    for t in s['defines']:
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

    for t in s['defines']:
        output += "\\\n_(VL_API_%s, %s, %08x) " % \
                   (t.name.upper(), t.name, t.crc)
    output += "\n#endif"

    return output


def typedefs(s, filename):
    name = filename.replace('.', '_')
    output = '''\


/****** Typedefs ******/

#ifdef vl_typedefs
#ifndef included_{module}
#define included_{module}
'''
    output = output.format(module=name)
    for e in s['enums']:
        output += "typedef enum {\n"
        for b in e.block:
            output += "    %s = %s,\n" % (b[0], b[1])
        output += '} vl_api_%s_t;\n\n' % e.name

    for t in s['typedefs'] + s['defines']:
        output += "typedef VL_API_PACKED(struct _vl_api_%s {\n" % t.name
        for b in t.block:
            if len(b) == 3:
                if type(b[2]) is str:
                    output += "    %s %s[0];\n" % (b[0], b[1])
                else:
                    output += "    %s %s[%s];\n" % (b[0], b[1], b[2])
            elif len(b) == 2:
                output += "    %s %s;\n" % (b[0], b[1])
            else:
                raise ValueError("Error in processing array type %s" % b)
        output += '}) vl_api_%s_t;\n\n' % t.name

    output += "\n#endif"
    output += "\n#endif\n\n"

    return output


format_strings = {'u8': '%u',
                  'i8': '%d',
                  'u16': '%u',
                  'i16': '%d',
                  'u32': '%u',
                  'i32': '%ld',
                  'u64': '%llu',
                  'i64': '%llu',
                  'f64': '%.2f', }


def printfun(s):
    output = '''\
/****** Print functions *****/
#ifdef vl_printfun

#ifdef LP64
#define _uword_fmt \"%lld\"
#define _uword_cast (long long)
#else
#define _uword_fmt \"%ld\"
#define _uword_cast long
#endif

'''
    for t in s['typedefs'] + s['defines']:
        if t.manual_print:
            output += "/***** manual: vl_api_%s_t_print  *****/\n\n" % t.name
            continue

        output += "static inline void *vl_api_%s_t_print (vl_api_%s_t *a," % \
                  (t.name, t.name)
        output += "void *handle)\n{\n"
        output += "    vl_print(handle, \"vl_api_%s_t:\\n\");\n" % t.name

        for o in t.block:
            if len(o) != 2:
                continue
            if o[0] in format_strings:
                output += "    vl_print(handle, \"%s: %s\\n\", a->%s);\n" % \
                          (o[1], format_strings[o[0]], o[1])

        output += '    return handle;\n'
        output += '}\n\n'

    output += "\n#endif /* vl_printfun */\n"

    return output


endian_strings = {
    'u16': 'clib_net_to_host_u16',
    'u32': 'clib_net_to_host_u32',
    'u64': 'clib_net_to_host_u64',
    'i16': 'clib_net_to_host_u16',
    'i32': 'clib_net_to_host_u32',
    'i64': 'clib_net_to_host_u64',
}


def endianfun(s):
    output = '''\

/****** Endian swap functions *****/\n\
#ifdef vl_endianfun

#undef clib_net_to_host_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#endif

'''

    for t in s['typedefs'] + s['defines']:
        if t.manual_endian:
            output += "/***** manual: vl_api_%s_t_endian  *****/\n\n" % t.name
            continue

        output += "static inline void vl_api_%s_t_endian (vl_api_%s_t *a)" % \
                  (t.name, t.name)
        output += "\n{\n"

        for o in t.block:
            if len(o) != 2:
                continue
            if o[0] in endian_strings:
                output += "    a->%s = %s(a->%s);\n" % \
                        (o[1], endian_strings[o[0]], o[1])
            else:
                output += "    /* a->%s = a->%s (no-op) */\n" % \
                                          (o[1], o[1])

        output += '}\n\n'

    output += "\n#endif /* vl_endianfun */\n\n"

    return output


def version_tuple(s, module):
    output = '''\
/****** Version tuple *****/

#ifdef vl_api_version_tuple

'''
    if 'version' in s['options']:
        v = s['options']['version']
        (major, minor, patch) = v.split('.')
        output += "vl_api_version_tuple(%s, %s, %s, %s)\n" % \
                  (module, major, minor, patch)

    output += "\n#endif /* vl_api_version_tuple */\n\n"

    return output


#
# Plugin entry point
#
def run(input_filename, s, file_crc):
    basename = os.path.basename(input_filename)
    filename, file_extension = os.path.splitext(basename)
    output = top_boilerplate.format(datestring=datestring,
                                    input_filename=basename)
    output += msg_ids(s)
    output += msg_names(s)
    output += msg_name_crc_list(s, filename)
    output += typedefs(s, filename + file_extension)
    output += printfun(s)
    output += endianfun(s)
    output += version_tuple(s, basename)
    output += bottom_boilerplate.format(input_filename=basename,
                                        file_crc=file_crc)

    return output
