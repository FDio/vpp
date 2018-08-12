# C generation
import datetime
import os
import time

datestring = datetime.datetime.utcfromtimestamp(int(os.environ.get('SOURCE_DATE_EPOCH', time.time())))
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


def duplicate_wrapper_head(name):
    s = "#ifndef defined_%s\n" % name
    s += "#define defined_%s\n" % name
    return s


def duplicate_wrapper_tail():
    return '#endif\n\n'


def typedefs(objs, filename):
    name = filename.replace('.', '_')
    output = '''\


/****** Typedefs ******/

#ifdef vl_typedefs
#ifndef included_{module}
#define included_{module}
'''
    output = output.format(module=name)
    for o in objs:
        tname = o.__class__.__name__
        output += duplicate_wrapper_head(o.name)
        try:
            if o.typedef_alias == True:
                output += "typedef %s vl_api_%s_t;\n" % (o.block, o.name)
                output += "#endif\n"
                continue
        except:
            pass

        if tname == 'Enum':
            output += "typedef enum {\n"
            for b in o.block:
                output += "    %s = %s,\n" % (b[0], b[1])
            output += '} vl_api_%s_t;\n' % o.name
        else:
            if tname == 'Union':
                output += "typedef VL_API_PACKED(union _vl_api_%s {\n" % o.name
            else:
                output += "typedef VL_API_PACKED(struct _vl_api_%s {\n" % o.name
            for b in o.block:
                if b.type == 'Field':
                    output += "    %s %s;\n" % (b.fieldtype, b.fieldname)
                elif b.type == 'Array':
                    if b.lengthfield:
                        output += "    %s %s[0];\n" % (b.fieldtype, b.fieldname)
                    else:
                        output += "    %s %s[%s];\n" % (b.fieldtype, b.fieldname,
                                                        b.length)
                else:
                    raise ValueError("Error in processing array type %s" % b)

            output += '}) vl_api_%s_t;\n' % o.name
        output += duplicate_wrapper_tail()

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


def printfun(objs):
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
    for t in objs:
        if t.__class__.__name__ == 'Enum':
            continue
        try:
            if t.typedef_alias == True:
                continue
        except:
            pass

        if t.manual_print:
            output += "/***** manual: vl_api_%s_t_print  *****/\n\n" % t.name
            continue
        output += duplicate_wrapper_head(t.name + '_t_print')
        output += "static inline void *vl_api_%s_t_print (vl_api_%s_t *a," % \
                  (t.name, t.name)
        output += "void *handle)\n{\n"
        output += "    vl_print(handle, \"vl_api_%s_t:\\n\");\n" % t.name

        for o in t.block:
            if o.type != 'Field':
                continue
            if o.fieldtype in format_strings:
                output += "    vl_print(handle, \"%s: %s\\n\", a->%s);\n" % \
                          (o.fieldname, format_strings[o.fieldtype],
                           o.fieldname)

        output += '    return handle;\n'
        output += '}\n\n'
        output += duplicate_wrapper_tail()

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


def endianfun(objs):
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

    for t in objs:
        if t.__class__.__name__ == 'Enum':
            continue
        try:
            if t.typedef_alias == True:
                continue
        except:
            pass

        if t.manual_endian:
            output += "/***** manual: vl_api_%s_t_endian  *****/\n\n" % t.name
            continue
        output += duplicate_wrapper_head(t.name + '_t_endian')
        output += "static inline void vl_api_%s_t_endian (vl_api_%s_t *a)" % \
                  (t.name, t.name)
        output += "\n{\n"

        for o in t.block:
            if o.type != 'Field':
                continue
            if o.fieldtype in endian_strings:
                output += "    a->%s = %s(a->%s);\n" % \
                        (o.fieldname, endian_strings[o.fieldtype], o.fieldname)
            else:
                output += "    /* a->%s = a->%s (no-op) */\n" % \
                                          (o.fieldname, o.fieldname)

        output += '}\n\n'
        output += duplicate_wrapper_tail()
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
def run(input_filename, s, file_crc):
    basename = os.path.basename(input_filename)
    filename, file_extension = os.path.splitext(basename)
    output = top_boilerplate.format(datestring=datestring,
                                    input_filename=basename)
    output += msg_ids(s)
    output += msg_names(s)
    output += msg_name_crc_list(s, filename)
    output += typedefs(s['types'] + s['Define'], filename + file_extension)
    output += printfun(s['types'] + s['Define'])
    output += endianfun(s['types'] + s['Define'])
    output += version_tuple(s, basename)
    output += bottom_boilerplate.format(input_filename=basename,
                                        file_crc=file_crc)

    return output
