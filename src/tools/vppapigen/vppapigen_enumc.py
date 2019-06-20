
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

'''

def enum_typedef(objs, filename):
    name = filename.replace('.', '_')
    output = ''
    output = output.format(module=name)

    for o in objs:
        tname = o.__class__.__name__
        if tname != 'Enum':
            continue
        if o.enumtype == 'u32':
            output += "typedef enum {\n"
        else:
            output += "typedef enum __attribute__((__packed__)) {\n"

        for b in o.block:
            output += "    %s = %s,\n" % (b['id'], b['const'])
        output += '} vl_api_%s_t;\n' % o.name
        if o.enumtype != 'u32':
            size1 = 'sizeof(vl_api_%s_t)' % o.name
            size2 = 'sizeof(%s)' % o.enumtype
            err_str = 'size of API enum %s is wrong' % o.name
            output += 'STATIC_ASSERT(%s == %s, "%s");\n' % (size1, size2, err_str)

    return output

def enum_c(objs, filename):
    name = filename.replace('.', '_')
    output = ''
    output = output.format(module=name)

    for o in objs:
        tname = o.__class__.__name__
        if tname != 'Enum':
            continue

        output += "u8 *format_vl_api_%s (u8 * s, va_list * args) {\n" % o.name
        output += "  vl_api_%s_t r = va_arg (*args, vl_api_%s_t);\n" % (o.name, o.name)
        output += "  switch (r) {\n"
        for b in o.block:
            output += "  case %s:\n" % b['id']
            d = b['desc'] if 'desc' in b else b['id']
            output += '     return format(s, "%s");\n' % d
        output += "  default:\n"
        output += '    break;\n'
        output += "  }\n"
        output += '  return format(s, "unknown";\n'
        output += "}\n"

    return output


#
# Plugin entry point
#
def run(input_filename, s):
    basename = os.path.basename(input_filename)
    filename, file_extension = os.path.splitext(basename)
    output = top_boilerplate.format(datestring=datestring,
                                    input_filename=basename)
    output += enum_typedef(s['types'], filename + file_extension)
    output += enum_c(s['types'], filename + file_extension)


    return output
