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

#
# Provide two classes FromJSON and TOJSON that converts between JSON and VPP's
# binary API format
#

'''
This module creates C code for core VPP, VPP plugins and client side VAT and
VAT2 tests.
'''

import datetime
import os
import time
import sys
from io import StringIO
import shutil

process_imports = False

###############################################################################
class ToJSON():
    '''Class to generate functions converting from VPP binary API to JSON.'''
    _dispatch = {}
    noprint_fields = {'_vl_msg_id': None,
                      'client_index': None,
                      'context': None}
    is_number = {'u8': None,
                 'i8': None,
                 'u16': None,
                 'i16': None,
                 'u32': None,
                 'i32': None,
                 'u64': None,
                 'i64': None,
                 'f64': None,
                 }

    def __init__(self, module, types, defines, imported_types, stream):
        self.stream = stream
        self.module = module
        self.defines = defines
        self.types = types
        self.types_hash = {'vl_api_'+d.name+'_t':
                           d for d in types + imported_types}
        self.defines_hash = {d.name: d for d in defines}

    def header(self):
        '''Output the top boilerplate.'''
        write = self.stream.write
        write('#ifndef included_{}_api_tojson_h\n'.format(self.module))
        write('#define included_{}_api_tojson_h\n'.format(self.module))
        write('#include <vppinfra/cJSON.h>\n\n')
        write('#include <vat2/jsonconvert.h>\n\n')

    def footer(self):
        '''Output the bottom boilerplate.'''
        write = self.stream.write
        write('#endif\n')

    def get_json_func(self, t):
        '''Given the type, returns the function to use to create a
        cJSON object'''
        vt_type = None
        try:
            vt = self.types_hash[t]
            if vt.type == 'Using' and 'length' not in vt.alias:
                vt_type = vt.alias['type']
        except KeyError:
            vt = t

        if t in self.is_number or vt_type in self.is_number:
            return 'cJSON_AddNumberToObject', '', False
        if t == 'bool':
            return 'cJSON_AddBoolToObject', '', False

        # Lookup type name check if it's enum
        if vt.type == 'Enum':
            return '{t}_tojson'.format(t=t), '', True
        return '{t}_tojson'.format(t=t), '&', True

    def get_json_array_func(self, t):
        '''Given a type returns the function to create a cJSON object
        for arrays.'''
        if t in self.is_number:
            return 'cJSON_CreateNumber', ''
        if t == 'bool':
            return 'cJSON_CreateBool', ''
        return '{t}_tojson'.format(t=t), '&'

    def print_string(self, o):
        '''Create cJSON object from vl_api_string_t'''
        write = self.stream.write
        if o.modern_vla:
            write('    vl_api_string_cJSON_AddToObject(o, "{n}", &a->{n});\n'
                  .format(n=o.fieldname))
        else:

            write('    cJSON_AddStringToObject(o, "{n}", (char *)a->{n});\n'
                  .format(n=o.fieldname))

    def print_field(self, o):
        '''Called for every field in a typedef or define.'''
        write = self.stream.write
        if o.fieldname in self.noprint_fields:
            return

        f, p, newobj = self.get_json_func(o.fieldtype)

        if newobj:
            write('    cJSON_AddItemToObject(o, "{n}", {f}({p}a->{n}));\n'
                  .format(f=f, p=p, n=o.fieldname))
        else:
            write('    {f}(o, "{n}", {p}a->{n});\n'
                  .format(f=f, p=p, n=o.fieldname))

    _dispatch['Field'] = print_field

    def print_array(self, o):
        '''Converts a VPP API array to cJSON array.'''
        write = self.stream.write

        forloop = '''\
    {{
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "{n}");
        for (i = 0; i < {lfield}; i++) {{
            cJSON_AddItemToArray(array, {f}({p}a->{n}[i]));
        }}
    }}
'''

        if o.fieldtype == 'string':
            self.print_string(o)
            return

        lfield = 'a->' + o.lengthfield if o.lengthfield else o.length
        if o.fieldtype == 'u8':
            write('    {\n')
            # What is length field doing here?
            write('    u8 *s = format(0, "0x%U", format_hex_bytes, '
                  '&a->{n}, {lfield});\n'
                  .format(n=o.fieldname, lfield=lfield))
            write('    cJSON_AddStringToObject(o, "{n}", (char *)s);\n'
                  .format(n=o.fieldname))
            write('    vec_free(s);\n')
            write('    }\n')
            return

        f, p = self.get_json_array_func(o.fieldtype)
        write(forloop.format(lfield=lfield,
                             t=o.fieldtype,
                             n=o.fieldname,
                             f=f,
                             p=p))

    _dispatch['Array'] = print_array

    def print_enum(self, o):
        '''Create cJSON object (string) for VPP API enum'''
        write = self.stream.write
        write('static inline cJSON *vl_api_{name}_t_tojson '
              '(vl_api_{name}_t a) {{\n'.format(name=o.name))

        write("    switch(a) {\n")
        for b in o.block:
            write("    case %s:\n" % b[1])
            write('        return cJSON_CreateString("{}");\n'.format(b[0]))
        write('    default: return cJSON_CreateString("Invalid ENUM");\n')
        write('    }\n')
        write('    return 0;\n')
        write('}\n')

    _dispatch['Enum'] = print_enum

    def print_typedef(self, o):
        '''Create cJSON (dictionary) object from VPP API typedef'''
        write = self.stream.write
        write('static inline cJSON *vl_api_{name}_t_tojson '
              '(vl_api_{name}_t *a) {{\n'.format(name=o.name))
        write('    cJSON *o = cJSON_CreateObject();\n')

        for t in o.block:
            self._dispatch[t.type](self, t)

        write('    return o;\n')
        write('}\n')

    def print_define(self, o):
        '''Create cJSON (dictionary) object from VPP API define'''
        write = self.stream.write
        write('static inline cJSON *vl_api_{name}_t_tojson '
              '(vl_api_{name}_t *a) {{\n'.format(name=o.name))
        write('    cJSON *o = cJSON_CreateObject();\n')
        write('    cJSON_AddStringToObject(o, "_msgname", "{}");\n'
              .format(o.name))

        for t in o.block:
            self._dispatch[t.type](self, t)

        write('    return o;\n')
        write('}\n')

    def print_using(self, o):
        '''Create cJSON (dictionary) object from VPP API aliased type'''
        if o.manual_print:
            return

        write = self.stream.write
        write('static inline cJSON *vl_api_{name}_t_tojson '
              '(vl_api_{name}_t *a) {{\n'.format(name=o.name))

        write('    u8 *s = format(0, "%U", format_vl_api_{}_t, a);\n'
              .format(o.name))
        write('    cJSON *o = cJSON_CreateString((char *)s);\n')
        write('    vec_free(s);\n')
        write('    return o;\n')
        write('}\n')

    _dispatch['Typedef'] = print_typedef
    _dispatch['Define'] = print_define
    _dispatch['Using'] = print_using
    _dispatch['Union'] = print_typedef

    def generate_function(self, t):
        '''Main entry point'''
        write = self.stream.write
        if t.manual_print:
            write('/* Manual print {} */\n'.format(t.name))
            return
        self._dispatch[t.type](self, t)

    def generate_types(self):
        '''Main entry point'''
        for t in self.types:
            self.generate_function(t)

    def generate_defines(self):
        '''Main entry point'''
        for t in self.defines:
            self.generate_function(t)


class FromJSON():
    '''
    Parse JSON objects into VPP API binary message structures.
    '''
    _dispatch = {}
    noprint_fields = {'_vl_msg_id': None,
                      'client_index': None,
                      'context': None}
    is_number = {'u8': None,
                 'i8': None,
                 'u16': None,
                 'i16': None,
                 'u32': None,
                 'i32': None,
                 'u64': None,
                 'i64': None,
                 'f64': None,
                 }

    def __init__(self, module, types, defines, imported_types, stream):
        self.stream = stream
        self.module = module
        self.defines = defines
        self.types = types
        self.types_hash = {'vl_api_'+d.name+'_t':
                           d for d in types + imported_types}
        self.defines_hash = {d.name: d for d in defines}

    def header(self):
        '''Output the top boilerplate.'''
        write = self.stream.write
        write('#ifndef included_{}_api_fromjson_h\n'.format(self.module))
        write('#define included_{}_api_fromjson_h\n'.format(self.module))
        write('#include <vppinfra/cJSON.h>\n\n')
        write('#include <vat2/jsonconvert.h>\n\n')

    def is_base_type(self, t):
        '''Check if a type is one of the VPP API base types'''
        if t in self.is_number:
            return True
        if t == 'bool':
            return True
        return False

    def footer(self):
        '''Output the bottom boilerplate.'''
        write = self.stream.write
        write('#endif\n')

    def print_string(self, o, toplevel=False):
        '''Convert JSON string to vl_api_string_t'''
        write = self.stream.write

        msgvar = "a" if toplevel else "mp"
        msgsize = "l" if toplevel else "*len"

        if o.modern_vla:
            write('    char *p = cJSON_GetStringValue(item);\n')
            write('    size_t plen = strlen(p);\n')
            write('    {msgvar} = realloc({msgvar}, {msgsize} + plen);\n'
                  .format(msgvar=msgvar, msgsize=msgsize))
            write('    vl_api_c_string_to_api_string(p, (void *){msgvar} + '
                  '{msgsize} - sizeof(vl_api_string_t));\n'
                  .format(msgvar=msgvar, msgsize=msgsize))
            write('    {msgsize} += plen;\n'.format(msgsize=msgsize))
        else:
            write('    strncpy_s((char *)a->{n}, sizeof(a->{n}), '
                  'cJSON_GetStringValue(item), sizeof(a->{n}) - 1);\n'
                  .format(n=o.fieldname))

    def print_field(self, o, toplevel=False):
        '''Called for every field in a typedef or define.'''
        write = self.stream.write
        write('    // start field {}\n'.format(o.fieldname))
        if o.fieldname in self.noprint_fields:
            return
        is_bt = self.is_base_type(o.fieldtype)
        t = 'vl_api_{}'.format(o.fieldtype) if is_bt else o.fieldtype

        msgvar = "a" if toplevel else "mp"
        msgsize = "&l" if toplevel else "len"

        if is_bt:
            write('    vl_api_{t}_fromjson(item, &a->{n});\n'
                  .format(t=o.fieldtype, n=o.fieldname))
        else:
            write('    {msgvar} = {t}_fromjson({msgvar}, '
                  '{msgsize}, item, &a->{n});\n'
                  .format(t=t, n=o.fieldname, msgvar=msgvar, msgsize=msgsize))
            write('    if (!{msgvar}) return 0;\n'.format(msgvar=msgvar))

        write('    // end field {}\n'.format(o.fieldname))

    _dispatch['Field'] = print_field

    def print_array(self, o, toplevel=False):
        '''Convert JSON array to VPP API array'''
        write = self.stream.write

        forloop = '''\
    {{
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "{n}");
        int size = cJSON_GetArraySize(array);
        if (size != {lfield}) return 0;
        for (i = 0; i < size; i++) {{
            cJSON *e = cJSON_GetArrayItem(array, i);
            {call}
        }}
    }}
'''
        forloop_vla = '''\
    {{
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "{n}");
        int size = cJSON_GetArraySize(array);
        {lfield} = size;
        {msgvar} = realloc({msgvar}, {msgsize} + sizeof({t}) * size);
        {t} *d = (void *){msgvar} + {msgsize};
        {msgsize} += sizeof({t}) * size;
        for (i = 0; i < size; i++) {{
            cJSON *e = cJSON_GetArrayItem(array, i);
            {call}
        }}
    }}
'''
        t = o.fieldtype
        if o.fieldtype == 'string':
            self.print_string(o, toplevel)
            return

        lfield = 'a->' + o.lengthfield if o.lengthfield else o.length
        msgvar = "a" if toplevel else "mp"
        msgsize = "l" if toplevel else "*len"

        if o.fieldtype == 'u8':
            if o.lengthfield:
                write('    s = u8string_fromjson(o, "{}");\n'
                      .format(o.fieldname))
                write('    if (!s) return 0;\n')
                write('    {} = vec_len(s);\n'.format(lfield))

                write('    {msgvar} = realloc({msgvar}, {msgsize} + '
                      'vec_len(s));\n'.format(msgvar=msgvar, msgsize=msgsize))
                write('    memcpy((void *){msgvar} + {msgsize}, s, '
                      'vec_len(s));\n'.format(msgvar=msgvar, msgsize=msgsize))
                write('    {msgsize} += vec_len(s);\n'.format(msgsize=msgsize))

                write('    vec_free(s);\n')
            else:
                write('    u8string_fromjson2(o, "{n}", a->{n});\n'
                      .format(n=o.fieldname))
            return

        is_bt = self.is_base_type(o.fieldtype)

        if o.lengthfield:
            if is_bt:
                call = ('vl_api_{t}_fromjson(e, &d[i]);'
                        .format(t=o.fieldtype))
            else:
                call = ('{t}_fromjson({msgvar}, len, e, &d[i]); '
                        .format(t=o.fieldtype, msgvar=msgvar))
            write(forloop_vla.format(lfield=lfield,
                                     t=o.fieldtype,
                                     n=o.fieldname,
                                     call=call,
                                     msgvar=msgvar,
                                     msgsize=msgsize))
        else:
            if is_bt:
                call = ('vl_api_{t}_fromjson(e, &a->{n}[i]);'
                        .format(t=t, n=o.fieldname))
            else:
                call = ('a = {}_fromjson({}, len, e, &a->{}[i]);'
                        .format(t, msgvar, o.fieldname))
            write(forloop.format(lfield=lfield,
                                 t=t,
                                 n=o.fieldname,
                                 call=call,
                                 msgvar=msgvar,
                                 msgsize=msgsize))

    _dispatch['Array'] = print_array

    def print_enum(self, o):
        '''Convert to JSON enum(string) to VPP API enum (int)'''
        write = self.stream.write
        write('static inline void *vl_api_{n}_t_fromjson '
              '(void *mp, int *len, cJSON *o, vl_api_{n}_t *a) {{\n'
              .format(n=o.name))
        write('    char *p = cJSON_GetStringValue(o);\n')
        for b in o.block:
            write('    if (strcmp(p, "{}") == 0) {{*a = {}; return mp;}}\n'
                  .format(b[0], b[1]))
        write('   return 0;\n')
        write('}\n')

    _dispatch['Enum'] = print_enum

    def print_typedef(self, o):
        '''Convert from JSON object to VPP API binary representation'''
        write = self.stream.write

        write('static inline void *vl_api_{name}_t_fromjson (void *mp, '
              'int *len, cJSON *o, vl_api_{name}_t *a) {{\n'
              .format(name=o.name))
        write('    cJSON *item __attribute__ ((unused));\n')
        write('    u8 *s __attribute__ ((unused));\n')
        for t in o.block:
            if t.type == 'Field' and t.is_lengthfield:
                continue
            write('    item = cJSON_GetObjectItem(o, "{}");\n'
                  .format(t.fieldname))
            write('    if (!item) return 0;\n')

            self._dispatch[t.type](self, t)

        write('    return mp;\n')
        write('}\n')

    def print_union(self, o):
        '''Convert JSON object to VPP API binary union'''
        write = self.stream.write

        write('static inline void *vl_api_{name}_t_fromjson (void *mp, '
              'int *len, cJSON *o, vl_api_{name}_t *a) {{\n'
              .format(name=o.name))
        write('    cJSON *item __attribute__ ((unused));\n')
        write('    u8 *s __attribute__ ((unused));\n')
        for t in o.block:
            if t.type == 'Field' and t.is_lengthfield:
                continue
            write('    item = cJSON_GetObjectItem(o, "{}");\n'
                  .format(t.fieldname))
            write('    if (item) {\n')
            self._dispatch[t.type](self, t)
            write('    };\n')
        write('    return mp;\n')
        write('}\n')

    def print_define(self, o):
        '''Convert JSON object to VPP API message'''
        write = self.stream.write
        write('static inline vl_api_{name}_t *vl_api_{name}_t_fromjson '
              '(cJSON *o, int *len) {{\n'.format(name=o.name))
        write('    cJSON *item __attribute__ ((unused));\n')
        write('    u8 *s __attribute__ ((unused));\n')
        write('    int l = sizeof(vl_api_{}_t);\n'.format(o.name))
        write('    vl_api_{}_t *a = malloc(l);\n'.format(o.name))

        for t in o.block:
            if t.fieldname in self.noprint_fields:
                continue
            if t.type == 'Field' and t.is_lengthfield:
                continue
            write('    // processing {}: {} {}\n'
                  .format(o.name, t.fieldtype, t.fieldname))

            write('    item = cJSON_GetObjectItem(o, "{}");\n'
                  .format(t.fieldname))
            write('    if (!item) return 0;\n')
            self._dispatch[t.type](self, t, toplevel=True)
            write('\n')

        write('\n')
        write('    *len = l;\n')
        write('    return a;\n')
        write('}\n')

    def print_using(self, o):
        '''Convert JSON field to VPP type alias'''
        write = self.stream.write

        if o.manual_print:
            return

        t = o.using
        write('static inline void *vl_api_{name}_t_fromjson (void *mp, '
              'int *len, cJSON *o, vl_api_{name}_t *a) {{\n'
              .format(name=o.name))
        if 'length' in o.alias:
            if t.fieldtype != 'u8':
                raise ValueError("Error in processing type {} for {}"
                                 .format(t.fieldtype, o.name))
            write('    vl_api_u8_string_fromjson(o, (u8 *)a, {});\n'
                  .format(o.alias['length']))
        else:
            write('    vl_api_{t}_fromjson(o, ({t} *)a);\n'
                  .format(t=t.fieldtype))

        write('    return mp;\n')
        write('}\n')

    _dispatch['Typedef'] = print_typedef
    _dispatch['Define'] = print_define
    _dispatch['Using'] = print_using
    _dispatch['Union'] = print_union

    def generate_function(self, t):
        '''Main entry point'''
        write = self.stream.write
        if t.manual_print:
            write('/* Manual print {} */\n'.format(t.name))
            return
        self._dispatch[t.type](self, t)

    def generate_types(self):
        '''Main entry point'''
        for t in self.types:
            self.generate_function(t)

    def generate_defines(self):
        '''Main entry point'''
        for t in self.defines:
            self.generate_function(t)


def generate_tojson(s, modulename, stream):
    '''Generate all functions to convert from API to JSON'''
    write = stream.write

    write('/* Imported API files */\n')
    for i in s['Import']:
        f = i.filename.replace('plugins/', '')
        write('#include <{}_tojson.h>\n'.format(f))

    pp = ToJSON(modulename, s['types'], s['Define'], s['imported']['types'],
                stream)
    pp.header()
    pp.generate_types()
    pp.generate_defines()
    pp.footer()
    return ''


def generate_fromjson(s, modulename, stream):
    '''Generate all functions to convert from JSON to API'''
    write = stream.write
    write('/* Imported API files */\n')
    for i in s['Import']:
        f = i.filename.replace('plugins/', '')
        write('#include <{}_fromjson.h>\n'.format(f))

    pp = FromJSON(modulename, s['types'], s['Define'], s['imported']['types'],
                  stream)
    pp.header()
    pp.generate_types()
    pp.generate_defines()
    pp.footer()

    return ''

###############################################################################


DATESTRING = datetime.datetime.utcfromtimestamp(
    int(os.environ.get('SOURCE_DATE_EPOCH', time.time())))
TOP_BOILERPLATE = '''\
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

BOTTOM_BOILERPLATE = '''\
/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version({input_filename}, {file_crc:#08x})

#endif
'''


def msg_ids(s):
    '''Generate macro to map API message id to handler'''
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
    '''Generate calls to name mapping macro'''
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
    '''Generate list of names to CRC mappings'''
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
    '''Map between API type names and internal VPP type names'''
    mappingtable = {'string': 'vl_api_string_t', }
    if fieldtype in mappingtable:
        return mappingtable[fieldtype]
    return fieldtype


def typedefs(filename):
    '''Include in the main files to the types file'''
    output = '''\

/****** Typedefs ******/

#ifdef vl_typedefs
#include "{include}.api_types.h"
#endif
'''.format(include=filename)
    return output


FORMAT_STRINGS = {'u8': '%u',
                  'bool': '%u',
                  'i8': '%d',
                  'u16': '%u',
                  'i16': '%d',
                  'u32': '%u',
                  'i32': '%ld',
                  'u64': '%llu',
                  'i64': '%lld',
                  'f64': '%.2f'}


class Printfun():
    '''Functions for pretty printing VPP API messages'''
    _dispatch = {}
    noprint_fields = {'_vl_msg_id': None,
                      'client_index': None,
                      'context': None}

    def __init__(self, stream):
        self.stream = stream

    @staticmethod
    def print_string(o, stream):
        '''Pretty print a vl_api_string_t'''
        write = stream.write
        if o.modern_vla:
            write('    if (vl_api_string_len(&a->{f}) > 0) {{\n'
                  .format(f=o.fieldname))
            write('        s = format(s, "\\n%U{f}: %U", '
                  'format_white_space, indent, '
                  'vl_api_format_string, (&a->{f}));\n'.format(f=o.fieldname))
            write('    } else {\n')
            write('        s = format(s, "\\n%U{f}:", '
                  'format_white_space, indent);\n'.format(f=o.fieldname))
            write('    }\n')
        else:
            write('    s = format(s, "\\n%U{f}: %s", '
                  'format_white_space, indent, a->{f});\n'
                  .format(f=o.fieldname))

    def print_field(self, o, stream):
        '''Pretty print API field'''
        write = stream.write
        if o.fieldname in self.noprint_fields:
            return
        if o.fieldtype in FORMAT_STRINGS:
            f = FORMAT_STRINGS[o.fieldtype]
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
        '''Pretty print API array'''
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
            self.print_string(o, stream)
            return

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
        if o.fieldtype in FORMAT_STRINGS:
            write(forloop_format.format(lfield=lfield,
                                        t=FORMAT_STRINGS[o.fieldtype],
                                        n=o.fieldname))
        else:
            write(forloop.format(lfield=lfield, t=o.fieldtype, n=o.fieldname))

    _dispatch['Array'] = print_array

    @staticmethod
    def print_alias(k, v, stream):
        '''Pretty print type alias'''
        write = stream.write
        if ('length' in v.alias and v.alias['length'] and
                v.alias['type'] == 'u8'):
            write('    return format(s, "%U", format_hex_bytes, a, {});\n'
                  .format(v.alias['length']))
        elif v.alias['type'] in FORMAT_STRINGS:
            write('    return format(s, "{}", *a);\n'
                  .format(FORMAT_STRINGS[v.alias['type']]))
        else:
            write('    return format(s, "{} (print not implemented)");\n'
                  .format(k))

    @staticmethod
    def print_enum(o, stream):
        '''Pretty print API enum'''
        write = stream.write
        write("    switch(*a) {\n")
        for b in o:
            write("    case %s:\n" % b[1])
            write('        return format(s, "{}");\n'.format(b[0]))
        write('    }\n')

    _dispatch['Enum'] = print_enum

    def print_obj(self, o, stream):
        '''Entry point'''
        write = stream.write

        if o.type in self._dispatch:
            self._dispatch[o.type](self, o, stream)
        else:
            write('    s = format(s, "\\n{} {} {} (print not implemented");\n'
                  .format(o.type, o.fieldtype, o.fieldname))


def printfun(objs, stream, modulename):
    '''Main entry point for pretty print function generation'''
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
    '''Pretty print API types'''
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


def generate_imports(imports):
    '''Add #include matching the API import statements'''
    output = '/* Imported API files */\n'
    output += '#ifndef vl_api_version\n'

    for i in imports:
        s = i.filename.replace('plugins/', '')
        output += '#include <{}.h>\n'.format(s)
    output += '#endif\n'
    return output


ENDIAN_STRINGS = {
    'u16': 'clib_net_to_host_u16',
    'u32': 'clib_net_to_host_u32',
    'u64': 'clib_net_to_host_u64',
    'i16': 'clib_net_to_host_i16',
    'i32': 'clib_net_to_host_i32',
    'i64': 'clib_net_to_host_i64',
    'f64': 'clib_net_to_host_f64',
}


def endianfun_array(o):
    '''Generate endian functions for arrays'''
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
        if o.fieldtype in ENDIAN_STRINGS:
            output += (forloop
                       .format(length=lfield,
                               format=ENDIAN_STRINGS[o.fieldtype],
                               name=o.fieldname))
        else:
            output += (forloop_format
                       .format(length=lfield, type=o.fieldtype,
                               name=o.fieldname))
    return output


NO_ENDIAN_CONVERSION = {'client_index': None}


def endianfun_obj(o):
    '''Generate endian conversion function for type'''
    output = ''
    if o.type == 'Array':
        return endianfun_array(o)
    if o.type != 'Field':
        output += ('    s = format(s, "\\n{} {} {} (print not implemented");\n'
                   .format(o.type, o.fieldtype, o.fieldname))
        return output
    if o.fieldname in NO_ENDIAN_CONVERSION:
        output += '    /* a->{n} = a->{n} (no-op) */\n'.format(n=o.fieldname)
        return output
    if o.fieldtype in ENDIAN_STRINGS:
        output += ('    a->{name} = {format}(a->{name});\n'
                   .format(name=o.fieldname,
                           format=ENDIAN_STRINGS[o.fieldtype]))
    elif o.fieldtype.startswith('vl_api_'):
        output += ('    {type}_endian(&a->{name});\n'
                   .format(type=o.fieldtype, name=o.fieldname))
    else:
        output += '    /* a->{n} = a->{n} (no-op) */\n'.format(n=o.fieldname)

    return output


def endianfun(objs, modulename):
    '''Main entry point for endian function generation'''
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
            if t.enumtype in ENDIAN_STRINGS:
                output += ('    *a = {}(*a);\n'
                           .format(ENDIAN_STRINGS[t.enumtype]))
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
            elif t.alias['type'] in FORMAT_STRINGS:
                output += ('    *a = {}(*a);\n'
                           .format(ENDIAN_STRINGS[t.alias['type']]))
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
    '''Generate semantic version string'''
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
    '''Generate <name>.api_enum.h'''
    write = stream.write

    if 'Define' in s:
        write('typedef enum {\n')
        for t in s['Define']:
            write('   VL_API_{},\n'.format(t.name.upper()))
        write('   VL_MSG_{}_LAST\n'.format(module.upper()))
        write('}} vl_api_{}_enum_t;\n'.format(module))


def generate_include_counters(s, stream):
    '''Include file for the counter data model types.'''
    write = stream.write

    for counters in s:
        csetname = counters.name
        write('typedef enum {\n')
        for c in counters.block:
            write('   {}_ERROR_{},\n'
                  .format(csetname.upper(), c['name'].upper()))
        write('   {}_N_ERROR\n'.format(csetname.upper()))
        write('}} vl_counter_{}_enum_t;\n'.format(csetname))

        write('extern vl_counter_t {}_error_counters[];\n'.format(csetname))


def generate_include_types(s, module, stream):
    '''Generate separate API _types file.'''
    write = stream.write

    write('#ifndef included_{module}_api_types_h\n'.format(module=module))
    write('#define included_{module}_api_types_h\n'.format(module=module))

    if 'version' in s['Option']:
        v = s['Option']['version']
        (major, minor, patch) = v.split('.')
        write('#define VL_API_{m}_API_VERSION_MAJOR {v}\n'
              .format(m=module.upper(), v=major))
        write('#define VL_API_{m}_API_VERSION_MINOR {v}\n'
              .format(m=module.upper(), v=minor))
        write('#define VL_API_{m}_API_VERSION_PATCH {v}\n'
              .format(m=module.upper(), v=patch))

    if 'Import' in s:
        write('/* Imported API files */\n')
        for i in s['Import']:
            filename = i.filename.replace('plugins/', '')
            write('#include <{}_types.h>\n'.format(filename))

    for o in s['types'] + s['Define']:
        tname = o.__class__.__name__
        if tname == 'Using':
            if 'length' in o.alias:
                write('typedef %s vl_api_%s_t[%s];\n' %
                      (o.alias['type'], o.name, o.alias['length']))
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
                write("typedef union __attribute__ ((packed)) _vl_api_%s {\n"
                      % o.name)
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

    for t in s['Define']:
        write('#define VL_API_{ID}_CRC "{n}_{crc:08x}"\n'
              .format(n=t.name, ID=t.name.upper(), crc=t.crc))

    write("\n#endif\n")


def generate_c_boilerplate(services, defines, counters, file_crc,
                           module, stream):
    '''VPP side plugin.'''
    write = stream.write
    define_hash = {d.name: d for d in defines}

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
    write('   api_main_t *am = my_api_main;\n')
    write('   vl_msg_api_msg_config_t c;\n')
    write('   u16 msg_id_base = vl_msg_api_get_msg_ids ("{}_{crc:08x}", '
          'VL_MSG_{m}_LAST);\n'
          .format(module, crc=file_crc, m=module.upper()))

    for d in defines:
        write('   vl_msg_api_add_msg_name_crc (am, "{n}_{crc:08x}",\n'
              '                                VL_API_{ID} + msg_id_base);\n'
              .format(n=d.name, ID=d.name.upper(), crc=d.crc))
    for s in services:
        d = define_hash[s.caller]
        write('   c = (vl_msg_api_msg_config_t) '
              ' {{.id = VL_API_{ID} + msg_id_base,\n'
              '   .name = "{n}",\n'
              '   .handler = vl_api_{n}_t_handler,\n'
              '   .cleanup = vl_noop_handler,\n'
              '   .endian = vl_api_{n}_t_endian,\n'
              '   .print = vl_api_{n}_t_print,\n'
              '   .is_autoendian = 0}};\n'
              .format(n=s.caller, ID=s.caller.upper()))
        write('   vl_msg_api_config (&c);\n')
        try:
            d = define_hash[s.reply]
            write('   c = (vl_msg_api_msg_config_t) '
                  '{{.id = VL_API_{ID} + msg_id_base,\n'
                  '  .name = "{n}",\n'
                  '  .handler = 0,\n'
                  '  .cleanup = vl_noop_handler,\n'
                  '  .endian = vl_api_{n}_t_endian,\n'
                  '  .print = vl_api_{n}_t_print,\n'
                  '  .is_autoendian = 0}};\n'
                  .format(n=s.reply, ID=s.reply.upper()))
            write('   vl_msg_api_config (&c);\n')
        except KeyError:
            pass

    write('   return msg_id_base;\n')
    write('}\n')

    severity = {'error': 'VL_COUNTER_SEVERITY_ERROR',
                'info': 'VL_COUNTER_SEVERITY_INFO',
                'warn': 'VL_COUNTER_SEVERITY_WARN'}

    for cnt in counters:
        csetname = cnt.name
        write('vl_counter_t {}_error_counters[] = {{\n'.format(csetname))
        for c in cnt.block:
            write('  {\n')
            write('   .name = "{}",\n'.format(c['name']))
            write('   .desc = "{}",\n'.format(c['description']))
            write('   .severity = {},\n'.format(severity[c['severity']]))
            write('  },\n')
        write('};\n')


def generate_c_test_boilerplate(services, defines, file_crc, module, plugin,
                                stream):
    '''Generate code for legacy style VAT. To be deleted.'''
    write = stream.write

    define_hash = {d.name: d for d in defines}

    hdr = '''\
#define vl_endianfun            /* define message structures */
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
        except KeyError:
            continue
        if d.manual_print:
            write('/*\n'
                  ' * Manual definition requested for: \n'
                  ' * vl_api_{n}_t_handler()\n'
                  ' */\n'
                  .format(n=s.reply))
            continue
        if not define_hash[s.caller].autoreply:
            write('/* Generation not supported (vl_api_{n}_t_handler()) */\n'
                  .format(n=s.reply))
            continue
        write('#ifndef VL_API_{n}_T_HANDLER\n'.format(n=s.reply.upper()))
        write('static void\n')
        write('vl_api_{n}_t_handler (vl_api_{n}_t * mp) {{\n'
              .format(n=s.reply))
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
        write('   vl_msg_api_set_handlers(VL_API_{ID} + msg_id_base, '
              '                           "{n}",\n'
              '                           vl_api_{n}_t_handler, '
              '                           vl_noop_handler,\n'
              '                           vl_api_{n}_t_endian, '
              '                           vl_api_{n}_t_print,\n'
              '                           sizeof(vl_api_{n}_t), 1);\n'
              .format(n=s.reply, ID=s.reply.upper()))
        write('   hash_set_mem (vam->function_by_name, "{n}", api_{n});\n'
              .format(n=s.caller))
        try:
            write('   hash_set_mem (vam->help_by_name, "{n}", "{help}");\n'
                  .format(n=s.caller,
                          help=define_hash[s.caller].options['vat_help']))
        except KeyError:
            pass

        # Events
        for e in s.events:
            write('   vl_msg_api_set_handlers(VL_API_{ID} + msg_id_base, '
                  '                          "{n}",\n'
                  '                           vl_api_{n}_t_handler, '
                  '                           vl_noop_handler,\n'
                  '                           vl_api_{n}_t_endian, '
                  '                           vl_api_{n}_t_print,\n'
                  '                           sizeof(vl_api_{n}_t), 1);\n'
                  .format(n=e, ID=e.upper()))

    write('}\n')
    if plugin:
        write('clib_error_t * vat_plugin_register (vat_main_t *vam)\n')
    else:
        write('clib_error_t * vat_{}_plugin_register (vat_main_t *vam)\n'
              .format(module))
    write('{\n')
    write('   {n}_test_main_t * mainp = &{n}_test_main;\n'.format(n=module))
    write('   mainp->vat_main = vam;\n')
    write('   mainp->msg_id_base = vl_client_get_first_plugin_msg_id '
          '                       ("{n}_{crc:08x}");\n'
          .format(n=module, crc=file_crc))
    write('   if (mainp->msg_id_base == (u16) ~0)\n')
    write('      return clib_error_return (0, "{} plugin not loaded...");\n'
          .format(module))
    write('   setup_message_id_table (vam, mainp->msg_id_base);\n')
    write('#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE\n')
    write('    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);\n')
    write('#endif\n')
    write('   return 0;\n')
    write('}\n')


def apifunc(func):
    '''Check if a method is generated already.'''
    def _f(module, d, processed, *args):
        if d.name in processed:
            return None
        processed[d.name] = True
        return func(module, d, *args)
    return _f


def c_test_api_service(s, dump, stream):
    '''Generate JSON code for a service.'''
    write = stream.write

    req_reply_template = '''\
static cJSON *
api_{n} (cJSON *o)
{{
  vl_api_{n}_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_{n}_t_fromjson(o, &len);
  if (!mp) {{
    fprintf(stderr, "Failed converting JSON to API\\n");
    return 0;
  }}

  mp->_vl_msg_id = vac_get_msg_index(VL_API_{N}_CRC);
  vl_api_{n}_t_endian(mp);
  vac_write((char *)mp, len);
  free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_{R}_CRC)) {{
    fprintf(stderr, "Mismatched reply\\n");
    return 0;
  }}
  vl_api_{r}_t *rmp = (vl_api_{r}_t *)p;
  vl_api_{r}_t_endian(rmp);
  return vl_api_{r}_t_tojson(rmp);
}}

'''
    dump_details_template = '''\
static cJSON *
api_{n} (cJSON *o)
{{
  u16 msg_id = vac_get_msg_index(VL_API_{N}_CRC);
  int len;
  if (!o) return 0;
  vl_api_{n}_t *mp = vl_api_{n}_t_fromjson(o, &len);
  if (!mp) {{
      fprintf(stderr, "Failed converting JSON to API\\n");
      return 0;
  }}
  mp->_vl_msg_id = msg_id;
  vl_api_{n}_t_endian(mp);
  vac_write((char *)mp, len);
  free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_{R}_CRC);

  while (1) {{
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 reply_msg_id = ntohs(*((u16 *)p));
    if (reply_msg_id == ping_reply_msg_id) {{
        break;
    }}

    if (reply_msg_id == details_msg_id) {{
        vl_api_{r}_t *rmp = (vl_api_{r}_t *)p;
        vl_api_{r}_t_endian(rmp);
        cJSON_AddItemToArray(reply, vl_api_{r}_t_tojson(rmp));
    }}
  }}
  return reply;
}}

'''
    gets_details_reply_template = '''\
static cJSON *
api_{n} (cJSON *o)
{{
    u16 msg_id = vac_get_msg_index(VL_API_{N}_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_{n}_t *mp = vl_api_{n}_t_fromjson(o, &len);
  if (!mp) {{
    fprintf(stderr, "Failed converting JSON to API\\n");
    return 0;
  }}
  mp->_vl_msg_id = msg_id;

  vl_api_{n}_t_endian(mp);
  vac_write((char *)mp, len);
  free(mp);

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
        vl_api_{r}_t_endian(rmp);
        cJSON_AddItemToArray(reply, vl_api_{r}_t_tojson(rmp));
        break;
    }}

    if (msg_id == details_msg_id) {{
        vl_api_{d}_t *rmp = (vl_api_{d}_t *)p;
        vl_api_{d}_t_endian(rmp);
        cJSON_AddItemToArray(reply, vl_api_{d}_t_tojson(rmp));
    }}
  }}
  return reply;
}}

'''

    if dump:
        if s.stream_message:
            write(gets_details_reply_template
                  .format(n=s.caller, r=s.reply, N=s.caller.upper(),
                          R=s.reply.upper(), d=s.stream_message,
                          D=s.stream_message.upper()))
        else:
            write(dump_details_template.format(n=s.caller, r=s.reply,
                                               N=s.caller.upper(),
                                               R=s.reply.upper()))
    else:
        write(req_reply_template.format(n=s.caller, r=s.reply,
                                        N=s.caller.upper(),
                                        R=s.reply.upper()))


def generate_c_test2_boilerplate(services, defines, module, stream):
    '''Generate code for VAT2 plugin.'''
    write = stream.write

    define_hash = {d.name: d for d in defines}
    # replies = {}

    hdr = '''\
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip_format_fns.h>
#include <vnet/ethernet/ethernet_format_fns.h>

#define vl_typedefs             /* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#include "{module}.api_enum.h"
#include "{module}.api_types.h"

#define vl_endianfun		/* define message structures */
#include "{module}.api.h"
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include "{module}.api.h"
#undef vl_printfun

#include "{module}.api_tojson.h"
#include "{module}.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

'''

    write(hdr.format(module=module))

    for s in services:
        if s.reply not in define_hash:
            continue
        c_test_api_service(s, s.stream, stream)

    write('void vat2_register_function(char *, cJSON * (*)(cJSON *));\n')
    # write('__attribute__((constructor))')
    write('clib_error_t *\n')
    write('vat2_register_plugin (void) {\n')
    for s in services:
        write('   vat2_register_function("{n}", api_{n});\n'
              .format(n=s.caller))
    write('   return 0;\n')
    write('}\n')


#
# Plugin entry point
#
def run(args, apifilename, s):
    '''Main plugin entry point.'''
    stream = StringIO()

    if not args.outputdir:
        sys.stderr.write('Missing --outputdir argument')
        return None

    basename = os.path.basename(apifilename)
    filename, _ = os.path.splitext(basename)
    modulename = filename.replace('.', '_')
    filename_enum = os.path.join(args.outputdir + '/' + basename + '_enum.h')
    filename_types = os.path.join(args.outputdir + '/' + basename + '_types.h')
    filename_c = os.path.join(args.outputdir + '/' + basename + '.c')
    filename_c_test = os.path.join(args.outputdir + '/' + basename + '_test.c')
    filename_c_test2 = (os.path.join(args.outputdir + '/' + basename +
                                     '_test2.c'))
    filename_c_tojson = (os.path.join(args.outputdir +
                                      '/' + basename + '_tojson.h'))
    filename_c_fromjson = (os.path.join(args.outputdir + '/' +
                                        basename + '_fromjson.h'))

    # Generate separate types file
    st = StringIO()
    generate_include_types(s, modulename, st)
    with open(filename_types, 'w') as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()

    # Generate separate enum file
    st = StringIO()
    st.write('#ifndef included_{}_api_enum_h\n'.format(modulename))
    st.write('#define included_{}_api_enum_h\n'.format(modulename))
    generate_include_enum(s, modulename, st)
    generate_include_counters(s['Counters'], st)
    st.write('#endif\n')
    with open(filename_enum, 'w') as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()

    # Generate separate C file
    st = StringIO()
    generate_c_boilerplate(s['Service'], s['Define'], s['Counters'],
                           s['file_crc'], modulename, st)
    with open(filename_c, 'w') as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()

    # Generate separate C test file
    st = StringIO()
    plugin = bool('plugin' in apifilename)
    generate_c_test_boilerplate(s['Service'], s['Define'],
                                s['file_crc'],
                                modulename, plugin, st)
    with open(filename_c_test, 'w') as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()

    # Fully autogenerated VATv2 C test file
    st = StringIO()
    generate_c_test2_boilerplate(s['Service'], s['Define'],
                                 modulename, st)
    with open(filename_c_test2, 'w') as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()                  #

    # Generate separate JSON file
    st = StringIO()
    generate_tojson(s, modulename, st)
    with open(filename_c_tojson, 'w') as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()
    st = StringIO()
    generate_fromjson(s, modulename, st)
    with open(filename_c_fromjson, 'w') as fd:
        st.seek(0)
        shutil.copyfileobj(st, fd)
    st.close()

    output = TOP_BOILERPLATE.format(datestring=DATESTRING,
                                    input_filename=basename)
    output += generate_imports(s['Import'])
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
    output += BOTTOM_BOILERPLATE.format(input_filename=basename,
                                        file_crc=s['file_crc'])

    return output
