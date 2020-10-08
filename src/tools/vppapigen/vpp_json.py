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

class ToJSON():
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
        write = self.stream.write
        write('#ifndef included_{}_api_tojson_h\n'.format(self.module))
        write('#define included_{}_api_tojson_h\n'.format(self.module))
        write('#include <vppinfra/cJSON.h>\n\n')
        write('#include <vat2/jsonconvert.h>\n\n')

    def footer(self):
        write = self.stream.write
        write('#endif\n')

    def get_json_func(self, t):
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
        if t in self.is_number:
            return 'cJSON_CreateNumber', ''
        if t == 'bool':
            return 'cJSON_CreateBool', ''
        return '{t}_tojson'.format(t=t), '&'

    def print_string(self, o):
        write = self.stream.write
        if o.modern_vla:
            write('    vl_api_string_cJSON_AddToObject(o, "{n}", &a->{n});\n'
                  .format(n=o.fieldname))
        else:

            write('    cJSON_AddStringToObject(o, "{n}", (char *)a->{n});\n'
                  .format(n=o.fieldname))

    def print_field(self, o):
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
            return self.print_string(o)

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
        write = self.stream.write
        write('static inline cJSON *vl_api_{name}_t_tojson '
              '(vl_api_{name}_t *a) {{\n'.format(name=o.name))
        write('    cJSON *o = cJSON_CreateObject();\n')

        for t in o.block:
            self._dispatch[t.type](self, t)

        write('    return o;\n')
        write('}\n')

    def print_define(self, o):
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
        write = self.stream.write
        if t.manual_print:
            write('/* Manual print {} */\n'.format(t.name))
            return
        self._dispatch[t.type](self, t)

    def generate_types(self):
        for t in self.types:
            self.generate_function(t)

    def generate_defines(self):
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
        write = self.stream.write
        write('#ifndef included_{}_api_fromjson_h\n'.format(self.module))
        write('#define included_{}_api_fromjson_h\n'.format(self.module))
        write('#include <vppinfra/cJSON.h>\n\n')
        write('#include <vat2/jsonconvert.h>\n\n')

    def is_base_type(self, t):
        if t in self.is_number:
            return True
        if t == 'bool':
            return True
        return False

    def footer(self):
        write = self.stream.write
        write('#endif\n')

    def print_string(self, o, toplevel=False):
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
            return self.print_string(o, toplevel)

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

    def print_typedef(self, o, vla=False):
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

    def print_union(self, o, vla=False):
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
        write = self.stream.write

        if o.manual_print:
            return

        t = o.using
        write('static inline void *vl_api_{name}_t_fromjson (void *mp, '
              'int *len, cJSON *o, vl_api_{name}_t *a) {{\n'
              .format(name=o.name))
        if 'length' in o.alias:
            if t.fieldtype != 'u8':
                raise
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
        write = self.stream.write
        if t.manual_print:
            write('/* Manual print {} */\n'.format(t.name))
            return
        self._dispatch[t.type](self, t)

    def generate_types(self):
        for t in self.types:
            self.generate_function(t)

    def generate_defines(self):
        for t in self.defines:
            self.generate_function(t)


def generate_tojson(s, modulename, stream):
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
