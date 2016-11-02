#!/usr/bin/env python
#
# Copyright (c) 2016 Cisco and/or its affiliates.
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

from __future__ import print_function
import argparse, sys, os, importlib, pprint

parser = argparse.ArgumentParser(description='VPP Python API generator')
parser.add_argument('-i', '--input', action="store", dest="inputfile", type=argparse.FileType('r'))
parser.add_argument('-c', '--cfile', action="store")
args = parser.parse_args()

#
# Read API definitions file into vppapidefs
#
exec(args.inputfile.read())

# https://docs.python.org/3/library/struct.html
format_struct = {'u8': 'B',
                 'u16' : 'H',
                 'u32' : 'I',
                 'i32' : 'i',
                 'u64' : 'Q',
                 'f64' : 'd',
                 'vl_api_fib_path_t' : 'IIBBBBBBBBBBBBBBBBBBBBB',
                 'vl_api_ip4_fib_counter_t' : 'IBQQ',
                 'vl_api_ip6_fib_counter_t' : 'QQBQQ',
                 'vl_api_lisp_adjacency_t' : 'B' * 35
                 };
#
# NB: If new types are introduced in vpe.api, these must be updated.
#
type_size = {'u8':   1,
             'u16' : 2,
             'u32' : 4,
             'i32' : 4,
             'u64' : 8,
             'f64' : 8,
             'vl_api_fib_path_t' : 29,
             'vl_api_ip4_fib_counter_t' : 21,
             'vl_api_ip6_fib_counter_t' : 33,
             'vl_api_lisp_adjacency_t' : 35
};

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def get_args(t):
    argslist = []
    for i in t:
        if i[1][0] == '_':
            argslist.append(i[1][1:])
        else:
            argslist.append(i[1])

    return argslist

def get_pack(f):
    zeroarray = False
    bytecount = 0
    pack = ''
    elements = 1
    if len(f) is 3 or len(f) is 4:
        size = type_size[f[0]]
        bytecount += size * int(f[2])
        # Check if we have a zero length array
        if f[2] == '0':
            # If len 3 zero array
            elements = 0;
            pack += format_struct[f[0]]
            bytecount = size
        elif size == 1:
            n = f[2] * size
            pack += str(n) + 's'
        else:
            pack += format_struct[f[0]] * int(f[2])
            elements = int(f[2])
    else:
        bytecount += type_size[f[0]]
        pack += format_struct[f[0]]
    return (pack, elements, bytecount)


'''
def get_reply_func(f):
    if f['name']+'_reply' in func_name:
        return func_name[f['name']+'_reply']
    if f['name'].find('_dump') > 0:
        r = f['name'].replace('_dump','_details')
        if r in func_name:
            return func_name[r]
    return None
'''

def footer_print():
    print('''
def msg_id_base_set(b):
    global base
    base = b

import os
name = os.path.splitext(os.path.basename(__file__))[0]
    ''')
    print(u"plugin_register(name, api_func_table, api_name_to_id,", vl_api_version, ", msg_id_base_set)")

def api_table_print(name, i):
    msg_id_in = 'VL_API_' + name.upper()
    fstr = name + '_decode'
    print('api_func_table.append(' + fstr + ')')
    print('api_name_to_id["' + msg_id_in + '"] =', i)
    print('')


def encode_print(name, id, t):
    args = get_args(t)

    if name.find('_dump') > 0:
        multipart = True
    else:
        multipart = False

    if len(args) < 4:
        print(u"def", name + "(async = False):")
    else:
        print(u"def", name + "(" + ', '.join(args[3:]) + ", async = False):")
    print(u"    global base")
    print(u"    context = get_context(base + " + id + ")")

    print('''
    results_prepare(context)
    waiting_for_reply_set()
    ''')
    if multipart == True:
        print(u"    results_more_set(context)")

    t = list(t)

    # only the last field can be a variable-length-array
    # it can either be 0, or a string
    # first, deal with all the other fields
    pack = '>' + ''.join([get_pack(f)[0] for f in t[:-1]])

    # named variable-length-array
    if len(t[-1]) == 4 and t[-1][2] == '0' and t[-1][3] == t[-2][1]:
        print(u"    vpp_api.write(pack('" + pack + "', base + "
              + id + ", 0, context, " + ', '.join(args[3:-2] + ["len(" + args[-1] + ")"])
              + ") + " + args[-1] + ")")

    # unnamed variable-length-array
    elif len(t[-1]) >= 3 and t[-1][2] == '0':
        print(u"    vpp_api.write(pack('" + pack + "', base + " +
              id + ", 0, context, " + ', '.join(args[3:-1]) + ") + "
              + args[-1] + ")")


    # not a variable-length-array
    else:
        pack += get_pack(t[-1])[0]
        print(u"    vpp_api.write(pack('" + pack + "', base + " + id +
              ", 0, context, " + ', '.join(args[3:]) + "))")

    if multipart == True:
        print(
            u"    vpp_api.write(pack('>HII', VL_API_CONTROL_PING, 0, context))")

    print('''
    if not async:
        results_event_wait(context, 5)
        return results_get(context)
    return context
    ''')

def get_normal_pack(t, i, pack, offset):
    while t:
        f = t.pop(0)
        i += 1
        if len(f) >= 3:
            return t, i, pack, offset, f
        p, elements, size = get_pack(f)
        pack += p
        offset += size
    return t, i, pack, offset, None

def decode_print(name, t):
    #
    # Generate code for each element
    #
    print(u'def ' + name + u'_decode(msg):')
    total = 0
    args = get_args(t)
    print(u"    n = namedtuple('" + name + "', '" + ', '.join(args) + "')")
    print(u"    res = []")

    pack = '>'
    start = 0
    end = 0
    offset = 0
    t = list(t)
    i = 0
    while t:
        t, i, pack, offset, array = get_normal_pack(t, i, pack, offset)
        if array:
            p, elements, size = get_pack(array)

            # Byte string
            if elements > 0 and type_size[array[0]] == 1:
                pack += p
                offset += size * elements
                continue

            # Dump current pack string
            if pack != '>':
                print(u"    tr = unpack_from('" + pack + "', msg[" + str(start) + ":])")
                print(u"    res.extend(list(tr))")
                start += offset
            pack = '>'

            if elements == 0:
                # This has to be the last element
                if len(array) == 3:
                    print(u"    res.append(msg[" + str(offset) + ":])")
                    if len(t) > 0:
                        eprint('WARNING: Variable length array must be last element in message', name, array)

                    continue
                if size == 1 or len(p) == 1:
                    # Do it as a bytestring.
                    if p == 'B':
                        p = 's'
                    # XXX: Assume that length parameter is the previous field. Add validation.
                    print(u"    c = res[" + str(i - 2) + "]")
                    print(u"    tr = unpack_from('>' + str(c) + '" + p + "', msg[" + str(start) + ":])")
                    print(u"    res.append(tr)")
                    continue
                print(u"    tr2 = []")
                print(u"    offset = " + str(total))
                print(u"    for j in range(res[" + str(i - 2) + "]):")
                print(u"        tr2.append(unpack_from('>" + p + "', msg[" + str(start) + ":], offset))")
                print(u"        offset += " + str(size))
                print(u"    res.append(tr2)")
                continue

            # Missing something!!
            print(u"    tr = unpack_from('>" + p + "', msg[" + str(start) + ":])")
            start += size

            print(u"    res.append(tr)")

    if pack != '>':
        print(u"    tr = unpack_from('" + pack + "', msg[" + str(start) + ":])")
        print(u"    res.extend(list(tr))")
    print(u"    return n._make(res)")
    print('')

#
# Generate the main Python file
#
def main():
    print('''
#
# AUTO-GENERATED FILE. PLEASE DO NOT EDIT.
#
from vpp_api_base import *
from struct import *
from collections import namedtuple
import vpp_api
api_func_table = []
api_name_to_id = {}
    ''')

    for i, a in enumerate(messages):
        name = a[0]
        encode_print(name, str(i), a[1:])
        decode_print(name, a[1:])
        api_table_print(name, i)
    footer_print()

if __name__ == "__main__":
    main()
