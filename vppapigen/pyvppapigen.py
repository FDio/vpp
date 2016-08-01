#!/usr/bin/env python3
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
                 'vl_api_ip4_fib_counter_t' : 'IBQQ',
                 'vl_api_ip6_fib_counter_t' : 'QQBQQ',
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
             'vl_api_ip4_fib_counter_t' : 21,
             'vl_api_ip6_fib_counter_t' : 33,
};

def get_args(t):
    argslist = []
    for i in t:
        if i[1][0] == '_':
            argslist.append(i[1][1:])
        else:
            argslist.append(i[1])

    return argslist

def get_pack(t):
    zeroarray = False
    bytecount = 0
    pack = '>'
    tup = u''
    j = -1
    for i in t:
        if len(i) == 4:
            print('##i:', i)
        j += 1
        if len(i) is 3 or len(i) is 4:  # TODO: add support for variable length arrays (VPP-162)
            size = type_size[i[0]]
            bytecount += size * int(i[2])
            # Check if we have a zero length array
            if i[2] == '0':
                tup += 'msg[' + str(bytecount) + ':],'
                zeroarray = True
                continue
            if size == 1:
                n = i[2] * size
                pack += str(n) + 's'
                tup += 'tr[' + str(j) + '],'
                continue
            pack += format_struct[i[0]] * int(i[2])
            tup += 'tr[' + str(j) + ':' + str(j + int(i[2])) + '],'
            j += int(i[2]) - 1
        else:
            bytecount += type_size[i[0]]
            pack += format_struct[i[0]]
            tup += 'tr[' + str(j) + '],'
    return pack, bytecount, tup, zeroarray

def get_reply_func(f):
    if f['name']+'_reply' in func_name:
        return func_name[f['name']+'_reply']
    if f['name'].find('_dump') > 0:
        r = f['name'].replace('_dump','_details')
        if r in func_name:
            return func_name[r]
    return None

def get_definitions():
    # Pass 1
    func_list = []
    func_name = {}
    i = 1
    for a in vppapidef:
        pack, packlen, tup, zeroarray = get_pack(a[1:])
        func_name[a[0]] = dict([('name', a[0]), ('pack', pack), ('packlen', packlen), ('tup', tup), ('args', get_args(a[1:])),
                                ('zeroarray', zeroarray)])
        func_list.append(func_name[a[0]])  # Indexed by name
    return func_list, func_name


#
# Print array with a hash of 'decode' and 'multipart'
# Simplify to do only decode for now. And deduce multipart from _dump?
#
def decode_function_print(name, args, pack, packlen, tup):

    print(u'def ' + name + u'_decode(msg):')
    print(u"    n = namedtuple('" + name + "', '" + ', '.join(args) + "')" +
    '''
    if not n:
        return None
    ''')
    print(u"    tr = unpack('" + pack + "', msg[:" + str(packlen) + "])")
    print(u"    r = n._make((" + tup + "))" +
    '''
    if not r:
        return None
    return r
    ''')

def function_print(name, id, args, pack, multipart, zeroarray):
    if len(args) < 4:
        print(u"def", name + "(async = False):")
    else:
        print(u"def", name + "(" + ', '.join(args[3:]) + ", async = False):")
    print(u"    global base")
    print(u"    context = get_context(" + id + ")")

    print('''
    results_prepare(context)
    waiting_for_reply_set()
    ''')
    if multipart == True:
        print(u"    results_more_set(context)")

    if zeroarray == True:
        print(u"    vpp_api.write(pack('" + pack + "', " + id + ", 0, context, " + ', '.join(args[3:-1]) + ") + " + args[-1] + ")")
    else:
        print(u"    vpp_api.write(pack('" + pack + "', " + id + ", 0, context, " + ', '.join(args[3:]) + "))")

    if multipart == True:
        print(u"    vpp_api.write(pack('>HII', VL_API_CONTROL_PING, 0, context))")

    print('''
    if not async:
        results_event_wait(context, 5)
        return results_get(context)
    return context
    ''')


#
# Generate the main Python file
#

print('''

#
# AUTO-GENERATED FILE. PLEASE DO NOT EDIT.
#
from vpp_api_base import *
from struct import *
from collections import namedtuple
import vpp_api
''')

func_list, func_name = get_definitions()

# Pass 2

#
# 1) The VPE API lacks a clear definition of what messages are reply messages
# 2) Length is missing, and has to be pre-known or in case of variable sized ones calculated per message type
#
for i, f in enumerate(func_list):
    #if f['name'].find('_reply') > 0 or f['name'].find('_details') > 0:
    decode_function_print(f['name'], f['args'], f['pack'], f['packlen'], f['tup'])

    #r = get_reply_func(f)
    #if not r:
    #    #
    #    # XXX: Functions here are not taken care of. E.g. events
    #    #
    #    print('Missing function', f)
    #    continue

    if f['name'].find('_dump') > 0:
        f['multipart'] = True
    else:
        f['multipart'] = False
    #msg_id_in = 'VL_API_' + f['name'].upper()
    msg_id_in = 'base + ' + str(i)
    function_print(f['name'], msg_id_in, f['args'], f['pack'], f['multipart'], f['zeroarray'])

#
# Create plugin registration function
#
print('def msg_id_base_set(b):')
print('    global base')
print('    base = b')

print("api_func_table = []")
print("api_name_to_id = {}")
for i, f in enumerate(func_list):
    msg_id_in = 'VL_API_' + f['name'].upper()
    fstr = f['name'] + '_decode'
    print('api_func_table.append(' + fstr + ')')
    print('api_name_to_id["' + msg_id_in + '"] =', i)
print("import os")
print("name = os.path.splitext(os.path.basename(__file__))[0]")
print("plugin_register(name, api_func_table, api_name_to_id,", vl_api_version, ", msg_id_base_set)")
