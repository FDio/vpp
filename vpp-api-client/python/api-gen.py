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

import argparse, sys, os, importlib, pprint

parser = argparse.ArgumentParser(description='VPP Python API generator')
parser.add_argument('-i', action="store", dest="inputfile")
parser.add_argument('-c', '--cfile', action="store")
args = parser.parse_args()

sys.path.append(".")

inputfile = args.inputfile.replace('.py', '')
cfg = importlib.import_module(inputfile, package=None)

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
    args = None
    for i in t:
        arg = i[1]
        arg = arg.replace('_','')
        if args == None:
            args = arg
            continue
        args = args + ', ' +  arg
    return args

def get_pack(t):
    bytecount = 0
    pack = '>'
    tup = u''
    j = -1
    for i in t:
        j += 1
        if len(i) is 3:
            size = type_size[i[0]]
            bytecount += size * int(i[2])
            if i[2] == '0':
                tup += 'msg[' + str(bytecount) + ':],'
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
    return pack, bytecount, tup

def get_reply_func(f):
    if f['name']+'_reply' in func_name:
        return func_name[f['name']+'_reply']
    if f['name'].find('_dump') > 0:
        r = f['name'].replace('_dump','_details')
        if r in func_name:
            return func_name[r]
    return None

def get_enums():
    # Read enums from stdin
    enums_by_name = {}
    enums_by_index = {}
    i = 1
    for l in sys.stdin:
        l = l.replace(',\n','')
        print l, "=", i

        l = l.replace('VL_API_','').lower()
        enums_by_name[l] = i
        enums_by_index[i] = l

        i += 1
    return enums_by_name, enums_by_index

def get_definitions():
    # Pass 1
    func_list = []
    func_name = {}
    i = 1
    for a in cfg.vppapidef:
        pack, packlen, tup = get_pack(a[1:])
        func_name[a[0]] = dict([('name', a[0]), ('args', get_args(a[4:])), ('full_args', get_args(a[1:])), ('pack', pack), ('packlen', packlen), ('tup', tup)])
        func_list.append(func_name[a[0]])  # Indexed by name
    return func_list, func_name

def generate_c_macros(func_list, enums_by_name):
    file = open(args.cfile, 'w+')
    print >>file, "#define foreach_api_msg \\"
    for f in func_list:
        if not f['name'] in enums_by_name:
            continue
        print >>file, "_(" + f['name'].upper() + ", " + f['name'] + ") \\"
    print >>file, '''
void pneum_set_handlers(void) {
#define _(N,n)							\\
  api_func_table[VL_API_##N] = sizeof(vl_api_##n##_t);
  foreach_api_msg;
#undef _
}
    '''

print '''
import threading
import vpp_papi
from struct import *
import pneum
from collections import namedtuple
'''


enums_by_name, enums_by_index = get_enums()
func_list, func_name = get_definitions()

#
# Not needed with the new msg_size field.
# generate_c_macros(func_list, enums_by_name)
#

pp = pprint.PrettyPrinter(indent=4)
#print 'enums_by_index =', pp.pprint(enums_by_index)
#print 'func_name =', pp.pprint(func_name)

# Pass 2

#
# XXX:Deal with empty arrays
# Print array with a hash of 'decode' and 'multipart'
# Simplify to do only decode for now. And deduce multipart from _dump?
#
def decode_function_print(name, args, pack, packlen, tup):

    print(u'def ' + name + u'_decode(msg):')
    print(u"    n = namedtuple('" + name + "', '" + args + "')" +
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

def function_print(name, id, args, pack, multipart):
    if not args:
        args = ""
        print "def", name + "(async = False):"
    else:
        print "def", name + "(" + args + ",async = False):"
    print "    context = vpp_papi.get_context(" + id + ")"

    print '''
    vpp_papi.results[context] = {}
    vpp_papi.results[context]['e'] = threading.Event()
    vpp_papi.results[context]['e'].clear()
    vpp_papi.results[context]['r'] = []
    vpp_papi.waiting_for_reply = True
    '''
    if multipart == True:
        print "    vpp_papi.results[context]['m'] = True"

    print "    pneum.write(pack('" + pack + "', " + id + ", 0, context, " + args + "))"

    if multipart == True:
        print "    pneum.write(pack('>HII', VL_API_CONTROL_PING, 0, context))"

    print '''
    if not async:
        vpp_papi.results[context]['e'].wait(5)
        return vpp_papi.results[context]['r']
    return context
    '''

#
# Should dynamically create size
#
def api_table_print (name, msg_id):
    f = name + '_decode'
    print('api_func_table[' + msg_id + '] = ' + f)
    
#
# 1) The VPE API lacks a clear definition of what messages are reply messages
# 2) Length is missing, and has to be pre-known or in case of variable sized ones calculated per message type
#
for f in func_list:
    #if f['name'].find('_reply') > 0 or f['name'].find('_details') > 0:
    decode_function_print(f['name'], f['full_args'], f['pack'], f['packlen'], f['tup'])

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
    msg_id_in = 'VL_API_' + f['name'].upper()
    function_print(f['name'], msg_id_in, f['args'], f['pack'], f['multipart'])


print "api_func_table = [0] * 10000"
for f in func_list:
    #    if f['name'].find('_reply') > 0 or f['name'].find('_details') > 0:
    msg_id_in = 'VL_API_' + f['name'].upper()
    api_table_print(f['name'], msg_id_in)
