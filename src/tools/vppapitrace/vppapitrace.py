#!/usr/bin/env python3

#
# Copyright (c) 2019 Cisco and/or its affiliates.
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
# Convert from VPP API trace to JSON.

import argparse
import base64
import json
import logging
import os
import struct
import sys
import textwrap
from collections import namedtuple
from ipaddress import *

from vpp_papi import MACAddress, VPPApiJSONFiles


def serialize_likely_small_unsigned_integer(x):
    r = x

    # Low bit set means it fits into 1 byte.
    if r < (1 << 7):
        return struct.pack("B", 1 + 2 * r)

    # Low 2 bits 1 0 means it fits into 2 bytes.
    r -= (1 << 7)
    if r < (1 << 14):
        return struct.pack("<H", 4 * r + 2)

    r -= (1 << 14)
    if r < (1 << 29):
        return struct.pack("<I", 8 * r + 4)

    return struct.pack("<BQ", 0, x)


def unserialize_likely_small_unsigned_integer(data, offset):
    y = struct.unpack_from("B", data, offset)[0]
    if y & 1:
        return y // 2, 1
    r = 1 << 7
    if y & 2:
        p = struct.unpack_from("B", data, offset + 1)[0]
        r += (y // 4) + (p << 6)
        return r, 2
    r += 1 << 14
    if y & 4:
        (p1, p2, p3) = struct.unpack_from("BBB", data, offset+1)
        r += ((y // 8) + (p1 << (5 + 8 * 0))
              + (p2 << (5 + 8 * 1)) + (p3 << (5 + 8 * 2)))
        return r, 3
    return struct.unpack_from(">Q", data, offset+1)[0], 8


def serialize_cstring(s):
    bstring = s.encode('utf8')
    l = len(bstring)
    b = serialize_likely_small_unsigned_integer(l)
    b += struct.pack('{}s'.format(l), bstring)
    return b


def unserialize_cstring(data, offset):
    l, size = unserialize_likely_small_unsigned_integer(data, offset)
    name = struct.unpack_from('{}s'.format(l), data, offset+size)[0]
    return name.decode('utf8'), size + len(name)


def unserialize_msgtbl(data, offset):
    msgtable_by_id = {}
    msgtable_by_name = {}
    i = 0
    nmsg = struct.unpack_from(">I", data, offset)[0]
    o = 4
    while i < nmsg:
        (msgid, size) = unserialize_likely_small_unsigned_integer(
            data, offset + o)
        o += size
        (name, size) = unserialize_cstring(data, offset + o)
        o += size
        msgtable_by_id[msgid] = name
        msgtable_by_name[name] = msgid

        i += 1
    return msgtable_by_id, msgtable_by_name, o


def serialize_msgtbl(messages):
    offset = 0
    # XXX 100K?
    data = bytearray(100000)
    nmsg = len(messages)
    data = struct.pack(">I", nmsg)

    for k, v in messages.items():
        name = k + '_' + v.crc[2:]
        data += serialize_likely_small_unsigned_integer(v._vl_msg_id)
        data += serialize_cstring(name)
    return data


def apitrace2json(messages, filename):
    result = []
    with open(filename, 'rb') as file:
        bytes_read = file.read()
        # Read header
        (nitems, msgtbl_size, wrapped) = struct.unpack_from(">IIB",
                                                            bytes_read, 0)
        logging.debug('nitems: {} message table size: {} wrapped: {}'
                      .format(nitems, msgtbl_size, wrapped))
        if wrapped:
            sys.stdout.write('Wrapped/incomplete trace, results may vary')
        offset = 9

        msgtbl_by_id, msgtbl_by_name, size = unserialize_msgtbl(bytes_read,
                                                                offset)
        offset += size

        i = 0
        while i < nitems:
            size = struct.unpack_from(">I", bytes_read, offset)[0]
            offset += 4
            if size == 0:
                break
            msgid = struct.unpack_from(">H", bytes_read, offset)[0]
            name = msgtbl_by_id[msgid]
            n = name[:name.rfind("_")]
            msgobj = messages[n]
            if n + '_' + msgobj.crc[2:] != name:
                sys.exit("CRC Mismatch between JSON API definition "
                         "and trace. {}".format(name))

            x, s = msgobj.unpack(bytes_read[offset:offset+size])
            msgname = type(x).__name__
            offset += size
            # Replace named tuple illegal _0
            y = x._asdict()
            y.pop('_0')
            result.append({'name': msgname, 'args': y})
            i += 1

    file.close()
    return result


def json2apitrace(messages, filename):
    """Input JSON file and API message definition. Output API trace
    bytestring."""

    msgs = []
    with open(filename, 'r') as file:
        msgs = json.load(file, object_hook=vpp_decode)
    result = b''
    for m in msgs:
        name = m['name']
        msgobj = messages[name]
        m['args']['_vl_msg_id'] = messages[name]._vl_msg_id
        b = msgobj.pack(m['args'])

        result += struct.pack('>I', len(b))
        result += b
    return len(msgs), result


class VPPEncoder(json.JSONEncoder):
    def default(self, o):
        if type(o) is bytes:
            return "base64:" + base64.b64encode(o).decode('utf-8')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, o)

    def encode(self, obj):
        def hint_tuples(item):
            if isinstance(item, tuple):
                return hint_tuples(item._asdict())
            if isinstance(item, list):
                return [hint_tuples(e) for e in item]
            if isinstance(item, dict):
                return {key: hint_tuples(value) for key, value in item.items()}
            else:
                return item

        return super(VPPEncoder, self).encode(hint_tuples(obj))


def vpp_decode(obj):
    for k, v in obj.items():
        if type(v) is str and v.startswith('base64:'):
            s = v.lstrip('base64:')
            obj[k] = base64.b64decode(v[7:])
    return obj


def vpp_encoder(obj):
    if isinstance(obj, IPv6Network):
        return str(obj)
    if isinstance(obj, IPv4Network):
        return str(obj)
    if isinstance(obj, IPv6Address):
        return str(obj)
    if isinstance(obj, IPv4Address):
        return str(obj)
    if isinstance(obj, MACAddress):
        return str(obj)
    if type(obj) is bytes:
        return "base64:" + base64.b64encode(obj).decode('ascii')
    raise TypeError('Unknown object {} {}\n'.format(type(obj), obj))

message_filter = {
    'control_ping',
    'memclnt_create',
    'memclnt_delete',
    'get_first_msg_id',
}

argument_filter = {
    'client_index',
    'context',
}

def topython(messages, services):
    import pprint
    pp = pprint.PrettyPrinter()

    s = '''\
#!/usr/bin/env python3
from vpp_papi import VPP, VppEnum
vpp = VPP(use_socket=True)
vpp.connect(name='vppapitrace')
'''

    for m in messages:
        if m['name'] not in services:
            s += '# ignoring reply message: {}\n'.format(m['name'])
            continue
        if m['name'] in message_filter:
            s += '# ignoring message {}\n'.format(m['name'])
            continue
        for k in argument_filter:
            try:
                m['args'].pop(k)
            except KeyError:
                pass
        a = pp.pformat(m['args'])
        s += 'rv = vpp.api.{}(**{})\n'.format(m['name'], a)
        s += 'print("RV:", rv)\n'
    s += 'vpp.disconnect()\n'

    return s

def todump_items(k, v, level):
    klen = len(k) if k else 0
    spaces = '  ' * level + ' ' * (klen + 3)
    wrapper = textwrap.TextWrapper(initial_indent="", subsequent_indent=spaces, width=60)
    s = ''
    if type(v) is dict:
        if k:
            s += '   ' * level + '{}:\n'.format(k)
        for k2, v2 in v.items():
            s += todump_items(k2, v2, level + 1)
        return s

    if type(v) is list:
        for v2 in v:
            s += '{}'.format(todump_items(k, v2, level))
        return s

    if type(v) is bytes:
        w = wrapper.fill(bytes.hex(v))
        s += '   ' * level + '{}: {}\n'.format(k, w)
    else:
        if type(v) is str:
            v = wrapper.fill(v)
        s += '   ' * level + '{}: {}\n'.format(k, v)
    return s


def todump(messages, services):
    import pprint
    pp = pprint.PrettyPrinter()

    s = ''
    for m in messages:
        if m['name'] not in services:
            s += '# ignoring reply message: {}\n'.format(m['name'])
            continue
        #if m['name'] in message_filter:
        #    s += '# ignoring message {}\n'.format(m['name'])
        #    continue
        for k in argument_filter:
            try:
                m['args'].pop(k)
            except KeyError:
                pass
        a = pp.pformat(m['args'])
        s += '{}:\n'.format(m['name'])
        s += todump_items(None, m['args'], 0)
    return s


def init_api(apidir):
    # Read API definitions
    apifiles = VPPApiJSONFiles.find_api_files(api_dir=apidir)
    messages = {}
    services = {}
    for file in apifiles:
        with open(file) as apidef_file:
            m, s = VPPApiJSONFiles.process_json_file(apidef_file)
            messages.update(m)
            services.update(s)
    return messages, services


def replaymsgs(vpp, msgs):
    for m in msgs:
        name = m['name']
        if name not in vpp.services:
            continue
        if name == 'control_ping':
            continue
        try:
            m['args'].pop('client_index')
        except KeyError:
            pass
        if m['args']['context'] == 0:
            m['args']['context'] = 1
        f = vpp.get_function(name)
        rv = f(**m['args'])
        print('RV {}'.format(rv))


def replay(args):
    """Replay into running VPP instance"""

    from vpp_papi import VPP

    JSON = 1
    APITRACE = 2

    filename, file_extension = os.path.splitext(args.input)
    input_type = JSON if file_extension == '.json' else APITRACE

    vpp = VPP(use_socket=args.socket)
    rv = vpp.connect(name='vppapireplay', chroot_prefix=args.shmprefix)
    if rv != 0:
        sys.exit('Cannot connect to VPP')

    if input_type == JSON:
        with open(args.input, 'r') as file:
            msgs = json.load(file, object_hook=vpp_decode)
    else:
        msgs = apitrace2json(messages, args.input)

    replaymsgs(vpp, msgs)

    vpp.disconnect()


def generate(args):
    """Generate JSON"""

    JSON = 1
    APITRACE = 2
    PYTHON = 3
    DUMP = 4

    filename, file_extension = os.path.splitext(args.input)
    input_type = JSON if file_extension == '.json' else APITRACE
    filename, file_extension = os.path.splitext(args.output)

    if args.todump:
        output_type = DUMP
    else:
        if file_extension == '.json' or filename == '-':
            output_type = JSON
        elif file_extension == '.py':
            output_type = PYTHON
        else:
            output_type = APITRACE

    if input_type == output_type:
        sys.exit("error: Nothing to convert between")

    if input_type != JSON and output_type == APITRACE:
        sys.exit("error: Input file must be JSON file: {}".format(args.input))

    messages, services = init_api(args.apidir)

    if input_type == JSON and output_type == APITRACE:
        i = 0
        for k, v in messages.items():
            v._vl_msg_id = i
            i += 1

        n, result = json2apitrace(messages, args.input)
        msgtbl = serialize_msgtbl(messages)

        print('API messages: {}'.format(n))
        header = struct.pack(">IIB", n, len(msgtbl), 0)

        with open(args.output, 'wb') as outfile:
            outfile.write(header)
            outfile.write(msgtbl)
            outfile.write(result)

        return

    if input_type == APITRACE:
        result = apitrace2json(messages, args.input)
        if output_type == PYTHON:
            s = json.dumps(result, cls=VPPEncoder, default=vpp_encoder)
            x = json.loads(s, object_hook=vpp_decode)
            s = topython(x, services)
        elif output_type == DUMP:
            s = json.dumps(result, cls=VPPEncoder, default=vpp_encoder)
            x = json.loads(s, object_hook=vpp_decode)
            s = todump(x, services)
        else:
            s = json.dumps(result, cls=VPPEncoder,
                           default=vpp_encoder, indent=4 * ' ')
    elif output_type == PYTHON:
        with open(args.input, 'r') as file:
            x = json.load(file, object_hook=vpp_decode)
            s = topython(x, services)
    else:
        sys.exit('Input file must be API trace file: {}'.format(args.input))

    if args.output == '-':
        sys.stdout.write(s + '\n')
    else:
        print('Generating {} from API trace: {}'
              .format(args.output, args.input))
        with open(args.output, 'w') as outfile:
            outfile.write(s)

def general(args):
    return

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true',
                        help='enable debug mode')
    parser.add_argument('--apidir',
                        help='Location of JSON API definitions')

    parser.set_defaults(func=general)
    subparsers = parser.add_subparsers(title='subcommands',
                                       description='valid subcommands',
                                       help='additional help')

    parser_convert = subparsers.add_parser('convert',
                                           help='Convert API trace to JSON or Python and back')
    parser_convert.add_argument('input',
                                help='Input file (API trace | JSON)')
    parser_convert.add_argument('--todump', action='store_true', help='Output text format')
    parser_convert.add_argument('output',
                                help='Output file (Python | JSON | API trace)')
    parser_convert.set_defaults(func=generate)


    parser_replay = subparsers.add_parser('replay',
                                          help='Replay messages to running VPP instance')
    parser_replay.add_argument('input', help='Input file (API trace | JSON)')
    parser_replay.add_argument('--socket', action='store_true',
                               help='use default socket to connect to VPP')
    parser_replay.add_argument('--shmprefix',
                               help='connect to VPP on shared memory prefix')
    parser_replay.set_defaults(func=replay)

    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    args.func(args)


main()
