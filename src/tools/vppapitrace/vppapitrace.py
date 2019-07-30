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
import struct
import sys
import logging
import json
from ipaddress import *
from collections import namedtuple
from vpp_papi import MACAddress, VPPApiJSONFiles
import base64


def apitrace2json(messages, filename):

    result = []
    msgtable_by_id = {}
    msgtable_by_name = {}
    with open(filename, 'rb') as file:
        bytes_read = file.read()
        # Read header
        (nitems, nmsg, wrapped) = struct.unpack_from(">IIB", bytes_read, 0)
        if wrapped:
            sys.stdout.write('Wrapped/incomplete trace, results may vary')
        offset = 9

        i = 0
        while i < nmsg:
            (msgid, name) = struct.unpack_from(">H64s", bytes_read, offset)
            name = name.decode('utf-8').rstrip('\x00')
            msgtable_by_id[msgid] = name
            msgtable_by_name[name] = msgid
            offset += 66
            i += 1

        i = 0
        while i < nitems:
            size = struct.unpack_from(">I", bytes_read, offset)[0]
            offset += 4
            if size == 0:
                break
            msgid = struct.unpack_from(">H", bytes_read, offset)[0]
            name = msgtable_by_id[msgid]
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
    '''Input JSON file and API message definition. Output API trace
       bytestring.'''

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


def topython(messages):
    import pprint
    pp = pprint.PrettyPrinter()

    s = '''\
#!/usr/bin/env python3
from vpp_papi import VPP, VppEnum
vpp = VPP(use_socket=True)
vpp.connect(name='vppapitrace')
'''

    for m in messages:
        a = pp.pformat(m['args'])
        s += 'rv = vpp.api.{}(**{})\n'.format(m['name'], a)
        s += 'print("RV:", rv)\n'
    s += 'vpp.disconnect()\n'

    return s


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true',
                        help='enable debug mode')
    parser.add_argument('--python', action='store_true',
                        help='generate Python code')
    parser.add_argument('--trace', action='store_true',
                        help='generate API trace')
    parser.add_argument('--apidir',
                        help='Location of JSON API definitions')
    parser.add_argument('input',
                        help='Input file (API trace | JSON)')
    parser.add_argument('output',
                        help='Output file (Python | JSON | API trace)')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    # Read API definitions
    apifiles = VPPApiJSONFiles.find_api_files(api_dir=args.apidir)
    messages = {}
    services = {}
    for file in apifiles:
        with open(file) as apidef_file:
            m, s = VPPApiJSONFiles.process_json_file(apidef_file)
            messages.update(m)
            services.update(s)

    if args.trace:
        i = 0
        for k, v in messages.items():
            v._vl_msg_id = i
            i += 1

        n, result = json2apitrace(messages, args.input)
        print('API messages: {}'.format(n))
        header = struct.pack(">IIB", n, len(messages), 0)

        i = 0
        msgtbl = bytes()
        for k, v in messages.items():
            name = k + '_' + v.crc[2:]
            msgtbl += struct.pack('>H64s', v._vl_msg_id, name.encode())

        with open(args.output, 'wb') as outfile:
            outfile.write(header)
            outfile.write(msgtbl)
            outfile.write(result)

    else:
        result = apitrace2json(messages, args.input)
        if args.python:
            s = json.dumps(result, cls=VPPEncoder, default=vpp_encoder)
            x = json.loads(s)
            s = topython(x)
        else:
            s = json.dumps(result, cls=VPPEncoder,
                           default=vpp_encoder, indent=4 * ' ')
        if args.output == '-':
            sys.stdout.write(s + '\n')
        else:
            print('Generating {} from API trace: {}'
                  .format(args.output, args.input))
            with open(args.output, 'w') as outfile:
                outfile.write(s)


main()
