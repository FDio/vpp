#!/usr/bin/env python3

#
# to_json:
# 1. Connect to VPP to get message table.
# 2. Read binary file
# 3. Generate JSON representation
#
# to_binary:
# 1. Connect to VPP to get message table.
# 2. Read JSON file
# 3. Generate binary file
#
# To consider:
# Include message table in API trace file, so a running VPP is not required.
#

import argparse
import struct
import sys
import logging
import yaml
import json
from ipaddress import *
from collections import namedtuple
import simplejson as json
from simplejson import JSONEncoder
from vpp_papi import VPP

class VPPEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, IPv6Network):
            return str(obj)
        if isinstance(obj, IPv4Network):
            return str(obj)
        if type(obj) is bytes:
            return str(obj)

        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

VL_API_LITTLE_ENDIAN = 0x00
VL_API_BIG_ENDIAN    = 0x01

def apitrace2json(vpp, filename):

    result = []
    with open(filename, 'rb') as file:
        bytes_read = file.read()
        # Read header
        endian = struct.unpack("B", bytes_read[:1])[0]
        if endian == VL_API_LITTLE_ENDIAN:
            byteorder = '<'
        elif endian == VL_API_BIG_ENDIAN:
            byteorder = '>'
        else:
            sys.exit('Binary file header error {}'.format(filename))

        (endian, wrapped, nitems) = struct.unpack(byteorder + "BBI", bytes_read[:6])
        if wrapped:
            sys.stdout.write('Wrapped/incomplete trace, results may vary')
        i = 0
        offset = 6
        while i < nitems:
            size = struct.unpack_from(">I", bytes_read, offset)[0]
            offset += 4
            if size == 0:
                break
            msgid = struct.unpack_from(">H", bytes_read, offset)[0]
            msgobj = vpp.id_msgdef[msgid]

            i += 1
            x, s = msgobj.unpack(bytes_read[offset:offset+size])
            msgname = type(x).__name__
            offset += size
            # Replace named tuple illegal _0
            y = x._asdict()
            y['_vl_msg_id'] = y.pop('_0')
            result.append({'name': msgname, 'args': y})
    file.close()
    return result

def json2apitrace(vpp, filename):
    msgs = []
    with open(filename, 'r') as file:
        msgs = json.load(file)
    result = b''
    for m in msgs:
        msgid = m['args']['_vl_msg_id']
        msgobj = vpp.id_msgdef[msgid]
        b = msgobj.pack(m['args'])
        x = msgobj.unpack(b)
        result += struct.pack('>I', len(b))
        result += b
    return len(msgs), result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tojson', action='store_true', help='read from API trace and convert to JSON')
    parser.add_argument('--totrace', action='store_true', help='read from API trace and convert to JSON')
    parser.add_argument('--socket', action='store_true', help='use default socket to connect to VPP')
    parser.add_argument('--shmprefix', help='connect to VPP on shared memory prefix')
    parser.add_argument('input', help='Input file (API trace or JSON)')
    parser.add_argument('output', help='Output file (API trace or JSON)')
    args = parser.parse_args()

    vpp = VPP(use_socket=args.socket)
    rv = vpp.connect(name='vppapitrace', chroot_prefix=args.shmprefix)
    if rv != 0:
        sys.exit('Cannot connect to VPP')
    #logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    if args.tojson:
        print('Generating JSON {} from API trace: {}'.format(args.output, args.input))
        result = apitrace2json(vpp, args.input)
        if args.output == '-':
            sys.stdout.write(json.dumps(result, cls=VPPEncoder, indent=4 * ' '))
        else:
            with open(args.output, 'w') as outfile:
                json.dump(result, outfile, cls=VPPEncoder, indent=4 * ' ')
    elif args.totrace:
        print('Generating API trace {} from JSON: {}'.format(args.output, args.input))
        n, result = json2apitrace(vpp, args.input)
        header = struct.pack(">BBI", VL_API_BIG_ENDIAN, 0, n)
        with open(args.output, 'wb') as outfile:
            outfile.write(header)
            outfile.write(result)

    vpp.disconnect()


main()
