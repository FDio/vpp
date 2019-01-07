#
# Copyright (c) 2018 Cisco and/or its affiliates.
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

import struct
import collections
from enum import IntEnum
import logging
from . import vpp_format
import ipaddress
import sys
import socket

#
# Set log-level in application by doing e.g.:
# logger = logging.getLogger('vpp_serializer')
# logger.setLevel(logging.DEBUG)
#
logger = logging.getLogger(__name__)

if sys.version[0] == '2':
    def check(d): type(d) is dict
else:
    def check(d): type(d) is dict or type(d) is bytes


def conversion_required(data, field_type):
    if check(data):
        return False
    try:
        if type(data).__name__ in vpp_format.conversion_table[field_type]:
            return True
    except KeyError:
        return False


def conversion_packer(data, field_type):
    t = type(data).__name__
    return types[field_type].pack(vpp_format.
                                  conversion_table[field_type][t](data))


def conversion_unpacker(data, field_type):
    if field_type not in vpp_format.conversion_unpacker_table:
        return data
    return vpp_format.conversion_unpacker_table[field_type](data)


class BaseTypes(object):
    def __init__(self, type, elements=0):
        base_types = {'u8': '>B',
                      'string': '>s',
                      'u16': '>H',
                      'u32': '>I',
                      'i32': '>i',
                      'u64': '>Q',
                      'f64': '>d',
                      'bool': '>?',
                      'header': '>HI'}

        if elements > 0 and (type == 'u8' or type == 'string'):
            self.packer = struct.Struct('>%ss' % elements)
        else:
            self.packer = struct.Struct(base_types[type])
        self.size = self.packer.size

    def pack(self, data, kwargs=None):
        if not data:  # Default to zero if not specified
            data = 0
        return self.packer.pack(data)

    def unpack(self, data, offset, result=None, ntc=False):
        return self.packer.unpack_from(data, offset)[0], self.packer.size


class String(object):
    def __init__(self):
        self.name = 'string'
        self.size = 1
        self.length_field_packer = BaseTypes('u32')

    def pack(self, list, kwargs=None):
        if not list:
            return self.length_field_packer.pack(0) + b""
        return self.length_field_packer.pack(len(list)) + list.encode('utf8')

    def unpack(self, data, offset=0, result=None, ntc=False):
        length, length_field_size = self.length_field_packer.unpack(data,
                                                                    offset)
        if length == 0:
            return b'', 0
        p = BaseTypes('u8', length)
        x, size = p.unpack(data, offset + length_field_size)
        x2 = x.split(b'\0', 1)[0]
        return (x2.decode('utf8'), size + length_field_size)


types = {'u8': BaseTypes('u8'), 'u16': BaseTypes('u16'),
         'u32': BaseTypes('u32'), 'i32': BaseTypes('i32'),
         'u64': BaseTypes('u64'), 'f64': BaseTypes('f64'),
         'bool': BaseTypes('bool'), 'string': String()}


def vpp_get_type(name):
    try:
        return types[name]
    except KeyError:
        return None


class VPPSerializerValueError(ValueError):
    pass


class FixedList_u8(object):
    def __init__(self, name, field_type, num):
        self.name = name
        self.num = num
        self.packer = BaseTypes(field_type, num)
        self.size = self.packer.size
        self.field_type = field_type

    def pack(self, data, kwargs=None):
        """Packs a fixed length bytestring. Left-pads with zeros
        if input data is too short."""
        if not data:
            return b'\x00' * self.size

        if len(data) > self.num:
            raise VPPSerializerValueError(
                'Fixed list length error for "{}", got: {}'
                ' expected: {}'
                .format(self.name, len(data), self.num))

        return self.packer.pack(data)

    def unpack(self, data, offset=0, result=None, ntc=False):
        if len(data[offset:]) < self.num:
            raise VPPSerializerValueError(
                'Invalid array length for "{}" got {}'
                ' expected {}'
                .format(self.name, len(data[offset:]), self.num))
        if self.field_type == 'string':
            s = self.packer.unpack(data, offset)
            s2 = s[0].split(b'\0', 1)[0]
            return (s2.decode('utf-8'), self.num)
        return self.packer.unpack(data, offset)


class FixedList(object):
    def __init__(self, name, field_type, num):
        self.num = num
        self.packer = types[field_type]
        self.size = self.packer.size * num
        self.name = name
        self.field_type = field_type

    def pack(self, list, kwargs):
        if len(list) != self.num:
            raise VPPSerializerValueError(
                'Fixed list length error, got: {} expected: {}'
                .format(len(list), self.num))
        b = bytes()
        for e in list:
            b += self.packer.pack(e)
        return b

    def unpack(self, data, offset=0, result=None, ntc=False):
        # Return a list of arguments
        result = []
        total = 0
        for e in range(self.num):
            x, size = self.packer.unpack(data, offset, ntc=ntc)
            result.append(x)
            offset += size
            total += size
        return result, total


class VLAList(object):
    def __init__(self, name, field_type, len_field_name, index):
        self.name = name
        self.field_type = field_type
        self.index = index
        self.packer = types[field_type]
        self.size = self.packer.size
        self.length_field = len_field_name

    def pack(self, list, kwargs=None):
        if not list:
            return b""
        if len(list) != kwargs[self.length_field]:
            raise VPPSerializerValueError(
                'Variable length error, got: {} expected: {}'
                .format(len(list), kwargs[self.length_field]))
        b = bytes()

        # u8 array

        if self.packer.size == 1:
            return bytearray(list)

        for e in list:
            b += self.packer.pack(e)
        return b

    def unpack(self, data, offset=0, result=None, ntc=False):
        # Return a list of arguments
        total = 0

        # u8 array
        if self.packer.size == 1:
            if result[self.index] == 0:
                return b'', 0
            p = BaseTypes('u8', result[self.index])
            return p.unpack(data, offset, ntc=ntc)

        r = []
        for e in range(result[self.index]):
            x, size = self.packer.unpack(data, offset, ntc=ntc)
            r.append(x)
            offset += size
            total += size
        return r, total


class VLAList_legacy():
    def __init__(self, name, field_type):
        self.packer = types[field_type]
        self.size = self.packer.size

    def pack(self, list, kwargs=None):
        if self.packer.size == 1:
            return bytes(list)

        b = bytes()
        for e in list:
            b += self.packer.pack(e)
        return b

    def unpack(self, data, offset=0, result=None, ntc=False):
        total = 0
        # Return a list of arguments
        if (len(data) - offset) % self.packer.size:
            raise VPPSerializerValueError(
                'Legacy Variable Length Array length mismatch.')
        elements = int((len(data) - offset) / self.packer.size)
        r = []
        for e in range(elements):
            x, size = self.packer.unpack(data, offset, ntc=ntc)
            r.append(x)
            offset += self.packer.size
            total += size
        return r, total


class VPPEnumType(object):
    def __init__(self, name, msgdef):
        self.size = types['u32'].size
        e_hash = {}
        for f in msgdef:
            if type(f) is dict and 'enumtype' in f:
                if f['enumtype'] != 'u32':
                    raise NotImplementedError
                continue
            ename, evalue = f
            e_hash[ename] = evalue
        self.enum = IntEnum(name, e_hash)
        types[name] = self

    def __getattr__(self, name):
        return self.enum[name]

    def __nonzero__(self):
        return True

    def pack(self, data, kwargs=None):
        return types['u32'].pack(data)

    def unpack(self, data, offset=0, result=None, ntc=False):
        x, size = types['u32'].unpack(data, offset)
        return self.enum(x), size


class VPPUnionType(object):
    def __init__(self, name, msgdef):
        self.name = name
        self.size = 0
        self.maxindex = 0
        fields = []
        self.packers = collections.OrderedDict()
        for i, f in enumerate(msgdef):
            if type(f) is dict and 'crc' in f:
                self.crc = f['crc']
                continue
            f_type, f_name = f
            if f_type not in types:
                raise VPPSerializerValueError(
                    'Unknown message type {}'.format(f_type))
            fields.append(f_name)
            size = types[f_type].size
            self.packers[f_name] = types[f_type]
            if size > self.size:
                self.size = size
                self.maxindex = i

        types[name] = self
        self.tuple = collections.namedtuple(name, fields, rename=True)

    # Union of variable length?
    def pack(self, data, kwargs=None):
        if not data:
            return b'\x00' * self.size

        for k, v in data.items():
            logger.debug("Key: {} Value: {}".format(k, v))
            b = self.packers[k].pack(v, kwargs)
            break
        r = bytearray(self.size)
        r[:len(b)] = b
        return r

    def unpack(self, data, offset=0, result=None, ntc=False):
        r = []
        maxsize = 0
        for k, p in self.packers.items():
            x, size = p.unpack(data, offset, ntc=ntc)
            if size > maxsize:
                maxsize = size
            r.append(x)
        return self.tuple._make(r), maxsize


class VPPTypeAlias(object):
    def __init__(self, name, msgdef):
        self.name = name
        t = vpp_get_type(msgdef['type'])
        if not t:
            raise ValueError()
        if 'length' in msgdef:
            if msgdef['length'] == 0:
                raise ValueError()
            if msgdef['type'] == 'u8':
                self.packer = FixedList_u8(name, msgdef['type'],
                                           msgdef['length'])
                self.size = self.packer.size
            else:
                self.packer = FixedList(name, msgdef['type'], msgdef['length'])
        else:
            self.packer = t
            self.size = t.size

        types[name] = self

    def pack(self, data, kwargs=None):
        if data and conversion_required(data, self.name):
            try:
                return conversion_packer(data, self.name)
            # Python 2 and 3 raises different exceptions from inet_pton
            except(OSError, socket.error, TypeError):
                pass

        return self.packer.pack(data, kwargs)

    def unpack(self, data, offset=0, result=None, ntc=False):
        t, size = self.packer.unpack(data, offset, result, ntc=ntc)
        if not ntc:
            return conversion_unpacker(t, self.name), size
        return t, size


class VPPType(object):
    # Set everything up to be able to pack / unpack
    def __init__(self, name, msgdef):
        self.name = name
        self.msgdef = msgdef
        self.packers = []
        self.fields = []
        self.fieldtypes = []
        self.field_by_name = {}
        size = 0
        for i, f in enumerate(msgdef):
            if type(f) is dict and 'crc' in f:
                self.crc = f['crc']
                continue
            f_type, f_name = f[:2]
            self.fields.append(f_name)
            self.field_by_name[f_name] = None
            self.fieldtypes.append(f_type)
            if f_type not in types:
                raise VPPSerializerValueError(
                    'Unknown message type {}'.format(f_type))
            if len(f) == 3:  # list
                list_elements = f[2]
                if list_elements == 0:
                    p = VLAList_legacy(f_name, f_type)
                    self.packers.append(p)
                elif f_type == 'u8' or f_type == 'string':
                    p = FixedList_u8(f_name, f_type, list_elements)
                    self.packers.append(p)
                    size += p.size
                else:
                    p = FixedList(f_name, f_type, list_elements)
                    self.packers.append(p)
                    size += p.size
            elif len(f) == 4:  # Variable length list
                length_index = self.fields.index(f[3])
                p = VLAList(f_name, f_type, f[3], length_index)
                self.packers.append(p)
            else:
                self.packers.append(types[f_type])
                size += types[f_type].size

        self.size = size
        self.tuple = collections.namedtuple(name, self.fields, rename=True)
        types[name] = self

    def pack(self, data, kwargs=None):
        if not kwargs:
            kwargs = data
        b = bytes()

        # Try one of the format functions
        if data and conversion_required(data, self.name):
            return conversion_packer(data, self.name)

        for i, a in enumerate(self.fields):
            if data and type(data) is not dict and a not in data:
                raise VPPSerializerValueError(
                    "Invalid argument: {} expected {}.{}".
                    format(data, self.name, a))

            # Defaulting to zero.
            if not data or a not in data:  # Default to 0
                arg = None
                kwarg = None  # No default for VLA
            else:
                arg = data[a]
                kwarg = kwargs[a] if a in kwargs else None
            if isinstance(self.packers[i], VPPType):
                b += self.packers[i].pack(arg, kwarg)
            else:
                b += self.packers[i].pack(arg, kwargs)

        return b

    def unpack(self, data, offset=0, result=None, ntc=False):
        # Return a list of arguments
        result = []
        total = 0
        for p in self.packers:
            x, size = p.unpack(data, offset, result, ntc)
            if type(x) is tuple and len(x) == 1:
                x = x[0]
            result.append(x)
            offset += size
            total += size
        t = self.tuple._make(result)
        if not ntc:
            t = conversion_unpacker(t, self.name)
        return t, total


class VPPMessage(VPPType):
    pass
