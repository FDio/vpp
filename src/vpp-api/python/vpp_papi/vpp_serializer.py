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
from .vpp_format import VPPFormat

#
# Set log-level in application by doing e.g.:
# logger = logging.getLogger('vpp_serializer')
# logger.setLevel(logging.DEBUG)
#
logger = logging.getLogger(__name__)


class BaseTypes():
    def __init__(self, type, elements=0):
        base_types = {'u8': '>B',
                      'u16': '>H',
                      'u32': '>I',
                      'i32': '>i',
                      'u64': '>Q',
                      'f64': '>d',
                      'bool': '>?',
                      'header': '>HI'}

        if elements > 0 and type == 'u8':
            self.packer = struct.Struct('>%ss' % elements)
        else:
            self.packer = struct.Struct(base_types[type])
        self.size = self.packer.size
        logger.debug('Adding {} with format: {}'
                     .format(type, base_types[type]))

    def pack(self, data, kwargs=None):
        if not data:  # Default to zero if not specified
            data = 0
        return self.packer.pack(data)

    def unpack(self, data, offset, result=None):
        return self.packer.unpack_from(data, offset)[0], self.packer.size


types = {}
types['u8'] = BaseTypes('u8')
types['u16'] = BaseTypes('u16')
types['u32'] = BaseTypes('u32')
types['i32'] = BaseTypes('i32')
types['u64'] = BaseTypes('u64')
types['f64'] = BaseTypes('f64')
types['bool'] = BaseTypes('bool')

def vpp_get_type(name):
    try:
        return types[name]
    except KeyError:
        return None


class FixedList_u8():
    def __init__(self, name, field_type, num):
        self.name = name
        self.num = num
        self.packer = BaseTypes(field_type, num)
        self.size = self.packer.size

    def pack(self, list, kwargs):
        """Packs a fixed length bytestring. Left-pads with zeros
        if input data is too short."""
        if not list:
            return b'\x00' * self.size
        if len(list) > self.num:
            raise ValueError('Fixed list length error for "{}", got: {}'
                             ' expected: {}'
                             .format(self.name, len(list), self.num))
        return self.packer.pack(list)

    def unpack(self, data, offset=0, result=None):
        if len(data[offset:]) < self.num:
            raise ValueError('Invalid array length for "{}" got {}'
                             ' expected {}'
                             .format(self.name, len(data[offset:]), self.num))
        return self.packer.unpack(data, offset)


class FixedList():
    def __init__(self, name, field_type, num):
        self.num = num
        self.packer = types[field_type]
        self.size = self.packer.size * num

    def pack(self, list, kwargs):
        if len(list) != self.num:
            raise ValueError('Fixed list length error, got: {} expected: {}'
                             .format(len(list), self.num))
        b = bytes()
        for e in list:
            b += self.packer.pack(e)
        return b

    def unpack(self, data, offset=0, result=None):
        # Return a list of arguments
        result = []
        total = 0
        for e in range(self.num):
            x, size = self.packer.unpack(data, offset)
            result.append(x)
            offset += size
            total += size
        return result, total


class VLAList():
    def __init__(self, name, field_type, len_field_name, index):
        self.name = name
        self.index = index
        self.packer = types[field_type]
        self.size = self.packer.size
        self.length_field = len_field_name

    def pack(self, list, kwargs=None):
        if not list:
            return b""
        if len(list) != kwargs[self.length_field]:
            raise ValueError('Variable length error, got: {} expected: {}'
                             .format(len(list), kwargs[self.length_field]))
        b = bytes()

        # u8 array
        if self.packer.size == 1:
            return bytearray(list)

        for e in list:
            b += self.packer.pack(e)
        return b

    def unpack(self, data, offset=0, result=None):
        # Return a list of arguments
        total = 0

        # u8 array
        if self.packer.size == 1:
            if result[self.index] == 0:
                return b'', 0
            p = BaseTypes('u8', result[self.index])
            return p.unpack(data, offset)

        r = []
        for e in range(result[self.index]):
            x, size = self.packer.unpack(data, offset)
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

    def unpack(self, data, offset=0, result=None):
        total = 0
        # Return a list of arguments
        if (len(data) - offset) % self.packer.size:
            raise ValueError('Legacy Variable Length Array length mismatch.')
        elements = int((len(data) - offset) / self.packer.size)
        r = []
        for e in range(elements):
            x, size = self.packer.unpack(data, offset)
            r.append(x)
            offset += self.packer.size
            total += size
        return r, total


class VPPEnumType():
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
        logger.debug('Adding enum {}'.format(name))

    def __getattr__(self, name):
        return self.enum[name]

    def __nonzero__(self):
        return True

    def pack(self, data, kwargs=None):
        return types['u32'].pack(data)

    def unpack(self, data, offset=0, result=None):
        x, size = types['u32'].unpack(data, offset)
        return self.enum(x), size


class VPPUnionType():
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
                logger.debug('Unknown union type {}'.format(f_type))
                raise ValueError('Unknown message type {}'.format(f_type))
            fields.append(f_name)
            size = types[f_type].size
            self.packers[f_name] = types[f_type]
            if size > self.size:
                self.size = size
                self.maxindex = i

        types[name] = self
        self.tuple = collections.namedtuple(name, fields, rename=True)
        logger.debug('Adding union {}'.format(name))

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

    def unpack(self, data, offset=0, result=None):
        r = []
        maxsize = 0
        for k, p in self.packers.items():
            x, size = p.unpack(data, offset)
            if size > maxsize:
                maxsize = size
            r.append(x)
        return self.tuple._make(r), maxsize


class VPPType():
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
                logger.debug('Unknown type {}'.format(f_type))
                raise ValueError('Unknown message type {}'.format(f_type))
            if len(f) == 3:  # list
                list_elements = f[2]
                if list_elements == 0:
                    p = VLAList_legacy(f_name, f_type)
                    self.packers.append(p)
                elif f_type == 'u8':
                    p = FixedList_u8(f_name, f_type, list_elements)
                    self.packers.append(p)
                    size += p.size
                else:
                    p = FixedList(f_name, f_type, list_elements)
                    self.packers.append(p)
                    size += p.size
            elif len(f) == 4:  # Variable length list
                    # Find index of length field
                    length_index = self.fields.index(f[3])
                    p = VLAList(f_name, f_type, f[3], length_index)
                    self.packers.append(p)
            else:
                self.packers.append(types[f_type])
                size += types[f_type].size

        self.size = size
        self.tuple = collections.namedtuple(name, self.fields, rename=True)
        types[name] = self
        logger.debug('Adding type {}'.format(name))

    def pack(self, data, kwargs=None):
        if not kwargs:
            kwargs = data
        b = bytes()
        for i, a in enumerate(self.fields):

            # Try one of the format functions
            if data and type(data) is not dict and a not in data:
                raise ValueError("Invalid argument: {} expected {}.{}".
                                 format(data, self.name, a))

            # Defaulting to zero.
            if not data or a not in data:  # Default to 0
                arg = None
                kwarg = None  # No default for VLA
            else:
                arg = data[a]
                kwarg = kwargs[a] if a in kwargs else None

            if isinstance(self.packers[i], VPPType):
                try:
                    b += self.packers[i].pack(arg, kwarg)
                except ValueError:
                    # Invalid argument, can we convert it?
                    arg = VPPFormat.format(self.packers[i].name, data[a])
                    data[a] = arg
                    kwarg = arg
                    b += self.packers[i].pack(arg, kwarg)
            else:
                b += self.packers[i].pack(arg, kwargs)

        return b

    def unpack(self, data, offset=0, result=None):
        # Return a list of arguments
        result = []
        total = 0
        for p in self.packers:
            x, size = p.unpack(data, offset, result)
            if type(x) is tuple and len(x) == 1:
                x = x[0]
            result.append(x)
            offset += size
            total += size
        t = self.tuple._make(result)
        return t, total


class VPPMessage(VPPType):
    pass
