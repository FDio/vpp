# Copyright (c) 2017 Comcast Cable Communications Management, LLC.
#
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

"""Partial implementation of the VPP unserializer for Python objects."""

from struct import Struct


"""Mapping of basic VPP types to Struct decoders."""
_base_types = {
    # There is an inconsistency in that "small ints" are encoded using
    # little endian, but other values are encoded with big endian (aka
    # network byte order). Thus we need to provide variants for both.
    '<u8':  Struct('B'),
    '<u16': Struct('<H'),
    '<u32': Struct('<I'),
    '<i32': Struct('<i'),
    '<u64': Struct('<Q'),
    '<f64': Struct('<d'),

    '>u8':  Struct('B'),
    '>u16': Struct('>H'),
    '>u32': Struct('>I'),
    '>i32': Struct('>i'),
    '>u64': Struct('>Q'),
    '>f64': Struct('>d'),
}


class VPPUnserializeBuffer(object):
    """A simple unserialzer buffer.

    This hosts a data object and an offset pointer that can be advanced.
    """

    """The data object"""
    data = None
    """The current offset into the data object"""
    offset = 0

    def __init__(self, data, offset=0):
        super(VPPUnserializeBuffer, self).__init__()
        self.data = data
        self.offset = offset

    def __repr__(self):
        return 'VPPUnserializeBuffer(size=%d, offset=%d)' % (
                len(self.data), self.offset)


class VPPUnserialize(object):
    """The VPP unserializer.

    Subclasses will typically override the value of 'struct' with a list of
    lists where each sublist describes a class property that data is
    unserialized into.
    """

    """The description of attributes in the class to unserialize into.

    This is a list of lists where each sublist is either:
        [name, type]
    or, when 'type' is the value 'list':
        [name, 'list', length_attr, object_klass]

    * 'name' is the string name of the field. This is the attribute name
      into which the value is unserialized.
    * 'type' is a description of the serialized type. This can be one of the
      values of _base_types, one of the special VPP types 'suint' or
      'ssint' for "likely small" integers, 'cstring' for a length-value encoded
      string, another VPPUnserialize subclass or an instance of struct.Struct.
    * 'length_attr' is the attribute from which to read the number of items
      to unserialize into a list.
    * 'object_klass' is a class reference that is instantiated for each element
      in the list.
    """
    struct = None

    def __init__(self, buf=None):
        """Initializes the VPPUnserialize object.
        :param buf: If provided, this VPPUnserializeBuffer is used to
          immediately start unserializing from.
        """
        super(VPPUnserialize, self).__init__()

        if buf:
            self.decode(buf)

    def action_for_type(self, info):
        """Returns a function reference that performs the
        appropriate action for the type information in 'info'.

        :param info: A list of [type, ...] information. When
          'type' is 'list' then it also contains information on
          the number of elements to instantiate and the class
          reference to be used for each element.

        :returns: A function reference that accepts a single 'buf'
          parameter for the VPPUnserializeBuffer to use. As each
          item is unserialized from buf.data, buf.pointer is
          incremented appropriately.
        """
        t = info[0]
        if t == 'suint':
            return self.decode_likely_small_unsigned_integer
        elif t == 'ssint':
            return self.decode_likely_small_signed_integer
        elif t == 'cstring':
            return self.decode_cstring
        elif t == 'list':
            count = getattr(self, info[1])
            cls = self.action_for_type(info[2:])
            return lambda buf: [cls(buf) for i in range(count)]
        elif t in _base_types:
            return lambda buf: self.decode_from_struct(buf, _base_types[t])
        elif issubclass(t, VPPUnserialize):
            return t  # treating class as fn
        elif isinstance(t, Struct):
            return lambda buf: self.decode_from_struct(buf, t)
        else:
            raise NotImplementedError("Unknown VPP type '%s'" % t)

    def decode(self, buf):
        """Iterates over items in self.struct and unserializes
        data from buf into this class or others it instantiates.

        :param buf: The VPPUnserializeBuffer to unserialize from.
        """
        for item in self.struct:
            name = item[0]

            action = self.action_for_type(item[1:])
            setattr(self, name, action(buf))

    def decode_from_struct(self, buf, s):
        """Uses a Struct object to unserialize data from the buffer.
        Uses buf.data and increments buf.offset accordingly.

        :param buf: The VPPUnserializeBuffer to unserialize from.
        :param s:   An instance of struct.Struct to unpack with.
        :returns: The unserialized value.
        """
        v = s.unpack_from(buf.data, buf.offset)[0]
        buf.offset += s.size
        return v

    def decode_likely_small_unsigned_integer(self, buf):
        """This uses a mechanism to pack the number based on its value
        so that small values use fewer bytes, upto 64 bits.
        Uses buf.data and increments buf.offset accordingly.

        :param buf: The VPPUnserializeBuffer to unserialize from.
        :rtype: int
        :returns: The unserialized value.
        """
        v = _base_types['<u8'].unpack_from(buf.data, buf.offset)[0]
        if (v & 1) == 1:
            buf.offset += 1
            return v // 2

        if (v & 2) == 2:
            v = _base_types['<u16'].unpack_from(buf.data, buf.offset)[0]
            buf.offset += 2
            return (v // 4) + (1 << 7)

        if (v & 4) == 4:
            v = _base_types['<u32'].unpack_from(buf.data, buf.offset)[0]
            buf.offset += 4
            return (v // 8) + (1 << 7) + (1 << 14)

        buf.offset += 1
        v = _base_types['<u64'].unpack_from(buf.data, buf.offset)[0]
        buf.offset += 8
        return v

    def decode_likely_small_signed_integer(self, buf):
        """This uses a mechanism to pack the number based on its value
        so that small values use fewer bytes, upto 64 bits.
        Uses buf.data and increments buf.offset accordingly.

        :param buf :The VPPUnserializeBuffer to unserialize from.
        :rtype: int
        :returns: The unserialized value.
        """
        v = self.decode_likely_small_unsigned_integer(buf)
        s = v // 2
        return -s if (u & 1) else s

    def decode_cstring(self, buf):
        """Unserializes a run-length encoded string.
        Uses buf.data and increments buf.offset accordingly.

        :param buf: The VPPUnserializeBuffer to unserialize from.
        :rtype: str
        :returns: The unserialized string.
        """
        length = self.decode_likely_small_unsigned_integer(buf)
        s = Struct("%ds" % length)
        string = s.unpack_from(buf.data, buf.offset)[0]
        buf.offset += length
        return string


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
