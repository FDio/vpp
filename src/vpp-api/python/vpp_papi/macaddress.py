#!/usr/bin/env python3
#
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

import binascii


def mac_pton(s):
    '''Convert MAC address as text to binary'''
    return binascii.unhexlify(s.replace(':', ''))


def mac_ntop(binary):
    '''Convert MAC address as binary to text'''
    x = b':'.join(binascii.hexlify(binary)[i:i + 2]
                  for i in range(0, 12, 2))
    return str(x.decode('ascii'))


class MACAddress():
    def __init__(self, mac):
        '''MAC Address as a text-string (aa:bb:cc:dd:ee:ff) or 6 bytes'''
        # Of course Python 2 doesn't distinguish str from bytes
        if type(mac) is bytes and len(mac) == 6:
            self.mac_binary = mac
            self.mac_string = mac_ntop(mac)
        else:
            self.mac_binary = mac_pton(mac)
            self.mac_string = mac

    @property
    def packed(self):
        return self.mac_binary

    def __len__(self):
        return 6

    def __str__(self):
        return self.mac_string

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, self.mac_string)

    def __eq__(self, other):

        if not isinstance(other, MACAddress):
            try:
                # if it looks like a mac address, we'll take it.
                # (allows for equality with scapy hw-addresses)
                return self.mac_binary == MACAddress(other).mac_binary
            except Exception:
                return NotImplemented
        return self.mac_binary == other.mac_binary

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.mac_binary)
