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
            return NotImplemented
        return self.mac_binary == other.mac_binary

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.mac_binary)
