# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""" BFD protocol implementation """

from random import randint
from socket import AF_INET, AF_INET6, inet_pton
from scapy.all import bind_layers
from scapy.layers.inet import UDP
from scapy.packet import Packet
from scapy.fields import BitField, BitEnumField, XByteField, FlagsField,\
    ConditionalField, StrField
from vpp_object import VppObject
from util import NumericConstant
from vpp_papi import VppEnum


class BFDDiagCode(NumericConstant):
    """ BFD Diagnostic Code """
    no_diagnostic = 0
    control_detection_time_expired = 1
    echo_function_failed = 2
    neighbor_signaled_session_down = 3
    forwarding_plane_reset = 4
    path_down = 5
    concatenated_path_down = 6
    administratively_down = 7
    reverse_concatenated_path_down = 8

    desc_dict = {
        no_diagnostic: "No diagnostic",
        control_detection_time_expired: "Control Detection Time Expired",
        echo_function_failed: "Echo Function Failed",
        neighbor_signaled_session_down: "Neighbor Signaled Session Down",
        forwarding_plane_reset: "Forwarding Plane Reset",
        path_down: "Path Down",
        concatenated_path_down: "Concatenated Path Down",
        administratively_down: "Administratively Down",
        reverse_concatenated_path_down: "Reverse Concatenated Path Down",
    }


class BFDState(NumericConstant):
    """ BFD State """
    admin_down = 0
    down = 1
    init = 2
    up = 3

    desc_dict = {
        admin_down: "AdminDown",
        down: "Down",
        init: "Init",
        up: "Up",
    }


class BFDAuthType(NumericConstant):
    """ BFD Authentication Type """
    no_auth = 0
    simple_pwd = 1
    keyed_md5 = 2
    meticulous_keyed_md5 = 3
    keyed_sha1 = 4
    meticulous_keyed_sha1 = 5

    desc_dict = {
        no_auth: "No authentication",
        simple_pwd: "Simple Password",
        keyed_md5: "Keyed MD5",
        meticulous_keyed_md5: "Meticulous Keyed MD5",
        keyed_sha1: "Keyed SHA1",
        meticulous_keyed_sha1: "Meticulous Keyed SHA1",
    }


def bfd_is_auth_used(pkt):
    """ is packet authenticated? """
    return "A" in pkt.sprintf("%BFD.flags%")


def bfd_is_simple_pwd_used(pkt):
    """ is simple password authentication used? """
    return bfd_is_auth_used(pkt) and pkt.auth_type == BFDAuthType.simple_pwd


def bfd_is_sha1_used(pkt):
    """ is sha1 authentication used? """
    return bfd_is_auth_used(pkt) and pkt.auth_type in \
        (BFDAuthType.keyed_sha1, BFDAuthType.meticulous_keyed_sha1)


def bfd_is_md5_used(pkt):
    """ is md5 authentication used? """
    return bfd_is_auth_used(pkt) and pkt.auth_type in \
        (BFDAuthType.keyed_md5, BFDAuthType.meticulous_keyed_md5)


def bfd_is_md5_or_sha1_used(pkt):
    """ is md5 or sha1 used? """
    return bfd_is_md5_used(pkt) or bfd_is_sha1_used(pkt)


class BFD(Packet):
    """ BFD protocol layer for scapy """

    udp_dport = 3784  #: BFD destination port per RFC 5881
    udp_dport_echo = 3785  # : BFD destination port for ECHO per RFC 5881
    udp_sport_min = 49152  #: BFD source port min value per RFC 5881
    udp_sport_max = 65535  #: BFD source port max value per RFC 5881
    bfd_pkt_len = 24  # : length of BFD pkt without authentication section
    sha1_auth_len = 28  # : length of authentication section if SHA1 used

    name = "BFD"

    fields_desc = [
        BitField("version", 1, 3),
        BitEnumField("diag", 0, 5, BFDDiagCode.desc_dict),
        BitEnumField("state", 0, 2, BFDState.desc_dict),
        FlagsField("flags", 0, 6, ['M', 'D', 'A', 'C', 'F', 'P']),
        XByteField("detect_mult", 0),
        BitField("length", bfd_pkt_len, 8),
        BitField("my_discriminator", 0, 32),
        BitField("your_discriminator", 0, 32),
        BitField("desired_min_tx_interval", 0, 32),
        BitField("required_min_rx_interval", 0, 32),
        BitField("required_min_echo_rx_interval", 0, 32),
        ConditionalField(
            BitEnumField("auth_type", 0, 8, BFDAuthType.desc_dict),
            bfd_is_auth_used),
        ConditionalField(BitField("auth_len", 0, 8), bfd_is_auth_used),
        ConditionalField(BitField("auth_key_id", 0, 8), bfd_is_auth_used),
        ConditionalField(BitField("auth_reserved", 0, 8),
                         bfd_is_md5_or_sha1_used),
        ConditionalField(
            BitField("auth_seq_num", 0, 32), bfd_is_md5_or_sha1_used),
        ConditionalField(StrField("auth_key_hash", "0" * 16), bfd_is_md5_used),
        ConditionalField(
            StrField("auth_key_hash", "0" * 20), bfd_is_sha1_used),
    ]

    def mysummary(self):
        return self.sprintf("BFD(my_disc=%BFD.my_discriminator%,"
                            "your_disc=%BFD.your_discriminator%)")


# glue the BFD packet class to scapy parser
bind_layers(UDP, BFD, dport=BFD.udp_dport)


class BFD_vpp_echo(Packet):
    """ BFD echo packet as used by VPP (non-rfc, as rfc doesn't define one) """

    udp_dport = 3785  #: BFD echo destination port per RFC 5881
    name = "BFD_VPP_ECHO"

    fields_desc = [
        BitField("discriminator", 0, 32),
        BitField("expire_time_clocks", 0, 64),
        BitField("checksum", 0, 64)
    ]

    def mysummary(self):
        return self.sprintf(
            "BFD_VPP_ECHO(disc=%BFD_VPP_ECHO.discriminator%,"
            "expire_time_clocks=%BFD_VPP_ECHO.expire_time_clocks%)")


# glue the BFD echo packet class to scapy parser
bind_layers(UDP, BFD_vpp_echo, dport=BFD_vpp_echo.udp_dport)


class VppBFDAuthKey(VppObject):
    """ Represents BFD authentication key in VPP """

    def __init__(self, test, conf_key_id, auth_type, key):
        self._test = test
        self._key = key
        self._auth_type = auth_type
        test.assertIn(auth_type, BFDAuthType.desc_dict)
        self._conf_key_id = conf_key_id

    @property
    def test(self):
        """ Test which created this key """
        return self._test

    @property
    def auth_type(self):
        """ Authentication type for this key """
        return self._auth_type

    @property
    def key(self):
        """ key data """
        return self._key

    @key.setter
    def key(self, value):
        self._key = value

    @property
    def conf_key_id(self):
        """ configuration key ID """
        return self._conf_key_id

    def add_vpp_config(self):
        self.test.vapi.bfd_auth_set_key(
            conf_key_id=self._conf_key_id, auth_type=self._auth_type,
            key=self._key, key_len=len(self._key))
        self._test.registry.register(self, self.test.logger)

    def get_bfd_auth_keys_dump_entry(self):
        """ get the entry in the auth keys dump corresponding to this key """
        result = self.test.vapi.bfd_auth_keys_dump()
        for k in result:
            if k.conf_key_id == self._conf_key_id:
                return k
        return None

    def query_vpp_config(self):
        return self.get_bfd_auth_keys_dump_entry() is not None

    def remove_vpp_config(self):
        self.test.vapi.bfd_auth_del_key(conf_key_id=self._conf_key_id)

    def object_id(self):
        return "bfd-auth-key-%s" % self._conf_key_id


class VppBFDUDPSession(VppObject):
    """ Represents BFD UDP session in VPP """

    def __init__(self, test, interface, peer_addr, local_addr=None, af=AF_INET,
                 desired_min_tx=300000, required_min_rx=300000, detect_mult=3,
                 sha1_key=None, bfd_key_id=None, is_tunnel=False):
        self._test = test
        self._interface = interface
        self._af = af
        if local_addr:
            self._local_addr = local_addr
        else:
            self._local_addr = None
        self._peer_addr = peer_addr
        self._desired_min_tx = desired_min_tx
        self._required_min_rx = required_min_rx
        self._detect_mult = detect_mult
        self._sha1_key = sha1_key
        if bfd_key_id is not None:
            self._bfd_key_id = bfd_key_id
        else:
            self._bfd_key_id = randint(0, 255)
        self._is_tunnel = is_tunnel

    @property
    def test(self):
        """ Test which created this session """
        return self._test

    @property
    def interface(self):
        """ Interface on which this session lives """
        return self._interface

    @property
    def af(self):
        """ Address family - AF_INET or AF_INET6 """
        return self._af

    @property
    def local_addr(self):
        """ BFD session local address (VPP address) """
        if self._local_addr is None:
            if self.af == AF_INET:
                return self._interface.local_ip4
            elif self.af == AF_INET6:
                return self._interface.local_ip6
            else:
                raise Exception("Unexpected af '%s'" % self.af)
        return self._local_addr

    @property
    def peer_addr(self):
        """ BFD session peer address """
        return self._peer_addr

    def get_bfd_udp_session_dump_entry(self):
        """ get the namedtuple entry from bfd udp session dump """
        result = self.test.vapi.bfd_udp_session_dump()
        for s in result:
            self.test.logger.debug("session entry: %s" % str(s))
            if s.sw_if_index == self.interface.sw_if_index:
                if self.af == AF_INET \
                        and self.interface.local_ip4 == str(s.local_addr) \
                        and self.interface.remote_ip4 == str(s.peer_addr):
                    return s
                if self.af == AF_INET6 \
                        and self.interface.local_ip6 == str(s.local_addr) \
                        and self.interface.remote_ip6 == str(s.peer_addr):
                    return s
        return None

    @property
    def state(self):
        """ BFD session state """
        session = self.get_bfd_udp_session_dump_entry()
        if session is None:
            raise Exception("Could not find BFD session in VPP response")
        return session.state

    @property
    def desired_min_tx(self):
        """ desired minimum tx interval """
        return self._desired_min_tx

    @property
    def required_min_rx(self):
        """ required minimum rx interval """
        return self._required_min_rx

    @property
    def detect_mult(self):
        """ detect multiplier """
        return self._detect_mult

    @property
    def sha1_key(self):
        """ sha1 key """
        return self._sha1_key

    @property
    def bfd_key_id(self):
        """ bfd key id in use """
        return self._bfd_key_id

    @property
    def is_tunnel(self):
        return self._is_tunnel

    def activate_auth(self, key, bfd_key_id=None, delayed=False):
        """ activate authentication for this session """
        self._bfd_key_id = bfd_key_id if bfd_key_id else randint(0, 255)
        self._sha1_key = key
        conf_key_id = self._sha1_key.conf_key_id
        is_delayed = 1 if delayed else 0
        self.test.vapi.bfd_udp_auth_activate(
            sw_if_index=self._interface.sw_if_index,
            local_addr=self.local_addr,
            peer_addr=self.peer_addr,
            bfd_key_id=self._bfd_key_id,
            conf_key_id=conf_key_id,
            is_delayed=is_delayed)

    def deactivate_auth(self, delayed=False):
        """ deactivate authentication """
        self._bfd_key_id = None
        self._sha1_key = None
        is_delayed = 1 if delayed else 0
        self.test.vapi.bfd_udp_auth_deactivate(
            sw_if_index=self._interface.sw_if_index,
            local_addr=self.local_addr,
            peer_addr=self.peer_addr,
            is_delayed=is_delayed)

    def modify_parameters(self,
                          detect_mult=None,
                          desired_min_tx=None,
                          required_min_rx=None):
        """ modify session parameters """
        if detect_mult:
            self._detect_mult = detect_mult
        if desired_min_tx:
            self._desired_min_tx = desired_min_tx
        if required_min_rx:
            self._required_min_rx = required_min_rx
        self.test.vapi.bfd_udp_mod(sw_if_index=self._interface.sw_if_index,
                                   desired_min_tx=self.desired_min_tx,
                                   required_min_rx=self.required_min_rx,
                                   detect_mult=self.detect_mult,
                                   local_addr=self.local_addr,
                                   peer_addr=self.peer_addr)

    def add_vpp_config(self):
        bfd_key_id = self._bfd_key_id if self._sha1_key else None
        conf_key_id = self._sha1_key.conf_key_id if self._sha1_key else None
        is_authenticated = True if self._sha1_key else False
        self.test.vapi.bfd_udp_add(sw_if_index=self._interface.sw_if_index,
                                   desired_min_tx=self.desired_min_tx,
                                   required_min_rx=self.required_min_rx,
                                   detect_mult=self.detect_mult,
                                   local_addr=self.local_addr,
                                   peer_addr=self.peer_addr,
                                   bfd_key_id=bfd_key_id,
                                   conf_key_id=conf_key_id,
                                   is_authenticated=is_authenticated)
        self._test.registry.register(self, self.test.logger)

    def query_vpp_config(self):
        session = self.get_bfd_udp_session_dump_entry()
        return session is not None

    def remove_vpp_config(self):
        self.test.vapi.bfd_udp_del(self._interface.sw_if_index,
                                   local_addr=self.local_addr,
                                   peer_addr=self.peer_addr)

    def object_id(self):
        return "bfd-udp-%s-%s-%s-%s" % (self._interface.sw_if_index,
                                        self.local_addr,
                                        self.peer_addr,
                                        self.af)

    def admin_up(self):
        """ set bfd session admin-up """
        self.test.vapi.bfd_udp_session_set_flags(
            flags=VppEnum.vl_api_if_status_flags_t.IF_STATUS_API_FLAG_ADMIN_UP,
            sw_if_index=self._interface.sw_if_index,
            local_addr=self.local_addr,
            peer_addr=self.peer_addr)

    def admin_down(self):
        """ set bfd session admin-down """
        self.test.vapi.bfd_udp_session_set_flags(
            flags=0, sw_if_index=self._interface.sw_if_index,
            local_addr=self.local_addr,
            peer_addr=self.peer_addr)
