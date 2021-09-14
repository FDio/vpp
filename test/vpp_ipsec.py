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
from vpp_object import VppObject
from ipaddress import ip_address
from vpp_papi import VppEnum
from vpp_interface import VppInterface

try:
    text_type = unicode
except NameError:
    text_type = str


def mk_counter():
    return {'packets': 0, 'bytes': 0}


class VppIpsecSpd(VppObject):
    """
    VPP SPD DB
    """

    def __init__(self, test, id):
        self.test = test
        self.id = id

    def add_vpp_config(self):
        self.test.vapi.ipsec_spd_add_del(self.id)
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipsec_spd_add_del(self.id, is_add=0)

    def object_id(self):
        return "ipsec-spd-%d" % self.id

    def query_vpp_config(self):
        spds = self.test.vapi.ipsec_spds_dump()
        for spd in spds:
            if spd.spd_id == self.id:
                return True
        return False


class VppIpsecSpdItfBinding(VppObject):
    """
    VPP SPD DB to interface binding
    (i.e. this SPD is used on this interface)
    """

    def __init__(self, test, spd, itf):
        self.test = test
        self.spd = spd
        self.itf = itf

    def add_vpp_config(self):
        self.test.vapi.ipsec_interface_add_del_spd(self.spd.id,
                                                   self.itf.sw_if_index)
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipsec_interface_add_del_spd(self.spd.id,
                                                   self.itf.sw_if_index,
                                                   is_add=0)

    def object_id(self):
        return "bind-%s-to-%s" % (self.spd.id, self.itf)

    def query_vpp_config(self):
        bs = self.test.vapi.ipsec_spd_interface_dump()
        for b in bs:
            if b.sw_if_index == self.itf.sw_if_index:
                return True
        return False


class VppIpsecSpdEntry(VppObject):
    """
    VPP SPD DB Entry
    """

    def __init__(self, test, spd, sa_id,
                 local_start, local_stop,
                 remote_start, remote_stop,
                 proto,
                 priority=100,
                 policy=None,
                 is_outbound=1,
                 remote_port_start=0,
                 remote_port_stop=65535,
                 local_port_start=0,
                 local_port_stop=65535):
        self.test = test
        self.spd = spd
        self.sa_id = sa_id
        self.local_start = ip_address(text_type(local_start))
        self.local_stop = ip_address(text_type(local_stop))
        self.remote_start = ip_address(text_type(remote_start))
        self.remote_stop = ip_address(text_type(remote_stop))
        self.proto = proto
        self.is_outbound = is_outbound
        self.priority = priority
        if not policy:
            self.policy = (VppEnum.vl_api_ipsec_spd_action_t.
                           IPSEC_API_SPD_ACTION_BYPASS)
        else:
            self.policy = policy
        self.is_ipv6 = (0 if self.local_start.version == 4 else 1)
        self.local_port_start = local_port_start
        self.local_port_stop = local_port_stop
        self.remote_port_start = remote_port_start
        self.remote_port_stop = remote_port_stop

    def add_vpp_config(self):
        rv = self.test.vapi.ipsec_spd_entry_add_del(
            self.spd.id,
            self.sa_id,
            self.local_start,
            self.local_stop,
            self.remote_start,
            self.remote_stop,
            protocol=self.proto,
            is_ipv6=self.is_ipv6,
            is_outbound=self.is_outbound,
            priority=self.priority,
            policy=self.policy,
            local_port_start=self.local_port_start,
            local_port_stop=self.local_port_stop,
            remote_port_start=self.remote_port_start,
            remote_port_stop=self.remote_port_stop)
        self.stat_index = rv.stat_index
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.test.vapi.ipsec_spd_entry_add_del(
            self.spd.id,
            self.sa_id,
            self.local_start,
            self.local_stop,
            self.remote_start,
            self.remote_stop,
            protocol=self.proto,
            is_ipv6=self.is_ipv6,
            is_outbound=self.is_outbound,
            priority=self.priority,
            policy=self.policy,
            local_port_start=self.local_port_start,
            local_port_stop=self.local_port_stop,
            remote_port_start=self.remote_port_start,
            remote_port_stop=self.remote_port_stop,
            is_add=0)

    def object_id(self):
        return "spd-entry-%d-%d-%d-%d-%d-%d" % (self.spd.id,
                                                self.priority,
                                                self.policy,
                                                self.is_outbound,
                                                self.is_ipv6,
                                                self.remote_port_start)

    def query_vpp_config(self):
        ss = self.test.vapi.ipsec_spd_dump(self.spd.id)
        for s in ss:
            if s.entry.sa_id == self.sa_id and \
               s.entry.is_outbound == self.is_outbound and \
               s.entry.priority == self.priority and \
               s.entry.policy == self.policy and \
               s.entry.remote_address_start == self.remote_start and \
               s.entry.remote_port_start == self.remote_port_start:
                return True
        return False

    def get_stats(self, worker=None):
        c = self.test.statistics.get_counter("/net/ipsec/policy")
        if worker is None:
            total = mk_counter()
            for t in c:
                total['packets'] += t[self.stat_index]['packets']
            return total
        else:
            # +1 to skip main thread
            return c[worker+1][self.stat_index]


class VppIpsecSA(VppObject):
    """
    VPP SAD Entry
    """

    DEFAULT_UDP_PORT = 4500

    def __init__(self, test, id, spi,
                 integ_alg, integ_key,
                 crypto_alg, crypto_key,
                 proto,
                 tun_src=None, tun_dst=None,
                 flags=None, salt=0, tun_flags=None,
                 dscp=None,
                 udp_src=None, udp_dst=None, hop_limit=None):
        e = VppEnum.vl_api_ipsec_sad_flags_t
        self.test = test
        self.id = id
        self.spi = spi
        self.integ_alg = integ_alg
        self.integ_key = integ_key
        self.crypto_alg = crypto_alg
        self.crypto_key = crypto_key
        self.proto = proto
        self.salt = salt

        self.table_id = 0
        self.tun_src = tun_src
        self.tun_dst = tun_dst
        if not flags:
            self.flags = e.IPSEC_API_SAD_FLAG_NONE
        else:
            self.flags = flags
        if (tun_src):
            self.tun_src = ip_address(text_type(tun_src))
            self.flags = self.flags | e.IPSEC_API_SAD_FLAG_IS_TUNNEL
        if (tun_dst):
            self.tun_dst = ip_address(text_type(tun_dst))
        self.udp_src = udp_src
        self.udp_dst = udp_dst
        self.tun_flags = (VppEnum.vl_api_tunnel_encap_decap_flags_t.
                          TUNNEL_API_ENCAP_DECAP_FLAG_NONE)
        if tun_flags:
            self.tun_flags = tun_flags
        self.dscp = VppEnum.vl_api_ip_dscp_t.IP_API_DSCP_CS0
        if dscp:
            self.dscp = dscp
        self.hop_limit = 255
        if hop_limit:
            self.hop_limit = hop_limit

    def tunnel_encode(self):
        return {'src': (self.tun_src if self.tun_src else []),
                'dst': (self.tun_dst if self.tun_dst else []),
                'encap_decap_flags': self.tun_flags,
                'dscp': self.dscp,
                'hop_limit': self.hop_limit,
                'table_id': self.table_id
                }

    def add_vpp_config(self):
        entry = {
            'sad_id': self.id,
            'spi': self.spi,
            'integrity_algorithm': self.integ_alg,
            'integrity_key': {
                'length': len(self.integ_key),
                'data': self.integ_key,
            },
            'crypto_algorithm': self.crypto_alg,
            'crypto_key': {
                'data': self.crypto_key,
                'length': len(self.crypto_key),
            },
            'protocol': self.proto,
            'tunnel': self.tunnel_encode(),
            'flags': self.flags,
            'salt': self.salt
        }
        # don't explicitly send the defaults, let papi fill them in
        if self.udp_src:
            entry['udp_src_port'] = self.udp_src
        if self.udp_dst:
            entry['udp_dst_port'] = self.udp_dst
        r = self.test.vapi.ipsec_sad_entry_add(entry=entry)
        self.stat_index = r.stat_index
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.test.vapi.ipsec_sad_entry_del(id=self.id)

    def object_id(self):
        return "ipsec-sa-%d" % self.id

    def query_vpp_config(self):
        e = VppEnum.vl_api_ipsec_sad_flags_t

        bs = self.test.vapi.ipsec_sa_v3_dump()
        for b in bs:
            if b.entry.sad_id == self.id:
                # if udp encap is configured then the ports should match
                # those configured or the default
                if (self.flags & e.IPSEC_API_SAD_FLAG_UDP_ENCAP):
                    if not b.entry.flags & e.IPSEC_API_SAD_FLAG_UDP_ENCAP:
                        return False
                    if self.udp_src:
                        if self.udp_src != b.entry.udp_src_port:
                            return False
                    else:
                        if self.DEFAULT_UDP_PORT != b.entry.udp_src_port:
                            return False
                    if self.udp_dst:
                        if self.udp_dst != b.entry.udp_dst_port:
                            return False
                    else:
                        if self.DEFAULT_UDP_PORT != b.entry.udp_dst_port:
                            return False
                return True
        return False

    def get_stats(self, worker=None):
        c = self.test.statistics.get_counter("/net/ipsec/sa")
        if worker is None:
            total = mk_counter()
            for t in c:
                total['packets'] += t[self.stat_index]['packets']
            return total
        else:
            # +1 to skip main thread
            return c[worker+1][self.stat_index]

    def get_lost(self, worker=None):
        c = self.test.statistics.get_counter("/net/ipsec/sa/lost")
        if worker is None:
            total = 0
            for t in c:
                total += t[self.stat_index]
            return total
        else:
            # +1 to skip main thread
            return c[worker+1][self.stat_index]


class VppIpsecTunProtect(VppObject):
    """
    VPP IPSEC tunnel protection
    """

    def __init__(self, test, itf, sa_out, sas_in, nh=None):
        self.test = test
        self.itf = itf
        self.sas_in = []
        for sa in sas_in:
            self.sas_in.append(sa.id)
        self.sa_out = sa_out.id
        self.nh = nh
        if not self.nh:
            self.nh = "0.0.0.0"

    def update_vpp_config(self, sa_out, sas_in):
        self.sas_in = []
        for sa in sas_in:
            self.sas_in.append(sa.id)
        self.sa_out = sa_out.id
        self.test.vapi.ipsec_tunnel_protect_update(
            tunnel={
                'sw_if_index': self.itf._sw_if_index,
                'n_sa_in': len(self.sas_in),
                'sa_out': self.sa_out,
                'sa_in': self.sas_in,
                'nh': self.nh})

    def object_id(self):
        return "ipsec-tun-protect-%s-%s" % (self.itf, self.nh)

    def add_vpp_config(self):
        self.test.vapi.ipsec_tunnel_protect_update(
            tunnel={
                'sw_if_index': self.itf._sw_if_index,
                'n_sa_in': len(self.sas_in),
                'sa_out': self.sa_out,
                'sa_in': self.sas_in,
                'nh': self.nh})
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipsec_tunnel_protect_del(
            sw_if_index=self.itf.sw_if_index,
            nh=self.nh)

    def query_vpp_config(self):
        bs = self.test.vapi.ipsec_tunnel_protect_dump(
            sw_if_index=self.itf.sw_if_index)
        for b in bs:
            if b.tun.sw_if_index == self.itf.sw_if_index and \
               self.nh == str(b.tun.nh):
                return True
        return False


class VppIpsecInterface(VppInterface):
    """
    VPP IPSec interface
    """

    def __init__(self, test, mode=None, instance=0xffffffff):
        super(VppIpsecInterface, self).__init__(test)

        self.mode = mode
        if not self.mode:
            self.mode = (VppEnum.vl_api_tunnel_mode_t.
                         TUNNEL_API_MODE_P2P)
        self.instance = instance

    def add_vpp_config(self):
        r = self.test.vapi.ipsec_itf_create(itf={
            'user_instance': self.instance,
            'mode': self.mode,
        })
        self.set_sw_if_index(r.sw_if_index)
        self.test.registry.register(self, self.test.logger)
        ts = self.test.vapi.ipsec_itf_dump(sw_if_index=self._sw_if_index)
        self.instance = ts[0].itf.user_instance
        return self

    def remove_vpp_config(self):
        self.test.vapi.ipsec_itf_delete(sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        ts = self.test.vapi.ipsec_itf_dump(sw_if_index=0xffffffff)
        for t in ts:
            if t.itf.sw_if_index == self._sw_if_index:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "ipsec%d" % self.instance
