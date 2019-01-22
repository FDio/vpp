"""
  SRv6 LocalSIDs

  object abstractions for representing SRv6 localSIDs in VPP
"""

import ipaddress
from vpp_object import *
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
try:
    text_type = unicode
except NameError:
    text_type = str


def vl_api_srv6_sid_t(value):
    return {'addr': value}


def vl_api_address_t(address):
    # Copied from vl_api_address_t definition
    ADDRESS_IP4 = 0
    ADDRESS_IP6 = 1

    _addr = ipaddress.ip_address(text_type(address))
    _vl_api_address_t =  \
        {'af': ADDRESS_IP4 if _addr.version == 4 else ADDRESS_IP6,
         'un': {'ip%s' % _addr.version: _addr.packed}
         }
    print(_vl_api_address_t)
    return _vl_api_address_t


def vl_api_prefix_t(address, length):
    return {'address': vl_api_address_t(address),
            'address_length': length}


class SRv6LocalSIDBehaviors():
    # from src/vnet/srv6/sr.h
    SR_BEHAVIOR_END = 1
    SR_BEHAVIOR_X = 2
    SR_BEHAVIOR_T = 3
    SR_BEHAVIOR_D_FIRST = 4   # Unused. Separator in between regular and D
    SR_BEHAVIOR_DX2 = 5
    SR_BEHAVIOR_DX6 = 6
    SR_BEHAVIOR_DX4 = 7
    SR_BEHAVIOR_DT6 = 8
    SR_BEHAVIOR_DT4 = 9
    SR_BEHAVIOR_LAST = 10      # Must always be the last one


class SRv6PolicyType():
    # from src/vnet/srv6/sr.h
    SR_POLICY_TYPE_DEFAULT = 0
    SR_POLICY_TYPE_SPRAY = 1


class SRv6PolicySteeringTypes():
    # from src/vnet/srv6/sr.h
    SR_STEER_L2 = 2
    SR_STEER_IPV4 = 4
    SR_STEER_IPV6 = 6


class VppSRv6LocalSID(VppObject):
    """
    SRv6 LocalSID
    """

    def __init__(self, test, localsid, behavior, nh_addr4, nh_addr6,
                 end_psp, sw_if_index, vlan_index, fib_table):
        self._test = test
        self.localsid = localsid
        # keep binary format in _localsid
        self.localsid["addr"] = inet_pton(AF_INET6, self.localsid["addr"])
        self.behavior = behavior
        self.nh_addr4 = inet_pton(AF_INET, nh_addr4)
        self.nh_addr6 = inet_pton(AF_INET6, nh_addr6)
        self.end_psp = end_psp
        self.sw_if_index = sw_if_index
        self.vlan_index = vlan_index
        self.fib_table = fib_table
        self._configured = False

    def add_vpp_config(self):
        self._test.vapi.sr_localsid_add_del(
            self.localsid,
            self.behavior,
            self.nh_addr4,
            self.nh_addr6,
            is_del=0,
            end_psp=self.end_psp,
            sw_if_index=self.sw_if_index,
            vlan_index=self.vlan_index,
            fib_table=self.fib_table)
        self._configured = True

    def remove_vpp_config(self):
        self._test.vapi.sr_localsid_add_del(
            self.localsid,
            self.behavior,
            self.nh_addr4,
            self.nh_addr6,
            is_del=1,
            end_psp=self.end_psp,
            sw_if_index=self.sw_if_index,
            vlan_index=self.vlan_index,
            fib_table=self.fib_table)
        self._configured = False

    def query_vpp_config(self):
        # sr_localsids_dump API is disabled
        # use _configured flag for now
        return self._configured

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d;%s,%d"
                % (self.fib_table,
                   self.localsid,
                   self.behavior))


class VppSRv6Policy(VppObject):
    """
    SRv6 Policy
    """

    def __init__(self, test, bsid,
                 is_encap, sr_type, weight, fib_table,
                 segments, source):
        self._test = test
        self.bsid = bsid
        # keep binary format in _bsid
        self._bsid = inet_pton(AF_INET6, bsid)
        self.is_encap = is_encap
        self.sr_type = sr_type
        self.weight = weight
        self.fib_table = fib_table
        self.segments = segments
        # list of vl_api_srv6_sid_t
        self._segments = []
        for seg in segments:
            packed_seg = inet_pton(AF_INET6, seg)
            self._segments.append(vl_api_srv6_sid_t(packed_seg))
        self.n_segments = len(self._segments)
        self.source = source
        self._configured = False
        self.sr_policy_index = ~0

    @property
    def vl_api_srv6_sid_list_t(self):
        return {
            'num_sids': self.n_segments,
            'weight': self.weight,
            'sids': self._segments
        }

    def add_vpp_config(self):
        rv = self._test.vapi.sr_policy_add(
                     vl_api_srv6_sid_t(self._bsid),
                     self.weight,
                     self.is_encap,
                     self.sr_type,
                     self.fib_table,
                     self.vl_api_srv6_sid_list_t
        )
        self.sr_policy_index = rv.sr_policy_index
        self._configured = True

    def remove_vpp_config(self):
        self._test.vapi.sr_policy_del(
                     vl_api_srv6_sid_t(self._bsid),
                     self.sr_policy_index
                        )
        self._configured = False

    def query_vpp_config(self):
        # no API to query SR Policies
        # use _configured flag for now
        return self._configured

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d;%s-><%s>;%d"
                % (self.sr_type,
                   self.bsid,
                   ','.join(self.segments),
                   self.is_encap))


class VppSRv6Steering(VppObject):
    """
    SRv6 Steering
    """

    def __init__(self, test,
                 bsid,
                 prefix,
                 mask_width,
                 traffic_type,
                 sr_policy_index,
                 table_id,
                 sw_if_index):
        self._test = test
        self.bsid = bsid
        # keep binary format in _bsid
        self._bsid = inet_pton(AF_INET6, bsid)
        # keep binary format in _prefix
        if ':' in prefix:
            # IPv6
            self._prefix = inet_pton(AF_INET6, prefix)
        else:
            # IPv4
            # API expects 16 octets (128 bits)
            # last 4 octets are used for IPv4
            # --> prepend 12 octets
            self._prefix = ('\x00' * 12) + inet_pton(AF_INET, prefix)
        self.mask_width = mask_width
        self.traffic_type = traffic_type
        self.sr_policy_index = sr_policy_index
        self.sw_if_index = sw_if_index
        self.table_id = table_id
        self._configured = False

    def add_vpp_config(self):
        self._test.vapi.sr_steering_add_del(
                     0,
                     vl_api_srv6_sid_t(self._bsid),
                     self.sr_policy_index,
                     self.table_id,
                     self._prefix,
                     self.mask_width,
                     self.sw_if_index,
                     self.traffic_type)
        self._configured = True

    def remove_vpp_config(self):
        self._test.vapi.sr_steering_add_del(
                     1,
                     vl_api_srv6_sid_t(self._bsid),
                     self.sr_policy_index,
                     self.table_id,
                     self._prefix,
                     self.mask_width,
                     self.sw_if_index,
                     self.traffic_type)
        self._configured = False

    def query_vpp_config(self):
        # no API to query steering entries
        # use _configured flag for now
        return self._configured

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d;%d;%s/%d->%s"
                % (self.table_id,
                   self.traffic_type,
                   self.prefix,
                   self.mask_width,
                   self.bsid))
