"""
  SRv6 LocalSIDs

  object abstractions for representing SRv6 localSIDs in VPP
"""

from vpp_object import *
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6


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

    def __init__(self, test, localsid_addr, behavior, nh_addr, end_psp,
                 sw_if_index, vlan_index, fib_table):
        self._test = test
        self.localsid_addr = inet_pton(AF_INET6, localsid_addr)
        self.behavior = behavior
        self.nh_addr = inet_pton(AF_INET6, nh_addr)
        self.end_psp = end_psp
        self.sw_if_index = sw_if_index
        self.vlan_index = vlan_index
        self.fib_table = fib_table

    def add_vpp_config(self):
        self._test.vapi.sr_localsid_add_del(
            self.localsid_addr,
            self.behavior,
            self.nh_addr,
            is_del=0,
            end_psp=self.end_psp,
            sw_if_index=self.sw_if_index,
            vlan_index=self.vlan_index,
            fib_table=self.fib_table)
        # self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.sr_localsid_add_del(
            self.localsid_addr,
            self.behavior,
            self.nh_addr,
            is_del=1,
            end_psp=self.end_psp,
            sw_if_index=self.sw_if_index,
            vlan_index=self.vlan_index,
            fib_table=self.fib_table)

    def query_vpp_config(self):
        return True

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s,%d"
                % (self.fib_table,
                   self.localsid_addr,
                   self.behavior))


class VppSRv6Policy(VppObject):
    """
    SRv6 Policy
    """

    def __init__(self, test, bsid,
                 is_encap, sr_type, weight, fib_table,
                 segments, source):
        self._test = test
        self.bsid = inet_pton(AF_INET6, bsid)
        self.is_encap = is_encap
        self.sr_type = sr_type
        self.weight = weight
        self.fib_table = fib_table
        self.segments = []
        for seg in segments:
            self.segments.extend(inet_pton(AF_INET6, seg))
        self.n_segments = len(segments)
        # source not passed to API
        self.source = inet_pton(AF_INET6, source)

    def add_vpp_config(self):
        self._test.vapi.sr_policy_add(
                     self.bsid,
                     self.weight,
                     self.is_encap,
                     self.sr_type,
                     self.fib_table,
                     self.n_segments,
                     self.segments)

    def remove_vpp_config(self):
        self._test.vapi.sr_policy_del(
                     self.bsid)

    def query_vpp_config(self):
        return True

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s/%d"
                % (self.sr_type,
                   self.bsid,
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
        self.bsid = inet_pton(AF_INET6, bsid)
        if ':' in prefix:
            # IPv6
            self.prefix = inet_pton(AF_INET6, prefix)
        else:
            # IPv4
            self.prefix = inet_pton(AF_INET, prefix)
        self.mask_width = mask_width
        self.traffic_type = traffic_type
        self.sr_policy_index = sr_policy_index
        self.sw_if_index = sw_if_index
        self.table_id = table_id

    def modify(self, is_encap=0):
        self.mask_width = 0

    def add_vpp_config(self):
        self._test.vapi.sr_steering_add_del(
                     0,
                     self.bsid,
                     self.sr_policy_index,
                     self.table_id,
                     self.prefix,
                     self.mask_width,
                     self.sw_if_index,
                     self.traffic_type)

    def remove_vpp_config(self):
        self._test.vapi.sr_steering_add_del(
                     1,
                     self.bsid,
                     self.sr_policy_index,
                     self.table_id,
                     self.prefix,
                     self.mask_width,
                     self.sw_if_index,
                     self.traffic_type)

    def query_vpp_config(self):
        return True

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s/%d"
                % (self.sr_type,
                   self.bsid,
                   self.is_encap))
