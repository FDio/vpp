"""
  SRv6

  object abstractions for representing SRv6 policies in VPP
"""

from vpp_object import *
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6


class VppSRv6Policy(VppObject):
    """
    SRv6 Policy
    """

    def __init__(self, test, bsid,
                 is_encap, sr_type, weight, fib_table, 
                 num_segments, segment_i=[]):
        self._test = test
        self.bsid = inet_pton(AF_INET6, bsid)
        self.is_encap = is_encap 
        self.sr_type = sr_type
        self.weight = weight
        self.fib_table = fib_table
        self.n_segments = num_segments
        self.segments = bytearray("")
        for  ii in range(num_segments):
            self.segments.extend(inet_pton(AF_INET6, segment_i[ii]))

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
                     self.bsid,
                     self.weight,
                     self.is_encap,
                     self.sr_type,
                     self.fib_table,
                     self.n_segments,
                     self.segment)

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

    def __init__(self, test, bsid,
                 mask_width, prefix, sr_policy_index, table_id, sw_if_index,
                 traffic_type):
        self._test = test
        self.bsid = inet_pton(AF_INET6, bsid)
        self.prefix = inet_pton(AF_INET6, prefix)
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


