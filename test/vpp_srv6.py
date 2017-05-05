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
                 num_segments, segment_i=[]):
        self._test = test
        self.num_segments = num_segments
        self.is_encap = 0
        self.type = 0
        self.weight = 0xFFFFFFFF
        self.fib_table = 0xFFFFFFFF
        self.bsid = inet_pton(AF_INET6, bsid)
        self.n_segments = num_segments
        self.segments = bytearray("")
        self.segments.extend(inet_pton(AF_INET6, segment_i[0]))
        self.segments.extend(inet_pton(AF_INET6, segment_i[1]))
        self.segments.extend(inet_pton(AF_INET6, segment_i[2]))

    def modify(self, is_encap=0):
        self.is_encap = is_encap

    def add_vpp_config(self):
        self._test.vapi.sr_policy_add(
                     self.bsid,
                     self.weight,
                     self.is_encap,
                     self.type,
                     self.fib_table,
                     self.n_segments,
                     self.segments)

    def remove_vpp_config(self):
        self._test.vapi.sr_policy_del(
                     self.bsid,
                     self.weight,
                     self.is_encap,
                     self.type,
                     self.fib_table,
                     self.n_segments,
                     self.segment)

    def query_vpp_config(self):
        return True

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s/%d"
                % (self.table_id,
                   self.dest_addr_p,
                   self.dest_addr_len))

class VppSRv6Steering(VppObject):
    """
    SRv6 Steering
    """

    def __init__(self, test, bsid,
                 mask_width, prefix):
        self._test = test
        self.mask_width = mask_width
        self.bsid = inet_pton(AF_INET6, bsid)
        self.prefix = inet_pton(AF_INET6, prefix)

    def modify(self, is_encap=0):
        self.mask_width = 0

    def add_vpp_config(self):
        self._test.vapi.sr_steering_add_del(
                     0, 
                     self.bsid,
                     0xFFFFFFFF,
                     0xFFFFFFFF,
                     self.prefix,
                     self.mask_width,
                     0xFFFFFFFF, 6)

    def remove_vpp_config(self):
        self._test.vapi.sr_steering_add_del(
                     1, 
                     self.bsid,
                     0,
                     0,
                     self.prefix,
                     self.mask_width,
                     0, 0)
    def query_vpp_config(self):
        return True

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s/%d"
                % (self.table_id,
                   self.dest_addr_p,
                   self.dest_addr_len))


