"""
  iOAM-Trace

  object abstractions for representing iOAM trace configuration in VPP
"""

from vpp_object import *


class VppiOAMTrace (VppObject):
    """
    iOAMTrace Configuration
    """

    def __init__(self, test, ioam_trace_type, num_elts,
                 trace_tsp, node_id, app_data):
        self._test = test
        self.num_elts = num_elts
        self.ioam_trace_type = ioam_trace_type
        self.trace_tsp = trace_tsp
        self.node_id = node_id
        self.app_data = app_data


    def add_vpp_config(self):
        self._test.vapi.ioam_trace_profile_add(
                     self.ioam_trace_type,
                     self.num_elts,
                     self.trace_tsp,
                     self.node_id,
                     self.app_data
                     )

    def remove_vpp_config(self):
        self._test.vapi.ioam_trace_profile_del()

    def query_vpp_config(self):
        return True

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%d/%d"
                % (self.trace_type,
                   self.num_elts,
                   self.trace_tsp))


