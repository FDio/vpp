import abc
from vpp_pg_interface import is_ipv6_misc
from vpp_interface import VppInterface


class VppTunnelInterface(VppInterface, metaclass=abc.ABCMeta):
    """ VPP tunnel interface abstraction """

    def __init__(self, test, parent_if):
        super(VppTunnelInterface, self).__init__(test)
        self.parent_if = parent_if

    @property
    def local_mac(self):
        return self.parent_if.local_mac

    @property
    def remote_mac(self):
        return self.parent_if.remote_mac

    def enable_capture(self):
        return self.parent_if.enable_capture()

    def add_stream(self, pkts):
        return self.parent_if.add_stream(pkts)

    def get_capture(self, expected_count=None, remark=None, timeout=1,
                    filter_out_fn=is_ipv6_misc):
        return self.parent_if.get_capture(expected_count, remark, timeout,
                                          filter_out_fn)
