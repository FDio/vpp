
from vpp_interface import VppInterface
from vpp_ip_route import VppRoutePath, VppMplsLabel
import socket


class VppMPLSTunnelInterface(VppInterface):
    """
    VPP MPLS Tunnel interface
    """

    def __init__(self, test, paths, is_multicast=0, is_l2=0):
        """ Create MPLS Tunnel interface """
        self._sw_if_index = 0
        super(VppMPLSTunnelInterface, self).__init__(test)
        self._test = test
        self.paths = paths
        self.is_multicast = is_multicast
        self.is_l2 = is_l2
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

    def add_vpp_config(self):
        self._sw_if_index = 0xffffffff

        reply = self.test.vapi.mpls_tunnel_add_del(
            self._sw_if_index,
            self.encoded_paths,
            is_multicast=self.is_multicast,
            l2_only=self.is_l2)
        self._sw_if_index = reply.sw_if_index

    def remove_vpp_config(self):
        reply = self.test.vapi.mpls_tunnel_add_del(
            self.sw_if_index,
            self.encoded_paths,
            is_add=0)
