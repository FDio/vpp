
from vpp_interface import VppInterface
from vpp_ip_route import VppRoutePath
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
        self.t_paths = paths
        self.is_multicast = is_multicast
        self.is_l2 = is_l2

    def add_vpp_config(self):
        self._sw_if_index = 0xffffffff
        for path in self.t_paths:
            reply = self.test.vapi.mpls_tunnel_add_del(
                self._sw_if_index,
                1,  # IPv4 next-hop
                path.nh_addr,
                path.nh_itf,
                path.nh_table_id,
                path.weight,
                next_hop_out_label_stack=path.nh_labels,
                next_hop_n_out_labels=len(path.nh_labels),
                is_multicast=self.is_multicast,
                l2_only=self.is_l2)
            self._sw_if_index = reply.sw_if_index

    def remove_vpp_config(self):
        for path in self.t_paths:
            reply = self.test.vapi.mpls_tunnel_add_del(
                self.sw_if_index,
                1,  # IPv4 next-hop
                path.nh_addr,
                path.nh_itf,
                path.nh_table_id,
                path.weight,
                next_hop_out_label_stack=path.nh_labels,
                next_hop_n_out_labels=len(path.nh_labels),
                is_add=0)
