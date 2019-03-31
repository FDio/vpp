
from vpp_interface import VppInterface


class VppMPLSTunnelInterface(VppInterface):
    """
    VPP MPLS Tunnel interface
    """

    def __init__(self, test, paths, is_multicast=0, is_l2=0):
        """ Create MPLS Tunnel interface """
        super(VppMPLSTunnelInterface, self).__init__(test)
        self.t_paths = paths
        self.is_multicast = is_multicast
        self.is_l2 = is_l2

    def add_vpp_config(self):
        sw_if_index = 0xffffffff
        for path in self.t_paths:
            lstack = path.encode_labels()

            reply = self.test.vapi.mpls_tunnel_add_del(
                sw_if_index,
                1,  # IPv4 next-hop
                path.nh_addr,
                path.nh_itf,
                path.nh_table_id,
                path.weight,
                next_hop_via_label=path.nh_via_label,
                next_hop_out_label_stack=lstack,
                next_hop_n_out_labels=len(lstack),
                is_multicast=self.is_multicast,
                l2_only=self.is_l2)
            sw_if_index = reply.sw_if_index
            self.tunnel_index = reply.tunnel_index
        self.set_sw_if_index(sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        for path in self.t_paths:
            lstack = path.encode_labels()

            self.test.vapi.mpls_tunnel_add_del(
                self.sw_if_index,
                1,  # IPv4 next-hop
                path.nh_addr,
                path.nh_itf,
                path.nh_table_id,
                path.weight,
                next_hop_via_label=path.nh_via_label,
                next_hop_out_label_stack=lstack,
                next_hop_n_out_labels=len(lstack),
                is_add=0)

    def query_vpp_config(self):
        dump = self._test.vapi.mpls_tunnel_dump()
        for t in dump:
            if self.sw_if_index == t.mt_sw_if_index and \
               self.tunnel_index == t.mt_tunnel_index:
                return True
        return False

    def object_id(self):
        return ("mpls-tunnel%d-%d" % (self.tunnel_index,
                                      self.sw_if_index))
