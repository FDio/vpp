
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
        self.encoded_paths = []
        for path in self.t_paths:
            self.encoded_paths.append(path.encode())

    def add_vpp_config(self):
        reply = self.test.vapi.mpls_tunnel_add_del(
            0xffffffff,
            self.encoded_paths,
            is_multicast=self.is_multicast,
            l2_only=self.is_l2)
        self.set_sw_if_index(reply.sw_if_index)
        self.tunnel_index = reply.tunnel_index
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        reply = self.test.vapi.mpls_tunnel_add_del(
            self.sw_if_index,
            self.encoded_paths,
            is_add=0)

    def query_vpp_config(self):
        dump = self._test.vapi.mpls_tunnel_dump()
        for t in dump:
            if self.sw_if_index == t.mt_tunnel.mt_sw_if_index and \
               self.tunnel_index == t.mt_tunnel.mt_tunnel_index:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("mpls-tunnel%d-%d" % (self.tunnel_index,
                                      self.sw_if_index))
