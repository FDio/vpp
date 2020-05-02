
from vpp_interface import VppInterface


class VppMPLSTunnelInterface(VppInterface):
    """
    VPP MPLS Tunnel interface
    """
    details_api = 'mpls_tunnel_dump'

    def __init__(self, test, paths, is_multicast=None, is_l2=None,):
        """ Create MPLS Tunnel interface """
        super(VppMPLSTunnelInterface, self).__init__(test)
        self.t_paths = paths
        self.is_multicast = is_multicast
        self.l2_only = is_l2
        self.tunnel_index = None  # instance
        self.encoded_paths = [p.encode() for p in self.t_paths]

    def encode(self):
        return {'mt_sw_if_index': self.sw_if_index,
                'mt_tunnel_index': self.tunnel_index,
                'mt_l2_only': self.l2_only,
                'mt_is_multicast': self.is_multicast,
                'mt_n_paths': len(self.encoded_paths),
                'mt_paths': self.encoded_paths,
                }

    def add_vpp_config(self):
        reply = self.test.vapi.mpls_tunnel_add_del(
            mt_tunnel=self.encode()
        )
        self.set_sw_if_index(reply.sw_if_index)
        self.tunnel_index = reply.tunnel_index
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self.test.vapi.mpls_tunnel_add_del(
            mt_tunnel=self.encode(),
            mt_is_add=0)

    def object_id(self):
        return ("mpls-tunnel%d-%d" % (self.tunnel_index,
                                      self.sw_if_index))

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self._test)}, " \
               f"{repr(self.t_paths)}, " \
               f"is_multicast={repr(self.is_multicast)}, " \
               f"is_l2={repr(self.l2_only)})"
