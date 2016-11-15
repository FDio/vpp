
from vpp_interface import VppInterface
import socket


class VppGreInterface(VppInterface):
    """
    VPP GRE interface
    """

    def __init__(self, test, src_ip, dst_ip, outer_fib_id=0, is_teb=0):
        """ Create VPP loopback interface """
        self._test = test
        self.t_src = src_ip
        self.t_dst = dst_ip
        self.t_outer_fib = outer_fib_id
        self.t_is_teb = is_teb

    def add_vpp_config(self):
        s = socket.inet_pton(socket.AF_INET, self.t_src)
        d = socket.inet_pton(socket.AF_INET, self.t_dst)
        r = self.test.vapi.gre_tunnel_add_del(s, d,
                                              outer_fib_id=self.t_outer_fib,
                                              is_teb=self.t_is_teb)
        self._sw_if_index = r.sw_if_index
        self.post_init_setup()

    def remove_vpp_config(self):
        s = socket.inet_pton(socket.AF_INET, self.t_src)
        d = socket.inet_pton(socket.AF_INET, self.t_dst)
        self.unconfig()
        r = self.test.vapi.gre_tunnel_add_del(s, d,
                                              outer_fib_id=self.t_outer_fib,
                                              is_add=0)
