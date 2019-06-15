
from vpp_interface import VppInterface
import socket
from vpp_papi import VppEnum


class VppGreInterface(VppInterface):
    """
    VPP GRE interface
    """

    def __init__(self, test, src_ip, dst_ip, outer_fib_id=0, type=None,
                 session=0):
        """ Create VPP GRE interface """
        super(VppGreInterface, self).__init__(test)
        self.t_src = src_ip
        self.t_dst = dst_ip
        self.t_outer_fib = outer_fib_id
        self.t_session = session
        self.t_type = type
        if not self.t_type:
            self.t_type = (VppEnum.vl_api_gre_tunnel_type_t.
                           GRE_API_TUNNEL_TYPE_L3)

    def add_vpp_config(self):
        r = self.test.vapi.gre_tunnel_add_del(self.t_src,
                                              self.t_dst,
                                              outer_fib_id=self.t_outer_fib,
                                              tunnel_type=self.t_type,
                                              session_id=self.t_session)
        self.set_sw_if_index(r.sw_if_index)
        self.generate_remote_hosts()
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.unconfig()
        self.test.vapi.gre_tunnel_add_del(self.t_src,
                                          self.t_dst,
                                          outer_fib_id=self.t_outer_fib,
                                          tunnel_type=self.t_type,
                                          session_id=self.t_session,
                                          is_add=0)

    def object_id(self):
        return "gre-%d" % self.sw_if_index

    def query_vpp_config(self):
        return (self.test.vapi.gre_tunnel_dump(
            sw_if_index=self._sw_if_index))
