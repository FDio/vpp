
from vpp_interface import VppInterface
import socket


class VppGreInterface(VppInterface):
    """
    VPP GRE interface
    """

    def __init__(self, test, src_ip, dst_ip, outer_fib_id=0, type=0,
                 session=0):
        """ Create VPP GRE interface """
        self._sw_if_index = 0
        super(VppGreInterface, self).__init__(test)
        self._test = test
        self.t_src = src_ip
        self.t_dst = dst_ip
        self.t_outer_fib = outer_fib_id
        self.t_type = type
        self.t_session = session

    def add_vpp_config(self):
        s = socket.inet_pton(socket.AF_INET, self.t_src)
        d = socket.inet_pton(socket.AF_INET, self.t_dst)
        r = self.test.vapi.gre_tunnel_add_del(s, d,
                                              outer_fib_id=self.t_outer_fib,
                                              tunnel_type=self.t_type,
                                              session_id=self.t_session)
        self._sw_if_index = r.sw_if_index
        self.generate_remote_hosts()
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        s = socket.inet_pton(socket.AF_INET, self.t_src)
        d = socket.inet_pton(socket.AF_INET, self.t_dst)
        self.unconfig()
        self.test.vapi.gre_tunnel_add_del(s, d,
                                          outer_fib_id=self.t_outer_fib,
                                          tunnel_type=self.t_type,
                                          session_id=self.t_session,
                                          is_add=0)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gre-%d" % self._sw_if_index


class VppGre6Interface(VppInterface):
    """
    VPP GRE IPv6 interface
    """

    def __init__(self, test, src_ip, dst_ip, outer_fib_id=0, type=0,
                 session=0):
        """ Create VPP GRE interface """
        self._sw_if_index = 0
        super(VppGre6Interface, self).__init__(test)
        self._test = test
        self.t_src = src_ip
        self.t_dst = dst_ip
        self.t_outer_fib = outer_fib_id
        self.t_type = type
        self.t_session = session

    def add_vpp_config(self):
        s = socket.inet_pton(socket.AF_INET6, self.t_src)
        d = socket.inet_pton(socket.AF_INET6, self.t_dst)
        r = self.test.vapi.gre_tunnel_add_del(s, d,
                                              outer_fib_id=self.t_outer_fib,
                                              tunnel_type=self.t_type,
                                              session_id=self.t_session,
                                              is_ip6=1)
        self._sw_if_index = r.sw_if_index
        self.generate_remote_hosts()
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        s = socket.inet_pton(socket.AF_INET6, self.t_src)
        d = socket.inet_pton(socket.AF_INET6, self.t_dst)
        self.unconfig()
        self.test.vapi.gre_tunnel_add_del(s, d,
                                          outer_fib_id=self.t_outer_fib,
                                          tunnel_type=self.t_type,
                                          session_id=self.t_session,
                                          is_add=0,
                                          is_ip6=1)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gre-%d" % self._sw_if_index
