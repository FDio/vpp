
from vpp_interface import VppInterface
import socket
from vpp_papi import VppEnum


class VppGreInterface(VppInterface):
    """
    VPP GRE interface
    """
    details_api = 'gre_tunnel_dump'

    def __init__(self, test, src_ip, dst_ip, outer_table_id=None,
                 type=None, mode=None, flags=None,
                 session=None, instance=None):
        """ Create VPP GRE interface """
        super(VppGreInterface, self).__init__(test)
        self.t_src = src_ip
        self.t_dst = dst_ip
        self.t_outer_table = outer_table_id
        self.instance = instance
        self.t_session = session
        self.t_flags = flags
        self.t_type = type
        # TODO: remove when papi supports enums as defaults
        if self.t_type is None:
            self.t_type = (VppEnum.vl_api_gre_tunnel_type_t.
                           GRE_API_TUNNEL_TYPE_L3)
        self.t_mode = mode
        # TODO: remove when papi supports enums as defaults
        if self.t_mode is None:
            self.t_mode = (VppEnum.vl_api_tunnel_mode_t.
                           TUNNEL_API_MODE_P2P)

    def encode(self):
        return {
                'src': self.t_src,
                'dst': self.t_dst,
                'outer_table_id': self.t_outer_table,
                'instance': self.instance,
                'type': self.t_type,
                'mode': self.t_mode,
                'flags': self.t_flags,
                'session_id': self.t_session
        }

    def add_vpp_config(self):
        r = self.test.vapi.gre_tunnel_add_del(
            tunnel=self.encode())
        self.set_sw_if_index(r.sw_if_index)
        self.generate_remote_hosts()
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.unconfig()
        self.test.vapi.gre_tunnel_add_del(
            is_add=0,
            tunnel=self.encode())

    def object_id(self):
        return "gre-%d" % self.sw_if_index

    def __repr__(self):
        return f"{self.__class__.__name__}({self.test}, {self.t_src}, " \
               f"{self.t_dst}, outer_table_id={repr(self.t_outer_table)}, " \
               f"type={repr(self.t_type)}, mode={repr(self.t_mode)}, " \
               f"flags={repr(self.t_flags)}, " \
               f"session={repr(self.t_session)}, " \
               f"instance={repr(self.instance)})"

    @property
    def remote_ip(self):
        return self.t_dst

    @property
    def local_ip(self):
        return self.t_src
