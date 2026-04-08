from vpp_interface import VppInterface
from vpp_papi import VppEnum


class VppGreInterface(VppInterface):
    """
    VPP GRE interface
    """

    def __init__(
        self,
        test,
        src_ip,
        dst_ip,
        outer_table_id=0,
        type=None,
        mode=None,
        flags=0,
        session=0,
        gre_key=0,
    ):
        """Create VPP GRE interface"""
        super(VppGreInterface, self).__init__(test)
        self.t_src = src_ip
        self.t_dst = dst_ip
        self.t_outer_table = outer_table_id
        self.t_session = session
        self.t_gre_key = gre_key  # Added GRE key field
        self.t_flags = flags
        self.t_type = type
        if not self.t_type:
            self.t_type = VppEnum.vl_api_gre_tunnel_type_t.GRE_API_TUNNEL_TYPE_L3
        self.t_mode = mode
        if not self.t_mode:
            self.t_mode = VppEnum.vl_api_tunnel_mode_t.TUNNEL_API_MODE_P2P
        self.vpp_sw_if_index = 0xFFFFFFFF

    def add_vpp_config(self):
        r = self.test.vapi.gre_tunnel_add_del_v2(
            is_add=1,
            tunnel={
                "src": self.t_src,
                "dst": self.t_dst,
                "outer_table_id": self.t_outer_table,
                "instance": 0xFFFFFFFF,
                "type": self.t_type,
                "mode": self.t_mode,
                "flags": self.t_flags,
                "session_id": self.t_session,
                "key": self.t_gre_key,
            },
        )

        self.set_sw_if_index(r.sw_if_index)
        self.vpp_sw_if_index = r.sw_if_index
        self.generate_remote_hosts()
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.unconfig()

        self.test.vapi.gre_tunnel_add_del_v2(
            is_add=0,
            tunnel={
                "src": self.t_src,
                "dst": self.t_dst,
                "outer_table_id": self.t_outer_table,
                "instance": 0xFFFFFFFF,
                "type": self.t_type,
                "mode": self.t_mode,
                "flags": self.t_flags,
                "session_id": self.t_session,
                "key": self.t_gre_key,
            },
        )

    def object_id(self):
        return "gre-%d" % self.sw_if_index

    def query_vpp_config(self):
        dump = self.test.vapi.gre_tunnel_v2_dump(sw_if_index=self.vpp_sw_if_index)

        # Validate dump data matches this tunnel's configuration
        for entry in dump:
            # Compare tunnel parameters
            key_match = True
            if self.t_gre_key != 0:
                # For tunnels with keys, also validate the key value
                key_match = entry.tunnel.key == self.t_gre_key

            if (
                entry.tunnel.sw_if_index == self.sw_if_index
                and str(entry.tunnel.src) == str(self.t_src)
                and str(entry.tunnel.dst) == str(self.t_dst)
                and entry.tunnel.type == self.t_type
                and key_match
            ):
                return True

        return False

    @property
    def remote_ip(self):
        return self.t_dst

    @property
    def local_ip(self):
        return self.t_src
