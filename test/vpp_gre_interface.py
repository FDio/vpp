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
        self.t_gre_key = gre_key
        self.t_flags = flags
        self.t_type = type
        if not self.t_type:
            self.t_type = VppEnum.vl_api_gre_tunnel_type_t.GRE_API_TUNNEL_TYPE_L3
        self.t_mode = mode
        if not self.t_mode:
            self.t_mode = VppEnum.vl_api_tunnel_mode_t.TUNNEL_API_MODE_P2P

    def add_vpp_config(self):
        # Check if we have the gre_key attribute, which might be missing in older class instances
        gre_key = getattr(self, 't_gre_key', 0)
        
        # If we need a key, use the v2 API
        if gre_key != 0:
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
                    "key": gre_key,
                },
            )
            self.set_sw_if_index(r.sw_if_index)
        else:
            # Use regular v1 API for tunnels without key
            r = self.test.vapi.gre_tunnel_add_del(
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
                },
            )
            self.set_sw_if_index(r.sw_if_index)
            
        self.generate_remote_hosts()
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.unconfig()
        
        try:
            self.test.vapi.sw_interface_set_flags(self.sw_if_index, 0)  # admin down
        except Exception:
            pass
            
        gre_key = getattr(self, 't_gre_key', 0)
        
        if gre_key != 0:
            try:
                # Use CLI command which supports GRE key
                self.test.logger.info(f"Deleting GRE tunnel with CLI - src: {self.t_src}, dst: {self.t_dst}, key: {gre_key}")
                cli_cmd = f"create gre tunnel del src {self.t_src} dst {self.t_dst} key {gre_key}"
                self.test.vapi.cli(cli_cmd)
                self.test.logger.info(f"Successfully removed GRE tunnel with CLI")
                return
            except Exception:
                pass
        # For tunnels without keys, use standard v1 API
        try:
            self.test.vapi.gre_tunnel_add_del(
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
                },
            )
        except Exception:
            pass

    def object_id(self):
        return "gre-%d" % self.sw_if_index

    def query_vpp_config(self):
        """
        Query the GRE tunnel configuration from VPP
        
        Return True if tunnel exists, False otherwise.
        This method handles both tunnels with and without keys.
        """
        try:
            # First check if the interface exists at all
            if not hasattr(self, 'sw_if_index') or self.sw_if_index == 0xFFFFFFFF:
                return False
                
            # Query interface info to verify it exists
            sw_if_indices = []
            try:
                # Try to get interface info - will fail if interface doesn't exist
                ifs = self.test.vapi.sw_interface_dump(sw_if_index=self.sw_if_index)
                for i in ifs:
                    sw_if_indices.append(i.sw_if_index)
                
                # Interface not found
                if self.sw_if_index not in sw_if_indices:
                    return False
            except Exception:
                return False
                
            # For tunnels with keys, use CLI to verify if it exists
            gre_key = getattr(self, 't_gre_key', 0)
            if gre_key != 0:
                tunnels_info = self.test.vapi.cli("show gre tunnel")
                key_pattern = f"key {gre_key}"
                src_pattern = str(self.t_src)
                dst_pattern = str(self.t_dst)
                
                if (key_pattern in tunnels_info and 
                    src_pattern in tunnels_info and 
                    dst_pattern in tunnels_info):
                    return True
                return False
            else:
                # For tunnels without keys, use the v1 API
                dump = self.test.vapi.gre_tunnel_dump(sw_if_index=self.sw_if_index)
                # If the dump returns any entries, the tunnel exists
                return len(dump) > 0
                
        except Exception:
            # Any exception means the tunnel doesn't exist or is inaccessible
            return False

    @property
    def remote_ip(self):
        return self.t_dst

    @property
    def local_ip(self):
        return self.t_src
