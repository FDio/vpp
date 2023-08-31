from vpp_tunnel_interface import VppTunnelInterface
from vpp_papi import VppEnum


class VppIpIpTunInterface(VppTunnelInterface):
    """
    VPP IP-IP Tunnel interface
    """

    def __init__(
        self, test, parent_if, src, dst, table_id=0, dscp=0x0, flags=0, mode=None
    ):
        super(VppIpIpTunInterface, self).__init__(test, parent_if)
        self.src = src
        self.dst = dst
        self.table_id = table_id
        self.dscp = dscp
        self.flags = flags
        self.mode = mode
        if not self.mode:
            self.mode = VppEnum.vl_api_tunnel_mode_t.TUNNEL_API_MODE_P2P

    def add_vpp_config(self):
        r = self.test.vapi.ipip_add_tunnel(
            tunnel={
                "src": self.src,
                "dst": self.dst,
                "table_id": self.table_id,
                "flags": self.flags,
                "dscp": self.dscp,
                "instance": 0xFFFFFFFF,
                "mode": self.mode,
            }
        )
        self.set_sw_if_index(r.sw_if_index)
        r = self.test.vapi.ipip_tunnel_dump(sw_if_index=self.sw_if_index)
        self.instance = r[0].tunnel.instance
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.test.vapi.ipip_del_tunnel(sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        ts = self.test.vapi.ipip_tunnel_dump(sw_if_index=0xFFFFFFFF)
        for t in ts:
            if t.tunnel.sw_if_index == self._sw_if_index:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "ipip%d" % self.instance

    @property
    def remote_ip(self):
        return self.dst

    @property
    def local_ip(self):
        return self.src
