from ipaddress import ip_address

from vpp_tunnel_interface import VppTunnelInterface


class VppIpIpTunInterface(VppTunnelInterface):
    """
    VPP IP-IP Tunnel interface
    """

    def __init__(self, test, parent_if, src, dst):
        super(VppIpIpTunInterface, self).__init__(test, parent_if)
        self.src = src
        self.dst = dst

    def add_vpp_config(self):
        r = self.test.vapi.ipip_add_tunnel(
            tunnel={
                'src': self.src,
                'dst': self.dst,
                'table_id': 0,
                'instance': 0xffffffff,
            })
        self.set_sw_if_index(r.sw_if_index)
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipip_del_tunnel(sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        ts = self.test.vapi.ipip_tunnel_dump(sw_if_index=0xffffffff)
        for t in ts:
            if t.tunnel.sw_if_index == self._sw_if_index:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "ipip-%d" % self._sw_if_index

    @property
    def remote_ip(self):
        return self.dst

    @property
    def local_ip(self):
        return self.src
