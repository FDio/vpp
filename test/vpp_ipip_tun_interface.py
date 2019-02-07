from vpp_tunnel_interface import VppTunnelInterface
from ipaddress import ip_address


class VppIpIpTunInterface(VppTunnelInterface):
    """
    VPP IP-IP Tunnel interface
    """

    def __init__(self, test, parent_if, src, dst):
        super(VppIpIpTunInterface, self).__init__(test, parent_if)
        self.src = ip_address(unicode(src))
        self.dst = ip_address(unicode(dst))

    def add_vpp_config(self):
        r = self.test.vapi.ipip_add_tunnel(
            src_address=self.src.packed,
            dst_address=self.dst.packed,
            is_ipv6=self.src.version == 6)
        self.set_sw_if_index(r.sw_if_index)
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipip_del_tunnel(sw_if_index=self._sw_if_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "ipip-%d" % self._sw_if_index
