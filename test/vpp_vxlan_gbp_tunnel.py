
from vpp_interface import VppInterface
from vpp_ip import VppIpAddress


INDEX_INVALID = 0xffffffff


def find_vxlan_gbp_tunnel(test, src, dst, vni):
    vsrc = VppIpAddress(src)
    vdst = VppIpAddress(dst)

    ts = test.vapi.vxlan_gbp_tunnel_dump(INDEX_INVALID)
    for t in ts:
        if vsrc == t.tunnel.src and \
           vdst == t.tunnel.dst and \
           t.tunnel.vni == vni:
            return t.tunnel.sw_if_index
    return INDEX_INVALID


class VppVxlanGbpTunnel(VppInterface):
    """
    VPP VXLAN GBP interface
    """

    def __init__(self, test, src, dst, vni, mcast_itf=None):
        """ Create VXLAN-GBP Tunnel interface """
        super(VppVxlanGbpTunnel, self).__init__(test)
        self.src = VppIpAddress(src)
        self.dst = VppIpAddress(dst)
        self.vni = vni
        self.mcast_itf = mcast_itf

    def add_vpp_config(self):
        mcast_sw_if_index = INDEX_INVALID
        if (self.mcast_itf):
            mcast_sw_if_index = self.mcast_itf.sw_if_index
        reply = self.test.vapi.vxlan_gbp_tunnel_add_del(
            self.src.encode(),
            self.dst.encode(),
            vni=self.vni,
            mcast_sw_if_index=mcast_sw_if_index)
        self.set_sw_if_index(reply.sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        mcast_sw_if_index = INDEX_INVALID
        if (self.mcast_itf):
            mcast_sw_if_index = self.mcast_itf.sw_if_index
        self.test.vapi.vxlan_gbp_tunnel_add_del(
            self.src.encode(),
            self.dst.encode(),
            vni=self.vni,
            is_add=0,
            mcast_sw_if_index=mcast_sw_if_index)

    def query_vpp_config(self):
        return (INDEX_INVALID != find_vxlan_gbp_tunnel(self._test,
                                                       self.src.address,
                                                       self.dst.address,
                                                       self.vni))

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "vxlan-gbp-%d-%d-%s-%s" % (self.sw_if_index, self.vni,
                                          self.src, self.dst)
