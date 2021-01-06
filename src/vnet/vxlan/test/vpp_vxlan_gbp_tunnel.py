
from vpp_interface import VppInterface
from vpp_papi import VppEnum


INDEX_INVALID = 0xffffffff


def find_vxlan_gbp_tunnel(test, src, dst, vni):
    ts = test.vapi.vxlan_gbp_tunnel_dump(INDEX_INVALID)
    for t in ts:
        if src == str(t.tunnel.src) and \
           dst == str(t.tunnel.dst) and \
           t.tunnel.vni == vni:
            return t.tunnel.sw_if_index
    return INDEX_INVALID


class VppVxlanGbpTunnel(VppInterface):
    """
    VPP VXLAN GBP interface
    """

    def __init__(self, test, src, dst, vni, mcast_itf=None, mode=None,
                 is_ipv6=None, encap_table_id=None, instance=0xffffffff):
        """ Create VXLAN-GBP Tunnel interface """
        super(VppVxlanGbpTunnel, self).__init__(test)
        self.src = src
        self.dst = dst
        self.vni = vni
        self.mcast_itf = mcast_itf
        self.ipv6 = is_ipv6
        self.encap_table_id = encap_table_id
        self.instance = instance
        if not mode:
            self.mode = (VppEnum.vl_api_vxlan_gbp_api_tunnel_mode_t.
                         VXLAN_GBP_API_TUNNEL_MODE_L2)
        else:
            self.mode = mode

    def add_vpp_config(self):
        mcast_sw_if_index = INDEX_INVALID
        if (self.mcast_itf):
            mcast_sw_if_index = self.mcast_itf.sw_if_index
        reply = self.test.vapi.vxlan_gbp_tunnel_add_del(
            is_add=1,
            tunnel={
                'src': self.src,
                'dst': self.dst,
                'mode': self.mode,
                'vni': self.vni,
                'mcast_sw_if_index': mcast_sw_if_index,
                'encap_table_id': self.encap_table_id,
                'instance': self.instance
            })
        self.set_sw_if_index(reply.sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        mcast_sw_if_index = INDEX_INVALID
        if (self.mcast_itf):
            mcast_sw_if_index = self.mcast_itf.sw_if_index
        self.test.vapi.vxlan_gbp_tunnel_add_del(
            is_add=0,
            tunnel={
                'src': self.src,
                'dst': self.dst,
                'mode': self.mode,
                'vni': self.vni,
                'mcast_sw_if_index': mcast_sw_if_index,
                'encap_table_id': self.encap_table_id,
                'instance': self.instance,
            })

    def query_vpp_config(self):
        return (INDEX_INVALID != find_vxlan_gbp_tunnel(self._test,
                                                       self.src,
                                                       self.dst,
                                                       self.vni))

    def object_id(self):
        return "vxlan-gbp-%d-%d-%s-%s" % (self.sw_if_index, self.vni,
                                          self.src, self.dst)
