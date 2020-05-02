
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
    details_api = 'vxlan_gbp_tunnel_dump'

    def __init__(self, test, src, dst, vni, mcast_itf=None, mode=None,
                 is_ipv6=None, encap_table_id=None, instance=None):
        """ Create VXLAN-GBP Tunnel interface """
        super(VppVxlanGbpTunnel, self).__init__(test)
        self.src = src
        self.dst = dst
        self.vni = vni
        self.mcast_itf = mcast_itf
        self.ipv6 = is_ipv6
        self.encap_table_id = encap_table_id
        self.instance = instance
        # TODO: remove when papi supports enums as defaults
        if mode is None:
            self.mode = (VppEnum.vl_api_vxlan_gbp_api_tunnel_mode_t.
                         VXLAN_GBP_API_TUNNEL_MODE_L2)
        else:
            self.mode = mode

    def encode(self):
        mcast_sw_if_index = INDEX_INVALID
        if self.mcast_itf is not None:
            mcast_sw_if_index = self.mcast_itf.sw_if_index
        return {
                'src': self.src,
                'dst': self.dst,
                'mode': self.mode,
                'vni': self.vni,
                'mcast_sw_if_index': mcast_sw_if_index,
                'encap_table_id': self.encap_table_id,
                'instance': self.instance,
        }

    def add_vpp_config(self):
        reply = self.test.vapi.vxlan_gbp_tunnel_add_del(
            tunnel=self.encode())
        self.set_sw_if_index(reply.sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self.test.vapi.vxlan_gbp_tunnel_add_del(
            is_add=0,
            tunnel=self.encode())

    def object_id(self):
        return "vxlan-gbp-%d-%d-%s-%s" % (self.sw_if_index, self.vni,
                                          self.src, self.dst)

    def __repr__(self):
        return f""
