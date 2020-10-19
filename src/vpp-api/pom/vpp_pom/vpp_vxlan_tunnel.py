from .vpp_interface import VppInterface
from vpp_papi import VppEnum


INDEX_INVALID = 0xffffffff


def find_vxlan_tunnel(vclient, src, dst, vni):
    ts = vclient.vxlan_tunnel_dump(INDEX_INVALID)
    for t in ts:
        if src == str(t.src_address) and \
           dst == str(t.dst_address) and \
           t.vni == vni:
            return t.sw_if_index
    return INDEX_INVALID


class VppVxlanTunnel(VppInterface):
    """
    VPP VXLAN interface
    """

    def __init__(self, vclient, src, dst, vni, mcast_itf=None,
                 mcast_sw_if_index=INDEX_INVALID,
                 decap_next_index=INDEX_INVALID,
                 encap_vrf_id=None, instance=0xffffffff):
        """ Create VXLAN Tunnel interface """
        super(VppVxlanTunnel, self).__init__(vclient)
        self.src = src
        self.dst = dst
        self.vni = vni
        self.mcast_itf = mcast_itf
        self.mcast_sw_if_index = mcast_sw_if_index
        self.encap_vrf_id = encap_vrf_id
        self.decap_next_index = decap_next_index
        self.instance = instance

        if (self.mcast_itf):
            self.mcast_sw_if_index = self.mcast_itf.sw_if_index

    def add_vpp_config(self):
        reply = self.vclient.vxlan_add_del_tunnel(
            is_add=1, src_address=self.src, dst_address=self.dst, vni=self.vni,
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id,
            instance=self.instance, decap_next_index=self.decap_next_index)
        self.set_sw_if_index(reply.sw_if_index)
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        self.vclient.vxlan_add_del_tunnel(
            is_add=0, src_address=self.src, dst_address=self.dst, vni=self.vni,
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id, instance=self.instance,
            decap_next_index=self.decap_next_index)

    def query_vpp_config(self):
        return (INDEX_INVALID != find_vxlan_tunnel(self._vclient,
                                                   self.src,
                                                   self.dst,
                                                   self.vni))

    def object_id(self):
        return "vxlan-%d-%d-%s-%s" % (self.sw_if_index, self.vni,
                                      self.src, self.dst)
