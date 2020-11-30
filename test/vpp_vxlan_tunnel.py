from vpp_interface import VppInterface
from vpp_papi import VppEnum


INDEX_INVALID = 0xffffffff
DEFAULT_PORT = 4789


def find_vxlan_tunnel(test, src, dst, s_port, d_port, vni):
    ts = test.vapi.vxlan_tunnel_v2_dump(INDEX_INVALID)

    src_port = DEFAULT_PORT
    if s_port is not None:
        src_port = s_port

    dst_port = DEFAULT_PORT
    if d_port is not None:
        dst_port = d_port

    for t in ts:
        if src == str(t.src_address) and \
           dst == str(t.dst_address) and \
           src_port == t.src_port and \
           dst_port == t.dst_port and \
           t.vni == vni:
            return t.sw_if_index
    return INDEX_INVALID


class VppVxlanTunnel(VppInterface):
    """
    VPP VXLAN interface
    """

    def __init__(self, test, src, dst, vni,
                 src_port=None, dst_port=None,
                 mcast_itf=None,
                 mcast_sw_if_index=INDEX_INVALID,
                 decap_next_index=INDEX_INVALID,
                 encap_vrf_id=None, instance=0xffffffff):
        """ Create VXLAN Tunnel interface """
        super(VppVxlanTunnel, self).__init__(test)
        self.src = src
        self.dst = dst
        self.vni = vni
        self.src_port = src_port
        self.dst_port = dst_port
        self.mcast_itf = mcast_itf
        self.mcast_sw_if_index = mcast_sw_if_index
        self.encap_vrf_id = encap_vrf_id
        self.decap_next_index = decap_next_index
        self.instance = instance

        if (self.mcast_itf):
            self.mcast_sw_if_index = self.mcast_itf.sw_if_index

    def add_vpp_config(self):
        reply = self.test.vapi.vxlan_add_del_tunnel_v2(
            is_add=1, src_address=self.src, dst_address=self.dst, vni=self.vni,
            src_port=self.src_port, dst_port=self.dst_port,
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id,
            instance=self.instance, decap_next_index=self.decap_next_index)
        self.set_sw_if_index(reply.sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self.test.vapi.vxlan_add_del_tunnel_v2(
            is_add=0, src_address=self.src, dst_address=self.dst, vni=self.vni,
            src_port=self.src_port, dst_port=self.dst_port,
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id, instance=self.instance,
            decap_next_index=self.decap_next_index)

    def query_vpp_config(self):
        return (INDEX_INVALID != find_vxlan_tunnel(self._test,
                                                   self.src,
                                                   self.dst,
                                                   self.src_port,
                                                   self.dst_port,
                                                   self.vni))

    def object_id(self):
        return "vxlan-%d-%d-%s-%s" % (self.sw_if_index, self.vni,
                                      self.src, self.dst)
