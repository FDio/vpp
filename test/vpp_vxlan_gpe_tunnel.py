from vpp_interface import VppInterface
from vpp_papi import VppEnum


INDEX_INVALID = 0xffffffff
DEFAULT_PORT = 4790
UNDEFINED_PORT = 0


def find_vxlan_gpe_tunnel(test, src, dst, s_port, d_port, vni):
    ts = test.vapi.vxlan_gpe_tunnel_v2_dump(INDEX_INVALID)

    src_port = DEFAULT_PORT
    if s_port != UNDEFINED_PORT:
        src_port = s_port

    dst_port = DEFAULT_PORT
    if d_port != UNDEFINED_PORT:
        dst_port = d_port

    for t in ts:
        if src == str(t.local) and \
           dst == str(t.remote) and \
           src_port == t.local_port and \
           dst_port == t.remote_port and \
           t.vni == vni:
            return t.sw_if_index
    return INDEX_INVALID


class VppVxlanGpeTunnel(VppInterface):
    """
    VPP VXLAN GPE interface
    """

    def __init__(self, test, src_addr, dst_addr, vni,
                 src_port=UNDEFINED_PORT, dst_port=UNDEFINED_PORT,
                 mcast_sw_if_index=INDEX_INVALID,
                 encap_vrf_id=None,
                 decap_vrf_id=None, protocol=3):
        """ Create VXLAN GPE Tunnel interface """
        super(VppVxlanGpeTunnel, self).__init__(test)
        self.src = src_addr
        self.dst = dst_addr
        self.vni = vni
        self.src_port = src_port
        self.dst_port = dst_port
        self.mcast_sw_if_index = mcast_sw_if_index
        self.encap_vrf_id = encap_vrf_id
        self.decap_vrf_id = decap_vrf_id
        self.protocol = 3

    def add_vpp_config(self):
        reply = self.test.vapi.vxlan_gpe_add_del_tunnel_v2(
            is_add=1, local=self.src, remote=self.dst, vni=self.vni,
            local_port=self.src_port, remote_port=self.dst_port,
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id,
            decap_vrf_id=self.decap_vrf_id,
            protocol=self.protocol)
        self.set_sw_if_index(reply.sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self.test.vapi.vxlan_gpe_add_del_tunnel_v2(
            is_add=0, local=self.src, remote=self.dst, vni=self.vni,
            local_port=self.src_port, remote_port=self.dst_port,
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id,
            decap_vrf_id=self.decap_vrf_id,
            protocol=self.protocol)

    def query_vpp_config(self):
        return (INDEX_INVALID != find_vxlan_gpe_tunnel(self._test,
                                                       self.src,
                                                       self.dst,
                                                       self.src_port,
                                                       self.dst_port,
                                                       self.vni))

    def object_id(self):
        return "vxlan-%d-%d-%s-%s" % (self.sw_if_index, self.vni,
                                      self.src, self.dst)
