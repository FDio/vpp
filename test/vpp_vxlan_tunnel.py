from vpp_interface import VppInterface, INDEX_INVALID


def find_vxlan_tunnel(test, src, dst, vni):
    ts = test.vapi.vxlan_tunnel_dump(INDEX_INVALID)
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
    details_api = 'vxlan_tunnel_dump'

    def __init__(self, test, src, dst, vni, mcast_itf=None,
                 mcast_sw_if_index=None,
                 decap_next_index=None,
                 encap_vrf_id=None, instance=None):
        """ Create VXLAN Tunnel interface """
        super(VppVxlanTunnel, self).__init__(test)
        self.src = src
        self.dst = dst
        self.vni = vni
        self.mcast_itf = mcast_itf
        self.mcast_sw_if_index = mcast_sw_if_index
        self.encap_vrf_id = encap_vrf_id
        self.decap_next_index = decap_next_index
        self.instance = instance

        if self.mcast_itf is not None:
            self.mcast_sw_if_index = self.mcast_itf.sw_if_index

    def add_vpp_config(self):
        reply = self.test.vapi.vxlan_add_del_tunnel(
            src_address=self.src, dst_address=self.dst, vni=self.vni,
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id,
            instance=self.instance,
            decap_next_index=self.decap_next_index)
        self._sw_if_index = reply.sw_if_index
        self.set_sw_if_index(reply.sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self.test.vapi.vxlan_add_del_tunnel(
            is_add=0,
            src_address=self.src, dst_address=self.dst, vni=self.vni,
            sw_if_index=self._sw_if_index,
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id,
            instance=self.instance,
            decap_next_index=self.decap_next_index)

        self._test.registry.unregister(self, self._test.logger)

    def object_id(self):
        return "vxlan-%s-%d-%s-%s" % (self.sw_if_index, self.vni,
                                      self.src, self.dst)

    def __repr__(self):
        return f"{self.__class__.__name__}({self._test}, {self.src}, " \
               f"{self.dst}, {self.vni}, mcast_itf={repr(self.mcast_itf)}," \
               f"mcast_sw_if_index={repr(self.mcast_sw_if_index)}," \
               f"decap_next_index={repr(self.decap_next_index)}," \
               f"encap_vrf_id={repr(self.encap_vrf_id)}, " \
               f"instance={repr(self.instance)})"
