<<<<<<< HEAD
from vpp_interface import VppInterface
from vpp_papi import VppEnum


INDEX_INVALID = 0xffffffff
DEFAULT_PORT = 4789
UNDEFINED_PORT = 0
=======
from vpp_interface import VppInterface, INDEX_INVALID
>>>>>>> tests: refactor VppInterface


def find_vxlan_tunnel(test, src, dst, s_port, d_port, vni):
    ts = test.vapi.vxlan_tunnel_v2_dump(INDEX_INVALID)

    src_port = DEFAULT_PORT
    if s_port != UNDEFINED_PORT:
        src_port = s_port

    dst_port = DEFAULT_PORT
    if d_port != UNDEFINED_PORT:
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
    details_api = 'vxlan_tunnel_dump'

<<<<<<< HEAD
    def __init__(self, test, src, dst, vni,
                 src_port=UNDEFINED_PORT, dst_port=UNDEFINED_PORT,
                 mcast_itf=None,
                 mcast_sw_if_index=INDEX_INVALID,
                 decap_next_index=INDEX_INVALID,
                 encap_vrf_id=None, instance=0xffffffff):
=======
    def __init__(self, test, src, dst, vni, mcast_itf=None,
                 mcast_sw_if_index=None,
                 decap_next_index=None,
                 encap_vrf_id=None, instance=None):
>>>>>>> tests: refactor VppInterface
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

        if self.mcast_itf is not None:
            self.mcast_sw_if_index = self.mcast_itf.sw_if_index

    def add_vpp_config(self):
<<<<<<< HEAD
        reply = self.test.vapi.vxlan_add_del_tunnel_v2(
            is_add=1, src_address=self.src, dst_address=self.dst, vni=self.vni,
            src_port=self.src_port, dst_port=self.dst_port,
=======
        reply = self.test.vapi.vxlan_add_del_tunnel(
            src_address=self.src, dst_address=self.dst, vni=self.vni,
>>>>>>> tests: refactor VppInterface
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id,
            instance=self.instance,
            decap_next_index=self.decap_next_index)
        self._sw_if_index = reply.sw_if_index
        self.set_sw_if_index(reply.sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
<<<<<<< HEAD
        self.test.vapi.vxlan_add_del_tunnel_v2(
            is_add=0, src_address=self.src, dst_address=self.dst, vni=self.vni,
            src_port=self.src_port, dst_port=self.dst_port,
=======
        self.test.vapi.vxlan_add_del_tunnel(
            is_add=0,
            src_address=self.src, dst_address=self.dst, vni=self.vni,
            sw_if_index=self._sw_if_index,
>>>>>>> tests: refactor VppInterface
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id,
            instance=self.instance,
            decap_next_index=self.decap_next_index)

<<<<<<< HEAD
    def query_vpp_config(self):
        return (INDEX_INVALID != find_vxlan_tunnel(self._test,
                                                   self.src,
                                                   self.dst,
                                                   self.src_port,
                                                   self.dst_port,
                                                   self.vni))
=======
        self._test.registry.unregister(self, self._test.logger)
>>>>>>> tests: refactor VppInterface

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
