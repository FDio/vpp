from vpp_tunnel_interface import VppTunnelInterface
from vpp_papi import VppEnum


class VppIpIpTunInterface(VppTunnelInterface):
    """
    VPP IP-IP Tunnel interface
    """
    details_api = 'ipip_tunnel_dump'

    def __init__(self, test, parent_if, src, dst,
                 table_id=None, dscp=None,
                 flags=None, mode=None, instance=None):
        super(VppIpIpTunInterface, self).__init__(test, parent_if)
        self.src = src
        self.dst = dst
        self.table_id = table_id
        self.dscp = dscp
        self.flags = flags
        self.instance = instance
        self.mode = mode

        if self.mode is None:
            self.mode = (VppEnum.vl_api_tunnel_mode_t.
                         TUNNEL_API_MODE_P2P)

    def encode(self):
        return {
                'src': self.src,
                'dst': self.dst,
                'table_id': self.table_id,
                'flags': self.flags,
                'dscp': self.dscp,
                'instance': self.instance,
                'mode': self.mode,
        }

    def add_vpp_config(self):
        r = self.test.vapi.ipip_add_tunnel(
            tunnel=self.encode())
        self.set_sw_if_index(r.sw_if_index)
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.test.vapi.ipip_del_tunnel(sw_if_index=self._sw_if_index)
        self.test.registry.unregister(self, self.test.logger)

    def __str__(self):
        return self.object_id()

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self._test)}, " \
               f"{repr(self.parent_if)}, " \
               f"{repr(self.src)}, {repr(self.dst)}, " \
               f"table_id={repr(self.table_id)}, " \
               f"dscp={repr({self.dscp})}, flags={repr(self.flags)}, " \
               f"mode={repr(self.mode)}, instance={repr(self.instance)})"

    def object_id(self):
        return "ipip-%d" % self._sw_if_index

    @property
    def remote_ip(self):
        return self.dst

    @property
    def local_ip(self):
        return self.src
