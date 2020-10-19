from .vpp_object import VppObject
from .vpp_interface import VppInterface


class VppLoInterface(VppInterface, VppObject):
    """VPP loopback interface."""

    def __init__(self, vclient):
        """ Create VPP loopback interface """
        super(VppLoInterface, self).__init__(vclient)
        self.add_vpp_config()

    def add_vpp_config(self):
        if self.query_vpp_config():
            raise RuntimeError("Configuration already present")
        r = self.vclient.vapi.create_loopback()
        self.set_sw_if_index(r.sw_if_index)
        self.vclient.registry.register(self, self.vclient.logger)

    def remove_vpp_config(self):
        self.vclient.vapi.delete_loopback(sw_if_index=self.sw_if_index)
    
    def get_vpp_dump(self):
        if not self.sw_if_index:
            return None
        dump = self._vclient.vapi.sw_interface_dump(
            sw_if_index=self.sw_if_index)
        return dump

    def query_vpp_config(self):
        dump = self.get_vpp_dump()
        return bool(dump)

    def object_id(self):
        return "loopback-%d" % self._sw_if_index
