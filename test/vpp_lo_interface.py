from vpp_object import VppObject
from vpp_interface import VppInterface


class VppLoInterface(VppInterface, VppObject):
    """VPP loopback interface."""

    def __init__(self, test, lo_index):
        """ Create VPP loopback interface """
        r = test.vapi.create_loopback()
        self._sw_if_index = r.sw_if_index
        super(VppLoInterface, self).__init__(test)
        self._lo_index = lo_index

    def add_vpp_config(self):
        # nothing to implement
        pass

    def remove_vpp_config(self):
        self._test.vapi.delete_loopback(self._sw_if_index)

    def query_vpp_config(self):
        dump = self.vapi.sw_interface_dump()
        return self.querry_vpp_lo_config_from_dump(dump) and self.querry_vpp_ip4_config_from_dump

    def querry_vpp_lo_config_from_dump(self, dump):
        # TODO: check also state?
        dumped_interfaces = [
            (i.interface_name.rstrip(' \t\r\n\0'), i.sw_if_index) for i in dump]
        return (self.name, self.sw_if_index, ) in dumped_interfaces

    def object_id(self):
        return "loopback-%d" % self._sw_if_index
