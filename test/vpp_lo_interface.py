from vpp_object import VppObject
from vpp_interface import VppInterface


class VppLoInterface(VppInterface, VppObject):
    """VPP loopback interface."""

    def __init__(self, test):
        """ Create VPP loopback interface """
        super(VppLoInterface, self).__init__(test)
        self.add_vpp_config()

    def add_vpp_config(self):
        r = self.test.vapi.create_loopback()
        self.set_sw_if_index(r.sw_if_index)

    def remove_vpp_config(self):
        self.test.vapi.delete_loopback(self.sw_if_index)

    def object_id(self):
        return "loopback-%d" % self._sw_if_index
