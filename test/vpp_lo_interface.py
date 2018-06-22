from vpp_object import VppObject
from vpp_interface import VppInterface


class VppLoInterface(VppInterface, VppObject):
    """VPP loopback interface."""

    def __init__(self, test, lo_index):
        """ Create VPP loopback interface """
        self._test = test
        self.add_vpp_config()
        super(VppLoInterface, self).__init__(test)
        self._lo_index = lo_index

    def add_vpp_config(self):
        r = self.test.vapi.create_loopback()
        self._sw_if_index = r.sw_if_index

    def remove_vpp_config(self):
        self.test.vapi.delete_loopback(self.sw_if_index)

    def object_id(self):
        return "loopback-%d" % self._sw_if_index
