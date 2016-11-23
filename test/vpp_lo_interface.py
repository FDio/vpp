
from vpp_interface import VppInterface


class VppLoInterface(VppInterface):
    """VPP loopback interface."""

    def __new__(cls, test, lo_index):
        instance = VppInterface.__new__(cls, test)
        r = test.vapi.create_loopback()
        instance._sw_if_index = r.sw_if_index
        return instance

    def __init__(self, test, lo_index):
        """ Create VPP loopback interface """
        super(VppLoInterface, self).__init__(test)
        self._lo_index = lo_index
