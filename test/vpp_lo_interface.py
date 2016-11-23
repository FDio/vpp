
from vpp_interface import VppInterface


class VppLoInterface(VppInterface):
    """VPP loopback interface."""

    def __init__(self, test, lo_index):
        """ Create VPP loopback interface """
        r = test.vapi.create_loopback()
        self._sw_if_index = r.sw_if_index
        super(VppLoInterface, self).__init__(test)
        self._lo_index = lo_index
