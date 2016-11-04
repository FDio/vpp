
from vpp_interface import VppInterface


class VppLoInterface(VppInterface):
    """
    VPP loopback interface
    """

    def __init__(self, test, lo_index):
        """ Create VPP loopback interface """
        self._lo_index = lo_index
        self._test = test
        r = self.test.vapi.create_loopback()
        self._sw_if_index = r.sw_if_index
        self.post_init_setup()
