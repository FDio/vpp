from vpp_object import VppObject
from vpp_interface import VppInterface


class VppBviInterface(VppInterface, VppObject):
    """VPP bvi interface."""

    def __init__(self, test, *, user_instance=None, mac=None):
        """ Create VPP BVI interface """
        super(VppBviInterface, self).__init__(test)
        self.user_instance = user_instance
        self.mac = mac
        self.add_vpp_config()

    def add_vpp_config(self):
        r = self.test.vapi.bvi_create(user_instance=self.user_instance,
                                      mac=self.mac)
        self.set_sw_if_index(r.sw_if_index)

    def remove_vpp_config(self):
        self.test.vapi.bvi_delete(sw_if_index=self.sw_if_index)

    def object_id(self):
        return "bvi-%d" % self._sw_if_index

    def __repr__(self):
        return f"{self.__class__.__name__}({self._test}, *, " \
               f"user_instance={repr(self.user_instance)}, " \
               f"mac={repr(self.mac)})"
