from .vpp_object import VppObject
from .vpp_interface import VppInterface


class VppBviInterface(VppInterface, VppObject):
    """VPP bvi interface."""

    def __init__(self, vclient):
        """ Create VPP BVI interface """
        super(VppBviInterface, self).__init__(vclient)

    def add_vpp_config(self, register=True):
        r = self.vclient.bvi_create(user_instance=0xffffffff,
                                    mac="00:00:00:00:00:00")
        self.set_sw_if_index(r.sw_if_index)
        if register:
            self.vclient.registry.register(self, self.vclient.logger)

    def remove_vpp_config(self):
        self.vclient.bvi_delete(sw_if_index=self.sw_if_index)

    def object_id(self):
        return "bvi-%d" % self._sw_if_index
