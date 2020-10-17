from vpp_object import VppObject
from vpp_papi import VppEnum
from vpp_interface import VppInterface


class VppNullInterface(VppInterface):
    """
    VPP Null interface
    """

    def __init__(self, test, instance=0xffffffff):
        super(VppNullInterface, self).__init__(test)
        self.instance = instance

    def add_vpp_config(self):
        r = self.test.vapi.null_create(user_instance=self.instance)
        self.set_sw_if_index(r.sw_if_index)
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.test.vapi.null_delete(sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        ts = self.test.vapi.sw_interface_dump(sw_if_index=0xffffffff)
        for t in ts:
            if t.sw_if_index == self._sw_if_index:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "null-%d" % self._sw_if_index
