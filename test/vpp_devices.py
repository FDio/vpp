from vpp_interface import VppInterface


class VppTAPInterface(VppInterface):

    @property
    def tap_id(self):
        """TAP id"""
        return self._tap_id

    def __init__(self, test, tap_id=0xffffffff, mac_addr=None):
        self._test = test
        self._tap_id = tap_id
        self._mac_addr = mac_addr

    def get_vpp_dump(self):
        dump = self._test.vapi.sw_interface_tap_v2_dump()
        for entry in dump:
            if entry.sw_if_index == self.sw_if_index:
                return entry

    def add_vpp_config(self):
        use_random_mac = True if self._mac_addr else False
        reply = self._test.vapi.tap_create_v2(
            id=self._tap_id,
            use_random_mac=use_random_mac,
            mac_address=self._mac_addr)
        self.set_sw_if_index(reply.sw_if_index)
        self._test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self._test.vapi.tap_delete_v2(sw_if_index=self.sw_if_index)

    def query_vpp_config(self):
        dump = self.get_vpp_dump()
        if dump:
            return True
        return False

    def object_id(self):
        return "tap-%s" % self._tap_id
