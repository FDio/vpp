from vpp_interface import VppInterface


class VppNetmapInterface(VppInterface):

    def __init__(self, test, host_if_name, mac_addr=None, is_pipe=False, is_master=False):
        self._test = test
        self._host_if_name = host_if_name
        self._mac_addr = mac_addr
        self._is_pipe = is_pipe
        self._is_master = is_master

    def get_vpp_dump(self):
        dump = self._test.vapi.netmap_dump()
        for entry in dump:
            if entry.sw_if_index == self.sw_if_index:
                return entry

    def add_vpp_config(self):
        use_random_mac = True if self._mac_addr else False
        reply = self._test.vapi.netmap_create(
            netmap_if_name=self._host_if_name,
            use_random_hw_addr=use_random_mac,
            hw_addr=self._mac_addr,
            is_pipe=self._is_pipe,
            is_master=self._is_master)
        self.set_sw_if_index(reply.sw_if_index)
        self._test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self._test.vapi.netmap_delete(netmap_if_name=self._host_if_name)

    def query_vpp_config(self):
        dump = self.get_vpp_dump()
        if dump:
            return True
        return False

    def object_id(self):
        return "netmap-%s" % self._host_if_name
