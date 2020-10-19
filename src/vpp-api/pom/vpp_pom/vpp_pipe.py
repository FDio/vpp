from vpp_pom.vpp_interface import VppInterface


class VppPipe(VppInterface):
    """
    VPP Pipe
    """

    @property
    def east(self):
        return self.result.pipe_sw_if_index[1]

    @property
    def west(self):
        return self.result.pipe_sw_if_index[0]

    def __init__(self, vclient, instance=0xffffffff):
        super(VppPipe, self).__init__(vclient)
        self._vclient = vclient
        self.instance = instance

    def add_vpp_config(self):
        self.result = self._vclient.pipe_create(
            0 if self.instance == 0xffffffff else 1,
            self.instance)
        self.set_sw_if_index(self.result.sw_if_index)

    def remove_vpp_config(self):
        self._vclient.pipe_delete(
            self.result.sw_if_index)

    def object_id(self):
        return "pipe-%d" % (self._sw_if_index)

    def query_vpp_config(self):
        pipes = self._vclient.pipe_dump()
        for p in pipes:
            if p.sw_if_index == self.result.sw_if_index:
                return True
        return False

    def set_unnumbered(self, ip_sw_if_index, is_add=True):
        res = self._vclient.sw_interface_set_unnumbered(ip_sw_if_index,
                                                        self.east, is_add)
        res = self._vclient.sw_interface_set_unnumbered(ip_sw_if_index,
                                                        self.west, is_add)
