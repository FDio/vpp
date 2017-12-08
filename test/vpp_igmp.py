
from vpp_object import VppObject


class IgmpSG():
    def __init__(self, saddr, gaddr):
        self.saddr = saddr
        self.gaddr = gaddr


class VppIgmpConfig(VppObject):
    def __init__(self, test, sw_if_index, sg=None):
        self._test = test
        self.sw_if_index = sw_if_index
        if isinstance(sg, list):
            self.sg_list = sg
        else:
            self.sg_list = []
            self.sg_list.append(sg)

    def add_sg(self, sg):
        self.sg.append(sg)

    def add_vpp_config(self):
        for e in self.sg_list:
            self._test.vapi.igmp_listen(
                1, self.sw_if_index, e.saddr, e.gaddr)

    def remove_vpp_config(self):
        self._test.vapi.igmp_clear_interface(self.sw_if_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "%s:%d" % (self.sg_list, self.sw_if_index)

    def query_vpp_config(self):
        return self._test.vapi.igmp_dump()
