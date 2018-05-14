import socket

from enum import Enum

from vpp_object import VppObject


class IgmpConfigFlags(Enum):
    CLI_API_CONFIGURED = (1 << 2)
    PROXY_ENABLED = (1 << 3)


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
        return self._test.vapi.igmp_config_dump(self.sw_if_index)

    def query_sg_config(self):
        return self._test.vapi.igmp_dump(self.sw_if_index)


class VppIgmpProxy(VppObject):

    def __init__(self, test, sw_if_index, addr=None):
        self._test = test
        self.sw_if_index = sw_if_index
        if addr is None:
            self.addr = socket.inet_pton(socket.AF_INET, "10.0.1.1")
        else:
            self.addr = addr

    def add_vpp_config(self):
        self._test.vapi.igmp_proxy(1, self.sw_if_index, self.addr)

    def remove_vpp_config(self):
        self._test.vapi.igmp_proxy(0, self.sw_if_index, self.addr)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "%s:%d" % (self.addr, self.sw_if_index)

    def query_vpp_config(self):
        return self._test.vapi.igmp_config_dump(self.sw_if_index)

    def query_sg_config(self):
        return self._test.vapi.igmp_dump(self.sw_if_index)
