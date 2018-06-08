
from vpp_object import VppObject
import socket


class IGMP_MODE:
    ROUTER = 0
    HOST = 1


class IGMP_FILTER:
    INCLUDE = 1
    EXCLUDE = 0


def find_igmp_state(states, sw_if_index, gaddr, saddr):
    for s in states:
        if s.sw_if_index == sw_if_index and \
           s.gaddr == socket.inet_pton(socket.AF_INET, gaddr) and \
           s.saddr == socket.inet_pton(socket.AF_INET, saddr):
            return True
    return False


def find_igmp_event(ev, itf, gaddr, saddr, is_join):
    if ev.sw_if_index == itf.sw_if_index and \
       ev.gaddr == socket.inet_pton(socket.AF_INET, gaddr) and \
       ev.saddr == socket.inet_pton(socket.AF_INET, saddr) and \
       ev.is_join == is_join:
        return True
    return False


class IgmpSG():
    def __init__(self, saddrs, gaddr):
        self.saddr = saddr
        self.gaddr = gaddr
        self.gaddr_p = socket.inet_pton(socket.AF_INET, gaddr)
        self.saddr_p = socket.inet_pton(socket.AF_INET, saddr)


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
                1, self.sw_if_index, e.saddr_p, e.gaddr_p)

    def remove_vpp_config(self):
        for e in self.sg_list:
            self._test.vapi.igmp_listen(
                0, self.sw_if_index, e.saddr_p, e.gaddr_p)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "%s:%d" % (self.sg_list, self.sw_if_index)

    def query_vpp_config(self):
        return self._test.vapi.igmp_dump()


class VppHostState(VppObject):
    def __init__(self, test, filter, sw_if_index, saddrs, gaddr):
        self._test = test
        self.sw_if_index = sw_if_index
        self.filter = filter
        self.saddrs = saddrs
        self.gaddr = gaddr
        self.gaddr_p = socket.inet_pton(socket.AF_INET, gaddr)
        self.saddrs_p = []
        self.saddrs_encoded = []
        for s in saddrs:
            ss = socket.inet_pton(socket.AF_INET, s)
            self.saddrs_p.append(ss)
            self.saddrs_encoded.append({'address': ss})

    def add_vpp_config(self):
        self._test.vapi.igmp_listen(
            self.filter, self.sw_if_index, self.saddrs_encoded, self.gaddr_p)

    def remove_vpp_config(self):
        self._test.vapi.igmp_listen(
            self.filter,
            self.sw_if_index,
            [],
            self.gaddr_p)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "%s:%d" % (self.sg_list, self.sw_if_index)

    def query_vpp_config(self):
        return self._test.vapi.igmp_dump()
