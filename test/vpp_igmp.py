
import enum
import socket

from vpp_object import VppObject


class IGMP_MODE(enum.IntEnum):  # noqa
    ROUTER = 0
    HOST = 1


class IGMP_FILTER(enum.IntEnum):  # noqa
    INCLUDE = 1
    EXCLUDE = 0


def find_igmp_state(states, itf, gaddr, saddr):
    for s in states:
        if s.sw_if_index == itf.sw_if_index and \
           str(s.gaddr) == gaddr and str(s.saddr) == saddr:
            return True
    return False


def wait_for_igmp_event(test, timeout, itf, gaddr, saddr, ff):
    ev = test.vapi.wait_for_event(timeout, "igmp_event")
    if ev.sw_if_index == itf.sw_if_index and \
       str(ev.gaddr) == gaddr and str(ev.saddr) == saddr and \
       ev.filter == ff:
        return True
    return False


class IgmpSG(object):
    def __init__(self, gaddr, saddrs):
        self.gaddr = gaddr
        self.gaddr_p = socket.inet_pton(socket.AF_INET, gaddr)
        self.saddrs = saddrs
        self.saddrs_p = []
        self.saddrs_encoded = []
        for s in saddrs:
            ss = socket.inet_pton(socket.AF_INET, s)
            self.saddrs_p.append(ss)
            self.saddrs_encoded.append(ss)


class IgmpRecord(object):
    def __init__(self, sg, type):
        self.sg = sg
        self.type = type


class VppHostState(VppObject):
    def __init__(self, test, filter, sw_if_index, sg):
        self._test = test
        self.sw_if_index = sw_if_index
        self.filter = filter
        self.sg = sg

    def add_vpp_config(self):
        self._test.vapi.igmp_listen(
            self.filter, self.sw_if_index,
            self.sg.saddrs_encoded, self.sg.gaddr_p)

    def remove_vpp_config(self):
        self._test.vapi.igmp_listen(
            self.filter,
            self.sw_if_index,
            [],
            self.sg.gaddr_p)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "%s:%d" % (self.sg, self.sw_if_index)

    def query_vpp_config(self):
        return self._test.vapi.igmp_dump()
