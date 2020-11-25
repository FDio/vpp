
from vpp_object import VppObject
from vpp_papi import VppEnum
from vpp_feature import VppFeature
import socket
import os


class Igmp(VppFeature):
    """Igmp feature."""

    @classmethod
    def init_feature_class(cls, vapi):
        super(Igmp, cls).init_feature_class(vapi)
        cls.mode_router = 0
        cls.mode_host = 1
        cls.filter_include = VppEnum.vl_api_filter_mode_t.INCLUDE
        cls.filter_exclude = VppEnum.vl_api_filter_mode_t.EXCLUDE

    @classmethod
    def clear_interface(cls, sw_if_index):
        """ Clear igmp state (S, G)s from the interface.

        :param sw_if_index: interface index
        """
        vapi = cls.get_vapi()
        vapi.igmp_clear_interface(sw_if_index=sw_if_index)

    @classmethod
    def dump(cls, sw_if_index=None):
        """ Dump igmp.

        :param sw_if_index: filter on interface
        """
        vapi = cls.get_vapi()
        if sw_if_index:
            return vapi.igmp_dump(sw_if_index=sw_if_index)
        return vapi.igmp_dump()

    @classmethod
    def enable_on_interface(cls, sw_if_index, mode=1):
        """ Enable IGMP on a given interface.

        :param sw_if_index: interface index
        :param mode: Host (1) / Router (0)
        """
        vapi = cls.get_vapi()
        return vapi.igmp_enable_disable(enable=True, mode=mode,
                                        sw_if_index=sw_if_index)

    @classmethod
    def disable_on_interface(cls, sw_if_index, mode=1):
        """ Disable IGMP on a given interface.

        :param sw_if_index: interface index
        :param mode: Host (1) / Router (0)
        """
        vapi = cls.get_vapi()
        return vapi.igmp_enable_disable(enable=False, mode=mode,
                                        sw_if_index=sw_if_index)


class IgmpEvent:

    @staticmethod
    def subscribe():
        """Subscribe to receive igmp events."""
        vapi = Igmp.get_vapi()
        vapi.want_igmp_events(enable=True, pid=os.getpid())

    @staticmethod
    def unsubscribe():
        """Unsubscribe from receiving igmp events."""
        vapi = Igmp.get_vapi()
        vapi.want_igmp_events(enable=False, pid=os.getpid())

    @staticmethod
    def read(timeout=0):
        """Read igmp event from queue.

        :param timeout: wait for event timeout
        """
        vapi = Igmp.get_vapi()
        event = vapi.wait_for_event(timeout, "igmp_event")
        return IgmpEvent(event.sw_if_index, event.gaddr, event.saddr,
                         event.filter)

    def __init__(self, sw_if_index, gaddr, saddr, filter):
        """Igmp event object mapping.

        :param sw_if_index: interface index
        :param gaddr: group address
        :param saddr: source address
        :param filter: igmp filter (Igmp.include/Igmp.exclude)
        """
        self._sw_if_index = sw_if_index
        self._gaddr = gaddr
        self._saddr = saddr
        self._filter = filter

    @property
    def sw_if_index(self):
        return self._sw_if_index

    @property
    def gaddr(self):
        return self._gaddr

    @property
    def saddr(self):
        return self._saddr

    @property
    def filter(self):
        return self._filter

    @property
    def state(self):
        """Returns igmp state as dictionary."""
        return {"sw_if_index": self.sw_if_index, "saddr": self.saddr,
                "gaddr": self.gaddr}

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            if other.sw_if_index == self.sw_if_index and \
               other.gaddr == self.gaddr and other.saddr == self.saddr and \
               other.filter == self.filter:
                return True
            return False
        return NotImplemented

    def __str__(self):
        return f"{self.sw_if_index}, {self.saddr}, {self.gaddr}, {self.filter}"


class VppIgmpProxyDevice(VppObject):
    def __init__(self, test, vrf_id, sw_if_index):
        """Igmp proxy device.

        :param test: test case
        :param vrf_id: vrf id
        :param sw_if_index: interface index - can be a list of indexes in
                            which case proxy device is created on the first
                            element
        """
        self._test = test
        self._vrf_id = vrf_id
        self._interfaces = sw_if_index if type(sw_if_index) is list \
            else [sw_if_index]
        self._config_present = False

    def add_vpp_config(self):
        self._test.vapi.igmp_proxy_device_add_del(
            vrf_id=self._vrf_id, sw_if_index=self._interfaces[0], add=True)
        for sw_if_index in self._interfaces[1:]:
            self._test.vapi.igmp_proxy_device_add_del_interface(
                vrf_id=self._vrf_id, sw_if_index=sw_if_index, add=True)

    def remove_vpp_config(self):
        for sw_if_index in self._interfaces[1:]:
            self._test.vapi.igmp_proxy_device_add_del_interface(
                vrf_id=self._vrf_id, sw_if_index=sw_if_index, add=False)
        self._test.vapi.igmp_proxy_device_add_del(
            vrf_id=self._vrf_id, sw_if_index=self._interfaces[0], add=False)

    def add_interface(self, sw_if_index):
        """Add interface to proxy device.
           Device must be present on VPP.

        :param sw_if_index: interface index
        """
        self._interfaces.append(sw_if_index)
        self._test.vapi.igmp_proxy_device_add_del_interface(
            vrf_id=self._vrf_id, sw_if_index=self._interfaces[-1], add=True)

    def remove_interface(self, sw_if_index):
        """Remove interface from proxy device.
           Device must be present on VPP.

        :param sw_if_index: interface index
        """
        idx = self._interfaces.index(sw_if_index)
        if not idx:
            raise ValueError(f"Interface {sw_if_index} not found")
        elif idx == 0:
            raise ValueError(f"Cannot remove proxy device")
        self._test.vapi.igmp_proxy_device_add_del_interface(
            vrf_id=self._vrf_id, sw_if_index=self._interfaces[idx], add=False)
        del self._interfaces[idx]

    def query_vpp_config(self):
        return NotImplemented

    def object_id(self):
        return "igmp-proxy-device-%d" % self._interfaces[0]


class IgmpSG():
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


class IgmpRecord():
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
        group = {"filter": self.filter, "sw_if_index": self.sw_if_index,
                 "n_srcs": len(self.sg.saddrs),
                 "saddrs": self.sg.saddrs_encoded, "gaddr": self.sg.gaddr_p}
        self._test.vapi.igmp_listen(group=group)

    def remove_vpp_config(self):
        group = {"filter": self.filter, "sw_if_index": self.sw_if_index,
                 "n_srcs": 0, "saddrs": [], "gaddr": self.sg.gaddr_p}
        self._test.vapi.igmp_listen(group=group)

    def object_id(self):
        return "%s:%d" % (self.sg, self.sw_if_index)

    def query_vpp_config(self):
        return self._test.vapi.igmp_dump()
