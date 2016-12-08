from socket import AF_INET, AF_INET6
from scapy.all import *
from scapy.packet import *
from scapy.fields import *
from framework import *
from vpp_object import *
from util import NumericConstant


class BFDDiagCode(NumericConstant):
    """ BFD Diagnostic Code """
    no_diagnostic = 0
    control_detection_time_expired = 1
    echo_function_failed = 2
    neighbor_signaled_session_down = 3
    forwarding_plane_reset = 4
    path_down = 5
    concatenated_path_down = 6
    administratively_down = 7
    reverse_concatenated_path_down = 8

    desc_dict = {
        no_diagnostic: "No diagnostic",
        control_detection_time_expired: "Control Detection Time Expired",
        echo_function_failed: "Echo Function Failed",
        neighbor_signaled_session_down: "Neighbor Signaled Session Down",
        forwarding_plane_reset: "Forwarding Plane Reset",
        path_down: "Path Down",
        concatenated_path_down: "Concatenated Path Down",
        administratively_down: "Administratively Down",
        reverse_concatenated_path_down: "Reverse Concatenated Path Down",
    }

    def __init__(self, value):
        NumericConstant.__init__(self, value)


class BFDState(NumericConstant):
    """ BFD State """
    admin_down = 0
    down = 1
    init = 2
    up = 3

    desc_dict = {
        admin_down: "AdminDown",
        down: "Down",
        init: "Init",
        up: "Up",
    }

    def __init__(self, value):
        NumericConstant.__init__(self, value)


class BFD(Packet):

    udp_dport = 3784  #: BFD destination port per RFC 5881
    udp_sport_min = 49152  #: BFD source port min value per RFC 5881
    udp_sport_max = 65535  #: BFD source port max value per RFC 5881

    name = "BFD"

    fields_desc = [
        BitField("version", 1, 3),
        BitEnumField("diag", 0, 5, BFDDiagCode.desc_dict),
        BitEnumField("state", 0, 2, BFDState.desc_dict),
        FlagsField("flags", 0, 6, ['P', 'F', 'C', 'A', 'D', 'M']),
        XByteField("detect_mult", 0),
        XByteField("length", 24),
        BitField("my_discriminator", 0, 32),
        BitField("your_discriminator", 0, 32),
        BitField("desired_min_tx_interval", 0, 32),
        BitField("required_min_rx_interval", 0, 32),
        BitField("required_min_echo_rx_interval", 0, 32)]

    def mysummary(self):
        return self.sprintf("BFD(my_disc=%BFD.my_discriminator%,"
                            "your_disc=%BFD.your_discriminator%)")

# glue the BFD packet class to scapy parser
bind_layers(UDP, BFD, dport=BFD.udp_dport)


class VppBFDUDPSession(VppObject):
    """ Represents BFD UDP session in VPP """

    @property
    def test(self):
        """ Test which created this session """
        return self._test

    @property
    def interface(self):
        """ Interface on which this session lives """
        return self._interface

    @property
    def af(self):
        """ Address family - AF_INET or AF_INET6 """
        return self._af

    @property
    def bs_index(self):
        """ BFD session index from VPP """
        if self._bs_index is not None:
            return self._bs_index
        raise NotConfiguredException("not configured")

    @property
    def local_addr(self):
        """ BFD session local address (VPP address) """
        if self._local_addr is None:
            return self._interface.local_ip4
        return self._local_addr

    @property
    def local_addr_n(self):
        """ BFD session local address (VPP address) - raw, suitable for API """
        if self._local_addr is None:
            return self._interface.local_ip4n
        return self._local_addr_n

    @property
    def peer_addr(self):
        """ BFD session peer address """
        return self._peer_addr

    @property
    def peer_addr_n(self):
        """ BFD session peer address - raw, suitable for API """
        return self._peer_addr_n

    @property
    def state(self):
        """ BFD session state """
        result = self.test.vapi.bfd_udp_session_dump()
        session = None
        for s in result:
            if s.sw_if_index == self.interface.sw_if_index:
                if self.af == AF_INET \
                        and s.is_ipv6 == 0 \
                        and self.interface.local_ip4n == s.local_addr[:4] \
                        and self.interface.remote_ip4n == s.peer_addr[:4]:
                    session = s
                    break
        if session is None:
            raise Exception(
                "Could not find BFD session in VPP response: %s" % repr(result))
        return session.state

    @property
    def desired_min_tx(self):
        return self._desired_min_tx

    @property
    def required_min_rx(self):
        return self._required_min_rx

    @property
    def detect_mult(self):
        return self._detect_mult

    def __init__(self, test, interface, peer_addr, local_addr=None, af=AF_INET,
                 desired_min_tx=100000, required_min_rx=100000, detect_mult=3):
        self._test = test
        self._interface = interface
        self._af = af
        self._local_addr = local_addr
        self._peer_addr = peer_addr
        self._peer_addr_n = socket.inet_pton(af, peer_addr)
        self._bs_index = None
        self._desired_min_tx = desired_min_tx
        self._required_min_rx = required_min_rx
        self._detect_mult = detect_mult

    def add_vpp_config(self):
        is_ipv6 = 1 if AF_INET6 == self.af else 0
        result = self.test.vapi.bfd_udp_add(
            self._interface.sw_if_index,
            self.desired_min_tx,
            self.required_min_rx,
            self.detect_mult,
            self.local_addr_n,
            self.peer_addr_n,
            is_ipv6=is_ipv6)
        self._bs_index = result.bs_index

    def query_vpp_config(self):
        result = self.test.vapi.bfd_udp_session_dump()
        session = None
        for s in result:
            if s.sw_if_index == self.interface.sw_if_index:
                if self.af == AF_INET \
                        and s.is_ipv6 == 0 \
                        and self.interface.local_ip4n == s.local_addr[:4] \
                        and self.interface.remote_ip4n == s.peer_addr[:4]:
                    session = s
                    break
        if session is None:
            return False
        return True

    def remove_vpp_config(self):
        if hasattr(self, '_bs_index'):
            is_ipv6 = 1 if AF_INET6 == self._af else 0
            self.test.vapi.bfd_udp_del(
                self._interface.sw_if_index,
                self.local_addr_n,
                self.peer_addr_n,
                is_ipv6=is_ipv6)

    def object_id(self):
        return "bfd-udp-%d" % self.bs_index

    def admin_up(self):
        self.test.vapi.bfd_session_set_flags(self.bs_index, 1)
