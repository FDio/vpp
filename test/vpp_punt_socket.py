from socket import socket, AF_UNIX, SOCK_DGRAM
from select import select
from time import time
from struct import unpack, calcsize
from util import ppc
from scapy.layers.l2 import Ether

client_uds_socket_name = "client-uds-socket"
vpp_uds_socket_name = "vpp-uds-socket"

VPP_PUNT_HEADER_FMT = '=Ii'
VPP_PUNT_HEADER_SIZE = calcsize(VPP_PUNT_HEADER_FMT)


class VppPuntAction:
    PUNT_L2 = 0
    PUNT_IP4_ROUTED = 1
    PUNT_IP6_ROUTED = 2


class VppUDSPuntSocket(object):
    def __init__(self, testcase, port, is_ip4=1, l4_protocol=0x11):
        client_path = '%s/%s-%s-%s' % (testcase.tempdir,
                                       client_uds_socket_name,
                                       "4" if is_ip4 else "6", port)
        testcase.vapi.punt_socket_register(
            port, client_path, is_ip4=is_ip4, l4_protocol=l4_protocol)
        self.testcase = testcase
        self.uds = socket(AF_UNIX, SOCK_DGRAM)
        self.uds.bind(client_path)
        self.uds.connect(testcase.punt_socket_path)

    def wait_for_packets(self, count, timeout=1):
        packets = []
        now = time()
        deadline = now + timeout
        while len(packets) < count and now < deadline:
            r, w, e = select([self.uds], [], [self.uds], deadline - now)
            if self.uds in r:
                x = self.uds.recv(1024 * 1024)
                sw_if_index, punt_action = unpack(
                    VPP_PUNT_HEADER_FMT, x[:VPP_PUNT_HEADER_SIZE])
                packets.append({'sw_if_index': sw_if_index,
                                'punt_action': punt_action,
                                'packet': x[VPP_PUNT_HEADER_SIZE:]})

            if self.uds in e:
                raise Exception("select() indicates error on UDS socket")
            now = time()

        if len(packets) != count:
            raise Exception("Unexpected packet count received, got %s packets,"
                            " expected %s packets" % (len(packets), count))
        self.testcase.logger.debug(
            "Got %s packets via punt socket" % len(packets))
        return packets

    def assert_nothing_captured(self, timeout=.25):
        packets = []
        now = time()
        deadline = now + timeout
        while now < deadline:
            r, w, e = select([self.uds], [], [self.uds], deadline - now)
            if self.uds in r:
                x = self.uds.recv(1024 * 1024)
                packets.append(Ether(x[VPP_PUNT_HEADER_SIZE:]))
            if self.uds in e:
                raise Exception("select() indicates error on UDS socket")
            now = time()

        if len(packets) > 0:
            self.testcase.logger.error(
                ppc("Unexpected packets captured:", packets))
            raise Exception("Unexpected packet count received, got %s packets,"
                            " expected no packets" % len(packets))
