#!/usr/bin/env python
## @file test_l2xc.py
#  Module to provide L2 cross-connect test case.
#
#  The module provides a set of tools for L2 cross-connect tests.

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import unittest
import random
from framework import VppTestCase, VppTestRunner
from scapy.layers.l2 import Ether, Raw
from scapy.layers.inet import IP, UDP


## Subclass of the VppTestCase class.
#
#  This subclass is a class for L2 cross-connect test cases. It provides methods
#  to create interfaces, configuring L2 cross-connects, creating and verifying
#  packet streams.
class TestL2xc(VppTestCase):
    """ L2XC Test Case """

    # Test variables
    interf_nr = 4           # Number of interfaces
    hosts_nr = 10           # Number of hosts
    pkts_per_burst = 257    # Number of packets per burst

    ## Class method to start the test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  There is used try..except statement to ensure that the tear down of
    #  the class will be executed even if any exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestL2xc, cls).setUpClass()

        try:
            ## Create interfaces
            cls.interfaces = range(TestL2xc.interf_nr)
            cls.create_interfaces(cls.interfaces)

            ## Create bi-directional cross-connects between pg0 and pg1
            cls.api("sw_interface_set_l2_xconnect rx pg0 tx pg1 enable")
            cls.api("sw_interface_set_l2_xconnect rx pg1 tx pg0 enable")

            ## Create bi-directional cross-connects between pg2 and pg3
            cls.api("sw_interface_set_l2_xconnect rx pg2 tx pg3 enable")
            cls.api("sw_interface_set_l2_xconnect rx pg3 tx pg2 enable")

            cls.cli(0, "show l2patch")

            ## Create host MAC and IPv4 lists
            cls.create_host_lists(TestL2xc.hosts_nr)

        except Exception as e:
            cls.tearDownClass()
            raise e

    ## Method to define tear down VPP actions of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        self.cli(2, "show int")
        self.cli(2, "show trace")
        self.cli(2, "show hardware")
        self.cli(2, "show l2patch")
        self.cli(2, "show error")
        self.cli(2, "show run")

    ## Class method to create required number of MAC and IPv4 addresses.
    #  Create required number of host MAC addresses and distribute them among
    #  interfaces. Create host IPv4 address for every host MAC address too.
    #  @param cls The class pointer.
    #  @param count Integer variable to store the number of MAC addresses to be
    #  created.
    @classmethod
    def create_host_lists(cls, count):
        for i in cls.interfaces:
            cls.MY_MACS[i] = []
            cls.MY_IP4S[i] = []
            for j in range(0, count):
                cls.MY_MACS[i].append("00:00:00:ff:%02x:%02x" % (i, j))
                cls.MY_IP4S[i].append("172.17.1%02x.%u" % (i, j))
        ## @var MY_MACS
        #  Dictionary variable to store list of MAC addresses per interface.
        ## @var MY_IP4S
        #  Dictionary variable to store list of IPv4 addresses per interface.

    ## Method to create packet stream for the packet generator interface.
    #  Create input packet stream for the given packet generator interface with
    #  packets of different length targeted for all other created packet
    #  generator interfaces.
    #  @param self The object pointer.
    #  @param pg_id Integer variable to store the index of the interface to
    #  create the input packet stream.
    #  @return pkts List variable to store created input stream of packets.
    def create_stream(self, pg_id):
        # TODO: use variables to create lists based on interface number
        pg_targets = [None] * 4
        pg_targets[0] = [1]
        pg_targets[1] = [0]
        pg_targets[2] = [3]
        pg_targets[3] = [2]
        pkts = []
        for i in range(0, TestL2xc.pkts_per_burst):
            target_pg_id = pg_targets[pg_id][0]
            target_host_id = random.randrange(len(self.MY_MACS[target_pg_id]))
            source_host_id = random.randrange(len(self.MY_MACS[pg_id]))
            pkt_info = self.create_packet_info(pg_id, target_pg_id)
            payload = self.info_to_payload(pkt_info)
            p = (Ether(dst=self.MY_MACS[target_pg_id][target_host_id],
                       src=self.MY_MACS[pg_id][source_host_id]) /
                 IP(src=self.MY_IP4S[pg_id][source_host_id],
                    dst=self.MY_IP4S[target_pg_id][target_host_id]) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            pkt_info.data = p.copy()
            packet_sizes = [64, 512, 1518, 9018]
            size = packet_sizes[(i / 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts
        ## @var pg_targets
        #  List variable to store list of indexes of target packet generator
        #  interfaces for every source packet generator interface.
        ## @var target_pg_id
        #  Integer variable to store the index of the random target packet
        #  generator interfaces.
        ## @var target_host_id
        #  Integer variable to store the index of the randomly chosen
        #  destination host MAC/IPv4 address.
        ## @var source_host_id
        #  Integer variable to store the index of the randomly chosen source
        #  host MAC/IPv4 address.
        ## @var pkt_info
        #  Object variable to store the information about the generated packet.
        ## @var payload
        #  String variable to store the payload of the packet to be generated.
        ## @var p
        #  Object variable to store the generated packet.
        ## @var packet_sizes
        #  List variable to store required packet sizes.
        ## @var size
        #  List variable to store required packet sizes.

    ## Method to verify packet stream received on the packet generator interface.
    #  Verify packet-by-packet the output stream captured on a given packet
    #  generator (pg) interface using following packet payload data - order of
    #  packet in the stream, index of the source and destination pg interface,
    #  src and dst host IPv4 addresses and src port and dst port values of UDP
    #  layer.
    #  @param self The object pointer.
    #  @param o Integer variable to store the index of the interface to
    #  verify the output packet stream.
    #  @param capture List variable to store the captured output packet stream.
    def verify_capture(self, o, capture):
        last_info = {}
        for i in self.interfaces:
            last_info[i] = None
        for packet in capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                payload_info = self.payload_to_info(str(packet[Raw]))
                self.assertEqual(payload_info.dst, o)
                self.log("Got packet on port %u: src=%u (id=%u)"
                         % (o, payload_info.src, payload_info.index), 2)
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, payload_info.dst,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(payload_info.index, next_info.index)
                # Check standard fields
                self.assertEqual(ip.src, next_info.data[IP].src)
                self.assertEqual(ip.dst, next_info.data[IP].dst)
                self.assertEqual(udp.sport, next_info.data[UDP].sport)
                self.assertEqual(udp.dport, next_info.data[UDP].dport)
            except:
                self.log("Unexpected or invalid packet:")
                packet.show()
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i, o, last_info[i])
            self.assertTrue(remaining_packet is None,
                            "Port %u: Packet expected from source %u didn't"
                            " arrive" % (o, i))
        ## @var last_info
        #  Dictionary variable to store verified packets per packet generator
        #  interface.
        ## @var ip
        #  Object variable to store the IP layer of the packet.
        ## @var udp
        #  Object variable to store the UDP layer of the packet.
        ## @var payload_info
        #  Object variable to store required information about the packet.
        ## @var next_info
        #  Object variable to store information about next packet.
        ## @var remaining_packet
        #  Object variable to store information about remaining packet.

    ## Method defining L2 cross-connect test case.
    #  Contains steps of the test case.
    #  @param self The object pointer.
    def test_l2xc(self):
        """ L2XC test

        Test scenario:
        1.config
            2 pairs of 2 interfaces, l2xconnected

        2.sending l2 eth packets between 4 interfaces
            64B, 512B, 1518B, 9018B (ether_size)
            burst of packets per interface
        """

        ## Create incoming packet streams for packet-generator interfaces
        for i in self.interfaces:
            pkts = self.create_stream(i)
            self.pg_add_stream(i, pkts)

        ## Enable packet capturing and start packet sending
        self.pg_enable_capture(self.interfaces)
        self.pg_start()

        ## Verify outgoing packet streams per packet-generator interface
        for i in self.interfaces:
            out = self.pg_get_capture(i)
            self.log("Verifying capture %u" % i)
            self.verify_capture(i, out)
        ## @var pkts
        #  List variable to store created input stream of packets for the packet
        #  generator interface.
        ## @var out
        #  List variable to store captured output stream of packets for
        #  the packet generator interface.


if __name__ == '__main__':
    unittest.main(testRunner = VppTestRunner)
