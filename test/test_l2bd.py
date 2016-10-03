#!/usr/bin/env python
## @file test_l2bd.py
#  Module to provide L2 bridge domain test case.
#
#  The module provides a set of tools for L2 bridge domain tests.

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import unittest
import random

from framework import *
from scapy.all import *


## Subclass of the VppTestCase class.
#
#  This subclass is a class for L2 bridge domain test cases. It provides methods
#  to create interfaces, configure L2 bridge domain, create and verify packet
#  streams.
class TestL2bd(VppTestCase):
    """ L2BD Test Case """

    ## Test variables
    interf_nr = 3           # Number of interfaces
    bd_id = 1               # Bridge domain ID
    mac_entries = 100       # Number of MAC entries for bridge-domain to learn
    dot1q_sub_id = 100      # SubID of dot1q sub-interface
    dot1q_tag = 100         # VLAN tag for dot1q sub-interface
    dot1ad_sub_id = 200     # SubID of dot1ad sub-interface
    dot1ad_outer_tag = 200  # VLAN S-tag for dot1ad sub-interface
    dot1ad_inner_tag = 300  # VLAN C-tag for dot1ad sub-interface
    pkts_per_burst = 257    # Number of packets per burst

    ## Class method to start the test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestL2bd, cls).setUpClass()

        try:
            ## Create interfaces and sub-interfaces
            cls.create_interfaces_and_subinterfaces(TestL2bd.interf_nr)

            ## Create BD with MAC learning enabled and put interfaces and
            #  sub-interfaces to this BD
            cls.api("bridge_domain_add_del bd_id %u learn 1" % TestL2bd.bd_id)
            for i in cls.interfaces:
                if isinstance(cls.INT_DETAILS[i], cls.Subint):
                    interface = "pg%u.%u" % (i, cls.INT_DETAILS[i].sub_id)
                else:
                    interface = "pg%u" % i
                cls.api("sw_interface_set_l2_bridge %s bd_id %u"
                        % (interface, TestL2bd.bd_id))

            ## Make the BD learn a number of MAC entries specified by the test
            # variable <mac_entries>.
            cls.create_mac_entries(TestL2bd.mac_entries)
            cls.cli(0, "show l2fib")

        except Exception as e:
          super(TestL2bd, cls).tearDownClass()
          raise e

    ## Method to define tear down VPP actions of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        self.cli(2, "show int")
        self.cli(2, "show trace")
        self.cli(2, "show hardware")
        self.cli(2, "show l2fib verbose")
        self.cli(2, "show error")
        self.cli(2, "show run")
        self.cli(2, "show bridge-domain 1 detail")

    ## Class method to create VLAN sub-interface.
    #  Uses VPP API command to create VLAN sub-interface.
    #  @param cls The class pointer.
    #  @param pg_index Integer variable to store the index of the packet
    #  generator interface to create VLAN sub-interface on.
    #  @param vlan_id Integer variable to store required VLAN tag value.
    @classmethod
    def create_vlan_subif(cls, pg_index, vlan_id):
        cls.api("create_vlan_subif pg%u vlan %u" % (pg_index, vlan_id))

    ## Class method to create dot1ad sub-interface.
    #  Use VPP API command to create dot1ad sub-interface.
    #  @param cls The class pointer.
    #  @param pg_index Integer variable to store the index of the packet
    #  generator interface to create dot1ad sub-interface on.
    #  @param outer_vlan_id Integer variable to store required outer VLAN tag
    #  value (S-TAG).
    #  @param inner_vlan_id Integer variable to store required inner VLAN tag
    #  value (C-TAG).
    @classmethod
    def create_dot1ad_subif(cls, pg_index, sub_id, outer_vlan_id,
                            inner_vlan_id):
        cls.api("create_subif pg%u sub_id %u outer_vlan_id %u inner_vlan_id"
                " %u dot1ad" % (pg_index, sub_id, outer_vlan_id, inner_vlan_id))

    ## Base class for interface.
    #  To define object representation of the interface.
    class Interface(object):
        pass

    ## Sub-class of the interface class.
    #  To define object representation of the HW interface.
    class HardInt(Interface):
        pass

    ## Sub-class of the interface class.
    #  To define object representation of the SW interface.
    class SoftInt(Interface):
        pass

    ## Sub-class of the SW interface class.
    #  To represent the general sub-interface.
    class Subint(SoftInt):
        ## The constructor.
        #  @param sub_id Integer variable to store sub-interface ID.
        def __init__(self, sub_id):
            self.sub_id = sub_id

    ## Sub-class of the SW interface class.
    #  To represent dot1q sub-interface.
    class Dot1QSubint(Subint):
        ## The constructor.
        #  @param sub_id Integer variable to store sub-interface ID.
        #  @param vlan Integer variable (optional) to store VLAN tag value. Set
        #  to sub_id value when VLAN tag value not provided.
        def __init__(self, sub_id, vlan=None):
            if vlan is None:
                vlan = sub_id
            super(TestL2bd.Dot1QSubint, self).__init__(sub_id)
            self.vlan = vlan

    ## Sub-class of the SW interface class.
    #  To represent dot1ad sub-interface.
    class Dot1ADSubint(Subint):
        ## The constructor.
        #  @param sub_id Integer variable to store sub-interface ID.
        #  @param outer_vlan Integer variable to store outer VLAN tag value.
        #  @param inner_vlan Integer variable to store inner VLAN tag value.
        def __init__(self, sub_id, outer_vlan, inner_vlan):
            super(TestL2bd.Dot1ADSubint, self).__init__(sub_id)
            self.outer_vlan = outer_vlan
            self.inner_vlan = inner_vlan

    ## Class method to create interfaces and sub-interfaces.
    #  Current implementation: create three interfaces, then create Dot1Q
    #  sub-interfaces for the second and the third interface with VLAN tags
    #  equal to their sub-interface IDs. Set sub-interfaces status to admin-up.
    #  @param cls The class pointer.
    #  @param int_nr Integer variable to store the number of interfaces to be
    #  created.
    # TODO: Parametrize required numbers of dot1q and dot1ad to be created.
    @classmethod
    def create_interfaces_and_subinterfaces(cls, int_nr):
        ## A class list variable to store interface indexes.
        cls.interfaces = range(int_nr)

        # Create interfaces
        cls.create_interfaces(cls.interfaces)

        # Make vpp_api_test see interfaces created using debug CLI (in function
        # create_interfaces)
        cls.api("sw_interface_dump")

        ## A class dictionary variable to store data about interfaces.
        #  First create an empty dictionary then store interface data there.
        cls.INT_DETAILS = dict()

        # 1st interface is untagged - no sub-interface required
        cls.INT_DETAILS[0] = cls.HardInt()

        # 2nd interface is dot1q tagged
        cls.INT_DETAILS[1] = cls.Dot1QSubint(TestL2bd.dot1q_sub_id,
                                             TestL2bd.dot1q_tag)
        cls.create_vlan_subif(1, cls.INT_DETAILS[1].vlan)

        # 3rd interface is dot1ad tagged
        # FIXME: Wrong packet format/wrong layer on output of interface 2
        #self.INT_DETAILS[2] = self.Dot1ADSubint(TestL2bd.dot1ad_sub_id, TestL2bd.dot1ad_outer_tag, TestL2bd.dot1ad_inner_tag)
        #self.create_dot1ad_subif(2, self.INT_DETAILS[2].sub_id, self.INT_DETAILS[2].outer_vlan, self.INT_DETAILS[2].inner_vlan)

        # Use dot1q for now.
        cls.INT_DETAILS[2] = cls.Dot1QSubint(TestL2bd.dot1ad_sub_id,
                                             TestL2bd.dot1ad_outer_tag)
        cls.create_vlan_subif(2, cls.INT_DETAILS[2].vlan)

        for i in cls.interfaces:
            if isinstance(cls.INT_DETAILS[i], cls.Subint):
                cls.api("sw_interface_set_flags pg%u.%u admin-up"
                        % (i, cls.INT_DETAILS[i].sub_id))
        ## @var interfaces
        #  List variable to store interface indexes.
        ## @var INT_DETAILS
        #  Dictionary variable to store data about interfaces.

    ## Class method for bridge-domain to learn defined number of MAC addresses.
    #  Create required number of host MAC addresses and distribute them among
    #  interfaces. Create host IPv4 address for every host MAC address. Create
    #  L2 MAC packet stream with host MAC addresses per interface to let
    #  the bridge domain learn these MAC addresses.
    #  @param cls The class pointer.
    #  @param count Integer variable to store the number of MAC addresses to be
    #  created.
    @classmethod
    def create_mac_entries(cls, count):
        n_int = len(cls.interfaces)
        macs_per_if = count / n_int
        for i in cls.interfaces:
            start_nr = macs_per_if*i
            end_nr = count if i == (n_int - 1) else macs_per_if*(i+1)
            cls.MY_MACS[i] = []
            cls.MY_IP4S[i] = []
            packets = []
            for j in range(start_nr, end_nr):
                cls.MY_MACS[i].append("00:00:00:ff:%02x:%02x" % (i, j))
                cls.MY_IP4S[i].append("172.17.1%02x.%u" % (i, j))
                packet = (Ether(dst="ff:ff:ff:ff:ff:ff", src=cls.MY_MACS[i]))
                packets.append(packet)
            cls.pg_add_stream(i, packets)
        # Based on the verbosity level set in the system print the log.
        cls.log("Sending broadcast eth frames for MAC learning", 1)
        cls.pg_start()
        # Packet stream capturing is not started as we don't need to read
        #  the output.
        ## @var n_int
        #  Integer variable to store the number of interfaces.
        ## @var macs_per_if
        #  Integer variable to store the number of MAC addresses per interface.
        ## @var start_nr
        #  Integer variable to store the starting number of the range used to
        #  generate MAC addresses for the interface.
        ## @var end_nr
        #  Integer variable to store the ending number of the range used to
        #  generate MAC addresses for the interface.
        ## @var MY_MACS
        #  Dictionary variable to store list of MAC addresses per interface.
        ## @var MY_IP4S
        #  Dictionary variable to store list of IPv4 addresses per interface.

    ## Class method to add dot1q or dot1ad layer to the packet.
    #  Based on sub-interface data of the defined interface add dot1q or dot1ad
    #  Ethernet header layer to the packet.
    #  @param cls The class pointer.
    #  @param i Integer variable to store the index of the interface.
    #  @param packet Object variable to store the packet where to add dot1q or
    #  dot1ad layer.
    # TODO: Move this class method to utils.py.
    @classmethod
    def add_dot1_layers(cls, i, packet):
        assert(type(packet) is Ether)
        payload = packet.payload
        if isinstance(cls.INT_DETAILS[i], cls.Dot1QSubint):
            packet.remove_payload()
            packet.add_payload(Dot1Q(vlan=cls.INT_DETAILS[i].vlan) / payload)
        elif isinstance(cls.INT_DETAILS[i], cls.Dot1ADSubint):
            packet.remove_payload()
            packet.add_payload(Dot1Q(vlan=cls.INT_DETAILS[i].outer_vlan,
                                     type=0x8100) /
                               Dot1Q(vlan=cls.INT_DETAILS[i].inner_vlan) /
                               payload)
            packet.type = 0x88A8
        ## @var payload
        #  Object variable to store payload of the packet.
        ## @var INT_DETAILS
        #  Dictionary variable to store data about interfaces.
        ## @var Dot1QSubint
        #  Class variable representing dot1q sub-interfaces.
        ## @var Dot1ADSubint
        #  Class variable representing dot1ad sub-interfaces.

    ## Method to remove dot1q or dot1ad layer from the packet.
    #  Based on sub-interface data of the defined interface remove dot1q or
    #  dot1ad layer from the packet.
    #  @param cls The class pointer.
    #  @param i Integer variable to store the index of the interface.
    #  @param packet Object variable to store the packet where to remove dot1q
    #  or dot1ad layer.
    def remove_dot1_layers(self, i, packet):
        self.assertEqual(type(packet), Ether)
        payload = packet.payload
        if isinstance(self.INT_DETAILS[i], self.Dot1QSubint):
            self.assertEqual(type(payload), Dot1Q)
            self.assertEqual(payload.vlan, self.INT_DETAILS[i].vlan)
            payload = payload.payload
        elif isinstance(self.INT_DETAILS[i], self.Dot1ADSubint):  # TODO: change 88A8 type
            self.assertEqual(type(payload), Dot1Q)
            self.assertEqual(payload.vlan, self.INT_DETAILS[i].outer_vlan)
            payload = payload.payload
            self.assertEqual(type(payload), Dot1Q)
            self.assertEqual(payload.vlan, self.INT_DETAILS[i].inner_vlan)
            payload = payload.payload
        packet.remove_payload()
        packet.add_payload(payload)
        ## @var payload
        #  Object variable to store payload of the packet.
        ## @var INT_DETAILS
        #  Dictionary variable to store data about interfaces.
        ## @var Dot1QSubint
        #  Class variable representing dot1q sub-interfaces.
        ## @var Dot1ADSubint
        #  Class variable representing dot1ad sub-interfaces.

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
        pg_targets = [None] * 3
        pg_targets[0] = [1, 2]
        pg_targets[1] = [0, 2]
        pg_targets[2] = [0, 1]
        pkts = []
        for i in range(0, TestL2bd.pkts_per_burst):
            target_pg_id = pg_targets[pg_id][i % 2]
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
            self.add_dot1_layers(pg_id, p)
            if not isinstance(self.INT_DETAILS[pg_id], self.Subint):
                packet_sizes = [64, 512, 1518, 9018]
            else:
                packet_sizes = [64, 512, 1518+4, 9018+4]
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
                # Check VLAN tags and Ethernet header
                # TODO: Rework to check VLAN tag(s) and do not remove them
                self.remove_dot1_layers(payload_info.src, packet)
                self.assertTrue(Dot1Q not in packet)
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

    ## Method defining VPP L2 bridge domain test case.
    #  Contains execution steps of the test case.
    #  @param self The object pointer.
    def test_l2bd(self):
        """ L2BD MAC learning test

        1.config
            MAC learning enabled
            learn 100 MAC enries
            3 interfaces: untagged, dot1q, dot1ad (dot1q used instead of dot1ad
             in the first version)

        2.sending l2 eth pkts between 3 interface
            64B, 512B, 1518B, 9200B (ether_size)
            burst of 257 pkts per interface
        """

        ## Create incoming packet streams for packet-generator interfaces
        for i in self.interfaces:
            pkts = self.create_stream(i)
            self.pg_add_stream(i, pkts)

        ## Enable packet capture and start packet sending
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
