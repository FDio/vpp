#!/usr/bin/env python

from abc import abstractmethod, ABCMeta

from scapy.layers.l2 import Ether, Raw
from scapy.layers.inet import IP, UDP


class BridgeDomain(object):
    """ Bridge domain abstraction """
    __metaclass__ = ABCMeta

    @property
    def frame_pg0_to_pg1(self):
        """ Ethernet frame sent from pg0 and expected to arrive at pg1 """
        return (Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') /
                IP(src='1.2.3.4', dst='4.3.2.1') /
                UDP(sport=10000, dport=20000) /
                Raw('\xa5' * 100))

    @property
    def frame_pg1_to_pg0(self):
        """ Ethernet frame sent from pg1 and expected to arrive at pg0 """
        return (Ether(src='00:00:00:00:00:02', dst='00:00:00:00:00:01') /
                IP(src='4.3.2.1', dst='1.2.3.4') /
                UDP(sport=20000, dport=10000) /
                Raw('\xa5' * 100))

    @abstractmethod
    def encapsulate(self, pkt):
        """ Encapsulate packet """
        pass

    @abstractmethod
    def decapsulate(self, pkt):
        """ Decapsulate packet """
        pass

    @abstractmethod
    def check_encapsulation(self, pkt):
        """ Verify the encapsulation """
        pass

    def test_decap(self):
        """ Decapsulation test
        Send encapsulated frames from pg0
        Verify receipt of decapsulated frames on pg1
        """

        encapsulated_pkt = self.encapsulate(self.frame_pg0_to_pg1)

        self.pg0.add_stream([encapsulated_pkt, ])

        self.pg1.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's the non-encapsulated frame
        out = self.pg1.get_capture(1)
        pkt = out[0]

        # TODO: add error messages
        self.assertEqual(pkt[Ether].src, self.frame_pg0_to_pg1[Ether].src)
        self.assertEqual(pkt[Ether].dst, self.frame_pg0_to_pg1[Ether].dst)
        self.assertEqual(pkt[IP].src, self.frame_pg0_to_pg1[IP].src)
        self.assertEqual(pkt[IP].dst, self.frame_pg0_to_pg1[IP].dst)
        self.assertEqual(pkt[UDP].sport, self.frame_pg0_to_pg1[UDP].sport)
        self.assertEqual(pkt[UDP].dport, self.frame_pg0_to_pg1[UDP].dport)
        self.assertEqual(pkt[Raw], self.frame_pg0_to_pg1[Raw])

    def test_encap(self):
        """ Encapsulation test
        Send frames from pg1
        Verify receipt of encapsulated frames on pg0
        """
        self.pg1.add_stream([self.frame_pg1_to_pg0])

        self.pg0.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's corectly encapsulated.
        out = self.pg0.get_capture(1)
        pkt = out[0]
        self.check_encapsulation(pkt)

        payload = self.decapsulate(pkt)
        # TODO: add error messages
        self.assertEqual(payload[Ether].src, self.frame_pg1_to_pg0[Ether].src)
        self.assertEqual(payload[Ether].dst, self.frame_pg1_to_pg0[Ether].dst)
        self.assertEqual(payload[IP].src, self.frame_pg1_to_pg0[IP].src)
        self.assertEqual(payload[IP].dst, self.frame_pg1_to_pg0[IP].dst)
        self.assertEqual(payload[UDP].sport, self.frame_pg1_to_pg0[UDP].sport)
        self.assertEqual(payload[UDP].dport, self.frame_pg1_to_pg0[UDP].dport)
        self.assertEqual(payload[Raw], self.frame_pg1_to_pg0[Raw])
