# -*- coding: utf-8 eval: (yapf-mode 1) -*-
# SPDX-License-Identifier: Apache-2.0
#
# November 5 2019, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2019, LabN Consulting, L.L.C.
# All Rights Reserved.
#
import unittest
from config import config
import socket
from iptfs_d.template_iptfs import REWIN, TemplateIPTFS4
import scapy_handlers.iptfs as iptfs


class _TestReorderIPTFS4(TemplateIPTFS4):
    # It's important that we don't have a decrypt thread where packets can get
    # dropped do to handoff congestion
    num_workers = 2

    def _test_tun_drop_XtoYofN(self, x, y, n, exceptevery=0):
        self.vapi.cli("clear errors")

        # Generate encrypted IPTFS stream (count packets)
        count = n + 1
        p = self.params[socket.AF_INET]
        tunpkts = iptfs.gen_encrypt_pkts(p.scapy_tun_sa,
                                         self.tun_if,
                                         src=p.remote_tun_if_host,
                                         dst=self.pg1.remote_ip4,
                                         count=count)
        tunpkts = self.init_seq_num(p, tunpkts)
        count = len(tunpkts)
        seqnos = [seqno for seqno in range(1, count + 1)]

        addts = []
        addss = []
        if exceptevery:
            for i in range(x, y, exceptevery):
                if i == x:
                    continue
                addts.append(tunpkts[i])
                addss.append(seqnos[i])

        tunpkts = tunpkts[:x - 1] + addts + tunpkts[y:]
        seqnos = seqnos[:x - 1] + addss + seqnos[y:]

        self.vapi.cli("iptfs debug enable packet")
        self.verify_decap_44(p, tunpkts, seqnos=seqnos)
        self.vapi.cli("iptfs debug disable packet")

    def _test_tun_reverse_XofYxZ(self, x, y, z, clump=None):
        self.vapi.cli("clear errors")
        # Generate encrypted IPTFS stream (count packets)
        count = y * z + 1
        p = self.params[socket.AF_INET]
        tunpkts = iptfs.gen_encrypt_pkts(p.scapy_tun_sa,
                                         self.tun_if,
                                         src=p.remote_tun_if_host,
                                         dst=self.pg1.remote_ip4,
                                         count=count)
        tunpkts = self.init_seq_num(p, tunpkts)

        iseqnos = [seqno for seqno in range(1, count)]
        seqnos = []

        drop = 0
        if x > REWIN + 1:
            drop = x - (REWIN + 1)

        # reverse x elements every y elements.
        for i in range(0, count - 1, y):
            tunpkts[i:i + x] = reversed(tunpkts[i:i + x])
            seqnos.extend(iseqnos[i + drop:i + x])
        self.logger.debug("expected seqnos: %s", str(seqnos))

        self.verify_decap_44(p, tunpkts, seqnos=seqnos, clump=clump)


class TestReorderIPTFS4(_TestReorderIPTFS4):
    """ IPTFS Re-order tests"""
    def test_tun_reorder_pathalogical_first_2of2(self):
        self.vapi.cli("clear errors")
        # Generate encrypted IPTFS stream (count packets)
        count = 2
        p = self.params[socket.AF_INET]
        tunpkts = iptfs.gen_encrypt_pkts(p.scapy_tun_sa,
                                         self.tun_if,
                                         src=p.remote_tun_if_host,
                                         dst=self.pg1.remote_ip4,
                                         count=count)
        # To keep things easy, let's give it the first packet in order.
        tunpkts.reverse()
        # We expect the first packet to drop b/c we haven't established
        # a starting sequence number and the second packet is passed it
        # which establishes the starting point. This only happens when
        # the first packet is out-of-order.
        self.verify_decap_44(p, tunpkts, seqnos=[1])
        # XXX check drop count for 1 here.

    # def _test_tun_drop_1of5(self):
    #     # We don't timeout our reordering window b/c we expect more packets
    #     # always so this test won't work.

    def test_tun_reorder_2of3(self):
        self.vapi.cli("clear errors")
        # Generate encrypted IPTFS stream (count packets)
        count = 3
        p = self.params[socket.AF_INET]
        tunpkts = iptfs.gen_encrypt_pkts(p.scapy_tun_sa,
                                         self.tun_if,
                                         src=p.remote_tun_if_host,
                                         dst=self.pg1.remote_ip4,
                                         count=count)
        tunpkts = self.init_seq_num(p, tunpkts)
        tunpkts.reverse()
        self.verify_decap_44(p, tunpkts)

    def test_tun_reorder_4of5(self):
        self.vapi.cli("clear errors")
        # Generate encrypted IPTFS stream (count packets)
        count = 6
        p = self.params[socket.AF_INET]
        tunpkts = iptfs.gen_encrypt_pkts(p.scapy_tun_sa,
                                         self.tun_if,
                                         src=p.remote_tun_if_host,
                                         dst=self.pg1.remote_ip4,
                                         count=count)
        tunpkts = self.init_seq_num(p, tunpkts)
        tunpkts.reverse()
        self.verify_decap_44(p, tunpkts)

    def test_tun_reorder_6of7_drop1(self):
        self.vapi.cli("clear errors")
        # Generate encrypted IPTFS stream (count packets)
        count = 8
        p = self.params[socket.AF_INET]
        tunpkts = iptfs.gen_encrypt_pkts(p.scapy_tun_sa,
                                         self.tun_if,
                                         src=p.remote_tun_if_host,
                                         dst=self.pg1.remote_ip4,
                                         count=count)
        tunpkts = self.init_seq_num(p, tunpkts)
        count = len(tunpkts)
        tunpkts.reverse()

        # Since it's reversed we should see the second packet get dropped
        self.verify_decap_44(p, tunpkts, seqnos=[2, 3, 4, 5, 6, 7])

    def test_tun_reverse_5of5x30(self):
        self._test_tun_reverse_XofYxZ(5, 5, 30)

    def test_tun_reverse_5of5x30_clump1(self):
        self._test_tun_reverse_XofYxZ(5, 5, 30, 1)

    def test_tun_reverse_5of5x30_clump2(self):
        self._test_tun_reverse_XofYxZ(5, 5, 30, 2)

    def test_tun_reverse_5of5x30_clump3(self):
        self._test_tun_reverse_XofYxZ(5, 5, 30, 3)

    def test_tun_reverse_5of5x30_clump4(self):
        self._test_tun_reverse_XofYxZ(5, 5, 30, 4)

    def test_tun_reverse_5of5x30_clump5(self):
        self._test_tun_reverse_XofYxZ(5, 5, 30, 5)

    def test_tun_reverse_7of7(self):
        self._test_tun_reverse_XofYxZ(7, 7, 1, 1)

    def test_tun_reverse_7of7x30(self):
        self._test_tun_reverse_XofYxZ(7, 7, 30, 5)

    def test_tun_reverse_7of7x30_clump1(self):
        self._test_tun_reverse_XofYxZ(7, 7, 30, 5)

    def test_tun_reverse_7of7x30_clump2(self):
        self._test_tun_reverse_XofYxZ(7, 7, 30, 5)

    def test_tun_reverse_7of7x30_clump3(self):
        self._test_tun_reverse_XofYxZ(7, 7, 30, 5)

    def test_tun_reverse_7of7x30_clump4(self):
        self._test_tun_reverse_XofYxZ(7, 7, 30, 5)

    def test_tun_reverse_7of7x30_clump5(self):
        self._test_tun_reverse_XofYxZ(7, 7, 30, 5)


# Purpose of this function is to decorate these tests so that they are
# not executed unless caller asks for extended tests.
def make_attr(*args):
    return unittest.skipUnless(
        config.extended, "part of extended tests")(
            lambda s: s._test_tun_drop_XtoYofN(2, *args))

def add_function_to_class(cls, name, *args):
    #setattr(cls, name, lambda s: s._test_tun_drop_XtoYofN(2, *args))
    setattr(cls, name, make_attr(*args))


# Generate more tests.
for Z in range(0, 5):
    exec("""
class TestReorderIPTFS4_{} (_TestReorderIPTFS4):
    "IPTFS Re-order tests excepting every {}"
    pass
    """.format(Z, Z))
    for Y in range(2, 10):
        for N in range(Y + 6, 17):
            if Z == 0:
                name = "test_tun_drop_{}to{}of{}".format(2, Y, N)
            else:
                name = "test_tun_drop_{}to{}of{}_exceptevery_{}".format(2, Y, N, Z)
            add_function_to_class(eval("TestReorderIPTFS4_{}".format(Z)), name, Y, N, Z)
