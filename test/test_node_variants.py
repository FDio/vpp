#!/usr/bin/env python3
import re
import unittest
import platform
from framework import VppTestCase


def checkX86():
    return platform.machine() in ["x86_64", "AMD64"]


def skipVariant(variant):
    with open("/proc/cpuinfo") as f:
        cpuinfo = f.read()

    exp = re.compile(
        r'(?:flags\s+:)(?:\s\w+)+(?:\s(' + variant + r'))(?:\s\w+)+')
    match = exp.search(cpuinfo, re.DOTALL | re.MULTILINE)

    return checkX86() and match is not None


class TestNodeVariant(VppTestCase):
    """ Test Node Variants """

    @classmethod
    def setUpConstants(cls, variant):
        super(TestNodeVariant, cls).setUpConstants()
        # find the position of node_variants in the cmdline args.

        if checkX86():
            node_variants = cls.vpp_cmdline.index("node-variants { ") + 1
            cls.vpp_cmdline[node_variants] = ("defaults { default 100 } "
                                              "ip4-rewrite { " +
                                              variant + " 150 } ")

    @classmethod
    def setUpClass(cls):
        super(TestNodeVariant, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestNodeVariant, cls).tearDownClass()

    def setUp(self):
        super(TestNodeVariant, self).setUp()

    def tearDown(self):
        super(TestNodeVariant, self).tearDown()

    def getActiveVariant(self, node):
        node_desc = self.vapi.cli("show node " + node)
        self.logger.info(node_desc)

        with open("/tmp/test.txt", "w") as f:
            f.write(node_desc)

        match = re.search(r'\s+(\S+)\s+(\d+)\s+(:?yes)',
                          node_desc, re.DOTALL | re.MULTILINE)

        return match.groups(0)

    def checkVariant(self, variant):
        """ Test node variants defaults """

        variant_info = self.getActiveVariant("ip4-lookup")
        self.assertEqual(variant_info[0], "default")
        self.assertEqual(int(variant_info[1]), 100)

        variant_info = self.getActiveVariant("ip4-rewrite")
        self.assertEqual(variant_info[0], variant)
        self.assertEqual(int(variant_info[1]), 150)


class TestAVX512Variant(TestNodeVariant):
    """ Test avx512 Node Variants """

    VARIANT = "avx512"
    LINUX_VARIANT = VARIANT + "f"

    @classmethod
    def setUpConstants(cls):
        super(TestAVX512Variant, cls).setUpConstants(cls.VARIANT)

    @classmethod
    def setUpClass(cls):
        super(TestAVX512Variant, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestAVX512Variant, cls).tearDownClass()

    @unittest.skipUnless(skipVariant(LINUX_VARIANT),
                         VARIANT + " not a supported variant, skip.")
    def test_avx512(self):
        self.checkVariant(self.VARIANT)


class TestAVX2Variant(TestNodeVariant):
    """ Test avx2 Node Variants """

    VARIANT = "avx2"

    @classmethod
    def setUpConstants(cls):
        super(TestAVX2Variant, cls).setUpConstants(cls.VARIANT)

    @classmethod
    def setUpClass(cls):
        super(TestAVX2Variant, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestAVX2Variant, cls).tearDownClass()

    @unittest.skipUnless(skipVariant(VARIANT),
                         VARIANT + " not a supported variant, skip.")
    def test_avx2(self):
        self.checkVariant(self.VARIANT)
