#!/usr/bin/env python3
import re
import unittest
import platform
from asfframework import VppAsfTestCase


def checkX86():
    return platform.machine() in ["x86_64", "AMD64"]


def skipVariant(variant):
    with open("/proc/cpuinfo") as f:
        cpuinfo = f.read()

    exp = re.compile(r"(?:flags\s+:)(?:\s\w+)+(?:\s(" + variant + r"))(?:\s\w+)+")
    match = exp.search(cpuinfo, re.DOTALL | re.MULTILINE)

    return checkX86() and match is not None


class TestNodeVariant(VppAsfTestCase):
    """Test Node Variants"""

    @classmethod
    def setUpConstants(cls, variant):
        super(TestNodeVariant, cls).setUpConstants()
        # find the position of node_variants in the cmdline args.

        if checkX86():
            node_variants = cls.vpp_cmdline.index("node { ") + 1
            cls.vpp_cmdline[node_variants] = (
                "default { variant default } "
                "ip4-rewrite { variant " + variant + " } "
            )

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

        match = re.search(
            r"\s+(\S+)\s+(\d+)\s+(:?yes)", node_desc, re.DOTALL | re.MULTILINE
        )

        return match.groups(0)

    def checkVariant(self, variant):
        """Test node variants defaults"""

        variant_info = self.getActiveVariant("ip4-lookup")
        self.assertEqual(variant_info[0], "default")

        variant_info = self.getActiveVariant("ip4-rewrite")
        self.assertEqual(variant_info[0], variant)


class TestICLVariant(TestNodeVariant):
    """Test icl Node Variants"""

    VARIANT = "icl"
    LINUX_VARIANT = "avx512_bitalg"

    @classmethod
    def setUpConstants(cls):
        super(TestICLVariant, cls).setUpConstants(cls.VARIANT)

    @classmethod
    def setUpClass(cls):
        super(TestICLVariant, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestICLVariant, cls).tearDownClass()

    @unittest.skipUnless(
        skipVariant(LINUX_VARIANT), VARIANT + " not a supported variant, skip."
    )
    def test_icl(self):
        self.checkVariant(self.VARIANT)


class TestSKXVariant(TestNodeVariant):
    """Test skx Node Variants"""

    VARIANT = "skx"
    LINUX_VARIANT = "avx512f"

    @classmethod
    def setUpConstants(cls):
        super(TestSKXVariant, cls).setUpConstants(cls.VARIANT)

    @classmethod
    def setUpClass(cls):
        super(TestSKXVariant, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSKXVariant, cls).tearDownClass()

    @unittest.skipUnless(
        skipVariant(LINUX_VARIANT), VARIANT + " not a supported variant, skip."
    )
    def test_skx(self):
        self.checkVariant(self.VARIANT)


class TestHSWVariant(TestNodeVariant):
    """Test avx2 Node Variants"""

    VARIANT = "hsw"
    LINUX_VARIANT = "avx2"

    @classmethod
    def setUpConstants(cls):
        super(TestHSWVariant, cls).setUpConstants(cls.VARIANT)

    @classmethod
    def setUpClass(cls):
        super(TestHSWVariant, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestHSWVariant, cls).tearDownClass()

    @unittest.skipUnless(
        skipVariant(LINUX_VARIANT), VARIANT + " not a supported variant, skip."
    )
    def test_hsw(self):
        self.checkVariant(self.VARIANT)
