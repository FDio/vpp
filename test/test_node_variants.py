#!/usr/bin/env python3
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
            node_variants = cls.vpp_cmdline.index("node { ") + 1
            cls.vpp_cmdline[node_variants] = ("default { variant default } "
                                              "ip4-rewrite { variant " +
                                              variant + " } ")

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

        match = re.search(r'\s+(\S+)\s+(\d+)\s+(:?yes)',
                          node_desc, re.DOTALL | re.MULTILINE)

        return match.groups(0)

    def checkVariant(self, variant):
        """ Test node variants defaults """

        variant_info = self.getActiveVariant("ip4-lookup")
        self.assertEqual(variant_info[0], "default")

        variant_info = self.getActiveVariant("ip4-rewrite")
        self.assertEqual(variant_info[0], variant)


class TestICLVariant(TestNodeVariant):
    """ Test icl Node Variants """

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

    @unittest.skipUnless(skipVariant(LINUX_VARIANT),
                         VARIANT + " not a supported variant, skip.")
    def test_icl(self):
        self.checkVariant(self.VARIANT)


class TestSKXVariant(TestNodeVariant):
    """ Test skx Node Variants """

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

    @unittest.skipUnless(skipVariant(LINUX_VARIANT),
                         VARIANT + " not a supported variant, skip.")
    def test_skx(self):
        self.checkVariant(self.VARIANT)


class TestHSWVariant(TestNodeVariant):
    """ Test avx2 Node Variants """

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

    @unittest.skipUnless(skipVariant(LINUX_VARIANT),
                         VARIANT + " not a supported variant, skip.")
    def test_hsw(self):
        self.checkVariant(self.VARIANT)
