# -*- coding: utf-8 eval: (yapf-mode 1) -*-
# SPDX-License-Identifier: Apache-2.0
#
# July 12 2019, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2019, LabN Consulting, L.L.C.
# All Rights Reserved.
#
import unittest
from asfframework import VppTestRunner

from iptfs_d.iptfs_basic import TestBasicIPTFS4

# from dontfrag import TestBasicDontFragmentIPTFS4, TestBasicDontFragmentChainedIPTFS4

from iptfs_d.iptfs_frag import TestFragIPTFS4
from iptfs_d.iptfs_imix import TestIMixIPTFS
from iptfs_d.iptfs_nopad import TestVerifyNoPad4
from iptfs_d.iptfs_reorder import *

if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)

__author__ = "Christian Hopps"
__date__ = "July 12 2019"
__version__ = "1.0"
__docformat__ = "restructuredtext en"
