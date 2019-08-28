# -*- coding: utf-8 eval: (yapf-mode 1) -*-
# SPDX-License-Identifier: Apache-2.0
#
# November 3 2019, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2019, LabN Consulting, L.L.C.
# All Rights Reserved.
#
import unittest
from asfframework import VppTestRunner

# from basic import TestBasicIPTFS4
# TestBasicIPTFS4.dpdk_crypto_dev = "vdev crypto_aesni_gcm vdev crypto_null"

# from dontfrag import TestBasicDontFragmentIPTFS4, TestBasicDontFragmentChainedIPTFS4
# TestBasicDontFragmentIPTFS4.dpdk_crypto_dev = "vdev crypto_aesni_gcm vdev crypto_null"
# TestBasicDontFragmentChainedIPTFS4.dpdk_crypto_dev = "vdev crypto_aesni_gcm vdev crypto_null"

# Not enabled yet
# from frag import TestFragIPTFS4
# from imix import TestIMixIPTFS
# from reorder import *

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
