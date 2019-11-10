#  Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import ctypes
import multiprocessing as mp
import unittest

from vpp_papi import vpp_papi


class TestVppPapiVPPApiClient(unittest.TestCase):

    def test_getcontext(self):
        vpp_papi.VPPApiClient.apidir = '.'
        c = vpp_papi.VPPApiClient(testmode=True, use_socket=True)

        # reset initialization at module load time.
        c.get_context.context = mp.Value(ctypes.c_uint, 0)
        for _ in range(10):
            c.get_context()
        self.assertEqual(11, c.get_context())


class TestVppPapiVPPApiClientMp(unittest.TestCase):
    # Test under multiple processes to simulate running forked under
    # run_tests.py (eg. make test TEST_JOBS=10)

    def test_get_context_mp(self):
        vpp_papi.VPPApiClient.apidir = '.'
        c = vpp_papi.VPPApiClient(testmode=True, use_socket=True)

        # reset initialization at module load time.
        c.get_context.context = mp.Value(ctypes.c_uint, 0)
        procs = [mp.Process(target=c.get_context, args=()) for i in range(10)]

        for p in procs:
            p.start()
        for p in procs:
            p.join()

        # AssertionError: 11 != 1
        self.assertEqual(11, c.get_context())
