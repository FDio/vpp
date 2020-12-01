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
from unittest import mock

from vpp_papi import vpp_papi, vpp_transport_shmem


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


class TestVppTypes(unittest.TestCase):

    def test_enum_from_json(self):
        json_api = """\
{
    "enums": [

        [
            "address_family",
            [
                "ADDRESS_IP4",
                0
            ],
            [
                "ADDRESS_IP6",
                1
            ],
            {
                "enumtype": "u8"
            }
        ],
        [
            "if_type",
            [
                "IF_API_TYPE_HARDWARE",
                0
            ],
            [
                "IF_API_TYPE_SUB",
                1
            ],
            [
                "IF_API_TYPE_P2P",
                2
            ],
            [
                "IF_API_TYPE_PIPE",
                3
            ],
            {
                "enumtype": "u32"
            }
        ]
    ]
}
"""
        processor = vpp_papi.VPPApiJSONFiles()

        # add the types to vpp_serializer
        processor.process_json_str(json_api)

        vpp_transport_shmem.VppTransport = mock.MagicMock()
        ac = vpp_papi.VPPApiClient(apifiles=[], testmode=True)
        type_name = "vl_api_if_type_t"
        t = ac.get_type(type_name)
        self.assertTrue(str(t).startswith("VPPEnumType"))
        self.assertEqual(t.name, type_name)

