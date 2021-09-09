# Copyright (c) 2021 Vinci Consulting Corp. All Rights Reserved.
#
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import ctypes
import multiprocessing as mp
import sys
import unittest
from unittest import mock

from vpp_papi import vpp_papi
from vpp_papi import vpp_transport_shmem


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

    def test_enumflagmixed_from_json(self):
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
        ]
        ],
    "enumflags": [

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
        print(ac)
        type_name = "vl_api_if_type_t"
        t = ac.get_type(type_name)
        print(t)
        self.assertTrue(str(t).startswith("VPPEnumType"))
        self.assertEqual(t.name, type_name)

    def test_enumflag_from_json(self):
        json_api = """\
{
    "enumflags": [

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


class TestVppPapiLogging(unittest.TestCase):
    def test_logger(self):
        class Transport:
            connected = True

        class Vpp:
            transport = Transport()

            def disconnect(self):
                pass

        client = Vpp
        with self.assertLogs('vpp_papi', level='DEBUG') as cm:
            vpp_papi.vpp_atexit(client)
        self.assertEqual(cm.output, ['DEBUG:vpp_papi:Cleaning up VPP on exit'])

        with self.assertRaises(AssertionError):
            with self.assertLogs('vpp_papi.serializer', level='DEBUG') as cm:
                vpp_papi.vpp_atexit(client)
        self.assertEqual(cm.output, [])
