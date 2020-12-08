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
import socket
import struct
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
        with self.assertLogs("vpp_papi", level="DEBUG") as cm:
            vpp_papi.vpp_atexit(client)
        self.assertEqual(cm.output, ["DEBUG:vpp_papi:Cleaning up VPP on exit"])

        with self.assertRaises(AssertionError):
            with self.assertLogs("vpp_papi.serializer", level="DEBUG") as cm:
                vpp_papi.vpp_atexit(client)
        self.assertEqual(cm.output, [])


class TestVppPapiCall(unittest.TestCase):
    def test_call(self):
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
    "messages": [
        [
            "control_ping",
            [
                "u16",
                "_vl_msg_id"
            ],
            [
                "u32",
                "client_index"
            ],
            [
                "u32",
                "context"
            ],
            {
                "crc": "0x51077d14"
            }
        ],
        [
            "control_ping_reply",
            [
                "u16",
                "_vl_msg_id"
            ],
            [
                "u32",
                "context"
            ],
            [
                "i32",
                "retval"
            ],
            [
                "u32",
                "client_index"
            ],
            [
                "u32",
                "vpe_pid"
            ],
            {
                "crc": "0xf6b0b8ca"
            }
        ],
        [
            "map_domains_get",
            [
                "u16",
                "_vl_msg_id"
            ],
            [
                "u32",
                "client_index"
            ],
            [
                "u32",
                "context"
            ],
            [
                "u32",
                "cursor"
            ],
            {
                "crc": "0xf75ba505"
            }
        ],
        [
            "map_domains_get_reply",
            [
                "u16",
                "_vl_msg_id"
            ],
            [
                "u32",
                "context"
            ],
            [
                "i32",
                "retval"
            ],
            [
                "u32",
                "cursor"
            ],
            {
                "crc": "0x53b48f5d"
            }
        ],
        [
            "cli_inband",
            [
                "u16",
                "_vl_msg_id"
            ],
            [
                "u32",
                "client_index"
            ],
            [
                "u32",
                "context"
            ],
            [
                "string",
                "cmd",
                0
            ],
            {
                "crc": "0xf8377302"
            }
        ],
        [
            "cli_inband_reply",
            [
                "u16",
                "_vl_msg_id"
            ],
            [
                "u32",
                "context"
            ],
            [
                "i32",
                "retval"
            ],
            [
                "string",
                "reply",
                0
            ],
            {
                "crc": "0x05879051"
            }
        ]
    ],
    "services": {
        "control_ping": {
            "reply": "control_ping_reply"
        },
        "cli_inband": {
            "reply": "cli_inband_reply"
        },
        "map_domains_get": {
            "reply": "map_domains_get_reply",
            "stream": true,
            "stream_msg": "map_domain_details"
        }
    }
}
"""
        processor = vpp_papi.VPPApiJSONFiles()

        # add the types to vpp_serializer
        messages, services = processor.process_json_str(json_api)

        # intentionally not using mock to illustrate the dependencies
        class Vapi:
            def vac_mem_init(self):
                pass

            def vac_connect(name, pfx, msg_handler, rx_qlen):
                # return success
                return 0

            def vac_disconnect():
                return 0

            def vac_set_error_handler(self):
                pass

            def vac_msg_table_max_index():
                return 10

            def vac_get_msg_index(name):
                # transport is returned in bytes
                idx = {
                    b"control_ping_51077d14": 1,
                    b"control_ping_reply_f6b0b8ca": 2,
                    b"map_domains_get_f75ba505": 3,
                    b"map_domains_get_reply_53b48f5d": 4,
                    b"cli_inband_f8377302": 5,
                    b"cli_inband_reply_05879051": 6,
                }
                return idx[name]

            def vac_rx_suspend():
                pass

            def vac_rx_resume():
                pass

            def vac_read(mem, size, timeout):
                return 0

            def vac_write(buf, len):
                return 0

            def vac_free(mem):
                pass

        def read_map_domains_get_mock(self, timeout=None):
            # msgid, context retval cursor
            return struct.pack(">HIiI", 4, 1, 8, 16)

        def read_cli_inband_reply_mock(self, timeout=None):
            # msgid, context retval cursor
            return struct.pack(">HIiI4s", 6, 2, 0, 4, b"Kane")

        vpp_transport_shmem.vpp_api = Vapi
        vpp_transport_shmem.VppTransport.read = read_map_domains_get_mock

        ac = vpp_papi.VPPApiClient(apifiles=[], testmode=True)
        # manually process the messages because we're using a json string snippet
        ac.messages.update(messages)
        ac.services.update(services)
        ac.connect("foo")

        # test a stream message
        fn, fn_list = ac.api.map_domains_get.__call__()
        self.assertEqual(fn.__class__.__name__, "map_domains_get_reply")
        self.assertEqual(fn._0, 4)
        self.assertEqual(fn.retval, 8)

        # test a <foo>/<foo>_reply message
        messages, services = processor.process_json_str(json_api)
        ac = vpp_papi.VPPApiClient(apifiles=[], testmode=True)
        # manually process the messages because we're using a json string snippet
        ac.messages.update(messages)
        ac.services.update(services)
        ac.connect("foo")
        vpp_transport_shmem.VppTransport.read = read_cli_inband_reply_mock
        fn = ac.api.cli_inband.__call__(cmd="Foo")
        self.assertEqual(fn._0, 6)
        self.assertEqual(fn.retval, 0)
        self.assertEqual(fn.reply, "Kane")
