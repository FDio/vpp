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

import aenum

import framework

kwargs = {"is_add": 1,
          "route": {"paths": [{"nh": {"obj_id": 4294967295,
                                      "via_label": 1048576,
                                      "address": {"ip4": "0a0a0a02"}},
                               "rpf_id": 4294967295,
                               "weight": 1,
                               "proto": 0,
                               "n_labels": 0,
                               "label_stack": [0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0],
                               "sw_if_index": 1,
                               "flags": 0,
                               "preference": 1,
                               "table_id": 0,
                               "type": 0}],
                    "prefix": {"address_length": 32,
                               "address": {"un": {"ip4": "c0a80001"},
                                           "af": 0}},
                    "n_paths": 1,
                    "table_id": 0},
          "is_multipath": 0}


class TestPapi(framework.VppTestCase):
    """TestPapi"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_version(self):
        ver = self.vapi.vppapiclient.__version__
        self.assertTrue(ver)
        maj, min, patch = ver.split('.')
        self.assertTrue(maj.isnumeric(),
                        "'maj' is not numeric: %r" % maj)
        self.assertTrue(min.isnumeric(),
                        "'min' is not numeric: %r" % min)
        self.assertTrue(patch.isnumeric(),
                        "'patch' is not numeric: %r" % patch)

    def test_VPPApiClientNotImplementedError(self):
        with self.assertRaises(
                self.vapi.vppapiclient.VPPApiClientNotImplementedError) as ctx:
            raise self.vapi.vpp.VPPApiClientNotImplementedError

        with self.assertRaises(
                self.vapi.vppapiclient.VPPApiClientNotImplementedError) as ctx:
            raise self.vapi.vpp.VPPApiClientNotImplementedError(
                "Scheduled for next release.")

        # uncomment to see the actual exception
        # raise self.vapi.vpp.VPPApiClientNotImplementedError(
        #    "Scheduled for next release.")

    def test_no_such_api(self):
        with self.assertRaises(
                self.vapi.vppapiclient.VPPApiClientNoSuchApiError) as ctx:
            rv = self.vapi.no_such_api()

    def test_exception_repr(self):
        with self.assertRaises(
                self.vapi.vppapiclient.VPPApiClientValueError) as ctx:
            raise self.vapi.vppapiclient.VPPApiClientValueError(
                api_fn_name='api_fn_name', api_fn_args='api_fn_args')
        self.assertEqual(
            repr(ctx.exception),
            "<VPPApiClientValueError(api_fn_name='api_fn_name', "
            "api_fn_args='api_fn_args'); extra=api_fn_name='api_fn_name', "
            "api_fn_args='api_fn_args'>")

    def test_get_type(self):
        rv = self.vapi.vppapiclient.get_type('foo')
        self.assertIsNone(rv, 'invalid type should return None.')

        rv = self.vapi.vppapiclient.get_type('vl_api_prefix_t')
        self.assertEqual(rv.name, 'vl_api_prefix_t')

        rv = self.vapi.vppapiclient.get_type('vl_api_address_family_t')
        self.assertEqual((rv.name, rv.enumtype),
                         ('vl_api_address_family_t', 'u32'))

        rv = self.vapi.vppapiclient.get_enum_type('vl_api_address_family_t')
        self.assertEqual(rv.__class__, aenum.EnumMeta)

    def test_typedef_validation(self):
        rv = self.vapi.ip_route_add_del(**kwargs)
