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

import framework


class TestPapi(framework.VppTestCase):
    """TestPapi"""

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
            "api_fn_args='api_fn_args')>")
