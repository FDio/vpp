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
import unittest


class TestPgApi(framework.VppTestCase):
    """TestPgApi"""

    def test_pg_create_interface(self):
        rv = self.vapi.pg_create_interface()
        print(rv)

    def test_pg_capture(self):
        rv = self.vapi.pg_capture()
        print(rv)

    def test_pg_capture_dump(self):

        rv = self.vapi.pg_capture_dump(sw_if_index=0xffffffff)
        print(rv)
        sw_if_index = self.vapi.pg_create_interface().sw_if_index
        rv = self.vapi.pg_capture(interface_id=0,
                                  is_enabled=1,
                                  pcap_file_name='foo.pcap')
        rv = self.vapi.pg_capture(interface_id=0,
                                  is_enabled=0,)

        rv = self.vapi.pg_capture_dump(sw_if_index=sw_if_index)
        print(rv)
