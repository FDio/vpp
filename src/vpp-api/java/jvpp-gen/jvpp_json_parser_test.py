#!/usr/bin/env python2
#
# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import logging
import sys
import unittest

from jvpp_json_parser import JsonParser, Dump, Request, Reply, Details


# Generating json file from api file:
# python ~/vpp/src/tools/vppapigen/vppapigen.py --input test.api --pluginpath ~/vpp/src/tools/vppapigen/
# --output test.api.json JSON
#

class JsonParserTest(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
        self.logger = logging.getLogger("JVPP PARSER TEST")

    def testParse(self):
        jsonparser = JsonParser(self.logger, ["test.api.json"], "core")
        m1 = Request("foo_request", "0x4199095a", [], "foo_request_reply")
        m2 = Reply("foo_request_reply", "0xe8d4e804", [])
        m3 = Dump("foo_dump", "0x8ac76db6", [], "foo_details")
        m4 = Details("foo_details", "0xe18f0c91", [])

        self.assertMessage(m1, jsonparser.messages)
        self.assertMessage(m2, jsonparser.messages)
        self.assertMessage(m3, jsonparser.messages)
        self.assertMessage(m4, jsonparser.messages)

    def assertMessage(self, msg, messages):
        self.assertIn(msg, messages, "%s was not found in [%s]" % (msg, " ".join([str(x) for x in messages])))

if __name__ == '__main__':
    unittest.main()
