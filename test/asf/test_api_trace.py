import os
import unittest
from asfframework import VppTestCase, VppTestRunner
from vpp_papi import VppEnum
import json


class TestJsonApiTrace(VppTestCase):
    """JSON API trace related tests"""

    @classmethod
    def setUpClass(cls):
        super(TestJsonApiTrace, cls).setUpClass()

    def setUp(self):
        self.vapi.cli("api trace free")
        self.vapi.cli("api trace on")
        self.vapi.cli("api trace tx on")

    @classmethod
    def tearDownClass(cls):
        super(TestJsonApiTrace, cls).tearDownClass()

    def test_json_api_trace_save(self):
        self.vapi.show_version()

        fname = "test_api_trace-%d.json" % self.vpp.pid
        tmp_api_trace = "/tmp/%s" % fname
        fpath = "%s/%s" % (self.tempdir, fname)
        self.vapi.cli("api trace save-json {}".format(fname))
        shuil.move(tmp_api_trace, fpath)
        with open(fpath, encoding="utf-8") as f:
            s = f.read()
        trace = json.loads(s)
        found = False
        for o in trace:
            if o["_msgname"] == "show_version":
                found = True
                break
        self.assertTrue(found)
        self.assertEquals(o["_msgname"], "show_version")

    def test_json_api_trace_replay(self):
        fname = "/tmp/create_loop.json"
        req = """
[
{
        "_msgname": "create_loopback",
        "_crc": "42bb5d22",
        "mac_address": "00:00:00:00:00:00"
}]
"""
        with open(fname, "w") as f:
            f.write(req)
        self.vapi.cli("api trace replay-json {}".format(fname))
        r = self.vapi.sw_interface_dump(name_filter="loop", name_filter_valid=True)
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].interface_name, "loop0")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
