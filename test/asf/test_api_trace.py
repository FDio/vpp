import unittest
from asfframework import VppAsfTestCase, VppTestRunner
import json
import shutil


class TestJsonApiTrace(VppAsfTestCase):
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

    def save_json_trace(self):
        fname = "test_api_trace-%d.json" % self.vpp.pid
        tmp_api_trace = "/tmp/%s" % fname
        fpath = "%s/%s" % (self.tempdir, fname)
        self.vapi.cli("api trace save-json {}".format(fname))
        shutil.move(tmp_api_trace, fpath)
        with open(fpath, encoding="utf-8") as f:
            return json.load(f)

    def test_json_api_trace_save(self):
        self.vapi.show_version()

        trace = self.save_json_trace()
        found = False
        for o in trace:
            if o["_msgname"] == "show_version":
                found = True
                break
        self.assertTrue(found)
        self.assertEqual(o["_msgname"], "show_version")

    def test_json_api_trace_variable_length_message(self):
        """A message with a variable length array is traced and saved whole"""
        n_segments = 100
        # The request is traced when it is received, the reply is of no
        # interest here, so call the API without the return value check. The
        # stored copy has to hold all the segments: a copy cut short keeps the
        # element count and the dump walks off the end of it.
        self.vapi.papi.sr_mpls_policy_add(
            bsid=1,
            weight=1,
            is_spray=False,
            n_segments=n_segments,
            segments=list(range(100, 100 + n_segments)),
        )

        trace = self.save_json_trace()
        o = [e for e in trace if e["_msgname"] == "sr_mpls_policy_add"][0]
        self.assertEqual(o["n_segments"], n_segments)
        self.assertEqual(o["segments"], list(range(100, 100 + n_segments)))

        # dumping walks the same arrays as saving
        dump = self.vapi.cli("api trace dump-json")
        self.assertIn("sr_mpls_policy_add", dump)
        self.assertIn("segments", dump)

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
