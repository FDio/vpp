from asfframework import VppTestRunner
from framework import VppTestCase
import unittest
from config import config


@unittest.skipIf("snort" in config.excluded_plugins, "Exclude snort plugin test")
class TestSnort(VppTestCase):
    """Simple Snort plugin test"""

    @classmethod
    def setUpClass(cls):
        super(TestSnort, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4().resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestSnort, cls).tearDownClass()

    def test_snort_cli(self):
        # TODO: add a test with packets
        # { cli command : part of the expected reply }
        commands_replies = {
            "snort create-instance name snortTest queue-size 16 on-disconnect drop": "",
            "snort create-instance name snortTest2 queue-size 16 on-disconnect pass": "",
            "snort attach instance snortTest interface pg0 output": "",
            "snort attach instance snortTest2 interface pg1 input": "",
            "show snort instances": "snortTest",
            "show snort interfaces": "pg0",
            "show snort clients": "number of clients",
            "show snort mode": "input mode: interrupt",
            "snort mode polling": "",
            "snort mode interrupt": "",
            "snort detach interface pg0": "",
            "snort detach interface pg1": "",
            "snort delete instance snortTest": "",
        }

        for command, reply in commands_replies.items():
            actual_reply = self.vapi.cli(command)
            self.assertIn(reply, actual_reply)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
