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
            cls.create_pg_interfaces(range(4))
            for i in cls.pg_interfaces:
                i.config_ip4().resolve_arp()
                i.admin_down()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
        super(TestSnort, cls).tearDownClass()

    def test_snort_cli(self):
        # TODO: add a test with packets
        # { cli command : part of the expected reply }
        commands_replies = {
            "snort create-instance name snortTest queue-size 16 on-disconnect drop": "",
            "snort create-instance name snortTest2 queue-size 16 on-disconnect pass": "",
            "snort attach instance snortTest interface pg0 output": "",
            "snort attach instance snortTest2 interface pg1 input": "",
            "snort attach instance snortTest instance snortTest2 interface pg3 inout": "",
            "show snort instances": "snortTest",
            "show snort interfaces": "pg0",
            "show snort clients": "number of clients",
            "snort detach instance snortTest interface pg0": "",
            "snort detach instance snortTest2 interface pg1": "",
            "snort detach instance snortTest instance snortTest2 interface pg3": "",
            "snort delete instance snortTest": "",
            "snort delete instance snortTest2": "",
        }

        for command, reply in commands_replies.items():
            actual_reply = self.vapi.cli(command)
            self.assertIn(reply, actual_reply)


@unittest.skipIf("snort" in config.excluded_plugins, "Exclude snort plugin test")
class TestSnortVapi(VppTestCase):
    """Snort plugin test [VAPI]"""

    @classmethod
    def setUpClass(cls):
        super(TestSnortVapi, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()
                i.admin_down()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
        super(TestSnortVapi, cls).tearDownClass()

    def test_snort_01_modes_set_interrupt(self):
        """Set mode to interrupt"""
        with self.vapi.assert_negative_api_retval():
            reply = self.vapi.snort_input_mode_set(input_mode=1)
            self.assertEqual(reply.retval, -126)
        with self.vapi.assert_negative_api_retval():
            reply = self.vapi.snort_input_mode_get()
            self.assertEqual(reply.retval, -126)

    def test_snort_02_modes_set_polling(self):
        """Set mode to polling"""
        with self.vapi.assert_negative_api_retval():
            reply = self.vapi.snort_input_mode_set(input_mode=0)
            self.assertEqual(reply.retval, -126)
        with self.vapi.assert_negative_api_retval():
            reply = self.vapi.snort_input_mode_get()
            self.assertEqual(reply.retval, -126)

    def test_snort_03_create(self):
        """Create two snort instances"""
        reply = self.vapi.snort_instance_create(
            queue_size=8, drop_on_disconnect=0, name="snortTest0"
        )
        self.assertEqual(reply.instance_index, 0)
        reply = self.vapi.snort_instance_create(
            queue_size=32, drop_on_disconnect=1, name="snortTest1"
        )
        self.assertEqual(reply.instance_index, 1)
        reply = self.vapi.cli("show snort instances")
        self.assertIn("snortTest0", reply)
        self.assertIn("snortTest1", reply)
        self.vapi.snort_instance_delete(instance_index=1)
        self.vapi.snort_instance_delete(instance_index=0)

    def test_snort_04_attach_if(self):
        """Interfaces can be attached"""
        self.vapi.snort_instance_create(
            queue_size=8, drop_on_disconnect=0, name="snortTest0"
        )
        self.vapi.snort_instance_create(
            queue_size=32, drop_on_disconnect=1, name="snortTest1"
        )
        self.vapi.snort_interface_attach(instance_index=0, sw_if_index=1, snort_dir=1)
        self.vapi.snort_interface_attach(instance_index=0, sw_if_index=2, snort_dir=2)
        # verify attaching with an invalid direction is rejected
        try:
            reply = self.vapi.snort_interface_attach(
                instance_index=1, sw_if_index=2, snort_dir=4
            )
        except:
            pass
        else:
            self.assertNotEqual(reply.retval, 0)
        self.vapi.snort_interface_attach(instance_index=1, sw_if_index=2, snort_dir=3)
        reply = self.vapi.cli("show snort interfaces")
        self.assertIn("input instances:", reply)
        self.assertIn("pg0:	snortTest0", reply)
        self.assertIn("pg1:	snortTest1", reply)
        self.assertIn("output instances:", reply)
        self.assertIn("pg1:	snortTest1", reply)

        # verify attaching a previously attached interface is rejected
        try:
            reply = self.vapi.snort_interface_attach(
                instance_index=1, sw_if_index=2, snort_dir=2
            )
        except:
            pass
        else:
            self.assertNotEqual(reply.retval, 0)

        # verify attaching an invalid sw_if_index is rejected
        try:
            reply = self.vapi.snort_interface_attach(
                instance_index=1, sw_if_index=3, snort_dir=2
            )
        except:
            pass
        else:
            self.assertNotEqual(reply.retval, 0)
        reply = self.vapi.cli("show snort interfaces")
        self.assertIn("snortTest1", reply)
        self.vapi.snort_instance_delete(instance_index=1)
        self.vapi.snort_instance_delete(instance_index=0)

    def test_snort_05_delete_instance(self):
        """Instances can be deleted"""
        reply = self.vapi.snort_instance_create(
            queue_size=8, drop_on_disconnect=0, name="snortTest0"
        )
        self.assertEqual(reply.instance_index, 0)
        reply = self.vapi.snort_instance_delete(instance_index=0)
        self.assertEqual(reply.retval, 0)
        reply = self.vapi.cli("show snort interfaces")
        self.assertNotIn("snortTest0", reply)

    def test_snort_06_detach_if(self):
        """Interfaces can be detached"""
        reply = self.vapi.snort_instance_create(
            queue_size=8, drop_on_disconnect=0, name="snortTest0"
        )
        self.assertEqual(reply.instance_index, 0)
        reply = self.vapi.snort_instance_create(
            queue_size=128, drop_on_disconnect=1, name="snortTest1"
        )
        self.assertEqual(reply.instance_index, 1)
        reply = self.vapi.snort_interface_attach(
            instance_index=0, sw_if_index=1, snort_dir=1
        )
        reply = self.vapi.snort_interface_attach(
            instance_index=1, sw_if_index=1, snort_dir=2
        )
        reply = self.vapi.snort_interface_attach(
            instance_index=1, sw_if_index=2, snort_dir=3
        )
        # verify detaching an invalid sw_if_index is rejected
        try:
            reply = self.vapi.snort_interface_detach(sw_if_index=3)
        except:
            pass
        else:
            self.assertNotEqual(reply.retval, 0)
        reply = self.vapi.snort_interface_detach(sw_if_index=1)
        self.assertEqual(reply.retval, 0)
        reply = self.vapi.snort_interface_detach(sw_if_index=2)
        self.assertEqual(reply.retval, 0)
        self.assertNotIn("pg0", reply)
        self.assertNotIn("pg1", reply)
        self.vapi.snort_instance_delete(instance_index=1)
        self.vapi.snort_instance_delete(instance_index=0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
