from asfframework import VppTestRunner
from framework import VppTestCase
import unittest
from config import config
from scapy.layers.l2 import Ether
from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUPortID,
    LLDPDUTimeToLive,
    LLDPDUEndOfLLDPDU,
    LLDPDU,
)

from ipaddress import IPv4Address, IPv6Address


@unittest.skipIf("lldp" in config.excluded_plugins, "Exclude lldp plugin tests")
class TestLldpCli(VppTestCase):
    """LLDP plugin tests [CLI]"""

    @classmethod
    def setUpClass(cls):
        super(TestLldpCli, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestLldpCli, cls).tearDownClass()

    def create_frame(self, src_if):
        if src_if == self.pg0:
            chassis_id = "01:02:03:04:05:06"
            port_id = "07:08:09:0a:0b:0c"
        else:
            chassis_id = "11:12:13:14:15:16"
            port_id = "17:18:19:1a:1b:1c"

        lldp_frame = (
            Ether(src=src_if.remote_mac, dst="01:80:C2:00:00:03")
            / LLDPDU()
            / LLDPDUChassisID(subtype=4, id=chassis_id)
            / LLDPDUPortID(subtype=3, id=port_id)
            / LLDPDUTimeToLive(ttl=120)
            / LLDPDUEndOfLLDPDU()
        )

        return lldp_frame

    def test_lldp_cli(self):
        """Enable, send frames, show, disable, verify"""

        packets = self.create_frame(self.pg0)
        self.pg0.add_stream(packets)
        packets = self.create_frame(self.pg1)
        self.pg1.add_stream(packets)

        self.vapi.cli("set lldp system-name VPP tx-hold 4 tx-interval 10")
        # configure everything to increase coverage
        self.vapi.cli(
            f"set interface lldp pg0 port-desc vtf:pg0 mgmt-ip4"
            f" {self.pg0.local_ip4} mgmt-ip6 {self.pg0.local_ip6} mgmt-oid '1234'"
        )
        self.vapi.cli("set interface lldp pg1 port-desc vtf:pg1")

        self.pg_start()

        reply = self.vapi.cli("show lldp")
        expected = [
            "01:02:03:04:05:06",
            "07:08:09:0a:0b:0c",
            "11:12:13:14:15:16",
            "17:18:19:1a:1b:1c",
        ]
        for entry in expected:
            self.assertIn(entry, reply)

        # only checking for an output
        reply = self.vapi.cli("show lldp detail")
        self.assertIn("Local Interface name: pg0", reply)
        self.assertIn("Local Interface name: pg1", reply)

        # disable LLDP on an interface and verify
        self.vapi.cli("set interface lldp pg0 disable")
        reply = self.vapi.cli("show lldp")
        self.assertNotIn("pg0", reply)


@unittest.skipIf("lldp" in config.excluded_plugins, "Exclude lldp plugin tests")
class TestLldpVapi(VppTestCase):
    """LLDP plugin test [VAPI]"""

    @classmethod
    def setUpClass(cls):
        super(TestLldpVapi, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestLldpVapi, cls).tearDownClass()

    def test_lldp_vapi(self):
        """Enable, show, disable, verify"""
        self.vapi.lldp_config(tx_hold=4, tx_interval=1, system_name="VAPI")
        self.vapi.sw_interface_set_lldp(
            sw_if_index=1,
            mgmt_ip4=self.pg0.local_ip4,
            port_desc="vtf:pg0",
        )
        self.vapi.sw_interface_set_lldp(
            sw_if_index=2,
            mgmt_ip4=self.pg1.local_ip4,
            port_desc="vtf:pg1",
            mgmt_ip6=self.pg1.local_ip6,
            mgmt_oid=b"1",
        )

        # only check if LLDP gets enabled, functionality is tested in CLI class
        reply = self.vapi.cli("show lldp")
        self.assertIn("pg1", reply)

        self.vapi.sw_interface_set_lldp(sw_if_index=2, enable=False)
        reply = self.vapi.cli("show lldp")
        self.assertNotIn("pg1", reply)


@unittest.skipIf("lldp" in config.excluded_plugins, "Exclude lldp plugin tests")
class TestLldpDump(VppTestCase):
    """LLDP plugin test [DUMP]"""

    SYSTEM_NAME = "lldp-test"
    TX_HOLD = 8
    TX_INTERVAL = 15

    CHASSIS_ID_PG0 = "01:02:03:04:05:06"
    PORT_ID_PG0 = "07:08:09:0a:0b:0c"
    IP4_PG0 = "111.222.44.88"
    IP6_PG0 = "fd01:2::1"
    OID_PG0 = "1.2.4.0.1"
    OIDB_PG0 = b"1.2.4.0.1"

    CHASSIS_ID_PG1 = "11:12:13:14:15:16"
    PORT_ID_PG1 = "17:18:19:1a:1b:1c"
    IP4_PG1 = "88.44.222.111"
    IP6_PG1 = "fd01:2::2"
    OID_PG1 = "2.2.4.0.2"
    OIDB_PG1 = b"2.2.4.0.2"

    #
    # Status values are defined in vpp/src/plugins/lldp/lldp.api.
    #
    STATUS_ACTIVE = 0x01
    STATUS_INACTIVE = 0x02

    #######################################################################

    @classmethod
    def setUpClass(cls):
        super(TestLldpDump, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    #######################################################################

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestLldpDump, cls).tearDownClass()

    #######################################################################

    def create_frame(self, src_if, dst_if):
        if src_if == self.pg0:
            chassis_id = self.CHASSIS_ID_PG0
            port_id = self.PORT_ID_PG0
        else:
            chassis_id = self.CHASSIS_ID_PG1
            port_id = self.PORT_ID_PG1

        ttlval = self.TX_HOLD * self.TX_INTERVAL

        lldp_frame = (
            Ether(src=src_if.remote_mac, dst="01:80:C2:00:00:03")
            / LLDPDU()
            / LLDPDUChassisID(subtype=4, id=chassis_id)
            / LLDPDUPortID(subtype=3, id=port_id)
            / LLDPDUTimeToLive(ttl=ttlval)
            / LLDPDUEndOfLLDPDU()
        )

        return lldp_frame

    #######################################################################

    def test_lldp_dump(self):
        """Dump, verify, enable, send frames, dump, verify"""

        #
        # Initialize the global LLDP configuration.
        #
        self.vapi.lldp_config(
            system_name=self.SYSTEM_NAME,
            tx_hold=self.TX_HOLD,
            tx_interval=self.TX_INTERVAL,
        )

        val_sw_if_ind = 1
        val_mgmt_ip4 = self.IP4_PG0
        val_mgmt_ip6 = self.IP6_PG0
        val_mgmt_oid = self.OID_PG0
        val_mgmt_oidb = self.OIDB_PG0
        val_port_desc = "port 1 for dump testing"

        #
        # Initialize an interface with LLDP settings and disable it.
        #
        self.vapi.sw_interface_set_lldp(
            sw_if_index=val_sw_if_ind,
            mgmt_ip4=val_mgmt_ip4,
            mgmt_ip6=val_mgmt_ip6,
            mgmt_oid=val_mgmt_oidb,
            enable=False,
            port_desc=val_port_desc,
        )

        #
        # Ensure an LLDP-disabled interface doesn't dump.
        #
        result, details = self.vapi.lldp_dump()
        self.assert_equal(len(details), 0)

        #
        # Initialize an interface with LLDP settings and enable it.
        #
        self.vapi.sw_interface_set_lldp(
            sw_if_index=val_sw_if_ind,
            mgmt_ip4=val_mgmt_ip4,
            mgmt_ip6=val_mgmt_ip6,
            mgmt_oid=val_mgmt_oidb,
            enable=True,
            port_desc=val_port_desc,
        )

        #
        # Ensure an inactive LLDP-enabled interface dumps with
        # expected values.
        #
        result, details = self.vapi.lldp_dump()
        self.assertNotEqual(len(details), 0)

        #
        # Validate the various pieces of the LLDP dump data.
        #
        for d in details:
            new_system_name = d.system_name.decode("ascii").replace("\x00", "")
            new_port_id = d.port_id.decode("ascii").replace("\x00", "")
            new_chassis_id = d.chassis_id.decode("ascii").replace("\x00", "")
            new_port_desc = d.port_desc.decode("ascii").replace("\x00", "")
            new_mgmt_oid = d.mgmt_oid.decode("ascii").replace("\x00", "")

            self.assert_equal(new_system_name, self.SYSTEM_NAME)
            self.assert_equal(d.tx_hold, self.TX_HOLD)
            self.assert_equal(d.tx_interval, self.TX_INTERVAL)

            self.assert_equal(d.sw_if_index, val_sw_if_ind)
            self.assert_equal(d.mgmt_ip4, IPv4Address(val_mgmt_ip4))
            self.assert_equal(d.mgmt_ip6, IPv6Address(val_mgmt_ip6))
            self.assert_equal(new_mgmt_oid, val_mgmt_oid)
            self.assert_equal(new_port_desc, val_port_desc)

            self.assert_equal(d.status, self.STATUS_INACTIVE)
            self.assert_equal(d.ttl, 0)
            self.assert_equal(d.last_heard, 0.0)

            self.assert_equal(new_port_id, "")
            self.assert_equal(len(new_port_id), 0)
            self.assert_equal(d.port_id_len, 0)
            self.assert_equal(d.port_id_subtype, 0)

            self.assert_equal(new_chassis_id, "")
            self.assert_equal(len(new_chassis_id), 0)
            self.assert_equal(d.chassis_id_len, 0)
            self.assert_equal(d.chassis_id_subtype, 0)

        #
        # Initialize two interfaces to connect with LLDP and enable them.
        #
        self.vapi.sw_interface_set_lldp(
            sw_if_index=1,
            mgmt_ip4=self.IP4_PG0,
            mgmt_ip6=self.IP6_PG0,
            mgmt_oid=self.OIDB_PG0,
            port_desc="port 1 for dump testing",
            enable=True,
        )
        self.vapi.sw_interface_set_lldp(
            sw_if_index=2,
            mgmt_ip4=self.IP4_PG1,
            mgmt_ip6=self.IP6_PG1,
            mgmt_oid=self.OIDB_PG1,
            port_desc="port 2 for dump testing",
            enable=True,
        )

        #
        # Do the test-infrastructure magic so the interfaces are LLDP-talking.
        #
        self.pg0.enable_capture()
        self.pg1.enable_capture()

        recvd0 = self.pg0.wait_for_packet(30)
        recvd1 = self.pg1.wait_for_packet(30)

        packets0 = self.create_frame(self.pg0, self.pg1)
        packets1 = self.create_frame(self.pg1, self.pg0)

        self.virtual_sleep(75)

        self.pg0.add_stream(packets0)
        self.pg1.add_stream(packets1)

        self.vapi.cli(
            f"set interface lldp pg0 port-desc vtf:pg0 mgmt-ip4"
            f" {self.pg0.local_ip4} mgmt-ip6 {self.pg0.local_ip6}"
            f" mgmt-oid {val_mgmt_oid}"
        )
        self.vapi.cli("set interface lldp pg1 port-desc vtf:pg1")

        self.pg_start()

        self.pg0.add_stream(packets0)
        self.pg1.add_stream(packets1)

        #
        # Pretend to wait so LLDP will flow, then get the LLDP dump data.
        #
        self.virtual_sleep(10)
        result, details = self.vapi.lldp_dump()

        #
        # Validate the various pieces of the LLDP dump data.
        #
        for d in details:
            self.assert_equal(d.status, self.STATUS_ACTIVE)

            cttl = self.TX_HOLD * self.TX_INTERVAL
            self.assert_equal(d.ttl, cttl)

            self.assert_equal(d.chassis_id_subtype, 4)
            self.assert_equal(d.port_id_subtype, 3)

            self.assertNotEqual(d.chassis_id_len, 0)
            self.assertNotEqual(d.port_id_len, 0)

            self.assertNotEqual(d.last_heard, 0)
            self.assertNotEqual(d.last_sent, 0)
            self.assertNotEqual(d.last_heard_age, 0)
            self.assertNotEqual(d.last_sent_age, 0)

            port_id = "%02x:%02x:%02x:%02x:%02x:%02x" % (
                d.port_id[0],
                d.port_id[1],
                d.port_id[2],
                d.port_id[3],
                d.port_id[4],
                d.port_id[5],
            )

            chassis_id = "%02x:%02x:%02x:%02x:%02x:%02x" % (
                d.chassis_id[0],
                d.chassis_id[1],
                d.chassis_id[2],
                d.chassis_id[3],
                d.chassis_id[4],
                d.chassis_id[5],
            )

            oid = d.mgmt_oid.decode("ascii").replace("\x00", "")

            if d.sw_if_index == 1:
                self.assert_equal(port_id, self.PORT_ID_PG0)
                self.assert_equal(chassis_id, self.CHASSIS_ID_PG0)
                self.assert_equal(d.mgmt_ip4, IPv4Address(self.IP4_PG0))
                self.assert_equal(d.mgmt_ip6, IPv6Address(self.IP6_PG0))
                self.assert_equal(oid, self.OID_PG0)
            else:
                self.assert_equal(port_id, self.PORT_ID_PG1)
                self.assert_equal(chassis_id, self.CHASSIS_ID_PG1)
                self.assert_equal(d.mgmt_ip4, IPv4Address(self.IP4_PG1))
                self.assert_equal(d.mgmt_ip6, IPv6Address(self.IP6_PG1))
                self.assert_equal(oid, self.OID_PG1)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
