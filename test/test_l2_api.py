#!/usr/bin/env python3
"""L2 interface feature flags API test"""

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_l2 import VppBridgeDomain, VppBridgeDomainPort
from vpp_papi import VppEnum


class TestL2IntfFeatFlags(VppTestCase):
    """L2 interface feature flags get/set API"""

    @classmethod
    def setUpClass(cls):
        super(TestL2IntfFeatFlags, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.admin_down()
        super(TestL2IntfFeatFlags, cls).tearDownClass()

    def setUp(self):
        super(TestL2IntfFeatFlags, self).setUp()
        self.ff = VppEnum.vl_api_l2_intf_feat_flags_t
        self.bd = VppBridgeDomain(self, bd_id=1).add_vpp_config()
        self.port0 = VppBridgeDomainPort(self, self.bd, self.pg0).add_vpp_config()
        self.port1 = VppBridgeDomainPort(self, self.bd, self.pg1).add_vpp_config()

    def tearDown(self):
        self.port0.remove_vpp_config()
        self.port1.remove_vpp_config()
        self.bd.remove_vpp_config()
        super(TestL2IntfFeatFlags, self).tearDown()

    def get_flags(self, iface):
        """Return the L2 feature flags bitmask for the given interface."""
        reply = self.vapi.l2_interface_feat_flags_get(sw_if_index=iface.sw_if_index)
        return reply.flags

    def set_flags(self, iface, flags, is_set):
        """Enable or disable the given L2 feature flags on an interface."""
        self.vapi.l2_interface_feat_flags_set(
            sw_if_index=iface.sw_if_index,
            flags=flags,
            is_set=is_set,
        )

    def test_default_flags(self):
        """Read default feature flags: learn, fwd, flood"""

        flags = self.get_flags(self.pg0)

        self.assertTrue(
            flags & self.ff.L2_INTF_FEAT_LEARN,
            "Expected LEARN to be set by default, flags=0x%x" % flags,
        )
        self.assertTrue(
            flags & self.ff.L2_INTF_FEAT_FWD,
            "Expected FWD to be set by default, flags=0x%x" % flags,
        )
        self.assertTrue(
            flags & self.ff.L2_INTF_FEAT_FLOOD,
            "Expected FLOOD to be set by default, flags=0x%x" % flags,
        )

    def test_set_flags_off_one_by_one(self):
        """Disable learn, fwd, flood one by one"""

        # Step 1: turn LEARN off
        self.set_flags(self.pg0, self.ff.L2_INTF_FEAT_LEARN, is_set=False)
        flags = self.get_flags(self.pg0)
        self.assertFalse(
            flags & self.ff.L2_INTF_FEAT_LEARN,
            "Expected LEARN off, flags=0x%x" % flags,
        )
        self.assertTrue(
            flags & self.ff.L2_INTF_FEAT_FWD,
            "Expected FWD still on, flags=0x%x" % flags,
        )
        self.assertTrue(
            flags & self.ff.L2_INTF_FEAT_FLOOD,
            "Expected FLOOD still on, flags=0x%x" % flags,
        )

        # Step 2: turn FWD off
        self.set_flags(self.pg0, self.ff.L2_INTF_FEAT_FWD, is_set=False)
        flags = self.get_flags(self.pg0)
        self.assertFalse(
            flags & self.ff.L2_INTF_FEAT_LEARN,
            "Expected LEARN off, flags=0x%x" % flags,
        )
        self.assertFalse(
            flags & self.ff.L2_INTF_FEAT_FWD,
            "Expected FWD off, flags=0x%x" % flags,
        )
        self.assertTrue(
            flags & self.ff.L2_INTF_FEAT_FLOOD,
            "Expected FLOOD still on, flags=0x%x" % flags,
        )

        # Step 3: turn FLOOD off
        self.set_flags(self.pg0, self.ff.L2_INTF_FEAT_FLOOD, is_set=False)
        flags = self.get_flags(self.pg0)
        self.assertFalse(
            flags & self.ff.L2_INTF_FEAT_LEARN,
            "Expected LEARN off, flags=0x%x" % flags,
        )
        self.assertFalse(
            flags & self.ff.L2_INTF_FEAT_FWD,
            "Expected FWD off, flags=0x%x" % flags,
        )
        self.assertFalse(
            flags & self.ff.L2_INTF_FEAT_FLOOD,
            "Expected FLOOD off, flags=0x%x" % flags,
        )

    def test_disable_enable_multiple_flags(self):
        """Toggle learn, fwd, flood using single set/get"""

        # Disable all three first so we have a known off state
        self.set_flags(
            self.pg0,
            self.ff.L2_INTF_FEAT_LEARN
            | self.ff.L2_INTF_FEAT_FWD
            | self.ff.L2_INTF_FEAT_FLOOD,
            is_set=False,
        )

        # Re-enable all three in one call
        self.set_flags(
            self.pg0,
            self.ff.L2_INTF_FEAT_LEARN
            | self.ff.L2_INTF_FEAT_FWD
            | self.ff.L2_INTF_FEAT_FLOOD,
            is_set=True,
        )

        # Single GET to confirm all three are back on
        flags = self.get_flags(self.pg0)
        self.assertTrue(
            flags & self.ff.L2_INTF_FEAT_LEARN,
            "Expected LEARN on after restore, flags=0x%x" % flags,
        )
        self.assertTrue(
            flags & self.ff.L2_INTF_FEAT_FWD,
            "Expected FWD on after restore, flags=0x%x" % flags,
        )
        self.assertTrue(
            flags & self.ff.L2_INTF_FEAT_FLOOD,
            "Expected FLOOD on after restore, flags=0x%x" % flags,
        )


# Raw internal L2 input feature bitmap bits (L2INPUT_FEAT_* from l2_input.h).
# The foreach_l2input_feat macro enumerates features in bit order starting at 0.
L2_INPUT_FEAT_FLOOD = 1 << 2  # L2INPUT_FEAT_FLOOD_BIT
L2_INPUT_FEAT_FWD = 1 << 7  # L2INPUT_FEAT_FWD_BIT
L2_INPUT_FEAT_LEARN = 1 << 9  # L2INPUT_FEAT_LEARN_BIT

# Raw internal L2 output feature bitmap bits (L2OUTPUT_FEAT_* from l2_output.h).
L2_OUTPUT_FEAT_STP_BLOCKED = 1 << 8  # L2OUTPUT_FEAT_STP_BLOCKED_BIT
L2_OUTPUT_FEAT_LINESTATUS_DOWN = 1 << 9  # L2OUTPUT_FEAT_LINESTATUS_DOWN_BIT


class TestL2FlagsSetGet(VppTestCase):
    """l2_flags_set / l2_flags_get raw bitmap API"""

    @classmethod
    def setUpClass(cls):
        super(TestL2FlagsSetGet, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.admin_down()
        super(TestL2FlagsSetGet, cls).tearDownClass()

    def setUp(self):
        super(TestL2FlagsSetGet, self).setUp()
        self.bd = VppBridgeDomain(self, bd_id=1).add_vpp_config()
        self.port0 = VppBridgeDomainPort(self, self.bd, self.pg0).add_vpp_config()
        self.port1 = VppBridgeDomainPort(self, self.bd, self.pg1).add_vpp_config()

    def tearDown(self):
        self.port0.remove_vpp_config()
        self.port1.remove_vpp_config()
        self.bd.remove_vpp_config()
        super(TestL2FlagsSetGet, self).tearDown()

    def get_flags(self, iface):
        """Return (input_feature_bitmap, output_feature_bitmap) for the interface."""
        reply = self.vapi.l2_flags_get(sw_if_index=iface.sw_if_index)
        return reply.input_feature_bitmap, reply.output_feature_bitmap

    def set_flags(self, iface, in_bitmap, out_bitmap, is_set):
        """Set or clear raw feature bitmap bits on input and/or output path."""
        self.vapi.l2_flags_set(
            sw_if_index=iface.sw_if_index,
            input_feature_bitmap=in_bitmap,
            output_feature_bitmap=out_bitmap,
            is_set=is_set,
        )

    def test_set_input_features(self):
        """l2_flags_set: set multiple input features"""
        mask = L2_INPUT_FEAT_LEARN | L2_INPUT_FEAT_FWD | L2_INPUT_FEAT_FLOOD

        # Clear first to establish a known baseline
        self.set_flags(self.pg0, mask, 0, False)
        in_bmap, _ = self.get_flags(self.pg0)
        self.assertFalse(
            in_bmap & mask,
            "bits should be clear before set, in_bmap=0x%x" % in_bmap,
        )

        # Set all three in one call and verify each bit
        self.set_flags(self.pg0, mask, 0, True)
        in_bmap, _ = self.get_flags(self.pg0)
        self.assertTrue(
            in_bmap & L2_INPUT_FEAT_LEARN,
            "Expected LEARN set, in_bmap=0x%x" % in_bmap,
        )
        self.assertTrue(
            in_bmap & L2_INPUT_FEAT_FWD,
            "Expected FWD set, in_bmap=0x%x" % in_bmap,
        )
        self.assertTrue(
            in_bmap & L2_INPUT_FEAT_FLOOD,
            "Expected FLOOD set, in_bmap=0x%x" % in_bmap,
        )

    def test_clear_input_features(self):
        """l2_flags_set: clear input features"""
        mask = L2_INPUT_FEAT_LEARN | L2_INPUT_FEAT_FWD | L2_INPUT_FEAT_FLOOD

        # Ensure all three are on before clearing
        self.set_flags(self.pg0, mask, 0, True)
        in_bmap, _ = self.get_flags(self.pg0)
        self.assertEqual(
            in_bmap & mask,
            mask,
            "Expected bits set before clear, in_bmap=0x%x" % in_bmap,
        )

        # Clear all three and verify each bit is gone
        self.set_flags(self.pg0, mask, 0, False)
        in_bmap, _ = self.get_flags(self.pg0)
        self.assertFalse(
            in_bmap & L2_INPUT_FEAT_LEARN,
            "Expected LEARN clear, in_bmap=0x%x" % in_bmap,
        )
        self.assertFalse(
            in_bmap & L2_INPUT_FEAT_FWD,
            "Expected FWD clear, in_bmap=0x%x" % in_bmap,
        )
        self.assertFalse(
            in_bmap & L2_INPUT_FEAT_FLOOD,
            "Expected FLOOD clear, in_bmap=0x%x" % in_bmap,
        )

    def test_set_output_features(self):
        """l2_flags_set: set output features"""
        mask = L2_OUTPUT_FEAT_STP_BLOCKED | L2_OUTPUT_FEAT_LINESTATUS_DOWN

        # Verify neither bit is set before we touch them
        _, out_bmap = self.get_flags(self.pg0)
        self.assertFalse(
            out_bmap & mask,
            "Expected output bits clear initially, out_bmap=0x%x" % out_bmap,
        )

        # Set both output flags and verify each one
        self.set_flags(self.pg0, 0, mask, True)
        _, out_bmap = self.get_flags(self.pg0)
        self.assertTrue(
            out_bmap & L2_OUTPUT_FEAT_STP_BLOCKED,
            "Expected STP_BLOCKED set, out_bmap=0x%x" % out_bmap,
        )
        self.assertTrue(
            out_bmap & L2_OUTPUT_FEAT_LINESTATUS_DOWN,
            "Expected LINESTATUS_DOWN set, out_bmap=0x%x" % out_bmap,
        )

    def test_clear_output_features(self):
        """l2_flags_set: clear output features"""
        mask = L2_OUTPUT_FEAT_STP_BLOCKED | L2_OUTPUT_FEAT_LINESTATUS_DOWN

        # Ensure both are on before clearing
        self.set_flags(self.pg0, 0, mask, True)
        _, out_bmap = self.get_flags(self.pg0)
        self.assertEqual(
            out_bmap & mask,
            mask,
            "Expected output bits set before clear, out_bmap=0x%x" % out_bmap,
        )

        # Clear both and verify each is gone
        self.set_flags(self.pg0, 0, mask, False)
        _, out_bmap = self.get_flags(self.pg0)
        self.assertFalse(
            out_bmap & L2_OUTPUT_FEAT_STP_BLOCKED,
            "Expected STP_BLOCKED clear, out_bmap=0x%x" % out_bmap,
        )
        self.assertFalse(
            out_bmap & L2_OUTPUT_FEAT_LINESTATUS_DOWN,
            "Expected LINESTATUS_DOWN clear, out_bmap=0x%x" % out_bmap,
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
