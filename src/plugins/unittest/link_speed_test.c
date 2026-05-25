/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco and/or its affiliates.
 */

/*
 * Unit test for set-link-speed API with a stub device class that
 * implements the set_link_speed_function callback.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>

typedef struct
{
  u32 hw_if_index;
  u32 sw_if_index;
  vnet_hw_if_speed_t last_requested_speed;
  u32 set_speed_call_count;
} link_speed_test_main_t;

static link_speed_test_main_t link_speed_test_main;

static u8 *
format_link_speed_test_interface_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "test-speed%d", dev_instance);
}

static uword
link_speed_test_interface_tx (vlib_main_t *vm, vlib_node_runtime_t *node,
			      vlib_frame_t *frame)
{
  return frame->n_vectors;
}

static clib_error_t *
link_speed_test_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
		   VNET_HW_INTERFACE_FLAG_LINK_UP :
		   0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

static clib_error_t *
link_speed_test_set_link_speed (vnet_main_t *vnm, u32 hw_if_index,
				vnet_hw_if_speed_t speed)
{
  link_speed_test_main_t *tm = &link_speed_test_main;

  tm->last_requested_speed = speed;
  tm->set_speed_call_count++;

  /* Simulate driver: report the new speed as operational */
  vnet_hw_interface_set_link_speed (vnm, hw_if_index,
				    vnet_hw_if_speed_to_kbps (speed));
  return 0;
}

VNET_DEVICE_CLASS (link_speed_test_device_class, static) = {
  .name = "Test link-speed interface",
  .format_device_name = format_link_speed_test_interface_name,
  .tx_function = link_speed_test_interface_tx,
  .admin_up_down_function = link_speed_test_admin_up_down,
  .set_link_speed_function = link_speed_test_set_link_speed,
};

static int
link_speed_test_create_interface (vlib_main_t *vm)
{
  link_speed_test_main_t *tm = &link_speed_test_main;
  vnet_main_t *vnm = vnet_get_main ();
  u8 hw_address[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };

  vnet_eth_interface_registration_t eir = {};
  eir.dev_class_index = link_speed_test_device_class.index;
  eir.dev_instance = 0;
  eir.address = hw_address;
  tm->hw_if_index = vnet_eth_register_interface (vnm, &eir);

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, tm->hw_if_index);
  tm->sw_if_index = hw->sw_if_index;

  /* Populate supported speeds: 10G, 25G, 100G */
  hw->supported_link_speeds = VNET_HW_IF_SPEED_10G | VNET_HW_IF_SPEED_25G |
			      VNET_HW_IF_SPEED_100G;

  vnet_hw_interface_set_flags (vnm, tm->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  vnet_sw_interface_set_flags (vnm, tm->sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  return 0;
}

static int
link_speed_test_delete_interface (void)
{
  link_speed_test_main_t *tm = &link_speed_test_main;
  vnet_main_t *vnm = vnet_get_main ();

  vnet_sw_interface_set_flags (vnm, tm->sw_if_index, 0);
  vnet_hw_interface_set_flags (vnm, tm->hw_if_index, 0);
  ethernet_delete_interface (vnm, tm->hw_if_index);

  clib_memset (tm, 0, sizeof (*tm));
  return 0;
}

#define LINK_SPEED_TEST_ASSERT(cond, fmt, ...)                                \
  do                                                                          \
    {                                                                         \
      if (!(cond))                                                            \
	{                                                                     \
	  error = clib_error_return (0, "FAIL: " fmt, ##__VA_ARGS__);         \
	  goto done;                                                          \
	}                                                                     \
      vlib_cli_output (vm, "  PASS: " fmt, ##__VA_ARGS__);                    \
    }                                                                         \
  while (0)

static clib_error_t *
test_link_speed_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  link_speed_test_main_t *tm = &link_speed_test_main;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  clib_error_t *err;

  link_speed_test_create_interface (vm);

  vlib_cli_output (vm, "--- Link Speed Unit Tests ---");

  /* Test 1: Set valid speed that's in supported_link_speeds */
  tm->set_speed_call_count = 0;
  err = vnet_hw_interface_change_link_speed (vnm, tm->hw_if_index, 10000000);
  LINK_SPEED_TEST_ASSERT (err == 0, "set speed 10G returns success");
  LINK_SPEED_TEST_ASSERT (tm->set_speed_call_count == 1,
			  "driver callback invoked (count=%u)",
			  tm->set_speed_call_count);
  LINK_SPEED_TEST_ASSERT (tm->last_requested_speed == VNET_HW_IF_SPEED_10G,
			  "driver received SPEED_10G (got 0x%x)",
			  tm->last_requested_speed);

  /* Verify hw->link_speed was updated by driver callback */
  {
    vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, tm->hw_if_index);
    LINK_SPEED_TEST_ASSERT (hw->link_speed == 10000000,
			    "hw->link_speed == 10000000 (got %u)",
			    hw->link_speed);
  }

  /* Test 2: Set another valid speed (25G) */
  err = vnet_hw_interface_change_link_speed (vnm, tm->hw_if_index, 25000000);
  LINK_SPEED_TEST_ASSERT (err == 0, "set speed 25G returns success");
  LINK_SPEED_TEST_ASSERT (tm->last_requested_speed == VNET_HW_IF_SPEED_25G,
			  "driver received SPEED_25G (got 0x%x)",
			  tm->last_requested_speed);

  /* Test 3: Set 100G */
  err = vnet_hw_interface_change_link_speed (vnm, tm->hw_if_index, 100000000);
  LINK_SPEED_TEST_ASSERT (err == 0, "set speed 100G returns success");
  LINK_SPEED_TEST_ASSERT (tm->last_requested_speed == VNET_HW_IF_SPEED_100G,
			  "driver received SPEED_100G (got 0x%x)",
			  tm->last_requested_speed);

  /* Test 4: Reject unsupported speed (40G not in our caps) */
  tm->set_speed_call_count = 0;
  err = vnet_hw_interface_change_link_speed (vnm, tm->hw_if_index, 40000000);
  LINK_SPEED_TEST_ASSERT (err != 0, "set speed 40G rejected");
  clib_error_free (err);
  LINK_SPEED_TEST_ASSERT (tm->set_speed_call_count == 0,
			  "driver NOT called for unsupported speed (count=%u)",
			  tm->set_speed_call_count);

  /* Test 5: Reject invalid speed (not matching any enum) */
  err = vnet_hw_interface_change_link_speed (vnm, tm->hw_if_index, 12345678);
  LINK_SPEED_TEST_ASSERT (err != 0, "set arbitrary speed 12345678 rejected");
  clib_error_free (err);

  /* Test 6: Verify kbps<->enum conversion */
  LINK_SPEED_TEST_ASSERT (
    vnet_hw_if_speed_from_kbps (10000000) == VNET_HW_IF_SPEED_10G,
    "10000000 Kbps -> SPEED_10G");
  LINK_SPEED_TEST_ASSERT (
    vnet_hw_if_speed_from_kbps (25000000) == VNET_HW_IF_SPEED_25G,
    "25000000 Kbps -> SPEED_25G");
  LINK_SPEED_TEST_ASSERT (
    vnet_hw_if_speed_from_kbps (100000000) == VNET_HW_IF_SPEED_100G,
    "100000000 Kbps -> SPEED_100G");
  LINK_SPEED_TEST_ASSERT (
    vnet_hw_if_speed_from_kbps (99999) == VNET_HW_IF_SPEED_UNKNOWN,
    "99999 Kbps -> SPEED_UNKNOWN");
  LINK_SPEED_TEST_ASSERT (vnet_hw_if_speed_to_kbps (VNET_HW_IF_SPEED_10G) ==
			    10000000,
			  "SPEED_10G -> 10000000 Kbps");
  LINK_SPEED_TEST_ASSERT (
    vnet_hw_if_speed_to_kbps (VNET_HW_IF_SPEED_UNKNOWN) == 0,
    "SPEED_UNKNOWN -> 0 Kbps");

  /* Test 7: Verify supported_link_speeds bitmask */
  {
    vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, tm->hw_if_index);
    LINK_SPEED_TEST_ASSERT (
      hw->supported_link_speeds ==
	(VNET_HW_IF_SPEED_10G | VNET_HW_IF_SPEED_25G | VNET_HW_IF_SPEED_100G),
      "supported_link_speeds has 10G|25G|100G (got 0x%x)",
      hw->supported_link_speeds);
  }

  vlib_cli_output (vm, "--- All tests passed ---");

done:
  link_speed_test_delete_interface ();
  return error;
}

VLIB_CLI_COMMAND (test_link_speed_command, static) = {
  .path = "test link-speed",
  .short_help = "test link-speed",
  .function = test_link_speed_command_fn,
};
