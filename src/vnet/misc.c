/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2012 Eliot Dresselhaus
 */

/* misc.c: vnet misc */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

vnet_main_t vnet_main;

vnet_main_t *
vnet_get_main (void)
{
  return &vnet_main;
}

static uword
vnet_local_interface_tx (vlib_main_t * vm,
			 vlib_node_runtime_t * node, vlib_frame_t * f)
{
  ASSERT (0);
  return f->n_vectors;
}

VNET_DEVICE_CLASS (vnet_local_interface_device_class) = {
  .name = "local",
  .tx_function = vnet_local_interface_tx,
};

VNET_HW_INTERFACE_CLASS (vnet_local_interface_hw_class,static) = {
  .name = "local",
};

clib_error_t *
vnet_main_init (vlib_main_t * vm)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index;
  vnet_hw_interface_t *hw;

  vnm->vlib_main = vm;

  hw_if_index = vnet_register_interface
    (vnm, vnet_local_interface_device_class.index, /* instance */ 0,
     vnet_local_interface_hw_class.index, /* instance */ 0);
  hw = vnet_get_hw_interface (vnm, hw_if_index);

  vnm->local_interface_hw_if_index = hw_if_index;
  vnm->local_interface_sw_if_index = hw->sw_if_index;

  vnm->pcap.current_filter_function =
    vlib_is_packet_traced_default_function ();

  return 0;
}

VLIB_INIT_FUNCTION (vnet_main_init) = {
  .init_order = VLIB_INITS ("vnet_interface_init", "ethernet_init",
			    "fib_module_init", "mfib_module_init",
			    "ip_main_init", "ip4_lookup_init",
			    "ip6_lookup_init", "mpls_init", "vnet_main_init"),
};
