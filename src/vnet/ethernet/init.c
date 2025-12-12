/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ethernet_init.c: ethernet initialization */

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>		// for feature registration

/* Global main structure. */
ethernet_main_t ethernet_main;

static void
add_type (ethernet_main_t * em, ethernet_type_t type, char *type_name)
{
  ethernet_type_info_t *ti;
  u32 i;

  vec_add2 (em->type_infos, ti, 1);
  i = ti - em->type_infos;

  ti->name = type_name;
  ti->type = type;
  ti->next_index = ti->node_index = ~0;

  hash_set (em->type_info_by_type, type, i);
  hash_set_mem (em->type_info_by_name, ti->name, i);
}

/* Built-in ip4 tx feature path definition */
VNET_FEATURE_ARC_INIT (ethernet_output, static) =
{
  .arc_name  = "ethernet-output",
  .last_in_arc = "error-drop",
  .start_nodes = VNET_FEATURES ("adj-l2-midchain"),
  .arc_index_ptr = &ethernet_main.output_feature_arc_index,
};

VNET_FEATURE_INIT (ethernet_tx_drop, static) =
{
  .arc_name = "ethernet-output",
  .node_name = "error-drop",
  .runs_before = 0,	/* not before any other features */
};

static clib_error_t *
ethernet_init (vlib_main_t * vm)
{
  ethernet_main_t *em = &ethernet_main;

  em->vlib_main = vm;

  em->type_info_by_name = hash_create_string (0, sizeof (uword));
  em->type_info_by_type = hash_create (0, sizeof (uword));
  /*
   * System default ethernet interface MTU, configure via ethernet_config in
   * interface.c if desired.
   */
  em->default_mtu = 9000;

#define ethernet_type(n,s) add_type (em, ETHERNET_TYPE_##s, #s);
#include "types.def"
#undef ethernet_type

  /*
   * ethernet_input_init is effectively part of this function.
   * Simply ensuring that it happens after we set up the hash tables
   * is not sufficient.
   */
  ethernet_input_init (vm, em);
  return 0;
}

VLIB_INIT_FUNCTION (ethernet_init) =
{
  /*
   * Set up the L2 path before ethernet_init, or we'll wipe out the L2 ARP
   * registration set up by ethernet_arp_init.
   */
  .init_order = VLIB_INITS("l2_init",
                           "ethernet_init",
                           "llc_init",
                           "vnet_feature_init"),
};

ethernet_main_t *
ethernet_get_main (vlib_main_t * vm)
{
  return &ethernet_main;
}
