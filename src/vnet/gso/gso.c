/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/gso/gso.h>

gso_main_t gso_main;

int
vnet_sw_interface_gso_enable_disable (u32 sw_if_index, u8 enable)
{
  vnet_feature_enable_disable ("ip4-output", "gso-ip4", sw_if_index, enable,
			       0, 0);
  vnet_feature_enable_disable ("ip6-output", "gso-ip6", sw_if_index, enable,
			       0, 0);

  vnet_l2_feature_enable_disable ("l2-output-nonip", "gso-l2-nonip",
				  sw_if_index, enable, 0, 0);
  vnet_l2_feature_enable_disable ("l2-output-ip4", "gso-l2-ip4",
				  sw_if_index, enable, 0, 0);
  vnet_l2_feature_enable_disable ("l2-output-ip6", "gso-l2-ip6",
				  sw_if_index, enable, 0, 0);

  return (0);
}

static clib_error_t *
gso_init (vlib_main_t * vm)
{
  gso_main_t *gm = &gso_main;

  clib_memset (gm, 0, sizeof (gm[0]));
  gm->vlib_main = vm;
  gm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (gso_init);
