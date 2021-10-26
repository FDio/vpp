/*
 * sr_steering.c: ipv6 segment routing steering into SR policy
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file
 * @brief Packet steering into SR Policies
 *
 * This file is in charge of handling the FIB appropiatly to steer packets
 * through SR Policies as defined in 'sr_policy_rewrite.c'. Notice that here
 * we are only doing steering. SR policy application is done in
 * sr_policy_rewrite.c
 *
 * Supports:
 *  - Steering of IPv6 traffic Destination Address based
 *  - Steering of IPv4 traffic Destination Address based
 *  - Steering of L2 frames, interface based (sw interface)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/srv6/sr.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/dpo.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

/**
 * @brief Steer traffic L2 and L3 traffic through a given SR policy
 *
 * @param is_del
 * @param bsid is the bindingSID of the SR Policy (alt to sr_policy_index)
 * @param sr_policy is the index of the SR Policy (alt to bsid)
 * @param table_id is the VRF where to install the FIB entry for the BSID
 * @param prefix is the IPv4/v6 address for L3 traffic type
 * @param mask_width is the mask for L3 traffic type
 * @param sw_if_index is the incoming interface for L2 traffic
 * @param traffic_type describes the type of traffic
 *
 * @return 0 if correct, else error
 */
int
sr_steering_policy (int is_del, ip6_address_t * bsid, u32 sr_policy_index,
		    u32 table_id, ip46_address_t * prefix, u32 mask_width,
		    u32 sw_if_index, u8 traffic_type)
{
  ip6_sr_main_t *sm = &sr_main;
  sr_steering_key_t key;
  ip6_sr_steering_policy_t *steer_pl;
  fib_prefix_t pfx = { 0 };

  ip6_sr_policy_t *sr_policy = 0;
  uword *p = 0;

  clib_memset (&key, 0, sizeof (sr_steering_key_t));

  /* Compute the steer policy key */
  if (traffic_type == SR_STEER_IPV4 || traffic_type == SR_STEER_IPV6)
    {
      key.l3.prefix.as_u64[0] = prefix->as_u64[0];
      key.l3.prefix.as_u64[1] = prefix->as_u64[1];
      key.l3.mask_width = mask_width;
      key.l3.fib_table = (table_id != (u32) ~ 0 ? table_id : 0);
    }
  else if (traffic_type == SR_STEER_L2)
    {
      key.l2.sw_if_index = sw_if_index;

      /* Sanitise the SW_IF_INDEX */
      if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			      sw_if_index))
	return -3;

      vnet_sw_interface_t *sw =
	vnet_get_sw_interface (sm->vnet_main, sw_if_index);
      if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	return -3;
    }
  else
    return -1;

  key.traffic_type = traffic_type;

  /* Search for the item */
  p = mhash_get (&sm->sr_steer_policies_hash, &key);

  if (p)
    {
      /* Retrieve Steer Policy function */
      steer_pl = pool_elt_at_index (sm->steer_policies, p[0]);

      if (is_del)
	{
	  if (steer_pl->classify.traffic_type == SR_STEER_IPV6)
	    {
	      /* Remove FIB entry */
	      pfx.fp_proto = FIB_PROTOCOL_IP6;
	      pfx.fp_len = steer_pl->classify.l3.mask_width;
	      pfx.fp_addr.ip6 = steer_pl->classify.l3.prefix.ip6;

	      fib_table_entry_delete (fib_table_find
				      (FIB_PROTOCOL_IP6,
				       steer_pl->classify.l3.fib_table),
				      &pfx, FIB_SOURCE_SR);
	    }
	  else if (steer_pl->classify.traffic_type == SR_STEER_IPV4)
	    {
	      /* Remove FIB entry */
	      pfx.fp_proto = FIB_PROTOCOL_IP4;
	      pfx.fp_len = steer_pl->classify.l3.mask_width;
	      pfx.fp_addr.ip4 = steer_pl->classify.l3.prefix.ip4;

	      fib_table_entry_delete (fib_table_find
				      (FIB_PROTOCOL_IP4,
				       steer_pl->classify.l3.fib_table), &pfx,
				      FIB_SOURCE_SR);
	    }
	  else if (steer_pl->classify.traffic_type == SR_STEER_L2)
	    {
	      /* Remove HW redirection */
	      int ret = vnet_feature_enable_disable ("device-input",
						     "sr-pl-rewrite-encaps-l2",
						     sw_if_index, 0, 0, 0);

	      if (ret != 0)
		return -1;

	      sm->sw_iface_sr_policies[sw_if_index] = ~(u32) 0;

	      /* Remove promiscous mode from interface */
	      vnet_main_t *vnm = vnet_get_main ();
	      vnet_hw_interface_t *hi =
		vnet_get_sup_hw_interface (vnm, sw_if_index);
	      /* Make sure it is main interface */
	      if (hi->sw_if_index == sw_if_index)
		ethernet_set_flags (vnm, hi->hw_if_index, 0);
	    }

	  /* Delete SR steering policy entry */
	  pool_put (sm->steer_policies, steer_pl);
	  mhash_unset (&sm->sr_steer_policies_hash, &key, NULL);

	  /* If no more SR policies or steering policies */
	  if (!pool_elts (sm->sr_policies) && !pool_elts (sm->steer_policies))
	    {
	      fib_table_unlock (sm->fib_table_ip6,
				FIB_PROTOCOL_IP6, FIB_SOURCE_SR);
	      fib_table_unlock (sm->fib_table_ip4,
				FIB_PROTOCOL_IP6, FIB_SOURCE_SR);
	      sm->fib_table_ip6 = (u32) ~ 0;
	      sm->fib_table_ip4 = (u32) ~ 0;
	    }

	  return 0;
	}
      else			/* It means user requested to update an existing SR steering policy */
	{
	  /* Retrieve SR steering policy */
	  if (bsid)
	    {
	      p = mhash_get (&sm->sr_policies_index_hash, bsid);
	      if (p)
		sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);
	      else
		return -2;
	    }
	  else
	    sr_policy = pool_elt_at_index (sm->sr_policies, sr_policy_index);

	  steer_pl->sr_policy = sr_policy - sm->sr_policies;

	  /* Remove old FIB/hw redirection and create a new one */
	  if (steer_pl->classify.traffic_type == SR_STEER_IPV6)
	    {
	      /* Remove FIB entry */
	      pfx.fp_proto = FIB_PROTOCOL_IP6;
	      pfx.fp_len = steer_pl->classify.l3.mask_width;
	      pfx.fp_addr.ip6 = steer_pl->classify.l3.prefix.ip6;

	      fib_table_entry_delete (fib_table_find
				      (FIB_PROTOCOL_IP6,
				       steer_pl->classify.l3.fib_table),
				      &pfx, FIB_SOURCE_SR);

	      /* Create a new one */
	      goto update_fib;
	    }
	  else if (steer_pl->classify.traffic_type == SR_STEER_IPV4)
	    {
	      /* Remove FIB entry */
	      pfx.fp_proto = FIB_PROTOCOL_IP4;
	      pfx.fp_len = steer_pl->classify.l3.mask_width;
	      pfx.fp_addr.ip4 = steer_pl->classify.l3.prefix.ip4;

	      fib_table_entry_delete (fib_table_find
				      (FIB_PROTOCOL_IP4,
				       steer_pl->classify.l3.fib_table),
				      &pfx, FIB_SOURCE_SR);

	      /* Create a new one */
	      goto update_fib;
	    }
	  else if (steer_pl->classify.traffic_type == SR_STEER_L2)
	    {
	      /* Update L2-HW redirection */
	      goto update_fib;
	    }
	}
    }
  else
    /* delete; steering policy does not exist; complain */
  if (is_del)
    return -4;

  /* Retrieve SR policy */
  if (bsid)
    {
      p = mhash_get (&sm->sr_policies_index_hash, bsid);
      if (p)
	sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);
      else
	return -2;
    }
  else
    sr_policy = pool_elt_at_index (sm->sr_policies, sr_policy_index);

  /* Create a new steering policy */
  pool_get (sm->steer_policies, steer_pl);
  clib_memset (steer_pl, 0, sizeof (*steer_pl));

  if (traffic_type == SR_STEER_IPV4 || traffic_type == SR_STEER_IPV6)
    {
      clib_memcpy_fast (&steer_pl->classify.l3.prefix, prefix,
			sizeof (ip46_address_t));
      steer_pl->classify.l3.mask_width = mask_width;
      steer_pl->classify.l3.fib_table =
	(table_id != (u32) ~ 0 ? table_id : 0);
      steer_pl->classify.traffic_type = traffic_type;
    }
  else if (traffic_type == SR_STEER_L2)
    {
      steer_pl->classify.l2.sw_if_index = sw_if_index;
      steer_pl->classify.traffic_type = traffic_type;
    }
  else
    {
      /* Incorrect API usage. Should never get here */
      pool_put (sm->steer_policies, steer_pl);
      mhash_unset (&sm->sr_steer_policies_hash, &key, NULL);
      return -1;
    }
  steer_pl->sr_policy = sr_policy - sm->sr_policies;

  /* Create and store key */
  mhash_set (&sm->sr_steer_policies_hash, &key, steer_pl - sm->steer_policies,
	     NULL);

  if (traffic_type == SR_STEER_L2)
    {
      if (!sr_policy->is_encap)
	goto cleanup_error_encap;

      if (vnet_feature_enable_disable
	  ("device-input", "sr-pl-rewrite-encaps-l2", sw_if_index, 1, 0, 0))
	goto cleanup_error_redirection;

      /* Set promiscous mode on interface */
      vnet_main_t *vnm = vnet_get_main ();
      vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
      /* Make sure it is main interface */
      if (hi->sw_if_index == sw_if_index)
	ethernet_set_flags (vnm, hi->hw_if_index,
			    ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);
    }
  else if (traffic_type == SR_STEER_IPV4)
    if (!sr_policy->is_encap)
      goto cleanup_error_encap;

update_fib:
  /* FIB API calls - Recursive route through the BindingSID */
  if (traffic_type == SR_STEER_IPV6)
    {
      pfx.fp_proto = FIB_PROTOCOL_IP6;
      pfx.fp_len = steer_pl->classify.l3.mask_width;
      pfx.fp_addr.ip6 = steer_pl->classify.l3.prefix.ip6;

      fib_table_entry_path_add (fib_table_find (FIB_PROTOCOL_IP6,
						(table_id !=
						 (u32) ~ 0 ?
						 table_id : 0)),
				&pfx, FIB_SOURCE_SR,
				FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
				DPO_PROTO_IP6,
				(ip46_address_t *) & sr_policy->bsid, ~0,
				sm->fib_table_ip6, 1, NULL,
				FIB_ROUTE_PATH_FLAG_NONE);
    }
  else if (traffic_type == SR_STEER_IPV4)
    {
      pfx.fp_proto = FIB_PROTOCOL_IP4;
      pfx.fp_len = steer_pl->classify.l3.mask_width;
      pfx.fp_addr.ip4 = steer_pl->classify.l3.prefix.ip4;

      fib_table_entry_path_add (fib_table_find (FIB_PROTOCOL_IP4,
						(table_id !=
						 (u32) ~ 0 ?
						 table_id : 0)),
				&pfx, FIB_SOURCE_SR,
				FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
				DPO_PROTO_IP6,
				(ip46_address_t *) & sr_policy->bsid, ~0,
				sm->fib_table_ip4, 1, NULL,
				FIB_ROUTE_PATH_FLAG_NONE);
    }
  else if (traffic_type == SR_STEER_L2)
    {
      if (sw_if_index < vec_len (sm->sw_iface_sr_policies))
	sm->sw_iface_sr_policies[sw_if_index] = steer_pl->sr_policy;
      else
	{
	  vec_resize (sm->sw_iface_sr_policies,
		      (pool_len (sm->vnet_main->interface_main.sw_interfaces)
		       - vec_len (sm->sw_iface_sr_policies)));
	  sm->sw_iface_sr_policies[sw_if_index] = steer_pl->sr_policy;
	}
    }

  return 0;

cleanup_error_encap:
  pool_put (sm->steer_policies, steer_pl);
  mhash_unset (&sm->sr_steer_policies_hash, &key, NULL);
  return -5;

cleanup_error_redirection:
  pool_put (sm->steer_policies, steer_pl);
  mhash_unset (&sm->sr_steer_policies_hash, &key, NULL);
  return -3;
}

static clib_error_t *
sr_steer_policy_command_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();

  int is_del = 0;

  ip46_address_t prefix;
  u32 dst_mask_width = 0;
  u32 sw_if_index = (u32) ~ 0;
  u8 traffic_type = 0;
  u32 fib_table = (u32) ~ 0;

  ip6_address_t bsid;
  u32 sr_policy_index = (u32) ~ 0;

  u8 sr_policy_set = 0;

  clib_memset (&prefix, 0, sizeof (ip46_address_t));

  int rv;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_del = 1;
      else if (!traffic_type
	       && unformat (input, "l3 %U/%d", unformat_ip6_address,
			    &prefix.ip6, &dst_mask_width))
	traffic_type = SR_STEER_IPV6;
      else if (!traffic_type
	       && unformat (input, "l3 %U/%d", unformat_ip4_address,
			    &prefix.ip4, &dst_mask_width))
	traffic_type = SR_STEER_IPV4;
      else if (!traffic_type
	       && unformat (input, "l2 %U", unformat_vnet_sw_interface, vnm,
			    &sw_if_index))
	traffic_type = SR_STEER_L2;
      else if (!sr_policy_set
	       && unformat (input, "via index %d", &sr_policy_index))
	sr_policy_set = 1;
      else if (!sr_policy_set
	       && unformat (input, "via bsid %U",
			    unformat_ip6_address, &bsid))
	sr_policy_set = 1;
      else if (fib_table == (u32) ~ 0
	       && unformat (input, "fib-table %d", &fib_table));
      else
	break;
    }

  if (!traffic_type)
    return clib_error_return (0, "No L2/L3 traffic specified");
  if (!is_del && !sr_policy_set)
    return clib_error_return (0, "No SR policy specified");

  /* Make sure that the prefixes are clean */
  if (traffic_type == SR_STEER_IPV4)
    {
      u32 mask =
	(dst_mask_width ? (0xFFFFFFFFu >> (32 - dst_mask_width)) : 0);
      prefix.ip4.as_u32 &= mask;
    }
  else if (traffic_type == SR_STEER_IPV6)
    {
      ip6_address_t mask;
      ip6_address_mask_from_width (&mask, dst_mask_width);
      ip6_address_mask (&prefix.ip6, &mask);
    }

  rv =
    sr_steering_policy (is_del, (sr_policy_index == ~(u32) 0 ? &bsid : NULL),
			sr_policy_index, fib_table, &prefix, dst_mask_width,
			sw_if_index, traffic_type);

  switch (rv)
    {
    case 0:
      break;
    case 1:
      return 0;
    case -1:
      return clib_error_return (0, "Incorrect API usage.");
    case -2:
      return clib_error_return (0,
				"The requested SR policy could not be located. Review the BSID/index.");
    case -3:
      return clib_error_return (0,
				"Unable to do SW redirect. Incorrect interface.");
    case -4:
      return clib_error_return (0,
				"The requested SR steering policy could not be deleted.");
    case -5:
      return clib_error_return (0,
				"The SR policy is not an encapsulation one.");
    default:
      return clib_error_return (0, "BUG: sr steer policy returns %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (sr_steer_policy_command, static) = {
  .path = "sr steer",
  .short_help = "sr steer (del) [l3 <ip_addr/mask>|l2 <sf_if>] "
    "via [index <sr_policy_index>|bsid <bsid_ip6_addr>] "
    "(fib-table <fib_table_index>)",
  .long_help =
    "\tSteer a L2 or L3 traffic through an existing SR policy.\n"
    "\tExamples:\n"
    "\t\tsr steer l3 2001::/64 via sr_policy index 5\n"
    "\t\tsr steer l3 2001::/64 via sr_policy bsid 2010::9999:1\n"
    "\t\tsr steer l2 GigabitEthernet0/5/0 via sr_policy index 5\n"
    "\t\tsr steer del l3 2001::/64 via sr_policy index 5\n",
  .function = sr_steer_policy_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_sr_steering_policies_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_steering_policy_t **steer_policies = 0;
  ip6_sr_steering_policy_t *steer_pl;

  vnet_main_t *vnm = vnet_get_main ();

  ip6_sr_policy_t *pl = 0;
  int i;

  vlib_cli_output (vm, "SR steering policies:");
  /* *INDENT-OFF* */
  pool_foreach (steer_pl, sm->steer_policies) {vec_add1(steer_policies, steer_pl);}
  /* *INDENT-ON* */
  vlib_cli_output (vm, "Traffic\t\tSR policy BSID");
  for (i = 0; i < vec_len (steer_policies); i++)
    {
      steer_pl = steer_policies[i];
      pl = pool_elt_at_index (sm->sr_policies, steer_pl->sr_policy);
      if (steer_pl->classify.traffic_type == SR_STEER_L2)
	{
	  vlib_cli_output (vm, "L2 %U\t%U",
			   format_vnet_sw_if_index_name, vnm,
			   steer_pl->classify.l2.sw_if_index,
			   format_ip6_address, &pl->bsid);
	}
      else if (steer_pl->classify.traffic_type == SR_STEER_IPV4)
	{
	  vlib_cli_output (vm, "L3 %U/%d\t%U",
			   format_ip4_address,
			   &steer_pl->classify.l3.prefix.ip4,
			   steer_pl->classify.l3.mask_width,
			   format_ip6_address, &pl->bsid);
	}
      else if (steer_pl->classify.traffic_type == SR_STEER_IPV6)
	{
	  vlib_cli_output (vm, "L3 %U/%d\t%U",
			   format_ip6_address,
			   &steer_pl->classify.l3.prefix.ip6,
			   steer_pl->classify.l3.mask_width,
			   format_ip6_address, &pl->bsid);
	}
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_sr_steering_policies_command, static) = {
  .path = "show sr steering-policies",
  .short_help = "show sr steering-policies",
  .function = show_sr_steering_policies_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
sr_steering_init (vlib_main_t * vm)
{
  ip6_sr_main_t *sm = &sr_main;

  /* Init memory for function keys */
  mhash_init (&sm->sr_steer_policies_hash, sizeof (uword),
	      sizeof (sr_steering_key_t));

  sm->sw_iface_sr_policies = 0;

  sm->vnet_main = vnet_get_main ();

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (sr_steering_init);
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT (sr_pl_rewrite_encaps_l2, static) =
{
  .arc_name = "device-input",
  .node_name = "sr-pl-rewrite-encaps-l2",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON* */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
