/*
 * sr_localsid.c: ipv6 segment routing Endpoint behaviors
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
 * @brief Processing of packets with a SRH
 *
 * CLI to define new Segment Routing End processing functions.
 * Graph node to support such functions.
 *
 * Each function associates an SRv6 segment (IPv6 address) with an specific
 * Segment Routing function.
 *
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/srv6/sr.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

/**
 * @brief Dynamically added SR localsid DPO type
 */
static dpo_type_t sr_localsid_dpo_type;
static dpo_type_t sr_localsid_d_dpo_type;
static dpo_type_t sr_localsid_un_dpo_type;
static dpo_type_t sr_localsid_un_perf_dpo_type;

static void
sr_localsid_key_create (sr_localsid_key_t * key, ip6_address_t * addr,
			u16 pref_len)
{
  clib_memset (key, 0, sizeof (sr_localsid_key_t));
  clib_memcpy (&key->address, addr, sizeof (ip6_address_t));
  key->pref_len = pref_len;
}

/**
 * @brief SR localsid add/del
 *
 * Function to add or delete SR LocalSIDs.
 *
 * @param is_del Boolean of whether its a delete instruction
 * @param localsid_addr IPv6 address of the localsid
 * @param is_decap Boolean of whether decapsulation is allowed in this function
 * @param behavior Type of behavior (function) for this localsid
 * @param sw_if_index Only for L2/L3 xconnect. OIF. In VRF variant the fib_table.
 * @param vlan_index Only for L2 xconnect. Outgoing VLAN tag.
 * @param fib_table  FIB table in which we should install the localsid entry
 * @param nh_addr Next Hop IPv4/IPv6 address. Only for L2/L3 xconnect.
 *
 * @return 0 on success, error otherwise.
 */
int
sr_cli_localsid (char is_del, ip6_address_t * localsid_addr,
		 u16 localsid_prefix_len, char end_psp, u8 behavior,
		 u32 sw_if_index, u32 vlan_index, u32 fib_table,
		 ip46_address_t * nh_addr, int usid_len, void *ls_plugin_mem)
{
  ip6_sr_main_t *sm = &sr_main;
  uword *p;
  int rv;
  u8 pref_length = 128;
  sr_localsid_fn_registration_t *plugin = 0;
  sr_localsid_key_t key;

  ip6_sr_localsid_t *ls = 0;

  dpo_id_t dpo = DPO_INVALID;

  /* Search for the item */
  sr_localsid_key_create (&key, localsid_addr, localsid_prefix_len);
  p = mhash_get (&sm->sr_localsids_index_hash, &key);

  if (p)
    {
      if (is_del)
	{
	  /* Retrieve localsid */
	  ls = pool_elt_at_index (sm->localsids, p[0]);
	  if (ls->behavior >= SR_BEHAVIOR_LAST)
	    {
	      plugin = pool_elt_at_index (sm->plugin_functions,
					  ls->behavior - SR_BEHAVIOR_LAST);
	      pref_length = plugin->prefix_length;
	    }

	  if (localsid_prefix_len != 0)
	    {
	      pref_length = localsid_prefix_len;
	    }

	  /* Delete FIB entry */
	  fib_prefix_t pfx = {
	    .fp_proto = FIB_PROTOCOL_IP6,
	    .fp_len = pref_length,
	    .fp_addr = {
			.ip6 = *localsid_addr,
			}
	  };

	  fib_table_entry_delete (fib_table_find
				  (FIB_PROTOCOL_IP6, fib_table), &pfx,
				  FIB_SOURCE_SR);

	  /* In case it is a Xconnect iface remove the (OIF, NHOP) adj */
	  if (ls->behavior == SR_BEHAVIOR_X || ls->behavior == SR_BEHAVIOR_DX6
	      || ls->behavior == SR_BEHAVIOR_DX4)
	    adj_unlock (ls->nh_adj);

	  if (ls->behavior >= SR_BEHAVIOR_LAST)
	    {
	      /* Callback plugin removal function */
	      rv = plugin->removal (ls);
	    }

	  /* Delete localsid registry */
	  pool_put (sm->localsids, ls);
	  mhash_unset (&sm->sr_localsids_index_hash, &key, NULL);
	  return 0;
	}
      else			/* create with function already existing; complain */
	return -1;
    }
  else
    /* delete; localsid does not exist; complain */
  if (is_del)
    return -2;

  if (behavior >= SR_BEHAVIOR_LAST)
    {
      sr_localsid_fn_registration_t *plugin = 0;
      plugin =
	pool_elt_at_index (sm->plugin_functions, behavior - SR_BEHAVIOR_LAST);
      pref_length = plugin->prefix_length;
    }

  if (localsid_prefix_len != 0)
    {
      pref_length = localsid_prefix_len;
    }

  /* Check whether there exists a FIB entry with such address */
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = pref_length,
  };

  pfx.fp_addr.as_u64[0] = localsid_addr->as_u64[0];
  pfx.fp_addr.as_u64[1] = localsid_addr->as_u64[1];
  pfx.fp_len = pref_length;

  /* Lookup the FIB index associated to the table id provided */
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP6, fib_table);
  if (fib_index == ~0)
    return -3;

  /* Lookup the localsid in such FIB table */
  fib_node_index_t fei = fib_table_lookup_exact_match (fib_index, &pfx);
  if (FIB_NODE_INDEX_INVALID != fei)
    return -4;			//There is an entry for such address (the localsid addr)

  /* Create a new localsid registry */
  pool_get (sm->localsids, ls);
  clib_memset (ls, 0, sizeof (*ls));

  clib_memcpy (&ls->localsid, localsid_addr, sizeof (ip6_address_t));
  ls->localsid_prefix_len = pref_length;
  ls->end_psp = end_psp;
  ls->behavior = behavior;
  ls->nh_adj = (u32) ~ 0;
  ls->fib_table = fib_table;
  switch (behavior)
    {
    case SR_BEHAVIOR_END:
      break;
    case SR_BEHAVIOR_END_UN:
    case SR_BEHAVIOR_END_UN_PERF:
      if (usid_len)
	{
	  int usid_width;
	  clib_memcpy (&ls->usid_block, localsid_addr,
		       sizeof (ip6_address_t));

	  usid_width = pref_length - usid_len;
	  ip6_address_mask_from_width (&ls->usid_block_mask, usid_width);

	  ls->usid_index = usid_width / 8;
	  ls->usid_len = usid_len / 8;
	  ls->usid_next_index = ls->usid_index + ls->usid_len;
	  ls->usid_next_len = 16 - ls->usid_next_index;
	}
      break;
    case SR_BEHAVIOR_X:
      ls->sw_if_index = sw_if_index;
      clib_memcpy (&ls->next_hop.ip6, &nh_addr->ip6, sizeof (ip6_address_t));
      break;
    case SR_BEHAVIOR_T:
      ls->vrf_index = fib_table_find (FIB_PROTOCOL_IP6, sw_if_index);
      break;
    case SR_BEHAVIOR_DX4:
      ls->sw_if_index = sw_if_index;
      clib_memcpy (&ls->next_hop.ip4, &nh_addr->ip4, sizeof (ip4_address_t));
      break;
    case SR_BEHAVIOR_DX6:
      ls->sw_if_index = sw_if_index;
      clib_memcpy (&ls->next_hop.ip6, &nh_addr->ip6, sizeof (ip6_address_t));
      break;
    case SR_BEHAVIOR_DT6:
      ls->vrf_index = fib_table_find (FIB_PROTOCOL_IP6, sw_if_index);
      break;
    case SR_BEHAVIOR_DT4:
      ls->vrf_index = fib_table_find (FIB_PROTOCOL_IP4, sw_if_index);
      break;
    case SR_BEHAVIOR_DX2:
      ls->sw_if_index = sw_if_index;
      ls->vlan_index = vlan_index;
      break;
    }

  /* Figure out the adjacency magic for Xconnect variants */
  if (ls->behavior == SR_BEHAVIOR_X || ls->behavior == SR_BEHAVIOR_DX4
      || ls->behavior == SR_BEHAVIOR_DX6)
    {
      adj_index_t nh_adj_index = ADJ_INDEX_INVALID;

      /* Retrieve the adjacency corresponding to the (OIF, next_hop) */
      if (ls->behavior == SR_BEHAVIOR_DX6 || ls->behavior == SR_BEHAVIOR_X)
	nh_adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP6, VNET_LINK_IP6,
					    nh_addr, sw_if_index);

      else if (ls->behavior == SR_BEHAVIOR_DX4)
	nh_adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_IP4,
					    nh_addr, sw_if_index);

      /* Check for ADJ creation error. If so panic */
      if (nh_adj_index == ADJ_INDEX_INVALID)
	{
	  pool_put (sm->localsids, ls);
	  return -5;
	}

      ls->nh_adj = nh_adj_index;
    }

  /* Set DPO */
  if (ls->behavior == SR_BEHAVIOR_END || ls->behavior == SR_BEHAVIOR_X
      || ls->behavior == SR_BEHAVIOR_T)
    dpo_set (&dpo, sr_localsid_dpo_type, DPO_PROTO_IP6, ls - sm->localsids);
  else if (ls->behavior == SR_BEHAVIOR_END_UN)
    dpo_set (&dpo, sr_localsid_un_dpo_type, DPO_PROTO_IP6,
	     ls - sm->localsids);
  else if (ls->behavior == SR_BEHAVIOR_END_UN_PERF)
    dpo_set (&dpo, sr_localsid_un_perf_dpo_type, DPO_PROTO_IP6,
	     ls - sm->localsids);
  else if (ls->behavior > SR_BEHAVIOR_D_FIRST
	   && ls->behavior < SR_BEHAVIOR_LAST)
    dpo_set (&dpo, sr_localsid_d_dpo_type, DPO_PROTO_IP6, ls - sm->localsids);
  else if (ls->behavior >= SR_BEHAVIOR_LAST)
    {
      sr_localsid_fn_registration_t *plugin = 0;
      plugin = pool_elt_at_index (sm->plugin_functions,
				  ls->behavior - SR_BEHAVIOR_LAST);
      /* Copy the unformat memory result */
      ls->plugin_mem = ls_plugin_mem;
      /* Callback plugin creation function */
      rv = plugin->creation (ls);
      if (rv)
	{
	  pool_put (sm->localsids, ls);
	  return -6;
	}
      dpo_set (&dpo, plugin->dpo, DPO_PROTO_IP6, ls - sm->localsids);
    }

  /* Set hash key for searching localsid by address */
  mhash_set (&sm->sr_localsids_index_hash, &key, ls - sm->localsids, NULL);

  fib_table_entry_special_dpo_add (fib_index, &pfx, FIB_SOURCE_SR,
				   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
  dpo_reset (&dpo);

  /* Set counter to zero */
  vlib_validate_combined_counter (&(sm->sr_ls_valid_counters),
				  ls - sm->localsids);
  vlib_validate_combined_counter (&(sm->sr_ls_invalid_counters),
				  ls - sm->localsids);

  vlib_zero_combined_counter (&(sm->sr_ls_valid_counters),
			      ls - sm->localsids);
  vlib_zero_combined_counter (&(sm->sr_ls_invalid_counters),
			      ls - sm->localsids);

  return 0;
}

/**
 * @brief SR LocalSID CLI function.
 *
 * @see sr_cli_localsid
 */
static clib_error_t *
sr_cli_localsid_command_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_sr_main_t *sm = &sr_main;
  u32 sw_if_index = (u32) ~ 0, vlan_index = (u32) ~ 0, fib_index = 0;
  int prefix_len = 0;
  int is_del = 0;
  int end_psp = 0;
  ip6_address_t resulting_address;
  ip46_address_t next_hop;
  char address_set = 0;
  char behavior = 0;
  void *ls_plugin_mem = 0;
  int usid_size = 0;

  int rv;

  clib_memset (&resulting_address, 0, sizeof (ip6_address_t));
  ip46_address_reset (&next_hop);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_del = 1;
      else if (!address_set
	       && unformat (input, "prefix %U/%u", unformat_ip6_address,
			    &resulting_address, &prefix_len))
	address_set = 1;
      else if (!address_set
	       && unformat (input, "address %U", unformat_ip6_address,
			    &resulting_address))
	address_set = 1;
      else if (!address_set
	       && unformat (input, "addr %U", unformat_ip6_address,
			    &resulting_address))
	address_set = 1;
      else if (unformat (input, "fib-table %u", &fib_index));
      else if (vlan_index == (u32) ~ 0
	       && unformat (input, "vlan %u", &vlan_index));
      else if (!behavior && unformat (input, "behavior"))
	{
	  if (unformat (input, "end.x %U %U",
			unformat_vnet_sw_interface, vnm, &sw_if_index,
			unformat_ip6_address, &next_hop.ip6))
	    behavior = SR_BEHAVIOR_X;
	  else if (unformat (input, "end.t %u", &sw_if_index))
	    behavior = SR_BEHAVIOR_T;
	  else if (unformat (input, "end.dx6 %U %U",
			     unformat_vnet_sw_interface, vnm, &sw_if_index,
			     unformat_ip6_address, &next_hop.ip6))
	    behavior = SR_BEHAVIOR_DX6;
	  else if (unformat (input, "end.dx4 %U %U",
			     unformat_vnet_sw_interface, vnm, &sw_if_index,
			     unformat_ip4_address, &next_hop.ip4))
	    behavior = SR_BEHAVIOR_DX4;
	  else if (unformat (input, "end.dx2 %U",
			     unformat_vnet_sw_interface, vnm, &sw_if_index))
	    behavior = SR_BEHAVIOR_DX2;
	  else if (unformat (input, "end.dt6 %u", &sw_if_index))
	    behavior = SR_BEHAVIOR_DT6;
	  else if (unformat (input, "end.dt4 %u", &sw_if_index))
	    behavior = SR_BEHAVIOR_DT4;
	  else if (unformat (input, "un %u", &usid_size))
	    behavior = SR_BEHAVIOR_END_UN_PERF;
	  else if (unformat (input, "un.flex %u", &usid_size))
	    behavior = SR_BEHAVIOR_END_UN;
	  else
	    {
	      /* Loop over all the plugin behavior format functions */
	      sr_localsid_fn_registration_t *plugin = 0, **vec_plugins = 0;
	      sr_localsid_fn_registration_t **plugin_it = 0;

	      /* Create a vector out of the plugin pool as recommended */
              /* *INDENT-OFF* */
              pool_foreach (plugin, sm->plugin_functions,
                {
                  vec_add1 (vec_plugins, plugin);
                });
              /* *INDENT-ON* */

	      vec_foreach (plugin_it, vec_plugins)
	      {
		if (unformat
		    (input, "%U", (*plugin_it)->ls_unformat, &ls_plugin_mem))
		  {
		    behavior = (*plugin_it)->sr_localsid_function_number;
		    break;
		  }
	      }
	    }

	  if (!behavior)
	    {
	      if (unformat (input, "end"))
		behavior = SR_BEHAVIOR_END;
	      else
		break;
	    }
	}
      else if (!end_psp && unformat (input, "psp"))
	end_psp = 1;
      else
	break;
    }

  if (!behavior && end_psp)
    behavior = SR_BEHAVIOR_END;

  if (usid_size)
    {
      if (prefix_len < usid_size)
	return clib_error_return (0,
				  "Error: Prefix length must be greater"
				  " than uSID length.");

      if (usid_size != 16 && usid_size != 32)
	return clib_error_return (0,
				  "Error: Invalid uSID length (16 or 32).");

      if ((prefix_len - usid_size) & 0x7)
	return clib_error_return (0,
				  "Error: Prefix Length must be multiple of 8.");
    }

  if (!address_set)
    return clib_error_return (0,
			      "Error: SRv6 LocalSID address is mandatory.");
  if (!is_del && !behavior)
    return clib_error_return (0,
			      "Error: SRv6 LocalSID behavior is mandatory.");
  if (vlan_index != (u32) ~ 0)
    return clib_error_return (0,
			      "Error: SRv6 End.DX2 with rewrite VLAN tag not supported by now.");
  if (end_psp && !(behavior == SR_BEHAVIOR_END || behavior == SR_BEHAVIOR_X))
    return clib_error_return (0,
			      "Error: SRv6 PSP only compatible with End and End.X");

  rv =
    sr_cli_localsid (is_del, &resulting_address, prefix_len, end_psp,
		     behavior, sw_if_index, vlan_index, fib_index, &next_hop,
		     usid_size, ls_plugin_mem);

  if (behavior == SR_BEHAVIOR_END_UN_PERF)
    {
      if (rv == 0)
	{
	  u16 perf_len;
	  perf_len = prefix_len + usid_size;
	  rv = sr_cli_localsid (is_del, &resulting_address, perf_len, end_psp,
				SR_BEHAVIOR_END, sw_if_index, vlan_index,
				fib_index, &next_hop, 0, ls_plugin_mem);
	}
    }

  switch (rv)
    {
    case 0:
      break;
    case 1:
      return 0;
    case -1:
      return clib_error_return (0,
				"Identical localsid already exists. Requested localsid not created.");
    case -2:
      return clib_error_return (0,
				"The requested localsid could not be deleted. SR localsid not found");
    case -3:
      return clib_error_return (0, "FIB table %u does not exist", fib_index);
    case -4:
      return clib_error_return (0, "There is already one FIB entry for the"
				"requested localsid non segment routing related");
    case -5:
      return clib_error_return (0,
				"Could not create ARP/ND entry for such next_hop. Internal error.");
    case -6:
      return clib_error_return (0,
				"Error on the plugin based localsid creation.");
    default:
      return clib_error_return (0, "BUG: sr localsid returns %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (sr_localsid_command, static) = {
  .path = "sr localsid",
  .short_help = "sr localsid (del) address XX:XX::YY:YY"
      "(fib-table 8) behavior STRING",
  .long_help =
    "Create SR LocalSID and binds it to a particular behavior\n"
    "Arguments:\n"
    "\tlocalSID IPv6_addr(128b)   LocalSID IPv6 address\n"
    "\t(fib-table X)              Optional. VRF where to install SRv6 localsid\n"
    "\tbehavior STRING            Specifies the behavior\n"
    "\n\tBehaviors:\n"
    "\tEnd\t-> Endpoint.\n"
    "\tEnd.uN\t-> Endpoint with uSID.\n"
    "\tEnd.X\t-> Endpoint with decapsulation and Layer-3 cross-connect.\n"
    "\t\tParameters: '<iface> <ip6_next_hop>'\n"
    "\tEnd.DX2\t-> Endpoint with decapsulation and Layer-2 cross-connect.\n"
    "\t\tParameters: '<iface>'\n"
    "\tEnd.DX6\t-> Endpoint with decapsulation and IPv6 cross-connect.\n"
    "\t\tParameters: '<iface> <ip6_next_hop>'\n"
    "\tEnd.DX4\t-> Endpoint with decapsulation and IPv4 cross-connect.\n"
    "\t\tParameters: '<iface> <ip4_next_hop>'\n"
    "\tEnd.DT6\t-> Endpoint with decapsulation and specific IPv6 table lookup.\n"
    "\t\tParameters: '<ip6_fib_table>'\n"
    "\tEnd.DT4\t-> Endpoint with decapsulation and specific IPv4 table lookup.\n"
    "\t\tParameters: '<ip4_fib_table>'\n",
  .function = sr_cli_localsid_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief CLI function to 'show' all SR LocalSIDs on console.
 */
static clib_error_t *
show_sr_localsid_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_localsid_t **localsid_list = 0;
  ip6_sr_localsid_t *ls;
  int i;

  vlib_cli_output (vm, "SRv6 - My LocalSID Table:");
  vlib_cli_output (vm, "=========================");
  /* *INDENT-OFF* */
  pool_foreach (ls, sm->localsids, ({ vec_add1 (localsid_list, ls); }));
  /* *INDENT-ON* */
  for (i = 0; i < vec_len (localsid_list); i++)
    {
      ls = localsid_list[i];
      switch (ls->behavior)
	{
	case SR_BEHAVIOR_END:
	  vlib_cli_output (vm, "\tAddress: \t%U\n\tBehavior: \tEnd",
			   format_ip6_address, &ls->localsid);
	  break;
	case SR_BEHAVIOR_END_UN:
	  vlib_cli_output (vm,
			   "\tAddress: \t%U\n\tBehavior: \tEnd (flex) [uSID:\t%U/%d, length: %d]",
			   format_ip6_address, &ls->localsid,
			   format_ip6_address, &ls->usid_block,
			   ls->usid_index * 8, ls->usid_len * 8);
	  break;
	case SR_BEHAVIOR_END_UN_PERF:
	  vlib_cli_output (vm,
			   "\tAddress: \t%U\n\tBehavior: \tEnd [uSID:\t%U/%d, length: %d]",
			   format_ip6_address, &ls->localsid,
			   format_ip6_address, &ls->usid_block,
			   ls->usid_index * 8, ls->usid_len * 8);
	  break;
	case SR_BEHAVIOR_X:
	  vlib_cli_output (vm,
			   "\tAddress: \t%U/%u\n\tBehavior: \tX (Endpoint with Layer-3 cross-connect)"
			   "\n\tIface:  \t%U\n\tNext hop: \t%U",
			   format_ip6_address, &ls->localsid,
			   ls->localsid_prefix_len,
			   format_vnet_sw_if_index_name, vnm, ls->sw_if_index,
			   format_ip6_address, &ls->next_hop.ip6);
	  break;
	case SR_BEHAVIOR_T:
	  vlib_cli_output (vm,
			   "\tAddress: \t%U/%u\n\tBehavior: \tT (Endpoint with specific IPv6 table lookup)"
			   "\n\tTable:  \t%u",
			   format_ip6_address, &ls->localsid,
			   ls->localsid_prefix_len,
			   fib_table_get_table_id (ls->vrf_index,
						   FIB_PROTOCOL_IP6));
	  break;
	case SR_BEHAVIOR_DX4:
	  vlib_cli_output (vm,
			   "\tAddress: \t%U/%u\n\tBehavior: \tDX4 (Endpoint with decapsulation and IPv4 cross-connect)"
			   "\n\tIface:  \t%U\n\tNext hop: \t%U",
			   format_ip6_address, &ls->localsid,
			   ls->localsid_prefix_len,
			   format_vnet_sw_if_index_name, vnm, ls->sw_if_index,
			   format_ip4_address, &ls->next_hop.ip4);
	  break;
	case SR_BEHAVIOR_DX6:
	  vlib_cli_output (vm,
			   "\tAddress: \t%U/%u\n\tBehavior: \tDX6 (Endpoint with decapsulation and IPv6 cross-connect)"
			   "\n\tIface:  \t%U\n\tNext hop: \t%U",
			   format_ip6_address, &ls->localsid,
			   ls->localsid_prefix_len,
			   format_vnet_sw_if_index_name, vnm, ls->sw_if_index,
			   format_ip6_address, &ls->next_hop.ip6);
	  break;
	case SR_BEHAVIOR_DX2:
	  if (ls->vlan_index == (u32) ~ 0)
	    vlib_cli_output (vm,
			     "\tAddress: \t%U/%u\n\tBehavior: \tDX2 (Endpoint with decapulation and Layer-2 cross-connect)"
			     "\n\tIface:  \t%U", format_ip6_address,
			     &ls->localsid, ls->localsid_prefix_len,
			     format_vnet_sw_if_index_name, vnm,
			     ls->sw_if_index);
	  else
	    vlib_cli_output (vm,
			     "Unsupported yet. (DX2 with egress VLAN rewrite)");
	  break;
	case SR_BEHAVIOR_DT6:
	  vlib_cli_output (vm,
			   "\tAddress: \t%U/%u\n\tBehavior: \tDT6 (Endpoint with decapsulation and specific IPv6 table lookup)"
			   "\n\tTable: %u", format_ip6_address, &ls->localsid,
			   ls->localsid_prefix_len,
			   fib_table_get_table_id (ls->vrf_index,
						   FIB_PROTOCOL_IP6));
	  break;
	case SR_BEHAVIOR_DT4:
	  vlib_cli_output (vm,
			   "\tAddress: \t%U/%u\n\tBehavior: \tDT4 (Endpoint with decapsulation and specific IPv4 table lookup)"
			   "\n\tTable: \t%u", format_ip6_address,
			   &ls->localsid, ls->localsid_prefix_len,
			   fib_table_get_table_id (ls->vrf_index,
						   FIB_PROTOCOL_IP4));
	  break;
	default:
	  if (ls->behavior >= SR_BEHAVIOR_LAST)
	    {
	      sr_localsid_fn_registration_t *plugin =
		pool_elt_at_index (sm->plugin_functions,
				   ls->behavior - SR_BEHAVIOR_LAST);

	      vlib_cli_output (vm, "\tAddress: \t%U/%u\n"
			       "\tBehavior: \t%s (%s)\n\t%U",
			       format_ip6_address, &ls->localsid,
			       ls->localsid_prefix_len, plugin->keyword_str,
			       plugin->def_str, plugin->ls_format,
			       ls->plugin_mem);
	    }
	  else
	    //Should never get here...
	    vlib_cli_output (vm, "Internal error");
	  break;
	}
      if (ls->end_psp)
	vlib_cli_output (vm, "\tPSP: \tTrue\n");

      /* Print counters */
      vlib_counter_t valid, invalid;
      vlib_get_combined_counter (&(sm->sr_ls_valid_counters), i, &valid);
      vlib_get_combined_counter (&(sm->sr_ls_invalid_counters), i, &invalid);
      vlib_cli_output (vm, "\tGood traffic: \t[%Ld packets : %Ld bytes]\n",
		       valid.packets, valid.bytes);
      vlib_cli_output (vm, "\tBad traffic:  \t[%Ld packets : %Ld bytes]\n",
		       invalid.packets, invalid.bytes);
      vlib_cli_output (vm, "--------------------");
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_sr_localsid_command, static) = {
  .path = "show sr localsids",
  .short_help = "show sr localsids",
  .function = show_sr_localsid_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief Function to 'clear' ALL SR localsid counters
 */
static clib_error_t *
clear_sr_localsid_counters_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  ip6_sr_main_t *sm = &sr_main;

  vlib_clear_combined_counters (&(sm->sr_ls_valid_counters));
  vlib_clear_combined_counters (&(sm->sr_ls_invalid_counters));

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_sr_localsid_counters_command, static) = {
  .path = "clear sr localsid-counters",
  .short_help = "clear sr localsid-counters",
  .function = clear_sr_localsid_counters_command_fn,
};
/* *INDENT-ON* */

/************************ SR LocalSID graphs node ****************************/
/**
 * @brief SR localsid node trace
 */
typedef struct
{
  ip6_address_t localsid;
  u16 behavior;
  u8 sr[256];
  u8 num_segments;
  u8 segments_left;
} sr_localsid_trace_t;

#define foreach_sr_localsid_error                                   \
_(NO_INNER_HEADER, "(SR-Error) No inner IP header")                 \
_(NO_MORE_SEGMENTS, "(SR-Error) No more segments")                  \
_(NO_SRH, "(SR-Error) No SR header")                                \
_(NO_PSP, "(SR-Error) PSP Not available (segments left > 0)")       \
_(NOT_LS, "(SR-Error) Decaps not available (segments left > 0)")    \
_(L2, "(SR-Error) SRv6 decapsulated a L2 frame without dest")

typedef enum
{
#define _(sym,str) SR_LOCALSID_ERROR_##sym,
  foreach_sr_localsid_error
#undef _
    SR_LOCALSID_N_ERROR,
} sr_localsid_error_t;

static char *sr_localsid_error_strings[] = {
#define _(sym,string) string,
  foreach_sr_localsid_error
#undef _
};

#define foreach_sr_localsid_next        \
_(ERROR, "error-drop")                  \
_(IP6_LOOKUP, "ip6-lookup")             \
_(IP4_LOOKUP, "ip4-lookup")             \
_(IP6_REWRITE, "ip6-rewrite")           \
_(IP4_REWRITE, "ip4-rewrite")           \
_(INTERFACE_OUTPUT, "interface-output")

typedef enum
{
#define _(s,n) SR_LOCALSID_NEXT_##s,
  foreach_sr_localsid_next
#undef _
    SR_LOCALSID_N_NEXT,
} sr_localsid_next_t;

/**
 * @brief SR LocalSID graph node trace function
 *
 * @see sr_localsid
 */
u8 *
format_sr_localsid_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sr_localsid_trace_t *t = va_arg (*args, sr_localsid_trace_t *);

  s =
    format (s, "SR-LOCALSID:\n\tLocalsid: %U\n", format_ip6_address,
	    &t->localsid);
  switch (t->behavior)
    {
    case SR_BEHAVIOR_END:
      s = format (s, "\tBehavior: End\n");
      break;
    case SR_BEHAVIOR_END_UN:
      s = format (s, "\tBehavior: End.uN (flex)\n");
      break;
    case SR_BEHAVIOR_END_UN_PERF:
      s = format (s, "\tBehavior: End.uN\n");
      break;
    case SR_BEHAVIOR_DX6:
      s = format (s, "\tBehavior: Decapsulation with IPv6 L3 xconnect\n");
      break;
    case SR_BEHAVIOR_DX4:
      s = format (s, "\tBehavior: Decapsulation with IPv4 L3 xconnect\n");
      break;
    case SR_BEHAVIOR_X:
      s = format (s, "\tBehavior: IPv6 L3 xconnect\n");
      break;
    case SR_BEHAVIOR_T:
      s = format (s, "\tBehavior: IPv6 specific table lookup\n");
      break;
    case SR_BEHAVIOR_DT6:
      s = format (s, "\tBehavior: Decapsulation with IPv6 Table lookup\n");
      break;
    case SR_BEHAVIOR_DT4:
      s = format (s, "\tBehavior: Decapsulation with IPv4 Table lookup\n");
      break;
    case SR_BEHAVIOR_DX2:
      s = format (s, "\tBehavior: Decapsulation with L2 xconnect\n");
      break;
    default:
      s = format (s, "\tBehavior: defined in plugin\n");	//TODO
      break;
    }
  if (t->num_segments != 0xFF)
    {
      if (t->num_segments > 0)
	{
	  s = format (s, "\tSegments left: %d\n", t->segments_left);
	  s = format (s, "\tSID list: [in ietf order]");
	  int i = 0;
	  for (i = 0; i < t->num_segments; i++)
	    {
	      s = format (s, "\n\t-> %U", format_ip6_address,
			  (ip6_address_t *) & t->sr[i *
						    sizeof (ip6_address_t)]);
	    }
	}
    }
  return s;
}

/**
 * @brief Function doing End processing.
 */
static_always_inline void
end_srh_processing (vlib_node_runtime_t * node,
		    vlib_buffer_t * b0,
		    ip6_header_t * ip0,
		    ip6_sr_header_t * sr0,
		    ip6_sr_localsid_t * ls0,
		    u32 * next0, u8 psp, ip6_ext_header_t * prev0)
{
  ip6_address_t *new_dst0;

  if (PREDICT_TRUE (sr0 && sr0->type == ROUTING_HEADER_TYPE_SR))
    {
      if (sr0->segments_left == 1 && psp)
	{
	  u32 new_l0, sr_len;
	  u64 *copy_dst0, *copy_src0;
	  u32 copy_len_u64s0 = 0;

	  ip0->dst_address.as_u64[0] = sr0->segments->as_u64[0];
	  ip0->dst_address.as_u64[1] = sr0->segments->as_u64[1];

	  /* Remove the SRH taking care of the rest of IPv6 ext header */
	  if (prev0)
	    prev0->next_hdr = sr0->protocol;
	  else
	    ip0->protocol = sr0->protocol;

	  sr_len = ip6_ext_header_len (sr0);
	  vlib_buffer_advance (b0, sr_len);
	  new_l0 = clib_net_to_host_u16 (ip0->payload_length) - sr_len;
	  ip0->payload_length = clib_host_to_net_u16 (new_l0);
	  copy_src0 = (u64 *) ip0;
	  copy_dst0 = copy_src0 + (sr0->length + 1);
	  /* number of 8 octet units to copy
	   * By default in absence of extension headers it is equal to length of ip6 header
	   * With extension headers it number of 8 octet units of ext headers preceding
	   * SR header
	   */
	  copy_len_u64s0 =
	    (((u8 *) sr0 - (u8 *) ip0) - sizeof (ip6_header_t)) >> 3;
	  copy_dst0[4 + copy_len_u64s0] = copy_src0[4 + copy_len_u64s0];
	  copy_dst0[3 + copy_len_u64s0] = copy_src0[3 + copy_len_u64s0];
	  copy_dst0[2 + copy_len_u64s0] = copy_src0[2 + copy_len_u64s0];
	  copy_dst0[1 + copy_len_u64s0] = copy_src0[1 + copy_len_u64s0];
	  copy_dst0[0 + copy_len_u64s0] = copy_src0[0 + copy_len_u64s0];

	  int i;
	  for (i = copy_len_u64s0 - 1; i >= 0; i--)
	    {
	      copy_dst0[i] = copy_src0[i];
	    }

	  if (ls0->behavior == SR_BEHAVIOR_X)
	    {
	      vnet_buffer (b0)->ip.adj_index = ls0->nh_adj;
	      *next0 = SR_LOCALSID_NEXT_IP6_REWRITE;
	    }
	  else if (ls0->behavior == SR_BEHAVIOR_T)
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = ls0->vrf_index;
	    }
	}
      else if (PREDICT_TRUE (sr0->segments_left > 0))
	{
	  sr0->segments_left -= 1;
	  new_dst0 = (ip6_address_t *) (sr0->segments);
	  new_dst0 += sr0->segments_left;
	  ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
	  ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];

	  if (ls0->behavior == SR_BEHAVIOR_X)
	    {
	      vnet_buffer (b0)->ip.adj_index = ls0->nh_adj;
	      *next0 = SR_LOCALSID_NEXT_IP6_REWRITE;
	    }
	  else if (ls0->behavior == SR_BEHAVIOR_T)
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = ls0->vrf_index;
	    }
	}
      else
	{
	  *next0 = SR_LOCALSID_NEXT_ERROR;
	  b0->error = node->errors[SR_LOCALSID_ERROR_NO_MORE_SEGMENTS];
	}
    }
  else
    {
      /* Error. Routing header of type != SR */
      *next0 = SR_LOCALSID_NEXT_ERROR;
      b0->error = node->errors[SR_LOCALSID_ERROR_NO_SRH];
    }
}

/**
 * @brief Function doing End uN processing.
 */
static_always_inline void
end_un_srh_processing (vlib_node_runtime_t * node,
		       vlib_buffer_t * b0,
		       ip6_header_t * ip0,
		       ip6_sr_header_t * sr0,
		       ip6_sr_localsid_t * ls0,
		       u32 * next0, u8 psp, ip6_ext_header_t * prev0)
{
  ip6_address_t *new_dst0;
  bool next_usid = false;
  u8 next_usid_index;
  u8 usid_len;
  u8 index;

  usid_len = ls0->usid_len;
  next_usid_index = ls0->usid_next_index;

  /* uSID */
  for (index = 0; index < usid_len; index++)
    {
      if (ip0->dst_address.as_u8[next_usid_index + index] != 0)
	{
	  next_usid = true;
	  break;
	}
    }

  if (PREDICT_TRUE (next_usid))
    {
      u8 offset;

      index = ls0->usid_index;

      /* advance next usid */
      for (offset = 0; offset < ls0->usid_next_len; offset++)
	{
	  ip0->dst_address.as_u8[index + offset] =
	    ip0->dst_address.as_u8[next_usid_index + offset];
	}

      for (index = 16 - usid_len; index < 16; index++)
	{
	  ip0->dst_address.as_u8[index] = 0;
	}

      return;
    }

  if (PREDICT_TRUE (sr0 && sr0->type == ROUTING_HEADER_TYPE_SR))
    {
      if (sr0->segments_left == 1 && psp)
	{
	  u32 new_l0, sr_len;
	  u64 *copy_dst0, *copy_src0;
	  u32 copy_len_u64s0 = 0;

	  ip0->dst_address.as_u64[0] = sr0->segments->as_u64[0];
	  ip0->dst_address.as_u64[1] = sr0->segments->as_u64[1];

	  /* Remove the SRH taking care of the rest of IPv6 ext header */
	  if (prev0)
	    prev0->next_hdr = sr0->protocol;
	  else
	    ip0->protocol = sr0->protocol;

	  sr_len = ip6_ext_header_len (sr0);
	  vlib_buffer_advance (b0, sr_len);
	  new_l0 = clib_net_to_host_u16 (ip0->payload_length) - sr_len;
	  ip0->payload_length = clib_host_to_net_u16 (new_l0);
	  copy_src0 = (u64 *) ip0;
	  copy_dst0 = copy_src0 + (sr0->length + 1);
	  /* number of 8 octet units to copy
	   * By default in absence of extension headers it is equal to length of ip6 header
	   * With extension headers it number of 8 octet units of ext headers preceding
	   * SR header
	   */
	  copy_len_u64s0 =
	    (((u8 *) sr0 - (u8 *) ip0) - sizeof (ip6_header_t)) >> 3;
	  copy_dst0[4 + copy_len_u64s0] = copy_src0[4 + copy_len_u64s0];
	  copy_dst0[3 + copy_len_u64s0] = copy_src0[3 + copy_len_u64s0];
	  copy_dst0[2 + copy_len_u64s0] = copy_src0[2 + copy_len_u64s0];
	  copy_dst0[1 + copy_len_u64s0] = copy_src0[1 + copy_len_u64s0];
	  copy_dst0[0 + copy_len_u64s0] = copy_src0[0 + copy_len_u64s0];

	  int i;
	  for (i = copy_len_u64s0 - 1; i >= 0; i--)
	    {
	      copy_dst0[i] = copy_src0[i];
	    }
	}
      else if (PREDICT_TRUE (sr0->segments_left > 0))
	{
	  sr0->segments_left -= 1;
	  new_dst0 = (ip6_address_t *) (sr0->segments);
	  new_dst0 += sr0->segments_left;
	  ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
	  ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];
	}
      else
	{
	  *next0 = SR_LOCALSID_NEXT_ERROR;
	  b0->error = node->errors[SR_LOCALSID_ERROR_NO_MORE_SEGMENTS];
	}
    }
  else
    {
      /* Error. Routing header of type != SR */
      *next0 = SR_LOCALSID_NEXT_ERROR;
      b0->error = node->errors[SR_LOCALSID_ERROR_NO_SRH];
    }
}

static_always_inline void
end_un_processing (ip6_header_t * ip0, ip6_sr_localsid_t * ls0)
{
  u8 next_usid_index;
  u8 index;
  u8 offset;

  /* uSID */
  index = ls0->usid_index;
  next_usid_index = ls0->usid_next_index;

  /* advance next usid */
  for (offset = 0; offset < ls0->usid_next_len; offset++)
    {
      ip0->dst_address.as_u8[index + offset] =
	ip0->dst_address.as_u8[next_usid_index + offset];
    }

  for (index = 16 - ls0->usid_len; index < 16; index++)
    {
      ip0->dst_address.as_u8[index] = 0;
    }

  return;
}

/*
 * @brief Function doing SRH processing for D* variants
 */
static_always_inline void
end_decaps_srh_processing (vlib_node_runtime_t * node,
			   vlib_buffer_t * b0,
			   ip6_header_t * ip0,
			   ip6_sr_header_t * sr0,
			   ip6_sr_localsid_t * ls0, u32 * next0)
{
  /* Compute the size of the IPv6 header with all Ext. headers */
  u8 next_proto;
  ip6_ext_header_t *next_ext_header;
  u16 total_size = 0;

  next_proto = ip0->protocol;
  next_ext_header = (void *) (ip0 + 1);
  total_size = sizeof (ip6_header_t);
  while (ip6_ext_hdr (next_proto))
    {
      total_size += ip6_ext_header_len (next_ext_header);
      next_proto = next_ext_header->next_hdr;
      next_ext_header = ip6_ext_next_header (next_ext_header);
    }

  /* Ensure this is the last segment. Otherwise drop. */
  if (sr0 && sr0->segments_left != 0)
    {
      *next0 = SR_LOCALSID_NEXT_ERROR;
      b0->error = node->errors[SR_LOCALSID_ERROR_NOT_LS];
      return;
    }

  switch (next_proto)
    {
    case IP_PROTOCOL_IPV6:
      /* Encap-End IPv6. Pop outer IPv6 header. */
      if (ls0->behavior == SR_BEHAVIOR_DX6)
	{
	  vlib_buffer_advance (b0, total_size);
	  vnet_buffer (b0)->ip.adj_index = ls0->nh_adj;
	  *next0 = SR_LOCALSID_NEXT_IP6_REWRITE;
	  return;
	}
      else if (ls0->behavior == SR_BEHAVIOR_DT6)
	{
	  vlib_buffer_advance (b0, total_size);
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ls0->vrf_index;
	  return;
	}
      break;
    case IP_PROTOCOL_IP_IN_IP:
      /* Encap-End IPv4. Pop outer IPv6 header */
      if (ls0->behavior == SR_BEHAVIOR_DX4)
	{
	  vlib_buffer_advance (b0, total_size);
	  vnet_buffer (b0)->ip.adj_index = ls0->nh_adj;
	  *next0 = SR_LOCALSID_NEXT_IP4_REWRITE;
	  return;
	}
      else if (ls0->behavior == SR_BEHAVIOR_DT4)
	{
	  vlib_buffer_advance (b0, total_size);
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ls0->vrf_index;
	  *next0 = SR_LOCALSID_NEXT_IP4_LOOKUP;
	  return;
	}
      break;
    case IP_PROTOCOL_IP6_ETHERNET:
      /* L2 encaps */
      if (ls0->behavior == SR_BEHAVIOR_DX2)
	{
	  vlib_buffer_advance (b0, total_size);
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ls0->sw_if_index;
	  *next0 = SR_LOCALSID_NEXT_INTERFACE_OUTPUT;
	  return;
	}
      break;
    }
  *next0 = SR_LOCALSID_NEXT_ERROR;
  b0->error = node->errors[SR_LOCALSID_ERROR_NO_INNER_HEADER];
  return;
}

/**
 * @brief SR LocalSID graph node. Supports all default SR Endpoint variants with decaps
 */
static uword
sr_localsid_d_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  ip6_sr_main_t *sm = &sr_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;
  u32 thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Quad - Loop */
      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  ip6_header_t *ip0, *ip1, *ip2, *ip3;
	  ip6_sr_header_t *sr0, *sr1, *sr2, *sr3;
	  u32 next0, next1, next2, next3;
	  next0 = next1 = next2 = next3 = SR_LOCALSID_NEXT_IP6_LOOKUP;
	  ip6_sr_localsid_t *ls0, *ls1, *ls2, *ls3;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p4, *p5, *p6, *p7;

	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
	    p6 = vlib_get_buffer (vm, from[6]);
	    p7 = vlib_get_buffer (vm, from[7]);

	    /* Prefetch the buffer header and packet for the N+4 loop iteration */
	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_header (p6, LOAD);
	    vlib_prefetch_buffer_header (p7, LOAD);

	    CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next[2] = bi2 = from[2];
	  to_next[3] = bi3 = from[3];
	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  ls0 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b0)->ip.adj_index);
	  ls1 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b1)->ip.adj_index);
	  ls2 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b2)->ip.adj_index);
	  ls3 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b3)->ip.adj_index);

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  ip2 = vlib_buffer_get_current (b2);
	  ip3 = vlib_buffer_get_current (b3);

	  sr0 =
	    ip6_ext_header_find (vm, b0, ip0, IP_PROTOCOL_IPV6_ROUTE, NULL);
	  sr1 =
	    ip6_ext_header_find (vm, b1, ip1, IP_PROTOCOL_IPV6_ROUTE, NULL);
	  sr2 =
	    ip6_ext_header_find (vm, b2, ip2, IP_PROTOCOL_IPV6_ROUTE, NULL);
	  sr3 =
	    ip6_ext_header_find (vm, b3, ip3, IP_PROTOCOL_IPV6_ROUTE, NULL);

	  end_decaps_srh_processing (node, b0, ip0, sr0, ls0, &next0);
	  end_decaps_srh_processing (node, b1, ip1, sr1, ls1, &next1);
	  end_decaps_srh_processing (node, b2, ip2, sr2, ls2, &next2);
	  end_decaps_srh_processing (node, b3, ip3, sr3, ls3, &next3);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls0->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls0->behavior;
	      if (ip0 == vlib_buffer_get_current (b0))
		{
		  if (ip0->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr0->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr0->segments, sr0->length * 8);
		      tr->num_segments =
			sr0->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr0->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b1, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls1->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls1->behavior;
	      if (ip1 == vlib_buffer_get_current (b1))
		{
		  if (ip1->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr1->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr1->segments, sr1->length * 8);
		      tr->num_segments =
			sr1->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr1->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b2, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls2->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls2->behavior;
	      if (ip2 == vlib_buffer_get_current (b2))
		{
		  if (ip2->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr2->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr2->segments, sr2->length * 8);
		      tr->num_segments =
			sr2->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr2->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b3, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls3->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls3->behavior;
	      if (ip3 == vlib_buffer_get_current (b3))
		{
		  if (ip3->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr3->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr3->segments, sr3->length * 8);
		      tr->num_segments =
			sr3->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr3->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  vlib_increment_combined_counter
	    (((next0 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls0 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_increment_combined_counter
	    (((next1 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls1 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b1));

	  vlib_increment_combined_counter
	    (((next2 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls2 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b2));

	  vlib_increment_combined_counter
	    (((next3 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls3 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b3));

	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0;
	  ip6_sr_header_t *sr0;
	  u32 next0 = SR_LOCALSID_NEXT_IP6_LOOKUP;
	  ip6_sr_localsid_t *ls0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);

	  /* Lookup the SR End behavior based on IP DA (adj) */
	  ls0 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b0)->ip.adj_index);

	  /* Find SRH as well as previous header */
	  sr0 =
	    ip6_ext_header_find (vm, b0, ip0, IP_PROTOCOL_IPV6_ROUTE, NULL);

	  /* SRH processing and End variants */
	  end_decaps_srh_processing (node, b0, ip0, sr0, ls0, &next0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls0->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls0->behavior;
	      if (ip0 == vlib_buffer_get_current (b0))
		{
		  if (ip0->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr0->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr0->segments, sr0->length * 8);
		      tr->num_segments =
			sr0->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr0->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  /* Increase the counters */
	  vlib_increment_combined_counter
	    (((next0 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls0 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_localsid_d_node) = {
  .function = sr_localsid_d_fn,
  .name = "sr-localsid-d",
  .vector_size = sizeof (u32),
  .format_trace = format_sr_localsid_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SR_LOCALSID_N_ERROR,
  .error_strings = sr_localsid_error_strings,
  .n_next_nodes = SR_LOCALSID_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_LOCALSID_NEXT_##s] = n,
    foreach_sr_localsid_next
#undef _
  },
};
/* *INDENT-ON* */

/**
 * @brief SR LocalSID graph node. Supports all default SR Endpoint without decaps
 */
static uword
sr_localsid_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  ip6_sr_main_t *sm = &sr_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;
  u32 thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Quad - Loop */
      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  ip6_header_t *ip0, *ip1, *ip2, *ip3;
	  ip6_sr_header_t *sr0, *sr1, *sr2, *sr3;
	  ip6_ext_header_t *prev0, *prev1, *prev2, *prev3;
	  u32 next0, next1, next2, next3;
	  next0 = next1 = next2 = next3 = SR_LOCALSID_NEXT_IP6_LOOKUP;
	  ip6_sr_localsid_t *ls0, *ls1, *ls2, *ls3;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p4, *p5, *p6, *p7;

	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
	    p6 = vlib_get_buffer (vm, from[6]);
	    p7 = vlib_get_buffer (vm, from[7]);

	    /* Prefetch the buffer header and packet for the N+2 loop iteration */
	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_header (p6, LOAD);
	    vlib_prefetch_buffer_header (p7, LOAD);

	    CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next[2] = bi2 = from[2];
	  to_next[3] = bi3 = from[3];
	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  ip2 = vlib_buffer_get_current (b2);
	  ip3 = vlib_buffer_get_current (b3);

	  sr0 =
	    ip6_ext_header_find (vm, b0, ip0, IP_PROTOCOL_IPV6_ROUTE, &prev0);
	  sr1 =
	    ip6_ext_header_find (vm, b1, ip1, IP_PROTOCOL_IPV6_ROUTE, &prev1);
	  sr2 =
	    ip6_ext_header_find (vm, b2, ip2, IP_PROTOCOL_IPV6_ROUTE, &prev2);
	  sr3 =
	    ip6_ext_header_find (vm, b3, ip3, IP_PROTOCOL_IPV6_ROUTE, &prev3);

	  ls0 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b0)->ip.adj_index);
	  ls1 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b1)->ip.adj_index);
	  ls2 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b2)->ip.adj_index);
	  ls3 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b3)->ip.adj_index);

	  end_srh_processing (node, b0, ip0, sr0, ls0, &next0, ls0->end_psp,
			      prev0);
	  end_srh_processing (node, b1, ip1, sr1, ls1, &next1, ls1->end_psp,
			      prev1);
	  end_srh_processing (node, b2, ip2, sr2, ls2, &next2, ls2->end_psp,
			      prev2);
	  end_srh_processing (node, b3, ip3, sr3, ls3, &next3, ls3->end_psp,
			      prev3);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls0->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls0->behavior;
	      if (ip0 == vlib_buffer_get_current (b0))
		{
		  if (ip0->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr0->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr0->segments, sr0->length * 8);
		      tr->num_segments =
			sr0->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr0->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b1, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls1->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls1->behavior;
	      if (ip1 == vlib_buffer_get_current (b1))
		{
		  if (ip1->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr1->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr1->segments, sr1->length * 8);
		      tr->num_segments =
			sr1->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr1->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b2, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls2->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls2->behavior;
	      if (ip2 == vlib_buffer_get_current (b2))
		{
		  if (ip2->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr2->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr2->segments, sr2->length * 8);
		      tr->num_segments =
			sr2->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr2->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b3, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls3->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls3->behavior;
	      if (ip3 == vlib_buffer_get_current (b3))
		{
		  if (ip3->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr3->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr3->segments, sr3->length * 8);
		      tr->num_segments =
			sr3->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr3->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  vlib_increment_combined_counter
	    (((next0 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls0 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_increment_combined_counter
	    (((next1 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls1 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b1));

	  vlib_increment_combined_counter
	    (((next2 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls2 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b2));

	  vlib_increment_combined_counter
	    (((next3 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls3 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b3));

	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip6_ext_header_t *prev0;
	  ip6_sr_header_t *sr0;
	  u32 next0 = SR_LOCALSID_NEXT_IP6_LOOKUP;
	  ip6_sr_localsid_t *ls0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  sr0 =
	    ip6_ext_header_find (vm, b0, ip0, IP_PROTOCOL_IPV6_ROUTE, &prev0);

	  /* Lookup the SR End behavior based on IP DA (adj) */
	  ls0 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b0)->ip.adj_index);

	  /* SRH processing */
	  end_srh_processing (node, b0, ip0, sr0, ls0, &next0, ls0->end_psp,
			      prev0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls0->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls0->behavior;
	      if (ip0 == vlib_buffer_get_current (b0))
		{
		  if (ip0->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr0->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr0->segments, sr0->length * 8);
		      tr->num_segments =
			sr0->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr0->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  vlib_increment_combined_counter
	    (((next0 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls0 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_localsid_node) = {
  .function = sr_localsid_fn,
  .name = "sr-localsid",
  .vector_size = sizeof (u32),
  .format_trace = format_sr_localsid_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SR_LOCALSID_N_ERROR,
  .error_strings = sr_localsid_error_strings,
  .n_next_nodes = SR_LOCALSID_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_LOCALSID_NEXT_##s] = n,
    foreach_sr_localsid_next
#undef _
  },
};
/* *INDENT-ON* */

/**
 * @brief SR LocalSID uN graph node. Supports all default SR Endpoint without decaps
 */
static uword
sr_localsid_un_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  ip6_sr_main_t *sm = &sr_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;
  u32 thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Quad - Loop */
      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  ip6_header_t *ip0, *ip1, *ip2, *ip3;
	  ip6_sr_header_t *sr0, *sr1, *sr2, *sr3;
	  ip6_ext_header_t *prev0, *prev1, *prev2, *prev3;
	  u32 next0, next1, next2, next3;
	  next0 = next1 = next2 = next3 = SR_LOCALSID_NEXT_IP6_LOOKUP;
	  ip6_sr_localsid_t *ls0, *ls1, *ls2, *ls3;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p4, *p5, *p6, *p7;

	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
	    p6 = vlib_get_buffer (vm, from[6]);
	    p7 = vlib_get_buffer (vm, from[7]);

	    /* Prefetch the buffer header and packet for the N+2 loop iteration */
	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_header (p6, LOAD);
	    vlib_prefetch_buffer_header (p7, LOAD);

	    CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next[2] = bi2 = from[2];
	  to_next[3] = bi3 = from[3];
	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  ip2 = vlib_buffer_get_current (b2);
	  ip3 = vlib_buffer_get_current (b3);

	  sr0 =
	    ip6_ext_header_find (vm, b0, ip0, IP_PROTOCOL_IPV6_ROUTE, &prev0);
	  sr1 =
	    ip6_ext_header_find (vm, b1, ip1, IP_PROTOCOL_IPV6_ROUTE, &prev1);
	  sr2 =
	    ip6_ext_header_find (vm, b2, ip2, IP_PROTOCOL_IPV6_ROUTE, &prev2);
	  sr3 =
	    ip6_ext_header_find (vm, b3, ip3, IP_PROTOCOL_IPV6_ROUTE, &prev3);

	  ls0 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b0)->ip.adj_index);
	  ls1 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b1)->ip.adj_index);
	  ls2 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b2)->ip.adj_index);
	  ls3 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b3)->ip.adj_index);

	  end_un_srh_processing (node, b0, ip0, sr0, ls0, &next0,
				 ls0->end_psp, prev0);
	  end_un_srh_processing (node, b1, ip1, sr1, ls1, &next1,
				 ls1->end_psp, prev1);
	  end_un_srh_processing (node, b2, ip2, sr2, ls2, &next2,
				 ls2->end_psp, prev2);
	  end_un_srh_processing (node, b3, ip3, sr3, ls3, &next3,
				 ls3->end_psp, prev3);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls0->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls0->behavior;
	      if (ip0 == vlib_buffer_get_current (b0))
		{
		  if (ip0->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr0->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr0->segments, sr0->length * 8);
		      tr->num_segments =
			sr0->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr0->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b1, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls1->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls1->behavior;
	      if (ip1 == vlib_buffer_get_current (b1))
		{
		  if (ip1->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr1->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr1->segments, sr1->length * 8);
		      tr->num_segments =
			sr1->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr1->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b2, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls2->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls2->behavior;
	      if (ip2 == vlib_buffer_get_current (b2))
		{
		  if (ip2->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr2->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr2->segments, sr2->length * 8);
		      tr->num_segments =
			sr2->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr2->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b3, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls3->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls3->behavior;
	      if (ip3 == vlib_buffer_get_current (b3))
		{
		  if (ip3->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr3->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr3->segments, sr3->length * 8);
		      tr->num_segments =
			sr3->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr3->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  vlib_increment_combined_counter
	    (((next0 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls0 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_increment_combined_counter
	    (((next1 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls1 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b1));

	  vlib_increment_combined_counter
	    (((next2 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls2 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b2));

	  vlib_increment_combined_counter
	    (((next3 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls3 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b3));

	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip6_ext_header_t *prev0;
	  ip6_sr_header_t *sr0;
	  u32 next0 = SR_LOCALSID_NEXT_IP6_LOOKUP;
	  ip6_sr_localsid_t *ls0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  sr0 =
	    ip6_ext_header_find (vm, b0, ip0, IP_PROTOCOL_IPV6_ROUTE, &prev0);

	  /* Lookup the SR End behavior based on IP DA (adj) */
	  ls0 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b0)->ip.adj_index);

	  /* SRH processing */
	  end_un_srh_processing (node, b0, ip0, sr0, ls0, &next0,
				 ls0->end_psp, prev0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls0->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls0->behavior;
	      if (ip0 == vlib_buffer_get_current (b0))
		{
		  if (ip0->protocol == IP_PROTOCOL_IPV6_ROUTE
		      && sr0->type == ROUTING_HEADER_TYPE_SR)
		    {
		      clib_memcpy (tr->sr, sr0->segments, sr0->length * 8);
		      tr->num_segments =
			sr0->length * 8 / sizeof (ip6_address_t);
		      tr->segments_left = sr0->segments_left;
		    }
		}
	      else
		tr->num_segments = 0xFF;
	    }

	  vlib_increment_combined_counter
	    (((next0 ==
	       SR_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) :
	      &(sm->sr_ls_valid_counters)), thread_index, ls0 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_localsid_un_node) = {
  .function = sr_localsid_un_fn,
  .name = "sr-localsid-un",
  .vector_size = sizeof (u32),
  .format_trace = format_sr_localsid_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SR_LOCALSID_N_ERROR,
  .error_strings = sr_localsid_error_strings,
  .n_next_nodes = SR_LOCALSID_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_LOCALSID_NEXT_##s] = n,
    foreach_sr_localsid_next
#undef _
  },
};
/* *INDENT-ON* */

static uword
sr_localsid_un_perf_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  ip6_sr_main_t *sm = &sr_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;
  u32 thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Quad - Loop */
      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  ip6_header_t *ip0, *ip1, *ip2, *ip3;
	  u32 next0, next1, next2, next3;
	  next0 = next1 = next2 = next3 = SR_LOCALSID_NEXT_IP6_LOOKUP;
	  ip6_sr_localsid_t *ls0, *ls1, *ls2, *ls3;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p4, *p5, *p6, *p7;

	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
	    p6 = vlib_get_buffer (vm, from[6]);
	    p7 = vlib_get_buffer (vm, from[7]);

	    /* Prefetch the buffer header and packet for the N+2 loop iteration */
	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_header (p6, LOAD);
	    vlib_prefetch_buffer_header (p7, LOAD);

	    CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next[2] = bi2 = from[2];
	  to_next[3] = bi3 = from[3];
	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  ip2 = vlib_buffer_get_current (b2);
	  ip3 = vlib_buffer_get_current (b3);

	  ls0 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b0)->ip.adj_index);
	  ls1 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b1)->ip.adj_index);
	  ls2 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b2)->ip.adj_index);
	  ls3 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b3)->ip.adj_index);

	  end_un_processing (ip0, ls0);
	  end_un_processing (ip1, ls1);
	  end_un_processing (ip2, ls2);
	  end_un_processing (ip3, ls3);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls0->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls0->behavior;
	    }

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b1, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls1->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls1->behavior;
	    }

	  if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b2, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls2->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls2->behavior;
	    }

	  if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b3, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls3->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls3->behavior;
	    }

	  vlib_increment_combined_counter
	    (&(sm->sr_ls_valid_counters), thread_index, ls0 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_increment_combined_counter
	    (&(sm->sr_ls_valid_counters), thread_index, ls1 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b1));

	  vlib_increment_combined_counter
	    (&(sm->sr_ls_valid_counters), thread_index, ls2 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b2));

	  vlib_increment_combined_counter
	    (&(sm->sr_ls_valid_counters), thread_index, ls3 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b3));

	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  u32 next0 = SR_LOCALSID_NEXT_IP6_LOOKUP;
	  ip6_sr_localsid_t *ls0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);

	  /* Lookup the SR End behavior based on IP DA (adj) */
	  ls0 =
	    pool_elt_at_index (sm->localsids, vnet_buffer (b0)->ip.adj_index);

	  /* SRH processing */
	  end_un_processing (ip0, ls0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->num_segments = 0;
	      clib_memcpy (tr->localsid.as_u8, ls0->localsid.as_u8,
			   sizeof (tr->localsid.as_u8));
	      tr->behavior = ls0->behavior;
	    }

	  vlib_increment_combined_counter
	    (&(sm->sr_ls_valid_counters), thread_index, ls0 - sm->localsids,
	     1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_localsid_un_perf_node) = {
  .function = sr_localsid_un_perf_fn,
  .name = "sr-localsid-un-perf",
  .vector_size = sizeof (u32),
  .format_trace = format_sr_localsid_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SR_LOCALSID_N_ERROR,
  .error_strings = sr_localsid_error_strings,
  .n_next_nodes = SR_LOCALSID_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_LOCALSID_NEXT_##s] = n,
    foreach_sr_localsid_next
#undef _
  },
};
/* *INDENT-ON* */

static u8 *
format_sr_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: localsid_index:[%d]", index));
}

const static dpo_vft_t sr_loc_vft = {
  .dv_lock = sr_dpo_lock,
  .dv_unlock = sr_dpo_unlock,
  .dv_format = format_sr_dpo,
};

const static char *const sr_loc_ip6_nodes[] = {
  "sr-localsid",
  NULL,
};

const static char *const *const sr_loc_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = sr_loc_ip6_nodes,
};

const static char *const sr_loc_d_ip6_nodes[] = {
  "sr-localsid-d",
  NULL,
};

const static char *const *const sr_loc_d_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = sr_loc_d_ip6_nodes,
};

const static char *const sr_loc_un_ip6_nodes[] = {
  "sr-localsid-un",
  NULL,
};

const static char *const *const sr_loc_un_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = sr_loc_un_ip6_nodes,
};

const static char *const sr_loc_un_perf_ip6_nodes[] = {
  "sr-localsid-un-perf",
  NULL,
};

const static char *const *const sr_loc_un_perf_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = sr_loc_un_perf_ip6_nodes,
};

/*************************** SR LocalSID plugins ******************************/
/**
 * @brief SR LocalSID plugin registry
 */
int
sr_localsid_register_function (vlib_main_t * vm, u8 * fn_name,
			       u8 * keyword_str, u8 * def_str,
			       u8 * params_str, u8 prefix_length,
			       dpo_type_t * dpo,
			       format_function_t * ls_format,
			       unformat_function_t * ls_unformat,
			       sr_plugin_callback_t * creation_fn,
			       sr_plugin_callback_t * removal_fn)
{
  ip6_sr_main_t *sm = &sr_main;
  uword *p;

  sr_localsid_fn_registration_t *plugin;

  /* Did this function exist? If so update it */
  p = hash_get_mem (sm->plugin_functions_by_key, fn_name);
  if (p)
    {
      plugin = pool_elt_at_index (sm->plugin_functions, p[0]);
    }
  /* Else create a new one and set hash key */
  else
    {
      pool_get (sm->plugin_functions, plugin);
      hash_set_mem (sm->plugin_functions_by_key, fn_name,
		    plugin - sm->plugin_functions);
    }

  clib_memset (plugin, 0, sizeof (*plugin));

  plugin->sr_localsid_function_number = (plugin - sm->plugin_functions);
  plugin->sr_localsid_function_number += SR_BEHAVIOR_LAST;
  plugin->prefix_length = prefix_length;
  plugin->ls_format = ls_format;
  plugin->ls_unformat = ls_unformat;
  plugin->creation = creation_fn;
  plugin->removal = removal_fn;
  clib_memcpy (&plugin->dpo, dpo, sizeof (dpo_type_t));
  plugin->function_name = format (0, "%s%c", fn_name, 0);
  plugin->keyword_str = format (0, "%s%c", keyword_str, 0);
  plugin->def_str = format (0, "%s%c", def_str, 0);
  plugin->params_str = format (0, "%s%c", params_str, 0);

  return plugin->sr_localsid_function_number;
}

/**
 * @brief CLI function to 'show' all available SR LocalSID behaviors
 */
static clib_error_t *
show_sr_localsid_behaviors_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  ip6_sr_main_t *sm = &sr_main;
  sr_localsid_fn_registration_t *plugin;
  sr_localsid_fn_registration_t **plugins_vec = 0;
  int i;

  vlib_cli_output (vm,
		   "SR LocalSIDs behaviors:\n-----------------------\n\n");

  /* *INDENT-OFF* */
  pool_foreach (plugin, sm->plugin_functions,
    ({ vec_add1 (plugins_vec, plugin); }));
  /* *INDENT-ON* */

  /* Print static behaviors */
  vlib_cli_output (vm, "Default behaviors:\n"
		   "\tEnd\t-> Endpoint.\n"
		   "\tEnd.X\t-> Endpoint with Layer-3 cross-connect.\n"
		   "\t\tParameters: '<iface> <ip6_next_hop>'\n"
		   "\tEnd.T\t-> Endpoint with specific IPv6 table lookup.\n"
		   "\t\tParameters: '<fib_table>'\n"
		   "\tEnd.DX2\t-> Endpoint with decapsulation and Layer-2 cross-connect.\n"
		   "\t\tParameters: '<iface>'\n"
		   "\tEnd.DX6\t-> Endpoint with decapsulation and IPv6 cross-connect.\n"
		   "\t\tParameters: '<iface> <ip6_next_hop>'\n"
		   "\tEnd.DX4\t-> Endpoint with decapsulation and IPv4 cross-connect.\n"
		   "\t\tParameters: '<iface> <ip4_next_hop>'\n"
		   "\tEnd.DT6\t-> Endpoint with decapsulation and specific IPv6 table lookup.\n"
		   "\t\tParameters: '<ip6_fib_table>'\n"
		   "\tEnd.DT4\t-> Endpoint with decapsulation and specific IPv4 table lookup.\n"
		   "\t\tParameters: '<ip4_fib_table>'\n");
  vlib_cli_output (vm, "Plugin behaviors:\n");
  for (i = 0; i < vec_len (plugins_vec); i++)
    {
      plugin = plugins_vec[i];
      vlib_cli_output (vm, "\t%s\t-> %s.\n", plugin->keyword_str,
		       plugin->def_str);
      vlib_cli_output (vm, "\t\tParameters: '%s'\n", plugin->params_str);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_sr_localsid_behaviors_command, static) = {
  .path = "show sr localsids behaviors",
  .short_help = "show sr localsids behaviors",
  .function = show_sr_localsid_behaviors_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief SR LocalSID initialization
 */
clib_error_t *
sr_localsids_init (vlib_main_t * vm)
{
  /* Init memory for function keys */
  ip6_sr_main_t *sm = &sr_main;
  mhash_init (&sm->sr_localsids_index_hash, sizeof (uword),
	      sizeof (sr_localsid_key_t));
  /* Init SR behaviors DPO type */
  sr_localsid_dpo_type = dpo_register_new_type (&sr_loc_vft, sr_loc_nodes);
  /* Init SR behaviors DPO type */
  sr_localsid_d_dpo_type =
    dpo_register_new_type (&sr_loc_vft, sr_loc_d_nodes);
  /* Init SR bhaviors DPO type */
  sr_localsid_un_dpo_type =
    dpo_register_new_type (&sr_loc_vft, sr_loc_un_nodes);
  sr_localsid_un_perf_dpo_type =
    dpo_register_new_type (&sr_loc_vft, sr_loc_un_perf_nodes);
  /* Init memory for localsid plugins */
  sm->plugin_functions_by_key = hash_create_string (0, sizeof (uword));
  return 0;
}

VLIB_INIT_FUNCTION (sr_localsids_init);
/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
