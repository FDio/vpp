/*
 * sr_local.c: ipv6 segment routing local (end) behaviors
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
 * Segment Routing behavior.
 *
 * Supports:
 *  - End (regular segment endpoint processing)
 *  - Cleanup of SRH upon consumition of all segments
 *  - Decapsulation of IPv6 with SRH upon consumition of all segments
 *  - L2 and L3 xconnects (compatible with any decap/clean variant)
 *  - VRF (ability to specify any table-id for the function) 
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/sr/sr.h>
#include <vnet/ip/ip.h>
#include <vnet/sr/sr_packet.h>
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
int sr_cli_localsid (vlib_main_t * vm, char is_del, ip6_address_t *localsid_addr, 
  char is_decap, u8 behavior, u32 sw_if_index, u32 vlan_index, u32 fib_table,
  ip46_address_t *nh_addr, void *ls_plugin_mem)
{
  ip6_sr_main_t * sm = &sr_main;
  uword * p;

  ip6_sr_localsid_t *ls=0;
  ip6_address_t *key_copy;
  
  dpo_id_t dpo = DPO_INVALID;

  /* Search for the item */
  p = hash_get_mem (sm->localsids_index_by_key, localsid_addr);
  
  if (p)
  {
    if (is_del)
    {
      hash_pair_t *hp;
      /* Retrieve localsid */
      ls = pool_elt_at_index (sm->localsids, p[0]);
      /* Delete FIB entry */
      fib_prefix_t pfx = {
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_len = 128,
        .fp_addr = {
          .ip6 = *localsid_addr,
        }
      };

      fib_table_entry_delete (
        fib_table_id_find_fib_index(FIB_PROTOCOL_IP6, fib_table),
        &pfx, FIB_SOURCE_SR);

      /* In case it is a Xconnect iface remove the (OIF, NHOP) adj */
      if(ls->behavior == SR_BEHAVIOR_Xv6 || ls->behavior == SR_BEHAVIOR_Xv4)
        adj_unlock (ls->nh_adj);

      if(ls->behavior >= SR_BEHAVIOR_LAST)
      {
        sr_localsid_fn_registration_t *plugin = 0;
        plugin = pool_elt_at_index (sm->plugin_functions, 
                                    ls->behavior - SR_BEHAVIOR_LAST);

        /* Callback plugin removal function */
        plugin->removal(ls);
      }

      /* Delete localsid registry */
      pool_put (sm->localsids, ls);
      hp = hash_get_pair (sm->localsids_index_by_key, localsid_addr);
      key_copy = (void *)(hp->key);
      hash_unset_mem (sm->localsids_index_by_key, localsid_addr);
      vec_free (key_copy);
      return 1;
    }
    else /* create with function already existing; complain*/
      return -1;
  }
  else
    /* delete; localsid does not exist; complain */
    if (is_del)
      return -2;
  
  /* Check whether there exists a FIB entry with such address */
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
  };

  pfx.fp_addr.as_u64[0] = localsid_addr->as_u64[0];
  pfx.fp_addr.as_u64[1] = localsid_addr->as_u64[1];

  /* Lookup the FIB index associated to the table id provided */
  u32 fib_index = fib_table_id_find_fib_index (FIB_PROTOCOL_IP6, fib_table);
  if (fib_index == ~0)
    return -3;

  /* Lookup the localsid in such FIB table */
  fib_node_index_t fei = fib_table_lookup_exact_match (fib_index, &pfx);
  if (FIB_NODE_INDEX_INVALID != fei)
    return -4; //There is an entry for such address (the localsid addr)

  /* Create a new localsid registry */
  pool_get (sm->localsids, ls);
  memset (ls, 0, sizeof (*ls));
  
  clib_memcpy (&ls->localsid, localsid_addr, sizeof (ip6_address_t));
  ls->decap_allowed = is_decap;
  ls->behavior = behavior;
  ls->nh_adj = (u32)~0;
  ls->fib_table = fib_table;
  switch (behavior)
  {
    case SR_BEHAVIOR_END:
      break;
    case SR_BEHAVIOR_Xv4:
      ls->sw_if_index = sw_if_index;
      clib_memcpy (&ls->next_hop.ip4, &nh_addr->ip4, sizeof (ip4_address_t));
      break;
    case SR_BEHAVIOR_Xv6:
      ls->sw_if_index = sw_if_index;
      clib_memcpy (&ls->next_hop.ip6, &nh_addr->ip6, sizeof (ip6_address_t));
      break;
    case SR_BEHAVIOR_T:
      ls->vrf_index = sw_if_index;
      break;
    case SR_BEHAVIOR_XL2:
      ls->sw_if_index = sw_if_index;
      ls->vlan_index = vlan_index;
      break;
  }

  if(ls->behavior >= SR_BEHAVIOR_LAST)
  {
    sr_localsid_fn_registration_t *plugin = 0;
    plugin = pool_elt_at_index (sm->plugin_functions, 
                                ls->behavior - SR_BEHAVIOR_LAST);

    /* Copy the unformat memory result */
    ls->plugin_mem = ls_plugin_mem;

    /* Callback plugin removal function */
    plugin->creation(ls);

    dpo_set (&dpo, sr_localsid_dpo_type, DPO_PROTO_IP6, ls - sm->localsids);
  }
  /* Figure out the adjacency magic for Xconnect variants */
  if(ls->behavior == SR_BEHAVIOR_Xv6 || ls->behavior == SR_BEHAVIOR_Xv4)
  {
    adj_index_t nh_adj_index = ADJ_INDEX_INVALID;

    /* Retrieve the adjacency corresponding to the (OIF, next_hop) */
    if(ls->behavior == SR_BEHAVIOR_Xv6)
      nh_adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP6, VNET_LINK_ETHERNET,
                                          nh_addr, sw_if_index);

    else if(ls->behavior == SR_BEHAVIOR_Xv6)
      nh_adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_ETHERNET,
                                          nh_addr, sw_if_index);

    /* Check for ADJ creation error. If so panic */
    if(nh_adj_index == ADJ_INDEX_INVALID)
    {
      pool_put (sm->localsids, ls);
      return -5;
    }

    ls->nh_adj = nh_adj_index;
  }

  /* Set hash key for searching localsid by address */
  key_copy = vec_new (ip6_address_t, 1);
  clib_memcpy (key_copy, localsid_addr, sizeof (ip6_address_t));
  hash_set_mem (sm->localsids_index_by_key, key_copy, ls - sm->localsids);

  /* Create DPO and add FIB entry */
  dpo_set (&dpo, sr_localsid_dpo_type, DPO_PROTO_IP6, ls - sm->localsids);

  fib_table_entry_special_dpo_add (
    fib_table_id_find_fib_index(FIB_PROTOCOL_IP6, fib_table),
    &pfx, FIB_SOURCE_SR, FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
  dpo_reset (&dpo);

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
  vnet_main_t * vnm = vnet_get_main();
  ip6_sr_main_t * sm = &sr_main;
  u32 sw_if_index = (u32)~0, vlan_index = (u32)~0, fib_index = 0;
  int is_del = 0;
  int is_decap = 0;
  ip6_address_t resulting_address;
  ip46_address_t next_hop;
  char address_set = 0;
  char behavior = 0;
  void *ls_plugin_mem = 0;

  int rv;

  memset (&resulting_address, 0, sizeof(ip6_address_t));
  ip46_address_reset(&next_hop);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat (input, "del"))
      is_del = 1;
    else if (!address_set && unformat (input, "address %U", unformat_ip6_address, 
        &resulting_address))
      address_set = 1;
    else if (unformat (input, "fib-table %i", &fib_index));
    else if (vlan_index == (u32)~0 && unformat (input, "vlan %i", &vlan_index));
    else if (!is_decap && unformat (input, "decap"))
      is_decap = 1;
    else if (!behavior && unformat (input, "behavior end"))
      behavior = SR_BEHAVIOR_END;
    else if (!behavior && unformat (input, "behavior xconnect l3 %U %U", 
        unformat_vnet_sw_interface, vnm, &sw_if_index, unformat_ip6_address, 
        &next_hop.ip6))
      behavior = SR_BEHAVIOR_Xv6;
    else if (!behavior && unformat (input, "behavior xconnect l3 %U %U", 
        unformat_vnet_sw_interface, vnm, &sw_if_index, unformat_ip4_address, 
        &next_hop.ip4))
      behavior = SR_BEHAVIOR_Xv4;
    else if (!behavior && unformat (input, "behavior xconnect l2 %U", 
        unformat_vnet_sw_interface, vnm, &sw_if_index))
      behavior = SR_BEHAVIOR_XL2; 
    else if (!behavior && unformat (input, "behavior next-table %u", &sw_if_index))
      behavior = SR_BEHAVIOR_T;
    else if (!behavior)
    {
      /* Loop over all the plugin behavior format functions */
      sr_localsid_fn_registration_t *plugin = 0, **vec_plugins = 0;
      sr_localsid_fn_registration_t **plugin_it = 0;

      /* Create a vector out of the plugin pool as recommended*/
      pool_foreach (plugin, sm->plugin_functions, 
      { 
        vec_add1 (vec_plugins, plugin);
      });

      vec_foreach(plugin_it, vec_plugins)
      {
        if (unformat (input, "behavior %U", (*plugin_it)->ls_unformat, ls_plugin_mem))
          behavior = (*plugin_it)->sr_localsid_function_number;
          break; 
      }
    }
    else 
      break;
  }

  if (!address_set)
    return clib_error_return (0, "Error: Locator is mandatory.");
  if (!is_del && !behavior)
    return clib_error_return (0, "Error: Behavior is mandatory.");  
  if (behavior == SR_BEHAVIOR_XL2 && is_decap)
    return clib_error_return (0, "Error: End.X2 behavior is not compatible with decap");
  if (vlan_index != (u32)~0)
    return clib_error_return (0, "Error: VLAN tag not supported by now.");

  rv = sr_cli_localsid (vm, is_del, &resulting_address, is_decap, behavior, 
    sw_if_index, vlan_index, fib_index, &next_hop, &ls_plugin_mem);
  
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
      return clib_error_return (0, "FIB table %d does not exist", fib_index);
    case -4:
      return clib_error_return (0, "There is already one FIB entry for the"
        "requested localsid non segment routing related");
    case -5:
      return clib_error_return (0, 
        "Could not create ARP/ND entry for such next_hop. Internal error.");
    default:
      return clib_error_return (0, "BUG: sr localsid returns %d", rv);
  }
  return 0;
}

VLIB_CLI_COMMAND (sr_localsid_command, static) = {
  .path = "sr localsid",
  .short_help = "sr localsid (del) locator XX:: function yy:yy (arguments zz:zz)"
      "(fib-table 8) behavior STRING (decaps)",
  .long_help =
    "Create SR LocalSID and binds it to a particular behavior\n"
    "Arguments:\n"
    "\tlocator IPv6_addr(64b)   Locator IPv6 prefix. Max. 64b\n"
    "\tfunction IPv6_addr(32b)    Function IPv6 addr. Max. 32b\n"
    "\targuments IPv6_addr(32b) (Opt.) Local argument to the segment. Max.32b\n"
    "\tbehavior STRING      Specifies the behavior\n"
    "\n\tBehaviors:\n"
    "\t-> end\t\t\t\tBasic end behavior. Decap optional.\n"
    "\t-> xconnect l3 TenGE0/1/0 <next_hop(IP)> [decap]\tEnd.X behavior."
    "Xconnect interface TenGE0/1/0\n"
    "\t-> xconnect l2 TenGE0/1/0 [vlan 10]\tEnd.L2X behavior. L2 Xconnect"
    " interface TenGE0/1/0\n"
    "\t-> next-table <fib-table>\t\t\tEnd.V behavior. Next lookup on FIB fib_index\n",
  .function = sr_cli_localsid_command_fn,
};

/**
 * @brief CLI function to 'show' all SR LocalSIDs on console.
 */
static clib_error_t * 
show_sr_localsid_command_fn (vlib_main_t * vm, unformat_input_t * input, 
  vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_sr_main_t * sm = &sr_main;
  ip6_sr_localsid_t ** localsid_list = 0;
  ip6_sr_localsid_t * ls;
  int i;

  vlib_cli_output (vm,"SR LocalSIDs:");
  pool_foreach (ls, sm->localsids, ({ vec_add1 (localsid_list, ls); }));
  vlib_cli_output (vm, "Locator\t\t\tFunction\tArguments\tBehavior");
  for (i = 0; i < vec_len (localsid_list); i++)
  {
    ls = localsid_list[i];
    switch (ls->behavior)
    {
      case SR_BEHAVIOR_END:
        vlib_cli_output (vm,"%02x%02x:%02x%02x:%02x%02x:%02x%02x\t%02x%02x:%02x%02x\t"
          "%02x%02x:%02x%02x\tEnd",
          ls->localsid.as_u8[0], ls->localsid.as_u8[1], ls->localsid.as_u8[2],
          ls->localsid.as_u8[3], ls->localsid.as_u8[4], ls->localsid.as_u8[5],
          ls->localsid.as_u8[6], ls->localsid.as_u8[7], ls->localsid.as_u8[8], 
          ls->localsid.as_u8[9], ls->localsid.as_u8[10], ls->localsid.as_u8[11],
          ls->localsid.as_u8[12], ls->localsid.as_u8[13], ls->localsid.as_u8[14],
          ls->localsid.as_u8[15]);
        break;
      case SR_BEHAVIOR_Xv4:
        vlib_cli_output (vm,"%02x%02x:%02x%02x:%02x%02x:%02x%02x\t%02x%02x:%02x%02x\t"
          "%02x%02x:%02x%02x\txconnect L3 interface %U\tnext_hop %U",
          ls->localsid.as_u8[0], ls->localsid.as_u8[1], ls->localsid.as_u8[2],
          ls->localsid.as_u8[3], ls->localsid.as_u8[4], ls->localsid.as_u8[5],
          ls->localsid.as_u8[6], ls->localsid.as_u8[7], ls->localsid.as_u8[8], 
          ls->localsid.as_u8[9], ls->localsid.as_u8[10], ls->localsid.as_u8[11],
          ls->localsid.as_u8[12], ls->localsid.as_u8[13], ls->localsid.as_u8[14],
          ls->localsid.as_u8[15], format_vnet_sw_if_index_name, vnm, ls->sw_if_index, 
          format_ip4_address, &ls->next_hop.ip4);
        break;
      case SR_BEHAVIOR_Xv6:
        vlib_cli_output (vm,"%02x%02x:%02x%02x:%02x%02x:%02x%02x\t%02x%02x:%02x%02x\t"
          "%02x%02x:%02x%02x\txconnect L3 interface %U\tnext_hop %U",
          ls->localsid.as_u8[0], ls->localsid.as_u8[1], ls->localsid.as_u8[2],
          ls->localsid.as_u8[3], ls->localsid.as_u8[4], ls->localsid.as_u8[5],
          ls->localsid.as_u8[6], ls->localsid.as_u8[7], ls->localsid.as_u8[8], 
          ls->localsid.as_u8[9], ls->localsid.as_u8[10], ls->localsid.as_u8[11],
          ls->localsid.as_u8[12], ls->localsid.as_u8[13], ls->localsid.as_u8[14],
          ls->localsid.as_u8[15], format_vnet_sw_if_index_name, vnm, ls->sw_if_index, 
          format_ip6_address, &ls->next_hop.ip6);
        break;
      case SR_BEHAVIOR_XL2:
        if(ls->vlan_index == (u32)~0)
          vlib_cli_output (vm,"%02x%02x:%02x%02x:%02x%02x:%02x%02x\t%02x%02x:%02x%02x\t"
            "%02x%02x:%02x%02x\txconnect L2 interface %U",
            ls->localsid.as_u8[0], ls->localsid.as_u8[1], ls->localsid.as_u8[2],
            ls->localsid.as_u8[3], ls->localsid.as_u8[4], ls->localsid.as_u8[5],
            ls->localsid.as_u8[6], ls->localsid.as_u8[7], ls->localsid.as_u8[8], 
            ls->localsid.as_u8[9], ls->localsid.as_u8[10], ls->localsid.as_u8[11],
            ls->localsid.as_u8[12], ls->localsid.as_u8[13], ls->localsid.as_u8[14],
            ls->localsid.as_u8[15], format_vnet_sw_if_index_name, vnm, ls->sw_if_index);
        else
          vlib_cli_output (vm,"Unsupported yet");
        break;
      case SR_BEHAVIOR_T:
        vlib_cli_output (vm,"%02x%02x:%02x%02x:%02x%02x:%02x%02x\t%02x%02x:%02x%02x\t"
          "%02x%02x:%02x%02x\tVRF fib-id %u",
          ls->localsid.as_u8[0], ls->localsid.as_u8[1], ls->localsid.as_u8[2],
          ls->localsid.as_u8[3], ls->localsid.as_u8[4], ls->localsid.as_u8[5],
          ls->localsid.as_u8[6], ls->localsid.as_u8[7], ls->localsid.as_u8[8], 
          ls->localsid.as_u8[9], ls->localsid.as_u8[10], ls->localsid.as_u8[11],
          ls->localsid.as_u8[12], ls->localsid.as_u8[13], ls->localsid.as_u8[14],
          ls->localsid.as_u8[15], ls->fib_table);
        break;
      default:
        if(ls->behavior >= SR_BEHAVIOR_LAST)
        {
          sr_localsid_fn_registration_t *plugin = 
            pool_elt_at_index(sm->plugin_functions, ls->behavior-SR_BEHAVIOR_LAST);

          vlib_cli_output (vm,"%U", plugin->ls_format, ls);
        }
        else
          //Should never get here...
          vlib_cli_output (vm, "Internal error");
        break;
    }
  }
  return 0;
}

VLIB_CLI_COMMAND (show_sr_localsid_command, static) = {
  .path = "show sr localsid",
  .short_help = "show sr localsid",
  .function = show_sr_localsid_command_fn,
};

/**
 * @brief SR localsid node trace
 */
typedef struct {
  u32 localsid_index;
  ip6_address_t src, out_dst;
  u8 sr[256];
  u8 num_segments;
  u8 segments_left;
  //With SRv6 header update include flags here.
} sr_localsid_trace_t;

#define foreach_sr_localsid_error                                   \
_(NO_INNER_HEADER, "(SR-Error) No inner IP header")                 \
_(NO_MORE_SEGMENTS, "(SR-Error) No more segments")                  \
_(NO_SRH, "(SR-Error) No SR header")                                \
_(L2, "(SR-Error) SRv6 decapsulated a L2 frame without dest")       \
_(COUNTER_TOTAL, "Total SRv6 processed packets")                    \
_(COUNTER_V6, "SRv6 processed headers")                             \
_(COUNTER_D_V6, "SRv6 decapsulated packets with inner AF IPv6")     \
_(COUNTER_D_V4, "SRv6 decapsulated packets with inner AF IPv4")     \
_(COUNTER_D_L2, "SRv6 decapsulated packets with inner L2 frame")    \
_(COUNTER_ENDV, "SRv6 VRF packets")                                 \
_(COUNTER_L3XCONNECT, "SR xconnected L3 packets")                   \
_(COUNTER_L3XCONNECTv6, "SR xconnected L3 IPv6 packets")            \
_(COUNTER_L3XCONNECTv4, "SR xconnected L3 IPv4 packets")            \
_(COUNTER_L2XCONNECT, "SR xconnected L2 frames")

typedef enum {
#define _(sym,str) SR_LOCALSID_ERROR_##sym,
  foreach_sr_localsid_error
#undef _
  SR_LOCALSID_N_ERROR,
} sr_localsid_error_t;

static char * sr_localsid_error_strings[] = {
#define _(sym,string) string,
  foreach_sr_localsid_error
#undef _
};

#define foreach_sr_localsid_next        \
_(IP6_LOOKUP, "ip6-lookup")             \
_(IP4_LOOKUP, "ip4-lookup")             \
_(ERROR, "error-drop")                  \
_(IP6_REWRITE, "ip6-rewrite")           \
_(IP4_REWRITE, "ip4-rewrite")   \
_(INTERFACE_OUTPUT, "interface-output")

typedef enum {
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
u8 * format_sr_localsid_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_sr_main_t * sm = &sr_main;
  sr_localsid_trace_t * t = va_arg (*args, sr_localsid_trace_t *);

  ip6_sr_localsid_t *ls = pool_elt_at_index (sm->localsids, t->localsid_index);

  s = format(s, "SR-LOCALSID:\n\tLocalsid: %U\n", format_ip6_address, &ls->localsid);
  switch (ls->behavior)
  {
    case SR_BEHAVIOR_Xv4:
      s = format(s, "\tBehavior: L3 xconnect\n");
      break;
    case SR_BEHAVIOR_Xv6:
      s = format(s, "\tBehavior: L3 xconnect\n");
      break;
    case SR_BEHAVIOR_T:
      s = format(s, "\tBehavior: VRF lookup\n");
      break;
    case SR_BEHAVIOR_XL2:
      s = format(s, "\tBehavior: L2 xconnect\n");
      break;
    default:
      s = format(s, "\tBehavior: defined in plugin\n"); //TODO
      break;
  }
  if(t->num_segments != 0xFF)
  {
    s = format(s, "\tSRC: %U \tDST: %U\n", format_ip6_address, &t->src, 
      format_ip6_address, &t->out_dst);
    if(t->num_segments > 0)
    {
      s = format(s, "\tSegments left: %d\n", t->num_segments);
      s = format(s, "\tSID list: [in ietf order]");
      int i = 0;
      for(i=0; i<t->num_segments; i++)
      {
        s = format(s, "\n\t-> %U", format_ip6_address, 
          (ip6_address_t *)&t->sr[i*sizeof(ip6_address_t)]);
      }
    }
  }
  return s;
}

/** 
 * @brief Function doing SRH processing. To be used in SR LocalSID or plugins
 */
static_always_inline void
process_srh ( vlib_node_runtime_t * node,
              vlib_buffer_t * b0,
              ip6_header_t * ip0,
              ip6_sr_header_t * sr0,
              ip6_sr_localsid_t * ls0,
              u32 * next0,
              u32 * counter_end_v6,
              u32 * counter_end_decap_v6,
              u32 * counter_end_decap_v4,
              u32 * counter_end_decap_l2)
{
  ip6_address_t *new_dst0;
  u64 *copy_src0 = 0, *copy_dst0 = 0;
  u32 new_l0;

  if(PREDICT_TRUE(ip0->protocol == IP_PROTOCOL_IPV6_ROUTE))
  {
    if(PREDICT_TRUE(sr0->type == ROUTING_HEADER_TYPE_SR))
    {
      if(PREDICT_TRUE(sr0->segments_left != 0))
      {
        sr0->segments_left -= 1;
        new_dst0 = (ip6_address_t *)(sr0->segments);
        new_dst0 += sr0->segments_left;
        ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
        ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];
        /* If we've reached last segment, clean if necessary */
        if(PREDICT_FALSE(sr0->segments_left == 0) && ls0->cleanup)
        {
          ip0->protocol = sr0->protocol;
          vlib_buffer_advance (b0, (sr0->length+1)*8);
          new_l0 = clib_net_to_host_u16(ip0->payload_length) - (sr0->length+1)*8;
          ip0->payload_length = clib_host_to_net_u16(new_l0);

          copy_src0 = (u64 *)ip0;
          copy_dst0 = copy_src0 + (sr0->length + 1);
          copy_dst0 [4] = copy_src0[4];
          copy_dst0 [3] = copy_src0[3];
          copy_dst0 [2] = copy_src0[2];
          copy_dst0 [1] = copy_src0[1];
          copy_dst0 [0] = copy_src0[0];
        }
        (*counter_end_v6) ++;
      }
      else if(ls0->decap_allowed)
      {
        /* Consumed outer IPv6 header & SRH. Decap. Inside IPv6 */
        if(sr0->protocol == IP_PROTOCOL_IPV6)
        {
          vlib_buffer_advance (b0, IPv6_DEFAULT_HEADER_LENGTH+((sr0->length+1)*8));
          (*counter_end_decap_v6) ++;
        }
        /* Consumed outer IPv6 header & SRH. Decap. Inside IPv4 */
        else if(sr0->protocol == IP_PROTOCOL_IP_IN_IP)
        {
          *next0 = SR_LOCALSID_NEXT_IP4_LOOKUP;
          vlib_buffer_advance (b0, IPv6_DEFAULT_HEADER_LENGTH+((sr0->length+1)*8));
          (*counter_end_decap_v4) ++;
        }
        /* Consumed outer IPv6 header & SRH. Decap. Inside L2 */
        else if(sr0->protocol == IP_PROTOCOL_ETHERIP)
        {
          vlib_buffer_advance (b0, IPv6_DEFAULT_HEADER_LENGTH+((sr0->length+1)*8));
          (*counter_end_decap_l2) ++;
          *next0 = SR_LOCALSID_NEXT_ERROR;
          b0->error = node->errors[SR_LOCALSID_ERROR_L2];
        }
        else
        {
          /* Error. No inner header and consumed header. */
          *next0 = SR_LOCALSID_NEXT_ERROR;
          b0->error = node->errors[SR_LOCALSID_ERROR_NO_INNER_HEADER];
        }
      }
    }
    else
    {
      /* Error. Routing header of type != SR */
      *next0 = SR_LOCALSID_NEXT_ERROR;
      b0->error = node->errors[SR_LOCALSID_ERROR_NO_SRH];
    }
  }
  else
  {
    if (PREDICT_TRUE(ip0->protocol == IP_PROTOCOL_IPV6))
    {
      /* Encap-End IPv6. Pop outer IPv6 header. */
      vlib_buffer_advance (b0, IPv6_DEFAULT_HEADER_LENGTH);
      (*counter_end_decap_v6) ++;
    }
    else if (PREDICT_FALSE(ip0->protocol == IP_PROTOCOL_IP_IN_IP))
    {
      /* Encap-End IPv4. Pop outer IPv6 header */
      *next0 = SR_LOCALSID_NEXT_IP4_LOOKUP;
      vlib_buffer_advance (b0, IPv6_DEFAULT_HEADER_LENGTH);
      (*counter_end_decap_v4) ++;
    }
    else if (PREDICT_FALSE(ip0->protocol == IP_PROTOCOL_ETHERIP))
    {
      /* Temporary. Not defined yet. */
      vlib_buffer_advance (b0, IPv6_DEFAULT_HEADER_LENGTH);
      b0->error = node->errors[SR_LOCALSID_ERROR_L2];
      *next0 = SR_LOCALSID_NEXT_ERROR;
      (*counter_end_decap_l2) ++;
    }
    else
    {
      *next0 = SR_LOCALSID_NEXT_ERROR;
      b0->error = node->errors[SR_LOCALSID_ERROR_NO_SRH];
    }
  }
}

/**
 * @brief SR LocalSID graph node. Supports all default SR Endpoint variants
 */
static uword 
sr_localsid (vlib_main_t * vm, vlib_node_runtime_t * node, 
  vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  ip6_sr_main_t * sm = &sr_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  u32 c_end_v6 = 0, c_end_decap_v6 = 0;
  u32 c_end_decap_v4 = 0, c_end_decap_l2 = 0;

  u32 c_xconnect_v4 = 0, c_xconnect_v6 = 0;
  u32 c_xconnect_l2 = 0;
  u32 c_endv = 0;

  while (n_left_from > 0)
  {
    u32 n_left_to_next;
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    /* Quad - Loop */
    while (n_left_from >= 8 && n_left_to_next >= 4)
    {
      u32 bi0, bi1, bi2, bi3;
      vlib_buffer_t *b0, *b1, *b2, *b3;
      ip6_header_t * ip0, *ip1, *ip2, *ip3;
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

      sr0 = (ip6_sr_header_t *)(ip0+1);
      sr1 = (ip6_sr_header_t *)(ip1+1);
      sr2 = (ip6_sr_header_t *)(ip2+1);
      sr3 = (ip6_sr_header_t *)(ip3+1);

      ls0 = pool_elt_at_index (sm->localsids, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);
      ls1 = pool_elt_at_index (sm->localsids, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);
      ls2 = pool_elt_at_index (sm->localsids, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);
      ls3 = pool_elt_at_index (sm->localsids, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);

      process_srh ( node, b0, ip0, sr0, ls0, &next0, &c_end_v6,
              &c_end_decap_v6, &c_end_decap_v4, &c_end_decap_l2);
      process_srh ( node, b1, ip1, sr1, ls1, &next1, &c_end_v6,
              &c_end_decap_v6, &c_end_decap_v4, &c_end_decap_l2);
      process_srh ( node, b2, ip2, sr2, ls2, &next2, &c_end_v6,
              &c_end_decap_v6, &c_end_decap_v4, &c_end_decap_l2);
      process_srh ( node, b3, ip3, sr3, ls3, &next3, &c_end_v6,
              &c_end_decap_v6, &c_end_decap_v4, &c_end_decap_l2);

      //TODO: trace.

      switch (ls0->behavior)
      {
        case SR_BEHAVIOR_Xv6:
          vnet_buffer(b0)->ip.adj_index[VLIB_TX] = ls0->nh_adj;
          next0 = SR_LOCALSID_NEXT_IP6_REWRITE;
          c_xconnect_v6 ++;
          break;
        case SR_BEHAVIOR_Xv4:
          vnet_buffer(b0)->ip.adj_index[VLIB_TX] = ls0->nh_adj;
          next0 = SR_LOCALSID_NEXT_IP4_REWRITE;
          c_xconnect_v4 ++;
          break;
        case SR_BEHAVIOR_T:
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = ls0->fib_table;
          c_endv ++;
          break;
        case SR_BEHAVIOR_XL2:
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = ls0->sw_if_index;
          next0 = SR_LOCALSID_NEXT_INTERFACE_OUTPUT;
          c_xconnect_l2 ++;
          break;
      }

      switch (ls1->behavior)
      {
        case SR_BEHAVIOR_Xv6:
          vnet_buffer(b1)->ip.adj_index[VLIB_TX] = ls1->nh_adj;
          next1 = SR_LOCALSID_NEXT_IP6_REWRITE;
          c_xconnect_v6 ++;
          break;
        case SR_BEHAVIOR_Xv4:
          vnet_buffer(b1)->ip.adj_index[VLIB_TX] = ls1->nh_adj;
          next1 = SR_LOCALSID_NEXT_IP4_REWRITE;
          c_xconnect_v4 ++;
          break;
        case SR_BEHAVIOR_T:
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = ls1->fib_table;
          c_endv ++;
          break;
        case SR_BEHAVIOR_XL2:
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = ls1->sw_if_index;
          next1 = SR_LOCALSID_NEXT_INTERFACE_OUTPUT;
          c_xconnect_l2 ++;
          break;
      }

      switch (ls2->behavior)
      {
        case SR_BEHAVIOR_Xv6:
          vnet_buffer(b2)->ip.adj_index[VLIB_TX] = ls2->nh_adj;
          next2 = SR_LOCALSID_NEXT_IP6_REWRITE;
          c_xconnect_v6 ++;
          break;
        case SR_BEHAVIOR_Xv4:
          vnet_buffer(b2)->ip.adj_index[VLIB_TX] = ls2->nh_adj;
          next2 = SR_LOCALSID_NEXT_IP4_REWRITE;
          c_xconnect_v4 ++;
          break;
        case SR_BEHAVIOR_T:
          vnet_buffer(b2)->sw_if_index[VLIB_TX] = ls2->fib_table;
          c_endv ++;
          break;
        case SR_BEHAVIOR_XL2:
          vnet_buffer(b2)->sw_if_index[VLIB_TX] = ls2->sw_if_index;
          next2 = SR_LOCALSID_NEXT_INTERFACE_OUTPUT;
          c_xconnect_l2 ++;
          break;
      }

      switch (ls3->behavior)
      {
        case SR_BEHAVIOR_Xv6:
          vnet_buffer(b3)->ip.adj_index[VLIB_TX] = ls3->nh_adj;
          next3 = SR_LOCALSID_NEXT_IP6_REWRITE;
          c_xconnect_v6 ++;
          break;
        case SR_BEHAVIOR_Xv4:
          vnet_buffer(b3)->ip.adj_index[VLIB_TX] = ls3->nh_adj;
          next3 = SR_LOCALSID_NEXT_IP4_REWRITE;
          c_xconnect_v4 ++;
          break;
        case SR_BEHAVIOR_T:
          vnet_buffer(b3)->sw_if_index[VLIB_TX] = ls3->fib_table;
          c_endv ++;
          break;
        case SR_BEHAVIOR_XL2:
          vnet_buffer(b3)->sw_if_index[VLIB_TX] = ls3->sw_if_index;
          next3 = SR_LOCALSID_NEXT_INTERFACE_OUTPUT;
          c_xconnect_l2 ++;
          break;
      }

      vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next, n_left_to_next, 
        bi0, bi1, bi2, bi3, next0, next1, next2, next3);
    }

    /* Single loop for potentially the last three packets */      
    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      ip6_header_t * ip0 = 0;
      ip6_sr_header_t * sr0;
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
      sr0 = (ip6_sr_header_t *)(ip0+1);

      /* Lookup the SR End behavior based on IP DA (adj) */
      ls0 = pool_elt_at_index (sm->localsids, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);

      /* SRH processing */
      process_srh ( node, b0, ip0, sr0, ls0, &next0, &c_end_v6,
              &c_end_decap_v6, &c_end_decap_v4, &c_end_decap_l2);

      /* End variants */
      switch (ls0->behavior)
      {
        /* Xconnect IPv6 variant.
         * Send the packet to ip6-rewrite with the adjacency of the 
         * next_hop neighbor through the xconnect link                */
        case SR_BEHAVIOR_Xv6:
          vnet_buffer(b0)->ip.adj_index[VLIB_TX] = ls0->nh_adj;
          next0 = SR_LOCALSID_NEXT_IP6_REWRITE;
          c_xconnect_v6 ++;
          break;
        /* Xconnect  IPv4 variant.
         * Send the packet to ip4-rewrite with the adjacency of the 
         * next_hop neighbor through the xconnect link                */
        case SR_BEHAVIOR_Xv4:
          vnet_buffer(b0)->ip.adj_index[VLIB_TX] = ls0->nh_adj;
          next0 = SR_LOCALSID_NEXT_IP4_REWRITE;
          c_xconnect_v4 ++;
          break;
        /* VRF variant.
         * Modify VRF to the specified one. Send packet to ip6-lookup   */
        case SR_BEHAVIOR_T:
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = ls0->fib_table;
          c_endv ++;
          break;
        /* L2 Xconnect variant.
         * Modify outgoing interface and send to iface output           */
        case SR_BEHAVIOR_XL2:
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = ls0->sw_if_index;
          next0 = SR_LOCALSID_NEXT_INTERFACE_OUTPUT;
          c_xconnect_l2 ++;
          break;
      } 

      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
      {
        sr_localsid_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
        tr->num_segments = 0;
        tr->localsid_index = ls0 - sm->localsids;

        if(ip0 == vlib_buffer_get_current (b0))
        {
          clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8, sizeof (tr->src.as_u8));
          clib_memcpy (tr->out_dst.as_u8, ip0->dst_address.as_u8, sizeof (tr->out_dst.as_u8));
          if(ip0->protocol == IP_PROTOCOL_IPV6_ROUTE && sr0->type == ROUTING_HEADER_TYPE_SR)
          {
            clib_memcpy (tr->sr, sr0->segments, sr0->length*8);
            tr->num_segments = sr0->length*8/sizeof(ip6_address_t);
            tr->segments_left = sr0->segments_left;
          }
        }
        else
          tr->num_segments = 0xFF;
      }

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, 
        n_left_to_next, bi0, next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  }

  vlib_node_increment_counter (vm, sr_localsid_node.index, 
    SR_LOCALSID_ERROR_COUNTER_TOTAL, 
    (c_end_v6 + c_end_decap_v4 + c_end_decap_v6 + c_end_decap_l2));

  vlib_node_increment_counter (vm, sr_localsid_node.index, 
    SR_LOCALSID_ERROR_COUNTER_V6, c_end_v6);
  vlib_node_increment_counter (vm, sr_localsid_node.index, 
    SR_LOCALSID_ERROR_COUNTER_D_V4, c_end_decap_v4);
  vlib_node_increment_counter (vm, sr_localsid_node.index, 
    SR_LOCALSID_ERROR_COUNTER_D_V6, c_end_decap_v6);
  vlib_node_increment_counter (vm, sr_localsid_node.index, 
    SR_LOCALSID_ERROR_COUNTER_D_L2, c_end_decap_l2);

  vlib_node_increment_counter (vm, sr_localsid_node.index, 
    SR_LOCALSID_ERROR_COUNTER_L3XCONNECT, (c_xconnect_v4+c_xconnect_v6));
  vlib_node_increment_counter (vm, sr_localsid_node.index, 
    SR_LOCALSID_ERROR_COUNTER_L3XCONNECTv6, c_xconnect_v6);
  vlib_node_increment_counter (vm, sr_localsid_node.index, 
    SR_LOCALSID_ERROR_COUNTER_L3XCONNECTv4, c_xconnect_v4);
  vlib_node_increment_counter (vm, sr_localsid_node.index, 
    SR_LOCALSID_ERROR_COUNTER_L2XCONNECT, c_xconnect_l2);

  vlib_node_increment_counter (vm, sr_localsid_node.index, 
    SR_LOCALSID_ERROR_COUNTER_ENDV, c_endv);

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (sr_localsid_node) = {
  .function = sr_localsid,
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

/*************************** SR LocalSID plugins ******************************/
/**
 * @brief SR LocalSID plugin registry
 */
int
sr_localsid_register_function (vlib_main_t * vm, uword *fn_name, dpo_type_t *dpo,
  format_function_t *ls_format, unformat_function_t *ls_unformat, 
  sr_plugin_callback_t *creation_fn, sr_plugin_callback_t *removal_fn)
{
  ip6_sr_main_t * sm = &sr_main;
  uword *p;

  sr_localsid_fn_registration_t *plugin;

  /* Did this function exist? If so update it */
  p = hash_get_mem (sm->plugin_functions_by_key, fn_name);
  if(p)
    plugin = pool_elt_at_index (sm->plugin_functions, p[0]);
  /* Else create a new one and set hash key */
  else
  {
    pool_get (sm->plugin_functions, plugin);
    hash_set_mem (sm->plugin_functions_by_key, fn_name, 
                  plugin - sm->plugin_functions);
  }

  memset (plugin, 0, sizeof(*plugin));

  plugin->sr_localsid_function_number = (plugin - sm->plugin_functions);
  plugin->sr_localsid_function_number += SR_BEHAVIOR_LAST;
  plugin->ls_format = ls_format;
  plugin->ls_unformat = ls_unformat;
  plugin->creation = creation_fn;
  plugin->removal = removal_fn;
  clib_memcpy (&plugin->dpo, dpo, sizeof(dpo_type_t));
  plugin->function_name = format (0, "%s%c", fn_name, 0);

  return plugin->sr_localsid_function_number;
}

/**
 * @brief SR LocalSID initialization
 */
clib_error_t *
sr_behaviors_init (vlib_main_t *vm)
{
  /* Init memory for function keys */
  ip6_sr_main_t * sm = &sr_main;
  sm->localsids_index_by_key = hash_create_mem (0, sizeof (ip6_address_t),
    sizeof (uword));
  /* Init SR behaviors DPO type */
  sr_localsid_dpo_type = dpo_register_new_type (&sr_loc_vft, sr_loc_nodes);
  /* Init memory for localsid plugins */
  sm->plugin_functions_by_key = hash_create_string (0, sizeof (uword));
  return 0;
}

VLIB_INIT_FUNCTION(sr_behaviors_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/