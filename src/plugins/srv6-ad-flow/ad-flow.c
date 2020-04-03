/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

/*
 *------------------------------------------------------------------
 * ad-flow.c - SRv6 Flow-based Dynamic Proxy (AD.Flow) behavior
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/adj/adj.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <srv6-ad-flow/ad-flow.h>

#include <vppinfra/bihash_template.c>

#define SID_CREATE_IFACE_FEATURE_ERROR -1
#define SID_CREATE_INVALID_IFACE_TYPE  -3
#define SID_CREATE_INVALID_IFACE_INDEX -4
#define SID_CREATE_INVALID_ADJ_INDEX   -5

unsigned char function_name[] = "SRv6-AD-Flow-plugin";
unsigned char keyword_str[] = "End.AD.Flow";
unsigned char def_str[] =
  "Endpoint with flow-based dynamic proxy to SR-unaware appliance";
unsigned char params_str[] = "nh <next-hop> oif <iface-out> iif <iface-in>";

srv6_ad_flow_main_t srv6_ad_flow_main;

static u32
ad_flow_calc_bihash_buckets (u32 n_elts)
{
  return 1 << (max_log2 (n_elts >> 1) + 1);
}

static u32
ad_flow_calc_bihash_memory (u32 n_buckets, uword kv_size)
{
  return n_buckets * (8 + kv_size * 4);
}

/*****************************************/
/* SRv6 LocalSID instantiation and removal functions */
static int
srv6_ad_flow_localsid_creation_fn (ip6_sr_localsid_t *localsid)
{
  ip6_sr_main_t *srm = &sr_main;
  srv6_ad_flow_main_t *sm = &srv6_ad_flow_main;
  srv6_ad_flow_localsid_t *ls_mem = localsid->plugin_mem;
  u32 localsid_index = localsid - srm->localsids;

  /* Step 1: Prepare xconnect adjacency for sending packets to the VNF */

  /* Retrieve the adjacency corresponding to the (OIF, next_hop) */
  adj_index_t nh_adj_index = ADJ_INDEX_INVALID;
  if (ls_mem->inner_type == AD_TYPE_IP4)
    nh_adj_index =
      adj_nbr_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_IP4, &ls_mem->nh_addr,
			   ls_mem->sw_if_index_out);
  else if (ls_mem->inner_type == AD_TYPE_IP6)
    nh_adj_index =
      adj_nbr_add_or_lock (FIB_PROTOCOL_IP6, VNET_LINK_IP6, &ls_mem->nh_addr,
			   ls_mem->sw_if_index_out);

  if (nh_adj_index == ADJ_INDEX_INVALID)
    {
      clib_mem_free (ls_mem);
      return SID_CREATE_INVALID_ADJ_INDEX;
    }

  ls_mem->nh_adj = nh_adj_index;

  /* Step 2: Prepare inbound policy for packets returning from the VNF */

  /* Sanitise the SW_IF_INDEX */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  ls_mem->sw_if_index_in))
    {
      adj_unlock (ls_mem->nh_adj);
      clib_mem_free (ls_mem);
      return SID_CREATE_INVALID_IFACE_INDEX;
    }

  vnet_sw_interface_t *sw =
    vnet_get_sw_interface (sm->vnet_main, ls_mem->sw_if_index_in);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    {
      adj_unlock (ls_mem->nh_adj);
      clib_mem_free (ls_mem);
      return SID_CREATE_INVALID_IFACE_TYPE;
    }

  if (ls_mem->inner_type == AD_TYPE_IP4)
    {
      /* Enable End.AD4 rewrite node for this interface */
      int ret =
	vnet_feature_enable_disable ("ip4-unicast", "srv6-ad4-flow-rewrite",
				     ls_mem->sw_if_index_in, 1, 0, 0);
      if (ret != 0)
	{
	  adj_unlock (ls_mem->nh_adj);
	  clib_mem_free (ls_mem);
	  return SID_CREATE_IFACE_FEATURE_ERROR;
	}

      /* Associate local SID index to this interface (resize vector if needed)
       */
      if (ls_mem->sw_if_index_in >= vec_len (sm->sw_iface_localsid4))
	{
	  vec_resize (sm->sw_iface_localsid4,
		      (pool_len (sm->vnet_main->interface_main.sw_interfaces) -
		       vec_len (sm->sw_iface_localsid4)));
	}
      sm->sw_iface_localsid4[ls_mem->sw_if_index_in] = localsid_index;
    }
  else if (ls_mem->inner_type == AD_TYPE_IP6)
    {
      /* Enable End.AD6 rewrite node for this interface */
      int ret =
	vnet_feature_enable_disable ("ip6-unicast", "srv6-ad6-flow-rewrite",
				     ls_mem->sw_if_index_in, 1, 0, 0);
      if (ret != 0)
	{
	  adj_unlock (ls_mem->nh_adj);
	  clib_mem_free (ls_mem);
	  return SID_CREATE_IFACE_FEATURE_ERROR;
	}

      /* Associate local SID index to this interface (resize vector if needed)
       */
      if (ls_mem->sw_if_index_in >= vec_len (sm->sw_iface_localsid6))
	{
	  vec_resize (sm->sw_iface_localsid6,
		      (pool_len (sm->vnet_main->interface_main.sw_interfaces) -
		       vec_len (sm->sw_iface_localsid6)));
	}
      sm->sw_iface_localsid6[ls_mem->sw_if_index_in] = localsid_index;
    }

  /* Initialize flow and cache tables */
  ls_mem->cache_size = SRV6_AD_FLOW_DEFAULT_CACHE_SIZE;
  ls_mem->cache_buckets = ad_flow_calc_bihash_buckets (ls_mem->cache_size);
  ls_mem->cache_memory_size = ad_flow_calc_bihash_memory (
    ls_mem->cache_buckets, sizeof (clib_bihash_40_8_t));

  pool_alloc (ls_mem->cache, ls_mem->cache_size);
  pool_alloc (ls_mem->lru_pool, ls_mem->cache_size);

  dlist_elt_t *head;
  pool_get (ls_mem->lru_pool, head);
  ls_mem->lru_head_index = head - ls_mem->lru_pool;
  clib_dlist_init (ls_mem->lru_pool, ls_mem->lru_head_index);

  clib_bihash_init_40_8 (&ls_mem->ftable, "ad-flow", ls_mem->cache_buckets,
			 ls_mem->cache_memory_size);

  /* Step 3: Initialize rewrite counters */
  srv6_ad_flow_localsid_t **ls_p;
  pool_get (sm->sids, ls_p);
  *ls_p = ls_mem;
  ls_mem->index = ls_p - sm->sids;

  vlib_validate_combined_counter (&(sm->sid_bypass_counters), ls_mem->index);
  vlib_validate_combined_counter (&(sm->sid_punt_counters), ls_mem->index);
  vlib_validate_combined_counter (&(sm->sid_cache_full_counters),
				  ls_mem->index);
  vlib_validate_combined_counter (&(sm->rw_valid_counters), ls_mem->index);
  vlib_validate_combined_counter (&(sm->rw_invalid_counters), ls_mem->index);

  vlib_zero_combined_counter (&(sm->sid_bypass_counters), ls_mem->index);
  vlib_zero_combined_counter (&(sm->sid_punt_counters), ls_mem->index);
  vlib_zero_combined_counter (&(sm->sid_cache_full_counters), ls_mem->index);
  vlib_zero_combined_counter (&(sm->rw_valid_counters), ls_mem->index);
  vlib_zero_combined_counter (&(sm->rw_invalid_counters), ls_mem->index);

  return 0;
}

static int
srv6_ad_flow_localsid_removal_fn (ip6_sr_localsid_t *localsid)
{
  srv6_ad_flow_main_t *sm = &srv6_ad_flow_main;
  srv6_ad_flow_localsid_t *ls_mem = localsid->plugin_mem;

  if (ls_mem->inner_type == AD_TYPE_IP4)
    {
      /* Disable End.AD4 rewrite node for this interface */
      int ret =
	vnet_feature_enable_disable ("ip4-unicast", "srv6-ad4-flow-rewrite",
				     ls_mem->sw_if_index_in, 0, 0, 0);
      if (ret != 0)
	return -1;

      /* Remove local SID pointer from interface table */
      sm->sw_iface_localsid4[ls_mem->sw_if_index_in] = ~(u32) 0;
    }
  else if (ls_mem->inner_type == AD_TYPE_IP6)
    {
      /* Disable End.AD6 rewrite node for this interface */
      int ret =
	vnet_feature_enable_disable ("ip6-unicast", "srv6-ad6-flow-rewrite",
				     ls_mem->sw_if_index_in, 0, 0, 0);
      if (ret != 0)
	return -1;

      /* Remove local SID pointer from interface table */
      sm->sw_iface_localsid6[ls_mem->sw_if_index_in] = ~(u32) 0;
    }

  /* Unlock (OIF, NHOP) adjacency */
  adj_unlock (ls_mem->nh_adj);

  /* Delete SID entry */
  pool_put (sm->sids, pool_elt_at_index (sm->sids, ls_mem->index));

  /* Clean up local SID memory */
  srv6_ad_flow_entry_t *e;
  pool_foreach (e, ls_mem->cache)
    {
      vec_free (e->rw_data);
    }
  pool_free (ls_mem->cache);
  pool_free (ls_mem->lru_pool);
  clib_bihash_free_40_8 (&ls_mem->ftable);
  clib_mem_free (localsid->plugin_mem);

  return 0;
}

/**********************************/
/* SRv6 LocalSID format functions */
/*
 * Prints nicely the parameters of a localsid
 * Example: print "Table 5"
 */
u8 *
format_srv6_ad_flow_localsid (u8 *s, va_list *args)
{
  srv6_ad_flow_localsid_t *ls_mem = va_arg (*args, void *);

  vnet_main_t *vnm = vnet_get_main ();
  srv6_ad_flow_main_t *sm = &srv6_ad_flow_main;

  if (ls_mem->inner_type == AD_TYPE_IP4)
    {
      s = format (s, "Next-hop:\t%U\n\t", format_ip4_address,
		  &ls_mem->nh_addr.ip4);
    }
  else if (ls_mem->inner_type == AD_TYPE_IP6)
    {
      s = format (s, "Next-hop:\t%U\n\t", format_ip6_address,
		  &ls_mem->nh_addr.ip6);
    }

  s = format (s, "Outgoing iface:\t%U\n", format_vnet_sw_if_index_name, vnm,
	      ls_mem->sw_if_index_out);
  s = format (s, "\tIncoming iface:\t%U\n", format_vnet_sw_if_index_name, vnm,
	      ls_mem->sw_if_index_in);

  vlib_counter_t sid_bypass, sid_punt, sid_full, rw_valid, rw_invalid;
  vlib_get_combined_counter (&(sm->sid_bypass_counters), ls_mem->index,
			     &sid_bypass);
  vlib_get_combined_counter (&(sm->sid_punt_counters), ls_mem->index,
			     &sid_punt);
  vlib_get_combined_counter (&(sm->sid_cache_full_counters), ls_mem->index,
			     &sid_full);
  vlib_get_combined_counter (&(sm->rw_valid_counters), ls_mem->index,
			     &rw_valid);
  vlib_get_combined_counter (&(sm->rw_invalid_counters), ls_mem->index,
			     &rw_invalid);

  s =
    format (s, "\tTraffic that bypassed the NF: \t[%Ld packets : %Ld bytes]\n",
	    sid_bypass.packets, sid_bypass.bytes);
  s = format (s, "\tPunted traffic: \t[%Ld packets : %Ld bytes]\n",
	      sid_punt.packets, sid_punt.bytes);
  s =
    format (s, "\tDropped traffic (cache full): \t[%Ld packets : %Ld bytes]\n",
	    sid_full.packets, sid_full.bytes);
  s = format (s, "\tGood rewrite traffic: \t[%Ld packets : %Ld bytes]\n",
	      rw_valid.packets, rw_valid.bytes);
  s = format (s, "\tBad rewrite traffic:  \t[%Ld packets : %Ld bytes]\n",
	      rw_invalid.packets, rw_invalid.bytes);

  return s;
}

/*
 * Process the parameters of a localsid
 * Example: process from:
 * sr localsid address cafe::1 behavior new_srv6_localsid 5
 * everything from behavior on... so in this case 'new_srv6_localsid 5'
 * Notice that it MUST match the keyword_str and params_str defined above.
 */
uword
unformat_srv6_ad_flow_localsid (unformat_input_t *input, va_list *args)
{
  void **plugin_mem_p = va_arg (*args, void **);
  srv6_ad_flow_localsid_t *ls_mem;

  vnet_main_t *vnm = vnet_get_main ();

  u8 inner_type = AD_TYPE_IP4;
  ip46_address_t nh_addr;
  u32 sw_if_index_out;
  u32 sw_if_index_in;

  u8 params = 0;
#define PARAM_AD_NH  (1 << 0)
#define PARAM_AD_OIF (1 << 1)
#define PARAM_AD_IIF (1 << 2)

  if (!unformat (input, "end.ad.flow"))
    return 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!(params & PARAM_AD_NH) &&
	  unformat (input, "nh %U", unformat_ip4_address, &nh_addr.ip4))
	{
	  inner_type = AD_TYPE_IP4;
	  params |= PARAM_AD_NH;
	}
      if (!(params & PARAM_AD_NH) &&
	  unformat (input, "nh %U", unformat_ip6_address, &nh_addr.ip6))
	{
	  inner_type = AD_TYPE_IP6;
	  params |= PARAM_AD_NH;
	}
      else if (!(params & PARAM_AD_OIF) &&
	       unformat (input, "oif %U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index_out))
	{
	  params |= PARAM_AD_OIF;
	}
      else if (!(params & PARAM_AD_IIF) &&
	       unformat (input, "iif %U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index_in))
	{
	  params |= PARAM_AD_IIF;
	}
      else
	{
	  break;
	}
    }

  /* Make sure that all parameters are supplied */
  u8 params_chk = (PARAM_AD_NH | PARAM_AD_OIF | PARAM_AD_IIF);
  if ((params & params_chk) != params_chk)
    {
      return 0;
    }

  /* Allocate and initialize memory block for local SID parameters */
  ls_mem = clib_mem_alloc_aligned_at_offset (sizeof *ls_mem, 0, 0, 1);
  clib_memset (ls_mem, 0, sizeof *ls_mem);
  *plugin_mem_p = ls_mem;

  /* Set local SID parameters */
  ls_mem->inner_type = inner_type;
  if (inner_type == AD_TYPE_IP4)
    ls_mem->nh_addr.ip4 = nh_addr.ip4;
  else if (inner_type == AD_TYPE_IP6)
    ls_mem->nh_addr.ip6 = nh_addr.ip6;
  ls_mem->sw_if_index_out = sw_if_index_out;
  ls_mem->sw_if_index_in = sw_if_index_in;

  return 1;
}

/*************************/
/* SRv6 LocalSID FIB DPO */
static u8 *
format_srv6_ad_flow_dpo (u8 *s, va_list *args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: dynamic_proxy_index:[%u]", index));
}

void
srv6_ad_flow_dpo_lock (dpo_id_t *dpo)
{
}

void
srv6_ad_flow_dpo_unlock (dpo_id_t *dpo)
{
}

const static dpo_vft_t srv6_ad_flow_vft = {
  .dv_lock = srv6_ad_flow_dpo_lock,
  .dv_unlock = srv6_ad_flow_dpo_unlock,
  .dv_format = format_srv6_ad_flow_dpo,
};

const static char *const srv6_ad_flow_ip6_nodes[] = {
  "srv6-ad-flow-localsid",
  NULL,
};

const static char *const *const srv6_ad_flow_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_ad_flow_ip6_nodes,
};

/**********************/
static clib_error_t *
srv6_ad_flow_init (vlib_main_t *vm)
{
  srv6_ad_flow_main_t *sm = &srv6_ad_flow_main;
  int rv = 0;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  /* Create DPO */
  sm->srv6_ad_flow_dpo_type =
    dpo_register_new_type (&srv6_ad_flow_vft, srv6_ad_flow_nodes);

  /* Register SRv6 LocalSID */
  rv = sr_localsid_register_function (
    vm, function_name, keyword_str, def_str, params_str, 128,
    &sm->srv6_ad_flow_dpo_type, format_srv6_ad_flow_localsid,
    unformat_srv6_ad_flow_localsid, srv6_ad_flow_localsid_creation_fn,
    srv6_ad_flow_localsid_removal_fn);
  if (rv < 0)
    clib_error_return (0, "SRv6 LocalSID function could not be registered.");
  else
    sm->srv6_localsid_behavior_id = rv;

  return 0;
}

VNET_FEATURE_INIT (srv6_ad4_flow_rewrite, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "srv6-ad4-flow-rewrite",
  .runs_before = 0,
};

VNET_FEATURE_INIT (srv6_ad6_flow_rewrite, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "srv6-ad6-flow-rewrite",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_ad_flow_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Dynamic Segment Routing for IPv6 (SRv6) Proxy",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
