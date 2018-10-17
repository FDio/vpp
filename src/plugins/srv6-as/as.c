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
 * as.c - SRv6 Static Proxy (AS) function
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/adj/adj.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <srv6-as/as.h>

#define SID_CREATE_IFACE_FEATURE_ERROR  -1
#define SID_CREATE_INVALID_IFACE_TYPE   -3
#define SID_CREATE_INVALID_IFACE_INDEX  -4
#define SID_CREATE_INVALID_ADJ_INDEX    -5

unsigned char function_name[] = "SRv6-AS-plugin";
unsigned char keyword_str[] = "End.AS";
unsigned char def_str[] =
  "Endpoint with static proxy to SR-unaware appliance";
unsigned char params_str[] =
  "nh <next-hop> oif <iface-out> iif <iface-in> src <src-addr> next <sid> [next <sid> ...]";


static inline u8 *
prepare_rewrite (ip6_address_t src_addr, ip6_address_t * sid_list,
		 u8 protocol)
{
  u8 *rewrite_str = NULL;
  u32 rewrite_len = IPv6_DEFAULT_HEADER_LENGTH;

  u8 num_sids = vec_len (sid_list);
  u32 sr_hdr_len = 0;

  if (num_sids > 1)
    {
      sr_hdr_len =
	sizeof (ip6_sr_header_t) + num_sids * sizeof (ip6_address_t);
      rewrite_len += sr_hdr_len;
    }

  vec_validate (rewrite_str, rewrite_len - 1);

  /* Fill IP header */
  ip6_header_t *iph = (ip6_header_t *) rewrite_str;
  iph->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0 | ((6 & 0xF) << 28));
  iph->src_address = src_addr;
  iph->dst_address = sid_list[0];
  iph->payload_length = sr_hdr_len;
  iph->hop_limit = IPv6_DEFAULT_HOP_LIMIT;

  if (num_sids > 1)
    {
      /* Set Next Header value to Routing Extension */
      iph->protocol = IP_PROTOCOL_IPV6_ROUTE;

      /* Fill SR header */
      ip6_sr_header_t *srh = (ip6_sr_header_t *) (iph + 1);
      srh->protocol = protocol;
      srh->length = sr_hdr_len / 8 - 1;
      srh->type = ROUTING_HEADER_TYPE_SR;
      srh->segments_left = num_sids - 1;
      srh->first_segment = num_sids - 1;
      srh->flags = 0x00;
      srh->reserved = 0x00;

      /* Fill segment list */
      ip6_address_t *this_address;
      ip6_address_t *addrp = srh->segments + srh->first_segment;
      vec_foreach (this_address, sid_list)
      {
	*addrp = *this_address;
	addrp--;
      }
    }
  else
    {
      /* Set Next Header value to inner protocol */
      iph->protocol = protocol;
    }

  return rewrite_str;
}

static inline void
free_ls_mem (srv6_as_localsid_t * ls_mem)
{
  vec_free (ls_mem->rewrite);
  vec_free (ls_mem->sid_list);
  clib_mem_free (ls_mem);
}


/*****************************************/
/* SRv6 LocalSID instantiation and removal functions */
static int
srv6_as_localsid_creation_fn (ip6_sr_localsid_t * localsid)
{
  ip6_sr_main_t *srm = &sr_main;
  srv6_as_main_t *sm = &srv6_as_main;
  srv6_as_localsid_t *ls_mem = localsid->plugin_mem;
  u32 localsid_index = localsid - srm->localsids;

  /* Step 1: Prepare xconnect adjacency for sending packets to the VNF */

  /* Retrieve the adjacency corresponding to the (OIF, next_hop) */
  adj_index_t nh_adj_index = ADJ_INDEX_INVALID;
  if (ls_mem->inner_type != AS_TYPE_L2)
    {
      if (ls_mem->inner_type == AS_TYPE_IP4)
	nh_adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP4,
					    VNET_LINK_IP4, &ls_mem->nh_addr,
					    ls_mem->sw_if_index_out);
      else if (ls_mem->inner_type == AS_TYPE_IP6)
	nh_adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP6,
					    VNET_LINK_IP6, &ls_mem->nh_addr,
					    ls_mem->sw_if_index_out);
      if (nh_adj_index == ADJ_INDEX_INVALID)
	{
	  free_ls_mem (ls_mem);
	  return SID_CREATE_INVALID_ADJ_INDEX;
	}
    }

  ls_mem->nh_adj = nh_adj_index;


  /* Step 2: Prepare inbound policy for packets returning from the VNF */

  /* Make sure the provided incoming interface index is valid */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  ls_mem->sw_if_index_in))
    {
      adj_unlock (ls_mem->nh_adj);
      free_ls_mem (ls_mem);
      return SID_CREATE_INVALID_IFACE_INDEX;
    }

  /* Retrieve associated interface structure */
  vnet_sw_interface_t *sw = vnet_get_sw_interface (sm->vnet_main,
						   ls_mem->sw_if_index_in);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    {
      adj_unlock (ls_mem->nh_adj);
      free_ls_mem (ls_mem);
      return SID_CREATE_INVALID_IFACE_TYPE;
    }

  if (ls_mem->inner_type == AS_TYPE_L2)
    {
      /* Enable End.AS2 rewrite node for this interface */
      int ret =
	vnet_feature_enable_disable ("device-input", "srv6-as2-rewrite",
				     ls_mem->sw_if_index_in, 1, 0, 0);
      if (ret != 0)
	{
	  free_ls_mem (ls_mem);
	  return SID_CREATE_IFACE_FEATURE_ERROR;
	}

      /* Set interface in promiscuous mode */
      vnet_main_t *vnm = vnet_get_main ();
      ethernet_set_flags (vnm, ls_mem->sw_if_index_in,
			  ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);

      /* Prepare rewrite string */
      ls_mem->rewrite = prepare_rewrite (ls_mem->src_addr, ls_mem->sid_list,
					 IP_PROTOCOL_IP6_NONXT);

      /* Associate local SID index to this interface (resize vector if needed) */
      if (ls_mem->sw_if_index_in >= vec_len (sm->sw_iface_localsid2))
	{
	  vec_resize (sm->sw_iface_localsid2,
		      (pool_len (sm->vnet_main->interface_main.sw_interfaces)
		       - vec_len (sm->sw_iface_localsid2)));
	}
      sm->sw_iface_localsid2[ls_mem->sw_if_index_in] = localsid_index;
    }
  else if (ls_mem->inner_type == AS_TYPE_IP4)
    {
      /* Enable End.AS4 rewrite node for this interface */
      int ret =
	vnet_feature_enable_disable ("ip4-unicast", "srv6-as4-rewrite",
				     ls_mem->sw_if_index_in, 1, 0, 0);
      if (ret != 0)
	{
	  adj_unlock (ls_mem->nh_adj);
	  free_ls_mem (ls_mem);
	  return SID_CREATE_IFACE_FEATURE_ERROR;
	}

      /* Prepare rewrite string */
      ls_mem->rewrite = prepare_rewrite (ls_mem->src_addr, ls_mem->sid_list,
					 IP_PROTOCOL_IP_IN_IP);

      /* Associate local SID index to this interface (resize vector if needed) */
      if (ls_mem->sw_if_index_in >= vec_len (sm->sw_iface_localsid4))
	{
	  vec_resize (sm->sw_iface_localsid4,
		      (pool_len (sm->vnet_main->interface_main.sw_interfaces)
		       - vec_len (sm->sw_iface_localsid4)));
	}
      sm->sw_iface_localsid4[ls_mem->sw_if_index_in] = localsid_index;
    }
  else if (ls_mem->inner_type == AS_TYPE_IP6)
    {
      /* Enable End.AS6 rewrite node for this interface */
      int ret =
	vnet_feature_enable_disable ("ip6-unicast", "srv6-as6-rewrite",
				     ls_mem->sw_if_index_in, 1, 0, 0);
      if (ret != 0)
	{
	  adj_unlock (ls_mem->nh_adj);
	  free_ls_mem (ls_mem);
	  return SID_CREATE_IFACE_FEATURE_ERROR;
	}

      /* Prepare rewrite string */
      ls_mem->rewrite = prepare_rewrite (ls_mem->src_addr, ls_mem->sid_list,
					 IP_PROTOCOL_IPV6);

      /* Associate local SID index to this interface (resize vector if needed) */
      if (ls_mem->sw_if_index_in >= vec_len (sm->sw_iface_localsid6))
	{
	  vec_resize (sm->sw_iface_localsid6,
		      (pool_len (sm->vnet_main->interface_main.sw_interfaces)
		       - vec_len (sm->sw_iface_localsid6)));
	}
      sm->sw_iface_localsid6[ls_mem->sw_if_index_in] = localsid_index;
    }

  /* Step 3: Initialize rewrite counters */
  srv6_as_localsid_t **ls_p;
  pool_get (sm->sids, ls_p);
  *ls_p = ls_mem;
  ls_mem->index = ls_p - sm->sids;

  vlib_validate_combined_counter (&(sm->valid_counters), ls_mem->index);
  vlib_validate_combined_counter (&(sm->invalid_counters), ls_mem->index);

  vlib_zero_combined_counter (&(sm->valid_counters), ls_mem->index);
  vlib_zero_combined_counter (&(sm->invalid_counters), ls_mem->index);

  return 0;
}

static int
srv6_as_localsid_removal_fn (ip6_sr_localsid_t * localsid)
{
  srv6_as_main_t *sm = &srv6_as_main;
  srv6_as_localsid_t *ls_mem = localsid->plugin_mem;

  if (ls_mem->inner_type == AS_TYPE_L2)
    {
      /* Disable End.AS2 rewrite node for this interface */
      int ret;
      ret = vnet_feature_enable_disable ("device-input", "srv6-as2-rewrite",
					 ls_mem->sw_if_index_in, 0, 0, 0);
      if (ret != 0)
	return -1;

      /* Disable promiscuous mode on the interface */
      vnet_main_t *vnm = vnet_get_main ();
      ethernet_set_flags (vnm, ls_mem->sw_if_index_in, 0);

      /* Remove local SID index from interface table */
      sm->sw_iface_localsid2[ls_mem->sw_if_index_in] = ~(u32) 0;
    }
  else if (ls_mem->inner_type == AS_TYPE_IP4)
    {
      /* Disable End.AS4 rewrite node for this interface */
      int ret;
      ret = vnet_feature_enable_disable ("ip4-unicast", "srv6-as4-rewrite",
					 ls_mem->sw_if_index_in, 0, 0, 0);
      if (ret != 0)
	return -1;

      /* Remove local SID index from interface table */
      sm->sw_iface_localsid4[ls_mem->sw_if_index_in] = ~(u32) 0;
    }
  else if (ls_mem->inner_type == AS_TYPE_IP6)
    {
      /* Disable End.AS6 rewrite node for this interface */
      int ret;
      ret = vnet_feature_enable_disable ("ip6-unicast", "srv6-as6-rewrite",
					 ls_mem->sw_if_index_in, 0, 0, 0);
      if (ret != 0)
	return -1;

      /* Remove local SID index from interface table */
      sm->sw_iface_localsid6[ls_mem->sw_if_index_in] = ~(u32) 0;
    }


  /* Unlock (OIF, NHOP) adjacency (from sr_localsid.c:103) */
  adj_unlock (ls_mem->nh_adj);

  /* Delete SID entry */
  pool_put (sm->sids, pool_elt_at_index (sm->sids, ls_mem->index));

  /* Clean up local SID memory */
  free_ls_mem (ls_mem);

  return 0;
}

/**********************************/
/* SRv6 LocalSID format functions */
/*
 * Prints nicely the parameters of a localsid
 * Example: print "Table 5"
 */
u8 *
format_srv6_as_localsid (u8 * s, va_list * args)
{
  srv6_as_localsid_t *ls_mem = va_arg (*args, void *);

  vnet_main_t *vnm = vnet_get_main ();
  srv6_as_main_t *sm = &srv6_as_main;

  if (ls_mem->inner_type == AS_TYPE_IP4)
    {
      s =
	format (s, "Next-hop:\t%U\n\t", format_ip4_address,
		&ls_mem->nh_addr.ip4);
    }
  else if (ls_mem->inner_type == AS_TYPE_IP6)
    {
      s =
	format (s, "Next-hop:\t%U\n\t", format_ip6_address,
		&ls_mem->nh_addr.ip6);
    }

  s = format (s, "Outgoing iface:\t%U\n", format_vnet_sw_if_index_name, vnm,
	      ls_mem->sw_if_index_out);
  s = format (s, "\tIncoming iface:\t%U\n", format_vnet_sw_if_index_name, vnm,
	      ls_mem->sw_if_index_in);
  s = format (s, "\tSource address:\t%U\n", format_ip6_address,
	      &ls_mem->src_addr);

  s = format (s, "\tSegment list:\t< ");
  ip6_address_t *addr;
  vec_foreach (addr, ls_mem->sid_list)
  {
    s = format (s, "%U, ", format_ip6_address, addr);
  }
  s = format (s, "\b\b >\n");

  vlib_counter_t valid, invalid;
  vlib_get_combined_counter (&(sm->valid_counters), ls_mem->index, &valid);
  vlib_get_combined_counter (&(sm->invalid_counters), ls_mem->index,
			     &invalid);
  s =
    format (s, "\tGood rewrite traffic: \t[%Ld packets : %Ld bytes]\n",
	    valid.packets, valid.bytes);
  s =
    format (s, "\tBad rewrite traffic:  \t[%Ld packets : %Ld bytes]\n",
	    invalid.packets, invalid.bytes);

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
unformat_srv6_as_localsid (unformat_input_t * input, va_list * args)
{
  void **plugin_mem_p = va_arg (*args, void **);
  srv6_as_localsid_t *ls_mem;

  vnet_main_t *vnm = vnet_get_main ();

  u8 inner_type = AS_TYPE_L2;
  ip46_address_t nh_addr;
  u32 sw_if_index_out;
  u32 sw_if_index_in;
  ip6_address_t src_addr;
  ip6_address_t next_sid;
  ip6_address_t *sid_list = NULL;

  u8 params = 0;
#define PARAM_AS_NH   (1 << 0)
#define PARAM_AS_OIF  (1 << 1)
#define PARAM_AS_IIF  (1 << 2)
#define PARAM_AS_SRC  (1 << 3)

  if (!unformat (input, "end.as"))
    return 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!(params & PARAM_AS_NH) && unformat (input, "nh %U",
					       unformat_ip4_address,
					       &nh_addr.ip4))
	{
	  inner_type = AS_TYPE_IP4;
	  params |= PARAM_AS_NH;
	}
      if (!(params & PARAM_AS_NH) && unformat (input, "nh %U",
					       unformat_ip6_address,
					       &nh_addr.ip6))
	{
	  inner_type = AS_TYPE_IP6;
	  params |= PARAM_AS_NH;
	}
      else if (!(params & PARAM_AS_OIF) && unformat (input, "oif %U",
						     unformat_vnet_sw_interface,
						     vnm, &sw_if_index_out))
	{
	  params |= PARAM_AS_OIF;
	}
      else if (!(params & PARAM_AS_IIF) && unformat (input, "iif %U",
						     unformat_vnet_sw_interface,
						     vnm, &sw_if_index_in))
	{
	  params |= PARAM_AS_IIF;
	}
      else if (!(params & PARAM_AS_SRC) && unformat (input, "src %U",
						     unformat_ip6_address,
						     &src_addr))
	{
	  params |= PARAM_AS_SRC;
	}
      else if (unformat (input, "next %U", unformat_ip6_address, &next_sid))
	{
	  vec_add1 (sid_list, next_sid);
	}
      else
	{
	  break;
	}
    }

  /* Make sure that all parameters are supplied */
  u8 params_chk = (PARAM_AS_OIF | PARAM_AS_IIF | PARAM_AS_SRC);
  if ((params & params_chk) != params_chk || sid_list == NULL)
    {
      vec_free (sid_list);
      return 0;
    }

  /* Allocate and initialize memory block for local SID parameters */
  ls_mem = clib_mem_alloc_aligned_at_offset (sizeof *ls_mem, 0, 0, 1);
  clib_memset (ls_mem, 0, sizeof *ls_mem);
  *plugin_mem_p = ls_mem;

  /* Set local SID parameters */
  ls_mem->inner_type = inner_type;
  if (inner_type == AS_TYPE_IP4)
    ls_mem->nh_addr.ip4 = nh_addr.ip4;
  else if (inner_type == AS_TYPE_IP6)
    ls_mem->nh_addr.ip6 = nh_addr.ip6;
  ls_mem->sw_if_index_out = sw_if_index_out;
  ls_mem->sw_if_index_in = sw_if_index_in;
  ls_mem->src_addr = src_addr;
  ls_mem->sid_list = sid_list;

  return 1;
}

/*************************/
/* SRv6 LocalSID FIB DPO */
static u8 *
format_srv6_as_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: static_proxy_index:[%u]", index));
}

void
srv6_as_dpo_lock (dpo_id_t * dpo)
{
}

void
srv6_as_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t srv6_as_vft = {
  .dv_lock = srv6_as_dpo_lock,
  .dv_unlock = srv6_as_dpo_unlock,
  .dv_format = format_srv6_as_dpo,
};

const static char *const srv6_as_ip6_nodes[] = {
  "srv6-as-localsid",
  NULL,
};

const static char *const *const srv6_as_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_as_ip6_nodes,
};

/**********************/
static clib_error_t *
srv6_as_init (vlib_main_t * vm)
{
  srv6_as_main_t *sm = &srv6_as_main;
  int rv = 0;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  /* Create DPO */
  sm->srv6_as_dpo_type = dpo_register_new_type (&srv6_as_vft, srv6_as_nodes);

  /* Register SRv6 LocalSID */
  rv = sr_localsid_register_function (vm,
				      function_name,
				      keyword_str,
				      def_str,
				      params_str,
				      &sm->srv6_as_dpo_type,
				      format_srv6_as_localsid,
				      unformat_srv6_as_localsid,
				      srv6_as_localsid_creation_fn,
				      srv6_as_localsid_removal_fn);
  if (rv < 0)
    clib_error_return (0, "SRv6 LocalSID function could not be registered.");
  else
    sm->srv6_localsid_behavior_id = rv;

  return 0;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (srv6_as2_rewrite, static) =
{
  .arc_name = "device-input",
  .node_name = "srv6-as2-rewrite",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (srv6_as4_rewrite, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "srv6-as4-rewrite",
  .runs_before = 0,
};

VNET_FEATURE_INIT (srv6_as6_rewrite, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "srv6-as6-rewrite",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_as_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Static SRv6 proxy",
};
/* *INDENT-ON* */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
