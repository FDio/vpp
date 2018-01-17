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
 * am.c - SRv6 Masquerading Proxy (AM) function
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/adj/adj.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <srv6-am/am.h>

unsigned char function_name[] = "SRv6-AM-plugin";
unsigned char keyword_str[] = "End.AM";
unsigned char def_str[] = "Endpoint to SR-unaware appliance via masquerading";
unsigned char params_str[] = "nh <next-hop> oif <iface-out> iif <iface-in>";


/*****************************************/
/* SRv6 LocalSID instantiation and removal functions */
static int
srv6_am_localsid_creation_fn (ip6_sr_localsid_t * localsid)
{
  srv6_am_main_t *sm = &srv6_am_main;
  srv6_am_localsid_t *ls_mem = localsid->plugin_mem;
  adj_index_t nh_adj_index = ADJ_INDEX_INVALID;

  /* Step 1: Prepare xconnect adjacency for sending packets to the VNF */

  /* Retrieve the adjacency corresponding to the (OIF, next_hop) */
  nh_adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP6,
				      VNET_LINK_IP6, &ls_mem->nh_addr,
				      ls_mem->sw_if_index_out);
  if (nh_adj_index == ADJ_INDEX_INVALID)
    return -5;

  localsid->nh_adj = nh_adj_index;


  /* Step 2: Prepare inbound policy for packets returning from the VNF */

  /* Sanitise the SW_IF_INDEX */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  ls_mem->sw_if_index_in))
    return -3;

  vnet_sw_interface_t *sw = vnet_get_sw_interface (sm->vnet_main,
						   ls_mem->sw_if_index_in);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return -3;

  int ret = vnet_feature_enable_disable ("ip6-unicast", "srv6-am-rewrite",
					 ls_mem->sw_if_index_in, 1, 0, 0);
  if (ret != 0)
    return -1;

  return 0;
}

static int
srv6_am_localsid_removal_fn (ip6_sr_localsid_t * localsid)
{
  srv6_am_localsid_t *ls_mem = localsid->plugin_mem;

  /* Remove hardware indirection (from sr_steering.c:137) */
  int ret = vnet_feature_enable_disable ("ip6-unicast", "srv6-am-rewrite",
					 ls_mem->sw_if_index_in, 0, 0, 0);
  if (ret != 0)
    return -1;

  /* Unlock (OIF, NHOP) adjacency (from sr_localsid.c:103) */
  adj_unlock (localsid->nh_adj);

  /* Clean up local SID memory */
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
format_srv6_am_localsid (u8 * s, va_list * args)
{
  srv6_am_localsid_t *ls_mem = va_arg (*args, void *);

  vnet_main_t *vnm = vnet_get_main ();

  return (format (s,
		  "Next-hop:\t%U\n"
		  "\tOutgoing iface: %U\n"
		  "\tIncoming iface: %U",
		  format_ip6_address, &ls_mem->nh_addr.ip6,
		  format_vnet_sw_if_index_name, vnm, ls_mem->sw_if_index_out,
		  format_vnet_sw_if_index_name, vnm, ls_mem->sw_if_index_in));
}

/*
 * Process the parameters of a localsid
 * Example: process from:
 * sr localsid address cafe::1 behavior new_srv6_localsid 5
 * everything from behavior on... so in this case 'new_srv6_localsid 5'
 * Notice that it MUST match the keyword_str and params_str defined above.
 */
uword
unformat_srv6_am_localsid (unformat_input_t * input, va_list * args)
{
  void **plugin_mem_p = va_arg (*args, void **);
  srv6_am_localsid_t *ls_mem;

  vnet_main_t *vnm = vnet_get_main ();

  ip46_address_t nh_addr;
  u32 sw_if_index_out;
  u32 sw_if_index_in;

  if (unformat (input, "end.am nh %U oif %U iif %U",
		unformat_ip6_address, &nh_addr.ip6,
		unformat_vnet_sw_interface, vnm, &sw_if_index_out,
		unformat_vnet_sw_interface, vnm, &sw_if_index_in))
    {
      /* Allocate a portion of memory */
      ls_mem = clib_mem_alloc_aligned_at_offset (sizeof *ls_mem, 0, 0, 1);

      /* Set to zero the memory */
      memset (ls_mem, 0, sizeof *ls_mem);

      /* Our brand-new car is ready */
      clib_memcpy (&ls_mem->nh_addr.ip6, &nh_addr.ip6,
		   sizeof (ip6_address_t));
      ls_mem->sw_if_index_out = sw_if_index_out;
      ls_mem->sw_if_index_in = sw_if_index_in;

      /* Dont forget to add it to the localsid */
      *plugin_mem_p = ls_mem;
      return 1;
    }
  return 0;
}

/*************************/
/* SRv6 LocalSID FIB DPO */
static u8 *
format_srv6_am_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: dynamic_proxy_index:[%u]", index));
}

void
srv6_am_dpo_lock (dpo_id_t * dpo)
{
}

void
srv6_am_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t srv6_am_vft = {
  .dv_lock = srv6_am_dpo_lock,
  .dv_unlock = srv6_am_dpo_unlock,
  .dv_format = format_srv6_am_dpo,
};

const static char *const srv6_am_ip6_nodes[] = {
  "srv6-am-localsid",
  NULL,
};

const static char *const *const srv6_am_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_am_ip6_nodes,
};

/**********************/
static clib_error_t *
srv6_am_init (vlib_main_t * vm)
{
  srv6_am_main_t *sm = &srv6_am_main;
  int rv = 0;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  /* Create DPO */
  sm->srv6_am_dpo_type = dpo_register_new_type (&srv6_am_vft, srv6_am_nodes);

  /* Register SRv6 LocalSID */
  rv = sr_localsid_register_function (vm,
				      function_name,
				      keyword_str,
				      def_str,
				      params_str,
				      &sm->srv6_am_dpo_type,
				      format_srv6_am_localsid,
				      unformat_srv6_am_localsid,
				      srv6_am_localsid_creation_fn,
				      srv6_am_localsid_removal_fn);
  if (rv < 0)
    clib_error_return (0, "SRv6 LocalSID function could not be registered.");
  else
    sm->srv6_localsid_behavior_id = rv;

  return 0;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (srv6_am_rewrite, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "srv6-am-rewrite",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_am_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Masquerading SRv6 proxy",
};
/* *INDENT-ON* */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
