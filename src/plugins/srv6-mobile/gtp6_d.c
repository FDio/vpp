/*
 * srv6_end_m_gtp6_d.c
 *
 * Copyright (c) 2019 Arrcus Inc and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/adj/adj.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <srv6-mobile/mobile.h>

srv6_end_main_v6_decap_t srv6_end_main_v6_decap;

static void
clb_dpo_lock_srv6_end_m_gtp6_d (dpo_id_t * dpo)
{
}

static void
clb_dpo_unlock_srv6_end_m_gtp6_d (dpo_id_t * dpo)
{
}

static u8 *
clb_dpo_format_srv6_end_m_gtp6_d (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: dynamic_proxy_index:[%u]", index));
}

const static dpo_vft_t dpo_vft = {
  .dv_lock = clb_dpo_lock_srv6_end_m_gtp6_d,
  .dv_unlock = clb_dpo_unlock_srv6_end_m_gtp6_d,
  .dv_format = clb_dpo_format_srv6_end_m_gtp6_d,
};

const static char *const srv6_end_m_gtp6_d_nodes[] = {
  "srv6-end-m-gtp6-d",
  NULL,
};

const static char *const *const dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_end_m_gtp6_d_nodes,
};

static u8 fn_name[] = "SRv6-End.M.GTP6.D-plugin";
static u8 keyword_str[] = "end.m.gtp6.d";
static u8 def_str[] =
  "Endpoint function with dencapsulation for IPv6/GTP tunnel";
static u8 param_str[] =
  "<sr-prefix>/<sr-prefixlen> [nhtype <nhtype>] fib-table <id>";

static u8 *
clb_format_srv6_end_m_gtp6_d (u8 * s, va_list * args)
{
  srv6_end_gtp6_d_param_t *ls_mem = va_arg (*args, void *);

  s = format (s, "SRv6 End gtp6.d\n\t");

  s =
    format (s, "SR Prefix: %U/%d", format_ip6_address, &ls_mem->sr_prefix,
	    ls_mem->sr_prefixlen);

  if (ls_mem->nhtype != SRV6_NHTYPE_NONE)
    {
      if (ls_mem->nhtype == SRV6_NHTYPE_IPV4)
	s = format (s, ", NHType IPv4");
      else if (ls_mem->nhtype == SRV6_NHTYPE_IPV6)
	s = format (s, ", NHType IPv6");
      else if (ls_mem->nhtype == SRV6_NHTYPE_NON_IP)
	s = format (s, ", NHType Non-IP");
      else
	s = format (s, ", NHType Unknow(%d)", ls_mem->nhtype);
    }

  s = format (s, " FIB table %d", ls_mem->fib_table);

  s = format (s, " Drop In %d", ls_mem->drop_in);

  return s;
}

void
alloc_param_srv6_end_m_gtp6_d (void **plugin_mem_p, const void *sr_prefix,
			       const u32 sr_prefixlen, const u8 nhtype,
			       const bool drop_in, const u32 fib_table)
{
  srv6_end_gtp6_d_param_t *ls_mem;
  ls_mem = clib_mem_alloc (sizeof *ls_mem);
  clib_memset (ls_mem, 0, sizeof *ls_mem);
  *plugin_mem_p = ls_mem;

  ls_mem->sr_prefixlen = sr_prefixlen;
  memcpy (&ls_mem->sr_prefix, sr_prefix, sizeof (ip6_address_t));
  ls_mem->nhtype = nhtype;
  ls_mem->drop_in = drop_in;
  ls_mem->fib_table = fib_table;
  ls_mem->fib4_index = ip4_fib_index_from_table_id (fib_table);
  ls_mem->fib6_index = ip6_fib_index_from_table_id (fib_table);
}

static uword
clb_unformat_srv6_end_m_gtp6_d (unformat_input_t * input, va_list * args)
{
  void **plugin_mem_p = va_arg (*args, void **);
  ip6_address_t sr_prefix;
  u32 sr_prefixlen;
  u8 nhtype = SRV6_NHTYPE_NONE;
  bool drop_in = false;
  bool config = false;
  u32 fib_table = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "end.m.gtp6.d %U/%d nh-type ipv4 fib-table %d",
		    unformat_ip6_address, &sr_prefix, &sr_prefixlen,
		    &fib_table))
	{
	  config = true;
	  nhtype = SRV6_NHTYPE_IPV4;
	}
      else if (unformat (input, "end.m.gtp6.d %U/%d nh-type ipv6 fib-table %d",
			 unformat_ip6_address, &sr_prefix, &sr_prefixlen,
			 &fib_table))
	{
	  config = true;
	  nhtype = SRV6_NHTYPE_IPV6;
	}
      else if (unformat (input, "end.m.gtp6.d %U/%d nh-type none",
			 unformat_ip6_address, &sr_prefix, &sr_prefixlen))
	{
	  config = true;
	  nhtype = SRV6_NHTYPE_NON_IP;
	}
      else if (unformat (input, "end.m.gtp6.d %U/%d fib-table %d",
			 unformat_ip6_address, &sr_prefix, &sr_prefixlen,
			 &fib_table))
	{
	  config = true;
	  nhtype = SRV6_NHTYPE_NONE;
	}
      else if (unformat (input, "drop-in"))
	{
	  drop_in = true;
	}
      else
	{
	  return 0;
	}
    }

  if (!config)
    {
      return 0;
    }

  alloc_param_srv6_end_m_gtp6_d (plugin_mem_p, &sr_prefix, sr_prefixlen,
				 nhtype, drop_in, fib_table);

  return 1;
}

static int
clb_creation_srv6_end_m_gtp6_d (ip6_sr_localsid_t * localsid)
{
  return 0;
}

static int
clb_creation_srv6_end_m_gtp6_d_2 (ip6_sr_policy_t *sr_policy)
{
  return 0;
}

static int
clb_removal_srv6_end_m_gtp6_d (ip6_sr_localsid_t * localsid)
{
  srv6_end_gtp6_d_param_t *ls_mem;

  ls_mem = localsid->plugin_mem;

  clib_mem_free (ls_mem);

  return 0;
}

static int
clb_removal_srv6_end_m_gtp6_d_2 (ip6_sr_policy_t *sr_policy)
{
  srv6_end_gtp6_d_param_t *ls_mem;

  ls_mem = sr_policy->plugin_mem;

  clib_mem_free (ls_mem);

  return 0;
}

static clib_error_t *
srv6_end_m_gtp6_d_init (vlib_main_t * vm)
{
  srv6_end_main_v6_decap_t *sm = &srv6_end_main_v6_decap;
  ip6_header_t *ip6;
  dpo_type_t dpo_type;
  vlib_node_t *node;
  int rc;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  node = vlib_get_node_by_name (vm, (u8 *) "srv6-end-m-gtp6-d");
  sm->end_m_gtp6_d_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  sm->error_node_index = node->index;

  ip6 = &sm->cache_hdr;

  clib_memset_u8 (ip6, 0, sizeof (ip6_header_t));

  // IPv6 header (default)
  ip6->ip_version_traffic_class_and_flow_label = 0x60;
  ip6->hop_limit = 64;
  ip6->protocol = IP_PROTOCOL_IPV6;

  dpo_type = dpo_register_new_type (&dpo_vft, dpo_nodes);

  rc = sr_localsid_register_function (vm, fn_name, keyword_str, def_str, param_str, 128,	//prefix len
				      &dpo_type,
				      clb_format_srv6_end_m_gtp6_d,
				      clb_unformat_srv6_end_m_gtp6_d,
				      clb_creation_srv6_end_m_gtp6_d,
				      clb_removal_srv6_end_m_gtp6_d);
  if (rc < 0)
    clib_error_return (0, "SRv6 Endpoint GTP6.D LocalSID function"
		       "couldn't be registered");

  rc = sr_policy_register_function (
    vm, fn_name, keyword_str, def_str, param_str, 128, // prefix len
    &dpo_type, clb_format_srv6_end_m_gtp6_d, clb_unformat_srv6_end_m_gtp6_d,
    clb_creation_srv6_end_m_gtp6_d_2, clb_removal_srv6_end_m_gtp6_d_2);
  if (rc < 0)
    clib_error_return (0, "SRv6 GTP6.D Steering function"
			  "couldn't be registered");

  return 0;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (srv6_end_m_gtp6_d, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "srv6-end-m-gtp6-d",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_end_m_gtp6_d_init);
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
