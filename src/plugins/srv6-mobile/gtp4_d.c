/*
 * srv6_t_m_gtp4_d.c
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

srv6_t_main_v4_decap_t srv6_t_main_v4_decap;

static void
clb_dpo_lock_srv6_t_m_gtp4_d (dpo_id_t * dpo)
{
}

static void
clb_dpo_unlock_srv6_t_m_gtp4_d (dpo_id_t * dpo)
{
}

static u8 *
clb_dpo_format_srv6_t_m_gtp4_d (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: dynamic_proxy_index:[%u]", index));
}

const static dpo_vft_t dpo_vft = {
  .dv_lock = clb_dpo_lock_srv6_t_m_gtp4_d,
  .dv_unlock = clb_dpo_unlock_srv6_t_m_gtp4_d,
  .dv_format = clb_dpo_format_srv6_t_m_gtp4_d,
};

const static char *const srv6_t_m_gtp4_d_nodes[] = {
  "srv6-t-m-gtp4-d",
  NULL,
};

const static char *const srv6_t_m_gtp4_d_v6_nodes[] = {
  "error-drop",
  NULL,
};

const static char *const *const dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_t_m_gtp4_d_v6_nodes,
  [DPO_PROTO_IP4] = srv6_t_m_gtp4_d_nodes,
};

static u8 fn_name[] = "SRv6-T.M.GTP4.D-plugin";
static u8 keyword_str[] = "t.m.gtp4.d";
static u8 def_str[] =
  "Transit function with decapsulation for IPv4/GTP tunnel";
static u8 param_str[] =
  "<sr-prefix>/<sr-prefixlen> v6src_prefix <v6src_prefix>/<prefixlen> [nhtype <nhtype>]";

static u8 *
clb_format_srv6_t_m_gtp4_d (u8 * s, va_list * args)
{
  srv6_end_gtp4_param_t *ls_mem = va_arg (*args, void *);

  s = format (s, "SRv6 T.M.GTP4.D\n\t");

  s =
    format (s, "SR Prefix: %U/%d, ", format_ip6_address, &ls_mem->sr_prefix,
	    ls_mem->sr_prefixlen);

  s =
    format (s, "v6src Prefix: %U/%d", format_ip6_address,
	    &ls_mem->v6src_prefix, ls_mem->v6src_prefixlen);

  if (ls_mem->nhtype != SRV6_NHTYPE_NONE)
    {
      if (ls_mem->nhtype == SRV6_NHTYPE_IPV4)
	s = format (s, ", NHType IPv4\n");
      else if (ls_mem->nhtype == SRV6_NHTYPE_IPV6)
	s = format (s, ", NHType IPv6\n");
      else if (ls_mem->nhtype == SRV6_NHTYPE_NON_IP)
	s = format (s, ", NHType Non-IP\n");
      else
	s = format (s, ", NHType Unknow(%d)\n", ls_mem->nhtype);
    }
  else
    s = format (s, "\n");

  return s;
}

static uword
clb_unformat_srv6_t_m_gtp4_d (unformat_input_t * input, va_list * args)
{
  void **plugin_mem_p = va_arg (*args, void **);
  srv6_end_gtp4_param_t *ls_mem;
  ip6_address_t sr_prefix;
  u32 sr_prefixlen;
  ip6_address_t v6src_prefix;
  u32 v6src_prefixlen;
  u8 nhtype;

  if (unformat (input, "t.m.gtp4.d %U/%d v6src_prefix %U/%d nhtype ipv4",
		unformat_ip6_address, &sr_prefix, &sr_prefixlen,
		unformat_ip6_address, &v6src_prefix, &v6src_prefixlen))
    {
      nhtype = SRV6_NHTYPE_IPV4;
    }
  else
    if (unformat
	(input, "t.m.gtp4.d %U/%d v6src_prefix %U/%d nhtype ipv6",
	 unformat_ip6_address, &sr_prefix, &sr_prefixlen,
	 unformat_ip6_address, &v6src_prefix, &v6src_prefixlen))
    {
      nhtype = SRV6_NHTYPE_IPV6;
    }
  else
    if (unformat
	(input, "t.m.gtp4.d %U/%d v6src_prefix %U/%d nhtype non-ip",
	 unformat_ip6_address, &sr_prefix, &sr_prefixlen,
	 unformat_ip6_address, &v6src_prefix, &v6src_prefixlen))
    {
      nhtype = SRV6_NHTYPE_NON_IP;
    }
  else if (unformat (input, "t.m.gtp4.d %U/%d v6src_prefix %U/%d",
		     unformat_ip6_address, &sr_prefix, &sr_prefixlen,
		     unformat_ip6_address, &v6src_prefix, &v6src_prefixlen))
    {
      nhtype = SRV6_NHTYPE_NONE;
    }
  else
    {
      return 0;
    }

  ls_mem = clib_mem_alloc_aligned_at_offset (sizeof *ls_mem, 0, 0, 1);
  clib_memset (ls_mem, 0, sizeof *ls_mem);
  *plugin_mem_p = ls_mem;

  ls_mem->sr_prefix = sr_prefix;
  ls_mem->sr_prefixlen = sr_prefixlen;

  ls_mem->v6src_prefix = v6src_prefix;
  ls_mem->v6src_prefixlen = v6src_prefixlen;

  ls_mem->nhtype = nhtype;

  return 1;
}

static int
clb_creation_srv6_t_m_gtp4_d (ip6_sr_policy_t * sr_policy)
{
  return 0;
}

static int
clb_removal_srv6_t_m_gtp4_d (ip6_sr_policy_t * sr_policy)
{
  srv6_end_gtp4_param_t *ls_mem;

  ls_mem = (srv6_end_gtp4_param_t *) sr_policy->plugin_mem;

  clib_mem_free (ls_mem);

  return 0;
}

static clib_error_t *
srv6_t_m_gtp4_d_init (vlib_main_t * vm)
{
  srv6_t_main_v4_decap_t *sm = &srv6_t_main_v4_decap;
  ip6_header_t *ip6;
  dpo_type_t dpo_type;
  vlib_node_t *node;
  int rc;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  node = vlib_get_node_by_name (vm, (u8 *) "srv6-t-m-gtp4-d");
  sm->t_m_gtp4_d_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  sm->error_node_index = node->index;

  ip6 = &sm->cache_hdr;

  clib_memset_u8 (ip6, 0, sizeof (ip6_header_t));

  // IPv6 header (default)
  ip6->ip_version_traffic_class_and_flow_label = 0x60;
  ip6->hop_limit = 64;
  ip6->protocol = IP_PROTOCOL_IPV6;

  dpo_type = dpo_register_new_type (&dpo_vft, dpo_nodes);

  rc = sr_policy_register_function (vm, fn_name, keyword_str, def_str, param_str, 128,	//prefix len
				    &dpo_type,
				    clb_format_srv6_t_m_gtp4_d,
				    clb_unformat_srv6_t_m_gtp4_d,
				    clb_creation_srv6_t_m_gtp4_d,
				    clb_removal_srv6_t_m_gtp4_d);
  if (rc < 0)
    clib_error_return (0, "SRv6 Transit GTP4.D Policy function"
		       "couldn't be registered");
  return 0;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (srv6_t_m_gtp4_d, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "srv6-t-m-gtp4-d",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_t_m_gtp4_d_init);
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
