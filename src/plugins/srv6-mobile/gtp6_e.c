/*
 * srv6_end_m_gtp6_e.c
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
#include <srv6-mobile/sr_mobile_api.h>
srv6_end_main_v6_t srv6_end_main_v6;

static void
clb_dpo_lock_srv6_end_m_gtp6_e (dpo_id_t * dpo)
{
}

static void
clb_dpo_unlock_srv6_end_m_gtp6_e (dpo_id_t * dpo)
{
}

static u8 *
clb_dpo_format_srv6_end_m_gtp6_e (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: dynamic_proxy_index:[%u]", index));
}

const static dpo_vft_t dpo_vft = {
  .dv_lock = clb_dpo_lock_srv6_end_m_gtp6_e,
  .dv_unlock = clb_dpo_unlock_srv6_end_m_gtp6_e,
  .dv_format = clb_dpo_format_srv6_end_m_gtp6_e,
};

const static char *const srv6_end_m_gtp6_e_nodes[] = {
  "srv6-end-m-gtp6-e",
  NULL,
};

const static char *const *const dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_end_m_gtp6_e_nodes,
};

static u8 fn_name[] = "SRv6-End.M.GTP6.E-plugin";
static u8 keyword_str[] = "end.m.gtp6.e";
static u8 def_str[] =
  "Endpoint function with encapsulation for IPv6/GTP tunnel";
static u8 param_str[] = "";

static u8 *
clb_format_srv6_end_m_gtp6_e (u8 * s, va_list * args)
{
  srv6_end_gtp6_e_param_t *ls_mem = va_arg (*args, void *);
  ;

  s = format (s, "SRv6 End.M.GTP6.E function.");

  s = format (s, "\tFib Table %d\n", ls_mem->fib_table);

  return s;
}

void
alloc_param_srv6_end_m_gtp6_e (void **plugin_mem_p, const u32 fib_table)
{
  srv6_end_gtp6_e_param_t *ls_mem;
  ls_mem = clib_mem_alloc (sizeof *ls_mem);
  clib_memset (ls_mem, 0, sizeof *ls_mem);
  *plugin_mem_p = ls_mem;

  ls_mem->fib_table = fib_table;
  ls_mem->fib4_index = ip4_fib_index_from_table_id (fib_table);
  ls_mem->fib6_index = ip6_fib_index_from_table_id (fib_table);
}

static uword
clb_unformat_srv6_end_m_gtp6_e (unformat_input_t *input, va_list *args)
{
  void **plugin_mem_p = va_arg (*args, void **);
  u32 fib_table;

  if (!unformat (input, "end.m.gtp6.e fib-table %d", &fib_table))
    return 0;

  alloc_param_srv6_end_m_gtp6_e (plugin_mem_p, fib_table);

  return 1;
}

static int
clb_creation_srv6_end_m_gtp6_e (ip6_sr_localsid_t * localsid)
{
  return 0;
}

static int
clb_removal_srv6_end_m_gtp6_e (ip6_sr_localsid_t * localsid)
{
  srv6_end_gtp6_e_param_t *ls_mem;

  ls_mem = localsid->plugin_mem;

  clib_mem_free (ls_mem);

  return 0;
}

static clib_error_t *
srv6_end_m_gtp6_e_init (vlib_main_t * vm)
{
  srv6_end_main_v6_t *sm = &srv6_end_main_v6;
  ip6_header_t *ip6 = &sm->cache_hdr.ip6;
  udp_header_t *udp = &sm->cache_hdr.udp;
  gtpu_header_t *gtpu = &sm->cache_hdr.gtpu;
  dpo_type_t dpo_type;
  vlib_node_t *node;
  int rc;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  node = vlib_get_node_by_name (vm, (u8 *) "srv6-end-m-gtp6-e");
  sm->end_m_gtp6_e_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  sm->error_node_index = node->index;

  // clear the pre cached packet
  clib_memset_u8 (ip6, 0, sizeof (ip6_gtpu_header_t));

  // set defaults
  ip6->ip_version_traffic_class_and_flow_label = 0x60;
  ip6->protocol = IP_PROTOCOL_UDP;
  ip6->hop_limit = 64;

  udp->dst_port = clib_host_to_net_u16 (SRV6_GTP_UDP_DST_PORT);

  gtpu->ver_flags = GTPU_V1_VER | GTPU_PT_GTP;
  gtpu->type = GTPU_TYPE_GTPU;

  dpo_type = dpo_register_new_type (&dpo_vft, dpo_nodes);

  rc = sr_localsid_register_function (vm, fn_name, keyword_str, def_str, param_str, 128,	//prefix len
				      &dpo_type,
				      clb_format_srv6_end_m_gtp6_e,
				      clb_unformat_srv6_end_m_gtp6_e,
				      clb_creation_srv6_end_m_gtp6_e,
				      clb_removal_srv6_end_m_gtp6_e);
  if (rc < 0)
    clib_error_return (0, "SRv6 Endpoint GTP6.E LocalSID function"
		       "couldn't be registered");
  return 0;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (srv6_end_m_gtp6_e, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "srv6-end-m-gtp6-e",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_end_m_gtp6_e_init);
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
