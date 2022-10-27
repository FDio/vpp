/*
 * srv6_end_m_gtp4_e.c
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

srv6_end_main_v4_t srv6_end_main_v4;

static void
clb_dpo_lock_srv6_end_m_gtp4_e (dpo_id_t * dpo)
{
}

static void
clb_dpo_unlock_srv6_end_m_gtp4_e (dpo_id_t * dpo)
{
}

static u8 *
clb_dpo_format_srv6_end_m_gtp4_e (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: dynamic_proxy_index:[%u]", index));
}

const static dpo_vft_t dpo_vft = {
  .dv_lock = clb_dpo_lock_srv6_end_m_gtp4_e,
  .dv_unlock = clb_dpo_unlock_srv6_end_m_gtp4_e,
  .dv_format = clb_dpo_format_srv6_end_m_gtp4_e,
};

const static char *const srv6_end_m_gtp4_e_nodes[] = {
  "srv6-end-m-gtp4-e",
  NULL,
};

const static char *const *const dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_end_m_gtp4_e_nodes,
};

static u8 fn_name[] = "SRv6-End.M.GTP4.E-plugin";
static u8 keyword_str[] = "end.m.gtp4.e";
static u8 def_str[] =
  "Endpoint function with encapsulation for IPv4/GTP tunnel";
static u8 param_str[] = "";

static u8 *
clb_format_srv6_end_m_gtp4_e (u8 * s, va_list * args)
{
  srv6_end_gtp4_e_param_t *ls_mem = va_arg (*args, void *);

  s = format (s, "SRv6 End gtp4.e\n");

  s = format (s, "\tIPv4 address position: %d\n", ls_mem->v4src_position);

  s = format (s, "\tIPv4 source address: %U\n", format_ip4_address,
	      &ls_mem->v4src_addr);

  s = format (s, "\tFib Table %d\n", ls_mem->fib_table);

  return s;
}

void
alloc_param_srv6_end_m_gtp4_e (void **plugin_mem_p, const void *v4src_addr,
			       const u32 v4src_position, const u32 fib_table)
{
  srv6_end_gtp4_e_param_t *ls_mem;
  ls_mem = clib_mem_alloc (sizeof *ls_mem);
  clib_memset (ls_mem, 0, sizeof *ls_mem);
  *plugin_mem_p = ls_mem;
  ls_mem->v4src_position = v4src_position;
  memcpy (&ls_mem->v4src_addr, v4src_addr, sizeof (ip4_address_t));

  ls_mem->fib_table = fib_table;
  ls_mem->fib4_index = ip4_fib_index_from_table_id (fib_table);
  ls_mem->fib6_index = ip6_fib_index_from_table_id (fib_table);
}

static uword
clb_unformat_srv6_end_m_gtp4_e (unformat_input_t * input, va_list * args)
{
  void **plugin_mem_p = va_arg (*args, void **);
  ip4_address_t v4src_addr;
  u32 v4src_position = 0;
  u32 fib_table;
  bool config = false;

  memset (&v4src_addr, 0, sizeof (ip4_address_t));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "end.m.gtp4.e v4src_position %d fib-table %d",
		    &v4src_position, &fib_table))
	{
	  config = true;
	}
      else if (unformat (input, "end.m.gtp4.e v4src_addr %U fib-table %d",
			 unformat_ip4_address, &v4src_addr, &fib_table))
	{
	  config = true;
	}
      else
	{
	  return 0;
	}
    }

  if (!config)
    return 0;

  alloc_param_srv6_end_m_gtp4_e (plugin_mem_p, &v4src_addr, v4src_position,
				 fib_table);

  return 1;
}

static int
clb_creation_srv6_end_m_gtp4_e (ip6_sr_localsid_t * localsid)
{
  return 0;
}

static int
clb_removal_srv6_end_m_gtp4_e (ip6_sr_localsid_t * localsid)
{
  srv6_end_gtp4_e_param_t *ls_mem;

  ls_mem = localsid->plugin_mem;

  clib_mem_free (ls_mem);

  return 0;
}

static clib_error_t *
srv6_end_m_gtp4_e_init (vlib_main_t * vm)
{
  srv6_end_main_v4_t *sm = &srv6_end_main_v4;
  ip4_header_t *ip4 = &sm->cache_hdr.ip4;
  udp_header_t *udp = &sm->cache_hdr.udp;
  gtpu_header_t *gtpu = &sm->cache_hdr.gtpu;
  dpo_type_t dpo_type;
  vlib_node_t *node;
  int rc;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  node = vlib_get_node_by_name (vm, (u8 *) "srv6-end-m-gtp4-e");
  sm->end_m_gtp4_e_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  sm->error_node_index = node->index;

  sm->dst_p_len = 32;
  sm->src_p_len = 64;

  // clear the pre cached packet
  clib_memset_u8 (ip4, 0, sizeof (ip4_gtpu_header_t));

  // set defaults
  ip4->ip_version_and_header_length = 0x45;
  ip4->protocol = IP_PROTOCOL_UDP;
  ip4->ttl = 64;

  udp->dst_port = clib_host_to_net_u16 (SRV6_GTP_UDP_DST_PORT);

  gtpu->ver_flags = GTPU_V1_VER | GTPU_PT_GTP;
  gtpu->type = GTPU_TYPE_GTPU;
  //

  dpo_type = dpo_register_new_type (&dpo_vft, dpo_nodes);

  rc = sr_localsid_register_function (vm, fn_name, keyword_str, def_str, param_str, 32,	//prefix len
				      &dpo_type,
				      clb_format_srv6_end_m_gtp4_e,
				      clb_unformat_srv6_end_m_gtp4_e,
				      clb_creation_srv6_end_m_gtp4_e,
				      clb_removal_srv6_end_m_gtp4_e);
  if (rc < 0)
    clib_error_return (0, "SRv6 Endpoint GTP4.E LocalSID function"
		       "couldn't be registered");
  return 0;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (srv6_end_m_gtp4_e, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "srv6-end-m-gtp4-e",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_end_m_gtp4_e_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "SRv6 GTP Endpoint Functions",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
