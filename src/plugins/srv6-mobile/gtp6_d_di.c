/*
 * srv6_end_m_gtp6_d_di_di.c
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

srv6_end_main_v6_decap_di_t srv6_end_main_v6_decap_di;

static void
clb_dpo_lock_srv6_end_m_gtp6_d_di (dpo_id_t * dpo)
{
}

static void
clb_dpo_unlock_srv6_end_m_gtp6_d_di (dpo_id_t * dpo)
{
}

static u8 *
clb_dpo_format_srv6_end_m_gtp6_d_di (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: dynamic_proxy_index:[%u]", index));
}

const static dpo_vft_t dpo_vft = {
  .dv_lock = clb_dpo_lock_srv6_end_m_gtp6_d_di,
  .dv_unlock = clb_dpo_unlock_srv6_end_m_gtp6_d_di,
  .dv_format = clb_dpo_format_srv6_end_m_gtp6_d_di,
};

const static char *const srv6_end_m_gtp6_d_di_nodes[] = {
  "srv6-end-m-gtp6-d-di",
  NULL,
};

const static char *const *const dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_end_m_gtp6_d_di_nodes,
};

static u8 fn_name[] = "SRv6-End.M.GTP6.D.DI-plugin";
static u8 keyword_str[] = "end.m.gtp6.d.di";
static u8 def_str[] = "Endpoint function with drop-in dencapsulation for IPv6/GTP tunnel";
static u8 param_str[] = "";

static u8 *
clb_format_srv6_end_m_gtp6_d_di (u8 * s, va_list * args)
{
  s = format (s, "SRv6 End format function unsupported.");
  return s;
}

static uword
clb_unformat_srv6_end_m_gtp6_d_di (unformat_input_t * input, va_list * args)
{
  if (!unformat (input, "end.m.gtp6.d.di"))
    return 0;
  return 1;
}

static int
clb_creation_srv6_end_m_gtp6_d_di (ip6_sr_localsid_t * localsid)
{
  return 0;
}

static int
clb_removal_srv6_end_m_gtp6_d_di (ip6_sr_localsid_t * localsid)
{
  return 0;
}

static clib_error_t *
srv6_end_m_gtp6_d_di_init (vlib_main_t * vm)
{
  srv6_end_main_v6_decap_di_t *sm = &srv6_end_main_v6_decap_di;
  ip6srv_combo_header_t *ip6;
  dpo_type_t dpo_type;
  vlib_node_t *node;
  u32 rc;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  node = vlib_get_node_by_name (vm, (u8 *) "srv6-end-m-gtp6-d-di");
  sm->end_m_gtp6_d_di_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  sm->error_node_index = node->index;

  ip6 = &sm->cache_header;

  clib_memset_u8 (ip6, 0, sizeof(ip6srv_combo_header_t));

  // IPv6 header (default)
  ip6->ip.ip_version_traffic_class_and_flow_label = 0x60;
  ip6->ip.hoplimit = 64;
  ip6->protocol = IPPROTO_IPV6_ROUTE;

  // SR header (default)
  ip6->sr.type = 4;

  dpo_type = dpo_register_new_type (&dpo_vft, dpo_nodes);

  rc = sr_localsid_register_function (vm,
                                      fn_name,
                                      keyword_str,
                                      def_str,
                                      param_str,
                                      64, //prefix len
                                      &dpo_type,
                                      clb_format_srv6_end_m_gtp6_d_di,
                                      clb_unformat_srv6_end_m_gtp6_d_di,
                                      clb_creation_srv6_end_m_gtp6_d_di,
                                      clb_removal_srv6_end_m_gtp6_d_di);
  if (rc < 0)
    clib_error_return (0, "SRv6 Endpoint GTP6.D.DI LocalSID function"
                          "couldn't be registered");
  return 0;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (srv6_end_m_gtp6_d_di, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "srv6-end-m-gtp6-d-di",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_end_m_gtp6_d_di_init);
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
