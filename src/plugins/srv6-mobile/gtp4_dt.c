/*
 * srv6_t_m_gtp4_dt.c
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
#include <vnet/fib/fib_table.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <srv6-mobile/mobile.h>

srv6_t_main_v4_dt_t srv6_t_main_v4_dt;

static void
clb_dpo_lock_srv6_t_m_gtp4_dt (dpo_id_t * dpo)
{
}

static void
clb_dpo_unlock_srv6_t_m_gtp4_dt (dpo_id_t * dpo)
{
}

static u8 *
clb_dpo_format_srv6_t_m_gtp4_dt (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: dynamic_proxy_index:[%u]", index));
}

const static dpo_vft_t dpo_vft = {
  .dv_lock = clb_dpo_lock_srv6_t_m_gtp4_dt,
  .dv_unlock = clb_dpo_unlock_srv6_t_m_gtp4_dt,
  .dv_format = clb_dpo_format_srv6_t_m_gtp4_dt,
};

const static char *const srv6_t_m_gtp4_dt_nodes[] = {
  "srv6-t-m-gtp4-dt",
  NULL,
};

const static char *const srv6_t_m_gtp4_dt_v6_nodes[] = {
  "error-drop",
  NULL,
};

const static char *const *const dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_t_m_gtp4_dt_v6_nodes,
  [DPO_PROTO_IP4] = srv6_t_m_gtp4_dt_nodes,
};

static u8 fn_name[] = "SRv6-T.M.GTP4.DT-plugin";
static u8 keyword_str[] = "t.m.gtp4.dt";
static u8 def_str[] = "Transit function with DT for IPv4/GTP tunnel";
static u8 param_str[] = "fib-index <index> [local-fib-table <index>]";

static u8 *
clb_format_srv6_t_m_gtp4_dt (u8 * s, va_list * args)
{
  srv6_t_gtp4_dt_param_t *ls_mem = va_arg (*args, void *);

  s = format (s, "SRv6 Transit gtp4.dt\n\t");

  if (ls_mem->type == SRV6_GTP4_DT4)
    s = format (s, " Type GTP4.DT4 fib-table %u\n", ls_mem->fib4_index);
  else if (ls_mem->type == SRV6_GTP4_DT6)
    s = format (s, " Type GTP4.DT6, fib-table %u, local-fib-table %u\n",
		ls_mem->fib6_index, ls_mem->local_fib_index);
  else if (ls_mem->type == SRV6_GTP4_DT46)
    s = format (s, " Type GTP4.DT46, fib-table %u, local-fib-table %u\n",
		ls_mem->fib6_index, ls_mem->local_fib_index);
  else
    s = format (s, "\n");

  return s;
}

void
alloc_param_srv6_t_m_gtp4_dt (void **plugin_mem_p, const u32 fib_index,
			      const u32 local_fib_index, const u8 type)
{
  srv6_t_gtp4_dt_param_t *ls_mem;
  ls_mem = clib_mem_alloc (sizeof *ls_mem);
  clib_memset (ls_mem, 0, sizeof *ls_mem);
  *plugin_mem_p = ls_mem;

  ls_mem->fib4_index = fib_table_find (FIB_PROTOCOL_IP4, fib_index);
  ls_mem->fib6_index = fib_table_find (FIB_PROTOCOL_IP6, fib_index);

  if (type == SRV6_GTP4_DT6 || type == SRV6_GTP4_DT46)
    {
      ls_mem->local_fib_index =
	fib_table_find (FIB_PROTOCOL_IP6, local_fib_index);
    }

  ls_mem->type = type;
}

static uword
clb_unformat_srv6_t_m_gtp4_dt (unformat_input_t * input, va_list * args)
{
  void **plugin_mem_p = va_arg (*args, void **);
  u32 fib_index = 0;
  u32 local_fib_index = 0;
  u32 type;

  if (unformat (input, "t.m.gtp4.dt4 fib-table %u", &fib_index))
    {
      type = SRV6_GTP4_DT4;
    }
  else if (unformat (input, "t.m.gtp4.dt6 fib-table %u local-fib-table %u",
		     &fib_index, &local_fib_index))
    {
      type = SRV6_GTP4_DT6;
    }
  else if (unformat (input, "t.m.gtp4.dt46 fib-table %u local-fib-table %u",
		     &fib_index, &local_fib_index))
    {
      type = SRV6_GTP4_DT46;
    }
  else
    {
      return 0;
    }

  alloc_param_srv6_t_m_gtp4_dt (plugin_mem_p, fib_index, local_fib_index,
				type);

  return 1;
}

static int
clb_creation_srv6_t_m_gtp4_dt (ip6_sr_policy_t * sr_policy)
{
  return 0;
}

static int
clb_removal_srv6_t_m_gtp4_dt (ip6_sr_policy_t * sr_policy)
{
  srv6_t_gtp4_dt_param_t *ls_mem;

  ls_mem = (srv6_t_gtp4_dt_param_t *) sr_policy->plugin_mem;

  clib_mem_free (ls_mem);

  return 0;
}

static clib_error_t *
srv6_t_m_gtp4_dt_init (vlib_main_t * vm)
{
  srv6_t_main_v4_dt_t *sm = &srv6_t_main_v4_dt;
  dpo_type_t dpo_type;
  vlib_node_t *node;
  int rc;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  node = vlib_get_node_by_name (vm, (u8 *) "srv6-t-m-gtp4-dt");
  sm->t_m_gtp4_dt_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  sm->error_node_index = node->index;

  dpo_type = dpo_register_new_type (&dpo_vft, dpo_nodes);

  rc = sr_policy_register_function (vm, fn_name, keyword_str, def_str, param_str, 128,	//prefix len
				    &dpo_type,
				    clb_format_srv6_t_m_gtp4_dt,
				    clb_unformat_srv6_t_m_gtp4_dt,
				    clb_creation_srv6_t_m_gtp4_dt,
				    clb_removal_srv6_t_m_gtp4_dt);
  if (rc < 0)
    clib_error_return (0, "SRv6 Transit GTP4.DT Policy function"
		       "couldn't be registered");
  return 0;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (srv6_t_m_gtp4_dt, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "srv6-t-m-gtp4-dt",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_t_m_gtp4_dt_init);
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
