/*
 *------------------------------------------------------------------
 * sr_mobile_api.c - ipv6 segment routing for mobile u-plane api
 *
 * Copyright (c) 2022 BBSakura Networks Inc and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdint.h>
#include <vnet/vnet.h>
#include <vnet/srv6/sr.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>
#include <vnet/srv6/sr.api_enum.h>
#include <vnet/srv6/sr.api_types.h>

#include <srv6-mobile/mobile.h>
#include <srv6-mobile/sr_mobile.api_types.h>
#include <srv6-mobile/sr_mobile_types.api_types.h>
#include <srv6-mobile/sr_mobile.api_enum.h>

#include <srv6-mobile/sr_mobile_api.h>

u16 msg_id_base;
#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static inline uint16_t
sr_plugin_localsid_fn_num_find_by (ip6_sr_main_t *sm, const char *keyword_str,
				   size_t keyword_len)
{
  sr_localsid_fn_registration_t *plugin = 0, **vec_plugins = 0;
  sr_localsid_fn_registration_t **plugin_it = 0;
  pool_foreach (plugin, sm->plugin_functions)
    {
      vec_add1 (vec_plugins, plugin);
    }

  vec_foreach (plugin_it, vec_plugins)
    {
      if (!srv6_mobile_strcmp_with_size (keyword_str, keyword_len,
					 (char *) (*plugin_it)->keyword_str))
	{
	  return (*plugin_it)->sr_localsid_function_number;
	}
    }
  return UINT16_MAX;
}

static inline uint16_t
sr_plugin_policy_fn_num_find_by (ip6_sr_main_t *sm, const char *keyword_str,
				 size_t keyword_len)
{
  sr_policy_fn_registration_t *plugin = 0, **vec_plugins = 0;
  sr_policy_fn_registration_t **plugin_it = 0;
  pool_foreach (plugin, sm->policy_plugin_functions)
    {
      vec_add1 (vec_plugins, plugin);
    }

  vec_foreach (plugin_it, vec_plugins)
    {
      if (!srv6_mobile_strcmp_with_size (keyword_str, keyword_len,
					 (char *) (*plugin_it)->keyword_str))
	{
	  return (*plugin_it)->sr_policy_function_number;
	}
    }
  return UINT16_MAX;
}

static void
vl_api_sr_mobile_localsid_add_del_t_handler (
  vl_api_sr_mobile_localsid_add_del_t *mp)
{
  ip6_sr_main_t *sm = &sr_main;
  vl_api_sr_mobile_localsid_add_del_reply_t *rmp;
  int rv = 0;
  ip6_address_t localsid;
  u16 localsid_prefix_len = 128;
  void *ls_plugin_mem = 0;
  u16 behavior = 0;
  u32 dt_type;
  size_t behavior_size = 0;
  mobile_localsid_function_list_t kind_fn =
    SRV6_MOBILE_LOCALSID_UNKNOWN_FUNCTION;

  mp->behavior[sizeof (mp->behavior) - 1] = '\0';
  behavior_size = sizeof (mp->behavior);
  // search behavior index
  if (mp->behavior[0])
    {
      if (!srv6_mobile_strcmp_with_size ((char *) mp->behavior, behavior_size,
					 "end.m.gtp4.e"))
	{
	  kind_fn = SRV6_MOBILE_LOCALSID_END_M_GTP4_E;
	}
      else if (!srv6_mobile_strcmp_with_size ((char *) mp->behavior,
					      behavior_size, "end.m.gtp6.e"))
	{
	  kind_fn = SRV6_MOBILE_LOCALSID_END_M_GTP6_E;
	}
      else if (!srv6_mobile_strcmp_with_size ((char *) mp->behavior,
					      behavior_size, "end.m.gtp6.d"))
	{
	  kind_fn = SRV6_MOBILE_LOCALSID_END_M_GTP6_D;
	}
      else if (!srv6_mobile_strcmp_with_size (
		 (char *) mp->behavior, behavior_size, "end.m.gtp6.d.di"))
	{
	  kind_fn = SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DI;
	}
      else if (!srv6_mobile_strcmp_with_size (
		 (char *) mp->behavior, behavior_size, "end.m.gtp6.d.dt4"))
	{
	  kind_fn = SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DT4;
	  dt_type = SRV6_GTP6_DT4;
	}
      else if (!srv6_mobile_strcmp_with_size (
		 (char *) mp->behavior, behavior_size, "end.m.gtp6.d.dt6"))
	{
	  kind_fn = SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DT6;
	  dt_type = SRV6_GTP6_DT6;
	}
      else if (!srv6_mobile_strcmp_with_size (
		 (char *) mp->behavior, behavior_size, "end.m.gtp6.d.dt46"))
	{
	  kind_fn = SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DT46;
	  dt_type = SRV6_GTP6_DT46;
	}
      else
	{
	  return;
	}
      switch (kind_fn)
	{
	case SRV6_MOBILE_LOCALSID_END_M_GTP4_E:
	  alloc_param_srv6_end_m_gtp4_e (&ls_plugin_mem, &mp->v4src_addr,
					 ntohl (mp->v4src_position),
					 ntohl (mp->fib_table));
	  break;
	case SRV6_MOBILE_LOCALSID_END_M_GTP6_E:
	  alloc_param_srv6_end_m_gtp6_e (&ls_plugin_mem,
					 ntohl (mp->fib_table));
	  break;
	case SRV6_MOBILE_LOCALSID_END_M_GTP6_D:
	  alloc_param_srv6_end_m_gtp6_d (
	    &ls_plugin_mem, &mp->sr_prefix.address, mp->sr_prefix.len,
	    (u8) ntohl (mp->nhtype), mp->drop_in, ntohl (mp->fib_table));
	  break;
	case SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DI:
	  alloc_param_srv6_end_m_gtp6_di (
	    &ls_plugin_mem, &mp->sr_prefix.address, mp->sr_prefix.len,
	    (u8) ntohl (mp->nhtype));
	  break;
	case SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DT4:
	case SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DT6:
	case SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DT46:
	  alloc_param_srv6_end_m_gtp6_dt (
	    &ls_plugin_mem, ntohl (mp->fib_table), ntohl (mp->local_fib_table),
	    dt_type);
	  break;
	case SRV6_MOBILE_LOCALSID_UNKNOWN_FUNCTION:
	default:
	  return; // error
	}
      behavior = sr_plugin_localsid_fn_num_find_by (sm, (char *) mp->behavior,
						    behavior_size);
      if (behavior == UINT16_MAX)
	return;
    }
  else
    {
      return;
    }
  ip6_address_decode (mp->localsid_prefix.address, &localsid);
  localsid_prefix_len = mp->localsid_prefix.len;

  rv = sr_cli_localsid (mp->is_del, &localsid, localsid_prefix_len,
			0, // ignore end_psp
			behavior,
			0, // ignore sw_if_index
			0, // ignore vlan_index
			ntohl (mp->fib_table),
			NULL, // ignore nh_addr
			0,    // ignore usid_len
			ls_plugin_mem);

  REPLY_MACRO (VL_API_SR_MOBILE_LOCALSID_ADD_DEL_REPLY);
}

static void
vl_api_sr_mobile_policy_add_t_handler (vl_api_sr_mobile_policy_add_t *mp)
{
  ip6_sr_main_t *sm = &sr_main;
  vl_api_sr_mobile_policy_add_reply_t *rmp;
  ip6_address_t bsid_addr;
  void *ls_plugin_mem = 0;
  u16 behavior = 0;
  size_t behavior_size = 0;

  u32 dt_type;
  mobile_policy_function_list_t kind_fn = SRV6_MOBILE_POLICY_UNKNOWN_FUNCTION;

  ip6_address_decode (mp->bsid_addr, &bsid_addr);
  mp->behavior[sizeof (mp->behavior) - 1] = '\0';
  behavior_size = sizeof (mp->behavior);

  // search behavior index
  if (mp->behavior[0])
    {
      if (!srv6_mobile_strcmp_with_size ((char *) mp->behavior, behavior_size,
					 "t.m.gtp4.d"))
	{
	  kind_fn = SRV6_MOBILE_POLICY_T_M_GTP4_D;
	}
      else if (!srv6_mobile_strcmp_with_size ((char *) mp->behavior,
					      behavior_size, "t.m.gtp4.dt4"))
	{
	  kind_fn = SRV6_MOBILE_POLICY_T_M_GTP4_DT4;
	  dt_type = SRV6_GTP4_DT4;
	}
      else if (!srv6_mobile_strcmp_with_size ((char *) mp->behavior,
					      behavior_size, "t.m.gtp4.dt6"))
	{
	  kind_fn = SRV6_MOBILE_POLICY_T_M_GTP4_DT6;
	  dt_type = SRV6_GTP4_DT6;
	}
      else if (!srv6_mobile_strcmp_with_size ((char *) mp->behavior,
					      behavior_size, "t.m.gtp4.dt46"))
	{
	  kind_fn = SRV6_MOBILE_POLICY_T_M_GTP4_DT46;
	  dt_type = SRV6_GTP4_DT46;
	}
      else if (!srv6_mobile_strcmp_with_size ((char *) mp->behavior,
					      behavior_size, "end.m.gtp6.d"))
	{
	  kind_fn = SRV6_MOBILE_POLICY_END_M_GTP6_D;
	}
      else
	{
	  return;
	}

      switch (kind_fn)
	{
	case SRV6_MOBILE_POLICY_T_M_GTP4_D:
	  alloc_param_srv6_t_m_gtp4_d (
	    &ls_plugin_mem, &mp->v6src_prefix.address, mp->v6src_prefix.len,
	    &mp->sr_prefix.address, mp->sr_prefix.len, ntohl (mp->fib_table),
	    mp->drop_in, (u8) ntohl (mp->nhtype));
	  break;
	case SRV6_MOBILE_POLICY_END_M_GTP6_D:
	  alloc_param_srv6_end_m_gtp6_d (
	    &ls_plugin_mem, &mp->sr_prefix.address, mp->sr_prefix.len,
	    (u8) ntohl (mp->nhtype), mp->drop_in, ntohl (mp->fib_table));
	  break;
	case SRV6_MOBILE_POLICY_T_M_GTP4_DT4:
	case SRV6_MOBILE_POLICY_T_M_GTP4_DT6:
	case SRV6_MOBILE_POLICY_T_M_GTP4_DT46:
	  alloc_param_srv6_t_m_gtp4_dt (&ls_plugin_mem, ntohl (mp->fib_table),
					ntohl (mp->local_fib_table), dt_type);
	  break;
	case SRV6_MOBILE_POLICY_UNKNOWN_FUNCTION:
	default:
	  return; // error
	}

      behavior = sr_plugin_policy_fn_num_find_by (sm, (char *) mp->behavior,
						  behavior_size);
      if (behavior == UINT16_MAX)
	return;
    }
  else
    {
      return;
    }

  int rv = 0;
  ip6_address_t *segments = 0, *this_seg;
  vec_add2 (segments, this_seg, 1);
  rv = sr_policy_add (&bsid_addr,
		      segments, // ignore segments
		      ntohl (mp->weight),
		      0, // ignore type
		      ntohl (mp->fib_table),
		      0, // ignore is_encap,
		      behavior, ls_plugin_mem);
  vec_free (segments);

  REPLY_MACRO (VL_API_SR_MOBILE_POLICY_ADD_REPLY);
}

#include <srv6-mobile/sr_mobile.api.c>
static clib_error_t *
sr_mobile_api_hookup (vlib_main_t *vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (sr_mobile_api_hookup);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
