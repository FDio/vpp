/*
 * upf.c - 3GPP TS 29.244 GTP-U UP plug-in for vpp
 *
 * Copyright (c) 2017 Travelping GmbH
 *
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

#define _LGPL_SOURCE		/* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>		/* QSBR RCU flavor */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_hop_by_hop.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/pfcp.h>
#include <upf/upf_pfcp_server.h>

/* Action function shared between message handler and debug CLI */
#include <upf/flowtable.h>
#include <upf/upf_adf.h>

int
upf_enable_disable (upf_main_t * sm, u32 sw_if_index, int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (sm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("device-input", "upf",
			       sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
upf_enable_disable_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  upf_main_t *sm = &upf_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 sm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = upf_enable_disable (sm, sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "upf_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_enable_disable_command, static) =
{
  .path = "upf enable-disable",
  .short_help =
  "upf enable-disable <interface-name> [disable]",
  .function = upf_enable_disable_command_fn,
};
/* *INDENT-ON* */

int
vnet_upf_pfcp_endpoint_add_del (ip46_address_t * ip, u32 fib_index, u8 add)
{
  upf_main_t *gtm = &upf_main;
  ip46_address_fib_t key;
  upf_pfcp_endpoint_t *ep;
  uword *p;

  key.addr = *ip;
  key.fib_index = fib_index;

  p = hash_get_mem (gtm->pfcp_endpoint_index, &key);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (gtm->pfcp_endpoints, ep);
      memset (ep, 0, sizeof (*ep));

      ep->key = key;

      hash_set_mem_alloc (&gtm->pfcp_endpoint_index, &ep->key,
			  ep - gtm->pfcp_endpoints);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      ep = pool_elt_at_index (gtm->pfcp_endpoints, p[0]);
      hash_unset_mem_free (&gtm->pfcp_endpoint_index, &ep->key);
      pool_put (gtm->pfcp_endpoints, ep);
    }

  return 0;
}

clib_error_t *
upf_pfcp_endpoint_ip_add_del_command_fn (vlib_main_t * vm,
					 unformat_input_t * main_input,
					 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u32 fib_index = 0;
  ip46_address_t ip;
  u8 addr_set = 0;
  u32 vrf = ~0;
  u8 add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else
	if (unformat
	    (line_input, "%U", unformat_ip46_address, &ip, IP46_TYPE_ANY))
	addr_set = 1;
      else if (unformat (line_input, "vrf %u", &vrf))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (!addr_set)
    {
      error = clib_error_return (0, "endpoint IP be specified");
      goto done;
    }

  if (vrf != ~0)
    {
      fib_index =
	fib_table_find (fib_ip_proto (!ip46_address_is_ip4 (&ip)), vrf);
      if (fib_index == ~0)
	{
	  error = clib_error_return (0, "nonexistent vrf %d", vrf);
	  goto done;
	}
    }

  rv = vnet_upf_pfcp_endpoint_add_del (&ip, fib_index, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance does not exist...");
      break;

    default:
      error = clib_error_return (0, "vnet_upf_pfcp_endpoint_add_del %d", rv);
      break;
    }

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_pfcp_endpoint_ip_add_del_command, static) =
{
  .path = "upf pfcp endpoint ip",
  .short_help =
  "upf pfcp endpoint ip <address> [vrf <table-id>] [del]",
  .function = upf_pfcp_endpoint_ip_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_pfcp_show_endpoint_command_fn (vlib_main_t * vm,
				   unformat_input_t * main_input,
				   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *gtm = &upf_main;
  clib_error_t *error = NULL;
  upf_pfcp_endpoint_t *ep;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {

      clib_warning ("Past unformat");
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  error = unformat_parse_error (line_input);
	  unformat_free (line_input);
	  goto done;
	}

      unformat_free (line_input);
    }

  clib_warning ("pool");

  vlib_cli_output (vm, "Endpoints: %d\n", pool_elts (gtm->pfcp_endpoints));
  /* *INDENT-OFF* */
  pool_foreach (ep, gtm->pfcp_endpoints,
  ({
    vlib_cli_output (vm, "  %U\n", format_pfcp_endpoint, ep);
  }));
  /* *INDENT-ON* */

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_pfcp_show_endpoint_command, static) =
{
  .path = "show upf pfcp endpoint",
  .short_help =
  "show upf pfcp endpoint",
  .function = upf_pfcp_show_endpoint_command_fn,
};
/* *INDENT-ON* */

int
vnet_upf_nwi_add_del (u8 * name, u32 table_id, u8 add)
{
  upf_main_t *gtm = &upf_main;
  upf_nwi_t *nwi;
  uword *p;

  p = hash_get_mem (gtm->nwi_index_by_name, name);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (gtm->nwis, nwi);
      nwi->name = vec_dup (name);
      nwi->table_id = table_id;

      hash_set_mem (gtm->nwi_index_by_name, nwi->name, nwi - gtm->nwis);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      nwi = pool_elt_at_index (gtm->nwis, p[0]);

      hash_unset_mem (gtm->nwi_index_by_name, nwi->name);
      vec_free (nwi->name);
      pool_put (gtm->nwis, nwi);
    }

  return 0;
}

/**
 * Translate "foo.com" into "0x3 f o o 0x3 c o m 0x0"
 * A historical / hysterical micro-TLV scheme. DGMS.
 */
static u8 *
upf_name_to_labels (u8 * name)
{
  int i;
  int last_label_index;
  u8 *rv;

  rv = vec_dup (name);

  /* punch in space for the first length */
  vec_insert (rv, 1, 0);
  last_label_index = 0;
  i = 1;

  while (i < vec_len (rv))
    {
      if (rv[i] == '.')
	{
	  rv[last_label_index] = (i - last_label_index) - 1;
	  if ((i - last_label_index) > 63)
	    clib_warning ("stupid name, label length %d",
			  i - last_label_index);
	  last_label_index = i;
	  rv[i] = 0;
	}
      i++;
    }
  /* Set the last real label length */
  rv[last_label_index] = (i - last_label_index) - 1;

  return rv;
}

static clib_error_t *
upf_nwi_add_del_command_fn (vlib_main_t * vm,
			    unformat_input_t * main_input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = NULL;
  u8 *s;
  u32 table_id = 0;
  u8 add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "name %_%v%_", &s))
	{
	  name = upf_name_to_labels (s);
	  vec_free (s);
	}
      else if (unformat (line_input, "table %u", &table_id))
	;
      else if (unformat (line_input, "vrf %u", &table_id))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (!name)
    {
      error =clib_error_return (0, "name or label must be specified!");
      goto done;
    }

  if (~0 == fib_table_find (FIB_PROTOCOL_IP4, table_id))
    clib_warning ("table %d not (yet) defined for IPv4", table_id);
  if (~0 == fib_table_find (FIB_PROTOCOL_IP6, table_id))
    clib_warning ("table %d not (yet) defined for IPv6", table_id);

  rv = vnet_upf_nwi_add_del (name, table_id, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "network instance already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance does not exist...");
      break;

    default:
      error = clib_error_return (0, "vnet_upf_nwi_add_del returned %d", rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_nwi_add_del_command, static) =
{
  .path = "upf nwi",
  .short_help =
  "upf nwi name <name> [table <table-id>] [del]",
  .function = upf_nwi_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_nwi_command_fn (vlib_main_t * vm,
			 unformat_input_t * main_input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *gtm = &upf_main;
  clib_error_t *error = NULL;
  upf_nwi_t *nwi;
  u8 *name = NULL;
  u8 *s;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "name %_%v%_", &s))
	    {
	      name = upf_name_to_labels (s);
	      vec_free (s);
	    }
	  else
	    {
	      error = unformat_parse_error (line_input);
	      unformat_free (line_input);
	      goto done;
	    }
	}

      unformat_free (line_input);
    }

  /* *INDENT-OFF* */
  pool_foreach (nwi, gtm->nwis,
  ({
    if (name && !vec_is_equal(name, nwi->name))
      continue;

    vlib_cli_output (vm, "%U, table-id: %u\n",
		     format_network_instance, nwi->name, nwi->table_id);
  }));
  /* *INDENT-ON* */

done:
  vec_free (name);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_nwi_command, static) =
{
  .path = "show upf nwi",
  .short_help =
  "show upf nwi",
  .function = upf_show_nwi_command_fn,
};
/* *INDENT-ON* */

#if 0
static void
vtep_ip4_ref (ip4_address_t * ip, u8 ref)
{
  uword *vtep = hash_get (upf_main.vtep4, ip->as_u32);
  if (ref)
    {
      if (vtep)
	++(*vtep);
      else
	hash_set (upf_main.vtep4, ip->as_u32, 1);
    }
  else
    {
      if (!vtep)
	return;

      if (--(*vtep) == 0)
	hash_unset (upf_main.vtep4, ip->as_u32);
    }
}

static void
vtep_ip6_ref (ip6_address_t * ip, u8 ref)
{
  uword *vtep = hash_get_mem (upf_main.vtep6, ip);
  if (ref)
    {
      if (vtep)
	++(*vtep);
      else
	hash_set_mem_alloc (&upf_main.vtep6, ip, 1);
    }
  else
    {
      if (!vtep)
	return;

      if (--(*vtep) == 0)
	hash_unset_mem_free (&upf_main.vtep6, ip);
    }
}

static void
vtep_if_address_add_del (u32 sw_if_index, u8 add)
{
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;
  ip4_address_t *ip4;
  ip6_address_t *ip6;

  /* *INDENT-OFF* */
  foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* unnumbered */ ,
  ({
    ip4 = ip_interface_address_get_address (lm4, ia);
    vtep_ip4_ref(ip4, add);
  }));
  foreach_ip_interface_address (lm6, ia, sw_if_index, 1 /* unnumbered */ ,
  ({
    ip6 = ip_interface_address_get_address (lm6, ia);
    vtep_ip6_ref(ip6, add);
  }));
  /* *INDENT-ON* */
}
#endif

int
vnet_upf_upip_add_del (ip4_address_t * ip4, ip6_address_t * ip6,
		       u8 * name, u8 intf, u32 teid, u32 mask, u8 add)
{
  upf_main_t *gtm = &upf_main;
  upf_upip_res_t *ip_res;
  upf_upip_res_t res = {
    .ip4 = *ip4,
    .ip6 = *ip6,
    .nwi = ~0,
    .intf = intf,
    .teid = teid,
    .mask = mask
  };
  uword *p;

  if (name)
    {
      p = hash_get_mem (gtm->nwi_index_by_name, name);
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      res.nwi = p[0];
    }

  p = hash_get_mem (gtm->upip_res_index, &res);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (gtm->upip_res, ip_res);
      memcpy (ip_res, &res, sizeof (res));

      hash_set_mem (gtm->upip_res_index, ip_res, ip_res - gtm->upip_res);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      ip_res = pool_elt_at_index (gtm->upip_res, p[0]);
      hash_unset_mem (gtm->upip_res_index, ip_res);
      pool_put (gtm->upip_res, ip_res);
    }

  return 0;
}

clib_error_t *
upf_gtpu_endpoint_add_del_command_fn (vlib_main_t * vm,
				      unformat_input_t * main_input,
				      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 teid = 0, mask = 0, teidri = 0;
  clib_error_t *error = NULL;
  ip6_address_t ip6 = ip6_address_initializer;
  ip4_address_t ip4 = ip4_address_initializer;
  u8 ip_set = 0;
  u8 *name = NULL;
  u8 intf = INTF_INVALID;
  u8 add = 1;
  int rv;
  u8 *s;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "ip %U", unformat_ip4_address, &ip4))
	ip_set |= 1;
      else if (unformat (line_input, "ip6 %U", unformat_ip6_address, &ip6))
	ip_set |= 2;
      else if (unformat (line_input, "nwi %_%v%_", &s))
	{
	  name = upf_name_to_labels (s);
	  vec_free (s);
	}
      else if (unformat (line_input, "intf access"))
	intf = SRC_INTF_ACCESS;
      else if (unformat (line_input, "intf core"))
	intf = SRC_INTF_CORE;
      else if (unformat (line_input, "intf sgi"))
	/*
	 * WTF: the specification does permit that,
	 *      but what does that mean in terms
	 *      of the UPIP IE?
	 */
	intf = SRC_INTF_SGI_LAN;
      else if (unformat (line_input, "intf cp"))
	intf = SRC_INTF_CP;
      else if (unformat (line_input, "teid %u/%u", &teid, &teidri))
	{
	  if (teidri > 7)
	    {
	      error =
		clib_error_return (0,
				   "TEID Range Indication to large (%d > 7)",
				   teidri);
	      goto done;
	    }
	  mask = 0xfe000000 << (7 - teidri);
	}
      else if (unformat (line_input, "teid 0x%x/%u", &teid, &teidri))
	{
	  if (teidri > 7)
	    {
	      error =
		clib_error_return (0,
				   "TEID Range Indication to large (%d > 7)",
				   teidri);
	      goto done;
	    }
	  mask = 0xfe000000 << (7 - teidri);
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (!ip_set)
    {
      error = clib_error_return (0, "ip or ip6 need to be set");
      goto done;
    }

  rv = vnet_upf_upip_add_del (&ip4, &ip6, name, intf, teid, mask, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error =
	clib_error_return (0, "network instance or entry does not exist...");
      break;

    default:
      error = clib_error_return
	(0, "vnet_upf_nwi_set_intf_role returned %d", rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);
  return error;
}

/**********************************************************/

int
vnet_upf_tdf_ul_table_add_del (u32 vrf, fib_protocol_t fproto, u32 table_id, u8 add)
{
  u32 fib_index, vrf_fib_index;
  upf_main_t *gtm = &upf_main;

  if (add)
    {
      vrf_fib_index = fib_table_find (fproto, vrf);
      if (~0 == vrf_fib_index)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      fib_index = fib_table_find_or_create_and_lock (fproto, table_id, FIB_SOURCE_PLUGIN_LOW);

      vec_validate_init_empty (gtm->tdf_ul_table[fproto], vrf_fib_index, ~0);
      vec_elt (gtm->tdf_ul_table[fproto], vrf_fib_index) = fib_index;
    }
  else
    {
      vrf_fib_index = fib_table_find (fproto, vrf);
      if (~0 == vrf_fib_index)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (vrf_fib_index >= vec_len(gtm->tdf_ul_table[fproto]))
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      fib_index = fib_table_find (fproto, table_id);
      if (~0 == fib_index)
	return VNET_API_ERROR_NO_SUCH_FIB;

      if (vec_elt (gtm->tdf_ul_table[fproto], vrf_fib_index) != fib_index)
	return VNET_API_ERROR_NO_SUCH_TABLE;

      vec_elt (gtm->tdf_ul_table[fproto], vrf_fib_index) = ~0;
      fib_table_unlock (fib_index, fproto, FIB_SOURCE_PLUGIN_LOW);

      return (0);
    }

  return 0;
}

static clib_error_t *
upf_tdf_ul_table_add_del_command_fn (vlib_main_t * vm,
				     unformat_input_t * main_input,
				     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  fib_protocol_t fproto = FIB_PROTOCOL_IP4;
  u32 table_id = ~0;
  u32 vrf = 0;
  u8 add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "vrf %u", &vrf))
	;
      else if (unformat (line_input, "ip4"))
	fproto = FIB_PROTOCOL_IP4;
      else if (unformat (line_input, "ip6"))
	fproto = FIB_PROTOCOL_IP6;
      else if (unformat (line_input, "table-id %u", &table_id))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (table_id == ~0)
    return clib_error_return (0, "table-id must be specified");

  rv = vnet_upf_tdf_ul_table_add_del (vrf, fproto, table_id, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_FIB:
      error = clib_error_return (0, "TDF UL lookup table already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "In VRF instance does not exist...");
      break;

    default:
      error = clib_error_return (0, "vvnet_upf_tdf_ul_table_add_del %d", rv);
      break;
    }

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_tdf_ul_table_add_del_command, static) =
{
  .path = "upf tdf ul table",
  .short_help =
  "upf tdf ul table vrf <table-id> [ip4|ip6] table-id <src-lookup-table-id> [del]",
  .function = upf_tdf_ul_table_add_del_command_fn,
};
/* *INDENT-ON* */

static u32
upf_table_id_from_fib_index(fib_protocol_t fproto, u32 fib_index)
{
  return (fproto == FIB_PROTOCOL_IP4) ?
    ip4_fib_get(fib_index)->table_id :
    ip6_fib_get(fib_index)->table_id;
};

static clib_error_t *
upf_tdf_ul_table_show_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  upf_main_t *gtm = &upf_main;
  fib_protocol_t fproto;
  u32 ii;

  vlib_cli_output (vm, "UPF TDF UpLink VRF to fib-index mappings:");
  FOR_EACH_FIB_IP_PROTOCOL (fproto)
  {
    vlib_cli_output (vm, " %U", format_fib_protocol, fproto);
    vec_foreach_index (ii, gtm->tdf_ul_table[fproto])
    {
      if (~0 != vec_elt (gtm->tdf_ul_table[fproto], ii))
	{
	  u32 vrf_table_id =
	    upf_table_id_from_fib_index (fproto, ii);
	  u32 fib_table_id =
	    upf_table_id_from_fib_index (fproto, vec_elt (gtm->tdf_ul_table[fproto], ii));

	  vlib_cli_output (vm, "  %u -> %u", vrf_table_id, fib_table_id);
	}
    }
  }
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_tdf_ul_table_show_command, static) = {
  .path = "show upf tdf ul tables",
  .short_help = "Show UPF TDF UpLink tables",
  .function = upf_tdf_ul_table_show_fn,
};
/* *INDENT-ON* */

int
vnet_upf_tdf_ul_lookup_add_i (u32 tdf_ul_fib_index, const fib_prefix_t * pfx, u32 ue_fib_index)
{
  dpo_id_t dpo = DPO_INVALID;

  /*
   * create a data-path object to perform the source address lookup
   * in the TDF FIB
   */
  lookup_dpo_add_or_lock_w_fib_index (tdf_ul_fib_index,
				      fib_proto_to_dpo (pfx->fp_proto),
				      LOOKUP_UNICAST,
				      LOOKUP_INPUT_SRC_ADDR,
				      LOOKUP_TABLE_FROM_CONFIG, &dpo);

  /*
   * add the entry to the destination FIB that uses the lookup DPO
   */
  fib_table_entry_special_dpo_add (ue_fib_index, pfx,
				   FIB_SOURCE_PLUGIN_LOW,
				   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);

  /*
   * the DPO is locked by the FIB entry, and we have no further
   * need for it.
   */
   dpo_unlock (&dpo);

  return 0;
}


int
vnet_upf_tdf_ul_lookup_delete (u32 tdf_ul_fib_index, const fib_prefix_t * pfx)
{
  fib_table_entry_special_remove (tdf_ul_fib_index, pfx, FIB_SOURCE_PLUGIN_LOW);

  return (0);
}

static int
upf_tdf_ul_enable (fib_protocol_t fproto, u32 sw_if_index)
{
  upf_main_t *gtm = &upf_main;
  fib_prefix_t pfx = {
    .fp_proto = fproto,
  };
  u32 fib_index;

  fib_index =
    fib_table_get_index_for_sw_if_index (fproto, sw_if_index);

  if (fib_index >= vec_len(gtm->tdf_ul_table[fproto]))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (~0 == vec_elt (gtm->tdf_ul_table[fproto], fib_index))
    return VNET_API_ERROR_NO_SUCH_FIB;

  /*
   * now we know which interface the table will serve, we can add the default
   * route to use the table that the interface is bound to.
   */
  vnet_upf_tdf_ul_lookup_add_i (vec_elt (gtm->tdf_ul_table[fproto], fib_index), &pfx, fib_index);


  /*
  vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				"ip4-unicast" :
				"ip6-unicast"),
			       (FIB_PROTOCOL_IP4 == fproto ?
				"svs-ip4" :
				"svs-ip6"), sw_if_index, 1, NULL, 0);
  */

  return 0;
}

static int
upf_tdf_ul_disable (fib_protocol_t fproto, u32 sw_if_index)
{
  upf_main_t *gtm = &upf_main;
  u32 fib_index;

  fib_index =
    fib_table_get_index_for_sw_if_index (fproto, sw_if_index);

  if (fib_index >= vec_len(gtm->tdf_ul_table[fproto]))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (~0 == vec_elt (gtm->tdf_ul_table[fproto], fib_index))
    return VNET_API_ERROR_NO_SUCH_FIB;

  /*
  vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				"ip4-unicast" :
				"ip6-unicast"),
			       (FIB_PROTOCOL_IP4 == fproto ?
				"svs-ip4" :
				"svs-ip6"), sw_if_index, 0, NULL, 0);
  */
  return 0;
}

static clib_error_t *
upf_tdf_ul_enable_command_fn (vlib_main_t * vm,
			      unformat_input_t * main_input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_protocol_t fproto = FIB_PROTOCOL_IP4;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 enable = 1;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (line_input, "enable"))
	enable = 1;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else if (unformat (line_input, "ip4"))
	fproto = FIB_PROTOCOL_IP4;
      else if (unformat (line_input, "ip6"))
	fproto = FIB_PROTOCOL_IP6;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");

  if (enable)
    upf_tdf_ul_enable (fproto, sw_if_index);
  else
    upf_tdf_ul_disable (fproto, sw_if_index);

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_tdf_ul_enable_command, static) = {
    .path = "upf tdf ul enable",
    .short_help = "UPF TDF UpLink [enable|disable] [ip4|ip6] <interface>",
    .function = upf_tdf_ul_enable_command_fn,
};
/* *INDENT-ON* */


/**********************************************************/

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_gtpu_endpoint_command, static) =
{
  .path = "upf gtpu endpoint",
  .short_help =
  "upf gtpu endpoint [ip <v4 address>] [ip6 <v6 address>] [nwi <name>]"
  " [src access | core | sgi | cp] [teid <teid>/<mask>] [del]",
  .function = upf_gtpu_endpoint_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_gtpu_endpoint_command_fn (vlib_main_t * vm,
				   unformat_input_t * main_input,
				   vlib_cli_command_t * cmd)
{
  upf_main_t *gtm = &upf_main;
  clib_error_t *error = NULL;
  upf_upip_res_t *res;

  /* TBD....
  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "name %_%v%_", &s))
	    {
	      name = upf_name_to_labels (s);
	      vec_free (s);
	    }
	  else
	    {
	      error = unformat_parse_error (line_input);
	      unformat_free (line_input);
	      goto done;
	    }
	}

      unformat_free (line_input);
    }
  */

  /* *INDENT-OFF* */
  pool_foreach (res, gtm->upip_res,
  ({
    vlib_cli_output (vm, "[%d]: %U", res - gtm->upip_res,
		     format_gtpu_endpoint, res);
  }));
  /* *INDENT-ON* */

  //done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_gtpu_endpoint_command, static) =
{
  .path = "show upf gtpu endpoint",
  .short_help =
  "show upf gtpu endpoint",
  .function = upf_show_gtpu_endpoint_command_fn,
};
/* *INDENT-ON* */

void
upf_flows_out_cb (BVT (clib_bihash_kv) * kvp, void *arg)
{
  flowtable_main_t *fm = &flowtable_main;
  vlib_main_t *vm = (vlib_main_t *) arg;
  flow_entry_t *flow;

  flow = pool_elt_at_index (fm->flows, kvp->value);
  vlib_cli_output (vm, "%U", format_flow, flow);
}

static clib_error_t *
upf_show_session_command_fn (vlib_main_t * vm,
			     unformat_input_t * main_input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *gtm = &upf_main;
  clib_error_t *error = NULL;
  u64 cp_seid, up_seid;
  ip46_address_t cp_ip;
  u8 has_cp_f_seid = 0, has_up_seid = 0;
  upf_session_t *sess = NULL;
  int debug = 0;
#if FLOWTABLE_TODO
  u8 has_flows = 0;
#endif

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "cp %U seid %lu",
			unformat_ip46_address, &cp_ip, IP46_TYPE_ANY,
			&cp_seid))
	    has_cp_f_seid = 1;
	  else if (unformat (line_input, "cp %U seid 0x%lx",
			     unformat_ip46_address, &cp_ip, IP46_TYPE_ANY,
			     &cp_seid))
	    has_cp_f_seid = 1;
	  else if (unformat (line_input, "up seid %lu", &up_seid))
	    has_up_seid = 1;
	  else if (unformat (line_input, "up seid 0x%lx", &up_seid))
	    has_up_seid = 1;
	  else if (unformat (line_input, "debug"))
	    debug = 1;
#if FLOWTABLE_TODO
	  else if (unformat (line_input, "%lu flows", &up_seid))
	    has_flows = 1;
	  else if (unformat (line_input, "0x%lx flows", &up_seid))
	    has_flows = 1;
#endif
	  else
	    {
	      error = unformat_parse_error (line_input);
	      unformat_free (line_input);
	      goto done;
	    }
	}

      unformat_free (line_input);
    }

#if FLOWTABLE_TODO
  if (has_flows)
    {
      if (!(sess = sx_lookup (up_seid)))
	{
	  error = clib_error_return (0, "Sessions 0x%lx not found", up_seid);
	  goto done;
	}

      BV (clib_bihash_foreach_key_value_pair)
	(&sess->fmt.flows_ht, upf_flows_out_cb, vm);
      goto done;
    }
#endif

  if (has_cp_f_seid)
    {
      error = clib_error_return (0, "CP F_SEID is not supported, yet");
      goto done;
    }

  if (has_up_seid)
    {
      if (!(sess = sx_lookup (up_seid)))
	{
	  error = clib_error_return (0, "Sessions %d not found", up_seid);
	  goto done;
	}

      vlib_cli_output (vm, "%U", format_sx_session, sess, SX_ACTIVE, debug);
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (sess, gtm->sessions,
      ({
	vlib_cli_output (vm, "%U", format_sx_session, sess, SX_ACTIVE, debug);
      }));
      /* *INDENT-ON* */
    }

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_session_command, static) =
{
  .path = "show upf session",
  .short_help =
  "show upf session",
  .function = upf_show_session_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_assoc_command_fn (vlib_main_t * vm,
			   unformat_input_t * main_input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *gtm = &upf_main;
  clib_error_t *error = NULL;
  u8 has_ip = 0, has_fqdn = 0;
  ip46_address_t node_ip;
  upf_node_assoc_t *node;
  u8 verbose = 0;
  u8 *fqdn = 0;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "ip %U",
			unformat_ip46_address, &node_ip, IP46_TYPE_ANY))
	    has_ip = 1;
	  else if (unformat (line_input, "fqdn %_%v%_", &fqdn))
	    has_fqdn = 1;
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else
	    {
	      error = unformat_parse_error (line_input);
	      unformat_free (line_input);
	      goto done;
	    }
	}

      unformat_free (line_input);
    }

  if (has_ip && has_fqdn)
    {
      error =
	clib_error_return (0,
			   "Only one selector is allowed, eith ip or fqdn");
      goto done;
    }

  if (has_ip && has_fqdn)
    {
      pfcp_node_id_t node_id;

      if (has_ip)
	{
	  node_id.type = ip46_address_is_ip4 (&node_ip) ? NID_IPv4 : NID_IPv6;
	  node_id.ip = node_ip;
	}
      if (has_fqdn)
	{
	  node_id.type = NID_FQDN;
	  node_id.fqdn = upf_name_to_labels (fqdn);
	}

      node = sx_get_association (&node_id);

      if (node_id.type == NID_FQDN)
	vec_free (node_id.fqdn);

      if (!node)
	{
	  error = clib_error_return (0, "Association not found");
	  goto done;
	}

      vlib_cli_output (vm, "%U", format_sx_node_association, node, verbose);
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (node, gtm->nodes,
      ({
	vlib_cli_output (vm, "%U", format_sx_node_association, node, verbose);
      }));
      /* *INDENT-ON* */
    }

done:
  if (fqdn)
    vec_free (fqdn);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_assoc_command, static) =
{
  .path = "show upf association",
  .short_help =
  "show upf association",
  .function = upf_show_assoc_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_flows_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  flowtable_main_t *fm = &flowtable_main;
  flowtable_main_per_cpu_t *fmt = &fm->per_cpu[0];

  BV (clib_bihash_foreach_key_value_pair)
    (&fmt->flows_ht, upf_flows_out_cb, vm);

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_flows_command, static) =
{
  .path = "show upf flows",
  .short_help = "show upf flows",
  .function = upf_show_flows_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_init (vlib_main_t * vm)
{
  upf_main_t *sm = &upf_main;
  clib_error_t *error;

  sm->vnet_main = vnet_get_main ();
  sm->vlib_main = vm;

  if ((error =
       vlib_call_init_function (vm, upf_proxy_main_init)))
    return error;

  sm->pfcp_endpoint_index =
    hash_create_mem (0, sizeof (ip46_address_t), sizeof (uword));

  sm->nwi_index_by_name =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));

  sm->upip_res_index =
    hash_create_mem (0, sizeof (upf_upip_res_t), sizeof (uword));

  /* initialize the IP/TEID hash's */
  clib_bihash_init_8_8 (&sm->v4_tunnel_by_key,
			"upf_v4_tunnel_by_key", UPF_MAPPING_BUCKETS,
			UPF_MAPPING_MEMORY_SIZE);
  clib_bihash_init_24_8 (&sm->v6_tunnel_by_key,
			 "upf_v6_tunnel_by_key", UPF_MAPPING_BUCKETS,
			 UPF_MAPPING_MEMORY_SIZE);

  sm->peer_index_by_ip =
    hash_create_mem (0, sizeof (ip46_address_fib_t), sizeof (uword));

  sm->node_index_by_fqdn =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));
  sm->node_index_by_ip =
    hash_create_mem (0, sizeof (ip46_address_t), sizeof (uword));

#if 0
  sm->vtep6 = hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
#endif

  clib_bihash_init_8_8 (&sm->qer_by_id,
			"upf_qer_by_ie", UPF_MAPPING_BUCKETS,
			UPF_MAPPING_MEMORY_SIZE);

  udp_register_dst_port (vm, UDP_DST_PORT_GTPU,
			 gtpu4_input_node.index, /* is_ip4 */ 1);
  udp_register_dst_port (vm, UDP_DST_PORT_GTPU6,
			 gtpu6_input_node.index, /* is_ip4 */ 0);

  sm->fib_node_type = fib_node_register_new_type (&upf_vft);

  sm->upf_app_by_name = hash_create_vec ( /* initial length */ 32,
					 sizeof (u8), sizeof (uword));

  error = flowtable_init (vm);
  if (error)
    return error;

  return sx_server_main_init (vm);
}

VLIB_INIT_FUNCTION (upf_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (upf, static) =
{
  .arc_name = "device-input",
  .node_name = "upf",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

u8 *
format_upf_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_encap_trace_t *t = va_arg (*args, upf_encap_trace_t *);

  s = format (s, "GTPU encap to upf_session%d teid 0x%08x",
	      t->session_index, t->teid);
  return s;
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
