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

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/pfcp.h>
#include <upf/upf_pfcp_server.h>

/* Action function shared between message handler and debug CLI */
#include <upf/flowtable.h>
#include <upf/upf_adf.h>

int upf_enable_disable (upf_main_t * sm, u32 sw_if_index,
			  int enable_disable)
{
  vnet_sw_interface_t * sw;
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
  upf_main_t * sm = &upf_main;
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

  switch(rv)
    {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "upf_enable_disable returned %d",
			      rv);
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

int vnet_upf_pfcp_endpoint_add_del(ip46_address_t *ip, u32 fib_index, u8 add)
{
  upf_main_t * gtm = &upf_main;
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

      hash_set_mem_alloc (&gtm->pfcp_endpoint_index, &ep->key, ep - gtm->pfcp_endpoints);
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
  clib_error_t * error = NULL;
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
      else if (unformat (line_input, "%U", unformat_ip46_address, &ip, IP46_TYPE_ANY))
	addr_set = 1;
      else if (unformat (line_input, "vrf %u", &vrf))
	;
      else {
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
      fib_index = fib_table_find (fib_ip_proto (!ip46_address_is_ip4(&ip)), vrf);
      if (fib_index == ~0)
	{
	  error = clib_error_return (0, "nonexistent vrf %d", vrf);
	  goto done;
	}
    }

  rv = vnet_upf_pfcp_endpoint_add_del(&ip, fib_index, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance does not exist...");
      break;

    default:
      error = clib_error_return
	(0, "vnet_upf_pfcp_endpoint_add_del %d", rv);
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
  upf_main_t * gtm = &upf_main;
  clib_error_t * error = NULL;
  upf_pfcp_endpoint_t *ep;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {

      clib_warning("Past unformat");
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  error = unformat_parse_error (line_input);
	  unformat_free (line_input);
	  goto done;
	}

      unformat_free (line_input);
    }

  clib_warning("pool");

  vlib_cli_output (vm, "Endpoints: %d\n", pool_elts (gtm->pfcp_endpoints));
  pool_foreach (ep, gtm->pfcp_endpoints,
	({
	  vlib_cli_output (vm, "  %U\n", format_pfcp_endpoint, ep);
	}));

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

int vnet_upf_nwi_add_del(u8 * name, u8 add)
{
  upf_main_t * gtm = &upf_main;
  upf_nwi_t * nwi;
  uword *p;

  p = hash_get_mem (gtm->nwi_index_by_name, name);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (gtm->nwis, nwi);
      memset (nwi, 0, sizeof (*nwi));

      nwi->name = vec_dup(name);

      for (int i = 0; i < ARRAY_LEN(nwi->intf_sw_if_index); i++)
	nwi->intf_sw_if_index[i] = ~0;

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
  clib_error_t * error = NULL;
  u8 *name = NULL;
  u8 *label = NULL;
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
      else if (unformat (line_input, "name %_%v%_", &name))
	;
      else if (unformat (line_input, "label %_%v%_", &label))
	;
      else {
	error = unformat_parse_error (line_input);
	goto done;
      }
    }

  if (!name && !label)
    return clib_error_return (0, "name or label must be specified!");

  if (!name)
    name = upf_name_to_labels(label);

  rv = vnet_upf_nwi_add_del(name, add);

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
      error = clib_error_return
	(0, "vnet_upf_nwi_add_del returned %d", rv);
      break;
    }

done:
  vec_free (name);
  vec_free (label);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_nwi_add_del_command, static) =
{
  .path = "upf nwi create",
  .short_help =
  "upf nwi create [name <name> | dns <label>]",
  .function = upf_nwi_add_del_command_fn,
};
/* *INDENT-ON* */

#if 0
static void vtep_ip4_ref(ip4_address_t * ip, u8 ref)
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

static void vtep_ip6_ref(ip6_address_t * ip, u8 ref)
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

static void vtep_if_address_add_del(u32 sw_if_index, u8 add)
{
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;
  ip4_address_t *ip4;
  ip6_address_t *ip6;

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
}
#endif

int vnet_upf_nwi_set_addr(u8 * name, ip46_address_t *ip, u32 teid, u32 mask, u8 add)
{
  upf_main_t * gtm = &upf_main;
  upf_nwi_ip_res_t *ip_res;
  upf_nwi_t * nwi;
  uword *p;

  p = hash_get_mem (gtm->nwi_index_by_name, name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  nwi = pool_elt_at_index (gtm->nwis, p[0]);
  if (!nwi->ip_res_index_by_ip)
    nwi->ip_res_index_by_ip =
      hash_create_mem (0, sizeof (ip46_address_t), sizeof (uword));

  p = hash_get_mem (nwi->ip_res_index_by_ip, ip);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (nwi->ip_res, ip_res);
      memset (ip_res, 0, sizeof (*ip_res));

      ip_res->ip = *ip;
      ip_res->teid = teid & mask;
      ip_res->mask = mask;

      hash_set_mem_alloc(&nwi->ip_res_index_by_ip, &ip_res->ip, ip_res - nwi->ip_res);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      ip_res = pool_elt_at_index (nwi->ip_res, p[0]);
      hash_unset_mem_free (&nwi->ip_res_index_by_ip, &ip_res->ip);
      pool_put(nwi->ip_res, ip_res);
    }

  return 0;
}

clib_error_t *
upf_nwi_set_addr_command_fn (vlib_main_t * vm,
			       unformat_input_t * main_input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t * error = NULL;
  u32 addr_set = 0;
  ip46_address_t ip;
  u32 teid = 0, mask = 0, teidri = 0;
  u8 *name = NULL;
  u8 *label = NULL;
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
      else if (unformat (line_input, "name %_%v%_", &name))
	;
      else if (unformat (line_input, "label %_%v%_", &label))
	;
      else if (unformat (line_input, "%U", unformat_ip46_address, &ip, IP46_TYPE_ANY))
	addr_set = 1;
      else if (unformat (line_input, "teid %u/%u", &teid, &teidri))
	{
	  if (teidri > 7) {
	    error = clib_error_return (0, "TEID Range Indication to large (%d > 7)", teidri);
	    goto done;
	  }
	  mask = 0xfe000000 << (7 - teidri);
	}
      else if (unformat (line_input, "teid 0x%x/%u", &teid, &teidri))
	{
	  if (teidri > 7) {
	    error = clib_error_return (0, "TEID Range Indication to large (%d > 7)", teidri);
	    goto done;
	  }
	  mask = 0xfe000000 << (7 - teidri);
	}
      else {
	error = unformat_parse_error (line_input);
	goto done;
      }
    }

  if (!addr_set)
    {
      error = clib_error_return (0, "No IP address provided");
      goto done;
    }
  if (!name && !label)
    {
      error = clib_error_return (0, "name or label must be specified");
      goto done;
    }

  if (!name)
    name = upf_name_to_labels(label);

  rv = vnet_upf_nwi_set_addr(name, &ip, teid, mask, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "IP resource already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance or IP resource does not exist...");
      break;

    default:
      error = clib_error_return
	(0, "vnet_upf_nwi_set_addr returned %d", rv);
      break;
    }

 done:
  vec_free (name);
  vec_free (label);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_nwi_set_addr_command, static) =
{
  .path = "upf nwi set gtpu address",
  .short_help =
  "upf nwi set gtpu address [name <name> | dns <label>] <address> [teid <teid>/<mask>] [del]",
  .function = upf_nwi_set_addr_command_fn,
};
/* *INDENT-ON* */

int vnet_upf_nwi_set_intf_role(u8 * name, u8 intf, u32 sw_if_index, u8 add)
{
  upf_main_t * gtm = &upf_main;
  upf_nwi_t * nwi;
  u32 nwi_index;
  uword *p;

  if (intf >= INTF_NUM)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  p = hash_get_mem (gtm->nwi_index_by_name, name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  nwi_index = p[0];
  nwi = pool_elt_at_index (gtm->nwis, nwi_index);

  if (add)
    {
      if (sw_if_index < vec_len(gtm->nwi_index_by_sw_if_index) &&
	  gtm->nwi_index_by_sw_if_index[sw_if_index] != ~0)
	return VNET_API_ERROR_VALUE_EXIST;

      vec_validate_init_empty(gtm->nwi_index_by_sw_if_index, sw_if_index, ~0);
      vec_validate_init_empty(gtm->intf_type_by_sw_if_index, sw_if_index, ~0);
      gtm->nwi_index_by_sw_if_index[sw_if_index] = nwi_index;
      gtm->intf_type_by_sw_if_index[sw_if_index] = intf;
      nwi->intf_sw_if_index[intf] = sw_if_index;
    }
  else
    {
      if (sw_if_index > vec_len(gtm->nwi_index_by_sw_if_index) ||
	  gtm->nwi_index_by_sw_if_index[sw_if_index] != nwi_index)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      gtm->nwi_index_by_sw_if_index[sw_if_index] = ~0;
      gtm->intf_type_by_sw_if_index[sw_if_index] = ~0;
      nwi->intf_sw_if_index[intf] = ~0;
    }

  return 0;
}

clib_error_t *
upf_nwi_set_intf_role_command_fn (vlib_main_t * vm,
				    unformat_input_t * main_input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t * error = NULL;
  u8 *name = NULL;
  u8 *label = NULL;
  u8 intf = ~0;
  u32 sw_if_index = ~0;
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
      else if (unformat (line_input, "name %_%v%_", &name))
	;
      else if (unformat (line_input, "label %_%v%_", &label))
	;
      else if (unformat (line_input, "interface %U",
			   unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "access"))
	intf = INTF_ACCESS;
      else if (unformat (line_input, "core"))
	intf = INTF_CORE;
      else if (unformat (line_input, "sgi"))
	intf = INTF_SGI_LAN;
      else if (unformat (line_input, "cp"))
	intf = INTF_CP;
      else if (unformat (line_input, "li"))
	intf = INTF_LI;
      else {
	error = unformat_parse_error (line_input);
	goto done;
      }
    }

  if (intf == (u8)~0)
    {
      error = clib_error_return (0, "Interface type not specified");
      goto done;
    }
  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "Interface or sw_if_index not specified");
      goto done;
    }
  if (!name && !label)
    {
      error = clib_error_return (0, "name or label must be specified");
      goto done;
    }

  if (!name)
    name = upf_name_to_labels(label);

  rv = vnet_upf_nwi_set_intf_role(name, intf, sw_if_index, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance does not exist...");
      break;

    default:
      error = clib_error_return
	(0, "vnet_upf_nwi_set_intf_role returned %d", rv);
      break;
    }

 done:
  vec_free (name);
  vec_free (label);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_nwi_set_intf_role_command, static) =
{
  .path = "upf nwi set interface type",
  .short_help =
  "upf nwi set interface type [name <name> | dns <label>] [access | core | sgi | cp] [interface <interface> | sw_if_index <inde>] [del]",
  .function = upf_nwi_set_intf_role_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_nwi_command_fn (vlib_main_t * vm,
			   unformat_input_t * main_input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  upf_main_t * gtm = &upf_main;
  clib_error_t * error = NULL;
  upf_nwi_t * nwi;
  u8 *label = NULL;
  u8 *name = NULL;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "name %_%v%_", &name))
	    ;
	  else if (unformat (line_input, "label %_%v%_", &label))
	    ;
	  else {
	    error = unformat_parse_error (line_input);
	    unformat_free (line_input);
	    goto done;
	  }
	}

      unformat_free (line_input);
    }

  if (!name && label)
    name = upf_name_to_labels(label);

  pool_foreach (nwi, gtm->nwis,
    ({
      upf_nwi_ip_res_t * ip_res;

      if (name && !vec_is_equal(name, nwi->name))
	continue;

      vlib_cli_output (vm, "%U", format_network_instance, nwi->name);
      vlib_cli_output (vm, "  Access: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_ACCESS]);
      vlib_cli_output (vm, "  Core: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_CORE]);
      vlib_cli_output (vm, "  SGi LAN: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_SGI_LAN]);
      vlib_cli_output (vm, "  CP: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_CP]);
      vlib_cli_output (vm, "  LI: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_LI]);

      vlib_cli_output (vm, "  IPs: %d", pool_elts(nwi->ip_res));

      pool_foreach (ip_res, nwi->ip_res,
	({
	  vlib_cli_output (vm, "  [%d]: IP: %U, teid: 0x%08x/%d (0x%08x)",
			   ip_res - nwi->ip_res,
			   format_ip46_address, &ip_res->ip, IP46_TYPE_ANY,
			   ip_res->teid, __builtin_popcount(ip_res->mask),
			   ip_res->mask);
	}));
    }));

done:
  vec_free (name);
  vec_free (label);
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

void upf_flows_out_cb (BVT (clib_bihash_kv) * kvp, void * arg)
{
  flowtable_main_t * fm = &flowtable_main;
  vlib_main_t * vm = (vlib_main_t *) arg;
  flow_entry_t *flow;

  flow = pool_elt_at_index(fm->flows, kvp->value);
  vlib_cli_output (vm, "%U", format_flow, flow);
}

static clib_error_t *
upf_show_session_command_fn (vlib_main_t * vm,
			       unformat_input_t * main_input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t * gtm = &upf_main;
  clib_error_t * error = NULL;
  u64 cp_seid, up_seid;
  ip46_address_t cp_ip;
  u8 has_cp_f_seid = 0, has_up_seid = 0;
  upf_session_t *sess = NULL;
#if FLOWTABLE_TODO
  u8 has_flows = 0;
#endif

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "cp %U seid %lu",
			unformat_ip46_address, &cp_ip, IP46_TYPE_ANY, &cp_seid))
	    has_cp_f_seid = 1;
	  else if (unformat (line_input, "cp %U seid 0x%lx",
			     unformat_ip46_address, &cp_ip, IP46_TYPE_ANY, &cp_seid))
	    has_cp_f_seid = 1;
	  else if (unformat (line_input, "up seid %lu", &up_seid))
	    has_up_seid = 1;
	  else if (unformat (line_input, "up seid 0x%lx", &up_seid))
	    has_up_seid = 1;
#if FLOWTABLE_TODO
	  else if (unformat (line_input, "%lu flows", &up_seid))
	    has_flows = 1;
	  else if (unformat (line_input, "0x%lx flows", &up_seid))
	    has_flows = 1;
#endif
	  else {
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
      if (!(sess = sx_lookup(up_seid)))
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
      if (!(sess = sx_lookup(up_seid)))
	{
	  error = clib_error_return (0, "Sessions %d not found", up_seid);
	  goto done;
	}

      vlib_cli_output (vm, "%U", format_sx_session, sess, SX_ACTIVE);
    }
  else
      pool_foreach (sess, gtm->sessions,
	({
	  vlib_cli_output (vm, "%U", format_sx_session, sess, SX_ACTIVE);
	}));

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
  upf_main_t * gtm = &upf_main;
  clib_error_t * error = NULL;
  u8 has_ip = 0, has_fqdn = 0;
  ip46_address_t node_ip;
  upf_node_assoc_t *node;
  u8 verbose = 0;
  u8 * fqdn = 0;

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
	  else {
	    error = unformat_parse_error (line_input);
	    unformat_free (line_input);
	    goto done;
	  }
	}

      unformat_free (line_input);
    }

  if (has_ip && has_fqdn)
    {
      error = clib_error_return (0, "Only one selector is allowed, eith ip or fqdn");
      goto done;
    }

  if (has_ip && has_fqdn)
    {
      pfcp_node_id_t node_id;

      if (has_ip)
	{
	  node_id.type = ip46_address_is_ip4(&node_ip) ? NID_IPv4 : NID_IPv6;
	  node_id.ip = node_ip;
	}
      if (has_fqdn)
	{
	  node_id.type = NID_FQDN;
	  node_id.fqdn = upf_name_to_labels(fqdn);
	}

      node = sx_get_association(&node_id);

      if (node_id.type == NID_FQDN)
	vec_free(node_id.fqdn);

      if (!node)
	{
	  error = clib_error_return (0, "Association not found");
	  goto done;
	}

      vlib_cli_output (vm, "%U", format_sx_node_association, node, verbose);
    }
  else
    pool_foreach (node, gtm->nodes,
      ({
	vlib_cli_output (vm, "%U", format_sx_node_association, node, verbose);
      }));

 done:
  if (fqdn)
    vec_free(fqdn);

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
			   unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  flowtable_main_t * fm = &flowtable_main;
  flowtable_main_per_cpu_t * fmt = &fm->per_cpu[0];

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

static clib_error_t * upf_init (vlib_main_t * vm)
{
  upf_main_t * sm = &upf_main;
  char *argv[] = { "upf", "--no-huge", "--no-pci", NULL };
  clib_error_t * error;
  int ret;

  sm->vnet_main = vnet_get_main ();
  sm->vlib_main = vm;

  ret = rte_eal_init (3, argv);
  if (ret < 0)
    return clib_error_return (0, "rte_eal_init returned %d", ret);
  rte_log_set_global_level (RTE_LOG_DEBUG);

  sm->pfcp_endpoint_index = hash_create_mem (0, sizeof (ip46_address_t), sizeof (uword));

  sm->nwi_index_by_name =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));

  /* initialize the IP/TEID hash's */
  clib_bihash_init_8_8 (&sm->v4_tunnel_by_key,
			"upf_v4_tunnel_by_key", UPF_MAPPING_BUCKETS,
			UPF_MAPPING_MEMORY_SIZE);
  clib_bihash_init_24_8 (&sm->v6_tunnel_by_key,
			"upf_v6_tunnel_by_key", UPF_MAPPING_BUCKETS,
			UPF_MAPPING_MEMORY_SIZE);

  sm->peer_index_by_ip = hash_create_mem (0, sizeof (ip46_address_fib_t), sizeof (uword));

  sm->node_index_by_fqdn =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));
  sm->node_index_by_ip = hash_create_mem (0, sizeof (ip46_address_t), sizeof (uword));

#if 0
  sm->vtep6 = hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
#endif

  udp_register_dst_port (vm, UDP_DST_PORT_GTPU,
			 gtpu4_input_node.index, /* is_ip4 */ 1);
  udp_register_dst_port (vm, UDP_DST_PORT_GTPU6,
			 gtpu6_input_node.index, /* is_ip4 */ 0);

  sm->fib_node_type = fib_node_register_new_type (&upf_vft);

  sm->upf_app_by_name = hash_create_vec ( /* initial length */ 32,
				      sizeof (u8), sizeof (uword));

  error = flowtable_init(vm);
  if (error)
    return error;

  return sx_server_main_init(vm);
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
