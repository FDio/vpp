/*
 * nsh_cli.c - nsh cli functions
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
#include <vnet/plugin/plugin.h>
#include <nsh/nsh.h>
#include <vnet/adj/adj.h>

/* format from network order */
u8 *
format_nsh_pop_header (u8 * s, va_list * args)
{
  return format_nsh_header (s, args);
}

u8 *
format_nsh_pop_node_map_trace (u8 * s, va_list * args)
{
  return format_nsh_node_map_trace (s, args);
}

static uword
unformat_nsh_action (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 tmp;

  if (unformat (input, "swap"))
    *result = NSH_ACTION_SWAP;
  else if (unformat (input, "push"))
    *result = NSH_ACTION_PUSH;
  else if (unformat (input, "pop"))
    *result = NSH_ACTION_POP;
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;

  return 1;
}

static u8 *
format_nsh_action (u8 * s, va_list * args)
{
  u32 nsh_action = va_arg (*args, u32);

  switch (nsh_action)
    {
    case NSH_ACTION_SWAP:
      return format (s, "swap");
    case NSH_ACTION_PUSH:
      return format (s, "push");
    case NSH_ACTION_POP:
      return format (s, "pop");
    default:
      return format (s, "unknown %d", nsh_action);
    }
  return s;
}

u8 *
format_nsh_map (u8 * s, va_list * args)
{
  nsh_map_t *map = va_arg (*args, nsh_map_t *);

  s = format (s, "nsh entry nsp: %d nsi: %d ",
	      (map->nsp_nsi >> NSH_NSP_SHIFT) & NSH_NSP_MASK,
	      map->nsp_nsi & NSH_NSI_MASK);
  s = format (s, "maps to nsp: %d nsi: %d ",
	      (map->mapped_nsp_nsi >> NSH_NSP_SHIFT) & NSH_NSP_MASK,
	      map->mapped_nsp_nsi & NSH_NSI_MASK);

  s = format (s, " nsh_action %U\n", format_nsh_action, map->nsh_action);

  switch (map->next_node)
    {
    case NSH_NODE_NEXT_ENCAP_GRE4:
      {
	s = format (s, "encapped by GRE4 intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_ENCAP_GRE6:
      {
	s = format (s, "encapped by GRE6 intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_ENCAP_VXLANGPE:
      {
	s = format (s, "encapped by VXLAN GPE intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_ENCAP_VXLAN4:
      {
	s = format (s, "encapped by VXLAN4 intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_ENCAP_VXLAN6:
      {
	s = format (s, "encapped by VXLAN6 intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_DECAP_ETH_INPUT:
      {
	s = format (s, "encap-none");
	break;
      }
    case NSH_NODE_NEXT_ENCAP_LISP_GPE:
      {
	s = format (s, "encapped by LISP GPE intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_ENCAP_ETHERNET:
      {
	s = format (s, "encapped by Ethernet intf: %d", map->sw_if_index);
	break;
      }
    default:
      s = format (s, "only GRE and VXLANGPE support in this rev");
    }

  return s;
}

static adj_index_t
nsh_get_adj_by_sw_if_index (u32 sw_if_index)
{
  adj_index_t ai = ~0;

  /* *INDENT-OFF* */
  pool_foreach_index(ai, adj_pool,
  ({
      if (sw_if_index == adj_get_sw_if_index(ai))
      {
        return ai;
      }
  }));
  /* *INDENT-ON* */

  return ~0;
}


/**
 * CLI command for NSH map
 */
static clib_error_t *
nsh_add_del_map_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 nsp, nsi, mapped_nsp, mapped_nsi, nsh_action;
  int nsp_set = 0, nsi_set = 0, mapped_nsp_set = 0, mapped_nsi_set = 0;
  int nsh_action_set = 0;
  u32 next_node = ~0;
  u32 adj_index = ~0;
  u32 sw_if_index = ~0;		// temporary requirement to get this moved over to NSHSFC
  u32 rx_sw_if_index = ~0;	// temporary requirement to get this moved over to NSHSFC
  nsh_add_del_map_args_t _a, *a = &_a;
  u32 map_index;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "nsp %d", &nsp))
	nsp_set = 1;
      else if (unformat (line_input, "nsi %d", &nsi))
	nsi_set = 1;
      else if (unformat (line_input, "mapped-nsp %d", &mapped_nsp))
	mapped_nsp_set = 1;
      else if (unformat (line_input, "mapped-nsi %d", &mapped_nsi))
	mapped_nsi_set = 1;
      else if (unformat (line_input, "nsh_action %U", unformat_nsh_action,
			 &nsh_action))
	nsh_action_set = 1;
      else if (unformat (line_input, "encap-gre4-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_GRE4;
      else if (unformat (line_input, "encap-gre6-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_GRE6;
      else if (unformat (line_input, "encap-vxlan-gpe-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_VXLANGPE;
      else if (unformat (line_input, "encap-lisp-gpe-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_LISP_GPE;
      else if (unformat (line_input, "encap-vxlan4-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_VXLAN4;
      else if (unformat (line_input, "encap-vxlan6-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_VXLAN6;
      else if (unformat (line_input, "encap-eth-intf %d", &sw_if_index))
	{
	  next_node = NSH_NODE_NEXT_ENCAP_ETHERNET;
	  adj_index = nsh_get_adj_by_sw_if_index (sw_if_index);
	}
      else
	if (unformat
	    (line_input, "encap-none %d %d", &sw_if_index, &rx_sw_if_index))
	next_node = NSH_NODE_NEXT_DECAP_ETH_INPUT;
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (nsp_set == 0 || nsi_set == 0)
    return clib_error_return (0, "nsp nsi pair required. Key: for NSH entry");

  if (mapped_nsp_set == 0 || mapped_nsi_set == 0)
    return clib_error_return (0,
			      "mapped-nsp mapped-nsi pair required. Key: for NSH entry");

  if (nsh_action_set == 0)
    return clib_error_return (0, "nsh_action required: swap|push|pop.");

  if (next_node == ~0)
    return clib_error_return (0,
			      "must specific action: [encap-gre-intf <nn> | encap-vxlan-gpe-intf <nn> | encap-lisp-gpe-intf <nn> | encap-none <tx_sw_if_index> <rx_sw_if_index>]");

  clib_memset (a, 0, sizeof (*a));

  /* set args structure */
  a->is_add = is_add;
  a->map.nsp_nsi = (nsp << NSH_NSP_SHIFT) | nsi;
  a->map.mapped_nsp_nsi = (mapped_nsp << NSH_NSP_SHIFT) | mapped_nsi;
  a->map.nsh_action = nsh_action;
  a->map.sw_if_index = sw_if_index;
  a->map.rx_sw_if_index = rx_sw_if_index;
  a->map.next_node = next_node;
  a->map.adj_index = adj_index;

  rv = nsh_add_del_map (a, &map_index);

  switch (rv)
    {
    case 0:
      break;
    case -1:			//TODO API_ERROR_INVALID_VALUE:
      return clib_error_return (0,
				"mapping already exists. Remove it first.");

    case -2:			// TODO API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "mapping does not exist.");

    default:
      return clib_error_return (0, "nsh_add_del_map returned %d", rv);
    }

  if ((a->map.next_node == NSH_NODE_NEXT_ENCAP_VXLAN4)
      | (a->map.next_node == NSH_NODE_NEXT_ENCAP_VXLAN6))
    {
      rv = nsh_add_del_proxy_session (a);

      switch (rv)
	{
	case 0:
	  break;
	case -1:		//TODO API_ERROR_INVALID_VALUE:
	  return clib_error_return (0,
				    "nsh-proxy-session already exists. Remove it first.");

	case -2:		// TODO API_ERROR_NO_SUCH_ENTRY:
	  return clib_error_return (0, "nsh-proxy-session does not exist.");

	default:
	  return clib_error_return
	    (0, "nsh_add_del_proxy_session() returned %d", rv);
	}
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_nsh_map_command, static) = {
  .path = "create nsh map",
  .short_help =
    "create nsh map nsp <nn> nsi <nn> [del] mapped-nsp <nn> mapped-nsi <nn> nsh_action [swap|push|pop] "
    "[encap-gre4-intf <nn> | encap-gre4-intf <nn> | encap-vxlan-gpe-intf <nn> | encap-lisp-gpe-intf <nn> "
    " encap-vxlan4-intf <nn> | encap-vxlan6-intf <nn>| encap-eth-intf <nn> | encap-none]\n",
  .function = nsh_add_del_map_command_fn,
};
/* *INDENT-ON* */

/**
 * CLI command for showing the mapping between NSH entries
 */
static clib_error_t *
show_nsh_map_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nsh_main_t *nm = &nsh_main;
  nsh_map_t *map;

  if (pool_elts (nm->nsh_mappings) == 0)
    vlib_cli_output (vm, "No nsh maps configured.");

  pool_foreach (map, nm->nsh_mappings, (
					 {
					 vlib_cli_output (vm, "%U",
							  format_nsh_map,
							  map);
					 }
		));

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_nsh_map_command, static) = {
  .path = "show nsh map",
  .function = show_nsh_map_command_fn,
};
/* *INDENT-ON* */

/**
 * CLI command for adding NSH entry
 */
static clib_error_t *
nsh_add_del_entry_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u8 ver_o_c = 0;
  u8 ttl = 63;
  u8 length = 0;
  u8 md_type = 0;
  u8 next_protocol = 1;		/* default: ip4 */
  u32 nsp;
  u8 nsp_set = 0;
  u32 nsi;
  u8 nsi_set = 0;
  u32 nsp_nsi;
  u32 c1 = 0;
  u32 c2 = 0;
  u32 c3 = 0;
  u32 c4 = 0;
  u8 *data = 0;
  nsh_tlv_header_t tlv_header;
  u8 cur_len = 0, tlvs_len = 0;
  u8 *current;
  nsh_main_t *nm = &nsh_main;
  nsh_option_map_t _nsh_option, *nsh_option = &_nsh_option;
  u8 option_size = 0;
  u32 tmp;
  int rv;
  u32 entry_index;
  nsh_add_del_entry_args_t _a, *a = &_a;
  u8 has_ioam_trace_option = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "version %d", &tmp))
	ver_o_c |= (tmp & 3) << 6;
      else if (unformat (line_input, "o-bit %d", &tmp))
	ver_o_c |= (tmp & 1) << 5;
      else if (unformat (line_input, "c-bit %d", &tmp))
	ver_o_c |= (tmp & 1) << 4;
      else if (unformat (line_input, "ttl %d", &ttl))
	ver_o_c |= (ttl & NSH_LEN_MASK) >> 2;
      else if (unformat (line_input, "md-type %d", &tmp))
	md_type = tmp;
      else if (unformat (line_input, "next-ip4"))
	next_protocol = 1;
      else if (unformat (line_input, "next-ip6"))
	next_protocol = 2;
      else if (unformat (line_input, "next-ethernet"))
	next_protocol = 3;
      else if (unformat (line_input, "c1 %d", &c1))
	;
      else if (unformat (line_input, "c2 %d", &c2))
	;
      else if (unformat (line_input, "c3 %d", &c3))
	;
      else if (unformat (line_input, "c4 %d", &c4))
	;
      else if (unformat (line_input, "nsp %d", &nsp))
	nsp_set = 1;
      else if (unformat (line_input, "nsi %d", &nsi))
	nsi_set = 1;
      else if (unformat (line_input, "tlv-ioam-trace"))
	has_ioam_trace_option = 1;
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (nsp_set == 0)
    return clib_error_return (0, "nsp not specified");

  if (nsi_set == 0)
    return clib_error_return (0, "nsi not specified");

  if (md_type == 1 && has_ioam_trace_option == 1)
    return clib_error_return (0, "Invalid MD Type");

  nsp_nsi = (nsp << 8) | nsi;

  clib_memset (a, 0, sizeof (*a));
  a->is_add = is_add;

  if (md_type == 1)
    {
      a->nsh_entry.md.md1_data.c1 = c1;
      a->nsh_entry.md.md1_data.c2 = c2;
      a->nsh_entry.md.md1_data.c3 = c3;
      a->nsh_entry.md.md1_data.c4 = c4;
      length = (sizeof (nsh_base_header_t) + sizeof (nsh_md1_data_t)) >> 2;
    }
  else if (md_type == 2)
    {
      length = sizeof (nsh_base_header_t) >> 2;

      vec_free (a->nsh_entry.tlvs_data);
      tlvs_len = (MAX_METADATA_LEN << 2);
      vec_validate_aligned (data, tlvs_len - 1, CLIB_CACHE_LINE_BYTES);
      a->nsh_entry.tlvs_data = data;
      current = data;

      if (has_ioam_trace_option)
	{
	  tlv_header.class = clib_host_to_net_u16 (NSH_MD2_IOAM_CLASS);
	  tlv_header.type = NSH_MD2_IOAM_OPTION_TYPE_TRACE;
	  /* Uses network order's class and type to lookup */
	  nsh_option =
	    nsh_md2_lookup_option (tlv_header.class, tlv_header.type);
	  if (nsh_option == NULL)
	    return clib_error_return (0, "iOAM Trace not registered");

	  if (nm->add_options[nsh_option->option_id] != NULL)
	    {
	      if (0 != nm->add_options[nsh_option->option_id] ((u8 *) current,
							       &option_size))
		{
		  return clib_error_return (0, "Invalid MD Type");
		}
	    }

	  nm->options_size[nsh_option->option_id] = option_size;
	  /* round to 4-byte */
	  option_size = (((option_size + 3) >> 2) << 2);

	  cur_len += option_size;
	  current = data + option_size;
	}

      /* Add more options' parsing */

      a->nsh_entry.tlvs_len = cur_len;
      length += (cur_len >> 2);
    }
  length = (length & NSH_LEN_MASK) | ((ttl & 0x3) << 6);

#define _(x) a->nsh_entry.nsh_base.x = x;
  foreach_copy_nsh_base_hdr_field;
#undef _

  rv = nsh_add_del_entry (a, &entry_index);

  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "nsh_add_del_entry returned %d", rv);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_nsh_entry_command, static) = {
  .path = "create nsh entry",
  .short_help =
    "create nsh entry {nsp <nn> nsi <nn>} [ttl <nn>] [md-type <nn>]"
    "  [c1 <nn> c2 <nn> c3 <nn> c4 <nn>] [tlv-ioam-trace] [del]\n",
  .function = nsh_add_del_entry_command_fn,
};
/* *INDENT-ON* */

/* format from network order */
u8 *
format_nsh_header (u8 * s, va_list * args)
{
  nsh_main_t *nm = &nsh_main;
  nsh_md2_data_t *opt0;
  nsh_md2_data_t *limit0;
  nsh_option_map_t *nsh_option;
  u8 option_len = 0;

  u8 *header = va_arg (*args, u8 *);
  nsh_base_header_t *nsh_base = (nsh_base_header_t *) header;
  nsh_md1_data_t *nsh_md1 = (nsh_md1_data_t *) (nsh_base + 1);
  nsh_md2_data_t *nsh_md2 = (nsh_md2_data_t *) (nsh_base + 1);
  opt0 = (nsh_md2_data_t *) nsh_md2;
  limit0 = (nsh_md2_data_t *) ((u8 *) nsh_md2 +
			       ((nsh_base->length & NSH_LEN_MASK) * 4
				- sizeof (nsh_base_header_t)));

  s = format (s, "nsh ver %d ", (nsh_base->ver_o_c >> 6));
  if (nsh_base->ver_o_c & NSH_O_BIT)
    s = format (s, "O-set ");

  if (nsh_base->ver_o_c & NSH_C_BIT)
    s = format (s, "C-set ");

  s = format (s, "ttl %d ", (nsh_base->ver_o_c & NSH_TTL_H4_MASK) << 2 |
	      (nsh_base->length & NSH_TTL_L2_MASK) >> 6);

  s = format (s, "len %d (%d bytes) md_type %d next_protocol %d\n",
	      (nsh_base->length & NSH_LEN_MASK),
	      (nsh_base->length & NSH_LEN_MASK) * 4,
	      nsh_base->md_type, nsh_base->next_protocol);

  s = format (s, "  service path %d service index %d\n",
	      (clib_net_to_host_u32 (nsh_base->nsp_nsi) >> NSH_NSP_SHIFT) &
	      NSH_NSP_MASK,
	      clib_net_to_host_u32 (nsh_base->nsp_nsi) & NSH_NSI_MASK);

  if (nsh_base->md_type == 1)
    {
      s = format (s, "  c1 %d c2 %d c3 %d c4 %d\n",
		  clib_net_to_host_u32 (nsh_md1->c1),
		  clib_net_to_host_u32 (nsh_md1->c2),
		  clib_net_to_host_u32 (nsh_md1->c3),
		  clib_net_to_host_u32 (nsh_md1->c4));
    }
  else if (nsh_base->md_type == 2)
    {
      s = format (s, "  Supported TLVs: \n");

      /* Scan the set of variable metadata, network order */
      while (opt0 < limit0)
	{
	  nsh_option = nsh_md2_lookup_option (opt0->class, opt0->type);
	  if (nsh_option != NULL)
	    {
	      if (nm->trace[nsh_option->option_id] != NULL)
		{
		  s = (*nm->trace[nsh_option->option_id]) (s, opt0);
		}
	      else
		{
		  s =
		    format (s, "\n    untraced option %d length %d",
			    opt0->type, opt0->length);
		}
	    }
	  else
	    {
	      s =
		format (s, "\n    unrecognized option %d length %d",
			opt0->type, opt0->length);
	    }

	  /* round to 4-byte */
	  option_len = ((opt0->length + 3) >> 2) << 2;
	  opt0 =
	    (nsh_md2_data_t *) (((u8 *) opt0) + sizeof (nsh_md2_data_t) +
				option_len);
	}
    }

  return s;
}

u8 *
format_nsh_node_map_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nsh_input_trace_t *t = va_arg (*args, nsh_input_trace_t *);

  s = format (s, "\n  %U", format_nsh_header, &(t->trace_data));

  return s;
}

static clib_error_t *
show_nsh_entry_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nsh_main_t *nm = &nsh_main;
  nsh_entry_t *nsh_entry;

  if (pool_elts (nm->nsh_entries) == 0)
    vlib_cli_output (vm, "No nsh entries configured.");

  pool_foreach (nsh_entry, nm->nsh_entries, (
					      {
					      vlib_cli_output (vm, "%U",
							       format_nsh_header,
							       nsh_entry->rewrite);
					      vlib_cli_output (vm,
							       "  rewrite_size: %d bytes",
							       nsh_entry->rewrite_size);
					      }
		));

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_nsh_entry_command, static) = {
  .path = "show nsh entry",
  .function = show_nsh_entry_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
