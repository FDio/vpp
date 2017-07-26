/*
 * mpls.c: mpls
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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
#include <vnet/mpls/mpls.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/mpls_fib.h>

const static char* mpls_eos_bit_names[] = MPLS_EOS_BITS;

mpls_main_t mpls_main;

u8 * format_mpls_unicast_label (u8 * s, va_list * args)
{
  mpls_label_t label = va_arg (*args, mpls_label_t);

  switch (label) {
  case MPLS_IETF_IPV4_EXPLICIT_NULL_LABEL:
      s = format (s, "%s", MPLS_IETF_IPV4_EXPLICIT_NULL_STRING);
      break;
  case MPLS_IETF_ROUTER_ALERT_LABEL:
      s = format (s, "%s", MPLS_IETF_ROUTER_ALERT_STRING);
      break;
  case MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL:
      s = format (s, "%s", MPLS_IETF_IPV6_EXPLICIT_NULL_STRING);
      break;
  case MPLS_IETF_IMPLICIT_NULL_LABEL:
      s = format (s, "%s", MPLS_IETF_IMPLICIT_NULL_STRING);
      break;
  case MPLS_IETF_ELI_LABEL:
      s = format (s, "%s", MPLS_IETF_ELI_STRING);
      break;
  case MPLS_IETF_GAL_LABEL:
      s = format (s, "%s", MPLS_IETF_GAL_STRING);
      break;
  default:
      s = format (s, "%d", label);
      break;
  }
  return s;
}

uword unformat_mpls_unicast_label (unformat_input_t * input, va_list * args)
{
  mpls_label_t *label = va_arg (*args, mpls_label_t*);
  
  if (unformat (input, MPLS_IETF_IPV4_EXPLICIT_NULL_STRING))
      *label = MPLS_IETF_IPV4_EXPLICIT_NULL_LABEL;
  else if (unformat (input, MPLS_IETF_IPV6_EXPLICIT_NULL_STRING))
      *label = MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL;
  else if (unformat (input, MPLS_IETF_ROUTER_ALERT_STRING))
      *label = MPLS_IETF_ROUTER_ALERT_LABEL;
  else if (unformat (input, MPLS_IETF_IMPLICIT_NULL_STRING))
      *label = MPLS_IETF_IMPLICIT_NULL_LABEL;
  else if (unformat (input, MPLS_IETF_IPV4_EXPLICIT_NULL_BRIEF_STRING))
      *label = MPLS_IETF_IPV4_EXPLICIT_NULL_LABEL;
  else if (unformat (input, MPLS_IETF_IPV6_EXPLICIT_NULL_BRIEF_STRING))
      *label = MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL;
  else if (unformat (input, MPLS_IETF_ROUTER_ALERT_BRIEF_STRING))
      *label = MPLS_IETF_ROUTER_ALERT_LABEL;
  else if (unformat (input, MPLS_IETF_IMPLICIT_NULL_BRIEF_STRING))
      *label = MPLS_IETF_IMPLICIT_NULL_LABEL;
  else if (unformat (input, "%d", label))
      ;
  else
    return (0);

  return (1);
}

u8 * format_mpls_eos_bit (u8 * s, va_list * args)
{
  mpls_eos_bit_t eb = va_arg (*args, mpls_eos_bit_t);

  ASSERT(eb <= MPLS_EOS);

  s = format(s, "%s", mpls_eos_bit_names[eb]);

  return (s);
}

u8 * format_mpls_header (u8 * s, va_list * args)
{
  mpls_unicast_header_t hdr = va_arg (*args, mpls_unicast_header_t);

  return (format(s, "[%U:%d:%d:%U]",
		 format_mpls_unicast_label, 
		 vnet_mpls_uc_get_label(hdr.label_exp_s_ttl),
		 vnet_mpls_uc_get_ttl(hdr.label_exp_s_ttl),
		 vnet_mpls_uc_get_exp(hdr.label_exp_s_ttl),
		 format_mpls_eos_bit,
		 vnet_mpls_uc_get_s(hdr.label_exp_s_ttl)));
}

uword
unformat_mpls_header (unformat_input_t * input, va_list * args)
{
  u8 ** result = va_arg (*args, u8 **);
  mpls_unicast_header_t _h, * h = &_h;
  u32 label, label_exp_s_ttl;

  if (! unformat (input, "MPLS %d", &label))
    return 0;

  label_exp_s_ttl = (label<<12) | (1<<8) /* s-bit */ | 0xFF;
  h->label_exp_s_ttl = clib_host_to_net_u32 (label_exp_s_ttl);

  /* Add gre, mpls headers to result. */
  {
    void * p;
    u32 h_n_bytes = sizeof (h[0]);

    vec_add2 (*result, p, h_n_bytes);
    clib_memcpy (p, h, h_n_bytes);
  }

  return 1;
}

uword
unformat_mpls_label_net_byte_order (unformat_input_t * input,
                                        va_list * args)
{
  u32 * result = va_arg (*args, u32 *);
  u32 label;

  if (!unformat (input, "MPLS: label %d", &label))
    return 0;

  label = (label<<12) | (1<<8) /* s-bit set */ | 0xFF /* ttl */;

  *result = clib_host_to_net_u32 (label);
  return 1;
}

u8 * format_mpls_unicast_header_host_byte_order (u8 * s, va_list * args)
{
  mpls_unicast_header_t *h = va_arg(*args, mpls_unicast_header_t *);
  u32 label = h->label_exp_s_ttl;
  
  s = format (s, "label %d exp %d, s %d, ttl %d",
              vnet_mpls_uc_get_label (label),
              vnet_mpls_uc_get_exp (label),
              vnet_mpls_uc_get_s (label),
              vnet_mpls_uc_get_ttl (label));
  return s;
}

u8 * format_mpls_unicast_header_net_byte_order (u8 * s, va_list * args)
{
  mpls_unicast_header_t *h = va_arg(*args, mpls_unicast_header_t *);
  mpls_unicast_header_t h_host;

  h_host.label_exp_s_ttl = clib_net_to_host_u32 (h->label_exp_s_ttl);

  return format (s, "%U", format_mpls_unicast_header_host_byte_order,
                 &h_host);
}

typedef struct {
  u32 fib_index;
  u32 entry_index;
  u32 dest;
  u32 s_bit;
  u32 label;
} show_mpls_fib_t;

int
mpls_dest_cmp(void * a1, void * a2)
{
  show_mpls_fib_t * r1 = a1;
  show_mpls_fib_t * r2 = a2;

  return clib_net_to_host_u32(r1->dest) - clib_net_to_host_u32(r2->dest);
}

int
mpls_fib_index_cmp(void * a1, void * a2)
{
  show_mpls_fib_t * r1 = a1;
  show_mpls_fib_t * r2 = a2;

  return r1->fib_index - r2->fib_index;
}

int
mpls_label_cmp(void * a1, void * a2)
{
  show_mpls_fib_t * r1 = a1;
  show_mpls_fib_t * r2 = a2;

  return r1->label - r2->label;
}

static clib_error_t *
vnet_mpls_local_label (vlib_main_t * vm,
                       unformat_input_t * input,
                       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  fib_route_path_t *rpaths = NULL, rpath;
  u32 table_id, is_del, is_ip;
  mpls_label_t local_label;
  mpls_label_t out_label;
  clib_error_t * error;
  mpls_eos_bit_t eos;
  vnet_main_t * vnm;
  fib_prefix_t pfx;

  vnm = vnet_get_main();
  error = NULL;
  is_ip = 0;
  table_id = 0;
  eos = MPLS_EOS;
  is_del = 0;
  local_label = MPLS_LABEL_INVALID;
  memset(&pfx, 0, sizeof(pfx));

   /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      memset(&rpath, 0, sizeof(rpath));

      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "add"))
	is_del = 0;
      else if (unformat (line_input, "eos"))
	pfx.fp_eos = MPLS_EOS;
      else if (unformat (line_input, "non-eos"))
	pfx.fp_eos = MPLS_NON_EOS;
      else if (unformat (line_input, "%U/%d",
			 unformat_ip4_address,
			 &pfx.fp_addr.ip4,
			 &pfx.fp_len))
      {
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
          is_ip = 1;
      }
      else if (unformat (line_input, "%U/%d",
			 unformat_ip6_address,
			 &pfx.fp_addr.ip6,
			 &pfx.fp_len))
      {
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
          is_ip = 1;
      }
      else if (unformat (line_input, "via %U %U weight %u",
			 unformat_ip4_address,
			 &rpath.frp_addr.ip4,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index,
			 &rpath.frp_weight))
      {
	  rpath.frp_proto = DPO_PROTO_IP4;
	  vec_add1(rpaths, rpath);
      }

      else if (unformat (line_input, "via %U %U weight %u",
			 unformat_ip6_address,
			 &rpath.frp_addr.ip6,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index,
			 &rpath.frp_weight))
      {
	  rpath.frp_proto = DPO_PROTO_IP6;
	  vec_add1(rpaths, rpath);
      }

      else if (unformat (line_input, "via %U %U",
			 unformat_ip4_address,
 			 &rpath.frp_addr.ip4,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index))
      {
	  rpath.frp_weight = 1;
	  rpath.frp_proto = DPO_PROTO_IP4;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "rx-ip4 %U",
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index))
      {
	  rpath.frp_weight = 1;
	  rpath.frp_proto = DPO_PROTO_IP4;
          rpath.frp_flags = FIB_ROUTE_PATH_INTF_RX;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "via %U %U",
			 unformat_ip6_address,
 			 &rpath.frp_addr.ip6,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index))
      {
	  rpath.frp_weight = 1;
	  rpath.frp_proto = DPO_PROTO_IP6;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "via %U next-hop-table %d",
			 unformat_ip4_address,
  			 &rpath.frp_addr.ip4,
			 &rpath.frp_fib_index))
      {
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_proto = DPO_PROTO_IP4;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "via %U next-hop-table %d",
			 unformat_ip6_address,
  			 &rpath.frp_addr.ip6,
			 &rpath.frp_fib_index))
      {
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_proto = DPO_PROTO_IP6;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "via %U",
			 unformat_ip4_address,
  			 &rpath.frp_addr.ip4))
      {
	  /*
	   * the recursive next-hops are by default in the same table
	   * as the prefix
	   */
	  rpath.frp_fib_index = table_id;
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_proto = DPO_PROTO_IP4;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "via %U",
			 unformat_ip6_address,
  			 &rpath.frp_addr.ip6))
      {
	  rpath.frp_fib_index = table_id;
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_proto = DPO_PROTO_IP6;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "%d", &local_label))
	;
      else if (unformat (line_input,
			 "ip4-lookup-in-table %d",
			 &rpath.frp_fib_index))
      {
          rpath.frp_proto = DPO_PROTO_IP4;
          rpath.frp_sw_if_index = FIB_NODE_INDEX_INVALID;
	  pfx.fp_payload_proto = DPO_PROTO_IP4;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input,
			 "ip6-lookup-in-table %d",
			 &rpath.frp_fib_index))
      {
          rpath.frp_proto = DPO_PROTO_IP6;
          rpath.frp_sw_if_index = FIB_NODE_INDEX_INVALID;
	  vec_add1(rpaths, rpath);
	  pfx.fp_payload_proto = DPO_PROTO_IP6;
      }
      else if (unformat (line_input,
			 "mpls-lookup-in-table %d",
			 &rpath.frp_fib_index))
      {
          rpath.frp_proto = DPO_PROTO_MPLS;
          rpath.frp_sw_if_index = FIB_NODE_INDEX_INVALID;
	  pfx.fp_payload_proto = DPO_PROTO_MPLS;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input,
			 "l2-input-on %U",
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index))
      {
          rpath.frp_proto = DPO_PROTO_ETHERNET;
	  pfx.fp_payload_proto = DPO_PROTO_ETHERNET;
          rpath.frp_flags = FIB_ROUTE_PATH_INTF_RX;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "out-labels"))
      {
	  if (vec_len (rpaths) == 0)
          {
	      error = clib_error_return (0, "Paths then labels");
	      goto done;
          }
          else
          {
              while (unformat (line_input, "%U",
                               unformat_mpls_unicast_label,
                               &out_label))
              {
                  vec_add1 (rpaths[vec_len (rpaths) - 1].frp_label_stack,
                            out_label);
              }
          }
      }
      else
      {
          error = clib_error_return (0, "unkown input: %U",
                                     format_unformat_error, line_input);
          goto done;
      }

    }

  if (MPLS_LABEL_INVALID == local_label)
  {
      error = clib_error_return (0, "local-label required: %U",
				 format_unformat_error, input);
      goto done;
  }


  if (is_ip)
  {
      u32 fib_index = fib_table_find(pfx.fp_proto, table_id);

      if (FIB_NODE_INDEX_INVALID == fib_index)
      {
          error = clib_error_return (0, "%U table-id %d does not exist",
                                     format_fib_protocol, pfx.fp_proto, table_id);
          goto done;
      }

      if (is_del)
      {
          fib_table_entry_local_label_remove(fib_index, &pfx, local_label);
      }
      else
      {
          fib_table_entry_local_label_add(fib_index, &pfx, local_label);
      }
  }
  else
  {
      fib_node_index_t fib_index;
      u32 fi;

      if (NULL == rpaths)
      {
	  error = clib_error_return(0 , "no paths");
	  goto done;
      }

      pfx.fp_proto = FIB_PROTOCOL_MPLS;
      pfx.fp_len = 21;
      pfx.fp_label = local_label;
      pfx.fp_payload_proto = rpaths[0].frp_proto;

      /*
       * the CLI parsing stored table Ids, swap to FIB indicies
       */
      if (FIB_NODE_INDEX_INVALID == rpath.frp_sw_if_index)
      {
	  fi = fib_table_find(dpo_proto_to_fib(pfx.fp_payload_proto),
                              rpaths[0].frp_fib_index);

	  if (~0 == fi)
	  {
	      error = clib_error_return(0 , "%U Via table %d does not exist",
					format_dpo_proto, pfx.fp_payload_proto,
					rpaths[0].frp_fib_index);
	      goto done;
	  }
	  rpaths[0].frp_fib_index = fi;
      }

      fib_index = mpls_fib_index_from_table_id(table_id);

      if (FIB_NODE_INDEX_INVALID == fib_index)
      {
          error = clib_error_return (0, "MPLS table-id %d does not exist",
                                     table_id);
          goto done;
      }

      if (is_del)
      {
          fib_table_entry_path_remove2(fib_index,
                                       &pfx,
                                       FIB_SOURCE_CLI,
                                       rpaths);
      }
      else
      {
          fib_node_index_t lfe;

          lfe = fib_table_entry_path_add2(fib_index,
                                          &pfx,
                                          FIB_SOURCE_CLI,
                                          FIB_ENTRY_FLAG_NONE,
                                          rpaths);

          if (FIB_NODE_INDEX_INVALID == lfe)
          {
              error = clib_error_return (0, "Failed to create %U-%U in MPLS table-id %d",
                                         format_mpls_unicast_label, local_label,
                                         format_mpls_eos_bit, eos,
                                         table_id);
              goto done;
          }
      }
  }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (mpls_local_label_command, static) = {
  .path = "mpls local-label",
  .function = vnet_mpls_local_label,
  .short_help = "Create/Delete MPL local labels",
};

clib_error_t *
vnet_mpls_table_cmd (vlib_main_t * vm,
                     unformat_input_t * main_input,
                     vlib_cli_command_t * cmdo)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u32 table_id, is_add;

  is_add = 1;
  table_id = ~0;

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d", &table_id))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add"))
	is_add = 1;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (~0 == table_id)
    {
      error = clib_error_return (0, "No table id");
      goto done;
    }
  else if (0 == table_id)
    {
      error = clib_error_return (0, "Can't change the default table");
      goto done;
    }
  else
    {
      if (is_add)
        {
          mpls_table_create (table_id, 0);
        }
      else
        {
          mpls_table_delete (table_id, 0);
        }
    }

 done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-ON* */
/*?
 * This command is used to add or delete MPLS Tables. All
 * Tables must be explicitly added before that can be used,
 * Including the default table.
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_table_command, static) = {
  .path = "mpla table",
  .short_help = "mpls table [add|del] <table-id>",
  .function = vnet_mpls_table_cmd,
  .is_mp_safe = 1,
};

int
mpls_fib_reset_labels (u32 fib_id)
{
  // FIXME
  return 0;
}

static clib_error_t *
mpls_init (vlib_main_t * vm)
{
  clib_error_t * error;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  return vlib_call_init_function (vm, mpls_input_init);
}

VLIB_INIT_FUNCTION (mpls_init);
