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
  else if (unformat (input, "%d", label))
      ;

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

u8 * format_mpls_gre_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mpls_gre_tx_trace_t * t = va_arg (*args, mpls_gre_tx_trace_t *);
  mpls_main_t * mm = &mpls_main;
    
  if (t->lookup_miss)
    s = format (s, "MPLS: lookup miss");
  else
    {
      s = format (s, "MPLS: tunnel %d labels %U len %d src %U dst %U",
                  t->tunnel_id,
                  format_mpls_encap_index, mm, t->mpls_encap_index, 
                  clib_net_to_host_u16 (t->length),
                  format_ip4_address, &t->src.as_u8,
                  format_ip4_address, &t->dst.as_u8);
    }
  return s;
}

u8 * format_mpls_eth_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mpls_eth_tx_trace_t * t = va_arg (*args, mpls_eth_tx_trace_t *);
  mpls_main_t * mm = &mpls_main;
    
  if (t->lookup_miss)
    s = format (s, "MPLS: lookup miss");
  else
    {
      s = format (s, "MPLS: tunnel %d labels %U len %d tx_sw_index %d dst %U",
                  t->tunnel_id,
                  format_mpls_encap_index, mm, t->mpls_encap_index, 
                  clib_net_to_host_u16 (t->length),
                  t->tx_sw_if_index, 
                  format_ethernet_address, t->dst);
    }
  return s;
}

u8 * format_mpls_eth_header_with_length (u8 * s, va_list * args)
{
  ethernet_header_t * h = va_arg (*args, ethernet_header_t *);
  mpls_unicast_header_t * m = (mpls_unicast_header_t *)(h+1);
  u32 max_header_bytes = va_arg (*args, u32);
  uword header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "ethernet header truncated");

  s = format 
    (s, "ETHERNET-MPLS label %d", 
     vnet_mpls_uc_get_label (clib_net_to_host_u32 (m->label_exp_s_ttl)));

  return s;
}

u8 * format_mpls_gre_header_with_length (u8 * s, va_list * args)
{
  gre_header_t * h = va_arg (*args, gre_header_t *);
  mpls_unicast_header_t * m = (mpls_unicast_header_t *)(h+1);
  u32 max_header_bytes = va_arg (*args, u32);
  uword header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "gre header truncated");

  s = format 
    (s, "GRE-MPLS label %d", 
     vnet_mpls_uc_get_label (clib_net_to_host_u32 (m->label_exp_s_ttl)));

  return s;
}

u8 * format_mpls_gre_header (u8 * s, va_list * args)
{
  gre_header_t * h = va_arg (*args, gre_header_t *);
  return format (s, "%U", format_mpls_gre_header_with_length, h, 0);
}

uword
unformat_mpls_gre_header (unformat_input_t * input, va_list * args)
{
  u8 ** result = va_arg (*args, u8 **);
  gre_header_t _g, * g = &_g;
  mpls_unicast_header_t _h, * h = &_h;
  u32 label, label_exp_s_ttl;
  
  if (! unformat (input, "MPLS %d", &label))
    return 0;

  g->protocol = clib_host_to_net_u16 (GRE_PROTOCOL_mpls_unicast);

  label_exp_s_ttl = (label<<12) | (1<<8) /* s-bit */ | 0xFF;
  h->label_exp_s_ttl = clib_host_to_net_u32 (label_exp_s_ttl);

  /* Add gre, mpls headers to result. */
  {
    void * p;
    u32 g_n_bytes = sizeof (g[0]);
    u32 h_n_bytes = sizeof (h[0]);

    vec_add2 (*result, p, g_n_bytes);
    clib_memcpy (p, g, g_n_bytes);

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

mpls_encap_t * 
mpls_encap_by_fib_and_dest (mpls_main_t * mm, u32 rx_fib, u32 dst_address)
{
  uword * p;
  mpls_encap_t * e;
  u64 key;

  key = ((u64)rx_fib<<32) | ((u64) dst_address);
  p = hash_get (mm->mpls_encap_by_fib_and_dest, key);

  if (!p)
    return 0;

  e = pool_elt_at_index (mm->encaps, p[0]);
  return e;
}

int vnet_mpls_add_del_encap (ip4_address_t *dest, u32 fib_id, 
                             u32 *labels_host_byte_order,
                             u32 policy_tunnel_index,
                             int no_dst_hash, u32 * indexp, int is_add)
{
  mpls_main_t * mm = &mpls_main;
  ip4_main_t * im = &ip4_main;
  mpls_encap_t * e;
  u32 label_net_byte_order, label_host_byte_order;
  u32 fib_index;
  u64 key;
  uword *p;
  int i;
  
  p = hash_get (im->fib_index_by_table_id, fib_id);
  if (! p)
    return VNET_API_ERROR_NO_SUCH_FIB;
  
  fib_index = p[0];
  
  key = ((u64)fib_index<<32) | ((u64) dest->as_u32);
  
  if (is_add)
    {
      pool_get (mm->encaps, e);
      memset (e, 0, sizeof (*e));
      
      for (i = 0; i < vec_len (labels_host_byte_order); i++)
        {
          mpls_unicast_header_t h;
          label_host_byte_order = labels_host_byte_order[i];
          
          /* Reformat label into mpls_unicast_header_t */
          label_host_byte_order <<= 12;
	  // FIXME NEOS AND EOS
          //if (i == vec_len(labels_host_byte_order) - 1)
          //  label_host_byte_order |= 1<<8;            /* S=1 */
          label_host_byte_order |= 0xff;            /* TTL=FF */
          label_net_byte_order = clib_host_to_net_u32 (label_host_byte_order);
          h.label_exp_s_ttl = label_net_byte_order;
          vec_add1 (e->labels, h);
        }
      if (no_dst_hash == 0)
        hash_set (mm->mpls_encap_by_fib_and_dest, key, e - mm->encaps);
      if (indexp)
        *indexp = e - mm->encaps;
      if (policy_tunnel_index != ~0)
        return vnet_mpls_policy_tunnel_add_rewrite (mm, e, policy_tunnel_index);
    }
  else
    {
      p = hash_get (mm->mpls_encap_by_fib_and_dest, key);
      if (!p)
        return VNET_API_ERROR_NO_SUCH_LABEL;
      
      e = pool_elt_at_index (mm->encaps, p[0]);
      
      vec_free (e->labels);
      vec_free (e->rewrite);
      pool_put(mm->encaps, e);
      
      if (no_dst_hash == 0)
        hash_unset (mm->mpls_encap_by_fib_and_dest, key);    
    }
  return 0;
}

static clib_error_t *
mpls_add_encap_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  u32 fib_id;
  u32 *labels = 0;
  u32 this_label;
  ip4_address_t dest;
  u32 policy_tunnel_index = ~0;
  int no_dst_hash = 0;
  int rv;
  int fib_set = 0;
  int dest_set = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "fib %d", &fib_id))
        fib_set = 1;
      else if (unformat (input, "dest %U", unformat_ip4_address, &dest))
        dest_set = 1;
      else if (unformat (input, "no-dst-hash"))
        no_dst_hash = 1;
      else if (unformat (input, "label %d", &this_label))
        vec_add1 (labels, this_label);
      else if (unformat (input, "policy-tunnel %d", &policy_tunnel_index))
        ;
      else
        break;
    }

  if (fib_set == 0)
    return clib_error_return (0, "fib-id missing");
  if (dest_set == 0)
    return clib_error_return (0, "destination IP address missing");
  if (vec_len (labels) == 0)
    return clib_error_return (0, "label stack missing");
  
  rv = vnet_mpls_add_del_encap (&dest, fib_id, labels, 
                                policy_tunnel_index, 
                                no_dst_hash, 0 /* indexp */,
                                1 /* is_add */);
  vec_free (labels);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "fib id %d unknown", fib_id);
      
    default:
      return clib_error_return (0, "vnet_mpls_add_del_encap returned %d", 
                                rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (mpls_add_encap_command, static) = {
  .path = "mpls encap add",
  .short_help = 
  "mpls encap add label <label> ... fib <id> dest <ip4-address>",
  .function = mpls_add_encap_command_fn,
};

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

static clib_error_t *
mpls_del_encap_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  u32 fib_id;
  ip4_address_t dest;
  int rv;
  
  if (unformat (input, "fib %d dest %U", &fib_id, 
                unformat_ip4_address, &dest)) 
    {
      rv = vnet_mpls_add_del_encap (&dest, fib_id, 0 /* labels */, 
                                    ~0 /* policy_tunnel_index */,
                                    0 /* no_dst_hash */,
                                    0 /* indexp */,
                                    0 /* is_add */);
      switch (rv)
        {
        case VNET_API_ERROR_NO_SUCH_FIB:
          return clib_error_return (0, "fib id %d unknown", fib_id);
        case VNET_API_ERROR_NO_SUCH_ENTRY:
          return clib_error_return (0, "dest %U not in fib %d",
                                    format_ip4_address, &dest, fib_id);
        default:
          break;
        }
      return 0;
    }
  else
    return clib_error_return (0, "unknown input `%U'",
                              format_unformat_error, input);
}

VLIB_CLI_COMMAND (mpls_del_encap_command, static) = {
  .path = "mpls encap delete",
  .short_help = "mpls encap delete fib <id> dest <ip4-address>",
  .function = mpls_del_encap_command_fn,
};

int vnet_mpls_add_del_decap (u32 rx_fib_id, 
                             u32 tx_fib_id,
                             u32 label_host_byte_order, 
                             int s_bit, int next_index, int is_add)
{
  mpls_main_t * mm = &mpls_main;
  ip4_main_t * im = &ip4_main;
  mpls_decap_t * d;
  u32 rx_fib_index, tx_fib_index_or_output_swif_index;
  uword *p;
  u64 key;
  
  p = hash_get (im->fib_index_by_table_id, rx_fib_id);
  if (! p)
    return VNET_API_ERROR_NO_SUCH_FIB;

  rx_fib_index = p[0];

  /* L3 decap => transform fib ID to fib index */
  if (next_index == MPLS_LOOKUP_NEXT_IP4_INPUT)
    {
      p = hash_get (im->fib_index_by_table_id, tx_fib_id);
      if (! p)
        return VNET_API_ERROR_NO_SUCH_INNER_FIB;
      
      tx_fib_index_or_output_swif_index = p[0];
    }
  else
    {
      /* L2 decap, tx_fib_id is actually the output sw_if_index */
      tx_fib_index_or_output_swif_index = tx_fib_id;
    }

  key = ((u64) rx_fib_index<<32) | ((u64) label_host_byte_order<<12)
    | ((u64) s_bit<<8);

  p = hash_get (mm->mpls_decap_by_rx_fib_and_label, key);

  /* If deleting, or replacing an old entry */
  if (is_add == 0 || p)
    {
      if (is_add == 0 && p == 0)
        return VNET_API_ERROR_NO_SUCH_LABEL;

      d = pool_elt_at_index (mm->decaps, p[0]);
      hash_unset (mm->mpls_decap_by_rx_fib_and_label, key);
      pool_put (mm->decaps, d);
      /* Deleting, we're done... */
      if (is_add == 0)
        return 0;
    }

  /* add decap entry... */
  pool_get (mm->decaps, d);
  memset (d, 0, sizeof (*d));
  d->tx_fib_index = tx_fib_index_or_output_swif_index;
  d->next_index = next_index;

  hash_set (mm->mpls_decap_by_rx_fib_and_label, key, d - mm->decaps);

  return 0;
}

uword
unformat_mpls_gre_input_next (unformat_input_t * input, va_list * args)
{
  u32 * result = va_arg (*args, u32 *);
  int rv = 0;

  if (unformat (input, "lookup"))
    {
      *result = MPLS_LOOKUP_NEXT_IP4_INPUT;
      rv = 1;
    }
  else if (unformat (input, "output"))
    {
      *result = MPLS_LOOKUP_NEXT_L2_OUTPUT;
      rv = 1;
    }
  return rv;
}

static clib_error_t *
mpls_add_decap_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  u32 rx_fib_id = 0;
  u32 tx_fib_or_sw_if_index;
  u32 label;
  int s_bit = 1;
  u32 next_index = 1;           /* ip4_lookup, see node.c */
  int tx_fib_id_set = 0;
  int label_set = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "fib %d", &tx_fib_or_sw_if_index))
        tx_fib_id_set = 1;
      else if (unformat (input, "sw_if_index %d", &tx_fib_or_sw_if_index))
        tx_fib_id_set = 1;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
                         &tx_fib_or_sw_if_index))
        tx_fib_id_set = 1;
      else if (unformat (input, "rx-fib %d", &rx_fib_id))
        ;
      else if (unformat (input, "label %d", &label))
        label_set = 1;
      else if (unformat (input, "s-bit-clear"))
        s_bit = 0;
      else if (unformat (input, "next %U", unformat_mpls_gre_input_next, 
                         &next_index))
        ;
      else
        break;
    }

  if (tx_fib_id_set == 0)
    return clib_error_return (0, "lookup FIB ID not set");
  if (label_set == 0)
    return clib_error_return (0, "missing label");
  
  rv = vnet_mpls_add_del_decap (rx_fib_id, tx_fib_or_sw_if_index, 
                                label, s_bit, next_index, 1 /* is_add */);
  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "no such rx fib id %d", rx_fib_id);

    case VNET_API_ERROR_NO_SUCH_INNER_FIB:
      return clib_error_return (0, "no such tx fib / swif %d", 
                                tx_fib_or_sw_if_index);

    default:
      return clib_error_return (0, "vnet_mpls_add_del_decap returned %d",
                                rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (mpls_add_decap_command, static) = {
    .path = "mpls decap add",
    .short_help = 
    "mpls decap add fib <id> label <nn> [s-bit-clear] [next-index <nn>]",
    .function = mpls_add_decap_command_fn, 
};

static clib_error_t *
mpls_del_decap_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  u32 rx_fib_id = 0;
  u32 tx_fib_id = 0;
  u32 label;
  int s_bit = 1;
  int label_set = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "rx-fib %d", &rx_fib_id))
        ;
      else if (unformat (input, "label %d", &label))
        label_set = 1;
      else if (unformat (input, "s-bit-clear"))
        s_bit = 0;
    }

  if (!label_set)
    return clib_error_return (0, "label not set");

  rv = vnet_mpls_add_del_decap (rx_fib_id, 
                                tx_fib_id /* not interesting */,
                                label, s_bit, 
                                0 /* next_index not interesting */,
                                0 /* is_add */);
  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "no such rx fib id %d", rx_fib_id);

    case VNET_API_ERROR_NO_SUCH_INNER_FIB:
      return clib_error_return (0, "no such lookup fib id %d", tx_fib_id);

    case VNET_API_ERROR_NO_SUCH_LABEL:
      return clib_error_return (0, "no such label %d rx fib id %d", 
                                label, rx_fib_id);

    default:
      return clib_error_return (0, "vnet_mpls_add_del_decap returned %d",
                                rv);
    }
  return 0;
}


VLIB_CLI_COMMAND (mpls_del_decap_command, static) = {
  .path = "mpls decap delete",
  .short_help = "mpls decap delete label <label> rx-fib <id> [s-bit-clear]",
  .function = mpls_del_decap_command_fn,
};

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
show_mpls_fib_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  u64 key; 
  u32 value;
  show_mpls_fib_t *records = 0;
  show_mpls_fib_t *s;
  mpls_main_t * mm = &mpls_main;
  ip4_fib_t * rx_fib;

  hash_foreach (key, value, mm->mpls_encap_by_fib_and_dest, 
  ({
    vec_add2 (records, s, 1);
    s->fib_index = (u32)(key>>32);
    s->dest = (u32)(key & 0xFFFFFFFF);
    s->entry_index = (u32) value;
  }));

  if (!vec_len(records))
    {
      vlib_cli_output (vm, "MPLS encap table empty");
    }
  /* sort output by dst address within fib */
  vec_sort_with_function (records, mpls_dest_cmp);
  vec_sort_with_function (records, mpls_fib_index_cmp);
  vlib_cli_output (vm, "MPLS encap table");
  vlib_cli_output (vm, "%=6s%=16s%=16s", "Table", "Dest address", "Labels");
  vec_foreach (s, records)
    {
      rx_fib = ip4_fib_get (s->fib_index);
      vlib_cli_output (vm, "%=6d%=16U%=16U", rx_fib->table_id, 
                       format_ip4_address, &s->dest,
                       format_mpls_encap_index, mm, s->entry_index);
    }

  vec_free(records);
  return 0;
}

VLIB_CLI_COMMAND (show_mpls_fib_command, static) = {
    .path = "show mpls encap",
    .short_help = "show mpls encap",
    .function = show_mpls_fib_command_fn,
};

static clib_error_t *
vnet_mpls_local_label (vlib_main_t * vm,
                       unformat_input_t * input,
                       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  fib_route_path_t *rpaths = NULL, rpath;
  clib_error_t * error = 0;
  u32 table_id, is_del, is_ip;
  fib_prefix_t pfx;
  mpls_label_t local_label;
  mpls_eos_bit_t eos;

  is_ip = 0;
  table_id = 0;
  eos = MPLS_EOS;

   /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      memset(&rpath, 0, sizeof(rpath));
      memset(&pfx, 0, sizeof(pfx));

      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "add"))
	is_del = 0;
      else if (unformat (line_input, "eos"))
	eos = MPLS_EOS;
      else if (unformat (line_input, "non-eos"))
	eos = MPLS_NON_EOS;
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
      else if (unformat (line_input, "%d", &local_label))
	;
      else if (unformat (line_input,
			 "ip4-lookup-in-table %d",
			 &rpath.frp_fib_index))
      {
	  rpath.frp_label = MPLS_LABEL_INVALID;
          rpath.frp_proto = FIB_PROTOCOL_IP4;
          rpath.frp_sw_if_index = FIB_NODE_INDEX_INVALID;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input,
			 "ip6-lookup-in-table %d",
			 &rpath.frp_fib_index))
      {
	  rpath.frp_label = MPLS_LABEL_INVALID;
          rpath.frp_proto = FIB_PROTOCOL_IP6;
          rpath.frp_sw_if_index = FIB_NODE_INDEX_INVALID;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input,
			 "mpls-lookup-in-table %d",
			 &rpath.frp_fib_index))
      {
	  rpath.frp_label = MPLS_LABEL_INVALID;
          rpath.frp_proto = FIB_PROTOCOL_IP4;
          rpath.frp_sw_if_index = FIB_NODE_INDEX_INVALID;
	  vec_add1(rpaths, rpath);
      }
      else
      {
          error = clib_error_return (0, "unkown input: %U",
                                     format_unformat_error, input);
          goto done;
      }

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
      fib_node_index_t lfe, fib_index;
      fib_prefix_t prefix = {
	  .fp_proto = FIB_PROTOCOL_MPLS,
	  .fp_label = local_label,
	  .fp_eos = eos,
      };

      fib_index = mpls_fib_index_from_table_id(table_id);

      if (FIB_NODE_INDEX_INVALID == fib_index)
      {
          error = clib_error_return (0, "MPLS table-id %d does not exist",
                                     table_id);
          goto done;
      }

      lfe = fib_table_entry_path_add2(fib_index,
				      &prefix,
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

done:
  return error;
}

VLIB_CLI_COMMAND (mpls_local_label_command, static) = {
  .path = "mpls local-label",
  .function = vnet_mpls_local_label,
  .short_help = "Create/Delete MPL local labels",
};

int mpls_fib_reset_labels (u32 fib_id)
{
  u64 key; 
  u32 value;
  show_mpls_fib_t *records = 0;
  show_mpls_fib_t *s;
  mpls_main_t * mm = &mpls_main;
  ip4_main_t * im = &ip4_main;
  u32 fib_index;
  uword *p;

  p = hash_get (im->fib_index_by_table_id, fib_id);
  if (! p)
    return VNET_API_ERROR_NO_SUCH_FIB;

  fib_index = p[0];

  hash_foreach (key, value, mm->mpls_encap_by_fib_and_dest, 
  ({
    if (fib_index == (u32)(key>>32)) {
        vec_add2 (records, s, 1);
        s->dest = (u32)(key & 0xFFFFFFFF);
        s->entry_index = (u32) value;
    }
  }));

  vec_foreach (s, records)
    {
      key = ((u64)fib_index<<32) | ((u64) s->dest);
      hash_unset (mm->mpls_encap_by_fib_and_dest, key);
      pool_put_index (mm->encaps, s->entry_index);
    }
                
  vec_reset_length(records);

  hash_foreach (key, value, mm->mpls_decap_by_rx_fib_and_label, 
  ({
    if (fib_index == (u32) (key>>32)) {
        vec_add2 (records, s, 1);
        s->entry_index = value;
        s->fib_index = fib_index;
        s->s_bit = key & (1<<8);
        s->dest = (u32)((key & 0xFFFFFFFF)>>12);
    }
  }));
  
  vec_foreach (s, records)
    {
       key = ((u64) fib_index <<32) | ((u64) s->dest<<12) |
        ((u64) s->s_bit);
      
      hash_unset (mm->mpls_decap_by_rx_fib_and_label, key);
      pool_put_index (mm->decaps, s->entry_index);
    }

  vec_free(records);
  return 0;
}

static clib_error_t * mpls_init (vlib_main_t * vm)
{
  mpls_main_t * mm = &mpls_main;
  clib_error_t * error;

  mm->vlib_main = vm;
  mm->vnet_main = vnet_get_main();

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  mm->mpls_encap_by_fib_and_dest = hash_create (0, sizeof (uword));
  mm->mpls_decap_by_rx_fib_and_label = hash_create (0, sizeof (uword));

  return vlib_call_init_function (vm, mpls_input_init);
}

VLIB_INIT_FUNCTION (mpls_init);

mpls_main_t * mpls_get_main (vlib_main_t * vm)
{
  vlib_call_init_function (vm, mpls_init);
  return &mpls_main;
}

