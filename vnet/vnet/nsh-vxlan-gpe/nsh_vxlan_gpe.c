/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/nsh-vxlan-gpe/nsh_vxlan_gpe.h>

nsh_vxlan_gpe_main_t nsh_vxlan_gpe_main;

static u8 * format_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case NSH_VXLAN_GPE_INPUT_NEXT_DROP:
      return format (s, "drop");
    case NSH_VXLAN_GPE_INPUT_NEXT_IP4_INPUT:
      return format (s, "ip4");
    case NSH_VXLAN_GPE_INPUT_NEXT_IP6_INPUT:
      return format (s, "ip6");
    case NSH_VXLAN_GPE_INPUT_NEXT_NSH_VXLAN_GPE_ENCAP:
      return format (s, "nsh-vxlan-gpe");
    default:
      return format (s, "unknown %d", next_index);
    }
  return s;
}

u8 * format_nsh_vxlan_gpe_tunnel (u8 * s, va_list * args)
{
  nsh_vxlan_gpe_tunnel_t * t = va_arg (*args, nsh_vxlan_gpe_tunnel_t *);
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;

  s = format (s, 
              "[%d] %U (src) %U (dst) fibs: encap %d, decap %d",
              t - ngm->tunnels,
              format_ip4_address, &t->src,
              format_ip4_address, &t->dst,
              t->encap_fib_index,
              t->decap_fib_index);
  s = format (s, " decap next %U\n", format_decap_next, t->decap_next_index);
  s = format (s, "  vxlan VNI %d ", t->vni);
  s = format (s, "nsh ver %d ", (t->ver_o_c>>6));
  if (t->ver_o_c & NSH_GRE_O_BIT)
      s = format (s, "O-set ");

  if (t->ver_o_c & NSH_GRE_C_BIT)
      s = format (s, "C-set ");

  s = format (s, "len %d (%d bytes) md_type %d next_protocol %d\n",
              t->length, t->length * 4, t->md_type, t->next_protocol);
  
  s = format (s, "  service path %d service index %d\n",
              (t->spi_si>>NSH_GRE_SPI_SHIFT) & NSH_GRE_SPI_MASK,
              t->spi_si & NSH_GRE_SINDEX_MASK);

  s = format (s, "  c1 %d c2 %d c3 %d c4 %d\n",
              t->c1, t->c2, t->c3, t->c4);

  return s;
}

static u8 * format_nsh_vxlan_gpe_name (u8 * s, va_list * args)
{
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;
  u32 i = va_arg (*args, u32);
  u32 show_dev_instance = ~0;

  if (i < vec_len (ngm->dev_inst_by_real))
    show_dev_instance = ngm->dev_inst_by_real[i];

  if (show_dev_instance != ~0)
    i = show_dev_instance;

  return format (s, "nsh_vxlan_gpe_tunnel%d", i);
}

static int nsh_vxlan_gpe_name_renumber (vnet_hw_interface_t * hi,
                                        u32 new_dev_instance)
{
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;

  vec_validate_init_empty (ngm->dev_inst_by_real, hi->dev_instance, ~0);

  ngm->dev_inst_by_real [hi->dev_instance] = new_dev_instance;

  return 0;
}

static uword dummy_interface_tx (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

VNET_DEVICE_CLASS (nsh_vxlan_gpe_device_class,static) = {
  .name = "NSH_VXLAN_GPE",
  .format_device_name = format_nsh_vxlan_gpe_name,
  .format_tx_trace = format_nsh_vxlan_gpe_encap_trace,
  .tx_function = dummy_interface_tx,
  .name_renumber = nsh_vxlan_gpe_name_renumber,
};

static uword dummy_set_rewrite (vnet_main_t * vnm,
                                u32 sw_if_index,
                                u32 l3_type,
                                void * dst_address,
                                void * rewrite,
                                uword max_rewrite_bytes)
{
  return 0;
}

static u8 * format_nsh_vxlan_gpe_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

VNET_HW_INTERFACE_CLASS (nsh_vxlan_gpe_hw_class) = {
  .name = "NSH_VXLAN_GPE",
  .format_header = format_nsh_vxlan_gpe_header_with_length,
  .set_rewrite = dummy_set_rewrite,
};

#define foreach_copy_field                      \
_(src.as_u32)                                   \
_(dst.as_u32)                                   \
_(vni)                                          \
_(encap_fib_index)                              \
_(decap_fib_index)                              \
_(decap_next_index)                             \
_(ver_o_c)                                      \
_(length)                                       \
_(md_type)                                      \
_(next_protocol)                                \
_(spi_si)                                       \
_(c1)                                           \
_(c2)                                           \
_(c3)                                           \
_(c4)                                           \
_(tlvs)

#define foreach_32bit_field                     \
_(spi_si)                                       \
_(c1)                                           \
_(c2)                                           \
_(c3)                                           \
_(c4)

static int nsh_vxlan_gpe_rewrite (nsh_vxlan_gpe_tunnel_t * t)
{
  u8 *rw = 0;
  ip4_header_t * ip0;
  nsh_header_t * nsh0;
  ip4_vxlan_gpe_and_nsh_header_t * h0;
  int len;

  len = sizeof (*h0) + vec_len(t->tlvs)*4;

  vec_validate_aligned (rw, len-1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip4_vxlan_gpe_and_nsh_header_t *) rw;

  /* Fixed portion of the (outer) ip4 header */
  ip0 = &h0->ip4;
  ip0->ip_version_and_header_length = 0x45;
  ip0->ttl = 254;
  ip0->protocol = IP_PROTOCOL_UDP;

  /* we fix up the ip4 header length and checksum after-the-fact */
  ip0->src_address.as_u32 = t->src.as_u32;
  ip0->dst_address.as_u32 = t->dst.as_u32;
  ip0->checksum = ip4_header_checksum (ip0);

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (4790);
  h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_vxlan_gpe);

  /* VXLAN header. Are we having fun yet? */
  h0->vxlan.flags = VXLAN_GPE_FLAGS_I | VXLAN_GPE_FLAGS_P;
  h0->vxlan.ver_res = VXLAN_GPE_VERSION;
  h0->vxlan.next_protocol = VXLAN_NEXT_PROTOCOL_NSH;
  h0->vxlan.vni_res = clib_host_to_net_u32 (t->vni<<8);

  /* NSH header */
  nsh0 = &h0->nsh;
  nsh0->ver_o_c = t->ver_o_c;
  nsh0->md_type = t->md_type;
  nsh0->next_protocol = t->next_protocol;
  nsh0->spi_si = t->spi_si;
  nsh0->c1 = t->c1;
  nsh0->c2 = t->c2;
  nsh0->c3 = t->c3;
  nsh0->c4 = t->c4;
  
  /* Endian swap 32-bit fields */
#define _(x) nsh0->x = clib_host_to_net_u32(nsh0->x);
  foreach_32bit_field;
#undef _

  /* fix nsh header length */
  t->length = 6 + vec_len(t->tlvs);
  nsh0->length = t->length;

  /* Copy any TLVs */
  if (vec_len(t->tlvs))
    memcpy (nsh0->tlvs, t->tlvs, 4*vec_len(t->tlvs));

  t->rewrite = rw;
  return (0);
}

int vnet_nsh_vxlan_gpe_add_del_tunnel 
(vnet_nsh_vxlan_gpe_add_del_tunnel_args_t *a, u32 * sw_if_indexp)
{
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;
  nsh_vxlan_gpe_tunnel_t *t = 0;
  vnet_main_t * vnm = ngm->vnet_main;
  vnet_hw_interface_t * hi;
  uword * p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  int rv;
  nsh_vxlan_gpe_tunnel_key_t key, *key_copy;
  hash_pair_t *hp;
  
  key.src = a->dst.as_u32; /* decap src in key is encap dst in config */
  key.vni = clib_host_to_net_u32 (a->vni << 8);
  key.spi_si = clib_host_to_net_u32(a->spi_si);
  key.pad = 0;

  p = hash_get_mem (ngm->nsh_vxlan_gpe_tunnel_by_key, &key);
  
  if (a->is_add)
    {
      /* adding a tunnel: tunnel must not already exist */
      if (p) 
        return VNET_API_ERROR_INVALID_VALUE;
      
      if (a->decap_next_index >= NSH_VXLAN_GPE_INPUT_N_NEXT)
        return VNET_API_ERROR_INVALID_DECAP_NEXT;
      
      pool_get_aligned (ngm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));
      
      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _
      
      rv = nsh_vxlan_gpe_rewrite (t);

      if (rv)
        {
          pool_put (ngm->tunnels, t);
          return rv;
        }

      key_copy = clib_mem_alloc (sizeof (*key_copy));
      memcpy (key_copy, &key, sizeof (*key_copy));

      hash_set_mem (ngm->nsh_vxlan_gpe_tunnel_by_key, key_copy, 
                    t - ngm->tunnels);
      
      if (vec_len (ngm->free_nsh_vxlan_gpe_tunnel_hw_if_indices) > 0)
        {
          hw_if_index = ngm->free_nsh_vxlan_gpe_tunnel_hw_if_indices
            [vec_len (ngm->free_nsh_vxlan_gpe_tunnel_hw_if_indices)-1];
          _vec_len (ngm->free_nsh_vxlan_gpe_tunnel_hw_if_indices) -= 1;
          
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->dev_instance = t - ngm->tunnels;
          hi->hw_instance = hi->dev_instance;
        }
      else 
        {
          hw_if_index = vnet_register_interface
            (vnm, nsh_vxlan_gpe_device_class.index, t - ngm->tunnels,
             nsh_vxlan_gpe_hw_class.index, t - ngm->tunnels);
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->output_node_index = nsh_vxlan_gpe_encap_node.index;
        }
      
      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index = hi->sw_if_index;
      
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 
                                   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
    }
  else
    {
      /* deleting a tunnel: tunnel must exist */
      if (!p) 
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (ngm->tunnels, p[0]);

      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */);
      vec_add1 (ngm->free_nsh_vxlan_gpe_tunnel_hw_if_indices, t->hw_if_index);

      hp = hash_get_pair (ngm->nsh_vxlan_gpe_tunnel_by_key, &key);
      key_copy = (void *)(hp->key);
      hash_unset_mem (ngm->nsh_vxlan_gpe_tunnel_by_key, &key);
      clib_mem_free (key_copy);

      vec_free (t->rewrite);
      pool_put (ngm->tunnels, t);
    }

  if (sw_if_indexp)
      *sw_if_indexp = sw_if_index;

  return 0;
}

static u32 fib_index_from_fib_id (u32 fib_id)
{
  ip4_main_t * im = &ip4_main;
  uword * p;

  p = hash_get (im->fib_index_by_table_id, fib_id);
  if (!p)
    return ~0;

  return p[0];
}

static uword unformat_decap_next (unformat_input_t * input, va_list * args)
{
  u32 * result = va_arg (*args, u32 *);
  u32 tmp;
  
  if (unformat (input, "drop"))
    *result = NSH_VXLAN_GPE_INPUT_NEXT_DROP;
  else if (unformat (input, "ip4"))
    *result = NSH_VXLAN_GPE_INPUT_NEXT_IP4_INPUT;
  else if (unformat (input, "ip6"))
    *result = NSH_VXLAN_GPE_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, "ethernet"))
    *result = NSH_VXLAN_GPE_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, "nsh-vxlan-gpe"))
    *result = NSH_VXLAN_GPE_INPUT_NEXT_NSH_VXLAN_GPE_ENCAP;
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static clib_error_t *
nsh_vxlan_gpe_add_del_tunnel_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  ip4_address_t src, dst;
  u8 is_add = 1;
  u8 src_set = 0;
  u8 dst_set = 0;
  u32 encap_fib_index = 0;
  u32 decap_fib_index = 0;
  u8 ver_o_c = 0;
  u8 length = 0;
  u8 md_type = 0;
  u8 next_protocol = 1; /* default: ip4 */
  u32 decap_next_index = NSH_VXLAN_GPE_INPUT_NEXT_IP4_INPUT;
  u32 spi;
  u8 spi_set = 0;
  u32 si;
  u32 vni;
  u8 vni_set = 0;
  u8 si_set = 0;
  u32 spi_si;
  u32 c1 = 0;
  u32 c2 = 0;
  u32 c3 = 0;
  u32 c4 = 0;
  u32 *tlvs = 0;
  u32 tmp;
  int rv;
  vnet_nsh_vxlan_gpe_add_del_tunnel_args_t _a, * a = &_a;
  
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "src %U", 
                       unformat_ip4_address, &src))
      src_set = 1;
    else if (unformat (line_input, "dst %U",
                       unformat_ip4_address, &dst))
      dst_set = 1;
    else if (unformat (line_input, "encap-vrf-id %d", &tmp))
      {
        encap_fib_index = fib_index_from_fib_id (tmp);
        if (encap_fib_index == ~0)
          return clib_error_return (0, "nonexistent encap fib id %d", tmp);
      }
    else if (unformat (line_input, "decap-vrf-id %d", &tmp))
      {
        decap_fib_index = fib_index_from_fib_id (tmp);
        if (decap_fib_index == ~0)
          return clib_error_return (0, "nonexistent decap fib id %d", tmp);
      }
    else if (unformat (line_input, "decap-next %U", unformat_decap_next, 
                       &decap_next_index))
      ;
    else if (unformat (line_input, "vni %d", &vni))
      vni_set = 1;
    else if (unformat (line_input, "version %d", &tmp))
      ver_o_c |= (tmp & 3) << 6;
    else if (unformat (line_input, "o-bit %d", &tmp))
      ver_o_c |= (tmp & 1) << 5;
    else if (unformat (line_input, "c-bit %d", &tmp))
      ver_o_c |= (tmp & 1) << 4;
    else if (unformat (line_input, "md-type %d", &tmp))
      md_type = tmp;
    else if (unformat(line_input, "next-ip4"))
      next_protocol = 1;
    else if (unformat(line_input, "next-ip6"))
      next_protocol = 2;
    else if (unformat(line_input, "next-ethernet"))
      next_protocol = 3;
    else if (unformat(line_input, "next-nsh"))
      next_protocol = 4;
    else if (unformat (line_input, "c1 %d", &c1))
      ;
    else if (unformat (line_input, "c2 %d", &c2))
      ;
    else if (unformat (line_input, "c3 %d", &c3))
      ;
    else if (unformat (line_input, "c4 %d", &c4))
      ;
    else if (unformat (line_input, "spi %d", &spi))
      spi_set = 1;
    else if (unformat (line_input, "si %d", &si))
      si_set = 1;
    else if (unformat (line_input, "tlv %x"))
        vec_add1 (tlvs, tmp);
    else 
      return clib_error_return (0, "parse error: '%U'", 
                                format_unformat_error, line_input);
  }

  unformat_free (line_input);

  if (src_set == 0)
    return clib_error_return (0, "tunnel src address not specified");

  if (dst_set == 0)
    return clib_error_return (0, "tunnel dst address not specified");

  if (vni_set == 0)
    return clib_error_return (0, "vni not specified");

  if (spi_set == 0)
    return clib_error_return (0, "spi not specified");
  
  if (si_set == 0)
    return clib_error_return (0, "si not specified");

  spi_si = (spi<<8) | si;
  
  memset (a, 0, sizeof (*a));

  a->is_add = is_add;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _
  
  rv = vnet_nsh_vxlan_gpe_add_del_tunnel (a, 0 /* hw_if_indexp */);

  switch(rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_DECAP_NEXT:
      return clib_error_return (0, "invalid decap-next...");

    case VNET_API_ERROR_TUNNEL_EXIST:
      return clib_error_return (0, "tunnel already exists...");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "tunnel does not exist...");

    default:
      return clib_error_return 
        (0, "vnet_nsh_vxlan_gpe_add_del_tunnel returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_nsh_vxlan_gpe_tunnel_command, static) = {
  .path = "nsh vxlan tunnel",
  .short_help = 
  "nsh vxlan tunnel src <ip4-addr> dst <ip4-addr>" 
  "    c1 <nn> c2 <nn> c3 <nn> c4 <nn> spi <nn> si <nn> vni <nn>\n"
  "    [encap-vrf-id <nn>] [decap-vrf-id <nn>] [o-bit <1|0>] [c-bit <1|0>]\n"
  "    [md-type <nn>][next-ip4][next-ip6][next-ethernet][next-nsh]\n"
  "    [tlv <xx>][decap-next [ip4|ip6|ethernet|nsh-vxlan-gpe]][del]\n",
  .function = nsh_vxlan_gpe_add_del_tunnel_command_fn,
};

static clib_error_t *
show_nsh_vxlan_gpe_tunnel_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;
  nsh_vxlan_gpe_tunnel_t * t;
  
  if (pool_elts (ngm->tunnels) == 0)
    vlib_cli_output (vm, "No nsh-vxlan-gpe tunnels configured...");

  pool_foreach (t, ngm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_nsh_vxlan_gpe_tunnel, t);
  }));
  
  return 0;
}

VLIB_CLI_COMMAND (show_nsh_vxlan_gpe_tunnel_command, static) = {
    .path = "show nsh vxlan tunnel",
    .function = show_nsh_vxlan_gpe_tunnel_command_fn,
};

clib_error_t *nsh_vxlan_gpe_init (vlib_main_t *vm)
{
  nsh_vxlan_gpe_main_t *ngm = &nsh_vxlan_gpe_main;
  
  ngm->vnet_main = vnet_get_main();
  ngm->vlib_main = vm;
  
  ngm->nsh_vxlan_gpe_tunnel_by_key 
    = hash_create_mem (0, sizeof(nsh_vxlan_gpe_tunnel_key_t), sizeof (uword));

  udp_register_dst_port (vm, UDP_DST_PORT_vxlan_gpe, 
                         nsh_vxlan_gpe_input_node.index, 1 /* is_ip4 */);
  return 0;
}

VLIB_INIT_FUNCTION(nsh_vxlan_gpe_init);
  
