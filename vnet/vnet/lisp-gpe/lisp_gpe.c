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
#include <vnet/lisp-gpe/lisp_gpe.h>

lisp_gpe_main_t lisp_gpe_main;

static u8 * format_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case LISP_GPE_INPUT_NEXT_DROP:
      return format (s, "drop");
    case LISP_GPE_INPUT_NEXT_IP4_INPUT:
      return format (s, "ip4");
    case LISP_GPE_INPUT_NEXT_IP6_INPUT:
      return format (s, "ip6");
    case LISP_GPE_INPUT_NEXT_LISP_GPE_ENCAP:
      return format (s, "nsh-lisp-gpe");
    default:
      return format (s, "unknown %d", next_index);
    }
  return s;
}

u8 * format_lisp_gpe_tunnel (u8 * s, va_list * args)
{
  lisp_gpe_tunnel_t * t = va_arg (*args, lisp_gpe_tunnel_t *);
  lisp_gpe_main_t * ngm = &lisp_gpe_main;

  s = format (s, 
              "[%d] %U (src) %U (dst) fibs: encap %d, decap %d",
              t - ngm->tunnels,
              format_ip4_address, &t->src,
              format_ip4_address, &t->dst,
              t->encap_fib_index,
              t->decap_fib_index);

  s = format (s, " decap next %U\n", format_decap_next, t->decap_next_index);
  s = format (s, "lisp ver %d ", (t->ver_res>>6));

#define _(n,v) if (t->flags & v) s = format (s, "%s-bit ", #n);
  foreach_lisp_gpe_flag_bit;
#undef _

  s = format (s, "next_protocol %d ver_res %x res %x\n",
              t->next_protocol, t->ver_res, t->res);
  
  s = format (s, "iid %d (0x%x)\n", t->iid, t->iid);
  return s;
}

static u8 * format_lisp_gpe_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "lisp_gpe_tunnel%d", dev_instance);
}

static uword dummy_interface_tx (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

VNET_DEVICE_CLASS (lisp_gpe_device_class,static) = {
  .name = "LISP_GPE",
  .format_device_name = format_lisp_gpe_name,
  .format_tx_trace = format_lisp_gpe_encap_trace,
  .tx_function = dummy_interface_tx,
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

u8 * format_lisp_gpe_header_with_length (u8 * s, va_list * args)
{
  lisp_gpe_header_t * h = va_arg (*args, lisp_gpe_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "gre-nsh header truncated");

  s = format (s, "flags: ");
#define _(n,v) if (h->flags & v) s = format (s, "%s ", #n);
  foreach_lisp_gpe_flag_bit;
#undef _

  s = format (s, "\n  ver_res %d res %d next_protocol %d iid %d(%x)",
              h->ver_res, h->res, h->next_protocol, 
              clib_net_to_host_u32 (h->iid),
              clib_net_to_host_u32 (h->iid));
  return s;
}

VNET_HW_INTERFACE_CLASS (lisp_gpe_hw_class) = {
  .name = "LISP_GPE",
  .format_header = format_lisp_gpe_header_with_length,
  .set_rewrite = dummy_set_rewrite,
};

#define foreach_copy_field                      \
_(src.as_u32)                                   \
_(dst.as_u32)                                   \
_(encap_fib_index)                              \
_(decap_fib_index)                              \
_(decap_next_index)                             \
_(flags)                                        \
_(next_protocol)				\
_(ver_res)                                      \
_(res)                                          \
_(iid)

static int lisp_gpe_rewrite (lisp_gpe_tunnel_t * t)
{
  u8 *rw = 0;
  ip4_header_t * ip0;
  lisp_gpe_header_t * lisp0;
  ip4_udp_lisp_gpe_header_t * h0;
  int len;

  len = sizeof (*h0);

  vec_validate_aligned (rw, len-1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip4_udp_lisp_gpe_header_t *) rw;

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
  h0->udp.src_port = clib_host_to_net_u16 (4341);
  h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_lisp_gpe);

  /* LISP-gpe header */
  lisp0 = &h0->lisp;
  
  lisp0->flags = t->flags;
  lisp0->ver_res = t->ver_res;
  lisp0->res = t->res;
  lisp0->next_protocol = t->next_protocol;
  lisp0->iid = clib_host_to_net_u32 (t->iid);
  
  t->rewrite = rw;
  return (0);
}

int vnet_lisp_gpe_add_del_tunnel 
(vnet_lisp_gpe_add_del_tunnel_args_t *a, u32 * sw_if_indexp)
{
  lisp_gpe_main_t * ngm = &lisp_gpe_main;
  lisp_gpe_tunnel_t *t = 0;
  vnet_main_t * vnm = ngm->vnet_main;
  vnet_hw_interface_t * hi;
  uword * p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  int rv;
  lisp_gpe_tunnel_key_t key, *key_copy;
  hash_pair_t *hp;
  
  key.src = a->src.as_u32;
  key.iid = clib_host_to_net_u32(a->iid);

  p = hash_get_mem (ngm->lisp_gpe_tunnel_by_key, &key);
  
  if (a->is_add)
    {
      /* adding a tunnel: tunnel must not already exist */
      if (p) 
        return VNET_API_ERROR_INVALID_VALUE;
      
      if (a->decap_next_index >= LISP_GPE_INPUT_N_NEXT)
        return VNET_API_ERROR_INVALID_DECAP_NEXT;
      
      pool_get_aligned (ngm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));
      
      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _
      
      rv = lisp_gpe_rewrite (t);

      if (rv)
        {
          pool_put (ngm->tunnels, t);
          return rv;
        }

      key_copy = clib_mem_alloc (sizeof (*key_copy));
      memcpy (key_copy, &key, sizeof (*key_copy));

      hash_set_mem (ngm->lisp_gpe_tunnel_by_key, key_copy, 
                    t - ngm->tunnels);
      
      if (vec_len (ngm->free_lisp_gpe_tunnel_hw_if_indices) > 0)
        {
          hw_if_index = ngm->free_lisp_gpe_tunnel_hw_if_indices
            [vec_len (ngm->free_lisp_gpe_tunnel_hw_if_indices)-1];
          _vec_len (ngm->free_lisp_gpe_tunnel_hw_if_indices) -= 1;
          
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->dev_instance = t - ngm->tunnels;
          hi->hw_instance = hi->dev_instance;
        }
      else 
        {
          hw_if_index = vnet_register_interface
            (vnm, lisp_gpe_device_class.index, t - ngm->tunnels,
             lisp_gpe_hw_class.index, t - ngm->tunnels);
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->output_node_index = lisp_gpe_encap_node.index;
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
      vec_add1 (ngm->free_lisp_gpe_tunnel_hw_if_indices, t->hw_if_index);

      hp = hash_get_pair (ngm->lisp_gpe_tunnel_by_key, &key);
      key_copy = (void *)(hp->key);
      hash_unset_mem (ngm->lisp_gpe_tunnel_by_key, &key);
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
    *result = LISP_GPE_INPUT_NEXT_DROP;
  else if (unformat (input, "ip4"))
    *result = LISP_GPE_INPUT_NEXT_IP4_INPUT;
  else if (unformat (input, "ip6"))
    *result = LISP_GPE_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, "ethernet"))
    *result = LISP_GPE_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, "lisp-gpe"))
    *result = LISP_GPE_INPUT_NEXT_LISP_GPE_ENCAP;
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static clib_error_t *
lisp_gpe_add_del_tunnel_command_fn (vlib_main_t * vm,
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
  u8 next_protocol = LISP_GPE_NEXT_PROTOCOL_IP4;
  u32 decap_next_index = LISP_GPE_INPUT_NEXT_IP4_INPUT;
  u8 flags = LISP_GPE_FLAGS_P;
  u8 ver_res = 0;
  u8 res = 0;
  u32 iid = 0;
  u8 iid_set = 0;
  u32 tmp;
  int rv;
  vnet_lisp_gpe_add_del_tunnel_args_t _a, * a = &_a;
  
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
    else if (unformat(line_input, "next-ip4"))
      next_protocol = 1;
    else if (unformat(line_input, "next-ip6"))
      next_protocol = 2;
    else if (unformat(line_input, "next-ethernet"))
      next_protocol = 3;
    else if (unformat(line_input, "next-nsh"))
      next_protocol = 4;
    /* Allow the user to specify anything they want in the LISP hdr */
    else if (unformat (line_input, "ver_res %x", &tmp))
      ver_res = tmp;
    else if (unformat (line_input, "res %x", &tmp))
      res = tmp;
    else if (unformat (line_input, "flags %x", &tmp))
      flags = tmp;
    else if (unformat (line_input, "n-bit"))
      flags |= LISP_GPE_FLAGS_N;
    else if (unformat (line_input, "l-bit"))
      flags |= LISP_GPE_FLAGS_L;
    else if (unformat (line_input, "e-bit"))
      flags |= LISP_GPE_FLAGS_E;
    else if (unformat (line_input, "v-bit"))
      flags |= LISP_GPE_FLAGS_V;
    else if (unformat (line_input, "i-bit"))
      flags |= LISP_GPE_FLAGS_V;
    else if (unformat (line_input, "not-p-bit"))
      flags &= ~LISP_GPE_FLAGS_P;
    else if (unformat (line_input, "p-bit"))
      flags |= LISP_GPE_FLAGS_P;
    else if (unformat (line_input, "o-bit"))
      flags |= LISP_GPE_FLAGS_O;
    else if (unformat (line_input, "iidx %x", &iid))
      iid_set = 1;
    else if (unformat (line_input, "iid %d", &iid))
      iid_set = 1;
    else 
      return clib_error_return (0, "parse error: '%U'", 
                                format_unformat_error, line_input);
  }

  unformat_free (line_input);

  if (src_set == 0)
    return clib_error_return (0, "tunnel src address not specified");

  if (dst_set == 0)
    return clib_error_return (0, "tunnel dst address not specified");

  if (iid_set == 0)
    return clib_error_return (0, "iid not specified");

  memset (a, 0, sizeof (*a));

  a->is_add = is_add;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _
  
  rv = vnet_lisp_gpe_add_del_tunnel (a, 0 /* hw_if_indexp */);

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
        (0, "vnet_lisp_gpe_add_del_tunnel returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_lisp_gpe_tunnel_command, static) = {
  .path = "lisp gpe tunnel",
  .short_help = 
  "lisp gpe tunnel src <ip4-addr> dst <ip4-addr> iidx <0xnn> | iid <nn>\n"
  "    [encap-fib-id <nn>] [decap-fib-id <nn>]\n"
  "    [n-bit][l-bit][e-bit][v-bit][i-bit][p-bit][not-p-bit][o-bit]\n"
  "    [next-ip4][next-ip6][next-ethernet][next-nsh]\n"
  "    [decap-next [ip4|ip6|ethernet|nsh-encap|<nn>]][del]\n",
  .function = lisp_gpe_add_del_tunnel_command_fn,
};

static clib_error_t *
show_lisp_gpe_tunnel_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t * ngm = &lisp_gpe_main;
  lisp_gpe_tunnel_t * t;
  
  if (pool_elts (ngm->tunnels) == 0)
    vlib_cli_output (vm, "No lisp-gpe tunnels configured...");

  pool_foreach (t, ngm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_lisp_gpe_tunnel, t);
  }));
  
  return 0;
}

VLIB_CLI_COMMAND (show_lisp_gpe_tunnel_command, static) = {
    .path = "show lisp gpe tunnel",
    .function = show_lisp_gpe_tunnel_command_fn,
};

clib_error_t *lisp_gpe_init (vlib_main_t *vm)
{
  lisp_gpe_main_t *ngm = &lisp_gpe_main;
  
  ngm->vnet_main = vnet_get_main();
  ngm->vlib_main = vm;
  
  ngm->lisp_gpe_tunnel_by_key 
    = hash_create_mem (0, sizeof(lisp_gpe_tunnel_key_t), sizeof (uword));

  udp_register_dst_port (vm, UDP_DST_PORT_lisp_gpe, 
                         lisp_gpe_input_node.index, 1 /* is_ip4 */);
  return 0;
}

VLIB_INIT_FUNCTION(lisp_gpe_init);
  
