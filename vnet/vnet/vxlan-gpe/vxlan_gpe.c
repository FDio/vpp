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
#include <vnet/vxlan-gpe/vxlan_gpe.h>

vxlan_gpe_main_t vxlan_gpe_main;

u8 * format_vxlan_gpe_tunnel (u8 * s, va_list * args)
{
  vxlan_gpe_tunnel_t * t = va_arg (*args, vxlan_gpe_tunnel_t *);
  vxlan_gpe_main_t * gm = &vxlan_gpe_main;

  s = format (s, "[%d] local: %U remote: %U ",
              t - gm->tunnels,
              format_ip4_address, &t->local,
              format_ip4_address, &t->remote);    

  switch (t->protocol)
    {
    case VXLAN_GPE_PROTOCOL_IP4:
      s = format (s, "next-protocol ip4");
    case VXLAN_GPE_PROTOCOL_IP6:
      s = format (s, "next-protocol ip6");
    case VXLAN_GPE_PROTOCOL_ETHERNET:
      s = format (s, "next-protocol ethernet");
    case VXLAN_GPE_PROTOCOL_NSH:
      s = format (s, "next-protocol nsh");
    default:
      s = format (s, "next-protocol unknown %d", t->protocol);
    }

  s = format (s, " fibs: (encap %d, decap %d)",
              t->encap_fib_index,
              t->decap_fib_index);

  s = format (s, "  vxlan VNI %d ", t->vni);

  return s;
}

static u8 * format_vxlan_gpe_name (u8 * s, va_list * args)
{
  vxlan_gpe_main_t * gm = &vxlan_gpe_main;
  u32 i = va_arg (*args, u32);
  u32 show_dev_instance = ~0;

  if (i < vec_len (gm->dev_inst_by_real))
    show_dev_instance = gm->dev_inst_by_real[i];

  if (show_dev_instance != ~0)
    i = show_dev_instance;

  return format (s, "vxlan_gpe_tunnel%d", i);
}

static int vxlan_gpe_name_renumber (vnet_hw_interface_t * hi,
                                        u32 new_dev_instance)
{
  vxlan_gpe_main_t * gm = &vxlan_gpe_main;

  vec_validate_init_empty (gm->dev_inst_by_real, hi->dev_instance, ~0);

  gm->dev_inst_by_real [hi->dev_instance] = new_dev_instance;

  return 0;
}

static uword dummy_interface_tx (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

static uword dummy_set_rewrite (vnet_main_t * vnm,
                                u32 sw_if_index,
                                u32 l3_type,
                                void * dst_address,
                                void * rewrite,
                                uword max_rewrite_bytes)
{
  return 0;
}

VNET_DEVICE_CLASS (vxlan_gpe_device_class,static) = {
  .name = "VXLAN_GPE",
  .format_device_name = format_vxlan_gpe_name,
  .format_tx_trace = format_vxlan_gpe_encap_trace,
  .tx_function = dummy_interface_tx,
  .name_renumber = vxlan_gpe_name_renumber,
};

static u8 * format_vxlan_gpe_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

VNET_HW_INTERFACE_CLASS (vxlan_gpe_hw_class) = {
  .name = "VXLAN_GPE",
  .format_header = format_vxlan_gpe_header_with_length,
  .set_rewrite = dummy_set_rewrite,
};


#define foreach_gpe_copy_field                  \
_(local.as_u32)                                 \
_(remote.as_u32)				\
_(vni)                                          \
_(protocol)                                \
_(encap_fib_index)                              \
_(decap_fib_index)                              

#define foreach_copy_field			\
_(src.as_u32)                                   \
_(dst.as_u32)                                   \
_(vni)                                          \
_(encap_fib_index)                              \
_(decap_fib_index)                              \
_(decap_next_index)



static int vxlan_gpe_rewrite (vxlan_gpe_tunnel_t * t)
{
  u8 *rw = 0;
  ip4_header_t * ip0;
  ip4_vxlan_gpe_header_t * h0;
  int len;

  len = sizeof (*h0);

  vec_validate_aligned (rw, len-1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip4_vxlan_gpe_header_t *) rw;

  /* Fixed portion of the (outer) ip4 header */
  ip0 = &h0->ip4;
  ip0->ip_version_and_header_length = 0x45;
  ip0->ttl = 254;
  ip0->protocol = IP_PROTOCOL_UDP;

  /* we fix up the ip4 header length and checksum after-the-fact */
  ip0->src_address.as_u32 = t->local.as_u32; 
  ip0->dst_address.as_u32 = t->remote.as_u32; 
  ip0->checksum = ip4_header_checksum (ip0);

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (4790);
  h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_vxlan_gpe);

  /* VXLAN header. Are we having fun yet? */
  h0->vxlan.flags = VXLAN_GPE_FLAGS_I | VXLAN_GPE_FLAGS_P;
  h0->vxlan.ver_res = VXLAN_GPE_VERSION;
  h0->vxlan.protocol = VXLAN_GPE_PROTOCOL_IP4;
  h0->vxlan.vni_res = clib_host_to_net_u32 (t->vni<<8);

  t->rewrite = rw;
  return (0);
}

int vnet_vxlan_gpe_add_del_tunnel 
(vnet_vxlan_gpe_add_del_tunnel_args_t *a, u32 * sw_if_indexp)
{
  vxlan_gpe_main_t * gm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t = 0;
  vnet_main_t * vnm = gm->vnet_main;
  vnet_hw_interface_t * hi;
  uword * p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  int rv;
  vxlan_gpe_tunnel_key_t key, *key_copy;
  hash_pair_t *hp;
  
  key.local = a->local.as_u32; 
  key.remote = a->remote.as_u32; 
  key.vni = clib_host_to_net_u32 (a->vni << 8);
  key.pad = 0;

  p = hash_get_mem (gm->vxlan_gpe_tunnel_by_key, &key);
  
  if (a->is_add)
    {
      /* adding a tunnel: tunnel must not already exist */
      if (p) 
        return VNET_API_ERROR_INVALID_VALUE;
      
      if (a->decap_next_index >= VXLAN_GPE_INPUT_N_NEXT)
        return VNET_API_ERROR_INVALID_DECAP_NEXT;
      
      pool_get_aligned (gm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));
      
      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_gpe_copy_field;
#undef _

      rv = vxlan_gpe_rewrite (t);

      if (rv)
        {
          pool_put (gm->tunnels, t);
          return rv;
        }

      key_copy = clib_mem_alloc (sizeof (*key_copy));
      clib_memcpy (key_copy, &key, sizeof (*key_copy));

      hash_set_mem (gm->vxlan_gpe_tunnel_by_key, key_copy, 
                    t - gm->tunnels);
      
      if (vec_len (gm->free_vxlan_gpe_tunnel_hw_if_indices) > 0)
        {
          hw_if_index = gm->free_vxlan_gpe_tunnel_hw_if_indices
            [vec_len (gm->free_vxlan_gpe_tunnel_hw_if_indices)-1];
          _vec_len (gm->free_vxlan_gpe_tunnel_hw_if_indices) -= 1;
          
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->dev_instance = t - gm->tunnels;
          hi->hw_instance = hi->dev_instance;
        }
      else 
        {
          hw_if_index = vnet_register_interface
            (vnm, vxlan_gpe_device_class.index, t - gm->tunnels,
             vxlan_gpe_hw_class.index, t - gm->tunnels);
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->output_node_index = vxlan_gpe_encap_node.index;
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

      t = pool_elt_at_index (gm->tunnels, p[0]);

      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */);
      vec_add1 (gm->free_vxlan_gpe_tunnel_hw_if_indices, t->hw_if_index);

      hp = hash_get_pair (gm->vxlan_gpe_tunnel_by_key, &key);
      key_copy = (void *)(hp->key);
      hash_unset_mem (gm->vxlan_gpe_tunnel_by_key, &key);
      clib_mem_free (key_copy);

      vec_free (t->rewrite);
      pool_put (gm->tunnels, t);
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

static uword unformat_gpe_decap_next (unformat_input_t * input, va_list * args)
{
  u32 * result = va_arg (*args, u32 *);
  u32 tmp;
  
  if (unformat (input, "drop"))
    *result = VXLAN_GPE_INPUT_NEXT_DROP;
  else if (unformat (input, "ip4"))
    *result = VXLAN_GPE_INPUT_NEXT_IP4_INPUT;
  else if (unformat (input, "ip6"))
    *result = VXLAN_GPE_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, "ethernet"))
    *result = VXLAN_GPE_INPUT_NEXT_ETHERNET_INPUT;
  else if (unformat (input, "nsh"))
    *result = VXLAN_GPE_INPUT_NEXT_NSH_INPUT;
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static clib_error_t *
vxlan_gpe_add_del_tunnel_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  ip4_address_t local, remote;
  u8 local_set = 0;
  u8 remote_set = 0;
  u32 encap_fib_index = 0;
  u32 decap_fib_index = 0;
  u8 protocol = VXLAN_GPE_PROTOCOL_IP4;
  u32 decap_next_index = VXLAN_GPE_INPUT_NEXT_IP4_INPUT; 
  u32 vni;
  u8 vni_set = 0;
  int rv;
  u32 tmp;
  vnet_vxlan_gpe_add_del_tunnel_args_t _a, * a = &_a;
  
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "local %U", 
                       unformat_ip4_address, &local))
      local_set = 1;
    else if (unformat (line_input, "remote %U",
                       unformat_ip4_address, &remote))
      remote_set = 1;
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
    else if (unformat (line_input, "decap-next %U", unformat_gpe_decap_next, 
                       &decap_next_index))
      ;
    else if (unformat (line_input, "vni %d", &vni))
      vni_set = 1;
    else if (unformat(line_input, "next-ip4"))
      protocol = VXLAN_GPE_PROTOCOL_IP4;
    else if (unformat(line_input, "next-ip6"))
      protocol = VXLAN_GPE_PROTOCOL_IP6;
    else if (unformat(line_input, "next-ethernet"))
      protocol = VXLAN_GPE_PROTOCOL_ETHERNET;
    else if (unformat(line_input, "next-nsh"))
      protocol = VXLAN_GPE_PROTOCOL_NSH;
    else 
      return clib_error_return (0, "parse error: '%U'", 
                                format_unformat_error, line_input);
  }

  unformat_free (line_input);

  if (local_set == 0)
    return clib_error_return (0, "tunnel local address not specified");

  if (remote_set == 0)
    return clib_error_return (0, "tunnel remote address not specified");

  if (vni_set == 0)
    return clib_error_return (0, "vni not specified");

  memset (a, 0, sizeof (*a));

  a->is_add = is_add;

#define _(x) a->x = x;
  foreach_gpe_copy_field;
#undef _

  rv = vnet_vxlan_gpe_add_del_tunnel (a, 0 /* hw_if_indexp */);

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
        (0, "vnet_vxlan_gpe_add_del_tunnel returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_vxlan_gpe_tunnel_command, static) = {
  .path = "create vxlan-gpe tunnel",
  .short_help = 
  "create vxlan-gpe tunnel local <ip4-addr> remote <ip4-addr>"
  " vni <nn> [next-ip4][next-ip6][next-ethernet][next-nsh]"
  " [encap-vrf-id <nn>] [decap-vrf-id <nn>]"
  " [del]\n",
  .function = vxlan_gpe_add_del_tunnel_command_fn,
};

static clib_error_t *
show_vxlan_gpe_tunnel_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  vxlan_gpe_main_t * gm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t * t;
  
  if (pool_elts (gm->tunnels) == 0)
    vlib_cli_output (vm, "No vxlan-gpe tunnels configured.");

  pool_foreach (t, gm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_vxlan_gpe_tunnel, t);
  }));
  
  return 0;
}

VLIB_CLI_COMMAND (show_vxlan_gpe_tunnel_command, static) = {
    .path = "show vxlan-gpe",
    .function = show_vxlan_gpe_tunnel_command_fn,
};

clib_error_t *vxlan_gpe_init (vlib_main_t *vm)
{
  vxlan_gpe_main_t *gm = &vxlan_gpe_main;
  
  gm->vnet_main = vnet_get_main();
  gm->vlib_main = vm;
  
  gm->vxlan_gpe_tunnel_by_key 
    = hash_create_mem (0, sizeof(vxlan_gpe_tunnel_key_t), sizeof (uword));

  udp_register_dst_port (vm, UDP_DST_PORT_vxlan_gpe, 
                         vxlan_gpe_input_node.index, 1 /* is_ip4 */);
  return 0;
}

VLIB_INIT_FUNCTION(vxlan_gpe_init);

