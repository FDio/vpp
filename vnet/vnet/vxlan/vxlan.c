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
#include <vnet/vxlan/vxlan.h>
#include <vnet/ip/format.h>

vxlan_main_t vxlan_main;

static u8 * format_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case VXLAN_INPUT_NEXT_DROP:
      return format (s, "drop");
    case VXLAN_INPUT_NEXT_L2_INPUT:
      return format (s, "l2");
    case VXLAN_INPUT_NEXT_IP4_INPUT:
      return format (s, "ip4");
    case VXLAN_INPUT_NEXT_IP6_INPUT:
      return format (s, "ip6");
    default:
      return format (s, "unknown %d", next_index);
    }
  return s;
}

u8 * format_vxlan_tunnel (u8 * s, va_list * args)
{
  vxlan_tunnel_t * t = va_arg (*args, vxlan_tunnel_t *);
  vxlan_main_t * ngm = &vxlan_main;

  s = format (s, 
              "[%d] %U (src) %U (dst) vni %d encap_fib_index %d",
              t - ngm->tunnels,
              format_ip46_address, &t->src,
              format_ip46_address, &t->dst,
              t->vni,
              t->encap_fib_index);
  s = format (s, " decap_next %U\n", format_decap_next, t->decap_next_index);
  return s;
}

static u8 * format_vxlan_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "vxlan_tunnel%d", dev_instance);
}

static uword dummy_interface_tx (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

static clib_error_t *
vxlan_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, hw_if_index, VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, hw_if_index, 0);

  return /* no error */ 0;
}

VNET_DEVICE_CLASS (vxlan_device_class,static) = {
  .name = "VXLAN",
  .format_device_name = format_vxlan_name,
  .format_tx_trace = format_vxlan_encap_trace,
  .tx_function = dummy_interface_tx,
  .admin_up_down_function = vxlan_interface_admin_up_down,
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

static u8 * format_vxlan_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

VNET_HW_INTERFACE_CLASS (vxlan_hw_class) = {
  .name = "VXLAN",
  .format_header = format_vxlan_header_with_length,
  .set_rewrite = dummy_set_rewrite,
};

#define foreach_copy_field                      \
_(vni)                                          \
_(encap_fib_index)                              \
_(decap_next_index)

#define foreach_copy_ipv4 {                     \
  _(src.ip4.as_u32)                             \
  _(dst.ip4.as_u32)                             \
}

#define foreach_copy_ipv6 {                     \
  _(src.ip6.as_u64[0])                          \
  _(src.ip6.as_u64[1])                          \
  _(dst.ip6.as_u64[0])                          \
  _(dst.ip6.as_u64[1])                          \
}

static int vxlan4_rewrite (vxlan_tunnel_t * t)
{
  u8 *rw = 0;
  ip4_header_t * ip0;
  ip4_vxlan_header_t * h0;
  int len = sizeof (*h0);

  vec_validate_aligned (rw, len-1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip4_vxlan_header_t *) rw;

  /* Fixed portion of the (outer) ip4 header */
  ip0 = &h0->ip4;
  ip0->ip_version_and_header_length = 0x45;
  ip0->ttl = 254;
  ip0->protocol = IP_PROTOCOL_UDP;

  /* we fix up the ip4 header length and checksum after-the-fact */
  ip0->src_address.as_u32 = t->src.ip4.as_u32;
  ip0->dst_address.as_u32 = t->dst.ip4.as_u32;
  ip0->checksum = ip4_header_checksum (ip0);

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (4789);
  h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_vxlan);

  /* VXLAN header */
  vnet_set_vni_and_flags(&h0->vxlan, t->vni);

  t->rewrite = rw;
  return (0);
}

static int vxlan6_rewrite (vxlan_tunnel_t * t)
{
  u8 *rw = 0;
  ip6_header_t * ip0;
  ip6_vxlan_header_t * h0;
  int len = sizeof (*h0);

  vec_validate_aligned (rw, len-1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip6_vxlan_header_t *) rw;

  /* Fixed portion of the (outer) ip6 header */
  ip0 = &h0->ip6;
  ip0->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32(6 << 28);
  ip0->hop_limit = 255;
  ip0->protocol = IP_PROTOCOL_UDP;

  ip0->src_address.as_u64[0] = t->src.ip6.as_u64[0];
  ip0->src_address.as_u64[1] = t->src.ip6.as_u64[1];
  ip0->dst_address.as_u64[0] = t->dst.ip6.as_u64[0];
  ip0->dst_address.as_u64[1] = t->dst.ip6.as_u64[1];

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (4789);
  h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_vxlan);

  /* VXLAN header */
  vnet_set_vni_and_flags(&h0->vxlan, t->vni);

  t->rewrite = rw;
  return (0);
}

int vnet_vxlan_add_del_tunnel 
(vnet_vxlan_add_del_tunnel_args_t *a, u32 * sw_if_indexp)
{
  vxlan_main_t * vxm = &vxlan_main;
  vxlan_tunnel_t *t = 0;
  vnet_main_t * vnm = vxm->vnet_main;
  ip4_main_t * im4 = &ip4_main;
  ip6_main_t * im6 = &ip6_main;
  vnet_hw_interface_t * hi;
  uword * p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  int rv;
  vxlan4_tunnel_key_t key4;
  vxlan6_tunnel_key_t key6;

  if (!a->is_ip6) {
    key4.src = a->dst.ip4.as_u32; /* decap src in key is encap dst in config */
    key4.vni = clib_host_to_net_u32 (a->vni << 8);
  
    p = hash_get (vxm->vxlan4_tunnel_by_key, key4.as_u64);
  } else {
    key6.src.as_u64[0] = a->dst.ip6.as_u64[0];
    key6.src.as_u64[1] = a->dst.ip6.as_u64[1];
    key6.vni = clib_host_to_net_u32 (a->vni << 8);

    p = hash_get (vxm->vxlan6_tunnel_by_key, pointer_to_uword(&key6));
  }
  
  if (a->is_add)
    {
      /* adding a tunnel: tunnel must not already exist */
      if (p)
        return VNET_API_ERROR_TUNNEL_EXIST;

      if (a->decap_next_index == ~0)
	  a->decap_next_index = VXLAN_INPUT_NEXT_L2_INPUT;

      if (a->decap_next_index >= VXLAN_INPUT_N_NEXT)
        return VNET_API_ERROR_INVALID_DECAP_NEXT;
      
      pool_get_aligned (vxm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));
      
      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
      if (!a->is_ip6) foreach_copy_ipv4
      else            foreach_copy_ipv6
#undef _
      
      if (a->is_ip6) {
        /* copy the key */
        t->key6 = key6;
      }

      if (!a->is_ip6) t->flags |= VXLAN_TUNNEL_IS_IPV4;

      if (!a->is_ip6) {
        rv = vxlan4_rewrite (t);
      } else {
        rv = vxlan6_rewrite (t);
      }

      if (rv)
        {
          pool_put (vxm->tunnels, t);
          return rv;
        }

      if (!a->is_ip6)
        hash_set (vxm->vxlan4_tunnel_by_key, key4.as_u64, t - vxm->tunnels);
      else
        hash_set (vxm->vxlan6_tunnel_by_key, pointer_to_uword(&t->key6), t - vxm->tunnels);
      
      if (vec_len (vxm->free_vxlan_tunnel_hw_if_indices) > 0)
        {
	  vnet_interface_main_t * im = &vnm->interface_main;
          hw_if_index = vxm->free_vxlan_tunnel_hw_if_indices
            [vec_len (vxm->free_vxlan_tunnel_hw_if_indices)-1];
          _vec_len (vxm->free_vxlan_tunnel_hw_if_indices) -= 1;
          
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->dev_instance = t - vxm->tunnels;
          hi->hw_instance = hi->dev_instance;

	  /* clear old stats of freed tunnel before reuse */
	  sw_if_index = hi->sw_if_index;
	  vnet_interface_counter_lock(im);
	  vlib_zero_combined_counter 
	    (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX], sw_if_index);
	  vlib_zero_combined_counter 
	    (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_RX], sw_if_index);
	  vlib_zero_simple_counter 
	    (&im->sw_if_counters[VNET_INTERFACE_COUNTER_DROP], sw_if_index);
	  vnet_interface_counter_unlock(im);
        }
      else 
        {
          hw_if_index = vnet_register_interface
            (vnm, vxlan_device_class.index, t - vxm->tunnels,
             vxlan_hw_class.index, t - vxm->tunnels);
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->output_node_index = vxlan_encap_node.index;
        }
      
      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index = hi->sw_if_index;
      
      vec_validate_init_empty (vxm->tunnel_index_by_sw_if_index, sw_if_index, ~0);
      vxm->tunnel_index_by_sw_if_index[sw_if_index] = t - vxm->tunnels;

      if (a->decap_next_index == VXLAN_INPUT_NEXT_L2_INPUT)
        {
	  l2input_main_t * l2im = &l2input_main;
	  /* setup l2 input config with l2 feature and bd 0 to drop packet */
	  vec_validate (l2im->configs, sw_if_index);
	  l2im->configs[sw_if_index].feature_bitmap = L2INPUT_FEAT_DROP;
	  l2im->configs[sw_if_index].bd_index = 0;
	}
      vnet_sw_interface_set_flags (vnm, sw_if_index, 
                                   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
      if (!a->is_ip6) {
      vec_validate (im4->fib_index_by_sw_if_index, sw_if_index);
      im4->fib_index_by_sw_if_index[sw_if_index] = t->encap_fib_index;
      } else {
        vec_validate (im6->fib_index_by_sw_if_index, sw_if_index);
        im6->fib_index_by_sw_if_index[sw_if_index] = t->encap_fib_index;
      }
    }
  else
    {
      /* deleting a tunnel: tunnel must exist */
      if (!p) 
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (vxm->tunnels, p[0]);

      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */);
      /* make sure tunnel is removed from l2 bd or xconnect */
      set_int_l2_mode(vxm->vlib_main, vnm, MODE_L3, t->sw_if_index, 0, 0, 0, 0);
      vec_add1 (vxm->free_vxlan_tunnel_hw_if_indices, t->hw_if_index);

      vxm->tunnel_index_by_sw_if_index[t->sw_if_index] = ~0;

      if (!a->is_ip6)
        hash_unset (vxm->vxlan4_tunnel_by_key, key4.as_u64);
      else
        hash_unset (vxm->vxlan6_tunnel_by_key, pointer_to_uword(&key6));

      vec_free (t->rewrite);
      if (!a->is_ip6) {
        t->rewrite = vxlan4_dummy_rewrite;
      } else {
        t->rewrite = vxlan6_dummy_rewrite;
      }
      pool_put (vxm->tunnels, t);
    }

  if (sw_if_indexp)
      *sw_if_indexp = sw_if_index;

  return 0;
}

static u32 fib4_index_from_fib_id (u32 fib_id)
{
  ip4_main_t * im = &ip4_main;
  uword * p;

  p = hash_get (im->fib_index_by_table_id, fib_id);
  if (!p)
    return ~0;

  return p[0];
}

static u32 fib6_index_from_fib_id (u32 fib_id)
{
  ip6_main_t * im = &ip6_main;
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
  
  if (unformat (input, "l2"))
    *result = VXLAN_INPUT_NEXT_L2_INPUT;
  else if (unformat (input, "drop"))
    *result = VXLAN_INPUT_NEXT_DROP;
  else if (unformat (input, "ip4"))
    *result = VXLAN_INPUT_NEXT_IP4_INPUT;
  else if (unformat (input, "ip6"))
    *result = VXLAN_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static clib_error_t *
vxlan_add_del_tunnel_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  ip46_address_t src, dst;
  u8 is_add = 1;
  u8 src_set = 0;
  u8 dst_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u32 encap_fib_index = 0;
  u32 decap_next_index = ~0;
  u32 vni = 0;
  u32 tmp;
  int rv;
  vnet_vxlan_add_del_tunnel_args_t _a, * a = &_a;
  u32 sw_if_index;
  
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      {
        is_add = 0;
      }
    else if (unformat (line_input, "src %U",
                       unformat_ip4_address, &src.ip4))
      {
        src_set = 1;
        ipv4_set = 1;
      }
    else if (unformat (line_input, "dst %U",
                       unformat_ip4_address, &dst.ip4))
      {
        dst_set = 1;
        ipv4_set = 1;
      }
    else if (unformat (line_input, "src %U", 
                       unformat_ip6_address, &src.ip6))
      {
        src_set = 1;
        ipv6_set = 1;
      }
    else if (unformat (line_input, "dst %U",
                       unformat_ip6_address, &dst.ip6))
      {
        dst_set = 1;
        ipv6_set = 1;
      }
    else if (unformat (line_input, "encap-vrf-id %d", &tmp))
      {
        if (ipv6_set)
          encap_fib_index = fib6_index_from_fib_id (tmp);
        else
          encap_fib_index = fib4_index_from_fib_id (tmp);
        if (encap_fib_index == ~0)
          return clib_error_return (0, "nonexistent encap-vrf-id %d", tmp);
      }
    else if (unformat (line_input, "decap-next %U", unformat_decap_next, 
                       &decap_next_index))
      ;
    else if (unformat (line_input, "vni %d", &vni))
      {
        if (vni >> 24)  
          return clib_error_return (0, "vni %d out of range", vni);
      }
    else 
      return clib_error_return (0, "parse error: '%U'", 
                                format_unformat_error, line_input);
  }

  unformat_free (line_input);

  if (src_set == 0)
    return clib_error_return (0, "tunnel src address not specified");

  if (dst_set == 0)
    return clib_error_return (0, "tunnel dst address not specified");

  if (ipv4_set && ipv6_set)
    return clib_error_return (0, "both IPv4 and IPv6 addresses specified");

  if ((ipv4_set && memcmp(&src.ip4, &dst.ip4, sizeof(src.ip4)) == 0) ||
      (ipv6_set && memcmp(&src.ip6, &dst.ip6, sizeof(src.ip6)) == 0))
    return clib_error_return (0, "src and dst addresses are identical");

  if (vni == 0)
    return clib_error_return (0, "vni not specified");

  memset (a, 0, sizeof (*a));

  a->is_add = is_add;
  a->is_ip6 = ipv6_set;

#define _(x) a->x = x;
  foreach_copy_field;
  if (ipv4_set) foreach_copy_ipv4
  else          foreach_copy_ipv6
#undef _
  
  rv = vnet_vxlan_add_del_tunnel (a, &sw_if_index);

  switch(rv)
    {
    case 0:
      if (is_add)
        vlib_cli_output(vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main(), sw_if_index);
      break;
    case VNET_API_ERROR_INVALID_DECAP_NEXT:
      return clib_error_return (0, "invalid decap-next...");

    case VNET_API_ERROR_TUNNEL_EXIST:
      return clib_error_return (0, "tunnel already exists...");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "tunnel does not exist...");

    default:
      return clib_error_return 
        (0, "vnet_vxlan_add_del_tunnel returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_vxlan_tunnel_command, static) = {
  .path = "create vxlan tunnel",
  .short_help = 
  "create vxlan tunnel src <local-vtep-addr> dst <remote-vtep-addr> vni <nn>" 
  " [encap-vrf-id <nn>] [decap-next [l2|ip4|ip6] [del]\n",
  .function = vxlan_add_del_tunnel_command_fn,
};

static clib_error_t *
show_vxlan_tunnel_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  vxlan_main_t * vxm = &vxlan_main;
  vxlan_tunnel_t * t;
  
  if (pool_elts (vxm->tunnels) == 0)
    vlib_cli_output (vm, "No vxlan tunnels configured...");

  pool_foreach (t, vxm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_vxlan_tunnel, t);
  }));
  
  return 0;
}

VLIB_CLI_COMMAND (show_vxlan_tunnel_command, static) = {
    .path = "show vxlan tunnel",
    .function = show_vxlan_tunnel_command_fn,
};


clib_error_t *vxlan_init (vlib_main_t *vm)
{
  vxlan_main_t * vxm = &vxlan_main;
  ip4_vxlan_header_t * hdr4;
  ip4_header_t * ip4;
  ip6_vxlan_header_t * hdr6;
  ip6_header_t * ip6;
  
  vxm->vnet_main = vnet_get_main();
  vxm->vlib_main = vm;

  /* initialize the ip6 hash */
  vxm->vxlan6_tunnel_by_key = hash_create_mem(0,
        sizeof(vxlan6_tunnel_key_t),
        sizeof(uword));

  /* init dummy rewrite string for deleted vxlan tunnels */
  _vec_len(vxlan4_dummy_rewrite) = sizeof(ip4_vxlan_header_t);
  hdr4 = (ip4_vxlan_header_t *) vxlan4_dummy_rewrite;
  ip4 = &hdr4->ip4;
  /* minimal rewrite setup, see vxlan_rewite() above as reference */
  ip4->ip_version_and_header_length = 0x45;
  ip4->checksum = ip4_header_checksum (ip4);

  /* Same again for IPv6 */
  _vec_len(vxlan6_dummy_rewrite) = sizeof(ip6_vxlan_header_t);
  hdr6 = (ip6_vxlan_header_t *) vxlan6_dummy_rewrite;
  ip6 = &hdr6->ip6;
  /* minimal rewrite setup, see vxlan_rewite() above as reference */
  ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32(6 << 28);
 
  udp_register_dst_port (vm, UDP_DST_PORT_vxlan, 
                         vxlan4_input_node.index, /* is_ip4 */ 1);
  udp_register_dst_port (vm, UDP_DST_PORT_vxlan6,
                         vxlan6_input_node.index, /* is_ip4 */ 0);
  return 0;
}

VLIB_INIT_FUNCTION(vxlan_init);
