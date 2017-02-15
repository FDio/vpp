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
/**
 *  @file
 *  @brief Common utility functions for IPv4 and IPv6 VXLAN GPE tunnels
 *
*/
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/fib/fib.h>
#include <vnet/ip/format.h>

vxlan_gpe_main_t vxlan_gpe_main;

/**
 * @brief Tracing function for VXLAN GPE tunnel packets
 *
 * @param *s formatting string
 * @param *args
 *
 * @return *s formatted string
 *
 */
u8 * format_vxlan_gpe_tunnel (u8 * s, va_list * args)
{
  vxlan_gpe_tunnel_t * t = va_arg (*args, vxlan_gpe_tunnel_t *);
  vxlan_gpe_main_t * gm = &vxlan_gpe_main;

  s = format (s, "[%d] local: %U remote: %U ",
              t - gm->tunnels,
              format_ip46_address, &t->local, IP46_TYPE_ANY,
              format_ip46_address, &t->remote, IP46_TYPE_ANY);

  s = format (s, "  vxlan VNI %d ", t->vni);

  switch (t->protocol)
    {
    case VXLAN_GPE_PROTOCOL_IP4:
      s = format (s, "next-protocol ip4");
      break;
    case VXLAN_GPE_PROTOCOL_IP6:
      s = format (s, "next-protocol ip6");
      break;
    case VXLAN_GPE_PROTOCOL_ETHERNET:
      s = format (s, "next-protocol ethernet");
      break;
    case VXLAN_GPE_PROTOCOL_NSH:
      s = format (s, "next-protocol nsh");
      break;
    default:
      s = format (s, "next-protocol unknown %d", t->protocol);
    }

  s = format (s, " fibs: (encap %d, decap %d)",
              t->encap_fib_index,
              t->decap_fib_index);

  return s;
}

/**
 * @brief Naming for VXLAN GPE tunnel
 *
 * @param *s formatting string
 * @param *args
 *
 * @return *s formatted string
 *
 */
static u8 * format_vxlan_gpe_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "vxlan_gpe_tunnel%d", dev_instance);
}

static uword dummy_interface_tx (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

/**
 * @brief CLI function for VXLAN GPE admin up/down
 *
 * @param *vnm
 * @param hw_if_index
 * @param flag
 *
 * @return *rc
 *
 */
static clib_error_t *
vxlan_gpe_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, hw_if_index, VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, hw_if_index, 0);

  return 0;
}

VNET_DEVICE_CLASS (vxlan_gpe_device_class,static) = {
  .name = "VXLAN_GPE",
  .format_device_name = format_vxlan_gpe_name,
  .format_tx_trace = format_vxlan_gpe_encap_trace,
  .tx_function = dummy_interface_tx,
  .admin_up_down_function = vxlan_gpe_interface_admin_up_down,
};


/**
 * @brief Formatting function for tracing VXLAN GPE with length
 *
 * @param *s
 * @param *args
 *
 * @return *s
 *
 */
static u8 * format_vxlan_gpe_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

VNET_HW_INTERFACE_CLASS (vxlan_gpe_hw_class) = {
  .name = "VXLAN_GPE",
  .format_header = format_vxlan_gpe_header_with_length,
  .build_rewrite = default_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};


#define foreach_gpe_copy_field                  \
_(vni)                                          \
_(protocol)                                \
_(encap_fib_index)                              \
_(decap_fib_index)

#define foreach_copy_ipv4 {                     \
  _(local.ip4.as_u32)                           \
  _(remote.ip4.as_u32)                          \
}

#define foreach_copy_ipv6 {                     \
  _(local.ip6.as_u64[0])                        \
  _(local.ip6.as_u64[1])                        \
  _(remote.ip6.as_u64[0])                       \
  _(remote.ip6.as_u64[1])                       \
}


/**
 * @brief Calculate IPv4 VXLAN GPE rewrite header
 *
 * @param *t
 *
 * @return rc
 *
 */
int vxlan4_gpe_rewrite (vxlan_gpe_tunnel_t * t, u32 extension_size, 
                        u8 protocol_override, uword encap_next_node)
{
  u8 *rw = 0;
  ip4_header_t * ip0;
  ip4_vxlan_gpe_header_t * h0;
  int len;

  len = sizeof (*h0) + extension_size;

  vec_free(t->rewrite);
  vec_validate_aligned (rw, len-1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip4_vxlan_gpe_header_t *) rw;

  /* Fixed portion of the (outer) ip4 header */
  ip0 = &h0->ip4;
  ip0->ip_version_and_header_length = 0x45;
  ip0->ttl = 254;
  ip0->protocol = IP_PROTOCOL_UDP;

  /* we fix up the ip4 header length and checksum after-the-fact */
  ip0->src_address.as_u32 = t->local.ip4.as_u32;
  ip0->dst_address.as_u32 = t->remote.ip4.as_u32;
  ip0->checksum = ip4_header_checksum (ip0);

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (4790);
  h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_vxlan_gpe);

  /* VXLAN header. Are we having fun yet? */
  h0->vxlan.flags = VXLAN_GPE_FLAGS_I | VXLAN_GPE_FLAGS_P;
  h0->vxlan.ver_res = VXLAN_GPE_VERSION;
  if (protocol_override)
  {
      h0->vxlan.protocol = protocol_override;
  }
  else
  {
      h0->vxlan.protocol = t->protocol;
  }
  t->rewrite_size = sizeof(ip4_vxlan_gpe_header_t) +  extension_size;
  h0->vxlan.vni_res = clib_host_to_net_u32 (t->vni<<8);

  t->rewrite = rw;
  t->encap_next_node = encap_next_node;
  return (0);
}

/**
 * @brief Calculate IPv6 VXLAN GPE rewrite header
 *
 * @param *t
 *
 * @return rc
 *
 */
int vxlan6_gpe_rewrite (vxlan_gpe_tunnel_t * t, u32 extension_size, 
                        u8 protocol_override, uword encap_next_node)
{
  u8 *rw = 0;
  ip6_header_t * ip0;
  ip6_vxlan_gpe_header_t * h0;
  int len;

  len = sizeof (*h0) + extension_size;

  vec_free(t->rewrite);
  vec_validate_aligned (rw, len-1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip6_vxlan_gpe_header_t *) rw;

  /* Fixed portion of the (outer) ip4 header */
  ip0 = &h0->ip6;
  ip0->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32(6 << 28);
  ip0->hop_limit = 255;
  ip0->protocol = IP_PROTOCOL_UDP;

  ip0->src_address.as_u64[0] = t->local.ip6.as_u64[0];
  ip0->src_address.as_u64[1] = t->local.ip6.as_u64[1];
  ip0->dst_address.as_u64[0] = t->remote.ip6.as_u64[0];
  ip0->dst_address.as_u64[1] = t->remote.ip6.as_u64[1];

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (4790);
  h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_vxlan_gpe);

  /* VXLAN header. Are we having fun yet? */
  h0->vxlan.flags = VXLAN_GPE_FLAGS_I | VXLAN_GPE_FLAGS_P;
  h0->vxlan.ver_res = VXLAN_GPE_VERSION;
  if (protocol_override)
  {
      h0->vxlan.protocol = t->protocol;
  }
  else
  {
      h0->vxlan.protocol = protocol_override;
  }
  t->rewrite_size = sizeof(ip4_vxlan_gpe_header_t) +  extension_size;
  h0->vxlan.vni_res = clib_host_to_net_u32 (t->vni<<8);

  t->rewrite = rw;
  t->encap_next_node = encap_next_node;
  return (0);
}

/**
 * @brief Add or Del a VXLAN GPE tunnel
 *
 * @param *a
 * @param *sw_if_index
 *
 * @return rc
 *
 */
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
  vxlan4_gpe_tunnel_key_t key4, *key4_copy;
  vxlan6_gpe_tunnel_key_t key6, *key6_copy;
  hash_pair_t *hp;

  if (!a->is_ip6)
  {
    key4.local = a->local.ip4.as_u32;
    key4.remote = a->remote.ip4.as_u32;
    key4.vni = clib_host_to_net_u32 (a->vni << 8);
    key4.pad = 0;

    p = hash_get_mem(gm->vxlan4_gpe_tunnel_by_key, &key4);
  }
  else
  {
    key6.local.as_u64[0] = a->local.ip6.as_u64[0];
    key6.local.as_u64[1] = a->local.ip6.as_u64[1];
    key6.remote.as_u64[0] = a->remote.ip6.as_u64[0];
    key6.remote.as_u64[1] = a->remote.ip6.as_u64[1];
    key6.vni = clib_host_to_net_u32 (a->vni << 8);

    p = hash_get_mem(gm->vxlan6_gpe_tunnel_by_key, &key6);
  }

  if (a->is_add)
    {
      /* adding a tunnel: tunnel must not already exist */
      if (p)
        return VNET_API_ERROR_INVALID_VALUE;

      pool_get_aligned (gm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_gpe_copy_field;
      if (!a->is_ip6) foreach_copy_ipv4
      else            foreach_copy_ipv6
#undef _

      if (!a->is_ip6) t->flags |= VXLAN_GPE_TUNNEL_IS_IPV4;

      if (!a->is_ip6) {
        rv = vxlan4_gpe_rewrite (t, 0, 0, VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP);
      } else {
        rv = vxlan6_gpe_rewrite (t, 0, 0, VXLAN_GPE_ENCAP_NEXT_IP6_LOOKUP);
      }

      if (rv)
      {
          pool_put (gm->tunnels, t);
          return rv;
      }

      if (!a->is_ip6)
      {
        key4_copy = clib_mem_alloc (sizeof (*key4_copy));
        clib_memcpy (key4_copy, &key4, sizeof (*key4_copy));
        hash_set_mem (gm->vxlan4_gpe_tunnel_by_key, key4_copy,
                      t - gm->tunnels);
      }
      else
      {
          key6_copy = clib_mem_alloc (sizeof (*key6_copy));
          clib_memcpy (key6_copy, &key6, sizeof (*key6_copy));
          hash_set_mem (gm->vxlan6_gpe_tunnel_by_key, key6_copy,
                        t - gm->tunnels);
      }

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
      vec_validate_init_empty (gm->tunnel_index_by_sw_if_index, sw_if_index, ~0);
      gm->tunnel_index_by_sw_if_index[sw_if_index] = t - gm->tunnels;

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

      gm->tunnel_index_by_sw_if_index[t->sw_if_index] = ~0;

      if (!a->is_ip6)
      {
        hp = hash_get_pair (gm->vxlan4_gpe_tunnel_by_key, &key4);
        key4_copy = (void *)(hp->key);
        hash_unset_mem (gm->vxlan4_gpe_tunnel_by_key, &key4);
        clib_mem_free (key4_copy);
      }
      else
      {
        hp = hash_get_pair (gm->vxlan6_gpe_tunnel_by_key, &key6);
        key6_copy = (void *)(hp->key);
        hash_unset_mem (gm->vxlan4_gpe_tunnel_by_key, &key6);
        clib_mem_free (key6_copy);
      }

      vec_free (t->rewrite);
      pool_put (gm->tunnels, t);
    }

  if (sw_if_indexp)
      *sw_if_indexp = sw_if_index;

  return 0;
}

static clib_error_t *
vxlan_gpe_add_del_tunnel_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  ip46_address_t local, remote;
  u8 local_set = 0;
  u8 remote_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u32 encap_fib_index = 0;
  u32 decap_fib_index = 0;
  u8 protocol = VXLAN_GPE_PROTOCOL_IP4;
  u32 vni;
  u8 vni_set = 0;
  int rv;
  u32 tmp;
  vnet_vxlan_gpe_add_del_tunnel_args_t _a, * a = &_a;
  u32 sw_if_index;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "local %U",
                       unformat_ip4_address, &local.ip4))
    {
      local_set = 1;
      ipv4_set = 1;
    }
    else if (unformat (line_input, "remote %U",
                       unformat_ip4_address, &remote.ip4))
    {
      remote_set = 1;
      ipv4_set = 1;
    }
    else if (unformat (line_input, "local %U",
                       unformat_ip6_address, &local.ip6))
    {
      local_set = 1;
      ipv6_set = 1;
    }
    else if (unformat (line_input, "remote %U",
                       unformat_ip6_address, &remote.ip6))
    {
      remote_set = 1;
      ipv6_set = 1;
    }
    else if (unformat (line_input, "encap-vrf-id %d", &tmp))
      {
        if (ipv6_set)
          encap_fib_index = ip6_fib_index_from_table_id (tmp);
        else
          encap_fib_index =  ip4_fib_index_from_table_id (tmp);

        if (encap_fib_index == ~0)
          {
            error = clib_error_return (0, "nonexistent encap fib id %d", tmp);
            goto done;
          }
      }
    else if (unformat (line_input, "decap-vrf-id %d", &tmp))
      {
        if (ipv6_set)
          decap_fib_index = ip6_fib_index_from_table_id (tmp);
        else
          decap_fib_index = ip4_fib_index_from_table_id (tmp);

        if (decap_fib_index == ~0)
          {
            error = clib_error_return (0, "nonexistent decap fib id %d", tmp);
            goto done;
          }
      }
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
      {
        error = clib_error_return (0, "parse error: '%U'",
                                   format_unformat_error, line_input);
        goto done;
      }
  }

  if (local_set == 0)
    {
      error = clib_error_return (0, "tunnel local address not specified");
      goto done;
    }

  if (remote_set == 0)
    {
      error = clib_error_return (0, "tunnel remote address not specified");
      goto done;
    }

  if (ipv4_set && ipv6_set)
    {
      error = clib_error_return (0, "both IPv4 and IPv6 addresses specified");
      goto done;
    }

  if ((ipv4_set && memcmp(&local.ip4, &remote.ip4, sizeof(local.ip4)) == 0) ||
      (ipv6_set && memcmp(&local.ip6, &remote.ip6, sizeof(local.ip6)) == 0))
    {
      error = clib_error_return (0, "src and dst addresses are identical");
      goto done;
    }

  if (vni_set == 0)
    {
      error = clib_error_return (0, "vni not specified");
      goto done;
    }

  memset (a, 0, sizeof (*a));

  a->is_add = is_add;
  a->is_ip6 = ipv6_set;

#define _(x) a->x = x;
  foreach_gpe_copy_field;
  if (ipv4_set) foreach_copy_ipv4
  else          foreach_copy_ipv6
#undef _

  rv = vnet_vxlan_gpe_add_del_tunnel (a, &sw_if_index);

  switch(rv)
    {
    case 0:
      vlib_cli_output(vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main(), sw_if_index);
      break;
    case VNET_API_ERROR_INVALID_DECAP_NEXT:
      error = clib_error_return (0, "invalid decap-next...");
      goto done;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "tunnel already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "tunnel does not exist...");
      goto done;

    default:
      error = clib_error_return
        (0, "vnet_vxlan_gpe_add_del_tunnel returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (create_vxlan_gpe_tunnel_command, static) = {
  .path = "create vxlan-gpe tunnel",
  .short_help =
  "create vxlan-gpe tunnel local <local-addr> remote <remote-addr>"
  " vni <nn> [next-ip4][next-ip6][next-ethernet][next-nsh]"
  " [encap-vrf-id <nn>] [decap-vrf-id <nn>]"
  " [del]\n",
  .function = vxlan_gpe_add_del_tunnel_command_fn,
};

/**
 * @brief CLI function for showing VXLAN GPE tunnels
 *
 * @param *vm
 * @param *input
 * @param *cmd
 *
 * @return error
 *
 */
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

/**
 * @brief Feature init function for VXLAN GPE
 *
 * @param *vm
 *
 * @return error
 *
 */
clib_error_t *vxlan_gpe_init (vlib_main_t *vm)
{
  vxlan_gpe_main_t *gm = &vxlan_gpe_main;

  gm->vnet_main = vnet_get_main();
  gm->vlib_main = vm;

  gm->vxlan4_gpe_tunnel_by_key
    = hash_create_mem (0, sizeof(vxlan4_gpe_tunnel_key_t), sizeof (uword));

  gm->vxlan6_gpe_tunnel_by_key
    = hash_create_mem (0, sizeof(vxlan6_gpe_tunnel_key_t), sizeof (uword));


  udp_register_dst_port (vm, UDP_DST_PORT_vxlan_gpe,
                         vxlan4_gpe_input_node.index, 1 /* is_ip4 */);
  udp_register_dst_port (vm, UDP_DST_PORT_vxlan6_gpe,
                         vxlan6_gpe_input_node.index, 0 /* is_ip4 */);

  /* Register the list of standard decap protocols supported */
  vxlan_gpe_register_decap_protocol (VXLAN_GPE_PROTOCOL_IP4,
                                     VXLAN_GPE_INPUT_NEXT_IP4_INPUT);
  vxlan_gpe_register_decap_protocol (VXLAN_GPE_PROTOCOL_IP6,
                                     VXLAN_GPE_INPUT_NEXT_IP6_INPUT);
  vxlan_gpe_register_decap_protocol (VXLAN_GPE_PROTOCOL_ETHERNET,
                                     VXLAN_GPE_INPUT_NEXT_ETHERNET_INPUT);
  return 0;
}

VLIB_INIT_FUNCTION(vxlan_gpe_init);

