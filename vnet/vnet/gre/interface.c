/*
 * gre_interface.c: gre interfaces
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
#include <vnet/pg/pg.h>
#include <vnet/gre/gre.h>
#include <vnet/ip/format.h>

u8 * format_gre_tunnel (u8 * s, va_list * args)
{
  gre_tunnel_t * t = va_arg (*args, gre_tunnel_t *);
  gre_main_t * gm = &gre_main;

  s = format (s,
              "[%d] %U (src) %U (dst) outer_fib_index %d",
              t - gm->tunnels,
              format_ip4_address, &t->tunnel_src,
              format_ip4_address, &t->tunnel_dst,
              t->outer_fib_index);
  return s;
}

int vnet_gre_add_del_tunnel
  (vnet_gre_add_del_tunnel_args_t *a, u32 * sw_if_indexp)
{
  gre_main_t * gm = &gre_main;
  vnet_main_t * vnm = gm->vnet_main;
  ip4_main_t * im = &ip4_main;
  gre_tunnel_t * t;
  vnet_hw_interface_t * hi;
  u32 hw_if_index, sw_if_index;
  u32 slot;
  u32 outer_fib_index;
  uword * p;
  u64 key;

  key = (u64)a->src.as_u32 << 32 | (u64)a->dst.as_u32;
  p = hash_get (gm->tunnel_by_key, key);

  if (a->is_add) {
    /* check if same src/dst pair exists */
    if (p)
      return VNET_API_ERROR_INVALID_VALUE;

    p = hash_get (im->fib_index_by_table_id, a->outer_fib_id);
    if (! p)
      return VNET_API_ERROR_NO_SUCH_FIB;

    outer_fib_index = p[0];

    pool_get_aligned (gm->tunnels, t, CLIB_CACHE_LINE_BYTES);
    memset (t, 0, sizeof (*t));

    if (vec_len (gm->free_gre_tunnel_hw_if_indices) > 0) {
        vnet_interface_main_t * im = &vnm->interface_main;

        hw_if_index = gm->free_gre_tunnel_hw_if_indices
          [vec_len (gm->free_gre_tunnel_hw_if_indices)-1];
          _vec_len (gm->free_gre_tunnel_hw_if_indices) -= 1;

        hi = vnet_get_hw_interface (vnm, hw_if_index);
        hi->dev_instance = t - gm->tunnels;
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
    } else {
        hw_if_index = vnet_register_interface
          (vnm, gre_device_class.index, t - gm->tunnels,
           gre_hw_interface_class.index,
           t - gm->tunnels);
        hi = vnet_get_hw_interface (vnm, hw_if_index);
        sw_if_index = hi->sw_if_index;
    }

    t->hw_if_index = hw_if_index;
    t->outer_fib_index = outer_fib_index;
    t->sw_if_index = sw_if_index;

    vec_validate_init_empty (gm->tunnel_index_by_sw_if_index, sw_if_index, ~0);
    gm->tunnel_index_by_sw_if_index[sw_if_index] = t - gm->tunnels;

    vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
    im->fib_index_by_sw_if_index[sw_if_index] = t->outer_fib_index;

    hi->min_packet_bytes = 64 + sizeof (gre_header_t) + sizeof (ip4_header_t);
    hi->per_packet_overhead_bytes =
      /* preamble */ 8 + /* inter frame gap */ 12;

    /* Standard default gre MTU. */
    hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] = 9000;

    clib_memcpy (&t->tunnel_src, &a->src, sizeof (t->tunnel_src));
    clib_memcpy (&t->tunnel_dst, &a->dst, sizeof (t->tunnel_dst));

    hash_set (gm->tunnel_by_key, key, t - gm->tunnels);

    slot = vlib_node_add_named_next_with_slot
      (vnm->vlib_main, hi->tx_node_index, "ip4-lookup", GRE_OUTPUT_NEXT_LOOKUP);

    ASSERT (slot == GRE_OUTPUT_NEXT_LOOKUP);

  } else { /* !is_add => delete */
    /* tunnel needs to exist */
    if (! p)
      return VNET_API_ERROR_NO_SUCH_ENTRY;

    t = pool_elt_at_index (gm->tunnels, p[0]);

    sw_if_index = t->sw_if_index;
    vnet_sw_interface_set_flags (vnm, sw_if_index, 0 /* down */);
    /* make sure tunnel is removed from l2 bd or xconnect */
    set_int_l2_mode(gm->vlib_main, vnm, MODE_L3, sw_if_index, 0, 0, 0, 0);
    vec_add1 (gm->free_gre_tunnel_hw_if_indices, t->hw_if_index);
    gm->tunnel_index_by_sw_if_index[sw_if_index] = ~0;

    hash_unset (gm->tunnel_by_key, key);
    pool_put (gm->tunnels, t);
  }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}


static clib_error_t *
create_gre_tunnel_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  vnet_gre_add_del_tunnel_args_t _a, * a = &_a;
  ip4_address_t src, dst;
  u32 outer_fib_id = 0;
  int rv;
  u32 num_m_args = 0;
  u8 is_add = 1;
  u32 sw_if_index;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "src %U", unformat_ip4_address, &src))
      num_m_args++;
    else if (unformat (line_input, "dst %U", unformat_ip4_address, &dst))
      num_m_args++;
    else if (unformat (line_input, "outer-fib-id %d", &outer_fib_id))
      ;
    else
      return clib_error_return (0, "unknown input `%U'",
                                format_unformat_error, input);
  }
  unformat_free (line_input);

  if (num_m_args < 2)
      return clib_error_return (0, "mandatory argument(s) missing");

  if (memcmp (&src, &dst, sizeof(src)) == 0)
      return clib_error_return (0, "src and dst are identical");

  memset (a, 0, sizeof (*a));
  a->is_add = is_add;
  a->outer_fib_id = outer_fib_id;
  clib_memcpy(&a->src, &src, sizeof(src));
  clib_memcpy(&a->dst, &dst, sizeof(dst));

  rv = vnet_gre_add_del_tunnel (a, &sw_if_index);

  switch(rv)
    {
    case 0:
      vlib_cli_output(vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main(), sw_if_index);
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "GRE tunnel already exists...");
    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "outer fib ID %d doesn't exist\n",
                                outer_fib_id);
    default:
      return clib_error_return (0, "vnet_gre_add_del_tunnel returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_gre_tunnel_command, static) = {
  .path = "create gre tunnel",
  .short_help = "create gre tunnel src <addr> dst <addr> "
                "[outer-fib-id <fib>] [del]",
  .function = create_gre_tunnel_command_fn,
};

static clib_error_t *
show_gre_tunnel_command_fn (vlib_main_t * vm,
                            unformat_input_t * input,
                            vlib_cli_command_t * cmd)
{
  gre_main_t * gm = &gre_main;
  gre_tunnel_t * t;

  if (pool_elts (gm->tunnels) == 0)
    vlib_cli_output (vm, "No GRE tunnels configured...");

  pool_foreach (t, gm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_gre_tunnel, t);
  }));

  return 0;
}

VLIB_CLI_COMMAND (show_gre_tunnel_command, static) = {
    .path = "show gre tunnel",
    .function = show_gre_tunnel_command_fn,
};

/* force inclusion from application's main.c */
clib_error_t *gre_interface_init (vlib_main_t *vm)
{
  return 0;
}
VLIB_INIT_FUNCTION(gre_interface_init);
