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

int
gre_register_interface (vnet_main_t * vnm,
                        u32 dev_class_index,
                        ip4_address_t *tunnel_src,
                        ip4_address_t *tunnel_dst,
                        u32 outer_fib_id,
                        u32 * gi_index_return)
{
  gre_main_t * gm = &gre_main;
  ip4_main_t * im = &ip4_main;
  gre_tunnel_t * t;
  vnet_hw_interface_t * hi;
  u32 hw_if_index;
  u32 slot;
  u32 outer_fib_index;
  uword * p;

  u64 key = (u64)tunnel_src->as_u32 << 32 | (u64)tunnel_dst->as_u32;

  /* check if same src/dst pair exists */
  if (hash_get (gm->tunnel_by_key, key))
    return VNET_API_ERROR_INVALID_VALUE;

  p = hash_get (im->fib_index_by_table_id, outer_fib_id);
  if (! p)
    return VNET_API_ERROR_NO_SUCH_FIB;

  outer_fib_index = p[0];

  pool_get (gm->tunnels, t);
  memset (t, 0, sizeof (*t));

  hw_if_index = vnet_register_interface
    (vnm, gre_device_class.index, t - gm->tunnels,
     gre_hw_interface_class.index,
     t - gm->tunnels);

  *gi_index_return = t - gm->tunnels;

  t->hw_if_index = hw_if_index;
  t->outer_fib_index = outer_fib_index;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  hi->min_packet_bytes = 64 + sizeof (gre_header_t) + sizeof (ip4_header_t);
  hi->per_packet_overhead_bytes =
    /* preamble */ 8 + /* inter frame gap */ 12;

  /* Standard default gre MTU. */
  hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] = 9000;

  clib_memcpy (&t->tunnel_src, tunnel_src, sizeof (t->tunnel_src));
  clib_memcpy (&t->tunnel_dst, tunnel_dst, sizeof (t->tunnel_dst));

  hash_set (gm->tunnel_by_key, key, t - gm->tunnels);

  slot = vlib_node_add_named_next_with_slot
    (vnm->vlib_main, hi->tx_node_index, "ip4-lookup", GRE_OUTPUT_NEXT_LOOKUP);

  ASSERT (slot == GRE_OUTPUT_NEXT_LOOKUP);

  return 0;
}


static clib_error_t *
create_gre_tunnel_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  vnet_main_t * vnm = vnet_get_main();
  ip4_address_t src, dst;
  u32 outer_fib_id = 0;
  int rv;
  u32 gi_index;
  u32 num_m_args = 0;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "src %U", unformat_ip4_address, &src))
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

  rv = gre_register_interface (vnm, gre_hw_interface_class.index,
                                      &src, &dst, outer_fib_id, &gi_index);

 switch(rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "GRE tunnel already exists...");
    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "outer fib ID %d doesn't exist\n",
                                outer_fib_id);
    default:
      return clib_error_return (0, "gre_register_interface returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_gre_tunnel_command, static) = {
  .path = "create gre tunnel",
  .short_help = "create gre tunnel src <addr> dst <addr> [outer-fib-id <fib>]",
  .function = create_gre_tunnel_command_fn,
};

/* force inclusion from application's main.c */
clib_error_t *gre_interface_init (vlib_main_t *vm)
{
  return 0;
}
VLIB_INIT_FUNCTION(gre_interface_init);
