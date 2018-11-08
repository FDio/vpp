/*
 * gre_interface.c: gre interfaces
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 * @file
 * @brief L2-GRE over IPSec tunnel interface.
 *
 * Creates ipsec-gre tunnel interface.
 * Provides a command line interface so humans can interact with VPP.
 */

#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ipsec-gre/ipsec_gre.h>
#include <vnet/ip/format.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/l2/l2_input.h>

#include <vnet/ipsec/esp.h>

u8 *
format_ipsec_gre_tunnel (u8 * s, va_list * args)
{
  ipsec_gre_tunnel_t *t = va_arg (*args, ipsec_gre_tunnel_t *);
  ipsec_gre_main_t *gm = &ipsec_gre_main;

  s = format (s,
	      "[%d] %U (src) %U (dst) local-sa %d remote-sa %d",
	      t - gm->tunnels,
	      format_ip4_address, &t->tunnel_src,
	      format_ip4_address, &t->tunnel_dst,
	      t->local_sa_id, t->remote_sa_id);
  return s;
}

static clib_error_t *
show_ipsec_gre_tunnel_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  ipsec_gre_main_t *igm = &ipsec_gre_main;
  ipsec_gre_tunnel_t *t;

  if (pool_elts (igm->tunnels) == 0)
    vlib_cli_output (vm, "No IPSec GRE tunnels configured...");

  /* *INDENT-OFF* */
  pool_foreach (t, igm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_ipsec_gre_tunnel, t);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ipsec_gre_tunnel_command, static) = {
    .path = "show ipsec gre tunnel",
    .function = show_ipsec_gre_tunnel_command_fn,
};
/* *INDENT-ON* */

/* force inclusion from application's main.c */
clib_error_t *
ipsec_gre_interface_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ipsec_gre_interface_init);

/**
 * @brief Add or delete ipsec-gre tunnel interface.
 *
 * @param *a vnet_ipsec_gre_add_del_tunnel_args_t - tunnel interface parameters
 * @param *sw_if_indexp u32 - software interface index
 * @return int - 0 if success otherwise <code>VNET_API_ERROR_</code>
 */
int
vnet_ipsec_gre_add_del_tunnel (vnet_ipsec_gre_add_del_tunnel_args_t * a,
			       u32 * sw_if_indexp)
{
  ipsec_gre_main_t *igm = &ipsec_gre_main;
  vnet_main_t *vnm = igm->vnet_main;
  ip4_main_t *im = &ip4_main;
  ipsec_gre_tunnel_t *t;
  vnet_hw_interface_t *hi;
  u32 hw_if_index, sw_if_index;
  u32 slot;
  uword *p;
  u64 key;
  ipsec_add_del_ipsec_gre_tunnel_args_t args;

  memset (&args, 0, sizeof (args));
  args.is_add = a->is_add;
  args.local_sa_id = a->lsa;
  args.remote_sa_id = a->rsa;
  args.local_ip.as_u32 = a->src.as_u32;
  args.remote_ip.as_u32 = a->dst.as_u32;

  key = (u64) a->src.as_u32 << 32 | (u64) a->dst.as_u32;
  p = hash_get (igm->tunnel_by_key, key);

  if (a->is_add)
    {
      /* check if same src/dst pair exists */
      if (p)
	return VNET_API_ERROR_INVALID_VALUE;

      pool_get_aligned (igm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      if (vec_len (igm->free_ipsec_gre_tunnel_hw_if_indices) > 0)
	{
	  vnet_interface_main_t *im = &vnm->interface_main;

	  hw_if_index = igm->free_ipsec_gre_tunnel_hw_if_indices
	    [vec_len (igm->free_ipsec_gre_tunnel_hw_if_indices) - 1];
	  _vec_len (igm->free_ipsec_gre_tunnel_hw_if_indices) -= 1;

	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  hi->dev_instance = t - igm->tunnels;
	  hi->hw_instance = hi->dev_instance;

	  /* clear old stats of freed tunnel before reuse */
	  sw_if_index = hi->sw_if_index;
	  vnet_interface_counter_lock (im);
	  vlib_zero_combined_counter
	    (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX],
	     sw_if_index);
	  vlib_zero_combined_counter
	    (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_RX],
	     sw_if_index);
	  vlib_zero_simple_counter
	    (&im->sw_if_counters[VNET_INTERFACE_COUNTER_DROP], sw_if_index);
	  vnet_interface_counter_unlock (im);
	}
      else
	{
	  hw_if_index = vnet_register_interface
	    (vnm, ipsec_gre_device_class.index, t - igm->tunnels,
	     ipsec_gre_hw_interface_class.index, t - igm->tunnels);
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  sw_if_index = hi->sw_if_index;
	}

      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index;
      t->local_sa_id = a->lsa;
      t->remote_sa_id = a->rsa;
      t->local_sa = ipsec_get_sa_index_by_sa_id (a->lsa);
      t->remote_sa = ipsec_get_sa_index_by_sa_id (a->rsa);

      ip4_sw_interface_enable_disable (sw_if_index, 1);

      vec_validate_init_empty (igm->tunnel_index_by_sw_if_index,
			       sw_if_index, ~0);
      igm->tunnel_index_by_sw_if_index[sw_if_index] = t - igm->tunnels;

      vec_validate (im->fib_index_by_sw_if_index, sw_if_index);

      hi->min_packet_bytes = 64 + sizeof (gre_header_t) +
	sizeof (ip4_header_t) + sizeof (esp_header_t) + sizeof (esp_footer_t);

      /* Standard default gre MTU. */
      /* TODO: Should take tunnel overhead into consideration */
      vnet_sw_interface_set_mtu (vnm, sw_if_index, 9000);

      clib_memcpy (&t->tunnel_src, &a->src, sizeof (t->tunnel_src));
      clib_memcpy (&t->tunnel_dst, &a->dst, sizeof (t->tunnel_dst));

      hash_set (igm->tunnel_by_key, key, t - igm->tunnels);

      slot = vlib_node_add_named_next_with_slot
	(vnm->vlib_main, hi->tx_node_index, "esp4-encrypt",
	 IPSEC_GRE_OUTPUT_NEXT_ESP_ENCRYPT);

      ASSERT (slot == IPSEC_GRE_OUTPUT_NEXT_ESP_ENCRYPT);

    }
  else
    {				/* !is_add => delete */
      /* tunnel needs to exist */
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (igm->tunnels, p[0]);

      sw_if_index = t->sw_if_index;
      ip4_sw_interface_enable_disable (sw_if_index, 0);
      vnet_sw_interface_set_flags (vnm, sw_if_index, 0 /* down */ );
      /* make sure tunnel is removed from l2 bd or xconnect */
      set_int_l2_mode (igm->vlib_main, vnm, MODE_L3, sw_if_index, 0,
		       L2_BD_PORT_TYPE_NORMAL, 0, 0);
      vec_add1 (igm->free_ipsec_gre_tunnel_hw_if_indices, t->hw_if_index);
      igm->tunnel_index_by_sw_if_index[sw_if_index] = ~0;

      hash_unset (igm->tunnel_by_key, key);
      pool_put (igm->tunnels, t);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return ipsec_add_del_ipsec_gre_tunnel (vnm, &args);
}

static clib_error_t *
create_ipsec_gre_tunnel_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 num_m_args = 0;
  ip4_address_t src, dst;
  u32 lsa = 0, rsa = 0;
  vnet_ipsec_gre_add_del_tunnel_args_t _a, *a = &_a;
  int rv;
  u32 sw_if_index;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "src %U", unformat_ip4_address, &src))
	num_m_args++;
      else if (unformat (line_input, "dst %U", unformat_ip4_address, &dst))
	num_m_args++;
      else if (unformat (line_input, "local-sa %d", &lsa))
	num_m_args++;
      else if (unformat (line_input, "remote-sa %d", &rsa))
	num_m_args++;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (num_m_args < 4)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }

  if (memcmp (&src, &dst, sizeof (src)) == 0)
    {
      error = clib_error_return (0, "src and dst are identical");
      goto done;
    }

  memset (a, 0, sizeof (*a));
  a->is_add = is_add;
  a->lsa = lsa;
  a->rsa = rsa;
  clib_memcpy (&a->src, &src, sizeof (src));
  clib_memcpy (&a->dst, &dst, sizeof (dst));

  rv = vnet_ipsec_gre_add_del_tunnel (a, &sw_if_index);

  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "GRE tunnel already exists...");
      goto done;
    default:
      error = clib_error_return (0,
				 "vnet_ipsec_gre_add_del_tunnel returned %d",
				 rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_ipsec_gre_tunnel_command, static) = {
  .path = "create ipsec gre tunnel",
  .short_help = "create ipsec gre tunnel src <addr> dst <addr> "
                "local-sa <id> remote-sa <id> [del]",
  .function = create_ipsec_gre_tunnel_command_fn,
};
/* *INDENT-ON* */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
