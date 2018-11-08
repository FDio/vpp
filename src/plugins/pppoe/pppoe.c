/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ppp/packet.h>
#include <pppoe/pppoe.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_mcast.h>

#include <vppinfra/hash.h>
#include <vppinfra/bihash_template.c>

pppoe_main_t pppoe_main;

u8 *
format_pppoe_session (u8 * s, va_list * args)
{
  pppoe_session_t *t = va_arg (*args, pppoe_session_t *);
  pppoe_main_t *pem = &pppoe_main;

  s = format (s, "[%d] sw-if-index %d client-ip %U session-id %d ",
	      t - pem->sessions, t->sw_if_index,
	      format_ip46_address, &t->client_ip, IP46_TYPE_ANY,
	      t->session_id);

  s = format (s, "encap-if-index %d decap-fib-index %d\n",
	      t->encap_if_index, t->decap_fib_index);

  s = format (s, "    local-mac %U  client-mac %U",
	      format_ethernet_address, t->local_mac,
	      format_ethernet_address, t->client_mac);

  return s;
}

static u8 *
format_pppoe_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "pppoe_session%d", dev_instance);
}

static uword
dummy_interface_tx (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

static clib_error_t *
pppoe_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (pppoe_device_class,static) = {
  .name = "PPPoE",
  .format_device_name = format_pppoe_name,
  .tx_function = dummy_interface_tx,
  .admin_up_down_function = pppoe_interface_admin_up_down,
};
/* *INDENT-ON* */

static u8 *
format_pppoe_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

static u8 *
pppoe_build_rewrite (vnet_main_t * vnm,
		     u32 sw_if_index,
		     vnet_link_t link_type, const void *dst_address)
{
  int len = sizeof (pppoe_header_t) + sizeof (ethernet_header_t);
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t;
  u32 session_id;
  u8 *rw = 0;

  session_id = pem->session_index_by_sw_if_index[sw_if_index];
  t = pool_elt_at_index (pem->sessions, session_id);

  vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

  ethernet_header_t *eth_hdr = (ethernet_header_t *) rw;
  clib_memcpy (eth_hdr->dst_address, t->client_mac, 6);
  clib_memcpy (eth_hdr->src_address, t->local_mac, 6);
  eth_hdr->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_SESSION);

  pppoe_header_t *pppoe = (pppoe_header_t *) (eth_hdr + 1);
  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = 0;
  pppoe->session_id = clib_host_to_net_u16 (t->session_id);
  pppoe->length = 0;		/* To be filled in at run-time */

  switch (link_type)
    {
    case VNET_LINK_IP4:
      pppoe->ppp_proto = clib_host_to_net_u16 (PPP_PROTOCOL_ip4);
      break;
    case VNET_LINK_IP6:
      pppoe->ppp_proto = clib_host_to_net_u16 (PPP_PROTOCOL_ip6);
      break;
    default:
      break;
    }

  return rw;
}

/**
 * @brief Fixup the adj rewrite post encap. Insert the packet's length
 */
static void
pppoe_fixup (vlib_main_t * vm,
	     ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  const pppoe_session_t *t;
  pppoe_header_t *pppoe0;

  /* update the rewrite string */
  pppoe0 = vlib_buffer_get_current (b0) + sizeof (ethernet_header_t);

  pppoe0->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
					 - sizeof (pppoe_header_t)
					 + sizeof (pppoe0->ppp_proto)
					 - sizeof (ethernet_header_t));
  /* Swap to the the packet's output interface to the encap (not the
   * session) interface */
  t = data;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = t->encap_if_index;
}

static void
pppoe_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  pppoe_main_t *pem = &pppoe_main;
  dpo_id_t dpo = DPO_INVALID;
  ip_adjacency_t *adj;
  pppoe_session_t *t;
  u32 session_id;

  ASSERT (ADJ_INDEX_INVALID != ai);

  adj = adj_get (ai);
  session_id = pem->session_index_by_sw_if_index[sw_if_index];
  t = pool_elt_at_index (pem->sessions, session_id);

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_GLEAN:
    case IP_LOOKUP_NEXT_BCAST:
      adj_nbr_midchain_update_rewrite (ai, pppoe_fixup, t,
				       ADJ_FLAG_NONE,
				       pppoe_build_rewrite (vnm,
							    sw_if_index,
							    adj->ia_link,
							    NULL));
      break;
    case IP_LOOKUP_NEXT_MCAST:
      /*
       * Construct a partial rewrite from the known ethernet mcast dest MAC
       * There's no MAC fixup, so the last 2 parameters are 0
       */
      adj_mcast_midchain_update_rewrite (ai, pppoe_fixup, t,
					 ADJ_FLAG_NONE,
					 pppoe_build_rewrite (vnm,
							      sw_if_index,
							      adj->ia_link,
							      NULL), 0, 0);
      break;

    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_MIDCHAIN:
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
      ASSERT (0);
      break;
    }

  interface_tx_dpo_add_or_lock (vnet_link_to_dpo_proto (adj->ia_link),
				t->encap_if_index, &dpo);

  adj_nbr_midchain_stack (ai, &dpo);

  dpo_reset (&dpo);
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (pppoe_hw_class) =
{
  .name = "PPPoE",
  .format_header = format_pppoe_header_with_length,
  .build_rewrite = pppoe_build_rewrite,
  .update_adjacency = pppoe_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

#define foreach_copy_field                      \
_(session_id)                                   \
_(encap_if_index)                               \
_(decap_fib_index)                              \
_(client_ip)

static bool
pppoe_decap_next_is_valid (pppoe_main_t * pem, u32 is_ip6,
			   u32 decap_fib_index)
{
  vlib_main_t *vm = pem->vlib_main;
  u32 input_idx = (!is_ip6) ? ip4_input_node.index : ip6_input_node.index;
  vlib_node_runtime_t *r = vlib_node_get_runtime (vm, input_idx);

  return decap_fib_index < r->n_next_nodes;
}

int vnet_pppoe_add_del_session
  (vnet_pppoe_add_del_session_args_t * a, u32 * sw_if_indexp)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t = 0;
  vnet_main_t *vnm = pem->vnet_main;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  u32 is_ip6 = a->is_ip6;
  pppoe_entry_key_t cached_key;
  pppoe_entry_result_t cached_result;
  u32 bucket;
  pppoe_entry_key_t key;
  pppoe_entry_result_t result;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  fib_prefix_t pfx;

  cached_key.raw = ~0;
  cached_result.raw = ~0;	/* warning be gone */
  clib_memset (&pfx, 0, sizeof (pfx));

  if (!is_ip6)
    {
      pfx.fp_addr.ip4.as_u32 = a->client_ip.ip4.as_u32;
      pfx.fp_len = 32;
      pfx.fp_proto = FIB_PROTOCOL_IP4;
    }
  else
    {
      pfx.fp_addr.ip6.as_u64[0] = a->client_ip.ip6.as_u64[0];
      pfx.fp_addr.ip6.as_u64[1] = a->client_ip.ip6.as_u64[1];
      pfx.fp_len = 128;
      pfx.fp_proto = FIB_PROTOCOL_IP6;
    }

  /* Get encap_if_index and local mac address from link_table */
  pppoe_lookup_1 (&pem->link_table, &cached_key, &cached_result,
		  a->client_mac, 0, &key, &bucket, &result);
  a->encap_if_index = result.fields.sw_if_index;

  if (a->encap_if_index == ~0)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  si = vnet_get_sw_interface (vnm, a->encap_if_index);
  hi = vnet_get_hw_interface (vnm, si->hw_if_index);

  /* lookup session_table */
  pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result,
		  a->client_mac, clib_host_to_net_u16 (a->session_id),
		  &key, &bucket, &result);

  /* learn client session */
  pppoe_learn_process (&pem->session_table, a->encap_if_index,
		       &key, &cached_key, &bucket, &result);

  if (a->is_add)
    {
      /* adding a session: session must not already exist */
      if (result.fields.session_index != ~0)
	return VNET_API_ERROR_TUNNEL_EXIST;

      /*if not set explicitly, default to ip4 */
      if (!pppoe_decap_next_is_valid (pem, is_ip6, a->decap_fib_index))
	return VNET_API_ERROR_INVALID_DECAP_NEXT;

      pool_get_aligned (pem->sessions, t, CLIB_CACHE_LINE_BYTES);
      clib_memset (t, 0, sizeof (*t));

      clib_memcpy (t->local_mac, hi->hw_address, 6);

      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _

      clib_memcpy (t->client_mac, a->client_mac, 6);

      /* update pppoe fib with session_index */
      result.fields.session_index = t - pem->sessions;
      pppoe_update_1 (&pem->session_table,
		      a->client_mac, clib_host_to_net_u16 (a->session_id),
		      &key, &bucket, &result);

      vnet_hw_interface_t *hi;
      if (vec_len (pem->free_pppoe_session_hw_if_indices) > 0)
	{
	  vnet_interface_main_t *im = &vnm->interface_main;
	  hw_if_index = pem->free_pppoe_session_hw_if_indices
	    [vec_len (pem->free_pppoe_session_hw_if_indices) - 1];
	  _vec_len (pem->free_pppoe_session_hw_if_indices) -= 1;

	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  hi->dev_instance = t - pem->sessions;
	  hi->hw_instance = hi->dev_instance;

	  /* clear old stats of freed session before reuse */
	  sw_if_index = hi->sw_if_index;
	  vnet_interface_counter_lock (im);
	  vlib_zero_combined_counter
	    (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX],
	     sw_if_index);
	  vlib_zero_combined_counter (&im->combined_sw_if_counters
				      [VNET_INTERFACE_COUNTER_RX],
				      sw_if_index);
	  vlib_zero_simple_counter (&im->sw_if_counters
				    [VNET_INTERFACE_COUNTER_DROP],
				    sw_if_index);
	  vnet_interface_counter_unlock (im);
	}
      else
	{
	  hw_if_index = vnet_register_interface
	    (vnm, pppoe_device_class.index, t - pem->sessions,
	     pppoe_hw_class.index, t - pem->sessions);
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	}

      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index = hi->sw_if_index;

      vec_validate_init_empty (pem->session_index_by_sw_if_index, sw_if_index,
			       ~0);
      pem->session_index_by_sw_if_index[sw_if_index] = t - pem->sessions;

      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
      si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
      vnet_sw_interface_set_flags (vnm, sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);

      /* add reverse route for client ip */
      fib_table_entry_path_add (a->decap_fib_index, &pfx,
				FIB_SOURCE_PLUGIN_HI, FIB_ENTRY_FLAG_NONE,
				fib_proto_to_dpo (pfx.fp_proto),
				&pfx.fp_addr, sw_if_index, ~0,
				1, NULL, FIB_ROUTE_PATH_FLAG_NONE);

    }
  else
    {
      /* deleting a session: session must exist */
      if (result.fields.session_index == ~0)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (pem->sessions, result.fields.session_index);
      sw_if_index = t->sw_if_index;

      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */ );
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, t->sw_if_index);
      si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

      vec_add1 (pem->free_pppoe_session_hw_if_indices, t->hw_if_index);

      pem->session_index_by_sw_if_index[t->sw_if_index] = ~0;

      /* update pppoe fib with session_inde=~0x */
      result.fields.session_index = ~0;
      pppoe_update_1 (&pem->session_table,
		      a->client_mac, clib_host_to_net_u16 (a->session_id),
		      &key, &bucket, &result);


      /* delete reverse route for client ip */
      fib_table_entry_path_remove (a->decap_fib_index, &pfx,
				   FIB_SOURCE_PLUGIN_HI,
				   fib_proto_to_dpo (pfx.fp_proto),
				   &pfx.fp_addr,
				   sw_if_index, ~0, 1,
				   FIB_ROUTE_PATH_FLAG_NONE);

      pool_put (pem->sessions, t);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}

static clib_error_t *
pppoe_add_del_session_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u16 session_id = 0;
  ip46_address_t client_ip;
  u8 is_add = 1;
  u8 client_ip_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u32 encap_if_index = 0;
  u32 decap_fib_index = 0;
  u8 client_mac[6] = { 0 };
  u8 client_mac_set = 0;
  int rv;
  u32 tmp;
  vnet_pppoe_add_del_session_args_t _a, *a = &_a;
  u32 session_sw_if_index;
  clib_error_t *error = NULL;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&client_ip, 0, sizeof client_ip);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (line_input, "session-id %d", &session_id))
	;
      else if (unformat (line_input, "client-ip %U",
			 unformat_ip4_address, &client_ip.ip4))
	{
	  client_ip_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "client-ip %U",
			 unformat_ip6_address, &client_ip.ip6))
	{
	  client_ip_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "decap-vrf-id %d", &tmp))
	{
	  if (ipv6_set)
	    decap_fib_index = fib_table_find (FIB_PROTOCOL_IP6, tmp);
	  else
	    decap_fib_index = fib_table_find (FIB_PROTOCOL_IP4, tmp);

	  if (decap_fib_index == ~0)
	    {
	      error =
		clib_error_return (0, "nonexistent decap fib id %d", tmp);
	      goto done;
	    }
	}
      else
	if (unformat
	    (line_input, "client-mac %U", unformat_ethernet_address,
	     client_mac))
	client_mac_set = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (client_ip_set == 0)
    {
      error =
	clib_error_return (0, "session client ip address not specified");
      goto done;
    }

  if (ipv4_set && ipv6_set)
    {
      error = clib_error_return (0, "both IPv4 and IPv6 addresses specified");
      goto done;
    }

  if (client_mac_set == 0)
    {
      error = clib_error_return (0, "session client mac not specified");
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));

  a->is_add = is_add;
  a->is_ip6 = ipv6_set;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _

  clib_memcpy (a->client_mac, client_mac, 6);

  rv = vnet_pppoe_add_del_session (a, &session_sw_if_index);

  switch (rv)
    {
    case 0:
      if (is_add)
	vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
			 vnet_get_main (), session_sw_if_index);
      break;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "session already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "session does not exist...");
      goto done;

    default:
      error = clib_error_return
	(0, "vnet_pppoe_add_del_session returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Add or delete a PPPoE Session.
 *
 * @cliexpar
 * Example of how to create a PPPoE Session:
 * @cliexcmd{create pppoe session client-ip 10.0.3.1 session-id 13
 *             client-mac 00:01:02:03:04:05 }
 * Example of how to delete a PPPoE Session:
 * @cliexcmd{create pppoe session client-ip 10.0.3.1 session-id 13
 *             client-mac 00:01:02:03:04:05 del }
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_pppoe_session_command, static) = {
  .path = "create pppoe session",
  .short_help =
  "create pppoe session client-ip <client-ip> session-id <nn>"
  " client-mac <client-mac> [decap-vrf-id <nn>] [del]",
  .function = pppoe_add_del_session_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
static clib_error_t *
show_pppoe_session_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t;

  if (pool_elts (pem->sessions) == 0)
    vlib_cli_output (vm, "No pppoe sessions configured...");

  pool_foreach (t, pem->sessions,
		({
		    vlib_cli_output (vm, "%U",format_pppoe_session, t);
		}));

  return 0;
}
/* *INDENT-ON* */

/*?
 * Display all the PPPoE Session entries.
 *
 * @cliexpar
 * Example of how to display the PPPoE Session entries:
 * @cliexstart{show pppoe session}
 * [0] client-ip 10.0.3.1 session_id 13 encap-if-index 0 decap-vrf-id 13 sw_if_index 5
 *     local-mac a0:b0:c0:d0:e0:f0 client-mac 00:01:02:03:04:05
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_pppoe_session_command, static) = {
    .path = "show pppoe session",
    .short_help = "show pppoe session",
    .function = show_pppoe_session_command_fn,
};
/* *INDENT-ON* */

typedef struct pppoe_show_walk_ctx_t_
{
  vlib_main_t *vm;
  u8 first_entry;
  u32 total_entries;
} pppoe_show_walk_ctx_t;

static void
pppoe_show_walk_cb (BVT (clib_bihash_kv) * kvp, void *arg)
{
  pppoe_show_walk_ctx_t *ctx = arg;
  pppoe_entry_result_t result;
  pppoe_entry_key_t key;

  if (ctx->first_entry)
    {
      ctx->first_entry = 0;
      vlib_cli_output (ctx->vm,
		       "%=19s%=12s%=13s%=14s",
		       "Mac-Address", "session_id", "sw_if_index",
		       "session_index");
    }

  key.raw = kvp->key;
  result.raw = kvp->value;

  vlib_cli_output (ctx->vm,
		   "%=19U%=12d%=13d%=14d",
		   format_ethernet_address, key.fields.mac,
		   clib_net_to_host_u16 (key.fields.session_id),
		   result.fields.sw_if_index == ~0
		   ? -1 : result.fields.sw_if_index,
		   result.fields.session_index == ~0
		   ? -1 : result.fields.session_index);
  ctx->total_entries++;
}

/** Display the contents of the PPPoE Fib. */
static clib_error_t *
show_pppoe_fib_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_show_walk_ctx_t ctx = {
    .first_entry = 1,
    .vm = vm,
  };

  BV (clib_bihash_foreach_key_value_pair)
    (&pem->session_table, pppoe_show_walk_cb, &ctx);

  if (ctx.total_entries == 0)
    vlib_cli_output (vm, "no pppoe fib entries");
  else
    vlib_cli_output (vm, "%lld pppoe fib entries", ctx.total_entries);

  return 0;
}

/*?
 * This command dispays the MAC Address entries of the PPPoE FIB table.
 * Output can be filtered to just get the number of MAC Addresses or display
 * each MAC Address.
 *
 * @cliexpar
 * Example of how to display the number of MAC Address entries in the PPPoE
 * FIB table:
 * @cliexstart{show pppoe fib}
 *     Mac Address      session_id      Interface           sw_if_index  session_index
 *  52:54:00:53:18:33     1          GigabitEthernet0/8/0        2          0
 *  52:54:00:53:18:55     2          GigabitEthernet0/8/1        3          1
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_pppoe_fib_command, static) = {
    .path = "show pppoe fib",
    .short_help = "show pppoe fib",
    .function = show_pppoe_fib_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
pppoe_init (vlib_main_t * vm)
{
  pppoe_main_t *pem = &pppoe_main;

  pem->vnet_main = vnet_get_main ();
  pem->vlib_main = vm;

  /* Create the hash table  */
  BV (clib_bihash_init) (&pem->link_table, "pppoe link table",
			 PPPOE_NUM_BUCKETS, PPPOE_MEMORY_SIZE);

  BV (clib_bihash_init) (&pem->session_table, "pppoe session table",
			 PPPOE_NUM_BUCKETS, PPPOE_MEMORY_SIZE);

  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_SESSION,
				pppoe_input_node.index);

  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_DISCOVERY,
				pppoe_cp_dispatch_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (pppoe_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "PPPoE",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
