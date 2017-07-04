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
#include <vnet/dpo/dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ppp/packet.h>
#include <pppoe/pppoe.h>


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
  .name = "PPPPOE",
  .format_device_name = format_pppoe_name,
  .format_tx_trace = format_pppoe_encap_trace,
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

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (pppoe_hw_class) =
{
  .name = "PPPPOE",
  .format_header = format_pppoe_header_with_length,
  .build_rewrite = default_build_rewrite,
};
/* *INDENT-ON* */

static void
pppoe_session_restack_dpo (pppoe_session_t * t)
{
  dpo_id_t dpo = DPO_INVALID;
  u32 encap_index = pppoe_encap_node.index;
  fib_forward_chain_type_t forw_type = ip46_address_is_ip4 (&t->client_ip) ?
    FIB_FORW_CHAIN_TYPE_UNICAST_IP4 : FIB_FORW_CHAIN_TYPE_UNICAST_IP6;

  fib_entry_contribute_forwarding (t->fib_entry_index, forw_type, &dpo);
  dpo_stack_from_node (encap_index, &t->next_dpo, &dpo);
  dpo_reset (&dpo);
}

static pppoe_session_t *
pppoe_session_from_fib_node (fib_node_t * node)
{
  return ((pppoe_session_t *) (((char *) node) -
			     STRUCT_OFFSET_OF (pppoe_session_t, node)));
}

/**
 * Function definition to backwalk a FIB node -
 * Here we will restack the new dpo of PPPPOE DIP to encap node.
 */
static fib_node_back_walk_rc_t
pppoe_session_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  pppoe_session_restack_dpo (pppoe_session_from_fib_node (node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
pppoe_session_fib_node_get (fib_node_index_t index)
{
  pppoe_session_t *t;
  pppoe_main_t *pem = &pppoe_main;

  t = pool_elt_at_index (pem->sessions, index);

  return (&t->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
pppoe_session_last_lock_gone (fib_node_t * node)
{
  /*
   * The PPPPOE session is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

/*
 * Virtual function table registered by PPPPOE sessions
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t pppoe_vft = {
  .fnv_get = pppoe_session_fib_node_get,
  .fnv_last_lock = pppoe_session_last_lock_gone,
  .fnv_back_walk = pppoe_session_back_walk,
};


#define foreach_copy_field                      \
_(session_id)                                   \
_(encap_if_index)                               \
_(decap_fib_index)                              \
_(client_ip)

static void
eth_pppoe_rewrite (pppoe_session_t * t, bool is_ip6)
{
  u8 *rw = 0;
  int len = sizeof(pppoe_header_t) + sizeof(ethernet_header_t);

  vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

  ethernet_header_t * eth_hdr = (ethernet_header_t *)rw;
  clib_memcpy (eth_hdr->dst_address, t->client_mac, 6);
  clib_memcpy (eth_hdr->src_address, t->local_mac, 6);
  eth_hdr->type = clib_host_to_net_u16(ETHERNET_TYPE_PPPOE_SESSION);

  pppoe_header_t *pppoe = (pppoe_header_t *)(eth_hdr + 1);
  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = 0;
  pppoe->session_id = clib_host_to_net_u16(t->session_id);
  pppoe->length = 0; /* To be filled in at run-time */

  if (!is_ip6)
    {
      pppoe->ppp_proto = clib_host_to_net_u16(PPP_PROTOCOL_ip4);
    }
  else
    {
      pppoe->ppp_proto = clib_host_to_net_u16(PPP_PROTOCOL_ip6);
    }

  t->rewrite = rw;
  _vec_len (t->rewrite) = len;

  return;
}

static bool
pppoe_decap_next_is_valid (pppoe_main_t * pem, u32 is_ip6, u32 decap_fib_index)
{
  vlib_main_t *vm = pem->vlib_main;
  u32 input_idx = (!is_ip6) ? ip4_input_node.index : ip6_input_node.index;
  vlib_node_runtime_t *r = vlib_node_get_runtime (vm, input_idx);

  return decap_fib_index < r->n_next_nodes;
}

static void
hash_set_key_copy (uword ** h, void *key, uword v)
{
  size_t ksz = hash_header (*h)->user;
  void *copy = clib_mem_alloc (ksz);
  clib_memcpy (copy, key, ksz);
  hash_set_mem (*h, copy, v);
}

static void
hash_unset_key_free (uword ** h, void *key)
{
  hash_pair_t *hp = hash_get_pair_mem (*h, key);
  ASSERT (hp);
  key = uword_to_pointer (hp->key, void *);
  hash_unset_mem (*h, key);
  clib_mem_free (key);
}

typedef CLIB_PACKED (union
		     {
		     struct
		     {
		     fib_node_index_t mfib_entry_index;
		     adj_index_t mcast_adj_index;
		     }; u64 as_u64;
		     }) mcast_shared_t;

static inline fib_protocol_t
fib_ip_proto (bool is_ip6)
{
  return (is_ip6) ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4;
}

int vnet_pppoe_add_del_session
  (vnet_pppoe_add_del_session_args_t * a, u32 * sw_if_indexp)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t = 0;
  vnet_main_t *vnm = pem->vnet_main;
  uword *p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  pppoe4_session_key_t key4;
  pppoe6_session_key_t key6;
  u32 is_ip6 = a->is_ip6;

  if (!is_ip6)
    {
      key4.client_ip = a->client_ip.ip4.as_u32;
      p = hash_get (pem->pppoe4_session_by_key, key4.client_ip);
    }
  else
    {
      key6.client_ip = a->client_ip.ip6;
      p = hash_get_mem (pem->pppoe6_session_by_key, &key6);
    }

  if (a->is_add)
    {
      /* adding a session: session must not already exist */
      if (p)
	return VNET_API_ERROR_TUNNEL_EXIST;

      /*if not set explicitly, default to ip4 */
      if (!pppoe_decap_next_is_valid (pem, is_ip6, a->decap_fib_index))
	return VNET_API_ERROR_INVALID_DECAP_NEXT;

      pool_get_aligned (pem->sessions, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _

      clib_memcpy (t->local_mac, a->local_mac, 6);
      clib_memcpy (t->client_mac, a->client_mac, 6);

      eth_pppoe_rewrite (t, is_ip6);

      /* copy the key */
      if (is_ip6)
	hash_set_key_copy (&pem->pppoe6_session_by_key, &key6,
			   t - pem->sessions);
      else
	hash_set (pem->pppoe4_session_by_key, key4.client_ip, t - pem->sessions);

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

      fib_node_init (&t->node, pem->fib_node_type);
      fib_prefix_t tun_dst_pfx;
      u32 encap_index = pppoe_encap_node.index;
      vnet_flood_class_t flood_class = VNET_FLOOD_CLASS_TUNNEL_NORMAL;

      fib_prefix_from_ip46_addr (&t->client_ip, &tun_dst_pfx);
      if (!ip46_address_is_multicast (&t->client_ip))
	{
	  /* Unicast session -
	   * source the FIB entry for the session's destination
	   * and become a child thereof. The session will then get poked
	   * when the forwarding for the entry updates, and the session can
	   * re-stack accordingly
	   */
	  t->fib_entry_index = fib_table_entry_special_add
	    (a->decap_fib_index, &tun_dst_pfx, FIB_SOURCE_RR,
	     FIB_ENTRY_FLAG_NONE);
	  t->sibling_index = fib_entry_child_add
	    (t->fib_entry_index, pem->fib_node_type, t - pem->sessions);
	  pppoe_session_restack_dpo (t);
	}

      /* Set pppoe session output node */
      hi->output_node_index = encap_index;

      vnet_get_sw_interface (vnet_get_main (), sw_if_index)->flood_class =
	flood_class;
    }
  else
    {
      /* deleting a session: session must exist */
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (pem->sessions, p[0]);
      sw_if_index = t->sw_if_index;

      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */ );
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, t->sw_if_index);
      si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

      vec_add1 (pem->free_pppoe_session_hw_if_indices, t->hw_if_index);

      pem->session_index_by_sw_if_index[t->sw_if_index] = ~0;

      if (!is_ip6)
	hash_unset (pem->pppoe4_session_by_key, key4.client_ip);
      else
	hash_unset_key_free (&pem->pppoe6_session_by_key, &key6);

      if (!ip46_address_is_multicast (&t->client_ip))
	{
	  fib_entry_child_remove (t->fib_entry_index, t->sibling_index);
	  fib_table_entry_delete_index (t->fib_entry_index, FIB_SOURCE_RR);
	}

      fib_node_deinit (&t->node);
      vec_free (t->rewrite);
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
  u8 local_mac[6] = { 0 };
  u8 client_mac[6] = { 0 };
  u8 client_mac_set = 0;
  int rv;
  u32 tmp;
  vnet_pppoe_add_del_session_args_t _a, *a = &_a;
  u32 session_sw_if_index;
  clib_error_t *error = NULL;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  memset (&client_ip, 0, sizeof client_ip);

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
      else if (unformat (line_input, "encap-if-index %d", &encap_if_index))
	;
      else if (unformat (line_input, "decap-vrf-id %d", &tmp))
        {
          if (ipv6_set)
            decap_fib_index = fib_table_find (FIB_PROTOCOL_IP6, tmp);
          else
            decap_fib_index = fib_table_find (FIB_PROTOCOL_IP4, tmp);

          if (decap_fib_index == ~0)
            {
              error = clib_error_return (0, "nonexistent decap fib id %d", tmp);
              goto done;
            }
        }
      else if (unformat (line_input, "local-mac %U", unformat_ethernet_address, local_mac))
	;
      else if (unformat (line_input, "client-mac %U", unformat_ethernet_address, client_mac))
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
      error = clib_error_return (0, "session client ip address not specified");
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

  memset (a, 0, sizeof (*a));

  a->is_add = is_add;
  a->is_ip6 = ipv6_set;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _

  memcpy (a->local_mac, local_mac, 6);
  memcpy (a->client_mac, client_mac, 6);

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
 * Add or delete a PPPPOE Session.
 *
 * @cliexpar
 * Example of how to create a PPPPOE Session:
 * @cliexcmd{create pppoe session client-ip 10.0.3.1 session-id 13 encap-if-index 7
 *             local-mac a0:b0:c0:d0:e0:f0 client-mac 00:01:02:03:04:05 }
 * Example of how to delete a PPPPOE Session:
 * @cliexcmd{create pppoe session client-ip 10.0.3.1 session-id 13 encap-if-index 7
 *             local-mac a0:b0:c0:d0:e0:f0 client-mac 00:01:02:03:04:05 del }
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_pppoe_session_command, static) = {
  .path = "create pppoe session",
  .short_help =
  "create pppoe session client-ip <client-ip> session-id <nn>"
  " [encap-if-index <nn>] [decap-vrf-id <nn>]] "
  " local-mac <local-mac> client-mac <client-mac> [del]",
  .function = pppoe_add_del_session_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_pppoe_session_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t;

  if (pool_elts (pem->sessions) == 0)
    vlib_cli_output (vm, "No pppoe sessions configured...");

  pool_foreach (t, pem->sessions, (
				   {
				   vlib_cli_output (vm, "%U",
						    format_pppoe_session, t);
				   }
		));

  return 0;
}

/*?
 * Display all the PPPPOE Session entries.
 *
 * @cliexpar
 * Example of how to display the PPPPOE Session entries:
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

clib_error_t *
pppoe_init (vlib_main_t * vm)
{
  pppoe_main_t *pem = &pppoe_main;

  pem->vnet_main = vnet_get_main ();
  pem->vlib_main = vm;

  /* initialize the ip6 hash */
  pem->pppoe6_session_by_key = hash_create_mem (0,
					        sizeof (pppoe6_session_key_t),
					        sizeof (uword));

  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_SESSION, pppoe_input_node.index);

  pem->fib_node_type = fib_node_register_new_type (&pppoe_vft);

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
