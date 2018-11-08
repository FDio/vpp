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
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/mpls/mpls.h>
#include <vnet/l2/l2_input.h>

static const char *gre_tunnel_type_names[] = GRE_TUNNEL_TYPE_NAMES;

static u8 *
format_gre_tunnel (u8 * s, va_list * args)
{
  gre_tunnel_t *t = va_arg (*args, gre_tunnel_t *);

  s = format (s, "[%d] instance %d src %U dst %U fib-idx %d sw-if-idx %d ",
	      t->dev_instance, t->user_instance,
	      format_ip46_address, &t->tunnel_src, IP46_TYPE_ANY,
	      format_ip46_address, &t->tunnel_dst.fp_addr, IP46_TYPE_ANY,
	      t->outer_fib_index, t->sw_if_index);

  s = format (s, "payload %s ", gre_tunnel_type_names[t->type]);

  if (t->type == GRE_TUNNEL_TYPE_ERSPAN)
    s = format (s, "session %d ", t->session_id);

  if (t->type != GRE_TUNNEL_TYPE_L3)
    s = format (s, "l2-adj-idx %d ", t->l2_adj_index);

  return s;
}

static gre_tunnel_t *
gre_tunnel_db_find (const vnet_gre_add_del_tunnel_args_t * a,
		    u32 outer_fib_index, gre_tunnel_key_t * key)
{
  gre_main_t *gm = &gre_main;
  uword *p;

  if (!a->is_ipv6)
    {
      gre_mk_key4 (a->src.ip4, a->dst.ip4, outer_fib_index,
		   a->tunnel_type, a->session_id, &key->gtk_v4);
      p = hash_get_mem (gm->tunnel_by_key4, &key->gtk_v4);
    }
  else
    {
      gre_mk_key6 (&a->src.ip6, &a->dst.ip6, outer_fib_index,
		   a->tunnel_type, a->session_id, &key->gtk_v6);
      p = hash_get_mem (gm->tunnel_by_key6, &key->gtk_v6);
    }

  if (NULL == p)
    return (NULL);

  return (pool_elt_at_index (gm->tunnels, p[0]));
}

static void
gre_tunnel_db_add (gre_tunnel_t * t, gre_tunnel_key_t * key)
{
  gre_main_t *gm = &gre_main;

  t->key = clib_mem_alloc (sizeof (*t->key));
  clib_memcpy (t->key, key, sizeof (*key));

  if (t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6)
    {
      hash_set_mem (gm->tunnel_by_key6, &t->key->gtk_v6, t->dev_instance);
    }
  else
    {
      hash_set_mem (gm->tunnel_by_key4, &t->key->gtk_v4, t->dev_instance);
    }
}

static void
gre_tunnel_db_remove (gre_tunnel_t * t)
{
  gre_main_t *gm = &gre_main;

  if (t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6)
    {
      hash_unset_mem (gm->tunnel_by_key6, &t->key->gtk_v6);
    }
  else
    {
      hash_unset_mem (gm->tunnel_by_key4, &t->key->gtk_v4);
    }

  clib_mem_free (t->key);
  t->key = NULL;
}

static gre_tunnel_t *
gre_tunnel_from_fib_node (fib_node_t * node)
{
  ASSERT (FIB_NODE_TYPE_GRE_TUNNEL == node->fn_type);
  return ((gre_tunnel_t *) (((char *) node) -
			    STRUCT_OFFSET_OF (gre_tunnel_t, node)));
}

/**
 * gre_tunnel_stack
 *
 * 'stack' (resolve the recursion for) the tunnel's midchain adjacency
 */
void
gre_tunnel_stack (adj_index_t ai)
{
  fib_forward_chain_type_t fib_fwd;
  gre_main_t *gm = &gre_main;
  dpo_id_t tmp = DPO_INVALID;
  ip_adjacency_t *adj;
  gre_tunnel_t *gt;
  u32 sw_if_index;

  adj = adj_get (ai);
  sw_if_index = adj->rewrite_header.sw_if_index;

  if ((vec_len (gm->tunnel_index_by_sw_if_index) <= sw_if_index) ||
      (~0 == gm->tunnel_index_by_sw_if_index[sw_if_index]))
    return;

  gt = pool_elt_at_index (gm->tunnels,
			  gm->tunnel_index_by_sw_if_index[sw_if_index]);

  if ((vnet_hw_interface_get_flags (vnet_get_main (), gt->hw_if_index) &
       VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
    {
      adj_nbr_midchain_unstack (ai);
      return;
    }

  fib_fwd = fib_forw_chain_type_from_fib_proto (gt->tunnel_dst.fp_proto);

  fib_entry_contribute_forwarding (gt->fib_entry_index, fib_fwd, &tmp);
  if (DPO_LOAD_BALANCE == tmp.dpoi_type)
    {
      /*
       * post GRE rewrite we will load-balance. However, the GRE encap
       * is always the same for this adjacency/tunnel and hence the IP/GRE
       * src,dst hash is always the same result too. So we do that hash now and
       * stack on the choice.
       * If the choice is an incomplete adj then we will need a poke when
       * it becomes complete. This happens since the adj update walk propagates
       * as far a recursive paths.
       */
      const dpo_id_t *choice;
      load_balance_t *lb;
      int hash;

      lb = load_balance_get (tmp.dpoi_index);

      if (fib_fwd == FIB_FORW_CHAIN_TYPE_UNICAST_IP4)
	hash = ip4_compute_flow_hash ((ip4_header_t *) adj_get_rewrite (ai),
				      lb->lb_hash_config);
      else
	hash = ip6_compute_flow_hash ((ip6_header_t *) adj_get_rewrite (ai),
				      lb->lb_hash_config);
      choice =
	load_balance_get_bucket_i (lb, hash & lb->lb_n_buckets_minus_1);
      dpo_copy (&tmp, choice);
    }

  adj_nbr_midchain_stack (ai, &tmp);
  dpo_reset (&tmp);
}

/**
 * @brief Call back when restacking all adjacencies on a GRE interface
 */
static adj_walk_rc_t
gre_adj_walk_cb (adj_index_t ai, void *ctx)
{
  gre_tunnel_stack (ai);

  return (ADJ_WALK_RC_CONTINUE);
}

static void
gre_tunnel_restack (gre_tunnel_t * gt)
{
  fib_protocol_t proto;

  /*
   * walk all the adjacencies on th GRE interface and restack them
   */
  FOR_EACH_FIB_IP_PROTOCOL (proto)
  {
    adj_nbr_walk (gt->sw_if_index, proto, gre_adj_walk_cb, NULL);
  }
}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
gre_tunnel_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  gre_tunnel_restack (gre_tunnel_from_fib_node (node));

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
gre_tunnel_fib_node_get (fib_node_index_t index)
{
  gre_tunnel_t *gt;
  gre_main_t *gm;

  gm = &gre_main;
  gt = pool_elt_at_index (gm->tunnels, index);

  return (&gt->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
gre_tunnel_last_lock_gone (fib_node_t * node)
{
  /*
   * The MPLS GRE tunnel is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

/*
 * Virtual function table registered by MPLS GRE tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t gre_vft = {
  .fnv_get = gre_tunnel_fib_node_get,
  .fnv_last_lock = gre_tunnel_last_lock_gone,
  .fnv_back_walk = gre_tunnel_back_walk,
};

static int
vnet_gre_tunnel_add (vnet_gre_add_del_tunnel_args_t * a,
		     u32 outer_fib_index, u32 * sw_if_indexp)
{
  gre_main_t *gm = &gre_main;
  vnet_main_t *vnm = gm->vnet_main;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  gre_tunnel_t *t;
  vnet_hw_interface_t *hi;
  u32 hw_if_index, sw_if_index;
  clib_error_t *error;
  u8 is_ipv6 = a->is_ipv6;
  gre_tunnel_key_t key;

  t = gre_tunnel_db_find (a, outer_fib_index, &key);
  if (NULL != t)
    return VNET_API_ERROR_IF_ALREADY_EXISTS;

  pool_get_aligned (gm->tunnels, t, CLIB_CACHE_LINE_BYTES);
  clib_memset (t, 0, sizeof (*t));

  /* Reconcile the real dev_instance and a possible requested instance */
  u32 t_idx = t - gm->tunnels;	/* tunnel index (or instance) */
  u32 u_idx = a->instance;	/* user specified instance */
  if (u_idx == ~0)
    u_idx = t_idx;
  if (hash_get (gm->instance_used, u_idx))
    {
      pool_put (gm->tunnels, t);
      return VNET_API_ERROR_INSTANCE_IN_USE;
    }
  hash_set (gm->instance_used, u_idx, 1);

  t->dev_instance = t_idx;	/* actual */
  t->user_instance = u_idx;	/* name */
  fib_node_init (&t->node, FIB_NODE_TYPE_GRE_TUNNEL);

  t->type = a->tunnel_type;
  if (t->type == GRE_TUNNEL_TYPE_ERSPAN)
    t->session_id = a->session_id;

  if (t->type == GRE_TUNNEL_TYPE_L3)
    hw_if_index = vnet_register_interface (vnm, gre_device_class.index, t_idx,
					   gre_hw_interface_class.index,
					   t_idx);
  else
    {
      /* Default MAC address (d00b:eed0:0000 + sw_if_index) */
      u8 address[6] =
	{ 0xd0, 0x0b, 0xee, 0xd0, (u8) (t_idx >> 8), (u8) t_idx };
      error =
	ethernet_register_interface (vnm, gre_device_class.index, t_idx,
				     address, &hw_if_index, 0);
      if (error)
	{
	  clib_error_report (error);
	  return VNET_API_ERROR_INVALID_REGISTRATION;
	}
    }

  /* Set GRE tunnel interface output node (not used for L3 payload) */
  vnet_set_interface_output_node (vnm, hw_if_index, gre_encap_node.index);

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  sw_if_index = hi->sw_if_index;

  t->hw_if_index = hw_if_index;
  t->outer_fib_index = outer_fib_index;
  t->sw_if_index = sw_if_index;
  t->l2_adj_index = ADJ_INDEX_INVALID;

  vec_validate_init_empty (gm->tunnel_index_by_sw_if_index, sw_if_index, ~0);
  gm->tunnel_index_by_sw_if_index[sw_if_index] = t_idx;

  if (!is_ipv6)
    {
      vec_validate (im4->fib_index_by_sw_if_index, sw_if_index);
      hi->min_packet_bytes =
	64 + sizeof (gre_header_t) + sizeof (ip4_header_t);
    }
  else
    {
      vec_validate (im6->fib_index_by_sw_if_index, sw_if_index);
      hi->min_packet_bytes =
	64 + sizeof (gre_header_t) + sizeof (ip6_header_t);
    }

  /* Standard default gre MTU. */
  vnet_sw_interface_set_mtu (vnm, sw_if_index, 9000);

  /*
   * source the FIB entry for the tunnel's destination
   * and become a child thereof. The tunnel will then get poked
   * when the forwarding for the entry updates, and the tunnel can
   * re-stack accordingly
   */

  clib_memcpy (&t->tunnel_src, &a->src, sizeof (t->tunnel_src));
  t->tunnel_dst.fp_len = !is_ipv6 ? 32 : 128;
  t->tunnel_dst.fp_proto = !is_ipv6 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  t->tunnel_dst.fp_addr = a->dst;

  gre_tunnel_db_add (t, &key);
  if (t->type == GRE_TUNNEL_TYPE_ERSPAN)
    {
      gre_sn_key_t skey;
      gre_sn_t *gre_sn;

      gre_mk_sn_key (t, &skey);
      gre_sn = (gre_sn_t *) hash_get_mem (gm->seq_num_by_key, &skey);
      if (gre_sn != NULL)
	{
	  gre_sn->ref_count++;
	  t->gre_sn = gre_sn;
	}
      else
	{
	  gre_sn = clib_mem_alloc (sizeof (gre_sn_t));
	  gre_sn->seq_num = 0;
	  gre_sn->ref_count = 1;
	  t->gre_sn = gre_sn;
	  hash_set_mem_alloc (&gm->seq_num_by_key, &skey, (uword) gre_sn);
	}
    }

  t->fib_entry_index = fib_table_entry_special_add
    (outer_fib_index, &t->tunnel_dst, FIB_SOURCE_RR, FIB_ENTRY_FLAG_NONE);
  t->sibling_index = fib_entry_child_add
    (t->fib_entry_index, FIB_NODE_TYPE_GRE_TUNNEL, t_idx);

  if (t->type != GRE_TUNNEL_TYPE_L3)
    {
      t->l2_adj_index = adj_nbr_add_or_lock
	(t->tunnel_dst.fp_proto, VNET_LINK_ETHERNET, &zero_addr, sw_if_index);
      gre_update_adj (vnm, t->sw_if_index, t->l2_adj_index);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}

static int
vnet_gre_tunnel_delete (vnet_gre_add_del_tunnel_args_t * a,
			u32 outer_fib_index, u32 * sw_if_indexp)
{
  gre_main_t *gm = &gre_main;
  vnet_main_t *vnm = gm->vnet_main;
  gre_tunnel_t *t;
  gre_tunnel_key_t key;
  u32 sw_if_index;

  t = gre_tunnel_db_find (a, outer_fib_index, &key);
  if (NULL == t)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  sw_if_index = t->sw_if_index;
  vnet_sw_interface_set_flags (vnm, sw_if_index, 0 /* down */ );

  /* make sure tunnel is removed from l2 bd or xconnect */
  set_int_l2_mode (gm->vlib_main, vnm, MODE_L3, sw_if_index, 0,
		   L2_BD_PORT_TYPE_NORMAL, 0, 0);
  gm->tunnel_index_by_sw_if_index[sw_if_index] = ~0;

  if (t->type == GRE_TUNNEL_TYPE_L3)
    vnet_delete_hw_interface (vnm, t->hw_if_index);
  else
    ethernet_delete_interface (vnm, t->hw_if_index);

  if (t->l2_adj_index != ADJ_INDEX_INVALID)
    adj_unlock (t->l2_adj_index);

  fib_entry_child_remove (t->fib_entry_index, t->sibling_index);
  fib_table_entry_delete_index (t->fib_entry_index, FIB_SOURCE_RR);

  ASSERT ((t->type != GRE_TUNNEL_TYPE_ERSPAN) || (t->gre_sn != NULL));
  if ((t->type == GRE_TUNNEL_TYPE_ERSPAN) && (t->gre_sn->ref_count-- == 1))
    {
      gre_sn_key_t skey;
      gre_mk_sn_key (t, &skey);
      hash_unset_mem_free (&gm->seq_num_by_key, &skey);
      clib_mem_free (t->gre_sn);
    }

  hash_unset (gm->instance_used, t->user_instance);
  gre_tunnel_db_remove (t);
  fib_node_deinit (&t->node);
  pool_put (gm->tunnels, t);

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}

int
vnet_gre_add_del_tunnel (vnet_gre_add_del_tunnel_args_t * a,
			 u32 * sw_if_indexp)
{
  u32 outer_fib_index;

  if (!a->is_ipv6)
    outer_fib_index = ip4_fib_index_from_table_id (a->outer_fib_id);
  else
    outer_fib_index = ip6_fib_index_from_table_id (a->outer_fib_id);

  if (~0 == outer_fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  if (a->session_id > GTK_SESSION_ID_MAX)
    return VNET_API_ERROR_INVALID_SESSION_ID;

  if (a->is_add)
    return (vnet_gre_tunnel_add (a, outer_fib_index, sw_if_indexp));
  else
    return (vnet_gre_tunnel_delete (a, outer_fib_index, sw_if_indexp));
}

clib_error_t *
gre_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  gre_main_t *gm = &gre_main;
  vnet_hw_interface_t *hi;
  gre_tunnel_t *t;
  u32 ti;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  if (NULL == gm->tunnel_index_by_sw_if_index ||
      hi->sw_if_index >= vec_len (gm->tunnel_index_by_sw_if_index))
    return (NULL);

  ti = gm->tunnel_index_by_sw_if_index[hi->sw_if_index];

  if (~0 == ti)
    /* not one of ours */
    return (NULL);

  t = pool_elt_at_index (gm->tunnels, ti);

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, hw_if_index,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, hw_if_index, 0 /* down */ );

  gre_tunnel_restack (t);

  return /* no error */ 0;
}

static clib_error_t *
create_gre_tunnel_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_gre_add_del_tunnel_args_t _a, *a = &_a;
  ip46_address_t src, dst;
  u32 instance = ~0;
  u32 outer_fib_id = 0;
  gre_tunnel_type_t t_type = GRE_TUNNEL_TYPE_L3;
  u32 session_id = 0;
  int rv;
  u32 num_m_args = 0;
  u8 is_add = 1;
  u32 sw_if_index;
  clib_error_t *error = NULL;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "instance %d", &instance))
	;
      else
	if (unformat (line_input, "src %U", unformat_ip4_address, &src.ip4))
	{
	  num_m_args++;
	  ipv4_set = 1;
	}
      else
	if (unformat (line_input, "dst %U", unformat_ip4_address, &dst.ip4))
	{
	  num_m_args++;
	  ipv4_set = 1;
	}
      else
	if (unformat (line_input, "src %U", unformat_ip6_address, &src.ip6))
	{
	  num_m_args++;
	  ipv6_set = 1;
	}
      else
	if (unformat (line_input, "dst %U", unformat_ip6_address, &dst.ip6))
	{
	  num_m_args++;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "outer-fib-id %d", &outer_fib_id))
	;
      else if (unformat (line_input, "teb"))
	t_type = GRE_TUNNEL_TYPE_TEB;
      else if (unformat (line_input, "erspan %d", &session_id))
	t_type = GRE_TUNNEL_TYPE_ERSPAN;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (num_m_args < 2)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }

  if ((ipv4_set && memcmp (&src.ip4, &dst.ip4, sizeof (src.ip4)) == 0) ||
      (ipv6_set && memcmp (&src.ip6, &dst.ip6, sizeof (src.ip6)) == 0))
    {
      error = clib_error_return (0, "src and dst are identical");
      goto done;
    }

  if (ipv4_set && ipv6_set)
    return clib_error_return (0, "both IPv4 and IPv6 addresses specified");

  if ((ipv4_set && memcmp (&dst.ip4, &zero_addr.ip4, sizeof (dst.ip4)) == 0)
      || (ipv6_set
	  && memcmp (&dst.ip6, &zero_addr.ip6, sizeof (dst.ip6)) == 0))
    {
      error = clib_error_return (0, "dst address cannot be zero");
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));
  a->is_add = is_add;
  a->outer_fib_id = outer_fib_id;
  a->tunnel_type = t_type;
  a->session_id = session_id;
  a->is_ipv6 = ipv6_set;
  a->instance = instance;
  if (!ipv6_set)
    {
      clib_memcpy (&a->src.ip4, &src.ip4, sizeof (src.ip4));
      clib_memcpy (&a->dst.ip4, &dst.ip4, sizeof (dst.ip4));
    }
  else
    {
      clib_memcpy (&a->src.ip6, &src.ip6, sizeof (src.ip6));
      clib_memcpy (&a->dst.ip6, &dst.ip6, sizeof (dst.ip6));
    }

  rv = vnet_gre_add_del_tunnel (a, &sw_if_index);

  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);
      break;
    case VNET_API_ERROR_IF_ALREADY_EXISTS:
      error = clib_error_return (0, "GRE tunnel already exists...");
      goto done;
    case VNET_API_ERROR_NO_SUCH_FIB:
      error = clib_error_return (0, "outer fib ID %d doesn't exist\n",
				 outer_fib_id);
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "GRE tunnel doesn't exist");
      goto done;
    case VNET_API_ERROR_INVALID_SESSION_ID:
      error = clib_error_return (0, "session ID %d out of range\n",
				 session_id);
      goto done;
    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "Instance is in use");
      goto done;
    default:
      error =
	clib_error_return (0, "vnet_gre_add_del_tunnel returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_gre_tunnel_command, static) = {
  .path = "create gre tunnel",
  .short_help = "create gre tunnel src <addr> dst <addr> [instance <n>] "
                "[outer-fib-id <fib>] [teb | erspan <session-id>] [del]",
  .function = create_gre_tunnel_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_gre_tunnel_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  gre_main_t *gm = &gre_main;
  gre_tunnel_t *t;
  u32 ti = ~0;

  if (pool_elts (gm->tunnels) == 0)
    vlib_cli_output (vm, "No GRE tunnels configured...");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &ti))
	;
      else
	break;
    }

  if (~0 == ti)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, gm->tunnels,
      ({
          vlib_cli_output (vm, "%U", format_gre_tunnel, t);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      t = pool_elt_at_index (gm->tunnels, ti);

      vlib_cli_output (vm, "%U", format_gre_tunnel, t);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_gre_tunnel_command, static) = {
    .path = "show gre tunnel",
    .function = show_gre_tunnel_command_fn,
};
/* *INDENT-ON* */

/* force inclusion from application's main.c */
clib_error_t *
gre_interface_init (vlib_main_t * vm)
{
  fib_node_register_type (FIB_NODE_TYPE_GRE_TUNNEL, &gre_vft);

  return 0;
}

VLIB_INIT_FUNCTION (gre_interface_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
