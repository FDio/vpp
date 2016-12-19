/*
 * mpls_tunnel.c: MPLS tunnel interfaces (i.e. for RSVP-TE)
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
#include <vnet/mpls/mpls_tunnel.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/adj/adj_midchain.h>

/**
 * @brief pool of tunnel instances
 */
static mpls_tunnel_t *mpls_tunnel_pool;

/**
 * @brief Pool of free tunnel SW indices - i.e. recycled indices
 */
static u32 * mpls_tunnel_free_hw_if_indices;

/**
 * @brief DB of SW index to tunnel index
 */
static u32 *mpls_tunnel_db;

/**
 * @brief Get a tunnel object from a SW interface index
 */
static mpls_tunnel_t*
mpls_tunnel_get_from_sw_if_index (u32 sw_if_index)
{
    if ((vec_len(mpls_tunnel_db) < sw_if_index) ||
	(~0 == mpls_tunnel_db[sw_if_index]))
	return (NULL);

    return (pool_elt_at_index(mpls_tunnel_pool,
			      mpls_tunnel_db[sw_if_index]));
}

/**
 * @brief Return true if the label stack is imp-null only
 */
static fib_forward_chain_type_t
mpls_tunnel_get_fwd_chain_type (const mpls_tunnel_t *mt)
{
    if ((1 == vec_len(mt->mt_label_stack)) &&
	(mt->mt_label_stack[0] == MPLS_IETF_IMPLICIT_NULL_LABEL))
    {
	/*
	 * the only label in the label stack is implicit null
	 * we need to build an IP chain.
	 */
	if (FIB_PROTOCOL_IP4 == fib_path_list_get_proto(mt->mt_path_list))
	{
	    return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
	}
	else
	{
	    return (FIB_FORW_CHAIN_TYPE_UNICAST_IP6);
	}
    }
    else
    {
	return (FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS);
    }
}

/**
 * @brief Build a rewrite string for the MPLS tunnel.
 *
 * We have choices here;
 *  1 - have an Adjacency with a zero length string and stack it on
 *       MPLS label objects
 *  2 - put the label header rewrites in the adjacency string.
 *
 * We choose 2 since it results in fewer graph nodes in the egress path
 */
static u8*
mpls_tunnel_build_rewrite (vnet_main_t * vnm,
			   u32 sw_if_index,
			   vnet_link_t link_type,
			   const void *dst_address)
{
    mpls_unicast_header_t *muh;
    mpls_tunnel_t *mt;
    u8 *rewrite;
    u32 mti, ii;

    rewrite = NULL;
    mti = mpls_tunnel_db[sw_if_index];
    mt = pool_elt_at_index(mpls_tunnel_pool, mti);

    /*
     * The vector must be allocated as u8 so the length is correct
     */
    ASSERT(0 < vec_len(mt->mt_label_stack));
    vec_validate(rewrite, (sizeof(*muh) * vec_len(mt->mt_label_stack)) - 1);
    ASSERT(rewrite);
    muh = (mpls_unicast_header_t *)rewrite;

    /*
     * The last (inner most) label in the stack may be EOS, all the rest Non-EOS
     */
    for (ii = 0; ii < vec_len(mt->mt_label_stack)-1; ii++)
    {
	vnet_mpls_uc_set_label(&muh[ii].label_exp_s_ttl, mt->mt_label_stack[ii]);
	vnet_mpls_uc_set_ttl(&muh[ii].label_exp_s_ttl, 255);
	vnet_mpls_uc_set_exp(&muh[ii].label_exp_s_ttl, 0);
	vnet_mpls_uc_set_s(&muh[ii].label_exp_s_ttl, MPLS_NON_EOS);
	muh[ii].label_exp_s_ttl = clib_host_to_net_u32(muh[ii].label_exp_s_ttl);
    }

    vnet_mpls_uc_set_label(&muh[ii].label_exp_s_ttl, mt->mt_label_stack[ii]);
    vnet_mpls_uc_set_ttl(&muh[ii].label_exp_s_ttl, 255);
    vnet_mpls_uc_set_exp(&muh[ii].label_exp_s_ttl, 0);

    if ((VNET_LINK_MPLS == link_type) &&
	(mt->mt_label_stack[ii] != MPLS_IETF_IMPLICIT_NULL_LABEL))
    {
	vnet_mpls_uc_set_s(&muh[ii].label_exp_s_ttl, MPLS_NON_EOS);
    }
    else
    {
	vnet_mpls_uc_set_s(&muh[ii].label_exp_s_ttl, MPLS_EOS);
    }

    muh[ii].label_exp_s_ttl = clib_host_to_net_u32(muh[ii].label_exp_s_ttl);

    return (rewrite);
}

/**
 * mpls_tunnel_stack
 *
 * 'stack' (resolve the recursion for) the tunnel's midchain adjacency
 */
static void
mpls_tunnel_stack (adj_index_t ai)
{
    ip_adjacency_t *adj;
    mpls_tunnel_t *mt;
    u32 sw_if_index;

    adj = adj_get(ai);
    sw_if_index = adj->rewrite_header.sw_if_index;

    mt = mpls_tunnel_get_from_sw_if_index(sw_if_index);

    if (NULL == mt)
	return;

    /*
     * find the adjacency that is contributed by the FIB path-list
     * that this tunnel resovles via, and use it as the next adj
     * in the midchain
     */
    if (vnet_hw_interface_get_flags(vnet_get_main(),
				    mt->mt_hw_if_index) &
	VNET_HW_INTERFACE_FLAG_LINK_UP)
    {
	dpo_id_t dpo = DPO_INVALID;

	fib_path_list_contribute_forwarding(mt->mt_path_list,
					    mpls_tunnel_get_fwd_chain_type(mt),
					    &dpo);

	if (DPO_LOAD_BALANCE == dpo.dpoi_type)
	{
	    /*
	     * we don't support multiple paths, so no need to load-balance.
	     * pull the first and only choice and stack directly on that.
	     */
	    load_balance_t *lb;

	    lb = load_balance_get (dpo.dpoi_index);

	    ASSERT(1 == lb->lb_n_buckets);

	    dpo_copy(&dpo, load_balance_get_bucket_i (lb, 0));
	}

	adj_nbr_midchain_stack(ai, &dpo);
	dpo_reset(&dpo);
    }
    else
    {
	adj_nbr_midchain_unstack(ai);
    }
}

/**
 * @brief Call back when restacking all adjacencies on a MPLS interface
 */
static adj_walk_rc_t
mpls_adj_walk_cb (adj_index_t ai,
		 void *ctx)
{
    mpls_tunnel_stack(ai);

    return (ADJ_WALK_RC_CONTINUE);
}

static void
mpls_tunnel_restack (mpls_tunnel_t *mt)
{
    fib_protocol_t proto;

    /*
     * walk all the adjacencies on the MPLS interface and restack them
     */
    FOR_EACH_FIB_PROTOCOL(proto)
    {
	adj_nbr_walk(mt->mt_sw_if_index,
		     proto,
		     mpls_adj_walk_cb,
		     NULL);
    }
}

static clib_error_t *
mpls_tunnel_admin_up_down (vnet_main_t * vnm,
			   u32 hw_if_index,
			   u32 flags)
{
    vnet_hw_interface_t * hi;
    mpls_tunnel_t *mt;

    hi = vnet_get_hw_interface (vnm, hw_if_index);

    mt = mpls_tunnel_get_from_sw_if_index(hi->sw_if_index);

    if (NULL == mt)
	return (NULL);

    if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
	vnet_hw_interface_set_flags (vnm, hw_if_index,
				     VNET_HW_INTERFACE_FLAG_LINK_UP);
    else
	vnet_hw_interface_set_flags (vnm, hw_if_index, 0 /* down */);

    mpls_tunnel_restack(mt);

    return (NULL);
}

/**
 * @brief Fixup the adj rewrite post encap. This is a no-op since the
 * rewrite is a stack of labels.
 */
static void
mpls_tunnel_fixup (vlib_main_t *vm,
		   ip_adjacency_t *adj,
		   vlib_buffer_t *b0)
{
}

static void
mpls_tunnel_update_adj (vnet_main_t * vnm,
			u32 sw_if_index,
			adj_index_t ai)
{
    adj_nbr_midchain_update_rewrite(
	ai, mpls_tunnel_fixup, 
	ADJ_MIDCHAIN_FLAG_NONE,
	mpls_tunnel_build_rewrite(vnm, sw_if_index,
				  adj_get_link_type(ai),
				  NULL));

    mpls_tunnel_stack(ai);
}

static u8 *
format_mpls_tunnel_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "mpls-tunnel%d", dev_instance);
}

static u8 *
format_mpls_tunnel_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);

  return (format (s, "MPLS-tunnel: id %d\n", dev_instance));
}

/**
 * @brief Packet trace structure
 */
typedef struct mpls_tunnel_trace_t_
{
    /**
   * Tunnel-id / index in tunnel vector
   */
  u32 tunnel_id;
} mpls_tunnel_trace_t;

static u8 *
format_mpls_tunnel_tx_trace (u8 * s,
			     va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mpls_tunnel_trace_t * t = va_arg (*args, mpls_tunnel_trace_t *);

  s = format (s, "MPLS: tunnel %d", t->tunnel_id);
  return s;
}

/**
 * @brief TX function. Only called L2. L3 traffic uses the adj-midchains
 */
static uword
mpls_tunnel_tx (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  u32 next_index;
  u32 * from, * to_next, n_left_from, n_left_to_next;
  vnet_interface_output_runtime_t * rd = (void *) node->runtime_data;
  const mpls_tunnel_t *mt;

  mt = pool_elt_at_index(mpls_tunnel_pool, rd->dev_instance);

  /* Vector of buffer / pkt indices we're supposed to process */
  from = vlib_frame_vector_args (frame);

  /* Number of buffers / pkts */
  n_left_from = frame->n_vectors;

  /* Speculatively send the first buffer to the last disposition we used */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      /* set up to enqueue to our disposition with index = next_index */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /*
       * FIXME DUAL LOOP
       */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * b0;
	  u32 bi0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer(vm, bi0);

	  vnet_buffer(b0)->ip.adj_index[VLIB_TX] = mt->mt_l2_adj;

	  if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      mpls_tunnel_trace_t *tr = vlib_add_trace (vm, node,
						   b0, sizeof (*tr));
	      tr->tunnel_id = rd->dev_instance;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, mt->mt_l2_tx_arc);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VNET_DEVICE_CLASS (mpls_tunnel_class) = {
    .name = "MPLS tunnel device",
    .format_device_name = format_mpls_tunnel_name,
    .format_device = format_mpls_tunnel_device,
    .format_tx_trace = format_mpls_tunnel_tx_trace,
    .tx_function = mpls_tunnel_tx,
    .admin_up_down_function = mpls_tunnel_admin_up_down,
};

VNET_HW_INTERFACE_CLASS (mpls_tunnel_hw_interface_class) = {
  .name = "MPLS-Tunnel",
//  .format_header = format_mpls_eth_header_with_length,
//  .unformat_header = unformat_mpls_eth_header,
  .update_adjacency = mpls_tunnel_update_adj,
  .build_rewrite = mpls_tunnel_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

const mpls_tunnel_t *
mpls_tunnel_get (u32 mti)
{
    return (pool_elt_at_index(mpls_tunnel_pool, mti));
}

/**
 * @brief Walk all the MPLS tunnels
 */
void
mpls_tunnel_walk (mpls_tunnel_walk_cb_t cb,
		  void *ctx)
{
    u32 mti;

    pool_foreach_index(mti, mpls_tunnel_pool,
    ({
	cb(mti, ctx);
    }));
}

void
vnet_mpls_tunnel_del (u32 sw_if_index)
{
    mpls_tunnel_t *mt;

    mt = mpls_tunnel_get_from_sw_if_index(sw_if_index);

    if (NULL == mt)
	return;
    
    fib_path_list_child_remove(mt->mt_path_list,
			       mt->mt_sibling_index);
    if (ADJ_INDEX_INVALID != mt->mt_l2_adj)
	adj_unlock(mt->mt_l2_adj);

    vec_free(mt->mt_label_stack);

    vec_add1 (mpls_tunnel_free_hw_if_indices, mt->mt_hw_if_index);
    pool_put(mpls_tunnel_pool, mt);
    mpls_tunnel_db[sw_if_index] = ~0;
}

void
vnet_mpls_tunnel_add (fib_route_path_t *rpaths,
		      mpls_label_t *label_stack,
		      u8 l2_only,
		      u32 *sw_if_index)
{
    vnet_hw_interface_t * hi;
    mpls_tunnel_t *mt;
    vnet_main_t * vnm;
    u32 mti;

    vnm = vnet_get_main();
    pool_get(mpls_tunnel_pool, mt);
    memset (mt, 0, sizeof (*mt));
    mti = mt - mpls_tunnel_pool;
    fib_node_init(&mt->mt_node, FIB_NODE_TYPE_MPLS_TUNNEL);
    mt->mt_l2_adj = ADJ_INDEX_INVALID;

    /*
     * Create a new, or re=use and old, tunnel HW interface
     */
    if (vec_len (mpls_tunnel_free_hw_if_indices) > 0)
    {
	mt->mt_hw_if_index = 
	    mpls_tunnel_free_hw_if_indices[vec_len(mpls_tunnel_free_hw_if_indices)-1];
	_vec_len (mpls_tunnel_free_hw_if_indices) -= 1;
	hi = vnet_get_hw_interface (vnm, mt->mt_hw_if_index);
	hi->hw_instance = mti;
	hi->dev_instance = mti;
    }
    else 
    {
	mt->mt_hw_if_index = vnet_register_interface(
	                         vnm,
				 mpls_tunnel_class.index,
				 mti,
				 mpls_tunnel_hw_interface_class.index,
				 mti);
	hi = vnet_get_hw_interface(vnm, mt->mt_hw_if_index);
    }

    /*
     * Add the new tunnel to the tunnel DB - key:SW if index
     */
    mt->mt_sw_if_index = hi->sw_if_index;
    vec_validate_init_empty(mpls_tunnel_db, mt->mt_sw_if_index, ~0);
    mpls_tunnel_db[mt->mt_sw_if_index] = mti;

    /*
     * construct a path-list from the path provided
     */
    mt->mt_path_list = fib_path_list_create(FIB_PATH_LIST_FLAG_SHARED, rpaths);
    mt->mt_sibling_index = fib_path_list_child_add(mt->mt_path_list,
						   FIB_NODE_TYPE_MPLS_TUNNEL,
						   mti);

    mt->mt_label_stack = vec_dup(label_stack);

    if (l2_only)
    {
	mt->mt_l2_adj =
	    adj_nbr_add_or_lock(fib_path_list_get_proto(mt->mt_path_list),
				VNET_LINK_ETHERNET,
				&zero_addr,
				mt->mt_sw_if_index);

	mt->mt_l2_tx_arc = vlib_node_add_named_next(vlib_get_main(),
						    hi->tx_node_index,
						    "adj-l2-midchain");
    }

    *sw_if_index = mt->mt_sw_if_index;
}

static clib_error_t *
vnet_create_mpls_tunnel_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, * line_input = &_line_input;
    vnet_main_t * vnm = vnet_get_main();
    u8 is_del = 0;
    u8 l2_only = 0;
    fib_route_path_t rpath, *rpaths = NULL;
    mpls_label_t out_label = MPLS_LABEL_INVALID, *labels = NULL;
    u32 sw_if_index;

    memset(&rpath, 0, sizeof(rpath));

    /* Get a line of input. */
    if (! unformat_user (input, unformat_line_input, line_input))
	return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (line_input, "del %U",
		      unformat_vnet_sw_interface, vnm,
		      &sw_if_index))
	    is_del = 1;
	else if (unformat (line_input, "add"))
	    is_del = 0;
	else if (unformat (line_input, "out-label %U",
			   unformat_mpls_unicast_label, &out_label))
	{
	    vec_add1(labels, out_label);
	}
	else if (unformat (line_input, "via %U %U",
			   unformat_ip4_address,
			   &rpath.frp_addr.ip4,
			   unformat_vnet_sw_interface, vnm,
			   &rpath.frp_sw_if_index))
	{
	    rpath.frp_weight = 1;
	    rpath.frp_proto = FIB_PROTOCOL_IP4;
	}
			 
	else if (unformat (line_input, "via %U %U",
			   unformat_ip6_address,
			   &rpath.frp_addr.ip6,
			   unformat_vnet_sw_interface, vnm,
			   &rpath.frp_sw_if_index))
	{
	    rpath.frp_weight = 1;
	    rpath.frp_proto = FIB_PROTOCOL_IP6;
	}
	else if (unformat (line_input, "via %U",
			   unformat_ip6_address,
			   &rpath.frp_addr.ip6))
	{
	    rpath.frp_fib_index = 0;
	    rpath.frp_weight = 1;
	    rpath.frp_sw_if_index = ~0;
	    rpath.frp_proto = FIB_PROTOCOL_IP6;
	}
	else if (unformat (line_input, "via %U",
			   unformat_ip4_address,
			   &rpath.frp_addr.ip4))
	{
	    rpath.frp_fib_index = 0;
	    rpath.frp_weight = 1;
	    rpath.frp_sw_if_index = ~0;
	    rpath.frp_proto = FIB_PROTOCOL_IP4;
	}
	else if (unformat (line_input, "l2-only"))
	    l2_only = 1;
	else
	    return clib_error_return (0, "unknown input '%U'",
				      format_unformat_error, line_input);
    }

    if (is_del)
    {
	vnet_mpls_tunnel_del(sw_if_index);
    }
    else
    {
	if (0 == vec_len(labels))
	    return clib_error_return (0, "No Output Labels '%U'",
				      format_unformat_error, line_input);

	vec_add1(rpaths, rpath);
	vnet_mpls_tunnel_add(rpaths, labels, l2_only, &sw_if_index);
    }

    vec_free(labels);
    vec_free(rpaths);

    return (NULL);
}

/*?
 * This command create a uni-directional MPLS tunnel
 *
 * @cliexpar
 * @cliexstart{create mpls tunnel}
 *  create mpls tunnel via 10.0.0.1 GigEthernet0/8/0 out-label 33 out-label 34
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (create_mpls_tunnel_command, static) = {
  .path = "mpls tunnel",
  .short_help = 
  "mpls tunnel via [addr] [interface] [out-labels]",
  .function = vnet_create_mpls_tunnel_command_fn,
};

static u8 *
format_mpls_tunnel (u8 * s, va_list * args)
{
    mpls_tunnel_t *mt = va_arg (*args, mpls_tunnel_t *);
    int ii;

    s = format(s, "mpls_tunnel%d: sw_if_index:%d hw_if_index:%d",
	       mt - mpls_tunnel_pool,
	       mt->mt_sw_if_index,
	       mt->mt_hw_if_index);
    s = format(s, "\n label-stack:\n  ");
    for (ii = 0; ii < vec_len(mt->mt_label_stack); ii++)
    {
	s = format(s, "%d, ", mt->mt_label_stack[ii]);
    }
    s = format(s, "\n via:\n");
    s = fib_path_list_format(mt->mt_path_list, s);
    s = format(s, "\n");

    return (s);
}

static clib_error_t *
show_mpls_tunnel_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
    mpls_tunnel_t * mt;
    u32 mti = ~0;

    if (pool_elts (mpls_tunnel_pool) == 0)
	vlib_cli_output (vm, "No MPLS tunnels configured...");

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (input, "%d", &mti))
	    ;
	else
	    break;
    }

    if (~0 == mti)
    {
	pool_foreach (mt, mpls_tunnel_pool,
	({
	    vlib_cli_output (vm, "[@%d] %U",
			     mt - mpls_tunnel_pool,
			     format_mpls_tunnel, mt);
	}));
    }
    else
    {
	if (pool_is_free_index(mpls_tunnel_pool, mti))
	    return clib_error_return (0, "Not atunnel index %d", mti);

	mt = pool_elt_at_index(mpls_tunnel_pool, mti);

	vlib_cli_output (vm, "[@%d] %U",
			 mt - mpls_tunnel_pool,
			 format_mpls_tunnel, mt);
    }

    return 0;
}

/*?
 * This command to show MPLS tunnels
 *
 * @cliexpar
 * @cliexstart{sh mpls tunnel 2}
 * [@2] mpls_tunnel2: sw_if_index:5 hw_if_index:5
 *  label-stack:
 *    3, 
 *  via:
 *   index:26 locks:1 proto:ipv4 uPRF-list:26 len:1 itfs:[2, ]
 *     index:26 pl-index:26 ipv4 weight=1 attached-nexthop:  oper-flags:resolved,
 *      10.0.0.2 loop0
 *         [@0]: ipv4 via 10.0.0.2 loop0: IP4: de:ad:00:00:00:00 -> 00:00:11:aa:bb:cc
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (show_mpls_tunnel_command, static) = {
    .path = "show mpls tunnel",
    .function = show_mpls_tunnel_command_fn,
};

static mpls_tunnel_t *
mpls_tunnel_from_fib_node (fib_node_t *node)
{
#if (CLIB_DEBUG > 0)
    ASSERT(FIB_NODE_TYPE_MPLS_TUNNEL == node->fn_type);
#endif
    return ((mpls_tunnel_t*) (((char*)node) -
                             STRUCT_OFFSET_OF(mpls_tunnel_t, mt_node)));
}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
mpls_tunnel_back_walk (fib_node_t *node,
		      fib_node_back_walk_ctx_t *ctx)
{
    mpls_tunnel_restack(mpls_tunnel_from_fib_node(node));

    return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t*
mpls_tunnel_fib_node_get (fib_node_index_t index)
{
    mpls_tunnel_t * mt;

    mt = pool_elt_at_index(mpls_tunnel_pool, index);

    return (&mt->mt_node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
mpls_tunnel_last_lock_gone (fib_node_t *node)
{
    /*
     * The MPLS MPLS tunnel is a root of the graph. As such
     * it never has children and thus is never locked.
     */
    ASSERT(0);
}

/*
 * Virtual function table registered by MPLS MPLS tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t mpls_vft = {
    .fnv_get = mpls_tunnel_fib_node_get,
    .fnv_last_lock = mpls_tunnel_last_lock_gone,
    .fnv_back_walk = mpls_tunnel_back_walk,
};

static clib_error_t *
mpls_tunnel_init (vlib_main_t *vm)
{
  fib_node_register_type(FIB_NODE_TYPE_MPLS_TUNNEL, &mpls_vft);

  return 0;
}
VLIB_INIT_FUNCTION(mpls_tunnel_init);
