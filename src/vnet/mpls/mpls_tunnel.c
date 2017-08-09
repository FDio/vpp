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
#include <vnet/mpls/mpls_types.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/dpo/replicate_dpo.h>
#include <vnet/fib/mpls_fib.h>

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
 * @brief MPLS tunnel flags strings
 */
static const char *mpls_tunnel_attribute_names[] = MPLS_TUNNEL_ATTRIBUTES;

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
 * @brief Build a rewrite string for the MPLS tunnel.
 */
static u8*
mpls_tunnel_build_rewrite_i (void)
{
    /*
     * passing the adj code a NULL rewirte means 'i don't have one cos
     * t'other end is unresolved'. That's not the case here. For the mpls
     * tunnel there are just no bytes of encap to apply in the adj. We'll impose
     * the label stack once we choose a path. So return a zero length rewrite.
     */
    u8 *rewrite = NULL;

    vec_validate(rewrite, 0);
    vec_reset_length(rewrite);

    return (rewrite);
}

/**
 * @brief Build a rewrite string for the MPLS tunnel.
 */
static u8*
mpls_tunnel_build_rewrite (vnet_main_t * vnm,
                           u32 sw_if_index,
                           vnet_link_t link_type,
                           const void *dst_address)
{
    return (mpls_tunnel_build_rewrite_i());
}

typedef struct mpls_tunnel_collect_forwarding_ctx_t_
{
    load_balance_path_t * next_hops;
    const mpls_tunnel_t *mt;
    fib_forward_chain_type_t fct;
} mpls_tunnel_collect_forwarding_ctx_t;

static fib_path_list_walk_rc_t
mpls_tunnel_collect_forwarding (fib_node_index_t pl_index,
                                fib_node_index_t path_index,
                                void *arg)
{
    mpls_tunnel_collect_forwarding_ctx_t *ctx;
    fib_path_ext_t *path_ext;

    ctx = arg;

    /*
     * if the path is not resolved, don't include it.
     */
    if (!fib_path_is_resolved(path_index))
    {
        return (FIB_PATH_LIST_WALK_CONTINUE);
    }

    /*
     * get the matching path-extension for the path being visited.
     */
    path_ext = fib_path_ext_list_find_by_path_index(&ctx->mt->mt_path_exts,
                                                    path_index);

    if (NULL != path_ext)
    {
        /*
         * found a matching extension. stack it to obtain the forwarding
         * info for this path.
         */
        ctx->next_hops = fib_path_ext_stack(path_ext,
                                            ctx->fct,
                                            ctx->fct,
                                            ctx->next_hops);
    }
    else
        ASSERT(0);
    /*
     * else
     *   There should be a path-extenios associated with each path
     */

    return (FIB_PATH_LIST_WALK_CONTINUE);
}

static void
mpls_tunnel_mk_lb (mpls_tunnel_t *mt,
                   vnet_link_t linkt,
                   fib_forward_chain_type_t fct,
                   dpo_id_t *dpo_lb)
{
    dpo_proto_t lb_proto;

    /*
     * If the entry has path extensions then we construct a load-balance
     * by stacking the extensions on the forwarding chains of the paths.
     * Otherwise we use the load-balance of the path-list
     */
    mpls_tunnel_collect_forwarding_ctx_t ctx = {
        .mt = mt,
        .next_hops = NULL,
        .fct = fct,
    };

    /*
     * As an optimisation we allocate the vector of next-hops to be sized
     * equal to the maximum nuber of paths we will need, which is also the
     * most likely number we will need, since in most cases the paths are 'up'.
     */
    vec_validate(ctx.next_hops, fib_path_list_get_n_paths(mt->mt_path_list));
    vec_reset_length(ctx.next_hops);

    lb_proto = fib_forw_chain_type_to_dpo_proto(fct);

    fib_path_list_walk(mt->mt_path_list,
                       mpls_tunnel_collect_forwarding,
                       &ctx);

    if (!dpo_id_is_valid(dpo_lb))
    {
        /*
         * first time create
         */
        if (mt->mt_flags & MPLS_TUNNEL_FLAG_MCAST)
        {
            dpo_set(dpo_lb,
                    DPO_REPLICATE,
                    lb_proto,
                    replicate_create(0, lb_proto));
        }
        else
        {
            flow_hash_config_t fhc;

            switch (linkt)
            {
            case VNET_LINK_MPLS:
                fhc = MPLS_FLOW_HASH_DEFAULT;
                break;
            case VNET_LINK_IP4:
            case VNET_LINK_IP6:
                fhc = IP_FLOW_HASH_DEFAULT;
                break;
            default:
                fhc = 0;
                break;
            }

            dpo_set(dpo_lb,
                    DPO_LOAD_BALANCE,
                    lb_proto,
                    load_balance_create(0, lb_proto, fhc));
        }
    }

    if (mt->mt_flags & MPLS_TUNNEL_FLAG_MCAST)
    {
        /*
         * MPLS multicast
         */
        replicate_multipath_update(dpo_lb, ctx.next_hops);
    }
    else
    {
        load_balance_multipath_update(dpo_lb,
                                      ctx.next_hops,
                                      LOAD_BALANCE_FLAG_NONE);
        vec_free(ctx.next_hops);
    }
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
     * while we're stacking the adj, remove the tunnel from the child list
     * of the path list. this breaks a circular dependency of walk updates
     * where the create of adjacencies in the children can lead to walks
     * that get back here.
     */
    fib_path_list_lock(mt->mt_path_list);

    fib_path_list_child_remove(mt->mt_path_list,
                               mt->mt_sibling_index);

    /*
     * Construct the DPO (load-balance or replicate) that we can stack
     * the tunnel's midchain on
     */
    if (vnet_hw_interface_get_flags(vnet_get_main(),
                                    mt->mt_hw_if_index) &
        VNET_HW_INTERFACE_FLAG_LINK_UP)
    {
        dpo_id_t dpo = DPO_INVALID;

        mpls_tunnel_mk_lb(mt,
                          adj->ia_link,
                          (VNET_LINK_MPLS == adj_get_link_type(ai) ?
                           FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
                           FIB_FORW_CHAIN_TYPE_MPLS_EOS),
                          &dpo);

        adj_nbr_midchain_stack(ai, &dpo);
        dpo_reset(&dpo);
    }
    else
    {
        adj_nbr_midchain_unstack(ai);
    }

    mt->mt_sibling_index = fib_path_list_child_add(mt->mt_path_list,
                                                   FIB_NODE_TYPE_MPLS_TUNNEL,
                                                   mt - mpls_tunnel_pool);

    fib_path_list_unlock(mt->mt_path_list);
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
    if (mt->mt_flags & MPLS_TUNNEL_FLAG_L2)
    {
        /*
         * Stack a load-balance that drops, whilst we have no paths
         */
        vnet_hw_interface_t * hi;
        dpo_id_t dpo = DPO_INVALID;

        mpls_tunnel_mk_lb(mt,
                          VNET_LINK_MPLS,
                          FIB_FORW_CHAIN_TYPE_ETHERNET,
                          &dpo);

        hi = vnet_get_hw_interface(vnet_get_main(), mt->mt_hw_if_index);
        dpo_stack_from_node(hi->tx_node_index,
                            &mt->mt_l2_lb,
                            &dpo);
        dpo_reset(&dpo);
    }
    else
    {
        FOR_EACH_FIB_PROTOCOL(proto)
        {
            adj_nbr_walk(mt->mt_sw_if_index,
                         proto,
                         mpls_adj_walk_cb,
                         NULL);
        }
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
    /*
     * A no-op w.r.t. the header. but reset the 'have we pushed any
     * MPLS labels onto the packet' flag. That way when we enter the
     * tunnel we'll get a TTL set to 255
     */
    vnet_buffer(b0)->mpls.first = 0;
}

static void
mpls_tunnel_update_adj (vnet_main_t * vnm,
                        u32 sw_if_index,
                        adj_index_t ai)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != ai);

    adj = adj_get(ai);

    switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_GLEAN:
        adj_nbr_midchain_update_rewrite(ai, mpls_tunnel_fixup,
                                        ADJ_FLAG_NONE,
                                        mpls_tunnel_build_rewrite_i());
        break;
    case IP_LOOKUP_NEXT_MCAST:
        /*
         * Construct a partial rewrite from the known ethernet mcast dest MAC
         * There's no MAC fixup, so the last 2 parameters are 0
         */
        adj_mcast_midchain_update_rewrite(ai, mpls_tunnel_fixup,
                                          ADJ_FLAG_NONE,
                                          mpls_tunnel_build_rewrite_i(),
                                          0, 0);
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

          vnet_buffer(b0)->ip.adj_index[VLIB_TX] = mt->mt_l2_lb.dpoi_index;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              mpls_tunnel_trace_t *tr = vlib_add_trace (vm, node,
                                                   b0, sizeof (*tr));
              tr->tunnel_id = rd->dev_instance;
            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, mt->mt_l2_lb.dpoi_next_node);
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

    if (FIB_NODE_INDEX_INVALID != mt->mt_path_list)
        fib_path_list_child_remove(mt->mt_path_list,
                                   mt->mt_sibling_index);
    dpo_reset(&mt->mt_l2_lb);

    vec_add1 (mpls_tunnel_free_hw_if_indices, mt->mt_hw_if_index);
    pool_put(mpls_tunnel_pool, mt);
    mpls_tunnel_db[sw_if_index] = ~0;
}

u32
vnet_mpls_tunnel_create (u8 l2_only,
                         u8 is_multicast)
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
    mt->mt_path_list = FIB_NODE_INDEX_INVALID;
    mt->mt_sibling_index = FIB_NODE_INDEX_INVALID;

    if (is_multicast)
        mt->mt_flags |= MPLS_TUNNEL_FLAG_MCAST;
    if (l2_only)
        mt->mt_flags |= MPLS_TUNNEL_FLAG_L2;

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
        hi = vnet_get_hw_interface (vnm, mt->mt_hw_if_index);
    }

    /*
     * Add the new tunnel to the tunnel DB - key:SW if index
     */
    mt->mt_sw_if_index = hi->sw_if_index;
    vec_validate_init_empty(mpls_tunnel_db, mt->mt_sw_if_index, ~0);
    mpls_tunnel_db[mt->mt_sw_if_index] = mti;

    return (mt->mt_sw_if_index);
}

void
vnet_mpls_tunnel_path_add (u32 sw_if_index,
                           fib_route_path_t *rpaths)
{
    mpls_tunnel_t *mt;
    u32 mti;

    mt = mpls_tunnel_get_from_sw_if_index(sw_if_index);

    if (NULL == mt)
        return;

    mti = mt - mpls_tunnel_pool;

    /*
     * construct a path-list from the path provided
     */
    if (FIB_NODE_INDEX_INVALID == mt->mt_path_list)
    {
        mt->mt_path_list = fib_path_list_create(FIB_PATH_LIST_FLAG_SHARED, rpaths);
        mt->mt_sibling_index = fib_path_list_child_add(mt->mt_path_list,
                                                       FIB_NODE_TYPE_MPLS_TUNNEL,
                                                       mti);
    }
    else
    {
        fib_node_index_t old_pl_index;

        old_pl_index = mt->mt_path_list;

        mt->mt_path_list =
            fib_path_list_copy_and_path_add(old_pl_index,
                                            FIB_PATH_LIST_FLAG_SHARED,
                                            rpaths);

        fib_path_list_child_remove(old_pl_index,
                                   mt->mt_sibling_index);
        mt->mt_sibling_index = fib_path_list_child_add(mt->mt_path_list,
                                                       FIB_NODE_TYPE_MPLS_TUNNEL,
                                                       mti);
        /*
         * re-resolve all the path-extensions with the new path-list
         */
        fib_path_ext_list_resolve(&mt->mt_path_exts, mt->mt_path_list);
    }
    fib_path_ext_list_insert(&mt->mt_path_exts,
                             mt->mt_path_list,
                             FIB_PATH_EXT_MPLS,
                             rpaths);
    mpls_tunnel_restack(mt);
}

int
vnet_mpls_tunnel_path_remove (u32 sw_if_index,
                              fib_route_path_t *rpaths)
{
    mpls_tunnel_t *mt;
    u32 mti;

    mt = mpls_tunnel_get_from_sw_if_index(sw_if_index);

    if (NULL == mt)
        return (0);

    mti = mt - mpls_tunnel_pool;

    /*
     * construct a path-list from the path provided
     */
    if (FIB_NODE_INDEX_INVALID == mt->mt_path_list)
    {
        /* can't remove a path if we have onoe */
        return (0);
    }
    else
    {
        fib_node_index_t old_pl_index;

        old_pl_index = mt->mt_path_list;

        mt->mt_path_list =
            fib_path_list_copy_and_path_remove(old_pl_index,
                                               FIB_PATH_LIST_FLAG_SHARED,
                                               rpaths);

        fib_path_list_child_remove(old_pl_index,
                                   mt->mt_sibling_index);

        if (FIB_NODE_INDEX_INVALID == mt->mt_path_list)
        {
            /* no paths left */
            return (0);
        }
        else
        {
            mt->mt_sibling_index =
                fib_path_list_child_add(mt->mt_path_list,
                                        FIB_NODE_TYPE_MPLS_TUNNEL,
                                        mti);
        }
        /*
         * find the matching path extension and remove it
         */
        fib_path_ext_list_remove(&mt->mt_path_exts,
                                  FIB_PATH_EXT_MPLS,
                                  rpaths);

        /*
         * re-resolve all the path-extensions with the new path-list
         */
        fib_path_ext_list_resolve(&mt->mt_path_exts,
                                  mt->mt_path_list);

        mpls_tunnel_restack(mt);
   }

    return (fib_path_list_get_n_paths(mt->mt_path_list));
}


static clib_error_t *
vnet_create_mpls_tunnel_command_fn (vlib_main_t * vm,
                                    unformat_input_t * input,
                                    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, * line_input = &_line_input;
    vnet_main_t * vnm = vnet_get_main();
    u8 is_del = 0, l2_only = 0, is_multicast =0;
    fib_route_path_t rpath, *rpaths = NULL;
    mpls_label_t out_label = MPLS_LABEL_INVALID;
    u32 sw_if_index = ~0;
    clib_error_t *error = NULL;

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
        else if (unformat (line_input, "add %U",
                           unformat_vnet_sw_interface, vnm,
                           &sw_if_index))
            is_del = 0;
        else if (unformat (line_input, "add"))
            is_del = 0;
        else if (unformat (line_input, "out-labels"))
	{
            while (unformat (line_input, "%U",
                             unformat_mpls_unicast_label,
                             &out_label))
            {
                vec_add1 (rpath.frp_label_stack, out_label);
            }
	}
        else if (unformat (line_input, "via %U %U",
                           unformat_ip4_address,
                           &rpath.frp_addr.ip4,
                           unformat_vnet_sw_interface, vnm,
                           &rpath.frp_sw_if_index))
        {
            rpath.frp_weight = 1;
            rpath.frp_proto = DPO_PROTO_IP4;
        }

        else if (unformat (line_input, "via %U %U",
                           unformat_ip6_address,
                           &rpath.frp_addr.ip6,
                           unformat_vnet_sw_interface, vnm,
                           &rpath.frp_sw_if_index))
        {
            rpath.frp_weight = 1;
            rpath.frp_proto = DPO_PROTO_IP6;
        }
        else if (unformat (line_input, "via %U",
                           unformat_ip6_address,
                           &rpath.frp_addr.ip6))
        {
            rpath.frp_fib_index = 0;
            rpath.frp_weight = 1;
            rpath.frp_sw_if_index = ~0;
            rpath.frp_proto = DPO_PROTO_IP6;
        }
        else if (unformat (line_input, "via %U",
                           unformat_ip4_address,
                           &rpath.frp_addr.ip4))
        {
            rpath.frp_fib_index = 0;
            rpath.frp_weight = 1;
            rpath.frp_sw_if_index = ~0;
            rpath.frp_proto = DPO_PROTO_IP4;
        }
        else if (unformat (line_input, "l2-only"))
            l2_only = 1;
        else if (unformat (line_input, "multicast"))
            is_multicast = 1;
        else
        {
            error = clib_error_return (0, "unknown input '%U'",
                                       format_unformat_error, line_input);
            goto done;
        }
    }

    vec_add1(rpaths, rpath);

    if (is_del)
    {
        if (!vnet_mpls_tunnel_path_remove(sw_if_index, rpaths))
        {
            vnet_mpls_tunnel_del(sw_if_index);
        }
    }
    else
    {
        if (0 == vec_len(rpath.frp_label_stack))
        {
            error = clib_error_return (0, "No Output Labels '%U'",
                                       format_unformat_error, line_input);
            goto done;
        }

        if (~0 == sw_if_index)
        {
            sw_if_index = vnet_mpls_tunnel_create(l2_only, is_multicast);
        }
        vnet_mpls_tunnel_path_add(sw_if_index, rpaths);
    }

done:
    vec_free(rpaths);
    unformat_free (line_input);

    return error;
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
    mpls_tunnel_attribute_t attr;

    s = format(s, "mpls_tunnel%d: sw_if_index:%d hw_if_index:%d",
               mt - mpls_tunnel_pool,
               mt->mt_sw_if_index,
               mt->mt_hw_if_index);
    if (MPLS_TUNNEL_FLAG_NONE != mt->mt_flags) {
        s = format(s, " \n flags:");
        FOR_EACH_MPLS_TUNNEL_ATTRIBUTE(attr) {
            if ((1<<attr) & mt->mt_flags) {
                s = format (s, "%s,", mpls_tunnel_attribute_names[attr]);
            }
        }
    }
    s = format(s, "\n via:\n");
    s = fib_path_list_format(mt->mt_path_list, s);
    s = format(s, "%U", format_fib_path_ext_list, &mt->mt_path_exts);
    s = format(s, "\n");

    if (mt->mt_flags & MPLS_TUNNEL_FLAG_L2)
    {
        s = format(s, " forwarding: %U\n",
                   format_fib_forw_chain_type,
                   FIB_FORW_CHAIN_TYPE_ETHERNET);
        s = format(s, " %U\n", format_dpo_id, &mt->mt_l2_lb, 2);
    }

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
