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

#include <vnet/tunnel/tunnel.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/fib_walk.h>

/**
 * Tunnel Key. source and desintation address in an IP-table.
 * This struct is purposely arragned with no padding so it can be
 * safely hashed.
 */
typedef struct tunnel_key_t_
{
    /**
     * Tunnel Source address
     */
    ip46_address_t tk_src;

    /**
     * Tunnel destination address
     */
    ip46_address_t tk_dst;

    /**
     * IP FIB index
     */
    u32 tk_fib_index;
} tunnel_key_t;

/**
 * Endpoint tunnel information.
 */
typedef struct tunnel_ep_t_
{
    /**
     * The FIB entry tracking data
     */
    fib_trkr_t te_trkr;

    /**
     * the DPO ID used for insertion. Allows us to track changes.
     * Which should never happen
     */
    u32 te_dpoi;
} tunnel_ep_t;

/**
 * A tunnel representation
 */
typedef struct tunnel_t_
{
    /**
     * Node for linkage into the FIB graph
     */
    fib_node_t t_node;

    /**
     * Tunnel's key in the hash DB
     * This is not inline in the struct so since the tunnel object
     * is subject to realloc.
     */
    tunnel_key_t *t_key;

    /**
     * Source tunnel endpoint info
     */
    tunnel_ep_t t_src;

    /**
     * Destination tunnel endpoint info
     */
    tunnel_ep_t t_dst;

    /**
     * The unique and constant ID.
     */
    tunnel_id_t t_id;
} tunnel_t;

/**
 * The hash table of all IP tunnels, keyed on the src,dst IP addresses
 */
static uword *tunnel_db;

/**
 * A pool of all the tunnels
 */
static tunnel_t *tunnel_pool;

static index_t
tunnel_get_index (const tunnel_t *tunnel)
{
    return (tunnel - tunnel_pool);
}

static tunnel_t *
tunnel_get (index_t tunnel_index)
{
    return (pool_elt_at_index(tunnel_pool, tunnel_index));
}

tunnel_id_t
tunnel_get_id (index_t tunnel_index)
{
    tunnel_t *tunnel = tunnel_get(tunnel_index);

    return (tunnel->t_id);
}

fib_node_index_t
tunnel_dst_fib_entry(index_t tunnel_index)
{
    tunnel_t *tunnel;

    tunnel = pool_elt_at_index(tunnel_pool, tunnel_index);

    return (tunnel->t_dst.te_trkr.ftk_fei);
}

void tunnel_unlock(index_t tunnel_index)
{
    tunnel_t *tunnel = tunnel_get(tunnel_index);

    fib_node_unlock(&tunnel->t_node);
}

/**
 * Get the receive DPO ID from the RX FIB entry
 */
static index_t
tunnel_decap_get_rx_index (const tunnel_t *tunnel)
{
    const dpo_id_t *ip_dpo, *rx_dpo;
    const load_balance_t *lb;

    ip_dpo = fib_entry_contribute_ip_forwarding(tunnel->t_src.te_trkr.ftk_fei);

    lb = load_balance_get (ip_dpo->dpoi_index);
    rx_dpo = load_balance_get_bucket_i (lb, 0);

    if (rx_dpo->dpoi_type == DPO_RECEIVE)
    {
        return (rx_dpo->dpoi_index);
    }

    return (INDEX_INVALID);
}

/**
 * Get the TX load-balance ID from the TX FIB entry
 */
static index_t
tunnel_decap_get_tx_index (const tunnel_t *tunnel)
{
    const dpo_id_t *ip_dpo;

    ip_dpo = fib_entry_contribute_ip_forwarding(tunnel->t_dst.te_trkr.ftk_fei);

    return (ip_dpo->dpoi_index);
}

/**
 * Build a tunnel ID from the RX and TX indecies
 */
static tunnel_id_t
tunnel_build_id (tunnel_t *tunnel)
{
    tunnel->t_src.te_dpoi = tunnel_decap_get_rx_index (tunnel);
    tunnel->t_dst.te_dpoi = tunnel_decap_get_tx_index (tunnel);

    /*
     * The RX ID is the recieve DPO index - we expect this to
     * be less than 64k
     * the TX ID loses one nibble to allow the user allocated
     * part of the ID to be 20 bits
     */
    if ((0xffff0000 & tunnel->t_src.te_dpoi) ||
        (0xf0000000 & tunnel->t_dst.te_dpoi))
    {
        return (~0);
    }

    return (tunnel_mk_id(tunnel->t_src.te_dpoi,
                         tunnel->t_dst.te_dpoi));
}

static index_t
tunnel_find_i (u32 fib_index,
               const ip46_address_t *src,
               const ip46_address_t *dst,
               tunnel_key_t *key)
{
    uword *p;

    key->tk_src = *src;
    key->tk_dst = *dst;
    key->tk_fib_index = fib_index;

    p = hash_get_mem(tunnel_db, key);

    if (NULL != p)
    {
        return (p[0]);
    }

    return (INDEX_INVALID);
}

index_t
tunnel_find (u32 fib_index,
             const ip46_address_t *src,
             const ip46_address_t *dst)
{
    tunnel_key_t key;

    return (tunnel_find_i(fib_index, src, dst, &key));
}

index_t
tunnel_add_or_lock (u32 fib_index,
                    const ip46_address_t *src,
                    const ip46_address_t *dst)
{
    /*
     * construct the key and serach the DB
     */
    tunnel_key_t key;
    tunnel_t *tunnel;
    tunnel_id_t tid;

    tid = tunnel_find_i(fib_index, src, dst, &key);

    if (INDEX_INVALID != tid)
    {
        /*
         * A tunnel already exists matching this key.
         * Bump the ref count and return the ID.
         */
        tunnel = pool_elt_at_index(tunnel_pool, tid);
    }
    else
    {
        /*
         * new tunnel.
         * allocate a new tunnel object, copy in the key, add
         * to the DB
         */
        pool_get(tunnel_pool, tunnel);
        tid = tunnel - tunnel_pool;

        tunnel->t_key = clib_mem_alloc(sizeof(tunnel_key_t));
        clib_memcpy(tunnel->t_key, &key, sizeof(tunnel_key_t));
        hash_set_mem(tunnel_db, tunnel->t_key, tid);

        fib_node_init(&tunnel->t_node,
                      FIB_NODE_TYPE_TUNNEL);

        /*
         * Setup the source and destination FIB entry tracking
         */
        fib_trkr_addr_add(tunnel->t_key->tk_fib_index,
                          &tunnel->t_key->tk_src,
                          FIB_NODE_TYPE_TUNNEL,
                          tid,
                          &tunnel->t_src.te_trkr);
        fib_trkr_addr_add(tunnel->t_key->tk_fib_index,
                          &tunnel->t_key->tk_dst,
                          FIB_NODE_TYPE_TUNNEL,
                          tid,
                          &tunnel->t_dst.te_trkr);

        /*
         * build the unique, and constant, ID
         */
        tunnel->t_id = tunnel_build_id(tunnel);
    }

    fib_node_lock(&tunnel->t_node);

    return (tid);
}

static tunnel_t*
tunnel_from_fib_node (fib_node_t *node)
{
    return ((tunnel_t*)(((char*)node) -
                        STRUCT_OFFSET_OF(tunnel_t, t_node)));
}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
tunnel_back_walk (fib_node_t *node,
                  fib_node_back_walk_ctx_t *ctx)
{
    tunnel_t *tunnel;

    tunnel = tunnel_from_fib_node(node);

    /*
     * propagate the backwalk further
     */
    fib_walk_sync(FIB_NODE_TYPE_TUNNEL,
		  tunnel_get_index(tunnel),
		  ctx);

    return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t*
tunnel_fib_node_get (fib_node_index_t index)
{
    tunnel_t *tunnel;

    tunnel = pool_elt_at_index(tunnel_pool, index);

    return (&tunnel->t_node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
tunnel_last_lock_gone (fib_node_t *node)
{
    /*
     * No more tunnel protocols need this tunnel; delete it
     */
    tunnel_t *tunnel;

    tunnel = tunnel_from_fib_node(node);

    hash_unset_mem(tunnel_db, tunnel->t_key);
    clib_mem_free(tunnel->t_key);

    fib_trkr_release(&tunnel->t_src.te_trkr);
    fib_trkr_release(&tunnel->t_dst.te_trkr);

    pool_put(tunnel_pool, tunnel);
}

/*
 * Virtual function table registered by tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t tunnel_vft = {
    .fnv_get = tunnel_fib_node_get,
    .fnv_last_lock = tunnel_last_lock_gone,
    .fnv_back_walk = tunnel_back_walk,
};

clib_error_t *tunnel_db_init (vlib_main_t *vm)
{
    fib_node_register_type(FIB_NODE_TYPE_TUNNEL, &tunnel_vft);
    tunnel_db = hash_create_mem (0,
                                 sizeof(tunnel_key_t),
                                 sizeof(uword));

    return (NULL);
}

VLIB_INIT_FUNCTION(tunnel_db_init);

u8 *
format_tunnel (u8 * s, va_list * args)
{
    index_t ti = va_arg (*args, index_t);
    tunnel_t *t;

    t = pool_elt_at_index(tunnel_pool, ti);
    
    s = format (s,
                "[%d] ID:0x%lx fib:%d src:%U dst:%U decap:[rx:[fei:%d recv:%d] tx:[fei:%d recv:%d]] locks:%d",
                t - tunnel_pool,
                t->t_id,
                t->t_key->tk_fib_index,
                format_ip46_address, &t->t_key->tk_src, IP46_TYPE_ANY,
                format_ip46_address, &t->t_key->tk_dst, IP46_TYPE_ANY,
                t->t_src.te_trkr.ftk_fei,
                t->t_src.te_dpoi,
                t->t_dst.te_trkr.ftk_fei,
                t->t_dst.te_dpoi,
                t->t_node.fn_locks);

    return s;
}

static clib_error_t *
show_tunnel_command_fn (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd)
{
    tunnel_t * t;
    u32 ti = ~0;

    if (pool_elts (tunnel_pool) == 0)
    {
        vlib_cli_output (vm, "No tunnels configured...");
    }

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "%d", &ti))
            ;
        else
            break;
    }

    if (~0 == ti)
    {
        pool_foreach (t, tunnel_pool,
        ({
            vlib_cli_output (vm, "%U", format_tunnel, tunnel_get_index(t));
        }));
    }
    else
    {
        t = pool_elt_at_index(tunnel_pool, ti);

        vlib_cli_output (vm, "%U", format_tunnel, tunnel_get_index(t));
    }

    return 0;
}

VLIB_CLI_COMMAND (show_tunnel_command, static) = {
    .path = "show tunnel",
    .function = show_tunnel_command_fn,
};
