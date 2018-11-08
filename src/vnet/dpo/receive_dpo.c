/*
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
 * @brief
 * The data-path object representing receiveing the packet, i.e. it's for-us
 */
#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/dpo/receive_dpo.h>

/**
 * @brief pool of all receive DPOs
 */
receive_dpo_t *receive_dpo_pool;

static receive_dpo_t *
receive_dpo_alloc (void)
{
    receive_dpo_t *rd;

    pool_get_aligned(receive_dpo_pool, rd, CLIB_CACHE_LINE_BYTES);
    memset(rd, 0, sizeof(*rd));

    return (rd);
}

static receive_dpo_t *
receive_dpo_get_from_dpo (const dpo_id_t *dpo)
{
    ASSERT(DPO_RECEIVE == dpo->dpoi_type);

    return (receive_dpo_get(dpo->dpoi_index));
}


/*
 * receive_dpo_add_or_lock
 *
 * The next_hop address here is used for source address selection in the DP.
 * The local adj is added to an interface's receive prefix, the next-hop
 * passed here is the local prefix on the same interface.
 */
void
receive_dpo_add_or_lock (dpo_proto_t proto,
                         u32 sw_if_index,
                         const ip46_address_t *nh_addr,
                         dpo_id_t *dpo)
{
    receive_dpo_t *rd;

    rd = receive_dpo_alloc();

    rd->rd_sw_if_index = sw_if_index;
    if (NULL != nh_addr)
    {
	rd->rd_addr = *nh_addr;
    }

    dpo_set(dpo, DPO_RECEIVE, proto, (rd - receive_dpo_pool));
}

static void
receive_dpo_lock (dpo_id_t *dpo)
{
    receive_dpo_t *rd;

    rd = receive_dpo_get_from_dpo(dpo);
    rd->rd_locks++;
}

static void
receive_dpo_unlock (dpo_id_t *dpo)
{
    receive_dpo_t *rd;

    rd = receive_dpo_get_from_dpo(dpo);
    rd->rd_locks--;

    if (0 == rd->rd_locks)
    {
        pool_put(receive_dpo_pool, rd);
    }
}

static u8*
format_receive_dpo (u8 *s, va_list *ap)
{
    CLIB_UNUSED(index_t index) = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    vnet_main_t * vnm = vnet_get_main();
    receive_dpo_t *rd;

    if (pool_is_free_index(receive_dpo_pool, index))
    {
        return (format(s, "dpo-receive DELETED"));
    }

    rd = receive_dpo_get(index);

    if (~0 != rd->rd_sw_if_index)
    {
        return (format(s, "dpo-receive: %U on %U",
                       format_ip46_address, &rd->rd_addr, IP46_TYPE_ANY,
                       format_vnet_sw_interface_name, vnm,
                       vnet_get_sw_interface(vnm, rd->rd_sw_if_index)));
    }
    else
    {
        return (format(s, "dpo-receive"));
    }
}

static void
receive_dpo_mem_show (void)
{
    fib_show_memory_usage("Receive",
			  pool_elts(receive_dpo_pool),
			  pool_len(receive_dpo_pool),
			  sizeof(receive_dpo_t));
}

const static dpo_vft_t receive_vft = {
    .dv_lock = receive_dpo_lock,
    .dv_unlock = receive_dpo_unlock,
    .dv_format = format_receive_dpo,
    .dv_mem_show = receive_dpo_mem_show,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a receive
 *        object.
 *
 * this means that these graph nodes are ones from which a receive is the
 * parent object in the DPO-graph.
 */
const static char* const receive_ip4_nodes[] =
{
    "ip4-local",
    NULL,
};
const static char* const receive_ip6_nodes[] =
{
    "ip6-local",
    NULL,
};

const static char* const * const receive_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = receive_ip4_nodes,
    [DPO_PROTO_IP6]  = receive_ip6_nodes,
    [DPO_PROTO_MPLS] = NULL,
};

void
receive_dpo_module_init (void)
{
    dpo_register(DPO_RECEIVE, &receive_vft, receive_nodes);
}
