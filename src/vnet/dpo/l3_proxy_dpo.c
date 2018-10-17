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
 * The data-path object representing l3_proxying the packet, i.e. it's for-us
 */
#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/dpo/l3_proxy_dpo.h>

/**
 * @brief pool of all l3_proxy DPOs
 */
l3_proxy_dpo_t *l3_proxy_dpo_pool;

static l3_proxy_dpo_t *
l3_proxy_dpo_alloc (void)
{
    l3_proxy_dpo_t *l3p;

    pool_get_aligned(l3_proxy_dpo_pool, l3p, CLIB_CACHE_LINE_BYTES);
    clib_memset(l3p, 0, sizeof(*l3p));

    return (l3p);
}

static l3_proxy_dpo_t *
l3_proxy_dpo_get_from_dpo (const dpo_id_t *dpo)
{
    ASSERT(DPO_L3_PROXY == dpo->dpoi_type);

    return (l3_proxy_dpo_get(dpo->dpoi_index));
}


/*
 * l3_proxy_dpo_add_or_lock
 *
 * The next_hop address here is used for source address selection in the DP.
 * The local adj is added to an interface's l3_proxy prefix, the next-hop
 * passed here is the local prefix on the same interface.
 */
void
l3_proxy_dpo_add_or_lock (dpo_proto_t proto,
                          u32 sw_if_index,
                          dpo_id_t *dpo)
{
    l3_proxy_dpo_t *l3p;

    l3p = l3_proxy_dpo_alloc();

    l3p->l3p_sw_if_index = sw_if_index;

    dpo_set(dpo, DPO_L3_PROXY, proto, (l3p - l3_proxy_dpo_pool));
}

static void
l3_proxy_dpo_lock (dpo_id_t *dpo)
{
    l3_proxy_dpo_t *l3p;

    l3p = l3_proxy_dpo_get_from_dpo(dpo);
    l3p->l3p_locks++;
}

static void
l3_proxy_dpo_unlock (dpo_id_t *dpo)
{
    l3_proxy_dpo_t *l3p;

    l3p = l3_proxy_dpo_get_from_dpo(dpo);
    l3p->l3p_locks--;

    if (0 == l3p->l3p_locks)
    {
        pool_put(l3_proxy_dpo_pool, l3p);
    }
}

static u32
l3_proxy_dpo_get_urpf (const dpo_id_t *dpo)
{
    l3_proxy_dpo_t *l3p;

    l3p = l3_proxy_dpo_get_from_dpo(dpo);

    return (l3p->l3p_sw_if_index);
}

static u8*
format_l3_proxy_dpo (u8 *s, va_list *ap)
{
    CLIB_UNUSED(index_t index) = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    vnet_main_t * vnm = vnet_get_main();
    l3_proxy_dpo_t *l3p;

    if (pool_is_free_index(l3_proxy_dpo_pool, index))
    {
        return (format(s, "dpo-l3_proxy DELETED"));
    }

    l3p = l3_proxy_dpo_get(index);

    if (~0 != l3p->l3p_sw_if_index)
    {
        return (format(s, "dpo-l3_proxy: %U",
                       format_vnet_sw_interface_name, vnm,
                       vnet_get_sw_interface(vnm, l3p->l3p_sw_if_index)));
    }
    else
    {
        return (format(s, "dpo-l3-proxy"));
    }
}

static void
l3_proxy_dpo_mem_show (void)
{
    fib_show_memory_usage("L3 Proxy",
			  pool_elts(l3_proxy_dpo_pool),
			  pool_len(l3_proxy_dpo_pool),
			  sizeof(l3_proxy_dpo_t));
}

const static dpo_vft_t l3_proxy_vft = {
    .dv_lock = l3_proxy_dpo_lock,
    .dv_unlock = l3_proxy_dpo_unlock,
    .dv_format = format_l3_proxy_dpo,
    .dv_get_urpf = l3_proxy_dpo_get_urpf,
    .dv_mem_show = l3_proxy_dpo_mem_show,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a l3_proxy
 *        object.
 *
 * this means that these graph nodes are ones from which a l3_proxy is the
 * parent object in the DPO-graph.
 */
const static char* const l3_proxy_ip4_nodes[] =
{
    "ip4-local",
    NULL,
};
const static char* const l3_proxy_ip6_nodes[] =
{
    "ip6-local",
    NULL,
};

const static char* const * const l3_proxy_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = l3_proxy_ip4_nodes,
    [DPO_PROTO_IP6]  = l3_proxy_ip6_nodes,
    [DPO_PROTO_MPLS] = NULL,
};

void
l3_proxy_dpo_module_init (void)
{
    dpo_register(DPO_L3_PROXY, &l3_proxy_vft, l3_proxy_nodes);
}
