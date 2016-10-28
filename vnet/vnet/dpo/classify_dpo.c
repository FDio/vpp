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

#include <vnet/ip/ip.h>
#include <vnet/dpo/classify_dpo.h>
#include <vnet/mpls/mpls.h>

/*
 * pool of all MPLS Label DPOs
 */
classify_dpo_t *classify_dpo_pool;

static classify_dpo_t *
classify_dpo_alloc (void)
{
    classify_dpo_t *cd;

    pool_get_aligned(classify_dpo_pool, cd, CLIB_CACHE_LINE_BYTES);
    memset(cd, 0, sizeof(*cd));

    return (cd);
}

static index_t
classify_dpo_get_index (classify_dpo_t *cd)
{
    return (cd - classify_dpo_pool);
}

index_t
classify_dpo_create (dpo_proto_t proto,
                     u32 classify_table_index)
{
    classify_dpo_t *cd;

    cd = classify_dpo_alloc();
    cd->cd_proto = proto;
    cd->cd_table_index = classify_table_index;

    return (classify_dpo_get_index(cd));
}

u8*
format_classify_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg (*args, index_t);
    CLIB_UNUSED(u32 indent) = va_arg (*args, u32);
    classify_dpo_t *cd;

    cd = classify_dpo_get(index);

    return (format(s, "%U-classify:[%d]:table:%d",
		   format_dpo_proto, cd->cd_proto,
		   index, cd->cd_table_index));
}

static void
classify_dpo_lock (dpo_id_t *dpo)
{
    classify_dpo_t *cd;

    cd = classify_dpo_get(dpo->dpoi_index);

    cd->cd_locks++;
}

static void
classify_dpo_unlock (dpo_id_t *dpo)
{
    classify_dpo_t *cd;

    cd = classify_dpo_get(dpo->dpoi_index);

    cd->cd_locks--;

    if (0 == cd->cd_locks)
    {
	pool_put(classify_dpo_pool, cd);
    }
}

static void
classify_dpo_mem_show (void)
{
    fib_show_memory_usage("Classify",
			  pool_elts(classify_dpo_pool),
			  pool_len(classify_dpo_pool),
			  sizeof(classify_dpo_t));
}

const static dpo_vft_t cd_vft = {
    .dv_lock = classify_dpo_lock,
    .dv_unlock = classify_dpo_unlock,
    .dv_format = format_classify_dpo,
    .dv_mem_show = classify_dpo_mem_show,
};

const static char* const classify_ip4_nodes[] =
{
    "ip4-classify",
    NULL,
};
const static char* const classify_ip6_nodes[] =
{
    "ip6-classify",
    NULL,
};
const static char* const * const classify_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = classify_ip4_nodes,
    [DPO_PROTO_IP6]  = classify_ip6_nodes,
    [DPO_PROTO_MPLS] = NULL,
};

void
classify_dpo_module_init (void)
{
    dpo_register(DPO_CLASSIFY, &cd_vft, classify_nodes);
}
