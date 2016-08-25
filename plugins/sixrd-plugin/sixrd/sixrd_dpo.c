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

#include "sixrd_dpo.h"
#include <vnet/ip/ip.h>

/**
 * pool of all MPLS Label DPOs
 */
sixrd_dpo_t *sixrd_dpo_pool;

/**
 * The register SIXRD DPO type
 */
dpo_type_t sixrd_dpo_type;

static sixrd_dpo_t *
sixrd_dpo_alloc (void)
{
    sixrd_dpo_t *sd;

    pool_get_aligned(sixrd_dpo_pool, sd, CLIB_CACHE_LINE_BYTES);
    memset(sd, 0, sizeof(*sd));

    return (sd);
}

static index_t
sixrd_dpo_get_index (sixrd_dpo_t *sd)
{
    return (sd - sixrd_dpo_pool);
}

void
sixrd_dpo_create (dpo_proto_t dproto,
		u32 domain_index,
		dpo_id_t *dpo)
{
    sixrd_dpo_t *sd;

    sd = sixrd_dpo_alloc();
    sd->sd_domain = domain_index;
    sd->sd_proto = dproto;

    dpo_set(dpo,
	    sixrd_dpo_type,
	    dproto,
	    sixrd_dpo_get_index(sd));
}

u8*
format_sixrd_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg (*args, index_t);
    CLIB_UNUSED(u32 indent) = va_arg (*args, u32);
    sixrd_dpo_t *sd;

    sd = sixrd_dpo_get(index);

    return (format(s, "sixrd:[%d]:%U domain:%d",
		   index,
                   format_dpo_proto, sd->sd_proto,
		   sd->sd_domain));
}


static void
sixrd_dpo_lock (dpo_id_t *dpo)
{
    sixrd_dpo_t *sd;

    sd = sixrd_dpo_get(dpo->dpoi_index);

    sd->sd_locks++;
}

static void
sixrd_dpo_unlock (dpo_id_t *dpo)
{
    sixrd_dpo_t *sd;

    sd = sixrd_dpo_get(dpo->dpoi_index);

    sd->sd_locks--;

    if (0 == sd->sd_locks)
    {
	pool_put(sixrd_dpo_pool, sd);
    }
}

const static dpo_vft_t sd_vft = {
    .dv_lock = sixrd_dpo_lock,
    .dv_unlock = sixrd_dpo_unlock,
    .dv_format = format_sixrd_dpo,
};

const static char* const sixrd_ip4_nodes[] =
{
    "ip4-sixrd",
    NULL,
};
const static char* const sixrd_ip6_nodes[] =
{
    "ip6-sixrd",
    NULL,
};

const static char* const * const sixrd_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = sixrd_ip4_nodes,
    [DPO_PROTO_IP6]  = sixrd_ip6_nodes,
    [DPO_PROTO_MPLS] = NULL,
};

void
sixrd_dpo_module_init (void)
{
    sixrd_dpo_type = dpo_register_new_type(&sd_vft, sixrd_nodes);
}
