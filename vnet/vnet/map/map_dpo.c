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
#include <vnet/map/map_dpo.h>

/**
 * pool of all MPLS Label DPOs
 */
map_dpo_t *map_dpo_pool;

/**
 * The register MAP DPO type
 */
dpo_type_t map_dpo_type;
dpo_type_t map_t_dpo_type;

static map_dpo_t *
map_dpo_alloc (void)
{
    map_dpo_t *md;

    pool_get_aligned(map_dpo_pool, md, CLIB_CACHE_LINE_BYTES);
    memset(md, 0, sizeof(*md));

    return (md);
}

static index_t
map_dpo_get_index (map_dpo_t *md)
{
    return (md - map_dpo_pool);
}

void
map_dpo_create (dpo_proto_t dproto,
		u32 domain_index,
		dpo_id_t *dpo)
{
    map_dpo_t *md;

    md = map_dpo_alloc();
    md->md_domain = domain_index;
    md->md_proto = dproto;

    dpo_set(dpo,
	    map_dpo_type,
	    dproto,
	    map_dpo_get_index(md));
}

void
map_t_dpo_create (dpo_proto_t dproto,
		  u32 domain_index,
		  dpo_id_t *dpo)
{
    map_dpo_t *md;

    md = map_dpo_alloc();
    md->md_domain = domain_index;
    md->md_proto = dproto;

    dpo_set(dpo,
	    map_t_dpo_type,
	    dproto,
	    map_dpo_get_index(md));
}


u8*
format_map_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg (*args, index_t);
    CLIB_UNUSED(u32 indent) = va_arg (*args, u32);
    map_dpo_t *md;

    md = map_dpo_get(index);

    return (format(s, "map:[%d]:%U domain:%d",
		   index,
                   format_dpo_proto, md->md_proto,
		   md->md_domain));
}

u8*
format_map_t_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg (*args, index_t);
    CLIB_UNUSED(u32 indent) = va_arg (*args, u32);
    map_dpo_t *md;

    md = map_dpo_get(index);

    return (format(s, "map-t:[%d]:%U domain:%d",
		   index,
                   format_dpo_proto, md->md_proto,
		   md->md_domain));
}


static void
map_dpo_lock (dpo_id_t *dpo)
{
    map_dpo_t *md;

    md = map_dpo_get(dpo->dpoi_index);

    md->md_locks++;
}

static void
map_dpo_unlock (dpo_id_t *dpo)
{
    map_dpo_t *md;

    md = map_dpo_get(dpo->dpoi_index);

    md->md_locks--;

    if (0 == md->md_locks)
    {
	pool_put(map_dpo_pool, md);
    }
}

const static dpo_vft_t md_vft = {
    .dv_lock = map_dpo_lock,
    .dv_unlock = map_dpo_unlock,
    .dv_format = format_map_dpo,
};

const static char* const map_ip4_nodes[] =
{
    "ip4-map",
    NULL,
};
const static char* const map_ip6_nodes[] =
{
    "ip6-map",
    NULL,
};

const static char* const * const map_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = map_ip4_nodes,
    [DPO_PROTO_IP6]  = map_ip6_nodes,
    [DPO_PROTO_MPLS] = NULL,
};

const static dpo_vft_t md_t_vft = {
    .dv_lock = map_dpo_lock,
    .dv_unlock = map_dpo_unlock,
    .dv_format = format_map_t_dpo,
};

const static char* const map_t_ip4_nodes[] =
{
    "ip4-map-t",
    NULL,
};
const static char* const map_t_ip6_nodes[] =
{
    "ip6-map-t",
    NULL,
};

const static char* const * const map_t_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = map_t_ip4_nodes,
    [DPO_PROTO_IP6]  = map_t_ip6_nodes,
    [DPO_PROTO_MPLS] = NULL,
};

void
map_dpo_module_init (void)
{
    map_dpo_type = dpo_register_new_type(&md_vft, map_nodes);
    map_t_dpo_type = dpo_register_new_type(&md_t_vft, map_t_nodes);
}
