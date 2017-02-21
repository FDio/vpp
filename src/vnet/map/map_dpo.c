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
 * The register MAP DPO type
 */
dpo_type_t map_dpo_type;
dpo_type_t map_t_dpo_type;

void
map_dpo_create (dpo_proto_t dproto,
		u32 domain_index,
		dpo_id_t *dpo)
{
    dpo_set(dpo,
	    map_dpo_type,
	    dproto,
	    domain_index);
}

void
map_t_dpo_create (dpo_proto_t dproto,
		  u32 domain_index,
		  dpo_id_t *dpo)
{
    dpo_set(dpo,
	    map_t_dpo_type,
	    dproto,
	    domain_index);
}


u8*
format_map_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg (*args, index_t);
    CLIB_UNUSED(u32 indent) = va_arg (*args, u32);

    return (format(s, "map: domain:%d", index));
}

u8*
format_map_t_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg (*args, index_t);
    CLIB_UNUSED(u32 indent) = va_arg (*args, u32);

    return (format(s, "map-t: domain:%d", index));
}


static void
map_dpo_lock (dpo_id_t *dpo)
{
}

static void
map_dpo_unlock (dpo_id_t *dpo)
{
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
