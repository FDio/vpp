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
 * The data-path object representing puntping the packet
 */

#include <vnet/dpo/dpo.h>

static dpo_id_t punt_dpos[DPO_PROTO_NUM];

const dpo_id_t *
punt_dpo_get (dpo_proto_t proto)
{
    dpo_set(&punt_dpos[proto], DPO_PUNT, proto, 1);

    return (&punt_dpos[proto]);
}

int
dpo_is_punt (const dpo_id_t *dpo)
{
    return (dpo->dpoi_type == DPO_PUNT);
}

static void
punt_dpo_lock (dpo_id_t *dpo)
{
    /*
     * not maintaining a lock count on the punt
     * more trouble than it's worth.
     * There always needs to be one around. no point it managaing its lifetime
     */
}
static void
punt_dpo_unlock (dpo_id_t *dpo)
{
}

static u8*
format_punt_dpo (u8 *s, va_list *ap)
{
    CLIB_UNUSED(index_t index) = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);

    return (format(s, "dpo-punt"));
}

const static dpo_vft_t punt_vft = {
    .dv_lock   = punt_dpo_lock,
    .dv_unlock = punt_dpo_unlock,
    .dv_format = format_punt_dpo,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a punt
 *        object.
 *
 * this means that these graph nodes are ones from which a punt is the
 * parent object in the DPO-graph.
 */
const static char* const punt_ip4_nodes[] =
{
    "ip4-punt",
    NULL,
};
const static char* const punt_ip6_nodes[] =
{
    "ip6-punt",
    NULL,
};
const static char* const punt_mpls_nodes[] =
{
    "mpls-punt",
    NULL,
};
const static char* const * const punt_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = punt_ip4_nodes,
    [DPO_PROTO_IP6]  = punt_ip6_nodes,
    [DPO_PROTO_MPLS] = punt_mpls_nodes,
};

void
punt_dpo_module_init (void)
{
    dpo_register(DPO_PUNT, &punt_vft, punt_nodes);
}
