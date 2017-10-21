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
 * The data-path object representing dropping the packet
 */

#include <vnet/dpo/dpo.h>

static dpo_id_t drop_dpos[DPO_PROTO_NUM];

const dpo_id_t *
drop_dpo_get (dpo_proto_t proto)
{
    dpo_set(&drop_dpos[proto], DPO_DROP, proto, proto);

    return (&drop_dpos[proto]);
}

int
dpo_is_drop (const dpo_id_t *dpo)
{
    return (dpo->dpoi_type == DPO_DROP);
}

static void
drop_dpo_lock (dpo_id_t *dpo)
{
    /*
     * not maintaining a lock count on the drop
     * more trouble than it's worth.
     * There always needs to be one around. no point it managaing its lifetime
     */
}
static void
drop_dpo_unlock (dpo_id_t *dpo)
{
}

static u8*
format_drop_dpo (u8 *s, va_list *ap)
{
    CLIB_UNUSED(index_t index) = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);

    return (format(s, "dpo-drop %U", format_dpo_proto, index));
}

const static dpo_vft_t drop_vft = {
    .dv_lock   = drop_dpo_lock,
    .dv_unlock = drop_dpo_unlock,
    .dv_format = format_drop_dpo,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a drop
 *        object.
 *
 * this means that these graph nodes are ones from which a drop is the
 * parent object in the DPO-graph.
 */
const static char* const drop_ip4_nodes[] =
{
    "ip4-drop",
    NULL,
};
const static char* const drop_ip6_nodes[] =
{
    "ip6-drop",
    NULL,
};
const static char* const drop_mpls_nodes[] =
{
    "mpls-drop",
    NULL,
};
const static char* const drop_ethernet_nodes[] =
{
    "error-drop",
    NULL,
};
const static char* const drop_nsh_nodes[] =
{
    "error-drop",
    NULL,
};
const static char* const drop_bier_nodes[] =
{
    "bier-drop",
    NULL,
};
const static char* const * const drop_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = drop_ip4_nodes,
    [DPO_PROTO_IP6]  = drop_ip6_nodes,
    [DPO_PROTO_MPLS] = drop_mpls_nodes,
    [DPO_PROTO_ETHERNET] = drop_ethernet_nodes,
    [DPO_PROTO_NSH] = drop_nsh_nodes,
    [DPO_PROTO_BIER] = drop_bier_nodes,
};

void
drop_dpo_module_init (void)
{
    dpo_register(DPO_DROP, &drop_vft, drop_nodes);
}
