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

#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/adj/rewrite.h>

/*
 * We do not lock nor unlock these DPOs since there is nothing to lock
 * all we do is construct DPO object wrappers around a sw_if_index
 */
static void
interface_tx_dpo_lock (dpo_id_t *dpo)
{
}

static void
interface_tx_dpo_unlock (dpo_id_t *dpo)
{
}

/*
 * interface_tx_dpo_add_or_lock
 *
 * construct DPO object wrappers around a sw_if_index
 */
void
interface_tx_dpo_add_or_lock (dpo_proto_t proto,
                              u32 sw_if_index,
                              dpo_id_t *dpo)
{
    dpo_set(dpo, DPO_INTERFACE_TX, proto, sw_if_index);
}

u8*
format_interface_tx_dpo (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    vnet_main_t * vnm = vnet_get_main();

    return (format(s, "%U-tx-dpo:",
                   format_vnet_sw_interface_name,
                   vnm,
                   vnet_get_sw_interface(vnm, index)));
}

static void
interface_tx_dpo_mem_show (void)
{
}

u32*
interface_tx_dpo_get_next_node (const dpo_id_t *dpo)
{
    u32 *node_indices = NULL;

    /*
     * return the interface's TX node for the wrapped sw_if_index
     */
    vec_add1(node_indices,
             vnet_tx_node_index_for_sw_interface(vnet_get_main(),
                                                 dpo->dpoi_index));

    return (node_indices);
}

const static dpo_vft_t interface_tx_dpo_vft = {
    .dv_lock = interface_tx_dpo_lock,
    .dv_unlock = interface_tx_dpo_unlock,
    .dv_format = format_interface_tx_dpo,
    .dv_mem_show = interface_tx_dpo_mem_show,
    .dv_get_next_node = interface_tx_dpo_get_next_node,
};

void
interface_tx_dpo_module_init (void)
{
    dpo_register(DPO_INTERFACE_TX, &interface_tx_dpo_vft, NULL);
}

