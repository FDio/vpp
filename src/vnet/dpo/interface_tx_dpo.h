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
 * The data-path object representing transmitting the packet on a n interface.
 * This is a convenient DPO wrapper around a simple interface transmit and thus
 * allows us to represent direct interface transmit in the DPO model.
 */

#ifndef __INTERFACE_TX_DPO_H__
#define __INTERFACE_TX_DPO_H__

#include <vnet/dpo/dpo.h>

extern void interface_tx_dpo_add_or_lock (dpo_proto_t proto,
                                          u32 sw_if_index,
                                          dpo_id_t *dpo);

extern void interface_tx_dpo_module_init(void);

#endif
