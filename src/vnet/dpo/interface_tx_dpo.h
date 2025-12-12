/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
