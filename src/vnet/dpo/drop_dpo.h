/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/**
 * @brief The Drop DPO will drop all packets, no questions asked. It is valid
 * for any packet protocol.
 */

#ifndef __DROP_DPO_H__
#define __DROP_DPO_H__

#include <vnet/dpo/dpo.h>

extern int dpo_is_drop(const dpo_id_t *dpo);

extern const dpo_id_t *drop_dpo_get(dpo_proto_t proto);

extern void drop_dpo_module_init(void);

#endif
