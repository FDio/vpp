/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/**
 * @brief A DPO to punt packets to the Control-plane
 */

#ifndef __PUNT_DPO_H__
#define __PUNT_DPO_H__

#include <vnet/dpo/dpo.h>

extern int dpo_is_punt(const dpo_id_t *dpo);

extern const dpo_id_t *punt_dpo_get(dpo_proto_t proto);

extern void punt_dpo_module_init(void);

#endif
