/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/**
 * @brief
 * The IP6 link-local DPO represents the lookup of a packet in the link-local
 * IPv6 FIB
 */

#ifndef __IP6_LL_DPO_H__
#define __IP6_LL_DPO_H__

#include <vnet/dpo/dpo.h>

extern const dpo_id_t *ip6_ll_dpo_get (void);

extern void ip6_ll_dpo_module_init (void);
#endif
