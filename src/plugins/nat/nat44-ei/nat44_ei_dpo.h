/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef __included_nat_dpo_h__
#define __included_nat_dpo_h__

#include <vnet/vnet.h>
#include <vnet/dpo/dpo.h>

void nat_dpo_create (dpo_proto_t dproto, u32 aftr_index, dpo_id_t *dpo);

u8 *format_nat_dpo (u8 *s, va_list *args);

void nat_dpo_module_init (void);

#endif /* __included_nat_dpo_h__ */
