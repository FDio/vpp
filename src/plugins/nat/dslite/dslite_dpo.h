/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef __included_dslite_dpo_h__
#define __included_dslite_dpo_h__

#include <vnet/vnet.h>
#include <vnet/dpo/dpo.h>

void dslite_dpo_create (dpo_proto_t dproto, u32 aftr_index, dpo_id_t * dpo);
void dslite_ce_dpo_create (dpo_proto_t dproto, u32 b4_index, dpo_id_t * dpo);

u8 *format_dslite_dpo (u8 * s, va_list * args);
u8 *format_dslite_ce_dpo (u8 * s, va_list * args);

void dslite_dpo_module_init (void);

#endif /* __included_dslite_dpo_h__ */
