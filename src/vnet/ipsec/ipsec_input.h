/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef IPSEC_INPUT_H
#define IPSEC_INPUT_H

#include <vppinfra/types.h>
#include <vnet/ipsec/ipsec_spd.h>
#include <vnet/ipsec/ipsec_spd_fp_lookup.h>

always_inline void
ipsec_fp_in_5tuple_from_ip4_range (ipsec_fp_5tuple_t *tuple, u32 la, u32 ra,
				   u32 spi, u8 action)
{
  clib_memset (tuple->l3_zero_pad, 0, sizeof (tuple->l3_zero_pad));
  tuple->laddr.as_u32 = la;
  tuple->raddr.as_u32 = ra;
  tuple->spi = spi;
  tuple->action = action;
  tuple->is_ipv6 = 0;
}

#endif /* !IPSEC_INPUT_H */
