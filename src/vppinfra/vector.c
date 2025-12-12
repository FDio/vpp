/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2005 Eliot Dresselhaus
 */

#include <vppinfra/types.h>

#if defined (__SSE2__)
u8 u32x4_compare_word_mask_table[256] = {
  [0xf0] = (1 << 1),
  [0x0f] = (1 << 0),
  [0xff] = (1 << 0) | (1 << 1),
};
#endif
