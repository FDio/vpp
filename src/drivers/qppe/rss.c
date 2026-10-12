/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

vnet_dev_rv_t
qppe_rss_init (vnet_dev_t *dev)
{
  u32 seed = clib_cpu_time_now ();

  const qppe_reg_val_t rv[] = {
    { .off = HPPE_REG_RSS_HASH_MASK, .val = 0xfff },
    { .off = HPPE_REG_RSS_HASH_MASK_IPV4, .val = 0xfff },
    { .off = HPPE_REG_RSS_HASH_SEED, .val = seed },
    { .off = HPPE_REG_RSS_HASH_SEED_IPV4, .val = seed },
    { .off = HPPE_REG_RSS_HASH_MIX (0), .val = 0x13 },
    { .off = HPPE_REG_RSS_HASH_MIX (1), .val = 0xb },
    { .off = HPPE_REG_RSS_HASH_MIX (2), .val = 0x13 },
    { .off = HPPE_REG_RSS_HASH_MIX (3), .val = 0xb },
    { .off = HPPE_REG_RSS_HASH_MIX (4), .val = 0x13 },
    { .off = HPPE_REG_RSS_HASH_MIX (5), .val = 0xb },
    { .off = HPPE_REG_RSS_HASH_MIX (6), .val = 0x13 },
    { .off = HPPE_REG_RSS_HASH_MIX (7), .val = 0xb },
    { .off = HPPE_REG_RSS_HASH_MIX (8), .val = 0x13 },
    { .off = HPPE_REG_RSS_HASH_MIX (9), .val = 0xb },
    { .off = HPPE_REG_RSS_HASH_MIX (10), .val = 0x13 },
    { .off = HPPE_REG_RSS_HASH_MIX_IPV4 (0), .val = 0x13 },
    { .off = HPPE_REG_RSS_HASH_FIN (0), .val = 0x205 },
    { .off = HPPE_REG_RSS_HASH_FIN_IPV4 (0), .val = 0x205 },
    { .off = HPPE_REG_RSS_HASH_MIX_IPV4 (1), .val = 0xb },
    { .off = HPPE_REG_RSS_HASH_FIN (1), .val = 0x264 },
    { .off = HPPE_REG_RSS_HASH_FIN_IPV4 (1), .val = 0x264 },
    { .off = HPPE_REG_RSS_HASH_MIX_IPV4 (2), .val = 0x13 },
    { .off = HPPE_REG_RSS_HASH_FIN (2), .val = 0x227 },
    { .off = HPPE_REG_RSS_HASH_FIN_IPV4 (2), .val = 0x227 },
    { .off = HPPE_REG_RSS_HASH_MIX_IPV4 (3), .val = 0xb },
    { .off = HPPE_REG_RSS_HASH_FIN (3), .val = 0x245 },
    { .off = HPPE_REG_RSS_HASH_FIN_IPV4 (3), .val = 0x245 },
    { .off = HPPE_REG_RSS_HASH_MIX_IPV4 (4), .val = 0x13 },
    { .off = HPPE_REG_RSS_HASH_FIN (4), .val = 0x201 },
    { .off = HPPE_REG_RSS_HASH_FIN_IPV4 (4), .val = 0x201 },
  };

  return qppe_mmio_write_validate (dev, rv, ARRAY_LEN (rv));
}
