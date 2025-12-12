/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef __BIER_BIT_STRING_H__
#define __BIER_BIT_STRING_H__

#include <vppinfra/byte_order.h>
#include <vppinfra/format.h>

#include <vnet/bier/bier_types.h>

#define BIER_BBS_LEN_TO_BUCKETS(_len) (_len)
#define BIER_BBS_LEN_TO_BITS(_len) (_len * 8)
#define BIER_BBS_LEN_TO_INTS(_len) ((_len) / sizeof(int))
#define BIER_BIT_MASK_BITS_PER_INT (sizeof(int) * 8)

/*
 * bier_find_first_bit_set
 *
 * find the position of the first bit set in a long
 */
static inline int
bier_find_first_bit_string_set (int mask)
{
    return (__builtin_ffs(clib_net_to_host_u32(mask)));
}

extern void bier_bit_string_set_bit(bier_bit_string_t *mask,
                                    bier_bp_t bp);


extern void bier_bit_string_clear_bit(bier_bit_string_t *mask,
                                      bier_bp_t bp);


extern u8 *format_bier_bit_string(u8 * s, va_list * args);

#define BIER_BBS_NUM_INT_BUCKETS(_bbs) \
    (BIER_BBS_LEN_TO_BUCKETS(_bbs->bbs_len) / sizeof(int))

always_inline int
bier_bit_string_is_zero (const bier_bit_string_t *src)
{
    u16 index;

    for (index = 0;
         index < BIER_BBS_NUM_INT_BUCKETS(src);
         index++) {
        if (((int*)src->bbs_buckets)[index] != 0) {
            return (0);
        }
    }
    return (1);
}

always_inline void
bier_bit_string_clear_string (const bier_bit_string_t *src,
                              bier_bit_string_t *dest)
{
    u16 index;

    ASSERT(src->bbs_len == dest->bbs_len);

    for (index = 0;
         index < BIER_BBS_NUM_INT_BUCKETS(src);
         index++) {
        ((int*)dest->bbs_buckets)[index] &= ~(((int*)src->bbs_buckets)[index]);
    }
}

always_inline void
bier_bit_string_logical_and_string (const bier_bit_string_t *src,
                                    bier_bit_string_t *dest)
{
    u16 index;

    ASSERT(src->bbs_len == dest->bbs_len);

    for (index = 0;
         index < BIER_BBS_NUM_INT_BUCKETS(src);
         index++) {
        ((int*)dest->bbs_buckets)[index] &= ((int*)src->bbs_buckets)[index];
    }
}

always_inline void
bier_bit_string_init (bier_bit_string_t *bbs,
                      bier_hdr_len_id_t len,
                      bier_bit_mask_bucket_t *buckets)
{
    bbs->bbs_len = bier_hdr_len_id_to_num_bytes(len);
    bbs->bbs_buckets = buckets;
}

#endif
