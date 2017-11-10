/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */

#include <vnet/vnet.h>

#include <vnet/bier/bier_types.h>
#include <vnet/bier/bier_bit_string.h>

/*
 * the first bit in the first byte is bit position 1.
 * bit position 0 is not valid
 */
#define BIER_GET_STRING_POS(_bp, _byte, _bit, _str)             \
{                                                               \
    _bp--;                                                      \
    _byte = ((BIER_BBS_LEN_TO_BUCKETS((_str)->bbs_len) - 1 ) -  \
             (_bp / BIER_BIT_MASK_BITS_PER_BUCKET));            \
    _bit = _bp % BIER_BIT_MASK_BITS_PER_BUCKET;                 \
}

static inline int
bier_bit_pos_is_valid (bier_bp_t bp,  const bier_bit_string_t *bbs)
{
    if (!((bp <= BIER_BBS_LEN_TO_BITS((bbs)->bbs_len)) &&
          (bp >= 1))) {
        return (0);
    }
    return (1);
}

/*
 * Validate a bit poistion
 */
#define BIER_BIT_POS_IS_VALID(_bp, _str)                                \
{                                                                       \
    if (!bier_bit_pos_is_valid(_bp, _str)) return;                      \
}

void
bier_bit_string_set_bit (bier_bit_string_t *bit_string,
                         bier_bp_t bp)
{
    bier_bit_mask_bucket_t bmask;
    u16 byte_pos, bit_pos;

    BIER_BIT_POS_IS_VALID(bp, bit_string);
    BIER_GET_STRING_POS(bp, byte_pos, bit_pos, bit_string);

    bmask = ((bier_bit_mask_bucket_t)1 << bit_pos);
    bit_string->bbs_buckets[byte_pos] |= bmask;
}

void
bier_bit_string_clear_bit (bier_bit_string_t *bit_string,
                           bier_bp_t bp)
{
    u16 byte_pos, bit_pos;

    BIER_BIT_POS_IS_VALID(bp, bit_string);
    BIER_GET_STRING_POS(bp, byte_pos, bit_pos, bit_string);

    bit_string->bbs_buckets[byte_pos] &= ~(1 << bit_pos);
}

u8 *
format_bier_bit_string (u8 * string,
                        va_list * args)
{
    bier_bit_string_t *bs = va_arg(*args, bier_bit_string_t *);
    int leading_marker = 0;
    int suppress_zero = 0;
    u16 index;
    u32 *ptr;

    ptr = (u32 *)bs->bbs_buckets;

    string = format(string, "%d#", (8 * bs->bbs_len));

    for (index = 0; index < (bs->bbs_len/4); index++) {
        if (!ptr[index]) {
            if (!leading_marker) {
                leading_marker = 1;
                suppress_zero = 1;
                string = format(string, ":");
                continue;
            }
            if (suppress_zero) continue;
        } else {
            suppress_zero = 0;
        }

        string = format(string, "%s%X", index ? ":" : "",
                        clib_net_to_host_u32(ptr[index]));
    }

    return (string);
}
