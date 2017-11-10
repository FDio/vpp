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

#include <vppinfra/types.h>
#include <vnet/bier/bier_types.h>
#include <vnet/bier/bier_hdr_inlines.h>

/*
 * enum to string conversions
 */
const static char* const bier_hdr_len_id_names[] = BIER_HDR_LEN_IDS;
const static char* const bier_hdr_proto_names[] = BIER_HDR_PROTO_ID_NAMES;

const static u16 bier_hdr_len_num_buckets[] = {
    [BIER_HDR_LEN_INVALID] = 0,
    [BIER_HDR_LEN_64] = 8,
    [BIER_HDR_LEN_128] = 16,
    [BIER_HDR_LEN_256] = 32,
    [BIER_HDR_LEN_512] = 64,
    [BIER_HDR_LEN_1024] = 128,
    [BIER_HDR_LEN_2048] = 256,
    [BIER_HDR_LEN_4096] = 512,
};

const static u16 bier_hdr_len_num_bits[] = {
    [BIER_HDR_LEN_INVALID] = 0,
    [BIER_HDR_LEN_64] = 64,
    [BIER_HDR_LEN_128] = 128,
    [BIER_HDR_LEN_256] = 256,
    [BIER_HDR_LEN_512] = 512,
    [BIER_HDR_LEN_1024] = 1024,
    [BIER_HDR_LEN_2048] = 2048,
    [BIER_HDR_LEN_4096] = 4096,
};

const static u16 bier_hdr_len_prefix_len[] = {
    [BIER_HDR_LEN_INVALID] = 0,
    [BIER_HDR_LEN_64] = 7,
    [BIER_HDR_LEN_128] = 8,
    [BIER_HDR_LEN_256] = 9,
    [BIER_HDR_LEN_512] = 10,
    [BIER_HDR_LEN_1024] = 11,
    [BIER_HDR_LEN_2048] = 12,
    [BIER_HDR_LEN_4096] = 13,
};

u32
bier_hdr_len_id_to_num_buckets (bier_hdr_len_id_t id)
{
    return (bier_hdr_len_num_buckets[id]);
}

u32
bier_hdr_len_id_to_num_bytes (bier_hdr_len_id_t id)
{
    return (bier_hdr_len_id_to_num_buckets(id));
}

u32
bier_hdr_len_id_to_max_bucket (bier_hdr_len_id_t id)
{
    return (bier_hdr_len_id_to_num_buckets(id) - 1);
}

u32
bier_hdr_len_id_to_num_bits (bier_hdr_len_id_t id)
{
    return (bier_hdr_len_num_bits[id]);
}

u32
bier_hdr_len_id_to_max_bit (bier_hdr_len_id_t id)
{
    return (bier_hdr_len_id_to_num_bits(id));
}

u32
bier_hdr_len_id_to_prefix_len (bier_hdr_len_id_t id)
{
    return (bier_hdr_len_prefix_len[id]);
}

u8 *
format_bier_hdr_len_id (u8 *s, va_list *ap)
{
    bier_hdr_len_id_t hli = va_arg(*ap, int); // int promotion of bier_hdr_len_id_t

    return (format(s, "%s", bier_hdr_len_id_names[hli]));
}

u8 *
format_bier_hdr_proto (u8 *s, va_list *ap)
{
    bier_hdr_proto_id_t pi = va_arg(*ap, int);

    return (format(s, "%s", bier_hdr_proto_names[pi]));
}

int
bier_table_id_cmp (const bier_table_id_t *btid1,
                   const bier_table_id_t *btid2)
{
    int res;

    res = (btid1->bti_set - btid2->bti_set);

    if (0 == res)
    {
        res  = (btid1->bti_sub_domain - btid2->bti_sub_domain);
    }
    if (0 == res)
    {
        res = (btid1->bti_ecmp - btid2->bti_ecmp);
    }
    if (0 == res)
    {
        res = (btid1->bti_hdr_len - btid2->bti_hdr_len);
    }
    if (0 == res)
    {
        res = (btid1->bti_type - btid2->bti_type);
    }
    return (res);
}

dpo_proto_t
bier_hdr_proto_to_dpo (bier_hdr_proto_id_t bproto)
{
    switch (bproto)
    {
    case BIER_HDR_PROTO_INVALID:
    case BIER_HDR_PROTO_CTRL:
    case BIER_HDR_PROTO_OAM:
        ASSERT(0);
        break;
    case BIER_HDR_PROTO_MPLS_DOWN_STREAM:
    case BIER_HDR_PROTO_MPLS_UP_STREAM:
        return (DPO_PROTO_MPLS);
    case BIER_HDR_PROTO_ETHERNET:
    case BIER_HDR_PROTO_VXLAN:
        return (DPO_PROTO_ETHERNET);
    case BIER_HDR_PROTO_IPV4:
        return (DPO_PROTO_IP4);
    case BIER_HDR_PROTO_IPV6:
        return (DPO_PROTO_IP4);
    }

    return (DPO_PROTO_NUM);
}

u8 *
format_bier_table_id (u8 *s, va_list *ap)
{
    bier_table_id_t *btid = va_arg(*ap, bier_table_id_t *);

    return (format(s, "sub-domain:%d set:%d ecmp:%d bsl:%U",
                   btid->bti_sub_domain,
                   btid->bti_set,
                   btid->bti_ecmp,
                   format_bier_hdr_len_id, btid->bti_hdr_len));
}

u8 *
format_bier_hdr (u8 *s, va_list *ap)
{
    bier_hdr_t *bh = va_arg(*ap, bier_hdr_t *);
    bier_hdr_t copy = *bh;

    bier_hdr_ntoh(&copy);

    return (format(s, "nibble:%d version:%d hdr-len:%U entropy:%d proto:%U src:%d",
                   bier_hdr_get_1st_nibble(&copy),
                   bier_hdr_get_version(&copy),
                   format_bier_hdr_len_id, bier_hdr_get_len_id(&copy),
                   bier_hdr_get_entropy(&copy),
                   format_bier_hdr_proto, bier_hdr_get_proto_id(&copy),
                   bier_hdr_get_src_id(&copy)));
}
