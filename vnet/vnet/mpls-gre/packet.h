#ifndef included_vnet_mpls_packet_h
#define included_vnet_mpls_packet_h

/*
 * MPLS packet format
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

typedef struct {
    /* Label: top 20 bits [in network byte order] */
    /* Experimental: 3 bits ... */
    /* S (bottom of label stack): 1 bit */
    /* TTL: 8 bits */
    u32 label_exp_s_ttl;
} mpls_unicast_header_t;

static inline u32 vnet_mpls_uc_get_label (u32 label_exp_s_ttl)
{
    return (label_exp_s_ttl>>12);
}

static inline u32 vnet_mpls_uc_get_exp (u32 label_exp_s_ttl)
{
    return ((label_exp_s_ttl>>9) & 0x7);
}

static inline u32 vnet_mpls_uc_get_s (u32 label_exp_s_ttl)
{
    return ((label_exp_s_ttl>>8) & 0x1);
}

static inline u32 vnet_mpls_uc_get_ttl (u32 label_exp_s_ttl)
{
    return (label_exp_s_ttl & 0xff);
}

#endif /* included_vnet_mpls_packet_h */
