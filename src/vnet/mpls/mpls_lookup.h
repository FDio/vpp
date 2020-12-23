/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __MPLS_LOOKUP_H__
#define __MPLS_LOOKUP_H__

#include <vnet/mpls/mpls.h>
#include <vnet/ip/ip.h>
#include <vnet/bier/bier_fwd.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

/**
 * The arc/edge from the MPLS lookup node to the MPLS replicate node
 */
extern u32 mpls_lookup_to_replicate_edge;

/**
 * Enum of statically configred MPLS lookup next nodes
 */
typedef enum mpls_lookup_next_t_
{
    MPLS_LOOKUP_NEXT_DROP = 0,
} mpls_lookup_next_t;

/*
 * Compute flow hash. 
 * We'll use it to select which adjacency to use for this flow.  And other things.
 */
always_inline u32
mpls_compute_flow_hash (const mpls_unicast_header_t * hdr,
                        flow_hash_config_t flow_hash_config)
{
    /*
     * We need to byte swap so we use the numerical value. i.e. an odd label
     * leads to an odd bucket. as opposed to a label above and below value X.
     */
    u8 next_label_is_entropy;
    mpls_label_t ho_label;
    u32 hash, value;

    ho_label = clib_net_to_host_u32(hdr->label_exp_s_ttl);
    hash = vnet_mpls_uc_get_label(ho_label);
    next_label_is_entropy = 0;

    while (MPLS_EOS != vnet_mpls_uc_get_s(ho_label))
    {
        hdr++;
        ho_label = clib_net_to_host_u32(hdr->label_exp_s_ttl);
        value = vnet_mpls_uc_get_label(ho_label);

        if (1 == next_label_is_entropy)
        {
            /*
             * The label is an entropy value, use it alone as the hash
             */
            return (ho_label);
        }
        if (MPLS_IETF_ENTROPY_LABEL == value)
        {
            /*
             * we've met a label in the stack indicating that tha next
             * label is an entropy value
             */
            next_label_is_entropy = 1;
        }
        else
        {
            /*
             * XOR the label values in the stack together to
             * build up the hash value
             */
            hash ^= value;
        }
    }

    /*
     * check the top nibble for v4 and v6
     */
    hdr++;

    switch (((u8*)hdr)[0] >> 4)
    {
    case 4:
        /* incorporate the v4 flow-hash */
	hash ^=
	  ip4_compute_flow_hash ((const ip4_header_t *) hdr, flow_hash_config);
	break;
    case 6:
        /* incorporate the v6 flow-hash */
	hash ^=
	  ip6_compute_flow_hash ((const ip6_header_t *) hdr, flow_hash_config);
	break;
    case 5:
        /* incorporate the bier flow-hash */
        hash ^= bier_compute_flow_hash ((const bier_hdr_t *)hdr);
        break;
    default:
        break;
    }

    return (hash);
}

#endif /* __MPLS_LOOKUP_H__ */
