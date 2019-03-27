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

#include <vnet/adj/adj_delegate.h>
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_internal.h>

/*
 * The per-type vector of virtual function tables
 */
static adj_delegate_vft_t *ad_vfts;

/**
 * The value of the last dynamically allocated delegate value
 */
static adj_delegate_type_t ad_max_id = ADJ_DELEGATE_LAST;

static adj_delegate_t *
adj_delegate_find_i (const ip_adjacency_t *adj,
                     adj_delegate_type_t type,
                     u32 *index)
{
    adj_delegate_t *delegate;
    int ii;

    ii = 0;
    vec_foreach(delegate, adj->ia_delegates)
    {
	if (delegate->ad_type == type)
	{
            if (NULL != index)
                *index = ii;

	    return (delegate);
	}
	else
	{
	    ii++;
	}
    }

    return (NULL);
}

adj_delegate_t *
adj_delegate_get (const ip_adjacency_t *adj,
                  adj_delegate_type_t type)
{
    return (adj_delegate_find_i(adj, type, NULL));
}

void
adj_delegate_remove (adj_index_t ai,
                     adj_delegate_type_t type)
{
    ip_adjacency_t *adj;
    adj_delegate_t *aed;
    u32 index = ~0;

    adj = adj_get(ai);
    aed = adj_delegate_find_i(adj, type, &index);

    ASSERT(NULL != aed);

    vec_del1(adj->ia_delegates, index);
}

static int
adj_delegate_cmp_for_sort (void * v1,
                           void * v2)
{
    adj_delegate_t *aed1 = v1, *aed2 = v2;

    return (aed1->ad_type - aed2->ad_type);
}

static void
adj_delegate_init (ip_adjacency_t *adj,
                   adj_delegate_type_t adt,
                   index_t adi)

{
    adj_delegate_t aed = {
        .ad_adj_index = adj_get_index(adj),
        .ad_type = adt,
        .ad_index = adi,
    };

    vec_add1(adj->ia_delegates, aed);
    vec_sort_with_function(adj->ia_delegates,
			   adj_delegate_cmp_for_sort);
}

int
adj_delegate_add (ip_adjacency_t *adj,
                  adj_delegate_type_t adt,
                  index_t adi)
{
    adj_delegate_t *delegate;

    delegate = adj_delegate_get(adj, adt);

    if (NULL == delegate)
    {
	adj_delegate_init(adj, adt, adi);
    }
    else
    {
        return (-1);
    }

    return (0);
}

void
adj_delegate_adj_deleted (ip_adjacency_t *adj)
{
    adj_delegate_t *aed;

    vec_foreach(aed, adj->ia_delegates)
    {
        if (ad_vfts[aed->ad_type].adv_adj_deleted)
        {
            ad_vfts[aed->ad_type].adv_adj_deleted(aed);
        }
    }

    vec_reset_length(adj->ia_delegates);
}

u8*
adj_delegate_format (u8* s, ip_adjacency_t *adj)
{
    adj_delegate_t *aed;

    vec_foreach(aed, adj->ia_delegates)
    {
        if (ad_vfts[aed->ad_type].adv_format)
        {
            s = format(s, "{");
            s = ad_vfts[aed->ad_type].adv_format(aed, s);
            s = format(s, "}");
        }
        else
        {
            s = format(s, "{unknown delegate}");
        }
    }

    return (s);
}

/**
 * adj_delegate_register_type
 *
 * Register the function table for a given type
 */
void
adj_delegate_register_type (adj_delegate_type_t type,
			    const adj_delegate_vft_t *vft)
{
    /*
     * assert that one only registration is made per-node type
     */
    if (vec_len(ad_vfts) > type)
        ASSERT(NULL == ad_vfts[type].adv_adj_deleted);

    vec_validate(ad_vfts, type);
    ad_vfts[type] = *vft;
}

/**
 * adj_delegate_register_new_type
 *
 * Register the function table for a new type
 */
adj_delegate_type_t
adj_delegate_register_new_type (const adj_delegate_vft_t *vft)
{
    adj_delegate_type_t type;

    type = ++ad_max_id;

    vec_validate(ad_vfts, type);
    ad_vfts[type] = *vft;

    return (type);
}
