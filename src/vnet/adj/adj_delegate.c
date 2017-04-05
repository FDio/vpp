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
adj_delegate_remove (ip_adjacency_t *adj,
                     adj_delegate_type_t type)
{
    adj_delegate_t *aed;
    u32 index = ~0;

    aed = adj_delegate_find_i(adj, type, &index);

    ASSERT(NULL != aed);

    vec_del1(adj->ia_delegates, index);
}

static int
adj_delegate_cmp_for_sort (void * v1,
                           void * v2)
{
    adj_delegate_t *delegate1 = v1, *delegate2 = v2;

    return (delegate1->ad_type - delegate2->ad_type);
}

static void
adj_delegate_init (ip_adjacency_t *adj,
                   adj_delegate_type_t type)

{
    adj_delegate_t delegate = {
	.ad_adj_index = adj_get_index(adj),
	.ad_type = type,
    };

    vec_add1(adj->ia_delegates, delegate);
    vec_sort_with_function(adj->ia_delegates,
			   adj_delegate_cmp_for_sort);
}

adj_delegate_t *
adj_delegate_find_or_add (ip_adjacency_t *adj,
                          adj_delegate_type_t adt)
{
    adj_delegate_t *delegate;

    delegate = adj_delegate_get(adj, adt);

    if (NULL == delegate)
    {
	adj_delegate_init(adj, adt);
    }

    return (adj_delegate_get(adj, adt));
}

/**
 * typedef for printing a delegate
 */
typedef u8 * (*adj_delegate_format_t)(const adj_delegate_t *aed,
                                      u8 *s);

/**
 * Print a delegate that represents BFD tracking
 */
static u8 *
adj_delegate_fmt_bfd (const adj_delegate_t *aed,
                      u8 *s)
{
    s = format(s, "BFD:[state:%d index:%d]",
               aed->ad_bfd_state,
               aed->ad_bfd_index);

    return (s);
}

/**
 * A delegate type to formatter map
 */
static adj_delegate_format_t aed_formatters[] =
{
    [ADJ_DELEGATE_BFD] = adj_delegate_fmt_bfd,
};

u8 *
format_adj_deletegate (u8 * s, va_list * args)
{
    adj_delegate_t *aed;

    aed = va_arg (*args, adj_delegate_t *);

    return (aed_formatters[aed->ad_type](aed, s));
}
