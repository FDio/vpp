/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/mfib/mfib_entry_delegate.h>
#include <vnet/mfib/mfib_entry.h>

static mfib_entry_delegate_t *
mfib_entry_delegate_find_i (const mfib_entry_t *mfib_entry,
                            mfib_entry_delegate_type_t type,
                            u32 *index)
{
    mfib_entry_delegate_t *delegate;
    int ii;

    ii = 0;
    vec_foreach(delegate, mfib_entry->fe_delegates)
    {
        if (delegate->mfd_type == type)
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

mfib_entry_delegate_t *
mfib_entry_delegate_get (const mfib_entry_t *mfib_entry,
                         mfib_entry_delegate_type_t type)
{
    return (mfib_entry_delegate_find_i(mfib_entry, type, NULL));
}

void
mfib_entry_delegate_remove (mfib_entry_t *mfib_entry,
                            mfib_entry_delegate_type_t type)
{
    mfib_entry_delegate_t *fed;
    u32 index = ~0;

    fed = mfib_entry_delegate_find_i(mfib_entry, type, &index);

    ASSERT(NULL != fed);

    vec_del1(mfib_entry->fe_delegates, index);
}

static int
mfib_entry_delegate_cmp_for_sort (void * v1,
                                  void * v2)
{
    mfib_entry_delegate_t *delegate1 = v1, *delegate2 = v2;

    return (delegate1->mfd_type - delegate2->mfd_type);
}

static void
mfib_entry_delegate_init (mfib_entry_t *mfib_entry,
                          mfib_entry_delegate_type_t type)

{
    mfib_entry_delegate_t delegate = {
        .mfd_entry_index = mfib_entry_get_index(mfib_entry),
        .mfd_type = type,
    };

    vec_add1(mfib_entry->fe_delegates, delegate);
    vec_sort_with_function(mfib_entry->fe_delegates,
                           mfib_entry_delegate_cmp_for_sort);
}

mfib_entry_delegate_t *
mfib_entry_delegate_find_or_add (mfib_entry_t *mfib_entry,
                                 mfib_entry_delegate_type_t fdt)
{
    mfib_entry_delegate_t *delegate;

    delegate = mfib_entry_delegate_get(mfib_entry, fdt);

    if (NULL == delegate)
    {
        mfib_entry_delegate_init(mfib_entry, fdt);
    }

    return (mfib_entry_delegate_get(mfib_entry, fdt));
}

/**
 * typedef for printing a delegate
 */
typedef u8 * (*mfib_entry_delegate_format_t)(const mfib_entry_delegate_t *fed,
                                             u8 *s);

/**
 * Print a delegate that represents cover tracking
 */
static u8 *
mfib_entry_delegate_fmt_covered (const mfib_entry_delegate_t *fed,
                                 u8 *s)
{
    s = format(s, "covered:[");
    s = fib_node_children_format(fed->mfd_list, s);
    s = format(s, "]");

    return (s);
}

/**
 * A delegate type to formatter map
 */
static mfib_entry_delegate_format_t fed_formatters[] =
{
    [MFIB_ENTRY_DELEGATE_COVERED] = mfib_entry_delegate_fmt_covered,
};

u8 *
format_mfib_entry_deletegate (u8 * s, va_list * args)
{
    mfib_entry_delegate_t *fed;

    fed = va_arg (*args, mfib_entry_delegate_t *);

    return (fed_formatters[fed->mfd_type](fed, s));
}
