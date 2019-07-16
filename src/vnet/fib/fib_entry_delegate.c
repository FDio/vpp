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

#include <vnet/fib/fib_entry_delegate.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_attached_export.h>

static fib_entry_delegate_t *fib_entry_delegate_pool;

fib_entry_delegate_t *
fib_entry_delegate_get (index_t fedi)
{
    return (pool_elt_at_index(fib_entry_delegate_pool, fedi));
}

fib_node_index_t
fib_entry_delegate_get_index (const fib_entry_delegate_t *fed)
{
    return (fed - fib_entry_delegate_pool);
}

static fib_entry_delegate_t *
fib_entry_delegate_find_i (const fib_entry_t *fib_entry,
                           fib_entry_delegate_type_t type,
                           u32 *index)
{
    fib_entry_delegate_t *delegate;
    index_t *fedi;
    int ii;

    ii = 0;
    vec_foreach(fedi, fib_entry->fe_delegates)
    {
        delegate = fib_entry_delegate_get(*fedi);

	if (delegate->fd_type == type)
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

fib_entry_delegate_t *
fib_entry_delegate_find (const fib_entry_t *fib_entry,
                        fib_entry_delegate_type_t type)
{
    return (fib_entry_delegate_find_i(fib_entry, type, NULL));
}

void
fib_entry_delegate_remove (fib_entry_t *fib_entry,
                           fib_entry_delegate_type_t type)
{
    fib_entry_delegate_t *fed;
    u32 index = ~0;

    fed = fib_entry_delegate_find_i(fib_entry, type, &index);

    ASSERT(NULL != fed);

    vec_del1(fib_entry->fe_delegates, index);

    pool_put(fib_entry_delegate_pool, fed);
}

static int
fib_entry_delegate_cmp_for_sort (void * v1,
                                 void * v2)
{
    fib_entry_delegate_t *delegate1, *delegate2;
    index_t *fedi1 = v1, *fedi2 = v2;

    delegate1 = fib_entry_delegate_get(*fedi1);
    delegate2 = fib_entry_delegate_get(*fedi2);

    return (delegate1->fd_type - delegate2->fd_type);
}

static void
fib_entry_delegate_init (fib_entry_t *fib_entry,
                         fib_entry_delegate_type_t type)

{
    fib_entry_delegate_t *delegate;

    pool_get_zero(fib_entry_delegate_pool, delegate);

    delegate->fd_entry_index = fib_entry_get_index(fib_entry);
    delegate->fd_type = type;

    vec_add1(fib_entry->fe_delegates, delegate - fib_entry_delegate_pool);
    vec_sort_with_function(fib_entry->fe_delegates,
			   fib_entry_delegate_cmp_for_sort);
}

fib_entry_delegate_t *
fib_entry_delegate_find_or_add (fib_entry_t *fib_entry,
                                fib_entry_delegate_type_t fdt)
{
    fib_entry_delegate_t *delegate;

    delegate = fib_entry_delegate_find(fib_entry, fdt);

    if (NULL == delegate)
    {
	fib_entry_delegate_init(fib_entry, fdt);
    }

    return (fib_entry_delegate_find(fib_entry, fdt));
}

fib_entry_delegate_type_t
fib_entry_chain_type_to_delegate_type (fib_forward_chain_type_t fct)
{
    switch (fct)
    {
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
        return (FIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP4);
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
        return (FIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP6);
    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
        return (FIB_ENTRY_DELEGATE_CHAIN_MPLS_EOS);
    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
        return (FIB_ENTRY_DELEGATE_CHAIN_MPLS_NON_EOS);
    case FIB_FORW_CHAIN_TYPE_ETHERNET:
        return (FIB_ENTRY_DELEGATE_CHAIN_ETHERNET);
    case FIB_FORW_CHAIN_TYPE_MCAST_IP4:
    case FIB_FORW_CHAIN_TYPE_MCAST_IP6:
    case FIB_FORW_CHAIN_TYPE_BIER:
        break;
    case FIB_FORW_CHAIN_TYPE_NSH:
        return (FIB_ENTRY_DELEGATE_CHAIN_NSH);
    }
    ASSERT(0);
    return (FIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP4);
}

fib_forward_chain_type_t
fib_entry_delegate_type_to_chain_type (fib_entry_delegate_type_t fdt)
{
    switch (fdt)
    {
    case FIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP4:
        return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
    case FIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP6:
        return (FIB_FORW_CHAIN_TYPE_UNICAST_IP6);
    case FIB_ENTRY_DELEGATE_CHAIN_MPLS_EOS:
        return (FIB_FORW_CHAIN_TYPE_MPLS_EOS);
    case FIB_ENTRY_DELEGATE_CHAIN_MPLS_NON_EOS:
        return (FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS);
    case FIB_ENTRY_DELEGATE_CHAIN_ETHERNET:
        return (FIB_FORW_CHAIN_TYPE_ETHERNET);
    case FIB_ENTRY_DELEGATE_CHAIN_NSH:
        return (FIB_FORW_CHAIN_TYPE_NSH);
    case FIB_ENTRY_DELEGATE_COVERED:
    case FIB_ENTRY_DELEGATE_ATTACHED_IMPORT:
    case FIB_ENTRY_DELEGATE_ATTACHED_EXPORT:
    case FIB_ENTRY_DELEGATE_BFD:
    case FIB_ENTRY_DELEGATE_TRACK:
        break;
    }
    ASSERT(0);
    return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
}

/**
 * typedef for printing a delegate
 */
typedef u8 * (*fib_entry_delegate_format_t)(const fib_entry_delegate_t *fed,
                                            u8 *s);

/**
 * Print a delegate that represents a forwarding chain
 */
static u8 *
fib_entry_delegate_fmt_fwd_chain (const fib_entry_delegate_t *fed,
                                  u8 *s)
{
    s = format(s, "%U-chain\n  %U",
               format_fib_forw_chain_type,
               fib_entry_delegate_type_to_chain_type(fed->fd_type),
               format_dpo_id, &fed->fd_dpo, 2);

    return (s);
}

/**
 * Print a delegate that represents cover tracking
 */
static u8 *
fib_entry_delegate_fmt_covered (const fib_entry_delegate_t *fed,
                                  u8 *s)
{
    s = format(s, "covered:[");
    s = fib_node_children_format(fed->fd_list, s);
    s = format(s, "]");

    return (s);
}

/**
 * Print a delegate that represents attached-import tracking
 */
static u8 *
fib_entry_delegate_fmt_import (const fib_entry_delegate_t *fed,
                               u8 *s)
{
    s = format(s, "import:");
    s = fib_ae_import_format(fed->fd_index, s);

    return (s);
}

/**
 * Print a delegate that represents attached-export tracking
 */
static u8 *
fib_entry_delegate_fmt_export (const fib_entry_delegate_t *fed,
                               u8 *s)
{
    s = format(s, "export:");
    s = fib_ae_export_format(fed->fd_index, s);

    return (s);
}

/**
 * Print a delegate that represents BFD tracking
 */
static u8 *
fib_entry_delegate_fmt_bfd (const fib_entry_delegate_t *fed,
                               u8 *s)
{
    s = format(s, "BFD:%d", fed->fd_bfd_state);

    return (s);
}

/**
 * Print a delegate that represents tracking
 */
static u8 *
fib_entry_delegate_fmt_track (const fib_entry_delegate_t *fed,
                              u8 *s)
{
    u32 indent = format_get_indent (s);

    s = format(s, "track: sibling:%d", fed->fd_track.fedt_sibling);

    s = format(s, "\n%UChildren:", format_white_space, indent);
    s = fib_node_children_format(fed->fd_track.fedt_node.fn_children, s);

    return (s);
}

/**
 * A delegate type to formatter map
 */
static fib_entry_delegate_format_t fed_formatters[] =
{
    [FIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP4] = fib_entry_delegate_fmt_fwd_chain,
    [FIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP6] = fib_entry_delegate_fmt_fwd_chain,
    [FIB_ENTRY_DELEGATE_CHAIN_MPLS_EOS] = fib_entry_delegate_fmt_fwd_chain,
    [FIB_ENTRY_DELEGATE_CHAIN_MPLS_NON_EOS] = fib_entry_delegate_fmt_fwd_chain,
    [FIB_ENTRY_DELEGATE_CHAIN_ETHERNET] = fib_entry_delegate_fmt_fwd_chain,
    [FIB_ENTRY_DELEGATE_CHAIN_NSH] = fib_entry_delegate_fmt_fwd_chain,
    [FIB_ENTRY_DELEGATE_COVERED] = fib_entry_delegate_fmt_covered,
    [FIB_ENTRY_DELEGATE_ATTACHED_IMPORT] = fib_entry_delegate_fmt_import,
    [FIB_ENTRY_DELEGATE_ATTACHED_EXPORT] = fib_entry_delegate_fmt_export,
    [FIB_ENTRY_DELEGATE_BFD] = fib_entry_delegate_fmt_bfd,
    [FIB_ENTRY_DELEGATE_TRACK] = fib_entry_delegate_fmt_track,
};

u8 *
format_fib_entry_delegate (u8 * s, va_list * args)
{
    fib_entry_delegate_t *fed;
    index_t fedi;

    fedi = va_arg (*args, index_t);
    fed = fib_entry_delegate_get(fedi);

    return (fed_formatters[fed->fd_type](fed, s));
}

static clib_error_t *
show_fib_entry_delegate_command (vlib_main_t * vm,
                                 unformat_input_t * input,
                                 vlib_cli_command_t * cmd)
{
    fib_node_index_t fedi;

    if (unformat (input, "%d", &fedi))
    {
	/*
	 * show one in detail
	 */
	if (!pool_is_free_index(fib_entry_delegate_pool, fedi))
	{
	    vlib_cli_output (vm, "%d@%U",
			     fedi,
			     format_fib_entry_delegate, fedi);
	}
	else
	{
	    vlib_cli_output (vm, "entry %d invalid", fedi);
	}
    }
    else
    {
	/*
	 * show all
	 */
	vlib_cli_output (vm, "FIB Entry Delegates:");
	pool_foreach_index(fedi, fib_entry_delegate_pool,
        ({
	    vlib_cli_output (vm, "%d@%U",
			     fedi,
			     format_fib_entry_delegate, fedi);
	}));
    }

    return (NULL);
}

VLIB_CLI_COMMAND (show_fib_entry, static) = {
  .path = "show fib entry-delegate",
  .function = show_fib_entry_delegate_command,
  .short_help = "show fib entry delegate",
};
