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

#include <vnet/fib/fib_node.h>
#include <vnet/fib/fib_node_list.h>

/*
 * The per-type vector of virtual function tables
 */
static fib_node_vft_t *fn_vfts;

/**
 * The last registered new type
 */
static fib_node_type_t last_new_type = FIB_NODE_TYPE_LAST;

/*
 * the node type names
 */
static const char *fn_type_names[] = FIB_NODE_TYPES;

const char*
fib_node_type_get_name (fib_node_type_t type)
{
    if (type < FIB_NODE_TYPE_LAST)
	return (fn_type_names[type]);
    else
    {
	if (NULL != fn_vfts[type].fnv_format)
	{
	    return ("fixme");
	}
	else
	{
	    return ("unknown");
	}
    }
}

/**
 * fib_node_register_type
 *
 * Register the function table for a given type
 */
void
fib_node_register_type (fib_node_type_t type,
			const fib_node_vft_t *vft)
{
    /*
     * assert that one only registration is made per-node type
     */
    if (vec_len(fn_vfts) > type)
	ASSERT(NULL == fn_vfts[type].fnv_get);

    /*
     * Assert that we are getting each of the required functions
     */
    ASSERT(NULL != vft->fnv_get);
    ASSERT(NULL != vft->fnv_last_lock);

    vec_validate(fn_vfts, type);
    fn_vfts[type] = *vft;
}

fib_node_type_t
fib_node_register_new_type (const fib_node_vft_t *vft)
{
    fib_node_type_t new_type;

    new_type = ++last_new_type;

    fib_node_register_type(new_type, vft);

    return (new_type);
}   

static u8*
fib_node_format (fib_node_ptr_t *fnp, u8*s)
{
    return (format(s, "{%s:%d}", fn_type_names[fnp->fnp_type], fnp->fnp_index)); 
}

u32
fib_node_child_add (fib_node_type_t parent_type,
                    fib_node_index_t parent_index,
                    fib_node_type_t type,
		    fib_node_index_t index)
{
    fib_node_t *parent;

    parent = fn_vfts[parent_type].fnv_get(parent_index);

    /*
     * return the index of the sibling in the child list
     */
    fib_node_lock(parent);

    if (FIB_NODE_INDEX_INVALID == parent->fn_children)
    {
        parent->fn_children = fib_node_list_create();
    }   

    return (fib_node_list_push_front(parent->fn_children,
                                     0, type,
                                     index));
}

void
fib_node_child_remove (fib_node_type_t parent_type,
                       fib_node_index_t parent_index,
                       fib_node_index_t sibling_index)
{
    fib_node_t *parent;

    parent = fn_vfts[parent_type].fnv_get(parent_index);

    fib_node_list_remove(parent->fn_children, sibling_index);

    if (0 == fib_node_list_get_size(parent->fn_children))
    {
        fib_node_list_destroy(&parent->fn_children);
    }

    fib_node_unlock(parent);
}

u32
fib_node_get_n_children (fib_node_type_t parent_type,
                         fib_node_index_t parent_index)
{
    fib_node_t *parent;

    parent = fn_vfts[parent_type].fnv_get(parent_index);

    return (fib_node_list_get_size(parent->fn_children));
}


fib_node_back_walk_rc_t
fib_node_back_walk_one (fib_node_ptr_t *ptr,
                        fib_node_back_walk_ctx_t *ctx)
{
    fib_node_t *node;

    node = fn_vfts[ptr->fnp_type].fnv_get(ptr->fnp_index);

    return (fn_vfts[ptr->fnp_type].fnv_back_walk(node, ctx));
}

static int
fib_node_ptr_format_one_child (fib_node_ptr_t *ptr,
			       void *arg)
{
    u8 **s = (u8**) arg;

    *s = fib_node_format(ptr, *s);

    return (1);
}

u8*
fib_node_children_format (fib_node_list_t list,
			  u8 *s)
{
    fib_node_list_walk(list, fib_node_ptr_format_one_child, (void*)&s);

    return (s);
}

void
fib_node_init (fib_node_t *node,
	       fib_node_type_t type)
{
#if CLIB_DEBUG > 0
    /**
     * The node's type. make sure we are dynamic/down casting correctly
     */
    node->fn_type = type;
#endif
    node->fn_locks = 0;
    node->fn_vft = &fn_vfts[type];
    node->fn_children = FIB_NODE_INDEX_INVALID;
}

void
fib_node_deinit (fib_node_t *node)
{
    fib_node_list_destroy(&node->fn_children);
}

void
fib_node_lock (fib_node_t *node)
{
    node->fn_locks++;
}

void
fib_node_unlock (fib_node_t *node)
{
    node->fn_locks--;

    if (0 == node->fn_locks)
    {
	node->fn_vft->fnv_last_lock(node);
    }
}

void
fib_show_memory_usage (const char *name,
		       u32 in_use_elts,
		       u32 allocd_elts,
		       size_t size_elt)
{
    vlib_cli_output (vlib_get_main(), "%=30s %=5d %=8d/%=9d   %d/%d ",
		     name, size_elt,
		     in_use_elts, allocd_elts,
		     in_use_elts*size_elt, allocd_elts*size_elt);
}

static clib_error_t *
fib_memory_show (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
    fib_node_vft_t *vft;

    vlib_cli_output (vm, "FIB memory");
    vlib_cli_output (vm, "%=30s %=5s %=8s/%=9s   totals",
		     "Name","Size", "in-use", "allocated");

    vec_foreach(vft, fn_vfts)
    {
	if (NULL != vft->fnv_mem_show)
	    vft->fnv_mem_show();
    }

    fib_node_list_memory_show();

    return (NULL);
}

/* *INDENT-OFF* */
/*?
 * The '<em>sh fib memory </em>' command displays the memory usage for each
 * FIB object type.
 *
 * @cliexpar
 * @cliexstart{show fib memory}
 * FIB memory
 *             Name               Size  in-use /allocated   totals
 *             Entry              120     11   /    11      1320/1320
 *         Entry Source            32     11   /    11      352/352
 *     Entry Path-Extensions       44      0   /    0       0/0
 *           Path-list             40     11   /    11      440/440
 *             Path                88     11   /    11      968/968
 *      Node-list elements         20     11   /    11      220/220
 *        Node-list heads          8      13   /    13      104/104
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_fib_memory, static) = {
    .path = "show fib memory",
    .function = fib_memory_show,
    .short_help = "show fib memory",
};
/* *INDENT-ON* */
