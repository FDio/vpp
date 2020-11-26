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
/**
 * @brief a hetrogeneous w.r.t. FIB node type, of FIB nodes.
 * Since we cannot use C pointers, due to memeory reallocs, the next/prev
 * are described as key:{type,index}.
 */

#include <vnet/fib/fib_node_list.h>

/**
 * @brief An element in the list
 */
typedef struct fib_node_list_elt_t_
{
    /**
     * The index of the list this element is in
     */
    fib_node_list_t fnle_list;

    /**
     * The owner of this element
     */
    fib_node_ptr_t fnle_owner;

    /**
     * The next element in the list
     */
    u32 fnle_next;

    /**
     * The previous element in the list
     */
    u32 fnle_prev;
} fib_node_list_elt_t;

/**
 * @brief A list of FIB nodes
 */
typedef struct fib_node_list_head_t_
{
    /**
     * The head element
     */
    u32 fnlh_head;

    /**
     * Number of elements in the list
     */
    u32 fnlh_n_elts;
} fib_node_list_head_t;

/**
 * Pools of list elements and heads
 */
static fib_node_list_elt_t *fib_node_list_elt_pool;
static fib_node_list_head_t *fib_node_list_head_pool;

static index_t
fib_node_list_elt_get_index (fib_node_list_elt_t *elt)
{
    return (elt - fib_node_list_elt_pool);
}

static fib_node_list_elt_t *
fib_node_list_elt_get (index_t fi)
{
    return (pool_elt_at_index(fib_node_list_elt_pool, fi));
}

static index_t
fib_node_list_head_get_index (fib_node_list_head_t *head)
{
    return (head - fib_node_list_head_pool);
}
static fib_node_list_head_t *
fib_node_list_head_get (fib_node_list_t fi)
{
    return (pool_elt_at_index(fib_node_list_head_pool, fi));
}

static fib_node_list_elt_t *
fib_node_list_elt_create (fib_node_list_head_t *head,
                          int id,
                          fib_node_type_t type,
                          fib_node_index_t index)
{
    fib_node_list_elt_t *elt;

    pool_get(fib_node_list_elt_pool, elt);

    elt->fnle_list = fib_node_list_head_get_index(head);
    elt->fnle_owner.fnp_type  = type;
    elt->fnle_owner.fnp_index = index;

    elt->fnle_next = FIB_NODE_INDEX_INVALID;
    elt->fnle_prev = FIB_NODE_INDEX_INVALID;

    return (elt);
}

static void
fib_node_list_head_init (fib_node_list_head_t *head)
{
    head->fnlh_n_elts = 0;
    head->fnlh_head = FIB_NODE_INDEX_INVALID;
}

/**
 * @brief Create a new node list.
 */
fib_node_list_t
fib_node_list_create (void)
{
    fib_node_list_head_t *head;

    pool_get(fib_node_list_head_pool, head);

    fib_node_list_head_init(head);

    return (fib_node_list_head_get_index(head));
}

void
fib_node_list_destroy (fib_node_list_t *list)
{
    fib_node_list_head_t *head;

    if (FIB_NODE_INDEX_INVALID == *list)
        return;

    head = fib_node_list_head_get(*list);
    ASSERT(0 == head->fnlh_n_elts);

    pool_put(fib_node_list_head_pool, head);
    *list = FIB_NODE_INDEX_INVALID;
}


/**
 * @brief Insert an element at the from of the list.
 */
u32
fib_node_list_push_front (fib_node_list_t list,
                          int owner_id,
                          fib_node_type_t type,
                          fib_node_index_t index)
{
    fib_node_list_elt_t *elt, *next;
    fib_node_list_head_t *head;

    head = fib_node_list_head_get(list);
    elt = fib_node_list_elt_create(head, owner_id, type, index);

    elt->fnle_prev = FIB_NODE_INDEX_INVALID;
    elt->fnle_next = head->fnlh_head;

    if (FIB_NODE_INDEX_INVALID != head->fnlh_head)
    {
        next = fib_node_list_elt_get(head->fnlh_head);
        next->fnle_prev = fib_node_list_elt_get_index(elt);
    }
    head->fnlh_head = fib_node_list_elt_get_index(elt);

    head->fnlh_n_elts++;

    return (fib_node_list_elt_get_index(elt));
}

u32
fib_node_list_push_back (fib_node_list_t list,
                        int owner_id,
                        fib_node_type_t type,
                        fib_node_index_t index)
{
    ASSERT(0);
    return (FIB_NODE_INDEX_INVALID);
}

static void
fib_node_list_extract (fib_node_list_head_t *head,
                       fib_node_list_elt_t *elt)
{
    fib_node_list_elt_t *next, *prev;

    if (FIB_NODE_INDEX_INVALID != elt->fnle_next)
    {
        next = fib_node_list_elt_get(elt->fnle_next);
        next->fnle_prev = elt->fnle_prev;
    }

    if (FIB_NODE_INDEX_INVALID != elt->fnle_prev)
    {
        prev = fib_node_list_elt_get(elt->fnle_prev);
        prev->fnle_next = elt->fnle_next;
    }
    else
    {
        ASSERT (fib_node_list_elt_get_index(elt) == head->fnlh_head);
        head->fnlh_head = elt->fnle_next;
    }
}

static void
fib_node_list_insert_after (fib_node_list_head_t *head,
                            fib_node_list_elt_t *prev,
                            fib_node_list_elt_t *elt)
{
    fib_node_list_elt_t *next;

    elt->fnle_next = prev->fnle_next;
    if (FIB_NODE_INDEX_INVALID != prev->fnle_next)
    {
        next = fib_node_list_elt_get(prev->fnle_next);
        next->fnle_prev = fib_node_list_elt_get_index(elt);
    }
    prev->fnle_next = fib_node_list_elt_get_index(elt);
    elt->fnle_prev = fib_node_list_elt_get_index(prev);
}

void
fib_node_list_remove (fib_node_list_t list,
                      u32 sibling)
{
    fib_node_list_head_t *head;
    fib_node_list_elt_t *elt;

    head = fib_node_list_head_get(list);
    elt  = fib_node_list_elt_get(sibling);

    fib_node_list_extract(head, elt);

    head->fnlh_n_elts--;
    pool_put(fib_node_list_elt_pool, elt);
}

void
fib_node_list_elt_remove (u32 sibling)
{
    fib_node_list_elt_t *elt;

    elt = fib_node_list_elt_get(sibling);

    fib_node_list_remove(elt->fnle_list, sibling);
}

/**
 * @brief Advance the sibling one step (toward the tail) in the list.
 * return 0 if at the end of the list, 1 otherwise.
 */
int
fib_node_list_advance (u32 sibling)
{
    fib_node_list_elt_t *elt, *next;
    fib_node_list_head_t *head;

    elt = fib_node_list_elt_get(sibling);
    head = fib_node_list_head_get(elt->fnle_list);

    if (FIB_NODE_INDEX_INVALID != elt->fnle_next)
    {
        /*
         * not at the end of the list
         */
        next = fib_node_list_elt_get(elt->fnle_next);

        fib_node_list_extract(head, elt);
        fib_node_list_insert_after(head, next, elt);

        return (1);
    }
    else
    {
        return (0);
    }
}

int
fib_node_list_elt_get_next (u32 sibling,
                            fib_node_ptr_t *ptr)
{
    fib_node_list_elt_t *elt, *next;

    elt = fib_node_list_elt_get(sibling);

    if (FIB_NODE_INDEX_INVALID != elt->fnle_next)
    {
        next = fib_node_list_elt_get(elt->fnle_next);

        *ptr = next->fnle_owner;
        return (1);
    }
    else
    {
        ptr->fnp_index = FIB_NODE_INDEX_INVALID;
        return (0);
    }
}

u32
fib_node_list_get_size (fib_node_list_t list)
{
    fib_node_list_head_t *head;

    if (FIB_NODE_INDEX_INVALID == list)
    {
        return (0);
    }

    head = fib_node_list_head_get(list);

    return (head->fnlh_n_elts);
}

int
fib_node_list_get_front (fib_node_list_t list,
                         fib_node_ptr_t *ptr)
{
    fib_node_list_head_t *head;
    fib_node_list_elt_t *elt;


    if (0 == fib_node_list_get_size(list))
    {
        ptr->fnp_index = FIB_NODE_INDEX_INVALID;
        return (0);
    }

    head = fib_node_list_head_get(list);
    elt = fib_node_list_elt_get(head->fnlh_head);
    
    *ptr = elt->fnle_owner;

    return (1);
}

/**
 * @brief Walk the list of node. This must be safe w.r.t. the removal
 * of nodes during the walk.
 */
void
fib_node_list_walk (fib_node_list_t list,
                    fib_node_list_walk_cb_t fn,
                    void *args)
{
    fib_node_list_elt_t *elt;
    fib_node_list_head_t *head;
    u32 sibling;

    if (FIB_NODE_INDEX_INVALID == list)
    {
        return;
    }

    head = fib_node_list_head_get(list);
    sibling = head->fnlh_head;

    while (FIB_NODE_INDEX_INVALID != sibling)
    {
        elt = fib_node_list_elt_get(sibling);
        sibling = elt->fnle_next;

        if (WALK_STOP == fn(&elt->fnle_owner, args))
            break;
    }
}

void
fib_node_list_memory_show (void)
{
    fib_show_memory_usage("Node-list elements",
			  pool_elts(fib_node_list_elt_pool),
			  pool_len(fib_node_list_elt_pool),
			  sizeof(fib_node_list_elt_t));
    fib_show_memory_usage("Node-list heads",
			  pool_elts(fib_node_list_head_pool),
			  pool_len(fib_node_list_head_pool),
			  sizeof(fib_node_list_head_t));
}
