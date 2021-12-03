/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Copyright (c) 2021 Graphiant and/or its affiliates.
 *
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

#include <vnet/dependency/dep_list.h>
#include <vnet/memory_usage.h>

/**
 * @brief An element in the list
 */
typedef struct dep_list_elt_t_
{
  /**
   * The index of the list this element is in
   */
  dep_list_t dle_list;

  /**
   * The owner of this element
   */
  dep_ptr_t dle_owner;

  /**
   * The next element in the list
   */
  u32 dle_next;

  /**
   * The previous element in the list
   */
  u32 dle_prev;
} dep_list_elt_t;

/**
 * @brief A list of FIB nodes
 */
typedef struct dep_list_head_t_
{
  /**
   * The head element
   */
  u32 dlh_head;

  /**
   * Number of elements in the list
   */
  u32 dlh_n_elts;
} dep_list_head_t;

/**
 * Pools of list elements and heads
 */
static dep_list_elt_t *dep_list_elt_pool;
static dep_list_head_t *dep_list_head_pool;

static uword
dep_list_elt_get_index (dep_list_elt_t *elt)
{
  return (elt - dep_list_elt_pool);
}

static dep_list_elt_t *
dep_list_elt_get (uword di)
{
  return (pool_elt_at_index (dep_list_elt_pool, di));
}

static uword
dep_list_head_get_index (dep_list_head_t *head)
{
  return (head - dep_list_head_pool);
}
static dep_list_head_t *
dep_list_head_get (dep_list_t di)
{
  return (pool_elt_at_index (dep_list_head_pool, di));
}

static dep_list_elt_t *
dep_list_elt_create (dep_list_head_t *head, int id, dep_type_t type,
		     dep_index_t index)
{
  dep_list_elt_t *elt;

  pool_get (dep_list_elt_pool, elt);

  elt->dle_list = dep_list_head_get_index (head);
  elt->dle_owner.dp_type = type;
  elt->dle_owner.dp_index = index;

  elt->dle_next = DEP_INDEX_INVALID;
  elt->dle_prev = DEP_INDEX_INVALID;

  return (elt);
}

static void
dep_list_head_init (dep_list_head_t *head)
{
  head->dlh_n_elts = 0;
  head->dlh_head = DEP_INDEX_INVALID;
}

/**
 * @brief Create a new node list.
 */
dep_list_t
dep_list_create (void)
{
  dep_list_head_t *head;

  pool_get (dep_list_head_pool, head);

  dep_list_head_init (head);

  return (dep_list_head_get_index (head));
}

void
dep_list_destroy (dep_list_t *list)
{
  dep_list_head_t *head;

  if (DEP_INDEX_INVALID == *list)
    return;

  head = dep_list_head_get (*list);
  ASSERT (0 == head->dlh_n_elts);

  pool_put (dep_list_head_pool, head);
  *list = DEP_INDEX_INVALID;
}

/**
 * @brief Insert an element at the from of the list.
 */
u32
dep_list_push_front (dep_list_t list, int owner_id, dep_type_t type,
		     dep_index_t index)
{
  dep_list_elt_t *elt, *next;
  dep_list_head_t *head;

  head = dep_list_head_get (list);
  elt = dep_list_elt_create (head, owner_id, type, index);

  elt->dle_prev = DEP_INDEX_INVALID;
  elt->dle_next = head->dlh_head;

  if (DEP_INDEX_INVALID != head->dlh_head)
    {
      next = dep_list_elt_get (head->dlh_head);
      next->dle_prev = dep_list_elt_get_index (elt);
    }
  head->dlh_head = dep_list_elt_get_index (elt);

  head->dlh_n_elts++;

  return (dep_list_elt_get_index (elt));
}

u32
dep_list_push_back (dep_list_t list, int owner_id, dep_type_t type,
		    dep_index_t index)
{
  ASSERT (0);
  return (DEP_INDEX_INVALID);
}

static void
dep_list_extract (dep_list_head_t *head, dep_list_elt_t *elt)
{
  dep_list_elt_t *next, *prev;

  if (DEP_INDEX_INVALID != elt->dle_next)
    {
      next = dep_list_elt_get (elt->dle_next);
      next->dle_prev = elt->dle_prev;
    }

  if (DEP_INDEX_INVALID != elt->dle_prev)
    {
      prev = dep_list_elt_get (elt->dle_prev);
      prev->dle_next = elt->dle_next;
    }
  else
    {
      ASSERT (dep_list_elt_get_index (elt) == head->dlh_head);
      head->dlh_head = elt->dle_next;
    }
}

static void
dep_list_insert_after (dep_list_head_t *head, dep_list_elt_t *prev,
		       dep_list_elt_t *elt)
{
  dep_list_elt_t *next;

  elt->dle_next = prev->dle_next;
  if (DEP_INDEX_INVALID != prev->dle_next)
    {
      next = dep_list_elt_get (prev->dle_next);
      next->dle_prev = dep_list_elt_get_index (elt);
    }
  prev->dle_next = dep_list_elt_get_index (elt);
  elt->dle_prev = dep_list_elt_get_index (prev);
}

void
dep_list_remove (dep_list_t list, u32 sibling)
{
  dep_list_head_t *head;
  dep_list_elt_t *elt;

  head = dep_list_head_get (list);
  elt = dep_list_elt_get (sibling);

  dep_list_extract (head, elt);

  head->dlh_n_elts--;
  pool_put (dep_list_elt_pool, elt);
}

void
dep_list_elt_remove (u32 sibling)
{
  dep_list_elt_t *elt;

  elt = dep_list_elt_get (sibling);

  dep_list_remove (elt->dle_list, sibling);
}

/**
 * @brief Advance the sibling one step (toward the tail) in the list.
 * return 0 if at the end of the list, 1 otherwise.
 */
int
dep_list_advance (u32 sibling)
{
  dep_list_elt_t *elt, *next;
  dep_list_head_t *head;

  elt = dep_list_elt_get (sibling);
  head = dep_list_head_get (elt->dle_list);

  if (DEP_INDEX_INVALID != elt->dle_next)
    {
      /*
       * not at the end of the list
       */
      next = dep_list_elt_get (elt->dle_next);

      dep_list_extract (head, elt);
      dep_list_insert_after (head, next, elt);

      return (1);
    }
  else
    {
      return (0);
    }
}

int
dep_list_elt_get_next (u32 sibling, dep_ptr_t *ptr)
{
  dep_list_elt_t *elt, *next;

  elt = dep_list_elt_get (sibling);

  if (DEP_INDEX_INVALID != elt->dle_next)
    {
      next = dep_list_elt_get (elt->dle_next);

      *ptr = next->dle_owner;
      return (1);
    }
  else
    {
      ptr->dp_index = DEP_INDEX_INVALID;
      return (0);
    }
}

u32
dep_list_get_size (dep_list_t list)
{
  dep_list_head_t *head;

  if (DEP_INDEX_INVALID == list)
    {
      return (0);
    }

  head = dep_list_head_get (list);

  return (head->dlh_n_elts);
}

int
dep_list_get_front (dep_list_t list, dep_ptr_t *ptr)
{
  dep_list_head_t *head;
  dep_list_elt_t *elt;

  if (0 == dep_list_get_size (list))
    {
      ptr->dp_index = DEP_INDEX_INVALID;
      return (0);
    }

  head = dep_list_head_get (list);
  elt = dep_list_elt_get (head->dlh_head);

  *ptr = elt->dle_owner;

  return (1);
}

/**
 * @brief Walk the list of node. This must be safe w.r.t. the removal
 * of nodes during the walk.
 */
void
dep_list_walk (dep_list_t list, dep_list_walk_cb_t fn, void *args)
{
  dep_list_elt_t *elt;
  dep_list_head_t *head;
  u32 sibling;

  if (DEP_INDEX_INVALID == list)
    {
      return;
    }

  head = dep_list_head_get (list);
  sibling = head->dlh_head;

  while (DEP_INDEX_INVALID != sibling)
    {
      elt = dep_list_elt_get (sibling);
      sibling = elt->dle_next;

      if (WALK_STOP == fn (&elt->dle_owner, args))
	break;
    }
}

void
dep_list_memory_show (vlib_main_t *vm)
{
  memory_usage_show (vm, "Node-list elements", pool_elts (dep_list_elt_pool),
		     pool_len (dep_list_elt_pool), sizeof (dep_list_elt_t));
  memory_usage_show (vm, "Node-list heads", pool_elts (dep_list_head_pool),
		     pool_len (dep_list_head_pool), sizeof (dep_list_head_t));
}

clib_error_t *
dep_list_module_init (vlib_main_t *vm)
{
  memory_usage_register (dep_list_memory_show);
  return (NULL);
}

VLIB_INIT_FUNCTION (dep_list_module_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
