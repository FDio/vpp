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
/*
 * node.c: VLIB processing nodes
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vlib/threads.h>

/* Query node given name. */
vlib_node_t *
vlib_get_node_by_name (vlib_main_t * vm, u8 * name)
{
  vlib_node_main_t *nm = &vm->node_main;
  uword *p;
  u8 *key = name;
  if (!clib_mem_is_heap_object (key))
    key = format (0, "%s", key);
  p = hash_get (nm->node_by_name, key);
  if (key != name)
    vec_free (key);
  return p ? vec_elt (nm->nodes, p[0]) : 0;
}

static void
node_set_elog_name (vlib_main_t * vm, uword node_index)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  elog_event_type_t *t;

  t = vec_elt_at_index (vm->node_call_elog_event_types, node_index);
  vec_free (t->format);
  t->format = (char *) format (0, "%v-call: %%d%c", n->name, 0);

  t = vec_elt_at_index (vm->node_return_elog_event_types, node_index);
  vec_free (t->format);
  t->format = (char *) format (0, "%v-return: %%d%c", n->name, 0);

  n->name_elog_string = elog_string (&vm->elog_main, "%v%c", n->name, 0);
}

static void
vlib_worker_thread_node_rename (u32 node_index)
{
  int i;
  vlib_main_t *vm;
  vlib_node_t *n;

  if (vec_len (vlib_mains) == 1)
    return;

  vm = vlib_mains[0];
  n = vlib_get_node (vm, node_index);

  ASSERT (vlib_get_thread_index () == 0);
  ASSERT (*vlib_worker_threads->wait_at_barrier == 1);

  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      vlib_main_t *vm_worker = vlib_mains[i];
      vlib_node_t *n_worker = vlib_get_node (vm_worker, node_index);

      n_worker->name = n->name;
      n_worker->name_elog_string = n->name_elog_string;
    }
}

void
vlib_node_rename (vlib_main_t * vm, u32 node_index, char *fmt, ...)
{
  va_list va;
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n = vlib_get_node (vm, node_index);

  va_start (va, fmt);
  hash_unset (nm->node_by_name, n->name);
  vec_free (n->name);
  n->name = va_format (0, fmt, &va);
  va_end (va);
  hash_set (nm->node_by_name, n->name, n->index);

  node_set_elog_name (vm, node_index);

  /* Propagate the change to all worker threads */
  vlib_worker_thread_node_rename (node_index);
}

static void
vlib_node_runtime_update (vlib_main_t * vm, u32 node_index, u32 next_index)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_runtime_t *r, *s;
  vlib_node_t *node, *next_node;
  vlib_next_frame_t *nf;
  vlib_pending_frame_t *pf;
  i32 i, j, n_insert;

  ASSERT (vlib_get_thread_index () == 0);

  vlib_worker_thread_barrier_sync (vm);

  node = vec_elt (nm->nodes, node_index);
  r = vlib_node_get_runtime (vm, node_index);

  n_insert = vec_len (node->next_nodes) - r->n_next_nodes;
  if (n_insert > 0)
    {
      i = r->next_frame_index + r->n_next_nodes;
      vec_insert (nm->next_frames, n_insert, i);

      /* Initialize newly inserted next frames. */
      for (j = 0; j < n_insert; j++)
	vlib_next_frame_init (nm->next_frames + i + j);

      /* Relocate other next frames at higher indices. */
      for (j = 0; j < vec_len (nm->nodes); j++)
	{
	  s = vlib_node_get_runtime (vm, j);
	  if (j != node_index && s->next_frame_index >= i)
	    s->next_frame_index += n_insert;
	}

      /* Pending frames may need to be relocated also. */
      vec_foreach (pf, nm->pending_frames)
      {
	if (pf->next_frame_index != VLIB_PENDING_FRAME_NO_NEXT_FRAME
	    && pf->next_frame_index >= i)
	  pf->next_frame_index += n_insert;
      }
      /* *INDENT-OFF* */
      pool_foreach (pf, nm->suspended_process_frames, ({
	  if (pf->next_frame_index != ~0 && pf->next_frame_index >= i)
	    pf->next_frame_index += n_insert;
      }));
      /* *INDENT-ON* */

      r->n_next_nodes = vec_len (node->next_nodes);
    }

  /* Set frame's node runtime index. */
  next_node = vlib_get_node (vm, node->next_nodes[next_index]);
  nf = nm->next_frames + r->next_frame_index + next_index;
  nf->node_runtime_index = next_node->runtime_index;

  vlib_worker_thread_node_runtime_update ();

  vlib_worker_thread_barrier_release (vm);
}

uword
vlib_node_get_next (vlib_main_t * vm, uword node_index, uword next_node_index)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *node;
  uword *p;

  node = vec_elt (nm->nodes, node_index);

  /* Runtime has to be initialized. */
  ASSERT (nm->flags & VLIB_NODE_MAIN_RUNTIME_STARTED);

  if ((p = hash_get (node->next_slot_by_node, next_node_index)))
    {
      return p[0];
    }

  return (~0);
}

/* Add next node to given node in given slot. */
uword
vlib_node_add_next_with_slot (vlib_main_t * vm,
			      uword node_index,
			      uword next_node_index, uword slot)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *node, *next;
  uword *p;

  node = vec_elt (nm->nodes, node_index);
  next = vec_elt (nm->nodes, next_node_index);

  /* Runtime has to be initialized. */
  ASSERT (nm->flags & VLIB_NODE_MAIN_RUNTIME_STARTED);

  if ((p = hash_get (node->next_slot_by_node, next_node_index)))
    {
      /* Next already exists: slot must match. */
      if (slot != ~0)
	ASSERT (slot == p[0]);
      return p[0];
    }

  if (slot == ~0)
    slot = vec_len (node->next_nodes);

  vec_validate_init_empty (node->next_nodes, slot, ~0);
  vec_validate (node->n_vectors_by_next_node, slot);

  node->next_nodes[slot] = next_node_index;
  hash_set (node->next_slot_by_node, next_node_index, slot);

  vlib_node_runtime_update (vm, node_index, slot);

  next->prev_node_bitmap = clib_bitmap_ori (next->prev_node_bitmap,
					    node_index);

  /* Siblings all get same node structure. */
  {
    uword sib_node_index, sib_slot;
    vlib_node_t *sib_node;
    /* *INDENT-OFF* */
    clib_bitmap_foreach (sib_node_index, node->sibling_bitmap, ({
      sib_node = vec_elt (nm->nodes, sib_node_index);
      if (sib_node != node)
	{
	  sib_slot = vlib_node_add_next_with_slot (vm, sib_node_index, next_node_index, slot);
	  ASSERT (sib_slot == slot);
	}
    }));
    /* *INDENT-ON* */
  }

  return slot;
}

/* Add named next node to given node in given slot. */
uword
vlib_node_add_named_next_with_slot (vlib_main_t * vm,
				    uword node, char *name, uword slot)
{
  vlib_node_main_t *nm;
  vlib_node_t *n, *n_next;

  nm = &vm->node_main;
  n = vlib_get_node (vm, node);

  n_next = vlib_get_node_by_name (vm, (u8 *) name);
  if (!n_next)
    {
      if (nm->flags & VLIB_NODE_MAIN_RUNTIME_STARTED)
	return ~0;

      if (slot == ~0)
	slot = clib_max (vec_len (n->next_node_names),
			 vec_len (n->next_nodes));
      vec_validate (n->next_node_names, slot);
      n->next_node_names[slot] = name;
      return slot;
    }

  return vlib_node_add_next_with_slot (vm, node, n_next->index, slot);
}

static void
node_elog_init (vlib_main_t * vm, uword ni)
{
  elog_event_type_t t;

  memset (&t, 0, sizeof (t));

  /* 2 event types for this node: one when node function is called.
     One when it returns. */
  vec_validate (vm->node_call_elog_event_types, ni);
  vm->node_call_elog_event_types[ni] = t;

  vec_validate (vm->node_return_elog_event_types, ni);
  vm->node_return_elog_event_types[ni] = t;

  node_set_elog_name (vm, ni);
}

#ifdef CLIB_UNIX
#define STACK_ALIGN (clib_mem_get_page_size())
#else
#define STACK_ALIGN CLIB_CACHE_LINE_BYTES
#endif

static void
register_node (vlib_main_t * vm, vlib_node_registration_t * r)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  u32 page_size = clib_mem_get_page_size ();
  int i;

  if (CLIB_DEBUG > 0)
    {
      /* Default (0) type should match INTERNAL. */
      vlib_node_t zero = { 0 };
      ASSERT (VLIB_NODE_TYPE_INTERNAL == zero.type);
    }

  ASSERT (r->function != 0);

  n = clib_mem_alloc_no_fail (sizeof (n[0]));
  memset (n, 0, sizeof (n[0]));
  n->index = vec_len (nm->nodes);

  vec_add1 (nm->nodes, n);

  /* Name is always a vector so it can be formatted with %v. */
  if (clib_mem_is_heap_object (vec_header (r->name, 0)))
    n->name = vec_dup ((u8 *) r->name);
  else
    n->name = format (0, "%s", r->name);

  if (!nm->node_by_name)
    nm->node_by_name = hash_create_vec ( /* size */ 32,
					sizeof (n->name[0]), sizeof (uword));

  /* Node names must be unique. */
  {
    vlib_node_t *o = vlib_get_node_by_name (vm, n->name);
    if (o)
      clib_error ("more than one node named `%v'", n->name);
  }

  hash_set (nm->node_by_name, n->name, n->index);

  r->index = n->index;		/* save index in registration */
  n->function = r->function;

  /* Node index of next sibling will be filled in by vlib_node_main_init. */
  n->sibling_of = r->sibling_of;
  if (r->sibling_of && r->n_next_nodes > 0)
    clib_error ("sibling node should not have any next nodes `%v'", n->name);

  if (r->type == VLIB_NODE_TYPE_INTERNAL)
    ASSERT (r->vector_size > 0);

#define _(f) n->f = r->f

  _(type);
  _(flags);
  _(state);
  _(scalar_size);
  _(vector_size);
  _(format_buffer);
  _(unformat_buffer);
  _(format_trace);
  _(validate_frame);

  /* Register error counters. */
  vlib_register_errors (vm, n->index, r->n_errors, r->error_strings);
  node_elog_init (vm, n->index);

  _(runtime_data_bytes);
  if (r->runtime_data_bytes > 0)
    {
      vec_resize (n->runtime_data, r->runtime_data_bytes);
      if (r->runtime_data)
	clib_memcpy (n->runtime_data, r->runtime_data, r->runtime_data_bytes);
    }

  vec_resize (n->next_node_names, r->n_next_nodes);
  for (i = 0; i < r->n_next_nodes; i++)
    n->next_node_names[i] = r->next_nodes[i];

  vec_validate_init_empty (n->next_nodes, r->n_next_nodes - 1, ~0);
  vec_validate (n->n_vectors_by_next_node, r->n_next_nodes - 1);

  n->owner_node_index = n->owner_next_index = ~0;

  /* Initialize node runtime. */
  {
    vlib_node_runtime_t *rt;
    u32 i;

    if (n->type == VLIB_NODE_TYPE_PROCESS)
      {
	vlib_process_t *p;
	uword log2_n_stack_bytes;

	log2_n_stack_bytes = clib_max (r->process_log2_n_stack_bytes, 15);

#ifdef CLIB_UNIX
	/*
	 * Bump the stack size if running over a kernel with a large page size,
	 * and the stack isn't any too big to begin with. Otherwise, we'll
	 * trip over the stack guard page for sure.
	 */
	if ((page_size > (4 << 10)) && log2_n_stack_bytes < 19)
	  {
	    if ((1 << log2_n_stack_bytes) <= page_size)
	      log2_n_stack_bytes = min_log2 (page_size) + 1;
	    else
	      log2_n_stack_bytes++;
	  }
#endif

	p = clib_mem_alloc_aligned_at_offset
	  (sizeof (p[0]) + (1 << log2_n_stack_bytes),
	   STACK_ALIGN, STRUCT_OFFSET_OF (vlib_process_t, stack),
	   0 /* no, don't call os_out_of_memory */ );
	if (p == 0)
	  clib_panic ("failed to allocate process stack (%d bytes)",
		      1 << log2_n_stack_bytes);

	memset (p, 0, sizeof (p[0]));
	p->log2_n_stack_bytes = log2_n_stack_bytes;

	/* Process node's runtime index is really index into process
	   pointer vector. */
	n->runtime_index = vec_len (nm->processes);

	vec_add1 (nm->processes, p);

	/* Paint first stack word with magic number so we can at least
	   detect process stack overruns. */
	p->stack[0] = VLIB_PROCESS_STACK_MAGIC;

	/* Node runtime is stored inside of process. */
	rt = &p->node_runtime;

#ifdef CLIB_UNIX
	/*
	 * Disallow writes to the bottom page of the stack, to
	 * catch stack overflows.
	 */
	if (mprotect (p->stack, page_size, PROT_READ) < 0)
	  clib_unix_warning ("process stack");
#endif

      }
    else
      {
	vec_add2_aligned (nm->nodes_by_type[n->type], rt, 1,
			  /* align */ CLIB_CACHE_LINE_BYTES);
	n->runtime_index = rt - nm->nodes_by_type[n->type];
      }

    if (n->type == VLIB_NODE_TYPE_INPUT)
      nm->input_node_counts_by_state[n->state] += 1;

    rt->function = n->function;
    rt->flags = n->flags;
    rt->state = n->state;
    rt->node_index = n->index;

    rt->n_next_nodes = r->n_next_nodes;
    rt->next_frame_index = vec_len (nm->next_frames);

    vec_resize (nm->next_frames, rt->n_next_nodes);
    for (i = 0; i < rt->n_next_nodes; i++)
      vlib_next_frame_init (nm->next_frames + rt->next_frame_index + i);

    vec_resize (rt->errors, r->n_errors);
    for (i = 0; i < vec_len (rt->errors); i++)
      rt->errors[i] = vlib_error_set (n->index, i);

    STATIC_ASSERT_SIZEOF (vlib_node_runtime_t, 128);
    ASSERT (vec_len (n->runtime_data) <= VLIB_NODE_RUNTIME_DATA_SIZE);

    if (vec_len (n->runtime_data) > 0)
      clib_memcpy (rt->runtime_data, n->runtime_data,
		   vec_len (n->runtime_data));

    vec_free (n->runtime_data);
  }
}

/* Register new packet processing node. */
u32
vlib_register_node (vlib_main_t * vm, vlib_node_registration_t * r)
{
  register_node (vm, r);
  return r->index;
}

static uword
null_node_fn (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u16 n_vectors = frame->n_vectors;

  vlib_node_increment_counter (vm, node->node_index, 0, n_vectors);
  vlib_buffer_free (vm, vlib_frame_args (frame), n_vectors);
  vlib_frame_free (vm, node, frame);

  return n_vectors;
}

void
vlib_register_all_static_nodes (vlib_main_t * vm)
{
  vlib_node_registration_t *r;

  static char *null_node_error_strings[] = {
    "blackholed packets",
  };

  static vlib_node_registration_t null_node_reg = {
    .function = null_node_fn,
    .vector_size = sizeof (u32),
    .name = "null-node",
    .n_errors = 1,
    .error_strings = null_node_error_strings,
  };

  /* make sure that node index 0 is not used by
     real node */
  register_node (vm, &null_node_reg);

  r = vm->node_main.node_registrations;
  while (r)
    {
      register_node (vm, r);
      r = r->next_registration;
    }
}

clib_error_t *
vlib_node_main_init (vlib_main_t * vm)
{
  vlib_node_main_t *nm = &vm->node_main;
  clib_error_t *error = 0;
  vlib_node_t *n;
  uword ni;

  nm->frame_size_hash = hash_create (0, sizeof (uword));
  nm->flags |= VLIB_NODE_MAIN_RUNTIME_STARTED;

  /* Generate sibling relationships */
  {
    vlib_node_t *n, *sib;
    uword si;

    for (ni = 0; ni < vec_len (nm->nodes); ni++)
      {
	n = vec_elt (nm->nodes, ni);

	if (!n->sibling_of)
	  continue;

	sib = vlib_get_node_by_name (vm, (u8 *) n->sibling_of);
	if (!sib)
	  {
	    error = clib_error_create ("sibling `%s' not found for node `%v'",
				       n->sibling_of, n->name);
	    goto done;
	  }

        /* *INDENT-OFF* */
	clib_bitmap_foreach (si, sib->sibling_bitmap, ({
	      vlib_node_t * m = vec_elt (nm->nodes, si);

	      /* Connect all of sibling's siblings to us. */
	      m->sibling_bitmap = clib_bitmap_ori (m->sibling_bitmap, n->index);

	      /* Connect us to all of sibling's siblings. */
	      n->sibling_bitmap = clib_bitmap_ori (n->sibling_bitmap, si);
	    }));
        /* *INDENT-ON* */

	/* Connect sibling to us. */
	sib->sibling_bitmap = clib_bitmap_ori (sib->sibling_bitmap, n->index);

	/* Connect us to sibling. */
	n->sibling_bitmap = clib_bitmap_ori (n->sibling_bitmap, sib->index);
      }
  }

  /* Resolve next names into next indices. */
  for (ni = 0; ni < vec_len (nm->nodes); ni++)
    {
      uword i;

      n = vec_elt (nm->nodes, ni);

      for (i = 0; i < vec_len (n->next_node_names); i++)
	{
	  char *a = n->next_node_names[i];

	  if (!a)
	    continue;

	  if (~0 == vlib_node_add_named_next_with_slot (vm, n->index, a, i))
	    {
	      error = clib_error_create
		("node `%v' refers to unknown node `%s'", n->name, a);
	      goto done;
	    }
	}

      vec_free (n->next_node_names);
    }

  /* Set previous node pointers. */
  for (ni = 0; ni < vec_len (nm->nodes); ni++)
    {
      vlib_node_t *n_next;
      uword i;

      n = vec_elt (nm->nodes, ni);

      for (i = 0; i < vec_len (n->next_nodes); i++)
	{
	  if (n->next_nodes[i] >= vec_len (nm->nodes))
	    continue;

	  n_next = vec_elt (nm->nodes, n->next_nodes[i]);
	  n_next->prev_node_bitmap =
	    clib_bitmap_ori (n_next->prev_node_bitmap, n->index);
	}
    }

  {
    vlib_next_frame_t *nf;
    vlib_node_runtime_t *r;
    vlib_node_t *next;
    uword i;

    vec_foreach (r, nm->nodes_by_type[VLIB_NODE_TYPE_INTERNAL])
    {
      if (r->n_next_nodes == 0)
	continue;

      n = vlib_get_node (vm, r->node_index);
      nf = vec_elt_at_index (nm->next_frames, r->next_frame_index);

      for (i = 0; i < vec_len (n->next_nodes); i++)
	{
	  next = vlib_get_node (vm, n->next_nodes[i]);

	  /* Validate node runtime indices are correctly initialized. */
	  ASSERT (nf[i].node_runtime_index == next->runtime_index);

	  nf[i].flags = 0;
	  if (next->flags & VLIB_NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH)
	    nf[i].flags |= VLIB_FRAME_NO_FREE_AFTER_DISPATCH;
	}
    }
  }

done:
  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
