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
  vlib_worker_thread_node_runtime_update ();
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
      pool_foreach (pf, nm->suspended_process_frames)  {
	  if (pf->next_frame_index != ~0 && pf->next_frame_index >= i)
	    pf->next_frame_index += n_insert;
      }
      /* *INDENT-ON* */

      r->n_next_nodes = vec_len (node->next_nodes);
    }

  /* Set frame's node runtime index. */
  next_node = vlib_get_node (vm, node->next_nodes[next_index]);
  nf = nm->next_frames + r->next_frame_index + next_index;
  nf->node_runtime_index = next_node->runtime_index;

  vlib_worker_thread_node_runtime_update ();
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
  vlib_node_t *node, *next, *old_next;
  u32 old_next_index;
  uword *p;

  ASSERT (vlib_get_thread_index () == 0);

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

  vlib_worker_thread_barrier_sync (vm);

  if (slot == ~0)
    slot = vec_len (node->next_nodes);

  vec_validate_init_empty (node->next_nodes, slot, ~0);
  vec_validate (node->n_vectors_by_next_node, slot);

  if ((old_next_index = node->next_nodes[slot]) != ~0u)
    {
      hash_unset (node->next_slot_by_node, old_next_index);
      old_next = vlib_get_node (vm, old_next_index);
      old_next->prev_node_bitmap =
	clib_bitmap_andnoti (old_next->prev_node_bitmap, node_index);
    }

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
    clib_bitmap_foreach (sib_node_index, node->sibling_bitmap)  {
      sib_node = vec_elt (nm->nodes, sib_node_index);
      if (sib_node != node)
	{
	  sib_slot = vlib_node_add_next_with_slot (vm, sib_node_index, next_node_index, slot);
	  ASSERT (sib_slot == slot);
	}
    }
    /* *INDENT-ON* */
  }

  vlib_worker_thread_barrier_release (vm);
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

  clib_memset (&t, 0, sizeof (t));

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

vlib_node_function_t *
vlib_node_get_preferred_node_fn_variant (vlib_main_t *vm,
					 vlib_node_fn_registration_t *regs)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_fn_registration_t *r;
  vlib_node_fn_variant_t *v;
  vlib_node_function_t *fn;
  int priority = -1;

  if (nm->node_fn_default_march_variant != ~0)
    {
      r = regs;
      while (r)
	{
	  if (r->march_variant == nm->node_fn_default_march_variant)
	    return r->function;
	  r = r->next_registration;
	}
    }

  r = regs;
  while (r)
    {
      v = vec_elt_at_index (nm->variants, r->march_variant);
      if (v->priority > priority)
	{
	  priority = v->priority;
	  fn = r->function;
	}
      r = r->next_registration;
    }

  ASSERT (fn);
  return fn;
}

static void
register_node (vlib_main_t * vm, vlib_node_registration_t * r)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  int i;

  if (CLIB_DEBUG > 0)
    {
      /* Default (0) type should match INTERNAL. */
      vlib_node_t zero = { 0 };
      ASSERT (VLIB_NODE_TYPE_INTERNAL == zero.type);
    }

  if (r->node_fn_registrations)
    {
      /* to avoid confusion, please remove ".function " statiement from
         CLIB_NODE_REGISTRATION() if using function function candidates */
      ASSERT (r->function == 0);

      r->function =
	vlib_node_get_preferred_node_fn_variant (vm, r->node_fn_registrations);
    }

  ASSERT (r->function != 0);

  n = clib_mem_alloc_no_fail (sizeof (n[0]));
  clib_memset (n, 0, sizeof (n[0]));
  n->index = vec_len (nm->nodes);
  n->node_fn_registrations = r->node_fn_registrations;
  n->protocol_hint = r->protocol_hint;

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
    /* vlib_get_node_by_name() expects NULL-terminated strings */
    u8 *name = format (0, "%v%c", n->name, 0);
    vlib_node_t *o = vlib_get_node_by_name (vm, name);
    vec_free (name);
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
  vlib_register_errors (vm, n->index, r->n_errors, r->error_strings,
			r->error_counters);
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

	log2_n_stack_bytes = clib_max (r->process_log2_n_stack_bytes,
				       VLIB_PROCESS_LOG2_STACK_SIZE);
	log2_n_stack_bytes = clib_max (log2_n_stack_bytes,
				       clib_mem_get_log2_page_size ());

	p = clib_mem_alloc_aligned (sizeof (p[0]), CLIB_CACHE_LINE_BYTES);
	clib_memset (p, 0, sizeof (p[0]));
	p->log2_n_stack_bytes = log2_n_stack_bytes;

	p->stack = clib_mem_vm_map_stack (1ULL << log2_n_stack_bytes,
					  CLIB_MEM_PAGE_SZ_DEFAULT,
					  "process stack: %U",
					  format_vlib_node_name, vm,
					  n->index);

	if (p->stack == CLIB_MEM_VM_MAP_FAILED)
	  clib_panic ("failed to allocate process stack (%d bytes)",
		      1ULL << log2_n_stack_bytes);

	/* Process node's runtime index is really index into process
	   pointer vector. */
	n->runtime_index = vec_len (nm->processes);

	vec_add1 (nm->processes, p);

	/* Paint first stack word with magic number so we can at least
	   detect process stack overruns. */
	p->stack[0] = VLIB_PROCESS_STACK_MAGIC;

	/* Node runtime is stored inside of process. */
	rt = &p->node_runtime;
      }
    else
      {
	vec_add2_aligned (nm->nodes_by_type[n->type], rt, 1,
			  /* align */ CLIB_CACHE_LINE_BYTES);
	if (n->type == VLIB_NODE_TYPE_INPUT)
	  clib_interrupt_resize (&nm->interrupts,
				 vec_len (nm->nodes_by_type[n->type]));
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
      rt->errors[i] = n->error_heap_index + i;

    STATIC_ASSERT_SIZEOF (vlib_node_runtime_t, 128);
    ASSERT (vec_len (n->runtime_data) <= VLIB_NODE_RUNTIME_DATA_SIZE);

    if (vec_len (n->runtime_data) > 0)
      clib_memcpy (rt->runtime_data, n->runtime_data,
		   vec_len (n->runtime_data));
    else
      clib_memset (rt->runtime_data, 0, VLIB_NODE_RUNTIME_DATA_SIZE);

    vec_free (n->runtime_data);
  }
#undef _
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
  vlib_buffer_free (vm, vlib_frame_vector_args (frame), n_vectors);
  vlib_frame_free (vm, node, frame);

  return n_vectors;
}

void
vlib_register_all_node_march_variants (vlib_main_t *vm)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_fn_variant_t *v;
  int prio = -1;

  nm->node_fn_default_march_variant = ~0;
  ASSERT (nm->variants == 0);
  vec_add2 (nm->variants, v, 1);
  v->desc = v->suffix = "default";
  v->index = CLIB_MARCH_VARIANT_TYPE;

#define _(s, n)                                                               \
  vec_add2 (nm->variants, v, 1);                                              \
  v->suffix = #s;                                                             \
  v->index = CLIB_MARCH_VARIANT_TYPE_##s;                                     \
  v->priority = clib_cpu_march_priority_##s ();                               \
  v->desc = n;

  foreach_march_variant;
#undef _

  nm->node_fn_march_variant_by_suffix = hash_create_string (0, sizeof (u32));

  vec_foreach (v, nm->variants)
    {
      ASSERT (v->index == v - nm->variants);
      hash_set (nm->node_fn_march_variant_by_suffix, v->suffix, v->index);
      if (v->priority > prio)
	prio = v->priority;
    }
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

void
vlib_node_get_nodes (vlib_main_t * vm, u32 max_threads, int include_stats,
		     int barrier_sync, vlib_node_t **** node_dupsp,
		     vlib_main_t *** stat_vmsp)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  vlib_node_t ***node_dups = *node_dupsp;
  vlib_node_t **nodes;
  vlib_main_t **stat_vms = *stat_vmsp;
  vlib_main_t *stat_vm;
  uword i, j;
  u32 threads_to_serialize;

  if (vec_len (stat_vms) == 0)
    {
      for (i = 0; i < vec_len (vlib_mains); i++)
	{
	  stat_vm = vlib_mains[i];
	  if (stat_vm)
	    vec_add1 (stat_vms, stat_vm);
	}
    }

  threads_to_serialize = clib_min (max_threads, vec_len (stat_vms));

  vec_validate (node_dups, threads_to_serialize - 1);

  /*
   * Barrier sync across stats scraping.
   * Otherwise, the counts will be grossly inaccurate.
   */
  if (barrier_sync)
    vlib_worker_thread_barrier_sync (vm);

  for (j = 0; j < threads_to_serialize; j++)
    {
      stat_vm = stat_vms[j];
      nm = &stat_vm->node_main;

      if (include_stats)
	{
	  for (i = 0; i < vec_len (nm->nodes); i++)
	    {
	      n = nm->nodes[i];
	      vlib_node_sync_stats (stat_vm, n);
	    }
	}

      nodes = node_dups[j];
      vec_validate (nodes, vec_len (nm->nodes) - 1);
      clib_memcpy (nodes, nm->nodes, vec_len (nm->nodes) * sizeof (nodes[0]));
      node_dups[j] = nodes;
    }

  if (barrier_sync)
    vlib_worker_thread_barrier_release (vm);

  *node_dupsp = node_dups;
  *stat_vmsp = stat_vms;
}

clib_error_t *
vlib_node_main_init (vlib_main_t * vm)
{
  vlib_node_main_t *nm = &vm->node_main;
  clib_error_t *error = 0;
  vlib_node_t *n;
  uword ni;

  nm->frame_sizes = vec_new (vlib_frame_size_t, 1);
#ifdef VLIB_SUPPORTS_ARBITRARY_SCALAR_SIZES
  nm->frame_size_hash = hash_create (0, sizeof (uword));
#endif
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
	clib_bitmap_foreach (si, sib->sibling_bitmap)  {
	      vlib_node_t * m = vec_elt (nm->nodes, si);

	      /* Connect all of sibling's siblings to us. */
	      m->sibling_bitmap = clib_bitmap_ori (m->sibling_bitmap, n->index);

	      /* Connect us to all of sibling's siblings. */
	      n->sibling_bitmap = clib_bitmap_ori (n->sibling_bitmap, si);
	    }
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

u32
vlib_process_create (vlib_main_t * vm, char *name,
		     vlib_node_function_t * f, u32 log2_n_stack_bytes)
{
  vlib_node_registration_t r;
  vlib_node_t *n;

  memset (&r, 0, sizeof (r));

  r.name = (char *) format (0, "%s", name, 0);
  r.function = f;
  r.process_log2_n_stack_bytes = log2_n_stack_bytes;
  r.type = VLIB_NODE_TYPE_PROCESS;

  vlib_worker_thread_barrier_sync (vm);

  vlib_register_node (vm, &r);
  vec_free (r.name);

  vlib_worker_thread_node_runtime_update ();
  vlib_worker_thread_barrier_release (vm);

  n = vlib_get_node (vm, r.index);
  vlib_start_process (vm, n->runtime_index);

  return (r.index);
}

int
vlib_node_set_march_variant (vlib_main_t *vm, u32 node_index,
			     clib_march_variant_type_t march_variant)
{
  vlib_node_fn_registration_t *fnr;
  vlib_node_fn_variant_t *v;
  vlib_node_t *n = vlib_get_node (vm, node_index);

  if (n->node_fn_registrations == 0)
    return -1;

  fnr = n->node_fn_registrations;
  v = vec_elt_at_index (vm->node_main.variants, march_variant);

  while (fnr)
    {
      if (fnr->march_variant == v->index)
	{
	  n->function = fnr->function;

	  for (int i = 0; i < vec_len (vlib_mains); i++)
	    {
	      vlib_node_runtime_t *nrt;
	      nrt = vlib_node_get_runtime (vlib_mains[i], n->index);
	      nrt->function = fnr->function;
	    }
	  return 0;
	}
      fnr = fnr->next_registration;
    }
  return -1;
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
