/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/stats/stats.h>

vlib_stats_main_t vlib_stats_main;

void
vlib_stats_segment_lock (void)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();

  /* already locked by us */
  if (sm->shared_header->in_progress &&
      vm->thread_index == sm->locking_thread_index)
    goto done;

  ASSERT (sm->locking_thread_index == ~0);
  ASSERT (sm->shared_header->in_progress == 0);
  ASSERT (sm->n_locks == 0);

  clib_spinlock_lock (sm->stat_segment_lockp);

  sm->shared_header->in_progress = 1;

  // Make sure in_progress write is visible to other cores before writing
  // to memory
  CLIB_MEMORY_BARRIER();

  sm->locking_thread_index = vm->thread_index;
done:
  sm->n_locks++;
}

void
vlib_stats_segment_unlock (void)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();

  ASSERT (sm->shared_header->in_progress == 1);
  ASSERT (sm->locking_thread_index == vm->thread_index);
  ASSERT (sm->n_locks > 0);

  sm->n_locks--;

  if (sm->n_locks > 0)
    return;

  // Make sure all writes are visible to other cores before increasing the epoch
  // Release would be enough but we use full for symmetry with the lock function
  CLIB_MEMORY_BARRIER();
  sm->shared_header->epoch++;

  // Here release is enough
  __atomic_store_n (&sm->shared_header->in_progress, 0, __ATOMIC_RELEASE);
  sm->locking_thread_index = ~0;
  clib_spinlock_unlock (sm->stat_segment_lockp);
}

/*
 * Change heap to the stats shared memory segment
 */
void *
vlib_stats_set_heap ()
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();

  ASSERT (sm && sm->shared_header);
  return clib_mem_set_heap (sm->heap);
}

u32
vlib_stats_find_entry_index (char *fmt, ...)
{
  u8 *name;
  va_list va;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  vec_add1 (name, 0);

  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  hash_pair_t *hp = hash_get_pair (sm->directory_vector_by_name, name);
  vec_free (name);
  return hp ? hp->value[0] : STAT_SEGMENT_INDEX_INVALID;
}

static void
hash_set_str_key_alloc (uword **h, const char *key, uword v)
{
  int size = strlen (key) + 1;
  void *copy = clib_mem_alloc (size);
  clib_memcpy_fast (copy, key, size);
  hash_set_mem (*h, copy, v);
}

static void
hash_unset_str_key_free (uword **h, const char *key)
{
  hash_pair_t *hp = hash_get_pair_mem (*h, key);
  if (hp)
    {
      void *_k = uword_to_pointer (hp->key, void *);
      hash_unset_mem (*h, _k);
      clib_mem_free (_k);
    }
}

u32
vlib_stats_create_counter (vlib_stats_entry_t *e)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  u32 index;

  if (sm->dir_vector_first_free_elt != CLIB_U32_MAX)
    {
      index = sm->dir_vector_first_free_elt;
      sm->dir_vector_first_free_elt = sm->directory_vector[index].index;
    }
  else
    {
      index = vec_len (sm->directory_vector);
      vec_validate (sm->directory_vector, index);
    }

  sm->directory_vector[index] = *e;

  hash_set_str_key_alloc (&sm->directory_vector_by_name, e->name, index);

  return index;
}

void
vlib_stats_remove_entry (u32 entry_index)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  counter_t **c;
  vlib_counter_t **vc;
  void *oldheap;
  u32 i;

  if (entry_index >= vec_len (sm->directory_vector))
    return;

  vlib_stats_segment_lock ();

  switch (e->type)
    {
    case STAT_DIR_TYPE_NAME_VECTOR:
      for (i = 0; i < vec_len (e->string_vector); i++)
	vec_free (e->string_vector[i]);
      vec_free (e->string_vector);
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      c = e->data;
      e->data = 0;
      oldheap = clib_mem_set_heap (sm->heap);
      for (i = 0; i < vec_len (c); i++)
	vec_free (c[i]);
      vec_free (c);
      clib_mem_set_heap (oldheap);
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      vc = e->data;
      e->data = 0;
      oldheap = clib_mem_set_heap (sm->heap);
      for (i = 0; i < vec_len (vc); i++)
	vec_free (vc[i]);
      vec_free (vc);
      clib_mem_set_heap (oldheap);
      break;

    case STAT_DIR_TYPE_SCALAR_INDEX:
    case STAT_DIR_TYPE_SYMLINK:
      break;
    default:
      ASSERT (0);
    }

  vlib_stats_segment_unlock ();

  hash_unset_str_key_free (&sm->directory_vector_by_name, e->name);

  memset (e, 0, sizeof (*e));
  e->type = STAT_DIR_TYPE_EMPTY;

  e->value = sm->dir_vector_first_free_elt;
  sm->dir_vector_first_free_elt = entry_index;
}

static void
vlib_stats_set_entry_name (vlib_stats_entry_t *e, char *s)
{
  u32 i, len = VLIB_STATS_MAX_NAME_SZ - 1;

  for (i = 0; i < len; i++)
    {
      e->name[i] = s[i];
      if (s[i] == 0)
	return;
    }
  ASSERT (i < VLIB_STATS_MAX_NAME_SZ - 1);
  s[i] = 0;
}

static u32
vlib_stats_new_entry_internal (stat_directory_type_t t, u8 *name)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_shared_header_t *shared_header = sm->shared_header;
  vlib_stats_entry_t e = { .type = t };

  ASSERT (shared_header);

  u32 vector_index = vlib_stats_find_entry_index ("%v", name);
  if (vector_index != STAT_SEGMENT_INDEX_INVALID) /* Already registered */
    {
      vector_index = ~0;
      goto done;
    }

  vec_add1 (name, 0);
  vlib_stats_set_entry_name (&e, (char *) name);

  vlib_stats_segment_lock ();
  vector_index = vlib_stats_create_counter (&e);

  shared_header->directory_vector = sm->directory_vector;

  vlib_stats_segment_unlock ();

done:
  vec_free (name);
  return vector_index;
}

u32
vlib_stats_add_gauge (char *fmt, ...)
{
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  return vlib_stats_new_entry_internal (STAT_DIR_TYPE_SCALAR_INDEX, name);
}

void
vlib_stats_set_gauge (u32 index, u64 value)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();

  ASSERT (index < vec_len (sm->directory_vector));
  sm->directory_vector[index].value = value;
}

u32
vlib_stats_add_timestamp (char *fmt, ...)
{
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  return vlib_stats_new_entry_internal (STAT_DIR_TYPE_SCALAR_INDEX, name);
}

void
vlib_stats_set_timestamp (u32 entry_index, f64 value)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();

  ASSERT (entry_index < vec_len (sm->directory_vector));
  sm->directory_vector[entry_index].value = value;
}

vlib_stats_string_vector_t
vlib_stats_add_string_vector (char *fmt, ...)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  va_list va;
  vlib_stats_header_t *sh;
  vlib_stats_string_vector_t sv;
  u32 index;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  index = vlib_stats_new_entry_internal (STAT_DIR_TYPE_NAME_VECTOR, name);
  if (index == CLIB_U32_MAX)
    return 0;

  sv = vec_new_generic (vlib_stats_string_vector_t, 0,
			sizeof (vlib_stats_header_t), 0, sm->heap);
  sh = vec_header (sv);
  sh->entry_index = index;
  sm->directory_vector[index].string_vector = sv;
  return sv;
}

void
vlib_stats_set_string_vector (vlib_stats_string_vector_t *svp,
			      u32 vector_index, char *fmt, ...)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_header_t *sh = vec_header (*svp);
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, sh->entry_index);
  va_list va;
  u8 *s;

  if (fmt[0] == 0)
    {
      if (vec_len (e->string_vector) <= vector_index)
	return;

      if (e->string_vector[vector_index] == 0)
	return;

      vlib_stats_segment_lock ();
      vec_free (e->string_vector[vector_index]);
      vlib_stats_segment_unlock ();
      return;
    }

  vlib_stats_segment_lock ();

  ASSERT (e->string_vector);

  vec_validate (e->string_vector, vector_index);
  svp[0] = e->string_vector;

  s = e->string_vector[vector_index];

  if (s == 0)
    s = vec_new_heap (u8 *, 0, sm->heap);

  vec_reset_length (s);

  va_start (va, fmt);
  s = va_format (s, fmt, &va);
  va_end (va);
  vec_add1 (s, 0);

  e->string_vector[vector_index] = s;

  vlib_stats_segment_unlock ();
}

void
vlib_stats_free_string_vector (vlib_stats_string_vector_t *sv)
{
  vlib_stats_header_t *sh = vec_header (*sv);
  vlib_stats_remove_entry (sh->entry_index);
}

u32
vlib_stats_add_counter_vector (char *fmt, ...)
{
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  return vlib_stats_new_entry_internal (STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE,
					name);
}

u32
vlib_stats_add_counter_pair_vector (char *fmt, ...)
{
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  return vlib_stats_new_entry_internal (STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED,
					name);
}

static int
vlib_stats_validate_will_expand_internal (u32 entry_index, va_list *va)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  void *oldheap;
  int rv = 1;

  oldheap = clib_mem_set_heap (sm->heap);
  if (e->type == STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE)
    {
      u32 idx0 = va_arg (*va, u32);
      u32 idx1 = va_arg (*va, u32);
      u64 **data = e->data;

      if (idx0 >= vec_len (data))
	goto done;

      for (u32 i = 0; i <= idx0; i++)
	if (idx1 >= vec_max_len (data[i]))
	  goto done;
    }
  else if (e->type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
    {
      u32 idx0 = va_arg (*va, u32);
      u32 idx1 = va_arg (*va, u32);
      vlib_counter_t **data = e->data;

      va_end (*va);

      if (idx0 >= vec_len (data))
	goto done;

      for (u32 i = 0; i <= idx0; i++)
	if (idx1 >= vec_max_len (data[i]))
	  goto done;
    }
  else
    ASSERT (0);

  rv = 0;
done:
  clib_mem_set_heap (oldheap);
  return rv;
}

int
vlib_stats_validate_will_expand (u32 entry_index, ...)
{
  va_list va;
  int rv;

  va_start (va, entry_index);
  rv = vlib_stats_validate_will_expand_internal (entry_index, &va);
  va_end (va);
  return rv;
}

void
vlib_stats_validate (u32 entry_index, ...)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  void *oldheap;
  va_list va;
  int will_expand;

  va_start (va, entry_index);
  will_expand = vlib_stats_validate_will_expand_internal (entry_index, &va);
  va_end (va);

  if (will_expand)
    vlib_stats_segment_lock ();

  oldheap = clib_mem_set_heap (sm->heap);

  va_start (va, entry_index);

  if (e->type == STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE)
    {
      u32 idx0 = va_arg (va, u32);
      u32 idx1 = va_arg (va, u32);
      u64 **data = e->data;

      vec_validate_aligned (data, idx0, CLIB_CACHE_LINE_BYTES);

      for (u32 i = 0; i <= idx0; i++)
	vec_validate_aligned (data[i], idx1, CLIB_CACHE_LINE_BYTES);
      e->data = data;
    }
  else if (e->type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
    {
      u32 idx0 = va_arg (va, u32);
      u32 idx1 = va_arg (va, u32);
      vlib_counter_t **data = e->data;

      vec_validate_aligned (data, idx0, CLIB_CACHE_LINE_BYTES);

      for (u32 i = 0; i <= idx0; i++)
	vec_validate_aligned (data[i], idx1, CLIB_CACHE_LINE_BYTES);
      e->data = data;
    }
  else
    ASSERT (0);

  va_end (va);

  clib_mem_set_heap (oldheap);

  if (will_expand)
    vlib_stats_segment_unlock ();
}

u32
vlib_stats_add_symlink (u32 entry_index, u32 vector_index, char *fmt, ...)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_shared_header_t *shared_header = sm->shared_header;
  vlib_stats_entry_t e;
  va_list va;
  u8 *name;

  ASSERT (shared_header);
  ASSERT (entry_index < vec_len (sm->directory_vector));

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  if (vlib_stats_find_entry_index ("%v", name) == STAT_SEGMENT_INDEX_INVALID)
    {
      vec_add1 (name, 0);
      vlib_stats_set_entry_name (&e, (char *) name);
      e.type = STAT_DIR_TYPE_SYMLINK;
      e.index1 = entry_index;
      e.index2 = vector_index;
      vector_index = vlib_stats_create_counter (&e);

      /* Warn clients to refresh any pointers they might be holding */
      shared_header->directory_vector = sm->directory_vector;
    }
  else
    vector_index = ~0;

  vec_free (name);
  return vector_index;
}

void
vlib_stats_rename_symlink (u64 entry_index, char *fmt, ...)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  va_list va;
  u8 *new_name;

  hash_unset_str_key_free (&sm->directory_vector_by_name, e->name);

  va_start (va, fmt);
  new_name = va_format (0, fmt, &va);
  va_end (va);

  vec_add1 (new_name, 0);
  vlib_stats_set_entry_name (e, (char *) new_name);
  hash_set_str_key_alloc (&sm->directory_vector_by_name, e->name, entry_index);
  vec_free (new_name);
}

f64
vlib_stats_get_segment_update_rate (void)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  return sm->update_interval;
}

void
vlib_stats_register_collector_fn (vlib_stats_collector_reg_t *reg)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_collector_t *c;

  ASSERT (reg->entry_index != ~0);

  pool_get_zero (sm->collectors, c);
  c->fn = reg->collect_fn;
  c->entry_index = reg->entry_index;
  c->vector_index = reg->vector_index;
  c->private_data = reg->private_data;

  return;
}
