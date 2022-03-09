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

  sm->shared_header->epoch++;
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
  return hp ? hp->value[0] : VLIB_STATS_INVALID_INDEX;
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
  void *oldheap;
  u32 index;

  index = clib_bitmap_first_clear (sm->used_indices);
  sm->used_indices = clib_bitmap_set (sm->used_indices, index, 1);

  oldheap = clib_mem_set_heap (sm->heap);
  vec_validate (sm->directory_vector, index);
  sm->directory_vector[index] = *e;
  sm->directory_vector[index].in_use = 1;

  clib_mem_set_heap (oldheap);
  hash_set_str_key_alloc (&sm->directory_vector_by_name, e->name, index);

  return index;
}

void
vlib_stats_remove_entry (u32 entry_index)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  void *oldheap;

  if (entry_index >= vec_len (sm->directory_vector))
    return;

  oldheap = clib_mem_set_heap (sm->heap);

  clib_mem_set_heap (oldheap);
  hash_unset_str_key_free (&sm->directory_vector_by_name, e->name);
  sm->used_indices = clib_bitmap_set (sm->used_indices, entry_index, 0);

  memset (e, 0, sizeof (*e));
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
vlib_stats_new_entry_internal (u8 *name, vlib_stats_data_type_t data_type,
			       u8 n_dim)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_shared_header_t *shared_header = sm->shared_header;
  vlib_stats_entry_t e = { .data_type = data_type, .n_dimensions = n_dim };

  ASSERT (shared_header);

  u32 vector_index = vlib_stats_find_entry_index ("%v", name);
  if (vector_index != VLIB_STATS_INVALID_INDEX) /* Already registered */
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
  return vlib_stats_new_entry_internal (name, VLIB_STATS_TYPE_UINT64, 0);
}

void
vlib_stats_set_gauge (u32 index, u64 value)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();

  ASSERT (index < vec_len (sm->directory_vector));
  sm->directory_vector[index].value = value;
}

u32
vlib_stats_add_epoch (char *fmt, ...)
{
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  return vlib_stats_new_entry_internal (name, VLIB_STATS_TYPE_EPOCH, 0);
}

void
vlib_stats_set_epoch (u32 entry_index, f64 value)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  e->value_as_float64 = value;
}

f64
vlib_stats_get_epoch (u32 entry_index)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  return e->value_as_float64;
}

u32
vlib_stats_add_string_vector (char *fmt, ...)
{
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  return vlib_stats_new_entry_internal (name, VLIB_STATS_TYPE_STRING, 1);
}

void
vlib_stats_set_string_vector (u32 entry_index, u32 vector_index, char *fmt,
			      ...)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  va_list va;
  void *oldheap;

  vlib_stats_segment_lock ();

  oldheap = clib_mem_set_heap (sm->heap);

  vec_validate (e->string_vector, vector_index);
  vec_reset_length (e->string_vector[vector_index]);

  va_start (va, fmt);
  e->string_vector[vector_index] =
    va_format (e->string_vector[vector_index], fmt, &va);
  va_end (va);

  clib_mem_set_heap (oldheap);

  vlib_stats_segment_unlock ();
}

u32
vlib_stats_add_counter_vector (char *fmt, ...)
{
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  return vlib_stats_new_entry_internal (name, VLIB_STATS_TYPE_UINT64, 1);
}

u32
vlib_stats_add (vlib_stats_data_type_t dt, u8 dim, char *fmt, ...)
{
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  return vlib_stats_new_entry_internal (name, dt, dim);
}

static void
vlib_stats_validate_last (u8 **d0, u32 elt_size, u32 index)
{
  if (*d0)
    _vec_len (*d0) *= elt_size;
  vec_validate_aligned (*d0, elt_size * (index + 1) - 1,
			CLIB_CACHE_LINE_BYTES);
  _vec_len (*d0) /= elt_size;
}

void
vlib_stats_validate (u32 entry_index, ...)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  vlib_stats_data_type_info_t *t = vlib_stats_data_types + e->data_type;
  void *oldheap;
  va_list va;

  va_start (va, entry_index);

  oldheap = clib_mem_set_heap (sm->heap);

  vlib_stats_segment_lock ();

  if (e->n_dimensions == 1)
    {
      u32 idx0 = va_arg (va, u32);
      vlib_stats_validate_last ((u8 **) &e->data, t->size, idx0);
    }
  else if (e->n_dimensions == 2)
    {
      u32 idx1 = va_arg (va, u32);
      u32 idx0 = va_arg (va, u32);
      u8 **data = e->data;

      vec_validate_aligned (data, idx1, CLIB_CACHE_LINE_BYTES);

      for (u32 i = 0; i <= idx1; i++)
	vlib_stats_validate_last (data + i, t->size, idx0);
      e->data = data;
    }
  else if (e->n_dimensions == 3)
    {
      u32 idx2 = va_arg (va, u32);
      u32 idx1 = va_arg (va, u32);
      u32 idx0 = va_arg (va, u32);
      u8 ***data = e->data;

      vec_validate_aligned (data, idx2, CLIB_CACHE_LINE_BYTES);
      for (u32 i = 0; i < vec_len (data); i++)
	{
	  vec_validate_aligned (data[idx2], idx1, CLIB_CACHE_LINE_BYTES);
	  for (u32 j = 0; j <= vec_len (data[idx2]); j++)
	    vlib_stats_validate_last (data[idx2] + j, t->size, idx0);
	}
      e->data = data;
    }
  else
    ASSERT (0);

  va_end (va);
  vlib_stats_segment_unlock ();
  clib_mem_set_heap (oldheap);
}

void *
vlib_stats_get_data_ptr (u32 entry_index, ...)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  vlib_stats_data_type_info_t *t = vlib_stats_data_types + e->data_type;
  va_list va;

  va_start (va, entry_index);

  if (e->n_dimensions == 0)
    {
      return t->size > sizeof (e->value) ? e->data : &e->value;
    }
  else if (e->n_dimensions == 1)
    {
      u32 idx0 = va_arg (va, u32);
      return (u8 *) e->data + (idx0 * t->size);
    }
  else if (e->n_dimensions == 2)
    {
      u32 idx1 = va_arg (va, u32);
      u32 idx0 = va_arg (va, u32);
      u8 **data = e->data;

      return (u8 *) data[idx1] + (idx0 * t->size);
    }
  else if (e->n_dimensions == 3)
    {
      u32 idx2 = va_arg (va, u32);
      u32 idx1 = va_arg (va, u32);
      u32 idx0 = va_arg (va, u32);
      u8 ***data = e->data;

      return (u8 *) data[idx2][idx1] + (idx0 * t->size);
    }
  else
    ASSERT (0);
  return 0;
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

  if (vlib_stats_find_entry_index ("%v", name) == VLIB_STATS_INVALID_INDEX)
    {
      vec_add1 (name, 0);
      vlib_stats_set_entry_name (&e, (char *) name);
      e.data_type = VLIB_STATS_TYPE_SYMLINK;
      e.n_dimensions = 0;
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
