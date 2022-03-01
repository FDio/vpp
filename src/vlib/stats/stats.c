/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/stats/stats.h>

vlib_stats_segment_t stat_segment_main;
#define STATSEG_MAX_NAMESZ 128

/*
 *  Used only by VPP writers
 */

void
vlib_stats_segment_lock (void)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  clib_spinlock_lock (sm->stat_segment_lockp);
  sm->shared_header->in_progress = 1;
}

void
vlib_stats_segment_unlock (void)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  sm->shared_header->epoch++;
  sm->shared_header->in_progress = 0;
  clib_spinlock_unlock (sm->stat_segment_lockp);
}

/*
 * Change heap to the stats shared memory segment
 */
void *
vlib_stats_set_heap ()
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);

  ASSERT (sm && sm->shared_header);
  return clib_mem_set_heap (sm->heap);
}

u32
vlib_stats_find_directory_index (char *fmt, ...)
{
  u8 *name;
  va_list va;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  vec_add1 (name, 0);

  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  hash_pair_t *hp = hash_get_pair (sm->directory_vector_by_name, name);
  vec_free (name);
  return hp ? hp->value[0] : STAT_SEGMENT_INDEX_INVALID;
}

static u32
vlib_stats_get_next_vector_index ()
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  ssize_t i;

  vec_foreach_index_backwards (i, sm->directory_vector)
    if (sm->directory_vector[i].type == STAT_DIR_TYPE_EMPTY)
      return i;

  return vec_len (sm->directory_vector);
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
vlib_stats_create_counter (vlib_stats_directory_entry_t *e)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  void *oldheap;

  oldheap = clib_mem_set_heap (sm->heap);

  u32 index = vlib_stats_get_next_vector_index ();
  vec_validate (sm->directory_vector, index);
  sm->directory_vector[index] = *e;

  clib_mem_set_heap (sm->hash_heap);
  hash_set_str_key_alloc (&sm->directory_vector_by_name, e->name, index);
  clib_mem_set_heap (oldheap);

  return index;
}

void
vlib_stats_remove_entry (u32 entry_index)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vlib_stats_directory_entry_t *e = sm->directory_vector + entry_index;
  void *oldheap;
  u32 i;

  if (entry_index >= vec_len (sm->directory_vector))
    return;

  oldheap = clib_mem_set_heap (sm->heap);

  switch (e->type)
    {
    case STAT_DIR_TYPE_NAME_VECTOR:
      for (i = 0; i < vec_len (e->string_vector); i++)
	vec_free (e->string_vector[i]);
      vec_free (e->string_vector);
      break;

    case STAT_DIR_TYPE_SCALAR_INDEX:
    case STAT_DIR_TYPE_SYMLINK:
      break;
    default:
      ASSERT (0);
    }

  clib_mem_set_heap (sm->hash_heap);
  hash_unset_str_key_free (&sm->directory_vector_by_name, e->name);
  clib_mem_set_heap (oldheap);

  memset (e, 0, sizeof (*e));
  e->type = STAT_DIR_TYPE_EMPTY;
}

void
vlib_stats_update_counter (void *cm_arg, u32 cindex,
			   stat_directory_type_t type)
{
  vlib_simple_counter_main_t *cm = (vlib_simple_counter_main_t *) cm_arg;
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vlib_stats_shared_header_t *shared_header = sm->shared_header;
  char *stat_segment_name;
  vlib_stats_directory_entry_t e = { 0 };

  /* Not all counters have names / hash-table entries */
  if (!cm->name && !cm->stat_segment_name)
    return;

  ASSERT (shared_header);

  vlib_stats_segment_lock ();

  /* Lookup hash-table is on the main heap */
  stat_segment_name = cm->stat_segment_name ? cm->stat_segment_name : cm->name;

  u32 vector_index = vlib_stats_find_directory_index ("%s", stat_segment_name);

  /* Update the vector */
  if (vector_index == STAT_SEGMENT_INDEX_INVALID)
    { /* New */
      strncpy_s (e.name, STATSEG_MAX_NAMESZ, stat_segment_name,
		 STATSEG_MAX_NAMESZ - 1);
      e.type = type;
      vector_index = vlib_stats_create_counter (&e);
    }

  vlib_stats_directory_entry_t *ep = &sm->directory_vector[vector_index];
  ep->data = cm->counters;

  /* Reset the client hash table pointer, since it WILL change! */
  shared_header->directory_vector = sm->directory_vector;

  vlib_stats_segment_unlock ();
}

void
vlib_stats_register_error_index (u8 *name, u64 *em_vec, u64 index)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vlib_stats_shared_header_t *shared_header = sm->shared_header;
  vlib_stats_directory_entry_t e;

  ASSERT (shared_header);

  vlib_stats_segment_lock ();
  u32 vector_index = vlib_stats_find_directory_index ("%s", name);

  if (vector_index == STAT_SEGMENT_INDEX_INVALID)
    {
      memcpy (e.name, name, vec_len (name));
      e.name[vec_len (name)] = '\0';
      e.type = STAT_DIR_TYPE_ERROR_INDEX;
      e.index = index;
      vector_index = vlib_stats_create_counter (&e);

      /* Warn clients to refresh any pointers they might be holding */
      shared_header->directory_vector = sm->directory_vector;
    }

  vlib_stats_segment_unlock ();
}

void
vlib_stats_update_error_vector (u64 *error_vector, u32 thread_index, int lock)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vlib_stats_shared_header_t *shared_header = sm->shared_header;
  void *oldheap = clib_mem_set_heap (sm->heap);

  ASSERT (shared_header);

  if (lock)
    vlib_stats_segment_lock ();

  /* Reset the client hash table pointer, since it WILL change! */
  vec_validate (sm->error_vector, thread_index);
  sm->error_vector[thread_index] = error_vector;

  shared_header->error_vector = sm->error_vector;
  shared_header->directory_vector = sm->directory_vector;

  if (lock)
    vlib_stats_segment_unlock ();
  clib_mem_set_heap (oldheap);
}

void
vlib_stats_delete_cm (void *cm_arg)
{
  vlib_simple_counter_main_t *cm = (vlib_simple_counter_main_t *) cm_arg;
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vlib_stats_directory_entry_t *e;
  void *oldheap;

  /* Not all counters have names / hash-table entries */
  if (!cm->name && !cm->stat_segment_name)
    return;

  vlib_stats_segment_lock ();

  /* Lookup hash-table is on the main heap */
  char *stat_segment_name =
    cm->stat_segment_name ? cm->stat_segment_name : cm->name;
  u32 index = vlib_stats_find_directory_index ("%s", stat_segment_name);

  e = &sm->directory_vector[index];

  oldheap = clib_mem_set_heap (sm->hash_heap);
  hash_unset_str_key_free (&sm->directory_vector_by_name, e->name);
  clib_mem_set_heap (oldheap);

  memset (e, 0, sizeof (*e));
  e->type = STAT_DIR_TYPE_EMPTY;

  vlib_stats_segment_unlock ();
}

static u32
vlib_stats_new_entry_internal (stat_directory_type_t t, u8 *name)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vlib_stats_shared_header_t *shared_header = sm->shared_header;
  vlib_stats_directory_entry_t e = { .type = t };
  void *oldheap;

  ASSERT (shared_header);

  u32 vector_index = vlib_stats_find_directory_index ("%v", name);
  if (vector_index != STAT_SEGMENT_INDEX_INVALID) /* Already registered */
    {
      vector_index = ~0;
      goto done;
    }

  strcpy_s (e.name, sizeof (e.name), (char *) name);

  oldheap = vlib_stats_set_heap ();
  vlib_stats_segment_lock ();
  vector_index = vlib_stats_create_counter (&e);

  shared_header->directory_vector = sm->directory_vector;

  vlib_stats_segment_unlock ();
  clib_mem_set_heap (oldheap);

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
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);

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
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);

  ASSERT (entry_index < vec_len (sm->directory_vector));
  sm->directory_vector[entry_index].value = value;
}

u32
vlib_stats_add_string_vector (char *fmt, ...)
{
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  return vlib_stats_new_entry_internal (STAT_DIR_TYPE_NAME_VECTOR, name);
}

void
vlib_stats_set_string_vector (u32 entry_index, u32 vector_index, char *fmt,
			      ...)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vlib_stats_directory_entry_t *e = sm->directory_vector + entry_index;
  va_list va;
  void *oldheap;

  oldheap = clib_mem_set_heap (sm->heap);
  vlib_stats_segment_lock ();

  vec_validate (e->string_vector, vector_index);
  vec_reset_length (e->string_vector[vector_index]);

  va_start (va, fmt);
  e->string_vector[vector_index] =
    va_format (e->string_vector[vector_index], fmt, &va);
  va_end (va);

  vlib_stats_segment_unlock ();
  clib_mem_set_heap (oldheap);
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
vlib_stats_add_symlink (u32 entry_index, u32 vector_index, char *fmt, ...)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vlib_stats_shared_header_t *shared_header = sm->shared_header;
  vlib_stats_directory_entry_t e;
  va_list va;
  u8 *name;

  ASSERT (shared_header);

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  if (vlib_stats_find_directory_index ("%v", name) ==
      STAT_SEGMENT_INDEX_INVALID)
    {
      vec_add1 (name, 0);
      strncpy_s (e.name, STATSEG_MAX_NAMESZ, (char *) name,
		 STATSEG_MAX_NAMESZ - 1);
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
vlib_stats_rename_symlink (u64 index, char *fmt, ...)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vlib_stats_directory_entry_t *e;
  va_list va;
  u8 *new_name;
  void *oldheap;

  ASSERT (clib_mem_get_heap () == sm->heap);
  ASSERT (index < vec_len (sm->directory_vector));
  if (index > vec_len (sm->directory_vector))
    return;

  e = &sm->directory_vector[index];

  oldheap = clib_mem_set_heap (sm->hash_heap);
  hash_unset_str_key_free (&sm->directory_vector_by_name, e->name);
  clib_mem_set_heap (oldheap);

  va_start (va, fmt);
  new_name = va_format (0, fmt, &va);
  va_end (va);
  vec_add1 (new_name, 0);

  strncpy_s (e->name, STATSEG_MAX_NAMESZ, (char *) new_name,
	     STATSEG_MAX_NAMESZ - 1);

  oldheap = clib_mem_set_heap (sm->hash_heap);
  hash_set_str_key_alloc (&sm->directory_vector_by_name, e->name, index);
  clib_mem_set_heap (oldheap);
}

f64
vlib_stats_get_segment_update_rate (void)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  return sm->update_interval;
}

void
vlib_stats_register_update_fn (u32 vector_index,
			       vlib_stats_update_fn update_fn,
			       u32 caller_index)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  stat_segment_gauges_pool_t *gauge;

  pool_get (sm->gauges, gauge);
  gauge->fn = update_fn;
  gauge->caller_index = caller_index;
  gauge->directory_index = vector_index;

  return;
}
