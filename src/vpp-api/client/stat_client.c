// API
// Connect / Disconnect
// collect() / iterator over counters?
// Copy them out of shared memory as quickly as possibly?
// Scraping, and then let them be "dumped"?
// A way to register which counters are of interest?
// App to just send in name-list? And a data structure to fill in?
// then collect()


/*
 *------------------------------------------------------------------
 * stat_client.c
 *
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vppinfra/socket.h>
#include <svm/ssvm.h>
#include <vpp/stats/stats.h>
#include <regex.h>
#include "stat_client.h"

typedef struct
{
  char *name;
  stat_directory_type_t type;

  /* Pointer or offsets to actual values */
  void *valuep;
  u32 error_index;

  /* Actual value of counter */
  f64 scalar_value; /* Scalar pointer */
  u64 error_value;  /* Error index */

  f64 value;
  vlib_counter_t *counter_vec;
} cached_pointer_t;

typedef struct
{
  u64 current_epoch;
  volatile int segment_ready;
  ssvm_private_t stat_segment;  /* mapped stats segment object */
  clib_spinlock_t *stat_segment_lockp;  /* Spinlock for the stats segment */
  cached_pointer_t *cached_pointers;
  uword *counter_vector_by_name;
  //int nitems;
  u64 *error_base;
} stat_client_main_t;

stat_client_main_t stat_client_main;

// TODO: Use Linux memory libraries. Don't use VPP data-structures!!!
__attribute__((constructor))
static void
stat_client_constructor (void)
{
  clib_mem_init (0, 1 << 28);
#if USE_DLMALLOC == 0
  {
      u8 *heap;
      mheap_t *h;

      heap = clib_mem_get_per_cpu_heap ();
      h = mheap_header (heap);
      /* make the main heap thread-safe */
      h->flags |= MHEAP_FLAG_THREAD_SAFE;
  }
#endif
}

__attribute__((destructor))
static void
stat_client_destructor (void)
{
}

int
stat_segment_connect (char *socket_name)
{
  stat_client_main_t *sm = &stat_client_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  clib_socket_t s = { 0 };
  clib_error_t *err;
  int fd = -1, retval;

  s.config = socket_name;
  s.flags = CLIB_SOCKET_F_IS_CLIENT | CLIB_SOCKET_F_SEQPACKET;
  err = clib_socket_init (&s);
  if (err) {
    clib_error_report (err);
    return -1;
  }
  err = clib_socket_recvmsg (&s, 0, 0, &fd, 1);
  if (err) {
    clib_error_report (err);
    return -1;
  }
  clib_socket_close (&s);

  memset (ssvmp, 0, sizeof (*ssvmp));
  ssvmp->fd = fd;

  /* Note: this closes memfd.fd */
  retval = ssvm_slave_init_memfd (ssvmp);
  if (retval) {
    clib_warning ("WARNING: segment map returned %d", retval);
    return -1;
  }

  fformat (stdout, "Stat segment mapped OK...\n");

  ASSERT (ssvmp && ssvmp->sh);

  /* Pick up the segment lock from the shared memory header */
  shared_header = ssvmp->sh;
  sm->stat_segment_lockp = (clib_spinlock_t *) (shared_header->opaque[0]);
  sm->segment_ready = 1;

  sm->counter_vector_by_name = (uword *) shared_header->opaque[STAT_SEGMENT_OPAQUE_DIR];

  return 0;
}

int
stat_segment_disconnect (void)
{
  return 0;
}

/*
 * The application needs to register which counters it is interested
 * in.
 */
int
stat_segment_register (u8 *stats[])
{
  int i;
  uword *p;
  stat_client_main_t *sm = &stat_client_main;
  cached_pointer_t *cp, *cached_pointer_vec = 0;

  for (i = 0; i < vec_len (stats); i++) {
    printf("Registering counter: %s\n", stats[i]);
    p = hash_get_mem (sm->counter_vector_by_name, stats[i]);
    if (p == 0)	{
      clib_warning ("WARN: %s not in directory!", stats[i]);
      continue;
    }
    vec_add2(cached_pointer_vec, cp, 1);
    cp->name = strdup((char *)stats[i]); // Point to p->key instead?
  }
  sm->cached_pointers = cached_pointer_vec;

#if 0
  /* Dump all avaliable entries in directory */
  stat_segment_directory_entry_t *ep;
  hash_pair_t *q;
  hash_foreach_pair (q, sm->counter_vector_by_name,
    ({
      ep = (stat_segment_directory_entry_t *) (q->value[0]);
      printf("Name: %s Type %d\n", (char *)q->key, ep->type);
    }));
#endif
  return 0;
}

static void
maybe_update_cached_pointers (stat_client_main_t * sm,
			      ssvm_shared_header_t * shared_header)
{
  uword *p;
  int i;
  stat_segment_directory_entry_t *ep;
  cached_pointer_t *cp;
  //  u64 *valuep;

  /* Cached pointers OK? */
  if (sm->current_epoch ==
      (u64) shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH])
    return;

  fformat (stdout, "Updating cached pointers...\n");

  /* Special case /err/0/counter_vector */
  p = hash_get_mem (sm->counter_vector_by_name, "/err/0/counter_vector");
  if (p) {
    ep = (stat_segment_directory_entry_t *) (p[0]);
    sm->error_base = ep->value;
  } else {
    clib_warning ("WARN: Cannot find error base counter!");
    sm->error_base = 0;
  }
  
  /* Nope, fix them... */
  for (i = 0; i < vec_len(sm->cached_pointers); i++) {
    cp = &sm->cached_pointers[i];

    p = hash_get_mem (sm->counter_vector_by_name, cp->name);
    if (p == 0)	{
      clib_warning ("WARN: %s not in directory!", cp->name);
      continue;
    }
    ep = (stat_segment_directory_entry_t *) (p[0]);
    cp->type = ep->type;
    switch (cp->type) {
    case STAT_DIR_TYPE_SCALAR_POINTER:
      printf("Scalar type: %s\n", cp->name);
      //cp->scalar_pointer = ep->value;
      break;
    case STAT_DIR_TYPE_VECTOR_POINTER:
      printf("Vector pointer: %s %d\n", cp->name, vec_len(ep->value));
      //cp->vector_pointer = ep->value;
      break;
    case STAT_DIR_TYPE_COUNTER_VECTOR:
      printf("Counter vector: %s %d\n", cp->name, vec_len(ep->value));
      //cp->counter_pointer = ep->value;
      break;
    case STAT_DIR_TYPE_ERROR_INDEX:
      printf("Error index: %s\n", cp->name);
      cp->error_index = (uintptr_t)ep->value;
      break;
    default:
      printf("Unknown type: %s\n", cp->name);
    }

    cp->valuep = ep->value;    

  }

  /* And remember that we did... */
  sm->current_epoch = (u64) shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH];
}

int
stat_segment_collect (void)
{
  stat_client_main_t *sm = &stat_client_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;

  printf("Collecting...\n");

  /* Grab the stats segment lock */
  clib_spinlock_lock (sm->stat_segment_lockp);

  /* see if we need to update cached pointers */
  maybe_update_cached_pointers (sm, ssvmp->sh);

  /* Walk list of counters, copy out value. */
  int i;
  cached_pointer_t *cp;
  printf("Array length: %d\n", vec_len(sm->cached_pointers));
  for (i = 0; i < vec_len(sm->cached_pointers); i++) {
    cp = &sm->cached_pointers[i];

    switch (cp->type) {
    case STAT_DIR_TYPE_SCALAR_POINTER:
      printf("Collecting Scalar type: %s\n", cp->name);
      cp->scalar_value = *(f64*)cp->valuep;
      printf("Counter: %.2f\n", cp->value);
      break;

    case STAT_DIR_TYPE_VECTOR_POINTER:
      printf("Collecting Vector pointer: %s\n", cp->name);
      //cp->vector_pointer = ep->value;
      // Only error base?
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR:
      printf("Collecting Counter vector: %s %d\n", cp->name, vec_len(cp->valuep));
      //cp->counter_pointer = ep->value;
      vec_reset_length (cp->counter_vec); // Here? Or outside of updating cached pointers...
      vlib_counter_t **c = cp->valuep;
      int len = vec_len (c[0]);
      printf("LENGTH %d\n", len);
      vec_validate (cp->counter_vec, len - 1);
      clib_memcpy (cp->counter_vec, c[0],
		   len * sizeof (vlib_counter_t));
      int j;
      for (j = 0; j < vec_len (cp->counter_vec); j++)
	{
	  fformat (stdout, "[%d]: %lld rx packets, %lld rx bytes\n",
		   j, cp->counter_vec[j].packets,
		   cp->counter_vec[j].bytes);
	}

      break;
    case STAT_DIR_TYPE_ERROR_INDEX:
      cp->error_value = sm->error_base[cp->error_index];
      printf("Collecting Error index: %s %d %lu\n", cp->name, cp->error_index, cp->error_value);
      break;
    default:
      printf("Unknown type: %s\n", cp->name);
    }

  }

  /* Drop the lock */
  clib_spinlock_unlock (sm->stat_segment_lockp);

  return 0;
}

u8 **
stat_segment_ls (char *pattern)
{
  stat_client_main_t *sm = &stat_client_main;
  hash_pair_t *p;
  u8 **dir = 0;
  regex_t regex, *r = 0;

  if (pattern) {
    r = &regex;
    int rv = regcomp(r, (char *)pattern, 0);
    if (rv) {
      fprintf(stderr, "Could not compile regex %s\n", pattern);
      return dir;
    }
  }

  clib_spinlock_lock (sm->stat_segment_lockp);

  /* *INDENT-OFF* */
  hash_foreach_pair (p, sm->counter_vector_by_name,
  ({
    if (r) {
      int rv = regexec(r, (char *)p->key, 0, NULL, 0);
      if (rv == 0)
	vec_add1 (dir, (u8 *)p->key);
    } else {
      vec_add1 (dir, (u8 *)p->key);
    }
  }));
  /* *INDENT-ON* */

  clib_spinlock_unlock (sm->stat_segment_lockp);

  if (r)
    regfree(r);

  return dir;
}

static u64 *
get_error_base (u32 thread_index)
{
  u64 *error_base = 0;
  uword *p;
  stat_client_main_t *sm = &stat_client_main;
  stat_segment_directory_entry_t *ep;

  /* Special case /err/0/counter_vector */
  p = hash_get_mem (sm->counter_vector_by_name,
		    format(0, "/err/%d/counter_vector", thread_index));
  if (p) {
    ep = (stat_segment_directory_entry_t *) (p[0]);
    error_base = ep->value;
  }
  return error_base;
}

stat_segment_data_t
copy_data (stat_segment_directory_entry_t *ep, u64 *error_base)
{
  stat_segment_data_t result = { 0 };
  u32 error_index;
  int len;
  vlib_counter_t **c;
  result.type = ep->type;
  switch (ep->type) {
  case STAT_DIR_TYPE_SCALAR_POINTER:
    result.scalar_value = *(f64*)ep->value;
    break;

  case STAT_DIR_TYPE_VECTOR_POINTER:
    result.vector_pointer = ep->value;
    break;

  case STAT_DIR_TYPE_COUNTER_VECTOR:
    c = ep->value;
    len = vec_len (c[0]);
    vec_validate (result.counter_vec, len - 1);
    clib_memcpy (result.counter_vec, c[0], len * sizeof (vlib_counter_t));
    break;

  case STAT_DIR_TYPE_ERROR_INDEX:
    error_index = (uintptr_t)ep->value;
    result.error_value = error_base[error_index];
    break;

  default:
    printf("Unknown type: %d\n", ep->type);
  }
  return result;
}

stat_segment_data_t *
stat_segment_dump (u8 *stats[])
{
  int i;
  uword *p;
  stat_client_main_t *sm = &stat_client_main;
  stat_segment_directory_entry_t *ep;
  stat_segment_data_t *res = 0;
  clib_spinlock_lock (sm->stat_segment_lockp);

  sm->error_base = get_error_base(0);
  for (i = 0; i < vec_len (stats); i++) {
    p = hash_get_mem (sm->counter_vector_by_name, stats[i]);
    if (p == 0)	{
      clib_warning ("WARN: %s not in directory!", stats[i]);
      continue;
    }
    /* Collect counter */
    ep = (stat_segment_directory_entry_t *) (p[0]);
    vec_add1(res, copy_data(ep, sm->error_base));
  }
  clib_spinlock_unlock (sm->stat_segment_lockp);

  return res;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
