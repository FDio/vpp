/*
 *------------------------------------------------------------------
 * stat_client.c - Library for access to VPP statistics segment
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
  u64 current_epoch;
  volatile int segment_ready;
  ssvm_private_t stat_segment;	/* mapped stats segment object */
  ssvm_shared_header_t *shared_header;
  clib_spinlock_t *stat_segment_lockp;	/* Spinlock for the stats segment */
  uword *counter_vector_by_name;
  u64 *error_base;
} stat_client_main_t;

stat_client_main_t stat_client_main;

int
stat_segment_connect (char *socket_name)
{
  stat_client_main_t *sm = &stat_client_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  clib_socket_t s = { 0 };
  clib_error_t *err;
  int fd = -1, retval;

  memset (sm, 0, sizeof (*sm));
  s.config = socket_name;
  s.flags = CLIB_SOCKET_F_IS_CLIENT | CLIB_SOCKET_F_SEQPACKET;
  err = clib_socket_init (&s);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }
  err = clib_socket_recvmsg (&s, 0, 0, &fd, 1);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }
  clib_socket_close (&s);

  memset (ssvmp, 0, sizeof (*ssvmp));
  ssvmp->fd = fd;

  /* Note: this closes memfd.fd */
  retval = ssvm_slave_init_memfd (ssvmp);
  if (retval)
    {
      fprintf (stderr, "WARNING: segment map returned %d\n", retval);
      return -1;
    }

  ASSERT (ssvmp && ssvmp->sh);

  /* Pick up the segment lock from the shared memory header */
  sm->shared_header = ssvmp->sh;
  sm->stat_segment_lockp = (clib_spinlock_t *) (sm->shared_header->opaque[0]);
  sm->segment_ready = 1;

  sm->counter_vector_by_name =
    (uword *) sm->shared_header->opaque[STAT_SEGMENT_OPAQUE_DIR];

  return 0;
}

void
stat_segment_disconnect (void)
{
  stat_client_main_t *sm = &stat_client_main;
  ssvm_delete_memfd (&sm->stat_segment);
  return;
}

/*
 * The application needs to register which counters it is interested
 * in.
 */
stat_segment_cached_pointer_t *
stat_segment_register (u8 * stats[])
{
  int i;
  uword *p;
  stat_client_main_t *sm = &stat_client_main;
  stat_segment_cached_pointer_t *cp, *cached_pointer_vec = 0;

  for (i = 0; i < vec_len (stats); i++)
    {
      p = hash_get_mem (sm->counter_vector_by_name, stats[i]);
      if (p == 0)
	{
	  fprintf (stderr, "WARN: %s not in directory!", stats[i]);
	  continue;
	}
      vec_add2 (cached_pointer_vec, cp, 1);
      cp->name = strdup ((char *) stats[i]);	// Point to p->key instead?
    }
  return cached_pointer_vec;
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
		    format (0, "/err/%d/counter_vector", thread_index));
  if (p)
    {
      ep = (stat_segment_directory_entry_t *) (p[0]);
      error_base = ep->value;
    }
  return error_base;
}

f64
stat_segment_heartbeat (void)
{
  f64 *heartbeat = 0;
  uword *p;
  stat_client_main_t *sm = &stat_client_main;
  stat_segment_directory_entry_t *ep;

  /* Special case /err/0/counter_vector */
  p = hash_get_mem (sm->counter_vector_by_name,
		    format (0, "/sys/heartbeat%c", 0));
  if (p)
    {
      ep = (stat_segment_directory_entry_t *) (p[0]);
      heartbeat = ep->value;
    }
  return *heartbeat;
}

static void
maybe_update_cached_pointers (stat_segment_cached_pointer_t * cached_pointers)
{
  stat_client_main_t *sm = &stat_client_main;
  stat_segment_cached_pointer_t *cp;
  uword *p;
  int i;

  /* Cached pointers OK? */
  if (sm->current_epoch ==
      (u64) sm->shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH])
    return;

  /* Special case /err/0/counter_vector */
  sm->error_base = get_error_base (0);

  /* Nope, fix them... */
  for (i = 0; i < vec_len (cached_pointers); i++)
    {
      cp = &cached_pointers[i];

      p = hash_get_mem (sm->counter_vector_by_name, cp->name);
      if (p == 0)
	{
	  fprintf (stderr, "WARN: %s not in directory!", cp->name);
	  continue;
	}
      cp->ep = (stat_segment_directory_entry_t *) (p[0]);
    }

  /* And remember that we did... */
  sm->current_epoch =
    (u64) sm->shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH];
}

stat_segment_data_t
copy_data (stat_segment_directory_entry_t * ep, u64 * error_base, char *name)
{
  stat_segment_data_t result = { 0 };
  u32 error_index;
  int i;
  vlib_counter_t **combined_c;	/* Combined counter */
  counter_t **simple_c;		/* Simple counter */
  result.type = ep->type;
  result.name = name;
  switch (ep->type)
    {
    case STAT_DIR_TYPE_SCALAR_POINTER:
      result.scalar_value = *(f64 *) ep->value;
      break;

    case STAT_DIR_TYPE_VECTOR_POINTER:
      result.vector_pointer = ep->value;
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      simple_c = ep->value;
      result.simple_counter_vec = vec_dup (simple_c);
      for (i = 0; i < vec_len (simple_c); i++)
	result.simple_counter_vec[i] = vec_dup (simple_c[i]);
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      combined_c = ep->value;
      result.combined_counter_vec = vec_dup (combined_c);
      for (i = 0; i < vec_len (combined_c); i++)
	result.combined_counter_vec[i] = vec_dup (combined_c[i]);
      break;

    case STAT_DIR_TYPE_ERROR_INDEX:
      error_index = (uintptr_t) ep->value;
      result.error_value = error_base[error_index];
      break;

    default:
      fprintf (stderr, "Unknown type: %d", ep->type);
    }
  return result;
}

stat_segment_data_t *
stat_segment_collect (stat_segment_cached_pointer_t * cached_pointers)
{
  stat_client_main_t *sm = &stat_client_main;
  stat_segment_data_t *res = 0;
  int i;

  /* Grab the stats segment lock */
  clib_spinlock_lock (sm->stat_segment_lockp);

  /* see if we need to update cached pointers */
  maybe_update_cached_pointers (cached_pointers);

  for (i = 0; i < vec_len (cached_pointers); i++)
    {
      vec_add1 (res,
		copy_data (cached_pointers[i].ep, sm->error_base,
			   cached_pointers[i].name));
    }

  /* Drop the lock */
  clib_spinlock_unlock (sm->stat_segment_lockp);

  return res;
}

void
stat_segment_data_free (stat_segment_data_t * res)
{
  int i, j;
  for (i = 0; i < vec_len (res); i++)
    {
      switch (res[i].type)
	{
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  for (j = 0; j < vec_len (res[i].simple_counter_vec); j++)
	    vec_free (res[i].simple_counter_vec[j]);
	  vec_free (res[i].simple_counter_vec);
	  break;
	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  for (j = 0; j < vec_len (res[i].combined_counter_vec); j++)
	    vec_free (res[i].combined_counter_vec[j]);
	  vec_free (res[i].combined_counter_vec);
	  break;
	default:
	  ;
	}
    }
  vec_free (res);
}

u8 **
stat_segment_ls (u8 ** patterns)
{
  stat_client_main_t *sm = &stat_client_main;
  hash_pair_t *p;
  u8 **dir = 0;
  regex_t regex[vec_len (patterns)];

  int i;
  for (i = 0; i < vec_len (patterns); i++)
    {
      int rv = regcomp (&regex[i], (char *) patterns[i], 0);
      if (rv)
	{
	  fprintf (stderr, "Could not compile regex %s\n", patterns[i]);
	  return dir;
	}
    }

  clib_spinlock_lock (sm->stat_segment_lockp);

  /* *INDENT-OFF* */
  hash_foreach_pair (p, sm->counter_vector_by_name,
  ({
    for (i = 0; i < vec_len(patterns); i++) {
      int rv = regexec(&regex[i], (char *)p->key, 0, NULL, 0);
      if (rv == 0) {
	vec_add1 (dir, (u8 *)p->key);
	break;
      }
    }
    if (vec_len(patterns) == 0)
      vec_add1 (dir, (u8 *)p->key);
  }));
  /* *INDENT-ON* */

  clib_spinlock_unlock (sm->stat_segment_lockp);

  for (i = 0; i < vec_len (patterns); i++)
    regfree (&regex[i]);

  return dir;
}

stat_segment_data_t *
stat_segment_dump (u8 * stats[])
{
  int i;
  uword *p;
  stat_client_main_t *sm = &stat_client_main;
  stat_segment_directory_entry_t *ep;
  stat_segment_data_t *res = 0;

  clib_spinlock_lock (sm->stat_segment_lockp);

  sm->error_base = get_error_base (0);
  for (i = 0; i < vec_len (stats); i++)
    {
      p = hash_get_mem (sm->counter_vector_by_name, stats[i]);
      if (p == 0)
	{
	  fprintf (stderr, "WARN: %s not in directory!", stats[i]);
	  continue;
	}
      /* Collect counter */
      ep = (stat_segment_directory_entry_t *) (p[0]);
      vec_add1 (res, copy_data (ep, sm->error_base, (char *) stats[i]));
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
