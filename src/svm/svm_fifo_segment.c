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

#include <svm/svm_fifo_segment.h>

svm_fifo_segment_main_t svm_fifo_segment_main;

/** (master) create an svm fifo segment */
int
svm_fifo_segment_create (svm_fifo_segment_create_args_t * a)
{
  int rv;
  svm_fifo_segment_private_t *s;
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;
  void *oldheap;

  /* Allocate a fresh segment */
  pool_get (sm->segments, s);
  memset (s, 0, sizeof (*s));

  s->ssvm.ssvm_size = a->segment_size;
  s->ssvm.i_am_master = 1;
  s->ssvm.my_pid = getpid ();
  s->ssvm.name = (u8 *) a->segment_name;
  s->ssvm.requested_va = sm->next_baseva;

  rv = ssvm_master_init (&s->ssvm, s - sm->segments);

  if (rv)
    {
      _vec_len (s) = vec_len (s) - 1;
      return (rv);
    }

  /* Note; requested_va updated due to seg base addr randomization */
  sm->next_baseva = s->ssvm.requested_va + a->segment_size;

  sh = s->ssvm.sh;
  oldheap = ssvm_push_heap (sh);

  /* Set up svm_fifo_segment shared header */
  fsh = clib_mem_alloc (sizeof (*fsh));
  memset (fsh, 0, sizeof (*fsh));
  sh->opaque[0] = fsh;
  s->h = fsh;
  fsh->segment_name = format (0, "%s%c", a->segment_name, 0);

  /* Avoid vec_add1(...) failure when adding a fifo, etc. */
  vec_validate (fsh->fifos, 64);
  _vec_len (fsh->fifos) = 0;

  ssvm_pop_heap (oldheap);

  sh->ready = 1;
  a->new_segment_index = s - sm->segments;
  return (0);
}

/** Create an svm fifo segment in process-private memory */
int
svm_fifo_segment_create_process_private (svm_fifo_segment_create_args_t * a)
{
  svm_fifo_segment_private_t *s;
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;

  /* Allocate a fresh segment */
  pool_get (sm->segments, s);
  memset (s, 0, sizeof (*s));

  s->ssvm.ssvm_size = ~0;
  s->ssvm.i_am_master = 1;
  s->ssvm.my_pid = getpid ();
  s->ssvm.name = (u8 *) a->segment_name;
  s->ssvm.requested_va = ~0;

  /* Allocate a [sic] shared memory header, in process memory... */
  sh = clib_mem_alloc_aligned (sizeof (*sh), CLIB_CACHE_LINE_BYTES);
  s->ssvm.sh = sh;

  memset (sh, 0, sizeof (*sh));
  sh->heap = clib_mem_get_heap ();

  /* Set up svm_fifo_segment shared header */
  fsh = clib_mem_alloc (sizeof (*fsh));
  memset (fsh, 0, sizeof (*fsh));
  sh->opaque[0] = fsh;
  s->h = fsh;
  fsh->segment_name = format (0, "%s%c", a->segment_name, 0);

  sh->ready = 1;
  a->new_segment_index = s - sm->segments;
  return (0);
}

/** (slave) attach to an svm fifo segment */
int
svm_fifo_segment_attach (svm_fifo_segment_create_args_t * a)
{
  int rv;
  svm_fifo_segment_private_t *s;
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;

  /* Allocate a fresh segment */
  pool_get (sm->segments, s);
  memset (s, 0, sizeof (*s));

  s->ssvm.ssvm_size = a->segment_size;
  s->ssvm.my_pid = getpid ();
  s->ssvm.name = (u8 *) a->segment_name;
  s->ssvm.requested_va = sm->next_baseva;

  rv = ssvm_slave_init (&s->ssvm, sm->timeout_in_seconds);

  if (rv)
    {
      _vec_len (s) = vec_len (s) - 1;
      return (rv);
    }

  /* Fish the segment header */
  sh = s->ssvm.sh;
  fsh = (svm_fifo_segment_header_t *) sh->opaque[0];
  s->h = fsh;

  a->new_segment_index = s - sm->segments;
  return (0);
}

void
svm_fifo_segment_delete (svm_fifo_segment_private_t * s)
{
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
  ssvm_delete (&s->ssvm);
  pool_put (sm->segments, s);
}

svm_fifo_t *
svm_fifo_segment_alloc_fifo (svm_fifo_segment_private_t * s,
			     u32 data_size_in_bytes)
{
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;
  svm_fifo_t *f;
  void *oldheap;

  sh = s->ssvm.sh;
  fsh = (svm_fifo_segment_header_t *) sh->opaque[0];

  ssvm_lock (sh, 1, 0);
  oldheap = ssvm_push_heap (sh);

  /* Note: this can fail, in which case: create another segment */
  f = svm_fifo_create (data_size_in_bytes);
  if (PREDICT_FALSE (f == 0))
    {
      ssvm_pop_heap (oldheap);
      ssvm_unlock (sh);
      return (0);
    }

  vec_add1 (fsh->fifos, f);
  ssvm_pop_heap (oldheap);
  ssvm_unlock (sh);
  return (f);
}

void
svm_fifo_segment_free_fifo (svm_fifo_segment_private_t * s, svm_fifo_t * f)
{
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;
  void *oldheap;
  int i;

  sh = s->ssvm.sh;
  fsh = (svm_fifo_segment_header_t *) sh->opaque[0];

  ssvm_lock (sh, 1, 0);
  oldheap = ssvm_push_heap (sh);
  for (i = 0; i < vec_len (fsh->fifos); i++)
    {
      if (fsh->fifos[i] == f)
	{
	  vec_delete (fsh->fifos, 1, i);
	  goto found;
	}
    }
  clib_warning ("fifo 0x%llx not found in fifo table...", f);

found:
  clib_mem_free (f);
  ssvm_pop_heap (oldheap);
  ssvm_unlock (sh);
}

void
svm_fifo_segment_init (u64 baseva, u32 timeout_in_seconds)
{
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;

  sm->next_baseva = baseva;
  sm->timeout_in_seconds = timeout_in_seconds;
}

u32
svm_fifo_segment_index (svm_fifo_segment_private_t * s)
{
  return s - svm_fifo_segment_main.segments;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
