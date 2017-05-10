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
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <vppinfra/longjmp.h>
#include <vppinfra/mheap.h>
#include <vppinfra/os.h>

void
clib_smp_free (clib_smp_main_t * m)
{
  clib_mem_vm_free (m->vm_base,
		    (uword) ((1 + m->n_cpus) << m->log2_n_per_cpu_vm_bytes));
}

static uword
allocate_per_cpu_mheap (uword cpu)
{
  clib_smp_main_t *m = &clib_smp_main;
  void *heap;
  uword vm_size, stack_size, mheap_flags;

  ASSERT (os_get_thread_index () == cpu);

  vm_size = (uword) 1 << m->log2_n_per_cpu_vm_bytes;
  stack_size = (uword) 1 << m->log2_n_per_cpu_stack_bytes;

  mheap_flags = MHEAP_FLAG_SMALL_OBJECT_CACHE;

  /* Heap extends up to start of stack. */
  heap = mheap_alloc_with_flags (clib_smp_vm_base_for_cpu (m, cpu),
				 vm_size - stack_size, mheap_flags);
  clib_mem_set_heap (heap);

  if (cpu == 0)
    {
      /* Now that we have a heap, allocate main structure on cpu 0. */
      vec_resize (m->per_cpu_mains, m->n_cpus);

      /* Allocate shared global heap (thread safe). */
      m->global_heap =
	mheap_alloc_with_flags (clib_smp_vm_base_for_cpu (m, cpu + m->n_cpus),
				vm_size,
				mheap_flags | MHEAP_FLAG_THREAD_SAFE);
    }

  m->per_cpu_mains[cpu].heap = heap;
  return 0;
}

void
clib_smp_init (void)
{
  clib_smp_main_t *m = &clib_smp_main;
  uword cpu;

  m->vm_base =
    clib_mem_vm_alloc ((uword) (m->n_cpus + 1) << m->log2_n_per_cpu_vm_bytes);
  if (!m->vm_base)
    clib_error ("error allocating virtual memory");

  for (cpu = 0; cpu < m->n_cpus; cpu++)
    clib_calljmp (allocate_per_cpu_mheap, cpu,
		  clib_smp_stack_top_for_cpu (m, cpu));
}

void
clib_smp_lock_init (clib_smp_lock_t ** pl)
{
  clib_smp_lock_t *l;
  uword i, n_bytes, n_fifo_elts;

  /* No locking necessary if n_cpus <= 1.
     Null means no locking is necessary. */
  if (clib_smp_main.n_cpus < 2)
    {
      *pl = 0;
      return;
    }

  /* Need n_cpus - 1 elts in waiting fifo.  One CPU holds lock
     and others could potentially be waiting. */
  n_fifo_elts = clib_smp_main.n_cpus - 1;

  n_bytes = sizeof (l[0]) + n_fifo_elts * sizeof (l->waiting_fifo[0]);
  ASSERT_AND_PANIC (n_bytes % CLIB_CACHE_LINE_BYTES == 0);

  l = clib_mem_alloc_aligned (n_bytes, CLIB_CACHE_LINE_BYTES);

  memset (l, 0, n_bytes);
  l->n_waiting_fifo_elts = n_fifo_elts;

  for (i = 0; i < l->n_waiting_fifo_elts; i++)
    l->waiting_fifo[i].wait_type = CLIB_SMP_LOCK_WAIT_EMPTY;

  *pl = l;
}

void
clib_smp_lock_free (clib_smp_lock_t ** pl)
{
  if (*pl)
    clib_mem_free (*pl);
  *pl = 0;
}

void
clib_smp_lock_slow_path (clib_smp_lock_t * l,
			 uword my_cpu,
			 clib_smp_lock_header_t h0, clib_smp_lock_type_t type)
{
  clib_smp_lock_header_t h1, h2, h3;
  uword is_reader = type == CLIB_SMP_LOCK_TYPE_READER;
  uword n_fifo_elts = l->n_waiting_fifo_elts;
  uword my_tail;

  /* Atomically advance waiting FIFO tail pointer; my_tail will point
     to entry where we can insert ourselves to wait for lock to be granted. */
  while (1)
    {
      h1 = h0;
      my_tail = h1.waiting_fifo.head_index + h1.waiting_fifo.n_elts;
      my_tail = my_tail >= n_fifo_elts ? my_tail - n_fifo_elts : my_tail;
      h1.waiting_fifo.n_elts += 1;
      h1.request_cpu = my_cpu;

      ASSERT_AND_PANIC (h1.waiting_fifo.n_elts <= n_fifo_elts);
      ASSERT_AND_PANIC (my_tail >= 0 && my_tail < n_fifo_elts);

      h2 = clib_smp_lock_set_header (l, h1, h0);

      /* Tail successfully advanced? */
      if (clib_smp_lock_header_is_equal (h0, h2))
	break;

      /* It is possible that if head and tail are both zero, CPU with lock would have unlocked lock. */
      else if (type == CLIB_SMP_LOCK_TYPE_SPIN)
	{
	  while (!h2.writer_has_lock)
	    {
	      ASSERT_AND_PANIC (h2.waiting_fifo.n_elts == 0);
	      h1 = h2;
	      h1.request_cpu = my_cpu;
	      h1.writer_has_lock = 1;

	      h3 = clib_smp_lock_set_header (l, h1, h2);

	      /* Got it? */
	      if (clib_smp_lock_header_is_equal (h2, h3))
		return;

	      h2 = h3;
	    }
	}

      /* Try to advance tail again. */
      h0 = h2;
    }

  {
    clib_smp_lock_waiting_fifo_elt_t *w;

    w = l->waiting_fifo + my_tail;

    while (w->wait_type != CLIB_SMP_LOCK_WAIT_EMPTY)
      clib_smp_pause ();

    w->wait_type = (is_reader
		    ? CLIB_SMP_LOCK_WAIT_READER : CLIB_SMP_LOCK_WAIT_WRITER);

    /* Wait until CPU holding the lock grants us the lock. */
    while (w->wait_type != CLIB_SMP_LOCK_WAIT_DONE)
      clib_smp_pause ();

    w->wait_type = CLIB_SMP_LOCK_WAIT_EMPTY;
  }
}

void
clib_smp_unlock_slow_path (clib_smp_lock_t * l,
			   uword my_cpu,
			   clib_smp_lock_header_t h0,
			   clib_smp_lock_type_t type)
{
  clib_smp_lock_header_t h1, h2;
  clib_smp_lock_waiting_fifo_elt_t *head;
  clib_smp_lock_wait_type_t head_wait_type;
  uword is_reader = type == CLIB_SMP_LOCK_TYPE_READER;
  uword n_fifo_elts = l->n_waiting_fifo_elts;
  uword head_index, must_wait_for_readers;

  while (1)
    {
      /* Advance waiting fifo giving lock to first waiter. */
      while (1)
	{
	  ASSERT_AND_PANIC (h0.waiting_fifo.n_elts != 0);

	  h1 = h0;

	  head_index = h1.waiting_fifo.head_index;
	  head = l->waiting_fifo + head_index;
	  if (is_reader)
	    {
	      ASSERT_AND_PANIC (h1.n_readers_with_lock > 0);
	      h1.n_readers_with_lock -= 1;
	    }
	  else
	    {
	      /* Writer will already have lock. */
	      ASSERT_AND_PANIC (h1.writer_has_lock);
	    }

	  while ((head_wait_type =
		  head->wait_type) == CLIB_SMP_LOCK_WAIT_EMPTY)
	    clib_smp_pause ();

	  /* Don't advance FIFO to writer unless all readers have unlocked. */
	  must_wait_for_readers =
	    (type != CLIB_SMP_LOCK_TYPE_SPIN
	     && head_wait_type == CLIB_SMP_LOCK_WAIT_WRITER
	     && h1.n_readers_with_lock != 0);

	  if (!must_wait_for_readers)
	    {
	      head_index += 1;
	      h1.waiting_fifo.n_elts -= 1;
	      if (type != CLIB_SMP_LOCK_TYPE_SPIN)
		{
		  if (head_wait_type == CLIB_SMP_LOCK_WAIT_WRITER)
		    h1.writer_has_lock = h1.n_readers_with_lock == 0;
		  else
		    {
		      h1.writer_has_lock = 0;
		      h1.n_readers_with_lock += 1;
		    }
		}
	    }

	  h1.waiting_fifo.head_index =
	    head_index == n_fifo_elts ? 0 : head_index;
	  h1.request_cpu = my_cpu;

	  ASSERT_AND_PANIC (h1.waiting_fifo.head_index >= 0
			    && h1.waiting_fifo.head_index < n_fifo_elts);
	  ASSERT_AND_PANIC (h1.waiting_fifo.n_elts >= 0
			    && h1.waiting_fifo.n_elts <= n_fifo_elts);

	  h2 = clib_smp_lock_set_header (l, h1, h0);

	  if (clib_smp_lock_header_is_equal (h2, h0))
	    break;

	  h0 = h2;

	  if (h0.waiting_fifo.n_elts == 0)
	    return clib_smp_unlock_inline (l, type);
	}

      if (must_wait_for_readers)
	return;

      /* Wake up head of waiting fifo. */
      {
	uword done_waking;

	/* Shift lock to first thread waiting in fifo. */
	head->wait_type = CLIB_SMP_LOCK_WAIT_DONE;

	/* For read locks we may be able to wake multiple readers. */
	done_waking = 1;
	if (head_wait_type == CLIB_SMP_LOCK_WAIT_READER)
	  {
	    uword hi = h0.waiting_fifo.head_index;
	    if (h0.waiting_fifo.n_elts != 0
		&& l->waiting_fifo[hi].wait_type == CLIB_SMP_LOCK_WAIT_READER)
	      done_waking = 0;
	  }

	if (done_waking)
	  break;
      }
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
