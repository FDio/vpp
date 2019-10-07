/*
 * Copyright (c) 2019 Arm Limited.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <vppinfra/mem.h>
#include <vppinfra/cache.h>
#include <vppinfra/lock.h>
#include <pthread.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/time.h>
#include <sched.h>
#include <stdlib.h>
#include <vppinfra/atomics.h>

static u32 all_threads_online = 0;

typedef struct
{
  uword threads_per_core;
  uword cpu_mask;
  uword num_cores;
  uword increment_per_thread;
  clib_spinlock_t slock;
  uword shared_count;
  uword iterations;
} spinlock_test_main_t;

void *
inc_shared_counter (void *arg)
{
  f64 *time = vec_new (f64, 1);
  *time = 0;
  spinlock_test_main_t *stm = arg;

  /* Wait for all threads to be created */
  while (!clib_atomic_load_acq_n (&all_threads_online));

  f64 start = clib_cpu_time_now ();
  for (uword i = 0; i < stm->increment_per_thread; i++)
    {
      clib_spinlock_lock (&stm->slock);
      stm->shared_count++;
      clib_spinlock_unlock (&stm->slock);
    }
  *time = clib_cpu_time_now () - start;
  return time;
}

unsigned
test_spinlock (spinlock_test_main_t * stm, f64 * elapse_time)
{
  int error;
  uword num_threads = stm->num_cores * stm->threads_per_core;
  pthread_t pthread[num_threads];

  cpu_set_t cpuset;
  unsigned cores_set = 0, cpu_id = 0;
  for (unsigned cpu_mask = stm->cpu_mask; cpu_mask; cpu_mask >>= 1)
    {
      if (!(cpu_mask & 1))
	{
	  cpu_id++;
	  continue;
	}

      CPU_ZERO (&cpuset);
      CPU_SET (cpu_id, &cpuset);
      for (uword t_num = 0; t_num < stm->threads_per_core; t_num++)
	{
	  uword t_index = cores_set * stm->threads_per_core + t_num;
	  if ((error = pthread_create (&pthread[t_index], NULL,
				       &inc_shared_counter, stm)))
	    clib_unix_warning ("pthread_create failed with %d", error);

	  if ((error = pthread_setaffinity_np (pthread[t_index],
					       sizeof (cpu_set_t), &cpuset)))
	    clib_unix_warning ("pthread_setaffinity_np failed with %d",
			       error);
	}
      cores_set++;
      cpu_id++;
    }

  /* Launch all threads */
  clib_atomic_store_rel_n (&all_threads_online, 1);

  for (uword thread_num = 0; thread_num < num_threads; thread_num++)
    {
      f64 *time;
      if ((error = pthread_join (pthread[thread_num], (void *) &time)))
	clib_unix_warning ("pthread_join failed with %d", error);
      *elapse_time += *time;
      vec_free (time);
    }

  fformat (stdout, "Time elapsed: %.4e cycles\n", *elapse_time);
  return stm->shared_count;
}

uword
num_cores_in_cpu_mask (uword mask)
{
  uword num_cores = 0;
  for (uword cpu_mask = mask; cpu_mask; cpu_mask >>= 1)
    num_cores += (cpu_mask & 1);
  return num_cores;
}

int
test_spinlock_main (unformat_input_t * i)
{
  spinlock_test_main_t _stm, *stm = &_stm;
  clib_memset (stm, 0, sizeof (spinlock_test_main_t));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (0 == unformat (i, "threads/core %d", &stm->threads_per_core)
	  && 0 == unformat (i, "cpu_mask %x", &stm->cpu_mask)
	  && 0 == unformat (i, "increment %d", &stm->increment_per_thread)
	  && 0 == unformat (i, "iterations %d", &stm->iterations))
	{
	  clib_unix_warning ("unknown input '%U'", format_unformat_error, i);
	  return 1;
	}
    }

  stm->num_cores = num_cores_in_cpu_mask (stm->cpu_mask);

  uword total_increment = stm->threads_per_core * stm->num_cores *
    stm->increment_per_thread;

  clib_spinlock_init (&stm->slock);

  f64 average_time = 0;
  for (uword trial = 0; trial < stm->iterations; trial++)
    {
      stm->shared_count = 0;
      f64 elapse_time = 0;
      if (test_spinlock (stm, &elapse_time) != total_increment)
	{
	  clib_spinlock_free (&stm->slock);
	  fformat (stdout, "FAILED: expected count: %d, actual count: %d\n",
		   total_increment, stm->shared_count);
	  return 1;
	}

      fformat (stdout, "Trial %d SUCCESS: %d = %d\n",
	       trial, stm->shared_count, total_increment);
      average_time = (average_time * trial + elapse_time) / (trial + 1);
      fformat (stdout, "Average lock/unlock cycles %.4e\n", average_time);
    }
  clib_spinlock_free (&stm->slock);
  return 0;
}

#ifdef CLIB_UNIX
/** Launches a number of threads to simultaneously increment a global
    counter, and records timestamps for spinlock performance benchmarking

    @param "threads/core [# threads/core]" - number of threads per core
    @param "cpu_mask [cpu_mask]" - cpu hex string e.g. input ff sets cpus 0 - 7
    @param "increment [# increments]" - number of increments per threads
    @param "iterations [# iterations]" - number of iterations
    @returns exit code
*/
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  i32 ret;
  clib_time_t time;

  clib_mem_init (0, 3ULL << 30);
  clib_time_init (&time);

  unformat_init_command_line (&i, argv);
  ret = test_spinlock_main (&i);
  unformat_free (&i);

  return ret;
}
#endif /* CLIB_UNIX */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
