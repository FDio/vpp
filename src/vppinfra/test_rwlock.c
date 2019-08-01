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
#include <vppinfra/atomics.h>

static u32 all_threads_online = 0;

typedef struct
{
  uword threads_per_core;
  uword cpu_mask_read;
  uword read_cores;
  uword cpu_mask_write;
  uword write_cores;
  uword increment_per_thread;
  clib_rwlock_t rwlock;
  uword shared_count;
  uword iterations;
} rwlock_test_main_t;

void *
write_shared_counter (void *arg)
{
  f64 *time = vec_new (f64, 1);
  *time = 0;
  rwlock_test_main_t *rtm = arg;

  /* Wait for all threads to be created */
  while (!clib_atomic_load_acq_n (&all_threads_online));

  f64 start = clib_cpu_time_now ();
  for (uword i = 0; i < rtm->increment_per_thread; i++)
    {
      clib_rwlock_writer_lock (&rtm->rwlock);
      rtm->shared_count++;
      clib_rwlock_writer_unlock (&rtm->rwlock);
    }
  *time = clib_cpu_time_now () - start;
  return time;
}

void *
read_shared_counter (void *arg)
{
  f64 *time = vec_new (f64, 1);
  *time = 0;
  rwlock_test_main_t *rtm = arg;
  uword cnt_cpy = 0, exp = rtm->increment_per_thread * rtm->write_cores *
    rtm->threads_per_core;

  /* Wait for all threads to be created */
  while (!clib_atomic_load_acq_n (&all_threads_online));

  f64 start = clib_cpu_time_now ();
  while (cnt_cpy < exp)
    {
      clib_rwlock_reader_lock (&rtm->rwlock);
      cnt_cpy = rtm->shared_count;
      clib_rwlock_reader_unlock (&rtm->rwlock);
    }
  *time = clib_cpu_time_now () - start;
  return time;
}

unsigned
test_rwlock (rwlock_test_main_t * rtm, f64 * elapse_time)
{
  int error = 0, total_threads = (rtm->read_cores + rtm->write_cores)
    * rtm->threads_per_core;
  pthread_t pthread[total_threads];

  cpu_set_t cpuset;
  unsigned cores_set = 0, cpu_id = 0;

  /* Spawn reader (consumer) threads */
  for (unsigned cpu_mask = rtm->cpu_mask_read; cpu_mask; cpu_mask >>= 1)
    {
      if (!(cpu_mask & 1))
	{
	  cpu_id++;
	  continue;
	}

      CPU_ZERO (&cpuset);
      CPU_SET (cpu_id, &cpuset);
      for (uword t_num = 0; t_num < rtm->threads_per_core; t_num++)
	{
	  uword t_index = cores_set * rtm->threads_per_core + t_num;
	  if ((error = pthread_create (&pthread[t_index], NULL,
				       &read_shared_counter, rtm)))
	    clib_unix_warning ("pthread_create failed with %d", error);

	  if ((error = pthread_setaffinity_np (pthread[t_index],
					       sizeof (cpu_set_t), &cpuset)))
	    clib_unix_warning ("pthread_set_affinity_np failed with %d",
			       error);
	}
      cores_set++;
      cpu_id++;
    }

  /* Spawn writer (producer) threads */
  cpu_id = 0;
  for (unsigned cpu_mask = rtm->cpu_mask_write; cpu_mask; cpu_mask >>= 1)
    {
      if (!(cpu_mask & 1))
	{
	  cpu_id++;
	  continue;
	}

      CPU_ZERO (&cpuset);
      CPU_SET (cpu_id, &cpuset);
      for (uword t_num = 0; t_num < rtm->threads_per_core; t_num++)
	{
	  uword t_index = cores_set * rtm->threads_per_core + t_num;
	  if ((error = pthread_create (&pthread[t_index], NULL,
				       &write_shared_counter, rtm)))
	    clib_unix_warning ("pthread_create failed with %d", error);

	  if ((error = pthread_setaffinity_np (pthread[t_index],
					       sizeof (cpu_set_t), &cpuset)))
	    clib_unix_warning ("pthread_set_affinity_np failed with %d",
			       error);
	}
      cores_set++;
      cpu_id++;
    }

  /* Launch all threads */
  clib_atomic_store_rel_n (&all_threads_online, 1);

  for (uword thread_num = 0; thread_num < total_threads; thread_num++)
    {
      f64 *time;
      if ((error = pthread_join (pthread[thread_num], (void *) &time)))
	clib_unix_warning ("pthread_join failed with %d", error);
      *elapse_time += *time;
      vec_free (time);
    }

  fformat (stdout, "Time elapsed: %.4e\n", *elapse_time);
  return rtm->shared_count;
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
test_rwlock_main (unformat_input_t * i)
{
  rwlock_test_main_t _rtm, *rtm = &_rtm;
  clib_memset (rtm, 0, sizeof (rwlock_test_main_t));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (0 == unformat (i, "threads/core %d", &rtm->threads_per_core)
	  && 0 == unformat (i, "cpu_mask_read %x", &rtm->cpu_mask_read)
	  && 0 == unformat (i, "cpu_mask_write %x", &rtm->cpu_mask_write)
	  && 0 == unformat (i, "increment %d", &rtm->increment_per_thread)
	  && 0 == unformat (i, "iterations %d", &rtm->iterations))
	{
	  clib_unix_warning ("unknown input '%U'", format_unformat_error, i);
	  return 1;
	}
    }

  rtm->read_cores = num_cores_in_cpu_mask (rtm->cpu_mask_read);
  rtm->write_cores = num_cores_in_cpu_mask (rtm->cpu_mask_write);

  uword total_increment = rtm->threads_per_core * rtm->write_cores *
    rtm->increment_per_thread;

  clib_rwlock_init (&rtm->rwlock);

  f64 average_time = 0;
  for (uword trial = 0; trial < rtm->iterations; trial++)
    {
      rtm->shared_count = 0;
      f64 elapse_time = 0;
      if (test_rwlock (rtm, &elapse_time) != total_increment)
	{
	  clib_rwlock_free (&rtm->rwlock);
	  fformat (stdout, "FAILED: expected count: %d, actual count: %d\n",
		   total_increment, rtm->shared_count);
	  return 1;
	}
      fformat (stdout, "Trial %d SUCCESS: %d = %d\n",
	       trial, rtm->shared_count, total_increment);
      average_time = (average_time * trial + elapse_time) / (trial + 1);
      fformat (stdout, "Average lock/unlock cycles: %.4e\n", average_time);
    }
  clib_rwlock_free (&rtm->rwlock);
  return 0;
}

#ifdef CLIB_UNIX
/** Launches a number of writer threads to simultaneously increment a global
    counter and a number of reader threads to continuously poll the counter,
    and records timestamps for rwlock performance benchmarking

    @param "threads/core [# threads/core]" - number of threads per core
    @param "cpu_mask_read [cpu_mask]" - reader thread cpu string e.g. input
            ff sets cpus 0 - 7
    @param "cpu_mask_write [cpu_mask]" - writer thread cpu string
    @param "increment [# increments]" - number of increments per writer thread
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
  ret = test_rwlock_main (&i);
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
