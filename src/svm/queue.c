/*
 *------------------------------------------------------------------
 * svm_queue.c - unidirectional shared-memory queues
 *
 * Copyright (c) 2009-2019 Cisco and/or its affiliates.
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <vppinfra/mem.h>
#include <vppinfra/format.h>
#include <vppinfra/cache.h>
#include <svm/queue.h>
#include <vppinfra/time.h>
#include <vppinfra/lock.h>

svm_queue_t *
svm_queue_init (void *base, int nels, int elsize)
{
  svm_queue_t *q;
  pthread_mutexattr_t attr;
  pthread_condattr_t cattr;

  q = (svm_queue_t *) base;
  clib_memset (q, 0, sizeof (*q));

  q->elsize = elsize;
  q->maxsize = nels;
  q->producer_evtfd = -1;
  q->consumer_evtfd = -1;

  clib_memset (&attr, 0, sizeof (attr));
  clib_memset (&cattr, 0, sizeof (cattr));

  if (pthread_mutexattr_init (&attr))
    clib_unix_warning ("mutexattr_init");
  if (pthread_mutexattr_setpshared (&attr, PTHREAD_PROCESS_SHARED))
    clib_unix_warning ("pthread_mutexattr_setpshared");
  if (pthread_mutexattr_setrobust (&attr, PTHREAD_MUTEX_ROBUST))
    clib_unix_warning ("setrobust");
  if (pthread_mutex_init (&q->mutex, &attr))
    clib_unix_warning ("mutex_init");
  if (pthread_mutexattr_destroy (&attr))
    clib_unix_warning ("mutexattr_destroy");
  if (pthread_condattr_init (&cattr))
    clib_unix_warning ("condattr_init");
  /* prints funny-looking messages in the Linux target */
  if (pthread_condattr_setpshared (&cattr, PTHREAD_PROCESS_SHARED))
    clib_unix_warning ("condattr_setpshared");
  if (pthread_cond_init (&q->condvar, &cattr))
    clib_unix_warning ("cond_init1");
  if (pthread_condattr_destroy (&cattr))
    clib_unix_warning ("cond_init2");

  return (q);
}

svm_queue_t *
svm_queue_alloc_and_init (int nels, int elsize, int consumer_pid)
{
  svm_queue_t *q;

  q = clib_mem_alloc_aligned (sizeof (svm_queue_t)
			      + nels * elsize, CLIB_CACHE_LINE_BYTES);
  clib_memset (q, 0, sizeof (*q));
  q = svm_queue_init (q, nels, elsize);
  q->consumer_pid = consumer_pid;

  return q;
}

/*
 * svm_queue_free
 */
void
svm_queue_free (svm_queue_t * q)
{
  (void) pthread_mutex_destroy (&q->mutex);
  (void) pthread_cond_destroy (&q->condvar);
  clib_mem_free (q);
}

void
svm_queue_lock (svm_queue_t * q)
{
  int rv = pthread_mutex_lock (&q->mutex);
  if (PREDICT_FALSE (rv == EOWNERDEAD))
    pthread_mutex_consistent (&q->mutex);
}

static int
svm_queue_trylock (svm_queue_t * q)
{
  int rv = pthread_mutex_trylock (&q->mutex);
  if (PREDICT_FALSE (rv == EOWNERDEAD))
    rv = pthread_mutex_consistent (&q->mutex);
  return rv;
}

void
svm_queue_unlock (svm_queue_t * q)
{
  pthread_mutex_unlock (&q->mutex);
}

int
svm_queue_is_full (svm_queue_t * q)
{
  return q->cursize == q->maxsize;
}

static inline void
svm_queue_send_signal_inline (svm_queue_t * q, u8 is_prod)
{
  if (q->producer_evtfd == -1)
    {
      (void) pthread_cond_broadcast (&q->condvar);
    }
  else
    {
      int __clib_unused rv, fd;
      u64 data = 1;
      ASSERT (q->consumer_evtfd > 0 && q->producer_evtfd > 0);
      fd = is_prod ? q->producer_evtfd : q->consumer_evtfd;
      rv = write (fd, &data, sizeof (data));
      if (PREDICT_FALSE (rv < 0))
	clib_unix_warning ("signal write on %d returned %d", fd, rv);
    }
}

void
svm_queue_send_signal (svm_queue_t * q, u8 is_prod)
{
  svm_queue_send_signal_inline (q, is_prod);
}

static inline void
svm_queue_wait_inline (svm_queue_t * q)
{
  if (q->producer_evtfd == -1)
    {
      pthread_cond_wait (&q->condvar, &q->mutex);
    }
  else
    {
      /* Fake a wait for event. We could use epoll but that would mean
       * using yet another fd. Should do for now */
      u32 cursize = q->cursize;
      svm_queue_unlock (q);
      while (q->cursize == cursize)
	CLIB_PAUSE ();
      svm_queue_lock (q);
    }
}

void
svm_queue_wait (svm_queue_t * q)
{
  svm_queue_wait_inline (q);
}

static inline int
svm_queue_timedwait_inline (svm_queue_t * q, double timeout)
{
  struct timespec ts;
  ts.tv_sec = unix_time_now () + (u32) timeout;
  ts.tv_nsec = (timeout - (u32) timeout) * 1e9;

  if (q->producer_evtfd == -1)
    {
      return pthread_cond_timedwait (&q->condvar, &q->mutex, &ts);
    }
  else
    {
      double max_time = unix_time_now () + timeout;
      u32 cursize = q->cursize;
      int rv;

      svm_queue_unlock (q);
      while (q->cursize == cursize && unix_time_now () < max_time)
	CLIB_PAUSE ();
      rv = unix_time_now () < max_time ? 0 : ETIMEDOUT;
      svm_queue_lock (q);
      return rv;
    }
}

int
svm_queue_timedwait (svm_queue_t * q, double timeout)
{
  return svm_queue_timedwait_inline (q, timeout);
}

/*
 * svm_queue_add_nolock
 */
int
svm_queue_add_nolock (svm_queue_t * q, u8 * elem)
{
  i8 *tailp;
  int need_broadcast = 0;

  if (PREDICT_FALSE (q->cursize == q->maxsize))
    {
      while (q->cursize == q->maxsize)
	svm_queue_wait_inline (q);
    }

  tailp = (i8 *) (&q->data[0] + q->elsize * q->tail);
  clib_memcpy_fast (tailp, elem, q->elsize);

  q->tail++;
  q->cursize++;

  need_broadcast = (q->cursize == 1);

  if (q->tail == q->maxsize)
    q->tail = 0;

  if (need_broadcast)
    svm_queue_send_signal_inline (q, 1);
  return 0;
}

void
svm_queue_add_raw (svm_queue_t * q, u8 * elem)
{
  i8 *tailp;

  tailp = (i8 *) (&q->data[0] + q->elsize * q->tail);
  clib_memcpy_fast (tailp, elem, q->elsize);

  q->tail = (q->tail + 1) % q->maxsize;
  q->cursize++;

  if (q->cursize == 1)
    svm_queue_send_signal_inline (q, 1);
}


/*
 * svm_queue_add
 */
int
svm_queue_add (svm_queue_t * q, u8 * elem, int nowait)
{
  i8 *tailp;
  int need_broadcast = 0;

  if (nowait)
    {
      /* zero on success */
      if (svm_queue_trylock (q))
	{
	  return (-1);
	}
    }
  else
    svm_queue_lock (q);

  if (PREDICT_FALSE (q->cursize == q->maxsize))
    {
      if (nowait)
	{
	  svm_queue_unlock (q);
	  return (-2);
	}
      while (q->cursize == q->maxsize)
	svm_queue_wait_inline (q);
    }

  tailp = (i8 *) (&q->data[0] + q->elsize * q->tail);
  clib_memcpy_fast (tailp, elem, q->elsize);

  q->tail++;
  q->cursize++;

  need_broadcast = (q->cursize == 1);

  if (q->tail == q->maxsize)
    q->tail = 0;

  if (need_broadcast)
    svm_queue_send_signal_inline (q, 1);

  svm_queue_unlock (q);

  return 0;
}

/*
 * svm_queue_add2
 */
int
svm_queue_add2 (svm_queue_t * q, u8 * elem, u8 * elem2, int nowait)
{
  i8 *tailp;
  int need_broadcast = 0;

  if (nowait)
    {
      /* zero on success */
      if (svm_queue_trylock (q))
	{
	  return (-1);
	}
    }
  else
    svm_queue_lock (q);

  if (PREDICT_FALSE (q->cursize + 1 == q->maxsize))
    {
      if (nowait)
	{
	  svm_queue_unlock (q);
	  return (-2);
	}
      while (q->cursize + 1 == q->maxsize)
	svm_queue_wait_inline (q);
    }

  tailp = (i8 *) (&q->data[0] + q->elsize * q->tail);
  clib_memcpy_fast (tailp, elem, q->elsize);

  q->tail++;
  q->cursize++;

  if (q->tail == q->maxsize)
    q->tail = 0;

  need_broadcast = (q->cursize == 1);

  tailp = (i8 *) (&q->data[0] + q->elsize * q->tail);
  clib_memcpy_fast (tailp, elem2, q->elsize);

  q->tail++;
  q->cursize++;

  if (q->tail == q->maxsize)
    q->tail = 0;

  if (need_broadcast)
    svm_queue_send_signal_inline (q, 1);

  svm_queue_unlock (q);

  return 0;
}

/*
 * svm_queue_sub
 */
int
svm_queue_sub (svm_queue_t * q, u8 * elem, svm_q_conditional_wait_t cond,
	       u32 time)
{
  i8 *headp;
  int need_broadcast = 0;
  int rc = 0;

  if (cond == SVM_Q_NOWAIT)
    {
      /* zero on success */
      if (svm_queue_trylock (q))
	{
	  return (-1);
	}
    }
  else
    svm_queue_lock (q);

  if (PREDICT_FALSE (q->cursize == 0))
    {
      if (cond == SVM_Q_NOWAIT)
	{
	  svm_queue_unlock (q);
	  return (-2);
	}
      else if (cond == SVM_Q_TIMEDWAIT)
	{
	  while (q->cursize == 0 && rc == 0)
	    rc = svm_queue_timedwait_inline (q, time);

	  if (rc == ETIMEDOUT)
	    {
	      svm_queue_unlock (q);
	      return ETIMEDOUT;
	    }
	}
      else
	{
	  while (q->cursize == 0)
	    svm_queue_wait_inline (q);
	}
    }

  headp = (i8 *) (&q->data[0] + q->elsize * q->head);
  clib_memcpy_fast (elem, headp, q->elsize);

  q->head++;
  /* $$$$ JFC shouldn't this be == 0? */
  if (q->cursize == q->maxsize)
    need_broadcast = 1;

  q->cursize--;

  if (q->head == q->maxsize)
    q->head = 0;

  if (need_broadcast)
    svm_queue_send_signal_inline (q, 0);

  svm_queue_unlock (q);

  return 0;
}

int
svm_queue_sub2 (svm_queue_t * q, u8 * elem)
{
  int need_broadcast;
  i8 *headp;

  svm_queue_lock (q);
  if (q->cursize == 0)
    {
      svm_queue_unlock (q);
      return -1;
    }

  headp = (i8 *) (&q->data[0] + q->elsize * q->head);
  clib_memcpy_fast (elem, headp, q->elsize);

  q->head++;
  need_broadcast = (q->cursize == q->maxsize / 2);
  q->cursize--;

  if (PREDICT_FALSE (q->head == q->maxsize))
    q->head = 0;
  svm_queue_unlock (q);

  if (need_broadcast)
    svm_queue_send_signal_inline (q, 0);

  return 0;
}

int
svm_queue_sub_raw (svm_queue_t * q, u8 * elem)
{
  int need_broadcast;
  i8 *headp;

  if (PREDICT_FALSE (q->cursize == 0))
    {
      while (q->cursize == 0)
	;
    }

  headp = (i8 *) (&q->data[0] + q->elsize * q->head);
  clib_memcpy_fast (elem, headp, q->elsize);

  need_broadcast = q->cursize == q->maxsize;

  q->head = (q->head + 1) % q->maxsize;
  q->cursize--;

  if (PREDICT_FALSE (need_broadcast))
    svm_queue_send_signal_inline (q, 0);

  return 0;
}

void
svm_queue_set_producer_event_fd (svm_queue_t * q, int fd)
{
  q->producer_evtfd = fd;
}

void
svm_queue_set_consumer_event_fd (svm_queue_t * q, int fd)
{
  q->consumer_evtfd = fd;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
