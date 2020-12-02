/*
 *------------------------------------------------------------------
 * svm_queue.h - shared-memory queues
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

#ifndef included_svm_queue_h
#define included_svm_queue_h

#include <pthread.h>
#include <vppinfra/clib.h>

typedef struct _svm_queue
{
  pthread_mutex_t mutex;	/* 8 bytes */
  pthread_cond_t condvar;	/* 8 bytes */
  int head;
  int tail;
  volatile int cursize;
  int maxsize;
  int elsize;
  int consumer_pid;
  int producer_evtfd;
  int consumer_evtfd;
  char data[0];
} svm_queue_t;

typedef enum
{
  SVM_Q_WAIT = 0,	/**< blocking call - best used in combination with
			     condvars, for eventfds we don't yield the cpu */
  SVM_Q_NOWAIT,		/**< non-blocking call - works with both condvar and
			     eventfd signaling */
  SVM_Q_TIMEDWAIT,	/**< blocking call, returns on signal or time-out -
			     best used in combination with condvars, with
			     eventfds we don't yield the cpu */
} svm_q_conditional_wait_t;

/**
 * Allocate and initialize svm queue
 *
 * @param nels		number of elements on the queue
 * @param elsize	element size, presumably 4 and cacheline-size will
 *          		be popular choices.
 * @param pid   	consumer pid
 * @return 		a newly initialized svm queue
 *
 * The idea is to call this function in the queue consumer,
 * and e-mail the queue pointer to the producer(s).
 *
 * The vpp process / main thread allocates one of these
 * at startup; its main input queue. The vpp main input queue
 * has a pointer to it in the shared memory segment header.
 *
 * You probably want to be on an svm data heap before calling this
 * function.
 */
svm_queue_t *svm_queue_alloc_and_init (int nels, int elsize,
				       int consumer_pid);
svm_queue_t *svm_queue_init (void *base, int nels, int elsize);
void svm_queue_free (svm_queue_t * q);
int svm_queue_add (svm_queue_t * q, u8 * elem, int nowait);
int svm_queue_add2 (svm_queue_t * q, u8 * elem, u8 * elem2, int nowait);
int svm_queue_sub (svm_queue_t * q, u8 * elem, svm_q_conditional_wait_t cond,
		   u32 time);
int svm_queue_sub2 (svm_queue_t * q, u8 * elem);
void svm_queue_lock (svm_queue_t * q);
void svm_queue_send_signal (svm_queue_t * q, u8 is_prod);
void svm_queue_unlock (svm_queue_t * q);
int svm_queue_is_full (svm_queue_t * q);
int svm_queue_add_nolock (svm_queue_t * q, u8 * elem);
int svm_queue_sub_raw (svm_queue_t * q, u8 * elem);

/**
 * Wait for queue event
 *
 * Must be called with mutex held.
 */
void svm_queue_wait (svm_queue_t * q);

/**
 * Timed wait for queue event
 *
 * Must be called with mutex held.
 *
 * @param q		svm queue
 * @param timeout	time in seconds
 * @return 		0 on success, ETIMEDOUT on timeout or an error
 */
int svm_queue_timedwait (svm_queue_t * q, double timeout);

/**
 * Add element to queue with mutex held
 * @param q		queue
 * @param elem		pointer element data to add
 */
void svm_queue_add_raw (svm_queue_t * q, u8 * elem);

/**
 * Set producer's event fd
 *
 * When the producer must generate an event it writes 1 to the provided fd.
 * Once this is set, condvars are not used anymore for signaling.
 */
void svm_queue_set_producer_event_fd (svm_queue_t * q, int fd);

/**
 * Set consumer's event fd
 *
 * When the consumer must generate an event it writes 1 to the provided fd.
 * Although in practice the two fds point to the same underlying file
 * description, because the producer and consumer are different processes
 * the descriptors will be different. It's the caller's responsibility to
 * ensure the file descriptors are properly exchanged between the two peers.
 */
void svm_queue_set_consumer_event_fd (svm_queue_t * q, int fd);

/*
 * DEPRECATED please use svm_queue_t instead
 */
typedef svm_queue_t unix_shared_memory_queue_t;

#endif /* included_svm_queue_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
