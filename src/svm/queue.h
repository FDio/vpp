/*
 *------------------------------------------------------------------
 * svm_queue.h - shared-memory queues
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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
  int signal_when_queue_non_empty;
  char data[0];
} svm_queue_t;

typedef enum
{
  /**
   * blocking call
   */
  SVM_Q_WAIT = 0,

  /**
   * non-blocking call
   */
  SVM_Q_NOWAIT,

  /**
   * blocking call, return on signal or time-out
   */
  SVM_Q_TIMEDWAIT,
} svm_q_conditional_wait_t;

svm_queue_t *svm_queue_init (int nels,
			     int elsize,
			     int consumer_pid,
			     int signal_when_queue_non_empty);
void svm_queue_free (svm_queue_t * q);
int svm_queue_add (svm_queue_t * q, u8 * elem, int nowait);
int svm_queue_add2 (svm_queue_t * q, u8 * elem, u8 * elem2, int nowait);
int svm_queue_sub (svm_queue_t * q, u8 * elem, svm_q_conditional_wait_t cond,
		   u32 time);
int svm_queue_sub2 (svm_queue_t * q, u8 * elem);
void svm_queue_lock (svm_queue_t * q);
void svm_queue_unlock (svm_queue_t * q);
int svm_queue_is_full (svm_queue_t * q);
int svm_queue_add_nolock (svm_queue_t * q, u8 * elem);
int svm_queue_sub_raw (svm_queue_t * q, u8 * elem);
int svm_queue_add_raw (svm_queue_t * q, u8 * elem);

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
