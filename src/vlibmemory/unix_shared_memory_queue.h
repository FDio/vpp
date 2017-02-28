/*
 *------------------------------------------------------------------
 * unix_shared_memory_queue.h - shared-memory queues
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

#ifndef included_unix_shared_memory_queue_h
#define included_unix_shared_memory_queue_h

#include <pthread.h>
#include <vppinfra/mem.h>

typedef struct _unix_shared_memory_queue
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
} unix_shared_memory_queue_t;

unix_shared_memory_queue_t *unix_shared_memory_queue_init (int nels,
							   int elsize,
							   int consumer_pid,
							   int
							   signal_when_queue_non_empty);
void unix_shared_memory_queue_free (unix_shared_memory_queue_t * q);
int unix_shared_memory_queue_add (unix_shared_memory_queue_t * q,
				  u8 * elem, int nowait);
int unix_shared_memory_queue_sub (unix_shared_memory_queue_t * q,
				  u8 * elem, int nowait);
void unix_shared_memory_queue_lock (unix_shared_memory_queue_t * q);
void unix_shared_memory_queue_unlock (unix_shared_memory_queue_t * q);
int unix_shared_memory_queue_is_full (unix_shared_memory_queue_t * q);
int unix_shared_memory_queue_add_nolock (unix_shared_memory_queue_t * q,
					 u8 * elem);

int unix_shared_memory_queue_sub_raw (unix_shared_memory_queue_t * q,
				      u8 * elem);
int unix_shared_memory_queue_add_raw (unix_shared_memory_queue_t * q,
				      u8 * elem);

#endif /* included_unix_shared_memory_queue_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
