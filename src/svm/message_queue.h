/*
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
 */
/**
 * @file
 * @brief Unidirectional shared-memory multi-ring message queue
 */

#ifndef SRC_SVM_MESSAGE_QUEUE_H_
#define SRC_SVM_MESSAGE_QUEUE_H_

#include <vppinfra/clib.h>
#include <pthread.h>

typedef struct svm_msg_q_ring_
{
  volatile u32 cursize;
  u32 nitems;
  u32 head;
  u32 tail;
  u32 elsize;
  u8 data[0];
} svm_msg_q_ring_t;

typedef struct svm_msg_q_
{
#ifdef SVM_MSG_Q_USE_EVENTFD
  int event_fd;
#else
  pthread_mutex_t mutex;
  pthread_cond_t condvar;
#endif
  svm_queue_t *q;
  svm_msg_q_ring_t *rings;
} svm_msg_q_t;

typedef struct svm_msg_q_ring_cfg_
{
  u32 nitems;
  u32 elsize;
  void *data;
} svm_msg_q_ring_cfg_t;

typedef struct svm_msg_q_cfg_
{
  int consumer_pid;			/**< pid of msg consumer */
  u32 q_nitems;				/**< msg queue size (not rings) */
  u32 n_rings;				/**< number of msg rings */
#ifdef SVM_MSG_Q_USE_EVENTFD
  int event_fd;
#endif
  svm_msg_q_ring_cfg_t *ring_cfgs;	/**< array of ring cfgs */
} svm_msg_q_cfg_t;

typedef struct
{
  u16 ring_index;
  u16 elt_index;
} svm_msg_q_msg_t;

svm_queue_t * svm_msg_q_alloc (svm_msg_q_cfg_t *cfg, int consumer_pid);
void svm_msg_q_free (svm_queue_t * mq);
#endif /* SRC_SVM_MESSAGE_QUEUE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
