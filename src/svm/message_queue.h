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
#include <svm/queue.h>

typedef struct svm_msg_q_ring_
{
  volatile u32 cursize;			/**< current size of the ring */
  u32 nitems;				/**< max size of the ring */
  u32 head;				/**< current head (for dequeue) */
  u32 tail;				/**< current tail (for enqueue) */
  u32 elsize;				/**< size of an element */
  u8 *data;				/**< chunk of memory for msg data */
} svm_msg_q_ring_t;

typedef struct svm_msg_q_
{
  svm_queue_t *q;			/**< queue for exchanging messages */
  svm_msg_q_ring_t *rings;		/**< rings with message data*/
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
  svm_msg_q_ring_cfg_t *ring_cfgs;	/**< array of ring cfgs */
} svm_msg_q_cfg_t;

typedef union
{
  struct
  {
    u32 ring_index;			/**< ring index, could be u8 */
    u32 elt_index;			/**< index in ring */
  };
  u64 as_u64;
} svm_msg_q_msg_t;

/**
 * Allocate message queue
 *
 * Allocates a message queue on the heap. Based on the configuration options,
 * apart from the message queue this also allocates (one or multiple)
 * shared-memory rings for the messages.
 *
 * @param cfg 		configuration options: queue len, consumer pid,
 * 			ring configs
 * @return		message queue
 */
svm_msg_q_t *svm_msg_q_alloc (svm_msg_q_cfg_t * cfg);

/**
 * Free message queue
 *
 * @param mq		message queue to be freed
 */
void svm_msg_q_free (svm_msg_q_t * mq);

/**
 * Allocate message buffer
 *
 * Message is allocated on the first available ring capable of holding
 * the requested number of bytes.
 *
 * @param mq		message queue
 * @param nbytes	number of bytes needed for message
 * @return		message structure pointing to the ring and position
 * 			allocated
 */
svm_msg_q_msg_t svm_msg_q_alloc_msg (svm_msg_q_t * mq, u32 nbytes);

/**
 * Free message buffer
 *
 * Marks message buffer on ring as free.
 *
 * @param mq		message queue
 * @param msg		message to be freed
 */
void svm_msg_q_free_msg (svm_msg_q_t * mq, svm_msg_q_msg_t * msg);
/**
 * Producer enqueue one message to queue
 *
 * Prior to calling this, the producer should've obtained a message buffer
 * from one of the rings by calling @ref svm_msg_q_alloc_msg.
 *
 * @param mq		message queue
 * @param msg		message (pointer to ring position) to be enqueued
 * @param nowait	flag to indicate if request is blocking or not
 * @return		success status
 */
int svm_msg_q_add (svm_msg_q_t * mq, svm_msg_q_msg_t msg, int nowait);

/**
 * Consumer dequeue one message from queue
 *
 * This returns the message pointing to the data in the message rings.
 * The consumer is expected to call @ref svm_msg_q_free_msg once it
 * finishes processing/copies the message data.
 *
 * @param mq		message queue
 * @param msg		pointer to structure where message is to be received
 * @param cond		flag that indicates if request should block or not
 * @return		success status
 */
int svm_msg_q_sub (svm_msg_q_t * mq, svm_msg_q_msg_t * msg,
		   svm_q_conditional_wait_t cond, u32 time);

/**
 * Get data for message in queu
 *
 * @param mq		message queue
 * @param msg		message for which the data is requested
 * @return		pointer to data
 */
void *svm_msg_q_msg_data (svm_msg_q_t * mq, svm_msg_q_msg_t * msg);

#endif /* SRC_SVM_MESSAGE_QUEUE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
