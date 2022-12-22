/*
 * Copyright (c) 2018-2019 Cisco and/or its affiliates.
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
#include <vppinfra/error.h>
#include <vppinfra/lock.h>
#include <svm/queue.h>

typedef struct svm_msg_q_shr_queue_
{
  pthread_mutex_t mutex;  /* 8 bytes */
  pthread_cond_t condvar; /* 8 bytes */
  u32 head;
  u32 tail;
  volatile u32 cursize;
  u32 maxsize;
  u32 elsize;
  u32 pad;
  u8 data[0];
} svm_msg_q_shared_queue_t;

typedef struct svm_msg_q_queue_
{
  svm_msg_q_shared_queue_t *shr; /**< pointer to shared queue */
  int evtfd;			 /**< producer/consumer eventfd */
  clib_spinlock_t lock;		 /**< private lock for multi-producer */
} svm_msg_q_queue_t;

typedef struct svm_msg_q_ring_shared_
{
  volatile u32 cursize;			/**< current size of the ring */
  u32 nitems;				/**< max size of the ring */
  volatile u32 head;			/**< current head (for dequeue) */
  volatile u32 tail;			/**< current tail (for enqueue) */
  u32 elsize;				/**< size of an element */
  u8 data[0];				/**< chunk of memory for msg data */
} svm_msg_q_ring_shared_t;

typedef struct svm_msg_q_ring_
{
  u32 nitems;			/**< max size of the ring */
  u32 elsize;			/**< size of an element */
  svm_msg_q_ring_shared_t *shr; /**< ring in shared memory */
} __clib_packed svm_msg_q_ring_t;

typedef struct svm_msg_q_shared_
{
  u32 n_rings;			 /**< number of rings after q */
  u32 pad;			 /**< 8 byte alignment for q */
  svm_msg_q_shared_queue_t q[0]; /**< queue for exchanging messages */
} __clib_packed svm_msg_q_shared_t;

typedef struct svm_msg_q_
{
  svm_msg_q_queue_t q;			/**< queue for exchanging messages */
  svm_msg_q_ring_t *rings;		/**< rings with message data*/
} __clib_packed svm_msg_q_t;

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

#define SVM_MQ_INVALID_MSG { .as_u64 = ~0 }

typedef enum svm_msg_q_wait_type_
{
  SVM_MQ_WAIT_EMPTY,
  SVM_MQ_WAIT_FULL
} svm_msg_q_wait_type_t;

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
svm_msg_q_shared_t *svm_msg_q_alloc (svm_msg_q_cfg_t *cfg);
svm_msg_q_shared_t *svm_msg_q_init (void *base, svm_msg_q_cfg_t *cfg);
uword svm_msg_q_size_to_alloc (svm_msg_q_cfg_t *cfg);

void svm_msg_q_attach (svm_msg_q_t *mq, void *smq_base);

/**
 * Cleanup mq's private data
 */
void svm_msg_q_cleanup (svm_msg_q_t *mq);

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
 * Allocate message buffer on ring
 *
 * Message is allocated, on requested ring. The caller MUST check that
 * the ring is not full.
 *
 * @param mq		message queue
 * @param ring_index	ring on which the allocation should occur
 * @return		message structure pointing to the ring and position
 * 			allocated
 */
svm_msg_q_msg_t svm_msg_q_alloc_msg_w_ring (svm_msg_q_t * mq, u32 ring_index);

/**
 * Lock message queue and allocate message buffer on ring
 *
 * This should be used when multiple writers/readers are expected to
 * compete for the rings/queue. Message should be enqueued by calling
 * @ref svm_msg_q_add_w_lock and the caller MUST unlock the queue once
 * the message in enqueued.
 *
 * @param mq		message queue
 * @param ring_index	ring on which the allocation should occur
 * @param noblock	flag that indicates if request should block
 * @param msg		pointer to message to be filled in
 * @return		0 on success, negative number otherwise
 */
int svm_msg_q_lock_and_alloc_msg_w_ring (svm_msg_q_t * mq, u32 ring_index,
					 u8 noblock, svm_msg_q_msg_t * msg);

/**
 * Free message buffer
 *
 * Marks message buffer on ring as free.
 *
 * @param mq		message queue
 * @param msg		message to be freed
 */
void svm_msg_q_free_msg (svm_msg_q_t * mq, svm_msg_q_msg_t * msg);

void svm_msg_q_add_raw (svm_msg_q_t *mq, u8 *elem);

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
int svm_msg_q_add (svm_msg_q_t * mq, svm_msg_q_msg_t * msg, int nowait);

/**
 * Producer enqueue one message to queue with mutex held
 *
 * Prior to calling this, the producer should've obtained a message buffer
 * from one of the rings by calling @ref svm_msg_q_alloc_msg. It assumes
 * the queue mutex is held.
 *
 * @param mq		message queue
 * @param msg		message (pointer to ring position) to be enqueued
 * @return		success status
 */
void svm_msg_q_add_and_unlock (svm_msg_q_t * mq, svm_msg_q_msg_t * msg);

/**
 * Consumer dequeue one message from queue
 *
 * This returns the message pointing to the data in the message rings.
 * Should only be used in single consumer scenarios as no locks are grabbed.
 * The consumer is expected to call @ref svm_msg_q_free_msg once it
 * finishes processing/copies the message data.
 *
 * @param mq		message queue
 * @param msg		pointer to structure where message is to be received
 * @param cond		flag that indicates if request should block or not
 * @param time		time to wait if condition it SVM_Q_TIMEDWAIT
 * @return		success status
 */
int svm_msg_q_sub (svm_msg_q_t * mq, svm_msg_q_msg_t * msg,
		   svm_q_conditional_wait_t cond, u32 time);

/**
 * Consumer dequeue one message from queue
 *
 * Returns the message pointing to the data in the message rings. Should only
 * be used in single consumer scenarios as no locks are grabbed. The consumer
 * is expected to call @ref svm_msg_q_free_msg once it finishes
 * processing/copies the message data.
 *
 * @param mq		message queue
 * @param msg		pointer to structure where message is to be received
 * @return		success status
 */
int svm_msg_q_sub_raw (svm_msg_q_t *mq, svm_msg_q_msg_t *elem);

/**
 * Consumer dequeue multiple messages from queue
 *
 * Returns the message pointing to the data in the message rings. Should only
 * be used in single consumer scenarios as no locks are grabbed. The consumer
 * is expected to call @ref svm_msg_q_free_msg once it finishes
 * processing/copies the message data.
 *
 * @param mq		message queue
 * @param msg_buf	pointer to array of messages to received
 * @param n_msgs	lengt of msg_buf array
 * @return		number of messages dequeued
 */
int svm_msg_q_sub_raw_batch (svm_msg_q_t *mq, svm_msg_q_msg_t *msg_buf,
			     u32 n_msgs);

/**
 * Get data for message in queue
 *
 * @param mq		message queue
 * @param msg		message for which the data is requested
 * @return		pointer to data
 */
void *svm_msg_q_msg_data (svm_msg_q_t * mq, svm_msg_q_msg_t * msg);

/**
 * Get message queue ring
 *
 * @param mq		message queue
 * @param ring_index	index of ring
 * @return		pointer to ring
 */
svm_msg_q_ring_t *svm_msg_q_ring (svm_msg_q_t * mq, u32 ring_index);

/**
 * Set event fd for queue
 *
 * If set, queue will exclusively use eventfds for signaling. Moreover,
 * afterwards, the queue should only be used in non-blocking mode. Waiting
 * for events should be done externally using something like epoll.
 *
 * @param mq		message queue
 * @param fd		consumer eventfd
 */
void svm_msg_q_set_eventfd (svm_msg_q_t *mq, int fd);

/**
 * Allocate event fd for queue
 */
int svm_msg_q_alloc_eventfd (svm_msg_q_t *mq);

/**
 * Format message queue, shows msg count for each ring
 */
u8 *format_svm_msg_q (u8 *s, va_list *args);

/**
 * Check length of message queue
 */
static inline u32
svm_msg_q_size (svm_msg_q_t *mq)
{
  return clib_atomic_load_relax_n (&mq->q.shr->cursize);
}

/**
 * Check if message queue is full
 */
static inline u8
svm_msg_q_is_full (svm_msg_q_t * mq)
{
  return (svm_msg_q_size (mq) == mq->q.shr->maxsize);
}

static inline u8
svm_msg_q_ring_is_full (svm_msg_q_t * mq, u32 ring_index)
{
  svm_msg_q_ring_t *ring = vec_elt_at_index (mq->rings, ring_index);
  return (clib_atomic_load_relax_n (&ring->shr->cursize) >= ring->nitems);
}

static inline u8
svm_msg_q_or_ring_is_full (svm_msg_q_t *mq, u32 ring_index)
{
  return (svm_msg_q_is_full (mq) || svm_msg_q_ring_is_full (mq, ring_index));
}

/**
 * Check if message queue is empty
 */
static inline u8
svm_msg_q_is_empty (svm_msg_q_t * mq)
{
  return (svm_msg_q_size (mq) == 0);
}

/**
 * Check if message is invalid
 */
static inline u8
svm_msg_q_msg_is_invalid (svm_msg_q_msg_t * msg)
{
  return (msg->as_u64 == (u64) ~ 0);
}

/**
 * Try locking message queue
 */
static inline int
svm_msg_q_try_lock (svm_msg_q_t * mq)
{
  if (mq->q.evtfd == -1)
    {
      int rv = pthread_mutex_trylock (&mq->q.shr->mutex);
      if (PREDICT_FALSE (rv == EOWNERDEAD))
	rv = pthread_mutex_consistent (&mq->q.shr->mutex);
      return rv;
    }
  else
    {
      return !clib_spinlock_trylock (&mq->q.lock);
    }
}

/**
 * Lock, or block trying, the message queue
 */
static inline int
svm_msg_q_lock (svm_msg_q_t * mq)
{
  if (mq->q.evtfd == -1)
    {
      int rv = pthread_mutex_lock (&mq->q.shr->mutex);
      if (PREDICT_FALSE (rv == EOWNERDEAD))
	rv = pthread_mutex_consistent (&mq->q.shr->mutex);
      return rv;
    }
  else
    {
      clib_spinlock_lock (&mq->q.lock);
      return 0;
    }
}

/**
 * Unlock message queue
 */
static inline void
svm_msg_q_unlock (svm_msg_q_t * mq)
{
  if (mq->q.evtfd == -1)
    {
      pthread_mutex_unlock (&mq->q.shr->mutex);
    }
  else
    {
      clib_spinlock_unlock (&mq->q.lock);
    }
}

/**
 * Wait for message queue event
 *
 * When eventfds are not configured, the shared memory mutex is locked
 * before waiting on the condvar. Typically called by consumers.
 */
int svm_msg_q_wait (svm_msg_q_t *mq, svm_msg_q_wait_type_t type);

/**
 * Wait for message queue event as producer
 *
 * Similar to @ref svm_msg_q_wait but lock (mutex or spinlock) must
 * be held. Should only be called by producers.
 */
int svm_msg_q_wait_prod (svm_msg_q_t *mq);

/**
 * Wait for message queue or ring event as producer
 *
 * Similar to @ref svm_msg_q_wait but lock (mutex or spinlock) must
 * be held. Should only be called by producers.
 */
int svm_msg_q_or_ring_wait_prod (svm_msg_q_t *mq, u32 ring_index);

/**
 * Timed wait for message queue event
 *
 * Must be called with mutex held.
 *
 * @param mq 		message queue
 * @param timeout	time in seconds
 */
int svm_msg_q_timedwait (svm_msg_q_t *mq, double timeout);

static inline int
svm_msg_q_get_eventfd (svm_msg_q_t *mq)
{
  return mq->q.evtfd;
}

#endif /* SRC_SVM_MESSAGE_QUEUE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
