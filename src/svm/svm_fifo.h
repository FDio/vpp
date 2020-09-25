/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
 * Copyright (c) 2019 Arm Limited
 * Copyright (c) 2010-2017 Intel Corporation and/or its affiliates.
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * Inspired from DPDK rte_ring.h (SPSC only) (derived from freebsd bufring.h).
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
#ifndef __included_ssvm_fifo_h__
#define __included_ssvm_fifo_h__

#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <svm/fifo_types.h>

#define OOO_SEGMENT_INVALID_INDEX 	((u32)~0)
#define SVM_FIFO_INVALID_SESSION_INDEX 	((u32)~0)
#define SVM_FIFO_INVALID_INDEX		((u32)~0)

typedef enum svm_fifo_deq_ntf_
{
  SVM_FIFO_NO_DEQ_NOTIF = 0,		/**< No notification requested */
  SVM_FIFO_WANT_DEQ_NOTIF = 1,		/**< Notify on dequeue */
  SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL = 2,	/**< Notify on transition from full */
  SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY = 4,	/**< Notify on transition to empty */
} svm_fifo_deq_ntf_t;

typedef enum svm_fifo_flag_
{
  SVM_FIFO_F_LL_TRACKED = 1 << 0,
} svm_fifo_flag_t;

typedef enum
{
  SVM_FIFO_EFULL = -2,
  SVM_FIFO_EEMPTY = -3,
  SVM_FIFO_EGROW = -4,
} svm_fifo_err_t;

typedef struct svm_fifo_seg_
{
  u8 *data;
  u32 len;
} svm_fifo_seg_t;

#if SVM_FIFO_TRACE
#define svm_fifo_trace_add(_f, _s, _l, _t)		\
{							\
  svm_fifo_trace_elem_t *trace_elt;			\
  vec_add2(_f->trace, trace_elt, 1);			\
  trace_elt->offset = _s;				\
  trace_elt->len = _l;					\
  trace_elt->action = _t;				\
}
#else
#define svm_fifo_trace_add(_f, _s, _l, _t)
#endif

u8 *svm_fifo_dump_trace (u8 * s, svm_fifo_t * f);
u8 *svm_fifo_replay (u8 * s, svm_fifo_t * f, u8 no_read, u8 verbose);

/**
 * Load head and tail optimized for consumer
 *
 * Internal function.
 */
static inline void
f_load_head_tail_cons (svm_fifo_t * f, u32 * head, u32 * tail)
{
  /* load-relaxed: consumer owned index */
  *head = f->head;
  /* load-acq: consumer foreign index (paired with store-rel in producer) */
  *tail = clib_atomic_load_acq_n (&f->tail);
}

/** Load head and tail optimized for producer
 *
 * Internal function
 */
static inline void
f_load_head_tail_prod (svm_fifo_t * f, u32 * head, u32 * tail)
{
  /* load relaxed: producer owned index */
  *tail = f->tail;
  /* load-acq: producer foreign index (paired with store-rel in consumer) */
  *head = clib_atomic_load_acq_n (&f->head);
}

/**
 * Load head and tail independent of producer/consumer role
 *
 * Internal function.
 */
static inline void
f_load_head_tail_all_acq (svm_fifo_t * f, u32 * head, u32 * tail)
{
  /* load-acq : consumer foreign index (paired with store-rel) */
  *tail = clib_atomic_load_acq_n (&f->tail);
  /* load-acq : producer foriegn index (paired with store-rel) */
  *head = clib_atomic_load_acq_n (&f->head);
}

/**
 * Fifo current size, i.e., number of bytes enqueued
 *
 * Internal function.
 */
static inline u32
f_cursize (svm_fifo_t * f, u32 head, u32 tail)
{
  return tail - head;
}

/**
 * Fifo free bytes, i.e., number of free bytes
 *
 * Internal function
 */
static inline u32
f_free_count (svm_fifo_t * f, u32 head, u32 tail)
{
  return (f->size - f_cursize (f, head, tail));
}

always_inline u32
f_chunk_end (svm_fifo_chunk_t * c)
{
  return c->start_byte + c->length;
}

always_inline int
f_pos_lt (u32 a, u32 b)
{
  return ((i32) (a - b) < 0);
}

always_inline int
f_pos_leq (u32 a, u32 b)
{
  return ((i32) (a - b) <= 0);
}

always_inline int
f_pos_gt (u32 a, u32 b)
{
  return ((i32) (a - b) > 0);
}

always_inline int
f_pos_geq (u32 a, u32 b)
{
  return ((i32) (a - b) >= 0);
}

always_inline u8
f_chunk_includes_pos (svm_fifo_chunk_t * c, u32 pos)
{
  return (f_pos_geq (pos, c->start_byte)
	  && f_pos_lt (pos, c->start_byte + c->length));
}

/**
 * Create fifo of requested size
 *
 * Allocates fifo on current heap.
 *
 * @param size		data size in bytes for fifo to be allocated. Will be
 * 			rounded to the next highest power-of-two value.
 * @return 		pointer to new fifo
 */
svm_fifo_t *svm_fifo_alloc (u32 size);
/**
 * Initialize fifo
 *
 * @param f		fifo
 * @param size		size for fifo
 */
void svm_fifo_init (svm_fifo_t * f, u32 size);
/**
 * Allocate a fifo chunk on heap
 *
 * If the chunk is allocated on a fifo segment, this should be called
 * with the segment's heap pushed.
 *
 * @param size	chunk size in bytes. Will be rounded to the next highest
 * 		power-of-two
 * @return	new chunk or 0 if alloc failed
 */
svm_fifo_chunk_t *svm_fifo_chunk_alloc (u32 size);
/**
 * Ensure the whole fifo size is writeable
 *
 * Allocates enough chunks to cover the whole fifo size.
 *
 * @param f	fifo
 */
int svm_fifo_fill_chunk_list (svm_fifo_t * f);
/**
 * Initialize rbtrees used for ooo lookups
 *
 * @param f		fifo
 * @param ooo_type	type of ooo operation (0 enqueue, 1 dequeue)
 */
void svm_fifo_init_ooo_lookup (svm_fifo_t * f, u8 ooo_type);
/**
 * Free fifo and associated state
 *
 * @param f	fifo
 */
void svm_fifo_free (svm_fifo_t * f);
/**
 * Cleanup fifo chunk lookup rb tree
 *
 * The rb tree is allocated in segment heap so this should be called
 * with it pushed.
 *
 * @param f 	fifo to cleanup
 */
void svm_fifo_free_chunk_lookup (svm_fifo_t * f);
/**
 * Cleanup fifo ooo data
 *
 * The ooo data is allocated in producer process memory. The fifo
 * segment heap should not be pushed.
 *
 * @param f	fifo to cleanup
 */
void svm_fifo_free_ooo_data (svm_fifo_t * f);
/**
 * Init fifo head and tail
 *
 * @param f	fifo
 * @param head	head value that will be matched to a chunk
 * @param tail	tail value that will be matched to a chunk
 */
void svm_fifo_init_pointers (svm_fifo_t * f, u32 head, u32 tail);
/**
 * Clone fifo
 *
 * Clones single/default chunk fifo. It does not work for fifos with
 * multiple chunks.
 */
void svm_fifo_clone (svm_fifo_t * df, svm_fifo_t * sf);
/**
 * Enqueue data to fifo
 *
 * Data is enqueued and tail pointer is updated atomically. If the new data
 * enqueued partly overlaps or "touches" an out-of-order segment, said segment
 * is "consumed" and the number of bytes returned is appropriately updated.
 *
 * @param f	fifo
 * @param len	length of data to copy
 * @param src	buffer from where to copy the data
 * @return	number of contiguous bytes that can be consumed or error
 */
int svm_fifo_enqueue (svm_fifo_t * f, u32 len, const u8 * src);
/**
 * Enqueue data to fifo with offset
 *
 * Data is enqueued without updating tail pointer. Instead, an out-of-order
 * list of segments is generated and maintained. Fifo takes care of coalescing
 * contiguous or overlapping segments.
 *
 * @param f		fifo
 * @param offset	offset at which to copy the data
 * @param len		len of data to copy
 * @param src		buffer from where to copy the data
 * @return		0 if enqueue was successful, error otherwise
 */
int svm_fifo_enqueue_with_offset (svm_fifo_t * f, u32 offset, u32 len,
				  u8 * src);

/**
 * Advance tail pointer
 *
 * Useful for moving tail pointer after external enqueue.
 *
 * @param f		fifo
 * @param len		number of bytes to add to tail
 */
void svm_fifo_enqueue_nocopy (svm_fifo_t * f, u32 len);
/**
 * Overwrite fifo head with new data
 *
 * This should be typically used by dgram transport protocols that need
 * to update the dgram header after dequeuing a chunk of data. It assumes
 * that the dgram header is at most spread over two chunks.
 *
 * @param f		fifo
 * @param src		src of new data
 * @param len		length of new data
 */
void svm_fifo_overwrite_head (svm_fifo_t * f, u8 * src, u32 len);
/**
 * Dequeue data from fifo
 *
 * Data is dequeued to consumer provided buffer and head is atomically
 * updated. This should not be used in combination with ooo lookups. If
 * ooo peeking of data is needed in combination with dequeuing use @ref
 * svm_fifo_dequeue_drop.
 *
 * @param f		fifo
 * @param len		length of data to dequeue
 * @param dst		buffer to where to dequeue the data
 * @return		number of bytes dequeued or error
 */
int svm_fifo_dequeue (svm_fifo_t * f, u32 len, u8 * dst);
/**
 * Peek data from fifo
 *
 * Data is copied from requested offset into provided dst buffer. Head is
 * not updated.
 *
 * @param f		fifo
 * @param offset	offset from which to copy the data
 * @param len		length of data to copy
 * @param dst		buffer to where to dequeue the data
 * @return		number of bytes peeked
 */
int svm_fifo_peek (svm_fifo_t * f, u32 offset, u32 len, u8 * dst);
/**
 * Dequeue and drop bytes from fifo
 *
 * Advances fifo head by requested amount of bytes.
 *
 * @param f		fifo
 * @param len		number of bytes to drop
 * @return		number of bytes dropped
 */
int svm_fifo_dequeue_drop (svm_fifo_t * f, u32 len);
/**
 * Dequeue and drop all bytes from fifo
 *
 * Advances head to tail position.
 *
 * @param f		fifo
 */
void svm_fifo_dequeue_drop_all (svm_fifo_t * f);
int svm_fifo_segments (svm_fifo_t * f, svm_fifo_seg_t * fs, u32 n_fs,
		       u32 max_bytes);
//void svm_fifo_segments_free (svm_fifo_t * f, svm_fifo_seg_t * fs);
/**
 * Add io events subscriber to list
 *
 * @param f	fifo
 * @param sub	subscriber opaque index (typically app worker index)
 */
void svm_fifo_add_subscriber (svm_fifo_t * f, u8 sub);
/**
 * Remove io events subscriber form list
 *
 * @param f	fifo
 * @param sub	subscriber index to be removed
 */
void svm_fifo_del_subscriber (svm_fifo_t * f, u8 subscriber);
/**
 * Number of out-of-order segments for fifo
 *
 * @param f	fifo
 * @return	number of out of order segments
 */
u32 svm_fifo_n_ooo_segments (svm_fifo_t * f);
/**
 * First out-of-order segment for fifo
 *
 * @param f	fifo
 * @return	first out-of-order segment for fifo
 */
ooo_segment_t *svm_fifo_first_ooo_segment (svm_fifo_t * f);
/**
 * Check if fifo is sane. Debug only.
 *
 * @param f	fifo
 * @return 	1 if sane, 0 otherwise
 */
u8 svm_fifo_is_sane (svm_fifo_t * f);
/**
 * Number of chunks linked into the fifo
 *
 * @param f	fifo
 * @return 	number of chunks in fifo linked list
 */
u32 svm_fifo_n_chunks (svm_fifo_t * f);
format_function_t format_svm_fifo;

/**
 * Fifo max bytes to dequeue optimized for consumer
 *
 * @param f	fifo
 * @return	max number of bytes that can be dequeued
 */
static inline u32
svm_fifo_max_dequeue_cons (svm_fifo_t * f)
{
  u32 tail, head;
  f_load_head_tail_cons (f, &head, &tail);
  return f_cursize (f, head, tail);
}

/**
 * Fifo max bytes to dequeue optimized for producer
 *
 * @param f	fifo
 * @return	max number of bytes that can be dequeued
 */
static inline u32
svm_fifo_max_dequeue_prod (svm_fifo_t * f)
{
  u32 tail, head;
  f_load_head_tail_prod (f, &head, &tail);
  return f_cursize (f, head, tail);
}

/**
 * Fifo max bytes to dequeue
 *
 * Note: use producer or consumer specific functions for performance:
 * @ref svm_fifo_max_dequeue_cons (svm_fifo_t *f)
 * @ref svm_fifo_max_dequeue_prod (svm_fifo_t *f)
 */
static inline u32
svm_fifo_max_dequeue (svm_fifo_t * f)
{
  u32 tail, head;
  f_load_head_tail_all_acq (f, &head, &tail);
  return f_cursize (f, head, tail);
}

/**
 * Check if fifo is full optimized for producer
 *
 * @param f	fifo
 * @return	1 if fifo is full 0 otherwise
 */
static inline int
svm_fifo_is_full_prod (svm_fifo_t * f)
{
  return (svm_fifo_max_dequeue_prod (f) == f->size);
}

/* Check if fifo is full.
 *
 * Note: use producer or consumer specific functions for performance.
 * @ref svm_fifo_is_full_prod (svm_fifo_t * f)
 * add cons version if needed
 */
static inline int
svm_fifo_is_full (svm_fifo_t * f)
{
  return (svm_fifo_max_dequeue (f) == f->size);
}

/**
 * Check if fifo is empty optimized for consumer
 *
 * @param f 	fifo
 * @return	1 if fifo is empty 0 otherwise
 */
static inline int
svm_fifo_is_empty_cons (svm_fifo_t * f)
{
  return (svm_fifo_max_dequeue_cons (f) == 0);
}

/**
 * Check if fifo is empty optimized for producer
 *
 * @param f	fifo
 * @return	1 if fifo is empty 0 otherwise
 */
static inline int
svm_fifo_is_empty_prod (svm_fifo_t * f)
{
  return (svm_fifo_max_dequeue_prod (f) == 0);
}

/**
 * Check if fifo is empty
 *
 * Note: use producer or consumer specific functions for perfomance.
 * @ref svm_fifo_is_empty_cons (svm_fifo_t * f)
 * @ref svm_fifo_is_empty_prod (svm_fifo_t * f)
 */
static inline int
svm_fifo_is_empty (svm_fifo_t * f)
{
  return (svm_fifo_max_dequeue (f) == 0);
}

/**
 * Check if fifo is wrapped
 *
 * @param f	fifo
 * @return 	1 if 'normalized' head is ahead of tail
 */
static inline u8
svm_fifo_is_wrapped (svm_fifo_t * f)
{
  u32 head, tail;
  f_load_head_tail_all_acq (f, &head, &tail);
  return head > tail;
}

/**
 * Maximum number of bytes that can be enqueued into fifo
 *
 * Optimized for producer
 *
 * @param f	fifo
 * @return	max number of bytes that can be enqueued into fifo
 */
static inline u32
svm_fifo_max_enqueue_prod (svm_fifo_t * f)
{
  u32 head, tail;
  f_load_head_tail_prod (f, &head, &tail);
  return f_free_count (f, head, tail);
}

/* Maximum number of bytes that can be enqueued into fifo
 *
 * Note: use producer or consumer specific functions for performance.
 * @ref svm_fifo_max_enqueue_prod (svm_fifo_t *f)
 * add consumer specific version if needed.
 */
static inline u32
svm_fifo_max_enqueue (svm_fifo_t * f)
{
  u32 head, tail;
  f_load_head_tail_all_acq (f, &head, &tail);
  return f_free_count (f, head, tail);
}

/**
 * Max contiguous chunk of data that can be read.
 *
 * Should only be called by consumers.
 */
u32 svm_fifo_max_read_chunk (svm_fifo_t * f);

/**
 * Max contiguous chunk of data that can be written
 *
 * Should only be called by producers
 */
u32 svm_fifo_max_write_chunk (svm_fifo_t * f);

/**
 * Fifo head chunk getter
 *
 * @param f	fifo
 * @return	head chunk pointer
 */
static inline svm_fifo_chunk_t *
svm_fifo_head_chunk (svm_fifo_t * f)
{
  return f->head_chunk;
}

/**
 * Fifo head pointer getter
 *
 * @param f	fifo
 * @return	head pointer
 */
static inline u8 *
svm_fifo_head (svm_fifo_t * f)
{
  if (!f->head_chunk)
    return 0;
  /* load-relaxed: consumer owned index */
  return (f->head_chunk->data + (f->head - f->head_chunk->start_byte));
}

/**
 * Fifo tail chunk getter
 *
 * @param f	fifo
 * @return	tail chunk pointer
 */
static inline svm_fifo_chunk_t *
svm_fifo_tail_chunk (svm_fifo_t * f)
{
  return f->tail_chunk;
}

/**
 * Fifo tail pointer getter
 *
 * @param f	fifo
 * @return	tail pointer
 */
static inline u8 *
svm_fifo_tail (svm_fifo_t * f)
{
  /* load-relaxed: producer owned index */
  return (f->tail_chunk->data + (f->tail - f->tail_chunk->start_byte));
}

/**
 * Fifo number of subscribers getter
 *
 * @param f	fifo
 * @return	number of subscribers
 */
static inline u8
svm_fifo_n_subscribers (svm_fifo_t * f)
{
  return f->n_subscribers;
}

/**
 * Check if fifo has out-of-order data
 *
 * @param f	fifo
 * @return	1 if fifo has ooo data, 0 otherwise
 */
static inline u8
svm_fifo_has_ooo_data (svm_fifo_t * f)
{
  return f->ooos_list_head != OOO_SEGMENT_INVALID_INDEX;
}

static inline ooo_segment_t *
svm_fifo_newest_ooo_segment (svm_fifo_t * f)
{
  if (f->ooos_newest == OOO_SEGMENT_INVALID_INDEX)
    return 0;
  return pool_elt_at_index (f->ooo_segments, f->ooos_newest);
}

static inline void
svm_fifo_newest_ooo_segment_reset (svm_fifo_t * f)
{
  f->ooos_newest = OOO_SEGMENT_INVALID_INDEX;
}

static inline u32
ooo_segment_offset_prod (svm_fifo_t * f, ooo_segment_t * s)
{
  u32 tail;
  /* load-relaxed: producer owned index */
  tail = f->tail;

  return (s->start - tail);
}

static inline u32
ooo_segment_length (svm_fifo_t * f, ooo_segment_t * s)
{
  return s->length;
}

static inline u32
svm_fifo_size (svm_fifo_t * f)
{
  return f->size;
}

static inline void
svm_fifo_set_size (svm_fifo_t * f, u32 size)
{
  if (size > (1 << f->fs_hdr->max_log2_chunk_size))
    return;
  fsh_virtual_mem_update (f->fs_hdr, f->slice_index, (int) f->size - size);
  f->size = size;
}

/**
 * Check if fifo has io event
 *
 * @param f	fifo
 * @return	1 if fifo has event, 0 otherwise
 */
static inline int
svm_fifo_has_event (svm_fifo_t * f)
{
  return f->has_event;
}

/**
 * Set fifo event flag.
 *
 * Forces release semantics.
 *
 * @param f	fifo
 * @return 	1 if flag was not set, 0 otherwise
 */
always_inline u8
svm_fifo_set_event (svm_fifo_t * f)
{
  return !clib_atomic_swap_rel_n (&f->has_event, 1);
}

/**
 * Unset fifo event flag.
 *
 * Forces acquire semantics
 *
 * @param f	fifo
 */
always_inline void
svm_fifo_unset_event (svm_fifo_t * f)
{
  clib_atomic_swap_acq_n (&f->has_event, 0);
}

/**
 * Set specific want notification flag
 *
 * For list of flags see @ref svm_fifo_deq_ntf_t
 *
 * @param f		fifo
 * @param ntf_type	type of notification requested
 */
static inline void
svm_fifo_add_want_deq_ntf (svm_fifo_t * f, u8 ntf_type)
{
  f->want_deq_ntf |= ntf_type;
}

/**
 * Clear specific want notification flag
 *
 * For list of flags see @ref svm_fifo_ntf_t
 *
 * @param f 		fifo
 * @param ntf_type	type of notification to be cleared
 */
static inline void
svm_fifo_del_want_deq_ntf (svm_fifo_t * f, u8 ntf_type)
{
  f->want_deq_ntf &= ~ntf_type;
}

/**
 * Clear the want notification flag and set has notification
 *
 * Should be used after enqueuing an event. This clears the
 * SVM_FIFO_WANT_NOTIF flag but it does not clear
 * SVM_FIFO_WANT_NOTIF_IF_FULL. If the latter was set, has_ntf is
 * set to avoid enqueueing events for for all dequeue operations until
 * it is manually cleared.
 *
 * @param f	fifo
 */
static inline void
svm_fifo_clear_deq_ntf (svm_fifo_t * f)
{
  /* Set the flag if want_notif_if_full was the only ntf requested */
  f->has_deq_ntf = f->want_deq_ntf == SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL;
  svm_fifo_del_want_deq_ntf (f, SVM_FIFO_WANT_DEQ_NOTIF);
}

/**
 * Clear has notification flag
 *
 * The fifo generates only one event per SVM_FIFO_WANT_NOTIF_IF_FULL
 * request and sets has_ntf. To received new events the flag must be
 * cleared using this function.
 *
 * @param f	fifo
 */
static inline void
svm_fifo_reset_has_deq_ntf (svm_fifo_t * f)
{
  f->has_deq_ntf = 0;
}

/**
 * Check if fifo needs dequeue notification
 *
 * Determines based on notification request flags and state of the fifo if
 * an event should be generated.
 *
 * @param f		fifo
 * @param n_last_deq	number of bytes last dequeued
 * @return		1 if event should be generated, 0 otherwise
 */
static inline u8
svm_fifo_needs_deq_ntf (svm_fifo_t * f, u32 n_last_deq)
{
  u8 want_ntf = f->want_deq_ntf;

  if (PREDICT_TRUE (want_ntf == SVM_FIFO_NO_DEQ_NOTIF))
    return 0;
  else if (want_ntf & SVM_FIFO_WANT_DEQ_NOTIF)
    return 1;
  if (want_ntf & SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL)
    {
      u32 max_deq = svm_fifo_max_dequeue_cons (f);
      u32 size = f->size;
      if (!f->has_deq_ntf && max_deq < size && max_deq + n_last_deq >= size)
	return 1;
    }
  if (want_ntf & SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY)
    {
      if (!f->has_deq_ntf && svm_fifo_is_empty (f))
	return 1;
    }
  return 0;
}

#endif /* __included_ssvm_fifo_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
