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
#include <vppinfra/rbtree.h>

/** Out-of-order segment */
typedef struct
{
  u32 next;	/**< Next linked-list element pool index */
  u32 prev;	/**< Previous linked-list element pool index */

  u32 start;	/**< Start of segment, normalized*/
  u32 length;	/**< Length of segment */
} ooo_segment_t;

#define SVM_FIFO_TRACE 			(0)
#define OOO_SEGMENT_INVALID_INDEX 	((u32)~0)
#define SVM_FIFO_INVALID_SESSION_INDEX 	((u32)~0)
#define SVM_FIFO_INVALID_INDEX		((u32)~0)
#define SVM_FIFO_MAX_EVT_SUBSCRIBERS	7

enum svm_fifo_tx_ntf_
{
  SVM_FIFO_NO_TX_NOTIF = 0,
  SVM_FIFO_WANT_TX_NOTIF = 1,
  SVM_FIFO_WANT_TX_NOTIF_IF_FULL = 2,
};

typedef struct
{
  u32 offset;
  u32 len;
  u32 action;
} svm_fifo_trace_elem_t;

typedef struct svm_fifo_chunk_
{
  u32 start_byte;
  u32 length;
  struct svm_fifo_chunk_ *next;
  u8 data[0];
} svm_fifo_chunk_t;

typedef enum svm_fifo_flag_
{
  SVM_FIFO_F_SIZE_UPDATE = 1 << 0,
  SVM_FIFO_F_MULTI_CHUNK = 1 << 1,
  SVM_FIFO_F_LL_TRACKED = 1 << 2,
} svm_fifo_flag_t;

typedef struct _svm_fifo
{
  CLIB_CACHE_LINE_ALIGN_MARK (shared_first);
  u32 size;			/**< size of the fifo */
  u32 nitems;			/**< usable size(size-1) */
  u8 flags;			/**< fifo flags */
  svm_fifo_chunk_t *start_chunk;/**< first chunk in fifo chunk list */
  svm_fifo_chunk_t *end_chunk;	/**< end chunk in fifo chunk list */
  svm_fifo_chunk_t *new_chunks;	/**< chunks yet to be added to list */
  rb_tree_t chunk_lookup;

    CLIB_CACHE_LINE_ALIGN_MARK (shared_second);
  volatile u32 has_event;	/**< non-zero if deq event exists */

  u32 master_session_index;
  u32 client_session_index;
  u8 master_thread_index;
  u8 client_thread_index;
  u32 segment_manager;
  u32 segment_index;
  u32 ct_session_index;		/**< Local session index for vpp */
  u32 freelist_index;		/**< aka log2(allocated_size) - const. */
  i8 refcnt;			/**< reference count  */
  struct _svm_fifo *next;	/**< next in freelist/active chain */
  struct _svm_fifo *prev;	/**< prev in active chain */

    CLIB_CACHE_LINE_ALIGN_MARK (consumer);
  u32 head;			/**< fifo head position/byte */
  svm_fifo_chunk_t *head_chunk;	/**< tracks chunk where head lands */
  svm_fifo_chunk_t *ooo_deq;	/**< last chunk used for ooo dequeue */
  volatile u32 want_tx_ntf;	/**< producer wants nudge */
  volatile u32 has_tx_ntf;

    CLIB_CACHE_LINE_ALIGN_MARK (producer);
  u32 tail;			/**< fifo tail position/byte */
  u32 ooos_list_head;		/**< Head of out-of-order linked-list */
  svm_fifo_chunk_t *tail_chunk;	/**< tracks chunk where tail lands */
  svm_fifo_chunk_t *ooo_enq;	/**< last chunk used for ooo enqueue */
  ooo_segment_t *ooo_segments;	/**< Pool of ooo segments */
  u32 ooos_newest;		/**< Last segment to have been updated */
  volatile u8 n_subscribers;
  u8 subscribers[SVM_FIFO_MAX_EVT_SUBSCRIBERS];

#if SVM_FIFO_TRACE
  svm_fifo_trace_elem_t *trace;
#endif

  svm_fifo_chunk_t default_chunk;
} svm_fifo_t;

typedef enum
{
  SVM_FIFO_FULL = -2,
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

/* internal function */
static inline void
f_load_head_tail_cons (svm_fifo_t * f, u32 * head, u32 * tail)
{
  /* load-relaxed: consumer owned index */
  *head = f->head;
  /* load-acq: consumer foreign index (paired with store-rel in producer) */
  *tail = clib_atomic_load_acq_n (&f->tail);
}

/* internal function */
static inline void
f_load_head_tail_prod (svm_fifo_t * f, u32 * head, u32 * tail)
{
  /* load relaxed: producer owned index */
  *tail = f->tail;
  /* load-acq: producer foreign index (paired with store-rel in consumer) */
  *head = clib_atomic_load_acq_n (&f->head);
}

/* producer consumer role independent */
/* internal function */
static inline void
f_load_head_tail_all_acq (svm_fifo_t * f, u32 * head, u32 * tail)
{
  /* load-acq : consumer foreign index (paired with store-rel) */
  *tail = clib_atomic_load_acq_n (&f->tail);
  /* load-acq : producer foriegn index (paired with store-rel) */
  *head = clib_atomic_load_acq_n (&f->head);
}

/* internal function */
static inline u32
f_free_count (svm_fifo_t * f, u32 head, u32 tail)
{
  return (f->nitems + head - tail);
}

/* internal function */
static inline u32
f_cursize (svm_fifo_t * f, u32 head, u32 tail)
{
  return (f->nitems - f_free_count (f, head, tail));
}

/* used by consumer */
static inline u32
svm_fifo_max_dequeue_cons (svm_fifo_t * f)
{
  u32 tail, head;
  f_load_head_tail_cons (f, &head, &tail);
  return f_cursize (f, head, tail);
}

/* used by producer*/
static inline u32
svm_fifo_max_dequeue_prod (svm_fifo_t * f)
{
  u32 tail, head;
  f_load_head_tail_prod (f, &head, &tail);
  return f_cursize (f, head, tail);
}

/* use producer or consumer specific functions for perfomance.
 * svm_fifo_max_dequeue_cons (svm_fifo_t *f)
 * svm_fifo_max_dequeue_prod (svm_fifo_t *f)
 */
static inline u32
svm_fifo_max_dequeue (svm_fifo_t * f)
{
  u32 tail, head;
  f_load_head_tail_all_acq (f, &head, &tail);
  return f_cursize (f, head, tail);
}

/* used by producer */
static inline int
svm_fifo_is_full_prod (svm_fifo_t * f)
{
  return (svm_fifo_max_dequeue_prod (f) == f->nitems);
}

/* use producer or consumer specific functions for perfomance.
 * svm_fifo_is_full_prod (svm_fifo_t * f)
 * add cons version if needed
 */
static inline int
svm_fifo_is_full (svm_fifo_t * f)
{
  return (svm_fifo_max_dequeue (f) == f->nitems);
}

/* used by consumer */
static inline int
svm_fifo_is_empty_cons (svm_fifo_t * f)
{
  return (svm_fifo_max_dequeue_cons (f) == 0);
}

/* used by producer */
static inline int
svm_fifo_is_empty_prod (svm_fifo_t * f)
{
  return (svm_fifo_max_dequeue_prod (f) == 0);
}

/* use producer or consumer specific functions for perfomance.
 * svm_fifo_is_empty_cons (svm_fifo_t * f)
 * svm_fifo_is_empty_prod (svm_fifo_t * f)
 */
static inline int
svm_fifo_is_empty (svm_fifo_t * f)
{
  return (svm_fifo_max_dequeue (f) == 0);
}

static inline u8
svm_fifo_is_wrapped (svm_fifo_t * f)
{
  u32 head, tail;
  f_load_head_tail_all_acq (f, &head, &tail);
  return head % f->size > tail % f->size;
}

/* used by producer*/
static inline u32
svm_fifo_max_enqueue_prod (svm_fifo_t * f)
{
  u32 head, tail;
  f_load_head_tail_prod (f, &head, &tail);
  return f_free_count (f, head, tail);
}

/* use producer or consumer specfic functions for perfomance.
 * svm_fifo_max_enqueue_prod (svm_fifo_t *f)
 * add consumer specific version if needed.
 */
static inline u32
svm_fifo_max_enqueue (svm_fifo_t * f)
{
  u32 head, tail;
  f_load_head_tail_all_acq (f, &head, &tail);
  return f_free_count (f, head, tail);
}

static inline int
svm_fifo_has_event (svm_fifo_t * f)
{
  return f->has_event;
}

static inline u8
svm_fifo_has_ooo_data (svm_fifo_t * f)
{
  return f->ooos_list_head != OOO_SEGMENT_INVALID_INDEX;
}

/**
 * Sets fifo event flag.
 *
 * Also acts as a release ordering.
 *
 * @return 1 if flag was not set.
 */
always_inline u8
svm_fifo_set_event (svm_fifo_t * f)
{
  /* return __sync_lock_test_and_set (&f->has_event, 1) == 0;
     return __sync_bool_compare_and_swap (&f->has_event, 0, 1); */
  return !clib_atomic_swap_rel_n (&f->has_event, 1);
}

/**
 * Unsets fifo event flag.
 *
 * Also acts as an acquire barrier.
 */
always_inline void
svm_fifo_unset_event (svm_fifo_t * f)
{
  clib_atomic_swap_acq_n (&f->has_event, 0);
}

svm_fifo_t *svm_fifo_create (u32 data_size_in_bytes);
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
 * Grow fifo size by adding chunk to chunk list
 *
 * If fifos are allocated on a segment, this should be called with
 * the segment's heap pushed.
 *
 * @param f	fifo to be extended
 * @param c 	chunk or linked list of chunks to be added
 */
void svm_fifo_add_chunk (svm_fifo_t * f, svm_fifo_chunk_t * c);
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

int svm_fifo_enqueue_nowait (svm_fifo_t * f, u32 max_bytes,
			     const u8 * copy_from_here);
int svm_fifo_enqueue_with_offset (svm_fifo_t * f, u32 offset,
				  u32 required_bytes, u8 * copy_from_here);
int svm_fifo_dequeue_nowait (svm_fifo_t * f, u32 max_bytes, u8 * copy_here);

int svm_fifo_peek (svm_fifo_t * f, u32 offset, u32 max_bytes, u8 * copy_here);
int svm_fifo_dequeue_drop (svm_fifo_t * f, u32 max_bytes);
void svm_fifo_dequeue_drop_all (svm_fifo_t * f);
int svm_fifo_segments (svm_fifo_t * f, svm_fifo_seg_t * fs);
void svm_fifo_segments_free (svm_fifo_t * f, svm_fifo_seg_t * fs);
void svm_fifo_init_pointers (svm_fifo_t * f, u32 head, u32 tail);
void svm_fifo_clone (svm_fifo_t * df, svm_fifo_t * sf);
void svm_fifo_overwrite_head (svm_fifo_t * f, u8 * data, u32 len);
void svm_fifo_add_subscriber (svm_fifo_t * f, u8 subscriber);
void svm_fifo_del_subscriber (svm_fifo_t * f, u8 subscriber);
format_function_t format_svm_fifo;

/**
 * Max contiguous chunk of data that can be read
 */
always_inline u32
svm_fifo_max_read_chunk (svm_fifo_t * f)
{
  u32 head, tail;
  u32 head_idx, tail_idx;
  f_load_head_tail_cons (f, &head, &tail);
  head_idx = head % f->size;
  tail_idx = tail % f->size;
  return tail_idx > head_idx ? (tail_idx - head_idx) : (f->size - head_idx);
}

/**
 * Max contiguous chunk of data that can be written
 */
always_inline u32
svm_fifo_max_write_chunk (svm_fifo_t * f)
{
  u32 head, tail;
  u32 head_idx, tail_idx;
  f_load_head_tail_prod (f, &head, &tail);
  head_idx = head % f->size;
  tail_idx = tail % f->size;
  return tail_idx >= head_idx ? (f->size - tail_idx) : (head_idx - tail_idx);
}

/**
 * Advance tail pointer
 *
 * Useful for moving tail pointer after external enqueue.
 */
always_inline void
svm_fifo_enqueue_nocopy (svm_fifo_t * f, u32 bytes)
{
  ASSERT (bytes <= svm_fifo_max_enqueue_prod (f));
  /* load-relaxed: producer owned index */
  u32 tail = f->tail;
  tail += bytes;
  /* store-rel: producer owned index (paired with load-acq in consumer) */
  clib_atomic_store_rel_n (&f->tail, tail);
}

always_inline u8 *
svm_fifo_head (svm_fifo_t * f)
{
  /* load-relaxed: consumer owned index */
  return (f->head_chunk->data
	  + ((f->head % f->size) - f->head_chunk->start_byte));
}

always_inline u8 *
svm_fifo_tail (svm_fifo_t * f)
{
  /* load-relaxed: producer owned index */
  return (f->tail_chunk->data
	  + ((f->tail % f->size) - f->tail_chunk->start_byte));
}

static inline void
svm_fifo_add_want_tx_ntf (svm_fifo_t * f, u8 ntf_type)
{
  f->want_tx_ntf |= ntf_type;
}

static inline void
svm_fifo_del_want_tx_ntf (svm_fifo_t * f, u8 ntf_type)
{
  f->want_tx_ntf &= ~ntf_type;
}

static inline void
svm_fifo_clear_tx_ntf (svm_fifo_t * f)
{
  /* Set the flag if want_tx_notif_if_full was the only ntf requested */
  f->has_tx_ntf = f->want_tx_ntf == SVM_FIFO_WANT_TX_NOTIF_IF_FULL;
  svm_fifo_del_want_tx_ntf (f, SVM_FIFO_WANT_TX_NOTIF);
}

static inline void
svm_fifo_reset_tx_ntf (svm_fifo_t * f)
{
  f->has_tx_ntf = 0;
}

static inline u8
svm_fifo_needs_tx_ntf (svm_fifo_t * f, u32 n_last_deq)
{
  u8 want_ntf = f->want_tx_ntf;

  if (PREDICT_TRUE (want_ntf == SVM_FIFO_NO_TX_NOTIF))
    return 0;
  else if (want_ntf & SVM_FIFO_WANT_TX_NOTIF)
    return 1;
  else if (want_ntf & SVM_FIFO_WANT_TX_NOTIF_IF_FULL)
    {
      u32 max_deq = svm_fifo_max_dequeue_cons (f);
      u32 nitems = f->nitems;
      if (!f->has_tx_ntf && max_deq < nitems
	  && max_deq + n_last_deq >= nitems)
	return 1;

      return 0;
    }
  return 0;
}

always_inline u8
svm_fifo_n_subscribers (svm_fifo_t * f)
{
  return f->n_subscribers;
}

u32 svm_fifo_number_ooo_segments (svm_fifo_t * f);
ooo_segment_t *svm_fifo_first_ooo_segment (svm_fifo_t * f);

always_inline ooo_segment_t *
svm_fifo_newest_ooo_segment (svm_fifo_t * f)
{
  if (f->ooos_newest == OOO_SEGMENT_INVALID_INDEX)
    return 0;
  return pool_elt_at_index (f->ooo_segments, f->ooos_newest);
}

always_inline void
svm_fifo_newest_ooo_segment_reset (svm_fifo_t * f)
{
  f->ooos_newest = OOO_SEGMENT_INVALID_INDEX;
}

always_inline u32
ooo_segment_distance_from_tail (svm_fifo_t * f, u32 pos, u32 tail)
{
  return ((f->size + pos - tail) % f->size);
}

always_inline u32
ooo_segment_distance_to_tail (svm_fifo_t * f, u32 pos, u32 tail)
{
  return ((f->size + tail - pos) % f->size);
}

always_inline u32
ooo_segment_offset_prod (svm_fifo_t * f, ooo_segment_t * s)
{
  u32 tail;
  /* load-relaxed: producer owned index */
  tail = f->tail;

  return ooo_segment_distance_from_tail (f, s->start, tail);
}

always_inline u32
ooo_segment_length (svm_fifo_t * f, ooo_segment_t * s)
{
  return s->length;
}

always_inline ooo_segment_t *
ooo_segment_get_prev (svm_fifo_t * f, ooo_segment_t * s)
{
  if (s->prev == OOO_SEGMENT_INVALID_INDEX)
    return 0;
  return pool_elt_at_index (f->ooo_segments, s->prev);
}

always_inline ooo_segment_t *
ooo_segment_next (svm_fifo_t * f, ooo_segment_t * s)
{
  if (s->next == OOO_SEGMENT_INVALID_INDEX)
    return 0;
  return pool_elt_at_index (f->ooo_segments, s->next);
}

#endif /* __included_ssvm_fifo_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
