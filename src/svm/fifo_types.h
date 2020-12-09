/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef SRC_SVM_FIFO_TYPES_H_
#define SRC_SVM_FIFO_TYPES_H_

#include <svm/ssvm.h>
#include <vppinfra/clib.h>
#include <vppinfra/rbtree.h>
#include <vppinfra/lock.h>

#define FS_MIN_LOG2_CHUNK_SZ	12	/**< also min fifo size */
#define FS_MAX_LOG2_CHUNK_SZ	20	/**< 1MB max chunk size */
#define FS_CHUNK_VEC_LEN	8	/**< difference max log2_chunk_sz
					      and min log2_chunk_sz */
#define FS_MAX_CHUNK_IDX 	7 	/**< max vec len - 1 */

STATIC_ASSERT ((FS_MAX_LOG2_CHUNK_SZ - FS_MIN_LOG2_CHUNK_SZ)
               == FS_CHUNK_VEC_LEN, "update chunk sizes");

#define SVM_FIFO_TRACE 			(0)
#define SVM_FIFO_MAX_EVT_SUBSCRIBERS	7

typedef struct fifo_segment_header_ fifo_segment_header_t;

typedef struct svm_fifo_chunk_
{
  u32 start_byte;		/**< chunk start byte */
  u32 length;			/**< length of chunk in bytes */
  struct svm_fifo_chunk_ *next;	/**< pointer to next chunk in linked-lists */
  rb_node_index_t enq_rb_index;	/**< enq node index if chunk in rbtree */
  rb_node_index_t deq_rb_index;	/**< deq node index if chunk in rbtree */
  u8 data[0];			/**< start of chunk data */
} svm_fifo_chunk_t;

typedef struct
{
  u32 next;	/**< Next linked-list element pool index */
  u32 prev;	/**< Previous linked-list element pool index */
  u32 start;	/**< Start of segment, normalized*/
  u32 length;	/**< Length of segment */
} ooo_segment_t;

typedef struct
{
  u32 offset;
  u32 len;
  u32 action;
} svm_fifo_trace_elem_t;

typedef struct svm_fifo_shr_
{
  CLIB_CACHE_LINE_ALIGN_MARK (shared);
svm_fifo_chunk_t *start_chunk;/**< first chunk in fifo chunk list */
svm_fifo_chunk_t *end_chunk;	/**< end chunk in fifo chunk list */
volatile u32 has_event;	/**< non-zero if deq event exists */
u32 min_alloc;		/**< min chunk alloc if space available */
u32 size;			/**< size of the fifo in bytes */
u32 master_session_index;	/**< session layer session index */
u32 client_session_index;	/**< app session index */
u8 slice_index;			/**< segment slice for fifo */
struct svm_fifo_shr_ *next;	/**< next in freelist/active chain */

  CLIB_CACHE_LINE_ALIGN_MARK (consumer);
svm_fifo_chunk_t *head_chunk;	/**< tracks chunk where head lands */
u32 head;			/**< fifo head position/byte */
volatile u32 want_deq_ntf;	/**< producer wants nudge */
volatile u32 has_deq_ntf;

  CLIB_CACHE_LINE_ALIGN_MARK (producer);
u32 tail;			/**< fifo tail position/byte */
svm_fifo_chunk_t *tail_chunk;	/**< tracks chunk where tail lands */
volatile u8 n_subscribers;	/**< Number of subscribers for io events */
u8 subscribers[SVM_FIFO_MAX_EVT_SUBSCRIBERS];
} svm_fifo_shared_t;

typedef struct _svm_fifo
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline);
  svm_fifo_shared_t *f_shr;
  fifo_segment_header_t *fs_hdr;/**< fifo segment header for fifo */
  rb_tree_t ooo_enq_lookup;	/**< rbtree for ooo enq chunk lookup */
  rb_tree_t ooo_deq_lookup;	/**< rbtree for ooo deq chunk lookup */
  svm_fifo_chunk_t *ooo_deq;	/**< last chunk used for ooo dequeue */
  svm_fifo_chunk_t *ooo_enq;	/**< last chunk used for ooo enqueue */
  ooo_segment_t *ooo_segments;	/**< Pool of ooo segments */
  u32 ooos_list_head;		/**< Head of out-of-order linked-list */
  u32 ooos_newest;		/**< Last segment to have been updated */

  u8 flags;			/**< fifo flags */
  u8 master_thread_index;	/**< session layer thread index */
  u8 client_thread_index;	/**< app worker index */
  i8 refcnt;			/**< reference count  */
  u32 segment_manager;		/**< session layer segment manager index */
  u32 segment_index;		/**< segment index in segment manager */

  struct _svm_fifo *next;	/**< prev in active chain */
  struct _svm_fifo *prev;	/**< prev in active chain */

  u32 pool_index;

#if SVM_FIFO_TRACE
  svm_fifo_trace_elem_t *trace;
#endif
} svm_fifo_t;

typedef struct fifo_segment_slice_
{
  svm_fifo_chunk_t *free_chunks[FS_CHUNK_VEC_LEN];/**< Free chunks by size */
  svm_fifo_t *fifos;			/**< Linked list of active RX fifos */
  svm_fifo_shared_t *free_fifos;	/**< Freelists of fifo shared hdrs  */
  uword n_fl_chunk_bytes;		/**< Chunk bytes on freelist */
  uword virtual_mem;			/**< Slice sum of all fifo sizes */
  u32 num_chunks[FS_CHUNK_VEC_LEN];	/**< Allocated chunks by chunk size */

  CLIB_CACHE_LINE_ALIGN_MARK (lock);
  u32 chunk_lock;
} fifo_segment_slice_t;

typedef struct fifo_slice_private_
{
  svm_fifo_t **fifos;			/**< fixed pool of fifo hdrs */
  uword virtual_mem;			/**< Slice sum of all fifo sizes */
} fifo_slice_private_t;

struct fifo_segment_header_
{
//  ssvm_shared_header_t *ssvm_sh;	/**< Pointer to fs ssvm shared hdr */
//  uword n_free_bytes;			/**< Segment free bytes */
  uword n_cached_bytes;			/**< Cached bytes */
  u32 n_active_fifos;			/**< Number of active fifos */
  u32 n_reserved_bytes;			/**< Bytes not to be allocated */
  u32 max_log2_fifo_size;		/**< Max log2(chunk size) for fs */
  u8 flags;				/**< Segment flags */
  u8 n_slices;				/**< Number of slices */
  u8 high_watermark;			/**< Memory pressure watermark high */
  u8 low_watermark;			/**< Memory pressure watermark low */
  u8 pct_first_alloc;			/**< Pct of fifo size to alloc */
  CLIB_CACHE_LINE_ALIGN_MARK (allocator);
  uword byte_index;
  uword max_byte_index;
  CLIB_CACHE_LINE_ALIGN_MARK (slice);
  fifo_segment_slice_t slices[0];	/** Fixed array of slices */
};

void fsh_virtual_mem_update (fifo_segment_header_t * fsh, u32 slice_index,
			     int n_bytes);

#endif /* SRC_SVM_FIFO_TYPES_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
