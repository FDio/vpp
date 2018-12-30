/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * buffer.h: VLIB buffers
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_vlib_buffer_h
#define included_vlib_buffer_h

#include <vppinfra/types.h>
#include <vppinfra/cache.h>
#include <vppinfra/serialize.h>
#include <vppinfra/vector.h>
#include <vppinfra/lock.h>
#include <vlib/error.h>		/* for vlib_error_t */

#include <vlib/config.h>	/* for __PRE_DATA_SIZE */
#define VLIB_BUFFER_DATA_SIZE		(2048)
#define VLIB_BUFFER_PRE_DATA_SIZE	__PRE_DATA_SIZE

/* Minimum buffer chain segment size. Does not apply to last buffer in chain.
   Dataplane code can safely asume that specified amount of data is not split
   into 2 chained buffers */
#define VLIB_BUFFER_MIN_CHAIN_SEG_SIZE	(128)

/* Amount of head buffer data copied to each replica head buffer */
#define VLIB_BUFFER_CLONE_HEAD_SIZE (256)

typedef u8 vlib_buffer_free_list_index_t;

/** \file
    vlib buffer structure definition and a few select
    access methods. This structure and the buffer allocation
    mechanism should perhaps live in vnet, but it would take a lot
    of typing to make it so.
*/

/**
 * Buffer Flags
 */
#define foreach_vlib_buffer_flag \
  _( 0, NON_DEFAULT_FREELIST, "non-default-fl")		\
  _( 1, IS_TRACED, 0)					\
  _( 2, NEXT_PRESENT, 0)				\
  _( 3, TOTAL_LENGTH_VALID, 0)				\
  _( 4, EXT_HDR_VALID, "ext-hdr-valid")

/* NOTE: only buffer generic flags should be defined here, please consider
   using user flags. i.e. src/vnet/buffer.h */

enum
{
#define _(bit, name, v) VLIB_BUFFER_##name  = (1 << (bit)),
  foreach_vlib_buffer_flag
#undef _
};

enum
{
#define _(bit, name, v) VLIB_BUFFER_LOG2_##name  = (bit),
  foreach_vlib_buffer_flag
#undef _
};

  /* User defined buffer flags. */
#define LOG2_VLIB_BUFFER_FLAG_USER(n) (32 - (n))
#define VLIB_BUFFER_FLAG_USER(n) (1 << LOG2_VLIB_BUFFER_FLAG_USER(n))
#define VLIB_BUFFER_FLAGS_ALL (0x1f)

/* VLIB buffer representation. */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  STRUCT_MARK (template_start);
  /* Offset within data[] that we are currently processing.
     If negative current header points into predata area. */
  i16 current_data;  /**< signed offset in data[], pre_data[]
                        that we are currently processing.
                        If negative current header points into predata area.
                     */
  u16 current_length;  /**< Nbytes between current data and
                          the end of this buffer.
                       */
  u32 flags; /**< buffer flags:
                <br> VLIB_BUFFER_FREE_LIST_INDEX_MASK: bits used to store free list index,
                <br> VLIB_BUFFER_IS_TRACED: trace this buffer.
                <br> VLIB_BUFFER_NEXT_PRESENT: this is a multi-chunk buffer.
                <br> VLIB_BUFFER_TOTAL_LENGTH_VALID: as it says
                <br> VLIB_BUFFER_EXT_HDR_VALID: buffer contains valid external buffer manager header,
                set to avoid adding it to a flow report
                <br> VLIB_BUFFER_FLAG_USER(n): user-defined bit N
             */

  u32 flow_id;	/**< Generic flow identifier */


  u32 next_buffer;   /**< Next buffer for this linked-list of buffers.
                        Only valid if VLIB_BUFFER_NEXT_PRESENT flag is set.
                     */

    STRUCT_MARK (template_end);

  u32 current_config_index; /**< Used by feature subgraph arcs to
                               visit enabled feature nodes
                            */
  vlib_error_t error;	/**< Error code for buffers to be enqueued
                           to error handler.
                        */
  u8 n_add_refs; /**< Number of additional references to this buffer. */

  u8 buffer_pool_index;	/**< index of buffer pool this buffer belongs. */

  u32 opaque[10]; /**< Opaque data used by sub-graphs for their own purposes.
                    See .../vnet/vnet/buffer.h
                 */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  u32 trace_index; /**< Specifies index into trace buffer
                      if VLIB_PACKET_IS_TRACED flag is set.
                   */
  u32 recycle_count; /**< Used by L2 path recycle code */

  u32 total_length_not_including_first_buffer;
  /**< Only valid for first buffer in chain. Current length plus
     total length given here give total number of bytes in buffer chain.
  */
  vlib_buffer_free_list_index_t free_list_index; /** < only used if
						   VLIB_BUFFER_NON_DEFAULT_FREELIST
						   flag is set */
  u8 align_pad[3]; /**< available */
  u32 opaque2[12];  /**< More opaque data, see ../vnet/vnet/buffer.h */

  /***** end of second cache line */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  u8 pre_data[VLIB_BUFFER_PRE_DATA_SIZE];  /**< Space for inserting data
                                               before buffer start.
                                               Packet rewrite string will be
                                               rewritten backwards and may extend
                                               back before buffer->data[0].
                                               Must come directly before packet data.
                                            */

  u8 data[0]; /**< Packet data. Hardware DMA here */
} vlib_buffer_t;		/* Must be a multiple of 64B. */

#define VLIB_BUFFER_HDR_SIZE  (sizeof(vlib_buffer_t) - VLIB_BUFFER_PRE_DATA_SIZE)

/** \brief Prefetch buffer metadata.
    The first 64 bytes of buffer contains most header information

    @param b - (vlib_buffer_t *) pointer to the buffer
    @param type - LOAD, STORE. In most cases, STORE is the right answer
*/

#define vlib_prefetch_buffer_header(b,type) CLIB_PREFETCH (b, 64, type)
#define vlib_prefetch_buffer_data(b,type) \
  CLIB_PREFETCH (vlib_buffer_get_current(b), CLIB_CACHE_LINE_BYTES, type)

always_inline void
vlib_buffer_struct_is_sane (vlib_buffer_t * b)
{
  ASSERT (sizeof (b[0]) % 64 == 0);

  /* Rewrite data must be before and contiguous with packet data. */
  ASSERT (b->pre_data + VLIB_BUFFER_PRE_DATA_SIZE == b->data);
}

always_inline uword
vlib_buffer_get_va (vlib_buffer_t * b)
{
  return pointer_to_uword (b->data);
}

/** \brief Get pointer to current data to process

    @param b - (vlib_buffer_t *) pointer to the buffer
    @return - (void *) (b->data + b->current_data)
*/

always_inline void *
vlib_buffer_get_current (vlib_buffer_t * b)
{
  /* Check bounds. */
  ASSERT ((signed) b->current_data >= (signed) -VLIB_BUFFER_PRE_DATA_SIZE);
  return b->data + b->current_data;
}

always_inline uword
vlib_buffer_get_current_va (vlib_buffer_t * b)
{
  return vlib_buffer_get_va (b) + b->current_data;
}

/** \brief Advance current data pointer by the supplied (signed!) amount

    @param b - (vlib_buffer_t *) pointer to the buffer
    @param l - (word) signed increment
*/
always_inline void
vlib_buffer_advance (vlib_buffer_t * b, word l)
{
  ASSERT (b->current_length >= l);
  b->current_data += l;
  b->current_length -= l;

  ASSERT ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0 ||
	  b->current_length >= VLIB_BUFFER_MIN_CHAIN_SEG_SIZE);
}

/** \brief Check if there is enough space in buffer to advance

    @param b - (vlib_buffer_t *) pointer to the buffer
    @param l - (word) size to check
    @return - 0 if there is less space than 'l' in buffer
*/
always_inline u8
vlib_buffer_has_space (vlib_buffer_t * b, word l)
{
  return b->current_length >= l;
}

/** \brief Reset current header & length to state they were in when
    packet was received.

    @param b - (vlib_buffer_t *) pointer to the buffer
*/

always_inline void
vlib_buffer_reset (vlib_buffer_t * b)
{
  b->current_length += clib_max (b->current_data, 0);
  b->current_data = 0;
}

/** \brief Get pointer to buffer's opaque data array

    @param b - (vlib_buffer_t *) pointer to the buffer
    @return - (void *) b->opaque
*/
always_inline void *
vlib_get_buffer_opaque (vlib_buffer_t * b)
{
  return (void *) b->opaque;
}

/** \brief Get pointer to buffer's opaque2 data array

    @param b - (vlib_buffer_t *) pointer to the buffer
    @return - (void *) b->opaque2
*/
always_inline void *
vlib_get_buffer_opaque2 (vlib_buffer_t * b)
{
  return (void *) b->opaque2;
}

/** \brief Get pointer to the end of buffer's data
 * @param b     pointer to the buffer
 * @return      pointer to tail of packet's data
 */
always_inline u8 *
vlib_buffer_get_tail (vlib_buffer_t * b)
{
  return b->data + b->current_data + b->current_length;
}

/** \brief Append uninitialized data to buffer
 * @param b     pointer to the buffer
 * @param size  number of uninitialized bytes
 * @return      pointer to beginning of uninitialized data
 */
always_inline void *
vlib_buffer_put_uninit (vlib_buffer_t * b, u16 size)
{
  void *p = vlib_buffer_get_tail (b);
  /* XXX make sure there's enough space */
  b->current_length += size;
  return p;
}

/** \brief Prepend uninitialized data to buffer
 * @param b     pointer to the buffer
 * @param size  number of uninitialized bytes
 * @return      pointer to beginning of uninitialized data
 */
always_inline void *
vlib_buffer_push_uninit (vlib_buffer_t * b, u8 size)
{
  ASSERT (b->current_data + VLIB_BUFFER_PRE_DATA_SIZE >= size);
  b->current_data -= size;
  b->current_length += size;

  return vlib_buffer_get_current (b);
}

/** \brief Make head room, typically for packet headers
 * @param b     pointer to the buffer
 * @param size  number of head room bytes
 * @return      pointer to start of buffer (current data)
 */
always_inline void *
vlib_buffer_make_headroom (vlib_buffer_t * b, u8 size)
{
  ASSERT (b->current_data + VLIB_BUFFER_PRE_DATA_SIZE >= size);
  b->current_data += size;
  return vlib_buffer_get_current (b);
}

/** \brief Retrieve bytes from buffer head
 * @param b     pointer to the buffer
 * @param size  number of bytes to pull
 * @return      pointer to start of buffer (current data)
 */
always_inline void *
vlib_buffer_pull (vlib_buffer_t * b, u8 size)
{
  if (b->current_length + VLIB_BUFFER_PRE_DATA_SIZE < size)
    return 0;

  void *data = vlib_buffer_get_current (b);
  vlib_buffer_advance (b, size);
  return data;
}

/* Forward declaration. */
struct vlib_main_t;

typedef struct vlib_buffer_free_list_t
{
  /* Template buffer used to initialize first 16 bytes of buffers
     allocated on this free list. */
  vlib_buffer_t buffer_init_template;

  /* Our index into vlib_main_t's buffer_free_list_pool. */
  vlib_buffer_free_list_index_t index;

  /* Number of data bytes for buffers in this free list. */
  u32 n_data_bytes;

  /* Number of buffers to allocate when we need to allocate new buffers */
  u32 min_n_buffers_each_alloc;

  /* Total number of buffers allocated from this free list. */
  u32 n_alloc;

  /* Vector of free buffers.  Each element is a byte offset into I/O heap. */
  u32 *buffers;

  /* index of buffer pool used to get / put buffers */
  u8 buffer_pool_index;

  /* Free list name. */
  u8 *name;

  /* Callback functions to initialize newly allocated buffers.
     If null buffers are zeroed. */
  void (*buffer_init_function) (struct vlib_main_t * vm,
				struct vlib_buffer_free_list_t * fl,
				u32 * buffers, u32 n_buffers);

  uword buffer_init_function_opaque;
} __attribute__ ((aligned (16))) vlib_buffer_free_list_t;

typedef uword (vlib_buffer_fill_free_list_cb_t) (struct vlib_main_t * vm,
						 vlib_buffer_free_list_t * fl,
						 uword min_free_buffers);
typedef void (vlib_buffer_free_cb_t) (struct vlib_main_t * vm, u32 * buffers,
				      u32 n_buffers);
typedef void (vlib_buffer_free_no_next_cb_t) (struct vlib_main_t * vm,
					      u32 * buffers, u32 n_buffers);

typedef struct
{
  vlib_buffer_fill_free_list_cb_t *vlib_buffer_fill_free_list_cb;
  vlib_buffer_free_cb_t *vlib_buffer_free_cb;
  vlib_buffer_free_no_next_cb_t *vlib_buffer_free_no_next_cb;
  void (*vlib_buffer_delete_free_list_cb) (struct vlib_main_t * vm,
					   vlib_buffer_free_list_index_t
					   free_list_index);
} vlib_buffer_callbacks_t;

extern vlib_buffer_callbacks_t *vlib_buffer_callbacks;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  uword start;
  uword size;
  uword log2_page_size;
  u32 physmem_map_index;
  u32 buffer_size;
  u32 *buffers;
  clib_spinlock_t lock;
} vlib_buffer_pool_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /* Virtual memory address and size of buffer memory, used for calculating
     buffer index */
  uword buffer_mem_start;
  uword buffer_mem_size;
  vlib_buffer_pool_t *buffer_pools;

  /* Buffer free callback, for subversive activities */
    u32 (*buffer_free_callback) (struct vlib_main_t * vm,
				 u32 * buffers,
				 u32 n_buffers, u32 follow_buffer_next);
#define VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX (0)
#define VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES VLIB_BUFFER_DATA_SIZE

  /* Hash table mapping buffer size (rounded to next unit of
     sizeof (vlib_buffer_t)) to free list index. */
  uword *free_list_by_size;

  /* Hash table mapping buffer index into number
     0 => allocated but free, 1 => allocated and not-free.
     If buffer index is not in hash table then this buffer
     has never been allocated. */
  uword *buffer_known_hash;
  clib_spinlock_t buffer_known_hash_lockp;

  /* Callbacks */
  vlib_buffer_callbacks_t cb;
  int callbacks_registered;
} vlib_buffer_main_t;

extern vlib_buffer_main_t buffer_main;

static_always_inline vlib_buffer_pool_t *
vlib_buffer_pool_get (u8 buffer_pool_index)
{
  vlib_buffer_main_t *bm = &buffer_main;
  return vec_elt_at_index (bm->buffer_pools, buffer_pool_index);
}

u8 vlib_buffer_register_physmem_map (struct vlib_main_t * vm,
				     u32 physmem_map_index);

clib_error_t *vlib_buffer_main_init (struct vlib_main_t *vm);


void *vlib_set_buffer_free_callback (struct vlib_main_t *vm, void *fp);

/*
 */

/** \brief Compile time buffer trajectory tracing option
    Turn this on if you run into "bad monkey" contexts,
    and you want to know exactly which nodes they've visited...
    See vlib/main.c...
*/
#define VLIB_BUFFER_TRACE_TRAJECTORY 0

#if VLIB_BUFFER_TRACE_TRAJECTORY > 0
extern void (*vlib_buffer_trace_trajectory_cb) (vlib_buffer_t * b, u32 index);
extern void (*vlib_buffer_trace_trajectory_init_cb) (vlib_buffer_t * b);
extern void vlib_buffer_trace_trajectory_init (vlib_buffer_t * b);
#define VLIB_BUFFER_TRACE_TRAJECTORY_INIT(b) \
  vlib_buffer_trace_trajectory_init (b);
#else
#define VLIB_BUFFER_TRACE_TRAJECTORY_INIT(b)
#endif /* VLIB_BUFFER_TRACE_TRAJECTORY */

#endif /* included_vlib_buffer_h */

#define VLIB_BUFFER_REGISTER_CALLBACKS(x,...)                           \
    __VA_ARGS__ vlib_buffer_callbacks_t __##x##_buffer_callbacks;       \
static void __vlib_add_buffer_callbacks_t_##x (void)                    \
    __attribute__((__constructor__)) ;                                  \
static void __vlib_add_buffer_callbacks_t_##x (void)                    \
{                                                                       \
    if (vlib_buffer_callbacks)                                          \
      clib_panic ("vlib buffer callbacks already registered");          \
    vlib_buffer_callbacks = &__##x##_buffer_callbacks;                  \
}                                                                       \
static void __vlib_rm_buffer_callbacks_t_##x (void)                     \
    __attribute__((__destructor__)) ;                                   \
static void __vlib_rm_buffer_callbacks_t_##x (void)                     \
{ vlib_buffer_callbacks = 0; }                                          \
__VA_ARGS__ vlib_buffer_callbacks_t __##x##_buffer_callbacks

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
