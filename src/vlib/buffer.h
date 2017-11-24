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

/** \file
    vlib buffer structure definition and a few select
    access methods. This structure and the buffer allocation
    mechanism should perhaps live in vnet, but it would take a lot
    of typing to make it so.
*/

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
                <br> VLIB_BUFFER_REPL_FAIL: packet replication failure
                <br> VLIB_BUFFER_RECYCLE: as it says
                <br> VLIB_BUFFER_FLOW_REPORT: buffer is a flow report,
                <br> VLIB_BUFFER_EXT_HDR_VALID: buffer contains valid external buffer manager header,
                set to avoid adding it to a flow report
                <br> VLIB_BUFFER_FLAG_USER(n): user-defined bit N
             */

/* any change to the following line requres update of
 * vlib_buffer_get_free_list_index(...) and
 * vlib_buffer_set_free_list_index(...) functions */
#define VLIB_BUFFER_FREE_LIST_INDEX_MASK ((1 << 5) - 1)

#define VLIB_BUFFER_IS_TRACED (1 << 5)
#define VLIB_BUFFER_LOG2_NEXT_PRESENT (6)
#define VLIB_BUFFER_NEXT_PRESENT (1 << VLIB_BUFFER_LOG2_NEXT_PRESENT)
#define VLIB_BUFFER_IS_RECYCLED (1 << 7)
#define VLIB_BUFFER_TOTAL_LENGTH_VALID (1 << 8)
#define VLIB_BUFFER_REPL_FAIL (1 << 9)
#define VLIB_BUFFER_RECYCLE (1 << 10)
#define VLIB_BUFFER_FLOW_REPORT (1 << 11)
#define VLIB_BUFFER_EXT_HDR_VALID (1 << 12)

  /* User defined buffer flags. */
#define LOG2_VLIB_BUFFER_FLAG_USER(n) (32 - (n))
#define VLIB_BUFFER_FLAG_USER(n) (1 << LOG2_VLIB_BUFFER_FLAG_USER(n))

    STRUCT_MARK (template_end);

  u32 next_buffer;   /**< Next buffer for this linked-list of buffers.
                        Only valid if VLIB_BUFFER_NEXT_PRESENT flag is set.
                     */

  vlib_error_t error;	/**< Error code for buffers to be enqueued
                           to error handler.
                        */
  u32 current_config_index; /**< Used by feature subgraph arcs to
                               visit enabled feature nodes
                            */

  u8 feature_arc_index;	/**< Used to identify feature arcs by intermediate
                           feature node
                        */

  u8 n_add_refs; /**< Number of additional references to this buffer. */

  u8 buffer_pool_index;	/**< index of buffer pool this buffer belongs. */
  u8 dont_waste_me[1]; /**< Available space in the (precious)
                          first 32 octets of buffer metadata
                          Before allocating any of it, discussion required!
                       */

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
  u32 align_pad; /**< available */
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

always_inline vlib_buffer_t *
vlib_buffer_next_contiguous (vlib_buffer_t * b, u32 buffer_bytes)
{
  return (void *) (b + 1) + buffer_bytes;
}

always_inline void
vlib_buffer_struct_is_sane (vlib_buffer_t * b)
{
  ASSERT (sizeof (b[0]) % 64 == 0);

  /* Rewrite data must be before and contiguous with packet data. */
  ASSERT (b->pre_data + VLIB_BUFFER_PRE_DATA_SIZE == b->data);
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
vlib_buffer_put_uninit (vlib_buffer_t * b, u8 size)
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
  u32 index;

  /* Number of data bytes for buffers in this free list. */
  u32 n_data_bytes;

  /* Number of buffers to allocate when we need to allocate new buffers
     from physmem heap. */
  u32 min_n_buffers_each_physmem_alloc;

  /* Total number of buffers allocated from this free list. */
  u32 n_alloc;

  /* Vector of free buffers.  Each element is a byte offset into I/O heap. */
  u32 *buffers;

  /* global vector of free buffers, used only on main thread.
     Bufers are returned to global buffers only in case when number of
     buffers on free buffers list grows about threshold */
  u32 *global_buffers;
  clib_spinlock_t global_buffers_lock;

  /* Memory chunks allocated for this free list
     recorded here so they can be freed when free list
     is deleted. */
  void **buffer_memory_allocated;

  /* Free list name. */
  u8 *name;

  /* Callback functions to initialize newly allocated buffers.
     If null buffers are zeroed. */
  void (*buffer_init_function) (struct vlib_main_t * vm,
				struct vlib_buffer_free_list_t * fl,
				u32 * buffers, u32 n_buffers);

  /* Callback function to announce that buffers have been
     added to the freelist */
  void (*buffers_added_to_freelist_function)
    (struct vlib_main_t * vm, struct vlib_buffer_free_list_t * fl);

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
  void (*vlib_packet_template_init_cb) (struct vlib_main_t * vm, void *t,
					void *packet_data,
					uword n_packet_data_bytes,
					uword
					min_n_buffers_each_physmem_alloc,
					u8 * name);
  void (*vlib_buffer_delete_free_list_cb) (struct vlib_main_t * vm,
					   u32 free_list_index);
} vlib_buffer_callbacks_t;

extern vlib_buffer_callbacks_t *vlib_buffer_callbacks;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  uword start;
  uword size;
  vlib_physmem_region_index_t physmem_region;
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
  /* Pool of buffer free lists.
     Multiple free lists exist for packet generator which uses
     separate free lists for each packet stream --- so as to avoid
     initializing static data for each packet generated. */
  vlib_buffer_free_list_t *buffer_free_list_pool;
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

  /* List of free-lists needing Blue Light Special announcements */
  vlib_buffer_free_list_t **announce_list;

  /* Callbacks */
  vlib_buffer_callbacks_t cb;
  int callbacks_registered;
} vlib_buffer_main_t;

u8 vlib_buffer_add_physmem_region (struct vlib_main_t *vm,
				   vlib_physmem_region_index_t region);

clib_error_t *vlib_buffer_main_init (struct vlib_main_t *vm);

typedef struct
{
  struct vlib_main_t *vlib_main;

  u32 first_buffer, last_buffer;

  union
  {
    struct
    {
      /* Total accumulated bytes in chain starting with first_buffer. */
      u32 n_total_data_bytes;

      /* Max number of bytes to accumulate in chain starting with first_buffer.
         As this limit is reached buffers are enqueued to next node. */
      u32 max_n_data_bytes_per_chain;

      /* Next node to enqueue buffers to relative to current process node. */
      u32 next_index;

      /* Free list to use to allocate new buffers. */
      u32 free_list_index;
    } tx;

    struct
    {
      /* CLIB fifo of buffer indices waiting to be unserialized. */
      u32 *buffer_fifo;

      /* Event type used to signal that RX buffers have been added to fifo. */
      uword ready_one_time_event;
    } rx;
  };
} vlib_serialize_buffer_main_t;

void serialize_open_vlib_buffer (serialize_main_t * m, struct vlib_main_t *vm,
				 vlib_serialize_buffer_main_t * sm);
void unserialize_open_vlib_buffer (serialize_main_t * m,
				   struct vlib_main_t *vm,
				   vlib_serialize_buffer_main_t * sm);

u32 serialize_close_vlib_buffer (serialize_main_t * m);
void unserialize_close_vlib_buffer (serialize_main_t * m);
void *vlib_set_buffer_free_callback (struct vlib_main_t *vm, void *fp);

always_inline u32
serialize_vlib_buffer_n_bytes (serialize_main_t * m)
{
  serialize_stream_t *s = &m->stream;
  vlib_serialize_buffer_main_t *sm
    = uword_to_pointer (m->stream.data_function_opaque,
			vlib_serialize_buffer_main_t *);
  return sm->tx.n_total_data_bytes + s->current_buffer_index +
    vec_len (s->overflow_buffer);
}

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
__VA_ARGS__ vlib_buffer_callbacks_t __##x##_buffer_callbacks

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
