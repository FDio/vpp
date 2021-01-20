/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
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
#ifndef __included_fifo_segment_h__
#define __included_fifo_segment_h__

#include <svm/ssvm.h>
#include <svm/fifo_types.h>
#include <svm/message_queue.h>
#include <svm/svm_fifo.h>

typedef enum
{
  FIFO_SEGMENT_FTYPE_NONE = -1,
  FIFO_SEGMENT_RX_FIFO = 0,
  FIFO_SEGMENT_TX_FIFO,
  FIFO_SEGMENT_N_FTYPES
} fifo_segment_ftype_t;

#define FIFO_SEGMENT_MIN_LOG2_FIFO_SIZE 12	/**< 4kB min fifo size */
#define FIFO_SEGMENT_MIN_FIFO_SIZE 4096		/**< 4kB min fifo size */
#define FIFO_SEGMENT_MAX_FIFO_SIZE (2ULL << 30)	/**< 2GB max fifo size */
#define FIFO_SEGMENT_ALLOC_BATCH_SIZE 32	/* Allocation quantum */

typedef enum fifo_segment_flags_
{
  FIFO_SEGMENT_F_IS_PREALLOCATED = 1 << 0,
  FIFO_SEGMENT_F_WILL_DELETE = 1 << 1,
  FIFO_SEGMENT_F_MEM_LIMIT = 1 << 2,
} fifo_segment_flags_t;

#define foreach_segment_mem_status	\
_(NO_PRESSURE, "No pressure")		\
_(LOW_PRESSURE, "Low pressure")		\
_(HIGH_PRESSURE, "High pressure")	\
_(NO_MEMORY, "No memory")

typedef enum
{
#define _(sym,str)  MEMORY_PRESSURE_##sym,
  foreach_segment_mem_status
#undef _
    MEMORY_N_PRESSURE,
} fifo_segment_mem_status_t;

#if 0
typedef enum fifo_segment_mem_status_
{
  MEMORY_PRESSURE_NO_PRESSURE,
  MEMORY_PRESSURE_LOW_PRESSURE,
  MEMORY_PRESSURE_HIGH_PRESSURE,
  MEMORY_PRESSURE_NO_MEMORY,
} fifo_segment_mem_status_t;
#endif

typedef struct
{
  ssvm_private_t ssvm;		/**< ssvm segment data */
  fifo_segment_header_t *h;	/**< fifo segment data */
  uword max_byte_index;
  u8 n_slices;			/**< number of fifo segment slices */
  fifo_slice_private_t *slices; /**< private slice information */
  svm_msg_q_t *mqs;		/**< private vec of attached mqs */
} fifo_segment_t;

typedef struct
{
  fifo_segment_t *segments;	/**< pool of fifo segments */
  uword next_baseva;		/**< Where to put the next one */
  u32 timeout_in_seconds;	/**< Time to wait during attach */
} fifo_segment_main_t;

typedef struct
{
  ssvm_segment_type_t segment_type;	/**< type of segment requested */
  u32 segment_size;			/**< size of the segment */
  int memfd_fd;				/**< fd for memfd segments */
  char *segment_name;			/**< segment name */
  u32 *new_segment_indices;		/**< return vec of new seg indices */
} fifo_segment_create_args_t;

#define fifo_segment_flags(_fs) _fs->h->flags

int fifo_segment_init (fifo_segment_t * fs);
int fifo_segment_create (fifo_segment_main_t * sm,
			 fifo_segment_create_args_t * a);
int fifo_segment_attach (fifo_segment_main_t * sm,
			 fifo_segment_create_args_t * a);
void fifo_segment_delete (fifo_segment_main_t * sm, fifo_segment_t * fs);
void fifo_segment_cleanup (fifo_segment_t *fs);
fifo_segment_t *fifo_segment_get_segment (fifo_segment_main_t * sm,
					  u32 fs_index);
u32 fifo_segment_index (fifo_segment_main_t * sm, fifo_segment_t * fs);
void fifo_segment_info (fifo_segment_t * seg, char **address, size_t * size);

always_inline void *
fifo_segment_ptr (fifo_segment_t *fs, uword offset)
{
  return (void *) ((u8 *) fs->h + offset);
}

always_inline uword
fifo_segment_offset (fifo_segment_t *fs, void *p)
{
  return (uword) ((u8 *) p - (u8 *) fs->h);
}

/**
 * Allocate fifo in fifo segment
 *
 * @param fs		fifo segment for fifo
 * @param data_bytes	size of default fifo chunk in bytes
 * @param ftype		fifo type @ref fifo_segment_ftype_t
 * @return		new fifo or 0 if alloc failed
 */
svm_fifo_t *fifo_segment_alloc_fifo_w_slice (fifo_segment_t * fs,
					     u32 slice_index,
					     u32 data_bytes,
					     fifo_segment_ftype_t ftype);
svm_fifo_t *fifo_segment_alloc_fifo_w_offset (fifo_segment_t *fs,
					      uword offset);

/**
 * Free fifo allocated in fifo segment
 *
 * @param fs		fifo segment for fifo
 * @param f		fifo to be freed
 */
void fifo_segment_free_fifo (fifo_segment_t * fs, svm_fifo_t * f);

void fifo_segment_detach_fifo (fifo_segment_t *fs, svm_fifo_t **f);
void fifo_segment_attach_fifo (fifo_segment_t *fs, svm_fifo_t **f,
			       u32 slice_index);
uword fifo_segment_fifo_offset (svm_fifo_t *f);

/**
 * Allocate message queue on segment
 *
 * @param fs		fifo segment for mq
 * @param mq_index	index in private mqs vector to use to attach
 * @param cfg		configuration for mq
 * @return		attached message queue
 */
svm_msg_q_t *fifo_segment_msg_q_alloc (fifo_segment_t *fs, u32 mq_index,
				       svm_msg_q_cfg_t *cfg);

/**
 *  Attach message queue at fifo segment offset
 *
 *  @param fs		fifo segment for mq
 *  @param offset	offset for shared mq on the segment
 *  @param mq_index	index in private mqs vector to use to attach
 *  @return		attached message queue
 */
svm_msg_q_t *fifo_segment_msg_q_attach (fifo_segment_t *fs, uword offset,
					u32 mq_index);
void fifo_segment_msg_qs_discover (fifo_segment_t *fs, int *fds, u32 n_fds);

/**
 * Message queue offset on segment
 *
 * @param fs		fifo segment for mq
 * @param mq_index	index of mq in private mqs vector
 * @return		offset of the shared mq the private mq is attached to
 */
uword fifo_segment_msg_q_offset (fifo_segment_t *fs, u32 mq_index);

/**
 * Try to preallocate fifo headers
 *
 * Tries to preallocate fifo headers and adds them to freelist.
 *
 * @param fs		fifo segment
 * @param batch_size	number of chunks to be allocated
 * @return		0 on success, negative number otherwise
 */
int fifo_segment_prealloc_fifo_hdrs (fifo_segment_t * fs, u32 slice_index,
				     u32 batch_size);

/**
 * Try to preallocate fifo chunks on segment
 *
 * Tries to preallocate chunks of requested size on segment and adds them
 * to chunk freelist.
 *
 * @param fs		fifo segment
 * @param chunk_size	size of chunks to be allocated in bytes
 * @param batch_size	number of chunks to be allocated
 * @return		0 on success, negative number otherwise
 */
int fifo_segment_prealloc_fifo_chunks (fifo_segment_t * fs, u32 slice_index,
				       u32 chunk_size, u32 batch_size);
/**
 * Pre-allocates fifo pairs in fifo segment
 *
 * The number of fifos pre-allocated is the minimum of the requested number
 * of pairs and the maximum number that fit within the segment. If the maximum
 * is hit, the number of fifo pairs requested is updated by subtracting the
 * number of fifos that have been successfully allocated.
 *
 * @param fs		fifo segment for fifo
 * @param rx_fifo_size	data size of rx fifos
 * @param tx_fifo_size	data size of tx fifos
 * @param n_fifo_pairs	number of pairs requested. Prior to returning, this
 * 			is decremented by the the number of pairs allocated.
 */
void fifo_segment_preallocate_fifo_pairs (fifo_segment_t * fs,
					  u32 rx_fifo_size,
					  u32 tx_fifo_size,
					  u32 * n_fifo_pairs);

/**
 * Allocate chunks in fifo segment
 *
 * @param fsh		fifo segment header
 * @param slice_index	slice where chunks should be alocated
 * @param chunk_size	chunk size needed
 * @return		chunk (or chunks) that cover at least chunk_size bytes
 * 			on success, 0 on failure.
 */
svm_fifo_chunk_t *fsh_alloc_chunk (fifo_segment_header_t * fsh,
				   u32 slice_index, u32 chunk_size);

/**
 * Return chunks to fifo segment
 *
 * @param fsh		fifo segment header
 * @param slice_index	slice where chunks should be returned
 * @param c		pointer to first chunk in 0 terminated linked list
 */
void fsh_collect_chunks (fifo_segment_header_t * fsh, u32 slice_index,
			 svm_fifo_chunk_t * c);

/**
 * Fifo segment has reached mem limit
 *
 * @param fsh           fifo segment header
 * @return              1 (if reached) or 0 (otherwise)
 */
u8 fsh_has_reached_mem_limit (fifo_segment_header_t * fsh);

/**
 * Fifo segment reset mem limit flag
 *
 * @param fs            fifo segment
 */
void fsh_reset_mem_limit (fifo_segment_header_t * fsh);

/**
 * Fifo segment reset mem limit flag
 *
 * @param fs            fifo segment
 * @param size		size requested
 * @return		pointer to memory allocated or 0
 */
void *fifo_segment_alloc (fifo_segment_t *fs, uword size);
/**
 * Fifo segment allocated size
 *
 * Returns fifo segment's allocated size
 *
 * @param fs            fifo segment
 * @return              allocated size in bytes
 */
uword fifo_segment_size (fifo_segment_t * fs);

/**
 * Fifo segment estimate of number of free bytes
 *
 * Returns fifo segment's internal estimate of the number of free bytes.
 * To force a synchronization between the segment and the underlying
 * memory allocator, call @ref fifo_segment_update_free_bytes
 *
 * @param fs		fifo segment
 * @return		free bytes estimate
 */
uword fifo_segment_free_bytes (fifo_segment_t * fs);

/**
 * Fifo segment number of cached bytes
 *
 * Returns fifo segment's number of cached bytes.
 *
 * @param fs            fifo segment
 * @return              cached bytes
 */
uword fifo_segment_cached_bytes (fifo_segment_t * fs);

uword fifo_segment_available_bytes (fifo_segment_t * fs);

/**
 * Number of bytes on chunk free lists
 *
 * @param fs		fifo segment
 * @return		free bytes on chunk free lists
 */
uword fifo_segment_fl_chunk_bytes (fifo_segment_t * fs);
u8 fifo_segment_has_fifos (fifo_segment_t * fs);
svm_fifo_t *fifo_segment_get_slice_fifo_list (fifo_segment_t * fs,
					      u32 slice_index);
u32 fifo_segment_num_fifos (fifo_segment_t * fs);
u32 fifo_segment_num_free_fifos (fifo_segment_t * fs);
/**
 * Find number of free chunks of given size
 *
 * @param fs	fifo segment
 * @param size	chunk size of interest or ~0 if all should be counted
 * @return	number of chunks of given size
 */
u32 fifo_segment_num_free_chunks (fifo_segment_t * fs, u32 size);

u8 fifo_segment_get_mem_usage (fifo_segment_t * fs);
fifo_segment_mem_status_t fifo_segment_determine_status
  (fifo_segment_header_t * fsh, u8 usage);
fifo_segment_mem_status_t fifo_segment_get_mem_status (fifo_segment_t * fs);

void fifo_segment_main_init (fifo_segment_main_t * sm, u64 baseva,
			     u32 timeout_in_seconds);

format_function_t format_fifo_segment;
format_function_t format_fifo_segment_type;

#endif /* __included_fifo_segment_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
