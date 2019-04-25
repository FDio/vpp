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
#include <svm/svm_fifo.h>

typedef enum
{
  FIFO_SEGMENT_FTYPE_NONE = -1,
  FIFO_SEGMENT_RX_FIFO = 0,
  FIFO_SEGMENT_TX_FIFO,
  FIFO_SEGMENT_N_FTYPES
} fifo_segment_ftype_t;

#define FIFO_SEGMENT_MIN_FIFO_SIZE 4096	/* 4kB min fifo size */
#define FIFO_SEGMENT_MAX_FIFO_SIZE (2 << 30)	/* 2GB max fifo size */
#define FIFO_SEGMENT_ALLOC_BATCH_SIZE 32	/* Allocation quantum */

typedef enum fifo_segment_flags_
{
  FIFO_SEGMENT_F_IS_PREALLOCATED = 1 << 0,
  FIFO_SEGMENT_F_WILL_DELETE = 1 << 1,
} fifo_segment_flags_t;

typedef struct
{
  svm_fifo_t *fifos;			/**< Linked list of active RX fifos */
  svm_fifo_t **free_fifos;		/**< Freelists by fifo size  */
  svm_fifo_chunk_t **free_chunks;	/**< Freelists by chunk size */
  u32 n_active_fifos;			/**< Number of active fifos */
  u8 flags;				/**< Segment flags */
} fifo_segment_header_t;

typedef struct
{
  ssvm_private_t ssvm;		/**< ssvm segment data */
  fifo_segment_header_t *h;	/**< fifo segment data */
} fifo_segment_t;

typedef struct
{
  fifo_segment_t *segments;	/**< pool of fifo segments */
  u64 next_baseva;		/**< Where to put the next one */
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
fifo_segment_t *fifo_segment_get_segment (fifo_segment_main_t * sm,
					  u32 fs_index);
u32 fifo_segment_index (fifo_segment_main_t * sm, fifo_segment_t * fs);
void fifo_segment_info (fifo_segment_t * seg, char **address, size_t * size);

/**
 * Allocate fifo in fifo segment
 *
 * @param fs		fifo segment for fifo
 * @param data_bytes	size of default fifo chunk in bytes
 * @param ftype		fifo type @ref fifo_segment_ftype_t
 * @return		new fifo or 0 if alloc failed
 */
svm_fifo_t *fifo_segment_alloc_fifo (fifo_segment_t * fs,
				     u32 data_bytes,
				     fifo_segment_ftype_t ftype);

/**
 * Free fifo allocated in fifo segment
 *
 * @param fs		fifo segment for fifo
 * @param f		fifo to be freed
 */
void fifo_segment_free_fifo (fifo_segment_t * fs, svm_fifo_t * f);

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
 * Grow fifo size by adding an additional chunk of memory
 *
 * @param fs		fifo segment for fifo
 * @param f		fifo to be grown
 * @param chunk_size	number of bytes to be added to fifo
 * @return		0 on success or a negative number otherwise
 */
int fifo_segment_grow_fifo (fifo_segment_t * fs, svm_fifo_t * f,
			    u32 chunk_size);
u8 fifo_segment_has_fifos (fifo_segment_t * fs);
svm_fifo_t *fifo_segment_get_fifo_list (fifo_segment_t * fs);
u32 fifo_segment_num_fifos (fifo_segment_t * fs);
u32 fifo_segment_num_free_fifos (fifo_segment_t * fs, u32 fifo_size_in_bytes);
/**
 * Find number of free chunks of given size
 *
 * @param fs	fifo segment
 * @param size	chunk size of interest or ~0 if all should be counted
 * @return	number of chunks of given size
 */
u32 fifo_segment_num_free_chunks (fifo_segment_t * fs, u32 size);

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
