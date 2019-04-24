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
#ifndef __included_ssvm_fifo_segment_h__
#define __included_ssvm_fifo_segment_h__

#include <svm/ssvm.h>
#include <svm/svm_fifo.h>

typedef enum
{
  FIFO_SEGMENT_FREELIST_NONE = -1,
  FIFO_SEGMENT_RX_FREELIST = 0,
  FIFO_SEGMENT_TX_FREELIST,
  FIFO_SEGMENT_N_FREELISTS
} svm_fifo_segment_freelist_t;

#define FIFO_SEGMENT_MIN_FIFO_SIZE 4096		/* 4kB min fifo size */
#define FIFO_SEGMENT_MAX_FIFO_SIZE (2 << 30)	/* 2GB max fifo size */
#define FIFO_SEGMENT_ALLOC_CHUNK_SIZE 32	/* Allocation quantum */

typedef enum svm_fifo_segment_flags_
{
  FIFO_SEGMENT_F_IS_PREALLOCATED = 1 << 0,
  FIFO_SEGMENT_F_WILL_DELETE = 1 << 1,
} svm_fifo_segment_flags_t;

typedef struct
{
  svm_fifo_t *fifos;		/**< Linked list of active RX fifos */
  svm_fifo_t **free_fifos;	/**< Freelists, by fifo size  */
  u32 n_active_fifos;		/**< Number of active fifos */
  u8 flags;			/**< Segment flags */
} svm_fifo_segment_header_t;

typedef struct
{
  ssvm_private_t ssvm;		/**< ssvm segment data */
  svm_fifo_segment_header_t *h;	/**< fifo segment data */
} svm_fifo_segment_t;

typedef struct
{
  svm_fifo_segment_t *segments;	/**< pool of fifo segments */
  u64 next_baseva;		/**< Where to put the next one */
  u32 timeout_in_seconds;	/**< Time to wait during attach */
} svm_fifo_segment_main_t;

typedef struct
{
  ssvm_segment_type_t segment_type;	/**< type of segment requested */
  u32 segment_size;			/**< size of the segment */
  int memfd_fd;				/**< fd for memfd segments */
  char *segment_name;			/**< segment name */
  u32 *new_segment_indices;		/**< return vec of new seg indices */
} svm_fifo_segment_create_args_t;

#define svm_fifo_segment_flags(_fs) _fs->h->flags

int svm_fifo_segment_init (svm_fifo_segment_t * s);
int svm_fifo_segment_create (svm_fifo_segment_main_t * sm,
			     svm_fifo_segment_create_args_t * a);
int svm_fifo_segment_attach (svm_fifo_segment_main_t * sm,
			     svm_fifo_segment_create_args_t * a);
void svm_fifo_segment_delete (svm_fifo_segment_main_t * sm,
			      svm_fifo_segment_t * s);
svm_fifo_segment_t *
svm_fifo_segment_get_segment (svm_fifo_segment_main_t * sm, u32 fs_index);
u32 svm_fifo_segment_index (svm_fifo_segment_main_t * sm,
			    svm_fifo_segment_t * s);
void svm_fifo_segment_info (svm_fifo_segment_t * seg, char **address,
			    size_t * size);

/**
 * Allocate fifo in fifo segment
 *
 * @param fs			fifo segment
 * @param data_size_in_bytes	size of default fifo chunk in bytes
 * @param list_index		list for new fifo
 * @return			new fifo or 0 if alloc failed
 */
svm_fifo_t *svm_fifo_segment_alloc_fifo (svm_fifo_segment_t * s,
                                         u32 data_size_in_bytes,
					 svm_fifo_segment_freelist_t index);

/**
 * Free fifo allocated in fifo segment
 *
 * @param fs		fifo segment
 * @param f		fifo to be freed
 * @param index		list for fifo
 */
void svm_fifo_segment_free_fifo (svm_fifo_segment_t * s, svm_fifo_t * f,
				 svm_fifo_segment_freelist_t index);
void svm_fifo_segment_preallocate_fifo_pairs (svm_fifo_segment_t * s,
					      u32 rx_fifo_size,
					      u32 tx_fifo_size,
					      u32 * n_fifo_pairs);
u8 svm_fifo_segment_has_fifos (svm_fifo_segment_t * fs);
svm_fifo_t *svm_fifo_segment_get_fifo_list (svm_fifo_segment_t * fs);
u32 svm_fifo_segment_num_fifos (svm_fifo_segment_t * fs);
u32 svm_fifo_segment_num_free_fifos (svm_fifo_segment_t *fs,
                                     u32 fifo_size_in_bytes);

void svm_fifo_segment_main_init (svm_fifo_segment_main_t * sm, u64 baseva,
				 u32 timeout_in_seconds);

format_function_t format_svm_fifo_segment;
format_function_t format_svm_fifo_segment_type;

#endif /* __included_ssvm_fifo_segment_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
