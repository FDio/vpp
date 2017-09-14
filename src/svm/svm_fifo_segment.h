/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <svm/svm_fifo.h>
#include <svm/ssvm.h>
#include <vppinfra/lock.h>

typedef enum
{
  FIFO_SEGMENT_FREELIST_NONE = -1,
  FIFO_SEGMENT_RX_FREELIST = 0,
  FIFO_SEGMENT_TX_FREELIST,
  FIFO_SEGMENT_N_FREELISTS
} svm_fifo_segment_freelist_t;

#define FIFO_SEGMENT_MIN_FIFO_SIZE 4096
#define FIFO_SEGMENT_MAX_FIFO_SIZE (8<<20)	/* 8mb max fifo size */
#define FIFO_SEGMENT_ALLOC_CHUNK_SIZE 32	/* Allocation quantum */

#define FIFO_SEGMENT_F_IS_PRIVATE 	1 << 0	/* Private segment */
#define FIFO_SEGMENT_F_IS_MAIN_HEAP	1 << 1	/* Segment is main heap */
#define FIFO_SEGMENT_F_IS_PREALLOCATED	1 << 2	/* Segment is preallocated */

typedef struct
{
  svm_fifo_t *fifos;		/**< Linked list of active RX fifos */
  u8 *segment_name;		/**< Segment name */
  svm_fifo_t **free_fifos;	/**< Freelists, by fifo size  */
  u32 n_active_fifos;		/**< Number of active fifos */
  u8 flags;			/**< Segment flags */
} svm_fifo_segment_header_t;

typedef struct
{
  ssvm_private_t ssvm;
  svm_fifo_segment_header_t *h;
} svm_fifo_segment_private_t;

typedef struct
{
  volatile u32 lock;

  /** pool of segments */
  svm_fifo_segment_private_t *segments;
  /* Where to put the next one */
  u64 next_baseva;
  u32 timeout_in_seconds;
} svm_fifo_segment_main_t;

extern svm_fifo_segment_main_t svm_fifo_segment_main;

typedef struct
{
  char *segment_name;
  u32 segment_size;
  u32 *new_segment_indices;
  u32 rx_fifo_size;
  u32 tx_fifo_size;
  u32 preallocated_fifo_pairs;
  u32 private_segment_count;
  u32 private_segment_size;
} svm_fifo_segment_create_args_t;

static inline svm_fifo_segment_private_t *
svm_fifo_segment_get_segment (u32 segment_index)
{
  svm_fifo_segment_main_t *ssm = &svm_fifo_segment_main;
  return vec_elt_at_index (ssm->segments, segment_index);
}

static inline u8
svm_fifo_segment_has_fifos (svm_fifo_segment_private_t * fifo_segment)
{
  return fifo_segment->h->fifos != 0;
}

static inline svm_fifo_t *
svm_fifo_segment_get_fifo_list (svm_fifo_segment_private_t * fifo_segment)
{
  return fifo_segment->h->fifos;
}

#define foreach_ssvm_fifo_segment_api_error             \
_(OUT_OF_SPACE, "Out of space in segment", -200)

typedef enum
{
#define _(n,s,c) SSVM_FIFO_SEGMENT_API_ERROR_##n = c,
  foreach_ssvm_fifo_segment_api_error
#undef _
} ssvm_fifo_segment_api_error_enum_t;

int svm_fifo_segment_create (svm_fifo_segment_create_args_t * a);
int svm_fifo_segment_create_process_private (svm_fifo_segment_create_args_t
					     * a);
int svm_fifo_segment_attach (svm_fifo_segment_create_args_t * a);
void svm_fifo_segment_delete (svm_fifo_segment_private_t * s);

svm_fifo_t *svm_fifo_segment_alloc_fifo (svm_fifo_segment_private_t * s,
					 u32 data_size_in_bytes,
					 svm_fifo_segment_freelist_t index);
void svm_fifo_segment_free_fifo (svm_fifo_segment_private_t * s,
				 svm_fifo_t * f,
				 svm_fifo_segment_freelist_t index);
void svm_fifo_segment_init (u64 baseva, u32 timeout_in_seconds);
u32 svm_fifo_segment_index (svm_fifo_segment_private_t * s);
u32 svm_fifo_segment_num_fifos (svm_fifo_segment_private_t * fifo_segment);
u32 svm_fifo_segment_num_free_fifos (svm_fifo_segment_private_t *
				     fifo_segment, u32 fifo_size_in_bytes);

svm_fifo_segment_private_t *svm_fifo_segment_segments_pool (void);
format_function_t format_svm_fifo_segment;

#endif /* __included_ssvm_fifo_segment_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
