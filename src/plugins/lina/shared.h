/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _LINA_H_
#define _LINA_H_

#include <stdint.h>

#define LINA_SHM_MAX_REGIONS 32

#define LINA_CACHELINE_SIZE 64
#define LINA_CACHELINE_ALIGN_MARK(mark) \
  uint8_t mark[0] __attribute__((aligned(LINA_CACHELINE_SIZE)))

typedef struct __attribute__ ((packed, aligned (128)))
{
  uint32_t instance;
  uint32_t n_regions;
  uint64_t region_size[LINA_SHM_MAX_REGIONS];
} lina_msg_t;

typedef struct
{
  LINA_CACHELINE_ALIGN_MARK (cacheline0);
  volatile uint32_t head;
    LINA_CACHELINE_ALIGN_MARK (cacheline1);
  volatile uint32_t tail;
} lina_shm_ring_hdr_t;

typedef struct
{
  LINA_CACHELINE_ALIGN_MARK (cacheline0);
  uint64_t offset;
  uint32_t length;
  uint8_t region;
  uint8_t action;
#define LINA_SHM_DESC_ACTION_DROP 0
#define LINA_SHM_DESC_ACTION_FORWARD 1
} lina_shm_desc_t;


typedef struct
{
  LINA_CACHELINE_ALIGN_MARK (cacheline0);
  uint32_t cookie;
#define LINA_SHM_HDR_COOKIE 0xdeadbeef
  uint32_t n_rings;
  uint32_t log2_ring_sz;
    LINA_CACHELINE_ALIGN_MARK (cacheline1);
  lina_shm_ring_hdr_t rings[0];
} lina_shm_hdr_t;

static inline lina_shm_ring_hdr_t *
lina_get_shm_ring (void *p, uint32_t index)
{
  lina_shm_hdr_t *hdr = (lina_shm_hdr_t *) p;
  return hdr->rings + index;
}

static inline lina_shm_desc_t *
lina_get_shm_desc (lina_shm_hdr_t * p, uint32_t ring_index,
		   uint32_t desc_index)
{
  lina_shm_hdr_t *hdr = (lina_shm_hdr_t *) p;
  uint8_t *rv = (uint8_t *) p;

  rv += sizeof (lina_shm_hdr_t);
  rv += hdr->n_rings * sizeof (lina_shm_ring_hdr_t);
  rv += (ring_index << hdr->log2_ring_sz) * sizeof (lina_shm_desc_t);
  return ((lina_shm_desc_t *) rv) + desc_index;
}

#endif /* _LINA_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
