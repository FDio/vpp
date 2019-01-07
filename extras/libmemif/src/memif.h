/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef _MEMIF_H_
#define _MEMIF_H_

#include <stdint.h>

#ifndef MEMIF_CACHELINE_SIZE
#define MEMIF_CACHELINE_SIZE 64
#endif

#define MEMIF_COOKIE		0x3E31F20
#define MEMIF_VERSION_MAJOR	2
#define MEMIF_VERSION_MINOR	0
#define MEMIF_VERSION		((MEMIF_VERSION_MAJOR << 8) | MEMIF_VERSION_MINOR)

/*
 *  Type definitions
 */

typedef enum memif_msg_type
{
  MEMIF_MSG_TYPE_NONE = 0,
  MEMIF_MSG_TYPE_ACK = 1,
  MEMIF_MSG_TYPE_HELLO = 2,
  MEMIF_MSG_TYPE_INIT = 3,
  MEMIF_MSG_TYPE_ADD_REGION = 4,
  MEMIF_MSG_TYPE_ADD_RING = 5,
  MEMIF_MSG_TYPE_CONNECT = 6,
  MEMIF_MSG_TYPE_CONNECTED = 7,
  MEMIF_MSG_TYPE_DISCONNECT = 8,
} memif_msg_type_t;

typedef enum
{
  MEMIF_RING_S2M = 0,
  MEMIF_RING_M2S = 1
} memif_ring_type_t;

typedef enum
{
  MEMIF_INTERFACE_MODE_ETHERNET = 0,
  MEMIF_INTERFACE_MODE_IP = 1,
  MEMIF_INTERFACE_MODE_PUNT_INJECT = 2,
} memif_interface_mode_t;

typedef uint16_t memif_region_index_t;
typedef uint32_t memif_region_offset_t;
typedef uint64_t memif_region_size_t;
typedef uint16_t memif_ring_index_t;
typedef uint32_t memif_interface_id_t;
typedef uint16_t memif_version_t;
typedef uint8_t memif_log2_ring_size_t;

/*
 *  Socket messages
 */

typedef struct __attribute__ ((packed))
{
  uint8_t name[32];
  memif_version_t min_version;
  memif_version_t max_version;
  memif_region_index_t max_region;
  memif_ring_index_t max_m2s_ring;
  memif_ring_index_t max_s2m_ring;
  memif_log2_ring_size_t max_log2_ring_size;
} memif_msg_hello_t;

typedef struct __attribute__ ((packed))
{
  memif_version_t version;
  memif_interface_id_t id;
  memif_interface_mode_t mode:8;
  uint8_t secret[24];
  uint8_t name[32];
} memif_msg_init_t;

typedef struct __attribute__ ((packed))
{
  memif_region_index_t index;
  memif_region_size_t size;
} memif_msg_add_region_t;

typedef struct __attribute__ ((packed))
{
  uint16_t flags;
#define MEMIF_MSG_ADD_RING_FLAG_S2M	(1 << 0)
  memif_ring_index_t index;
  memif_region_index_t region;
  memif_region_offset_t offset;
  memif_log2_ring_size_t log2_ring_size;
  uint16_t private_hdr_size;	/* used for private metadata */
} memif_msg_add_ring_t;

typedef struct __attribute__ ((packed))
{
  uint8_t if_name[32];
} memif_msg_connect_t;

typedef struct __attribute__ ((packed))
{
  uint8_t if_name[32];
} memif_msg_connected_t;

typedef struct __attribute__ ((packed))
{
  uint32_t code;
  uint8_t string[96];
} memif_msg_disconnect_t;

typedef struct __attribute__ ((packed, aligned (128)))
{
  memif_msg_type_t type:16;
  union
  {
    memif_msg_hello_t hello;
    memif_msg_init_t init;
    memif_msg_add_region_t add_region;
    memif_msg_add_ring_t add_ring;
    memif_msg_connect_t connect;
    memif_msg_connected_t connected;
    memif_msg_disconnect_t disconnect;
  };
} memif_msg_t;

_Static_assert (sizeof (memif_msg_t) == 128,
		"Size of memif_msg_t must be 128");

/*
 *  Ring and Descriptor Layout
 */

typedef struct __attribute__ ((packed))
{
  uint16_t flags;
#define MEMIF_DESC_FLAG_NEXT (1 << 0)
  memif_region_index_t region;
  uint32_t length;
  memif_region_offset_t offset;
  uint32_t metadata;
} memif_desc_t;

_Static_assert (sizeof (memif_desc_t) == 16,
		"Size of memif_dsct_t must be 16 bytes");

#define MEMIF_CACHELINE_ALIGN_MARK(mark) \
  uint8_t mark[0] __attribute__((aligned(MEMIF_CACHELINE_SIZE)))

typedef struct
{
  MEMIF_CACHELINE_ALIGN_MARK (cacheline0);
  uint32_t cookie;
  uint16_t flags;
#define MEMIF_RING_FLAG_MASK_INT 1
  volatile uint16_t head;
    MEMIF_CACHELINE_ALIGN_MARK (cacheline1);
  volatile uint16_t tail;
    MEMIF_CACHELINE_ALIGN_MARK (cacheline2);
  memif_desc_t desc[0];
} memif_ring_t;

#endif /* _MEMIF_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
