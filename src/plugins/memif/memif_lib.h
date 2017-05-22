/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

/* TODO: cleanup header file
         - sort deps
*/

#ifndef _MEMIF_LIB_H_
#define _MEMIF_LIB_H_

#include <sys/syscall.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdint.h>
#include <net/if.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <limits.h>

/*
 *  Type definitions
 */

typedef enum memif_msg_type
{
  MEMIF_MSG_TYPE_NONE = 0,
  MEMIF_MSG_TYPE_HELLO = 1,
  MEMIF_MSG_TYPE_INIT = 2,
  MEMIF_MSG_TYPE_ADD_REGION = 3,
  MEMIF_MSG_TYPE_ADD_RING = 4,
  MEMIF_MSG_TYPE_CONNECT = 5,
  MEMIF_MSG_TYPE_CONNECTED = 6,
  MEMIF_MSG_TYPE_DISCONNECT = 7,
  MEMIF_MSG_TYPE_RECV_MODE = 8
} memif_msg_type_t;

typedef enum
{
  MEMIF_RING_S2M = 0,
  MEMIF_RING_M2S = 1
} memif_ring_type_t;


typedef uint8_t memif_region_index_t;
typedef uint8_t memif_ring_index_t;

/*
 *  Socket messages
 */

typedef struct __attribute__ ((packed))
{
  uint16_t min_version;
  uint16_t max_version;
  uint8_t max_regions;
  uint8_t max_m2s_rings;
  uint8_t max_s2m_rings;
  uint8_t max_log2_ring_size;
} memif_msg_hello_t;

typedef struct __attribute__ ((packed))
{
  uint64_t key;
} memif_msg_init_t;

typedef struct __attribute__ ((packed))
{
  memif_region_index_t index;
  uint32_t size;
} memif_msg_add_region_t;

typedef struct __attribute__ ((packed))
{
  uint16_t flags;
#define MEMIF_MSG_ADD_RING_FLAG_S2M (1 << 0)
  memif_ring_index_t index;
  memif_region_index_t region;
  uint32_t offset;
  uint8_t log2_ring_size;
} memif_msg_add_ring_t;

typedef struct __attribute__ ((packed))
{
  uint32_t reason;
  uint8_t reason_string[96];
} memif_msg_disconnect_t;

typedef struct __attribute__ ((packed))
{
    uint8_t recv_mode;
    uint8_t qid;
} memif_msg_recv_mode_t;

typedef struct __attribute__ ((packed, aligned (128)))
{
  memif_msg_type_t type:16;
  union
  {
    memif_msg_hello_t hello;
    memif_msg_init_t init;
    memif_msg_add_region_t add_region;
    memif_msg_add_ring_t add_ring;
    memif_msg_disconnect_t disconnect;
    memif_msg_recv_mode_t recv_mode;
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
  uint16_t region;
  uint32_t buffer_length;
  uint32_t length;
  uint8_t reserved[4];
  uint64_t offset;
  uint64_t metadata;
} memif_desc_t;

_Static_assert (sizeof (memif_desc_t) == 32,
        "Size of memif_dsct_t must be 32");

typedef struct
{
  uint32_t cookie;
  uint16_t flags;
#define MEMIF_RING_FLAG_MASK_INT 1
  uint16_t head __attribute__ ((aligned (128)));
  uint16_t tail __attribute__ ((aligned (128)));
  uint64_t buffer_offset __attribute__ ((aligned (128)));
  uint16_t head_offset __attribute__ ((aligned (128)));
  memif_desc_t desc[0] __attribute__ ((aligned (128)));
} memif_ring_t;

/*
 *  Memif file
 *
 *  used for non-vpp api instead of VPP unix_file
 *  global var memif_file_main?
 */

struct memif_file;

typedef void *(memif_file_function_t) (struct memif_file *mf);

typedef struct memif_file
{
  int fd;
  uint32_t index;

  uint64_t data;
  memif_file_function_t *write_function, *read_function, *error_function;
} memif_file_t;

#endif
