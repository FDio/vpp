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

typedef struct
{
  u8 type;
} memif_msg_t;

typedef struct
{
  u32 cookie __attribute__ ((aligned (4096)));
} memif_shm_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *lockp;
  u32 flags;
#define MEMIF_IF_FLAG_ADMIN_UP (1 << 0)
#define MEMIF_IF_FLAG_IS_SLAVE (1 << 1)
#define MEMIF_IF_FLAG_CONNECTED (1 << 2)

  uword if_index;
  u32 hw_if_index;
  u32 sw_if_index;

  u32 per_interface_next_index;

  int fd;
  u32 unix_file_index;
  u8 *socket_file_name;

  memif_shm_t *shm;
} memif_if_t;

typedef struct
{
  char *mem;
  u32 region_size;
  int refcnt;
} memif_mem_region_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  memif_if_t *interfaces;

  /* bitmap of pending rx interfaces */
  uword *pending_input_bitmap;

  /* rx buffer cache */
  u32 **rx_buffers;

  /* hash of host interface names */
  mhash_t if_index_by_host_if_name;

  /* vector of memory regions */
  memif_mem_region_t *mem_regions;

  /* first cpu index */
  u32 input_cpu_first_index;

  /* total cpu count */
  u32 input_cpu_count;
} memif_main_t;

memif_main_t memif_main;
extern vnet_device_class_t memif_device_class;
extern vlib_node_registration_t memif_input_node;

typedef struct
{
  u8 *socket_file_name;
  u8 is_master;

  /* return */
  u32 sw_if_index;
} memif_create_if_args_t;

int memif_create_if (vlib_main_t * vm, memif_create_if_args_t * args);
int memif_delete_if (vlib_main_t * vm, u8 * host_if_name);


static inline int
memfd_create (const char *name, unsigned int flags)
{
  return syscall (__NR_memfd_create, name, flags);
}

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001	/* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002	/* prevent file from shrinking */
#define F_SEAL_GROW     0x0004	/* prevent file from growing */
#define F_SEAL_WRITE    0x0008	/* prevent writes */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
