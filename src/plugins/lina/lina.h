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

#include <vppinfra/lock.h>
#include <vlib/log.h>

#define lina_log_debug(lin, f, ...) do {                                \
  lina_instance_t *_lin = (lina_instance_t *) lin;                      \
  if (_lin)                                                             \
    vlib_log(VLIB_LOG_LEVEL_DEBUG, lina_main.log_class, "%u: " f,       \
             _lin->index, ##__VA_ARGS__);                               \
  else                                                                  \
    vlib_log(VLIB_LOG_LEVEL_DEBUG, lina_main.log_class, f,              \
             ##__VA_ARGS__);                                            \
} while (0)


typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 *bufs;
  lina_shm_ring_hdr_t *hdr;
  lina_shm_desc_t *descs;
} lina_ring_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 index;
  u32 flags;
#define LINA_INSTANCE_F_CONNECTED (1 << 0)

  clib_socket_t listener;
  clib_socket_t client;
  u8 *listener_filename;

  /* shared memory */
  int fd;
  lina_shm_hdr_t *shm_hdr;
  u64 shm_size;
  u32 shm_map_index;

  u32 log2_ring_sz;
  lina_ring_t *rings;

} lina_instance_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* pool of all memory interfaces */
  lina_instance_t *instances;

  /* logging */
  vlib_log_class_t log_class;
} lina_main_t;

extern lina_main_t lina_main;

typedef struct
{
  u8 *filename;
  u32 hw_if_index;
  u32 ring_size;

  /* return */
  clib_error_t *error;
} lina_create_instance_args_t;

extern vlib_node_registration_t lina_enqueue_node;
extern vlib_node_registration_t lina_dequeue_node;

void lina_create_instance (vlib_main_t *, lina_create_instance_args_t *);

/* socket */
clib_error_t *lina_socket_listener_create (vlib_main_t *, lina_instance_t *);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
