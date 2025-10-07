/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
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
#ifndef __included_selog_client_internal_h__
#define __included_selog_client_internal_h__

#include <svm/ssvm.h>
#include <vlibmemory/socket_client.h>
#include <vlibmemory/memory_client.h>
#include <selog/selog_shared.h>
#include "selog_client.h"

STATIC_ASSERT_SIZEOF (selog_event_t, 32);
STATIC_ASSERT_SIZEOF (elog_event_t, 32);
STATIC_ASSERT_OFFSET_OF (selog_event_t, time_cycles,
			 offsetof (elog_event_t, time_cycles));
STATIC_ASSERT_OFFSET_OF (selog_event_t, time, offsetof (elog_event_t, time));
STATIC_ASSERT_OFFSET_OF (selog_event_t, event_type,
			 offsetof (elog_event_t, event_type));
STATIC_ASSERT_OFFSET_OF (selog_event_t, track, offsetof (elog_event_t, track));
STATIC_ASSERT_OFFSET_OF (selog_event_t, data, offsetof (elog_event_t, data));

#define foreach_selog_client_internal_state                                   \
  _ (DISCONNECTED, "disconnected")                                            \
  _ (ERROR, "error")                                                          \
  _ (CONNECTED, "connected")                                                  \
  _ (WAITING_FOR_SHM, "waiting for shm")                                      \
  _ (SHM_RECEIVED, "shm received")                                            \
  _ (WAITING_FOR_STRING_TABLE, "waiting for string table")                    \
  _ (STRING_TABLE_LOADED, "string table loaded")                              \
  _ (WAITING_FOR_ALL_TRACKS, "waiting for all tracks")                        \
  _ (ALL_TRACKS_LOADED, "all tracks loaded")                                  \
  _ (WAITING_FOR_ALL_EVENT_TYPES, "waiting for all event types")              \
  _ (ALL_EVENT_TYPES_LOADED, "all event types loaded")                        \
  _ (WAITING_FOR_ENUM_STRINGS, "waiting for enum strings")                    \
  _ (ENUM_STRINGS_LOADED, "enum strings loaded")

enum
{
#define _(sym, str) SELOG_CLIENT_INTERNAL_STATE_##sym,
  foreach_selog_client_internal_state
#undef _
    SELOG_CLIENT_INTERNAL_N_STATE,
};

const char *selog_client_internal_state_strings[] = {
#define _(sym, str) str,
  foreach_selog_client_internal_state
#undef _
};

static inline const char *
selog_client_internal_state_str (u8 state)
{
  if (state >= SELOG_CLIENT_INTERNAL_N_STATE)
    return "unknown";
  return selog_client_internal_state_strings[state];
}
typedef struct
{
  u8 *string_offset;
  u8 *string_size;
} selog_type_private_t;

typedef struct
{
  selog_client_ctx_t client_ctx;
  clib_socket_t app_api_sock;
  socket_client_main_t bapi_sock_ctx;
  api_main_t bapi_api_ctx;
  memory_client_main_t bapi_mem_ctx;
  ssvm_private_t ssvm;
  clib_spinlock_t lock;
  elog_main_t private_em;
  svm_queue_t *vl_input_queue;
  selog_shared_header_t *sh;
  selog_type_private_t *event_type_private;
  uword current_event_type_index;
  uword next_event;
  u32 api_client_handle;
  int async_error;
  volatile u8 state;
  volatile u8 multipart_done;
} selog_client_internal_ctx_t;

typedef struct
{
  selog_client_internal_ctx_t *internal_ctx;
  u8 log_lvl;
  clib_time_t time;
} selog_client_main_t;

extern selog_client_main_t selog_client_main;

enum
{
  SELOG_LOG_LEVEL_ERROR,
  SELOG_LOG_LEVEL_WARNING,
  SELOG_LOG_LEVEL_INFO,
  SELOG_LOG_LEVEL_DEBUG,
  SELOG_LOG_LEVEL_TRACE
};
#define SELOG_INTERNAL_CTX(x) ((selog_client_internal_ctx_t *) x)
#define SELOG_LOG(lvl_, fmt_, args_...)                                       \
  do                                                                          \
    {                                                                         \
      if (selog_client_main.log_lvl > lvl_)                                   \
	fprintf (stderr, fmt_ "\n", ##args_);                                 \
    }                                                                         \
  while (0)

#define SELOG_LOG_ERROR(fmt_, args_...)                                       \
  SELOG_LOG (SELOG_LOG_LEVEL_ERROR, fmt_, ##args_)

#define SELOG_LOG_WARNING(fmt_, args_...)                                     \
  SELOG_LOG (SELOG_LOG_LEVEL_WARNING, fmt_, ##args_)

#define SELOG_LOG_INFO(fmt_, args_...)                                        \
  SELOG_LOG (SELOG_LOG_LEVEL_INFO, fmt_, ##args_)

#define SELOG_LOG_DEBUG(fmt_, args_...)                                       \
  SELOG_LOG (SELOG_LOG_LEVEL_DEBUG, fmt_, ##args_)

#define SELOG_LOG_TRACE(fmt_, args_...)                                       \
  SELOG_LOG (SELOG_LOG_LEVEL_TRACE, fmt_, ##args_)

#endif /* __included_selog_client_internal_h__ */
