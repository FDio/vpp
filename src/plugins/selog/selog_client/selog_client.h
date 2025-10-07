/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */
#ifndef __included_selog_client_h__
#define __included_selog_client_h__

#include <stdint.h>
#include <stddef.h>

#define foreach_selog_client_errors                                           \
  _ (NONE, "no error")                                                        \
  _ (INVALID_ARG, "invalid argument")                                         \
  _ (CONNECT_FAIL, "connect to vpp failed")                                   \
  _ (TIMEOUT, "timeout")

enum
{
#define _(sym, str) SELOG_CLIENT_ERROR_##sym,
  foreach_selog_client_errors
#undef _
    SELOG_CLIENT_N_ERROR,
};

const char *selog_client_error_strings[] = {
#define _(sym, str) str,
  foreach_selog_client_errors
#undef _
};

typedef struct
{
  const char *sock_name;
  const char *client_name;
} selog_client_ctx_t;

typedef struct
{
  union
  {
    uint64_t time_cycles;
    double time;
  };
  uint16_t event_type;
  uint16_t track;
  uint8_t data[20];
} selog_event_t;

selog_client_ctx_t *selog_client_ctx_alloc ();
void selog_client_ctx_free (selog_client_ctx_t *ctx);
int32_t selog_client_connect_to_vpp (selog_client_ctx_t *ctx);
int32_t selog_client_disconnect_from_vpp (selog_client_ctx_t *ctx);

int32_t selog_client_poll_event (selog_client_ctx_t *ctx, selog_event_t *event,
				 uint32_t max_events);

void selog_client_format_events (selog_client_ctx_t *ctx,
				 selog_event_t *events, uint32_t n_events,
				 char **result);
void selog_client_free_formatted_events (char **result, uint32_t n_events);
#endif /* __included_selog_client_h__ */
