// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_timer_h
#define included_vcdp_timer_h

#include "vcdp.h"

/* Default session state protocol timeouts */
#define foreach_vcdp_timeout                                                                                           \
  _(EMBRYONIC, 10, "embryonic")                                                                                         \
  _(ESTABLISHED, 240, "established")                                                                                   \
  _(TCP_TRANSITORY, 60, "tcp-transitory")                                                                              \
  _(TCP_ESTABLISHED, 7440, "tcp-established")                                                                          \
  _(SECURITY, 30, "security") // TODO: Needed?

typedef enum {
#define _(name, val, str) VCDP_TIMEOUT_##name,
  foreach_vcdp_timeout
#undef _
    VCDP_N_TIMEOUT
} vcdp_timeout_type_t;

typedef struct {
  /* head of LRU list in which this session is tracked */
  u32 lru_head_index;
  /* index in global LRU list */
  u32 lru_index;
  u32 last_lru_update;
  vcdp_timeout_type_t type;
} vcdp_session_timer_t;

#endif
