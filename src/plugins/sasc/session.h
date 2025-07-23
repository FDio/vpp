// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#ifndef __SASC_SESSION_H__
#define __SASC_SESSION_H__

#include "sasc.h"

bool sasc_session_is_expired(sasc_session_t *session, u32 now);
void sasc_session_remove(sasc_main_t *sasc, sasc_session_t *session, u32 thread_index, u32 session_index);
void sasc_session_timer_update(sasc_session_t *session, u32 thread_index);
sasc_session_t *sasc_create_session(u16 tenant_idx, sasc_session_key_t *primary, sasc_session_key_t *secondary,
                                    bool is_static, u32 *flow_index);
void sasc_session_clear(void);
sasc_session_t *sasc_lookup_session(u32 context_id, ip_address_t *src, u16 sport, u8 protocol, ip_address_t *dst,
                                    u16 dport);

int sasc_session_generate_reverse_key(sasc_session_key_t *forward_key, sasc_session_key_t *reverse_key);
bool sasc_session_walk_and_expire(u32 max_walk_entries, u32 max_expire_entries, u32 *cursor);

/* Callback function type for session expiry */
typedef void (*sasc_session_expiry_cb_t)(u32 *session_indices);

/* Callback registration functions */
int sasc_session_expiry_cb_register(sasc_session_expiry_cb_t callback);
int sasc_session_expiry_cb_unregister(sasc_session_expiry_cb_t callback);

#endif /* __SASC_SESSION_H__ */
