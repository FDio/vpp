/*
 *------------------------------------------------------------------
 * nat64_tcp_sm.h - Stateful NAT64 translation TCP State machine 
 *
 * Copyright (c) 2011 Cisco and/or its affiliates.
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
#ifndef __NAT64_TCP_SM_H__
#define __NAT64_TCP_SM_H__


/* TCP States */
typedef enum {
    TCP_CLOSED,
    TCP_V4_INIT,
    TCP_V6_INIT, 
    TCP_ESTABLISHED,
    TCP_V4_FIN_RCV,
    TCP_V6_FIN_RCV,
    TCP_V4V6_FIN_RCV,
    TCP_TRANS,
    TCP_NONE
} nat64_tcp_states;

/* TCP Events */
typedef enum {
    TCP_TIMEOUT_EV,
    TCP_V6_SYN_EV,
    TCP_V4_SYN_EV,
    TCP_V6_FIN_EV,
    TCP_V4_FIN_EV,
    TCP_V6_RST_EV,
    TCP_V4_RST_EV,
    TCP_DEFAULT_EV,
    TCP_EV_COUNT
} nat64_tcp_events;

/* TCP Actions */
typedef enum {
    TCP_FORWARD,
    TCP_COND_FORWARD, /* Conditional forward, based on presence of
                       * session and bib entries */
    TCP_STORE,
    TCP_PROBE,
    TCP_CREATE_SESSION,
    TCP_DELETE_SESSION,
    TCP_DROP,
    TCP_ACTION_NONE,
    TCP_ACTION_COUNT
} nat64_tcp_actions;

typedef struct {
    nat64_tcp_states next_state;
    nat64_tcp_actions action;
} nat64_tcp_trans_t;

typedef struct {
    nat64_tcp_trans_t event[TCP_EV_COUNT];
} nat64_tcp_state_trans_t;

extern nat64_tcp_state_trans_t nat64_tcp_sm_lookup[TCP_NONE];  

/*
inline void
nat64_update_v6_to_v4_tcp (nat64_v6_to_v4_pipeline_data_t *pctx_ptr,
                            nat64_bib_entry_t *bib_ptr);

inline u8 nat64_v6_to_v4_tcp_perform_action (
      spp_ctx_t *ctx,
      nat64_v6_to_v4_pipeline_data_t *pctx_ptr,
      nat64_bib_entry_t *bib_db,
      nat64_session_entry_t *session_db);

inline void
nat64_copy_tcp_into_pctx (nat64_v6_to_v4_pipeline_data_t *pctx_ptr);
*/



#endif
