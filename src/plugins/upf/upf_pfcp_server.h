/*
 * Copyright(c) 2017 Travelping GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _UPF_SX_SERVER_H
#define _UPF_SX_SERVER_H

#include <time.h>
#include "upf.h"
#include "pfcp.h"
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

#define PFCP_HB_INTERVAL 10
#define PFCP_SERVER_HB_TIMER 0
#define PFCP_SERVER_T1       1

typedef struct
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u32 fib_index;

  struct {
    ip46_address_t address;
    u16 port;
  } rmt;

  struct {
    ip46_address_t address;
    u16 port;
  } lcl;

  u32 pfcp_endpoint;
  u32 node;
  u32 seq_no;

  u32 timer;
  u32 n1;
  u32 t1;

  union {
    u8 * data;
    pfcp_header_t * hdr;
  };
} sx_msg_t;

typedef struct
{
  /* Sx Node Id is either IPv4, IPv6 or FQDN */
  u8 * node_id;
} sx_node_t;

typedef struct
{
  u32 seq_no;
  time_t start_time;
  ip46_address_t address;
  f64 now;

  TWT(tw_timer_wheel) timer;
  sx_msg_t * msg_pool;
  uword * request_q;

  vlib_main_t *vlib_main;
} sx_server_main_t;

extern sx_server_main_t sx_server_main;

extern vlib_node_registration_t sx4_input_node;
extern vlib_node_registration_t sx6_input_node;

#define UDP_DST_PORT_SX 8805

void upf_pfcp_session_stop_urr_time(urr_time_t *t);
void upf_pfcp_session_start_stop_urr_time(u32 si, f64 now, urr_time_t *t, u8 start_it);
void upf_pfcp_session_start_stop_urr_time_abs(u32 si, f64 now, urr_time_t *t);

u32 upf_pfcp_server_start_timer(u8 type, u32 id, u32 seconds);
void upf_pfcp_server_stop_timer(u32 handle);

int upf_pfcp_send_request(upf_session_t * sx, u8 type, struct pfcp_group * grp);

sx_msg_t * upf_pfcp_make_response(sx_msg_t * req, size_t len);
int upf_pfcp_send_response(sx_msg_t * req, u64 cp_seid, u8 type, struct pfcp_group * grp);

void upf_pfcp_server_session_usage_report(upf_session_t *sx);

void upf_pfcp_handle_input (vlib_main_t * vm, vlib_buffer_t *b, int is_ip4);

clib_error_t * sx_server_main_init (vlib_main_t * vm);

static inline void init_sx_msg(sx_msg_t * m)
{
  memset(m, 0, sizeof(*m));
  m->pfcp_endpoint = ~0;
  m->node = ~0;
}

static inline void sx_msg_free (sx_server_main_t *sxsm, sx_msg_t * m)
{
  if (!m)
    return;

  vec_free(m->data);
  pool_put (sxsm->msg_pool, m);
}

#endif /* _UPF_SX_SERVER_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
