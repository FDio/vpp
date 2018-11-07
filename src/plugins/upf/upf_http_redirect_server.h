/*
 * upf_http_redirect_server.h - 3GPP TS 29.244 GTP-U UP plug-in header file
 *
 * Copyright (c) 2018 Travelping GmbH
 *
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
#ifndef __included_upf_http_redirect_server_h__
#define __included_upf_http_redirect_server_h__

#include <vnet/vnet.h>
#include <vnet/session/application.h>

typedef struct
{
  u8 **rx_buf;
  svm_msg_q_t **vpp_queue;
  u64 byte_index;

  /* Sever's event queue */
  svm_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  u32 app_index;

  u32 prealloc_fifos;
  u32 private_segment_size;
  u32 fifo_size;
  vlib_main_t *vlib_main;

  u32 num_threads;

  u32 *ip4_listen_session_by_fib_index;
  u32 *ip6_listen_session_by_fib_index;
} http_redirect_server_main_t;

extern http_redirect_server_main_t http_redirect_server_main;

u32 upf_http_redirect_server_create(u32 fib_index, int is_ip4);

static inline u32 upf_http_redirect_session(u32 fib_index, int is_ip4)
{
  http_redirect_server_main_t *hsm = &http_redirect_server_main;

  if (is_ip4)
    {
      vec_validate_init_empty(hsm->ip4_listen_session_by_fib_index, fib_index, 0);

      if (PREDICT_TRUE (hsm->ip4_listen_session_by_fib_index[fib_index] != 0))
	return hsm->ip4_listen_session_by_fib_index[fib_index];
    }
  else
    {
      vec_validate_init_empty(hsm->ip6_listen_session_by_fib_index, fib_index, 0);

      if (PREDICT_TRUE (hsm->ip6_listen_session_by_fib_index[fib_index] != 0))
	return hsm->ip6_listen_session_by_fib_index[fib_index];
    }

  return upf_http_redirect_server_create(fib_index, is_ip4);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
