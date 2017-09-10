/*
 *------------------------------------------------------------------
 * vat_helper_macros.h - collect api client helper macros in one place
 *
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
#ifndef __vat_helper_macros_h__
#define __vat_helper_macros_h__

void vat_socket_read_reply (vat_main_t *vam);

/* M: construct, but don't yet send a message */
#define M(T, mp)                                                \
do {                                                            \
    vam->result_ready = 0;                                      \
    if (vam->socket_tx_buffer)                                  \
      {                                                         \
        mp = (void *)vam->socket_tx_buffer;                     \
        vam->socket_tx_nbytes = sizeof (*mp);                   \
      }                                                         \
    else                                                        \
      mp = vl_msg_api_alloc_as_if_client(sizeof(*mp));          \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T+__plugin_msg_base);      \
    mp->client_index = vam->my_client_index;                    \
} while(0);

/* MPING: construct a control-ping message, don't yet */
#define MPING(T, mp)                                            \
do {                                                            \
    vam->result_ready = 0;                                      \
    if (vam->socket_tx_buffer)                                  \
      {                                                         \
        mp = (void *)vam->socket_tx_buffer;                     \
        vam->socket_tx_nbytes = sizeof (*mp);                   \
      }                                                         \
    else                                                        \
      mp = vl_msg_api_alloc_as_if_client(sizeof(*mp));          \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T+__plugin_msg_base);      \
    mp->client_index = vam->my_client_index;                    \
    vam->control_pings_outstanding++;                           \
} while(0);

#define M2(T, mp, n)                                            \
do {                                                            \
    vam->result_ready = 0;                                      \
    if (vam->socket_tx_buffer)                                  \
      {                                                         \
        mp = (void *)vam->socket_tx_buffer;                     \
        vam->socket_tx_nbytes = sizeof (*mp) + n;               \
      }                                                         \
    else                                                        \
      mp = vl_msg_api_alloc_as_if_client(sizeof(*mp) + n);      \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T+__plugin_msg_base);      \
    mp->client_index = vam->my_client_index;                    \
} while(0);

/* S: send a message */
#define S(mp)                                                   \
do {                                                            \
  int n;                                                        \
  if (vam->socket_tx_buffer)                                    \
    {                                                           \
      msgbuf_t msgbuf;                                          \
                                                                \
      msgbuf.q = 0;                                             \
      msgbuf.gc_mark_timestamp = 0;                             \
      msgbuf.data_len = ntohl(vam->socket_tx_nbytes);           \
                                                                \
      n = write (vam->socket_fd, &msgbuf, sizeof (msgbuf));     \
      if (n < sizeof (msgbuf))                                  \
        clib_unix_warning ("socket write (msgbuf)");            \
                                                                \
      n = write (vam->socket_fd, vam->socket_tx_buffer,         \
                   vam->socket_tx_nbytes);                      \
      if (n < vam->socket_tx_nbytes)                            \
        clib_unix_warning ("socket write (msg)");               \
    }                                                           \
  else                                                          \
    vl_msg_api_send_shmem (vam->vl_input_queue, (u8 *)&mp);     \
 } while (0);

/* W: wait for results, with timeout */
#define W(ret)					\
do {                                            \
    f64 timeout = vat_time_now (vam) + 1.0;     \
    ret = -99;                                  \
                                                \
    vat_socket_read_reply (vam);		\
    while (vat_time_now (vam) < timeout) {      \
        if (vam->result_ready == 1) {           \
            ret = vam->retval;                  \
            break;                              \
        }                                       \
        vat_suspend (vam->vlib_main, 1e-5);     \
    }                                           \
} while(0);

/* W2: wait for results, with timeout */
#define W2(ret, body)				\
do {                                            \
    f64 timeout = vat_time_now (vam) + 1.0;     \
    ret = -99;                                  \
                                                \
    vat_socket_read_reply (vam);		\
    while (vat_time_now (vam) < timeout) {      \
        if (vam->result_ready == 1) {           \
	  (body);                               \
	  ret = vam->retval;                    \
          break;                                \
        }                                       \
        vat_suspend (vam->vlib_main, 1e-5);     \
    }                                           \
} while(0);


#endif /* __vat_helper_macros_h__ */
