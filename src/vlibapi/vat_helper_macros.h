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

/* M: construct, but don't yet send a message */
#define M(T, mp)                                                \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc_as_if_client(sizeof(*mp));            \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T+__plugin_msg_base);      \
    mp->client_index = vam->my_client_index;                    \
} while(0);

#define M2(T, mp, n)                                            \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc_as_if_client(sizeof(*mp)+(n));        \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T+__plugin_msg_base);      \
    mp->client_index = vam->my_client_index;                    \
} while(0);

/* S: send a message */
#define S(mp) (vl_msg_api_send_shmem (vam->vl_input_queue, (u8 *)&mp))

/* W: wait for results, with timeout */
#define W(ret)					\
do {                                            \
    f64 timeout = vat_time_now (vam) + 1.0;     \
    ret = -99;                                  \
                                                \
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
