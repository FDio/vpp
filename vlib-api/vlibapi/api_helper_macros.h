/*
 *------------------------------------------------------------------
 * api_helper_macros.h - message handler helper macros
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


#ifndef __api_helper_macros_h__
#define __api_helper_macros_h__

#define f64_endian(a)
#define f64_print(a,b)

#define REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t));                               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define REPLY_MACRO2(t, body)                                   \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t));                               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define REPLY_MACRO3(t, n, body)				\
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp) + n);                 \
    rmp->_vl_msg_id = ntohs((t));                               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define REPLY_MACRO4(t, n, body)                                \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    u8 is_error = 0;                                            \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc_or_null (sizeof (*rmp) + n);         \
    if (!rmp)                                                   \
      {                                                         \
        /* if there isn't enough memory, try to allocate */     \
        /* some at least for returning an error */              \
        rmp = vl_msg_api_alloc (sizeof (*rmp));                 \
        if (!rmp)                                               \
          return;                                               \
                                                                \
        memset (rmp, 0, sizeof (*rmp));                         \
        rv = VNET_API_ERROR_TABLE_TOO_BIG;                      \
        is_error = 1;                                           \
      }                                                         \
    rmp->_vl_msg_id = ntohs((t));                               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
    if (!is_error)                                              \
      do {body;} while (0);                                     \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

/* "trust, but verify" */

#define VALIDATE_SW_IF_INDEX(mp)				\
 do { u32 __sw_if_index = ntohl(mp->sw_if_index);		\
    vnet_main_t *__vnm = vnet_get_main();                       \
    if (pool_is_free_index(__vnm->interface_main.sw_interfaces, \
                           __sw_if_index)) {                    \
        rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;                \
        goto bad_sw_if_index;                                   \
    }                                                           \
} while(0);

#define BAD_SW_IF_INDEX_LABEL                   \
do {                                            \
bad_sw_if_index:                                \
    ;                                           \
} while (0);

#define VALIDATE_RX_SW_IF_INDEX(mp)				\
 do { u32 __rx_sw_if_index = ntohl(mp->rx_sw_if_index);		\
    vnet_main_t *__vnm = vnet_get_main();                       \
    if (pool_is_free_index(__vnm->interface_main.sw_interfaces, \
                           __rx_sw_if_index)) {			\
        rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;                \
        goto bad_rx_sw_if_index;				\
    }                                                           \
} while(0);

#define BAD_RX_SW_IF_INDEX_LABEL		\
do {                                            \
bad_rx_sw_if_index:				\
    ;                                           \
} while (0);

#define VALIDATE_TX_SW_IF_INDEX(mp)				\
 do { u32 __tx_sw_if_index = ntohl(mp->tx_sw_if_index);		\
    vnet_main_t *__vnm = vnet_get_main();                       \
    if (pool_is_free_index(__vnm->interface_main.sw_interfaces, \
                           __tx_sw_if_index)) {			\
        rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;                \
        goto bad_tx_sw_if_index;				\
    }                                                           \
} while(0);

#define BAD_TX_SW_IF_INDEX_LABEL		\
do {                                            \
bad_tx_sw_if_index:				\
    ;                                           \
} while (0);

#endif /* __api_helper_macros_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
