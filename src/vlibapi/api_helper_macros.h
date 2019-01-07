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

#ifndef REPLY_MSG_ID_BASE
#define REPLY_MSG_ID_BASE 0
#endif

#define REPLY_MACRO(t)                                                  \
do {                                                                    \
    vl_api_registration_t *rp;                                          \
    rv = vl_msg_api_pd_handler (mp, rv);                                \
    rp = vl_api_client_index_to_registration (mp->client_index);        \
    if (rp == 0)                                                        \
      return;                                                           \
                                                                        \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                             \
    rmp->_vl_msg_id = htons((t)+(REPLY_MSG_ID_BASE));                   \
    rmp->context = mp->context;                                         \
    rmp->retval = ntohl(rv);                                            \
                                                                        \
    vl_api_send_msg (rp, (u8 *)rmp);                                    \
} while(0);

#define REPLY_MACRO2(t, body)                                           \
do {                                                                    \
    vl_api_registration_t *rp;                                          \
    rv = vl_msg_api_pd_handler (mp, rv);                                \
    rp = vl_api_client_index_to_registration (mp->client_index);        \
    if (rp == 0)                                                        \
      return;                                                           \
                                                                        \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                             \
    rmp->_vl_msg_id = htons((t)+(REPLY_MSG_ID_BASE));                   \
    rmp->context = mp->context;                                         \
    rmp->retval = ntohl(rv);                                            \
    do {body;} while (0);                                               \
    vl_api_send_msg (rp, (u8 *)rmp);                                    \
} while(0);

#define REPLY_MACRO3(t, n, body)                                        \
do {                                                                    \
    vl_api_registration_t *rp;                                          \
    rv = vl_msg_api_pd_handler (mp, rv);                                \
    rp = vl_api_client_index_to_registration (mp->client_index);        \
    if (rp == 0)                                                        \
      return;                                                           \
                                                                        \
    rmp = vl_msg_api_alloc (sizeof (*rmp) + n);                         \
    rmp->_vl_msg_id = htons((t)+(REPLY_MSG_ID_BASE));                   \
    rmp->context = mp->context;                                         \
    rmp->retval = ntohl(rv);                                            \
    do {body;} while (0);                                               \
    vl_api_send_msg (rp, (u8 *)rmp);                                    \
} while(0);

#define REPLY_MACRO4(t, n, body)                                        \
do {                                                                    \
    vl_api_registration_t *rp;                                          \
    u8 is_error = 0;                                                    \
    rv = vl_msg_api_pd_handler (mp, rv);                                \
                                                                        \
    rp = vl_api_client_index_to_registration (mp->client_index);        \
    if (rp == 0)                                                        \
      return;                                                           \
                                                                        \
    rmp = vl_msg_api_alloc_or_null (sizeof (*rmp) + n);                 \
    if (!rmp)                                                           \
      {                                                                 \
        /* if there isn't enough memory, try to allocate */             \
        /* some at least for returning an error */                      \
        rmp = vl_msg_api_alloc (sizeof (*rmp));                         \
        if (!rmp)                                                       \
          return;                                                       \
                                                                        \
        clib_memset (rmp, 0, sizeof (*rmp));                                 \
        rv = VNET_API_ERROR_TABLE_TOO_BIG;                              \
        is_error = 1;                                                   \
      }                                                                 \
    rmp->_vl_msg_id = htons((t)+(REPLY_MSG_ID_BASE));                   \
    rmp->context = mp->context;                                         \
    rmp->retval = ntohl(rv);                                            \
    if (!is_error)                                                      \
      do {body;} while (0);                                             \
    vl_api_send_msg (rp, (u8 *)rmp);                                    \
} while(0);

/* "trust, but verify" */

static inline uword
vnet_sw_if_index_is_api_valid (u32 sw_if_index)
{
  return vnet_sw_interface_is_api_valid (vnet_get_main (), sw_if_index);
}

#define VALIDATE_SW_IF_INDEX(mp)				\
 do { u32 __sw_if_index = ntohl((mp)->sw_if_index);		\
    if (!vnet_sw_if_index_is_api_valid(__sw_if_index)) {        \
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
 do { u32 __rx_sw_if_index = ntohl((mp)->rx_sw_if_index);       \
    if (!vnet_sw_if_index_is_api_valid(__rx_sw_if_index)) {     \
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
    if (!vnet_sw_if_index_is_api_valid(__tx_sw_if_index)) {     \
        rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;                \
        goto bad_tx_sw_if_index;				\
    }                                                           \
} while(0);

#define BAD_TX_SW_IF_INDEX_LABEL		\
do {                                            \
bad_tx_sw_if_index:				\
    ;                                           \
} while (0);

#define VALIDATE_BD_ID(mp)			\
 do { u32 __rx_bd_id = ntohl(mp->bd_id);	\
    if (__rx_bd_id > L2_BD_ID_MAX) {     	\
        rv = VNET_API_ERROR_BD_ID_EXCEED_MAX;	\
        goto bad_bd_id;				\
    }						\
} while(0);

#define BAD_BD_ID_LABEL				\
do {                                            \
bad_bd_id:					\
    ;                                           \
} while (0);

#define pub_sub_handler(lca,UCA)                                        \
static void vl_api_want_##lca##_t_handler (                             \
    vl_api_want_##lca##_t *mp)                                          \
{                                                                       \
    vpe_api_main_t *vam = &vpe_api_main;                                \
    vpe_client_registration_t *rp;                                      \
    vl_api_want_##lca##_reply_t *rmp;                                   \
    uword *p;                                                           \
    i32 rv = 0;                                                         \
                                                                        \
    p = hash_get (vam->lca##_registration_hash, mp->client_index);      \
    if (p) {                                                            \
        if (mp->enable_disable) {                                       \
	    clib_warning ("pid %d: already enabled...", ntohl(mp->pid)); \
            rv = VNET_API_ERROR_INVALID_REGISTRATION;                   \
            goto reply;                                                 \
        } else {                                                        \
            rp = pool_elt_at_index (vam->lca##_registrations, p[0]);    \
            pool_put (vam->lca##_registrations, rp);                    \
            hash_unset (vam->lca##_registration_hash,                   \
                mp->client_index);                                      \
            goto reply;                                                 \
        }                                                               \
    }                                                                   \
    if (mp->enable_disable == 0) {                                      \
        clib_warning ("pid %d: already disabled...", mp->pid);          \
        rv = VNET_API_ERROR_INVALID_REGISTRATION;                       \
        goto reply;                                                     \
    }                                                                   \
    pool_get (vam->lca##_registrations, rp);                            \
    rp->client_index = mp->client_index;                                \
    rp->client_pid = mp->pid;                                           \
    hash_set (vam->lca##_registration_hash, rp->client_index,           \
              rp - vam->lca##_registrations);                           \
                                                                        \
reply:                                                                  \
    REPLY_MACRO (VL_API_WANT_##UCA##_REPLY);                            \
}                                                                       \
                                                                        \
static clib_error_t * vl_api_want_##lca##_t_reaper (u32 client_index)   \
{                                                                       \
    vpe_api_main_t *vam = &vpe_api_main;                                \
    vpe_client_registration_t *rp;                                      \
    uword *p;                                                           \
                                                                        \
    p = hash_get (vam->lca##_registration_hash, client_index);          \
    if (p)                                                              \
      {                                                                 \
        rp = pool_elt_at_index (vam->lca##_registrations, p[0]);        \
        pool_put (vam->lca##_registrations, rp);                        \
        hash_unset (vam->lca##_registration_hash, client_index);        \
      }                                                                 \
    return (NULL);                                                      \
}                                                                       \
                                                                        \
VL_MSG_API_REAPER_FUNCTION (vl_api_want_##lca##_t_reaper);              \

#define foreach_registration_hash               \
_(interface_events)                             \
_(to_netconf_server)                            \
_(from_netconf_server)                          \
_(to_netconf_client)                            \
_(from_netconf_client)                          \
_(oam_events)                                   \
_(bfd_events)                                   \
_(wc_ip6_nd_events)                             \
_(wc_ip4_arp_events)                            \
_(ip6_ra_events)                                \
_(dhcp6_pd_reply_events)                        \
_(dhcp6_reply_events)

typedef struct
{
  u32 client_index;		/* in memclnt registration pool */
  u32 client_pid;
} vpe_client_registration_t;

struct _vl_api_ip4_arp_event;
struct _vl_api_ip6_nd_event;

typedef struct
{
#define _(a) uword *a##_registration_hash;              \
    vpe_client_registration_t * a##_registrations;
  foreach_registration_hash
#undef _
    /* notifications happen really early in the game */
  u8 link_state_process_up;

  /* ip4 arp event registration pool */
  struct _vl_api_ip4_arp_event *arp_events;

  /* ip6 nd event registration pool */
  struct _vl_api_ip6_nd_event *nd_events;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} vpe_api_main_t;

extern vpe_api_main_t vpe_api_main;

#endif /* __api_helper_macros_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
