/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_vnet_dhcp6_pd_client_dp_h
#define included_vnet_dhcp6_pd_client_dp_h

#include <vlib/vlib.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

typedef struct
{
  u32 preferred_lt;
  u32 valid_lt;
  ip6_address_t prefix;
  u8 prefix_length;
} dhcp6_pd_send_client_message_params_prefix_t;

typedef struct
{
  u32 sw_if_index;
  u32 server_index;
  u32 irt;
  u32 mrt;
  u32 mrc;
  u32 mrd;
  u8 msg_type;
  u32 T1;
  u32 T2;
  dhcp6_pd_send_client_message_params_prefix_t *prefixes;
} dhcp6_pd_send_client_message_params_t;

void dhcp6_pd_send_client_message (vlib_main_t * vm, u32 sw_if_index, u8 stop,
				   dhcp6_pd_send_client_message_params_t *
				   params);
void dhcp6_pd_set_publisher_node (uword node_index, uword event_type);
void dhcp6_clients_enable_disable (u8 enable);

void
  vl_api_want_dhcp6_pd_reply_events_t_handler
  (vl_api_want_dhcp6_pd_reply_events_t * mp);
void
  vl_api_dhcp6_pd_send_client_message_t_handler
  (vl_api_dhcp6_pd_send_client_message_t * mp);
void
  vl_api_dhcp6_clients_enable_disable_t_handler
  (vl_api_dhcp6_clients_enable_disable_t * mp);

extern vlib_node_registration_t dhcp6_pd_reply_process_node;

enum
{ DHCP6_PD_DP_REPLY_REPORT, REPORT_MAX };

typedef struct _vnet_dhcp6_pd_reply_function_list_elt
{
  struct _vnet_dhcp6_pd_reply_function_list_elt
    *next_dhcp6_pd_reply_event_function;
  clib_error_t *(*fp) (vl_api_dhcp6_pd_reply_event_t * mp);
} _vnet_dhcp6_pd_reply_event_function_list_elt_t;

typedef struct
{
  _vnet_dhcp6_pd_reply_event_function_list_elt_t *functions;
} dhcp6_pd_client_public_main_t;

extern dhcp6_pd_client_public_main_t dhcp6_pd_client_public_main;

#define VNET_DHCP6_PD_REPLY_EVENT_FUNCTION(f)                             \
                                                                          \
static void __vnet_dhcp6_pd_reply_event_function_init_##f (void)          \
    __attribute__((__constructor__)) ;                                    \
                                                                          \
static void __vnet_dhcp6_pd_reply_event_function_init_##f (void)          \
{                                                                         \
 dhcp6_pd_client_public_main_t * nm = &dhcp6_pd_client_public_main;       \
 static _vnet_dhcp6_pd_reply_event_function_list_elt_t init_function;     \
 init_function.next_dhcp6_pd_reply_event_function = nm->functions;        \
 nm->functions = &init_function;                                          \
 init_function.fp = (void *) &f;                                          \
}                                                                         \
                                                                          \
static void __vnet_dhcp6_pd_reply_event_function_deinit_##f (void)        \
    __attribute__((__destructor__)) ;                                     \
                                                                          \
static void __vnet_dhcp6_pd_reply_event_function_deinit_##f (void)        \
{                                                                         \
 dhcp6_pd_client_public_main_t * nm = &dhcp6_pd_client_public_main;       \
 _vnet_dhcp6_pd_reply_event_function_list_elt_t *next;                    \
 if (nm->functions->fp == (void *) &f)                                    \
    {                                                                     \
      nm->functions =                                                     \
        nm->functions->next_dhcp6_pd_reply_event_function;                \
      return;                                                             \
    }                                                                     \
  next = nm->functions;                                                   \
  while (next->next_dhcp6_pd_reply_event_function)                        \
    {                                                                     \
      if (next->next_dhcp6_pd_reply_event_function->fp == (void *) &f)    \
        {                                                                 \
          next->next_dhcp6_pd_reply_event_function =                      \
            next->next_dhcp6_pd_reply_event_function->next_dhcp6_pd_reply_event_function; \
          return;                                                         \
        }                                                                 \
      next = next->next_dhcp6_pd_reply_event_function;                    \
    }                                                                     \
}

#endif /* included_vnet_dhcp6_pd_client_dp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
