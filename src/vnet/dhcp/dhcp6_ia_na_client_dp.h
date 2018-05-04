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

#ifndef included_vnet_dhcp6_client_dp_h
#define included_vnet_dhcp6_client_dp_h

#include <vlib/vlib.h>
#include <vnet/dhcp/dhcp6_client_common_dp.h>

typedef struct
{
  u32 preferred_lt;
  u32 valid_lt;
  ip6_address_t address;
} dhcp6_send_client_message_params_address_t;

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
  dhcp6_send_client_message_params_address_t *addresses;
} dhcp6_send_client_message_params_t;

typedef struct
{
  u8 entry_valid;
  u8 keep_sending_client_message;	/* when true then next fields are valid */
  dhcp6_send_client_message_params_t params;
  f64 transaction_start;
  f64 sleep_interval;
  f64 due_time;
  u32 n_left;
  f64 start_time;
  u32 transaction_id;
  vlib_buffer_t *buffer;
  u32 elapsed_pos;
  u32 adj_index;
} dhcp6_ia_na_client_state_t;

typedef struct
{
  dhcp6_ia_na_client_state_t *client_state_by_sw_if_index;

  uword publisher_node;
  uword publisher_et;

  u32 seed;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} dhcp6_ia_na_client_main_t;

extern dhcp6_ia_na_client_main_t dhcp6_ia_na_client_main;

typedef struct
{
  ip6_address_t address;
  u32 valid_time;
  u32 preferred_time;
  u16 status_code;
} dhcp6_address_info_t;

typedef struct
{
  dhcp6_report_common_t body;
  u32 n_addresses;
  dhcp6_address_info_t *addresses;
} address_report_t;

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

void dhcp6_send_client_message (vlib_main_t * vm, u32 sw_if_index, u8 stop,
				dhcp6_send_client_message_params_t * params);
void dhcp6_set_publisher_node (uword node_index, uword event_type);
int dhcp6_publish_report (address_report_t * r);


void
  vl_api_want_dhcp6_reply_events_t_handler
  (vl_api_want_dhcp6_reply_events_t * mp);
void
  vl_api_dhcp6_send_client_message_t_handler
  (vl_api_dhcp6_send_client_message_t * mp);
void
  vl_api_dhcp6_clients_enable_disable_t_handler
  (vl_api_dhcp6_clients_enable_disable_t * mp);

extern vlib_node_registration_t dhcp6_reply_process_node;

enum
{ DHCP6_DP_REPLY_REPORT, DHCP6_DP_REPORT_MAX };

typedef struct _vnet_dhcp6_reply_function_list_elt
{
  struct _vnet_dhcp6_reply_function_list_elt *next_dhcp6_reply_event_function;
  clib_error_t *(*fp) (vl_api_dhcp6_reply_event_t * mp);
} _vnet_dhcp6_reply_event_function_list_elt_t;

typedef struct
{
  _vnet_dhcp6_reply_event_function_list_elt_t *functions;
} dhcp6_ia_na_client_public_main_t;

extern dhcp6_ia_na_client_public_main_t dhcp6_ia_na_client_public_main;

#define VNET_DHCP6_REPLY_EVENT_FUNCTION(f)                                \
                                                                          \
static void __vnet_dhcp6_reply_event_function_init_##f (void)             \
    __attribute__((__constructor__)) ;                                    \
                                                                          \
static void __vnet_dhcp6_reply_event_function_init_##f (void)             \
{                                                                         \
 dhcp6_ia_na_client_public_main_t * nm = &dhcp6_ia_na_client_public_main; \
 static _vnet_dhcp6_reply_event_function_list_elt_t init_function;        \
 init_function.next_dhcp6_reply_event_function = nm->functions;           \
 nm->functions = &init_function;                                          \
 init_function.fp = (void *) &f;                                          \
}                                                                         \
                                                                          \
static void __vnet_dhcp6_reply_event_function_deinit_##f (void)           \
    __attribute__((__destructor__)) ;                                     \
                                                                          \
static void __vnet_dhcp6_reply_event_function_deinit_##f (void)           \
{                                                                         \
 dhcp6_ia_na_client_public_main_t * nm = &dhcp6_ia_na_client_public_main; \
 _vnet_dhcp6_reply_event_function_list_elt_t *next;                       \
 if (nm->functions->fp == (void *) &f)                                    \
    {                                                                     \
      nm->functions =                                                     \
        nm->functions->next_dhcp6_reply_event_function;                   \
      return;                                                             \
    }                                                                     \
  next = nm->functions;                                                   \
  while (next->next_dhcp6_reply_event_function)                           \
    {                                                                     \
      if (next->next_dhcp6_reply_event_function->fp == (void *) &f)       \
        {                                                                 \
          next->next_dhcp6_reply_event_function =                         \
            next->next_dhcp6_reply_event_function->next_dhcp6_reply_event_function; \
          return;                                                         \
        }                                                                 \
      next = next->next_dhcp6_reply_event_function;                       \
    }                                                                     \
}

#endif /* included_vnet_dhcp6_client_dp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
