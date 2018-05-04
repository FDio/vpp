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

#ifndef included_vnet_dhcp6_client_common_dp_h
#define included_vnet_dhcp6_client_common_dp_h

#include <vlib/vlib.h>
#include <vnet/dhcp/dhcp6_client_common_dp.h>
#include <vnet/dhcp/dhcp6_packet.h>
#include <vnet/vnet_msg_enum.h>
#include <vlibapi/api_common.h>
#include <vlibmemory/api.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

typedef struct
{
  u32 sw_if_index;
  u32 server_index;
  u8 msg_type;
  u32 T1;
  u32 T2;
  u16 inner_status_code;
  u16 status_code;
  u8 preference;
} dhcp6_report_common_t;

typedef struct
{
  u8 *data;
  u16 len;
} server_id_t;

typedef struct
{
  server_id_t *server_ids;
} dhcp6_client_common_main_t;

extern dhcp6_client_common_main_t dhcp6_client_common_main;

typedef union
{
  CLIB_PACKED (struct
	       {
	       u16 duid_type;
	       u16 hardware_type;
	       u8 lla[6];
	       });
  char bin_string[10];
} dhcpv6_duid_ll_string_t;

extern dhcpv6_duid_ll_string_t client_duid;
#define CLIENT_DUID_LENGTH sizeof (client_duid)
#define DHCPV6_CLIENT_IAID 1

void dhcp6_clients_enable_disable (u8 enable);
u32 server_index_get_or_create (u8 * data, u16 len);

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

void vl_api_dhcp6_duid_ll_set_t_handler (vl_api_dhcp6_duid_ll_set_t * mp);

static_always_inline f64
random_f64_from_to (f64 from, f64 to)
{
  static u32 seed = 0;
  static u8 seed_set = 0;
  if (!seed_set)
    {
      seed = random_default_seed ();
      seed_set = 1;
    }
  return random_f64 (&seed) * (to - from) + from;
}

static const ip6_address_t all_dhcp6_relay_agents_and_servers = {
  .as_u8 = {
	    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02}
};

#endif /* included_vnet_dhcp6_client_common_dp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
