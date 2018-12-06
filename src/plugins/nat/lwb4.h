/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#ifndef __included_lwb4_h__
#define __included_lwb4_h__

#include <vppinfra/bihash_8_8.h>
#include <nat/nat.h>

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t addr;
      u16 port;
      u8 proto;
      u8 pad;
    };
    u64 as_u64;
  };
} lwb4_session_key_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
{
  snat_session_key_t out2in;
  lwb4_session_key_t in2out;
  u32 per_b4_index;
  u32 per_b4_list_head_index;
  f64 last_heard;
  u64 total_bytes;
  u32 total_pkts;
  u32 outside_address_index;
}) lwb4_session_t;
/* *INDENT-ON* */

typedef struct
{
  /* Main lookup tables */
  clib_bihash_8_8_t out2in;
  clib_bihash_8_8_t in2out;

  /* B4 info */
  ip6_address_t addr;
  u32 sessions_list_head_index;
  u32 nsessions;

  /* Session pool */
  lwb4_session_t *sessions;

  /* Pool of doubly-linked list elements */
  dlist_elt_t *list_pool;
} lwb4_per_thread_data_t;

typedef struct
{
  ip6_address_t aftr_ip6_addr;
  ip6_address_t b4_ip6_addr;
  ip4_address_t b4_ip4_addr;

  u16 psid;
  u8 psid_length;
  u8 psid_shift;

  snat_address_t snat_addr;
  snat_address_t *addr_pool;
  lwb4_per_thread_data_t *per_thread_data;
  u32 num_workers;
  u32 first_worker_index;
} lwb4_main_t;

typedef struct
{
  u32 next_index;
  u32 session_index;
} lwb4_trace_t;

#define foreach_lwb4_error                      \
_(IN2OUT, "valid in2out lwB4 packets")          \
_(OUT2IN, "valid out2in lwB4 packets")          \
_(NO_TRANSLATION, "no translation")             \
_(BAD_IP6_PROTOCOL, "bad ip6 protocol")         \
_(OUT_OF_PORTS, "out of ports")                 \
_(UNSUPPORTED_PROTOCOL, "unsupported protocol") \
_(BAD_ICMP_TYPE, "unsupported icmp type")       \
_(BAD_ICMP_SRC, "wrong src address on icmp")    \
_(UNKNOWN, "unknown")

typedef enum
{
#define _(sym,str) LWB4_ERROR_##sym,
  foreach_lwb4_error
#undef _
    LWB4_N_ERROR,
} lwb4_error_t;

extern lwb4_main_t lwb4_main;
extern vlib_node_registration_t lwb4_in2out_node;
extern vlib_node_registration_t lwb4_in2out_slowpath_node;
extern vlib_node_registration_t lwb4_out2in_node;

void lwb4_init (vlib_main_t * vm);
int lwb4_set_aftr_ip6_addr (lwb4_main_t * dm, ip6_address_t * addr);
int lwb4_set_b4_params (lwb4_main_t * dm, ip6_address_t * ip6_addr,
			ip4_address_t * ip4_addr, u8 psid_length,
			u8 psid_shift, u16 psid);

u8 *format_lwb4_trace (u8 * s, va_list * args);

#endif /* __included_lwb4_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
