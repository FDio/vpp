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
#ifndef __included_dslite_h__
#define __included_dslite_h__

#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_24_8.h>
#include <nat/nat.h>

typedef struct
{
  union
  {
    struct
    {
      ip6_address_t softwire_id;
      ip4_address_t addr;
      u16 port;
      u8 proto;
      u8 pad;
    };
    u64 as_u64[3];
  };
} dslite_session_key_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
{
  snat_session_key_t out2in;
  dslite_session_key_t in2out;
  u32 per_b4_index;
  u32 per_b4_list_head_index;
  f64 last_heard;
  u64 total_bytes;
  u32 total_pkts;
  u32 outside_address_index;
}) dslite_session_t;
/* *INDENT-ON* */

typedef struct
{
  ip6_address_t addr;
  u32 sessions_per_b4_list_head_index;
  u32 nsessions;
} dslite_b4_t;

typedef struct
{
  /* Main lookup tables */
  clib_bihash_8_8_t out2in;
  clib_bihash_24_8_t in2out;

  /* Find a B4 */
  clib_bihash_16_8_t b4_hash;

  /* B4 pool */
  dslite_b4_t *b4s;

  /* Session pool */
  dslite_session_t *sessions;

  /* Pool of doubly-linked list elements */
  dlist_elt_t *list_pool;
} dslite_per_thread_data_t;

typedef struct
{
  ip6_address_t aftr_ip6_addr;
  ip4_address_t aftr_ip4_addr;
  dslite_per_thread_data_t *per_thread_data;
  snat_address_t *addr_pool;
  u32 num_workers;
  u32 first_worker_index;
  u16 port_per_thread;
} dslite_main_t;

typedef struct
{
  u32 next_index;
  u32 session_index;
} dslite_trace_t;

#define foreach_dslite_error                    \
_(IN2OUT, "valid in2out DS-Lite packets")       \
_(OUT2IN, "valid out2in DS-Lite packets")       \
_(NO_TRANSLATION, "no translation")             \
_(BAD_IP6_PROTOCOL, "bad ip6 protocol")         \
_(OUT_OF_PORTS, "out of ports")                 \
_(UNSUPPORTED_PROTOCOL, "unsupported protocol") \
_(BAD_ICMP_TYPE, "unsupported icmp type")       \
_(UNKNOWN, "unknown")

typedef enum
{
#define _(sym,str) DSLITE_ERROR_##sym,
  foreach_dslite_error
#undef _
    DSLITE_N_ERROR,
} dslite_error_t;

extern dslite_main_t dslite_main;
extern vlib_node_registration_t dslite_in2out_node;
extern vlib_node_registration_t dslite_in2out_slowpath_node;
extern vlib_node_registration_t dslite_out2in_node;

void dslite_init (vlib_main_t * vm);
int dslite_set_aftr_ip6_addr (dslite_main_t * dm, ip6_address_t * addr);
int dslite_add_del_pool_addr (dslite_main_t * dm, ip4_address_t * addr,
			      u8 is_add);
u8 *format_dslite_trace (u8 * s, va_list * args);

#endif /* __included_dslite_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
