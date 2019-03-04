
/*
 * ct6.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <current-year> <your-organization>
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
#ifndef __included_ct6_h__
#define __included_ct6_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/bihash_48_8.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
{
  union
  {
    struct
    {
      /* out2in */
      ip6_address_t src;
      ip6_address_t dst;
      u16 sport;
      u16 dport;
      u8 proto; /* byte 37 */
    };
    u64 as_u64[6];
  };
}) ct6_session_key_t;
/* *INDENT-ON* */

typedef struct
{
  ct6_session_key_t key;
  u32 thread_index;
  u32 next_index;
  u32 prev_index;
  f64 expires;
} ct6_session_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* session lookup table */
  clib_bihash_48_8_t session_hash;
  u8 feature_initialized;

  /* per_thread session pools */
  ct6_session_t **sessions;
  u32 *first_index;
  u32 *last_index;

  /* Config parameters */
  f64 session_timeout_interval;
  uword session_hash_memory;
  u32 max_sessions_per_worker;
  u32 session_hash_buckets;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} ct6_main_t;

extern ct6_main_t ct6_main;

extern vlib_node_registration_t ct6_out2in_node;
extern vlib_node_registration_t ct6_in2out_node;


#endif /* __included_ct6_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
