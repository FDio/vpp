/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

/**
 * @file
 * TODO
 */

#ifndef __included_reass_h
#define __included_reass_h

#include <stdbool.h>
#include <vnet/api_errno.h>
#include <vnet/vnet.h>

typedef enum
{
  REASS_OK = 0,
  REASS_ERR_OVERLAP,
  REASS_ERR_DUPLICATE,
} reass_rc_e;

typedef struct
{
  u16 fragment_first;
  u16 fragment_last;
  u16 range_first;
  u16 range_last;
  u32 next_range_bi;
  u16 ip6_frag_hdr_offset;
  u16 owner_feature_thread_index;
} reass_deep_per_fragment_ctx_t;

typedef enum
{
  REASS_SHALLOW_VIRTUAL = 0,
  REASS_DEEP,
} reass_type_e;

typedef struct
{
  reass_type_e type;		// type of reassembly
  bool overlap_is_error;	// if true, then overlapping fragment is rejected
  bool is_complete;		// if true, then this reassembly is complete
} reass_t;

always_inline reass_rc_e
reass_add_packet (reass_t * reass,
		  u32 frag_start, u32 frag_len, void *fragment,
		  u32 per_fragment_context_data[4])
{
  return REASS_OK;
}

#endif /* __included_ip4_reassembly_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
