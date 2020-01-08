/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __MATCH_TURBO_H__
#define __MATCH_TURBO_H__

#include <vppinfra/bitmap.h>
#include <vnet/match/match_set.h>

#define MATCH_TURBO_STRIDE_BYTES 2
#define MATCH_TURBO_STRIDE_BITS (MATCH_TURBO_STRIDE_BYTES * 8)
#define MATCH_TURBO_STRIDE_N_BUCKETS 0x10000

typedef struct match_turbo_lkup_t_
{
  clib_bitmap_t *mtl_any;
  // FIXME make this a vector
  clib_bitmap_t *mtl_lkup[MATCH_TURBO_STRIDE_N_BUCKETS];
} match_turbo_lkup_t;

typedef struct match_turbo_table_ip4_t_
{
  match_turbo_lkup_t mtti4_lkup[2];
} match_turbo_table_ip4_t;

typedef struct match_turbo_table_ip6_t_
{
  match_turbo_lkup_t mtti6_lkup[8];
} match_turbo_table_ip6_t;

/* typedef struct match_turbo_table_proto_t_ */
/* { */
/*   clib_bitmap_t mtp_any; */
/*   clib_bitmap_t mtp_lkup[MATCH_TURBO_STRIDE_N_BUCKETS/2]; */
/* } match_turbo_table_proto_t; */

typedef struct match_turbo_table_t_
{
  ip_address_family_t mtt_af;
  union
  {
    struct
    {
      match_turbo_table_ip6_t mtt_src_ip6;
      match_turbo_table_ip6_t mtt_dst_ip6;
    };
    struct
    {
      match_turbo_table_ip4_t mtt_src_ip4;
      match_turbo_table_ip4_t mtt_dst_ip4;
    };
  };
  match_turbo_lkup_t mtt_proto;
  match_turbo_lkup_t mtt_icmp_type;
  match_turbo_lkup_t mtt_icmp_code;
  match_turbo_lkup_t mtt_src_port;
  match_turbo_lkup_t mtt_dst_port;
  match_turbo_lkup_t mtt_tcp;
} match_turbo_table_t;

/**
 * A data maintained for each match-rule in the match-list
 */
typedef struct match_turbo_rule_t_
{
  match_mask_n_tuple_t mtr_rule;
  match_result_t mtr_res;
} match_turbo_rule_t;

typedef struct match_turbo_app_t_
{
  index_t mta_set;
  match_set_tag_flags_t mta_tag_flags;
  match_semantic_t mta_semantic;

  index_t *mta_lists;

  /** Arrays of lookup arrays - the result is a bit-map */
  match_turbo_table_t mta_table;

  /** pool of rules */
  match_turbo_rule_t *mta_rule_pool;

} match_turbo_app_t;

extern match_turbo_app_t *match_turbo_app_pool;

typedef struct match_turbo_per_thread_data_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  clib_bitmap_t **mpd_bitmaps;
  clib_bitmap_t *mpd_all;
  u32 mpd_index;
} match_turbo_per_thread_data_t;

extern match_turbo_per_thread_data_t *match_turbo_per_thread_data;
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
