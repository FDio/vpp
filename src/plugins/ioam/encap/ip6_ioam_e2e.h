/*
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
 */

#ifndef __included_ip6_ioam_e2e_h__
#define __included_ip6_ioam_e2e_h__

#include <ioam/lib-e2e/e2e_util.h>
#include "ip6_ioam_seqno.h"

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct {
  ip6_hop_by_hop_option_t hdr;
  ioam_e2e_packet_t e2e_hdr;
}) ioam_e2e_option_t;
/* *INDENT-ON* */

typedef struct ioam_e2e_data_t_ {
  u32 flow_ctx;
  u32 pad;
  ioam_seqno_data seqno_data;
} ioam_e2e_data_t;

typedef struct {
  ioam_e2e_data_t *e2e_data;
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} ioam_e2e_main_t;

extern ioam_e2e_main_t ioam_e2e_main;

static inline ioam_seqno_data *
ioam_e2ec_get_seqno_data_from_flow_ctx (u32 flow_ctx)
{
  ioam_e2e_data_t *data = NULL;
  u32 index;

  index =  get_flow_data_from_flow_ctx(flow_ctx,
                                       HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE);
  data = &ioam_e2e_main.e2e_data[index];
  return &(data->seqno_data);
}

static inline u32
ioam_e2e_get_cur_seqno_from_flow_ctx (u32 flow_ctx)
{
  ioam_seqno_data *data = NULL;

  data =  ioam_e2ec_get_seqno_data_from_flow_ctx(flow_ctx);
  return data->seq_num;
}

#endif /* __included_ioam_e2e_h__ */
