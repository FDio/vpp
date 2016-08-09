/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __included_ioam_e2e_h__
#define __included_ioam_e2e_h__

typedef struct ioam_e2e_data_main_t_ {
  u32 flow_ctx;
  void *ppc_ctx;
} ioam_e2e_data_main_t;

extern ioam_e2e_data_main_t *ioam_e2e_main;

static inline void *
ioam_e2ec_get_ppc_data_from_flow_ctx (u32 flow_ctx)
{
  ioam_e2e_data_main_t *data = NULL;

  data = (ioam_e2e_data_main_t *) get_flow_data_from_flow_ctx(flow_ctx,
                                          HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE);
  if (data)
      return data->ppc_ctx;

  return NULL;
}

#endif /* __included_ioam_e2e_h__ */
