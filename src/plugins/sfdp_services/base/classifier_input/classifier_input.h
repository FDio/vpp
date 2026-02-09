/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_sfdp_classifier_input_h__
#define __included_sfdp_classifier_input_h__

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/classify/vnet_classify.h>

typedef enum
{
  SFDP_CLASSIFIER_INPUT_PROTO_IP4 = 0,
  SFDP_CLASSIFIER_INPUT_PROTO_IP6 = 1,
  SFDP_CLASSIFIER_INPUT_N_PROTO,
} sfdp_classifier_input_proto_t;

typedef struct
{
  u32 *classify_table_index_by_sw_if_index[SFDP_CLASSIFIER_INPUT_N_PROTO]; /* vec, ~0 = no table */
  u16 msg_id_base;
} sfdp_classifier_input_main_t;

extern sfdp_classifier_input_main_t sfdp_classifier_input_main;

int sfdp_classifier_input_set_table (u32 sw_if_index, u32 table_index, u8 is_ip6, u8 is_del);
int sfdp_classifier_input_add_del_session (u32 tenant_id, u32 sw_if_index, u8 is_ip6,
					   const u8 *match, u32 match_len, u8 is_del);
int sfdp_classifier_input_enable_disable_interface (u32 sw_if_index, u8 is_enable, u8 is_ip6);

#endif /* __included_sfdp_classifier_input_h__ */
