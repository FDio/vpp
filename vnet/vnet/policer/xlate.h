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
/*---------------------------------------------------------------------------
 * from gdp_logical_qos.h
 *---------------------------------------------------------------------------
 */

#ifndef __included_xlate_h__
#define __included_xlate_h__

#include <vnet/policer/police.h>

/*
 * edt: * enum sse2_qos_policer_type_en
 *  Defines type of policer to be allocated
 */
typedef enum sse2_qos_policer_type_en_
{
  SSE2_QOS_POLICER_TYPE_1R2C = 0,
  SSE2_QOS_POLICER_TYPE_1R3C_RFC_2697 = 1,
  SSE2_QOS_POLICER_TYPE_2R3C_RFC_2698 = 2,
  SSE2_QOS_POLICER_TYPE_2R3C_RFC_4115 = 3,
  SSE2_QOS_POLICER_TYPE_2R3C_RFC_MEF5CF1 = 4,
  SSE2_QOS_POLICER_TYPE_MAX
} sse2_qos_policer_type_en;

/*
 * edt: * enum
 *  Enum used to define type of rounding used when calculating policer values
 */
typedef enum
{
  SSE2_QOS_ROUND_TO_CLOSEST = 0,
  SSE2_QOS_ROUND_TO_UP,
  SSE2_QOS_ROUND_TO_DOWN,
  SSE2_QOS_ROUND_INVALID
} sse2_qos_round_type_en;

/*
 * edt: * enum
 *  Enum used to define type of rate for configuration, either pps or kbps.
 *  If kbps, then burst is in bytes, if pps, then burst is in ms.
 *
 *  Default of zero is kbps, which is inline with how it is programmed
 *  in actual hardware.  However, the warning is that this is reverse logic
 *  of units_in_bits field in sse2_static_policer_parameters_st, which is
 *  inline with sse_punt_drop.h.
 */
typedef enum
{
  SSE2_QOS_RATE_KBPS = 0,
  SSE2_QOS_RATE_PPS,
  SSE2_QOS_RATE_INVALID
} sse2_qos_rate_type_en;

/*
 * edt: * enum
 * Defines type of policer actions.
 */
typedef enum
{
  SSE2_QOS_ACTION_DROP = 0,
  SSE2_QOS_ACTION_TRANSMIT,
  SSE2_QOS_ACTION_MARK_AND_TRANSMIT
} sse2_qos_action_type_en;

/*
 * edt * struct sse2_qos_pol_action_params_st
 * This structure is used to hold user configured police action parameters.
 *
 * element: action_type
 *      Action type (see sse2_qos_action_type_en).
 * elemtnt: dscp
 *      DSCP value to set when action is SSE2_QOS_ACTION_MARK_AND_TRANSMIT.
 */
typedef struct sse2_qos_pol_action_params_st_
{
  u8 action_type;
  u8 dscp;
} sse2_qos_pol_action_params_st;

/*
 * edt: * struct sse2_qos_pol_cfg_params_st
 *
 * Description:
 * This structure is used to hold user configured policing parameters.
 *
 * element: cir_kbps
 *      CIR in kbps.
 * element: eir_kbps
 *      EIR or PIR in kbps.
 * element: cb_bytes
 *      Committed Burst in bytes.
 * element: eb_bytes
 *      Excess or Peak Burst in bytes.
 * element: cir_pps
 *      CIR in pps.
 * element: eir_pps
 *      EIR or PIR in pps.
 * element: cb_ms
 *      Committed Burst in milliseconds.
 * element: eb_ms
 *      Excess or Peak Burst in milliseconds.
 * element: rate_type
 *      Indicates the union if in kbps/bytes or pps/ms.
 * element: rfc
 *      Policer algorithm - 1R2C, 1R3C (2697), 2R3C (2698) or 2R3C (4115). See
 *      sse_qos_policer_type_en
 * element: rnd_type
 *      Rounding type (see sse_qos_round_type_en). Needed when policer values
 *      need to be rounded. Caller can decide on type of rounding used
 */
typedef struct sse2_qos_pol_cfg_params_st_
{
  union
  {
    struct
    {
      u32 cir_kbps;
      u32 eir_kbps;
      u64 cb_bytes;
      u64 eb_bytes;
    } kbps;
    struct
    {
      u32 cir_pps;
      u32 eir_pps;
      u64 cb_ms;
      u64 eb_ms;
    } pps;
  } rb;				/* rate burst config */
  u8 rate_type;			/* sse2_qos_rate_type_en */
  u8 rnd_type;			/* sse2_qos_round_type_en */
  u8 rfc;			/* sse2_qos_policer_type_en */
  u8 color_aware;
  u8 overwrite_bucket;		/* for debugging purposes */
  u32 current_bucket;		/* for debugging purposes */
  u32 extended_bucket;		/* for debugging purposes */
  sse2_qos_pol_action_params_st conform_action;
  sse2_qos_pol_action_params_st exceed_action;
  sse2_qos_pol_action_params_st violate_action;
} sse2_qos_pol_cfg_params_st;


typedef struct sse2_qos_pol_hw_params_st_
{
  u8 rfc;
  u8 allow_negative;
  u8 rate_exp;
  u16 avg_rate_man;
  u16 peak_rate_man;
  u8 comm_bkt_limit_exp;
  u8 comm_bkt_limit_man;
  u8 extd_bkt_limit_exp;
  u8 extd_bkt_limit_man;
  u32 comm_bkt;
  u32 extd_bkt;
} sse2_qos_pol_hw_params_st;


int
sse2_pol_logical_2_physical (sse2_qos_pol_cfg_params_st * cfg,
			     policer_read_response_type_st * phys);


#endif /* __included_xlate_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
