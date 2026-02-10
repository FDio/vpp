/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

/*---------------------------------------------------------------------------
 * from gdp_logical_qos.h
 *---------------------------------------------------------------------------
 */

#ifndef __included_xlate_h__
#define __included_xlate_h__

#include <vnet/ip/ip_packet.h>

typedef enum
{
  QOS_ACTION_DROP = 0,
  QOS_ACTION_TRANSMIT,
  QOS_ACTION_MARK_AND_TRANSMIT,
  QOS_ACTION_HANDOFF
} __clib_packed qos_action_type_en;

/*
 * edt: * enum qos_policer_type_en
 *  Defines type of policer to be allocated
 */
typedef enum qos_policer_type_en_
{
  QOS_POLICER_TYPE_1R2C = 0,
  QOS_POLICER_TYPE_1R3C_RFC_2697 = 1,
  QOS_POLICER_TYPE_2R3C_RFC_2698 = 2,
  QOS_POLICER_TYPE_2R3C_RFC_4115 = 3,
  QOS_POLICER_TYPE_2R3C_RFC_MEF5CF1 = 4,
  QOS_POLICER_TYPE_MAX
} __clib_packed qos_policer_type_en;

/*
 * edt: * enum
 *  Enum used to define type of rounding used when calculating policer values
 */
typedef enum
{
  QOS_ROUND_TO_CLOSEST = 0,
  QOS_ROUND_TO_UP,
  QOS_ROUND_TO_DOWN,
  QOS_ROUND_INVALID
} __clib_packed qos_round_type_en;

/*
 * edt: * enum
 *  Enum used to define type of rate for configuration, either pps or kbps.
 *  If kbps, then burst is in bytes, if pps, then burst is in ms.
 *
 *  Default of zero is kbps, which is inline with how it is programmed
 *  in actual hardware.  However, the warning is that this is reverse logic
 *  of units_in_bits field in static_policer_parameters_st, which is
 *  inline with sse_punt_drop.h.
 */
typedef enum
{
  QOS_RATE_KBPS = 0,
  QOS_RATE_PPS,
  QOS_RATE_INVALID
} __clib_packed qos_rate_type_en;

/*
 * edt * struct qos_pol_action_params_st
 * This structure is used to hold user configured police action parameters.
 *
 * element: action_type
 *      Action type (see qos_action_type_en).
 * element: dscp
 *      DSCP value to set when action is QOS_ACTION_MARK_AND_TRANSMIT.
 */
typedef struct qos_pol_action_params_st_
{
  qos_action_type_en action_type;
  ip_dscp_t dscp;
} qos_pol_action_params_st;

/*
 * edt: * struct qos_pol_cfg_params_st
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
 *      qos_policer_type_en
 * element: rnd_type
 *      Rounding type (see qos_round_type_en). Needed when policer values
 *      need to be rounded. Caller can decide on type of rounding used
 */
typedef struct qos_pol_cfg_params_st_
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
  qos_rate_type_en rate_type;
  qos_round_type_en rnd_type;
  qos_policer_type_en rfc;
  u8 color_aware;
  u8 overwrite_bucket;		/* for debugging purposes */
  u32 current_bucket;		/* for debugging purposes */
  u32 extended_bucket;		/* for debugging purposes */
  qos_pol_action_params_st conform_action;
  qos_pol_action_params_st exceed_action;
  qos_pol_action_params_st violate_action;
} qos_pol_cfg_params_st;

typedef struct qos_pol_hw_params_st_
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
} qos_pol_hw_params_st;

#endif /* __included_xlate_h__ */
