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
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <stdint.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <vnet/policer/xlate.h>
#include <vnet/policer/police.h>

#define INTERNAL_SS 1

/* debugs */
#define SSE2_QOS_DEBUG_ERROR(msg, args...) \
    fformat(stderr, msg "\n", ##args);

#define SSE2_QOS_DEBUG_INFO(msg, args...) \
    fformat(stderr, msg "\n", ##args);


#define SSE2_QOS_TR_ERR(TpParms...)
// {
// }

#define SSE2_QOS_TR_INFO(TpParms...)

#ifndef MIN
#define MIN(x,y)            (((x)<(y))?(x):(y))
#endif

#ifndef MAX
#define MAX(x,y)            (((x)>(y))?(x):(y))
#endif

#define IPE_POLICER_FULL_WRITE_REQUEST_M40AH_OFFSET                   0
#define IPE_POLICER_FULL_WRITE_REQUEST_M40AH_MASK                     8
#define IPE_POLICER_FULL_WRITE_REQUEST_M40AH_SHIFT                   24

#define IPE_POLICER_FULL_WRITE_REQUEST_TYPE_OFFSET                    2
#define IPE_POLICER_FULL_WRITE_REQUEST_TYPE_MASK                      2
#define IPE_POLICER_FULL_WRITE_REQUEST_TYPE_SHIFT                    10

#define IPE_POLICER_FULL_WRITE_REQUEST_CMD_OFFSET                     3
#define IPE_POLICER_FULL_WRITE_REQUEST_CMD_MASK                       2
#define IPE_POLICER_FULL_WRITE_REQUEST_CMD_SHIFT                      0

#define IPE_POLICER_FULL_WRITE_REQUEST_M40AL_OFFSET                   4
#define IPE_POLICER_FULL_WRITE_REQUEST_M40AL_MASK                    32
#define IPE_POLICER_FULL_WRITE_REQUEST_M40AL_SHIFT                    0

#define IPE_POLICER_FULL_WRITE_REQUEST_RFC_OFFSET                     8
#define IPE_POLICER_FULL_WRITE_REQUEST_RFC_MASK                       2
#define IPE_POLICER_FULL_WRITE_REQUEST_RFC_SHIFT                     30

#define IPE_POLICER_FULL_WRITE_REQUEST_AN_OFFSET                      8
#define IPE_POLICER_FULL_WRITE_REQUEST_AN_MASK                        1
#define IPE_POLICER_FULL_WRITE_REQUEST_AN_SHIFT                      29

#define IPE_POLICER_FULL_WRITE_REQUEST_REXP_OFFSET                    8
#define IPE_POLICER_FULL_WRITE_REQUEST_REXP_MASK                      4
#define IPE_POLICER_FULL_WRITE_REQUEST_REXP_SHIFT                    22

#define IPE_POLICER_FULL_WRITE_REQUEST_ARM_OFFSET                     9
#define IPE_POLICER_FULL_WRITE_REQUEST_ARM_MASK                      11
#define IPE_POLICER_FULL_WRITE_REQUEST_ARM_SHIFT                     11

#define IPE_POLICER_FULL_WRITE_REQUEST_PRM_OFFSET                    10
#define IPE_POLICER_FULL_WRITE_REQUEST_PRM_MASK                      11
#define IPE_POLICER_FULL_WRITE_REQUEST_PRM_SHIFT                      0

#define IPE_POLICER_FULL_WRITE_REQUEST_CBLE_OFFSET                   12
#define IPE_POLICER_FULL_WRITE_REQUEST_CBLE_MASK                      5
#define IPE_POLICER_FULL_WRITE_REQUEST_CBLE_SHIFT                    27

#define IPE_POLICER_FULL_WRITE_REQUEST_CBLM_OFFSET                   12
#define IPE_POLICER_FULL_WRITE_REQUEST_CBLM_MASK                      7
#define IPE_POLICER_FULL_WRITE_REQUEST_CBLM_SHIFT                    20

#define IPE_POLICER_FULL_WRITE_REQUEST_EBLE_OFFSET                   13
#define IPE_POLICER_FULL_WRITE_REQUEST_EBLE_MASK                      5
#define IPE_POLICER_FULL_WRITE_REQUEST_EBLE_SHIFT                    15

#define IPE_POLICER_FULL_WRITE_REQUEST_EBLM_OFFSET                   14
#define IPE_POLICER_FULL_WRITE_REQUEST_EBLM_MASK                      7
#define IPE_POLICER_FULL_WRITE_REQUEST_EBLM_SHIFT                     8

#define IPE_POLICER_FULL_WRITE_REQUEST_CB_OFFSET                     16
#define IPE_POLICER_FULL_WRITE_REQUEST_CB_MASK                       31
#define IPE_POLICER_FULL_WRITE_REQUEST_CB_SHIFT                       0

#define IPE_POLICER_FULL_WRITE_REQUEST_EB_OFFSET                     20
#define IPE_POLICER_FULL_WRITE_REQUEST_EB_MASK                       31
#define IPE_POLICER_FULL_WRITE_REQUEST_EB_SHIFT                       0

#define IPE_RFC_RFC2697           0x00000000
#define IPE_RFC_RFC2698           0x00000001
#define IPE_RFC_RFC4115           0x00000002
#define IPE_RFC_MEF5CF1           0x00000003

/* End of constants copied from sse_ipe_desc_fmt.h */

/* Misc Policer specific definitions */
#define SSE2_QOS_POLICER_FIXED_PKT_SIZE    256

// TODO check what can be provided by hw macro based on ASIC
#define SSE2_QOS_POL_TICKS_PER_SEC     1000LL /* 1 tick = 1 ms */

/*
 * Default burst, in ms (byte format)
 */
#define SSE2_QOS_POL_DEF_BURST_BYTE    100

/*
 * Minimum burst needs to be such that the largest packet size is accomodated
 */
// Do we need to get it from some lib?
#define SSE2_QOS_POL_MIN_BURST_BYTE    9*1024


/*
 * Flag to indicate if AN is employed or not
 * 1 - TRUE, 0 - FALSE
 */
#define SSE2_QOS_POL_ALLOW_NEGATIVE    1

// Various Macros to take care of policer calculations

#define SSE2_QOS_POL_COMM_BKT_MAX \
                            (1<<IPE_POLICER_FULL_WRITE_REQUEST_CB_MASK)
#define SSE2_QOS_POL_EXTD_BKT_MAX \
                            (1<<IPE_POLICER_FULL_WRITE_REQUEST_EB_MASK)

#define SSE2_QOS_POL_RATE_EXP_SIZE \
                            (IPE_POLICER_FULL_WRITE_REQUEST_REXP_MASK)
#define SSE2_QOS_POL_RATE_EXP_MAX  ((1<<SSE2_QOS_POL_RATE_EXP_SIZE) - 1)
#define SSE2_QOS_POL_AVG_RATE_MANT_SIZE \
                            (IPE_POLICER_FULL_WRITE_REQUEST_ARM_MASK)
#define SSE2_QOS_POL_AVG_RATE_MANT_MAX    \
                            ((1<< SSE2_QOS_POL_AVG_RATE_MANT_SIZE) - 1) 
#define SSE2_QOS_POL_AVG_RATE_MAX \
                            (SSE2_QOS_POL_AVG_RATE_MANT_MAX << \
                             SSE2_QOS_POL_RATE_EXP_MAX)

#define SSE2_QOS_POL_PEAK_RATE_MANT_SIZE   \
                            (IPE_POLICER_FULL_WRITE_REQUEST_PRM_MASK)
#define SSE2_QOS_POL_PEAK_RATE_MANT_MAX    \
                            ((1<<SSE2_QOS_POL_PEAK_RATE_MANT_SIZE) - 1) 
#define SSE2_QOS_POL_PEAK_RATE_MAX \
                            (SSE2_QOS_POL_PEAK_RATE_MANT_MAX << \
                             SSE2_QOS_POL_RATE_EXP_MAX)

#define SSE2_QOS_POL_COMM_BKT_LIMIT_MANT_SIZE   \
                        (IPE_POLICER_FULL_WRITE_REQUEST_CBLM_MASK)
#define SSE2_QOS_POL_COMM_BKT_LIMIT_MANT_MAX   \
                        ((1<<SSE2_QOS_POL_COMM_BKT_LIMIT_MANT_SIZE) - 1)
#define SSE2_QOS_POL_COMM_BKT_LIMIT_EXP_SIZE   \
                        (IPE_POLICER_FULL_WRITE_REQUEST_CBLE_MASK)
#define SSE2_QOS_POL_COMM_BKT_LIMIT_EXP_MAX   \
                        ((1<<SSE2_QOS_POL_COMM_BKT_LIMIT_EXP_SIZE) - 1)
#define SSE2_QOS_POL_COMM_BKT_LIMIT_MAX \
                        ((uint64_t)SSE2_QOS_POL_COMM_BKT_LIMIT_MANT_MAX << \
                         (uint64_t)SSE2_QOS_POL_COMM_BKT_LIMIT_EXP_MAX)

#define SSE2_QOS_POL_EXTD_BKT_LIMIT_MANT_SIZE   \
                        (IPE_POLICER_FULL_WRITE_REQUEST_EBLM_MASK)
#define SSE2_QOS_POL_EXTD_BKT_LIMIT_MANT_MAX   \
                        ((1<<SSE2_QOS_POL_EXTD_BKT_LIMIT_MANT_SIZE) - 1)
#define SSE2_QOS_POL_EXTD_BKT_LIMIT_EXP_SIZE   \
                        (IPE_POLICER_FULL_WRITE_REQUEST_EBLE_MASK)
#define SSE2_QOS_POL_EXTD_BKT_LIMIT_EXP_MAX   \
                        ((1<<SSE2_QOS_POL_EXTD_BKT_LIMIT_EXP_SIZE) - 1)
#define SSE2_QOS_POL_EXT_BKT_LIMIT_MAX \
                        ((uint64_t)SSE2_QOS_POL_EXTD_BKT_LIMIT_MANT_MAX << \
                         (uint64_t)SSE2_QOS_POL_EXTD_BKT_LIMIT_EXP_MAX)

/*
 * Rates determine the units of the bucket
 *    256.114688 Gbps < Rate                      8 byte units
 *    128.057344 Gbps < Rate <= 256.114688 Gbps   4 byte units
 *     64.028672 Gbps < Rate <= 128.057344 Gbps   2 byte units
 *                      Rate <=  64.028672 Gbps   1 byte units
 *
 * The code uses bytes per tick as oppose to Gigabits per second.
 */
#define RATE256 (256114688000LL / 8LL / SSE2_QOS_POL_TICKS_PER_SEC)
#define RATE128 (128057344000LL / 8LL / SSE2_QOS_POL_TICKS_PER_SEC)
#define RATE64  ( 64028672000LL / 8LL / SSE2_QOS_POL_TICKS_PER_SEC)

#define RATE_OVER256_UNIT  8LL
#define RATE_128TO256_UNIT 4LL
#define RATE_64TO128_UNIT  2LL

static cerrno
sse2_qos_pol_round (uint64_t numerator,
                      uint64_t denominator,
                      uint64_t *rounded_value,
                      sse2_qos_round_type_en round_type)
{
    cerrno rc = EOK;

    if (denominator == 0) {
        SSE2_QOS_DEBUG_ERROR("Illegal denominator");
        SSE2_QOS_TR_ERR(SSE2_QOSRM_TP_ERR_59);
        return(EINVAL);
    }

    switch (round_type) {
    case SSE2_QOS_ROUND_TO_CLOSEST:
        *rounded_value = ((numerator + (denominator >> 1)) / denominator);
        break;

    case SSE2_QOS_ROUND_TO_UP:
        *rounded_value = (numerator / denominator);
        if ((*rounded_value * denominator) < numerator) {
            *rounded_value += 1;
        }
        break;

    case SSE2_QOS_ROUND_TO_DOWN:
        *rounded_value = (numerator / denominator);
        break;

    case SSE2_QOS_ROUND_INVALID:
    default:
        SSE2_QOS_DEBUG_ERROR("Illegal round type");
        SSE2_QOS_TR_ERR(SSE2_QOS_TP_ERR_60, round_type);
        rc = EINVAL;
        break;
    }
    return(rc);
}


static cerrno
sse2_pol_validate_cfg_params (sse2_qos_pol_cfg_params_st *cfg)
{
    uint64_t numer, denom, rnd_value;
    uint32_t cir_hw, eir_hw;
    cerrno rc = EOK;

    if ((cfg->rfc == SSE2_QOS_POLICER_TYPE_2R3C_RFC_2698) &&
        (cfg->rb.kbps.eir_kbps < cfg->rb.kbps.cir_kbps)) {
        SSE2_QOS_DEBUG_ERROR("CIR (%u kbps) is greater than PIR (%u kbps)",
                              cfg->rb.kbps.cir_kbps, cfg->rb.kbps.eir_kbps);
        SSE2_QOS_TR_ERR(SSE2_QOS_TP_ERR_39, cfg->rb.kbps.cir_kbps,
                        cfg->rb.kbps.eir_kbps);
        return(EINVAL);
    }

    /*
     * convert rates to bytes-per-tick
     */
    numer = (uint64_t)(cfg->rb.kbps.cir_kbps);
    denom = (uint64_t)(8 * SSE2_QOS_POL_TICKS_PER_SEC) / 1000;
    rc = sse2_qos_pol_round(numer, denom, &rnd_value,
                            (sse2_qos_round_type_en) cfg->rnd_type);
    if (CERR_IS_NOTOK(rc)) {
        SSE2_QOS_DEBUG_ERROR("Unable to convert CIR to bytes/tick format");
        // Error traced
        return(rc);
    }
    cir_hw = (uint32_t)rnd_value;

    numer = (uint64_t)(cfg->rb.kbps.eir_kbps);
    rc = sse2_qos_pol_round(numer, denom, &rnd_value,
                            (sse2_qos_round_type_en) cfg->rnd_type);
    if (CERR_IS_NOTOK(rc)) {
        SSE2_QOS_DEBUG_ERROR("Unable to convert EIR to bytes/tick format");
        // Error traced
        return(rc);
    }
    eir_hw = (uint32_t)rnd_value;

    if (cir_hw > SSE2_QOS_POL_AVG_RATE_MAX) {
        SSE2_QOS_DEBUG_ERROR("hw cir (%u bytes/tick) is greater than the "
                              "max supported value (%u)", cir_hw,
                              SSE2_QOS_POL_AVG_RATE_MAX);
        SSE2_QOS_TR_ERR(SSE2_QOS_TP_ERR_84, cir_hw, 
                         SSE2_QOS_POL_AVG_RATE_MAX);
        return(EINVAL);
    }

    if (eir_hw > SSE2_QOS_POL_PEAK_RATE_MAX) {
        SSE2_QOS_DEBUG_ERROR("hw eir (%u bytes/tick) is greater than the "
                 "max supported value (%u). Capping it to the max. "
                 "supported value", eir_hw, SSE2_QOS_POL_PEAK_RATE_MAX);
        SSE2_QOS_TR_ERR(SSE2_QOS_TP_ERR_85, 
                 eir_hw, SSE2_QOS_POL_PEAK_RATE_MAX);
        return(EINVAL);
    }
    /*
     * CIR = 0, with bc != 0 is not allowed
     */
    if ((cfg->rb.kbps.cir_kbps == 0) && cfg->rb.kbps.cb_bytes) {
        SSE2_QOS_DEBUG_ERROR("CIR = 0 with bc != 0");
        SSE2_QOS_TR_ERR(SSE2_QOS_TP_ERR_55);
        return(EINVAL);
    }

    if ((cfg->rb.kbps.eir_kbps == 0) &&
        (cfg->rfc > SSE2_QOS_POLICER_TYPE_1R3C_RFC_2697)) {
        SSE2_QOS_DEBUG_ERROR("EIR = 0 for a 2R3C policer (rfc: %u)", cfg->rfc);
        SSE2_QOS_TR_ERR(SSE2_QOS_TP_ERR_23, cfg->rb.kbps.eir_kbps, cfg->rfc);
        return(EINVAL);
    }

    if (cfg->rb.kbps.eir_kbps &&
       (cfg->rfc < SSE2_QOS_POLICER_TYPE_2R3C_RFC_2698)) {
        SSE2_QOS_DEBUG_ERROR("EIR: %u kbps for a 1-rate policer (rfc: %u)",
                            cfg->rb.kbps.eir_kbps, cfg->rfc);
        SSE2_QOS_TR_ERR(SSE2_QOS_TP_ERR_23, cfg->rb.kbps.eir_kbps, cfg->rfc);
        return(EINVAL);
    }

    if ((cfg->rfc == SSE2_QOS_POLICER_TYPE_1R2C) && cfg->rb.kbps.eb_bytes) {
        SSE2_QOS_DEBUG_ERROR("For a 1R1B policer, EB burst cannot be > 0");
        SSE2_QOS_TR_ERR(SSE2_QOS_TP_ERR_56);
        return(EINVAL);
    }

    return(EOK);
}

static void
sse2_qos_convert_value_to_exp_mant_fmt (uint64_t       value,
                                        uint16_t       max_exp_value,
                                        uint16_t       max_mant_value,
                                        sse2_qos_round_type_en type,
                                        uint8_t        *exp,
                                        uint32_t       *mant)
{
    uint64_t rnd_value;
    uint64_t temp_mant;
    uint8_t temp_exp;

    /*
     * Select the lowest possible exp, and the largest possible mant
     */
    temp_exp = 0;
    temp_mant = value;
    while (temp_exp <= max_exp_value) {
        if (temp_mant <= max_mant_value) {
            break;
        }

        temp_exp++;
        rnd_value = 0;
        (void)sse2_qos_pol_round((uint64_t)value, (uint64_t)(1 << temp_exp),
                               &rnd_value, type);
        temp_mant = rnd_value;
    }

    if (temp_exp > max_exp_value) {
        /*
         * CAP mant to its max value, and decrement exp
         */
        temp_exp--;
        temp_mant = max_mant_value;
    }

    *exp = temp_exp;
    *mant = (uint32_t)temp_mant;

    SSE2_QOS_DEBUG_INFO("value: 0x%llx, mant: %u, exp: %u", value, *mant, *exp);
    return;
}

static cerrno
sse2_pol_convert_cfg_rates_to_hw (sse2_qos_pol_cfg_params_st *cfg,
                                  sse2_qos_pol_hw_params_st  *hw)
{
    cerrno rc = EOK;
    uint32_t cir_hw, eir_hw, hi_mant, hi_rate, cir_rnded, eir_rnded, eir_kbps;
    uint64_t numer, denom, rnd_value;
    uint8_t exp;

    /*
     * convert rates to bytes-per-tick (tick is 1ms)
     * For rate conversion, the denominator is gonna be the same
     */
    denom = (uint64_t)((SSE2_QOS_POL_TICKS_PER_SEC * 8) / 1000);
    numer = (uint64_t)(cfg->rb.kbps.cir_kbps);
    rc = sse2_qos_pol_round(numer, denom, &rnd_value,
                            (sse2_qos_round_type_en) cfg->rnd_type);
    if (CERR_IS_NOTOK(rc)) {
        SSE2_QOS_DEBUG_ERROR("Rounding error, rate: %d kbps, rounding_type: %d",
                            cfg->rb.kbps.cir_kbps, cfg->rnd_type);
        // Error is traced
        return(rc);
    }
    cir_hw = (uint32_t)rnd_value;

    if (cfg->rb.kbps.cir_kbps && (cir_hw == 0)) {
        /*
         * After rounding, cir_hw = 0. Bump it up
         */
        cir_hw = 1;
    }

    if (cfg->rfc == SSE2_QOS_POLICER_TYPE_1R2C) {
        eir_kbps = 0;
    } else if (cfg->rfc == SSE2_QOS_POLICER_TYPE_1R3C_RFC_2697) {
        eir_kbps = cfg->rb.kbps.cir_kbps;
    } else if (cfg->rfc == SSE2_QOS_POLICER_TYPE_2R3C_RFC_4115) {
        eir_kbps = cfg->rb.kbps.eir_kbps - cfg->rb.kbps.cir_kbps;
    } else {
        eir_kbps = cfg->rb.kbps.eir_kbps;
    }

    numer = (uint64_t)eir_kbps;
    rc = sse2_qos_pol_round(numer, denom, &rnd_value,
                            (sse2_qos_round_type_en) cfg->rnd_type);
    if (CERR_IS_NOTOK(rc)) {
        SSE2_QOS_DEBUG_ERROR("Rounding error, rate: %d kbps, rounding_type: %d",
                              eir_kbps, cfg->rnd_type);
        // Error is traced
        return(rc);
    }
    eir_hw = (uint32_t)rnd_value;

    if (eir_kbps && (eir_hw == 0)) {
        /*
         * After rounding, eir_hw = 0. Bump it up
         */
        eir_hw = 1;
    }

    SSE2_QOS_DEBUG_INFO("cir_hw: %u bytes/tick, eir_hw: %u bytes/tick", cir_hw,
                         eir_hw);

    if (cir_hw > eir_hw) {
        hi_rate = cir_hw;
    } else {
        hi_rate = eir_hw;
    }

    if ((cir_hw == 0) && (eir_hw == 0)) {
        /*
         * Both the rates are 0. Use exp = 15, and set the RFC to 4115. Also
         * set AN = 0
         */
        exp = (uint8_t)SSE2_QOS_POL_RATE_EXP_MAX;
        hi_mant = 0;
        hw->rfc = IPE_RFC_RFC4115;
        hw->allow_negative = 0;
    } else {
        sse2_qos_convert_value_to_exp_mant_fmt(hi_rate, 
                            (uint16_t)SSE2_QOS_POL_RATE_EXP_MAX,
                            (uint16_t)SSE2_QOS_POL_AVG_RATE_MANT_MAX,
                            (sse2_qos_round_type_en) cfg->rnd_type,
                            &exp, &hi_mant);
    }

    denom = (1 << exp);
    if (hi_rate == eir_hw) {
        hw->peak_rate_man = (uint16_t)hi_mant;
        rc = sse2_qos_pol_round((uint64_t)cir_hw, denom, &rnd_value,
                                (sse2_qos_round_type_en) cfg->rnd_type);
        hw->avg_rate_man = (uint16_t)rnd_value;
    } else {
        hw->avg_rate_man = (uint16_t)hi_mant;
        rc = sse2_qos_pol_round((uint64_t)eir_hw, denom, &rnd_value,
                                (sse2_qos_round_type_en) cfg->rnd_type);
        hw->peak_rate_man = (uint16_t)rnd_value;
    }
    if (CERR_IS_NOTOK(rc)) {
        SSE2_QOS_DEBUG_ERROR("Rounding error");
        // Error is traced
        return(rc);
    }
    hw->rate_exp = exp;

    if ((hw->avg_rate_man == 0) && (cfg->rb.kbps.cir_kbps)) {
        /*
         * cir was reduced to 0 during rounding. Bump it up
         */
        hw->avg_rate_man = 1;
        SSE2_QOS_DEBUG_INFO("CIR = 0 during rounding. Bump it up to %u "
                           "bytes/tick", (hw->avg_rate_man << hw->rate_exp));
    }

    if ((hw->peak_rate_man == 0) && eir_kbps) {
        /*
         * eir was reduced to 0 during rounding. Bump it up
         */
        hw->peak_rate_man = 1;
        SSE2_QOS_DEBUG_INFO("EIR = 0 during rounding. Bump it up to %u "
                           "bytes/tick", (hw->peak_rate_man << hw->rate_exp));
    }

    cir_rnded = (hw->avg_rate_man << hw->rate_exp);
    eir_rnded = (hw->peak_rate_man << hw->rate_exp);

    SSE2_QOS_DEBUG_INFO("Configured(rounded) values, cir: %u "
                       "kbps (mant: %u, exp: %u, rate: %u bytes/tick)",
                       cfg->rb.kbps.cir_kbps, hw->avg_rate_man, 
                       hw->rate_exp, cir_rnded);

    SSE2_QOS_DEBUG_INFO("Configured(rounded) values, eir: %u "
                       "kbps (mant: %u, exp: %u, rate: %u bytes/tick)",
                       cfg->rb.kbps.eir_kbps, hw->peak_rate_man, 
                       hw->rate_exp, eir_rnded);

    return(rc);
}

/*****
 * NAME
 *   sse2_pol_get_bkt_max
 *
 * PARAMETERS
 *  rate_hw    - either the averate rate or peak rate
 *  bkt_max    - bit width in the current bucket or extended bucket
 *
 * RETURNS
 *  uint64_t   - maximum token bytes for the current or extended bucket
 *
 * DESCRIPTION
 *  The current bucket or extended bucket fields are in units of either
 *  1,2,4,8 bytes based on the average or peak rate respective to current
 *  or extended bucket.
 *
 *  To get the actual maximum number of bytes that can be stored in the
 *  field, the value must be multiplied by the units of either 1,2,4,8
 *  bytes based on the rate.
 *****/
uint64_t
sse2_pol_get_bkt_max (uint64_t rate_hw, uint64_t bkt_max)
{
    if (rate_hw <= RATE64) {
        return (bkt_max - 1);
    } else if (rate_hw <= RATE128) {
        return ((bkt_max * RATE_64TO128_UNIT) - RATE_64TO128_UNIT);
    } else if (rate_hw <= RATE256) {
        return ((bkt_max * RATE_128TO256_UNIT) - RATE_128TO256_UNIT);
    }
    /* rate must be over 256 */
    return ((bkt_max * RATE_OVER256_UNIT) - RATE_OVER256_UNIT);
}

/*****
 * NAME
 *   sse2_pol_get_bkt_value
 *
 * PARAMETERS
 *  rate_hw    - either the averate rate or peak rate
 *  byte_value - bytes for this token bucket
 *
 * RETURNS
 *  uint64_t   - unit value for the current or extended bucket field
 *
 * DESCRIPTION
 *  The current bucket or extended bucket fields are in units of either
 *  1,2,4,8 bytes based on the average or peak rate respective to current
 *  or extended bucket.
 *
 *  To get the units that can be stored in the field, the byte value must
 *  be divided by the units of either 1,2,4,8 bytes based on the rate.
 *****/
uint64_t
sse2_pol_get_bkt_value (uint64_t rate_hw, uint64_t byte_value)
{
    if (rate_hw <= RATE64) {
        return (byte_value);
    } else if (rate_hw <= RATE128) {
        return (byte_value / RATE_64TO128_UNIT);
    } else if (rate_hw <= RATE256) {
        return (byte_value / RATE_128TO256_UNIT);
    }
    /* rate must be over 256 */
    return (byte_value / RATE_OVER256_UNIT);
}

static void
sse2_pol_rnd_burst_byte_fmt (uint64_t cfg_burst,
                             uint16_t max_exp_value,
                             uint16_t max_mant_value,
                             uint32_t max_bkt_value,
                             uint32_t rate_hw,
                             uint8_t *exp,
                             uint32_t *mant,
                             uint32_t *bkt_value)
{
    uint64_t    bkt_max=max_bkt_value;
    uint64_t    bkt_limit_max;
    uint64_t    rnd_burst;
    uint64_t    temp_bkt_value;

    bkt_limit_max = ((uint64_t)max_mant_value<<(uint64_t)max_exp_value);
    bkt_max = sse2_pol_get_bkt_max(rate_hw, bkt_max);
    bkt_max=MIN(bkt_max, bkt_limit_max);
    if (!cfg_burst) {
        /*
         * If configured burst = 0, compute the burst to be 100ms at a given
         * rate. Note that for rate_hw = 0, exp = mant = 0.
         */
        cfg_burst = (uint64_t)rate_hw * (uint64_t)SSE2_QOS_POL_DEF_BURST_BYTE;
    }

    if (cfg_burst > bkt_max) {
        SSE2_QOS_DEBUG_ERROR("burst 0x%llx bytes is greater than the max. "
                            "supported value 0x%llx bytes. Capping it to the "
                            "max", cfg_burst, bkt_max);
        SSE2_QOS_TR_INFO(SSE2_QOS_TP_INFO_38, 
                          (uint)cfg_burst, (uint)bkt_max);
        cfg_burst = bkt_max;
    }

    if (cfg_burst < SSE2_QOS_POL_MIN_BURST_BYTE) {
        /*
         * Bump up the burst value ONLY if the cfg_burst is non-zero AND
         * less than the min. supported value
         */
        SSE2_QOS_DEBUG_INFO("burst 0x%llx bytes is less than the min "
                       "supported value %u bytes. Rounding it up to "
                       "the min", cfg_burst, SSE2_QOS_POL_MIN_BURST_BYTE);
        SSE2_QOS_TR_INFO(SSE2_QOS_TP_INFO_39, (uint)cfg_burst,
                        SSE2_QOS_POL_MIN_BURST_BYTE);
        cfg_burst = SSE2_QOS_POL_MIN_BURST_BYTE;
    }

    sse2_qos_convert_value_to_exp_mant_fmt(cfg_burst,
                                             max_exp_value,
                                             max_mant_value, 
                                             SSE2_QOS_ROUND_TO_DOWN,
                                             exp,
                                             mant);

    /* Bucket value is based on rate. */
    rnd_burst = ((uint64_t)(*mant) << (uint64_t)(*exp));
    temp_bkt_value = sse2_pol_get_bkt_value(rate_hw, rnd_burst);
    *bkt_value = (uint32_t)temp_bkt_value;
}

static cerrno
sse2_pol_convert_cfg_burst_to_hw (sse2_qos_pol_cfg_params_st *cfg,
                                  sse2_qos_pol_hw_params_st  *hw)
{
    uint8_t  temp_exp;
    uint32_t temp_mant, rate_hw; 
    uint64_t eb_bytes;
    uint32_t bkt_value;

    /*
     * compute Committed Burst
     */
    SSE2_QOS_DEBUG_INFO("Compute commit burst ...");
    rate_hw = (hw->avg_rate_man) << (hw->rate_exp);
    sse2_pol_rnd_burst_byte_fmt(cfg->rb.kbps.cb_bytes, 
                           (uint16_t)SSE2_QOS_POL_COMM_BKT_LIMIT_EXP_MAX,
                           (uint16_t)SSE2_QOS_POL_COMM_BKT_LIMIT_MANT_MAX,
                           (uint32_t)SSE2_QOS_POL_COMM_BKT_MAX,
                           rate_hw, &temp_exp, &temp_mant, &bkt_value);
    SSE2_QOS_DEBUG_INFO("Committed burst, burst_limit: 0x%llx mant : %u, "
                       "exp: %u, rnded: 0x%llx cb:%u bytes",
                       cfg->rb.kbps.cb_bytes, temp_mant, temp_exp, 
                       ((uint64_t)temp_mant << (uint64_t)temp_exp), bkt_value);

    hw->comm_bkt_limit_exp = temp_exp;
    hw->comm_bkt_limit_man = (uint8_t)temp_mant;
    hw->comm_bkt = bkt_value;

    /*
     * compute Exceed Burst
     */
    SSE2_QOS_DEBUG_INFO("Compute exceed burst ...");

    if (cfg->rfc == SSE2_QOS_POLICER_TYPE_1R2C) {
        /*
         * For 1R2C, hw uses 2R3C (RFC-4115). As such, the Exceed Bucket
         * params are set to 0. Recommendation is to use EB_exp = max_exp (=15)
         * and EB_mant = 0
         */
        hw->extd_bkt_limit_exp = (uint8_t)SSE2_QOS_POL_EXTD_BKT_LIMIT_EXP_MAX;
        hw->extd_bkt_limit_man = 0;
        SSE2_QOS_DEBUG_INFO("Excess burst, burst: 0x%llx mant: %u, "
               "exp: %u, rnded: 0x%llx bytes", 
               cfg->rb.kbps.eb_bytes, hw->extd_bkt_limit_man,
               hw->extd_bkt_limit_exp,
               ((uint64_t)hw->extd_bkt_limit_man <<
                (uint64_t)hw->extd_bkt_limit_exp));
        SSE2_QOS_TR_INFO(SSE2_QOS_TP_INFO_20, (uint)cfg->rb.kbps.eb_bytes, 
                            hw->extd_bkt_limit_man, hw->extd_bkt_limit_exp);
        return(EOK);
    }

    if (cfg->rfc == SSE2_QOS_POLICER_TYPE_1R3C_RFC_2697) {
        eb_bytes = cfg->rb.kbps.cb_bytes + cfg->rb.kbps.eb_bytes;
    } else if (cfg->rfc == SSE2_QOS_POLICER_TYPE_2R3C_RFC_4115) {
        eb_bytes = cfg->rb.kbps.eb_bytes - cfg->rb.kbps.cb_bytes;
    } else {
        eb_bytes = cfg->rb.kbps.eb_bytes;
    }

    rate_hw = (hw->peak_rate_man) << (hw->rate_exp);
    sse2_pol_rnd_burst_byte_fmt(eb_bytes, 
                           (uint16_t)SSE2_QOS_POL_EXTD_BKT_LIMIT_EXP_MAX,
                           (uint16_t)SSE2_QOS_POL_EXTD_BKT_LIMIT_MANT_MAX,
                           (uint32_t)SSE2_QOS_POL_EXTD_BKT_MAX,
                           rate_hw, &temp_exp, &temp_mant, &bkt_value);

    SSE2_QOS_DEBUG_INFO("Excess burst, burst_limit: 0x%llx mant: %u, "
                       "exp: %u, rnded: 0x%llx eb:%u bytes", 
                       cfg->rb.kbps.eb_bytes, temp_mant, temp_exp,
                       ((uint64_t)temp_mant << (uint64_t)temp_exp), bkt_value);

    hw->extd_bkt_limit_exp = (uint8_t)temp_exp;
    hw->extd_bkt_limit_man = (uint8_t)temp_mant;
    hw->extd_bkt = bkt_value;

    return(EOK);
}


/*
 * Input: configured parameter values in 'cfg'.
 * Output: h/w programmable parameter values in 'hw'.
 * Return: success or failure code.
 */
static cerrno
sse2_pol_convert_cfg_to_hw_params (sse2_qos_pol_cfg_params_st *cfg,
                                   sse2_qos_pol_hw_params_st  *hw)
{
    cerrno rc = EOK;

    /*
     * clear the hw_params
     */
    memset(hw, 0, sizeof(sse2_qos_pol_hw_params_st));

    hw->allow_negative = SSE2_QOS_POL_ALLOW_NEGATIVE;

    if ((cfg->rfc == SSE2_QOS_POLICER_TYPE_1R2C) ||
        (cfg->rfc == SSE2_QOS_POLICER_TYPE_2R3C_RFC_4115)) {
        hw->rfc = IPE_RFC_RFC4115;
    } else if (cfg->rfc == SSE2_QOS_POLICER_TYPE_1R3C_RFC_2697) {
        hw->rfc = IPE_RFC_RFC2697;
    } else if (cfg->rfc == SSE2_QOS_POLICER_TYPE_2R3C_RFC_2698) {
        hw->rfc = IPE_RFC_RFC2698;
    } else if (cfg->rfc == SSE2_QOS_POLICER_TYPE_2R3C_RFC_MEF5CF1) {
        hw->rfc = IPE_RFC_MEF5CF1;
    } else {
        SSE2_QOS_DEBUG_ERROR("Invalid RFC type %d\n", cfg->rfc);
        SSE2_QOS_TR_ERR(SSE2_QOS_TP_ERR_61, cfg->rfc);
        return(EINVAL);
    }

    rc = sse2_pol_convert_cfg_rates_to_hw(cfg, hw);
    if (CERR_IS_NOTOK(rc)) {
        SSE2_QOS_DEBUG_ERROR("Unable to convert config rates to hw. Error: %d",
                              rc);
        // Error is traced
        return(rc);
    }

    rc = sse2_pol_convert_cfg_burst_to_hw(cfg, hw);
    if (CERR_IS_NOTOK(rc)) {
        SSE2_QOS_DEBUG_ERROR("Unable to convert config burst to hw. Error: %d",
                              rc);
        // Error is traced
        return(rc);
    }

    return OK_pushHW;
}


uint32_t
sse2_qos_convert_pps_to_kbps (uint32_t rate_pps)
{
    // sse2_qos_ship_inc_counter(SSE2_QOS_SHIP_COUNTER_TYPE_API_CNT,
    //                            SSE2_QOS_SHIP_CNT_POL_CONV_PPS_TO_KBPS);

    uint64_t numer, rnd_value = 0;

    numer = (uint64_t)((uint64_t)rate_pps *
            (uint64_t)SSE2_QOS_POLICER_FIXED_PKT_SIZE * 8LL);
    (void)sse2_qos_pol_round(numer, 1000LL, &rnd_value,
                              SSE2_QOS_ROUND_TO_CLOSEST);

    return ((uint32_t)rnd_value);
}

uint32_t
sse2_qos_convert_burst_ms_to_bytes (uint32_t burst_ms,
                                     uint32_t rate_kbps)
{
    uint64_t numer, rnd_value = 0;

    //sse2_qos_ship_inc_counter(SSE2_QOS_SHIP_COUNTER_TYPE_API_CNT,
    //                          SSE2_QOS_SHIP_CNT_POL_CONV_BURST_MS_TO_BYTES);

    numer = (uint64_t)((uint64_t)burst_ms * (uint64_t)rate_kbps);

    (void)sse2_qos_pol_round(numer, 8LL, &rnd_value,
                             SSE2_QOS_ROUND_TO_CLOSEST);

    return ((uint32_t)rnd_value);
}


/*
 * Input: configured parameters in 'cfg'.
 * Output: h/w parameters are returned in 'hw',
 * Return: Status, success or failure code.
 */
trans_layer_rc
sse2_pol_compute_hw_params (sse2_qos_pol_cfg_params_st *cfg,
                            sse2_qos_pol_hw_params_st  *hw)
{
    cerrno rc = EOK;

    if (!cfg || !hw) {
        SSE2_QOS_DEBUG_ERROR("Illegal parameters");
        return(Not_OK);
    }

    /*
     * Validate the police config params being presented to RM
     */
    rc = sse2_pol_validate_cfg_params(cfg);
    if (CERR_IS_NOTOK(rc)) {
        SSE2_QOS_DEBUG_ERROR("Config parameter validation failed. Error: %d",
                            rc);
        // Error is traced
        return(Not_OK);
    }

    /*
     * first round configured values to h/w supported values. This func
     * also determines whether 'tick' or 'byte' format
     */
    rc = sse2_pol_convert_cfg_to_hw_params(cfg, hw);
    if (CERR_IS_NOTOK(rc)) {
        SSE2_QOS_DEBUG_ERROR("Unable to convert config params to hw params. "
                            "Error: %d", rc);
        SSE2_QOS_TR_ERR(SSE2_QOS_TP_ERR_53, rc);
        return(Not_OK);
    }

    return OK_pushHW;
}


#if defined (INTERNAL_SS) || defined (X86)

// For initializing the x86 policer format

/*
 * Return the number of hardware TSC timer ticks per second for the dataplane.
 * This is approximately, but not exactly, the clock speed.
 */
static uint64_t get_tsc_hz(void) 
{
    f64 cpu_freq;

    cpu_freq = os_cpu_clock_frequency();
    return (uint64_t) cpu_freq;
}

/*
 * Convert rates into bytes_per_period and scale.
 * Return 0 if ok or 1 if error.
 */
static int 
compute_policer_params (uint64_t hz,                 // CPU speed in clocks per second
                        uint64_t cir_rate,           // in bytes per second
                        uint64_t pir_rate,           // in bytes per second
                        uint32_t *current_limit,     // in bytes, output may scale the input
                        uint32_t *extended_limit,    // in bytes, output may scale the input
                        uint32_t *cir_bytes_per_period,
                        uint32_t *pir_bytes_per_period,
                        uint32_t *scale)
{
    double period;
    double internal_cir_bytes_per_period;
    double internal_pir_bytes_per_period;
    uint32_t max;
    uint32_t scale_shift;
    uint32_t scale_amount;
    uint32_t __attribute__((unused)) orig_current_limit = *current_limit;

    // Compute period. For 1Ghz-to-8Ghz CPUs, the period will be in 
    // the range of 16 to 116 usec.
    period = ((double) hz) / ((double) POLICER_TICKS_PER_PERIOD);

    // Determine bytes per period for each rate
    internal_cir_bytes_per_period = (double)cir_rate / period;
    internal_pir_bytes_per_period = (double)pir_rate / period;

    // Scale if possible. Scaling helps rate accuracy, but is contrained 
    // by the scaled rates and limits fitting in 32-bits.
    // In addition, we need to insure the scaled rate is no larger than
    // 2^22 tokens per period. This allows the dataplane to ignore overflow
    // in the tokens-per-period multiplication since it could only
    // happen if the policer were idle for more than a year.
    // This is not really a constraint because 100Gbps at 1Ghz is only
    // 1.6M tokens per period.
#define MAX_RATE_SHIFT 10
    max = MAX(*current_limit, *extended_limit);
    max = MAX(max, (uint32_t)internal_cir_bytes_per_period << MAX_RATE_SHIFT);
    max = MAX(max, (uint32_t)internal_pir_bytes_per_period << MAX_RATE_SHIFT);
    scale_shift = __builtin_clz(max);
    
    scale_amount = 1 << scale_shift;
    *scale = scale_shift;
    
    // Scale the limits
    *current_limit = *current_limit << scale_shift;
    *extended_limit = *extended_limit << scale_shift;

    // Scale the rates
    internal_cir_bytes_per_period = internal_cir_bytes_per_period * ((double)scale_amount);
    internal_pir_bytes_per_period = internal_pir_bytes_per_period * ((double)scale_amount);

    // Make sure the new rates are reasonable
    // Only needed for very low rates with large bursts
    if (internal_cir_bytes_per_period < 1.0) {
        internal_cir_bytes_per_period = 1.0;
    }
    if (internal_pir_bytes_per_period < 1.0) {
        internal_pir_bytes_per_period = 1.0;
    }

    *cir_bytes_per_period = (uint32_t)internal_cir_bytes_per_period;
    *pir_bytes_per_period = (uint32_t)internal_pir_bytes_per_period;

// #define PRINT_X86_POLICE_PARAMS 
#ifdef PRINT_X86_POLICE_PARAMS
    {
        uint64_t effective_BPS;

        // This value actually slightly conservative because it doesn't take into account
        // the partial period at the end of a second. This really matters only for very low
        // rates.
        effective_BPS = (((uint64_t) (*cir_bytes_per_period * (uint64_t)period)) >> *scale ); 

        printf("hz=%llu, cir_rate=%llu, limit=%u => "
               "periods-per-sec=%d usec-per-period=%d => "
               "scale=%d cir_BPP=%u, scaled_limit=%u => "
               "effective BPS=%llu, accuracy=%f\n",
          // input values
            (unsigned long long)hz,
            (unsigned long long)cir_rate,
            orig_current_limit,
          // computed values
            (uint32_t)(period),                   // periods per second 
            (uint32_t)(1000.0 * 1000.0 / period), // in usec
            *scale,
            *cir_bytes_per_period,
            *current_limit,
          // accuracy
            (unsigned long long)effective_BPS,
            (double)cir_rate / (double)effective_BPS);
    }
#endif

    return 0; // ok
}


/*
 * Input: configured parameters in 'cfg'.
 * Output: h/w parameters are returned in 'hw',
 * Return: Status, success or failure code.
 */
trans_layer_rc
x86_pol_compute_hw_params (sse2_qos_pol_cfg_params_st *cfg,
                           policer_read_response_type_st *hw)
{
    const int BYTES_PER_KBIT = (1000 / 8);
    uint64_t hz;
    uint32_t cap;

    if (!cfg || !hw) {
        SSE2_QOS_DEBUG_ERROR("Illegal parameters");
        return(Not_OK);
    }

    hz = get_tsc_hz();
    hw->last_update_time = 0;

    // Cap the bursts to 32-bits. This allows up to almost one second of
    // burst on a 40GE interface, which should be fine for x86.
    cap = (cfg->rb.kbps.cb_bytes > 0xFFFFFFFF) ? 0xFFFFFFFF : cfg->rb.kbps.cb_bytes;
    hw->current_limit = cap;
    cap = (cfg->rb.kbps.eb_bytes > 0xFFFFFFFF) ? 0xFFFFFFFF : cfg->rb.kbps.eb_bytes;
    hw->extended_limit = cap;

    if ((cfg->rb.kbps.cir_kbps == 0) && (cfg->rb.kbps.cb_bytes == 0) && (cfg->rb.kbps.eb_bytes == 0)) {
        // This is a uninitialized, always-violate policer
        hw->single_rate = 1;
        hw->cir_tokens_per_period = 0;
        return OK_pushHW;
    }

    if ((cfg->rfc == SSE2_QOS_POLICER_TYPE_1R2C) ||
        (cfg->rfc == SSE2_QOS_POLICER_TYPE_1R3C_RFC_2697)) {
        // Single-rate policer

        hw->single_rate = 1;

        if ((cfg->rfc == SSE2_QOS_POLICER_TYPE_1R2C) && cfg->rb.kbps.eb_bytes) {
            SSE2_QOS_DEBUG_ERROR("Policer parameter validation failed -- 1R2C.");
            return(Not_OK);
        }

        if ((cfg->rb.kbps.cir_kbps == 0) ||
            (cfg->rb.kbps.eir_kbps != 0) ||
            ((cfg->rb.kbps.cb_bytes == 0) && (cfg->rb.kbps.eb_bytes == 0))) {
            SSE2_QOS_DEBUG_ERROR("Policer parameter validation failed -- 1R.");
            return(Not_OK);
        }

        if (compute_policer_params(hz, 
                                   (uint64_t)cfg->rb.kbps.cir_kbps * BYTES_PER_KBIT, 
                                   0,
                                   &hw->current_limit, 
                                   &hw->extended_limit,
                                   &hw->cir_tokens_per_period,
                                   &hw->pir_tokens_per_period, 
                                   &hw->scale)) {
            SSE2_QOS_DEBUG_ERROR("Policer parameter computation failed.");
            return(Not_OK);
        }

    } else if ((cfg->rfc == SSE2_QOS_POLICER_TYPE_2R3C_RFC_2698) ||
               (cfg->rfc == SSE2_QOS_POLICER_TYPE_2R3C_RFC_4115)) {
        // Two-rate policer

        if ((cfg->rb.kbps.cir_kbps == 0) || (cfg->rb.kbps.eir_kbps == 0) || (cfg->rb.kbps.eir_kbps < cfg->rb.kbps.cir_kbps) ||
                (cfg->rb.kbps.cb_bytes == 0) || (cfg->rb.kbps.eb_bytes == 0)) {
            SSE2_QOS_DEBUG_ERROR("Config parameter validation failed.");
            return(Not_OK);
        }

        if (compute_policer_params(hz, 
                                   (uint64_t)cfg->rb.kbps.cir_kbps * BYTES_PER_KBIT, 
                                   (uint64_t)cfg->rb.kbps.eir_kbps * BYTES_PER_KBIT, 
                                   &hw->current_limit, 
                                   &hw->extended_limit,
                                   &hw->cir_tokens_per_period,
                                   &hw->pir_tokens_per_period, 
                                   &hw->scale)) {
            SSE2_QOS_DEBUG_ERROR("Policer parameter computation failed.");
            return(Not_OK);
        }

    } else {
        SSE2_QOS_DEBUG_ERROR("Config parameter validation failed. RFC not supported");
        return(Not_OK);
    }

    hw->current_bucket = hw->current_limit;
    hw->extended_bucket = hw->extended_limit;

    return OK_pushHW;
}
#endif


/*
 * Input: configured parameters in 'cfg'.
 * Output: physical structure is returned in 'phys',
 * Return: Status, success or failure code.
 */
trans_layer_rc
sse2_pol_logical_2_physical (sse2_qos_pol_cfg_params_st    *cfg,
                             policer_read_response_type_st *phys)
{
    trans_layer_rc rc;
    sse2_qos_pol_hw_params_st pol_hw;
    sse2_qos_pol_cfg_params_st kbps_cfg;

    memset(phys, 0, sizeof(policer_read_response_type_st));
    memset(&kbps_cfg, 0, sizeof(sse2_qos_pol_cfg_params_st));

    if (!cfg) {
        SSE2_QOS_DEBUG_ERROR("Illegal parameters");
        return(Not_OK);
    }

    switch (cfg->rate_type) {
    case SSE2_QOS_RATE_KBPS:
        /* copy all the data into kbps_cfg */
        kbps_cfg.rb.kbps.cir_kbps = cfg->rb.kbps.cir_kbps;
        kbps_cfg.rb.kbps.eir_kbps = cfg->rb.kbps.eir_kbps;
        kbps_cfg.rb.kbps.cb_bytes = cfg->rb.kbps.cb_bytes;
        kbps_cfg.rb.kbps.eb_bytes = cfg->rb.kbps.eb_bytes;
        break;
    case SSE2_QOS_RATE_PPS:
        kbps_cfg.rb.kbps.cir_kbps =
            sse2_qos_convert_pps_to_kbps(cfg->rb.pps.cir_pps);
        kbps_cfg.rb.kbps.eir_kbps =
            sse2_qos_convert_pps_to_kbps(cfg->rb.pps.eir_pps);
        kbps_cfg.rb.kbps.cb_bytes = sse2_qos_convert_burst_ms_to_bytes(
            (uint32_t) cfg->rb.pps.cb_ms, kbps_cfg.rb.kbps.cir_kbps);
        kbps_cfg.rb.kbps.eb_bytes = sse2_qos_convert_burst_ms_to_bytes(
            (uint32_t) cfg->rb.pps.eb_ms, kbps_cfg.rb.kbps.eir_kbps);
        break;
    default:
        SSE2_QOS_DEBUG_ERROR("Illegal rate type");
        return(Not_OK);
    }

    /* rate type is now converted to kbps */
    kbps_cfg.rate_type = SSE2_QOS_RATE_KBPS;
    kbps_cfg.rnd_type  = cfg->rnd_type;
    kbps_cfg.rfc       = cfg->rfc;

    phys->action[POLICE_CONFORM]    = cfg->conform_action.action_type;
    phys->mark_dscp[POLICE_CONFORM] = cfg->conform_action.dscp;
    phys->action[POLICE_EXCEED]     = cfg->exceed_action.action_type;
    phys->mark_dscp[POLICE_EXCEED]  = cfg->exceed_action.dscp;
    phys->action[POLICE_VIOLATE]    = cfg->violate_action.action_type;
    phys->mark_dscp[POLICE_VIOLATE] = cfg->violate_action.dscp;

    phys->color_aware = cfg->color_aware;

#if !defined (INTERNAL_SS) && !defined (X86)
    // convert logical into hw params which involves qos calculations
    rc = sse2_pol_compute_hw_params(&kbps_cfg, &pol_hw);
    if (rc == Not_OK) {
        SSE2_QOS_DEBUG_ERROR("Unable to compute hw param. Error: %d", rc);
        return (rc);
    }

    // convert hw params into the physical
    phys->rfc  = pol_hw.rfc;
    phys->an   = pol_hw.allow_negative;
    phys->rexp = pol_hw.rate_exp;
    phys->arm  = pol_hw.avg_rate_man;
    phys->prm  = pol_hw.peak_rate_man;
    phys->cble = pol_hw.comm_bkt_limit_exp;
    phys->cblm = pol_hw.comm_bkt_limit_man;
    phys->eble = pol_hw.extd_bkt_limit_exp;
    phys->eblm = pol_hw.extd_bkt_limit_man;
    phys->cb   = pol_hw.comm_bkt;
    phys->eb   = pol_hw.extd_bkt;

    /* for debugging purposes, the bucket token values can be overwritten */
    if (cfg->overwrite_bucket) {
        phys->cb = cfg->current_bucket;
        phys->eb = cfg->extended_bucket;
    }
#else
    // convert logical into hw params which involves qos calculations
    rc = x86_pol_compute_hw_params(&kbps_cfg, phys);
    if (rc == Not_OK) {
        SSE2_QOS_DEBUG_ERROR("Unable to compute hw param. Error: %d", rc);
        return (rc);
    }

    /* for debugging purposes, the bucket token values can be overwritten */
    if (cfg->overwrite_bucket) {
        phys->current_bucket = cfg->current_bucket;
        phys->extended_bucket = cfg->extended_bucket;
    }

    // Touch to avoid compiler warning for X86
    pol_hw.allow_negative = pol_hw.allow_negative;

#endif // if !defined (INTERNAL_SS) && !defined (X86)

    return OK_pushHW;
}


static void
sse2_qos_convert_pol_bucket_to_hw_fmt (
    policer_read_response_type_st *bkt,
    sse2_qos_pol_hw_params_st *hw_fmt)
{
    memset(hw_fmt, 0, sizeof(sse2_qos_pol_hw_params_st));
#if !defined (INTERNAL_SS) && !defined (X86)
    hw_fmt->rfc = (uint8_t)bkt->rfc;
    hw_fmt->allow_negative = (uint8_t)bkt->an;
    hw_fmt->rate_exp = (uint8_t)bkt->rexp;
    hw_fmt->avg_rate_man = (uint16_t)bkt->arm;
    hw_fmt->peak_rate_man = (uint16_t)bkt->prm;
    hw_fmt->comm_bkt_limit_man = (uint8_t)bkt->cblm;
    hw_fmt->comm_bkt_limit_exp = (uint8_t)bkt->cble;
    hw_fmt->extd_bkt_limit_man = (uint8_t)bkt->eblm;
    hw_fmt->extd_bkt_limit_exp = (uint8_t)bkt->eble;
    hw_fmt->extd_bkt = bkt->eb;
    hw_fmt->comm_bkt = bkt->cb;
#endif // if !defined (INTERNAL_SS) && !defined (X86)
}

/*
 * Input: h/w programmable parameter values in 'hw'
 * Output: configured parameter values in 'cfg'
 * Return: Status, success or failure code.
 */
static cerrno
sse2_pol_convert_hw_to_cfg_params (sse2_qos_pol_hw_params_st  *hw,
                                   sse2_qos_pol_cfg_params_st *cfg)
{
    uint64_t temp_rate;

    if ((hw == NULL) || (cfg == NULL)) {
        return EINVAL;
    }

    if ((hw->rfc == IPE_RFC_RFC4115) &&
        !(hw->peak_rate_man << hw->rate_exp) &&
        !(hw->extd_bkt_limit_man)) {
        /*
         * For a 1R2C, we set EIR = 0, EB = 0
         */
        cfg->rfc = SSE2_QOS_POLICER_TYPE_1R2C;
    } else if (hw->rfc == IPE_RFC_RFC2697) {
        cfg->rfc = SSE2_QOS_POLICER_TYPE_1R3C_RFC_2697;
    } else if (hw->rfc == IPE_RFC_RFC2698) {
        cfg->rfc = SSE2_QOS_POLICER_TYPE_2R3C_RFC_2698;
    } else if (hw->rfc == IPE_RFC_RFC4115) {
        cfg->rfc = SSE2_QOS_POLICER_TYPE_2R3C_RFC_4115;
    } else if (hw->rfc == IPE_RFC_MEF5CF1) {
        cfg->rfc = SSE2_QOS_POLICER_TYPE_2R3C_RFC_MEF5CF1;
    } else {
        return EINVAL;
    }

    temp_rate = ((hw->avg_rate_man << hw->rate_exp) * 8LL *
                SSE2_QOS_POL_TICKS_PER_SEC)/1000;
    cfg->rb.kbps.cir_kbps = (uint32_t)temp_rate;

    temp_rate = ((hw->peak_rate_man << hw->rate_exp) * 8LL *
                SSE2_QOS_POL_TICKS_PER_SEC)/1000;
    cfg->rb.kbps.eir_kbps = (uint32_t)temp_rate;

    cfg->rb.kbps.cb_bytes = ((uint64_t)hw->comm_bkt_limit_man << 
                            (uint64_t)hw->comm_bkt_limit_exp);
    cfg->rb.kbps.eb_bytes = ((uint64_t)hw->extd_bkt_limit_man << 
                            (uint64_t)hw->extd_bkt_limit_exp);

    if (cfg->rfc == SSE2_QOS_POLICER_TYPE_1R3C_RFC_2697) {
       /*
        * For 1R3C in the hardware, EB = sum(CB, EB). Also, EIR = CIR. Restore
        * values such that the configured params don't reflect this adjustment
        */
        cfg->rb.kbps.eb_bytes = (cfg->rb.kbps.eb_bytes -
                                 cfg->rb.kbps.cb_bytes);
        cfg->rb.kbps.eir_kbps = 0;
    } else if (cfg->rfc == SSE2_QOS_POLICER_TYPE_2R3C_RFC_4115) {
       /*
        * For 4115 in the hardware is excess rate and burst, but EA provides
        * peak-rate, so adjust it to be eir
        */
        cfg->rb.kbps.eir_kbps += cfg->rb.kbps.cir_kbps;
        cfg->rb.kbps.eb_bytes += cfg->rb.kbps.cb_bytes;
    }
    /* h/w conversion to cfg is in kbps */
    cfg->rate_type        = SSE2_QOS_RATE_KBPS;
    cfg->overwrite_bucket = 0;
    cfg->current_bucket   = hw->comm_bkt;
    cfg->extended_bucket  = hw->extd_bkt;

    SSE2_QOS_DEBUG_INFO("configured params, cir: %u kbps, eir: %u kbps, cb "
                     "burst: 0x%llx bytes, eb burst: 0x%llx bytes",
                        cfg->rb.kbps.cir_kbps, cfg->rb.kbps.eir_kbps,
                        cfg->rb.kbps.cb_bytes, cfg->rb.kbps.eb_bytes);
    SSE2_QOS_TR_INFO(SSE2_QOS_TP_INFO_22, cfg->rb.kbps.cir_kbps,
                   cfg->rb.kbps.eir_kbps,
                   (uint)cfg->rb.kbps.cb_bytes, (uint)cfg->rb.kbps.eb_bytes);

    return EOK;
}

uint32_t
sse2_qos_convert_kbps_to_pps (uint32_t rate_kbps)
{
    uint64_t numer, denom, rnd_value = 0;

    // sse_qosrm_ship_inc_counter(SSE2_QOS_SHIP_COUNTER_TYPE_API_CNT,
    //                            SSE2_QOS_SHIP_CNT_POL_CONV_KBPS_TO_PPS);

    numer = (uint64_t)((uint64_t)rate_kbps * 1000LL);
    denom = (uint64_t)((uint64_t)SSE2_QOS_POLICER_FIXED_PKT_SIZE * 8LL);

    (void)sse2_qos_pol_round(numer, denom, &rnd_value,
                             SSE2_QOS_ROUND_TO_CLOSEST);

    return((uint32_t)rnd_value);
}

uint32_t
sse2_qos_convert_burst_bytes_to_ms (uint64_t burst_bytes,
                                    uint32_t rate_kbps)
{
    uint64_t numer, denom, rnd_value = 0;

    //sse_qosrm_ship_inc_counter(SSE2_QOS_SHIP_COUNTER_TYPE_API_CNT,
    //                         SSE2_QOS_SHIP_CNT_POL_CONV_BYTES_TO_BURST_MS);

    numer = burst_bytes * 8LL;
    denom = (uint64_t)rate_kbps;

    (void)sse2_qos_pol_round(numer, denom, &rnd_value,
                             SSE2_QOS_ROUND_TO_CLOSEST);

    return((uint32_t)rnd_value);
}

/*
 * Input: physical structure in 'phys', rate_type in cfg
 * Output: configured parameters in 'cfg'.
 * Return: Status, success or failure code.
 */
trans_layer_rc
sse2_pol_physical_2_logical (policer_read_response_type_st *phys,
                             sse2_qos_pol_cfg_params_st    *cfg)
{
    cerrno rc;
    sse2_qos_pol_hw_params_st pol_hw;
    sse2_qos_pol_cfg_params_st kbps_cfg;

    memset(&pol_hw, 0, sizeof(sse2_qos_pol_hw_params_st));
    memset(&kbps_cfg, 0, sizeof(sse2_qos_pol_cfg_params_st));

    if (!phys) {
        SSE2_QOS_DEBUG_ERROR("Illegal parameters");
        return(Not_OK);
    }

    sse2_qos_convert_pol_bucket_to_hw_fmt (phys, &pol_hw);

    rc = sse2_pol_convert_hw_to_cfg_params(&pol_hw, &kbps_cfg);
    if (CERR_IS_NOTOK(rc)) {
        SSE2_QOS_DEBUG_ERROR("Unable to convert hw params to config params. "
                            "Error: %d", rc);
        return(Not_OK);
    }

    /* check what rate type is required */
    switch (cfg->rate_type) {
    case SSE2_QOS_RATE_KBPS:
        /* copy all the data into kbps_cfg */
        cfg->rb.kbps.cir_kbps = kbps_cfg.rb.kbps.cir_kbps;
        cfg->rb.kbps.eir_kbps = kbps_cfg.rb.kbps.eir_kbps;
        cfg->rb.kbps.cb_bytes = kbps_cfg.rb.kbps.cb_bytes;
        cfg->rb.kbps.eb_bytes = kbps_cfg.rb.kbps.eb_bytes;
        break;
    case SSE2_QOS_RATE_PPS:
        cfg->rb.pps.cir_pps =
            sse2_qos_convert_kbps_to_pps(kbps_cfg.rb.kbps.cir_kbps);
        cfg->rb.pps.eir_pps =
            sse2_qos_convert_kbps_to_pps(kbps_cfg.rb.kbps.eir_kbps);
        cfg->rb.pps.cb_ms = sse2_qos_convert_burst_bytes_to_ms(
            kbps_cfg.rb.kbps.cb_bytes, kbps_cfg.rb.kbps.cir_kbps);
        cfg->rb.pps.eb_ms = sse2_qos_convert_burst_bytes_to_ms(
            kbps_cfg.rb.kbps.eb_bytes, kbps_cfg.rb.kbps.eir_kbps);
        break;
    default:
        SSE2_QOS_DEBUG_ERROR("Illegal rate type");
        return(Not_OK);
    }

    /* cfg->rate_type remains what it was */
    cfg->rnd_type         = kbps_cfg.rnd_type;
    cfg->rfc              = kbps_cfg.rfc;
    cfg->overwrite_bucket = kbps_cfg.overwrite_bucket;
    cfg->current_bucket   = kbps_cfg.current_bucket;
    cfg->extended_bucket  = kbps_cfg.extended_bucket;

    return OK_pushHW;
}
