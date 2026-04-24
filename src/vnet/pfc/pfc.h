/*
 * Copyright (c) 2025 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef _PFC_H_
#define _PFC_H_

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <vnet/dev/types.h>

/**
 * This enum indicates the flow control mode
 */
typedef enum
{
  /** Disable flow control. */
  PFC_ETH_FC_NONE = 0,
  /** Rx pause frame, enable flowctrl on Tx side. */
  PFC_ETH_FC_RX_PAUSE,
  /** Tx pause frame, enable flowctrl on Rx side. */
  PFC_ETH_FC_TX_PAUSE,
  /**< Enable flow control on both side. */
  PFC_ETH_FC_FULL
} pfc_mode_t;

/**
 * PFC Capabilities params
 */
typedef struct pfc_capa_params_
{
  /** Maximum supported traffic class as per PFC (802.1Qbb) specification. */
  uint8_t tc_max;
  /** PFC mode capabilities. */
  pfc_mode_t mode;
} pfc_capa_params_t;

/**
 * A structure used to configure priority flow control on
 * ethernet device for given Rx/Tx queues.
 */
typedef struct pfc_params_
{
  /** Flow control mode */
  pfc_mode_t mode;
  /** Structure shall be used to configure given tx_qid with corresponding tc.
   * When device receives PFC frame with mentioned tc, traffic will be paused
   * on tx_qid for that tc.
   * Valid when (mode == PFC_ETH_FC_RX_PAUSE || mode == PFC_ETH_FC_FULL)
   */
  struct
  {
    /** Tx queue ID */
    uint16_t txq;
    /** Traffic class as per PFC (802.1Qbb) spec. The value must be
     * in the range [0, max_tx_queues - 1]
     */
    uint8_t tc;
  } rx_pause;
  /**
   * Structure shall be used to configure pfc on given rx_qid.
   * When rx_qid is congested, PFC frames are generated with tc
   * and pause_time to the peer.
   * Valid when (mode == PFC_ETH_FC_TX_PAUSE || mode == PFC_ETH_FC_FULL)
   */
  struct
  {
    /** Pause quota in the Pause frame */
    uint16_t pause_time;
    /** Rx queue ID */
    uint16_t rxq;
    /** Traffic class as per PFC (802.1Qbb) spec. The value must be
     * in the range [0, max_rx_queues - 1]
     */
    uint8_t tc;
  } tx_pause;
} pfc_params_t;

typedef struct pfc_system_t_
{
  u32 hw_if_idx;
  int (*pfc_configure) (u32 hw_if_idx, pfc_params_t *params);
  int (*pfc_get_capabilities) (u32 hw_if_idx, pfc_capa_params_t *capa_param);
  int (*pfc_disable_pause_frame_flow_ctrl) (u32 hw_if_idx, u32 disable);
} pfc_system_t;

/**
 * @brief Configure priority flow control on given device.
 * @param hw_if_idx - Hardware interface index.
 * @param capa_param - Pointer to structure containing pfc parameters.
 */
int pfc_sys_configure (u32 hw_if_idx, pfc_params_t *params);

/**
 * @brief Read capabilities for a pfc system.
 * @param hw_if_idx - Hardware interface index.
 * @param capa_param - Pointer to structure where capabilities are to be
 * filled.
 */
int pfc_sys_get_capabilities (u32 hw_if_idx, pfc_capa_params_t *capa_param);

/**
 * @brief Disable pause flow control.
 * @param hw_if_idx - Hardware interface index.
 * @param disable - Flag to toggle pause flow control.
 */
int pfc_sys_disable_pause_frame_flow_ctrl (u32 hw_if_idx, u32 disable);

/**
 * @brief Register the Priority Flow Control (PFC) system.
 *
 * @param pfc_sys - Pointer to the PFC system structure to be registered.
 * @param hw_if_idx - Hardware interface index.
 *
 * @return 0 on success.
 */
int pfc_system_register (pfc_system_t *pfc_sys, u32 hw_if_idx);
#endif
