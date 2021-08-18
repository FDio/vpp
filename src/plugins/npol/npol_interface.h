/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef included_npol_interface_h
#define included_npol_interface_h

#include <vppinfra/clib.h>

typedef struct
{
  /*
   * vec of policies indexes to apply on rx
   */
  u32 *rx_policies;
  /*
   * vec of policies indexes to apply on tx
   */
  u32 *tx_policies;
  /*
   *vec of policies indexes to use as profiles
   */
  u32 *profiles;
  /* set to 1 when policy is used for interface
   * as policy confs are stored in a sw_if_index
   * indexed vector, initialized to zero
   */
  u8 enabled;
  /*
   * Should we invert RX and TX
   */
  u8 invert_rx_tx;
  /*
   * Default action to apply after all policies on RX
   */
  u8 policy_default_rx;
  /*
   * Default action to apply after all policies on TX
   */
  u8 policy_default_tx;
  /*
   * Default action to apply after profiles on RX
   */
  u8 profile_default_rx;
  /*
   * Default action to apply after profiles on TX
   */
  u8 profile_default_tx;
} npol_interface_config_t;

extern npol_interface_config_t *npol_interface_configs;

int npol_configure_policies (u32 sw_if_index, npol_interface_config_t *conf);

#endif
