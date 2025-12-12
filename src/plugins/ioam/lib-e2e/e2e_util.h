/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_LIB_E2E_E2E_UTIL_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_LIB_E2E_E2E_UTIL_H_

#include <ioam/lib-e2e/ioam_seqno_lib.h>

typedef CLIB_PACKED(struct {
  u8 e2e_type;
  u8 reserved;
  u32 e2e_data;
}) ioam_e2e_packet_t;

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_LIB_E2E_E2E_UTIL_H_ */
