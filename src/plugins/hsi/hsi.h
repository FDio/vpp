/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_HSI_HSI_H_
#define SRC_PLUGINS_HSI_HSI_H_

#include <vnet/session/session.h>

typedef enum _hsi_error
{
#define hsi_error(n, s) HSI_ERROR_##n,
#include <hsi/hsi_error.def>
#undef hsi_error
  HSI_N_ERROR,
} hsi_error_t;

__clib_export void hsi_intercept_proto (transport_proto_t proto, u8 is_ip4,
					u8 is_enable);

#endif /* SRC_PLUGINS_HSI_HSI_H_ */
