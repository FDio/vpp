/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_HSI_HSI_H_
#define SRC_PLUGINS_HSI_HSI_H_

#include <hsi/hsi_types.h>

__clib_export void hsi_intercept_proto (transport_proto_t proto, u8 is_ip4,
					u8 is_enable);
/*
 * s0 must belong to the calling worker. For sessions on different workers, the
 * app must call once from each worker with the local session passed as s0.
 */
__clib_export int hsi_track_session_pair (session_t *s0, session_t *s1);

#endif /* SRC_PLUGINS_HSI_HSI_H_ */
