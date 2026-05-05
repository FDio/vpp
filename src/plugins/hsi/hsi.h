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
 * s must belong to the calling worker. For sessions on different workers, HSI
 * handles the peer worker updates with RPCs.
 */
__clib_export int hsi_track_session_pair (session_t *s, session_handle_t peer_session_handle);
/*
 * Returns 1 if the session pair is ready for pass-through, 0 if it is still
 * draining, and -1 if the session is invalid or not HSI-managed.
 */
__clib_export int hsi_track_session_pair_try_complete (session_t *s);

#endif /* SRC_PLUGINS_HSI_HSI_H_ */
