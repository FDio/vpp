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
 * handles deferral and peer worker updates with RPCs. A return value of 0 means
 * HSI owns both sessions and the application must not use them afterwards.
 */
/*
 * Returns 0 once HSI owns both sessions. On success, the application must stop
 * using and closing them; on failure, ownership remains with the caller.
 */
__clib_export int hsi_track_session_pair (session_t *s, session_handle_t peer_session_handle);

#endif /* SRC_PLUGINS_HSI_HSI_H_ */
