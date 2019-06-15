/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __PUNT_H__
#define __PUNT_H__

#include <vlib/vlib.h>

/**
 * The 'syatem' defined punt reasons.
 * Only add to this list reasons defined and used within the vlib subsystem.
 * To define new reasons in e.g. plgins, use punt_reason_alloc()
 */
typedef enum vlib_punt_reason_t_
{
  PUNT_N_REASONS,
} vlib_punt_reason_t;


/**
 * @brief Format a punt reason
 */
extern u8 *format_vlib_punt_reason (u8 * s, va_list * args);

/**
 * Typedef for a client handle
 */
typedef int vlib_punt_hdl_t;

/**
 * @brief Register a new clinet
 *
 * @param who - The name of the client
 *
 * @retrun the handle the punt infra allocated for this client that must
 *         be used when the client wishes to use the infra
 */
vlib_punt_hdl_t vlib_punt_client_register (const char *who);

/**
 * Allocate a new punt reason
 */
extern int vlib_punt_reason_alloc (vlib_punt_hdl_t client,
				   const char *reason_name,
				   vlib_punt_reason_t * reason);

/**
 * @brief Register a node to receive particular punted buffers
 *
 * @paran client - The registered client registering for the packets
 * @param reason - The reason the packet was punted
 * @param node   - The node to which the punted packets will be sent
 */
extern int vlib_punt_register (vlib_punt_hdl_t client,
			       vlib_punt_reason_t reason, const char *node);
extern int vlib_punt_unregister (vlib_punt_hdl_t client,
				 vlib_punt_reason_t pr, const char *node);

/**
 * FOR USE IN THE DP ONLY
 *
 * Arc[s] to follow for each reason
 */
extern u16 **punt_dp_db;

/**
 * FOR USE IN THE DP ONLY
 *
 * Per-reason counters
 */
extern vlib_combined_counter_main_t punt_counters;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
