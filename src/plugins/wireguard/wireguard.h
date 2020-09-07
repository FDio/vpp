/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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
#ifndef __included_wg_h__
#define __included_wg_h__

#include <wireguard/wireguard_index_table.h>
#include <wireguard/wireguard_messages.h>
#include <wireguard/wireguard_peer.h>

extern vlib_node_registration_t wg_input_node;
extern vlib_node_registration_t wg_output_tun_node;



typedef struct
{
  /* convenience */
  vlib_main_t *vlib_main;

  u16 msg_id_base;

  // Peers pool
  wg_peer_t *peers;
  wg_index_table_t index_table;

} wg_main_t;

extern wg_main_t wg_main;

#endif /* __included_wg_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
