/*
 * Copyright (c) 2024 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_SESSION_SESSION_SDL_H_
#define SRC_VNET_SESSION_SESSION_SDL_H_

#include <vnet/vnet.h>
#include <vnet/session/session_table.h>
#include <vnet/session/session_rules_table.h>

clib_error_t *session_sdl_enable_disable (int enable);
void session_sdl_rules_table_init (session_table_t *st,
				   session_rules_table_t *srt, const u8 *ns_id,
				   u32 fib_proto, u32 scope);
void session_sdl_rules_table_free (session_table_t *st,
				   session_rules_table_t *srt, u32 fib_proto);
void session_sdl_block_init (session_sdl_block_t *sdlb);

#endif /* SRC_VNET_SESSION_SESSION_SDL_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
