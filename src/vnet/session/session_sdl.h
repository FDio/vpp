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

clib_error_t *session_sdl_enable_disable (int enable);

typedef void (*session_sdl_table_walk_fn_t) (u32 fei, ip46_address_t *lcl_ip,
					     u16 fp_len, u32 action_index,
					     u32 fb_proto, u8 *tag, void *ctx);
void session_sdl_table_walk4 (u32 srt_handle, session_sdl_table_walk_fn_t fn,
			      void *args);
void session_sdl_table_walk6 (u32 srt_handle, session_sdl_table_walk_fn_t fn,
			      void *args);

#endif /* SRC_VNET_SESSION_SESSION_SDL_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
