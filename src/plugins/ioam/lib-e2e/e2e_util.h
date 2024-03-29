/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_LIB_E2E_E2E_UTIL_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_LIB_E2E_E2E_UTIL_H_

#include <ioam/lib-e2e/ioam_seqno_lib.h>

typedef CLIB_PACKED(struct {
  u8 e2e_type;
  u8 reserved;
  u32 e2e_data;
}) ioam_e2e_packet_t;

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_LIB_E2E_E2E_UTIL_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
