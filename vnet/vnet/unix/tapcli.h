/*
 * tapcli.h : tap support
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief TAPCLI definitions
 */

#ifndef __included_tapcli_h__
#define __included_tapcli_h__

/** TAP CLI errors */
#define foreach_tapcli_error				\
  /* Must be first. */                                  \
 _(NONE, "no error")                                    \
 _(READ, "read error")                                  \
 _(BUFFER_ALLOC, "buffer allocation error")             \
 _(UNKNOWN, "unknown error")

typedef enum {
#define _(sym,str) TAPCLI_ERROR_##sym,
  foreach_tapcli_error
#undef _
   TAPCLI_N_ERROR,
 } tapcli_error_t;

/** TAP CLI interface details struct */
typedef struct {
  u32 sw_if_index;
  u8 dev_name[64];
} tapcli_interface_details_t;

int vnet_tap_dump_ifs (tapcli_interface_details_t **out_tapids);

#define TAP_MTU_MIN 68
#define TAP_MTU_MAX 65535
#define TAP_MTU_DEFAULT 1500

#endif /* __included_tapcli_h__ */
