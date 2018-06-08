/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#ifndef _IGMP_ERROR_H_
#define _IGMP_ERROR_H_

#define foreach_igmp_error					\
  _ (NONE, "valid igmp packets")				\
  _ (UNSPECIFIED, "unspecified error")				\
  _ (INVALID_PROTOCOL, "invalid ip4 protocol")			\
  _ (BAD_CHECKSUM, "bad checksum")				\
  _ (UNKNOWN_TYPE, "unknown igmp message type")			\
  _ (NOT_ENABLED, "IGMP not enabled on this interface")         \

typedef enum
{
#define _(sym,str) IGMP_ERROR_##sym,
  foreach_igmp_error
#undef _
    IGMP_N_ERROR,
} igmp_error_t;

#endif /* IGMP_ERROR_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
