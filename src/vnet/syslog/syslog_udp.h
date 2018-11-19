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
/**
 * @file syslog protocol UDP transport layer declaration (RFC5426)
 */
#ifndef __included_syslog_udp_h__
#define __included_syslog_udp_h__

#include <vnet/syslog/syslog.h>

/**
 * @brief Add UDP/IP transport layer by prepending it to existing data
 */
void syslog_add_udp_transport (vlib_main_t * vm, u32 bi);

#endif /* __included_syslog_udp_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
