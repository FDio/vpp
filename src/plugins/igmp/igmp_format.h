/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#ifndef _IGMP_FORMAT_H_
#define _IGMP_FORMAT_H_

extern u8 *format_igmp_type (u8 * s, va_list * args);

extern u8 *format_igmp_membership_group_type (u8 * s, va_list * args);

extern u8 *format_igmp_header (u8 * s, va_list * args);

extern u8 *format_igmp_report_v3 (u8 * s, va_list * args);

extern u8 *format_igmp_query_v3 (u8 * s, va_list * args);

extern u8 *format_igmp_filter_mode (u8 * s, va_list * args);

extern u8 *format_igmp_src_addr_list (u8 * s, va_list * args);

extern u8 *format_igmp_key (u8 * s, va_list * args);

#endif /* IGMP_FORMAT_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
