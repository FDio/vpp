/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef _IGMP_FORMAT_H_
#define _IGMP_FORMAT_H_

extern u8 *format_igmp_type (u8 * s, va_list * args);

extern u8 *format_igmp_membership_group_type (u8 * s, va_list * args);

extern u8 *format_igmp_header (u8 * s, va_list * args);

extern u8 *format_igmp_report_v3 (u8 * s, va_list * args);

extern u8 *format_igmp_query_v3 (u8 * s, va_list * args);

extern u8 *format_igmp_filter_mode (u8 * s, va_list * args);

extern u8 *format_igmp_mode (u8 * s, va_list * args);

extern u8 *format_igmp_src_addr_list (u8 * s, va_list * args);

extern u8 *format_igmp_key (u8 * s, va_list * args);

extern u8 *format_igmp_proxy_device_id (u8 * s, va_list * args);

#endif /* IGMP_FORMAT_H */
