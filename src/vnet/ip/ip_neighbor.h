/*
 * ip_neighboor.h: ip neighbor generic services
 *
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

#ifndef included_ip_neighbor_h
#define included_ip_neighbor_h

#define IP_SCAN_DISABLED	0
#define IP_SCAN_V4_NEIGHBORS	(1 << 0)
#define IP_SCAN_V6_NEIGHBORS	(1 << 1)
#define IP_SCAN_V46_NEIGHBORS	(IP_SCAN_V4_NEIGHBORS | IP_SCAN_V6_NEIGHBORS)

typedef struct
{
  u8 mode;			/* 0: disable, 1: ip4, 2: ip6, 3: both */
  u8 scan_interval;		/* neighbor scan interval in minutes */
  u8 max_proc_time;		/* max processing time per run, in usecs */
  u8 max_update;		/* max probe/delete operations per run */
  u8 scan_int_delay;		/* delay in msecs, to resume scan on max */
  u8 stale_threshold;		/* Threashold in minutes to delete nei entry */
} ip_neighbor_scan_arg_t;

void ip_neighbor_scan_enable_disable (ip_neighbor_scan_arg_t * arg);

typedef enum ip_neighbor_flags_t_
{
  IP_NEIGHBOR_FLAG_NONE = 0,
  IP_NEIGHBOR_FLAG_STATIC = (1 << 0),
  IP_NEIGHBOR_FLAG_DYNAMIC = (1 << 1),
  IP_NEIGHBOR_FLAG_NO_FIB_ENTRY = (1 << 2),
} __attribute__ ((packed)) ip_neighbor_flags_t;

extern u8 *format_ip_neighbor_flags (u8 * s, va_list * args);

extern int ip_neighbor_add (const ip46_address_t * ip,
			    ip46_type_t type,
			    const mac_address_t * mac,
			    u32 sw_if_index,
			    ip_neighbor_flags_t flags, u32 * stats_index);

extern int ip_neighbor_del (const ip46_address_t * ip,
			    ip46_type_t type, u32 sw_if_index);

#endif /* included_ip_neighbor_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
