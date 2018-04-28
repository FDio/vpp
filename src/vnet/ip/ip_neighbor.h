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

#endif /* included_ip_neighbor_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
