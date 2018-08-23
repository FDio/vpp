/*
 * stat_client.h - Library for access to VPP statistics segment
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
#ifndef included_stat_client_h
#define included_stat_client_h

#include <vlib/vlib.h>
#include <vpp/stats/stats.h>

typedef struct
{
  char *name;
  stat_directory_type_t type;
  union
  {
    f64 scalar_value;
    u64 error_value;
    u64 *vector_pointer;
    counter_t **simple_counter_vec;
    vlib_counter_t **combined_counter_vec;
  };
} stat_segment_data_t;

typedef struct
{
  char *name;
  stat_segment_directory_entry_t *ep;
} stat_segment_cached_pointer_t;

int stat_segment_connect (char *socket_name);
void stat_segment_disconnect (void);

u8 **stat_segment_ls (u8 ** pattern);
stat_segment_data_t *stat_segment_dump (u8 ** counter_vec);

stat_segment_cached_pointer_t *stat_segment_register (u8 ** counter_vec);
stat_segment_data_t *stat_segment_collect (stat_segment_cached_pointer_t *);	/* Collects registered counters */

void stat_segment_data_free (stat_segment_data_t * res);

f64 stat_segment_heartbeat (void);

#endif /* included_stat_client_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
