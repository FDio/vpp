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
#ifndef included_stat_client_h
#define included_stat_client_h

#include <vlib/vlib.h>
#include <vpp/stats/stats.h>

typedef struct {
  stat_directory_type_t type;
  union {
    f64 scalar_value;
    u64 error_value;
    u64 *vector_pointer;
    vlib_counter_t *counter_vec;
  };
} stat_segment_data_t;

int stat_segment_connect (char *socket_name);
int stat_segment_disconnect (void);
int stat_segment_register (u8 **counter_vec);
int stat_segment_collect (void);
u8 **stat_segment_ls (char *pattern);
stat_segment_data_t *stat_segment_dump (u8 **counter_vec);

#endif /* included_stat_client_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
