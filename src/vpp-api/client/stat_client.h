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

#include <stdint.h>
#include <unistd.h>
#include <vlib/counter_types.h>

typedef enum
{
  STAT_DIR_TYPE_ILLEGAL = 0,
  STAT_DIR_TYPE_SCALAR_INDEX,
  STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE,
  STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED,
  STAT_DIR_TYPE_ERROR_INDEX,
  STAT_DIR_TYPE_NAME_VECTOR,
} stat_directory_type_t;

/* Default socket to exchange segment fd */
#define STAT_SEGMENT_SOCKET_FILE "/run/vpp/stats.sock"

typedef struct stat_client_main_t stat_client_main_t;

typedef struct
{
  char *name;
  stat_directory_type_t type;
  union
  {
    double scalar_value;
    uint64_t error_value;
    counter_t **simple_counter_vec;
    vlib_counter_t **combined_counter_vec;
    uint8_t **name_vector;
  };
} stat_segment_data_t;

stat_client_main_t *stat_client_get (void);
void stat_client_free (stat_client_main_t * sm);
int stat_segment_connect_r (const char *socket_name, stat_client_main_t * sm);
int stat_segment_connect (const char *socket_name);
void stat_segment_disconnect_r (stat_client_main_t * sm);
void stat_segment_disconnect (void);
uint8_t **stat_segment_string_vector (uint8_t ** string_vector,
				      const char *string);
int stat_segment_vec_len (void *vec);
void stat_segment_vec_free (void *vec);
uint32_t *stat_segment_ls_r (uint8_t ** patterns, stat_client_main_t * sm);
uint32_t *stat_segment_ls (uint8_t ** pattern);
stat_segment_data_t *stat_segment_dump_r (uint32_t * stats,
					  stat_client_main_t * sm);
stat_segment_data_t *stat_segment_dump (uint32_t * counter_vec);
stat_segment_data_t *stat_segment_dump_entry_r (uint32_t index,
						stat_client_main_t * sm);
stat_segment_data_t *stat_segment_dump_entry (uint32_t index);

void stat_segment_data_free (stat_segment_data_t * res);
double stat_segment_heartbeat_r (stat_client_main_t * sm);
double stat_segment_heartbeat (void);

char *stat_segment_index_to_name_r (uint32_t index, stat_client_main_t * sm);
char *stat_segment_index_to_name (uint32_t index);

#endif /* included_stat_client_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
