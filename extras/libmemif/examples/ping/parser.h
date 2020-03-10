/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef _PARSER_H_
#define _PARSER_H_

#include <libmemif.h>
#include "common.h"

void assign_unique_id (memif_connection_t * c, int idx_max);
int bad_params (memif_connection_t * c, char **err_msg);
int set_affinity_cpu (char *saveptr1, char **err_msg);
int set_arg_conn (memif_connection_t * c, char *saveptr1, char **err_msg);
int parse_arg (char argv[], char **err_msg);
int valid_ping (char *arg, uint8_t ip_ping[4], int *ping_index,
		int *ping_qid);

#endif /* _PARSER_H_ */
