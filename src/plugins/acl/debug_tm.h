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

#ifndef _ACL_DEBUG_TM_H_
#define _ACL_DEBUG_TM_H_


#include <stddef.h>
#include "acl.h"



clib_error_t*
acl_describe_partition (vlib_main_t * vm,
                                   unformat_input_t * i,
                                   vlib_cli_command_t * cmd);



clib_error_t*
acl_compare_partition (vlib_main_t * vm,
                                   unformat_input_t * i,
                                   vlib_cli_command_t * cmd);

clib_error_t*
acl_show_collision (vlib_main_t * vm,
                                   unformat_input_t * i,
                                   vlib_cli_command_t * cmd);

#endif
