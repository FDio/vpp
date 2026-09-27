/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#ifndef __included_fastacl_format_h__
#define __included_fastacl_format_h__

#include <fastacl/fastacl_types.h>

format_function_t format_fastacl_pps;
format_function_t format_fastacl_bps;
format_function_t format_fastacl_count_si;
format_function_t format_fastacl_bytes_si;

const char *fastacl_action_type_name (u8 type);
void fastacl_show_one_rule (vlib_main_t *vm, fastacl_rule_t *rule);

#endif
