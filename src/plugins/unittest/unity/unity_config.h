/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_unity_config_h__
#define __included_unity_config_h__
#include <vlib/vlib.h>
#define UNITY_EXCLUDE_SETJMP_H	1
#define UNITY_EXCLUDE_LONGJMP_H 1
#define UNITY_EXCLUDE_MATH_H	1
#define UNITY_EXCLUDE_STDDEF_H	1
#define UNITY_EXCLUDE_STDINT_H	1
#define UNITY_EXCLUDE_LIMITS_H	1
#define UNITY_OUTPUT_CHAR(a)                                                  \
  do                                                                          \
    {                                                                         \
      extern u8 *_sfdp_unittest_pending_output;                               \
      _sfdp_unittest_pending_output =                                         \
	format (_sfdp_unittest_pending_output, "%c", (a));                    \
    }                                                                         \
  while (0)

#define UNITY_OUTPUT_FLUSH()                                                  \
  do                                                                          \
    {                                                                         \
      extern u8 *_sfdp_unittest_pending_output;                               \
      vlib_cli_output (vlib_get_main (), "%v",                                \
		       _sfdp_unittest_pending_output);                        \
      vec_reset_length (_sfdp_unittest_pending_output);                       \
    }                                                                         \
  while (0)
#endif /* __included_unity_config_h__ */