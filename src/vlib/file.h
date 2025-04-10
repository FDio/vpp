/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __vlib_file_h__
#define __vlib_file_h__

#include <vppinfra/file.h>

extern clib_file_main_t file_main;

void vlib_file_poll_init (vlib_main_t *vm);
void vlib_file_poll (vlib_main_t *vm);
#endif /* __vlib_file_h__ */
