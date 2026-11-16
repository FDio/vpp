/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* vlib part of the declarative CLI, see vppinfra/cli_decl.h */

#pragma once

#include <vlib/vlib.h>

/* function of the commands which have a handler */
extern vlib_cli_command_function_t cli_dispatch;

/* calls the function of a command which has no handler, applies a trailing
 * "| grep|head|tail|count" of the line to its output */
clib_error_t *vlib_cli_call_function (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *c);
