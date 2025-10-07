/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */
#include <vlib/vlib.h>

#include <vlib/cli.h>
#include "selog.h"

static clib_error_t *
selog_emit_elog_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  selog_main_t *sm = &selog_main;
  elog_main_t *em = sm->em;
  char *msg = 0;

  if (unformat (input, "msg %s", &msg))
    {
      ELOG_TYPE_DECLARE (e) = {
	.format = "selog: %s",
	.format_args = "T4",
      };
      struct
      {
	u32 msg_offset;
      } *ed;
      ed = ELOG_DATA (em, e);
      ed->msg_offset = elog_string (em, msg);
      vec_free (msg);
      return 0;
    }
  return clib_error_return (0, "Please specify msg <string>");
}

VLIB_CLI_COMMAND (selog_emit_elog_command, static) = {
  .path = "selog emit-elog",
  .short_help = "selog emit-elog msg <string>",
  .function = selog_emit_elog_command_fn,
};