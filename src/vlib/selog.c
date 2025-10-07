/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vlib/selog.h>

clib_error_t *
vlib_selog_update_elog_main (elog_main_t *em)
{
  vlib_selog_main_t *sm = &vlib_selog_main;
  elog_merge (em, 0, sm->elog_main, 0, 0);
  sm->elog_main = em;
  return 0;
}

static clib_error_t *
selog_emit_elog_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  vlib_selog_main_t *sm = &vlib_selog_main;
  elog_main_t *em = sm->elog_main;
  char *msg = 0;

  if (unformat (input, "msg %s", &msg))
    {
      ELOG_TYPE_DECLARE (e) = {
	.format = "selog_emit: %s",
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

static clib_error_t *
vlib_selog_init (vlib_main_t *vm)
{
  elog_main_t *em = vlib_get_elog_main ();
  vlib_selog_main_t *sm = &vlib_selog_main;
  sm->elog_main = em;
  return 0;
}
VLIB_INIT_FUNCTION (vlib_selog_init);
vlib_selog_main_t vlib_selog_main;