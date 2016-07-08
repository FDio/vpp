/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vppinfra/elog.h>

static inline void
elog_four_int_sample (u32 * data)
{
  ELOG_TYPE_DECLARE (e) =
  {
  .format = "four int: first %d second %d third %d fourth %d",.format_args =
      "i4i4i4i4",};
  struct
  {
    u32 data[4];
  } *ed;
  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
  ed->data[0] = data[0];
  ed->data[1] = data[1];
  ed->data[2] = data[2];
  ed->data[3] = data[3];
}

static inline void
elog_four_int_track_sample (u32 * data)
{
  ELOG_TYPE_DECLARE (e) =
  {
  .format =
      "four_int_track: first %d second %d third %d fourth %d",.format_args =
      "i4i4i4i4",};
  struct
  {
    u32 data[4];
  } *ed;
  ELOG_TRACK (sample_track);
  ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, sample_track);
  ed->data[0] = data[0];
  ed->data[1] = data[1];
  ed->data[2] = data[2];
  ed->data[3] = data[3];
}

static inline void
elog_enum_sample (u8 which)
{
  ELOG_TYPE_DECLARE (e) =
  {
    .format = "my enum: %s",.format_args = "t1",.n_enum_strings =
      2,.enum_strings =
    {
  "string 1", "string 2",},};
  struct
  {
    u8 which;
  } *ed;
  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
  ed->which = which;
}

static inline void
elog_one_datum_sample (u32 data)
{
  ELOG_TYPE_DECLARE (e) =
  {
  .format = "one datum: %d",.format_args = "i4",};

  elog (&vlib_global_main.elog_main, &e, data);
}

static clib_error_t *
test_elog_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int i;
  u32 samples[4];

  for (i = 0; i < 10; i++)
    {
      samples[0] = i;
      samples[1] = i + 1;
      samples[2] = i + 2;
      samples[3] = i + 3;

      elog_four_int_sample (samples);
      elog_four_int_track_sample (samples);
      elog_enum_sample (0);
      elog_enum_sample (1);
      elog_one_datum_sample (i);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_elog_command, static) = {
  .path = "test elog sample",
  .short_help = "test elog sample",
  .function = test_elog_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
