/*
 *------------------------------------------------------------------
 * cj.c
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

/**
 * @file
 * Circular joournal diagnostic mechanism.
 *
 * The @c cj thread-safe circular log buffer scheme is occasionally useful
 * when chasing bugs. Calls to it should not be checked in.
 */
/*? %%clicmd:group_label Circular Journal %% ?*/
/*? %%syscfg:group_label Circular Journal %% ?*/

#include <stdio.h>
#include <vlib/vlib.h>

#include <vlib/unix/cj.h>

cj_main_t cj_main;

void
cj_log (u32 type, void *data0, void *data1)
{
  u64 new_tail;
  cj_main_t *cjm = &cj_main;
  cj_record_t *r;

  if (cjm->enable == 0)
    return;

  new_tail = clib_atomic_add_fetch (&cjm->tail, 1);

  r = (cj_record_t *) & (cjm->records[new_tail & (cjm->num_records - 1)]);
  r->time = vlib_time_now (cjm->vlib_main);
  r->thread_index = vlib_get_thread_index ();
  r->type = type;
  r->data[0] = pointer_to_uword (data0);
  r->data[1] = pointer_to_uword (data1);
}

void
cj_stop (void)
{
  cj_main_t *cjm = &cj_main;

  cjm->enable = 0;
}


clib_error_t *
cj_init (vlib_main_t * vm)
{
  cj_main_t *cjm = &cj_main;

  cjm->vlib_main = vm;
  return 0;
}

VLIB_INIT_FUNCTION (cj_init);

static clib_error_t *
cj_config (vlib_main_t * vm, unformat_input_t * input)
{
  cj_main_t *cjm = &cj_main;
  int matched = 0;
  int enable = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "records %d", &cjm->num_records))
	matched = 1;
      else if (unformat (input, "on"))
	enable = 1;
      else
	return clib_error_return (0, "cj_config: unknown input '%U'",
				  format_unformat_error, input);
    }

  if (matched == 0)
    return 0;

  cjm->num_records = max_pow2 (cjm->num_records);
  vec_validate (cjm->records, cjm->num_records - 1);
  clib_memset (cjm->records, 0xff, cjm->num_records * sizeof (cj_record_t));
  cjm->tail = ~0;
  cjm->enable = enable;

  return 0;
}

/*?
 * Configure the circular journal diagnostic mechanism. This is only useful
 * if you, the developer, have written code to make use of the circular
 * journal.
 *
 * @cfgcmd{records, &lt;number&gt;}
 * Configure the number of records to allocate for the circular journal.
 *
 * @cfgcmd{on}
 * Enable the collection of records in the circular journal at the
 * earliest opportunity.
?*/
VLIB_CONFIG_FUNCTION (cj_config, "cj");

void
cj_enable_disable (int is_enable)
{
  cj_main_t *cjm = &cj_main;

  if (cjm->num_records)
    cjm->enable = is_enable;
  else
    vlib_cli_output (cjm->vlib_main, "CJ not configured...");
}

static inline void
cj_dump_one_record (cj_record_t * r)
{
  fprintf (stderr, "[%d]: %10.6f T%02d %llx %llx\n",
	   r->thread_index, r->time, r->type,
	   (long long unsigned int) r->data[0],
	   (long long unsigned int) r->data[1]);
}

static void
cj_dump_internal (u8 filter0_enable, u64 filter0,
		  u8 filter1_enable, u64 filter1)
{
  cj_main_t *cjm = &cj_main;
  cj_record_t *r;
  u32 i, index;

  if (cjm->num_records == 0)
    {
      fprintf (stderr, "CJ not configured...\n");
      return;
    }

  if (cjm->tail == (u64) ~ 0)
    {
      fprintf (stderr, "No data collected...\n");
      return;
    }

  /* Has the trace wrapped? */
  index = (cjm->tail + 1) & (cjm->num_records - 1);
  r = &(cjm->records[index]);

  if (r->thread_index != (u32) ~ 0)
    {
      /* Yes, dump from tail + 1 to the end */
      for (i = index; i < cjm->num_records; i++)
	{
	  if (filter0_enable && (r->data[0] != filter0))
	    goto skip;
	  if (filter1_enable && (r->data[1] != filter1))
	    goto skip;
	  cj_dump_one_record (r);
	skip:
	  r++;
	}
    }
  /* dump from the beginning through the final tail */
  r = cjm->records;
  for (i = 0; i < index; i++)
    {
      if (filter0_enable && (r->data[0] != filter0))
	goto skip2;
      if (filter1_enable && (r->data[1] != filter1))
	goto skip2;
      cj_dump_one_record (r);
    skip2:
      r++;
    }
}

void
cj_dump (void)
{
  cj_dump_internal (0, 0, 0, 0);
}

void
cj_dump_filter_data0 (u64 filter0)
{
  cj_dump_internal (1 /* enable f0 */ , filter0, 0, 0);
}

void
cj_dump_filter_data1 (u64 filter1)
{
  cj_dump_internal (0, 0, 1 /* enable f1 */ , filter1);
}

void
cj_dump_filter_data12 (u64 filter0, u64 filter1)
{
  cj_dump_internal (1, filter0, 1, filter1);
}

static clib_error_t *
cj_command_fn (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int is_enable = -1;
  int is_dump = -1;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected enable | disable | dump");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable") || unformat (line_input, "on"))
	is_enable = 1;
      else if (unformat (line_input, "disable")
	       || unformat (line_input, "off"))
	is_enable = 0;
      else if (unformat (line_input, "dump"))
	is_dump = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (is_enable >= 0)
    cj_enable_disable (is_enable);

  if (is_dump > 0)
    cj_dump ();

done:
  unformat_free (line_input);
  return error;
}

/*?
 * Enable, disable the collection of diagnostic data into a
 * circular journal or dump the circular journal diagnostic data.
 * This is only useful if you, the deveoper, have written code to make
 * use of the circular journal.
 *
 * When dumping the data it is formatted and sent to @c stderr of the
 * VPP process; when running VPP in <code>unix interactive</code> mode
 * this is typically the same place as the Debug CLI.
?*/

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cj_command,static) = {
  .path = "cj",
  .short_help = "cj <enable | disable | dump>",
  .function = cj_command_fn,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
