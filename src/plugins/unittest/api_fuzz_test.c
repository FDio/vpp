/*
 *------------------------------------------------------------------
 * api_fuzz_test.c - Binary API fuzz hook
 *
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
#include <vppinfra/format.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/error.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>

static u32 fuzz_seed = 0xdeaddabe;
static u16 fuzz_first;
static u16 fuzz_cli_first, fuzz_cli_last;

extern void (*vl_msg_api_fuzz_hook) (u16, void *);

static void
fuzz_hook (u16 id, void *the_msg)
{
  /*
   * Fuzz (aka screw up) this message? Leave connection establishment
   * messages alone as well as CLI messages.
   */
  if ((id > fuzz_first) && !(id >= fuzz_cli_first && id < fuzz_cli_last))
    {
      msgbuf_t *mb;
      u8 *limit, *start;

      mb = (msgbuf_t *) (((u8 *) the_msg) - offsetof (msgbuf_t, data));

      limit = (u8 *) (mb->data + ntohl (mb->data_len));

      /*
       * Leave the first 14 octets alone, aka msg_id, client_index,
       * context, sw_if_index
       */

      start = ((u8 *) the_msg) + 14;

      for (; start < limit; start++)
	*start ^= (random_u32 (&fuzz_seed) & 0xFF);
    }
}

static void
default_fuzz_config (void)
{
  fuzz_first = vl_msg_api_get_msg_index
    ((u8 *) "memclnt_keepalive_reply_e8d4e804");
  fuzz_cli_first = vl_msg_api_get_msg_index ((u8 *) "cli_23bfbfff");
  fuzz_cli_last = vl_msg_api_get_msg_index
    ((u8 *) "cli_inband_reply_05879051");
}

static clib_error_t *
test_api_fuzz_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 tmp;

  default_fuzz_config ();

  if (fuzz_first == 0xFFFF)
    {
      vlib_cli_output (vm, "Couldn't find 'memclnt_keepalive_reply' ID");
      vlib_cli_output
	(vm, "Manual setting required, use 'show api message table'");
    }

  if (fuzz_cli_first == 0xFFFF)
    {
      vlib_cli_output (vm, "Couldn't find 'cli' ID");
      vlib_cli_output
	(vm, "Manual setting required, use 'show api message table'");
    }

  if (fuzz_cli_last == 0xFFFF)
    {
      vlib_cli_output (vm, "Couldn't find 'cli_inband_reply' ID");
      vlib_cli_output
	(vm, "Manual setting required, use 'show api message table'");
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "seed %d", &fuzz_seed))
	;
      else if (unformat (input, "disable") | unformat (input, "off"))
	fuzz_first = ~0;
      else if (unformat (input, "fuzz-first %d", &tmp))
	fuzz_first = (u16) tmp;
      else if (unformat (input, "fuzz-cli-first %d", &tmp))
	fuzz_cli_first = (u16) tmp;
      else if (unformat (input, "fuzz-cli-last %d", &tmp))
	fuzz_cli_last = (u16) tmp;
      else
	break;
    }

  if (fuzz_first == 0xFFFF)
    {
      vl_msg_api_fuzz_hook = 0;
      return clib_error_return (0, "fuzz_first is ~0, fuzzing disabled");
    }
  vl_msg_api_fuzz_hook = fuzz_hook;

  vlib_cli_output (vm, "Fuzzing enabled: first %d, skip cli range %d - %d",
		   (u32) fuzz_first, (u32) fuzz_cli_first,
		   (u32) fuzz_cli_last);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_api_fuzz, static) = {
   .path = "test api fuzz",
   .short_help = "test api fuzz [disable][seed nnn]\n"
   "           [fuzz-first nn][fuzz-cli-first nn][fuzz-cli-last nn]",
   .function = test_api_fuzz_command_fn,
  };
/* *INDENT-ON* */

static u8 main_loop_enter_enable_api_fuzz;

static clib_error_t *
api_fuzz_config (vlib_main_t * vm, unformat_input_t * input)
{
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "off")
	  || unformat (input, "disable") || unformat (input, "no"))
	;			/* ok, no action */
      else if (unformat (input, "on")
	       || unformat (input, "enable") || unformat (input, "yes"))
	main_loop_enter_enable_api_fuzz = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (api_fuzz_config, "api-fuzz");

static clib_error_t *
api_fuzz_api_init (vlib_main_t * vm)
{
  /* Are we supposed to fuzz API messages? */
  if (main_loop_enter_enable_api_fuzz == 0)
    return 0;

  default_fuzz_config ();

  if (fuzz_first == 0xFFFF)
    {
      return clib_error_return
	(0, "Couldn't find 'memclnt_keepalive_reply' ID");
    }
  /* Turn on fuzzing */
  vl_msg_api_fuzz_hook = fuzz_hook;
  return 0;
}

VLIB_API_INIT_FUNCTION (api_fuzz_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
