/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <sys/mman.h>

static clib_error_t *
test_crash_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u64 *p = (u64 *) 0xdefec8ed;

  /* *INDENT-OFF* */
  ELOG_TYPE_DECLARE (e) =
    {
      .format = "deliberate crash: touching %x",
      .format_args = "i4",
    };
  /* *INDENT-ON* */
  elog (&vlib_global_main.elog_main, &e, 0xdefec8ed);

  *p = 0xdeadbeef;

  /* Not so much... */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_crash_command, static) =
{
  .path = "test crash",
  .short_help = "crash the bus!",
  .function = test_crash_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
test_hash_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  uword hash1, hash2;
  u8 *baseaddr;
  u8 *key_loc;

  baseaddr = mmap (NULL, 8192, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 /* offset */ );

  if (baseaddr == 0)
    {
      clib_unix_warning ("mmap");
      return 0;
    }

  if (mprotect (baseaddr + (4 << 10), (4 << 10), PROT_NONE) < 0)
    {
      clib_unix_warning ("mprotect");
      return 0;
    }

  key_loc = baseaddr + (4 << 10) - 4;
  key_loc[0] = 0xde;
  key_loc[1] = 0xad;
  key_loc[2] = 0xbe;
  key_loc[3] = 0xef;

  hash1 = hash_memory (key_loc, 4, 0ULL);

  vlib_cli_output (vm, "hash1 is %llx", hash1);

  key_loc = baseaddr;

  key_loc[0] = 0xde;
  key_loc[1] = 0xad;
  key_loc[2] = 0xbe;
  key_loc[3] = 0xef;

  hash2 = hash_memory (key_loc, 4, 0ULL);

  vlib_cli_output (vm, "hash2 is %llx", hash2);

  if (hash1 == hash2)
    vlib_cli_output (vm, "PASS...");
  else
    vlib_cli_output (vm, "FAIL...");

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_hash_command, static) =
{
  .path = "test hash_memory",
  .short_help = "page boundary crossing test",
  .function = test_hash_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
