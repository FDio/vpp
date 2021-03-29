/*
 * fuzzer.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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

//https://reviews.llvm.org/rG34ddf0b2b040918a6c946f589eeaf1d4fef95e7a

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <fuzzer/fuzzer.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

fuzzer_main_t fuzzer_main;


static char *args[] = { "/tmp/fuzzer", 0 };


__clib_export int LLVMFuzzerRunDriver(int *argc, char ***argv,
                  int (*UserCb)(const void *Data, uword Size)) {
	clib_warning("Hello!");
	return 0;
}


extern int fuzzer_lib_main(int argc, char **argv);

static clib_error_t *
fuzzer_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  fuzzer_lib_main(1, args);
  return 0;
}

int LLVMFuzzerTestOneInput(const void *ptr, uword len) {
	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (fuzzer_enable_disable_command, static) =
{
  .path = "fuzzer enable-disable",
  .short_help =
  "fuzzer enable-disable <interface-name> [disable]",
  .function = fuzzer_enable_disable_command_fn,
};
/* *INDENT-ON* */

static clib_error_t * fuzzer_init (vlib_main_t * vm)
{
  fuzzer_main_t * fmp = &fuzzer_main;
  clib_error_t * error = 0;

  fmp->vlib_main = vm;
  fmp->vnet_main = vnet_get_main();

  return error;
}

VLIB_INIT_FUNCTION (fuzzer_init);

VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "fuzzer plugin description goes here",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
