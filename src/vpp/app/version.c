/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vppinfra/cpu.h>
#include <vpp/app/version.h>

/** \file
    Display image version information
*/

/*? %%clicmd:group_label Image Version Information %% ?*/

/*
 * Version variables are static to ensure that they're visible in core
 * dumps, i.e., not in the rodata segment
 */

/** The image version string */
char *vpe_version_string =
  "vpp v" VPP_BUILD_VER
  " built by " VPP_BUILD_USER " on " VPP_BUILD_HOST " at " VPP_BUILD_DATE;

/** The name of the compiler */
static char *vpe_compiler =
#if defined(__INTEL_COMPILER)
#define __(x) #x
#define _(x) __(x)
  "icc " _(__INTEL_COMPILER) " (" __VERSION__ ")";
#undef _
#undef __
#elif defined(__clang__)
  "Clang/LLVM " __clang_version__;
#elif defined (__GNUC__)
  "GCC " __VERSION__;
#else
  "unknown compiler";
#endif

/** \brief Display image version info, a debug CLI command function
 */
static clib_error_t *
show_vpe_version_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  int i;
  int verbose = 0;
  int cmdline = 0;
  int indent = 2;
  char **argv = (char **) vm->argv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %=", &verbose, 1))
	;
      else if (unformat (input, "cmdline %=", &cmdline, 1))
	;
      else
	break;
    }

  if (verbose)
    {
#define _(a,b,c) vlib_cli_output (vm, "%-25s " b, a ":", c);
      _("Version", "%s", "v" VPP_BUILD_VER);
      _("Compiled by", "%s", VPP_BUILD_USER);
      _("Compile host", "%s", VPP_BUILD_HOST);
      _("Compile date", "%s", VPP_BUILD_DATE);
      _("Compile location", "%s", VPP_BUILD_TOPDIR);
      _("Compiler", "%s", vpe_compiler);
      _("Current PID", "%d", getpid ());
#undef _
    }
  if (cmdline)
    {
      vlib_cli_output (vm, "%-25s", "Command line arguments:");

      for (i = 0; argv[i]; i++)
	{
	  if (strstr (argv[i], "{"))
	    indent += 2;
	  vlib_cli_output (vm, "%U%s", format_white_space, indent, argv[i]);
	  if (strstr (argv[i], "}"))
	    indent -= 2;
	}
    }
  if ((verbose + cmdline) == 0)
    vlib_cli_output (vm, "%s", vpe_version_string);
  return 0;
}

/*?
 * This command displays image version and command line arguments
 *
 * @cliexpar
 * How to display the image version string:
 * @cliexstart{show version}
 * vpp v18.07-rc0~509-gb9124828 built by vppuser on vppbuild at date
 * @cliexend
 *
 * @cliexpar
 * How to display verbose image version information:
 * @cliexstart{show version verbose}
 * Version:                  v18.07-rc0~509-gb9124828
 * Compiled by:              vppuser
 * Compile host:             vppbuild
 * Compile date:             Fri Jul 13 09:05:37 EDT 2018
 * Compile location:         /scratch/vpp-showversion
 * Compiler:                 GCC 7.3.0
 * Current PID:              5334
 * @cliexend
 *
 * @cliexpar
 * How to display the vpp command line arguments:
 * @cliexstart{show version cmdline}
 * vpp# show version cmdline
 * Command line arguments:
 *   /scratch/vpp-showversion/build-root/install-vpp_debug-native/vpp/bin/vpp
 *   unix
 *   interactive
 * @cliexend
?*/

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_vpe_version_command, static) = {
  .path = "show version",
  .short_help = "show version [verbose] [cmdline]",
  .function = show_vpe_version_command_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/** Return the image build directory name */
char *
vpe_api_get_build_directory (void)
{
  return VPP_BUILD_TOPDIR;
}

/** Return the image version string */
char *
vpe_api_get_version (void)
{
  return VPP_BUILD_VER;
}

/** return the build date */
char *
vpe_api_get_build_date (void)
{
  return VPP_BUILD_DATE;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
