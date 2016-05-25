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
#include <app/version.h>

#if DPDK > 0
#include <rte_version.h>
#include <vnet/vnet.h>
#include <vnet/devices/dpdk/dpdk.h>
#endif /* DPDK */

static char * vpe_version_string = 
    "vpp v" VPP_BUILD_VER 
    " built by " VPP_BUILD_USER 
    " on " VPP_BUILD_HOST 
    " at " VPP_BUILD_DATE;

static char * vpe_compiler =
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

static clib_error_t *
show_vpe_version_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  if (unformat (input, "verbose"))
    {
#define _(a,b,c) vlib_cli_output (vm, "%-25s " b, a ":", c);
      _("Version", "%s", "v" VPP_BUILD_VER);
      _("Compiled by", "%s", VPP_BUILD_USER);
      _("Compile host", "%s", VPP_BUILD_HOST);
      _("Compile date", "%s", VPP_BUILD_DATE);
      _("Compile location", "%s", VPP_BUILD_TOPDIR);
      _("Compiler", "%s", vpe_compiler);
      _("CPU model name", "%U", format_cpu_model_name);
      _("CPU microarchitecture", "%U", format_cpu_uarch);
      _("CPU flags", "%U", format_cpu_flags);
      _("Current PID", "%d", getpid());
#if DPDK > 0
      _("DPDK Version", "%s", rte_version());
      _("DPDK EAL init args", "%s", dpdk_config_main.eal_init_args_str);
#endif
#undef _
    }
  else
    vlib_cli_output (vm, "%s", vpe_version_string);
  return 0;
}

VLIB_CLI_COMMAND (show_vpe_version_command, static) = {
  .path = "show version",
  .short_help = "show version information",
  .function = show_vpe_version_command_fn,
};

char * vpe_api_get_build_directory (void) 
{
  return VPP_BUILD_TOPDIR;
}

char * vpe_api_get_version (void) 
{
  return VPP_BUILD_VER;
}
char * vpe_api_get_build_date (void) 
{
  return VPP_BUILD_DATE;
}
