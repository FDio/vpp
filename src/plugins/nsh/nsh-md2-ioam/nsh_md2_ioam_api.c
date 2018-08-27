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
/*
 *-----------------------------------------------------------------------
 * nsh_md2_ioam_api.c - iOAM for NSH/LISP-GPE related APIs to create
 *               and maintain profiles
 *-----------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vlib/unix/plugin.h>
#include <vnet/plugin/plugin.h>
#include <nsh/nsh-md2-ioam/nsh_md2_ioam.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message structures */
#define vl_typedefs
#include <nsh/nsh.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <nsh/nsh.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <nsh/nsh.api.h>
#undef vl_printfun

u8 *nsh_trace_main = NULL;
static clib_error_t *
nsh_md2_ioam_init (vlib_main_t * vm)
{
  nsh_md2_ioam_main_t *sm = &nsh_md2_ioam_main;
  clib_error_t *error = 0;

  nsh_trace_main =
    (u8 *) vlib_get_plugin_symbol ("ioam_plugin.so", "trace_main");

  if (!nsh_trace_main)
    return error;

  vec_new (nsh_md2_ioam_sw_interface_t, pool_elts (sm->sw_interfaces));
  sm->dst_by_ip4 = hash_create_mem (0, sizeof (fib_prefix_t), sizeof (uword));

  sm->dst_by_ip6 = hash_create_mem (0, sizeof (fib_prefix_t), sizeof (uword));

  nsh_md2_ioam_interface_init ();

  return error;
}

VLIB_INIT_FUNCTION (nsh_md2_ioam_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
