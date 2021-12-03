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

#include <vnet/memory_usage.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>

static memory_usage_fn_t *mem_fns;

void
memory_usage_show (vlib_main_t *vm, const char *name, u32 in_use_elts,
		   u32 allocd_elts, size_t size_elt)
{
  vlib_cli_output (vm, "%=30s %=5d %=8d/%=9d   %d/%d ", name, size_elt,
		   in_use_elts, allocd_elts, in_use_elts * size_elt,
		   allocd_elts * size_elt);
}

void
memory_usage_register (memory_usage_fn_t fn)
{
  vec_add1 (mem_fns, fn);
}

static clib_error_t *
show_memory_usage (vlib_main_t *vm, unformat_input_t *input,
		   vlib_cli_command_t *cmd)
{
  memory_usage_fn_t *fn;

  vlib_cli_output (vm, "FIB memory");
  vlib_cli_output (vm, "  Tables:");
  vlib_cli_output (vm, "%=30s %=6s %=12s", "SAFI", "Number", "Bytes");
  vlib_cli_output (vm, "%U", format_fib_table_memory);
  vlib_cli_output (vm, "%U", format_mfib_table_memory);
  vlib_cli_output (vm, "  Nodes:");
  vlib_cli_output (vm, "%=30s %=5s %=8s/%=9s   totals", "Name", "Size",
		   "in-use", "allocated");

  vec_foreach (fn, mem_fns)
    (*fn) (vm);

  return (NULL);
}

/*?
 * The '<em>sh memory-usage </em>' command displays the memory usage for each
 * object type.
 *
 * @cliexpar
 * @cliexstart{show fib memory}
 *FIB memory
 * Tables:
 *            SAFI              Number   Bytes
 *        IPv4 unicast             2    673066
 *        IPv6 unicast             2    1054608
 *            MPLS                 1    4194312
 *       IPv4 multicast            2     2322
 *       IPv6 multicast            2      ???
 * Nodes:
 *            Name               Size  in-use /allocated   totals
 *            Entry               96     20   /    20      1920/1920
 *        Entry Source            32      0   /    0       0/0
 *    Entry Path-Extensions       60      0   /    0       0/0
 *       multicast-Entry         192     12   /    12      2304/2304
 *          Path-list             40     28   /    28      1120/1120
 *          uRPF-list             16     20   /    20      320/320
 *            Path                72     28   /    28      2016/2016
 *     Node-list elements         20     28   /    28      560/560
 *       Node-list heads          8      30   /    30      240/240
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_memory_usage_node, static) = {
  .path = "show memory-usage",
  .function = show_memory_usage,
  .short_help = "show memory-usage",
};
