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
/*
 * ethernet_init.c: ethernet initialization
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>		// for feature registration

/* Global main structure. */
ethernet_main_t ethernet_main;

static void
add_type (ethernet_main_t * em, ethernet_type_t type, char *type_name)
{
  ethernet_type_info_t *ti;
  u32 i;

  vec_add2 (em->type_infos, ti, 1);
  i = ti - em->type_infos;

  ti->name = type_name;
  ti->type = type;
  ti->next_index = ti->node_index = ~0;

  hash_set (em->type_info_by_type, type, i);
  hash_set_mem (em->type_info_by_name, ti->name, i);
}

/* Built-in ip4 tx feature path definition */
/* *INDENT-OFF* */
VNET_FEATURE_ARC_INIT (ethernet_output, static) =
{
  .arc_name  = "ethernet-output",
  .start_nodes = VNET_FEATURES ("adj-l2-midchain"),
  .arc_index_ptr = &ethernet_main.output_feature_arc_index,
};

VNET_FEATURE_INIT (ethernet_tx_drop, static) =
{
  .arc_name = "ethernet-output",
  .node_name = "error-drop",
  .runs_before = 0,	/* not before any other features */
};
/* *INDENT-ON* */

static clib_error_t *
ethernet_init (vlib_main_t * vm)
{
  ethernet_main_t *em = &ethernet_main;
  clib_error_t *error;

  /*
   * Set up the L2 path now, or we'll wipe out the L2 ARP
   * registration set up by ethernet_arp_init.
   */
  if ((error = vlib_call_init_function (vm, l2_init)))
    return error;

  em->vlib_main = vm;

  em->type_info_by_name = hash_create_string (0, sizeof (uword));
  em->type_info_by_type = hash_create (0, sizeof (uword));

#define ethernet_type(n,s) add_type (em, ETHERNET_TYPE_##s, #s);
#include "types.def"
#undef ethernet_type

  if ((error = vlib_call_init_function (vm, llc_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ethernet_input_init)))
    return error;
  if ((error = vlib_call_init_function (vm, vnet_feature_init)))
    return error;

  return 0;
}

VLIB_INIT_FUNCTION (ethernet_init);

ethernet_main_t *
ethernet_get_main (vlib_main_t * vm)
{
  vlib_call_init_function (vm, ethernet_init);
  return &ethernet_main;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
