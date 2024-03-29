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
 * misc.c: vnet misc
 *
 * Copyright (c) 2012 Eliot Dresselhaus
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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

vnet_main_t vnet_main;

vnet_main_t *
vnet_get_main (void)
{
  return &vnet_main;
}

static uword
vnet_local_interface_tx (vlib_main_t * vm,
			 vlib_node_runtime_t * node, vlib_frame_t * f)
{
  ASSERT (0);
  return f->n_vectors;
}

VNET_DEVICE_CLASS (vnet_local_interface_device_class) = {
  .name = "local",
  .tx_function = vnet_local_interface_tx,
};

VNET_HW_INTERFACE_CLASS (vnet_local_interface_hw_class,static) = {
  .name = "local",
};

clib_error_t *
vnet_main_init (vlib_main_t * vm)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index;
  vnet_hw_interface_t *hw;

  vnm->vlib_main = vm;

  hw_if_index = vnet_register_interface
    (vnm, vnet_local_interface_device_class.index, /* instance */ 0,
     vnet_local_interface_hw_class.index, /* instance */ 0);
  hw = vnet_get_hw_interface (vnm, hw_if_index);

  vnm->local_interface_hw_if_index = hw_if_index;
  vnm->local_interface_sw_if_index = hw->sw_if_index;

  vnm->pcap.current_filter_function =
    vlib_is_packet_traced_default_function ();

  return 0;
}

VLIB_INIT_FUNCTION (vnet_main_init)=
{
  .init_order = VLIB_INITS("vnet_interface_init",
                           "ethernet_init",
                           "fib_module_init",
                           "mfib_module_init",
                           "ip_main_init",
                           "ip4_lookup_init",
                           "ip6_lookup_init",
                           "mpls_init",
                           "vnet_main_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
