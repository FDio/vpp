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

#include <vnet/ip/ip6_ll_types.h>

#include <vnet/ip/ip.h>

u8 *
format_ip6_ll_prefix (u8 * s, va_list * args)
{
  ip6_ll_prefix_t *ilp = va_arg (*args, ip6_ll_prefix_t *);
  vnet_main_t *vnm = vnet_get_main ();

  s = format (s, "(%U, %U)",
	      format_ip6_address, &ilp->ilp_addr,
	      format_vnet_sw_interface_name,
	      vnm, vnet_get_sw_interface (vnm, ilp->ilp_sw_if_index));

  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
