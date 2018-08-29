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

#include <vnet/ethernet/mac_address.h>

const mac_address_t ZERO_MAC_ADDRESS = {
  .bytes = {
	    0, 0, 0, 0, 0, 0,
	    },
};

u8 *
format_mac_address_t (u8 * s, va_list * args)
{
  const mac_address_t *mac = va_arg (*args, mac_address_t *);

  return (format (s, "%U", format_mac_address, mac->bytes));
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
