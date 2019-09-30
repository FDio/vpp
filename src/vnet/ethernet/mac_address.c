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

/* *INDENT-OFF* */
const mac_address_t ZERO_MAC_ADDRESS = {
  .bytes = {
    0, 0, 0, 0, 0, 0,
  },
};
/* *INDENT-ON* */

u8 *
format_mac_address_t (u8 * s, va_list * args)
{
  const mac_address_t *mac = va_arg (*args, mac_address_t *);

  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac->bytes[0], mac->bytes[1], mac->bytes[2],
		 mac->bytes[3], mac->bytes[4], mac->bytes[5]);
}

uword
unformat_mac_address_t (unformat_input_t * input, va_list * args)
{
  mac_address_t *mac = va_arg (*args, mac_address_t *);
  u32 i, a[3];

  if (unformat (input, "%_%X:%X:%X:%X:%X:%X%_",
		1, &mac->bytes[0], 1, &mac->bytes[1], 1, &mac->bytes[2],
		1, &mac->bytes[3], 1, &mac->bytes[4], 1, &mac->bytes[5]))
    return (1);
  else if (unformat (input, "%_%x.%x.%x%_", &a[0], &a[1], &a[2]))
    {
      for (i = 0; i < ARRAY_LEN (a); i++)
	if (a[i] >= (1 << 16))
	  return 0;

      mac->bytes[0] = (a[0] >> 8) & 0xff;
      mac->bytes[1] = (a[0] >> 0) & 0xff;
      mac->bytes[2] = (a[1] >> 8) & 0xff;
      mac->bytes[3] = (a[1] >> 0) & 0xff;
      mac->bytes[4] = (a[2] >> 8) & 0xff;
      mac->bytes[5] = (a[2] >> 0) & 0xff;

      return (1);
    }
  return (0);
}

void
mac_address_increment (mac_address_t * mac)
{
  u64 a;

  a = mac_address_as_u64 (mac);
  a++;
  mac_address_from_u64 (mac, a);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
