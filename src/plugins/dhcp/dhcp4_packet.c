/*
 * dhcp4_packet.c: dhcp packet format functions
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <dhcp/dhcp4_packet.h>
#include <vnet/ip/format.h>

u8 *
format_dhcp_packet_type (u8 * s, va_list * args)
{
  dhcp_packet_type_t pt = va_arg (*args, dhcp_packet_type_t);

  switch (pt)
    {
    case DHCP_PACKET_DISCOVER:
      s = format (s, "discover");
      break;
    case DHCP_PACKET_OFFER:
      s = format (s, "offer");
      break;
    case DHCP_PACKET_REQUEST:
      s = format (s, "request");
      break;
    case DHCP_PACKET_ACK:
      s = format (s, "ack");
      break;
    case DHCP_PACKET_NAK:
      s = format (s, "nack");
      break;
    }
  return (s);
}

u8 *
format_dhcp_header (u8 * s, va_list * args)
{
  dhcp_header_t *d = va_arg (*args, dhcp_header_t *);
  u32 max_bytes = va_arg (*args, u32);
  dhcp_option_t *o;
  u32 tmp;

  s = format (s, "opcode:%s", (d->opcode == 1 ? "request" : "reply"));
  s = format (s, " hw[type:%d addr-len:%d addr:%U]",
	      d->hardware_type, d->hardware_address_length,
	      format_hex_bytes, d->client_hardware_address,
	      d->hardware_address_length);
  s = format (s, " hops%d", d->hops);
  s = format (s, " transaction-ID:0x%x", d->transaction_identifier);
  s = format (s, " seconds:%d", d->seconds);
  s = format (s, " flags:0x%x", d->flags);
  s = format (s, " client:%U", format_ip4_address, &d->client_ip_address);
  s = format (s, " your:%U", format_ip4_address, &d->your_ip_address);
  s = format (s, " server:%U", format_ip4_address, &d->server_ip_address);
  s = format (s, " gateway:%U", format_ip4_address, &d->gateway_ip_address);
  s = format (s, " cookie:%U", format_ip4_address, &d->magic_cookie);

  o = (dhcp_option_t *) d->options;

  while (o->option != 0xFF /* end of options */  &&
	 (u8 *) o < (u8 *) d + max_bytes)
    {
      switch (o->option)
	{
	case 53:		/* dhcp message type */
	  tmp = o->data[0];
	  s =
	    format (s, ", option-53: type:%U", format_dhcp_packet_type, tmp);
	  break;
	case 54:		/* dhcp server address */
	  s = format (s, ", option-54: server:%U",
		      format_ip4_address, &o->data_as_u32[0]);
	  break;
	case 58:		/* lease renew time in seconds */
	  s = format (s, ", option-58: renewal:%d",
		      clib_host_to_net_u32 (o->data_as_u32[0]));
	  break;
	case 1:		/* subnet mask */
	  s = format (s, ", option-1: subnet-mask:%d",
		      clib_host_to_net_u32 (o->data_as_u32[0]));
	  break;
	case 3:		/* router address */
	  s = format (s, ", option-3: router:%U",
		      format_ip4_address, &o->data_as_u32[0]);
	  break;
	case 6:		/* domain server address */
	  s = format (s, ", option-6: domian-server:%U",
		      format_hex_bytes, o->data, o->length);
	  break;
	case 12:		/* hostname */
	  s = format (s, ", option-12: hostname:%U",
		      format_hex_bytes, o->data, o->length);
	  break;
	default:
	  tmp = o->option;
	  s = format (s, " option-%d: skipped", tmp);
	  break;
	}
      o = (dhcp_option_t *) (((u8 *) o) + (o->length + 2));
    }
  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
