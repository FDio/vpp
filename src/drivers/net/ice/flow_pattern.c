/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

/* Header locations are retained separately from the extraction sequence so
 * protocol offsets never depend on the length of the programming packet. */
typedef struct
{
  ice_flow_pattern_t *pattern;
  u8 mask[ICE_FDIR_PACKET_SIZE];
  u16 length;
  u16 ip[2];
  u8 ip_version[2];
  u8 ip_count;
  u8 l4;
  u8 tunnel;
  u8 have_l4;
  u16 transport[2];
  u8 transport_protocol[2];
  u8 n_transport;
} ice_flow_parser_t;

enum
{
  ICE_FLOW_TUNNEL_NONE,
  ICE_FLOW_TUNNEL_IP,
  ICE_FLOW_TUNNEL_GRE,
  ICE_FLOW_TUNNEL_VXLAN,
  ICE_FLOW_TUNNEL_GTPU,
  ICE_FLOW_TUNNEL_GTPC,
};

static u16
ice_flow_u16 (const u8 *p)
{
  return ((u16) p[0] << 8) | p[1];
}

static void
ice_flow_set_u16 (u8 *p, u16 value)
{
  p[0] = value >> 8;
  p[1] = value;
}

static void
ice_flow_ptype (ice_flow_pattern_t *p, u32 type)
{
  ASSERT (type < ICE_FDIR_PTYPE_COUNT);
  p->ptypes[type / uword_bits] |= (uword) 1 << (type % uword_bits);
}

static vnet_dev_rv_t
ice_flow_extract (ice_flow_parser_t *parser, u8 protocol, u16 start, u16 length,
		  u16 protocol_offset)
{
  ice_flow_pattern_t *p = parser->pattern;

  if ((u32) start + length > parser->length || (length & 1))
    return VNET_DEV_ERR_INVALID_DATA;
  for (u32 i = 0; i < length; i += 2)
    {
      u16 mask = ice_flow_u16 (parser->mask + start + i);
      if (!mask)
	continue;
      if (p->n_words == ICE_FDIR_MAX_WORDS || protocol_offset + i > 510)
	return VNET_DEV_ERR_NOT_SUPPORTED;
      p->values[p->n_words] = ice_flow_u16 (p->packet + start + i) & mask;
      p->words[p->n_words++] = (ice_flow_word_t) {
	.protocol = protocol,
	.offset = protocol_offset + i,
	.mask = mask,
      };
    }
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_flow_parse_ip (ice_flow_parser_t *parser, u16 *position, u16 ether_type)
{
  ice_flow_pattern_t *p = parser->pattern;
  u32 start = *position, length;
  u8 protocol, version;
  vnet_dev_rv_t rv;

  if (parser->ip_count == 2)
    return VNET_DEV_ERR_NOT_SUPPORTED;
  if (ether_type == 0x0800)
    {
      if (start + 20 > parser->length || p->packet[start] >> 4 != 4)
	return VNET_DEV_ERR_INVALID_DATA;
      length = (p->packet[start] & 15) * 4;
      if (length < 20 || start + length > parser->length)
	return VNET_DEV_ERR_INVALID_DATA;
      version = 4;
      protocol = parser->ip_count ? 33 : 32;
      parser->l4 = p->packet[start + 9];
    }
  else if (ether_type == 0x86dd)
    {
      if (start + 40 > parser->length || p->packet[start] >> 4 != 6)
	return VNET_DEV_ERR_INVALID_DATA;
      length = 40;
      version = 6;
      protocol = parser->ip_count ? 41 : 40;
      parser->l4 = p->packet[start + 6];
    }
  else
    return VNET_DEV_ERR_NOT_SUPPORTED;
  parser->ip[parser->ip_count] = start;
  parser->ip_version[parser->ip_count++] = version;
  if ((rv = ice_flow_extract (parser, protocol, start, length, 0)))
    return rv;
  *position += length;
  if (version == 6)
    while (parser->l4 == 0 || parser->l4 == 43 || parser->l4 == 60)
      {
	u32 offset = *position;
	if (offset + 2 > parser->length)
	  return VNET_DEV_ERR_INVALID_DATA;
	length = (p->packet[offset + 1] + 1) * 8;
	if (offset + length > parser->length)
	  return VNET_DEV_ERR_INVALID_DATA;
	/* The IPv6 next-header walker handles the extension chain. Arbitrary
	 * extension-header bytes have no stable FD protocol identifier. */
	for (u32 i = 0; i < length; i++)
	  if (parser->mask[offset + i])
	    return VNET_DEV_ERR_NOT_SUPPORTED;
	parser->l4 = p->packet[offset];
	*position += length;
      }
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_flow_parse_eth (ice_flow_parser_t *parser, u16 *position, int inner, u16 *ether_type)
{
  ice_flow_pattern_t *p = parser->pattern;
  u16 start = *position, offset = start + 12;
  vnet_dev_rv_t rv;

  if (start + 14 > parser->length)
    return VNET_DEV_ERR_INVALID_DATA;
  if ((rv = ice_flow_extract (parser, inner ? 4 : 1, start, 12, 0)))
    return rv;
  *ether_type = ice_flow_u16 (p->packet + offset);
  for (u32 n_tags = 0; *ether_type == 0x8100 || *ether_type == 0x88a8; n_tags++)
    {
      if (n_tags == 2 || offset + 6 > parser->length)
	return VNET_DEV_ERR_NOT_SUPPORTED;
      if ((rv = ice_flow_extract (parser, inner ? 4 : 1, offset, 4, offset - start)))
	return rv;
      offset += 4;
      *ether_type = ice_flow_u16 (p->packet + offset);
    }
  if ((rv = ice_flow_extract (parser, inner ? 10 : 9, offset, 2, 0)))
    return rv;
  *position = offset + 2;
  return VNET_DEV_OK;
}

static void
ice_flow_ptypes (ice_flow_parser_t *parser)
{
  ice_flow_pattern_t *p = parser->pattern;
  u32 base = parser->ip_version[0] == 6 ? 88 : 22;
  u32 last_version = parser->ip_version[parser->ip_count - 1];
  u32 l4_offset = 1;

  if (parser->l4 == IP_PROTOCOL_UDP)
    l4_offset = 2;
  else if (parser->l4 == IP_PROTOCOL_TCP)
    l4_offset = 4;
  else if (parser->l4 == IP_PROTOCOL_SCTP)
    l4_offset = 5;
  else if (parser->l4 == IP_PROTOCOL_ICMP || parser->l4 == IP_PROTOCOL_ICMP6)
    l4_offset = 6;
  if (parser->tunnel == ICE_FLOW_TUNNEL_GTPU)
    {
      u32 first = parser->ip_version[0] == 6 ? 330 : 329;
      ice_flow_ptype (p, first);
      if (first == 329)
	{
	  for (u32 i = 331; i <= 335; i++)
	    ice_flow_ptype (p, i);
	  for (u32 i = 341; i <= 345; i++)
	    ice_flow_ptype (p, i);
	}
      else
	{
	  for (u32 i = 336; i <= 340; i++)
	    ice_flow_ptype (p, i);
	  for (u32 i = 346; i <= 350; i++)
	    ice_flow_ptype (p, i);
	}
      return;
    }
  if (parser->tunnel == ICE_FLOW_TUNNEL_GTPC)
    {
      ice_flow_ptype (p, parser->ip_version[0] == 6 ? 326 : 325);
      return;
    }
  if (parser->tunnel == ICE_FLOW_TUNNEL_VXLAN)
    {
      base += 36;
      if (parser->ip_count == 1)
	{
	  for (u32 i = base; i <= base + 14; i++)
	    ice_flow_ptype (p, i);
	  return;
	}
      base += last_version == 6 ? 8 : 1;
    }
  else if (parser->tunnel == ICE_FLOW_TUNNEL_IP)
    base += last_version == 6 ? 14 : 7;
  else if (parser->tunnel == ICE_FLOW_TUNNEL_GRE)
    base += last_version == 6 ? 29 : 22;
  else if (parser->l4 == IP_PROTOCOL_IPSEC_ESP)
    {
      ice_flow_ptype (p, parser->ip_version[0] == 6 ? 161 : 160);
      return;
    }
  else if (parser->l4 == IP_PROTOCOL_IPSEC_AH)
    {
      ice_flow_ptype (p, parser->ip_version[0] == 6 ? 163 : 162);
      return;
    }
  else if (parser->l4 == 115)
    {
      ice_flow_ptype (p, parser->ip_version[0] == 6 ? 361 : 360);
      return;
    }
  if (parser->have_l4)
    ice_flow_ptype (p, base + l4_offset);
  else
    {
      ice_flow_ptype (p, base);
      ice_flow_ptype (p, base + 1);
      ice_flow_ptype (p, base + 2);
      ice_flow_ptype (p, base + 4);
      ice_flow_ptype (p, base + 5);
      ice_flow_ptype (p, base + 6);
    }
}

static vnet_dev_rv_t
ice_flow_packet_parse (ice_flow_parser_t *parser)
{
  ice_flow_pattern_t *p = parser->pattern;
  u16 position = 0, ether_type;
  vnet_dev_rv_t rv;

  if ((rv = ice_flow_parse_eth (parser, &position, 0, &ether_type)))
    return rv;
  if (ether_type != 0x0800 && ether_type != 0x86dd)
    {
      for (u32 i = 1; i < ICE_FDIR_PTYPE_COUNT; i++)
	ice_flow_ptype (p, i);
      for (u32 i = position; i < parser->length; i++)
	if (parser->mask[i])
	  return VNET_DEV_ERR_NOT_SUPPORTED;
      return VNET_DEV_OK;
    }
parse_ip:
  if ((rv = ice_flow_parse_ip (parser, &position, ether_type)))
    return rv;
  if (parser->l4 == IP_PROTOCOL_IP_IN_IP || parser->l4 == IP_PROTOCOL_IPV6)
    {
      parser->tunnel = ICE_FLOW_TUNNEL_IP;
      ether_type = parser->l4 == IP_PROTOCOL_IPV6 ? 0x86dd : 0x0800;
      goto parse_ip;
    }
  if (parser->l4 == IP_PROTOCOL_GRE)
    {
      if (position + 4 > parser->length || ice_flow_u16 (p->packet + position) != 0)
	return VNET_DEV_ERR_NOT_SUPPORTED;
      if ((rv = ice_flow_extract (parser, 64, position, 4, 0)))
	return rv;
      ether_type = ice_flow_u16 (p->packet + position + 2);
      position += 4;
      parser->tunnel = ICE_FLOW_TUNNEL_GRE;
      goto parse_ip;
    }
  if (position < parser->length)
    {
      u16 length = 0;
      u8 protocol = 0;
      if (parser->n_transport == 2)
	return VNET_DEV_ERR_NOT_SUPPORTED;
      parser->transport[parser->n_transport] = position;
      parser->transport_protocol[parser->n_transport++] = parser->l4;
      if (parser->l4 == IP_PROTOCOL_UDP)
	{
	  u16 destination;
	  if (position + 8 > parser->length)
	    return VNET_DEV_ERR_INVALID_DATA;
	  destination = ice_flow_u16 (p->packet + position + 2);
	  protocol = 53;
	  length = 8;
	  if (position + 16 <= parser->length &&
	      ((destination == 4789 && (p->packet[position + 8] & 8)) ||
	       (destination == 2152 && (p->packet[position + 8] & 0xf0) == 0x30) ||
	       (destination == 2123 && (p->packet[position + 8] & 0xe8) == 0x48)))
	    {
	      protocol = 52;
	      parser->tunnel = destination == 4789 ? ICE_FLOW_TUNNEL_VXLAN : ICE_FLOW_TUNNEL_GTPU;
	      if (destination == 2123)
		parser->tunnel = ICE_FLOW_TUNNEL_GTPC;
	      length = 16;
	      if ((rv = ice_flow_extract (parser, protocol, position, length, 0)))
		return rv;
	      position += length;
	      if (destination == 4789 && position + 14 <= parser->length)
		{
		  if ((rv = ice_flow_parse_eth (parser, &position, 1, &ether_type)))
		    return rv;
		  if (ether_type == 0x0800 || ether_type == 0x86dd)
		    goto parse_ip;
		}
	      parser->have_l4 = 1;
	      goto finish;
	    }
	}
      else if (parser->l4 == IP_PROTOCOL_TCP)
	{
	  protocol = 49;
	  length = 20;
	}
      else if (parser->l4 == IP_PROTOCOL_SCTP)
	{
	  protocol = 96;
	  length = 12;
	}
      else if (parser->l4 == IP_PROTOCOL_IPSEC_ESP)
	{
	  protocol = 88;
	  length = 8;
	}
      else if (parser->l4 == IP_PROTOCOL_IPSEC_AH)
	{
	  protocol = 89;
	  length = 12;
	}
      else if (parser->l4 == 115)
	{
	  protocol = 104;
	  length = 4;
	}
      else if (parser->l4 == IP_PROTOCOL_ICMP || parser->l4 == IP_PROTOCOL_ICMP6)
	{
	  protocol = parser->l4 == IP_PROTOCOL_ICMP ? 98 : 100;
	  length = 8;
	}
      if (length)
	{
	  if ((rv = ice_flow_extract (parser, protocol, position, length, 0)))
	    return rv;
	  parser->have_l4 = 1;
	  position += length;
	}
    }
finish:
  for (u32 i = position; i < parser->length; i++)
    if (parser->mask[i])
      return VNET_DEV_ERR_NOT_SUPPORTED;
  ice_flow_ptypes (parser);
  return VNET_DEV_OK;
}

static u32
ice_flow_checksum_sum (const u8 *data, u32 length, u32 sum)
{
  for (u32 i = 0; i < length; i += 2)
    {
      sum += (u32) data[i] << 8;
      if (i + 1 < length)
	sum += data[i + 1];
    }
  return sum;
}

static vnet_dev_rv_t
ice_flow_checksum_write (ice_flow_parser_t *parser, u32 offset, u32 sum)
{
  u16 checksum, original = ice_flow_u16 (parser->pattern->packet + offset);
  u16 mask = ice_flow_u16 (parser->mask + offset);
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  checksum = ~sum;
  if ((checksum ^ original) & mask)
    return VNET_DEV_ERR_INVALID_DATA;
  ice_flow_set_u16 (parser->pattern->packet + offset, checksum);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_flow_packet_checksums (ice_flow_parser_t *parser)
{
  u8 *packet = parser->pattern->packet;
  vnet_dev_rv_t rv;
  for (u32 i = 0; i < parser->ip_count; i++)
    {
      u32 ip = parser->ip[i];
      u16 offset = parser->ip_version[i] == 4 ? 2 : 4;
      u16 length = parser->length - ip - (parser->ip_version[i] == 6 ? 40 : 0);
      u16 original = ice_flow_u16 (packet + ip + offset);
      if ((original ^ length) & ice_flow_u16 (parser->mask + ip + offset))
	return VNET_DEV_ERR_INVALID_DATA;
      ice_flow_set_u16 (packet + ip + offset, length);
      if (parser->ip_version[i] == 4)
	{
	  u32 sum = ice_flow_checksum_sum (packet + ip, 10, 0);
	  sum = ice_flow_checksum_sum (packet + ip + 12, (packet[ip] & 15) * 4 - 12, sum);
	  if ((rv = ice_flow_checksum_write (parser, ip + 10, sum)))
	    return rv;
	}
    }
  for (u32 i = parser->n_transport; i > 0; i--)
    {
      u32 start = parser->transport[i - 1], ip_index = 0;
      u32 length = parser->length - start, checksum_offset, sum = 0;
      u8 protocol = parser->transport_protocol[i - 1];
      while (ip_index + 1 < parser->ip_count && parser->ip[ip_index + 1] < start)
	ip_index++;
      if (protocol == IP_PROTOCOL_UDP)
	{
	  u16 original = ice_flow_u16 (packet + start + 4);
	  if ((original ^ length) & ice_flow_u16 (parser->mask + start + 4))
	    return VNET_DEV_ERR_INVALID_DATA;
	  ice_flow_set_u16 (packet + start + 4, length);
	  checksum_offset = 6;
	}
      else if (protocol == IP_PROTOCOL_TCP)
	checksum_offset = 16;
      else if (protocol == IP_PROTOCOL_ICMP || protocol == IP_PROTOCOL_ICMP6)
	checksum_offset = 2;
      else if (protocol == IP_PROTOCOL_SCTP)
	{
	  u32 crc = ~0U;
	  if (length < 12)
	    return VNET_DEV_ERR_INVALID_DATA;
	  for (u32 j = 0; j < length; j++)
	    {
	      u8 byte = j >= 8 && j < 12 ? 0 : packet[start + j];
	      crc ^= byte;
	      for (u32 bit = 0; bit < 8; bit++)
		crc = (crc >> 1) ^ (0x82f63b78U & (0U - (crc & 1)));
	    }
	  crc = ~crc;
	  for (u32 j = 0; j < 4; j++)
	    {
	      u8 byte = crc >> (j * 8);
	      if ((byte ^ packet[start + 8 + j]) & parser->mask[start + 8 + j])
		return VNET_DEV_ERR_INVALID_DATA;
	      packet[start + 8 + j] = byte;
	    }
	  continue;
	}
      else
	continue;
      if (length < checksum_offset + 2)
	return VNET_DEV_ERR_INVALID_DATA;
      if (protocol != IP_PROTOCOL_ICMP)
	{
	  u32 ip = parser->ip[ip_index];
	  if (parser->ip_version[ip_index] == 4)
	    sum = ice_flow_checksum_sum (packet + ip + 12, 8, 0);
	  else
	    sum = ice_flow_checksum_sum (packet + ip + 8, 32, 0);
	  sum += length + protocol;
	}
      sum = ice_flow_checksum_sum (packet + start, checksum_offset, sum);
      sum = ice_flow_checksum_sum (packet + start + checksum_offset + 2,
				   length - checksum_offset - 2, sum);
      if (protocol == IP_PROTOCOL_UDP)
	{
	  while (sum >> 16)
	    sum = (sum & 0xffff) + (sum >> 16);
	  if (sum == 0xffff)
	    sum = 0;
	}
      if ((rv = ice_flow_checksum_write (parser, start + checksum_offset, sum)))
	return rv;
    }
  return VNET_DEV_OK;
}

static int
ice_flow_hex (u8 c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static vnet_dev_rv_t
ice_flow_decode (const u8 input[1024], u8 *output, u16 *length)
{
  int high = -1;
  u16 n = 0;
  for (u32 i = 0; i < 1024; i++)
    {
      int value;
      if (!input[i])
	{
	  if (high >= 0 || !n)
	    return VNET_DEV_ERR_INVALID_DATA;
	  *length = n;
	  return VNET_DEV_OK;
	}
      if (input[i] == ' ' || input[i] == '\n' || input[i] == '\t' || input[i] == ':')
	continue;
      value = ice_flow_hex (input[i]);
      if (value < 0)
	return VNET_DEV_ERR_INVALID_DATA;
      if (high < 0)
	high = value;
      else
	{
	  if (n == ICE_FDIR_PACKET_SIZE)
	    return VNET_DEV_ERR_INVALID_DATA;
	  output[n++] = (high << 4) | value;
	  high = -1;
	}
    }
  return VNET_DEV_ERR_INVALID_DATA;
}

static void
ice_flow_copy (u8 *dst, u8 *mask, const void *value, const void *value_mask, u32 size)
{
  clib_memcpy (dst, value, size);
  clib_memcpy (mask, value_mask, size);
}

vnet_dev_rv_t
ice_flow_parse (const vnet_flow_t *flow, ice_flow_pattern_t *pattern)
{
  ice_flow_parser_t parser = { .pattern = pattern };
  u8 *packet = pattern->packet, *mask = parser.mask;
  u16 position = 14, l4_start, type = 0x0800;
  u8 protocol = 0;
  int ip6 = 0, tuple = 0, tunnel = 0;
  vnet_dev_rv_t rv;

  *pattern = (ice_flow_pattern_t) {};
  if (flow->type == VNET_FLOW_TYPE_GENERIC)
    {
      u16 mask_length;
      if (!flow->generic_pattern)
	return VNET_DEV_ERR_INVALID_DATA;
      if ((rv = ice_flow_decode (flow->generic_pattern->spec, packet, &parser.length)) ||
	  (rv = ice_flow_decode (flow->generic_pattern->mask, mask, &mask_length)))
	return rv;
      if (mask_length != parser.length)
	return VNET_DEV_ERR_INVALID_DATA;
      pattern->packet_length = parser.length;
      rv = ice_flow_packet_parse (&parser);
      goto done;
    }
  switch (flow->type)
    {
    case VNET_FLOW_TYPE_ETHERNET:
      type = flow->pattern.ethernet.eth_hdr.type;
      ice_flow_set_u16 (packet + 12, type);
      mask[12] = mask[13] = 0xff;
      /* Ethernet flows in the VPP interface specify an EtherType. */
      if (type != 0x0800 && type != 0x86dd)
	{
	  parser.length = pattern->packet_length = 64;
	  rv = ice_flow_packet_parse (&parser);
	  goto done;
	}
      ip6 = type == 0x86dd;
      break;
    case VNET_FLOW_TYPE_IP6:
      ip6 = 1;
      break;
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED:
      ip6 = tuple = 1;
      break;
    case VNET_FLOW_TYPE_IP6_VXLAN:
      ip6 = tuple = 1;
      tunnel = 1;
      break;
    case VNET_FLOW_TYPE_IP4:
      break;
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED:
      tuple = 1;
      break;
    case VNET_FLOW_TYPE_IP4_VXLAN:
      tuple = 1;
      tunnel = 1;
      break;
    case VNET_FLOW_TYPE_IP4_GTPC:
      tuple = 1;
      tunnel = 2;
      break;
    case VNET_FLOW_TYPE_IP4_GTPU:
      tuple = 1;
      tunnel = 3;
      break;
    case VNET_FLOW_TYPE_IP4_L2TPV3OIP:
    case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
    case VNET_FLOW_TYPE_IP4_IPSEC_AH:
      break;
    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
  ice_flow_set_u16 (packet + 12, ip6 ? 0x86dd : 0x0800);
  mask[12] = mask[13] = 0xff;
  if (ip6)
    {
      const vnet_flow_ip6_t *ip = &flow->pattern.ip6;
      packet[position] = 0x60;
      packet[position + 7] = 64;
      if (flow->type != VNET_FLOW_TYPE_ETHERNET)
	{
	  protocol = ip->protocol.prot;
	  mask[position + 6] = ip->protocol.mask;
	  ice_flow_copy (packet + position + 8, mask + position + 8, &ip->src_addr.addr,
			 &ip->src_addr.mask, 16);
	  ice_flow_copy (packet + position + 24, mask + position + 24, &ip->dst_addr.addr,
			 &ip->dst_addr.mask, 16);
	}
      packet[position + 6] = protocol;
      position += 40;
    }
  else
    {
      const vnet_flow_ip4_t *ip = &flow->pattern.ip4;
      packet[position] = 0x45;
      packet[position + 8] = 64;
      if (flow->type != VNET_FLOW_TYPE_ETHERNET)
	{
	  protocol = ip->protocol.prot;
	  mask[position + 9] = ip->protocol.mask;
	  ice_flow_copy (packet + position + 12, mask + position + 12, &ip->src_addr.addr,
			 &ip->src_addr.mask, 4);
	  ice_flow_copy (packet + position + 16, mask + position + 16, &ip->dst_addr.addr,
			 &ip->dst_addr.mask, 4);
	}
      packet[position + 9] = protocol;
      position += 20;
    }
  l4_start = position;
  if (tuple)
    {
      const ip_port_and_mask_t *src, *dst;
      if (ip6)
	{
	  src = &flow->pattern.ip6_n_tuple.src_port;
	  dst = &flow->pattern.ip6_n_tuple.dst_port;
	}
      else
	{
	  src = &flow->pattern.ip4_n_tuple.src_port;
	  dst = &flow->pattern.ip4_n_tuple.dst_port;
	}
      if (protocol != IP_PROTOCOL_TCP && protocol != IP_PROTOCOL_UDP &&
	  protocol != IP_PROTOCOL_SCTP)
	return VNET_DEV_ERR_NOT_SUPPORTED;
      ice_flow_set_u16 (packet + position, src->port);
      ice_flow_set_u16 (packet + position + 2, dst->port);
      ice_flow_set_u16 (mask + position, src->mask);
      ice_flow_set_u16 (mask + position + 2, dst->mask);
      /* A tuple's transport header is part of its match, even when the
       * caller omitted the redundant protocol mask. */
      mask[ip6 ? 20 : 23] = 0xff;
    }
  if (protocol == IP_PROTOCOL_TCP)
    {
      packet[position + 12] = 0x50;
      position += 20;
    }
  else if (protocol == IP_PROTOCOL_UDP)
    position += 8;
  else if (protocol == IP_PROTOCOL_SCTP)
    position += 12;
  else if (protocol == IP_PROTOCOL_ICMP || protocol == IP_PROTOCOL_ICMP6)
    position += 8;
  if (tunnel)
    {
      u32 id;
      if (protocol != IP_PROTOCOL_UDP)
	return VNET_DEV_ERR_INVALID_DATA;
      if (tunnel == 1)
	{
	  id = ip6 ? flow->pattern.ip6_vxlan.vni : flow->pattern.ip4_vxlan.vni;
	  if (id > 0xffffff)
	    return VNET_DEV_ERR_INVALID_VALUE;
	  ice_flow_set_u16 (packet + l4_start + 2, 4789);
	  packet[position] = 8;
	  packet[position + 4] = id >> 16;
	  packet[position + 5] = id >> 8;
	  packet[position + 6] = id;
	  mask[position + 4] = mask[position + 5] = mask[position + 6] = 0xff;
	  position += 8;
	  ice_flow_set_u16 (packet + position + 12, 0x88b5);
	  position += 14;
	}
      else
	{
	  id = tunnel == 2 ? flow->pattern.ip4_gtpc.teid : flow->pattern.ip4_gtpu.teid;
	  ice_flow_set_u16 (packet + l4_start + 2, tunnel == 2 ? 2123 : 2152);
	  packet[position] = tunnel == 2 ? 0x48 : 0x30;
	  packet[position + 1] = tunnel == 2 ? 1 : 255;
	  for (u32 i = 0; i < 4; i++)
	    {
	      packet[position + 4 + i] = id >> (24 - i * 8);
	      mask[position + 4 + i] = 0xff;
	    }
	  if (tunnel == 2)
	    {
	      ice_flow_set_u16 (packet + position + 2, 8);
	      position += 12;
	    }
	  else
	    position += 8;
	}
      mask[l4_start + 2] = mask[l4_start + 3] = 0xff;
    }
  else if (flow->type == VNET_FLOW_TYPE_IP4_IPSEC_ESP ||
	   flow->type == VNET_FLOW_TYPE_IP4_IPSEC_AH || flow->type == VNET_FLOW_TYPE_IP4_L2TPV3OIP)
    {
      u32 id;
      u16 offset = position;
      if (flow->type == VNET_FLOW_TYPE_IP4_IPSEC_ESP)
	{
	  protocol = IP_PROTOCOL_IPSEC_ESP;
	  id = flow->pattern.ip4_ipsec_esp.spi;
	  position += 8;
	}
      else if (flow->type == VNET_FLOW_TYPE_IP4_IPSEC_AH)
	{
	  protocol = IP_PROTOCOL_IPSEC_AH;
	  id = flow->pattern.ip4_ipsec_ah.spi;
	  packet[position] = 59;
	  packet[position + 1] = 1;
	  offset += 4;
	  position += 12;
	}
      else
	{
	  protocol = 115;
	  id = flow->pattern.ip4_l2tpv3oip.session_id;
	  position += 4;
	}
      packet[23] = protocol;
      mask[23] = 0xff;
      for (u32 i = 0; i < 4; i++)
	{
	  packet[offset + i] = id >> (24 - i * 8);
	  mask[offset + i] = 0xff;
	}
    }
  parser.length = position;
  pattern->packet_length = clib_max (position, 64);
  if (protocol == IP_PROTOCOL_UDP)
    ice_flow_set_u16 (packet + l4_start + 4, position - l4_start);
  if (ip6)
    ice_flow_set_u16 (packet + 18, position - 54);
  else
    {
      ice_flow_set_u16 (packet + 16, position - 14);
    }
  rv = ice_flow_packet_parse (&parser);
  if (rv == VNET_DEV_OK && !tuple && !tunnel)
    {
      /* Layer-three rules also apply when transport fields are present. */
      clib_memset (pattern->ptypes, 0, sizeof (pattern->ptypes));
      parser.have_l4 = 0;
      ice_flow_ptypes (&parser);
    }
done:
  if (rv)
    return rv;
  if (flow->type == VNET_FLOW_TYPE_ETHERNET)
    for (u32 i = 1; i < ICE_FDIR_PTYPE_COUNT; i++)
      ice_flow_ptype (pattern, i);
  if (!pattern->n_words)
    return VNET_DEV_ERR_NOT_SUPPORTED;
  if ((rv = ice_flow_packet_checksums (&parser)))
    return rv;
  /* Canonical order makes profile sharing independent of parsing order. */
  for (u32 i = 1; i < pattern->n_words; i++)
    {
      ice_flow_word_t word = pattern->words[i];
      u16 value = pattern->values[i];
      u32 j = i;
      while (j && (pattern->words[j - 1].protocol > word.protocol ||
		   (pattern->words[j - 1].protocol == word.protocol &&
		    pattern->words[j - 1].offset > word.offset)))
	{
	  pattern->words[j] = pattern->words[j - 1];
	  pattern->values[j] = pattern->values[j - 1];
	  j--;
	}
      pattern->words[j] = word;
      pattern->values[j] = value;
    }
  return VNET_DEV_OK;
}
