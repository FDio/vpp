/*
** Copyright (C) 2025 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software Foundation, Inc.
** 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <daq.h>

#include "daq_vpp.h"

static inline char *
daq_vpp_dump_napt_info (const DAQ_NAPTInfo_t *info)
{
  char *buf = 0;
  size_t buf_size = 1024;
  int n = 0;
  char src_addr_str[INET6_ADDRSTRLEN];
  char dst_addr_str[INET6_ADDRSTRLEN];

  buf = malloc (buf_size);
  if (!buf)
    return NULL;

  memset (buf, 0, buf_size);

  n += snprintf (buf + n, buf_size - n, "--- DAQ NAPT Info ---\n");
  if (info == NULL)
    {
      n += snprintf (buf + n, buf_size - n,
		     "No Network Address and Port Translation\n");
    }
  else
    {
      inet_ntop (daq_napt_info_src_addr_family (info), &info->src_addr,
		 src_addr_str, sizeof (src_addr_str));
      inet_ntop (daq_napt_info_dst_addr_family (info), &info->dst_addr,
		 dst_addr_str, sizeof (dst_addr_str));

      n += snprintf (buf + n, buf_size - n, "  Source:         [%s]:%u\n",
		     src_addr_str, ntohs (info->src_port));
      n += snprintf (buf + n, buf_size - n, "  Destination:    [%s]:%u\n",
		     dst_addr_str, ntohs (info->dst_port));
      n += snprintf (buf + n, buf_size - n, "  Flags:          %#04x\n",
		     info->flags);

      n += snprintf (buf + n, buf_size - n, "  \tSource IP:");
      if ((info->flags & DAQ_NAPT_INFO_FLAG_SIP_V6) ==
	  DAQ_NAPT_INFO_FLAG_SIP_V6)
	n += snprintf (buf + n, buf_size - n, "      IPv6\n");
      else
	n += snprintf (buf + n, buf_size - n, "      IPv4\n");
      n += snprintf (buf + n, buf_size - n, "  \tDestination IP:");
      if ((info->flags & DAQ_NAPT_INFO_FLAG_DIP_V6) ==
	  DAQ_NAPT_INFO_FLAG_DIP_V6)
	n += snprintf (buf + n, buf_size - n, " IPv6\n");
      else
	n += snprintf (buf + n, buf_size - n, " IPv4\n");

      n += snprintf (buf + n, buf_size - n, "  IP Layer:       %u ",
		     info->ip_layer);
      switch (info->ip_layer)
	{
	case IPPROTO_TCP:
	  n += snprintf (buf + n, buf_size - n, "(TCP)\n");
	  break;
	case IPPROTO_UDP:
	  n += snprintf (buf + n, buf_size - n, "(UDP)\n");
	  break;
	case IPPROTO_ICMPV6:
	  n += snprintf (buf + n, buf_size - n, "(ICMPv6)\n");
	  break;
	default:
	  n += snprintf (buf + n, buf_size - n, "(Other)\n");
	  break;
	}
    }
  n += snprintf (buf + n, buf_size - n, "----------------------------\n");
  return buf;
}

static inline char *
daq_vpp_dump_packet_decode_flags (DAQ_PktDecodeFlags_t flags)
{
  char *buf = 0;
  size_t buf_size = 1024;
  int n = 0;

  buf = malloc (buf_size);
  if (!buf)
    return NULL;

  memset (buf, 0, buf_size);
  n += snprintf (buf + n, buf_size - n, "  Flags (0x%08x):\n", flags.all);

  // General parsing status
  if (flags.bits.l2)
    n += snprintf (buf + n, buf_size - n, "    - L2 Parsed\n");
  if (flags.bits.l3)
    n += snprintf (buf + n, buf_size - n, "    - L3 Parsed\n");
  if (flags.bits.l4)
    n += snprintf (buf + n, buf_size - n, "    - L4 Parsed\n");

  // Checksum status
  if (flags.bits.l2_checksum)
    n += snprintf (buf + n, buf_size - n, "    - L2 Checksum OK\n");
  if (flags.bits.l3_checksum)
    n += snprintf (buf + n, buf_size - n, "    - L3 Checksum OK\n");
  if (flags.bits.l4_checksum)
    n += snprintf (buf + n, buf_size - n, "    - L4 Checksum OK\n");
  if (flags.bits.checksum_error)
    n += snprintf (buf + n, buf_size - n, "    - Checksum Error Detected\n");

  // L2 details
  if (flags.bits.vlan)
    n += snprintf (buf + n, buf_size - n, "    - VLAN Tag Found\n");
  if (flags.bits.vlan_qinq)
    n += snprintf (buf + n, buf_size - n, "    - QinQ VLAN Tags Found\n");
  if (flags.bits.ethernet)
    n += snprintf (buf + n, buf_size - n, "    - Protocol: Ethernet\n");

  // L3 protocols
  if (flags.bits.ipv4)
    n += snprintf (buf + n, buf_size - n, "    - Protocol: IPv4\n");
  if (flags.bits.ipv6)
    n += snprintf (buf + n, buf_size - n, "    - Protocol: IPv6\n");

  // L4 protocols
  if (flags.bits.tcp)
    n += snprintf (buf + n, buf_size - n, "    - Protocol: TCP\n");
  if (flags.bits.udp)
    n += snprintf (buf + n, buf_size - n, "    - Protocol: UDP\n");
  if (flags.bits.icmp)
    n += snprintf (buf + n, buf_size - n, "    - Protocol: ICMP\n");

  // TCP options
  if (flags.bits.tcp_opt_mss)
    n += snprintf (buf + n, buf_size - n, "    - TCP Opt: MSS\n");
  if (flags.bits.tcp_opt_ws)
    n += snprintf (buf + n, buf_size - n, "    - TCP Opt: Window Scale\n");
  if (flags.bits.tcp_opt_ts)
    n += snprintf (buf + n, buf_size - n, "    - TCP Opt: Timestamp\n");

  return buf;
}

static inline char *
daq_vpp_dump_packet_decode_data (const DAQ_PktDecodeData_t *data)
{
  char *buf = 0;
  char *flags_buf = 0;
  size_t buf_size = 1024;
  int n = 0;

  buf = malloc (buf_size);
  if (!buf)
    return NULL;

  memset (buf, 0, buf_size);
  n += snprintf (buf + n, buf_size - n, "--- DAQ Packet Decode Data ---\n");

  if (data == NULL)
    {
      n += snprintf (buf + n, buf_size - n, "No Packet Decode Data\n");
    }
  else
    {

      // Call the helper to print the detailed flags
      flags_buf = daq_vpp_dump_packet_decode_flags (data->flags);
      if (flags_buf)
	{
	  n += snprintf (buf + n, buf_size - n, "%s", flags_buf);
	  free (flags_buf);
	}

      // Print the offsets, checking for the invalid sentinel value
      n += snprintf (buf + n, buf_size - n, "  Offsets:\n");
      n += snprintf (buf + n, buf_size - n, "    %-18s: ", "L2 Offset");
      if (data->l2_offset == DAQ_PKT_DECODE_OFFSET_INVALID)
	n += snprintf (buf + n, buf_size - n, "Invalid\n");
      else
	n += snprintf (buf + n, buf_size - n, "%u\n", data->l2_offset);

      n += snprintf (buf + n, buf_size - n, "    %-18s: ", "L3 Offset");
      if (data->l3_offset == DAQ_PKT_DECODE_OFFSET_INVALID)
	n += snprintf (buf + n, buf_size - n, "Invalid\n");
      else
	n += snprintf (buf + n, buf_size - n, "%u\n", data->l3_offset);

      n += snprintf (buf + n, buf_size - n, "    %-18s: ", "L4 Offset");
      if (data->l4_offset == DAQ_PKT_DECODE_OFFSET_INVALID)
	n += snprintf (buf + n, buf_size - n, "Invalid\n");
      else
	n += snprintf (buf + n, buf_size - n, "%u\n", data->l4_offset);

      n += snprintf (buf + n, buf_size - n, "    %-18s: ", "Payload Offset");
      if (data->payload_offset == DAQ_PKT_DECODE_OFFSET_INVALID)
	n += snprintf (buf + n, buf_size - n, "Invalid\n");
      else
	n += snprintf (buf + n, buf_size - n, "%u\n", data->payload_offset);

      n += snprintf (buf + n, buf_size - n, "    %-18s: ", "Checksum Offset");
      if (data->checksum_offset == DAQ_PKT_DECODE_OFFSET_INVALID)
	n += snprintf (buf + n, buf_size - n, "Invalid\n");
      else
	n += snprintf (buf + n, buf_size - n, "%u\n", data->checksum_offset);
    }
  n += snprintf (buf + n, buf_size - n, "-------------------------------\n");
  return buf;
}

static inline char *
daq_vpp_dump_packet_tcp_ack_data (const DAQ_PktTcpAckData_t *data)
{
  char *buf = 0;
  size_t buf_size = 512;
  int n = 0;

  buf = malloc (buf_size);
  if (!buf)
    return NULL;

  memset (buf, 0, buf_size);

  n += snprintf (buf + n, buf_size - n, "--- DAQ Packet TCP ACK Data ---\n");

  if (data == NULL)
    {
      n += snprintf (buf + n, buf_size - n, "No Packet Tcp Ack Data\n");
    }
  else
    {
      n +=
	snprintf (buf + n, buf_size - n, "--- DAQ TCP Elided ACK Data ---\n");

      // Use ntohl() ("network to host long") for the 32-bit sequence number.
      // The '%u' format specifier is for unsigned integers.
      n += snprintf (buf + n, buf_size - n, "  TCP Ack Number:  %u\n",
		     ntohl (data->tcp_ack_seq_num));

      // Use ntohs() ("network to host short") for the 16-bit window size.
      n += snprintf (buf + n, buf_size - n, "  TCP Window Size: %u\n",
		     ntohs (data->tcp_window_size));
    }

  n += snprintf (buf + n, buf_size - n, "---------------------------------\n");
  return buf;
}

char *
daq_vpp_dump_packet_data (const uint8_t *data, uint32_t len)
{
  char *buf = 0;
  size_t buf_size;
  int n = 0;

  // Each byte as two hex chars + space + 128bytes extra for formatting
  buf_size = len * 3 + 512;

  buf = malloc (buf_size);
  if (!buf)
    return NULL;

  memset (buf, 0, buf_size);
  n += snprintf (buf + n, buf_size - n,
		 "--- DAQ Packet (%u bytes) Hex Dump ---\n", len);

  if (data == NULL || len == 0)
    {
      n += snprintf (buf + n, buf_size - n, "No data to dump.\n");
    }
  else
    {

      for (uint32_t i = 0; i < len; i++)
	{
	  if (i % 16 == 0 && i > 0)
	    n += snprintf (buf + n, buf_size - n, "\n");
	  n += snprintf (buf + n, buf_size - n, "%02x ", data[i]);
	}
    }
  n += snprintf (buf + n, buf_size - n,
		 "\n-----------------------------------\n");
  return buf;
}

char *
daq_vpp_dump_pkt_hdr (const DAQ_PktHdr_t *hdr)
{
  char *buf = 0;
  size_t buf_size = 1024;
  int n = 0;

  buf = malloc (buf_size);
  if (!buf)
    return NULL;

  memset (buf, 0, buf_size);

  n += snprintf (buf + n, buf_size - n, "--- DAQ Packet Header ---\n");

  if (hdr == NULL)
    {
      n += snprintf (buf + n, buf_size - n, "No DAQ Packet Header\n");
    }
  else
    {
      // The %06ld for tv_usec ensures leading zeros are printed for
      // microseconds.
      n += snprintf (buf + n, buf_size - n,
		     "  Timestamp (ts)      : %ld.%06ld seconds\n",
		     hdr->ts.tv_sec, hdr->ts.tv_usec);
      n += snprintf (buf + n, buf_size - n,
		     "  Packet Length (pktlen): %u bytes\n", hdr->pktlen);
      n += snprintf (buf + n, buf_size - n, "  Ingress Index         : %d\n",
		     hdr->ingress_index);
      n += snprintf (buf + n, buf_size - n, "  Egress Index          : %d\n",
		     hdr->egress_index);
      n += snprintf (buf + n, buf_size - n, "  Ingress Group         : %d\n",
		     hdr->ingress_group);
      n += snprintf (buf + n, buf_size - n, "  Egress Group          : %d\n",
		     hdr->egress_group);
      // Printing opaque/ID values in both decimal and hex is often useful for
      // debugging.
      n += snprintf (buf + n, buf_size - n,
		     "  Opaque Value          : %u (0x%08x)\n", hdr->opaque,
		     hdr->opaque);
      n += snprintf (buf + n, buf_size - n,
		     "  Flow ID               : %u (0x%08x)\n", hdr->flow_id,
		     hdr->flow_id);
      // Flags are best viewed in hex to analyze the bitmask.
      n += snprintf (buf + n, buf_size - n,
		     "  Flags                 : 0x%08x\n", hdr->flags);
      n += snprintf (buf + n, buf_size - n, "  Address Space ID      : %u\n",
		     hdr->address_space_id);
      n += snprintf (buf + n, buf_size - n, "  Tenant ID             : %u\n",
		     hdr->tenant_id);
    }
  n += snprintf (buf + n, buf_size - n, "-------------------------\n");
  return buf;
}

const char *
daq_vpp_inject_direction (int reverse)
{
  switch (reverse)
    {
    case (DAQ_DIR_FORWARD):
      return "Forward Injection";
    case (DAQ_DIR_REVERSE):
      return "Reverse Injection";
    case (DAQ_DIR_BOTH):
      return "Forward & Reverse Injection";
    default:
      return "Unknown";
    }
}

static inline const char *
daq_vpp_msg_type_to_str (DAQ_MsgType type)
{
  switch (type)
    {
    case DAQ_MSG_TYPE_PACKET:
      return "DAQ_MSG_TYPE_PACKET";
    case DAQ_MSG_TYPE_PAYLOAD:
      return "DAQ_MSG_TYPE_PAYLOAD";
    case DAQ_MSG_TYPE_SOF:
      return "DAQ_MSG_TYPE_SOF";
    case DAQ_MSG_TYPE_EOF:
      return "DAQ_MSG_TYPE_EOF";
    case DAQ_MSG_TYPE_HA_STATE:
      return "DAQ_MSG_TYPE_HA_STATE";
    default:
      return "UNKNOWN_DAQ_MSG_TYPE";
    }
}

void
daq_vpp_dump_msg_type (DAQ_MsgType type)
{
  printf ("--- DAQ Message Type ---\n");
  printf ("  Type                 : %s (%d)\n", daq_vpp_msg_type_to_str (type),
	  type);
  printf ("------------------------\n");
}

static inline void
daq_vpp_dump_priv_data (const void *priv)
{
  printf ("--- DAQ Message Private Data ---\n");
  if (priv == NULL)
    {
      printf ("  No Private Data\n");
    }
  else
    {
      daq_vpp_msg_pool_entry_t *entry = (daq_vpp_msg_pool_entry_t *) priv;
      printf ("  desc index: %u\n", entry->index);
    }
  printf ("-------------------------------\n");
}

void
daq_vpp_dump_msg (DAQ_Msg_h msg)
{
  DAQ_PktHdr_t *pkthdr = (DAQ_PktHdr_t *) daq_msg_get_hdr (msg);
  DAQ_MsgType type = daq_msg_get_type (msg);
  const uint8_t *data = daq_msg_get_data (msg);
  uint32_t data_len = daq_msg_get_data_len (msg);
  const void *priv = daq_msg_get_priv_data (msg);

  char *napt_buf = NULL;
  char *decode_buf = NULL;
  char *tcp_ack_buf = NULL;
  char *pkt_hdr_buf = NULL;
  char *hex_dump_buf = NULL;

  // Print the Private Data
  daq_vpp_dump_priv_data (priv);

  // Print the Pkt Header
  pkt_hdr_buf = daq_vpp_dump_pkt_hdr (pkthdr);
  if (pkt_hdr_buf)
    {
      printf ("%s", pkt_hdr_buf);
      free (pkt_hdr_buf);
    }

  // Print the message type
  daq_vpp_dump_msg_type (type);

  // Print NAPT Info if present
  napt_buf =
    daq_vpp_dump_napt_info (daq_msg_get_meta (msg, DAQ_PKT_META_NAPT_INFO));
  if (napt_buf)
    {
      printf ("%s", napt_buf);
      free (napt_buf);
    }
  // Print Packet Decode Data if present
  decode_buf = daq_vpp_dump_packet_decode_data (
    daq_msg_get_meta (msg, DAQ_PKT_META_DECODE_DATA));
  if (decode_buf)
    {
      printf ("%s", decode_buf);
      free (decode_buf);
    }
  // Print TCP ACK Data if present
  tcp_ack_buf = daq_vpp_dump_packet_tcp_ack_data (
    daq_msg_get_meta (msg, DAQ_PKT_META_TCP_ACK_DATA));
  if (tcp_ack_buf)
    {
      printf ("%s", tcp_ack_buf);
      free (tcp_ack_buf);
    }

  // Print Hex Dump of Packet Data if present
  hex_dump_buf = daq_vpp_dump_packet_data (data, data_len);
  if (hex_dump_buf)
    {
      printf ("%s", hex_dump_buf);
      free (hex_dump_buf);
    }
}
