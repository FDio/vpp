/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * Implementation for a representation of TCP/IP packets.
 * Packets are represented in their wire format.
 */

#include "packet.h"

#include <stdlib.h>
#include <string.h>
#include "assert.h"
#include "ethernet.h"
#include "gre_packet.h"
#include "ip_packet.h"
#include "logging.h"
#include "mpls_packet.h"

/* Info for all types of header we support. */
struct header_type_info header_types[HEADER_NUM_TYPES] = {
  { "NONE", 0, 0, NULL },
  { "IPV4", IPPROTO_IPIP, ETHERTYPE_IP, ipv4_header_finish },
  { "IPV6", IPPROTO_IPV6, ETHERTYPE_IPV6, ipv6_header_finish },
  { "GRE", IPPROTO_GRE, 0, gre_header_finish },
  { "MPLS", 0, ETHERTYPE_MPLS_UC, mpls_header_finish },
  { "TCP", IPPROTO_TCP, 0, NULL },
  { "UDP", IPPROTO_UDP, 0, NULL },
  { "ICMPV4", IPPROTO_ICMP, 0, NULL },
  { "ICMPV6", IPPROTO_ICMPV6, 0, NULL },
};

struct packet *
packet_new (u32 buffer_bytes)
{
  struct packet *packet = calloc (1, sizeof (struct packet));
  packet->buffer = malloc (buffer_bytes);
  packet->buffer_bytes = buffer_bytes;
  return packet;
}

void
packet_free (struct packet *packet)
{
  free (packet->buffer);
  memset (packet, 0, sizeof (*packet)); /* paranoia to help catch bugs */
  free (packet);
}

struct packet_list *
packet_list_new (void)
{
  struct packet_list *list = calloc (1, sizeof (struct packet_list));
  list->packet = NULL;
  list->next = NULL;
  return list;
}

void
packet_list_free (struct packet_list *list)
{
  while (list != NULL)
    {
      struct packet_list *dead_list = list;
      if (list->packet)
	packet_free (list->packet);
      list = list->next;
      free (dead_list);
    }
}

int
packet_header_count (const struct packet *packet)
{
  int i;

  for (i = 0; i < ARRAY_SIZE (packet->headers); ++i)
    {
      if (packet->headers[i].type == HEADER_NONE)
	break;
    }
  return i;
}

/* Copy any header info from old_packet to new_packet. */
static void
packet_copy_headers (struct packet *new_packet, struct packet *old_packet,
		     int bytes_headroom)
{
  int i;
  u8 *base = new_packet->buffer + bytes_headroom;

  for (i = 0; i < ARRAY_SIZE (old_packet->headers); ++i)
    {
      struct header *old_header = &old_packet->headers[i];
      struct header *new_header = &new_packet->headers[i];
      int offset = 0;

      if (old_header->type == HEADER_NONE)
	break;
      offset = old_header->h.ptr - old_packet->buffer;
      new_header->h.ptr = base + offset;
      new_header->header_bytes = old_header->header_bytes;
      new_header->total_bytes = old_header->total_bytes;
      new_header->type = old_header->type;
    }
}

struct header *
packet_append_header (struct packet *packet, enum header_t header_type,
		      int header_bytes)
{
  struct header *header = NULL;
  int num_headers = packet_header_count (packet);
  int packet_bytes;

  assert (num_headers <= PACKET_MAX_HEADERS);
  if (num_headers == PACKET_MAX_HEADERS)
    return NULL;

  header = &packet->headers[num_headers];

  if (packet->ip_bytes + header_bytes > packet->buffer_bytes)
    return NULL;
  packet_bytes = packet->l2_header_bytes + packet->ip_bytes;
  header->h.ptr = packet->buffer + packet_bytes;
  packet->ip_bytes += header_bytes;

  header->type = header_type;
  header->header_bytes = header_bytes;
  header->total_bytes = 0;
  return header;
}

/* Map a pointer to a packet offset from an old base to a new base. */
static void *
offset_ptr (u8 *old_base, u8 *new_base, void *old_ptr)
{
  u8 *old = (u8 *) old_ptr;

  return (old == NULL) ? NULL : (new_base + (old - old_base));
}

static void
packet_duplicate_info (struct packet *packet, struct packet *old_packet,
		       int bytes_headroom, int extra_payload)
{
  u8 *old_base = old_packet->buffer;
  u8 *new_base = packet->buffer + bytes_headroom;

  packet->ip_bytes = old_packet->ip_bytes + extra_payload;
  packet->direction = old_packet->direction;
  packet->time_usecs = old_packet->time_usecs;
  packet->flags = old_packet->flags;
  packet->tos_chk = old_packet->tos_chk;

  packet_copy_headers (packet, old_packet, bytes_headroom);

  /* Set up layer 3 header pointer. */
  packet->ipv4 = offset_ptr (old_base, new_base, old_packet->ipv4);
  packet->ipv6 = offset_ptr (old_base, new_base, old_packet->ipv6);
  packet->tcp = offset_ptr (old_base, new_base, old_packet->tcp);
  packet->udp = offset_ptr (old_base, new_base, old_packet->udp);
  packet->icmpv4 = offset_ptr (old_base, new_base, old_packet->icmpv4);
  packet->icmpv6 = offset_ptr (old_base, new_base, old_packet->icmpv6);

  packet->tcp_ts_val = offset_ptr (old_base, new_base, old_packet->tcp_ts_val);
  packet->tcp_ts_ecr = offset_ptr (old_base, new_base, old_packet->tcp_ts_ecr);
  packet->echoed_header = old_packet->echoed_header;
}

/* Make a copy of the given old packet, but in the new copy reserve the
 * given number of bytes of headroom at the start of the packet->buffer.
 * This empty headroom can later be filled with outer packet headers.
 * A slow but simple model.
 */
static struct packet *
packet_copy_with_headroom (struct packet *old_packet, int bytes_headroom)
{
  /* Allocate a new packet and copy link layer header and IP datagram. */
  const int bytes_used = packet_end (old_packet) - old_packet->buffer;
  assert (bytes_used >= 0);
  assert (bytes_used <= 128 * 1024);
  struct packet *packet = packet_new (bytes_headroom + bytes_used);
  u8 *old_base = old_packet->buffer;
  u8 *new_base = packet->buffer + bytes_headroom;

  memcpy (new_base, old_base, bytes_used);

  packet_duplicate_info (packet, old_packet, bytes_headroom, 0);

  return packet;
}

struct packet *
packet_copy (struct packet *old_packet)
{
  return packet_copy_with_headroom (old_packet, 0);
}

/* Finalize all the headers once we know what's inside inner layers. */
static void
packet_finish_encapsulation_headers (struct packet *packet)
{
  int i;
  struct header *header = NULL, *next = NULL;

  /* Proceed from inner to outer. */
  for (i = ARRAY_SIZE (packet->headers) - 1; i >= 0; --i, next = header)
    {
      struct header_type_info *type_info = NULL;

      header = &packet->headers[i];
      if (header->type == HEADER_NONE)
	continue;

      type_info = header_type_info (header->type);
      if (type_info->finish != NULL)
	type_info->finish (packet, header, next);
    }
}

struct packet *
packet_encapsulate (struct packet *outer, struct packet *inner)
{
  struct packet *packet = NULL;
  const int outer_headers = packet_header_count (outer);
  const int inner_headers = packet_header_count (inner);

  assert (outer_headers + inner_headers <= PACKET_MAX_HEADERS);

  /* Copy the inner packet bits and header metadata. */
  packet = packet_copy_with_headroom (inner, outer->ip_bytes);

  /* Copy over the bits in the outer headers. */
  memcpy (packet->buffer, outer->buffer, outer->ip_bytes);

  /* Move the inner header metadata to make room for the outer. */
  memmove (packet->headers + outer_headers, packet->headers + 0,
	   inner_headers * sizeof (struct header));

  /* Copy over the metadata about the outer headers. */
  packet_copy_headers (packet, outer, 0);

  assert (packet_header_count (packet) == outer_headers + inner_headers);

  packet_finish_encapsulation_headers (packet);

  packet->ip_bytes = outer->ip_bytes + inner->ip_bytes;

  return packet;
}

struct header_type_info *
header_type_info (enum header_t header_type)
{
  assert (header_type > HEADER_NONE);
  assert (header_type < HEADER_NUM_TYPES);
  assert (ARRAY_SIZE (header_types) == HEADER_NUM_TYPES);
  return &header_types[header_type];
}

/* Aggregate a list of input packets into a single output packet. */
struct packet *
aggregate_packets (const struct packet_list *head,
		   const struct packet_list *tail, int payload_size)
{
  int i;
  /* Copy the headers from the last source packet. */
  struct packet *first_packet = head->packet;
  struct packet *last_packet = tail->packet;
  struct packet *old_packet = last_packet;
  /* Allocate a new packet that can accommodate the combined payload */
  int extra_payload = payload_size - packet_payload_len (old_packet);
  int headers_len = packet_payload (old_packet) - old_packet->buffer;
  int old_packet_size = packet_end (old_packet) - old_packet->buffer;
  struct packet *packet = packet_new (old_packet_size + extra_payload);

  u8 *old_base = old_packet->buffer;
  u8 *new_base = packet->buffer;
  u8 *iter_base = new_base + headers_len;

  DEBUGP ("aggregate_packets with combined payload size of %d bytes\n",
	  payload_size);
  memcpy (new_base, old_base, headers_len);

  /* Copy the payload from all the source packets. */
  do
    {
      memcpy (iter_base, packet_payload (head->packet),
	      packet_payload_len (head->packet));
      iter_base += packet_payload_len (head->packet);
      head = head->next;
    }
  while (head != NULL);

  packet_duplicate_info (packet, old_packet, 0, extra_payload);

  /* Adjust header bytes information to account for the larger payload. */
  for (i = 0; i < ARRAY_SIZE (packet->headers); ++i)
    {
      struct header *new_header = &packet->headers[i];

      if (new_header->type == HEADER_NONE)
	break;
      new_header->total_bytes += extra_payload;
      DEBUGP ("%s header starts at %p\n",
	      header_type_info (new_header->type)->name, new_header->h.ptr);
      /* For TCP header, we must copy the seq number and the cwr flag
       * from the first packet.
       */
      if (new_header->type == HEADER_TCP)
	{
	  assert (packet->tcp != NULL);
	  assert (first_packet->tcp != NULL);
	  packet->tcp->seq = first_packet->tcp->seq;
	  packet->tcp->cwr = first_packet->tcp->cwr;
	}
    }
  packet_finish_encapsulation_headers (packet);

  return packet;
}
