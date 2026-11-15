/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rubicon Communications, LLC.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_inlines.h>
#include <vnet/ip/ip6_to_ip4.h>

/*
 * ip6_ext_header_walk() cases check the walk's existing contract. A
 * negative find_hdr_type returns the index of the chain's last header,
 * which callers read from eh[res]. A negative return means a malformed
 * packet.
 *
 * ip6_ext_header_walk_bounded() cases check the status, the fragment
 * kind, the recorded chain and the terminating header of the bounded
 * walk.
 */

typedef struct
{
  u8 data[512];
  u32 length;
} test_packet_t;

static void
packet_init (test_packet_t *p, u8 protocol, u16 payload_length)
{
  ip6_header_t *ip6 = (ip6_header_t *) p->data;

  clib_memset (p, 0, sizeof (*p));
  ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x60000000);
  ip6->payload_length = clib_host_to_net_u16 (payload_length);
  ip6->protocol = protocol;
  ip6->hop_limit = 64;
  p->length = sizeof (ip6_header_t) + payload_length;
}

static void
packet_add_ext_header (test_packet_t *p, u32 offset, u8 next_hdr, u32 len)
{
  ip6_ext_header_t *ext = (ip6_ext_header_t *) (p->data + offset);

  ext->next_hdr = next_hdr;
  ext->n_data_u64s = (len >> 3) - 1;
}

static int
walk_packet_advanced (vlib_main_t *vm, test_packet_t *p, u32 advance, int find_hdr_type,
		      ip6_ext_hdr_chain_t *chain)
{
  vlib_buffer_t *b;
  ip6_header_t *ip;
  u32 bi;
  int res;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return -2;

  b = vlib_get_buffer (vm, bi);
  clib_memcpy_fast (vlib_buffer_get_current (b), p->data, p->length);
  b->current_length = p->length;
  ip = (ip6_header_t *) vlib_buffer_get_current (b);
  vlib_buffer_advance (b, advance);

  res = ip6_ext_header_walk (b, ip, find_hdr_type, chain);

  vlib_buffer_free (vm, &bi, 1);
  return res;
}

static int
walk_packet (vlib_main_t *vm, test_packet_t *p, int find_hdr_type, ip6_ext_hdr_chain_t *chain)
{
  return walk_packet_advanced (vm, p, 0, find_hdr_type, chain);
}

static u32
check_last_header (vlib_main_t *vm, const char *name, test_packet_t *p, int expect_res,
		   u16 expect_protocol, u16 expect_offset)
{
  ip6_ext_hdr_chain_t chain;
  int res;

  res = walk_packet (vm, p, -1, &chain);
  if (res != expect_res)
    {
      vlib_cli_output (vm, "FAIL: %s: return %d, expected %d", name, res, expect_res);
      return 1;
    }

  if (res < 0)
    return 0;

  if (chain.eh[res].protocol != expect_protocol || chain.eh[res].offset != expect_offset)
    {
      vlib_cli_output (vm,
		       "FAIL: %s: eh[%d] is protocol %u offset %u, expected "
		       "protocol %u offset %u",
		       name, res, chain.eh[res].protocol, chain.eh[res].offset, expect_protocol,
		       expect_offset);
      return 1;
    }

  return 0;
}

static u32
check_find_header (vlib_main_t *vm, const char *name, test_packet_t *p, int find_hdr_type,
		   int expect_res)
{
  ip6_ext_hdr_chain_t chain;
  int res;

  res = walk_packet (vm, p, find_hdr_type, &chain);
  if (res != expect_res)
    {
      vlib_cli_output (vm, "FAIL: %s: return %d, expected %d", name, res, expect_res);
      return 1;
    }

  return 0;
}

static u32
check_advanced_ip (vlib_main_t *vm)
{
  test_packet_t p;
  ip6_ext_hdr_chain_t chain;
  int res;

  /*
   * A node that has advanced past the IPv6 header still passes the old
   * walk a pointer that precedes the buffer's current data.
   */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 16);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_UDP, 8);
  res = walk_packet_advanced (vm, &p, sizeof (ip6_header_t), -1, &chain);
  if (res != 1 || chain.eh[1].protocol != IP_PROTOCOL_UDP || chain.eh[1].offset != 48)
    {
      vlib_cli_output (vm, "FAIL: IPv6 header before current data: return %d", res);
      return 1;
    }

  return 0;
}

static u32
run_normal_cases (vlib_main_t *vm)
{
  test_packet_t p;
  u32 failures = 0;

  /* UDP terminates a chain with no extension headers. */
  packet_init (&p, IP_PROTOCOL_UDP, 8);
  failures += check_last_header (vm, "plain UDP", &p, 0, IP_PROTOCOL_UDP, sizeof (ip6_header_t));

  /* UDP terminates a chain with one extension header. */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 16);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_UDP, 8);
  failures += check_last_header (vm, "hop-by-hop and UDP", &p, 1, IP_PROTOCOL_UDP, 48);

  /*
   * The walk returns the last recorded header index when the header is
   * absent.
   */
  packet_init (&p, IP_PROTOCOL_UDP, 8);
  failures +=
    check_find_header (vm, "absent fragment header", &p, IP_PROTOCOL_IPV6_FRAGMENTATION, 0);

  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 16);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_UDP, 8);
  failures += check_find_header (vm, "absent fragment header after a chain", &p,
				 IP_PROTOCOL_IPV6_FRAGMENTATION, 1);

  /* The walk returns the chain index of a present header. */
  packet_init (&p, IP_PROTOCOL_IPV6_FRAGMENTATION, 16);
  {
    ip6_frag_hdr_t *frag = (ip6_frag_hdr_t *) (p.data + 40);

    frag->next_hdr = IP_PROTOCOL_UDP;
    frag->fragment_offset_and_more = clib_host_to_net_u16 (8 << 3);
  }
  failures +=
    check_find_header (vm, "present fragment header", &p, IP_PROTOCOL_IPV6_FRAGMENTATION, 0);

  /*
   * Four extension headers fill the chain. The terminating UDP header
   * has no slot, so the walk returns the last chain header.
   */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 40);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_IPV6_ROUTE, 8);
  packet_add_ext_header (&p, 48, IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 8);
  packet_add_ext_header (&p, 56, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 8);
  packet_add_ext_header (&p, 64, IP_PROTOCOL_UDP, 8);
  failures += check_last_header (vm, "four chain headers and UDP", &p, 3,
				 IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 64);

  /* The walk reports the datagram protocol for a non-first fragment. */
  packet_init (&p, IP_PROTOCOL_IPV6_FRAGMENTATION, 16);
  {
    ip6_frag_hdr_t *frag = (ip6_frag_hdr_t *) (p.data + 40);

    frag->next_hdr = IP_PROTOCOL_UDP;
    frag->fragment_offset_and_more = clib_host_to_net_u16 (8 << 3);
  }
  failures += check_last_header (vm, "non-first fragment", &p, 1, IP_PROTOCOL_UDP, 48);

  /* A chain header that does not fit is malformed. */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 8);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_UDP, 8);
  p.length = sizeof (ip6_header_t) + 4;
  failures += check_last_header (vm, "truncated chain header", &p, -1, 0, 0);

  failures += check_advanced_ip (vm);

  return failures;
}

static u32
run_boundary_cases (vlib_main_t *vm)
{
  test_packet_t p;
  u32 failures = 0;

  /*
   * The old walk records a later chain header that does not fit before
   * it stops, so that header is the last one.
   */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 16);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 8);
  packet_add_ext_header (&p, 48, IP_PROTOCOL_UDP, 16);
  failures += check_last_header (vm, "later chain header past the datagram end", &p, 1,
				 IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 48);

  /*
   * The walk records a chain header that ends at the bound, then
   * continues.
   */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 8);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_IP6_NONXT, 8);
  failures +=
    check_last_header (vm, "chain header ends at the bound", &p, 1, IP_PROTOCOL_IP6_NONXT, 48);

  /*
   * For a non-first fragment that ends at the bound, the walk records
   * the datagram protocol as the last header.
   */
  packet_init (&p, IP_PROTOCOL_IPV6_FRAGMENTATION, 8);
  {
    ip6_frag_hdr_t *frag = (ip6_frag_hdr_t *) (p.data + 40);

    frag->next_hdr = IP_PROTOCOL_UDP;
    frag->fragment_offset_and_more = clib_host_to_net_u16 (8 << 3);
  }
  failures +=
    check_last_header (vm, "non-first fragment ends at the bound", &p, 1, IP_PROTOCOL_UDP, 48);

  /*
   * The old walk stops at a non-first fragment header that ends past
   * the scan bound.
   */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 220);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_IPSEC_AH, 8);
  {
    ip6_ext_header_t *ah = (ip6_ext_header_t *) (p.data + 48);

    ah->next_hdr = IP_PROTOCOL_IPV6_FRAGMENTATION;
    ah->n_data_u64s = 49;
  }
  {
    ip6_frag_hdr_t *frag = (ip6_frag_hdr_t *) (p.data + 252);

    frag->next_hdr = IP_PROTOCOL_UDP;
    frag->fragment_offset_and_more = clib_host_to_net_u16 (8 << 3);
  }
  failures += check_last_header (vm, "non-first fragment ends past the bound", &p, 2,
				 IP_PROTOCOL_IPV6_FRAGMENTATION, 252);
  failures += check_find_header (vm, "find HBH before a non-first fragment past the bound", &p,
				 IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 0);
  failures += check_find_header (vm, "find AH before a non-first fragment past the bound", &p,
				 IP_PROTOCOL_IPSEC_AH, 1);
  failures += check_find_header (vm, "find fragment header past the bound", &p,
				 IP_PROTOCOL_IPV6_FRAGMENTATION, 2);

  /* A first chain header whose end passes the depth limit is malformed. */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 224);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_UDP, 224);
  failures += check_last_header (vm, "first chain header past the depth limit", &p, -1, 0, 0);

  /* A header starting at the depth limit is part of the old chain. */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 232);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 216);
  packet_add_ext_header (&p, 256, IP_PROTOCOL_UDP, 8);
  failures += check_last_header (vm, "header starts at the depth limit", &p, 1,
				 IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 256);

  /* A plain packet whose fixed-length L4 header does not fit is malformed. */
  packet_init (&p, IP_PROTOCOL_UDP, 4);
  failures += check_last_header (vm, "plain UDP below its header length", &p, -1, 0, 0);
  packet_init (&p, IP_PROTOCOL_TCP, 19);
  failures += check_last_header (vm, "plain TCP below its header length", &p, -1, 0, 0);
  packet_init (&p, IP_PROTOCOL_ICMP6, 3);
  failures += check_last_header (vm, "plain ICMP6 below its header length", &p, -1, 0, 0);

  /* A terminating L4 header starting at the bound is in the old chain. */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 8);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_UDP, 8);
  failures +=
    check_last_header (vm, "terminating L4 starts at the bound", &p, 1, IP_PROTOCOL_UDP, 48);

  return failures;
}

typedef struct
{
  ip6_ext_hdr_chain_status_t status;
  ip6_frag_kind_t frag_kind;
  int length;
  u16 term_protocol;
  u16 term_offset;
  bool entry_limit;
  bool buffer_bound;
} bounded_expect_t;

static u32
check_bounded (vlib_main_t *vm, const char *name, test_packet_t *p, u32 valid_end, u32 datagram_end,
	       bounded_expect_t e, ip6_ext_hdr_chain_t *chain)
{
  clib_memset (chain, 0xaa, sizeof (*chain));
  ip6_ext_header_walk_bounded ((ip6_header_t *) p->data, valid_end, datagram_end, chain);

  if (chain->status != e.status || chain->frag_kind != e.frag_kind || chain->length != e.length ||
      chain->term_protocol != e.term_protocol || chain->term_offset != e.term_offset ||
      chain->entry_limit != e.entry_limit || chain->buffer_bound != e.buffer_bound)
    {
      vlib_cli_output (vm,
		       "FAIL: %s: status %u frag_kind %u length %d term %u/%u "
		       "entry_limit %u buffer_bound %u",
		       name, chain->status, chain->frag_kind, chain->length, chain->term_protocol,
		       chain->term_offset, chain->entry_limit, chain->buffer_bound);
      return 1;
    }

  return 0;
}

static u32
check_resolve (vlib_main_t *vm, const char *name, ip6_ext_hdr_chain_t *chain, int find_hdr_type,
	       bool expect_found, int expect_index, u16 expect_offset)
{
  int index = -1;
  u16 protocol = 0, offset = 0;
  bool found;

  found = ip6_ext_hdr_chain_resolve (chain, find_hdr_type, &index, &protocol, &offset);
  if (found != expect_found ||
      (found && (index != expect_index || protocol != find_hdr_type || offset != expect_offset)))
    {
      vlib_cli_output (vm, "FAIL: %s: found %u index %d protocol %u offset %u", name, found, index,
		       protocol, offset);
      return 1;
    }

  return 0;
}

static u32
check_walk_buffer_truncated_frame (vlib_main_t *vm)
{
  test_packet_t p;
  ip6_ext_hdr_chain_t chain;
  ip6_ext_hdr_chain_status_t status;
  vlib_buffer_t *b;
  u32 bi;

  /*
   * The IPv6 header declares a longer payload than the frame carries,
   * so the walk uses the bytes received as its bound. The hop-by-hop
   * header does not fit within them and does not continue in another
   * buffer.
   */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 1000);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_UDP, 16);
  p.length = sizeof (ip6_header_t) + 8;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return 1;

  b = vlib_get_buffer (vm, bi);
  clib_memcpy_fast (vlib_buffer_get_current (b), p.data, p.length);
  b->current_length = p.length;

  status = ip6_ext_header_walk_buffer (b, vlib_buffer_get_current (b), &chain);
  vlib_buffer_free (vm, &bi, 1);

  if (status != IP6_EXT_HDR_CHAIN_TRUNCATED || chain.buffer_bound)
    {
      vlib_cli_output (vm, "FAIL: truncated frame: status %u buffer_bound %u", status,
		       chain.buffer_bound);
      return 1;
    }

  return 0;
}

static u32
run_bounded_cases (vlib_main_t *vm)
{
  test_packet_t p;
  ip6_ext_hdr_chain_t chain;
  ip6_frag_hdr_t *frag;
  u32 failures = 0;
  int i;

  packet_init (&p, IP_PROTOCOL_UDP, 8);
  failures += check_bounded (vm, "plain UDP", &p, p.length, p.length,
			     (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_L4,
						  .term_protocol = IP_PROTOCOL_UDP,
						  .term_offset = 40 },
			     &chain);
  failures += check_resolve (vm, "resolve plain UDP", &chain, IP_PROTOCOL_UDP, true, 0, 40);

  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 8 + 20);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_TCP, 8);
  failures += check_bounded (vm, "hop-by-hop and TCP", &p, p.length, p.length,
			     (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_L4,
						  .length = 1,
						  .term_protocol = IP_PROTOCOL_TCP,
						  .term_offset = 48 },
			     &chain);
  failures += check_resolve (vm, "resolve hop-by-hop", &chain, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS,
			     true, 0, 40);
  failures +=
    check_resolve (vm, "resolve TCP after hop-by-hop", &chain, IP_PROTOCOL_TCP, true, 1, 48);
  failures += check_resolve (vm, "resolve absent fragment header", &chain,
			     IP_PROTOCOL_IPV6_FRAGMENTATION, false, 0, 0);

  packet_init (&p, IP_PROTOCOL_IPV6_FRAGMENTATION, 8 + 8);
  frag = (ip6_frag_hdr_t *) (p.data + 40);
  frag->next_hdr = IP_PROTOCOL_UDP;
  failures += check_bounded (vm, "first fragment", &p, p.length, p.length,
			     (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_L4,
						  .frag_kind = IP6_FRAG_FIRST,
						  .length = 1,
						  .term_protocol = IP_PROTOCOL_UDP,
						  .term_offset = 48 },
			     &chain);
  failures += check_resolve (vm, "resolve first fragment header", &chain,
			     IP_PROTOCOL_IPV6_FRAGMENTATION, true, 0, 40);

  frag->fragment_offset_and_more = ip6_frag_hdr_offset_and_more (1, 0);
  failures += check_bounded (vm, "non-first fragment", &p, p.length, p.length,
			     (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_NON_FIRST_FRAG,
						  .frag_kind = IP6_FRAG_NON_FIRST,
						  .length = 1,
						  .term_protocol = IP_PROTOCOL_UDP,
						  .term_offset = 48 },
			     &chain);
  failures += check_resolve (vm, "a non-first fragment has no UDP header", &chain, IP_PROTOCOL_UDP,
			     false, 0, 0);

  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 16 + 8);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_UDP, 16);
  failures +=
    check_bounded (vm, "truncated chain header", &p, 48, 48,
		   (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_TRUNCATED,
					.term_protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS,
					.term_offset = 40 },
		   &chain);
  failures +=
    check_bounded (vm, "chain header continues past the walk bound", &p, 48, p.length,
		   (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_TRUNCATED,
					.term_protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS,
					.term_offset = 40,
					.buffer_bound = true },
		   &chain);
  failures +=
    check_bounded (vm, "length byte past the bound", &p, 41, 41,
		   (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_TRUNCATED,
					.term_protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS,
					.term_offset = 40 },
		   &chain);

  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 8 + 10);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_TCP, 8);
  failures += check_bounded (vm, "truncated TCP header", &p, p.length, p.length,
			     (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_L4_TRUNCATED,
						  .length = 1,
						  .term_protocol = IP_PROTOCOL_TCP,
						  .term_offset = 48 },
			     &chain);
  failures += check_resolve (vm, "a truncated TCP header is not resolved", &chain, IP_PROTOCOL_TCP,
			     false, 0, 0);
  failures +=
    check_bounded (vm, "TCP header continues past the walk bound", &p, p.length, p.length + 10,
		   (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_L4_TRUNCATED,
					.length = 1,
					.term_protocol = IP_PROTOCOL_TCP,
					.term_offset = 48,
					.buffer_bound = true },
		   &chain);

  /* Four destination options headers, then UDP. */
  packet_init (&p, IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 4 * 8 + 8);
  for (i = 0; i < 4; i++)
    packet_add_ext_header (&p, 40 + 8 * i,
			   i < 3 ? IP_PROTOCOL_IP6_DESTINATION_OPTIONS : IP_PROTOCOL_UDP, 8);
  failures += check_bounded (vm, "L4 header after four chain headers", &p, p.length, p.length,
			     (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_L4,
						  .length = 4,
						  .term_protocol = IP_PROTOCOL_UDP,
						  .term_offset = 72 },
			     &chain);
  failures += check_resolve (vm, "resolve UDP after four chain headers", &chain, IP_PROTOCOL_UDP,
			     true, 4, 72);

  /* Five destination options headers, then UDP. */
  packet_init (&p, IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 5 * 8 + 8);
  for (i = 0; i < 5; i++)
    packet_add_ext_header (&p, 40 + 8 * i,
			   i < 4 ? IP_PROTOCOL_IP6_DESTINATION_OPTIONS : IP_PROTOCOL_UDP, 8);
  failures += check_bounded (
    vm, "entry limit", &p, p.length, p.length,
    (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_LIMIT, .length = 4, .entry_limit = true },
    &chain);

  /* A 224-byte hop-by-hop header ends at 264, past the scan depth. */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 224 + 8);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_UDP, 224);
  failures +=
    check_bounded (vm, "depth limit", &p, p.length, p.length,
		   (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_LIMIT, .length = 1 }, &chain);

  packet_init (&p, IP_PROTOCOL_UDP, 8);
  failures += check_bounded (vm, "bound inside the IPv6 header", &p, 20, 20,
			     (bounded_expect_t) { .status = IP6_EXT_HDR_CHAIN_LIMIT }, &chain);

  failures += check_walk_buffer_truncated_frame (vm);

  return failures;
}

static clib_error_t *
test_ip6_ext_header_walk_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  u32 failures;

  if (unformat (input, "boundary"))
    failures = run_boundary_cases (vm);
  else if (unformat (input, "bounded"))
    failures = run_bounded_cases (vm);
  else
    failures = run_normal_cases (vm);

  if (failures)
    return clib_error_return (0, "%u IPv6 extension header walk checks failed", failures);

  vlib_cli_output (vm, "PASS: ip6 extension header walk");
  return 0;
}

VLIB_CLI_COMMAND (test_ip6_ext_header_walk_command, static) = {
  .path = "test ip6 ext-header-walk",
  .short_help = "test ip6 ext-header-walk [boundary|bounded]",
  .function = test_ip6_ext_header_walk_command_fn,
};
