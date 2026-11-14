/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rubicon Communications, LLC.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>

/*
 * The walk's negative find_hdr_type contract predates the bounded walk.
 * External consumers pass -1, read the terminating header from eh[res]
 * and treat a negative return as a malformed packet.
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
walk_packet (vlib_main_t *vm, test_packet_t *p, int find_hdr_type, ip6_ext_hdr_chain_t *chain)
{
  vlib_buffer_t *b;
  u32 bi;
  int res;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return -2;

  b = vlib_get_buffer (vm, bi);
  clib_memcpy_fast (vlib_buffer_get_current (b), p->data, p->length);
  b->current_length = p->length;

  res = ip6_ext_header_walk (b, (ip6_header_t *) vlib_buffer_get_current (b), find_hdr_type, chain);

  vlib_buffer_free (vm, &bi, 1);
  return res;
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

  /* An absent header returns the last recorded header index. */
  packet_init (&p, IP_PROTOCOL_UDP, 8);
  failures +=
    check_find_header (vm, "absent fragment header", &p, IP_PROTOCOL_IPV6_FRAGMENTATION, 0);

  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 16);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_UDP, 8);
  failures += check_find_header (vm, "absent fragment header after a chain", &p,
				 IP_PROTOCOL_IPV6_FRAGMENTATION, 1);

  /* A present header returns its index. */
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
   * has no slot, so the last chain header is returned.
   */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 40);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_IPV6_ROUTE, 8);
  packet_add_ext_header (&p, 48, IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 8);
  packet_add_ext_header (&p, 56, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 8);
  packet_add_ext_header (&p, 64, IP_PROTOCOL_UDP, 8);
  failures += check_last_header (vm, "four chain headers and UDP", &p, 3,
				 IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 64);

  /* A non-first fragment reports the datagram protocol. */
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

  return failures;
}

static u32
run_boundary_cases (vlib_main_t *vm)
{
  test_packet_t p;
  u32 failures = 0;

  /*
   * A later chain header that does not fit is recorded before the old
   * walk stops, so it is the last header.
   */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 16);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 8);
  packet_add_ext_header (&p, 48, IP_PROTOCOL_UDP, 16);
  failures += check_last_header (vm, "later chain header past the datagram end", &p, 1,
				 IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 48);

  /* A chain header ending at the bound is recorded, and the walk continues. */
  packet_init (&p, IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 8);
  packet_add_ext_header (&p, 40, IP_PROTOCOL_IP6_NONXT, 8);
  failures +=
    check_last_header (vm, "chain header ends at the bound", &p, 1, IP_PROTOCOL_IP6_NONXT, 48);

  /*
   * A non-first fragment ending at the bound records the datagram
   * protocol as the last header.
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
   * A non-first fragment header that ends past the scan bound stops the
   * old walk at the fragment header.
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

static clib_error_t *
test_ip6_ext_header_walk_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  u32 failures;

  failures = unformat (input, "boundary") ? run_boundary_cases (vm) : run_normal_cases (vm);

  if (failures)
    return clib_error_return (0, "%u IPv6 extension header walk checks failed", failures);

  vlib_cli_output (vm, "PASS: ip6 extension header walk");
  return 0;
}

VLIB_CLI_COMMAND (test_ip6_ext_header_walk_command, static) = {
  .path = "test ip6 ext-header-walk",
  .short_help = "test ip6 ext-header-walk",
  .function = test_ip6_ext_header_walk_command_fn,
};
