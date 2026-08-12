/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/sfdp/lookup/parser_inlines.h>

/* example definition of a SFDP custom parser */
/* this custom parser creates a key based on packet IPv4 addresses / ports */

typedef struct
{
  ip4_address_t addr_lo;
  ip4_address_t addr_hi;
  u16 port_lo;
  u16 port_hi;
  u32 context_id;
  u8 protocol;
  u8 pad[7];
} sample_ip4_key_t;

STATIC_ASSERT_SIZEOF (sample_ip4_key_t, 24);

static_always_inline int
sample_ip4_endpoint_cmp (ip4_address_t *a_addr, u16 a_port, ip4_address_t *b_addr, u16 b_port)
{
  u32 a = clib_net_to_host_u32 (a_addr->as_u32);
  u32 b = clib_net_to_host_u32 (b_addr->as_u32);

  return a == b ? clib_net_to_host_u16 (a_port) > clib_net_to_host_u16 (b_port) : a > b;
}

static u8
sample_ip4_calc_key (vlib_buffer_t *b, u32 context_id, void *skey, u64 *lookup_val, u64 *hash,
		     i16 *l4_hdr_offset, u8 slowpath)
{
  sample_ip4_key_t *key = skey;
  ip4_header_t *ip = vlib_buffer_get_current (b);
  udp_header_t *l4 = (void *) ip + ip4_header_bytes (ip);
  u8 swap =
    sample_ip4_endpoint_cmp (&ip->src_address, l4->src_port, &ip->dst_address, l4->dst_port);

  clib_memset (key, 0, sizeof (*key));
  if (swap)
    {
      key->addr_lo = ip->dst_address;
      key->addr_hi = ip->src_address;
      key->port_lo = l4->dst_port;
      key->port_hi = l4->src_port;
    }
  else
    {
      key->addr_lo = ip->src_address;
      key->addr_hi = ip->dst_address;
      key->port_lo = l4->src_port;
      key->port_hi = l4->dst_port;
    }
  key->context_id = context_id;
  key->protocol = ip->protocol;
  lookup_val[0] = swap;
  l4_hdr_offset[0] = (u8 *) l4 - b->data;
  hash[0] = clib_bihash_hash_24_8 ((clib_bihash_kv_24_8_t *) key);
  return 0;
}

static void
sample_ip4_normalize_key (sfdp_session_t *session, void *result, u8 key_idx)
{
  sample_ip4_key_t *normalized = result;
  sample_ip4_key_t *key = (void *) session->keys_data[key_idx];

  *normalized = *key;
  if (session->pseudo_dir[key_idx])
    {
      normalized->addr_lo = key->addr_hi;
      normalized->addr_hi = key->addr_lo;
      normalized->port_lo = key->port_hi;
      normalized->port_hi = key->port_lo;
    }
}

static u8 *
format_sample_ip4_ingress (u8 *s, va_list *args)
{
  sample_ip4_key_t *key = va_arg (*args, sample_ip4_key_t *);
  return format (s, "%U:%u", format_ip4_address, &key->addr_lo,
		 clib_net_to_host_u16 (key->port_lo));
}

static u8 *
format_sample_ip4_egress (u8 *s, va_list *args)
{
  sample_ip4_key_t *key = va_arg (*args, sample_ip4_key_t *);
  return format (s, "%U:%u", format_ip4_address, &key->addr_hi,
		 clib_net_to_host_u16 (key->port_hi));
}

static u8 *
format_sample_ip4_context (u8 *s, va_list *args)
{
  sample_ip4_key_t *key = va_arg (*args, sample_ip4_key_t *);
  return format (s, "%u", key->context_id);
}

SFDP_PARSER_REGISTER (sample_ip4_parser) = {
  .name = "sample-ip4-parser",
  .calc_key_fn = sample_ip4_calc_key,
  .key_size = sizeof (sample_ip4_key_t),
  .proto_offset = STRUCT_OFFSET_OF (sample_ip4_key_t, protocol),
  .type = SFDP_SESSION_TYPE_USER,
  .format_fn = {
    [SFDP_PARSER_FORMAT_FUNCTION_INGRESS] = format_sample_ip4_ingress,
    [SFDP_PARSER_FORMAT_FUNCTION_EGRESS] = format_sample_ip4_egress,
    [SFDP_PARSER_FORMAT_FUNCTION_CONTEXT] = format_sample_ip4_context,
  },
  .normalize_key_fn = sample_ip4_normalize_key,
};

SFDP_PARSER_DEFINE_NODE (sample_ip4_parser);
