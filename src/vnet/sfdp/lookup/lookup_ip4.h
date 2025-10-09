#ifndef __included_sfdp_lookup_ip4_h__
#define __included_sfdp_lookup_ip4_h__
#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/lookup/lookup.h>
#include <vnet/sfdp/lookup/lookup_common.h>
static const u64 icmp4_type_ping_bitmask =
  (1ULL << ICMP4_echo_request) | (1ULL << ICMP4_echo_reply);

static const u64 icmp4_type_errors_bitmask =
  (1ULL << ICMP4_destination_unreachable) | (1ULL << ICMP4_redirect) |
  (1ULL << ICMP4_time_exceeded);

#define IP4_REASS_NEEDED_FLAGS                                                \
  ((u16) IP4_HEADER_FLAG_MORE_FRAGMENTS | (u16) ((1 << 13) - 1))

#define KEY_IP4_SHUFF_NO_NORM                                                 \
  0, 1, 2, 3, -1, 5, -1, -1, 8, 9, 10, 11, 12, 13, 14, 15

#define KEY_IP4_SHUFF_NORM                                                    \
  2, 3, 0, 1, -1, 5, -1, -1, 12, 13, 14, 15, 8, 9, 10, 11

#define SRC_IP4_BYTESWAP_X2                                                   \
  11, 10, 9, 8, 16, 16, 16, 16, 11, 10, 9, 8, 16, 16, 16, 16
#define DST_IP4_BYTESWAP_X2                                                   \
  15, 14, 13, 12, 16, 16, 16, 16, 15, 14, 13, 12, 16, 16, 16, 16

#define KEY_IP4_SWAP_ICMP                                                     \
  2, 3, 0, 1, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16

static const u8x16 key_ip4_shuff_no_norm = { KEY_IP4_SHUFF_NO_NORM };

static const u8x16 key_ip4_shuff_norm = { KEY_IP4_SHUFF_NORM };

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpsabi"
static_always_inline u8
sfdp_calc_key_v4 (vlib_buffer_t *b, u32 context_id,
		  sfdp_session_ip4_key_t *skey, u64 *lookup_val, u64 *h,
		  i16 *l4_hdr_offset, u8 slow_path)
{
  u8 pr;
  i64x2 norm, zero = {};
  u8x16 k, swap;
  u32 l4_hdr;
  void *next_header;
  ip4_header_t *ip = vlib_buffer_get_current (b);
  u8 slowpath_needed;
  u8 reass_needed;
  u8 l4_from_sv_reass = 0;
  u8 from_full_reass;
  u8 tcp_or_udp;
  u8 unknown_protocol;
  /* load last 16 bytes of ip header into 128-bit register */
  k = *(u8x16u *) ((u8 *) ip + 4);
  pr = ip->protocol;
  next_header = ip4_next_header (ip);
  l4_hdr_offset[0] = (u8 *) next_header - b->data;

  reass_needed = !!(ip->flags_and_fragment_offset &
		    clib_host_to_net_u16 (IP4_REASS_NEEDED_FLAGS));
  tcp_or_udp = pr == IP_PROTOCOL_TCP || pr == IP_PROTOCOL_UDP;
  unknown_protocol = !tcp_or_udp && pr != IP_PROTOCOL_ICMP;
  from_full_reass =
    sfdp_buffer2 (b)->flags & SFDP_BUFFER_FLAG_FULL_REASSEMBLED;
  slowpath_needed = !tcp_or_udp || reass_needed || from_full_reass;

  if (slow_path && reass_needed &&
      sfdp_buffer2 (b)->flags & SFDP_BUFFER_FLAG_SV_REASSEMBLED)
    {
      /* This packet comes back from shallow virtual reassembly */
      l4_from_sv_reass = 1;
    }
  else if (slow_path && reass_needed)
    {
      /* Reassembly is needed and has not been done yet */
      lookup_val[0] = (u64) SFDP_SP_NODE_IP4_REASS << 32 | SFDP_LV_TO_SP;
      return slowpath_needed;
    }

  /* non TCP, UDP or ICMP packets are going to slowpath */
  if (slow_path && unknown_protocol)
    {
      lookup_val[0] =
	(u64) SFDP_SP_NODE_IP4_UNKNOWN_PROTO << 32 | SFDP_LV_TO_SP;
      /*
       * full_reass will change the sfdp buf, need to restore it
       * before returing.
       */
      if (from_full_reass)
	goto restore_sfdp_buf;

      return slowpath_needed;
    }

  /* byteswap src and dst ip and splat into all 4 elts of u32x4, then
   * compare so result will hold all ones if we need to swap src and dst
   * signed vector type is used as */
  norm = (((i64x2) u8x16_shuffle2 (k, zero, SRC_IP4_BYTESWAP_X2)) >
	  ((i64x2) u8x16_shuffle2 (k, zero, DST_IP4_BYTESWAP_X2)));

  if (slow_path && pr == IP_PROTOCOL_ICMP)
    {
      u8 type;
      i64 x, y;

      if (l4_from_sv_reass)
	type = vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags;
      else
	{
	  icmp46_header_t *icmp = next_header;
	  type = icmp->type;
	}
      x = (1ULL << type) & icmp4_type_ping_bitmask;
      y = (1ULL << type) & icmp4_type_errors_bitmask;
      if (x == 0)
	{
	  /* If it's an known ICMP error, treat in the specific slowpath (with
	     a lookup on inner packet), otherwise, it's an unknown protocol */
	  lookup_val[0] =
	    y ? (u64) SFDP_SP_NODE_IP4_ICMP4_ERROR << 32 | SFDP_LV_TO_SP :
		(u64) SFDP_SP_NODE_IP4_UNKNOWN_PROTO << 32 | SFDP_LV_TO_SP;
	  /*
	   * full_reass will change the sfdp buf, need to restore it
	   * before returing.
	   */
	  if (from_full_reass)
	    goto restore_sfdp_buf;

	  return slowpath_needed;
	}
      norm &= i64x2_splat (x) != zero;
    }
  else
    {
      norm &= i64x2_splat ((1ULL << pr) & tcp_udp_bitmask) != zero;
    }
  swap = key_ip4_shuff_no_norm;
  /* if norm is zero, we don't need to normalize so nothing happens here */
  swap += (key_ip4_shuff_norm - key_ip4_shuff_no_norm) & (u8x16) norm;

  /* overwrite first 4 bytes with first 0 - 4 bytes of l4 header */
  if (slow_path && l4_from_sv_reass)
    {
      u16 src_port, dst_port;
      src_port = vnet_buffer (b)->ip.reass.l4_src_port;
      dst_port = vnet_buffer (b)->ip.reass.l4_dst_port;
      l4_hdr = dst_port << 16 | src_port;
      /* Mask seqnum field out for ICMP */
      if (pr == IP_PROTOCOL_ICMP)
	l4_hdr &= 0xff;
    }
  else if (slow_path)
    l4_hdr = ((u32 *) next_header + l4_offset_32w[pr])[0] &
	     pow2_mask (l4_mask_bits[pr]);
  else
    l4_hdr = *(u32 *) next_header & pow2_mask (l4_mask_bits[pr]);
  k = (u8x16) u32x4_insert ((u32x4) k, l4_hdr, 0);

  k = u8x16_shuffle_dynamic (k, swap);

  /* Reshuffle for ICMP
     TODO: merge with fast path? */
  if (slow_path && pr == IP_PROTOCOL_ICMP)
    k += u8x16_shuffle2 (k, zero, KEY_IP4_SWAP_ICMP);
  lookup_val[0] = ((u32x4) norm)[0] & 0x1;

  /* extract tcp flags */
  if (slow_path && l4_from_sv_reass && pr == IP_PROTOCOL_TCP)
    sfdp_buffer2 (b)->tcp_flags =
      vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags;
  else if (pr == IP_PROTOCOL_TCP)
    sfdp_buffer (b)->tcp_flags = *(u8 *) next_header + 13;
  else
    sfdp_buffer (b)->tcp_flags = 0;

  /* store key */
  skey->ip4_key.as_u8x16 = k;
  skey->context_id = context_id;
  clib_memset (skey->zeros, 0, sizeof (skey->zeros));
  /* calculate hash */
  h[0] = clib_bihash_hash_24_8 ((clib_bihash_kv_24_8_t *) (skey));

  if (slow_path && (l4_from_sv_reass || from_full_reass))
    {
    restore_sfdp_buf:
      /* Restore sfdp_buffer */
      /* TODO: optimise save/restore ? */
      sfdp_buffer (b)->flags = sfdp_buffer2 (b)->flags;
      sfdp_buffer (b)->service_bitmap = sfdp_buffer2 (b)->service_bitmap;
      sfdp_buffer (b)->tcp_flags = sfdp_buffer2 (b)->tcp_flags;
      sfdp_buffer (b)->ip6_final_proto = sfdp_buffer2 (b)->ip6_final_proto;
      sfdp_buffer (b)->tenant_index = sfdp_buffer2 (b)->tenant_index;
      sfdp_buffer (b)->session_version_before_handoff =
	sfdp_buffer2 (b)->session_version_before_handoff;

      /*Clear*/
      sfdp_buffer2 (b)->flags = 0;
      sfdp_buffer2 (b)->service_bitmap = 0;
      sfdp_buffer2 (b)->tcp_flags = 0;
      sfdp_buffer2 (b)->ip6_final_proto = 0;
      sfdp_buffer2 (b)->tenant_index = 0;
      sfdp_buffer2 (b)->session_version_before_handoff = 0;
    }

  /* If slowpath needed == 1, we may have done a lot of useless work that will
   be overwritten, but we avoid too much branching in fastpath */
  return slowpath_needed;
}
#pragma GCC diagnostic pop
#endif