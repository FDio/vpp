#ifndef __included_sfdp_lookup_ip6_h__
#define __included_sfdp_lookup_ip6_h__
#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/lookup/lookup.h>
#include <vnet/sfdp/lookup/lookup_common.h>

/*ICMP echo and reply are types 128 & 129 */
static const u64 icmp6_type_ping_bitmask_128off =
  (1ULL << (ICMP6_echo_request - 128)) | (1ULL << (ICMP6_echo_reply - 128));

static const u64 icmp6_type_errors_bitmask =
  (1ULL << ICMP6_destination_unreachable) | (1ULL << ICMP6_time_exceeded);

static const u64 icmp6_type_errors_bitmask_128off =
  (1ULL << (ICMP6_redirect - 128));

#define KEY_IP6_SHUFF_NO_NORM_A 0, 1, 2, 3, -1, -1, 6, -1
#define KEY_IP6_SHUFF_NORM_A	2, 3, 0, 1, -1, -1, 6, -1
#define KEY_IP6_SHUFF_NO_NORM_B 0, 1, 2, 3, 4, 5, 6, 7
#define KEY_IP6_SHUFF_NORM_B	4, 5, 6, 7, 0, 1, 2, 3
#define IP6_BYTESWAP		15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
#define KEY_IP6_SWAP_ICMP	2, 3, 0, 1, -1, -1, -1, -1

static const u8x8 key_ip6_shuff_no_norm_A = { KEY_IP6_SHUFF_NO_NORM_A };
static const u8x8 key_ip6_shuff_norm_A = { KEY_IP6_SHUFF_NORM_A };
static const u32x8 key_ip6_shuff_no_norm_B = { KEY_IP6_SHUFF_NO_NORM_B };
static const u32x8 key_ip6_shuff_norm_B = { KEY_IP6_SHUFF_NORM_B };
static const u8x8 key_ip6_swap_icmp = { KEY_IP6_SWAP_ICMP };

static_always_inline u8
sfdp_calc_key_v6 (vlib_buffer_t *b, u32 context_id,
		  sfdp_session_ip6_key_t *skey, u64 *lookup_val, u64 *h,
		  i16 *l4_hdr_offset, u8 slow_path)
{
  u8 pr;
  i64x2 norm, norm_reverse, zero = {};
  union
  {
    struct
    {
      u32x2u as_u32x2;
      u32x8u as_u32x8;
    };
    struct
    {
      u8x8u as_u8x8;
      u8x16u as_u8x16[2];
    };
    struct
    {
      u64 as_u64;
      u64x4u as_u64x4;
    };
  } k;
  u8x8 swap_A;
  u32x8 swap_B;
  STATIC_ASSERT_SIZEOF (k, 40);
  u8x16 src_ip6, dst_ip6;
  u32 l4_hdr;
  void *next_header;
  u8 *data = vlib_buffer_get_current (b);
  ip6_header_t *ip = (void *) data;
  int slowpath_needed;
  u8 ext_hdr = 0;
  u8 l4_from_sv_reass = 0;
  u8 from_full_reass;
  u8 tcp_or_udp;
  u8 unknown_protocol;

  /* loads 40 bytes of ip6 header */
  k.as_u32x2 = *(u32x2u *) data;
  k.as_u32x8 = *(u32x8u *) (data + 8);

  if (slow_path && PREDICT_FALSE (sfdp_buffer (b)->flags &
				  SFDP_BUFFER_FLAG_IP6_FINAL_PROTO_VALID))
    {
      pr = sfdp_buffer (b)->ip6_final_proto;
      ext_hdr = 0;
      next_header = b->data + vnet_buffer (b)->l4_hdr_offset;
      k.as_u8x8 = u8x8_insert (k.as_u8x8, pr, 6); /* use final proto in key */
    }
  else
    {
      pr = ip->protocol;
      ext_hdr = ip6_ext_hdr (pr);
      next_header = ip6_next_header (ip);
    }

  tcp_or_udp = pr == IP_PROTOCOL_TCP || pr == IP_PROTOCOL_UDP;
  from_full_reass =
    sfdp_buffer2 (b)->flags & SFDP_BUFFER_FLAG_FULL_REASSEMBLED;
  slowpath_needed = !tcp_or_udp || from_full_reass;

  /* byteswap src and dst ip and splat into all 4 elts of u32x4, then
   * compare so result will hold all ones if we need to swap src and dst
   * signed vector type is used as */
  src_ip6 = u8x16_shuffle2 (k.as_u8x16[0], zero, IP6_BYTESWAP);
  dst_ip6 = u8x16_shuffle2 (k.as_u8x16[1], zero, IP6_BYTESWAP);
  norm = (u64x2) src_ip6 > (u64x2) dst_ip6;
  norm_reverse = (u64x2) src_ip6 < (u64x2) dst_ip6;
  norm = i64x2_splat (norm[1] | (~norm_reverse[1] & norm[0]));

  if (slow_path && sfdp_buffer2 (b)->flags & SFDP_BUFFER_FLAG_SV_REASSEMBLED)
    {
      /* This packet comes back from shallow virtual reassembly */
      l4_from_sv_reass = 1;
    }
  if (slow_path && ext_hdr)
    {
      /* Parse the extension header chain and look for fragmentation */
      ip6_ext_hdr_chain_t chain = { 0 };
      int res =
	ip6_ext_header_walk (b, ip, IP_PROTOCOL_IPV6_FRAGMENTATION, &chain);
      if (!(l4_from_sv_reass || from_full_reass) && res >= 0 &&
	  chain.eh[res].protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
	{
	  /* Reassembly is needed and has not been done yet */
	  lookup_val[0] = (u64) SFDP_SP_NODE_IP6_REASS << 32 | SFDP_LV_TO_SP;
	  return slowpath_needed;
	}
      else
	{
	  next_header =
	    ip6_ext_next_header_offset (ip, chain.eh[chain.length - 1].offset);
	  pr = chain.eh[chain.length - 1].protocol;
	  tcp_or_udp = pr == IP_PROTOCOL_TCP || pr == IP_PROTOCOL_UDP;
	  k.as_u8x8 =
	    u8x8_insert (k.as_u8x8, pr, 6); /* use final proto in key */
	}
    }
  l4_hdr_offset[0] = (u8 *) next_header - b[0].data;
  unknown_protocol = !tcp_or_udp && pr != IP_PROTOCOL_ICMP6;

  if (slow_path && unknown_protocol)
    {
      lookup_val[0] =
	(u64) SFDP_SP_NODE_IP6_UNKNOWN_PROTO << 32 | SFDP_LV_TO_SP;
      /*
       * full_reass will change the sfdp buf, need to restore it
       * before returing.
       */
      if (from_full_reass)
	goto restore_sfdp_buf;

      return slowpath_needed;
    }

  if (slow_path && pr == IP_PROTOCOL_ICMP6)
    {
      u8 type;
      i64 x, y, t, t128;
      if (l4_from_sv_reass)
	type = vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags;
      else
	{
	  icmp46_header_t *icmp = next_header;
	  type = icmp->type;
	}
      t = (1ULL << type);
      t128 = (1ULL << ((u8) (type - 128)));
      x = t128 & icmp6_type_ping_bitmask_128off;
      y = t & icmp6_type_errors_bitmask;
      y |= t128 & icmp6_type_errors_bitmask_128off;
      if (x == 0)
	{
	  /* If it's an known ICMP error, treat in the specific slowpath (with
	 a lookup on inner packet), otherwise, it's an unknown protocol */
	  lookup_val[0] =
	    y ? (u64) SFDP_SP_NODE_IP6_ICMP6_ERROR << 32 | SFDP_LV_TO_SP :
		(u64) SFDP_SP_NODE_IP6_UNKNOWN_PROTO << 32 | SFDP_LV_TO_SP;
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
  swap_A = key_ip6_shuff_no_norm_A;
  swap_B = key_ip6_shuff_no_norm_B;

  /* if norm is zero, we don't need to normalize so nothing happens here */
  swap_A += (key_ip6_shuff_norm_A - key_ip6_shuff_no_norm_A) & (u8x8) norm[0];
  swap_B +=
    (key_ip6_shuff_norm_B - key_ip6_shuff_no_norm_B) & u32x8_splat (norm[0]);

  /* overwrite first 4 bytes with first 0 - 4 bytes of l4 header */
  if (slow_path && l4_from_sv_reass)
    {
      u16 src_port, dst_port;
      src_port = vnet_buffer (b)->ip.reass.l4_src_port;
      dst_port = vnet_buffer (b)->ip.reass.l4_dst_port;
      l4_hdr = dst_port << 16 | src_port;
      /* Mask seqnum field out for ICMP */
      if (pr == IP_PROTOCOL_ICMP6)
	l4_hdr &= 0xff;
    }
  else if (slow_path)
    l4_hdr = ((u32 *) next_header + l4_offset_32w[pr])[0] &
	     pow2_mask (l4_mask_bits[pr]);
  else
    l4_hdr = *(u32 *) next_header & pow2_mask (l4_mask_bits[pr]);

  k.as_u32x2 = u32x2_insert (k.as_u32x2, l4_hdr, 0);

  k.as_u8x8 = u8x8_shuffle (k.as_u8x8, swap_A);
  k.as_u32x8 = u32x8_shuffle_dynamic (k.as_u32x8, swap_B);
  /* Reshuffle for ICMP
     TODO: merge with fast path? */
  if (slow_path && pr == IP_PROTOCOL_ICMP6)
    k.as_u8x8 += u8x8_shuffle (k.as_u8x8, key_ip6_swap_icmp);
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
  skey->ip6_key.as_u64 = k.as_u64;
  skey->ip6_key.as_u64x4 = k.as_u64x4;
  skey->context_id = context_id;
  clib_memset (skey->zeros, 0, sizeof (skey->zeros));
  /* calculate hash */
  h[0] = clib_bihash_hash_48_8 ((clib_bihash_kv_48_8_t *) (skey));

  if (slow_path && (l4_from_sv_reass || from_full_reass))
    {
    restore_sfdp_buf:
      /* Restore sfdp_buffer */
      /* TODO: optimise save/restore ? */
      sfdp_buffer (b)->flags = sfdp_buffer2 (b)->flags;
      sfdp_buffer (b)->service_bitmap = sfdp_buffer2 (b)->service_bitmap;
      sfdp_buffer (b)->tcp_flags = sfdp_buffer2 (b)->tcp_flags;
      sfdp_buffer (b)->tenant_index = sfdp_buffer2 (b)->tenant_index;
      sfdp_buffer (b)->session_version_before_handoff =
	sfdp_buffer2 (b)->session_version_before_handoff;

      /*Clear*/
      sfdp_buffer2 (b)->flags = 0;
      sfdp_buffer2 (b)->service_bitmap = 0;
      sfdp_buffer2 (b)->tcp_flags = 0;
      sfdp_buffer2 (b)->tenant_index = 0;
      sfdp_buffer2 (b)->session_version_before_handoff = 0;
    }
  /* If slowpath needed == 1, we may have done a lot of useless work that will
   be overwritten, but we avoid too much branching in fastpath */
  return slowpath_needed;
}

#endif /* __included_sfdp_lookup_ip6_h__ */