/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __MATCH_TURBO_DP_H__
#define __MATCH_TURBO_DP_H__

#include <match-turbo/match_turbo.h>

#include <vnet/udp/udp_packet.h>
#include <vnet/ip/icmp46_packet.h>

static_always_inline void
match_turbo_lkup (const match_turbo_lkup_t * mtl,
		  u16 bucket, match_turbo_per_thread_data_t * mpd)
{
  clib_bitmap_copy (&mpd->mpd_bitmaps[mpd->mpd_index], mtl->mtl_lkup[bucket]);
  mpd->mpd_bitmaps[mpd->mpd_index] =
    clib_bitmap_or (mpd->mpd_bitmaps[mpd->mpd_index], mtl->mtl_any);

  mpd->mpd_index++;
}

static_always_inline void
match_turbo_lkup_ip4 (const match_turbo_table_ip4_t * mtti4,
		      const ip4_address_t * ip4,
		      match_turbo_per_thread_data_t * mpd)
{
  match_turbo_lkup (&mtti4->mtti4_lkup[0], ip4->as_u16[0], mpd);
  match_turbo_lkup (&mtti4->mtti4_lkup[1], ip4->as_u16[1], mpd);
}

static_always_inline void
match_turbo_lkup_ip6 (const match_turbo_table_ip6_t * mtti6,
		      const ip6_address_t * ip6,
		      match_turbo_per_thread_data_t * mpd)
{
  match_turbo_lkup (&mtti6->mtti6_lkup[0], ip6->as_u16[0], mpd);
  match_turbo_lkup (&mtti6->mtti6_lkup[1], ip6->as_u16[1], mpd);
  match_turbo_lkup (&mtti6->mtti6_lkup[2], ip6->as_u16[2], mpd);
  match_turbo_lkup (&mtti6->mtti6_lkup[3], ip6->as_u16[3], mpd);
  match_turbo_lkup (&mtti6->mtti6_lkup[4], ip6->as_u16[4], mpd);
  match_turbo_lkup (&mtti6->mtti6_lkup[5], ip6->as_u16[5], mpd);
  match_turbo_lkup (&mtti6->mtti6_lkup[6], ip6->as_u16[6], mpd);
  match_turbo_lkup (&mtti6->mtti6_lkup[7], ip6->as_u16[7], mpd);
}

static_always_inline bool
match_turbo_match_mask_n_tuple (vlib_main_t * vm,
				ip_address_family_t af,
				vlib_buffer_t * b,
				i16 l2_offset,
				i16 l3_offset,
				const match_set_app_t * app,
				f64 now, match_result_t * res)
{
  match_turbo_per_thread_data_t *mpd;
  const match_turbo_app_t *mta0;
  const match_turbo_rule_t *mtr;
  ip_protocol_t proto0;
  u8 ii, *h0, *l40;
  index_t mtri;

  h0 = vlib_buffer_get_current (b) + l3_offset;
  mpd = &match_turbo_per_thread_data[vm->thread_index];
  mta0 = pool_elt_at_index (match_turbo_app_pool, app->msa_index);

  mpd->mpd_index = 0;

  if (AF_IP4 == af)
    {
      const ip4_header_t *ip4 = (ip4_header_t *) h0;

      match_turbo_lkup_ip4 (&mta0->mta_table.mtt_src_ip4,
			    &ip4->src_address, mpd);
      match_turbo_lkup_ip4 (&mta0->mta_table.mtt_dst_ip4,
			    &ip4->dst_address, mpd);
      proto0 = ip4->protocol;
      l40 = h0 + sizeof (*ip4);
    }
  else
    {
      const ip6_header_t *ip6 = (ip6_header_t *) h0;

      match_turbo_lkup_ip6 (&mta0->mta_table.mtt_src_ip6,
			    &ip6->src_address, mpd);
      match_turbo_lkup_ip6 (&mta0->mta_table.mtt_dst_ip6,
			    &ip6->dst_address, mpd);
      proto0 = ip6->protocol;
      l40 = h0 + sizeof (*ip6);

      if (PREDICT_FALSE (ip6->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION))
	{
	  ip6_ext_header_t *ext = (ip6_ext_header_t *) (ip6 + 1);
	  l40 = ip6_ext_next_header (ext);
	  proto0 = ext->next_hdr;
	}
    }
  match_turbo_lkup (&mta0->mta_table.mtt_proto, proto0, mpd);

  /*
   * we've now match on src,dst IP and proto, these are the non-optional
   * paramters. AND all the bitmaps together to find the best rule.
   */
  if (vec_len (mpd->mpd_bitmaps[0]) == 0)
    return (false);
  clib_bitmap_copy (&mpd->mpd_all, mpd->mpd_bitmaps[0]);

  for (ii = 1; ii < mpd->mpd_index; ii++)
    {
      if (vec_len (mpd->mpd_bitmaps[ii]) == 0)
	return (false);
      mpd->mpd_all = clib_bitmap_and (mpd->mpd_all, mpd->mpd_bitmaps[ii]);
    }
  mtri = clib_bitmap_first_set (mpd->mpd_all);

  if (~0 != mtri)
    {
      mtr = pool_elt_at_index (mta0->mta_rule_pool, mtri);

      /*
       * if the best rule we match against is proto any, then we are done.
       * Otherwise we need to ensure we also match against that rule's
       * l4/icmp paramters
       */
      if (0 == mtr->mtr_rule.mnt_ip_proto)
	*res = mtr->mtr_res;
      else
	{
	  mpd->mpd_index = 0;

	  switch (proto0)
	    {
	    case IP_PROTOCOL_TCP:
	      {
		tcp_header_t *t0 = (tcp_header_t *) l40;

		match_turbo_lkup (&mta0->mta_table.mtt_tcp, t0->flags, mpd);
		/* FALL TRHOUGH */
	      }
	    case IP_PROTOCOL_UDP:
	      {
		udp_header_t *u0 = (udp_header_t *) l40;

		match_turbo_lkup (&mta0->mta_table.mtt_src_port,
				  u0->src_port, mpd);
		match_turbo_lkup (&mta0->mta_table.mtt_dst_port,
				  u0->dst_port, mpd);
		break;
	      }
	    case IP_PROTOCOL_ICMP:
	    case IP_PROTOCOL_ICMP6:
	      {
		icmp46_header_t *i0 = (icmp46_header_t *) l40;

		match_turbo_lkup (&mta0->mta_table.mtt_icmp_type,
				  i0->type, mpd);
		match_turbo_lkup (&mta0->mta_table.mtt_icmp_code,
				  i0->code, mpd);
		break;
	      }
	    default:
	      break;
	    }

	  /*
	   * combine the bitmaps from the IP match with the l4.
	   * then fetch the best rule
	   */
	  for (ii = 0; ii < mpd->mpd_index; ii++)
	    {
	      if (vec_len (mpd->mpd_bitmaps[ii]) == 0)
		return (false);
	      mpd->mpd_all = clib_bitmap_and (mpd->mpd_all,
					      mpd->mpd_bitmaps[ii]);
	    }

	  mtri = clib_bitmap_first_set (mpd->mpd_all);

	  if (~0 != mtri)
	    {
	      mtr = pool_elt_at_index (mta0->mta_rule_pool, mtri);
	      *res = mtr->mtr_res;
	    }
	}

      return (true);
    }

  return (false);
}

static_always_inline bool
match_turbo_match_mask_n_tuple_ip4 (vlib_main_t * vm,
				    vlib_buffer_t * b,
				    i16 l2_offset,
				    i16 l3_offset,
				    const match_set_app_t * app,
				    f64 now, match_result_t * res)
{
  return (match_turbo_match_mask_n_tuple (vm, AF_IP4, b, l2_offset, l3_offset,
					  app, now, res));
}

static_always_inline bool
match_turbo_match_mask_n_tuple_ip6 (vlib_main_t * vm,
				    vlib_buffer_t * b,
				    i16 l2_offset,
				    i16 l3_offset,
				    const match_set_app_t * app,
				    f64 now, match_result_t * res)
{
  return (match_turbo_match_mask_n_tuple (vm, AF_IP6, b, l2_offset, l3_offset,
					  app, now, res));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
