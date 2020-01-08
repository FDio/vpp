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


#include <vnet/match/match_engine.h>
#include <vnet/match/engines/classifier/match_classifier.h>
#include <vnet/match/engines/classifier/match_classifier_dp.h>

#include <vnet/ethernet/arp_packet.h>
#include <vnet/ip/ip.h>

/**
 * A mask 'class' requires its own classifier set
 */
typedef struct match_classifier_mask_class_t_
{
  mac_address_t mcmc_mac;
  u8 mcmc_ip;
  match_type_t mcmc_type;
  ethernet_type_t mcmc_proto;
} match_classifier_mask_class_t;

/**
 * The data 'installed' in the classifier for each class
 */
typedef struct match_classifier_mask_class_data_t_
{
  /** set index for each number of VLAN tags */
  u32 mcmcd_set_indices[3];
} match_classifier_mask_class_data_t;

static match_classifier_mask_class_data_t
  * match_classifier_mask_class_data_pool;

match_engine_classifier_t *match_engine_classifier_pool;

static u32
match_classifier_round_up_to_classifier_vector_size (u32 n_bytes)
{
  u32 d, m;
  /* round to size of u32x4 */
  d = n_bytes / sizeof (u32x4);
  m = n_bytes % sizeof (u32x4);
  if (m)
    d++;

  return ((d * sizeof (u32x4)) / sizeof (u32x4));
}

static void
match_classifier_mask_class_data_init (match_classifier_mask_class_data_t *
				       mcmcd)
{
  u32 i;
  for (i = 0; i <= 2; i++)
    mcmcd->mcmcd_set_indices[i] = INDEX_INVALID;
}

static u32
match_classifier_mk_table (void *mask,
			   u32 mask_len, u32 next_table_index, i16 offset)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 memory_size = 2 << 22;
  u32 nbuckets = 32;
  u32 table_index = ~0;

  /* *INDENT-OFF* */
  if (vnet_classify_add_del_table (cm, mask, nbuckets, memory_size,
                                   0,	// no skip, since we will match the ether-type
				   match_classifier_round_up_to_classifier_vector_size (mask_len),
                                   next_table_index,	// next-set-index
				   ~0,	// miss-set-index
				   &table_index,
                                   CLASSIFY_FLAG_USE_CURR_DATA,
                                   offset,	// current_data_offset,
				   1,	// is_add,
				   1	// delete_chain
                                   ))
    ASSERT (0);
  /* *INDENT-OON* */

  return (table_index);
}

static int
match_classifier_mk_session (u32 table_index,
                             void * match, u32 usr_context)
{
  vnet_classify_main_t *cm = &vnet_classify_main;

  /* *INDENT-OFF* */
  return (vnet_classify_add_del_session (cm, table_index, match,
                                         ~0,	// hit_next_index,
					 usr_context, 0,	// advance,
					 CLASSIFY_ACTION_NONE,
					 0 /* metadata */ ,
					 1 /* is_add */ ));
  /* *INDENT-ON* */
}

static i16
match_classifier_get_offset (ethernet_type_t rulet,
			     vnet_link_t linkt, match_set_tag_flags_t flag)
{
  /*
   * the link layer at which the match is performed
   * hence the layer at which the packet's get_current() will point
   */
  switch (linkt)
    {
    case VNET_LINK_IP4:
    case VNET_LINK_IP6:
    case VNET_LINK_ARP:
      if (ETHERNET_TYPE_IP4 == rulet ||
	  ETHERNET_TYPE_IP6 == rulet || ETHERNET_TYPE_ARP == rulet)
	{
	  /* the rule applie to ip4 over ethernet packets
	   * rewind to the ehternet header  */
	  if (flag == MATCH_SET_TAG_FLAG_0_TAG)
	    return -((i16) sizeof (ethernet_header_t));
	  if (flag == MATCH_SET_TAG_FLAG_1_TAG)
	    return -((i16) (sizeof (ethernet_header_t) +
			    sizeof (ethernet_vlan_header_t)));
	  if (flag == MATCH_SET_TAG_FLAG_2_TAG)
	    return -((i16) (sizeof (ethernet_header_t) +
			    sizeof (ethernet_vlan_header_t) +
			    sizeof (ethernet_vlan_header_t)));
	}
      break;
    case VNET_LINK_ETHERNET:
      return (0);
    default:
      ASSERT (0);
    }
  ASSERT (0);
  return (0);
}

static u32
match_classifier_mk_arp_tables (const match_classifier_mask_class_t * mcmc,
				u32 table_index,
				match_set_tag_flags_t flags,
				vnet_link_t linkt,
				match_classifier_mask_class_data_t * mcmcd)
{
  ethernet_arp_header_t ah = { };
  u8 who;
  u8 mask[5 * 16];

  clib_memset (mask, 0, sizeof (mask));

  switch (mcmc->mcmc_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      who = ARP_SENDER;
      break;
    case MATCH_TYPE_MASK_DST_IP_MAC:
      who = ARP_TARGET;
      break;
    default:
      ASSERT (0);
      return (~0);
    }

  mac_address_copy (&ah.ip4_over_ethernet[who].mac, &mcmc->mcmc_mac);
  ip4_preflen_to_mask (mcmc->mcmc_ip, &ah.ip4_over_ethernet[who].ip4);

  ethernet_header_t *eh = (ethernet_header_t *) mask;

  eh->type = 0xffff;

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    {
      clib_memcpy (eh + 1, &ah, sizeof (ah));

      mcmcd->mcmcd_set_indices[0] =
	table_index =
	match_classifier_mk_table (mask,
				   sizeof (*eh) + sizeof (ah),
				   table_index,
				   match_classifier_get_offset
				   (mcmc->mcmc_proto, linkt,
				    MATCH_SET_TAG_FLAG_0_TAG));
    }
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    {
      ethernet_vlan_header_t *ev = (ethernet_vlan_header_t *) (eh + 1);

      clib_memset (ev, 0, sizeof (*ev));
      ev->type = 0xffff;

      clib_memcpy (ev + 1, &ah, sizeof (ah));

      mcmcd->mcmcd_set_indices[1] =
	table_index =
	match_classifier_mk_table (mask,
				   sizeof (*eh) + sizeof (*ev) +
				   sizeof (ah), table_index,
				   match_classifier_get_offset
				   (mcmc->mcmc_proto, linkt,
				    MATCH_SET_TAG_FLAG_1_TAG));
    }
  if (flags & MATCH_SET_TAG_FLAG_2_TAG)
    {
      ethernet_vlan_header_t *evi, *evo = (ethernet_vlan_header_t *) (eh + 1);

      evi = (evo + 1);
      clib_memset (evi, 0, sizeof (*evi));
      clib_memset (evo, 0, sizeof (*evo));
      evo->type = 0xffff;
      evi->type = 0xffff;

      clib_memcpy (evi + 1, &ah, sizeof (ah));

      mcmcd->mcmcd_set_indices[2] =
	table_index =
	match_classifier_mk_table (mask,
				   sizeof (*eh) + 2 * sizeof (*evo) +
				   sizeof (ah), table_index,
				   match_classifier_get_offset
				   (mcmc->mcmc_proto, linkt,
				    MATCH_SET_TAG_FLAG_2_TAG));
    }

  return (table_index);
}

typedef struct match_classifier_ip_0_tag_t_
{
  ethernet_header_t eh;
  union
  {
    ip4_header_t ip4;
    ip6_header_t ip6;
  };
} __clib_packed match_classifier_ip_0_tag_t;
typedef struct match_classifier_ip_1_tag_t_
{
  ethernet_header_t eh;
  ethernet_vlan_header_t ev;
  union
  {
    ip4_header_t ip4;
    ip6_header_t ip6;
  };
} __clib_packed match_classifier_ip_1_tag_t;
typedef struct match_classifier_ip_2_tag_t_
{
  ethernet_header_t eh;
  ethernet_vlan_header_t evo;
  ethernet_vlan_header_t evi;
  union
  {
    ip4_header_t ip4;
    ip6_header_t ip6;
  };
} __clib_packed match_classifier_ip_2_tag_t;

typedef struct match_classifier_ip_tag_t_
{
  union
  {
    match_classifier_ip_2_tag_t t2;
    match_classifier_ip_1_tag_t t1;
    match_classifier_ip_0_tag_t t0;
  };
  u8 pad[2];
} match_classifier_ip_tag_t;

STATIC_ASSERT_SIZEOF (match_classifier_ip_tag_t, 4 * sizeof (u32x4));

/* *INDENT-OFF* */
const static match_classifier_ip_tag_t match_classifier_mask_ip_2_tag = {
  .t2 = {
    .eh = {
      .type = 0xffff,
    },
    .evo = {
      .type = 0xffff,
    },
    .evi = {
      .type = 0xffff,
    },
  },
};

const static match_classifier_ip_tag_t match_classifier_mask_ip_1_tag = {
  .t1 = {
    .eh = {
      .type = 0xffff,
    },
    .ev = {
      .type = 0xffff,
    },
  },
};

const static match_classifier_ip_tag_t match_classifier_mask_ip_0_tag = {
  .t0 = {
    .eh = {
      .type = 0xffff,
    },
  },
};

const static match_classifier_ip_tag_t match_classifier_ip4_0_tag = {
  .t0 = {
    .eh = {
      // clib_host_to_net_u16(ETHERNET_TYPE_IP4)
      .type = 0x0008,
    },
  },
};
const static match_classifier_ip_tag_t match_classifier_ip4_1_tag = {
  .t1 = {
    .eh = {
      // clib_host_to_net_u16(ETHERNET_TYPE_VLAN)
      .type = 0x0081,
    },
    .ev = {
      // clib_host_to_net_u16(ETHERNET_TYPE_IP4)
      .type = 0x0008,
    },
  },
};
const static match_classifier_ip_tag_t match_classifier_ip4_2_tag = {
  .t2 = {
    .evo = {
      // clib_host_to_net_u16(ETHERNET_TYPE_VLAN)
      .type = 0x0081,
    },
    .evi = {
      // clib_host_to_net_u16(ETHERNET_TYPE_IP4)
      .type = 0x0008,
    },
    .eh = {
      // clib_host_to_net_u16(ETHERNET_TYPE_DOT1AD)
      .type = 0xa888,
    },
  },
};

const static match_classifier_ip_tag_t match_classifier_ip6_0_tag = {
  .t0 = {
    .eh = {
      // clib_host_to_net_u16(ETHERNET_TYPE_IP6)
      .type = 0xdd86,
    },
  },
};
const static match_classifier_ip_tag_t match_classifier_ip6_1_tag = {
  .t1 = {
    .eh = {
      // clib_host_to_net_u16(ETHERNET_TYPE_VLAN)
      .type = 0x0081,
    },
    .ev = {
      // clib_host_to_net_u16(ETHERNET_TYPE_IP6)
      .type = 0xdd86,
    },
  },
};
const static match_classifier_ip_tag_t match_classifier_ip6_2_tag = {
  .t2 = {
    .eh = {
      // clib_host_to_net_u16(ETHERNET_TYPE_DOT1AD)
      .type = 0xa888,
    },
    .evo = {
      // clib_host_to_net_u16(ETHERNET_TYPE_VLAN)
      .type = 0x0081,
    },
    .evi = {
      // clib_host_to_net_u16(ETHERNET_TYPE_IP6)
      .type = 0xdd86,
    },
  },
};
/* *INDENT-ON* */

static void
match_classifier_mk_ip4_hdr_mask (const match_classifier_mask_class_t * mcmc,
				  ip4_header_t * ip, ethernet_header_t * eh)
{
  switch (mcmc->mcmc_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      ip4_preflen_to_mask (mcmc->mcmc_ip, &ip->src_address);
      mac_address_to_bytes (&mcmc->mcmc_mac, eh->src_address);
      break;
    case MATCH_TYPE_MASK_DST_IP_MAC:
      ip4_preflen_to_mask (mcmc->mcmc_ip, &ip->dst_address);
      mac_address_to_bytes (&mcmc->mcmc_mac, eh->dst_address);
      break;
    default:
      break;
    }
}

static void
match_classifier_mk_ip6_hdr_mask (const match_classifier_mask_class_t * mcmc,
				  ip6_header_t * ip, ethernet_header_t * eh)
{
  switch (mcmc->mcmc_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      ip6_preflen_to_mask (mcmc->mcmc_ip, &ip->src_address);
      mac_address_to_bytes (&mcmc->mcmc_mac, eh->src_address);
      break;
    case MATCH_TYPE_MASK_DST_IP_MAC:
      ip6_preflen_to_mask (mcmc->mcmc_ip, &ip->dst_address);
      mac_address_to_bytes (&mcmc->mcmc_mac, eh->dst_address);
      break;
    default:
      break;
    }
}

#define MATCH_CLASSIFIER_MK_IP4_TBL(_h, _s, _tempale, _i, _f)           \
{                                                                       \
  clib_memcpy (&(_h), (_tempale), sizeof ((_h)));                       \
                                                                        \
  match_classifier_mk_ip4_hdr_mask (mcmc, &_h._s.ip4, &_h._s.eh);       \
                                                                        \
  mcmcd->mcmcd_set_indices[_i] =                                        \
    table_index =                                                       \
    match_classifier_mk_table ((u8*) &h,                                \
                               sizeof (h),                              \
                               table_index,                             \
                               match_classifier_get_offset              \
                               (mcmc->mcmc_proto, linkt, _f));          \
}

#define MATCH_CLASSIFIER_MK_IP6_TBL(_h, _s, _tempale, _i, _f)           \
{                                                                       \
  clib_memcpy (&(_h), (_tempale), sizeof ((_h)));                       \
                                                                        \
  match_classifier_mk_ip6_hdr_mask (mcmc, &_h._s.ip6, &_h._s.eh);       \
                                                                        \
  mcmcd->mcmcd_set_indices[_i] =                                        \
    table_index =                                                       \
    match_classifier_mk_table (&h, sizeof (h),                          \
                               table_index,                             \
                               match_classifier_get_offset              \
                               (mcmc->mcmc_proto, linkt, _f));          \
}

static u32
match_classifier_mk_ip4_tables (const match_classifier_mask_class_t * mcmc,
				u32 table_index,
				match_set_tag_flags_t flags,
				vnet_link_t linkt,
				match_classifier_mask_class_data_t * mcmcd)
{
  match_classifier_ip_tag_t h;

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    MATCH_CLASSIFIER_MK_IP4_TBL (h, t0, &match_classifier_mask_ip_0_tag,
				 0, MATCH_SET_TAG_FLAG_0_TAG);
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    MATCH_CLASSIFIER_MK_IP4_TBL (h, t1, &match_classifier_mask_ip_1_tag,
				 1, MATCH_SET_TAG_FLAG_1_TAG);
  if (flags & MATCH_SET_TAG_FLAG_2_TAG)
    MATCH_CLASSIFIER_MK_IP4_TBL (h, t2, &match_classifier_mask_ip_2_tag,
				 2, MATCH_SET_TAG_FLAG_2_TAG);

  return (table_index);
}

static u32
match_classifier_mk_ip6_tables (const match_classifier_mask_class_t * mcmc,
				u32 table_index,
				match_set_tag_flags_t flags,
				vnet_link_t linkt,
				match_classifier_mask_class_data_t * mcmcd)
{
  match_classifier_ip_tag_t h;

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    MATCH_CLASSIFIER_MK_IP6_TBL (h, t0, &match_classifier_mask_ip_0_tag,
				 0, MATCH_SET_TAG_FLAG_0_TAG);
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    MATCH_CLASSIFIER_MK_IP6_TBL (h, t1, &match_classifier_mask_ip_1_tag,
				 1, MATCH_SET_TAG_FLAG_1_TAG);
  if (flags & MATCH_SET_TAG_FLAG_2_TAG)
    MATCH_CLASSIFIER_MK_IP6_TBL (h, t2, &match_classifier_mask_ip_2_tag,
				 2, MATCH_SET_TAG_FLAG_2_TAG);

  return (table_index);
}

static u32
match_classifier_mk_tables (const match_classifier_mask_class_t * mcmc,
			    u32 table_index,
			    match_set_tag_flags_t flags,
			    vnet_link_t linkt,
			    match_classifier_mask_class_data_t * mcmcd)
{
  switch (mcmc->mcmc_proto)
    {
    case ETHERNET_TYPE_ARP:
      return (match_classifier_mk_arp_tables (mcmc, table_index, flags,
					      linkt, mcmcd));
    case ETHERNET_TYPE_IP4:
      return (match_classifier_mk_ip4_tables (mcmc, table_index, flags,
					      linkt, mcmcd));
    case ETHERNET_TYPE_IP6:
      return (match_classifier_mk_ip6_tables (mcmc, table_index, flags,
					      linkt, mcmcd));
    default:
      ASSERT (0);
      break;
    }

  ASSERT (0);
  return (~0);
}

typedef struct match_classifier_ctx_t_
{
  uword *masks;
  vnet_link_t linkt;
  match_set_tag_flags_t flags;
  void *usr_ctx;
  match_classifier_mask_class_t *mask_vec;
} match_classifier_ctx_t;

static match_classifier_mask_class_t
match_classifier_rule_mk_mask (const match_rule_t * mr)
{
  match_classifier_mask_class_t mcmc = {
    .mcmc_proto = mr->mr_proto,
    .mcmc_type = mr->mr_type,
  };

  switch (mr->mr_type)
    {
    case MATCH_TYPE_EXACT_SRC_IP_MAC:
      break;
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      mac_address_copy (&mcmc.mcmc_mac,
			&mr->mr_mask_src_ip_mac.mm_mac.mmm_mask);
      mcmc.mcmc_ip = mr->mr_mask_src_ip_mac.mm_ip.mip_len;
      break;
    case MATCH_TYPE_MASK_DST_IP_MAC:
      mac_address_copy (&mcmc.mcmc_mac,
			&mr->mr_mask_dst_ip_mac.mm_mac.mmm_mask);
      mcmc.mcmc_ip = mr->mr_mask_dst_ip_mac.mm_ip.mip_len;
      break;
    }

  return (mcmc);
}

static walk_rc_t
match_classifier_mk_table_walk_rules (const match_rule_t * mr, void *data)
{
  match_classifier_ctx_t *ctx = data;
  match_classifier_mask_class_t mask;
  uword *p;

  mask = match_classifier_rule_mk_mask (mr);

  p = hash_get (ctx->masks, &mask);

  if (!p)
    {
      hash_set_mem_alloc (&ctx->masks, &mask, 0);
      vec_add1 (ctx->mask_vec, mask);
    }

  return (WALK_CONTINUE);
}

static walk_rc_t
match_classifier_mk_table_walk_entries (const match_set_entry_t * mse,
					void *data)
{
  match_classifier_ctx_t *ctx = data;

  ctx->usr_ctx = mse->mse_usr_ctxt;

  match_set_entry_walk_rules (mse,
			      match_classifier_mk_table_walk_rules, data);

  return (WALK_CONTINUE);
}

static void
match_classifier_mk_arp_sessions (const match_rule_t * mr,
				  const match_classifier_mask_class_data_t *
				  mcmcd, match_set_tag_flags_t flags)
{
  ethernet_arp_header_t ah = { };
  ethernet_header_t *eh;
  u8 match[5 * 16];

  eh = (ethernet_header_t *) match;

  switch (mr->mr_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      mac_address_copy (&ah.ip4_over_ethernet[ARP_SENDER].mac,
			&mr->mr_mask_src_ip_mac.mm_mac.mmm_mac);
      ah.ip4_over_ethernet[ARP_SENDER].ip4 =
	ip_addr_v4 (&mr->mr_mask_src_ip_mac.mm_ip.mip_ip);
      break;
    case MATCH_TYPE_MASK_DST_IP_MAC:
      mac_address_copy (&ah.ip4_over_ethernet[ARP_TARGET].mac,
			&mr->mr_mask_dst_ip_mac.mm_mac.mmm_mac);
      ah.ip4_over_ethernet[ARP_TARGET].ip4 =
	ip_addr_v4 (&mr->mr_mask_dst_ip_mac.mm_ip.mip_ip);
      break;
    default:
      return;
    }

  eh->type = clib_host_to_net_u16 (ETHERNET_TYPE_ARP);

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    {
      clib_memcpy (eh + 1, &ah, sizeof (ah));

      match_classifier_mk_session (mcmcd->mcmcd_set_indices[0],
				   match, mr->mr_index);
    }
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    {
      ethernet_vlan_header_t *ev = (ethernet_vlan_header_t *) (eh + 1);

      clib_memset (ev, 0, sizeof (*ev));
      eh->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      ev->type = clib_host_to_net_u16 (ETHERNET_TYPE_ARP);

      clib_memcpy (ev + 1, &ah, sizeof (ah));

      match_classifier_mk_session (mcmcd->mcmcd_set_indices[1],
				   match, mr->mr_index);
    }
  if (flags & MATCH_SET_TAG_FLAG_2_TAG)
    {
      ethernet_vlan_header_t *evi, *evo = (ethernet_vlan_header_t *) (eh + 1);

      evi = (evo + 1);
      clib_memset (evi, 0, sizeof (*evi));
      clib_memset (evo, 0, sizeof (*evo));

      eh->type = clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD);
      evi->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      evo->type = clib_host_to_net_u16 (ETHERNET_TYPE_ARP);

      clib_memcpy (evi + 1, &ah, sizeof (ah));

      match_classifier_mk_session (mcmcd->mcmcd_set_indices[2],
				   match, mr->mr_index);
    }
}

static void
match_classifier_mk_ip4_hdr (const match_rule_t * mr,
			     ip4_header_t * iph, ethernet_header_t * eh)
{
  switch (mr->mr_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      mac_address_to_bytes (&mr->mr_mask_src_ip_mac.mm_mac.mmm_mac,
			    eh->src_address);
      iph->src_address = ip_addr_v4 (&mr->mr_mask_src_ip_mac.mm_ip.mip_ip);
      break;
    case MATCH_TYPE_MASK_DST_IP_MAC:
      mac_address_to_bytes (&mr->mr_mask_src_ip_mac.mm_mac.mmm_mac,
			    eh->dst_address);
      iph->dst_address = ip_addr_v4 (&mr->mr_mask_dst_ip_mac.mm_ip.mip_ip);
      break;
    default:
      return;
    }
}

static void
match_classifier_mk_ip4_sessions (const match_rule_t * mr,
				  const match_classifier_mask_class_data_t *
				  mcmcd, match_set_tag_flags_t flags)
{
  match_classifier_ip_tag_t h;

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip4_0_tag, sizeof (h));
      match_classifier_mk_ip4_hdr (mr, &h.t0.ip4, &h.t0.eh);
      match_classifier_mk_session (mcmcd->mcmcd_set_indices[0],
				   &h, mr->mr_index);
    }
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip4_1_tag, sizeof (h));
      match_classifier_mk_ip4_hdr (mr, &h.t1.ip4, &h.t1.eh);
      match_classifier_mk_session (mcmcd->mcmcd_set_indices[1],
				   &h, mr->mr_index);
    }
  if (flags & MATCH_SET_TAG_FLAG_2_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip4_2_tag, sizeof (h));
      match_classifier_mk_ip4_hdr (mr, &h.t2.ip4, &h.t2.eh);
      match_classifier_mk_session (mcmcd->mcmcd_set_indices[2],
				   &h, mr->mr_index);
    }
}

static void
match_classifier_mk_ip6_hdr (const match_rule_t * mr,
			     ip6_header_t * iph, ethernet_header_t * eh)
{
  switch (mr->mr_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      mac_address_to_bytes (&mr->mr_mask_src_ip_mac.mm_mac.mmm_mac,
			    eh->src_address);
      iph->src_address = ip_addr_v6 (&mr->mr_mask_src_ip_mac.mm_ip.mip_ip);
      break;
    case MATCH_TYPE_MASK_DST_IP_MAC:
      mac_address_to_bytes (&mr->mr_mask_src_ip_mac.mm_mac.mmm_mac,
			    eh->dst_address);
      iph->dst_address = ip_addr_v6 (&mr->mr_mask_dst_ip_mac.mm_ip.mip_ip);
      break;
    default:
      return;
    }
}

static void
match_classifier_mk_ip6_sessions (const match_rule_t * mr,
				  const match_classifier_mask_class_data_t *
				  mcmcd, match_set_tag_flags_t flags)
{
  match_classifier_ip_tag_t h;

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip6_0_tag, sizeof (h));
      match_classifier_mk_ip6_hdr (mr, &h.t0.ip6, &h.t0.eh);
      match_classifier_mk_session (mcmcd->mcmcd_set_indices[0],
				   &h, mr->mr_index);
    }
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip6_1_tag, sizeof (h));
      match_classifier_mk_ip6_hdr (mr, &h.t1.ip6, &h.t1.eh);
      match_classifier_mk_session (mcmcd->mcmcd_set_indices[1],
				   &h, mr->mr_index);
    }
  if (flags & MATCH_SET_TAG_FLAG_2_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip6_2_tag, sizeof (h));
      match_classifier_mk_ip6_hdr (mr, &h.t2.ip6, &h.t2.eh);
      match_classifier_mk_session (mcmcd->mcmcd_set_indices[2],
				   &h, mr->mr_index);
    }
}

static void
match_classifier_mk_sessions (const match_rule_t * mr,
			      const match_classifier_mask_class_data_t *
			      mcmcd, match_set_tag_flags_t flags)
{
  switch (mr->mr_proto)
    {
    case ETHERNET_TYPE_ARP:
      return (match_classifier_mk_arp_sessions (mr, mcmcd, flags));
    case ETHERNET_TYPE_IP4:
      return (match_classifier_mk_ip4_sessions (mr, mcmcd, flags));
    case ETHERNET_TYPE_IP6:
      return (match_classifier_mk_ip6_sessions (mr, mcmcd, flags));
    default:
      ASSERT (0);
      break;
    }
}

static walk_rc_t
match_classifier_mk_session_walk_rules (const match_rule_t * mr, void *data)
{
  match_classifier_ctx_t *ctx = data;
  match_classifier_mask_class_t mask;
  uword *p;

  mask = match_classifier_rule_mk_mask (mr);

  p = hash_get (ctx->masks, &mask);

  if (!p)
    {
      return (WALK_CONTINUE);
    }

  match_classifier_mk_sessions
    (mr,
     pool_elt_at_index (match_classifier_mask_class_data_pool, p[0]),
     ctx->flags);

  return (WALK_CONTINUE);
}

static walk_rc_t
match_classifier_mk_session_walk_entries (const match_set_entry_t *
					  mse, void *data)
{
  match_set_entry_walk_rules (mse,
			      match_classifier_mk_session_walk_rules, data);

  return (WALK_CONTINUE);
}

/**
 * Large priority is better => earlier match
 */
static i8 match_classifier_proto_prio_set[0xffff] = {
  [ETHERNET_TYPE_ARP] = 10,
  [ETHERNET_TYPE_IP4] = 20,
  [ETHERNET_TYPE_IP6] = 30,
};

static i8 match_classifier_type_prio_set[MATCH_N_TYPES] = {
  [MATCH_TYPE_EXACT_SRC_IP_MAC] = 50,
  [MATCH_TYPE_MASK_SRC_IP_MAC] = 30,
  [MATCH_TYPE_MASK_DST_IP_MAC] = 30,
};

static int
match_classifier_mask_sort (void *s1, void *s2)
{
  const match_classifier_mask_class_t *m1 = s1, *m2 = s2;

  if (m1->mcmc_proto == m2->mcmc_proto)
    {
      if (m1->mcmc_type == m2->mcmc_type)
	{
	  switch (m1->mcmc_type)
	    {
	    case MATCH_TYPE_MASK_SRC_IP_MAC:
	    case MATCH_TYPE_MASK_DST_IP_MAC:
	      if (m1->mcmc_ip != m2->mcmc_ip)
		return (m1->mcmc_ip - m2->mcmc_ip);
	      return (mac_address_n_bits_set (&m1->mcmc_mac) -
		      mac_address_n_bits_set (&m2->mcmc_mac));
	    case MATCH_TYPE_EXACT_SRC_IP_MAC:
	      break;
	    }
	}
      else
	return (match_classifier_type_prio_set[m1->mcmc_type] -
		match_classifier_type_prio_set[m2->mcmc_type]);
    }
  else
    return (match_classifier_proto_prio_set[m1->mcmc_proto] -
	    match_classifier_proto_prio_set[m2->mcmc_proto]);
  return (0);
}

/**
 * Use the classifier sets to render the masek src IP and MAC match
 */
static void
match_classifier_apply_mask_src_ip_mac_i (match_set_t * ms,
					  vnet_link_t linkt,
					  match_set_tag_flags_t flags,
					  match_engine_classifier_t * ectx)
{
  /* first create the types of classifier sets that needed for each of the
   * rules.
   * we need a set for each combination of protocol, ip-mask-len and
   *  mac-mask-len */
  match_classifier_ctx_t ctx = {
    .linkt = linkt,
    .masks = hash_create_mem (0, sizeof (match_classifier_mask_class_t),
			      sizeof (u32)),
    .flags = flags,
  };

  /* collect the set of masks both in a hash set and vector */
  match_set_walk_entries (ms, match_classifier_mk_table_walk_entries, &ctx);

  /* sort the vector.
   * the set of classifier sets created will be in a chain, a miss in the
   * (n)th  set results in a lookup in the (n+1)th. So we want to sort the
   * sets in a way that reduces the number of lookups.
   * One obvious strategy is to place the ARP sets last, ARP is much lower
   * volume, so we first sort by protocol.
   * next, for correctness, longest prefix matches are required to support
   * FIRST match semantics (ANY sematics could order the sets differently).
   * We might argue that short mask matches are more common than longer mask
   * matches, because it covers more addresses, but the reality is that the
   * most common match will occur from the most chatty hosts on the link, and
   * we can't know those in advance.
   */
  vec_sort_with_function (ctx.mask_vec, match_classifier_mask_sort);

  /* The set are created in the reverse or to that which they are searched */
  const match_classifier_mask_class_t *mask;
  u32 next_table_index = ~0;

  vec_foreach (mask, ctx.mask_vec)
  {
    match_classifier_mask_class_data_t *mcmcd;

    pool_get_zero (match_classifier_mask_class_data_pool, mcmcd);

    match_classifier_mask_class_data_init (mcmcd);

    next_table_index = match_classifier_mk_tables (mask,
						   next_table_index,
						   ctx.flags, linkt, mcmcd);
    hash_set_mem_alloc (&ctx.masks, mask,
			mcmcd - match_classifier_mask_class_data_pool);
  }

  /* for each rule add a session to the appropriate classifier set */
  match_set_walk_entries (ms, match_classifier_mk_session_walk_entries, &ctx);


  ectx->mec_hash = ctx.masks;
  ectx->mec_table_index = next_table_index;
  // FIXME
  ectx->mec_usr_ctx = ctx.usr_ctx;

  vec_free (ctx.mask_vec);
}

static match_set_app_t
match_classifier_apply_mask_src_ip_mac (match_set_t * ms,
					vnet_link_t linkt,
					match_set_tag_flags_t flags)
{
  match_engine_classifier_t *ectx;

  pool_get (match_engine_classifier_pool, ectx);

  match_classifier_apply_mask_src_ip_mac_i (ms, linkt, flags, ectx);

  return (ectx - match_engine_classifier_pool);
}

static void
match_classifier_ctx_teardown (match_engine_classifier_t * ectx)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  match_classifier_mask_class_data_t *mcmcd;
  match_classifier_mask_class_t *mcmc;
  index_t mcmcdi;
  u32 ii;

  /*
   * deleting the classifier tables will free all its sessions
   */
  /* *INDENT-OFF* */
  hash_foreach (mcmc, mcmcdi, ectx->mec_hash,
  ({
    mcmcd = pool_elt_at_index(match_classifier_mask_class_data_pool, mcmcdi);

    for (ii = 0; ii < ARRAY_LEN(mcmcd->mcmcd_set_indices); ii++) {
      if (mcmcd->mcmcd_set_indices[ii] != ~0)
        vnet_classify_delete_table_index (cm, mcmcd->mcmcd_set_indices[ii], 0);
    }
  }));
  /* *INDENT-ON* */

  hash_free (ectx->mec_hash);
}


static void
match_classifier_unapply_mask_src_ip_mac (match_set_t * ms,
					  match_set_app_t mb)
{
  match_engine_classifier_t *ectx;

  ectx = pool_elt_at_index (match_engine_classifier_pool, mb);

  match_classifier_ctx_teardown (ectx);

  pool_put (match_engine_classifier_pool, ectx);
}

static void
match_classifier_update_mask_src_ip_mac (match_set_t * ms,
					 match_set_app_t msa,
					 vnet_link_t linkt,
					 match_set_tag_flags_t flags)
{
  /* nothing clever here. destroy all state and start again */
  match_engine_classifier_t *ectx;

  ectx = pool_elt_at_index (match_engine_classifier_pool, msa);

  match_classifier_ctx_teardown (ectx);
  match_classifier_apply_mask_src_ip_mac_i (ms, linkt, flags, ectx);
}

static u8 *
format_match_classifier (u8 * s, va_list * args)
{
  match_engine_classifier_t *ectx;
  match_classifier_mask_class_data_t *mcmcd;
  match_classifier_mask_class_t *mcmc;
  match_set_app_t mb;
  index_t mcmcdi;
  u32 ii, indent;

  mb = va_arg (*args, match_set_app_t);
  indent = va_arg (*args, u32);

  ectx = pool_elt_at_index (match_engine_classifier_pool, mb);

  /* *INDENT-OFF* */
  hash_foreach (mcmc, mcmcdi, ectx->mec_hash,
  ({
    mcmcd = pool_elt_at_index(match_classifier_mask_class_data_pool, mcmcdi);

    for (ii = 0; ii < ARRAY_LEN(mcmcd->mcmcd_set_indices); ii++) {
      if (mcmcd->mcmcd_set_indices[ii] != ~0)
        s = format (s, "%U%U",
                    format_white_space, indent,
                    format_vnet_classify_table, &vnet_classify_main, 1,
                    mcmcd->mcmcd_set_indices[ii]);
    }
  }));
  /* *INDENT-ON* */

  return (s);
}

const static match_engine_vft_t mc_vft = {
  .mev_apply = match_classifier_apply_mask_src_ip_mac,
  .mev_update = match_classifier_update_mask_src_ip_mac,
  .mev_unapply = match_classifier_unapply_mask_src_ip_mac,
  .mev_format = format_match_classifier,
  .mev_match = match_engine_classifier_match,
};

static clib_error_t *
match_classifier_init (vlib_main_t * vm)
{
  match_engine_register (MATCH_TYPE_MASK_SRC_IP_MAC,
			 MATCH_SEMANTIC_ANY, &mc_vft);

  return (NULL);
}

VLIB_INIT_FUNCTION (match_classifier_init) =
{
.runs_after = VLIB_INITS ("match_init"),};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
