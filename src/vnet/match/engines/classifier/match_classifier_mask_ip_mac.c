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
#include <vnet/match/engines/classifier/match_classifier_mask_ip_mac.h>
#include <vnet/match/engines/classifier/match_classifier_mask_ip_mac_dp.h>

#include <vnet/ethernet/arp_packet.h>
#include <vnet/ip/ip.h>

/**
 * A mask 'class' requires its own classifier set
 */
typedef struct match_classifier_mask_class_key_t_
{
  mac_address_t mcmck_mac;
  u8 mcmck_ip;
  match_type_t mcmck_type;
  ethernet_type_t mcmck_proto;
} match_classifier_mask_class_key_t;

/**
 * The data 'installed' in the classifier for each class
 */
typedef struct match_classifier_mask_class_t_
{
  /** vnet-classifier table index for each number of VLAN tags */
  u32 mcmc_table_indices[3];
} match_classifier_mask_class_t;

static match_classifier_mask_class_t *match_classifier_mask_class_pool;

match_engine_classifier_t *match_engine_classifier_pool;

static void
match_classifier_mask_class_data_init (match_classifier_mask_class_t * mcmc)
{
  u32 i;
  for (i = 0; i <= 2; i++)
    mcmc->mcmc_table_indices[i] = INDEX_INVALID;
}

static u32
match_classifier_mk_arp_tables (const match_classifier_mask_class_key_t *
				mcmck, match_orientation_t mo,
				u32 table_index, match_set_tag_flags_t flags,
				vnet_link_t linkt,
				match_classifier_mask_class_t * mcmc)
{
  ethernet_arp_header_t ah = { };
  u8 who;
  u8 mask[5 * 16];

  clib_memset (mask, 0, sizeof (mask));

  who = (MATCH_SRC == mo ? ARP_SENDER : ARP_TARGET);

  mac_address_copy (&ah.ip4_over_ethernet[who].mac, &mcmck->mcmck_mac);
  ip4_preflen_to_mask (mcmck->mcmck_ip, &ah.ip4_over_ethernet[who].ip4);

  ethernet_header_t *eh = (ethernet_header_t *) mask;

  eh->type = 0xffff;

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    {
      clib_memcpy (eh + 1, &ah, sizeof (ah));

      mcmc->mcmc_table_indices[0] =
	table_index =
	match_classifier_mk_table (mask,
				   sizeof (*eh) + sizeof (ah),
				   ~0,
				   table_index,
				   CLASSIFY_FLAG_USE_CURR_DATA,
				   match_set_get_l2_offset (linkt,
							    MATCH_SET_TAG_FLAG_0_TAG),
				   0);
    }
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    {
      ethernet_vlan_header_t *ev = (ethernet_vlan_header_t *) (eh + 1);

      clib_memset (ev, 0, sizeof (*ev));
      ev->type = 0xffff;

      clib_memcpy (ev + 1, &ah, sizeof (ah));

      mcmc->mcmc_table_indices[1] =
	table_index =
	match_classifier_mk_table (mask,
				   sizeof (*eh) + sizeof (*ev) + sizeof (ah),
				   ~0,
				   table_index,
				   CLASSIFY_FLAG_USE_CURR_DATA,
				   match_set_get_l2_offset (linkt,
							    MATCH_SET_TAG_FLAG_1_TAG),
				   0);
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

      mcmc->mcmc_table_indices[2] =
	table_index =
	match_classifier_mk_table (mask,
				   sizeof (*eh) + 2 * sizeof (*evo) +
				   sizeof (ah), ~0, table_index,
				   CLASSIFY_FLAG_USE_CURR_DATA,
				   match_set_get_l2_offset (linkt,
							    MATCH_SET_TAG_FLAG_2_TAG),
				   0);
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
    .eh = {
      // clib_host_to_net_u16(ETHERNET_TYPE_DOT1AD)
      .type = 0xa888,
    },
    .evi = {
      // clib_host_to_net_u16(ETHERNET_TYPE_IP4)
      .type = 0x0008,
    },
    .evo = {
      // clib_host_to_net_u16(ETHERNET_TYPE_VLAN)
      .type = 0x0081,
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
match_classifier_mk_ip4_hdr_mask (const match_classifier_mask_class_key_t *
				  mcmck, match_orientation_t mo,
				  ip4_header_t * ip, ethernet_header_t * eh)
{
  switch (mcmck->mcmck_type)
    {
    case MATCH_TYPE_MASK_IP_MAC:
      if (MATCH_SRC == mo)
	{
	  ip4_preflen_to_mask (mcmck->mcmck_ip, &ip->src_address);
	  mac_address_to_bytes (&mcmck->mcmck_mac, eh->src_address);
	}
      else
	{
	  ip4_preflen_to_mask (mcmck->mcmck_ip, &ip->dst_address);
	  mac_address_to_bytes (&mcmck->mcmck_mac, eh->dst_address);
	}
      break;
    default:
      break;
    }
}

static void
match_classifier_mk_ip6_hdr_mask (const match_classifier_mask_class_key_t *
				  mcmck, match_orientation_t mo,
				  ip6_header_t * ip, ethernet_header_t * eh)
{
  switch (mcmck->mcmck_type)
    {
    case MATCH_TYPE_MASK_IP_MAC:
      if (MATCH_SRC == mo)
	{
	  ip6_preflen_to_mask (mcmck->mcmck_ip, &ip->src_address);
	  mac_address_to_bytes (&mcmck->mcmck_mac, eh->src_address);
	}
      else
	{
	  ip6_preflen_to_mask (mcmck->mcmck_ip, &ip->dst_address);
	  mac_address_to_bytes (&mcmck->mcmck_mac, eh->dst_address);
	}
      break;
    default:
      break;
    }
}

#define MATCH_CLASSIFIER_MK_IP4_TBL(_h, _s, _o, _template, _i, _f)      \
{                                                                       \
  clib_memcpy (&(_h), (_template), sizeof ((_h)));                      \
                                                                        \
  match_classifier_mk_ip4_hdr_mask (mcmck, _o, &_h._s.ip4, &_h._s.eh);  \
                                                                        \
  mcmc->mcmc_table_indices[_i] =                                        \
    table_index =                                                       \
    match_classifier_mk_table ((u8*) &h,                                \
                               sizeof (h),                              \
                               ~0,                                      \
                               table_index,                             \
                               CLASSIFY_FLAG_USE_CURR_DATA,             \
                               match_set_get_l2_offset (linkt, _f),     \
                               0);                                      \
}

#define MATCH_CLASSIFIER_MK_IP6_TBL(_h, _s, _o, _template, _i, _f)      \
{                                                                       \
  clib_memcpy (&(_h), (_template), sizeof ((_h)));                      \
                                                                        \
  match_classifier_mk_ip6_hdr_mask (mcmck, _o, &_h._s.ip6, &_h._s.eh);  \
                                                                        \
  mcmc->mcmc_table_indices[_i] =                                        \
    table_index =                                                       \
    match_classifier_mk_table (&h, sizeof (h),                          \
                               ~0, table_index,                         \
                               CLASSIFY_FLAG_USE_CURR_DATA,             \
                               match_set_get_l2_offset (linkt, _f),     \
                               0);                                      \
}

static u32
match_classifier_mk_ip4_tables (const match_classifier_mask_class_key_t *
				mcmck, match_orientation_t mo,
				u32 table_index, match_set_tag_flags_t flags,
				vnet_link_t linkt,
				match_classifier_mask_class_t * mcmc)
{
  match_classifier_ip_tag_t h;

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    MATCH_CLASSIFIER_MK_IP4_TBL (h, t0, mo, &match_classifier_mask_ip_0_tag,
				 0, MATCH_SET_TAG_FLAG_0_TAG);
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    MATCH_CLASSIFIER_MK_IP4_TBL (h, t1, mo, &match_classifier_mask_ip_1_tag,
				 1, MATCH_SET_TAG_FLAG_1_TAG);
  if (flags & MATCH_SET_TAG_FLAG_2_TAG)
    MATCH_CLASSIFIER_MK_IP4_TBL (h, t2, mo, &match_classifier_mask_ip_2_tag,
				 2, MATCH_SET_TAG_FLAG_2_TAG);

  return (table_index);
}

static u32
match_classifier_mk_ip6_tables (const match_classifier_mask_class_key_t *
				mcmck, match_orientation_t mo,
				u32 table_index, match_set_tag_flags_t flags,
				vnet_link_t linkt,
				match_classifier_mask_class_t * mcmc)
{
  match_classifier_ip_tag_t h;

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    MATCH_CLASSIFIER_MK_IP6_TBL (h, t0, mo, &match_classifier_mask_ip_0_tag,
				 0, MATCH_SET_TAG_FLAG_0_TAG);
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    MATCH_CLASSIFIER_MK_IP6_TBL (h, t1, mo, &match_classifier_mask_ip_1_tag,
				 1, MATCH_SET_TAG_FLAG_1_TAG);
  if (flags & MATCH_SET_TAG_FLAG_2_TAG)
    MATCH_CLASSIFIER_MK_IP6_TBL (h, t2, mo, &match_classifier_mask_ip_2_tag,
				 2, MATCH_SET_TAG_FLAG_2_TAG);

  return (table_index);
}

static u32
match_classifier_mk_tables (const match_classifier_mask_class_key_t * mcmck,
			    match_orientation_t mo,
			    u32 table_index,
			    match_set_tag_flags_t flags,
			    vnet_link_t linkt,
			    match_classifier_mask_class_t * mcmc)
{
  switch (mcmck->mcmck_proto)
    {
    case ETHERNET_TYPE_ARP:
      return (match_classifier_mk_arp_tables (mcmck, mo, table_index, flags,
					      linkt, mcmc));
    case ETHERNET_TYPE_IP4:
      return (match_classifier_mk_ip4_tables (mcmck, mo, table_index, flags,
					      linkt, mcmc));
    case ETHERNET_TYPE_IP6:
      return (match_classifier_mk_ip6_tables (mcmck, mo, table_index, flags,
					      linkt, mcmc));
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
  match_classifier_mask_class_key_t *mask_vec;
} match_classifier_ctx_t;

static match_classifier_mask_class_key_t
match_classifier_rule_mk_mask (const match_rule_t * mr)
{
  match_classifier_mask_class_key_t mcmck = {
    .mcmck_proto = mr->mr_proto,
    .mcmck_type = mr->mr_type,
  };

  switch (mr->mr_type)
    {
    case MATCH_TYPE_MASK_IP_MAC:
      mac_address_copy (&mcmck.mcmck_mac,
			&mr->mr_mask_ip_mac.mmim_mac.mmm_mask);
      mcmck.mcmck_ip = mr->mr_mask_ip_mac.mmim_ip.mip_ip.len;
      break;
    case MATCH_TYPE_MASK_IP:
    case MATCH_TYPE_EXACT_IP_L4:
    case MATCH_TYPE_EXACT_IP:
    case MATCH_TYPE_MASK_N_TUPLE:
    case MATCH_TYPE_SETS:
      ASSERT (!"unsupported");
    }

  return (mcmck);
}

static walk_rc_t
match_classifier_mk_table_walk_rules (const match_rule_t * mr, void *data)
{
  match_classifier_ctx_t *ctx = data;
  match_classifier_mask_class_key_t mask;
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
					u32 index, void *data)
{
  match_classifier_ctx_t *ctx = data;

  ctx->usr_ctx = mse->mse_usr_ctxt;

  match_set_entry_walk_rules (mse,
			      match_classifier_mk_table_walk_rules, data);

  return (WALK_CONTINUE);
}

static void
match_classifier_mk_arp_sessions (const match_rule_t * mr,
				  const match_classifier_mask_class_t *
				  mcmc, match_set_tag_flags_t flags)
{
  ethernet_arp_header_t ah = { };
  ethernet_header_t *eh;
  u8 who, match[5 * 16];

  eh = (ethernet_header_t *) match;
  who = (MATCH_SRC == mr->mr_orientation ? ARP_SENDER : ARP_TARGET);

  switch (mr->mr_type)
    {
    case MATCH_TYPE_MASK_IP_MAC:
      mac_address_copy (&ah.ip4_over_ethernet[who].mac,
			&mr->mr_mask_ip_mac.mmim_mac.mmm_mac);
      ah.ip4_over_ethernet[who].ip4 =
	ip_addr_v4 (&mr->mr_mask_ip_mac.mmim_ip.mip_ip.addr);
      break;
    default:
      return;
    }

  eh->type = clib_host_to_net_u16 (ETHERNET_TYPE_ARP);

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    {
      clib_memcpy (eh + 1, &ah, sizeof (ah));

      match_classifier_mk_session (mcmc->mcmc_table_indices[0],
				   match, mr->mr_index, ~0);
    }
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    {
      ethernet_vlan_header_t *ev = (ethernet_vlan_header_t *) (eh + 1);

      clib_memset (ev, 0, sizeof (*ev));
      eh->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      ev->type = clib_host_to_net_u16 (ETHERNET_TYPE_ARP);

      clib_memcpy (ev + 1, &ah, sizeof (ah));

      match_classifier_mk_session (mcmc->mcmc_table_indices[1],
				   match, mr->mr_index, ~0);
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

      match_classifier_mk_session (mcmc->mcmc_table_indices[2],
				   match, mr->mr_index, ~0);
    }
}

static void
match_classifier_mk_ip4_hdr (const match_rule_t * mr,
			     ip4_header_t * iph, ethernet_header_t * eh)
{
  switch (mr->mr_type)
    {
    case MATCH_TYPE_MASK_IP_MAC:
      if (MATCH_SRC == mr->mr_orientation)
	{
	  mac_address_to_bytes (&mr->mr_mask_ip_mac.mmim_mac.mmm_mac,
				eh->src_address);
	  iph->src_address =
	    ip_addr_v4 (&mr->mr_mask_ip_mac.mmim_ip.mip_ip.addr);
	}
      else
	{
	  mac_address_to_bytes (&mr->mr_mask_ip_mac.mmim_mac.mmm_mac,
				eh->dst_address);
	  iph->dst_address =
	    ip_addr_v4 (&mr->mr_mask_ip_mac.mmim_ip.mip_ip.addr);
	}
      break;
    default:
      return;
    }
}

static void
match_classifier_mk_ip4_sessions (const match_rule_t * mr,
				  const match_classifier_mask_class_t *
				  mcmc, match_set_tag_flags_t flags)
{
  match_classifier_ip_tag_t h;

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip4_0_tag, sizeof (h));
      match_classifier_mk_ip4_hdr (mr, &h.t0.ip4, &h.t0.eh);
      match_classifier_mk_session (mcmc->mcmc_table_indices[0],
				   &h, mr->mr_index, ~0);
    }
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip4_1_tag, sizeof (h));
      match_classifier_mk_ip4_hdr (mr, &h.t1.ip4, &h.t1.eh);
      match_classifier_mk_session (mcmc->mcmc_table_indices[1],
				   &h, mr->mr_index, ~0);
    }
  if (flags & MATCH_SET_TAG_FLAG_2_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip4_2_tag, sizeof (h));
      match_classifier_mk_ip4_hdr (mr, &h.t2.ip4, &h.t2.eh);
      match_classifier_mk_session (mcmc->mcmc_table_indices[2],
				   &h, mr->mr_index, ~0);
    }
}

static void
match_classifier_mk_ip6_hdr (const match_rule_t * mr,
			     ip6_header_t * iph, ethernet_header_t * eh)
{
  switch (mr->mr_type)
    {
    case MATCH_TYPE_MASK_IP_MAC:
      if (MATCH_SRC == mr->mr_orientation)
	{
	  mac_address_to_bytes (&mr->mr_mask_ip_mac.mmim_mac.mmm_mac,
				eh->src_address);
	  iph->src_address =
	    ip_addr_v6 (&mr->mr_mask_ip_mac.mmim_ip.mip_ip.addr);
	}
      else
	{
	  mac_address_to_bytes (&mr->mr_mask_ip_mac.mmim_mac.mmm_mac,
				eh->dst_address);
	  iph->dst_address =
	    ip_addr_v6 (&mr->mr_mask_ip_mac.mmim_ip.mip_ip.addr);
	}
      break;
    default:
      return;
    }
}

static void
match_classifier_mk_ip6_sessions (const match_rule_t * mr,
				  const match_classifier_mask_class_t *
				  mcmc, match_set_tag_flags_t flags)
{
  match_classifier_ip_tag_t h;

  if (flags & MATCH_SET_TAG_FLAG_0_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip6_0_tag, sizeof (h));
      match_classifier_mk_ip6_hdr (mr, &h.t0.ip6, &h.t0.eh);
      match_classifier_mk_session (mcmc->mcmc_table_indices[0],
				   &h, mr->mr_index, ~0);
    }
  if (flags & MATCH_SET_TAG_FLAG_1_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip6_1_tag, sizeof (h));
      match_classifier_mk_ip6_hdr (mr, &h.t1.ip6, &h.t1.eh);
      match_classifier_mk_session (mcmc->mcmc_table_indices[1],
				   &h, mr->mr_index, ~0);
    }
  if (flags & MATCH_SET_TAG_FLAG_2_TAG)
    {
      clib_memcpy (&h, &match_classifier_ip6_2_tag, sizeof (h));
      match_classifier_mk_ip6_hdr (mr, &h.t2.ip6, &h.t2.eh);
      match_classifier_mk_session (mcmc->mcmc_table_indices[2],
				   &h, mr->mr_index, ~0);
    }
}

static void
match_classifier_mk_sessions (const match_rule_t * mr,
			      const match_classifier_mask_class_t *
			      mcmc, match_set_tag_flags_t flags)
{
  switch (mr->mr_proto)
    {
    case ETHERNET_TYPE_ARP:
      return (match_classifier_mk_arp_sessions (mr, mcmc, flags));
    case ETHERNET_TYPE_IP4:
      return (match_classifier_mk_ip4_sessions (mr, mcmc, flags));
    case ETHERNET_TYPE_IP6:
      return (match_classifier_mk_ip6_sessions (mr, mcmc, flags));
    default:
      ASSERT (0);
      break;
    }
}

static walk_rc_t
match_classifier_mk_session_walk_rules (const match_rule_t * mr, void *data)
{
  match_classifier_ctx_t *ctx = data;
  match_classifier_mask_class_key_t mask;
  uword *p;

  mask = match_classifier_rule_mk_mask (mr);

  p = hash_get (ctx->masks, &mask);

  if (!p)
    {
      return (WALK_CONTINUE);
    }

  match_classifier_mk_sessions
    (mr,
     pool_elt_at_index (match_classifier_mask_class_pool, p[0]), ctx->flags);

  return (WALK_CONTINUE);
}

static walk_rc_t
match_classifier_mk_session_walk_entries (const match_set_entry_t * mse,
					  u32 index, void *data)
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
  [MATCH_TYPE_MASK_IP_MAC] = 30,
};

static int
match_classifier_mask_sort (void *s1, void *s2)
{
  const match_classifier_mask_class_key_t *m1 = s1, *m2 = s2;

  if (m1->mcmck_proto == m2->mcmck_proto)
    {
      if (m1->mcmck_type == m2->mcmck_type)
	{
	  switch (m1->mcmck_type)
	    {
	    case MATCH_TYPE_MASK_IP_MAC:
	      if (m1->mcmck_ip != m2->mcmck_ip)
		return (m1->mcmck_ip - m2->mcmck_ip);
	      return (mac_address_n_bits_set (&m1->mcmck_mac) -
		      mac_address_n_bits_set (&m2->mcmck_mac));
	    case MATCH_TYPE_MASK_N_TUPLE:
	    case MATCH_TYPE_MASK_IP:
	    case MATCH_TYPE_EXACT_IP:
	    case MATCH_TYPE_EXACT_IP_L4:
	    case MATCH_TYPE_SETS:
	      ASSERT (!"unsupported");
	      break;
	    }
	}
      else
	return (match_classifier_type_prio_set[m1->mcmck_type] -
		match_classifier_type_prio_set[m2->mcmck_type]);
    }
  else
    return (match_classifier_proto_prio_set[m1->mcmck_proto] -
	    match_classifier_proto_prio_set[m2->mcmck_proto]);
  return (0);
}

/**
 * Use the classifier sets to render the masek src IP and MAC match
 */
static void
match_classifier_apply_mask_src_ip_mac_i (match_set_t * ms,
					  match_engine_classifier_t * mec)
{
  /* first create the types of classifier sets that needed for each of the
   * rules.
   * we need a set for each combination of protocol, ip-mask-len and
   *  mac-mask-len */
  match_classifier_ctx_t ctx = {
    .linkt = mec->mec_linkt,
    .masks = hash_create_mem (0, sizeof (match_classifier_mask_class_key_t),
			      sizeof (u32)),
    .flags = mec->mec_flags,
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
  const match_classifier_mask_class_key_t *mask;
  u32 next_table_index = ~0;

  vec_foreach (mask, ctx.mask_vec)
  {
    match_classifier_mask_class_t *mcmc;

    pool_get_zero (match_classifier_mask_class_pool, mcmc);

    match_classifier_mask_class_data_init (mcmc);

    next_table_index = match_classifier_mk_tables (mask,
						   ms->ms_orientation,
						   next_table_index,
						   ctx.flags,
						   mec->mec_linkt, mcmc);
    hash_set_mem_alloc (&ctx.masks, mask,
			mcmc - match_classifier_mask_class_pool);
  }

  /* for each rule add a session to the appropriate classifier set */
  match_set_walk_entries (ms, match_classifier_mk_session_walk_entries, &ctx);


  mec->mec_hash = ctx.masks;
  mec->mec_table_index = next_table_index;
  // FIXME
  mec->mec_usr_ctx = ctx.usr_ctx;

  vec_free (ctx.mask_vec);
}

static void
match_classifier_apply_mask_src_ip_mac (match_set_t * ms,
					match_semantic_t semantic,
					vnet_link_t linkt,
					match_set_tag_flags_t flags,
					match_set_app_t * msa)
{
  match_engine_classifier_t *mec;

  pool_get (match_engine_classifier_pool, mec);

  mec->mec_semantic = semantic;
  mec->mec_linkt = linkt;
  mec->mec_flags = flags;

  match_classifier_apply_mask_src_ip_mac_i (ms, mec);

  msa->msa_index = (mec - match_engine_classifier_pool);
  msa->msa_match = (semantic == MATCH_SEMANTIC_ANY ?
		    match_engine_classifier_match_mask_src_ip_mac_any :
		    match_engine_classifier_match_mask_src_ip_mac_first);
}

static void
match_classifier_ctx_teardown (match_engine_classifier_t * mec)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  match_classifier_mask_class_t *mcmc;
  match_classifier_mask_class_key_t *mcmck;
  index_t mcmci;
  u32 ii;

  /*
   * deleting the classifier tables will free all its sessions
   */
  /* *INDENT-OFF* */
  hash_foreach (mcmck, mcmci, mec->mec_hash,
  ({
    mcmc = pool_elt_at_index(match_classifier_mask_class_pool, mcmci);

    for (ii = 0; ii < ARRAY_LEN(mcmc->mcmc_table_indices); ii++) {
      if (mcmc->mcmc_table_indices[ii] != ~0)
        vnet_classify_delete_table_index (cm, mcmc->mcmc_table_indices[ii], 0);
      mcmc->mcmc_table_indices[ii] = ~0;
    }
  }));
  /* *INDENT-ON* */

  hash_free (mec->mec_hash);
}


static void
match_classifier_unapply_mask_src_ip_mac (match_set_t * ms,
					  const match_set_app_t * msa)
{
  match_engine_classifier_t *mec;

  mec = pool_elt_at_index (match_engine_classifier_pool, msa->msa_index);

  match_classifier_ctx_teardown (mec);

  pool_put (match_engine_classifier_pool, mec);
}

static void
match_classifier_update_mask_src_ip_mac (match_set_t * ms,
					 const match_set_app_t * msa)
{
  /* nothing clever here. destroy all state and start again */
  match_engine_classifier_t *mec;

  mec = pool_elt_at_index (match_engine_classifier_pool, msa->msa_index);

  match_classifier_ctx_teardown (mec);
  match_classifier_apply_mask_src_ip_mac_i (ms, mec);
}

static u8 *
format_match_classifier (u8 * s, va_list * args)
{
  match_engine_classifier_t *mec;
  match_classifier_mask_class_t *mcmc;
  match_classifier_mask_class_key_t *mcmck;
  index_t mb, mcmci;
  u32 ii, indent;

  mb = va_arg (*args, index_t);
  indent = va_arg (*args, u32);

  mec = pool_elt_at_index (match_engine_classifier_pool, mb);

  /* *INDENT-OFF* */
  hash_foreach (mcmck, mcmci, mec->mec_hash,
  ({
    mcmc = pool_elt_at_index(match_classifier_mask_class_pool, mcmci);

    for (ii = 0; ii < ARRAY_LEN(mcmc->mcmc_table_indices); ii++) {
      if (mcmc->mcmc_table_indices[ii] != ~0)
        s = format (s, "%U%U",
                    format_white_space, indent,
                    format_vnet_classify_table, &vnet_classify_main, 0,
                    mcmc->mcmc_table_indices[ii]);
    }
  }));
  /* *INDENT-ON* */

  return (s);
}

const static match_engine_vft_t mc_vft_first = {
  .mev_apply = match_classifier_apply_mask_src_ip_mac,
  .mev_update = match_classifier_update_mask_src_ip_mac,
  .mev_unapply = match_classifier_unapply_mask_src_ip_mac,
  .mev_format = format_match_classifier,
};

const static match_engine_vft_t mc_vft_any = {
  .mev_apply = match_classifier_apply_mask_src_ip_mac,
  .mev_update = match_classifier_update_mask_src_ip_mac,
  .mev_unapply = match_classifier_unapply_mask_src_ip_mac,
  .mev_format = format_match_classifier,
};

static clib_error_t *
match_classifier_init (vlib_main_t * vm)
{
  /**
   * The effectiviness of the tuple search algorithm is a function of the number
   * of classes not the number of rules. However, without parsing the rule set
   * before choosing an engine we don't know this. So we'll approxiamte a priority
   * based on the number of rules
   * At a low number of rules, this scheme is rather poor (.r.t. the linear search),
   * so we start poor and get better. the unmbers here are all relatvie to other
   * engines.
   */
  match_engine_priority_t mep, *meps = NULL;

  mep.len = 32;
  mep.prio = 200;
  vec_add1 (meps, mep);

  mep.len = 64;
  mep.prio = 50;
  vec_add1 (meps, mep);

  match_engine_register ("classifier", MATCH_TYPE_MASK_IP_MAC,
			 MATCH_SEMANTIC_ANY, &mc_vft_any, meps);
  match_engine_register ("classifier", MATCH_TYPE_MASK_IP_MAC,
			 MATCH_SEMANTIC_FIRST, &mc_vft_first, meps);

  vec_free (meps);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (match_classifier_init) =
{
  .runs_after = VLIB_INITS ("match_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
