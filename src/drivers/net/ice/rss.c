/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "rss",
};

/* outer and inner IPv4 and IPv6, each without transport and with TCP, UDP and SCTP, and
 * different fields for plain and tunnel classes */
#define ICE_RSS_PROFILE_LIMIT 32

typedef struct
{
  ice_profile_fv_t words[ICE_PROFILE_FV_WORDS];
  u8 pair[ICE_PROFILE_FV_WORDS];
  uword groups[ICE_PROFILE_PTG_COUNT / uword_bits];
  u32 fields;
  u8 ip, transport, n_words;
} ice_rss_profile_plan_t;

typedef struct
{
  ice_rss_profile_plan_t profiles[ICE_RSS_PROFILE_LIMIT];
  u8 n_profiles;
} ice_rss_plan_t;

static const struct
{
  u8 ip, transport;
  vnet_dev_rss_class_t class;
} ice_rss_protocols[] = {
  [ICE_PTYPE_IPV4_FRAG] = { .ip = ICE_PROT_IPV4_OUTER, .class = VNET_DEV_RSS_CLASS_IP4, },
  [ICE_PTYPE_IPV4_PAYLOAD] = { .ip = ICE_PROT_IPV4_OUTER, .class = VNET_DEV_RSS_CLASS_IP4, },
  [ICE_PTYPE_IPV4_UDP] = { .ip = ICE_PROT_IPV4_OUTER, .transport = ICE_PROT_UDP_INNER, .class = VNET_DEV_RSS_CLASS_IP4_UDP, },
  [ICE_PTYPE_IPV4_TCP] = { .ip = ICE_PROT_IPV4_OUTER, .transport = ICE_PROT_TCP_INNER, .class = VNET_DEV_RSS_CLASS_IP4_TCP, },
  [ICE_PTYPE_IPV4_SCTP] = { .ip = ICE_PROT_IPV4_OUTER, .transport = ICE_PROT_SCTP_INNER, .class = VNET_DEV_RSS_CLASS_IP4_SCTP, },
  [ICE_PTYPE_IPV4_ICMP] = { .ip = ICE_PROT_IPV4_OUTER, .class = VNET_DEV_RSS_CLASS_IP4, },
  [ICE_PTYPE_IPV6_FRAG] = { .ip = ICE_PROT_IPV6_OUTER, .class = VNET_DEV_RSS_CLASS_IP6, },
  [ICE_PTYPE_IPV6_PAYLOAD] = { .ip = ICE_PROT_IPV6_OUTER, .class = VNET_DEV_RSS_CLASS_IP6, },
  [ICE_PTYPE_IPV6_UDP] = { .ip = ICE_PROT_IPV6_OUTER, .transport = ICE_PROT_UDP_INNER, .class = VNET_DEV_RSS_CLASS_IP6_UDP, },
  [ICE_PTYPE_IPV6_TCP] = { .ip = ICE_PROT_IPV6_OUTER, .transport = ICE_PROT_TCP_INNER, .class = VNET_DEV_RSS_CLASS_IP6_TCP, },
  [ICE_PTYPE_IPV6_SCTP] = { .ip = ICE_PROT_IPV6_OUTER, .transport = ICE_PROT_SCTP_INNER, .class = VNET_DEV_RSS_CLASS_IP6_SCTP, },
  [ICE_PTYPE_IPV6_ICMP] = { .ip = ICE_PROT_IPV6_OUTER, .class = VNET_DEV_RSS_CLASS_IP6, },
};

/* tunnels are hashed on their outer header with the ipv4 or ipv6 class */
static const struct
{
  u16 first, last;
  u8 ip;
  vnet_dev_rss_class_t class;
} ice_rss_tunnels[] = {
  { ICE_PTYPE_IPV4_TUNNEL_FIRST, ICE_PTYPE_IPV4_TUNNEL_LAST, ICE_PROT_IPV4_OUTER,
    VNET_DEV_RSS_CLASS_IP4 },
  { ICE_PTYPE_IPV6_TUNNEL_FIRST, ICE_PTYPE_IPV6_TUNNEL_LAST, ICE_PROT_IPV6_OUTER,
    VNET_DEV_RSS_CLASS_IP6 },
};

/* tunnel packet types with an inner IP header come in blocks of seven, the offset in the block
 * gives the inner transport; IP-in-IP and GRE with the same inner header share a packet type
 * group, so both are the tunnel class */
static const struct
{
  u16 first;
  u8 outer, inner;
  vnet_dev_rss_class_t class;
} ice_rss_tunnel_blocks[] = {
  { 29, ICE_PROT_IPV4_OUTER, ICE_PROT_IPV4_INNER, VNET_DEV_RSS_CLASS_IP4_IPIP_GRE },
  { 36, ICE_PROT_IPV4_OUTER, ICE_PROT_IPV6_INNER, VNET_DEV_RSS_CLASS_IP4_IPIP_GRE },
  { 44, ICE_PROT_IPV4_OUTER, ICE_PROT_IPV4_INNER, VNET_DEV_RSS_CLASS_IP4_IPIP_GRE },
  { 51, ICE_PROT_IPV4_OUTER, ICE_PROT_IPV6_INNER, VNET_DEV_RSS_CLASS_IP4_IPIP_GRE },
  { 59, ICE_PROT_IPV4_OUTER, ICE_PROT_IPV4_INNER, VNET_DEV_RSS_CLASS_IP4_IPIP_GRE },
  { 66, ICE_PROT_IPV4_OUTER, ICE_PROT_IPV6_INNER, VNET_DEV_RSS_CLASS_IP4_IPIP_GRE },
  { 74, ICE_PROT_IPV4_OUTER, ICE_PROT_IPV4_INNER, VNET_DEV_RSS_CLASS_IP4_IPIP_GRE },
  { 81, ICE_PROT_IPV4_OUTER, ICE_PROT_IPV6_INNER, VNET_DEV_RSS_CLASS_IP4_IPIP_GRE },
  { 95, ICE_PROT_IPV6_OUTER, ICE_PROT_IPV4_INNER, VNET_DEV_RSS_CLASS_IP6_IPIP_GRE },
  { 102, ICE_PROT_IPV6_OUTER, ICE_PROT_IPV6_INNER, VNET_DEV_RSS_CLASS_IP6_IPIP_GRE },
  { 110, ICE_PROT_IPV6_OUTER, ICE_PROT_IPV4_INNER, VNET_DEV_RSS_CLASS_IP6_IPIP_GRE },
  { 117, ICE_PROT_IPV6_OUTER, ICE_PROT_IPV6_INNER, VNET_DEV_RSS_CLASS_IP6_IPIP_GRE },
  { 125, ICE_PROT_IPV6_OUTER, ICE_PROT_IPV4_INNER, VNET_DEV_RSS_CLASS_IP6_IPIP_GRE },
  { 132, ICE_PROT_IPV6_OUTER, ICE_PROT_IPV6_INNER, VNET_DEV_RSS_CLASS_IP6_IPIP_GRE },
  { 140, ICE_PROT_IPV6_OUTER, ICE_PROT_IPV4_INNER, VNET_DEV_RSS_CLASS_IP6_IPIP_GRE },
  { 147, ICE_PROT_IPV6_OUTER, ICE_PROT_IPV6_INNER, VNET_DEV_RSS_CLASS_IP6_IPIP_GRE },
};

/* fragment, payload, UDP, unused, TCP, SCTP, ICMP */
static const u8 ice_rss_tunnel_block_transport[7] = {
  [2] = ICE_PROT_UDP_INNER,
  [4] = ICE_PROT_TCP_INNER,
  [5] = ICE_PROT_SCTP_INNER,
};

typedef struct
{
  u32 fields;
  u8 ip, transport;
} ice_rss_ptype_hash_t;

/* what a packet type hashes on with the config, 0 if the packet type is not hashed */
static int
ice_rss_ptype_hash (u32 ptype, const vnet_dev_rss_config_t *cfg, ice_rss_ptype_hash_t *h)
{
  vnet_dev_rss_class_t class;
  vnet_dev_rss_fields_t f;
  u8 outer = 0, transport = 0, inner = 0, inner_transport = 0;

  if (ptype < ARRAY_LEN (ice_rss_protocols) && ice_rss_protocols[ptype].ip)
    {
      outer = ice_rss_protocols[ptype].ip;
      transport = ice_rss_protocols[ptype].transport;
      class = ice_rss_protocols[ptype].class;
    }

  for (u32 i = 0; outer == 0 && i < ARRAY_LEN (ice_rss_tunnel_blocks); i++)
    if (ptype >= ice_rss_tunnel_blocks[i].first &&
	ptype < ice_rss_tunnel_blocks[i].first + ARRAY_LEN (ice_rss_tunnel_block_transport))
      {
	u32 offset = ptype - ice_rss_tunnel_blocks[i].first;

	/* unused packet type in the block */
	if (offset == 3)
	  return 0;

	outer = ice_rss_tunnel_blocks[i].outer;
	inner = ice_rss_tunnel_blocks[i].inner;
	inner_transport = ice_rss_tunnel_block_transport[offset];
	class = ice_rss_tunnel_blocks[i].class;
      }

  /* other tunnels, without an inner IP header */
  for (u32 i = 0; outer == 0 && i < ARRAY_LEN (ice_rss_tunnels); i++)
    if (ptype >= ice_rss_tunnels[i].first && ptype <= ice_rss_tunnels[i].last)
      {
	outer = ice_rss_tunnels[i].ip;
	class = ice_rss_tunnels[i].class;
      }

  if (outer == 0)
    return 0;

  f = vnet_dev_rss_class_fields (cfg, class);
  *h = (ice_rss_ptype_hash_t) { .ip = outer, .transport = transport };

  if (f.inner && inner)
    {
      h->ip = inner;
      h->transport = inner_transport;
    }

  h->fields = f.as_u32 & VNET_DEV_RSS_FIELDS_4_TUPLE;

  if ((h->fields & ~VNET_DEV_RSS_FIELDS_2_TUPLE) == 0)
    h->transport = 0;

  return 1;
}

static u8
ice_rss_profile_add_word (ice_rss_profile_plan_t *profile, u8 protocol, u16 offset)
{
  u8 index = ICE_PROFILE_FV_WORDS - 1 - profile->n_words++;

  profile->words[index] = (ice_profile_fv_t) { .protocol = protocol, .offset = offset };
  return index;
}

/* pairs source and destination words for the symmetric hash when both are present */
static void
ice_rss_profile_add_words (ice_rss_profile_plan_t *profile, u8 protocol, u16 src_offset,
			   u16 dst_offset, u8 n_words, int src, int dst)
{
  for (u32 i = 0; i < n_words; i++)
    {
      u8 s = 0, d = 0;

      if (src)
	s = ice_rss_profile_add_word (profile, protocol, src_offset + i * 2);

      if (dst)
	d = ice_rss_profile_add_word (profile, protocol, dst_offset + i * 2);

      if (src && dst)
	{
	  profile->pair[s] = d + 1;
	  profile->pair[d] = s + 1;
	}
    }
}

static void
ice_rss_profile_words (ice_rss_profile_plan_t *profile, u8 ip, u8 transport,
		       vnet_dev_rss_fields_t fields)
{
  u8 ip6 = ip == ICE_PROT_IPV6_OUTER || ip == ICE_PROT_IPV6_INNER;
  u8 address_words = ip6 ? 8 : 2;
  u16 offset = ip6 ? 8 : 12;

  *profile = (ice_rss_profile_plan_t) {
    .ip = ip,
    .transport = transport,
    .fields = fields.as_u32,
  };

  for (u32 i = 0; i < ICE_PROFILE_FV_WORDS; i++)
    profile->words[i] =
      (ice_profile_fv_t) { .protocol = ICE_PROT_UNUSED, .offset = ICE_PROFILE_FV_OFFSET_UNUSED };

  ice_rss_profile_add_words (profile, ip, offset, offset + address_words * 2, address_words,
			     fields.src_ip, fields.dst_ip);

  if (transport)
    ice_rss_profile_add_words (profile, transport, 0, 2, 1, fields.src_port, fields.dst_port);
}

static vnet_dev_rv_t
ice_rss_make_plan (const u8 *xlt1, const vnet_dev_rss_config_t *cfg, ice_rss_plan_t *plan)
{
  ice_rss_ptype_hash_t by_group[ICE_PROFILE_PTG_COUNT] = {};
  u8 l3_only[ICE_PROFILE_PTG_COUNT] = {};

  *plan = (ice_rss_plan_t) {};

  /* all packet types of a group share its profile, so they must hash alike */
  for (u32 ptype = 0; ptype < ICE_PROFILE_PTYPE_COUNT; ptype++)
    {
      ice_rss_ptype_hash_t h, *g = by_group + xlt1[ptype];

      if (xlt1[ptype] == 0 || ice_rss_ptype_hash (ptype, cfg, &h) == 0)
	continue;

      if (g->ip == 0)
	{
	  *g = h;
	  continue;
	}

      if (g->ip != h.ip)
	return VNET_DEV_ERR_NOT_SUPPORTED;

      /* a group with different transports hashes the addresses only */
      if (g->transport != h.transport)
	l3_only[xlt1[ptype]] = 1;
      else if (g->fields != h.fields)
	return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  for (u32 group = 1; group < ICE_PROFILE_PTG_COUNT; group++)
    {
      ice_rss_ptype_hash_t *g = by_group + group;
      vnet_dev_rss_fields_t fields = { .as_u32 = g->fields };
      u8 transport = g->transport;
      u32 index;

      if (g->ip == 0)
	continue;

      if (l3_only[group])
	{
	  transport = 0;
	  fields.as_u32 &= VNET_DEV_RSS_FIELDS_2_TUPLE;
	}

      /* no hash fields, packets of this group are not hashed */
      if (fields.as_u32 == 0)
	continue;

      for (index = 0; index < plan->n_profiles; index++)
	if (plan->profiles[index].ip == g->ip && plan->profiles[index].transport == transport &&
	    plan->profiles[index].fields == fields.as_u32)
	  break;

      if (index == plan->n_profiles)
	{
	  if (index == ARRAY_LEN (plan->profiles))
	    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	  ice_rss_profile_words (&plan->profiles[plan->n_profiles++], g->ip, transport, fields);
	}

      plan->profiles[index].groups[group / uword_bits] |= (uword) 1 << (group % uword_bits);
    }

  return VNET_DEV_OK;
}

/* checks that the config, merged into the port config, can be programmed */
vnet_dev_rv_t
ice_rss_validate_fields (vlib_main_t *vm, vnet_dev_port_t *port,
			 const vnet_dev_rss_config_t *config)
{
  vnet_dev_rss_config_t merged = port->rss_config;
  u8 xlt1[ICE_PROFILE_PTYPE_COUNT];
  ice_rss_plan_t plan;
  vnet_dev_rv_t rv;

  vnet_dev_rss_config_merge (&merged, config);

  rv = ice_rss_read_xlt1 (vm, port->dev, xlt1);
  if (rv)
    return rv;

  return ice_rss_make_plan (xlt1, &merged, &plan);
}

static u32
ice_rss_hsymm_word (const ice_rss_profile_plan_t *profile, u32 group, int symmetric)
{
  ice_reg_glqf_hsymm_t hsymm = {};

  if (!symmetric)
    return 0;

  for (u32 i = 0; i < ARRAY_LEN (hsymm.words); i++)
    {
      u8 pair = profile->pair[group * ARRAY_LEN (hsymm.words) + i];

      if (pair)
	{
	  hsymm.words[i].fv_word_index = pair - 1;
	  hsymm.words[i].enable = 1;
	}
    }

  return hsymm.as_u32;
}

static u32
ice_rss_inset_word (u32 group, u32 n_active)
{
  ice_reg_glqf_hinset_t inset = {};

  ASSERT (n_active <= ICE_PROFILE_FV_WORDS);
  ASSERT (group < ICE_PROFILE_FV_WORDS / ARRAY_LEN (inset.words));

  for (u32 i = 0; i < ARRAY_LEN (inset.words); i++)
    if (group * ARRAY_LEN (inset.words) + i >= ICE_PROFILE_FV_WORDS - n_active)
      inset.words[i] = (ice_reg_input_set_word_t) {
	.fv_word_index = ICE_PROFILE_FV_INDEX_DEFAULT,
	.valid = 1,
      };

  return inset.as_u32;
}

vnet_dev_rv_t
ice_rss_section (vlib_main_t *vm, vnet_dev_t *dev, u32 sid, void *section, u16 size, int upload)
{
  u8 buffer[ICE_AQ_BUF_SIZE] = {};
  ice_pkg_buf_hdr_t *hdr = (void *) buffer;
  vnet_dev_rv_t rv;
  u32 data_end = sizeof (*hdr) + size;
  /* Firmware requires at least 28 DMA bytes; section lengths exclude padding. */
  u16 length = clib_max (ICE_PKG_MIN_DMA_SIZE, round_pow2 (data_end, ICE_PKG_ALIGNMENT));

  ASSERT (data_end <= sizeof (buffer));
  *hdr = (ice_pkg_buf_hdr_t) {
    .index_table_size = 1,
    .data_end = data_end,
    .section_type = sid,
    .section_offset = sizeof (*hdr),
    .section_size = size,
  };
  clib_memcpy (buffer + sizeof (*hdr), section, size);

  if (upload)
    rv = ice_aq_upload_section (vm, dev, buffer, length);
  else
    rv = ice_aq_update_package (vm, dev, buffer, length, 1);

  if (rv == VNET_DEV_OK && upload)
    clib_memcpy (section, buffer + sizeof (*hdr), size);

  return rv;
}

static vnet_dev_rv_t
ice_rss_map_vsi (vlib_main_t *vm, vnet_dev_t *dev, u16 vsi, u16 vsig)
{
  ice_pkg_xlt2_entry_t entry = { .count = 1, .offset = vsi, .value = vsig };
  return ice_rss_section (vm, dev, ICE_RSS_SECTION_XLT2, &entry, sizeof (entry), 0);
}

vnet_dev_rv_t
ice_rss_read_xlt1 (vlib_main_t *vm, vnet_dev_t *dev, u8 *values)
{
  ice_profile_xlt1_section_t section = { .count = ICE_PROFILE_PTYPE_COUNT };

  vnet_dev_rv_t rv = ice_rss_section (vm, dev, ICE_RSS_SECTION_XLT1, &section, sizeof (section), 1);
  if (rv)
    return rv;

  if (section.count != ICE_PROFILE_PTYPE_COUNT || section.offset)
    return VNET_DEV_ERR_INVALID_DATA;

  clib_memcpy (values, section.values, sizeof (section.values));
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_rss_find_vsig (vlib_main_t *vm, vnet_dev_t *dev, u16 vsi, u16 *vsig, u16 *saved_vsig)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  u8 occupied[ICE_PROFILE_VSI_COUNT] = {};
  ice_profile_xlt2_section_t xlt2 = { .count = ICE_PROFILE_VSI_COUNT };
  ice_profile_tcam_block_t tcam;
  vnet_dev_rv_t rv;

  if (vsi >= ICE_PROFILE_VSI_COUNT)
    return VNET_DEV_ERR_INVALID_ARG;

  rv = ice_rss_section (vm, dev, ICE_RSS_SECTION_XLT2, &xlt2, sizeof (xlt2), 1);
  if (rv)
    return rv;

  if (xlt2.count != ICE_PROFILE_VSI_COUNT || xlt2.offset)
    return VNET_DEV_ERR_INVALID_DATA;

  *saved_vsig = xlt2.values[vsi];

  for (u32 i = 0; i < ARRAY_LEN (xlt2.values); i++)
    {
      ice_vsig_t value = {
	.as_u16 = xlt2.values[i],
      };

      if (value.pf == id->pf_id && value.group < ARRAY_LEN (occupied))
	occupied[value.group] = 1;
    }

  for (u32 first = 0; first < ICE_PROFILE_TCAM_COUNT; first += ARRAY_LEN (tcam.entries))
    {
      tcam = (typeof (tcam)) { .count = ARRAY_LEN (tcam.entries) };

      for (u32 i = 0; i < ARRAY_LEN (tcam.entries); i++)
	tcam.entries[i].address = first + i;

      rv = ice_rss_section (vm, dev, ICE_RSS_SECTION_TCAM, &tcam, sizeof (tcam), 1);
      if (rv)
	return rv;

      if (tcam.count > ARRAY_LEN (tcam.entries))
	return VNET_DEV_ERR_INVALID_DATA;

      for (u32 i = 0; i < tcam.count; i++)
	{
	  ice_profile_tcam_t *entry = tcam.entries + i;
	  int valid = 1;

	  for (u32 j = 0; j < ARRAY_LEN (entry->zero.as_u8); j++)
	    if ((entry->zero.as_u8[j] | entry->one.as_u8[j]) != CLIB_U8_MAX)
	      valid = 0;

	  if (valid && (entry->zero.vsig.as_u16 ^ entry->one.vsig.as_u16) == CLIB_U16_MAX &&
	      entry->one.vsig.pf == id->pf_id && entry->one.vsig.group < ARRAY_LEN (occupied))
	    occupied[entry->one.vsig.group] = 1;
	}
    }

  for (u32 i = ARRAY_LEN (occupied) - 1; i; i--)
    if (!occupied[i])
      {
	ice_vsig_t value = {
	  .group = i,
	  .pf = id->pf_id,
	};

	*vsig = value.as_u16;
	return VNET_DEV_OK;
      }

  return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
}

static vnet_dev_rv_t
ice_rss_write_tcam (vlib_main_t *vm, vnet_dev_t *dev, u16 address, u8 profile, u8 ptg, u16 vsig,
		    int enable)
{
  ice_profile_tcam_entry_section_t section = {
    .count = 1, .entry = { .address = address, .profile = profile }
  };
  ice_profile_key_t value = {
    .ptg = ptg,
    .vsig.as_u16 = vsig,
  };

  for (u32 i = 0; i < ARRAY_LEN (value.as_u8); i++)
    {
      section.entry.zero.as_u8[i] = ~value.as_u8[i];
      section.entry.one.as_u8[i] = value.as_u8[i];
    }

  section.entry.zero.flags = section.entry.one.flags = CLIB_U16_MAX;

  if (!enable)
    section.entry.zero.flags = section.entry.one.flags = ICE_PROFILE_KEY_DISABLED_FLAGS;

  return ice_rss_section (vm, dev, ICE_RSS_SECTION_TCAM, &section, sizeof (section), 0);
}

static vnet_dev_rv_t
ice_rss_release_tcam (vlib_main_t *vm, vnet_dev_t *dev, u16 *tcam)
{
  u16 *address;
  vnet_dev_rv_t rv;

  vec_foreach (address, tcam)
    {
      if (*address == (u16) ~0)
	continue;

      rv = ice_rss_write_tcam (vm, dev, *address, 0, 0, 0, 0);

      if (!rv)
	rv = ice_aq_alloc_free_resource (vm, dev, ICE_RES_RSS_TCAM, 1, address, 0);

      if (rv)
	return rv;

      *address = ~0;
    }

  return VNET_DEV_OK;
}

static u16
ice_rss_get_queue_ids (vnet_dev_port_t *port, u8 queue_ids[ICE_RSS_MAX_QUEUES])
{
  u8 enabled[ICE_RSS_MAX_QUEUES] = {};
  u16 n_queues = 0;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    if (rxq->enabled)
      {
	ASSERT (rxq->queue_id < ICE_RSS_MAX_QUEUES);
	ASSERT (!enabled[rxq->queue_id]);
	enabled[rxq->queue_id] = 1;
      }

  for (u32 i = 0; i < ARRAY_LEN (enabled); i++)
    if (enabled[i])
      queue_ids[n_queues++] = i;

  return n_queues;
}

vnet_dev_rv_t
ice_rss_validate_config (vnet_dev_port_t *port, const vnet_dev_rss_config_t *config)
{
  if ((config->set_key && config->key_len != ICE_RSS_KEY_SIZE) ||
      (config->set_lut && config->lut_len != ICE_RSS_LUT_SIZE))
    return VNET_DEV_ERR_INVALID_DATA;

  if (config->set_lut)
    for (u32 i = 0; i < ICE_RSS_LUT_SIZE; i++)
      {
	vnet_dev_rx_queue_t *rxq;

	if (config->lut[i] >= ICE_RSS_MAX_QUEUES)
	  return VNET_DEV_ERR_INVALID_VALUE;

	rxq = vnet_dev_get_port_rx_queue_by_id (port, config->lut[i]);

	if (!rxq || !rxq->enabled)
	  return VNET_DEV_ERR_INVALID_VALUE;
      }

  return VNET_DEV_OK;
}

void
ice_rss_profiles_dispose (vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_rss_t *rss = ip->rss;
  ice_rss_profile_resource_t *profile;

  vec_foreach (profile, rss->profiles)
    vec_free (profile->tcam);

  vec_free (rss->profiles);
  clib_mem_free (rss);
  ip->rss = 0;
}

static vnet_dev_rv_t
ice_rss_profiles_destroy (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_rss_t *rss = ip->rss;
  ice_rss_profile_resource_t *profile;
  vnet_dev_rv_t rv;

  if (rss->active)
    {
      rv = ice_rss_map_vsi (vm, port->dev, ip->vsi.num, rss->saved_vsig);
      if (rv)
	return rv;

      rss->active = 0;
    }

  vec_foreach (profile, rss->profiles)
    {
      rv = ice_rss_release_tcam (vm, port->dev, profile->tcam);
      if (rv)
	return rv;

      if (profile->allocated)
	{
	  rv = ice_aq_alloc_free_resource (vm, port->dev, ICE_RES_RSS_PROFILE, 1, &profile->id, 0);
	  if (rv)
	    return rv;

	  profile->id = ~0;
	  profile->allocated = 0;
	}
    }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_rss_profiles_activate (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_rss_t *rss = ip->rss;
  vnet_dev_rv_t rv, rollback_rv;

  ASSERT (rss);

  if (rss->active)
    return VNET_DEV_OK;

  if (rss->failed)
    return VNET_DEV_ERR_NOT_READY;

  rv = ice_aq_request_resource (vm, port->dev, ICE_AQ_RES_ID_CHANGE_LOCK, ICE_AQ_RES_ACCESS_WRITE,
				1000);
  if (rv)
    return rv;

  rv = ice_rss_map_vsi (vm, port->dev, ip->vsi.num, rss->vsig);

  if (rv == VNET_DEV_OK)
    rss->active = 1;
  else
    {
      rollback_rv = ice_rss_map_vsi (vm, port->dev, ip->vsi.num, rss->saved_vsig);

      if (rollback_rv)
	{
	  /* A timed out write may have taken effect. Keep these resources
	   * until their mapping can be restored or the device is closed. */
	  rss->active = rss->failed = 1;
	  log_err (port->dev, "RSS mapping rollback failed: %U", format_vnet_dev_rv, rollback_rv);
	}
    }

  ice_aq_release_resource (vm, port->dev, ICE_AQ_RES_ID_CHANGE_LOCK);
  return rv;
}

static vnet_dev_rv_t
ice_rss_apply (vlib_main_t *vm, vnet_dev_port_t *port, const vnet_dev_rss_config_t *config,
	       int activate)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_aq_rss_key_t previous_key = {}, key = {};
  ice_aq_rss_lut_t previous_lut = {}, lut = {};
  vnet_dev_rv_t rv, rollback_rv;
  int key_attempted = 0, lut_attempted = 0, rollback_failed = 0;

  rv = ice_rss_validate_config (port, config);
  if (rv)
    return rv;

  if ((ip->rss && ip->rss->failed) ||
      (ip->rss_config_failed && !(config->set_key && config->set_lut)))
    return VNET_DEV_ERR_NOT_READY;

  if (config->set_key)
    {
      rv = ice_aq_get_rss_key (vm, port, &previous_key);
      if (rv)
	return rv;
    }

  if (config->set_lut)
    {
      rv = ice_aq_get_rss_lut (vm, port, &previous_lut);
      if (rv)
	return rv;
    }

  if (config->set_key)
    {
      clib_memcpy (key.standard_key, config->key, ICE_RSS_KEY_SIZE);
      key_attempted = 1;

      rv = ice_aq_set_rss_key (vm, port, &key);
      if (rv)
	goto rollback;
    }

  if (config->set_lut)
    {
      for (u32 i = 0; i < ICE_RSS_LUT_SIZE; i++)
	lut.entries[i] = config->lut[i];

      lut_attempted = 1;

      rv = ice_aq_set_rss_lut (vm, port, &lut);
      if (rv)
	goto rollback;
    }

  if (activate)
    {
      rv = ice_rss_profiles_activate (vm, port);
      if (rv)
	goto rollback;
    }

  if (config->set_key && config->set_lut)
    ip->rss_config_failed = 0;

  return VNET_DEV_OK;

rollback:
  if (lut_attempted)
    {
      rollback_rv = ice_aq_set_rss_lut (vm, port, &previous_lut);
      rollback_failed |= rollback_rv != VNET_DEV_OK;

      if (rollback_rv)
	log_err (port->dev, "RSS LUT rollback failed: %U", format_vnet_dev_rv, rollback_rv);
    }

  if (key_attempted)
    {
      rollback_rv = ice_aq_set_rss_key (vm, port, &previous_key);
      rollback_failed |= rollback_rv != VNET_DEV_OK;

      if (rollback_rv)
	log_err (port->dev, "RSS key rollback failed: %U", format_vnet_dev_rv, rollback_rv);
    }

  if (rollback_failed)
    ip->rss_config_failed = 1;

  return rv;
}

static vnet_dev_rv_t
ice_rss_reinit (vlib_main_t *vm, vnet_dev_port_t *port, const vnet_dev_rss_config_t *config,
		int user_lut)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rss_config_t saved = port->rss_config;
  int saved_user_lut = ip->rss->user_lut;
  vnet_dev_rv_t rv;

  ice_rss_free (vm, port);
  if (ip->rss)
    return VNET_DEV_ERR_NOT_READY;

  port->rss_config = *config;
  rv = ice_rss_init (vm, port);

  if (rv == VNET_DEV_OK)
    {
      ip->rss->user_lut = user_lut;
      return rv;
    }

  port->rss_config = saved;

  if (ice_rss_init (vm, port) == VNET_DEV_OK)
    ip->rss->user_lut = saved_user_lut;

  return rv;
}

vnet_dev_rv_t
ice_rss_set_config (vlib_main_t *vm, vnet_dev_port_t *port, const vnet_dev_rss_config_t *config)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rss_config_t merged = port->rss_config;
  vnet_dev_rv_t rv;

  /* The framework retains updates for later multi-queue initialization. */
  if (!ip->rss)
    return VNET_DEV_OK;

  vnet_dev_rss_config_merge (&merged, config);

  if (merged.function != port->rss_config.function ||
      clib_memcmp (merged.fields, port->rss_config.fields, sizeof (merged.fields)))
    rv = ice_rss_reinit (vm, port, &merged, ip->rss->user_lut || config->set_lut);
  else
    rv = ice_rss_apply (vm, port, config, 0);

  if (rv)
    log_err (port->dev, "VSI RSS update failed: %U", format_vnet_dev_rv, rv);
  else if (config->set_lut)
    ip->rss->user_lut = 1;

  return rv;
}

static vnet_dev_rv_t
ice_rss_set_hash_scheme (vlib_main_t *vm, vnet_dev_port_t *port, vnet_dev_rss_function_t function)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  static const u8 schemes[] = {
    [VNET_DEV_RSS_FUNCTION_TOEPLITZ] = ICE_AQ_VSI_Q_OPT_RSS_HASH_TOEPLITZ,
    [VNET_DEV_RSS_FUNCTION_SYMMETRIC_TOEPLITZ] = ICE_AQ_VSI_Q_OPT_RSS_HASH_SYM_TOEPLITZ,
  };
  ice_aqc_vsi_props_t props = {
    .valid_sections.queue_option_section = 1,
    .q_opt_rss = ip->vsi.props.q_opt_rss,
    .q_opt_tc = ip->vsi.props.q_opt_tc,
    .q_opt_flags = ip->vsi.props.q_opt_flags,
  };
  vnet_dev_rv_t rv;

  if (ip->vsi.props.q_opt_rss.hash_type == schemes[function])
    return VNET_DEV_OK;

  props.q_opt_rss.hash_type = schemes[function];

  rv = ice_aq_update_vsi (vm, port->dev, ip->vsi.num, &props);
  if (rv == VNET_DEV_OK)
    ip->vsi.props.q_opt_rss = props.q_opt_rss;

  return rv;
}

vnet_dev_rv_t
ice_rss_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rss_config_t saved = port->rss_config;
  int user_lut = ip->rss ? ip->rss->user_lut : saved.set_lut;
  u8 queue_ids[ICE_RSS_MAX_QUEUES];
  u16 n_queues = ice_rss_get_queue_ids (port, queue_ids);
  ice_rss_t *rss = ip->rss;
  vnet_dev_rv_t rv, cleanup_rv;
  vnet_dev_rss_config_t config = port->rss_config;
  int symmetric = config.function == VNET_DEV_RSS_FUNCTION_SYMMETRIC_TOEPLITZ;

  /* Require an enabled RX queue and disable RSS for a single queue. */
  if (!n_queues)
    return VNET_DEV_ERR_NOT_READY;

  if (n_queues == 1)
    {
      if (ip->rss)
	{
	  ice_rss_free (vm, port);

	  if (ip->rss)
	    return VNET_DEV_ERR_NOT_READY;

	  if (!user_lut)
	    port->rss_config.set_lut = 0;
	}

      return VNET_DEV_OK;
    }

  /* Validate the key and discard stale automatic or invalid user LUTs. */
  if (port->rss_config.key_len != ICE_RSS_KEY_SIZE)
    return VNET_DEV_ERR_INVALID_DATA;

  if (ip->rss && !user_lut &&
      (ip->rss->n_queues != n_queues || clib_memcmp (ip->rss->queues, queue_ids, n_queues)))
    saved.set_lut = 0;

  if (saved.set_lut && ice_rss_validate_config (port, &saved) != VNET_DEV_OK)
    user_lut = saved.set_lut = 0;

  /* Preserve the configured key and build the active queue LUT. */
  config.key_len = ICE_RSS_KEY_SIZE;
  config.lut_len = ICE_RSS_LUT_SIZE;
  config.set_key = config.set_lut = 1;

  for (u32 i = 0; i < ICE_RSS_LUT_SIZE; i++)
    config.lut[i] = saved.set_lut ? saved.lut[i] : queue_ids[i % n_queues];

  /* Reuse healthy profiles or initialize them for the first multi-queue start. */
  if (rss && rss->failed)
    {
      rv = VNET_DEV_ERR_NOT_READY;
      goto error;
    }

  if (!rss)
    {
      ice_rss_plan_t plan;
      u8 xlt1[ICE_PROFILE_PTYPE_COUNT];

      /* Lock the package and allocate RSS resource tracking. */
      rv =
	ice_aq_request_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK, ICE_AQ_RES_ACCESS_WRITE, 1000);
      if (rv)
	goto error;

      rss = clib_mem_alloc (sizeof (*rss));

      if (!rss)
	{
	  ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);
	  rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	  goto error;
	}

      *rss = (ice_rss_t) {};
      ip->rss = rss;
      rss->user_lut = port->rss_config.set_lut;
      /* Build profiles from the package packet groups and reserve a VSI group. */
      rv = ice_rss_read_xlt1 (vm, dev, xlt1);

      if (!rv)
	rv = ice_rss_make_plan (xlt1, &config, &plan);

      if (!rv)
	rv = ice_rss_find_vsig (vm, dev, ip->vsi.num, &rss->vsig, &rss->saved_vsig);

      if (rv)
	goto profile_error;

      /* Allocate and program each RSS profile and its packet-group matches. */
      for (u32 i = 0; i < plan.n_profiles; i++)
	{
	  ice_rss_profile_plan_t *p = plan.profiles + i;
	  ice_rss_profile_resource_t *profile;
	  ice_profile_fv_section_t fv = { .count = 1 };

	  /* Allocate the hardware profile and track it for cleanup. */
	  vec_add2 (rss->profiles, profile, 1);
	  *profile = (ice_rss_profile_resource_t) {};

	  rv = ice_aq_alloc_free_resource (vm, dev, ICE_RES_RSS_PROFILE, 1, &profile->id, 1);
	  if (rv)
	    goto profile_error;

	  profile->allocated = 1;

	  if (profile->id >= ICE_PROFILE_COUNT)
	    {
	      rv = VNET_DEV_ERR_INVALID_DATA;
	      goto profile_error;
	    }

	  /* Program field extraction and hash input selection. */
	  fv.offset = profile->id;

	  for (u32 j = 0; j < ICE_PROFILE_FV_WORDS; j++)
	    fv.words[j] = p->words[j];

	  for (u32 j = 0; j < ICE_PROFILE_FV_WORDS / 4; j++)
	    ice_reg_write (dev, ICE_GLQF_HINSET (profile->id, j),
			   ice_rss_inset_word (j, p->n_words));

	  for (u32 j = 0; j < ICE_PROFILE_FV_WORDS / 4; j++)
	    ice_reg_write (dev, ICE_GLQF_HSYMM (profile->id, j),
			   ice_rss_hsymm_word (p, j, symmetric));

	  ice_reg_write (dev, ICE_GLQF_HMASK_SEL (profile->id), 0);

	  rv = ice_rss_section (vm, dev, ICE_RSS_SECTION_FV, &fv, sizeof (fv), 0);
	  if (rv)
	    goto profile_error;

	  /* Map each matching packet group to this profile. */
	  for (u32 group = 1; group < ICE_PROFILE_PTG_COUNT; group++)
	    if (p->groups[group / uword_bits] & ((uword) 1 << (group % uword_bits)))
	      {
		u16 address = 0;

		rv = ice_aq_alloc_free_resource (vm, dev, ICE_RES_RSS_TCAM, 1, &address, 1);
		if (rv)
		  goto profile_error;

		vec_add1 (profile->tcam, address);

		rv = ice_rss_write_tcam (vm, dev, address, profile->id, group, rss->vsig, 1);
		if (rv)
		  goto profile_error;
	      }
	}

      rv = ice_rss_set_hash_scheme (vm, port, config.function);
      if (rv)
	goto profile_error;

      /* Release the package lock after all profile updates complete. */
      ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);
      log_debug (dev, "VSI %u RSS VSIG 0x%04x has %u profiles", ip->vsi.num, rss->vsig,
		 plan.n_profiles);
    }

  /* Program the key and LUT, then activate the RSS VSI mapping. */
  rv = ice_rss_apply (vm, port, &config, 1);
  if (rv)
    goto error;

  /* Save the applied configuration and queue layout for subsequent starts. */
  port->rss_config = config;
  ip->rss->user_lut = user_lut;
  ip->rss->n_queues = n_queues;
  clib_memcpy (ip->rss->queues, queue_ids, n_queues);
  return VNET_DEV_OK;

profile_error:
  /* Roll back partial profile allocation while holding the package lock. */
  cleanup_rv = ice_rss_profiles_destroy (vm, port);
  ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);

  if (cleanup_rv)
    {
      rss->failed = 1;
      log_err (dev, "RSS profile rollback failed: %U", format_vnet_dev_rv, cleanup_rv);
    }
  else
    ice_rss_profiles_dispose (port);

error:
  /* Report the original initialization error after any required cleanup. */
  log_err (dev, "RSS initialization failed: %U", format_vnet_dev_rv, rv);
  return rv;
}

void
ice_rss_free (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  if (!ip->rss)
    return;

  rv = ice_aq_request_resource (vm, port->dev, ICE_AQ_RES_ID_CHANGE_LOCK, ICE_AQ_RES_ACCESS_WRITE,
				1000);

  if (rv == VNET_DEV_OK)
    {
      rv = ice_rss_profiles_destroy (vm, port);
      ice_aq_release_resource (vm, port->dev, ICE_AQ_RES_ID_CHANGE_LOCK);
    }

  if (rv)
    {
      ip->rss->failed = 1;
      log_err (port->dev, "RSS profile cleanup failed: %U", format_vnet_dev_rv, rv);
      return;
    }

  ice_rss_profiles_dispose (port);
}
