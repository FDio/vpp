/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "rss",
};

#define ICE_RSS_PROFILE_LIMIT 8

typedef struct
{
  ice_profile_fv_t words[ICE_PROFILE_FV_WORDS];
  uword groups[ICE_PROFILE_PTG_COUNT / uword_bits];
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
} ice_rss_protocols[] = {
  [ICE_PTYPE_IPV4_FRAG] = { .ip = ICE_PROT_IPV4_OUTER, },
  [ICE_PTYPE_IPV4_PAYLOAD] = { .ip = ICE_PROT_IPV4_OUTER, },
  [ICE_PTYPE_IPV4_UDP] = { .ip = ICE_PROT_IPV4_OUTER, .transport = ICE_PROT_UDP_INNER, },
  [ICE_PTYPE_IPV4_TCP] = { .ip = ICE_PROT_IPV4_OUTER, .transport = ICE_PROT_TCP_INNER, },
  [ICE_PTYPE_IPV4_SCTP] = { .ip = ICE_PROT_IPV4_OUTER, .transport = ICE_PROT_SCTP_INNER, },
  [ICE_PTYPE_IPV4_ICMP] = { .ip = ICE_PROT_IPV4_OUTER, },
  [ICE_PTYPE_IPV6_FRAG] = { .ip = ICE_PROT_IPV6_OUTER, },
  [ICE_PTYPE_IPV6_PAYLOAD] = { .ip = ICE_PROT_IPV6_OUTER, },
  [ICE_PTYPE_IPV6_UDP] = { .ip = ICE_PROT_IPV6_OUTER, .transport = ICE_PROT_UDP_INNER, },
  [ICE_PTYPE_IPV6_TCP] = { .ip = ICE_PROT_IPV6_OUTER, .transport = ICE_PROT_TCP_INNER, },
  [ICE_PTYPE_IPV6_SCTP] = { .ip = ICE_PROT_IPV6_OUTER, .transport = ICE_PROT_SCTP_INNER, },
  [ICE_PTYPE_IPV6_ICMP] = { .ip = ICE_PROT_IPV6_OUTER, },
};

static void
ice_rss_profile_words (ice_rss_profile_plan_t *profile, u8 ip, u8 transport)
{
  u32 address_words = ip == ICE_PROT_IPV6_OUTER ? 16 : 4;
  u32 offset = address_words == 16 ? 8 : 12;

  *profile = (ice_rss_profile_plan_t) {
    .ip = ip,
    .transport = transport,
  };

  for (u32 i = 0; i < ICE_PROFILE_FV_WORDS; i++)
    profile->words[i] =
      (ice_profile_fv_t) { .protocol = ICE_PROT_UNUSED, .offset = ICE_PROFILE_FV_OFFSET_UNUSED };

  for (u32 i = 0; i < address_words; i++)
    profile->words[ICE_PROFILE_FV_WORDS - 1 - profile->n_words++] =
      (ice_profile_fv_t) { .protocol = ip, .offset = offset + i * 2 };

  if (transport)
    for (u32 i = 0; i < 2; i++)
      profile->words[ICE_PROFILE_FV_WORDS - 1 - profile->n_words++] =
	(ice_profile_fv_t) { .protocol = transport, .offset = i * 2 };
}

static vnet_dev_rv_t
ice_rss_make_plan (const u8 *xlt1, ice_rss_plan_t *plan)
{
  u8 ip_by_group[ICE_PROFILE_PTG_COUNT] = {}, transport_by_group[ICE_PROFILE_PTG_COUNT] = {},
     l3_only[ICE_PROFILE_PTG_COUNT] = {};

  *plan = (ice_rss_plan_t) {};

  for (u32 ptype = 0; ptype < ARRAY_LEN (ice_rss_protocols); ptype++)
    {
      u8 ip = ice_rss_protocols[ptype].ip, transport = ice_rss_protocols[ptype].transport;
      u8 group = xlt1[ptype];

      if (!group || !ip)
	continue;

      if (ip_by_group[group] && ip_by_group[group] != ip)
	return VNET_DEV_ERR_NOT_SUPPORTED;

      if (ip_by_group[group] && transport_by_group[group] != transport)
	l3_only[group] = 1;

      ip_by_group[group] = ip;
      transport_by_group[group] = transport;
    }

  for (u32 group = 1; group < ICE_PROFILE_PTG_COUNT; group++)
    {
      u8 ip = ip_by_group[group], transport = transport_by_group[group];
      u32 index;

      if (!ip)
	continue;

      if (l3_only[group])
	transport = 0;

      for (index = 0; index < plan->n_profiles; index++)
	if (plan->profiles[index].ip == ip && plan->profiles[index].transport == transport)
	  break;

      if (index == plan->n_profiles)
	{
	  ASSERT (index < ARRAY_LEN (plan->profiles));
	  ice_rss_profile_words (&plan->profiles[plan->n_profiles++], ip, transport);
	}

      plan->profiles[index].groups[group / uword_bits] |= (uword) 1 << (group % uword_bits);
    }

  return plan->n_profiles ? VNET_DEV_OK : VNET_DEV_ERR_NOT_SUPPORTED;
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
  if ((!config->set_key && !config->set_lut) ||
      (config->set_key && config->key_len != ICE_RSS_KEY_SIZE) ||
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

vnet_dev_rv_t
ice_rss_set_config (vlib_main_t *vm, vnet_dev_port_t *port, const vnet_dev_rss_config_t *config)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  /* The framework retains updates for later multi-queue initialization. */
  if (!ip->rss)
    return VNET_DEV_OK;

  rv = ice_rss_apply (vm, port, config, 0);

  if (rv)
    log_err (port->dev, "VSI RSS update failed: %U", format_vnet_dev_rv, rv);
  else if (config->set_lut)
    ip->rss->user_lut = 1;

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
  vnet_dev_rss_config_t config = {
    .key_len = ICE_RSS_KEY_SIZE,
    .lut_len = ICE_RSS_LUT_SIZE,
    .set_key = 1,
    .set_lut = 1,
  };

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
  clib_memcpy (config.key, port->rss_config.key, ICE_RSS_KEY_SIZE);

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
	rv = ice_rss_make_plan (xlt1, &plan);

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
