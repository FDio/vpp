/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "rss",
};

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

vnet_dev_rv_t
ice_rss_get_config (vlib_main_t *vm, vnet_dev_port_t *port, ice_aq_rss_key_t *key,
		    ice_aq_rss_lut_t *lut)
{
  vnet_dev_rv_t rv = ice_aq_get_rss_key (vm, port, key);

  if (rv)
    return rv;
  return ice_aq_get_rss_lut (vm, port, lut);
}

static void
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

/* The caller owns the Change Lock. Profiles are unreachable before activation
 * and after restoring XLT2, so individual table writes cannot affect traffic. */
static vnet_dev_rv_t
ice_rss_profiles_destroy (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_rss_t *rss = ip->rss;
  ice_rss_profile_resource_t *profile;
  vnet_dev_rv_t rv;

  if (rss->active)
    {
      if ((rv = ice_profile_map_vsi (vm, port->dev, ICE_RSS_SECTION_XLT2, ip->vsi.num,
				     rss->saved_vsig)))
	return rv;
      rss->active = 0;
    }
  vec_foreach (profile, rss->profiles)
    {
      if ((rv = ice_profile_release_tcam (vm, port->dev, ICE_RSS_SECTION_TCAM, ICE_RES_RSS_TCAM,
					  profile->tcam)))
	return rv;
      if (profile->allocated)
	{
	  if ((rv = ice_profile_release_id (vm, port->dev, ICE_RES_RSS_PROFILE, &profile->id)))
	    return rv;
	  profile->allocated = 0;
	}
    }
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_rss_profiles_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_rss_plan_t plan;
  u8 xlt1[ICE_PROFILE_PTYPE_COUNT];
  ice_rss_t *rss;
  vnet_dev_rv_t rv, cleanup_rv;

  if (ip->rss)
    return ip->rss->failed ? VNET_DEV_ERR_NOT_READY : VNET_DEV_OK;
  if ((rv = ice_aq_request_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK, ICE_AQ_RES_ACCESS_WRITE,
				     1000)))
    return rv;
  rss = clib_mem_alloc (sizeof (*rss));
  if (!rss)
    {
      ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }
  *rss = (ice_rss_t) {};
  ip->rss = rss;
  rss->user_lut = port->rss_config.set_lut;
  if ((rv = ice_profile_read_xlt1 (vm, dev, ICE_RSS_SECTION_XLT1, xlt1)) ||
      (rv = ice_rss_make_plan (xlt1, &plan)) ||
      (rv = ice_profile_find_vsig (vm, dev, ICE_RSS_SECTION_XLT2, ICE_RSS_SECTION_TCAM, ip->vsi.num,
				   &rss->vsig, &rss->saved_vsig)))
    goto error;
  rss->full_tuple_types = plan.full_tuple_types;
  for (u32 i = 0; i < plan.n_profiles; i++)
    {
      ice_rss_profile_plan_t *p = plan.profiles + i;
      ice_rss_profile_resource_t *profile;
      ice_profile_fv_section_t fv = { .count = 1 };

      vec_add2 (rss->profiles, profile, 1);
      *profile = (ice_rss_profile_resource_t) {};
      if ((rv = ice_aq_alloc_free_resource (vm, dev, ICE_RES_RSS_PROFILE, 1, &profile->id, 1)))
	goto error;
      profile->allocated = 1;
      if (profile->id >= ICE_PROFILE_COUNT)
	{
	  rv = VNET_DEV_ERR_INVALID_DATA;
	  goto error;
	}
      fv.offset = profile->id;
      for (u32 j = 0; j < ICE_PROFILE_FV_WORDS; j++)
	fv.words[j] = p->words[j];
      for (u32 j = 0; j < ICE_PROFILE_FV_WORDS / 4; j++)
	ice_reg_write (dev, ICE_GLQF_HINSET (profile->id, j),
		       ice_profile_inset_word (j, p->n_words, ICE_PROFILE_FV_WORDS));
      ice_reg_write (dev, ICE_GLQF_HMASK_SEL (profile->id), 0);
      if ((rv = ice_profile_section (vm, dev, ICE_RSS_SECTION_FV, &fv, sizeof (fv), 0)))
	goto error;
      for (u32 group = 1; group < 256; group++)
	if (p->groups[group / uword_bits] & ((uword) 1 << (group % uword_bits)))
	  {
	    u16 address = 0;
	    if ((rv = ice_aq_alloc_free_resource (vm, dev, ICE_RES_RSS_TCAM, 1, &address, 1)))
	      goto error;
	    vec_add1 (profile->tcam, address);
	    if ((rv = ice_profile_write_tcam (vm, dev, ICE_RSS_SECTION_TCAM, address, profile->id,
					      group, rss->vsig, 1)))
	      goto error;
	  }
    }
  ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);
  log_debug (dev, "VSI %u RSS VSIG 0x%04x has %u profiles", ip->vsi.num, rss->vsig,
	     plan.n_profiles);
  return VNET_DEV_OK;

error:
  cleanup_rv = ice_rss_profiles_destroy (vm, port);
  ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);
  if (cleanup_rv)
    {
      rss->failed = 1;
      log_err (dev, "RSS profile rollback failed: %U", format_vnet_dev_rv, cleanup_rv);
    }
  else
    ice_rss_profiles_dispose (port);
  return rv;
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
  if ((rv = ice_aq_request_resource (vm, port->dev, ICE_AQ_RES_ID_CHANGE_LOCK,
				     ICE_AQ_RES_ACCESS_WRITE, 1000)))
    return rv;
  rv = ice_profile_map_vsi (vm, port->dev, ICE_RSS_SECTION_XLT2, ip->vsi.num, rss->vsig);
  if (rv == VNET_DEV_OK)
    rss->active = 1;
  else
    {
      rollback_rv =
	ice_profile_map_vsi (vm, port->dev, ICE_RSS_SECTION_XLT2, ip->vsi.num, rss->saved_vsig);
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

  if ((rv = ice_rss_validate_config (port, config)))
    return rv;
  if ((ip->rss && ip->rss->failed) ||
      (ip->rss_config_failed && !(config->set_key && config->set_lut)))
    return VNET_DEV_ERR_NOT_READY;
  if (config->set_key && (rv = ice_aq_get_rss_key (vm, port, &previous_key)))
    return rv;
  if (config->set_lut && (rv = ice_aq_get_rss_lut (vm, port, &previous_lut)))
    return rv;
  if (config->set_key)
    {
      clib_memcpy (key.standard_key, config->key, ICE_RSS_KEY_SIZE);
      key_attempted = 1;
      if ((rv = ice_aq_set_rss_key (vm, port, &key)))
	goto rollback;
    }
  if (config->set_lut)
    {
      for (u32 i = 0; i < ICE_RSS_LUT_SIZE; i++)
	lut.entries[i] = config->lut[i];
      lut_attempted = 1;
      if ((rv = ice_aq_set_rss_lut (vm, port, &lut)))
	goto rollback;
    }
  if (activate && (rv = ice_rss_profiles_activate (vm, port)))
    goto rollback;
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
  else if (config->set_lut && ip->rss)
    ip->rss->user_lut = 1;
  return rv;
}

vnet_dev_rv_t
ice_rss_configure (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rss_config_t config = {
    .key_len = ICE_RSS_KEY_SIZE,
    .lut_len = ICE_RSS_LUT_SIZE,
    .set_key = 1,
    .set_lut = 1,
  };
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rss_config_t saved = port->rss_config;
  int user_lut = ip->rss ? ip->rss->user_lut : saved.set_lut;
  ice_aq_rss_lut_t lut;
  u8 queue_ids[ICE_RSS_MAX_QUEUES];
  u16 n_queues = ice_rss_get_queue_ids (port, queue_ids);
  vnet_dev_rv_t rv;

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
  if (port->rss_config.key_len != ICE_RSS_KEY_SIZE)
    return VNET_DEV_ERR_INVALID_DATA;
  if (ip->rss && !user_lut &&
      (ip->rss->n_queues != n_queues || clib_memcmp (ip->rss->queues, queue_ids, n_queues)))
    saved.set_lut = 0;
  if (saved.set_lut && ice_rss_validate_config (port, &saved) != VNET_DEV_OK)
    user_lut = 0;
  if ((rv = ice_rss_prepare_lut (queue_ids, n_queues, &saved, lut.entries)))
    return rv;
  clib_memcpy (config.key, port->rss_config.key, ICE_RSS_KEY_SIZE);
  for (u32 i = 0; i < ICE_RSS_LUT_SIZE; i++)
    config.lut[i] = lut.entries[i];
  if ((rv = ice_rss_profiles_init (vm, port)) || (rv = ice_rss_apply (vm, port, &config, 1)))
    {
      log_err (port->dev, "RSS initialization failed: %U", format_vnet_dev_rv, rv);
      return rv;
    }
  port->rss_config = config;
  ip->rss->user_lut = user_lut;
  ip->rss->n_queues = n_queues;
  clib_memcpy (ip->rss->queues, queue_ids, n_queues);
  return VNET_DEV_OK;
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

void
ice_rss_cleanup (vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);

  if (ip->rss)
    ice_rss_profiles_dispose (port);
}

u64
ice_rss_flow_types (vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);

  if (!ip->rss || !ip->rss->active || ip->rss->failed)
    return 0;
  return ip->rss->full_tuple_types;
}
