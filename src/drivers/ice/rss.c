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
  u16 n_queues = 0;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    if (rxq->enabled)
      {
	ASSERT (n_queues < ICE_RSS_MAX_QUEUES);
	ASSERT (rxq->queue_id < ICE_RSS_MAX_QUEUES);
	queue_ids[n_queues++] = rxq->queue_id;
      }

  return n_queues;
}

vnet_dev_rv_t
ice_rss_validate_config (const vnet_dev_rss_config_t *config)
{
  if (config->set_key && config->key_len != ICE_RSS_KEY_SIZE)
    return VNET_DEV_ERR_INVALID_DATA;
  if (config->set_lut && config->lut_len != ICE_RSS_LUT_SIZE)
    return VNET_DEV_ERR_INVALID_DATA;
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_rss_program_key (vlib_main_t *vm, vnet_dev_port_t *port, const u8 *key)
{
  ice_aq_rss_key_t aq_key = {};

  clib_memcpy (aq_key.standard_key, key, ICE_RSS_KEY_SIZE);
  return ice_aq_set_rss_key (vm, port, &aq_key);
}

vnet_dev_rv_t
ice_rss_set_config (vlib_main_t *vm, vnet_dev_port_t *port, const vnet_dev_rss_config_t *config)
{
  ice_aq_rss_lut_t aq_lut = {};
  vnet_dev_rv_t rv;

  if ((rv = ice_rss_validate_config (config)))
    return rv;

  if (config->set_key)
    {
      if ((rv = ice_rss_program_key (vm, port, config->key)))
	return rv;
      log_debug (port->dev, "programmed %u-byte RSS key", config->key_len);
    }

  if (config->set_lut)
    {
      for (u32 i = 0; i < ICE_RSS_LUT_SIZE; i++)
	aq_lut.entries[i] = config->lut[i];
      if ((rv = ice_aq_set_rss_lut (vm, port, &aq_lut)))
	{
	  if (config->set_key)
	    (void) ice_rss_program_key (vm, port, port->rss_config.key);
	  return rv;
	}
      log_debug (port->dev, "programmed %u-entry RSS LUT", config->lut_len);
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_rss_configure (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  u8 queue_ids[ICE_RSS_MAX_QUEUES];
  ice_aq_rss_lut_t lut = {};
  vnet_dev_rv_t rv;
  u16 n_queues;

  n_queues = ice_rss_get_queue_ids (port, queue_ids);
  if (n_queues <= 1)
    {
      log_debug (port->dev, "RSS not configured with %u enabled RX queue%s", n_queues,
		 n_queues == 1 ? "" : "s");
      return VNET_DEV_OK;
    }

  if ((rv = ice_rss_program_key (vm, port, port->rss_config.key)))
    return rv;

  for (u32 i = 0; i < ARRAY_LEN (lut.entries); i++)
    lut.entries[i] = queue_ids[i % n_queues];

  if ((rv = ice_aq_set_rss_lut (vm, port, &lut)))
    return rv;

  port->rss_config.lut_len = ICE_RSS_LUT_SIZE;
  port->rss_config.set_lut = 1;
  for (u32 i = 0; i < ICE_RSS_LUT_SIZE; i++)
    port->rss_config.lut[i] = lut.entries[i];

  log_debug (port->dev,
	     "programmed VSI %u RSS key (%u bytes) and LUT (%u entries) for %u RX queues",
	     ip->vsi.num, port->rss_config.key_len, ICE_RSS_LUT_SIZE, n_queues);
  return VNET_DEV_OK;
}
