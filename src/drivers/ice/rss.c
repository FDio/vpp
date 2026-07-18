/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "rss",
};

const vnet_dev_rss_key_t ice_default_rss_key = {
  .key = {
    0x94, 0xff, 0xfe, 0x8c, 0x39, 0xdf, 0x01, 0xb6, 0x9e, 0x88,
    0x5f, 0xf2, 0x9c, 0x78, 0x71, 0xe0, 0xfc, 0x1b, 0x94, 0xd1,
    0xb9, 0x41, 0x06, 0x96, 0x4e, 0x5b, 0x23, 0xdf, 0x26, 0x23,
    0x0f, 0xcd, 0x32, 0x49, 0x0c, 0xa3, 0xd9, 0xa7, 0x70, 0x97,
  },
  .length = ICE_RSS_KEY_SIZE,
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
ice_rss_validate_key (const vnet_dev_rss_key_t *key)
{
  return key->length == ICE_RSS_KEY_SIZE ? VNET_DEV_OK : VNET_DEV_ERR_INVALID_DATA;
}

static vnet_dev_rv_t
ice_rss_program_key (vlib_main_t *vm, vnet_dev_port_t *port, const vnet_dev_rss_key_t *key)
{
  ice_aq_rss_key_t aq_key = {};

  clib_memcpy (aq_key.standard_key, key->key, ICE_RSS_KEY_SIZE);
  return ice_aq_set_rss_key (vm, port, &aq_key);
}

vnet_dev_rv_t
ice_rss_set_key (vlib_main_t *vm, vnet_dev_port_t *port, const vnet_dev_rss_key_t *key)
{
  u8 queue_ids[ICE_RSS_MAX_QUEUES];
  vnet_dev_rv_t rv;

  if (ice_rss_validate_key (key) != VNET_DEV_OK)
    return VNET_DEV_ERR_INVALID_DATA;
  if (ice_rss_get_queue_ids (port, queue_ids) <= 1)
    return VNET_DEV_OK;

  rv = ice_rss_program_key (vm, port, key);
  if (rv == VNET_DEV_OK)
    log_debug (port->dev, "updated %u-byte RSS key", key->length);
  return rv;
}

vnet_dev_rv_t
ice_rss_configure (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ice_dev_t *id = vnet_dev_get_data (port->dev);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  u8 queue_ids[ICE_RSS_MAX_QUEUES];
  ice_aq_rss_lut_t lut = {};
  vnet_dev_rv_t rv;
  u16 n_queues;

  n_queues = ice_rss_get_queue_ids (port, queue_ids);
  ip->rss_configured = 0;
  ip->rss_queue_count = n_queues;
  if (n_queues <= 1)
    {
      log_debug (port->dev, "RSS not configured with %u enabled RX queue%s", n_queues,
		 n_queues == 1 ? "" : "s");
      return VNET_DEV_OK;
    }

  if ((rv = ice_rss_program_key (vm, port, &port->rss_key)))
    return rv;

  for (u32 i = 0; i < ARRAY_LEN (lut.entries); i++)
    lut.entries[i] = queue_ids[i % n_queues];

  if ((rv = ice_aq_set_rss_lut (vm, port, &lut)))
    return rv;

  ip->rss_lut = lut;
  ip->rss_configured = 1;
  log_debug (port->dev,
	     "programmed VSI %u RSS key (%u bytes) and LUT (%u entries) for %u RX queues",
	     id->vsi_num, port->rss_key.length, ICE_RSS_LUT_SIZE, n_queues);
  return VNET_DEV_OK;
}
