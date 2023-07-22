/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>

#include <dev_ena/ena.h>
#include <dev_ena/ena_inlines.h>

#define ENA_AENQ_POLL_INTERVAL 0.2

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "ena",
  .subclass_name = "aenq",
};

void
ena_aenq_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);

  ASSERT (ed->aenq_started == 0);

  vnet_dev_dma_mem_free (vm, dev, ed->aenq.entries);
  ed->aenq.depth = 0;
}

vnet_dev_rv_t
ena_aenq_olloc (vlib_main_t *vm, vnet_dev_t *dev, u16 depth)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  u32 alloc_sz = sizeof (ena_aenq_entry_t) * depth;
  vnet_dev_rv_t rv;

  ASSERT (ed->aenq.entries == 0);

  rv =
    vnet_dev_dma_mem_alloc (vm, dev, alloc_sz, 0, (void **) &ed->aenq.entries);
  if (rv != VNET_DEV_OK)
    goto err;

  ed->aenq.depth = depth;

  return VNET_DEV_OK;
err:
  ena_aenq_free (vm, dev);
  return rv;
}

static ena_aenq_entry_t *
ena_get_next_aenq_entry (vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  u16 index = ed->aenq.head & pow2_mask (ENA_ASYNC_QUEUE_LOG2_DEPTH);
  u16 phase = 1 & (ed->aenq.head >> ENA_ASYNC_QUEUE_LOG2_DEPTH);
  ena_aenq_entry_t *e = ed->aenq.entries + index;

  if (e->phase != phase)
    return 0;

  ed->aenq.head++;

  return e;
}

static vnet_dev_rv_t
ena_aenq_poll (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_aenq_entry_t *ae;

  while ((ae = ena_get_next_aenq_entry (dev)))
    {
      ena_device_t *ed = vnet_dev_get_data (dev);
      vnet_dev_port_state_changes_t changes = {};

      if (0)
	ena_log_debug (dev,
		       "aenq: group %u syndrome %u phase %u timestamp %lu",
		       ae->group, ae->syndrome, ae->phase, ae->timestamp);

      switch (ae->group)
	{
	case ENA_AENQ_GROUP_LINK_CHANGE:
	  ena_log_debug (dev, "link_change: status %u",
			 ae->link_change.link_status);
	  changes.link_state = 1;
	  changes.change.link_state = 1;
	  foreach_vnet_dev_pool (p, dev->ports)
	    vnet_dev_port_state_change (vm, p, changes);
	  break;

	case ENA_AENQ_GROUP_NOTIFICATION:
	  ena_log_warn (dev,
			"unhandled AENQ notification received [syndrome %u]",
			ae->syndrome);
	  break;

	case ENA_AENQ_GROUP_KEEP_ALIVE:
	  if (ae->keep_alive.rx_drops || ae->keep_alive.tx_drops)
	    ena_log_debug (dev, "keep_alive: rx_drops %lu tx_drops %lu",
			   ae->keep_alive.rx_drops, ae->keep_alive.tx_drops);
	  ed->aenq.rx_drops = ae->keep_alive.rx_drops - ed->aenq.rx_drops0;
	  ed->aenq.tx_drops = ae->keep_alive.tx_drops - ed->aenq.tx_drops0;
	  ed->aenq.last_keepalive = vlib_time_now (vm);
	  break;

	default:
	  ena_log_debug (dev, "unknown aenq entry (group %u) %U", ae->group,
			 format_hexdump, ae, sizeof (*ae));
	};
    }
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ena_aenq_start (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  u16 depth = ed->aenq.depth;
  u32 alloc_sz = sizeof (ena_aenq_entry_t) * depth;

  ASSERT (ed->aenq_started == 0);
  ASSERT (ed->aq_started == 1);

  ena_reg_aenq_caps_t aenq_caps = {
    .depth = depth,
    .entry_size = sizeof (ena_aenq_entry_t),
  };

  if (ena_aq_feature_is_supported (ed, ENA_ADMIN_FEAT_ID_AENQ_CONFIG))
    {
      ena_aq_feat_aenq_config_t aenq;
      vnet_dev_rv_t rv;

      if ((rv = ena_aq_get_feature (vm, dev, ENA_ADMIN_FEAT_ID_AENQ_CONFIG,
				    &aenq)))
	{
	  ena_log_err (dev, "aenq_start: get_Feature(AENQ_CONFIG) failed");
	  return rv;
	}

      aenq.enabled_groups.link_change = 1;
      aenq.enabled_groups.fatal_error = 1;
      aenq.enabled_groups.warning = 1;
      aenq.enabled_groups.notification = 1;
      aenq.enabled_groups.keep_alive = 1;
      aenq.enabled_groups.as_u32 &= aenq.supported_groups.as_u32;
      aenq.supported_groups.as_u32 = 0;

      if ((rv = ena_aq_set_feature (vm, dev, ENA_ADMIN_FEAT_ID_AENQ_CONFIG,
				    &aenq)))
	{
	  ena_log_err (dev, "aenq_start: set_Feature(AENQ_CONFIG) failed");
	  return rv;
	}
    }

  clib_memset (ed->aenq.entries, 0, alloc_sz);
  ed->aenq.head = depth;

  ena_reg_set_dma_addr (vm, dev, ENA_REG_AENQ_BASE_LO, ENA_REG_AENQ_BASE_HI,
			ed->aenq.entries);

  ena_reg_write (dev, ENA_REG_AENQ_CAPS, &aenq_caps);
  ena_reg_write (dev, ENA_REG_AENQ_HEAD_DB, &(u32){ depth });

  ed->aenq_started = 1;

  vnet_dev_poll_dev_add (vm, dev, ENA_AENQ_POLL_INTERVAL, ena_aenq_poll);

  return VNET_DEV_OK;
}

void
ena_aenq_stop (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  if (ed->aenq_started == 1)
    {
      ena_reg_aenq_caps_t aenq_caps = {};
      vnet_dev_poll_dev_remove (vm, dev, ena_aenq_poll);
      ena_reg_write (dev, ENA_REG_AENQ_CAPS, &aenq_caps);
      ed->aenq_started = 0;
    }
}
