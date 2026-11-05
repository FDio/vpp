/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "fdir",
};

static vnet_dev_rv_t
ice_fdir_xlt2 (vlib_main_t *vm, vnet_dev_t *dev, u16 vsi, u16 vsig)
{
  return ice_profile_map_vsi (vm, dev, ICE_FDIR_SECTION_XLT2, vsi, vsig);
}

static vnet_dev_rv_t
ice_fdir_vsi (vlib_main_t *vm, vnet_dev_port_t *port, int control, int enable)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_dev_t *id = vnet_dev_get_data (port->dev);
  ice_fdir_t *fd = ip->fdir;
  ice_aqc_vsi_props_t props = {};
  vnet_dev_rv_t rv;

  if (control)
    {
      props = ip->vsi.props;
      props.q_mapping[0] = id->fdir_rxq;
      props.q_mapping[1] = 1;
      props.tc_mapping[0].queue_count_log2 = 0;
      props.fd_options = 8;
      props.max_fd_fltr_dedicated = props.max_fd_fltr_shared = 0;
    }
  else
    {
      props.fd_options = enable ? 1 : 0;
      props.max_fd_fltr_dedicated = enable ? fd->guaranteed : 0;
      props.max_fd_fltr_shared = enable ? fd->shared : 0;
    }
  props.valid_sections.flow_director_section = 1;
  if (control)
    rv = ice_aq_add_vsi (vm, port->dev, &props, &fd->vsi);
  else
    rv = ice_aq_update_vsi (vm, port->dev, ip->vsi.num, &props);
  if (rv == VNET_DEV_OK && control)
    {
      fd->vsi_added = 1;
    }
  return rv;
}

static vnet_dev_rv_t
ice_fdir_rx_enable (vlib_main_t *vm, vnet_dev_t *dev, u16 queue, int enable)
{
  f64 end = vlib_time_now (vm) + 0.1;
  ice_reg_qrx_ctrl_t ctrl = { .enable_request = enable };

  ice_reg_write (dev, ICE_QRX_CTRL (queue), ctrl.as_u32);
  ice_reg_flush (dev);
  do
    {
      ctrl.as_u32 = ice_reg_read (dev, ICE_QRX_CTRL (queue));
      if (ctrl.enable_status == enable)
	return VNET_DEV_OK;
      vlib_process_suspend (vm, 1e-3);
    }
  while (vlib_time_now (vm) < end);
  return VNET_DEV_ERR_TIMEOUT;
}

static vnet_dev_rv_t
ice_fdir_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_fdir_t *fd = ip->fdir;
  ice_rxq_ctx_t rx = {
    .base = vnet_dev_get_dma_addr (vm, dev, fd->dma->rx) >> 7,
    .qlen = ICE_FDIR_RING_SIZE,
    .dbuf = 2,
    .crcstrip = 1,
    .rxmax = 256,
    .prefena = 1,
  };
  ice_txq_ctx_t tx = {
    .base = vnet_dev_get_dma_addr (vm, dev, fd->dma->tx) >> 7,
    .port_num = ip->lport,
    .pf_num = id->pf_id,
    .vmvf_type = 2,
    .src_vsi = fd->vsi,
    .qlen = ICE_FDIR_RING_SIZE,
    .legacy_int = 1,
  };
  ice_aqc_add_txq_group_t group = {
    .parent_teid = ip->tx_parent_teid,
    .num_txqs = 1,
    .txq = {
      .txq_id = id->fdir_txq,
      .info = {
	.valid_sections = 7,
	.cir_bw = { .bw_alloc = 4 },
	.eir_bw = { .bw_alloc = 4 },
      },
    },
  };
  vnet_dev_rv_t rv;

  for (u32 i = 0; i < ICE_FDIR_RING_SIZE; i++)
    fd->dma->rx[i].read.pkt_addr = vnet_dev_get_dma_addr (vm, dev, fd->dma->buffers[i]);
  ice_reg_write (dev, ICE_QRX_CTRL (id->fdir_rxq), 0);
  ice_reg_write (
    dev, ICE_QRXFLXP_CNTXT (id->fdir_rxq),
    (ice_reg_qrxflxp_cntxt_t) { .rxdid = ICE_RX_DESC_ID_FLEX_NIC, .priority = 3 }.as_u32);
  for (u32 i = 0; i < ARRAY_LEN (rx.as_u32); i++)
    ice_reg_write (dev, ICE_QRX_CONTEXT (i, id->fdir_rxq), rx.as_u32[i]);
  ice_reg_write (dev, ICE_QRX_TAIL (id->fdir_rxq), ICE_FDIR_RING_SIZE - 1);
  fd->rx_started = 1;
  if ((rv = ice_fdir_rx_enable (vm, dev, id->fdir_rxq, 1)))
    return rv;
  clib_memcpy (group.txq.txq_ctx, tx.as_u8, sizeof (group.txq.txq_ctx));
  fd->tx_started = 1;
  if ((rv = ice_aq_add_txq_group (vm, dev, &group)))
    return rv;
  ice_reg_write (dev, ICE_QTX_COMM_DBELL (id->fdir_txq), 0);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_fdir_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_fdir_t *fd;
  vnet_dev_rv_t rv;
  u16 unused = 0;
  u32 funcs = count_set_bits (id->valid_functions);
  u32 size = ice_reg_read (dev, 0x00460010);
  u16 size_mask = id->family == ICE_DEVICE_FAMILY_E810 ? 0x7fff : 0xffff;

  if (ip->fdir)
    return ip->fdir->failed ? VNET_DEV_ERR_NOT_READY : VNET_DEV_OK;
  if (id->fdir_rxq == (u16) ~0 || !funcs || !(id->valid_functions & (1 << id->pf_id)))
    return VNET_DEV_ERR_NOT_SUPPORTED;
  fd = clib_mem_alloc (sizeof (*fd));
  if (!fd)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  *fd = (ice_fdir_t) {};
  ip->fdir = fd;
  fd->mask_count = 32 / funcs;
  fd->mask_first = count_set_bits (id->valid_functions & ((1 << id->pf_id) - 1)) * fd->mask_count;
  fd->guaranteed = (size & size_mask) / funcs;
  fd->shared = (size >> 16) & size_mask;
  if (!fd->guaranteed && !fd->shared)
    {
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
      goto error;
    }
  if (fd->guaranteed)
    {
      if ((rv = ice_aq_alloc_free_resource (vm, dev, ICE_FDIR_RES_GUARANTEED, fd->guaranteed,
					    &unused, 1)))
	goto error;
      fd->guaranteed_allocated = 1;
    }
  if (fd->shared)
    {
      if ((rv = ice_aq_alloc_free_resource (vm, dev, ICE_FDIR_RES_SHARED, fd->shared, &unused, 1)))
	goto error;
      fd->shared_allocated = 1;
    }
  if ((rv = ice_aq_alloc_free_resource (vm, dev, ICE_FDIR_RES_COUNTER, 1, &fd->counter_block, 1)))
    goto error;
  fd->counter_allocated = 1;
  if (fd->counter_block >= 32)
    {
      rv = VNET_DEV_ERR_INVALID_DATA;
      goto error;
    }
  if ((rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (*fd->dma), 128, (void **) &fd->dma,
				    "Flow Director programming queues")))
    goto error;
  *fd->dma = (ice_fdir_dma_t) {};
  if ((rv = ice_fdir_vsi (vm, port, 1, 1)))
    goto error;
  if (fd->vsi >= 768 || ip->vsi.num >= 768)
    {
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
      goto error;
    }
  if ((rv = ice_aq_request_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK, ICE_AQ_RES_ACCESS_WRITE,
				     1000)))
    goto error;
  rv = ice_profile_read_xlt1 (vm, dev, ICE_FDIR_SECTION_XLT1, fd->xlt1);
  if (rv == VNET_DEV_OK)
    rv = ice_profile_find_vsig (vm, dev, ICE_FDIR_SECTION_XLT2, ICE_FDIR_SECTION_TCAM, ip->vsi.num,
				&fd->vsig, &fd->saved_vsig);
  if (rv == VNET_DEV_OK)
    {
      rv = ice_fdir_xlt2 (vm, dev, ip->vsi.num, fd->vsig);
      if (rv == VNET_DEV_OK)
	{
	  fd->mapped = 1;
	  rv = ice_fdir_xlt2 (vm, dev, fd->vsi, fd->vsig);
	}
    }
  ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);
  if (rv)
    goto error;
  fd->enabled = 1;
  if ((rv = ice_fdir_vsi (vm, port, 0, 1)))
    goto error;
  ice_reg_write (dev, ICE_PFQF_FD_ENA, 1);
  if ((rv = ice_fdir_queues (vm, port)))
    goto error;
  return VNET_DEV_OK;

error:
  log_err (dev, "Flow Director initialization failed: %U", format_vnet_dev_rv, rv);
  ice_fdir_free (vm, port);
  return rv;
}

static vnet_dev_rv_t
ice_fdir_profile_put (vlib_main_t *vm, vnet_dev_port_t *port, u32 index)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_fdir_t *fd = ip->fdir;
  ice_fdir_profile_t *profile = pool_elt_at_index (fd->profiles, index);
  vnet_dev_rv_t rv;

  if ((rv = ice_profile_release_tcam (vm, port->dev, ICE_FDIR_SECTION_TCAM, ICE_RES_FD_TCAM,
				      profile->tcam)))
    return rv;
  if (profile->allocated)
    {
      if ((rv = ice_profile_release_id (vm, port->dev, ICE_RES_FD_PROFILE, &profile->id)))
	return rv;
      profile->allocated = 0;
    }
  for (u32 i = 0; i < 32; i++)
    if (profile->masks & (1U << i))
      {
	ASSERT (fd->masks[i].references);
	if (!--fd->masks[i].references)
	  ice_reg_write (port->dev, ICE_GLQF_FDMASK (i), 0);
      }
  for (u32 i = 0; i < 256; i++)
    if (fd->ptg_owner[i] == index + 1)
      fd->ptg_owner[i] = 0;
  vec_free (profile->tcam);
  pool_put (fd->profiles, profile);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_fdir_profile_get (vlib_main_t *vm, vnet_dev_port_t *port, ice_flow_entry_t *entry)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_fdir_t *fd = ip->fdir;
  ice_flow_pattern_t *pattern = &entry->pattern;
  ice_fdir_profile_t *profile;
  u8 groups[256] = {};
  u32 n_groups = 0;
  vnet_dev_rv_t rv, cleanup_rv;
  ice_profile_fv_section_t fv = { .count = 1 };

  for (u32 i = 0; i < ICE_FDIR_PTYPE_COUNT; i++)
    if ((pattern->ptypes[i / uword_bits] & ((uword) 1 << (i % uword_bits))) && fd->xlt1[i])
      {
	if (!groups[fd->xlt1[i]])
	  n_groups++;
	groups[fd->xlt1[i]] = 1;
      }
  if (!n_groups)
    return VNET_DEV_ERR_NOT_SUPPORTED;
  pool_foreach (profile, fd->profiles)
    if (profile->n_words == pattern->n_words &&
	!clib_memcmp (profile->words, pattern->words, sizeof (pattern->words)) &&
	!clib_memcmp (profile->ptg, groups, sizeof (groups)))
      {
	entry->profile_index = profile - fd->profiles;
	profile->references++;
	return VNET_DEV_OK;
      }
  /* Each packet-type group selects one extraction sequence within a VSI. */
  for (u32 i = 0; i < 256; i++)
    if (groups[i] && fd->ptg_owner[i])
      return VNET_DEV_ERR_NOT_SUPPORTED;
  pool_get_zero (fd->profiles, profile);
  entry->profile_index = profile - fd->profiles;
  profile->n_words = pattern->n_words;
  clib_memcpy (profile->words, pattern->words, sizeof (pattern->words));
  if ((rv = ice_aq_alloc_free_resource (vm, port->dev, ICE_RES_FD_PROFILE, 1, &profile->id, 1)))
    goto error;
  profile->allocated = 1;
  if (profile->id >= 128)
    {
      rv = VNET_DEV_ERR_INVALID_DATA;
      goto error;
    }
  fv.offset = profile->id;
  for (u32 i = 0; i < ICE_FDIR_MAX_WORDS; i++)
    fv.words[i] = (ice_profile_fv_t) { .protocol = 255, .offset = 511 };
  for (u32 i = 0; i < pattern->n_words; i++)
    {
      ice_flow_word_t *word = pattern->words + i;
      u32 index = ICE_FDIR_MAX_WORDS - 1 - i;
      fv.words[index] = (ice_profile_fv_t) { .protocol = word->protocol, .offset = word->offset };
      if (word->mask != 0xffff)
	{
	  u32 m, unused = ~0U;
	  for (m = fd->mask_first; m < fd->mask_first + fd->mask_count; m++)
	    {
	      if (fd->masks[m].references && fd->masks[m].word == index &&
		  fd->masks[m].mask == word->mask)
		break;
	      if (!fd->masks[m].references && unused == ~0U)
		unused = m;
	    }
	  if (m == fd->mask_first + fd->mask_count)
	    m = unused;
	  if (m == ~0U)
	    {
	      rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	      goto error;
	    }
	  fd->masks[m].word = index;
	  fd->masks[m].mask = word->mask;
	  fd->masks[m].references++;
	  profile->masks |= 1U << m;
	  ice_reg_write (port->dev, ICE_GLQF_FDMASK (m), index | ((u32) word->mask << 16));
	}
    }
  for (u32 i = 0; i < ICE_FDIR_MAX_WORDS / 4; i++)
    {
      u32 inset = ice_profile_inset_word (i, pattern->n_words, ICE_FDIR_MAX_WORDS);
      u32 swap = 0;

      for (u32 j = 0; j < 4; j++)
	if (inset & (0xffU << (j * 8)))
	  swap |= (0x80U | (i * 4 + j)) << (j * 8);
      ice_reg_write (port->dev, ICE_GLQF_FDINSET (profile->id, i), inset);
      ice_reg_write (port->dev, ICE_GLQF_FDSWAP (profile->id, i), swap);
    }
  ice_reg_write (port->dev, ICE_GLQF_FDMASK_SEL (profile->id), profile->masks);
  if ((rv = ice_profile_section (vm, port->dev, ICE_FDIR_SECTION_FV, &fv, sizeof (fv), 0)))
    goto error;
  for (u32 i = 0; i < 256; i++)
    if (groups[i])
      {
	u16 address = 0;
	if ((rv = ice_aq_alloc_free_resource (vm, port->dev, ICE_RES_FD_TCAM, 1, &address, 1)))
	  goto error;
	vec_add1 (profile->tcam, address);
	if ((rv = ice_profile_write_tcam (vm, port->dev, ICE_FDIR_SECTION_TCAM, address,
					  profile->id, i, fd->vsig, 1)))
	  goto error;
	profile->ptg[i] = 1;
	fd->ptg_owner[i] = entry->profile_index + 1;
      }
  profile->references = 1;
  return VNET_DEV_OK;

error:
  cleanup_rv = ice_fdir_profile_put (vm, port, entry->profile_index);
  if (cleanup_rv)
    {
      fd->failed = 1;
      log_err (port->dev, "Flow Director profile rollback failed: %U", format_vnet_dev_rv,
	       cleanup_rv);
    }
  return rv;
}

static vnet_dev_rv_t
ice_fdir_program (vlib_main_t *vm, vnet_dev_port_t *port, ice_flow_entry_t *entry, int remove)
{
  vnet_dev_t *dev = port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_fdir_t *fd = ip->fdir;
  ice_fdir_desc_t descriptor = {
    .dtype = 8,
    .remove = remove,
    .vsi = ip->vsi.num,
    .completion_report = 2,
    .space = fd->guaranteed ? (fd->shared ? 2 : 0) : 1,
    .counter_enable = 1,
    .counter = entry->counter,
    .queue = entry->queue,
    .queue_region = entry->queue_region,
    .queue_priority = entry->queue_priority,
    .drop = entry->drop,
  };
  u16 tx_slot = fd->tx_tail, rx_slot = fd->rx_head;
  ice_tx_desc_t *packet_desc = fd->dma->tx + tx_slot + 1;
  ice_rx_desc_t *completion = fd->dma->rx + rx_slot;
  f64 end = vlib_time_now (vm) + 0.1;
  u64 status;

  if (fd->failed)
    return VNET_DEV_ERR_NOT_READY;
  clib_memcpy (fd->dma->packet, entry->pattern.packet, ICE_FDIR_PACKET_SIZE);
  fd->dma->tx[tx_slot] =
    (ice_tx_desc_t) { .buf_addr = descriptor.qword[0], .cmd.as_u64 = descriptor.qword[1] };
  *packet_desc = (ice_tx_desc_t) {
    .buf_addr = vnet_dev_get_dma_addr (vm, dev, fd->dma->packet),
    .cmd = { .end_of_packet = 1,
	     .report_status = 1,
	     .dummy = 1,
	     .buffer_size = ICE_FDIR_PACKET_SIZE },
  };
  CLIB_MEMORY_STORE_BARRIER ();
  fd->tx_tail = (tx_slot + 2) % ICE_FDIR_RING_SIZE;
  ice_reg_write (dev, ICE_QTX_COMM_DBELL (id->fdir_txq), fd->tx_tail);
  do
    {
      status = __atomic_load_n (&completion->qword[1], __ATOMIC_ACQUIRE);
      if ((status & 1) && (__atomic_load_n (&packet_desc->cmd.as_u64, __ATOMIC_ACQUIRE) & 0xf) ==
			    ICE_TX_DESC_TYPE_DONE)
	break;
      vlib_process_suspend (vm, 1e-5);
    }
  while (vlib_time_now (vm) < end);
  if (!(status & 1) || (packet_desc->cmd.as_u64 & 0xf) != ICE_TX_DESC_TYPE_DONE)
    {
      fd->failed = 1;
      log_err (dev, "Flow Director programming timeout; programming queues quarantined");
      return VNET_DEV_ERR_TIMEOUT;
    }
  if ((completion->qword[0] & 0xff) != 0x40 || ((status >> 1) & 3) != remove)
    {
      fd->failed = 1;
      return VNET_DEV_ERR_INVALID_DATA;
    }
  *completion = (ice_rx_desc_t) {
    .read.pkt_addr = vnet_dev_get_dma_addr (vm, dev, fd->dma->buffers[rx_slot]),
  };
  CLIB_MEMORY_STORE_BARRIER ();
  ice_reg_write (dev, ICE_QRX_TAIL (id->fdir_rxq), rx_slot);
  fd->rx_head = (rx_slot + 1) % ICE_FDIR_RING_SIZE;
  if (status & 0x30)
    {
      log_err (dev, "Flow Director %s failed: status 0x%lx", remove ? "remove" : "add", status);
      return status & 0x20 ? VNET_DEV_ERR_NOT_SUPPORTED : VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }
  return VNET_DEV_OK;
}

u64
ice_fdir_counter_read (vnet_dev_port_t *port, u16 counter)
{
  u32 reg = ICE_GLSTAT_FD_CNT (counter);
  u32 low, high, check;

  do
    {
      high = ice_reg_read (port->dev, reg + 4) & 0xff;
      low = ice_reg_read (port->dev, reg);
      check = ice_reg_read (port->dev, reg + 4) & 0xff;
    }
  while (high != check);
  return ((u64) high << 32) | low;
}

static void
ice_fdir_profile_release (vlib_main_t *vm, vnet_dev_port_t *port, u32 index)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_fdir_t *fd = ip->fdir;
  ice_fdir_profile_t *profile = pool_elt_at_index (fd->profiles, index);
  vnet_dev_rv_t rv;

  ASSERT (profile->references);
  if (--profile->references)
    return;
  rv = ice_aq_request_resource (vm, port->dev, ICE_AQ_RES_ID_CHANGE_LOCK, ICE_AQ_RES_ACCESS_WRITE,
				1000);
  if (rv == VNET_DEV_OK)
    {
      rv = ice_fdir_profile_put (vm, port, index);
      ice_aq_release_resource (vm, port->dev, ICE_AQ_RES_ID_CHANGE_LOCK);
    }
  if (rv)
    {
      fd->failed = 1;
      log_err (port->dev, "Flow Director profile release failed: %U", format_vnet_dev_rv, rv);
    }
}

vnet_dev_rv_t
ice_fdir_add (vlib_main_t *vm, vnet_dev_port_t *port, ice_flow_entry_t *entry)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_fdir_t *fd;
  vnet_dev_rv_t rv;
  u32 slot;
  ice_flow_entry_t *other;

  if ((rv = ice_fdir_init (vm, port)))
    return rv;
  fd = ip->fdir;
  for (slot = 0; slot < ICE_FDIR_COUNTERS; slot++)
    if (!(fd->counters[slot / uword_bits] & ((uword) 1 << (slot % uword_bits))))
      break;
  if (slot == ICE_FDIR_COUNTERS)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  if ((rv = ice_aq_request_resource (vm, port->dev, ICE_AQ_RES_ID_CHANGE_LOCK,
				     ICE_AQ_RES_ACCESS_WRITE, 1000)))
    return rv;
  rv = ice_fdir_profile_get (vm, port, entry);
  ice_aq_release_resource (vm, port->dev, ICE_AQ_RES_ID_CHANGE_LOCK);
  if (rv)
    return rv;
  pool_foreach (other, ip->flows)
    if (other != entry && other->installed && other->profile_index == entry->profile_index &&
	!clib_memcmp (other->pattern.values, entry->pattern.values, sizeof (entry->pattern.values)))
      {
	ice_fdir_profile_release (vm, port, entry->profile_index);
	return VNET_DEV_ERR_ALREADY_EXISTS;
      }
  entry->counter = fd->counter_block * ICE_FDIR_COUNTERS + slot;
  entry->counter_base = ice_fdir_counter_read (port, entry->counter);
  fd->counters[slot / uword_bits] |= (uword) 1 << (slot % uword_bits);
  rv = ice_fdir_program (vm, port, entry, 0);
  if (rv == VNET_DEV_OK)
    entry->installed = 1;
  else if (!fd->failed)
    {
      fd->counters[slot / uword_bits] &= ~((uword) 1 << (slot % uword_bits));
      ice_fdir_profile_release (vm, port, entry->profile_index);
    }
  else
    entry->pending = 1;
  return rv;
}

vnet_dev_rv_t
ice_fdir_del (vlib_main_t *vm, vnet_dev_port_t *port, ice_flow_entry_t *entry)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_fdir_t *fd = ip->fdir;
  u32 slot = entry->counter % ICE_FDIR_COUNTERS;
  vnet_dev_rv_t rv = ice_fdir_program (vm, port, entry, 1);

  if (rv)
    return rv;
  fd->counters[slot / uword_bits] &= ~((uword) 1 << (slot % uword_bits));
  ice_fdir_profile_release (vm, port, entry->profile_index);
  entry->installed = 0;
  return VNET_DEV_OK;
}

void
ice_fdir_free (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_fdir_t *fd = ip->fdir;
  vnet_dev_rv_t rv;
  u16 unused = 0;
  if (!fd)
    return;
  if (fd->enabled && (rv = ice_fdir_vsi (vm, port, 0, 0)))
    goto quarantine;
  if (fd->tx_started)
    {
      ice_aqc_dis_txq_item_t item = {
	.parent_teid = ip->tx_parent_teid,
	.num_queues = 1,
	.queue_id = id->fdir_txq,
      };
      rv = ice_aq_dis_txq_item (vm, dev, &item);
      if (rv)
	goto quarantine;
      fd->tx_started = 0;
    }
  if (fd->rx_started)
    {
      if ((rv = ice_fdir_rx_enable (vm, dev, id->fdir_rxq, 0)))
	goto quarantine;
      fd->rx_started = 0;
    }
  if (fd->mapped || pool_elts (fd->profiles))
    {
      rv =
	ice_aq_request_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK, ICE_AQ_RES_ACCESS_WRITE, 1000);
      if (rv)
	goto quarantine;
      if (fd->mapped)
	{
	  rv = ice_fdir_xlt2 (vm, dev, ip->vsi.num, fd->saved_vsig);
	  if (rv == VNET_DEV_OK)
	    rv = ice_fdir_xlt2 (vm, dev, fd->vsi, 0);
	  if (rv)
	    {
	      ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);
	      goto quarantine;
	    }
	}
      while (pool_elts (fd->profiles))
	{
	  u32 index = pool_get_first_index (fd->profiles);
	  rv = ice_fdir_profile_put (vm, port, index);
	  if (rv)
	    break;
	}
      ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);
      if (rv)
	goto quarantine;
    }
  if (fd->vsi_added)
    {
      if ((rv = ice_aq_free_vsi (vm, dev, fd->vsi)))
	goto quarantine;
      fd->vsi_added = 0;
    }
  if (fd->counter_allocated)
    {
      if ((rv =
	     ice_aq_alloc_free_resource (vm, dev, ICE_FDIR_RES_COUNTER, 1, &fd->counter_block, 0)))
	goto quarantine;
      fd->counter_allocated = 0;
    }
  if (fd->guaranteed_allocated)
    {
      if ((rv = ice_aq_alloc_free_resource (vm, dev, ICE_FDIR_RES_GUARANTEED, fd->guaranteed,
					    &unused, 0)))
	goto quarantine;
      fd->guaranteed_allocated = 0;
    }
  if (fd->shared_allocated)
    {
      if ((rv = ice_aq_alloc_free_resource (vm, dev, ICE_FDIR_RES_SHARED, fd->shared, &unused, 0)))
	goto quarantine;
      fd->shared_allocated = 0;
    }
  if (fd->dma)
    vnet_dev_dma_mem_free (vm, dev, fd->dma);
  ice_reg_write (dev, ICE_PFQF_FD_ENA, 0);
  pool_free (fd->profiles);
  clib_mem_free (fd);
  ip->fdir = 0;
  return;

quarantine:
  fd->failed = 1;
  log_err (dev, "Flow Director shutdown failed (%U); retaining DMA resources until reset",
	   format_vnet_dev_rv, rv);
}

/* The device layer closes the PCI device before releasing registered DMA
 * allocations. This drops CPU bookkeeping retained after failed shutdown. */
void
ice_fdir_cleanup (vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_fdir_t *fd = ip->fdir;
  ice_fdir_profile_t *profile;

  if (!fd)
    return;
  pool_foreach (profile, fd->profiles)
    vec_free (profile->tcam);
  pool_free (fd->profiles);
  clib_mem_free (fd);
  ip->fdir = 0;
}

u16
ice_fdir_control_vsi (vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  return ip->fdir && ip->fdir->vsi_added ? ip->fdir->vsi : (u16) ~0;
}
