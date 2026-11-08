/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "adminq",
};

struct ice_aq_mem
{
  ice_aq_desc_t atq[ICE_AQ_LEN];
  ice_aq_desc_t arq[ICE_AQ_LEN];
  u8 atq_buf[ICE_AQ_LEN][ICE_AQ_BUF_SIZE];
  u8 arq_buf[ICE_AQ_LEN][ICE_AQ_BUF_SIZE];
};

vnet_dev_rv_t
ice_aq_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (ice_aq_mem_t), 4096,
					     (void **) &id->aq, "AdminQ rings and buffers");

  if (rv != VNET_DEV_OK)
    log_err (dev, "AdminQ DMA allocation failed (%u bytes): %U", sizeof (ice_aq_mem_t),
	     format_vnet_dev_rv, rv);
  else
    log_debug (dev, "allocated at %p: %u entries per ring, %u-byte buffers", id->aq, ICE_AQ_LEN,
	       ICE_AQ_BUF_SIZE);

  return rv;
}

void
ice_aq_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);

  if (id->aq)
    {
      log_debug (dev, "freeing DMA memory at %p", id->aq);
      vnet_dev_dma_mem_free (vm, dev, id->aq);
      id->aq = 0;
    }

  vec_free (id->aq_events);
  id->aq_event_count = 0;
}

static void
ice_aq_arq_desc_init (vlib_main_t *vm, vnet_dev_t *dev, u16 slot)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_aq_mem_t *aq = id->aq;
  ice_aq_desc_t *d;
  u64 pa;

  if (PREDICT_FALSE (aq == 0))
    return;

  d = aq->arq + slot;
  pa = vnet_dev_get_dma_addr (vm, dev, aq->arq_buf[slot]);

  *d = (ice_aq_desc_t) {
    .flags = { .buffer = 1, .large_buffer = 1 },
    .datalen = ICE_AQ_BUF_SIZE,
  };
  d->params.indirect.addr_high = pa >> 32;
  d->params.indirect.addr_low = pa;
}

static vnet_dev_rv_t
ice_aq_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  u64 pa;

  log_debug (dev, "initializing with %u-entry rings", ICE_AQ_LEN);
  clib_memset (id->aq, 0, sizeof (*id->aq));
  ice_reg_write (dev, ICE_PF_FW_ATQLEN, 0);
  ice_reg_write (dev, ICE_PF_FW_ARQLEN, 0);
  id->atq_next = id->arq_next = 0;

  pa = vnet_dev_get_dma_addr (vm, dev, id->aq->atq);
  ice_reg_write (dev, ICE_PF_FW_ATQH, 0);
  ice_reg_write (dev, ICE_PF_FW_ATQT, 0);
  ice_reg_write (dev, ICE_PF_FW_ATQBAL, pa);
  ice_reg_write (dev, ICE_PF_FW_ATQBAH, pa >> 32);
  ice_reg_write (dev, ICE_PF_FW_ATQLEN,
		 (ice_reg_aq_len_t) { .length = ICE_AQ_LEN, .enable = 1 }.as_u32);

  pa = vnet_dev_get_dma_addr (vm, dev, id->aq->arq);
  ice_reg_write (dev, ICE_PF_FW_ARQH, 0);
  ice_reg_write (dev, ICE_PF_FW_ARQT, 0);
  ice_reg_write (dev, ICE_PF_FW_ARQBAL, pa);
  ice_reg_write (dev, ICE_PF_FW_ARQBAH, pa >> 32);

  for (u16 i = 0; i < ICE_AQ_LEN; i++)
    ice_aq_arq_desc_init (vm, dev, i);

  ice_reg_write (dev, ICE_PF_FW_ARQLEN,
		 (ice_reg_aq_len_t) { .length = ICE_AQ_LEN, .enable = 1 }.as_u32);
  ice_reg_write (dev, ICE_PF_FW_ARQT, ICE_AQ_LEN - 1);
  ice_reg_flush (dev);

  u64 atq_pa = vnet_dev_get_dma_addr (vm, dev, id->aq->atq);
  ice_reg_aq_len_t atq_len = { .as_u32 = ice_reg_read (dev, ICE_PF_FW_ATQLEN) };

  if (ice_reg_read (dev, ICE_PF_FW_ATQBAL) != (u32) atq_pa ||
      ice_reg_read (dev, ICE_PF_FW_ATQBAH) != (u32) (atq_pa >> 32) ||
      atq_len.length != ICE_AQ_LEN || !atq_len.enable)
    {
      log_err (dev, "AdminQ register configuration did not latch");
      return VNET_DEV_ERR_DEVICE_NO_REPLY;
    }

  log_debug (dev, "initialized: ATQ DMA 0x%lx ARQ DMA 0x%lx entries %u", atq_pa, pa, ICE_AQ_LEN);
  id->aq_failed = 0;
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_aq_send (vlib_main_t *vm, vnet_dev_t *dev, ice_aq_desc_t *desc, void *data, u16 len,
	     f64 timeout)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  u16 slot = id->atq_next;
  ice_aq_desc_t *d = id->aq->atq + slot;
  u8 *buf = id->aq->atq_buf[slot];
  f64 delay = 1e-5;
  f64 start = vlib_time_now (vm);

  if (id->aq_failed)
    return VNET_DEV_ERR_NOT_READY;

  if (len > ICE_AQ_BUF_SIZE)
    {
      log_debug (dev, "%U buffer len %u exceeds maximum %u", format_ice_adminq_opcode, desc->opcode,
		 len, ICE_AQ_BUF_SIZE);
      return VNET_DEV_ERR_INVALID_DATA;
    }

  if (desc->opcode != ICE_AQC_OP_GET_LINK_STATUS)
    log_debug (dev, "submit %U slot %u flags %U len %u timeout %.3fs params %U",
	       format_ice_adminq_opcode, desc->opcode, slot, format_ice_aq_flags,
	       desc->flags.as_u16, len, timeout, format_hex_bytes, &desc->params,
	       sizeof (desc->params));

  if (len && desc->flags.read)
    log_debug_noisy (dev, "%U request payload:\n%U", format_ice_adminq_opcode, desc->opcode,
		     format_hexdump, data, len);

  *d = *desc;
  d->flags.suppress_interrupt = 1;

  if (len)
    {
      u64 pa = vnet_dev_get_dma_addr (vm, dev, buf);
      d->flags.buffer = 1;

      if (len > ICE_AQ_LARGE_BUFFER_THRESHOLD)
	d->flags.large_buffer = 1;

      d->datalen = len;
      d->params.indirect.addr_high = pa >> 32;
      d->params.indirect.addr_low = pa;
      clib_memcpy_fast (buf, data, len);
    }

  id->atq_next = (slot + 1) & (ICE_AQ_LEN - 1);
  ice_reg_write (dev, ICE_PF_FW_ATQT, id->atq_next);
  ice_reg_flush (dev);

  while (1)
    {
      ice_aq_desc_flags_t flags;
      flags.as_u16 = __atomic_load_n (&d->flags.as_u16, __ATOMIC_ACQUIRE);

      if (flags.done && flags.complete)
	break;

      if (vlib_time_now (vm) - start > timeout)
	{
	  id->aq_failed = 1;
	  log_err (dev,
		   "AdminQ timeout for %U slot %u after %.6fs: flags %U "
		   "retval %u ATQ head %u tail %u length-reg 0x%08x",
		   format_ice_adminq_opcode, d->opcode, slot, vlib_time_now (vm) - start,
		   format_ice_aq_flags, flags.as_u16, d->retval, ice_reg_read (dev, ICE_PF_FW_ATQH),
		   ice_reg_read (dev, ICE_PF_FW_ATQT), ice_reg_read (dev, ICE_PF_FW_ATQLEN));
	  return VNET_DEV_ERR_TIMEOUT;
	}

      vlib_process_suspend (vm, delay);
      delay = clib_min (delay * 2, 1e-2);
    }

  *desc = *d;

  if (len)
    clib_memcpy_fast (data, buf, len);

  if (d->opcode != ICE_AQC_OP_GET_LINK_STATUS || d->flags.error || d->retval)
    log_debug (dev,
	       "complete %U slot %u after %.6fs: flags %U len %u "
	       "rv %u params %U",
	       format_ice_adminq_opcode, d->opcode, slot, vlib_time_now (vm) - start,
	       format_ice_aq_flags, d->flags.as_u16, d->datalen, d->retval, format_hex_bytes,
	       &d->params, sizeof (d->params));

  if (len)
    log_debug_noisy (dev, "%U response payload:\n%U", format_ice_adminq_opcode, d->opcode,
		     format_hexdump, data, clib_min (d->datalen, len));

  if (d->flags.error || d->retval)
    {
      if (d->opcode == ICE_AQC_OP_CLEAR_PXE && d->retval == ICE_AQ_RC_EEXIST)
	log_debug (dev, "%U reports existing state", format_ice_adminq_opcode, d->opcode);
      else
	log_err (dev, "AdminQ %U failed: slot %u flags %U retval %u length %u",
		 format_ice_adminq_opcode, d->opcode, slot, format_ice_aq_flags, d->flags.as_u16,
		 d->retval, d->datalen);

      return VNET_DEV_ERR_DEVICE_NO_REPLY;
    }

  id->aq_alive = 1;
  return VNET_DEV_OK;
}

static void
ice_aq_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);

  ice_aq_events_stop (vm, dev);

  if (id->aq_alive)
    {
      log_debug (dev, "shutting down");
      ice_aq_desc_t d = { .opcode = ICE_AQC_OP_Q_SHUTDOWN };
      d.params.q_shutdown.driver_unloading = 1;
      (void) ice_aq_send (vm, dev, &d, 0, 0, 0.5);
    }

  ice_reg_write (dev, ICE_PF_FW_ATQLEN, 0);
  ice_reg_write (dev, ICE_PF_FW_ARQLEN, 0);
  id->aq_alive = 0;
  log_debug (dev, "stopped");
}

static vnet_dev_rv_t
ice_aq_get_switch_config (vlib_main_t *vm, vnet_dev_t *dev, ice_port_t *ip, u16 *sw_id)
{
  u8 data[ICE_AQ_BUF_SIZE] = {};
  ice_aq_desc_t d = { .opcode = ICE_AQC_OP_GET_SW_CFG };
  vnet_dev_rv_t rv;

  rv = ice_aq_send (vm, dev, &d, data, sizeof (data), 1.0);
  if (rv)
    return rv;

  ice_aqc_sw_cfg_elem_t *e = (void *) data;

  for (u16 i = 0; i < d.params.sw_cfg.num_elems; i++)
    if (e[i].vsi_port.type == ICE_AQC_SW_CFG_PHYS_PORT)
      {
	ip->lport = e[i].vsi_port.number;
	*sw_id = e[i].swid;
	log_debug (dev, "switch cfg: logical port %u switch %u", ip->lport, *sw_id);
	return VNET_DEV_OK;
      }

  log_err (dev, "physical port not present in switch configuration");
  return VNET_DEV_ERR_DEVICE_NO_REPLY;
}

static vnet_dev_rv_t
ice_aq_get_mac (vlib_main_t *vm, vnet_dev_t *dev, u8 *default_mac)
{
  ice_aqc_mac_read_resp_t data[2] = {};
  ice_aq_desc_t d = { .opcode = ICE_AQC_OP_MANAGE_MAC_READ };
  vnet_dev_rv_t rv;

  rv = ice_aq_send (vm, dev, &d, data, sizeof (data), 1.0);
  if (rv)
    return rv;

  for (u8 i = 0; i < d.params.mac_read.num_addr; i++)
    if (data[i].addr_type == ICE_AQC_MAC_ADDR_TYPE_LAN)
      {
	clib_memcpy (default_mac, data[i].mac_addr, 6);
	log_info (dev, "default MAC address %U", format_ethernet_address, default_mac);
	return VNET_DEV_OK;
      }

  return VNET_DEV_ERR_DEVICE_NO_REPLY;
}

static vnet_dev_rv_t
ice_aq_get_tx_parent (vlib_main_t *vm, vnet_dev_t *dev, ice_port_t *ip)
{
  u8 data[ICE_AQ_BUF_SIZE] = {};
  ice_aq_desc_t d = { .opcode = ICE_AQC_OP_GET_DFLT_TOPO };
  vnet_dev_rv_t rv;

  d.params.topology.port_num = ip->lport;

  rv = ice_aq_send (vm, dev, &d, data, sizeof (data), 1.0);
  if (rv)
    return rv;

  if (d.params.topology.num_branches == 0)
    return VNET_DEV_ERR_DEVICE_NO_REPLY;

  ice_aqc_topo_branch_t *branch = (void *) data;
  u16 n = clib_min (branch->num_elems, (u16) ARRAY_LEN (branch->elem));

  if (n == 0)
    return VNET_DEV_ERR_DEVICE_NO_REPLY;

  if (n > 1 && branch->elem[n - 1].data.elem_type == ICE_AQC_SCHED_ELEM_LEAF)
    n--;

  ip->tx_parent_teid = branch->elem[n - 1].node_teid;
  log_debug (dev, "TX topology: %u branches, parent TEID %u", d.params.topology.num_branches,
	     ip->tx_parent_teid);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_aq_configure_vsi (vlib_main_t *vm, vnet_dev_t *dev, ice_port_t *ip, u16 sw_id, u16 rxq_count)
{
  ice_aqc_vsi_props_t props = {
    .valid_sections = {
      .switch_section = 1,
      .security_section = 1,
      .vlan_section = 1,
      .rxq_map_section = 1,
      .queue_option_section = 1,
    },
    .sw_id = sw_id,
    .sw_flags = {
      .allow_loopback = 1,
      .source_prune = 1,
    },
    .sw_flags2 = { .lan_enable = 1 },
    .sec_flags = { .allow_dest_override = 1 },
    .inner_vlan_flags = {
      .tx_mode = ICE_VSI_VLAN_TX_ACCEPT_ALL,
      .egress_mode = ICE_VSI_VLAN_EGRESS_KEEP,
    },
    .q_mapping = { 0, rxq_count },
    .tc_mapping = { { .queue_count_log2 = max_log2 (rxq_count) } },
  };

  vnet_dev_rv_t rv = ice_aq_add_vsi (vm, dev, &props, &ip->vsi.num);
  if (rv)
    return rv;

  ip->vsi.props = props;
  ip->vsi.added = 1;
  log_debug (dev, "created VSI %u", ip->vsi.num);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_aq_add_vsi (vlib_main_t *vm, vnet_dev_t *dev, ice_aqc_vsi_props_t *props, u16 *vsi)
{
  ice_aq_desc_t d = {
    .flags.read = 1,
    .opcode = ICE_AQC_OP_ADD_VSI,
    .params.vsi.vsi_flags.type = ICE_AQ_VSI_TYPE_PF,
  };
  vnet_dev_rv_t rv = ice_aq_send (vm, dev, &d, props, sizeof (*props), 1.0);

  if (rv == VNET_DEV_OK)
    *vsi = d.params.vsi.vsi_num.number;

  return rv;
}

vnet_dev_rv_t
ice_aq_get_vsi (vlib_main_t *vm, vnet_dev_t *dev, u16 vsi, ice_aqc_vsi_props_t *props)
{
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_GET_VSI,
    .params.vsi.vsi_num = { .number = vsi, .valid = 1, },
  };
  vnet_dev_rv_t rv = ice_aq_send (vm, dev, &d, props, sizeof (*props), 1.0);

  if (rv == VNET_DEV_OK && d.datalen != sizeof (*props))
    return VNET_DEV_ERR_INVALID_DATA;

  return rv;
}

vnet_dev_rv_t
ice_aq_free_vsi (vlib_main_t *vm, vnet_dev_t *dev, u16 vsi)
{
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_FREE_VSI,
    .params.vsi.vsi_num = { .number = vsi, .valid = 1, },
  };

  return ice_aq_send (vm, dev, &d, 0, 0, 1.0);
}

vnet_dev_rv_t
ice_aq_upload_section (vlib_main_t *vm, vnet_dev_t *dev, void *buffer, u16 length)
{
  ice_aq_desc_t d = {
    .flags.read = 1,
    .opcode = ICE_AQC_OP_UPLOAD_SECTION,
  };

  return ice_aq_send (vm, dev, &d, buffer, length, 1.0);
}

vnet_dev_rv_t
ice_aq_add_txq_group (vlib_main_t *vm, vnet_dev_t *dev, ice_aqc_add_txq_group_t *group)
{
  ice_aq_desc_t d = {
    .flags.read = 1,
    .opcode = ICE_AQC_OP_ADD_TXQS,
    .params.add_txqs.num_qgrps = 1,
  };

  return ice_aq_send (vm, dev, &d, group, sizeof (*group), 1.0);
}

vnet_dev_rv_t
ice_aq_dis_txq_item (vlib_main_t *vm, vnet_dev_t *dev, ice_aqc_dis_txq_item_t *item)
{
  ice_aq_desc_t d = {
    .flags.read = 1,
    .opcode = ICE_AQC_OP_DIS_TXQS,
    .params.disable_txqs = {
      .command_type.flush_pipe = 1,
      .num_entries = 1,
      .vmvf_and_timeout.timeout = 5,
    },
  };

  return ice_aq_send (vm, dev, &d, item, sizeof (*item), 1.0);
}

vnet_dev_rv_t
ice_aq_alloc_free_resource (vlib_main_t *vm, vnet_dev_t *dev, u16 type, u16 count, u16 *index,
			    int alloc)
{
  ice_aqc_resource_t resource = { .type = type, .count = count, .index = *index };
  ice_aq_desc_t d = {
    .flags = { .read = 1 },
    .opcode = alloc ? ICE_AQC_OP_ALLOC_RESOURCES : ICE_AQC_OP_FREE_RESOURCES,
  };
  vnet_dev_rv_t rv;

  d.params.alloc_free_resources.num_entries = 1;

  if (alloc && (type == ICE_RES_RSS_PROFILE || type == ICE_RES_RSS_TCAM))
    resource.ignore_index = 1;

  rv = ice_aq_send (vm, dev, &d, &resource, sizeof (resource), 1.0);

  if (rv == VNET_DEV_OK && alloc)
    *index = resource.index;

  return rv;
}

static vnet_dev_rv_t
ice_aq_rss_key (vlib_main_t *vm, vnet_dev_port_t *port, ice_aq_rss_key_t *key, int set)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_aq_desc_t d = {
    .flags.read = set,
    .opcode = set ? ICE_AQC_OP_SET_RSS_KEY : ICE_AQC_OP_GET_RSS_KEY,
    .params.rss_key.vsi_id = { .vsi_id = ip->vsi.num, .valid = 1 },
  };
  vnet_dev_rv_t rv = ice_aq_send (vm, port->dev, &d, key, sizeof (*key), 1.0);

  if (rv == VNET_DEV_OK && !set && d.datalen != sizeof (*key))
    return VNET_DEV_ERR_INVALID_DATA;

  return rv;
}

static vnet_dev_rv_t
ice_aq_rss_lut (vlib_main_t *vm, vnet_dev_port_t *port, ice_aq_rss_lut_t *lut, int set)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_aq_desc_t d = {
    .flags.read = set,
    .opcode = set ? ICE_AQC_OP_SET_RSS_LUT : ICE_AQC_OP_GET_RSS_LUT,
    .params.rss_lut.vsi_id = { .vsi_id = ip->vsi.num, .valid = 1 },
  };
  vnet_dev_rv_t rv = ice_aq_send (vm, port->dev, &d, lut, sizeof (*lut), 1.0);

  if (rv == VNET_DEV_OK && !set && d.datalen != sizeof (*lut))
    return VNET_DEV_ERR_INVALID_DATA;

  return rv;
}

vnet_dev_rv_t
ice_aq_get_rss_key (vlib_main_t *vm, vnet_dev_port_t *port, ice_aq_rss_key_t *key)
{
  return ice_aq_rss_key (vm, port, key, 0);
}

vnet_dev_rv_t
ice_aq_set_rss_key (vlib_main_t *vm, vnet_dev_port_t *port, const ice_aq_rss_key_t *key)
{
  ice_aq_rss_key_t data = *key;
  return ice_aq_rss_key (vm, port, &data, 1);
}

vnet_dev_rv_t
ice_aq_get_rss_lut (vlib_main_t *vm, vnet_dev_port_t *port, ice_aq_rss_lut_t *lut)
{
  return ice_aq_rss_lut (vm, port, lut, 0);
}

vnet_dev_rv_t
ice_aq_set_rss_lut (vlib_main_t *vm, vnet_dev_port_t *port, const ice_aq_rss_lut_t *lut)
{
  ice_aq_rss_lut_t data = *lut;
  return ice_aq_rss_lut (vm, port, &data, 1);
}

vnet_dev_rv_t
ice_aq_request_resource (vlib_main_t *vm, vnet_dev_t *dev, u16 resource_id, u16 access_type,
			 u32 timeout_ms)
{
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_REQUEST_RESOURCE,
  };

  d.params.resource.resource_id = resource_id;
  d.params.resource.access_type = access_type;
  d.params.resource.timeout = timeout_ms;
  return ice_aq_send (vm, dev, &d, 0, 0, 1.0);
}

vnet_dev_rv_t
ice_aq_release_resource (vlib_main_t *vm, vnet_dev_t *dev, u16 resource_id)
{
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_RELEASE_RESOURCE,
  };

  d.params.resource.resource_id = resource_id;
  return ice_aq_send (vm, dev, &d, 0, 0, 1.0);
}

vnet_dev_rv_t
ice_aq_use_active_ddp (vlib_main_t *vm, vnet_dev_t *dev)
{
  f64 deadline = vlib_time_now (vm) + 3.0;

  do
    {
      ice_aq_desc_t d = {
        .opcode = ICE_AQC_OP_REQUEST_RESOURCE,
        .params.resource = {
          .resource_id = ICE_AQ_RES_ID_GLOBAL_CFG_LOCK,
          .access_type = ICE_AQ_RES_ACCESS_WRITE,
          .timeout = 3000,
        },
      };
      vnet_dev_rv_t rv = ice_aq_send (vm, dev, &d, 0, 0, 1.0);

      if (rv && d.params.resource.status != ICE_AQ_RES_GLOBAL_IN_PROGRESS)
	return rv;

      switch (d.params.resource.status)
	{
	case ICE_AQ_RES_GLOBAL_SUCCESS:
	  return ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_GLOBAL_CFG_LOCK);
	case ICE_AQ_RES_GLOBAL_DONE:
	  return VNET_DEV_OK;
	case ICE_AQ_RES_GLOBAL_IN_PROGRESS:
	  vlib_process_suspend (vm, 0.01);
	  break;
	default:
	  return VNET_DEV_ERR_INVALID_DATA;
	}
    }
  while (vlib_time_now (vm) < deadline);

  return VNET_DEV_ERR_NOT_READY;
}

vnet_dev_rv_t
ice_aq_update_package (vlib_main_t *vm, vnet_dev_t *dev, void *buf, u16 len, u8 last_buffer)
{
  ice_aq_desc_t d = {
    .flags = { .read = 1 },
    .opcode = ICE_AQC_OP_UPDATE_PACKAGE,
  };

  d.params.update_pkg.flags.last_buffer = last_buffer;
  return ice_aq_send (vm, dev, &d, buf, len, 1.0);
}

static vnet_dev_rv_t
ice_aq_send_sw_rules (vlib_main_t *vm, vnet_dev_t *dev, void *rules, u16 size, u16 count,
		      ice_aq_opcode_t opcode)
{
  ice_aq_desc_t d = {
    .flags = { .read = 1 },
    .opcode = opcode,
  };

  d.params.sw_rules.num_rules = count;
  return ice_aq_send (vm, dev, &d, rules, size, 1.0);
}

static void
ice_sw_rule_init_full (ice_sw_rule_t *rule, ice_port_t *ip, ice_sw_lkup_type_t recipe,
		       ice_aqc_sw_rule_type_t type, u16 src, const u8 *mac, u8 loopback_enable,
		       u8 lan_enable)
{
  const u8 dummy[16] = {
    2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0x81, 0, 0, 0,
  };
  ice_sw_rule_action_t action = {
    .loopback_enable = loopback_enable,
    .lan_enable = lan_enable,
    .vsi_id = ip->vsi.num,
    .valid = 1,
  };

  *rule = (ice_sw_rule_t) {
    .type = type,
    .recipe_id = recipe,
    .src = src,
    .act = action.as_u32,
    .hdr_len = sizeof (dummy),
  };
  clib_memcpy (rule->hdr_data, dummy, sizeof (dummy));

  if (mac)
    clib_memcpy (rule->hdr_data, mac, 6);
}

static void
ice_sw_rule_init (ice_sw_rule_t *rule, ice_port_t *ip, ice_sw_lkup_type_t recipe, const u8 *mac,
		  u8 lan_enable)
{
  ice_sw_rule_init_full (rule, ip, recipe, ICE_AQC_SW_RULE_LKUP_TX, ip->vsi.num, mac, 1,
			 lan_enable);
}

static vnet_dev_rv_t
ice_aq_remove_sw_rules (vlib_main_t *vm, vnet_dev_t *dev, ice_sw_rule_t *rules, u16 count)
{
  ice_sw_rule_remove_t remove[4] = {};

  ASSERT (count <= ARRAY_LEN (remove));

  for (u32 i = 0; i < count; i++)
    remove[i].index = rules[i].index;

  return ice_aq_send_sw_rules (vm, dev, remove, count * sizeof (remove[0]), count,
			       ICE_AQC_OP_REMOVE_SW_RULES);
}

static vnet_dev_rv_t
ice_aq_add_sw_rules (vlib_main_t *vm, vnet_dev_t *dev, ice_port_t *ip, const u8 *default_mac)
{
  ice_sw_rule_t rules[2] = {};
  const u8 broadcast[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };
  vnet_dev_rv_t rv;

  ice_sw_rule_init (rules, ip, ICE_SW_LKUP_MAC, default_mac, 0);
  ice_sw_rule_init (rules + 1, ip, ICE_SW_LKUP_MAC, broadcast, 1);
  rv = ice_aq_send_sw_rules (vm, dev, rules, sizeof (rules), ARRAY_LEN (rules),
			     ICE_AQC_OP_ADD_SW_RULES);

  if (rv == VNET_DEV_OK)
    {
      vec_reset_length (ip->vsi.sw_rules);
      vec_add (ip->vsi.sw_rules, rules, ARRAY_LEN (rules));
      log_debug (dev, "installed unicast and broadcast rules for VSI %u", ip->vsi.num);
    }

  return rv;
}

vnet_dev_rv_t
ice_aq_add_mac_rule (vlib_main_t *vm, vnet_dev_port_t *port, const u8 *mac)
{
  vnet_dev_t *dev = port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_sw_rule_t rule;
  vnet_dev_rv_t rv;

  ice_sw_rule_init (&rule, ip, ICE_SW_LKUP_MAC, mac, ethernet_address_cast (mac));
  rv = ice_aq_send_sw_rules (vm, dev, &rule, sizeof (rule), 1, ICE_AQC_OP_ADD_SW_RULES);

  if (rv == VNET_DEV_OK)
    {
      vec_add1 (ip->vsi.sw_rules, rule);
      log_debug (dev, "added secondary MAC rule %U index %u", format_ethernet_address, mac,
		 rule.index);
    }

  return rv;
}

vnet_dev_rv_t
ice_aq_remove_mac_rule (vlib_main_t *vm, vnet_dev_port_t *port, const u8 *mac)
{
  vnet_dev_t *dev = port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;
  u32 pos;

  for (pos = 0; pos < vec_len (ip->vsi.sw_rules); pos++)
    if (ip->vsi.sw_rules[pos].recipe_id == ICE_SW_LKUP_MAC &&
	clib_memcmp (ip->vsi.sw_rules[pos].hdr_data, mac, 6) == 0)
      break;

  ASSERT (pos < vec_len (ip->vsi.sw_rules));

  rv = ice_aq_remove_sw_rules (vm, dev, ip->vsi.sw_rules + pos, 1);

  if (rv == VNET_DEV_OK)
    {
      u16 index = ip->vsi.sw_rules[pos].index;
      vec_del1 (ip->vsi.sw_rules, pos);
      log_debug (dev, "removed secondary MAC rule %U index %u", format_ethernet_address, mac,
		 index);
    }

  return rv;
}

vnet_dev_rv_t
ice_aq_change_primary_mac (vlib_main_t *vm, vnet_dev_port_t *port, const u8 *mac)
{
  vnet_dev_t *dev = port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_sw_rule_t new_rule;
  vnet_dev_rv_t rollback_rv;
  vnet_dev_rv_t rv;
  u32 pos;

  for (pos = 0; pos < vec_len (ip->vsi.sw_rules); pos++)
    if (ip->vsi.sw_rules[pos].recipe_id == ICE_SW_LKUP_MAC &&
	clib_memcmp (ip->vsi.sw_rules[pos].hdr_data, port->primary_hw_addr.eth_mac, 6) == 0)
      break;

  ASSERT (pos < vec_len (ip->vsi.sw_rules));

  ice_sw_rule_init (&new_rule, ip, ICE_SW_LKUP_MAC, mac, 0);

  rv = ice_aq_send_sw_rules (vm, dev, &new_rule, sizeof (new_rule), 1, ICE_AQC_OP_ADD_SW_RULES);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = ice_aq_remove_sw_rules (vm, dev, ip->vsi.sw_rules + pos, 1);
  if (rv != VNET_DEV_OK)
    {
      rollback_rv = ice_aq_remove_sw_rules (vm, dev, &new_rule, 1);

      if (rollback_rv != VNET_DEV_OK)
	{
	  vec_add1 (ip->vsi.sw_rules, new_rule);
	  log_err (dev, "failed to roll back primary MAC rule %U index %u", format_ethernet_address,
		   mac, new_rule.index);
	}

      return rv;
    }

  ip->vsi.sw_rules[pos] = new_rule;
  log_debug (dev, "changed primary MAC rule to %U index %u", format_ethernet_address, mac,
	     new_rule.index);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_aq_set_promisc (vlib_main_t *vm, vnet_dev_port_t *port, u8 enable)
{
  vnet_dev_t *dev = port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_sw_rule_t rules[4] = {};
  const u8 unicast[6] = {
    2, 0, 0, 0, 0, 0,
  };
  const u8 multicast[6] = {
    3, 0, 0, 0, 0, 0,
  };
  vnet_dev_rv_t rv;
  u32 count = 0;

  if (enable)
    {
      ice_sw_rule_init_full (rules, ip, ICE_SW_LKUP_PROMISC, ICE_AQC_SW_RULE_LKUP_RX, ip->lport,
			     unicast, 0, 0);
      ice_sw_rule_init_full (rules + 1, ip, ICE_SW_LKUP_PROMISC, ICE_AQC_SW_RULE_LKUP_TX,
			     ip->vsi.num, unicast, 1, 1);
      ice_sw_rule_init_full (rules + 2, ip, ICE_SW_LKUP_PROMISC, ICE_AQC_SW_RULE_LKUP_RX, ip->lport,
			     multicast, 0, 0);
      ice_sw_rule_init_full (rules + 3, ip, ICE_SW_LKUP_PROMISC, ICE_AQC_SW_RULE_LKUP_TX,
			     ip->vsi.num, multicast, 1, 1);
      rv = ice_aq_send_sw_rules (vm, dev, rules, sizeof (rules), ARRAY_LEN (rules),
				 ICE_AQC_OP_ADD_SW_RULES);

      if (rv == VNET_DEV_OK)
	{
	  vec_add (ip->vsi.sw_rules, rules, ARRAY_LEN (rules));
	  log_debug (dev, "installed %u promiscuous switch rules", ARRAY_LEN (rules));
	}

      return rv;
    }

  for (u32 i = 0; i < vec_len (ip->vsi.sw_rules); i++)
    if (ip->vsi.sw_rules[i].recipe_id == ICE_SW_LKUP_PROMISC)
      {
	ASSERT (count < ARRAY_LEN (rules));
	rules[count++] = ip->vsi.sw_rules[i];
      }

  ASSERT (count == ARRAY_LEN (rules));
  rv = ice_aq_remove_sw_rules (vm, dev, rules, count);

  if (rv == VNET_DEV_OK)
    {
      for (u32 i = vec_len (ip->vsi.sw_rules); i > 0; i--)
	if (ip->vsi.sw_rules[i - 1].recipe_id == ICE_SW_LKUP_PROMISC)
	  vec_del1 (ip->vsi.sw_rules, i - 1);

      log_debug (dev, "removed %u promiscuous switch rules", count);
    }

  return rv;
}

vnet_dev_rv_t
ice_aq_get_dev_caps (vlib_main_t *vm, vnet_dev_t *dev, ice_dev_info_t *info)
{
  ice_aqc_list_caps_elem_t data[ICE_AQ_BUF_SIZE / sizeof (ice_aqc_list_caps_elem_t)] = {};
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_LIST_DEV_CAPS,
  };
  vnet_dev_rv_t rv;
  u32 n_caps;
  u8 nvm_found = 0;

  rv = ice_aq_send (vm, dev, &d, data, sizeof (data), 1.0);
  if (rv)
    return rv;

  n_caps = clib_min (d.params.list_caps.count, ARRAY_LEN (data));
  vec_reset_length (info->dev_caps);
  vec_add (info->dev_caps, data, n_caps);

  for (u32 i = 0; i < n_caps; i++)
    {
      ice_aqc_nvm_cap_word_t words[3] = {
	{
	  .as_u32 = data[i].number,
	},
	{
	  .as_u32 = data[i].logical_id,
	},
	{
	  .as_u32 = data[i].phys_id,
	},
      };

      if (data[i].cap != ICE_AQC_CAPS_NVM_VER)
	continue;

      for (u32 j = 0; j < ARRAY_LEN (words); j++)
	if (words[j].word_address == ICE_SR_NVM_DEV_STARTER_VER)
	  {
	    ice_nvm_ver_t version = {
	      .as_u16 = words[j].value,
	    };

	    info->nvm_major = version.major;
	    info->nvm_minor = version.minor;
	    nvm_found = 1;
	  }
    }

  if (nvm_found == 0)
    {
      log_err (dev, "NVM version capability not found");
      return VNET_DEV_ERR_DEVICE_NO_REPLY;
    }

  log_debug (dev, "read %u device capability entries, NVM version %u.%u", n_caps, info->nvm_major,
	     info->nvm_minor);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_aq_get_ddp_version (vlib_main_t *vm, vnet_dev_t *dev, ice_dev_info_t *info)
{
  ice_aqc_pkg_info_resp_t data = {};
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_GET_PKG_INFO_LIST,
  };
  vnet_dev_rv_t rv;
  u32 count;

  rv = ice_aq_send (vm, dev, &d, &data, sizeof (data), 1.0);
  if (rv)
    return rv;

  count = clib_min (data.count, ARRAY_LEN (data.pkg_info));
  vec_reset_length (info->pkg_info);
  vec_add (info->pkg_info, data.pkg_info, count);

  for (u32 i = 0; i < count; i++)
    if (data.pkg_info[i].is_active)
      {
	info->ddp_ver = data.pkg_info[i].ver;
	log_debug (dev, "read %u package info entries, active DDP version %u.%u.%u.%u", count,
		   info->ddp_ver.major, info->ddp_ver.minor, info->ddp_ver.update,
		   info->ddp_ver.draft);
	return VNET_DEV_OK;
      }

  log_err (dev, "active DDP package not found");
  return VNET_DEV_ERR_DEVICE_NO_REPLY;
}

vnet_dev_rv_t
ice_aq_get_sensor_reading (vlib_main_t *vm, vnet_dev_t *dev, void *data)
{
  ice_aqc_sensor_reading_t *reading = data;
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_GET_SENSOR_READING,
  };
  vnet_dev_rv_t rv;

  rv = ice_aq_send (vm, dev, &d, 0, 0, 1.0);
  if (rv)
    return rv;

  *reading = d.params.sensor_reading;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_aq_sff_eeprom (vlib_main_t *vm, vnet_dev_t *dev, u8 lport_num, u8 i2c_addr, u16 mem_addr,
		   u8 page, u8 set_page, u8 *data, u8 length)
{
  ice_aq_desc_t d = {
    .flags = { .read = 1 },
    .opcode = ICE_AQC_OP_SFF_EEPROM,
    .params.sff_eeprom = {
      .lport_num = lport_num,
      .lport_num_valid = 1,
      .i2c_bus_addr = { .i2c_addr = i2c_addr, .set_page = set_page },
      .i2c_mem_addr = mem_addr,
      .eeprom_page = page,
    },
  };

  ASSERT (mem_addr <= CLIB_U8_MAX);

  return ice_aq_send (vm, dev, &d, data, length, 1.0);
}

vnet_dev_rv_t
ice_aq_get_dev_info (vlib_main_t *vm, vnet_dev_t *dev, void *data)
{
  ice_dev_info_t *info = data;
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_GET_VER,
  };
  vnet_dev_rv_t rv;

  rv = ice_aq_send (vm, dev, &d, 0, 0, 1.0);
  if (rv)
    return rv;

  info->rom_ver = d.params.get_version.rom_ver;
  info->fw_build = d.params.get_version.fw_build;
  info->fw_branch = d.params.get_version.fw_branch;
  info->fw_major = d.params.get_version.fw_major;
  info->fw_minor = d.params.get_version.fw_minor;
  info->fw_patch = d.params.get_version.fw_patch;
  info->api_branch = d.params.get_version.api_branch;
  info->api_major = d.params.get_version.api_major;
  info->api_minor = d.params.get_version.api_minor;
  info->api_patch = d.params.get_version.api_patch;
  rv = ice_aq_get_dev_caps (vm, dev, info);

  if (!rv)
    rv = ice_aq_get_ddp_version (vm, dev, info);

  if (rv)
    {
      vec_free (info->dev_caps);
      vec_free (info->pkg_info);
    }

  return rv;
}

vnet_dev_rv_t
ice_aq_start (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  u8 driver_name[] = "vpp";
  ice_aq_desc_t d;
  vnet_dev_rv_t rv;

  rv = ice_aq_init (vm, dev);
  if (rv)
    return rv;

  d = (ice_aq_desc_t) { .opcode = ICE_AQC_OP_GET_VER };

  rv = ice_aq_send (vm, dev, &d, 0, 0, 1.0);
  if (rv)
    return rv;

  id->health_events_supported = d.params.get_version.api_major > ICE_AQ_HEALTH_API_MAJOR ||
				(d.params.get_version.api_major == ICE_AQ_HEALTH_API_MAJOR &&
				 (d.params.get_version.api_minor > ICE_AQ_HEALTH_API_MINOR ||
				  (d.params.get_version.api_minor == ICE_AQ_HEALTH_API_MINOR &&
				   d.params.get_version.api_patch >= ICE_AQ_HEALTH_API_PATCH)));

  log_info (dev, "firmware %u.%u.%u API %u.%u.%u", d.params.get_version.fw_major,
	    d.params.get_version.fw_minor, d.params.get_version.fw_patch,
	    d.params.get_version.api_major, d.params.get_version.api_minor,
	    d.params.get_version.api_patch);

  d = (ice_aq_desc_t) { .opcode = ICE_AQC_OP_CLEAR_PF_CFG };

  rv = ice_aq_send (vm, dev, &d, 0, 0, 1.0);
  if (rv)
    return rv;

  log_debug (dev, "PF cfg cleared");

  d = (ice_aq_desc_t) { .opcode = ICE_AQC_OP_CLEAR_PXE };
  d.params.clear_pxe.rx_count = ICE_AQ_CLEAR_PXE_RX_COUNT;
  rv = ice_aq_send (vm, dev, &d, 0, 0, 1.0);

  if (rv == VNET_DEV_OK)
    log_debug (dev, "PXE cfg cleared");
  else if (d.retval == ICE_AQ_RC_EEXIST)
    log_debug (dev, "PXE cfg was already cleared");
  else
    log_debug (dev, "CLEAR_PXE returned firmware status %u, continuing", d.retval);

  /* Firmware must retain this PF's configuration when another PF unloads. */
  d = (ice_aq_desc_t) {
    .flags.read = 1,
    .opcode = ICE_AQC_OP_DRIVER_VER,
  };
  return ice_aq_send (vm, dev, &d, driver_name, sizeof (driver_name) - 1, 1.0);
}

vnet_dev_rv_t
ice_aq_get_speed_caps (vlib_main_t *vm, vnet_dev_t *dev, u8 lport, u32 *speed_caps)
{
  ice_aqc_get_phy_caps_data_t caps = {};
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_GET_PHY_CAPS,
    .params.phy_caps = {
      .lport_num = lport,
      .report_mode = ICE_AQC_REPORT_TOPO_CAP_NO_MEDIA,
    },
  };

  vnet_dev_rv_t rv = ice_aq_send (vm, dev, &d, &caps, sizeof (caps), 1.0);
  if (rv)
    return rv;

  *speed_caps = 0;
#define _(name, bit, mbps)                                                                         \
  {                                                                                                \
    ice_phy_type_low_t low;                                                                        \
    ice_phy_type_high_t high;                                                                      \
    if (ice_phy_type_for_speed ((mbps) * 1000, &low, &high) == VNET_DEV_OK &&                      \
	((low.as_u64 & caps.phy_type_low) || (high.as_u64 & caps.phy_type_high)))                  \
      *speed_caps |= (bit);                                                                        \
  }
  foreach_vnet_hw_if_speed
#undef _
    return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_aq_set_mac_cfg (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_SET_MAC_CFG,
    .params.set_mac_cfg = {
      .max_frame_size = ICE_AQC_MAC_MAX_FRAME_SIZE,
      .tx_tmr_value = ice_reg_read (dev, id->config.mac_tx_tmr_reg),
      .fc_refresh_threshold = ice_reg_read (dev, id->config.mac_fc_refresh_reg),
    },
  };

  return ice_aq_send (vm, dev, &d, 0, 0, 1.0);
}

vnet_dev_rv_t
ice_aq_configure (vlib_main_t *vm, vnet_dev_t *dev, ice_port_t *ip, u16 rxq_count, u8 *default_mac)
{
  vnet_dev_rv_t rv;
  u16 sw_id;

  rv = ice_aq_get_switch_config (vm, dev, ip, &sw_id);

  if (!rv)
    rv = ice_aq_get_mac (vm, dev, default_mac);

  if (!rv)
    rv = ice_aq_set_mac_cfg (vm, dev);

  if (!rv)
    rv = ice_aq_get_tx_parent (vm, dev, ip);

  if (!rv)
    rv = ice_aq_configure_vsi (vm, dev, ip, sw_id, rxq_count);

  if (!rv)
    rv = ice_aq_add_sw_rules (vm, dev, ip, default_mac);

  if (rv)
    return rv;

  return VNET_DEV_OK;
}

void
ice_aq_stop (vlib_main_t *vm, vnet_dev_t *dev, ice_port_t *ip)
{
  if (ip && ip->vsi.added)
    {
      log_debug (dev, "freeing VSI %u", ip->vsi.num);
      (void) ice_aq_free_vsi (vm, dev, ip->vsi.num);
      ip->vsi.added = 0;
      vec_reset_length (ip->vsi.sw_rules);
    }

  ice_aq_deinit (vm, dev);
}

vnet_dev_rv_t
ice_aq_get_port_status (vlib_main_t *vm, vnet_dev_t *dev, void *data)
{
  static const ice_aqc_phy_rpt_mode_t modes[] = {
    ICE_AQC_REPORT_TOPO_CAP_NO_MEDIA,
    ICE_AQC_REPORT_TOPO_CAP_MEDIA,
    ICE_AQC_REPORT_ACTIVE_CFG,
    ICE_AQC_REPORT_DFLT_CFG,
  };
  ice_port_status_t *status = data;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_GET_LINK_STATUS,
    .params.link_status.lport_num = status->lport,
  };
  u16 size = id->config.aqc_link_status_size;

  status->link_rv = ice_aq_send (vm, dev, &d, &status->link, size, 0.5);

  for (u32 i = 0; i < ARRAY_LEN (modes); i++)
    {
      d = (ice_aq_desc_t) {
	.opcode = ICE_AQC_OP_GET_PHY_CAPS,
	.params.phy_caps = { .lport_num = status->lport, .report_mode = modes[i] },
      };
      status->phy_rv[i] = ice_aq_send (vm, dev, &d, status->phy + i, sizeof (status->phy[i]), 1.0);
    }

  d = (ice_aq_desc_t) {
    .opcode = ICE_AQC_OP_GET_PORT_OPTIONS,
    .params.port_options = { .lport_num = status->lport, .lport_num_valid = 1 },
  };
  status->options_rv = ice_aq_send (vm, dev, &d, status->options, sizeof (status->options), 1.0);
  status->options_params = d.params;
  return VNET_DEV_OK;
}

u32
ice_aq_link_speed_from_status (const ice_aqc_link_status_t *status)
{
  static const u32 link_speeds[] = {
    10000,    100000,	1000000,   2500000,   5000000, 10000000, 20000000, 25000000,
    40000000, 50000000, 100000000, 200000000, 0,       0,	 0,	   0,
  };

  if (!status->link_info.link_up || !status->link_speed.as_u16)
    return 0;

  return link_speeds[get_lowest_set_bit_index (status->link_speed.as_u16)];
}

vnet_dev_rv_t
ice_aq_get_link_state (vlib_main_t *vm, vnet_dev_port_t *port, u8 enable_events, u8 *link_up,
		       u32 *link_speed)
{
  ice_dev_t *id = vnet_dev_get_data (port->dev);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_aqc_link_status_t status = {};
  ice_aq_desc_t d = { .opcode = ICE_AQC_OP_GET_LINK_STATUS };
  u16 size = id->config.aqc_link_status_size;

  d.params.link_status.lport_num = ip->lport;

  if (enable_events && id->arq_active)
    d.params.link_status.cmd_flags = ICE_AQC_LINK_EVENT_ENABLE;

  vnet_dev_rv_t rv = ice_aq_send (vm, port->dev, &d, &status, size, 0.5);

  if (rv == VNET_DEV_OK)
    {
      *link_up = status.link_info.link_up;
      *link_speed = ice_aq_link_speed_from_status (&status);
    }

  return rv;
}

static void
ice_aq_irq_enable (vnet_dev_t *dev)
{
  ice_reg_glint_dyn_ctl_t ctl = {
    .intena = 1,
    .clearpba = 1,
    .itr_indx = ICE_ITR_INDEX_NONE,
  };

  ice_reg_write (dev, ICE_GLINT_DYN_CTL (0), ctl.as_u32);
  ice_reg_flush (dev);
}

static ice_aq_event_t *
ice_aq_record_event (vnet_dev_t *dev, const ice_aq_desc_t *desc, const u8 *data, u16 slot)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_aq_event_t *event;

  vec_validate (id->aq_events, ICE_AQ_EVENT_HISTORY_SIZE - 1);
  event = id->aq_events + id->aq_event_count % ICE_AQ_EVENT_HISTORY_SIZE;
  *event = (ice_aq_event_t) {
    .timestamp = unix_time_now (),
    .desc = *desc,
    .slot = slot,
    .data_len = clib_min (desc->datalen, ICE_AQ_BUF_SIZE),
  };
  clib_memcpy (event->data, data, event->data_len);
  id->aq_event_count++;
  return event;
}

static void
ice_aq_log_health_event (vnet_dev_t *dev, const ice_aq_event_t *event)
{
  const ice_aqc_health_status_elem_t *elements = (const void *) event->data;
  u32 count =
    clib_min (event->desc.params.health_status_event.count, event->data_len / sizeof (*elements));
  int error = 0;

  for (u32 i = 0; i < count; i++)
    switch (elements[i].status_code)
      {
#define _(v, n, d, l)                                                                              \
  case ICE_AQ_HEALTH_##n:                                                                          \
    error |= VLIB_LOG_LEVEL_##l == VLIB_LOG_LEVEL_ERR;                                             \
    break;
	foreach_ice_aq_health_status
#undef _
	  default : break;
      }

  if (error)
    log_err (dev, "%U", format_ice_aq_event, event);
  else
    log_info (dev, "%U", format_ice_aq_event, event);
}

static void
ice_aq_poll (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_aq_mem_t *aq = id->aq;
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);
  ice_reg_aq_len_t len;
  u16 n_events = 0;
  u8 link_event = 0;

  if (!id->arq_active)
    return;

  if (PREDICT_FALSE (aq == 0))
    return;

  len.as_u32 = ice_reg_read (dev, ICE_PF_FW_ARQLEN);

  if (len.vf_error || len.overflow || len.critical_error)
    {
      log_warn (dev, "ARQ error: vf-error %u overflow %u critical-error %u head %u next %u",
		len.vf_error, len.overflow, len.critical_error, ice_reg_read (dev, ICE_PF_FW_ARQH),
		id->arq_next);
      len.vf_error = len.overflow = len.critical_error = 0;
      ice_reg_write (dev, ICE_PF_FW_ARQLEN, len.as_u32);
    }

  while (n_events < ICE_AQ_LEN)
    {
      u16 slot = id->arq_next;
      ice_aq_desc_t *d = aq->arq + slot;
      ice_aq_desc_flags_t flags;
      u8 *data = aq->arq_buf[slot];
      ice_aq_event_t *event;

      if (slot == (ice_reg_read (dev, ICE_PF_FW_ARQH) & (ICE_AQ_LEN - 1)))
	break;

      flags.as_u16 = __atomic_load_n (&d->flags.as_u16, __ATOMIC_ACQUIRE);

      event = ice_aq_record_event (dev, d, data, slot);
      log_debug (dev, "%U", format_ice_aq_event, event);

      if (flags.error || d->retval || d->datalen > ICE_AQ_BUF_SIZE)
	log_warn (dev, "invalid ARQ event: %U", format_ice_aq_event, event);
      else if (d->opcode == ICE_AQC_OP_HEALTH_STATUS_EVENT)
	ice_aq_log_health_event (dev, event);
      else if (d->opcode == ICE_AQC_OP_GET_LINK_STATUS)
	{
	  if (d->datalen < ICE_AQC_LINK_STATUS_V1_SIZE)
	    log_warn (dev, "short link status event: %u bytes", d->datalen);
	  else
	    {
	      ice_aqc_link_status_t *status = (ice_aqc_link_status_t *) data;
	      u32 speed = ice_aq_link_speed_from_status (status);

	      if (port)
		{
		  link_event = 1;

		  if (port->started)
		    ice_port_update_link_state (vm, port, status->link_info.link_up, speed);
		}
	    }
	}

      ice_aq_arq_desc_init (vm, dev, slot);
      __atomic_thread_fence (__ATOMIC_RELEASE);
      ice_reg_write (dev, ICE_PF_FW_ARQT, slot);
      id->arq_next = (slot + 1) % ICE_AQ_LEN;
      n_events++;
    }

  if (n_events)
    log_debug (dev, "drained %u events, next %u head %u", n_events, id->arq_next,
	       ice_reg_read (dev, ICE_PF_FW_ARQH));

  if (link_event)
    {
      u8 link_up;
      u32 speed;
      vnet_dev_rv_t rv = ice_aq_get_link_state (vm, port, /* enable_events */ 1, &link_up, &speed);

      if (rv != VNET_DEV_OK)
	log_warn (dev, "failed to rearm link events: %U", format_vnet_dev_rv, rv);
      else if (port->started)
	ice_port_update_link_state (vm, port, link_up, speed);
    }

  if (id->arq_irq_enabled)
    ice_aq_irq_enable (dev);

  if (n_events == ICE_AQ_LEN)
    vnet_dev_process_call_op_no_wait (vm, dev, ice_aq_poll);
}

static void
ice_aq_msix_handler (vlib_main_t *vm, vnet_dev_t *dev, u16 line)
{
  ice_dev_t *id = vnet_dev_get_data (dev);

  if (!id->arq_active)
    return;

  ice_reg_write (dev, ICE_GLINT_DYN_CTL (0), 0);
  log_debug (dev, "MSI-X interrupt %u, head %u next %u", line, ice_reg_read (dev, ICE_PF_FW_ARQH),
	     id->arq_next);
  vnet_dev_process_call_op_no_wait (vm, dev, ice_aq_poll);
}

static vnet_dev_rv_t
ice_aq_set_health_event_config (vlib_main_t *vm, vnet_dev_t *dev, u8 enable)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_SET_HEALTH_STATUS_CONFIG,
    .params.health_status_config.sources = {
      .pf_specific = enable,
      .global = enable,
    },
  };
  vnet_dev_rv_t rv = ice_aq_send (vm, dev, &d, 0, 0, 0.5);
  if (rv)
    return rv;

  id->health_events_enabled = enable;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_aq_events_start (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  const ice_aq_link_event_mask_t enabled = {
    .link_up_down = 1,
    .media_unavailable = 1,
    .link_fault = 1,
    .phy_temperature_alarm = 1,
    .excessive_errors = 1,
    .signal_detect = 1,
    .autoneg_completed = 1,
    .module_qualification_failure = 1,
    .port_tx_suspended = 1,
    .topology_conflict = 1,
    .media_conflict = 1,
    .phy_fw_load_failure = 1,
  };
  ice_aq_desc_t d = { .opcode = ICE_AQC_OP_SET_EVENT_MASK };
  vnet_dev_rv_t rv;
  u32 speed;
  u8 link_up;

  d.params.event_mask.lport_num = ip->lport;
  d.params.event_mask.event_mask = ~enabled.as_u16;

  rv = ice_aq_send (vm, dev, &d, 0, 0, 0.5);
  if (rv)
    return rv;

  id->arq_active = 1;
  vnet_dev_poll_dev_add (vm, dev, 0.5, ice_aq_poll);

  if (vnet_dev_get_pci_n_msix_interrupts (dev))
    {
      ice_reg_pfint_ctl_t ctl = { .cause_ena = 1 };

      rv = vnet_dev_pci_msix_add_handler (vm, dev, ice_aq_msix_handler, 0, 1);
      if (rv)
	goto error;

      rv = vnet_dev_pci_msix_enable (vm, dev, 0, 1);
      if (rv)
	{
	  vnet_dev_pci_msix_remove_handler (vm, dev, 0, 1);
	  goto error;
	}

      vnet_dev_pci_msix_set_polling_thread (vm, dev, 0, 0);
      id->arq_irq_enabled = 1;
      ice_reg_write (dev, ICE_PFINT_FW_CTL, ctl.as_u32);
      ice_aq_irq_enable (dev);
    }
  else
    log_notice (dev, "no MSI-X vector available, polling AdminQ events");

  if (id->health_events_supported)
    {
      rv = ice_aq_set_health_event_config (vm, dev, 1);
      if (rv)
	goto error;
    }
  else
    log_notice (dev, "firmware API does not support health event notifications");

  rv = ice_aq_get_link_state (vm, port, /* enable_events */ 1, &link_up, &speed);
  if (rv)
    goto error;

  log_debug (dev, "events enabled: lport %u mask 0x%04x MSI-X %u poll interval 0.5s", ip->lport,
	     d.params.event_mask.event_mask, id->arq_irq_enabled);
  return VNET_DEV_OK;

error:
  ice_aq_events_stop (vm, dev);
  return rv;
}

void
ice_aq_events_stop (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);

  if (!id->arq_active)
    return;

  if (id->health_events_enabled && id->aq_alive && !id->aq_failed)
    {
      vnet_dev_rv_t rv = ice_aq_set_health_event_config (vm, dev, 0);
      if (rv)
	log_err (dev, "failed to disable health event notifications: %U", format_vnet_dev_rv, rv);
    }

  id->arq_active = 0;
  ice_reg_write (dev, ICE_PFINT_FW_CTL, 0);

  if (id->arq_irq_enabled)
    {
      ice_reg_write (dev, ICE_GLINT_DYN_CTL (0), 0);
      ice_reg_flush (dev);
      vnet_dev_pci_msix_disable (vm, dev, 0, 1);
      vnet_dev_pci_msix_remove_handler (vm, dev, 0, 1);
      id->arq_irq_enabled = 0;
    }

  vnet_dev_poll_dev_remove (vm, dev, ice_aq_poll);
  log_debug (dev, "event handling stopped");
}

vnet_dev_rv_t
ice_aq_set_link (vlib_main_t *vm, vnet_dev_port_t *port, u32 link_speed_kbps, u8 link_enabled)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_phy_type_low_t new_low = {};
  ice_phy_type_high_t new_high = {};
  ice_aqc_get_phy_caps_data_t caps = {};
  ice_aqc_set_phy_cfg_data_t cfg;
  ice_aq_desc_t d;
  vnet_dev_rv_t rv;

  /* link_speed_kbps == 0 means auto: advertise everything the media supports */
  if (link_speed_kbps != 0)
    {
      rv = ice_phy_type_for_speed (link_speed_kbps, &new_low, &new_high);
      if (rv)
	return rv;
    }

  d = (ice_aq_desc_t) { .opcode = ICE_AQC_OP_GET_PHY_CAPS };
  d.params.phy_caps.lport_num = ip->lport;
  d.params.phy_caps.report_mode = ICE_AQC_REPORT_TOPO_CAP_MEDIA;

  rv = ice_aq_send (vm, port->dev, &d, &caps, sizeof (caps), 1.0);
  if (rv)
    return rv;

  if (link_speed_kbps == 0)
    {
      new_low.as_u64 = caps.phy_type_low;
      new_high.as_u64 = caps.phy_type_high;

      if (new_low.as_u64 == 0 && new_high.as_u64 == 0)
	{
	  log_debug (port->dev, "port %u no media, PHY configuration skipped", port->port_id);
	  return VNET_DEV_OK;
	}
    }
  else
    {
      new_low.as_u64 &= caps.phy_type_low;
      new_high.as_u64 &= caps.phy_type_high;

      if (new_low.as_u64 == 0 && new_high.as_u64 == 0)
	{
	  log_err (port->dev, "speed %u kbps not supported by installed media", link_speed_kbps);
	  return VNET_DEV_ERR_NOT_SUPPORTED;
	}
    }

  cfg = (ice_aqc_set_phy_cfg_data_t) {
    .phy_type_low = new_low.as_u64,
    .phy_type_high = new_high.as_u64,
    .caps_flags = {
      .tx_pause = caps.caps_flags.pause_tx,
      .rx_pause = caps.caps_flags.pause_rx,
      .low_power = caps.caps_flags.low_power,
      .link_enabled = link_enabled,
      .auto_link_update = 1,
      .lesm = caps.caps_flags.lesm,
      .auto_fec = caps.caps_flags.auto_fec,
    },
    .low_power_ctrl_an = caps.low_power_ctrl_an,
    .eee_cap = caps.eee_cap,
    .eeer_value = caps.eeer_value,
    .link_fec_opt = caps.link_fec_options,
    .module_compliance_enforcement = caps.module_compliance_enforcement,
  };

  log_debug (port->dev,
	     "port %u lport %u requested speed %u kbps link %sabled: PHY types "
	     "0x%016lx/0x%016lx, media types 0x%016lx/0x%016lx, caps 0x%02x FEC 0x%02x",
	     port->port_id, ip->lport, link_speed_kbps, link_enabled ? "en" : "dis",
	     cfg.phy_type_low, cfg.phy_type_high, caps.phy_type_low, caps.phy_type_high, cfg.caps,
	     cfg.link_fec_opt);
  d = (ice_aq_desc_t) { .opcode = ICE_AQC_OP_SET_PHY_CFG, .flags.read = 1 };
  d.params.phy_caps.lport_num = ip->lport;
  return ice_aq_send (vm, port->dev, &d, &cfg, sizeof (cfg), 1.0);
}

vnet_dev_rv_t
ice_aq_add_txq (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, const ice_txq_ctx_t *ctx)
{
  vnet_dev_t *dev = txq->port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (txq->port);
  u16 q = txq->queue_id;
  ice_aqc_add_txq_group_t group = {
    .parent_teid = ip->tx_parent_teid,
    .num_txqs = 1,
    .txq = {
      .txq_id = q,
      .info = {
        .valid_sections = { .generic = 1, .cir = 1, .eir = 1, },
        .cir_bw = { .bw_profile_idx = 0, .bw_alloc = 4 },
        .eir_bw = { .bw_profile_idx = 0, .bw_alloc = 4 },
      },
    },
  };
  vnet_dev_rv_t rv;

  clib_memcpy (group.txq.txq_ctx, ctx->as_u8, sizeof (group.txq.txq_ctx));
  rv = ice_aq_add_txq_group (vm, dev, &group);

  if (rv == VNET_DEV_OK)
    {
      log_debug (dev, "txq %u assigned TEID %u under parent %u", q, group.txq.q_teid,
		 ip->tx_parent_teid);
    }

  return rv;
}

vnet_dev_rv_t
ice_aq_dis_txq (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (txq->port);
  vnet_dev_rv_t rv;
  ice_aqc_dis_txq_item_t item = {
    .parent_teid = ip->tx_parent_teid,
    .num_queues = 1,
    .queue_id = txq->queue_id,
  };
  rv = ice_aq_dis_txq_item (vm, dev, &item);

  if (rv == VNET_DEV_OK)
    log_debug (dev, "txq %u disabled", item.queue_id);

  return rv;
}
