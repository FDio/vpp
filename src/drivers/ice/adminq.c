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
  return vnet_dev_dma_mem_alloc (vm, dev, sizeof (ice_aq_mem_t), 4096, (void **) &id->aq,
				 "AdminQ rings and buffers");
}

void
ice_aq_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  if (id->aq)
    {
      vnet_dev_dma_mem_free (vm, dev, id->aq);
      id->aq = 0;
    }
}

static void
ice_aq_arq_desc_init (vlib_main_t *vm, vnet_dev_t *dev, u16 slot)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_aq_desc_t *d = id->aq->arq + slot;
  u64 pa = vnet_dev_get_dma_addr (vm, dev, id->aq->arq_buf[slot]);

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

  log_debug (dev, "initializing AdminQ with %u-entry rings", ICE_AQ_LEN);
  clib_memset (id->aq, 0, sizeof (*id->aq));
  ice_reg_write (dev, ICE_PF_FW_ATQLEN, 0);
  ice_reg_write (dev, ICE_PF_FW_ARQLEN, 0);

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

  id->atq_next = 0;
  id->aq_alive = 0;
  log_debug (dev, "AdminQ initialized");
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

  if (len > ICE_AQ_BUF_SIZE)
    {
      log_debug (dev, "AdminQ %U buffer length %u exceeds maximum %u", format_ice_adminq_opcode,
		 desc->opcode, len, ICE_AQ_BUF_SIZE);
      return VNET_DEV_ERR_INVALID_DATA;
    }

  log_debug_noisy (dev, "AdminQ submit %U slot %u length %u", format_ice_adminq_opcode,
		   desc->opcode, slot, len);

  *d = *desc;
  d->flags.si = 1;
  if (len)
    {
      u64 pa = vnet_dev_get_dma_addr (vm, dev, buf);
      d->flags.buffer = 1;
      if (len > 512)
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
	  log_err (dev, "AdminQ timeout for %U", format_ice_adminq_opcode, d->opcode);
	  return VNET_DEV_ERR_TIMEOUT;
	}
      vlib_process_suspend (vm, delay);
      delay = clib_min (delay * 2, 1e-2);
    }

  *desc = *d;
  if (len)
    clib_memcpy_fast (data, buf, len);

  if (d->flags.error || d->retval)
    {
      if (d->opcode == ICE_AQC_OP_CLEAR_PXE && d->retval == ICE_AQ_RC_EEXIST)
	log_debug (dev, "AdminQ %U reports existing state", format_ice_adminq_opcode, d->opcode);
      else
	log_err (dev, "AdminQ %U failed, retval %u", format_ice_adminq_opcode, d->opcode,
		 d->retval);
      return VNET_DEV_ERR_DEVICE_NO_REPLY;
    }

  id->aq_alive = 1;
  log_debug_noisy (dev, "AdminQ complete %U slot %u length %u", format_ice_adminq_opcode, d->opcode,
		   slot, d->datalen);
  return VNET_DEV_OK;
}

static void
ice_aq_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);

  if (id->aq_alive)
    {
      log_debug (dev, "shutting down AdminQ");
      ice_aq_desc_t d = { .opcode = ICE_AQC_OP_Q_SHUTDOWN };
      d.params.q_shutdown.driver_unloading = 1;
      (void) ice_aq_send (vm, dev, &d, 0, 0, 0.5);
    }
  ice_reg_write (dev, ICE_PF_FW_ATQLEN, 0);
  ice_reg_write (dev, ICE_PF_FW_ARQLEN, 0);
  id->aq_alive = 0;
  log_debug (dev, "AdminQ stopped");
}

static vnet_dev_rv_t
ice_aq_get_switch_config (vlib_main_t *vm, vnet_dev_t *dev, u16 *sw_id)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  u8 data[ICE_AQ_BUF_SIZE] = {};
  ice_aq_desc_t d = { .opcode = ICE_AQC_OP_GET_SW_CFG };
  vnet_dev_rv_t rv;

  if ((rv = ice_aq_send (vm, dev, &d, data, sizeof (data), 1.0)))
    return rv;

  ice_aqc_sw_cfg_elem_t *e = (void *) data;
  for (u16 i = 0; i < d.params.sw_cfg.num_elems; i++)
    if (e[i].vsi_port.type == ICE_AQC_SW_CFG_PHYS_PORT)
      {
	id->lport = e[i].vsi_port.number;
	*sw_id = e[i].swid;
	log_debug (dev, "switch configuration: logical port %u switch %u", id->lport, *sw_id);
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

  if ((rv = ice_aq_send (vm, dev, &d, data, sizeof (data), 1.0)))
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
ice_aq_get_tx_parent (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  u8 data[ICE_AQ_BUF_SIZE] = {};
  ice_aq_desc_t d = { .opcode = ICE_AQC_OP_GET_DFLT_TOPO };
  vnet_dev_rv_t rv;

  d.params.topology.port_num = id->lport;
  if ((rv = ice_aq_send (vm, dev, &d, data, sizeof (data), 1.0)))
    return rv;
  if (d.params.topology.num_branches == 0)
    return VNET_DEV_ERR_DEVICE_NO_REPLY;

  ice_aqc_topo_branch_t *branch = (void *) data;
  u16 n = clib_min (branch->num_elems, (u16) ARRAY_LEN (branch->elem));
  if (n == 0)
    return VNET_DEV_ERR_DEVICE_NO_REPLY;
  if (n > 1 && branch->elem[n - 1].data.elem_type == ICE_AQC_SCHED_ELEM_LEAF)
    n--;
  id->tx_parent_teid = branch->elem[n - 1].node_teid;
  log_debug (dev, "TX topology: %u branches, parent TEID %u", d.params.topology.num_branches,
	     id->tx_parent_teid);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_aq_add_vsi (vlib_main_t *vm, vnet_dev_t *dev, u16 sw_id, u16 rxq_count)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_aqc_vsi_props_t props = {
    .valid_sections = {
      .switch_section = 1,
      .security_section = 1,
      .vlan_section = 1,
      .rxq_map_section = 1,
    },
    .sw_id = sw_id,
    .sw_flags = {
      .allow_loopback = 1,
      .local_loopback = 1,
      .source_prune = 1,
    },
    .sw_flags2 = { .lan_enable = 1 },
    .sec_flags = { .allow_dest_override = 1 },
    .inner_vlan_flags = {
      .tx_mode = 3,
      .egress_mode = 3,
    },
    .q_mapping = { id->rxq_base, rxq_count },
    .tc_mapping = { { .queue_count_log2 = max_log2 (rxq_count) } },
  };
  ice_aq_desc_t d = {
    .flags = { .read = 1 },
    .opcode = ICE_AQC_OP_ADD_VSI,
  };
  vnet_dev_rv_t rv;

  d.params.vsi.vsi_flags.type = ICE_AQ_VSI_TYPE_PF;
  if ((rv = ice_aq_send (vm, dev, &d, &props, sizeof (props), 1.0)))
    return rv;
  id->vsi_num = d.params.vsi.vsi_num.number;
  id->vsi_props = props;
  id->vsi_added = 1;
  log_debug (dev, "created VSI %u", id->vsi_num);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_aq_set_rss_key (vlib_main_t *vm, vnet_dev_port_t *port, const ice_aq_rss_key_t *key)
{
  ice_dev_t *id = vnet_dev_get_data (port->dev);
  ice_aq_rss_key_t data = *key;
  ice_aq_desc_t d = {
    .flags = { .read = 1 },
    .opcode = ICE_AQC_OP_SET_RSS_KEY,
  };

  d.params.rss_key.vsi_id.vsi_id = id->vsi_num;
  d.params.rss_key.vsi_id.valid = 1;
  return ice_aq_send (vm, port->dev, &d, &data, sizeof (data), 1.0);
}

vnet_dev_rv_t
ice_aq_set_rss_lut (vlib_main_t *vm, vnet_dev_port_t *port, const ice_aq_rss_lut_t *lut)
{
  ice_dev_t *id = vnet_dev_get_data (port->dev);
  ice_aq_rss_lut_t data = *lut;
  ice_aq_desc_t d = {
    .flags = { .read = 1 },
    .opcode = ICE_AQC_OP_SET_RSS_LUT,
  };

  d.params.rss_lut.vsi_id.vsi_id = id->vsi_num;
  d.params.rss_lut.vsi_id.valid = 1;
  return ice_aq_send (vm, port->dev, &d, &data, sizeof (data), 1.0);
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
ice_sw_rule_init_full (ice_sw_rule_t *rule, ice_dev_t *id, ice_sw_lkup_type_t recipe,
		       ice_aqc_sw_rule_type_t type, u16 src, const u8 *mac, u8 loopback_enable,
		       u8 lan_enable)
{
  const u8 dummy[16] = {
    2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0x81, 0, 0, 0,
  };
  ice_sw_rule_action_t action = {
    .loopback_enable = loopback_enable,
    .lan_enable = lan_enable,
    .vsi_id = id->vsi_num,
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
ice_sw_rule_init (ice_sw_rule_t *rule, ice_dev_t *id, ice_sw_lkup_type_t recipe, const u8 *mac,
		  u8 lan_enable)
{
  ice_sw_rule_init_full (rule, id, recipe, ICE_AQC_SW_RULE_LKUP_TX, id->vsi_num, mac, 1,
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
ice_aq_add_sw_rules (vlib_main_t *vm, vnet_dev_t *dev, const u8 *default_mac)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_sw_rule_t rules[3] = {};
  const u8 broadcast[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };
  vnet_dev_rv_t rv;

  ice_sw_rule_init (rules, id, ICE_SW_LKUP_MAC, default_mac, 0);
  ice_sw_rule_init (rules + 1, id, ICE_SW_LKUP_MAC, broadcast, 1);
  ice_sw_rule_init (rules + 2, id, ICE_SW_LKUP_DEFAULT, 0, 1);
  rv = ice_aq_send_sw_rules (vm, dev, rules, sizeof (rules), ARRAY_LEN (rules),
			     ICE_AQC_OP_ADD_SW_RULES);
  if (rv == VNET_DEV_OK)
    {
      vec_reset_length (id->sw_rules);
      vec_add (id->sw_rules, rules, ARRAY_LEN (rules));
      log_debug (dev, "installed unicast, broadcast, and default TX rules for VSI %u", id->vsi_num);
    }
  return rv;
}

vnet_dev_rv_t
ice_aq_add_mac_rule (vlib_main_t *vm, vnet_dev_port_t *port, const u8 *mac)
{
  vnet_dev_t *dev = port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_sw_rule_t rule;
  vnet_dev_rv_t rv;

  ice_sw_rule_init (&rule, id, ICE_SW_LKUP_MAC, mac, ethernet_address_cast (mac));
  rv = ice_aq_send_sw_rules (vm, dev, &rule, sizeof (rule), 1, ICE_AQC_OP_ADD_SW_RULES);
  if (rv == VNET_DEV_OK)
    {
      vec_add1 (id->sw_rules, rule);
      log_debug (dev, "added secondary MAC rule %U index %u", format_ethernet_address, mac,
		 rule.index);
    }
  return rv;
}

vnet_dev_rv_t
ice_aq_remove_mac_rule (vlib_main_t *vm, vnet_dev_port_t *port, const u8 *mac)
{
  vnet_dev_t *dev = port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  u32 pos;

  for (pos = 0; pos < vec_len (id->sw_rules); pos++)
    if (id->sw_rules[pos].recipe_id == ICE_SW_LKUP_MAC &&
	clib_memcmp (id->sw_rules[pos].hdr_data, mac, 6) == 0)
      break;
  ASSERT (pos < vec_len (id->sw_rules));

  rv = ice_aq_remove_sw_rules (vm, dev, id->sw_rules + pos, 1);
  if (rv == VNET_DEV_OK)
    {
      u16 index = id->sw_rules[pos].index;
      vec_del1 (id->sw_rules, pos);
      log_debug (dev, "removed secondary MAC rule %U index %u", format_ethernet_address, mac,
		 index);
    }
  return rv;
}

vnet_dev_rv_t
ice_aq_change_primary_mac (vlib_main_t *vm, vnet_dev_port_t *port, const u8 *mac)
{
  vnet_dev_t *dev = port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_sw_rule_t new_rule;
  vnet_dev_rv_t rollback_rv;
  vnet_dev_rv_t rv;
  u32 pos;

  for (pos = 0; pos < vec_len (id->sw_rules); pos++)
    if (id->sw_rules[pos].recipe_id == ICE_SW_LKUP_MAC &&
	clib_memcmp (id->sw_rules[pos].hdr_data, port->primary_hw_addr.eth_mac, 6) == 0)
      break;
  ASSERT (pos < vec_len (id->sw_rules));

  ice_sw_rule_init (&new_rule, id, ICE_SW_LKUP_MAC, mac, 0);
  rv = ice_aq_send_sw_rules (vm, dev, &new_rule, sizeof (new_rule), 1, ICE_AQC_OP_ADD_SW_RULES);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = ice_aq_remove_sw_rules (vm, dev, id->sw_rules + pos, 1);
  if (rv != VNET_DEV_OK)
    {
      rollback_rv = ice_aq_remove_sw_rules (vm, dev, &new_rule, 1);
      if (rollback_rv != VNET_DEV_OK)
	{
	  vec_add1 (id->sw_rules, new_rule);
	  log_err (dev, "failed to roll back primary MAC rule %U index %u", format_ethernet_address,
		   mac, new_rule.index);
	}
      return rv;
    }

  id->sw_rules[pos] = new_rule;
  log_debug (dev, "changed primary MAC rule to %U index %u", format_ethernet_address, mac,
	     new_rule.index);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_aq_set_promisc (vlib_main_t *vm, vnet_dev_port_t *port, u8 enable)
{
  vnet_dev_t *dev = port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
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
      ice_sw_rule_init_full (rules, id, ICE_SW_LKUP_PROMISC, ICE_AQC_SW_RULE_LKUP_RX, id->lport,
			     unicast, 0, 0);
      ice_sw_rule_init_full (rules + 1, id, ICE_SW_LKUP_PROMISC, ICE_AQC_SW_RULE_LKUP_TX,
			     id->vsi_num, unicast, 1, 1);
      ice_sw_rule_init_full (rules + 2, id, ICE_SW_LKUP_PROMISC, ICE_AQC_SW_RULE_LKUP_RX, id->lport,
			     multicast, 0, 0);
      ice_sw_rule_init_full (rules + 3, id, ICE_SW_LKUP_PROMISC, ICE_AQC_SW_RULE_LKUP_TX,
			     id->vsi_num, multicast, 1, 1);
      rv = ice_aq_send_sw_rules (vm, dev, rules, sizeof (rules), ARRAY_LEN (rules),
				 ICE_AQC_OP_ADD_SW_RULES);
      if (rv == VNET_DEV_OK)
	{
	  vec_add (id->sw_rules, rules, ARRAY_LEN (rules));
	  log_debug (dev, "installed %u promiscuous switch rules", ARRAY_LEN (rules));
	}
      return rv;
    }

  for (u32 i = 0; i < vec_len (id->sw_rules); i++)
    if (id->sw_rules[i].recipe_id == ICE_SW_LKUP_PROMISC)
      {
	ASSERT (count < ARRAY_LEN (rules));
	rules[count++] = id->sw_rules[i];
      }
  ASSERT (count == ARRAY_LEN (rules));
  rv = ice_aq_remove_sw_rules (vm, dev, rules, count);
  if (rv == VNET_DEV_OK)
    {
      for (u32 i = vec_len (id->sw_rules); i > 0; i--)
	if (id->sw_rules[i - 1].recipe_id == ICE_SW_LKUP_PROMISC)
	  vec_del1 (id->sw_rules, i - 1);
      log_debug (dev, "removed %u promiscuous switch rules", count);
    }
  return rv;
}

static vnet_dev_rv_t
ice_aq_get_dev_caps (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_aqc_list_caps_elem_t data[ICE_AQ_BUF_SIZE / sizeof (ice_aqc_list_caps_elem_t)] = {};
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_LIST_DEV_CAPS,
  };
  vnet_dev_rv_t rv;
  u32 n_caps;
  u8 nvm_found = 0;

  if ((rv = ice_aq_send (vm, dev, &d, data, sizeof (data), 1.0)))
    return rv;

  n_caps = clib_min (d.params.list_caps.count, ARRAY_LEN (data));
  vec_reset_length (id->dev_caps);
  vec_add (id->dev_caps, data, n_caps);
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

	    id->nvm_major = version.major;
	    id->nvm_minor = version.minor;
	    nvm_found = 1;
	  }
    }

  if (nvm_found == 0)
    {
      log_err (dev, "NVM version capability not found");
      return VNET_DEV_ERR_DEVICE_NO_REPLY;
    }

  log_debug (dev, "read %u device capability entries, NVM version %u.%u", n_caps, id->nvm_major,
	     id->nvm_minor);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_aq_get_ddp_version (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_aqc_pkg_info_resp_t data = {};
  ice_aq_desc_t d = {
    .opcode = ICE_AQC_OP_GET_PKG_INFO_LIST,
  };
  vnet_dev_rv_t rv;
  u32 count;

  if ((rv = ice_aq_send (vm, dev, &d, &data, sizeof (data), 1.0)))
    return rv;

  count = clib_min (data.count, ARRAY_LEN (data.pkg_info));
  vec_reset_length (id->pkg_info);
  vec_add (id->pkg_info, data.pkg_info, count);
  for (u32 i = 0; i < count; i++)
    if (data.pkg_info[i].is_active)
      {
	id->ddp_ver = data.pkg_info[i].ver;
	log_debug (dev, "read %u package info entries, active DDP version %u.%u.%u.%u", count,
		   id->ddp_ver.major, id->ddp_ver.minor, id->ddp_ver.update, id->ddp_ver.draft);
	return VNET_DEV_OK;
      }

  log_err (dev, "active DDP package not found");
  return VNET_DEV_ERR_DEVICE_NO_REPLY;
}

vnet_dev_rv_t
ice_aq_start (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_aq_desc_t d;
  vnet_dev_rv_t rv;

  if ((rv = ice_aq_init (vm, dev)))
    return rv;

  d = (ice_aq_desc_t) { .opcode = ICE_AQC_OP_GET_VER };
  if ((rv = ice_aq_send (vm, dev, &d, 0, 0, 1.0)))
    return rv;
  id->rom_ver = d.params.get_version.rom_ver;
  id->fw_build = d.params.get_version.fw_build;
  id->fw_branch = d.params.get_version.fw_branch;
  id->fw_major = d.params.get_version.fw_major;
  id->fw_minor = d.params.get_version.fw_minor;
  id->fw_patch = d.params.get_version.fw_patch;
  id->api_branch = d.params.get_version.api_branch;
  id->api_major = d.params.get_version.api_major;
  id->api_minor = d.params.get_version.api_minor;
  id->api_patch = d.params.get_version.api_patch;
  if ((rv = ice_aq_get_dev_caps (vm, dev)) || (rv = ice_aq_get_ddp_version (vm, dev)))
    return rv;
  log_info (dev, "firmware %u.%u.%u API %u.%u.%u", d.params.get_version.fw_major,
	    d.params.get_version.fw_minor, d.params.get_version.fw_patch,
	    d.params.get_version.api_major, d.params.get_version.api_minor,
	    d.params.get_version.api_patch);

  d = (ice_aq_desc_t) { .opcode = ICE_AQC_OP_CLEAR_PF_CFG };
  if ((rv = ice_aq_send (vm, dev, &d, 0, 0, 1.0)))
    return rv;
  log_debug (dev, "PF configuration cleared");

  d = (ice_aq_desc_t) { .opcode = ICE_AQC_OP_CLEAR_PXE };
  d.params.clear_pxe.rx_count = 2;
  rv = ice_aq_send (vm, dev, &d, 0, 0, 1.0);
  if (rv == VNET_DEV_OK)
    log_debug (dev, "PXE configuration cleared");
  else if (d.retval == ICE_AQ_RC_EEXIST)
    log_debug (dev, "PXE configuration was already cleared");
  else
    log_debug (dev, "CLEAR_PXE returned firmware status %u, continuing", d.retval);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_aq_configure (vlib_main_t *vm, vnet_dev_t *dev, u16 rxq_count, u8 *default_mac)
{
  vnet_dev_rv_t rv;
  u16 sw_id;

  if ((rv = ice_aq_get_switch_config (vm, dev, &sw_id)) ||
      (rv = ice_aq_get_mac (vm, dev, default_mac)) || (rv = ice_aq_get_tx_parent (vm, dev)) ||
      (rv = ice_aq_add_vsi (vm, dev, sw_id, rxq_count)) ||
      (rv = ice_aq_add_sw_rules (vm, dev, default_mac)))
    return rv;
  return VNET_DEV_OK;
}

void
ice_aq_stop (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);

  if (id->vsi_added)
    {
      log_debug (dev, "freeing VSI %u", id->vsi_num);
      ice_aq_desc_t d = { .opcode = ICE_AQC_OP_FREE_VSI };
      d.params.vsi.vsi_num.number = id->vsi_num;
      d.params.vsi.vsi_num.valid = 1;
      (void) ice_aq_send (vm, dev, &d, 0, 0, 1.0);
      id->vsi_added = 0;
      vec_reset_length (id->sw_rules);
    }
  ice_aq_deinit (vm, dev);
}

vnet_dev_rv_t
ice_aq_get_link_state (vlib_main_t *vm, vnet_dev_port_t *port, u8 *link_up)
{
  ice_dev_t *id = vnet_dev_get_data (port->dev);
  ice_aqc_link_status_t status = {};
  ice_aq_desc_t d = { .opcode = ICE_AQC_OP_GET_LINK_STATUS };
  u16 size = id->family == ICE_DEVICE_FAMILY_E810 ? ICE_AQC_LINK_STATUS_V1_SIZE :
						    ICE_AQC_LINK_STATUS_V2_SIZE;

  d.params.link_status.lport_num = id->lport;
  vnet_dev_rv_t rv = ice_aq_send (vm, port->dev, &d, &status, size, 0.5);
  if (rv == VNET_DEV_OK)
    *link_up = status.link_info.link_up;
  return rv;
}

vnet_dev_rv_t
ice_aq_add_txq (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, const ice_txq_ctx_t *ctx)
{
  vnet_dev_t *dev = txq->port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
  u16 q = id->txq_base + txq->queue_id;
  ice_aqc_add_txq_group_t group = {
    .parent_teid = id->tx_parent_teid,
    .num_txqs = 1,
    .txq = {
      .txq_id = q,
      .info = {
        .valid_sections = 7,
        .cir_bw = { .bw_profile_idx = 0, .bw_alloc = 4 },
        .eir_bw = { .bw_profile_idx = 0, .bw_alloc = 4 },
      },
    },
  };
  ice_aq_desc_t d = {
    .flags = { .read = 1 },
    .opcode = ICE_AQC_OP_ADD_TXQS,
  };
  vnet_dev_rv_t rv;

  clib_memcpy (group.txq.txq_ctx, ctx->as_u8, sizeof (group.txq.txq_ctx));
  d.params.add_txqs.num_qgrps = 1;
  rv = ice_aq_send (vm, dev, &d, &group, sizeof (group), 1.0);
  if (rv == VNET_DEV_OK)
    {
      iq->q_teid = group.txq.q_teid;
      log_debug (dev, "TX queue %u assigned TEID %u under parent %u", q, iq->q_teid,
		 id->tx_parent_teid);
    }
  return rv;
}

vnet_dev_rv_t
ice_aq_dis_txq (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  ice_aqc_dis_txq_item_t item = {
    .parent_teid = id->tx_parent_teid,
    .num_queues = 1,
    .queue_id = id->txq_base + txq->queue_id,
  };
  ice_aq_desc_t d = {
    .flags = { .read = 1 },
    .opcode = ICE_AQC_OP_DIS_TXQS,
  };

  d.params.disable_txqs.num_entries = 1;
  rv = ice_aq_send (vm, dev, &d, &item, sizeof (item), 1.0);
  if (rv == VNET_DEV_OK)
    log_debug (dev, "TX queue %u disabled", item.queue_id);
  return rv;
}
