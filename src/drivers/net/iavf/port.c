/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/dev/counters.h>
#include <iavf.h>
#include <iavf_regs.h>
#include <virtchnl.h>
#include <virtchnl_funcs.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (iavf_log, static) = {
  .class_name = "iavf",
  .subclass_name = "port",
};

const static iavf_dyn_ctl dyn_ctln_disabled = {};
const static iavf_dyn_ctl dyn_ctln_enabled = {
  .intena = 1,
  .clearpba = 1,
  .interval = IAVF_ITR_INT / 2,
};
const static iavf_dyn_ctl dyn_ctln_wb_on_itr = {
  .itr_indx = 1,
  .interval = 2,
  .wb_on_itr = 1,
};

vnet_dev_rv_t
iavf_port_vlan_strip_disable (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  virtchnl_vlan_caps_t vc;
  vnet_dev_rv_t rv = VNET_DEV_ERR_NOT_SUPPORTED;
  u32 outer, inner;
  const u32 mask = VIRTCHNL_VLAN_ETHERTYPE_8100;

  if (ap->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_VLAN_V2)
    {
      if ((rv = iavf_vc_op_get_offload_vlan_v2_caps (vm, dev, &vc)))
	return rv;

      outer = vc.offloads.stripping_support.outer;
      inner = vc.offloads.stripping_support.inner;

      outer = outer & VIRTCHNL_VLAN_TOGGLE ? outer & mask : 0;
      inner = inner & VIRTCHNL_VLAN_TOGGLE ? inner & mask : 0;

      virtchnl_vlan_setting_t vs = {
	.vport_id = ap->vsi_id,
	.outer_ethertype_setting = outer,
	.inner_ethertype_setting = inner,
      };

      if ((rv = iavf_vc_op_disable_vlan_stripping_v2 (vm, dev, &vs)))
	return rv;
    }

  if (ap->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_VLAN)
    return iavf_vc_op_disable_vlan_stripping (vm, dev);

  return rv;
}

static vnet_dev_rv_t
iavf_port_set_rss_key (vlib_main_t *vm, vnet_dev_port_t *port, const vnet_dev_rss_config_t *cfg)
{
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  u8 buffer[VIRTCHNL_MSG_SZ (virtchnl_rss_key_t, key, IAVF_MAX_RSS_KEY_SIZE)];
  virtchnl_rss_key_t *key = (virtchnl_rss_key_t *) buffer;

  ASSERT (cfg->key_len <= IAVF_MAX_RSS_KEY_SIZE);

  *key = (virtchnl_rss_key_t) {
    .vsi_id = ap->vsi_id,
    .key_len = cfg->key_len,
  };

  clib_memcpy (key->key, cfg->key, cfg->key_len);

  return iavf_vc_op_config_rss_key (vm, port->dev, key);
}

static const struct
{
  virtchnl_proto_hdr_type_t l3, l4;
} iavf_rss_class_hdrs[VNET_DEV_RSS_N_CLASSES] = {
  [VNET_DEV_RSS_CLASS_IP4] = { .l3 = VIRTCHNL_PROTO_HDR_IPV4, },
  [VNET_DEV_RSS_CLASS_IP4_TCP] = { .l3 = VIRTCHNL_PROTO_HDR_IPV4, .l4 = VIRTCHNL_PROTO_HDR_TCP, },
  [VNET_DEV_RSS_CLASS_IP4_UDP] = { .l3 = VIRTCHNL_PROTO_HDR_IPV4, .l4 = VIRTCHNL_PROTO_HDR_UDP, },
  [VNET_DEV_RSS_CLASS_IP4_SCTP] = { .l3 = VIRTCHNL_PROTO_HDR_IPV4, .l4 = VIRTCHNL_PROTO_HDR_SCTP, },
  [VNET_DEV_RSS_CLASS_IP6] = { .l3 = VIRTCHNL_PROTO_HDR_IPV6, },
  [VNET_DEV_RSS_CLASS_IP6_TCP] = { .l3 = VIRTCHNL_PROTO_HDR_IPV6, .l4 = VIRTCHNL_PROTO_HDR_TCP, },
  [VNET_DEV_RSS_CLASS_IP6_UDP] = { .l3 = VIRTCHNL_PROTO_HDR_IPV6, .l4 = VIRTCHNL_PROTO_HDR_UDP, },
  [VNET_DEV_RSS_CLASS_IP6_SCTP] = { .l3 = VIRTCHNL_PROTO_HDR_IPV6, .l4 = VIRTCHNL_PROTO_HDR_SCTP, },
};

/* fields of the class which apply to its headers */
static vnet_dev_rss_fields_t
iavf_rss_class_fields (const vnet_dev_rss_config_t *cfg, vnet_dev_rss_class_t class)
{
  vnet_dev_rss_fields_t f = vnet_dev_rss_class_fields (cfg, class);

  if (iavf_rss_class_hdrs[class].l4 == VIRTCHNL_PROTO_HDR_NONE)
    f.as_u32 &= VNET_DEV_RSS_FIELDS_2_TUPLE;
  else
    f.as_u32 &= VNET_DEV_RSS_FIELDS_4_TUPLE;

  return f;
}

static const virtchnl_proto_hdr_type_t iavf_rss_tunnel_outer[VNET_DEV_RSS_N_CLASSES] = {
  [VNET_DEV_RSS_CLASS_IP4_IPIP_GRE] = VIRTCHNL_PROTO_HDR_IPV4,
  [VNET_DEV_RSS_CLASS_IP6_IPIP_GRE] = VIRTCHNL_PROTO_HDR_IPV6,
};

/* fields programmed for a tunnel class, only inner ones get a config of their own */
static vnet_dev_rss_fields_t
iavf_rss_tunnel_fields (const vnet_dev_rss_config_t *cfg, vnet_dev_rss_class_t class)
{
  vnet_dev_rss_fields_t f = vnet_dev_rss_class_fields (cfg, class);

  if (f.inner == 0)
    return (vnet_dev_rss_fields_t) {};

  f.as_u32 &= IAVF_RSS_TUNNEL_FIELDS;
  return f;
}

/* the PF rejects a config without fields, so every class needs at least one field. Tunnels
 * without inner are hashed by the config of the outer ip class, so they can only take its
 * fields. */
static vnet_dev_rv_t
iavf_port_validate_rss_fields (vnet_dev_port_t *port, const vnet_dev_rss_config_t *req)
{
  vnet_dev_rss_config_t cfg = port->rss_config;

  if (!vnet_dev_rss_caps_has_fields (&port->attr.rss_caps))
    return VNET_DEV_OK;

  vnet_dev_rss_config_merge (&cfg, req);

  for (u32 i = 0; i < VNET_DEV_RSS_N_CLASSES; i++)
    {
      vnet_dev_rss_fields_t f;

      if (iavf_rss_class_hdrs[i].l3 && iavf_rss_class_fields (&cfg, i).as_u32 == 0)
	return VNET_DEV_ERR_NOT_SUPPORTED;

      if (iavf_rss_tunnel_outer[i] == VIRTCHNL_PROTO_HDR_NONE)
	continue;

      f = vnet_dev_rss_class_fields (&cfg, i);
      if (f.inner && (f.as_u32 & VNET_DEV_RSS_FIELDS_4_TUPLE) == 0)
	return VNET_DEV_ERR_NOT_SUPPORTED;

      if (f.inner == 0 && (f.as_u32 & VNET_DEV_RSS_FIELDS_2_TUPLE) !=
			    iavf_rss_class_fields (&cfg, vnet_dev_rss_class_parent (i)).as_u32)
	return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
iavf_port_set_rss_class (vlib_main_t *vm, vnet_dev_port_t *port, vnet_dev_rss_class_t class,
			 vnet_dev_rss_fields_t f)
{
  /* L2 headers without fields in front, as the DPDK driver sends them: without them the ice PF
   * files the config with its own default RSS and doesn't apply one equal to the default */
  virtchnl_rss_cfg_t msg = {
    .proto_hdrs = {
      .count = 4,
      .proto_hdr = {
        { .type = VIRTCHNL_PROTO_HDR_ETH, },
        { .type = VIRTCHNL_PROTO_HDR_S_VLAN, },
        { .type = VIRTCHNL_PROTO_HDR_C_VLAN, },
      },
    },
    .rss_algorithm = VIRTCHNL_RSS_ALG_TOEPLITZ_ASYMMETRIC,
  };
  virtchnl_proto_hdr_t *h = msg.proto_hdrs.proto_hdr;
  vnet_dev_rv_t rv;

  h[3] = (virtchnl_proto_hdr_t) {
    .type = iavf_rss_class_hdrs[class].l3,
    .field_selector =
      (f.src_ip ? VIRTCHNL_PROTO_HDR_FIELD_SRC : 0) | (f.dst_ip ? VIRTCHNL_PROTO_HDR_FIELD_DST : 0),
  };

  if (iavf_rss_class_hdrs[class].l4 != VIRTCHNL_PROTO_HDR_NONE)
    {
      h[4] = (virtchnl_proto_hdr_t) {
	.type = iavf_rss_class_hdrs[class].l4,
	.field_selector = (f.src_port ? VIRTCHNL_PROTO_HDR_FIELD_SRC : 0) |
			  (f.dst_port ? VIRTCHNL_PROTO_HDR_FIELD_DST : 0),
      };
      msg.proto_hdrs.count = 5;
    }

  rv = iavf_vc_op_add_rss_cfg (vm, port->dev, &msg);

  /* fragments, the first one included, hash with the ip class so they stay on one queue. The PF
   * only takes a fragment config with the fragment packet id (field 0 of the fragment header),
   * which is also hashed */
  if (rv == VNET_DEV_OK && iavf_rss_class_hdrs[class].l4 == VIRTCHNL_PROTO_HDR_NONE)
    {
      virtchnl_proto_hdr_type_t frag = VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG;

      if (iavf_rss_class_hdrs[class].l3 == VIRTCHNL_PROTO_HDR_IPV4)
	frag = VIRTCHNL_PROTO_HDR_IPV4_FRAG;
      h[4] = (virtchnl_proto_hdr_t) { .type = frag, .field_selector = 1 };
      msg.proto_hdrs.count = 5;
      rv = iavf_vc_op_add_rss_cfg (vm, port->dev, &msg);
    }

  if (rv)
    log_err (port->dev, "failed to set rss class %U fields %U: %U", format_vnet_dev_rss_class,
	     class, format_vnet_dev_rss_fields, f, format_vnet_dev_rv, rv);

  return rv;
}

/* inner headers are selected by a GRE header after an outer ip header without fields, the PF
 * applies such a config to the IP-in-IP and GRE packet types of that outer ip version */
static vnet_dev_rv_t
iavf_port_set_rss_tunnel (vlib_main_t *vm, vnet_dev_port_t *port, vnet_dev_rss_class_t class,
			  vnet_dev_rss_fields_t f, int add)
{
  static const virtchnl_proto_hdr_type_t inner_l3[] = {
    VIRTCHNL_PROTO_HDR_IPV4,
    VIRTCHNL_PROTO_HDR_IPV6,
  };
  static const virtchnl_proto_hdr_type_t inner_l4[] = {
    VIRTCHNL_PROTO_HDR_NONE,
    VIRTCHNL_PROTO_HDR_TCP,
    VIRTCHNL_PROTO_HDR_UDP,
    VIRTCHNL_PROTO_HDR_SCTP,
  };
  u32 l3_sel =
    (f.src_ip ? VIRTCHNL_PROTO_HDR_FIELD_SRC : 0) | (f.dst_ip ? VIRTCHNL_PROTO_HDR_FIELD_DST : 0);
  u32 l4_sel = (f.src_port ? VIRTCHNL_PROTO_HDR_FIELD_SRC : 0) |
	       (f.dst_port ? VIRTCHNL_PROTO_HDR_FIELD_DST : 0);
  vnet_dev_rv_t rv;

  for (u32 i = 0; i < ARRAY_LEN (inner_l3); i++)
    for (u32 j = 0; j < ARRAY_LEN (inner_l4); j++)
      {
	virtchnl_rss_cfg_t msg = {
	  .proto_hdrs = {
	    .count = 3,
	    .proto_hdr = {
	      { .type = iavf_rss_tunnel_outer[class], },
	      { .type = VIRTCHNL_PROTO_HDR_GRE, },
	      { .type = inner_l3[i], .field_selector = l3_sel, },
	      { .type = inner_l4[j], .field_selector = l4_sel, },
	    },
	  },
	  .rss_algorithm = VIRTCHNL_RSS_ALG_TOEPLITZ_ASYMMETRIC,
	};

	if (inner_l4[j] != VIRTCHNL_PROTO_HDR_NONE)
	  {
	    if (l4_sel == 0)
	      continue;
	    msg.proto_hdrs.count = 4;
	  }
	else if (l3_sel == 0)
	  continue;

	if (add)
	  rv = iavf_vc_op_add_rss_cfg (vm, port->dev, &msg);
	else
	  rv = iavf_vc_op_del_rss_cfg (vm, port->dev, &msg);

	if (rv)
	  {
	    log_err (port->dev, "failed to %s rss class %U fields %U: %U", add ? "set" : "remove",
		     format_vnet_dev_rss_class, class, format_vnet_dev_rss_fields, f,
		     format_vnet_dev_rv, rv);
	    return rv;
	  }
      }

  return VNET_DEV_OK;
}

/* sends the classes whose fields changed, a TCP, UDP or SCTP class after its IP class so the
 * more specific config wins */
static vnet_dev_rv_t
iavf_port_set_rss_fields (vlib_main_t *vm, vnet_dev_port_t *port, const vnet_dev_rss_config_t *cfg)
{
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  if (!vnet_dev_rss_caps_has_fields (&port->attr.rss_caps))
    return VNET_DEV_OK;

  for (u32 i = 0; i < VNET_DEV_RSS_N_CLASSES; i++)
    {
      vnet_dev_rss_fields_t f;

      if (iavf_rss_class_hdrs[i].l3 == VIRTCHNL_PROTO_HDR_NONE)
	continue;

      f = iavf_rss_class_fields (cfg, i);
      if (ap->rss_fields[i].as_u32 == f.as_u32)
	continue;

      rv = iavf_port_set_rss_class (vm, port, i, f);
      if (rv)
	return rv;

      ap->rss_fields[i] = f;
    }

  for (u32 i = 0; i < VNET_DEV_RSS_N_CLASSES; i++)
    {
      vnet_dev_rss_fields_t f;

      if (iavf_rss_tunnel_outer[i] == VIRTCHNL_PROTO_HDR_NONE)
	continue;

      f = iavf_rss_tunnel_fields (cfg, i);
      if (ap->rss_fields[i].as_u32 == f.as_u32)
	continue;

      if (ap->rss_fields[i].inner)
	{
	  rv = iavf_port_set_rss_tunnel (vm, port, i, ap->rss_fields[i], 0);
	  if (rv)
	    return rv;
	  ap->rss_fields[i] = (vnet_dev_rss_fields_t) {};
	}

      if (f.inner)
	{
	  rv = iavf_port_set_rss_tunnel (vm, port, i, f, 1);
	  if (rv)
	    return rv;
	  ap->rss_fields[i] = f;
	}
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
iavf_port_init_rss (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv;

  if (!port->attr.caps.rss)
    return VNET_DEV_OK;

  rv = iavf_port_set_rss_key (vm, port, &port->rss_config);
  if (rv || !vnet_dev_rss_caps_has_fields (&port->attr.rss_caps))
    return rv;

  /* the default RSS of the PF overrides the hash fields of some classes, remove it as the DPDK
   * driver does, a PF which can't is not fatal */
  if (iavf_vc_op_set_rss_hena (vm, port->dev, &(virtchnl_rss_hena_t) {}))
    log_warn (port->dev, "PF failed to remove its default RSS");

  return iavf_port_set_rss_fields (vm, port, &port->rss_config);
}

static vnet_dev_rv_t
iavf_port_update_rss_lut (vlib_main_t *vm, vnet_dev_port_t *port, const vnet_dev_rss_config_t *cfg)
{
  vnet_dev_t *dev = port->dev;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  u16 lut_size = clib_min (IAVF_MAX_RSS_LUT_SIZE, ap->rss_lut_size);
  u8 buffer[VIRTCHNL_MSG_SZ (virtchnl_rss_lut_t, lut, lut_size)];
  virtchnl_rss_lut_t *lut = (virtchnl_rss_lut_t *) buffer;
  u32 enabled_rxq_bmp = 0;

  if (!port->attr.caps.rss)
    return VNET_DEV_OK;

  *lut = (virtchnl_rss_lut_t){
    .vsi_id = ap->vsi_id,
    .lut_entries = lut_size,
  };

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      enabled_rxq_bmp |= 1ULL << q->queue_id;

  /* config RSS LUT */
  if (cfg->set_lut)
    for (u32 i = 0; i < lut->lut_entries; i++)
      lut->lut[i] = cfg->lut[i];
  else
    for (u32 i = 0, j; i < lut->lut_entries;)
      foreach_set_bit_index (j, enabled_rxq_bmp)
	{
	  lut->lut[i++] = j;
	  if (i >= lut->lut_entries)
	    break;
	}

  return iavf_vc_op_config_rss_lut (vm, dev, lut);
}

vnet_dev_rv_t
iavf_port_init_vsi_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  virtchnl_queue_pair_info_t *qpi;
  u16 vsi_id = ap->vsi_id;
  u32 default_data_size = vlib_buffer_get_default_data_size (vm);
  u32 data_size = clib_min (default_data_size, IAVF_RX_MAX_DATA_BUF_SIZE);
  u16 max_frame_size = port->max_rx_frame_size;
  u8 buffer[VIRTCHNL_MSG_SZ (virtchnl_vsi_queue_config_info_t, qpair,
			     ap->num_qp)];
  virtchnl_vsi_queue_config_info_t *ci =
    (virtchnl_vsi_queue_config_info_t *) buffer;

  data_size &= ~(IAVF_RX_DATA_BUF_ALIGN - 1);
  if (data_size < IAVF_RX_MIN_DATA_BUF_SIZE)
    {
      log_err (dev, "VPP buffer data size %u is too small for RX", default_data_size);
      return VNET_DEV_ERR_UNSUPPORTED_CONFIG;
    }

  if (data_size != default_data_size)
    log_notice (dev, "using RX data buffer size %u for VPP buffers of %u bytes", data_size,
		default_data_size);

  *ci = (virtchnl_vsi_queue_config_info_t){
    .num_queue_pairs = ap->num_qp,
    .vsi_id = vsi_id,
  };

  for (u16 i = 0; i < ap->num_qp; i++)
    ci->qpair[i] = (virtchnl_queue_pair_info_t){
      .rxq = { .vsi_id = vsi_id,
	       .queue_id = i,
	       .max_pkt_size = ETHERNET_MIN_PACKET_BYTES },
      .txq = { .vsi_id = vsi_id, .queue_id = i },
    };

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      iavf_rxq_t *arq = vnet_dev_get_rx_queue_data (q);
      qpi = ci->qpair + q->queue_id;
      qpi->rxq.ring_len = q->size;
      qpi->rxq.databuffer_size = data_size;
      qpi->rxq.dma_ring_addr = vnet_dev_get_dma_addr (vm, dev, arq->descs);
      qpi->rxq.max_pkt_size = max_frame_size;
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      iavf_txq_t *atq = vnet_dev_get_tx_queue_data (q);
      qpi = ci->qpair + q->queue_id;
      qpi->txq.ring_len = q->size;
      qpi->txq.dma_ring_addr = vnet_dev_get_dma_addr (vm, dev, atq->descs);
    }

  return iavf_vc_op_config_vsi_queues (vm, dev, ci);
}

vnet_dev_rv_t
iavf_port_rx_irq_config (vlib_main_t *vm, vnet_dev_port_t *port, int enable)
{
  vnet_dev_t *dev = port->dev;
  iavf_device_t *ad = vnet_dev_get_data (dev);
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  u16 n_rx_vectors = ap->n_rx_vectors;
  u8 buffer[VIRTCHNL_MSG_SZ (virtchnl_irq_map_info_t, vecmap, n_rx_vectors)];
  u8 n_intr_mode_queues_per_vector[n_rx_vectors];
  u8 n_timer_or_queues_per_vector[n_rx_vectors];
  virtchnl_irq_map_info_t *im = (virtchnl_irq_map_info_t *) buffer;
  const u32 rxq_map_bits = BITS (im->vecmap[0].rxq_map);
  vnet_dev_rv_t rv;

  log_debug (dev, "intr mode per queue bitmap 0x%x",
	     ap->intr_mode_per_rxq_bitmap);

  for (u32 i = 0; i < n_rx_vectors; i++)
    n_intr_mode_queues_per_vector[i] = n_timer_or_queues_per_vector[i] = 0;

  *im = (virtchnl_irq_map_info_t){
    .num_vectors = n_rx_vectors,
  };

  if (port->attr.caps.interrupt_mode)
    {
      for (u16 i = 0; i < im->num_vectors; i++)
	im->vecmap[i] = (virtchnl_vector_map_t){
	  .vsi_id = ap->vsi_id,
	  .vector_id = i + 1,
	};
      if (enable)
	foreach_vnet_dev_port_rx_queue (rxq, port)
	  if (rxq->enabled)
	    {
	      u32 i = rxq->rx_thread_index;

	      if (rxq->queue_id >= rxq_map_bits)
		{
		  log_err (dev,
			   "rx queue id %u exceeds virtchnl irq map limit "
			   "(%u)",
			   rxq->queue_id, rxq_map_bits);
		  return VNET_DEV_ERR_NOT_SUPPORTED;
		}

	      if (i >= n_rx_vectors)
		{
		  log_err (dev,
			   "rx queue %u thread index %u out of range "
			   "(%u vectors)",
			   rxq->queue_id, i, n_rx_vectors);
		  return VNET_DEV_ERR_BUG;
		}

	      im->vecmap[i].rxq_map |= 1 << rxq->queue_id;
	      n_timer_or_queues_per_vector[i]++;
	      n_intr_mode_queues_per_vector[i] +=
		u64_is_bit_set (ap->intr_mode_per_rxq_bitmap, rxq->queue_id);
	    }
    }
  else
    {
      im->vecmap[0] = (virtchnl_vector_map_t) {
	.vsi_id = ap->vsi_id,
	.vector_id = 1,
      };
      if (enable)
	foreach_vnet_dev_port_rx_queue (rxq, port)
	  if (rxq->enabled)
	    {
	      if (rxq->queue_id >= rxq_map_bits)
		{
		  log_err (dev,
			   "rx queue id %u exceeds virtchnl irq map limit "
			   "(%u)",
			   rxq->queue_id, rxq_map_bits);
		  return VNET_DEV_ERR_NOT_SUPPORTED;
		}
	      im->vecmap[0].rxq_map |= 1 << rxq->queue_id;
	      n_timer_or_queues_per_vector[0]++;
	    }
    }

  if ((rv = iavf_vc_op_config_irq_map (vm, dev, im)))
    return rv;

  for (int i = 0; i < n_rx_vectors; i++)
    {
      u32 val;

      if (enable == 0 || n_timer_or_queues_per_vector[i] == 0)
	val = dyn_ctln_disabled.as_u32;
      else if (ap->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_WB_ON_ITR &&
	       n_intr_mode_queues_per_vector[i] == 0)
	val = dyn_ctln_wb_on_itr.as_u32;
      else
	val = dyn_ctln_enabled.as_u32;

      iavf_reg_write (ad, IAVF_VFINT_DYN_CTLN (i), val);
      log_debug (dev, "VFINT_DYN_CTLN(%u) set to 0x%x", i, val);
    }

  return rv;
}

static void
avf_msix_n_handler (vlib_main_t *vm, vnet_dev_t *dev, u16 line)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);

  line--;

  iavf_reg_write (ad, IAVF_VFINT_DYN_CTLN (line), dyn_ctln_enabled.as_u32);
  vlib_node_set_interrupt_pending (vlib_get_main_by_index (line),
				   vnet_dev_get_port_rx_node_index (port));
}

vnet_dev_rv_t
iavf_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port %u", port->port_id);

  ap->intr_mode_per_rxq_bitmap = 0;
  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->interrupt_mode)
      u64_bit_set (&ap->intr_mode_per_rxq_bitmap, q->queue_id, 1);

  if ((rv = iavf_port_vlan_strip_disable (vm, port)))
    {
      if (rv == VNET_DEV_ERR_NOT_SUPPORTED)
	log_warn (port->dev, "device doesn't support vlan stripping");
      else
	return rv;
    }

  if ((rv = iavf_port_init_rss (vm, port)))
    return rv;

  rv = vnet_dev_pci_msix_add_handler (vm, dev, &avf_msix_n_handler, 1, ap->n_rx_vectors);
  if (rv)
    return rv;

  rv = vnet_dev_pci_msix_enable (vm, dev, 1, ap->n_rx_vectors);
  if (rv)
    return rv;

  for (u32 i = 0; i < ap->n_rx_vectors; i++)
    vnet_dev_pci_msix_set_polling_thread (vm, dev, i + 1, i);

  if (port->dev->poll_stats)
    iavf_port_add_counters (vm, port);

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
iavf_enable_disable_queues (vlib_main_t *vm, vnet_dev_port_t *port, int enable)
{
  iavf_port_t *ap = vnet_dev_get_port_data (port);

  virtchnl_queue_select_t qs = {
    .vsi_id = ap->vsi_id,
  };

  foreach_vnet_dev_port_rx_queue (q, port)
    if ((enable && q->enabled) || (!enable && q->started))
      qs.rx_queues |= 1ULL << q->queue_id;

  foreach_vnet_dev_port_tx_queue (q, port)
    if ((enable && q->enabled) || (!enable && q->started))
      qs.tx_queues |= 1ULL << q->queue_id;

  return enable ? iavf_vc_op_enable_queues (vm, port->dev, &qs) :
			iavf_vc_op_disable_queues (vm, port->dev, &qs);
}

vnet_dev_rv_t
iavf_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port %u", port->port_id);

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      vnet_dev_get_rx_queue_if_buffer_template_ptr (q)->flags |=
	VNET_BUFFER_F_L4_CHECKSUM_COMPUTED | VNET_BUFFER_F_L4_CHECKSUM_CORRECT;

      if (q->enabled)
	if ((rv = iavf_rx_queue_start (vm, q)))
	  goto done;
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    if ((rv = iavf_tx_queue_start (vm, q)))
      goto done;

  if ((rv = iavf_port_update_rss_lut (vm, port, &port->rss_config)))
    goto done;

  /* configure qpairs */
  if ((rv = iavf_port_init_vsi_queues (vm, port)))
    goto done;

  if ((rv = iavf_port_rx_irq_config (vm, port, /* enable */ 1)))
    goto done;

  if ((rv = iavf_enable_disable_queues (vm, port, 1)))
    goto done;

  if (port->dev->poll_stats)
    vnet_dev_poll_port_add (vm, port, 1, iavf_port_poll_stats);

done:
  if (rv)
    {
      foreach_vnet_dev_port_rx_queue (q, port)
	iavf_rx_queue_stop (vm, q);
      foreach_vnet_dev_port_tx_queue (q, port)
	iavf_tx_queue_stop (vm, q);
    }
  return rv;
}

void
iavf_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "port %u", port->port_id);

  iavf_enable_disable_queues (vm, port, /* enable */ 0);
  iavf_port_rx_irq_config (vm, port, /* disable */ 0);

  if (port->dev->poll_stats)
    vnet_dev_poll_port_remove (vm, port, iavf_port_poll_stats);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    iavf_rx_queue_stop (vm, rxq);

  foreach_vnet_dev_port_tx_queue (txq, port)
    iavf_tx_queue_stop (vm, txq);

}

vnet_dev_rv_t
iavf_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
			       vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      if (port->started)
	rv = VNET_DEV_ERR_PORT_STARTED;
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      break;

    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      {
	iavf_port_t *ap = vnet_dev_get_port_data (port);
	vnet_dev_rss_config_t *cfg = &req->rss_config;

	if ((cfg->set_key && cfg->key_len != clib_min (IAVF_MAX_RSS_KEY_SIZE, ap->rss_key_size)) ||
	    (cfg->set_lut && cfg->lut_len != clib_min (IAVF_MAX_RSS_LUT_SIZE, ap->rss_lut_size)))
	  rv = VNET_DEV_ERR_INVALID_DATA;
	else
	  rv = iavf_port_validate_rss_fields (port, cfg);
      }
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}

static vnet_dev_rv_t
iavf_port_add_del_eth_addr (vlib_main_t *vm, vnet_dev_port_t *port, vnet_dev_hw_addr_t *addr,
			    int is_add, int is_primary)
{
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  u8 buffer[VIRTCHNL_MSG_SZ (virtchnl_ether_addr_list_t, list, 1)];
  virtchnl_ether_addr_list_t *al = (virtchnl_ether_addr_list_t *) buffer;

  *al = (virtchnl_ether_addr_list_t) {
    .vsi_id = ap->vsi_id,
    .num_elements = 1,
    .list[0].primary = is_primary ? 1 : 0,
    .list[0].extra = is_primary ? 0 : 1,
  };

  clib_memcpy (al->list[0].addr, addr, sizeof (al->list[0].addr));

  return is_add ? iavf_vc_op_add_eth_addr (vm, port->dev, al) :
		  iavf_vc_op_del_eth_addr (vm, port->dev, al);
}

static vnet_dev_rv_t
iavf_port_cfg_rxq_int_mode_change (vlib_main_t *vm, vnet_dev_port_t *port,
				   u16 qid, u8 state, u8 all)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  vnet_dev_t *dev = port->dev;
  char *ed = state ? "ena" : "disa";
  char qstr[16];
  u64 old, new = 0;

  state = state != 0;
  old = ap->intr_mode_per_rxq_bitmap;

  if (all)
    {
      snprintf (qstr, sizeof (qstr), "all queues");
      if (state)
	foreach_vnet_dev_port_rx_queue (q, port)
	  u64_bit_set (&new, q->queue_id, 1);
    }
  else
    {
      snprintf (qstr, sizeof (qstr), "queue %u", qid);
      new = old;
      u64_bit_set (&new, qid, state);
    }

  if (new == old)
    {
      log_warn (dev, "interrupt mode already %sbled on %s", ed, qstr);
      return rv;
    }

  ap->intr_mode_per_rxq_bitmap = new;

  if (port->started)
    {
      if ((rv = iavf_port_rx_irq_config (vm, port, 1)))
	{
	  ap->intr_mode_per_rxq_bitmap = old;
	  log_err (dev, "failed to %sble interrupt mode on %s", ed, qstr);
	  return rv;
	}
    }

  log_debug (dev, "interrupt mode %sbled on %s, new bitmap is 0x%x", ed, qstr,
	     new);
  return rv;
}

vnet_dev_rv_t
iavf_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		      vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      {
	virtchnl_promisc_info_t pi = {
	  .vsi_id = ap->vsi_id,
	  .unicast_promisc = req->promisc,
	  .multicast_promisc = req->promisc,
	};

	rv = iavf_vc_op_config_promisc_mode (vm, dev, &pi);
      }
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      rv = iavf_port_add_del_eth_addr (vm, port, &port->primary_hw_addr,
				       /* is_add */ 0,
				       /* is_primary */ 1);
      if (rv == VNET_DEV_OK)
	rv = iavf_port_add_del_eth_addr (vm, port, &req->addr,
					 /* is_add */ 1,
					 /* is_primary */ 1);
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      rv = iavf_port_add_del_eth_addr (vm, port, &req->addr,
				       /* is_add */ 1,
				       /* is_primary */ 0);
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      rv = iavf_port_add_del_eth_addr (vm, port, &req->addr,
				       /* is_add */ 0,
				       /* is_primary */ 0);
      break;

    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;

    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      if (req->rss_config.set_key)
	rv = iavf_port_set_rss_key (vm, port, &req->rss_config);
      if (rv == VNET_DEV_OK && req->rss_config.set_lut && port->started)
	rv = iavf_port_update_rss_lut (vm, port, &req->rss_config);
      if (rv == VNET_DEV_OK)
	{
	  vnet_dev_rss_config_t cfg = port->rss_config;

	  vnet_dev_rss_config_merge (&cfg, &req->rss_config);
	  rv = iavf_port_set_rss_fields (vm, port, &cfg);
	  if (rv)
	    iavf_port_set_rss_fields (vm, port, &port->rss_config);
	}
      break;

    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
      rv = iavf_port_cfg_rxq_int_mode_change (vm, port, req->queue_id, 1,
					      req->all_queues);
      break;

    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      rv = iavf_port_cfg_rxq_int_mode_change (vm, port, req->queue_id, 0,
					      req->all_queues);
      break;

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
