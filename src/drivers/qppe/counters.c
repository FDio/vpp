/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

#define HPPE_REG_BM_SILENT_DROP_CNT(port)   (0x00b024 + 0x4 * (port))
#define HPPE_REG_BM_OVERFLOW_DROP_CNT(port) (0x0000e000 + 0x10 * (port))
#define APPE_REG_VP_RX_CNT(vp)		    (0x00150000 + 0x20 * (vp))
#define APPE_REG_PRE_L2_CNT(vsi)	    (0x0017c000 + 0x20 * (vsi))
#define HPPE_REG_QM_QUEUE_TX_CNT(queue)	    (0x81a000 + 0x10 * (queue))
#define HPPE_REG_QM_UNICAST_DROP_CNT(queue, type)                                                  \
  (0x009e0000 + 0x10 * ((queue) * HPPE_QM_UNICAST_DROP_TYPES + (type)))
#define HPPE_REG_PORT_TX_COUNTER_TBL(port)  (0x020900 + 0x10 * (port))
#define HPPE_REG_PORT_TX_DROP_CNT_TBL(port) (0x17d000 + 0x10 * (port))
#define PPE_GMAC_REG_MIB_CONTROL	    0x34
#define PPE_XGMAC_REG_MMC_CONTROL	    0x800

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "counters",
};

#define QPPE_COUNTER_ID_VENDOR(id) id,
#define QPPE_COUNTER_ID_GENERIC(id)
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_ID_##type (QPPE_XGMAC_CTR_RX_##name)
typedef enum
{
  QPPE_XGMAC_CTR_RX_BYTES,
  QPPE_XGMAC_CTR_RX_PACKETS,
  QPPE_XGMAC_CTR_TX_BYTES,
  QPPE_XGMAC_CTR_TX_PACKETS,
  foreach_ppe_xgmac_rx_counter
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_ID_##type (QPPE_XGMAC_CTR_TX_##name)
    foreach_ppe_xgmac_tx_counter QPPE_XGMAC_CTR_PPE_TX_PACKETS,
  QPPE_XGMAC_CTR_PPE_TX_DROP_PACKETS,
  QPPE_XGMAC_CTR_BM_SILENT_DROP,
  QPPE_XGMAC_CTR_BM_OVERFLOW_DROP,
  QPPE_XGMAC_CTR_PORT_RX_PACKETS,
  QPPE_XGMAC_CTR_PORT_RX_DROP,
  QPPE_XGMAC_CTR_VP_RX_PACKETS,
  QPPE_XGMAC_CTR_VP_RX_DROP,
  QPPE_XGMAC_CTR_QM_DEQUEUE_PACKETS,
  QPPE_XGMAC_CTR_QM_DROP_PACKETS,
  QPPE_XGMAC_CTR_PRE_L2_PACKETS,
  QPPE_XGMAC_CTR_PRE_L2_DROP,
} qppe_xgmac_counter_id_t;
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_ID_##type (QPPE_GMAC_CTR_RX_##name)
typedef enum
{
  QPPE_GMAC_CTR_RX_BYTES,
  QPPE_GMAC_CTR_RX_PACKETS,
  QPPE_GMAC_CTR_TX_BYTES,
  QPPE_GMAC_CTR_TX_PACKETS,
  foreach_ppe_gmac_rx_counter
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_ID_##type (QPPE_GMAC_CTR_TX_##name)
    foreach_ppe_gmac_tx_counter QPPE_GMAC_CTR_PPE_TX_PACKETS,
  QPPE_GMAC_CTR_PPE_TX_DROP_PACKETS,
  QPPE_GMAC_CTR_BM_SILENT_DROP,
  QPPE_GMAC_CTR_BM_OVERFLOW_DROP,
  QPPE_GMAC_CTR_PORT_RX_PACKETS,
  QPPE_GMAC_CTR_PORT_RX_DROP,
  QPPE_GMAC_CTR_VP_RX_PACKETS,
  QPPE_GMAC_CTR_VP_RX_DROP,
  QPPE_GMAC_CTR_QM_DEQUEUE_PACKETS,
  QPPE_GMAC_CTR_QM_DROP_PACKETS,
  QPPE_GMAC_CTR_PRE_L2_PACKETS,
  QPPE_GMAC_CTR_PRE_L2_DROP,
} qppe_gmac_counter_id_t;
#undef _
#undef QPPE_COUNTER_ID_VENDOR
#undef QPPE_COUNTER_ID_GENERIC

#define QPPE_COUNTER_DESC_VENDOR(index, direction, unit, description)                              \
  VNET_DEV_CTR_VENDOR (index, direction, unit, description),
#define QPPE_COUNTER_DESC_GENERIC(index, direction, unit, description)
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_DESC_##type (QPPE_XGMAC_CTR_RX_##name, RX, unit, description)
static vnet_dev_counter_t qppe_xgmac_port_counters[] = {
  [QPPE_XGMAC_CTR_RX_BYTES] = VNET_DEV_CTR_RX_BYTES (QPPE_XGMAC_CTR_RX_BYTES),
  [QPPE_XGMAC_CTR_RX_PACKETS] = VNET_DEV_CTR_RX_PACKETS (QPPE_XGMAC_CTR_RX_PACKETS),
  [QPPE_XGMAC_CTR_TX_BYTES] = VNET_DEV_CTR_TX_BYTES (QPPE_XGMAC_CTR_TX_BYTES),
  [QPPE_XGMAC_CTR_TX_PACKETS] = VNET_DEV_CTR_TX_PACKETS (QPPE_XGMAC_CTR_TX_PACKETS),
  foreach_ppe_xgmac_rx_counter
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_DESC_##type (QPPE_XGMAC_CTR_TX_##name, TX, unit, description)
    foreach_ppe_xgmac_tx_counter[QPPE_XGMAC_CTR_PPE_TX_PACKETS] =
      VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_PPE_TX_PACKETS, TX, PACKETS, "xgmac_ppe"),
  [QPPE_XGMAC_CTR_PPE_TX_DROP_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_PPE_TX_DROP_PACKETS, TX, PACKETS, "xgmac_ppe_drop"),
  [QPPE_XGMAC_CTR_BM_SILENT_DROP] =
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_BM_SILENT_DROP, RX, PACKETS, "xgmac_bm_silent_drop"),
  [QPPE_XGMAC_CTR_BM_OVERFLOW_DROP] =
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_BM_OVERFLOW_DROP, RX, PACKETS, "xgmac_bm_overflow_drop"),
  [QPPE_XGMAC_CTR_PORT_RX_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_PORT_RX_PACKETS, RX, PACKETS, "xgmac_port"),
  [QPPE_XGMAC_CTR_PORT_RX_DROP] =
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_PORT_RX_DROP, RX, PACKETS, "xgmac_port_drop"),
  [QPPE_XGMAC_CTR_VP_RX_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_VP_RX_PACKETS, RX, PACKETS, "xgmac_vp"),
  [QPPE_XGMAC_CTR_VP_RX_DROP] =
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_VP_RX_DROP, RX, PACKETS, "xgmac_vp_drop"),
  [QPPE_XGMAC_CTR_QM_DEQUEUE_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_QM_DEQUEUE_PACKETS, RX, PACKETS, "xgmac_qm_dequeue"),
  [QPPE_XGMAC_CTR_QM_DROP_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_QM_DROP_PACKETS, RX, PACKETS, "xgmac_qm_drop"),
  [QPPE_XGMAC_CTR_PRE_L2_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_PRE_L2_PACKETS, RX, PACKETS, "xgmac_pre_l2"),
  [QPPE_XGMAC_CTR_PRE_L2_DROP] =
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_PRE_L2_DROP, RX, PACKETS, "xgmac_pre_l2_drop"),
};
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_DESC_##type (QPPE_GMAC_CTR_RX_##name, RX, unit, description)
static vnet_dev_counter_t qppe_gmac_port_counters[] = {
  [QPPE_GMAC_CTR_RX_BYTES] = VNET_DEV_CTR_RX_BYTES (QPPE_GMAC_CTR_RX_BYTES),
  [QPPE_GMAC_CTR_RX_PACKETS] = VNET_DEV_CTR_RX_PACKETS (QPPE_GMAC_CTR_RX_PACKETS),
  [QPPE_GMAC_CTR_TX_BYTES] = VNET_DEV_CTR_TX_BYTES (QPPE_GMAC_CTR_TX_BYTES),
  [QPPE_GMAC_CTR_TX_PACKETS] = VNET_DEV_CTR_TX_PACKETS (QPPE_GMAC_CTR_TX_PACKETS),
  foreach_ppe_gmac_rx_counter
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_DESC_##type (QPPE_GMAC_CTR_TX_##name, TX, unit, description)
    foreach_ppe_gmac_tx_counter[QPPE_GMAC_CTR_PPE_TX_PACKETS] =
      VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_PPE_TX_PACKETS, TX, PACKETS, "gmac_ppe"),
  [QPPE_GMAC_CTR_PPE_TX_DROP_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_PPE_TX_DROP_PACKETS, TX, PACKETS, "gmac_ppe_drop"),
  [QPPE_GMAC_CTR_BM_SILENT_DROP] =
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_BM_SILENT_DROP, RX, PACKETS, "gmac_bm_silent_drop"),
  [QPPE_GMAC_CTR_BM_OVERFLOW_DROP] =
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_BM_OVERFLOW_DROP, RX, PACKETS, "gmac_bm_overflow_drop"),
  [QPPE_GMAC_CTR_PORT_RX_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_PORT_RX_PACKETS, RX, PACKETS, "gmac_port"),
  [QPPE_GMAC_CTR_PORT_RX_DROP] =
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_PORT_RX_DROP, RX, PACKETS, "gmac_port_drop"),
  [QPPE_GMAC_CTR_VP_RX_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_VP_RX_PACKETS, RX, PACKETS, "gmac_vp"),
  [QPPE_GMAC_CTR_VP_RX_DROP] =
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_VP_RX_DROP, RX, PACKETS, "gmac_vp_drop"),
  [QPPE_GMAC_CTR_QM_DEQUEUE_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_QM_DEQUEUE_PACKETS, RX, PACKETS, "gmac_qm_dequeue"),
  [QPPE_GMAC_CTR_QM_DROP_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_QM_DROP_PACKETS, RX, PACKETS, "gmac_qm_drop"),
  [QPPE_GMAC_CTR_PRE_L2_PACKETS] =
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_PRE_L2_PACKETS, RX, PACKETS, "gmac_pre_l2"),
  [QPPE_GMAC_CTR_PRE_L2_DROP] =
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_PRE_L2_DROP, RX, PACKETS, "gmac_pre_l2_drop"),
};
#undef _
#undef QPPE_COUNTER_DESC_VENDOR
#undef QPPE_COUNTER_DESC_GENERIC

typedef enum
{
  QPPE_MIB_COUNTER_TYPE_GENERIC,
  QPPE_MIB_COUNTER_TYPE_VENDOR,
} qppe_mib_counter_type_t;

typedef struct
{
  const char *name;
  u32 reg;
  u16 counter_index;
  u8 width;
  qppe_mib_counter_type_t type;
  vnet_dev_counter_direction_t direction;
  vnet_dev_counter_unit_t unit;
} qppe_mib_counter_t;

#define QPPE_COUNTER_INDEX_VENDOR(mac, direction, name, unit)  QPPE_##mac##_CTR_##direction##_##name
#define QPPE_COUNTER_INDEX_GENERIC(mac, direction, name, unit) QPPE_##mac##_CTR_##direction##_##unit
#define QPPE_COUNTER_TYPE_VENDOR			       QPPE_MIB_COUNTER_TYPE_VENDOR
#define QPPE_COUNTER_TYPE_GENERIC			       QPPE_MIB_COUNTER_TYPE_GENERIC
#define _(reg_offset, counter_name, counter_description, counter_width, counter_type,              \
	  counter_unit)                                                                            \
  {                                                                                                \
    .name = counter_description,                                                                   \
    .reg = reg_offset,                                                                             \
    .counter_index = QPPE_COUNTER_INDEX_##counter_type (XGMAC, RX, counter_name, counter_unit),    \
    .width = counter_width,                                                                        \
    .type = QPPE_COUNTER_TYPE_##counter_type,                                                      \
    .direction = VNET_DEV_CTR_DIR_RX,                                                              \
    .unit = VNET_DEV_CTR_UNIT_##counter_unit,                                                      \
  },
static const qppe_mib_counter_t qppe_xgmac_mib_counters[] = { foreach_ppe_xgmac_rx_counter
#undef _
#define _(reg_offset, counter_name, counter_description, counter_width, counter_type,              \
	  counter_unit)                                                                            \
  {                                                                                                \
    .name = counter_description,                                                                   \
    .reg = reg_offset,                                                                             \
    .counter_index = QPPE_COUNTER_INDEX_##counter_type (XGMAC, TX, counter_name, counter_unit),    \
    .width = counter_width,                                                                        \
    .type = QPPE_COUNTER_TYPE_##counter_type,                                                      \
    .direction = VNET_DEV_CTR_DIR_TX,                                                              \
    .unit = VNET_DEV_CTR_UNIT_##counter_unit,                                                      \
  },
								foreach_ppe_xgmac_tx_counter };
#undef _
#define _(reg_offset, counter_name, counter_description, counter_width, counter_type,              \
	  counter_unit)                                                                            \
  {                                                                                                \
    .name = counter_description,                                                                   \
    .reg = reg_offset,                                                                             \
    .counter_index = QPPE_COUNTER_INDEX_##counter_type (GMAC, RX, counter_name, counter_unit),     \
    .width = counter_width,                                                                        \
    .type = QPPE_COUNTER_TYPE_##counter_type,                                                      \
    .direction = VNET_DEV_CTR_DIR_RX,                                                              \
    .unit = VNET_DEV_CTR_UNIT_##counter_unit,                                                      \
  },
static const qppe_mib_counter_t qppe_gmac_mib_counters[] = { foreach_ppe_gmac_rx_counter
#undef _
#define _(reg_offset, counter_name, counter_description, counter_width, counter_type,              \
	  counter_unit)                                                                            \
  {                                                                                                \
    .name = counter_description,                                                                   \
    .reg = reg_offset,                                                                             \
    .counter_index = QPPE_COUNTER_INDEX_##counter_type (GMAC, TX, counter_name, counter_unit),     \
    .width = counter_width,                                                                        \
    .type = QPPE_COUNTER_TYPE_##counter_type,                                                      \
    .direction = VNET_DEV_CTR_DIR_TX,                                                              \
    .unit = VNET_DEV_CTR_UNIT_##counter_unit,                                                      \
  },
							       foreach_ppe_gmac_tx_counter };
#undef _
#undef QPPE_COUNTER_INDEX_VENDOR
#undef QPPE_COUNTER_INDEX_GENERIC
#undef QPPE_COUNTER_TYPE_VENDOR
#undef QPPE_COUNTER_TYPE_GENERIC

static u64
qppe_mib_counter_read64 (qppe_device_t *qd, u32 base, u32 reg)
{
  u32 low = qppe_mmio_read32 (qd, base + reg);
  u32 high = qppe_mmio_read32 (qd, base + reg + sizeof (u32));

  return ((u64) high << 32) | low;
}

static u64
qppe_mib_counter_read (qppe_device_t *qd, u32 base, u32 reg, u8 width)
{
  if (width == sizeof (u64))
    return qppe_mib_counter_read64 (qd, base, reg);

  return qppe_mmio_read32 (qd, base + reg);
}

/* Decodes APPE_REG_PHY_PORT_RX_CNT's 5-word entry: word0 is the packet count;
 * the drop count is split as word2's bits 8-31 (its own low 24 bits) and
 * word3's bits 0-7 (its own high 8 bits). */
static void
qppe_port_rx_cnt_read (qppe_device_t *qd, u32 reg, u32 *pkt_cnt, u32 *drop_cnt)
{
  *pkt_cnt = qppe_mmio_read32 (qd, reg);
  *drop_cnt = (qppe_mmio_read32 (qd, reg + 2 * sizeof (u32)) >> 8) |
	      ((qppe_mmio_read32 (qd, reg + 3 * sizeof (u32)) & 0xff) << 24);
}

/* Sums all HPPE_QM_UNICAST_DROP_TYPES per-reason drop counters (word0 of each
 * 3-word entry) for one hardware unicast queue into a single total. */
static u32
qppe_qm_drop_cnt_read (qppe_device_t *qd, u32 queue)
{
  u32 total = 0;
  u32 type;

  for (type = 0; type < HPPE_QM_UNICAST_DROP_TYPES; type++)
    total += qppe_mmio_read32 (qd, HPPE_REG_QM_UNICAST_DROP_CNT (queue, type));

  return total;
}

static u8
qppe_port_uses_xgmac (qppe_port_t *qp)
{
  return qp->phy_mode &&
	 (strcmp (qp->phy_mode, "2500base-x") == 0 || strcmp (qp->phy_mode, "usxgmii") == 0 ||
	  strcmp (qp->phy_mode, "10gbase-r") == 0 || strcmp (qp->phy_mode, "10g-qxgmii") == 0);
}

static void
qppe_port_ppe_tx_counters_clear (qppe_device_t *qd, u32 port_id)
{
  u32 offset;

  for (offset = 0; offset < 3 * sizeof (u32); offset += sizeof (u32))
    {
      qppe_mmio_write32 (qd, HPPE_REG_PORT_TX_COUNTER_TBL (port_id) + offset, 0);
      qppe_mmio_write32 (qd, HPPE_REG_PORT_TX_DROP_CNT_TBL (port_id) + offset, 0);
    }
}

vnet_dev_rv_t
qppe_port_counters_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  ppe_reg_xgmac_mmc_control_t mmc = {};
  u32 base;
  u32 offset;

  qppe_port_ppe_tx_counters_clear (qd, port->port_id);

  if (!qppe_port_uses_xgmac (qp))
    {
      ppe_reg_gmac_mib_control_t gmac_mib = {};

      base = PPE_REG_GMAC_BASE (port->port_id);
      offset = base + PPE_GMAC_REG_MIB_CONTROL;
      gmac_mib.as_u32 = qppe_mmio_read32 (qd, offset);
      log_debug (dev, "port %u read GMAC MIB control at offset 0x%x: 0x%08x", port->port_id, offset,
		 gmac_mib.as_u32);
      if (gmac_mib.as_u32 == 0xffffffff)
	{
	  log_err (dev, "port %u GMAC MIB control read returned all ones", port->port_id);
	  return VNET_DEV_ERR_INIT_FAILED;
	}

      gmac_mib.enable = 1;
      gmac_mib.reset = 1;
      gmac_mib.read_clear = 1;
      log_debug (dev, "port %u enabling/resetting GMAC read-clear MIB counters: 0x%08x",
		 port->port_id, gmac_mib.as_u32);
      qppe_mmio_write32 (qd, offset, gmac_mib.as_u32);
      gmac_mib.reset = 0;
      qppe_mmio_write32 (qd, offset, gmac_mib.as_u32);
      log_debug (dev, "port %u GMAC MIB counters enabled in read-clear mode", port->port_id);

      /* unlike the MAC's own MIB counters above, these are global PPE-core
       * state with no reset line of their own; clear them here so they read
       * "since this port last started" like everything else, rather than
       * carrying over drops from whatever ran on this chip before. */
      qppe_mmio_write32 (qd, HPPE_REG_BM_SILENT_DROP_CNT (port->port_id), 0);
      qppe_mmio_write32 (qd, HPPE_REG_BM_OVERFLOW_DROP_CNT (port->port_id), 0);
      qppe_mmio_write32 (qd, HPPE_REG_BM_OVERFLOW_DROP_CNT (port->port_id) + 4, 0);
      qppe_mmio_write32 (qd, HPPE_REG_BM_OVERFLOW_DROP_CNT (port->port_id) + 8, 0);
      for (offset = 0; offset < 5 * sizeof (u32); offset += sizeof (u32))
	{
	  qppe_mmio_write32 (qd, APPE_REG_PHY_PORT_RX_CNT (port->port_id) + offset, 0);
	  qppe_mmio_write32 (qd, APPE_REG_VP_RX_CNT (EDMA_VP_BASE + port->port_id) + offset, 0);
	}
      {
	u32 queue = qp->source_profile * EDMA_RX_QUEUES_PER_RING;
	u32 type;

	for (offset = 0; offset < 3 * sizeof (u32); offset += sizeof (u32))
	  qppe_mmio_write32 (qd, HPPE_REG_QM_QUEUE_TX_CNT (queue) + offset, 0);
	for (type = 0; type < HPPE_QM_UNICAST_DROP_TYPES; type++)
	  for (offset = 0; offset < 3 * sizeof (u32); offset += sizeof (u32))
	    qppe_mmio_write32 (qd, HPPE_REG_QM_UNICAST_DROP_CNT (queue, type) + offset, 0);
      }
      for (offset = 0; offset < 5 * sizeof (u32); offset += sizeof (u32))
	qppe_mmio_write32 (qd, APPE_REG_PRE_L2_CNT (port->port_id) + offset, 0);

      vnet_dev_port_add_counters (vm, port, qppe_gmac_port_counters,
				  ARRAY_LEN (qppe_gmac_port_counters));
      log_debug (dev, "port %u registered %u hardware GMAC MIB counters", port->port_id,
		 ARRAY_LEN (qppe_gmac_port_counters));
      return VNET_DEV_OK;
    }

  base = PPE_REG_XGMAC_BASE (port->port_id);
  offset = base + PPE_XGMAC_REG_MMC_CONTROL;

  mmc.as_u32 = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "port %u read XGMAC MMC control at offset 0x%x: 0x%08x", port->port_id, offset,
	     mmc.as_u32);
  if (mmc.as_u32 == 0xffffffff)
    {
      log_err (dev, "port %u XGMAC MMC control read returned all ones", port->port_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  mmc.counter_reset = 1;
  mmc.counter_freeze = 0;
  log_debug (dev, "port %u resetting XGMAC MIB counters with MMC control 0x%08x", port->port_id,
	     mmc.as_u32);
  qppe_mmio_write32 (qd, offset, mmc.as_u32);

  /* unlike the MAC's own MIB counters above, these are global PPE-core state
   * with no reset line of their own; clear them here so they read "since
   * this port last started" like everything else, rather than carrying over
   * drops from whatever ran on this chip before. */
  qppe_mmio_write32 (qd, HPPE_REG_BM_SILENT_DROP_CNT (port->port_id), 0);
  qppe_mmio_write32 (qd, HPPE_REG_BM_OVERFLOW_DROP_CNT (port->port_id), 0);
  qppe_mmio_write32 (qd, HPPE_REG_BM_OVERFLOW_DROP_CNT (port->port_id) + 4, 0);
  qppe_mmio_write32 (qd, HPPE_REG_BM_OVERFLOW_DROP_CNT (port->port_id) + 8, 0);
  for (offset = 0; offset < 5 * sizeof (u32); offset += sizeof (u32))
    {
      qppe_mmio_write32 (qd, APPE_REG_PHY_PORT_RX_CNT (port->port_id) + offset, 0);
      qppe_mmio_write32 (qd, APPE_REG_VP_RX_CNT (EDMA_VP_BASE + port->port_id) + offset, 0);
    }
  {
    u32 queue = qp->source_profile * EDMA_RX_QUEUES_PER_RING;
    u32 type;

    for (offset = 0; offset < 3 * sizeof (u32); offset += sizeof (u32))
      qppe_mmio_write32 (qd, HPPE_REG_QM_QUEUE_TX_CNT (queue) + offset, 0);
    for (type = 0; type < HPPE_QM_UNICAST_DROP_TYPES; type++)
      for (offset = 0; offset < 3 * sizeof (u32); offset += sizeof (u32))
	qppe_mmio_write32 (qd, HPPE_REG_QM_UNICAST_DROP_CNT (queue, type) + offset, 0);
  }
  for (offset = 0; offset < 5 * sizeof (u32); offset += sizeof (u32))
    qppe_mmio_write32 (qd, APPE_REG_PRE_L2_CNT (port->port_id) + offset, 0);

  vnet_dev_port_add_counters (vm, port, qppe_xgmac_port_counters,
			      ARRAY_LEN (qppe_xgmac_port_counters));
  log_debug (dev, "port %u registered %u hardware XGMAC MIB counters", port->port_id,
	     ARRAY_LEN (qppe_xgmac_port_counters));

  return VNET_DEV_OK;
}

void
qppe_port_counters_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  vnet_dev_counter_t *counter;
  u32 base;

  qppe_port_phy_poll (vm, port);

  if (!qppe_port_uses_xgmac (qp))
    {
      u64 rx_bytes = 0;
      u64 rx_packets = 0;
      u64 tx_bytes = 0;
      u64 tx_packets = 0;

      base = PPE_REG_GMAC_BASE (port->port_id);
      FOREACH_ARRAY_ELT (mib_counter, qppe_gmac_mib_counters)
	{
	  u64 value = qppe_mib_counter_read (qd, base, mib_counter->reg, mib_counter->width);

	  counter = vnet_dev_port_get_counter_by_index (vm, port, mib_counter->counter_index);
	  vnet_dev_counter_value_add (vm, counter, value);

	  if (mib_counter->type == QPPE_MIB_COUNTER_TYPE_GENERIC)
	    {
	      if (mib_counter->direction == VNET_DEV_CTR_DIR_RX)
		rx_bytes = value;
	      else
		tx_bytes = value;
	    }
	  else if (mib_counter->direction == VNET_DEV_CTR_DIR_RX &&
		   (mib_counter->counter_index == QPPE_GMAC_CTR_RX_UNICAST ||
		    mib_counter->counter_index == QPPE_GMAC_CTR_RX_MULTICAST ||
		    mib_counter->counter_index == QPPE_GMAC_CTR_RX_BROADCAST))
	    rx_packets += value;
	  else if (mib_counter->direction == VNET_DEV_CTR_DIR_TX &&
		   (mib_counter->counter_index == QPPE_GMAC_CTR_TX_UNICAST ||
		    mib_counter->counter_index == QPPE_GMAC_CTR_TX_MULTICAST ||
		    mib_counter->counter_index == QPPE_GMAC_CTR_TX_BROADCAST))
	    tx_packets += value;
	}

      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_RX_PACKETS);
      vnet_dev_counter_value_add (vm, counter, rx_packets);
      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_TX_PACKETS);
      vnet_dev_counter_value_add (vm, counter, tx_packets);

      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_PPE_TX_PACKETS);
      vnet_dev_counter_value_update (
	vm, counter, qppe_mmio_read32 (qd, HPPE_REG_PORT_TX_COUNTER_TBL (port->port_id)));
      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_PPE_TX_DROP_PACKETS);
      vnet_dev_counter_value_update (
	vm, counter, qppe_mmio_read32 (qd, HPPE_REG_PORT_TX_DROP_CNT_TBL (port->port_id)));

      if (0)
	log_debug (dev,
		   "port %u GMAC read-clear MIB sample: RX %llu packets/%llu bytes, "
		   "TX %llu packets/%llu bytes",
		   port->port_id, rx_packets, rx_bytes, tx_packets, tx_bytes);

      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_BM_SILENT_DROP);
      vnet_dev_counter_value_update (
	vm, counter, qppe_mmio_read32 (qd, HPPE_REG_BM_SILENT_DROP_CNT (port->port_id)));
      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_BM_OVERFLOW_DROP);
      vnet_dev_counter_value_update (
	vm, counter, qppe_mmio_read32 (qd, HPPE_REG_BM_OVERFLOW_DROP_CNT (port->port_id)));
      {
	u32 pkt_cnt, drop_cnt;

	qppe_port_rx_cnt_read (qd, APPE_REG_PHY_PORT_RX_CNT (port->port_id), &pkt_cnt, &drop_cnt);
	counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_PORT_RX_PACKETS);
	vnet_dev_counter_value_update (vm, counter, pkt_cnt);
	counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_PORT_RX_DROP);
	vnet_dev_counter_value_update (vm, counter, drop_cnt);

	qppe_port_rx_cnt_read (qd, APPE_REG_VP_RX_CNT (EDMA_VP_BASE + port->port_id), &pkt_cnt,
			       &drop_cnt);
	counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_VP_RX_PACKETS);
	vnet_dev_counter_value_update (vm, counter, pkt_cnt);
	counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_VP_RX_DROP);
	vnet_dev_counter_value_update (vm, counter, drop_cnt);
      }
      {
	u32 queue = qp->source_profile * EDMA_RX_QUEUES_PER_RING;

	counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_QM_DEQUEUE_PACKETS);
	vnet_dev_counter_value_update (vm, counter,
				       qppe_mmio_read32 (qd, HPPE_REG_QM_QUEUE_TX_CNT (queue)));
	counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_QM_DROP_PACKETS);
	vnet_dev_counter_value_update (vm, counter, qppe_qm_drop_cnt_read (qd, queue));
      }
      {
	u32 pkt_cnt, drop_cnt;

	qppe_port_rx_cnt_read (qd, APPE_REG_PRE_L2_CNT (port->port_id), &pkt_cnt, &drop_cnt);
	counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_PRE_L2_PACKETS);
	vnet_dev_counter_value_update (vm, counter, pkt_cnt);
	counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_PRE_L2_DROP);
	vnet_dev_counter_value_update (vm, counter, drop_cnt);
      }
      return;
    }

  base = PPE_REG_XGMAC_BASE (port->port_id);
  {
    u64 rx_bytes = 0;
    u64 rx_packets = 0;
    u64 tx_bytes = 0;
    u64 tx_packets = 0;

    FOREACH_ARRAY_ELT (mib_counter, qppe_xgmac_mib_counters)
      {
	u64 value = qppe_mib_counter_read (qd, base, mib_counter->reg, mib_counter->width);

	counter = vnet_dev_port_get_counter_by_index (vm, port, mib_counter->counter_index);
	vnet_dev_counter_value_update (vm, counter, value);

	if (mib_counter->type == QPPE_MIB_COUNTER_TYPE_GENERIC)
	  {
	    if (mib_counter->direction == VNET_DEV_CTR_DIR_RX &&
		mib_counter->unit == VNET_DEV_CTR_UNIT_BYTES)
	      rx_bytes = value;
	    else if (mib_counter->direction == VNET_DEV_CTR_DIR_RX &&
		     mib_counter->unit == VNET_DEV_CTR_UNIT_PACKETS)
	      rx_packets = value;
	    else if (mib_counter->direction == VNET_DEV_CTR_DIR_TX &&
		     mib_counter->unit == VNET_DEV_CTR_UNIT_BYTES)
	      tx_bytes = value;
	    else if (mib_counter->direction == VNET_DEV_CTR_DIR_TX &&
		     mib_counter->unit == VNET_DEV_CTR_UNIT_PACKETS)
	      tx_packets = value;
	  }
      }

    if (0)
      log_debug (dev,
		 "port %u XGMAC MIB sample: RX %llu packets/%llu bytes, TX %llu packets/%llu bytes",
		 port->port_id, rx_packets, rx_bytes, tx_packets, tx_bytes);
  }

  counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_BM_SILENT_DROP);
  vnet_dev_counter_value_update (
    vm, counter, qppe_mmio_read32 (qd, HPPE_REG_BM_SILENT_DROP_CNT (port->port_id)));
  counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_PPE_TX_PACKETS);
  vnet_dev_counter_value_update (
    vm, counter, qppe_mmio_read32 (qd, HPPE_REG_PORT_TX_COUNTER_TBL (port->port_id)));
  counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_PPE_TX_DROP_PACKETS);
  vnet_dev_counter_value_update (
    vm, counter, qppe_mmio_read32 (qd, HPPE_REG_PORT_TX_DROP_CNT_TBL (port->port_id)));
  counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_BM_OVERFLOW_DROP);
  vnet_dev_counter_value_update (
    vm, counter, qppe_mmio_read32 (qd, HPPE_REG_BM_OVERFLOW_DROP_CNT (port->port_id)));
  {
    u32 pkt_cnt, drop_cnt;

    qppe_port_rx_cnt_read (qd, APPE_REG_PHY_PORT_RX_CNT (port->port_id), &pkt_cnt, &drop_cnt);
    counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_PORT_RX_PACKETS);
    vnet_dev_counter_value_update (vm, counter, pkt_cnt);
    counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_PORT_RX_DROP);
    vnet_dev_counter_value_update (vm, counter, drop_cnt);

    qppe_port_rx_cnt_read (qd, APPE_REG_VP_RX_CNT (EDMA_VP_BASE + port->port_id), &pkt_cnt,
			   &drop_cnt);
    counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_VP_RX_PACKETS);
    vnet_dev_counter_value_update (vm, counter, pkt_cnt);
    counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_VP_RX_DROP);
    vnet_dev_counter_value_update (vm, counter, drop_cnt);
  }
  {
    u32 queue = qp->source_profile * EDMA_RX_QUEUES_PER_RING;

    counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_QM_DEQUEUE_PACKETS);
    vnet_dev_counter_value_update (vm, counter,
				   qppe_mmio_read32 (qd, HPPE_REG_QM_QUEUE_TX_CNT (queue)));
    counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_QM_DROP_PACKETS);
    vnet_dev_counter_value_update (vm, counter, qppe_qm_drop_cnt_read (qd, queue));
  }
  {
    u32 pkt_cnt, drop_cnt;

    qppe_port_rx_cnt_read (qd, APPE_REG_PRE_L2_CNT (port->port_id), &pkt_cnt, &drop_cnt);
    counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_PRE_L2_PACKETS);
    vnet_dev_counter_value_update (vm, counter, pkt_cnt);
    counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_PRE_L2_DROP);
    vnet_dev_counter_value_update (vm, counter, drop_cnt);
  }
}

void
qppe_port_phy_poll (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  vnet_dev_platform_ethernet_phy_state_t state = {};
  vnet_dev_rv_t rv;

  if (!qp->ethernet_phy_name || !qp->phy_aneg_started)
    return;

  rv = vnet_dev_platform_ethernet_phy_get_state (dev, qp->ethernet_phy_node_name,
						 qp->ethernet_phy_name, &state);
  if (rv != VNET_DEV_OK)
    return;

  if (qp->phy_state_valid && qp->phy_link_up == state.link &&
      qp->phy_speed_mbps == state.speed_mbps && qp->phy_full_duplex == state.full_duplex)
    {
      if (!qp->is_enabled || !state.link || qp->link_configured)
	return;
      qppe_port_apply_link (vm, port);
      return;
    }

  if (state.link)
    log_notice (dev, "port %u Ethernet PHY link up at %u Mbps, %s duplex, autonegotiation %s",
		port->port_id, state.speed_mbps, state.full_duplex ? "full" : "half",
		state.autoneg ? "enabled" : "disabled");
  else
    log_notice (dev, "port %u Ethernet PHY link down, autonegotiation %s", port->port_id,
		state.autoneg ? "enabled" : "disabled");

  qp->phy_state_valid = 1;
  qp->phy_link_up = state.link;
  qp->phy_speed_mbps = state.speed_mbps;
  qp->phy_full_duplex = state.full_duplex;
  qppe_port_apply_link (vm, port);
}
