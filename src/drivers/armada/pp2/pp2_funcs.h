/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

static_always_inline u32
mvpp2_reg_rd_relax (uintptr_t base, u32 offset)
{
  u32 *addr = (void *) (base + offset);

  return __atomic_load_n (addr, __ATOMIC_RELAXED);
}

static_always_inline void
mvpp2_reg_wr_relax (uintptr_t base, u32 offset, u32 value)
{
  u32 *addr = (void *) (base + offset);

  __atomic_store_n (addr, value, __ATOMIC_RELAXED);
}

static_always_inline u32
mvpp2_reg_rd (uintptr_t base, u32 offset)
{
  u32 value = mvpp2_reg_rd_relax (base, offset);

  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static_always_inline void
mvpp2_reg_wr (uintptr_t base, u32 offset, u32 value)
{
  asm volatile ("dsb st" : : : "memory");
  mvpp2_reg_wr_relax (base, offset, value);
}

static_always_inline u32
mvpp2_reg_wr_rd (uintptr_t base, u32 wr_offset, u32 value, u32 rd_offset)
{
  mvpp2_reg_wr_relax (base, wr_offset, value);
  asm volatile ("dsb sy" : : : "memory");
  return mvpp2_reg_rd_relax (base, rd_offset);
}

static_always_inline u32
mvpp2_dev_reg_rd_relax (vnet_dev_t *dev, u32 offset)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  return mvpp2_reg_rd_relax (md->pp_base, offset);
}

static_always_inline void
mvpp2_dev_reg_wr_relax (vnet_dev_t *dev, u32 offset, u32 value)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  mvpp2_reg_wr_relax (md->pp_base, offset, value);
}

static_always_inline u32
mvpp2_dev_reg_rd (vnet_dev_t *dev, u32 offset)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  return mvpp2_reg_rd (md->pp_base, offset);
}

static_always_inline void
mvpp2_dev_reg_wr (vnet_dev_t *dev, u32 offset, u32 value)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  mvpp2_reg_wr (md->pp_base, offset, value);
}

static_always_inline u32
mvpp2_dev_reg_wr_rd (vnet_dev_t *dev, u32 wr_offset, u32 value, u32 rd_offset)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  return mvpp2_reg_wr_rd (md->pp_base, wr_offset, value, rd_offset);
}

static_always_inline u32
mvpp2_cm3_reg_rd (vnet_dev_t *dev, u32 offset)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  return mvpp2_reg_rd (md->cm3_base, offset);
}

static_always_inline void
mvpp2_cm3_reg_wr (vnet_dev_t *dev, u32 offset, u32 value)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  mvpp2_reg_wr (md->cm3_base, offset, value);
}

static_always_inline u32
mvpp2_gop_gmac_reg_rd (vnet_dev_t *dev, int mac_num, u32 offset)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  return mvpp2_reg_rd (md->gop_hw_gmac.base, mac_num * md->gop_hw_gmac.obj_size + offset);
}

static_always_inline void
mvpp2_gop_gmac_reg_wr (vnet_dev_t *dev, int mac_num, u32 offset, u32 value)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  mvpp2_reg_wr (md->gop_hw_gmac.base, mac_num * md->gop_hw_gmac.obj_size + offset, value);
}

static_always_inline u32
mvpp2_gop_xlg_reg_rd (vnet_dev_t *dev, int mac_num, u32 offset)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  return mvpp2_reg_rd (md->gop_hw_xlg_mac.base, mac_num * md->gop_hw_xlg_mac.obj_size + offset);
}

static_always_inline void
mvpp2_gop_xlg_reg_wr (vnet_dev_t *dev, int mac_num, u32 offset, u32 value)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  mvpp2_reg_wr (md->gop_hw_xlg_mac.base, mac_num * md->gop_hw_xlg_mac.obj_size + offset, value);
}

static_always_inline u32
mvpp2_hif_reg_rd (mvpp2_hif_t *hif, u32 offset)
{
  return mvpp2_reg_rd (hif->base, offset);
}

static_always_inline void
mvpp2_hif_reg_wr_relax (mvpp2_hif_t *hif, u32 offset, u32 value)
{
  mvpp2_reg_wr_relax (hif->base, offset, value);
}

static_always_inline void
mvpp2_hif_reg_wr (mvpp2_hif_t *hif, u32 offset, u32 value)
{
  mvpp2_reg_wr (hif->base, offset, value);
}

static_always_inline char *
mvpp2_port_ifname (vnet_dev_port_t *port, char ifname[IFNAMSIZ])
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  if (if_indextoname (mp->if_index, ifname) == 0)
    ifname[0] = 0;
  return ifname;
}

static_always_inline u32
mvpp2_port_id (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  return mp->id;
}

static_always_inline u32
mvpp2_port_get_rxq_hw_id (vnet_dev_port_t *port, u32 rxq_id)
{
  return mvpp2_port_id (port) * PP2_HW_PORT_NUM_RXQS + rxq_id;
}
