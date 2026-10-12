/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>
#include <edma_hw.h>
#include <qppe.h>

#include <unistd.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "pcs",
};

/* Each UNIPHY/PCS block exposes exactly two clock outputs to nsscc
 * (index 0 = rx, 1 = tx), regardless of how many MII channels it serves
 * internally - see nsscc's "uniphyN_rx"/"uniphyN_tx" clock-names in
 * ipq9574.dtsi. */
#define QPPE_PCS_CLOCK_PROVIDER_N_OUTPUTS 2

/* Direct (AHB) PCS register space. */
#define QPPE_PCS_CALIBRATION	       0x1e0
#define QPPE_PCS_CALIBRATION_DONE      (1u << 7)
#define QPPE_PCS_MISC2		       0x218
#define QPPE_PCS_MISC2_MODE_MASK       (0x7u << 4)
#define QPPE_PCS_MISC2_MODE_SGMII_PLUS (0x5u << 4)
#define QPPE_PCS_MISC2_MODE_USXGMII    (0x7u << 4)
#define QPPE_PCS_MODE_CTRL	       0x46c
#define QPPE_PCS_MODE_SEL_MASK	       (0x1fu << 8)
#define QPPE_PCS_MODESEL_2500BASEX     (0x8u << 8)
#define QPPE_PCS_MODESEL_XPCS	       (0x10u << 8)
#define QPPE_PCS_MII_CTRL(x)	       (0x480 + 0x18 * (x))
#define QPPE_PCS_MII_ADPT_RESET	       (1u << 11)
#define QPPE_PCS_MII_STS(x)	       (0x488 + 0x18 * (x))
#define QPPE_PCS_MII_LINK_STS	       (1u << 7)
#define QPPE_PCS_MII_STS_DUPLEX_FULL   (1u << 6)
#define QPPE_PCS_PLL_RESET	       0x780
#define QPPE_PCS_PLL_ANA_SW_RESET      (1u << 6)
#define QPPE_PCS_PLL_RESET_ASSERT      0x2bf
#define QPPE_PCS_PLL_RESET_RELEASE     0x2ff

/* LOS-from-SFP select: on an SFP port, this must read real loss-of-signal
 * from the module's LOS pin rather than an internal (unconnected, so
 * stuck-asserted) source - a full PLL/analog reset leaves this at its
 * non-SFP default, and nothing in the mode-select sequence above touches
 * it back, unlike on a fresh boot where firmware is assumed to have
 * strapped it correctly. */
#define QPPE_PCS_LINK_DETECT		  0x570
#define QPPE_PCS_LINK_DETECT_LOS_FROM_SFP (0x7u << 6)

/* Indirectly-addressed XPCS register space: reg numbers at or above this
 * go through the AHB indirect address/data window instead of being read
 * or written directly. */
#define QPPE_XPCS_INDIRECT_BASE	    0x8000
#define QPPE_XPCS_INDIRECT_AHB_ADDR 0x83fc

#define QPPE_XPCS_KR_STS	      0x30020
#define QPPE_XPCS_KR_LINK_STS	      (1u << 12)
#define QPPE_XPCS_DIG_CTRL	      0x38000
#define QPPE_XPCS_USXG_ADPT_RESET     (1u << 10)
#define QPPE_XPCS_USXG_EN	      (1u << 9)
#define QPPE_XPCS_DIG_STS	      0x3800a
#define QPPE_XPCS_MII_CTRL	      0x1f0000
#define QPPE_XPCS_MII_AN_EN	      (1u << 12)
#define QPPE_XPCS_MII_AN_RESTART      (1u << 9)
#define QPPE_XPCS_DUPLEX_FULL	      (1u << 8)
#define QPPE_XPCS_SPEED_MASK	      ((1u << 13) | (1u << 6) | (1u << 5))
#define QPPE_XPCS_SPEED_10000	      ((1u << 13) | (1u << 6))
#define QPPE_XPCS_SPEED_5000	      ((1u << 13) | (1u << 5))
#define QPPE_XPCS_SPEED_2500	      (1u << 5)
#define QPPE_XPCS_SPEED_1000	      (1u << 6)
#define QPPE_XPCS_SPEED_100	      (1u << 13)
#define QPPE_XPCS_SPEED_10	      0
#define QPPE_XPCS_MII_AN_CTRL	      0x1f8001
#define QPPE_XPCS_MII_AN_8BIT	      (1u << 8)
#define QPPE_XPCS_MII_AN_INTR_EN      (1u << 0)
#define QPPE_XPCS_MII_AN_INTR_STS     0x1f8002
#define QPPE_XPCS_USXG_AN_LINK_STS    (1u << 14)
#define QPPE_XPCS_MII_AN_CL37_CMPLT   (1u << 0)
#define QPPE_XPCS_USXG_AN_SPEED_MASK  (0x7u << 10)
#define QPPE_XPCS_USXG_AN_SPEED_10    (0u << 10)
#define QPPE_XPCS_USXG_AN_SPEED_100   (1u << 10)
#define QPPE_XPCS_USXG_AN_SPEED_1000  (2u << 10)
#define QPPE_XPCS_USXG_AN_SPEED_10000 (3u << 10)
#define QPPE_XPCS_USXG_AN_SPEED_2500  (4u << 10)
#define QPPE_XPCS_USXG_AN_SPEED_5000  (5u << 10)

enum
{
  QPPE_PCS_IFACE_UNKNOWN,
  QPPE_PCS_IFACE_2500BASEX,
  QPPE_PCS_IFACE_USXGMII,
  QPPE_PCS_IFACE_10GBASER,
};

static_always_inline u32
qppe_pcs_reg_rd (void *regs, u32 reg)
{
  if (reg >= QPPE_XPCS_INDIRECT_BASE)
    {
      __atomic_store_n ((u32 *) ((u8 *) regs + QPPE_XPCS_INDIRECT_AHB_ADDR), (reg >> 8) & 0x1fff,
			__ATOMIC_RELEASE);
      return __atomic_load_n ((u32 *) ((u8 *) regs + QPPE_XPCS_INDIRECT_BASE + ((reg & 0xff) << 2)),
			      __ATOMIC_ACQUIRE);
    }
  return __atomic_load_n ((u32 *) ((u8 *) regs + reg), __ATOMIC_ACQUIRE);
}

static_always_inline void
qppe_pcs_reg_wr (void *regs, u32 reg, u32 val)
{
  if (reg >= QPPE_XPCS_INDIRECT_BASE)
    {
      __atomic_store_n ((u32 *) ((u8 *) regs + QPPE_XPCS_INDIRECT_AHB_ADDR), (reg >> 8) & 0x1fff,
			__ATOMIC_RELEASE);
      __atomic_store_n ((u32 *) ((u8 *) regs + QPPE_XPCS_INDIRECT_BASE + ((reg & 0xff) << 2)), val,
			__ATOMIC_RELEASE);
      return;
    }
  __atomic_store_n ((u32 *) ((u8 *) regs + reg), val, __ATOMIC_RELEASE);
}

static_always_inline void
qppe_pcs_reg_update (void *regs, u32 reg, u32 mask, u32 val)
{
  qppe_pcs_reg_wr (regs, reg, (qppe_pcs_reg_rd (regs, reg) & ~mask) | (val & mask));
}

static u8
qppe_pcs_mode_from_phy_mode (const char *phy_mode)
{
  if (!phy_mode)
    return QPPE_PCS_IFACE_UNKNOWN;
  if (strcmp (phy_mode, "2500base-x") == 0)
    return QPPE_PCS_IFACE_2500BASEX;
  if (strcmp (phy_mode, "usxgmii") == 0)
    return QPPE_PCS_IFACE_USXGMII;
  if (strcmp (phy_mode, "10gbase-r") == 0)
    return QPPE_PCS_IFACE_10GBASER;
  return QPPE_PCS_IFACE_UNKNOWN;
}

/* Rate nsscc's divider for this UNIPHY's rx/tx clock outputs must be
 * computed against - see ipq_pcs_clk_rate_get() in the kernel PCS
 * driver. Every mode on this board happens to use the XPCS/312.5MHz
 * SerDes reference; 125MHz (SGMII/QSGMII/PSGMII/1000BASE-X) is kept here
 * for completeness even though nothing on this board uses it. */
static u64
qppe_pcs_clock_rate (u8 pcs_mode)
{
  switch (pcs_mode)
    {
    case QPPE_PCS_IFACE_2500BASEX:
    case QPPE_PCS_IFACE_USXGMII:
    case QPPE_PCS_IFACE_10GBASER:
      return 312500000;
    default:
      return 125000000;
    }
}

static vnet_dev_rv_t
qppe_pcs_open_supply (vnet_dev_t *dev, u8 *device_name, vnet_dev_platform_resource_type_t type,
		      char *resource_name, int *fd)
{
  vnet_dev_rv_t rv = vnet_dev_platform_open_resource_on_device (dev, (char *) device_name, type, "",
								resource_name, 0, fd);

  if (rv != VNET_DEV_OK)
    log_warn (dev, "cannot open UNIPHY %s '%s', skipping PCS", resource_name, (char *) device_name);
  return rv;
}

vnet_dev_rv_t
qppe_pcs_port_probe (vnet_dev_t *dev, qppe_port_t *port_data, clib_dt_node_t *port_node)
{
  clib_dt_node_t *pcs_node = clib_dt_dereference_node (port_node, "pcs-handle");
  clib_dt_node_t *uniphy_node;
  clib_dt_property_t *p;
  char *last_separator;
  char *uio_region_name;
  u8 *device_name;
  vnet_dev_rv_t rv;
  int fd;

  if (!pcs_node)
    {
      log_debug (dev, "port node %v has no pcs-handle", port_node->path);
      return VNET_DEV_OK;
    }

  /* pcs0_ch0/pcs1_ch0/... are plain sub-nodes; the parent is the actual
   * platform device ("ethernet-pcs@7a00000" etc.) that owns the register
   * window, supplies its own sys/ahb clocks and xpcs/sys/soft resets, and
   * is registered with nsscc as a clock provider. Every failure below is
   * logged and skipped rather than failing the whole port/device: PCS
   * support must not be able to take an otherwise-working port down. */
  uniphy_node = pcs_node->parent;
  if (!uniphy_node)
    {
      log_warn (dev, "pcs-handle target %v has no parent device node, skipping PCS",
		pcs_node->path);
      return VNET_DEV_OK;
    }

  rv = vnet_dev_platform_dt_node_device_name (uniphy_node, &device_name);
  if (rv != VNET_DEV_OK)
    return VNET_DEV_OK;

  last_separator = strrchr ((char *) uniphy_node->path, '/');
  uio_region_name = last_separator ? last_separator + 1 : (char *) uniphy_node->path;

  rv = vnet_dev_platform_map_uio_region (dev, uio_region_name, &port_data->pcs_regs);
  if (rv != VNET_DEV_OK)
    {
      log_warn (dev,
		"cannot map UIO region '%s' for PCS node %v, skipping PCS (is it bound to "
		"UIO?)",
		uio_region_name, uniphy_node->path);
      vec_free (device_name);
      return VNET_DEV_OK;
    }

  rv = vnet_dev_platform_open_resource_on_device (dev, (char *) device_name,
						  VNET_DEV_PLATFORM_RESOURCE_CLOCK_PROVIDER, "",
						  "clocks", QPPE_PCS_CLOCK_PROVIDER_N_OUTPUTS, &fd);
  if (rv != VNET_DEV_OK)
    {
      log_warn (dev, "cannot open clock provider for PCS node %v, skipping PCS", uniphy_node->path);
      vec_free (device_name);
      return VNET_DEV_OK;
    }
  port_data->pcs_clock_provider_fd = fd;

  {
    /* nsscc's gated feedback clocks for this channel live on its MII
     * child node (pcs0_ch0 etc), not on the UNIPHY device node itself -
     * unlike every other clock/reset opened in this function. */
    char *mii_node_name = (char *) pcs_node->path + strlen ((char *) uniphy_node->path) + 1;

    rv = vnet_dev_platform_open_resource_on_device (
      dev, (char *) device_name, VNET_DEV_PLATFORM_RESOURCE_CLOCK, mii_node_name, "rx", 0, &fd);
    if (rv != VNET_DEV_OK || vnet_dev_platform_clock_enable_fd (dev, fd) != VNET_DEV_OK)
      {
	log_warn (dev, "cannot enable MII 'rx' clock for PCS node %v, skipping PCS",
		  pcs_node->path);
	vec_free (device_name);
	return VNET_DEV_OK;
      }
    port_data->pcs_mii_rx_clk_fd = fd;

    rv = vnet_dev_platform_open_resource_on_device (
      dev, (char *) device_name, VNET_DEV_PLATFORM_RESOURCE_CLOCK, mii_node_name, "tx", 0, &fd);
    if (rv != VNET_DEV_OK || vnet_dev_platform_clock_enable_fd (dev, fd) != VNET_DEV_OK)
      {
	log_warn (dev, "cannot enable MII 'tx' clock for PCS node %v, skipping PCS",
		  pcs_node->path);
	vec_free (device_name);
	return VNET_DEV_OK;
      }
    port_data->pcs_mii_tx_clk_fd = fd;
  }

  if (qppe_pcs_open_supply (dev, device_name, VNET_DEV_PLATFORM_RESOURCE_CLOCK, "sys", &fd) !=
	VNET_DEV_OK ||
      vnet_dev_platform_clock_enable_fd (dev, fd) != VNET_DEV_OK)
    {
      vec_free (device_name);
      return VNET_DEV_OK;
    }
  port_data->pcs_sys_clk_fd = fd;

  if (qppe_pcs_open_supply (dev, device_name, VNET_DEV_PLATFORM_RESOURCE_CLOCK, "ahb", &fd) !=
	VNET_DEV_OK ||
      vnet_dev_platform_clock_enable_fd (dev, fd) != VNET_DEV_OK)
    {
      vec_free (device_name);
      return VNET_DEV_OK;
    }
  port_data->pcs_ahb_clk_fd = fd;

  if (qppe_pcs_open_supply (dev, device_name, VNET_DEV_PLATFORM_RESOURCE_RESET, "xpcs", &fd) !=
      VNET_DEV_OK)
    {
      vec_free (device_name);
      return VNET_DEV_OK;
    }
  port_data->pcs_xpcs_reset_fd = fd;

  if (qppe_pcs_open_supply (dev, device_name, VNET_DEV_PLATFORM_RESOURCE_RESET, "sys", &fd) !=
      VNET_DEV_OK)
    {
      vec_free (device_name);
      return VNET_DEV_OK;
    }
  port_data->pcs_sys_reset_fd = fd;

  if (qppe_pcs_open_supply (dev, device_name, VNET_DEV_PLATFORM_RESOURCE_RESET, "soft", &fd) !=
      VNET_DEV_OK)
    {
      vec_free (device_name);
      return VNET_DEV_OK;
    }
  port_data->pcs_soft_reset_fd = fd;
  vec_free (device_name);

  p = clib_dt_get_node_property_by_name (pcs_node, "reg");
  port_data->pcs_mii_index = clib_dt_property_is_u32 (p) ? clib_dt_property_get_u32 (p) : 0;
  port_data->pcs_mode = qppe_pcs_mode_from_phy_mode (port_data->phy_mode);
  if (port_data->pcs_mode == QPPE_PCS_IFACE_UNKNOWN)
    {
      log_warn (dev,
		"port node %v has pcs-handle but unsupported/missing phy-mode '%s', "
		"skipping PCS",
		port_node->path, port_data->phy_mode ? port_data->phy_mode : "(unspecified)");
      return VNET_DEV_OK;
    }
  if (port_data->pcs_mii_index != 0 && port_data->pcs_mode != QPPE_PCS_IFACE_2500BASEX)
    {
      /* Only the base (index 0) XPCS AN/status/control registers are
       * implemented below - fine for this board, where every XPCS-mode
       * port is the sole channel of its UNIPHY block. */
      log_warn (dev,
		"port node %v uses PCS MII channel %u, but only channel 0 is implemented "
		"for XPCS modes, skipping PCS",
		port_node->path, port_data->pcs_mii_index);
      return VNET_DEV_OK;
    }

  port_data->has_pcs = 1;
  log_debug (dev, "port node %v: mapped PCS registers at %p, mode %s, MII channel %u",
	     port_node->path, port_data->pcs_regs, port_data->phy_mode, port_data->pcs_mii_index);
  return VNET_DEV_OK;
}

void
qppe_pcs_port_deinit (vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  if (!qp->has_pcs)
    return;

  close (qp->pcs_clock_provider_fd);
  close (qp->pcs_mii_rx_clk_fd);
  close (qp->pcs_mii_tx_clk_fd);
  close (qp->pcs_sys_clk_fd);
  close (qp->pcs_ahb_clk_fd);
  close (qp->pcs_xpcs_reset_fd);
  close (qp->pcs_sys_reset_fd);
  close (qp->pcs_soft_reset_fd);
  qp->has_pcs = 0;
}

/* One-time PCS/UNIPHY mode configuration: interface mode select, PLL
 * reset and SerDes calibration. Ported from the register sequence the
 * Qualcomm in-kernel PCS driver uses for the IPQ9574 UNIPHY (see
 * TODO.md); the NSS clock-provider rate this leaves cached for nsscc is
 * a known gap, also tracked there. */
static vnet_dev_rv_t
qppe_pcs_configure_mode (vlib_main_t *vm, vnet_dev_t *dev, qppe_port_t *qp)
{
  void *regs = qp->pcs_regs;
  u32 mode_val, misc2 = 0, val;
  u8 xpcs_mode;
  int tries;

  switch (qp->pcs_mode)
    {
    case QPPE_PCS_IFACE_2500BASEX:
      mode_val = QPPE_PCS_MODESEL_2500BASEX;
      misc2 = QPPE_PCS_MISC2_MODE_SGMII_PLUS;
      xpcs_mode = 0;
      break;
    case QPPE_PCS_IFACE_USXGMII:
      mode_val = QPPE_PCS_MODESEL_XPCS;
      misc2 = QPPE_PCS_MISC2_MODE_USXGMII;
      xpcs_mode = 1;
      break;
    case QPPE_PCS_IFACE_10GBASER:
      mode_val = QPPE_PCS_MODESEL_XPCS;
      xpcs_mode = 1;
      break;
    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  vnet_dev_platform_reset_assert_fd (dev, qp->pcs_xpcs_reset_fd);

  qppe_pcs_reg_update (regs, QPPE_PCS_MODE_CTRL, QPPE_PCS_MODE_SEL_MASK, mode_val);
  if (misc2)
    qppe_pcs_reg_update (regs, QPPE_PCS_MISC2, QPPE_PCS_MISC2_MODE_MASK, misc2);

  /* Pulse the UNIPHY resets as the vendor SSDK does: both held for
   * 100ms, then another 100ms to settle after release. */
  vnet_dev_platform_reset_assert_fd (dev, qp->pcs_sys_reset_fd);
  vnet_dev_platform_reset_assert_fd (dev, qp->pcs_soft_reset_fd);
  vlib_process_suspend (vm, 100e-3);
  vnet_dev_platform_reset_deassert_fd (dev, qp->pcs_sys_reset_fd);
  vnet_dev_platform_reset_deassert_fd (dev, qp->pcs_soft_reset_fd);
  vlib_process_suspend (vm, 100e-3);

  if (xpcs_mode)
    {
      /* The analog enables must be programmed as a whole register: the
       * power-on state leaves them in an indeterminate mix. */
      qppe_pcs_reg_wr (regs, QPPE_PCS_PLL_RESET, QPPE_PCS_PLL_RESET_ASSERT);
      vlib_process_suspend (vm, 100e-3);
      qppe_pcs_reg_wr (regs, QPPE_PCS_PLL_RESET, QPPE_PCS_PLL_RESET_RELEASE);
      vlib_process_suspend (vm, 100e-3);
    }
  else
    {
      qppe_pcs_reg_update (regs, QPPE_PCS_PLL_RESET, QPPE_PCS_PLL_ANA_SW_RESET, 0);
      vlib_process_suspend (vm, 20e-3);
      qppe_pcs_reg_update (regs, QPPE_PCS_PLL_RESET, QPPE_PCS_PLL_ANA_SW_RESET,
			   QPPE_PCS_PLL_ANA_SW_RESET);
    }

  for (tries = 0;; tries++)
    {
      val = qppe_pcs_reg_rd (regs, QPPE_PCS_CALIBRATION);
      if (val & QPPE_PCS_CALIBRATION_DONE)
	break;
      if (tries >= 100)
	{
	  log_err (dev, "PCS calibration timed out");
	  return VNET_DEV_ERR_TIMEOUT;
	}
      vlib_process_suspend (vm, 1e-3);
    }

  /* Push the real rate now, mirroring the kernel PCS driver's own
   * clk_set_rate() calls at this exact point in config_mode: calling
   * clk_set_rate() on its own output clock has no local .set_rate to run
   * (recalc_rate is fixed), but it does fire the clk-notifier chain any
   * registered consumer (nsscc) relies on to reprogram its downstream
   * divider to match - which only happens here, not whenever nsscc
   * itself later happens to ask. Without this push the link still trains
   * (idle-pattern lock tolerates a stale divider), but real frames don't
   * survive the mismatched MAC-facing clock. */
  {
    u64 rate = qppe_pcs_clock_rate (qp->pcs_mode);
    vnet_dev_rv_t nrv;

    nrv = vnet_dev_platform_clock_provider_notify_rate (dev, qp->pcs_clock_provider_fd, 0, rate);
    log_debug (dev, "notify-rate index 0 rate %llu: rv %d", rate, nrv);
    nrv = vnet_dev_platform_clock_provider_notify_rate (dev, qp->pcs_clock_provider_fd, 1, rate);
    log_debug (dev, "notify-rate index 1 rate %llu: rv %d", rate, nrv);
  }

  if (qp->pcs_mode == QPPE_PCS_IFACE_USXGMII)
    {
      /* Best-effort wait for the receiver to link before enabling rate
       * adaptation; the far-end SerDes may only come up later. */
      for (tries = 0;; tries++)
	{
	  val = qppe_pcs_reg_rd (regs, QPPE_XPCS_KR_STS);
	  if (val & QPPE_XPCS_KR_LINK_STS)
	    break;
	  if (tries >= 100)
	    {
	      log_warn (dev, "10GBASE-R link not up before USXGMII adaptation enable");
	      break;
	    }
	  vlib_process_suspend (vm, 1e-3);
	}
      qppe_pcs_reg_update (regs, QPPE_XPCS_DIG_CTRL, QPPE_XPCS_USXG_EN, QPPE_XPCS_USXG_EN);
      qppe_pcs_reg_update (regs, QPPE_XPCS_MII_AN_CTRL,
			   QPPE_XPCS_MII_AN_8BIT | QPPE_XPCS_MII_AN_INTR_EN,
			   QPPE_XPCS_MII_AN_8BIT | QPPE_XPCS_MII_AN_INTR_EN);
      qppe_pcs_reg_update (regs, QPPE_XPCS_MII_CTRL, QPPE_XPCS_MII_AN_EN, QPPE_XPCS_MII_AN_EN);
    }

  /* Must come after the reset pulses and PLL reset above, which would
   * otherwise clobber it back to its non-SFP default. */
  if (qp->ethernet_phy_name && strcmp (qp->ethernet_phy_name, "sfp") == 0)
    qppe_pcs_reg_update (regs, QPPE_PCS_LINK_DETECT, QPPE_PCS_LINK_DETECT_LOS_FROM_SFP,
			 QPPE_PCS_LINK_DETECT_LOS_FROM_SFP);

  if (xpcs_mode)
    vnet_dev_platform_reset_deassert_fd (dev, qp->pcs_xpcs_reset_fd);

  qp->pcs_mode_configured = 1;
  log_debug (dev, "PCS configured for mode %s", qp->phy_mode);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_pcs_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  if (qp->pcs_mode_configured)
    return VNET_DEV_OK;

  return qppe_pcs_configure_mode (vm, port->dev, qp);
}

/* USXGMII in-band AN only yields a usable link once this is run: restart
 * the AN, wait for the completion ack, then program the MAC-facing speed
 * and latch it with an adapter reset. Called on every down -> up
 * transition, mirroring the kernel PCS driver's phylink_pcs_link_up(). */
static vnet_dev_rv_t
qppe_pcs_usxgmii_link_up (vlib_main_t *vm, vnet_dev_t *dev, qppe_port_t *qp, u32 speed_mbps)
{
  void *regs = qp->pcs_regs;
  u32 speed_bits, val;
  int tries;

  qppe_pcs_reg_update (regs, QPPE_XPCS_MII_CTRL, QPPE_XPCS_MII_AN_RESTART,
		       QPPE_XPCS_MII_AN_RESTART);

  for (tries = 0;; tries++)
    {
      val = qppe_pcs_reg_rd (regs, QPPE_XPCS_MII_AN_INTR_STS);
      if (val & QPPE_XPCS_MII_AN_CL37_CMPLT)
	{
	  qppe_pcs_reg_update (regs, QPPE_XPCS_MII_AN_INTR_STS, QPPE_XPCS_MII_AN_CL37_CMPLT, 0);
	  break;
	}
      if (tries >= 100)
	{
	  log_warn (dev, "USXGMII in-band AN did not complete");
	  break;
	}
      vlib_process_suspend (vm, 1e-3);
    }

  switch (speed_mbps)
    {
    case 10000:
      speed_bits = QPPE_XPCS_SPEED_10000;
      break;
    case 5000:
      speed_bits = QPPE_XPCS_SPEED_5000;
      break;
    case 2500:
      speed_bits = QPPE_XPCS_SPEED_2500;
      break;
    case 1000:
      speed_bits = QPPE_XPCS_SPEED_1000;
      break;
    case 100:
      speed_bits = QPPE_XPCS_SPEED_100;
      break;
    case 10:
      speed_bits = QPPE_XPCS_SPEED_10;
      break;
    default:
      log_err (dev, "invalid USXGMII speed %u Mbps", speed_mbps);
      return VNET_DEV_ERR_INVALID_VALUE;
    }

  qppe_pcs_reg_update (regs, QPPE_XPCS_MII_CTRL, QPPE_XPCS_SPEED_MASK | QPPE_XPCS_DUPLEX_FULL,
		       speed_bits | QPPE_XPCS_DUPLEX_FULL);
  return vnet_dev_platform_reset_pulse_fd (dev, qp->pcs_xpcs_reset_fd) == VNET_DEV_OK ?
	   VNET_DEV_OK :
	   VNET_DEV_ERR_BUS;
}

static void
qppe_pcs_poll_10gbaser (vlib_main_t *vm, vnet_dev_port_t *port, qppe_port_t *qp)
{
  u32 val = qppe_pcs_reg_rd (qp->pcs_regs, QPPE_XPCS_KR_STS);
  u8 link = (val & QPPE_XPCS_KR_LINK_STS) != 0;

  if (qp->phy_state_valid && qp->phy_link_up == link)
    return;

  qp->phy_state_valid = 1;
  qp->phy_link_up = link;
  qp->phy_speed_mbps = link ? 10000 : 0;
  qp->phy_full_duplex = link;
  log_notice (port->dev, "port %u 10GBASE-R link %s", port->port_id, link ? "up" : "down");
  qppe_port_apply_link (vm, port);
}

static void
qppe_pcs_poll_usxgmii (vlib_main_t *vm, vnet_dev_port_t *port, qppe_port_t *qp)
{
  u32 val = qppe_pcs_reg_rd (qp->pcs_regs, QPPE_XPCS_MII_AN_INTR_STS);
  u8 link = (val & QPPE_XPCS_USXG_AN_LINK_STS) != 0;
  u32 speed_mbps = 0;

  if (link)
    switch (val & QPPE_XPCS_USXG_AN_SPEED_MASK)
      {
      case QPPE_XPCS_USXG_AN_SPEED_10000:
	speed_mbps = 10000;
	break;
      case QPPE_XPCS_USXG_AN_SPEED_5000:
	speed_mbps = 5000;
	break;
      case QPPE_XPCS_USXG_AN_SPEED_2500:
	speed_mbps = 2500;
	break;
      case QPPE_XPCS_USXG_AN_SPEED_1000:
	speed_mbps = 1000;
	break;
      case QPPE_XPCS_USXG_AN_SPEED_100:
	speed_mbps = 100;
	break;
      case QPPE_XPCS_USXG_AN_SPEED_10:
	speed_mbps = 10;
	break;
      default:
	link = 0;
	break;
      }

  if (qp->phy_state_valid && qp->phy_link_up == link && qp->phy_speed_mbps == speed_mbps)
    return;

  if (link && qppe_pcs_usxgmii_link_up (vm, port->dev, qp, speed_mbps) != VNET_DEV_OK)
    return;

  qp->phy_state_valid = 1;
  qp->phy_link_up = link;
  qp->phy_speed_mbps = speed_mbps;
  qp->phy_full_duplex = 1;
  if (link)
    log_notice (port->dev, "port %u USXGMII link up at %u Mbps", port->port_id, speed_mbps);
  else
    log_notice (port->dev, "port %u USXGMII link down", port->port_id);
  qppe_port_apply_link (vm, port);
}

static void
qppe_pcs_poll_2500basex (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port __clib_unused,
			 qppe_port_t *qp)
{
  /* lan1 has no in-band status: its MDIO PHY poll (qppe_port_phy_poll)
   * drives qp->phy_link_up. 2500BASE-X has no autoneg either, so all
   * that is needed here is one adapter reset pulse per down -> up
   * transition, mirroring the kernel PCS driver's pcs_link_up(). */
  if (!qp->phy_link_up || qp->pcs_link_was_up)
    {
      qp->pcs_link_was_up = qp->phy_link_up;
      return;
    }

  qppe_pcs_reg_update (qp->pcs_regs, QPPE_PCS_MII_CTRL (0), QPPE_PCS_MII_ADPT_RESET, 0);
  qppe_pcs_reg_update (qp->pcs_regs, QPPE_PCS_MII_CTRL (0), QPPE_PCS_MII_ADPT_RESET,
		       QPPE_PCS_MII_ADPT_RESET);
  qp->pcs_link_was_up = 1;
}

void
qppe_pcs_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  vnet_dev_platform_clock_provider_request_t req;
  vnet_dev_rv_t rv;

  if (!qp->has_pcs)
    return;

  rv = vnet_dev_platform_clock_provider_try_request (qp->pcs_clock_provider_fd, &req);
  if (rv == VNET_DEV_OK)
    {
      /* Always answer with the mode-derived rate, regardless of what the
       * request asked for: nsscc's divider computation for this port's
       * MAC-facing rx/tx clock depends on this UNIPHY rx/tx output's
       * cached rate being right, not on an unprompted echo of whatever
       * (often 0, at a bare PREPARE) the kernel caller happened to pass
       * in - see kdi_clk_recalc_rate() and the kernel PCS driver's own
       * ipq_pcs_clk_rate_get(). */
      u64 rate = qppe_pcs_clock_rate (qp->pcs_mode);

      log_debug (port->dev, "port %u: PCS clock provider request index %u op %u rate %llu -> %llu",
		 port->port_id, req.index, req.op, req.rate, rate);
      vnet_dev_platform_clock_provider_complete (qp->pcs_clock_provider_fd, 0, rate);
    }
  else if (rv != VNET_DEV_ERR_NOT_READY)
    log_err (port->dev, "port %u: PCS clock provider request read failed", port->port_id);

  if (!qp->pcs_mode_configured)
    return;

  switch (qp->pcs_mode)
    {
    case QPPE_PCS_IFACE_10GBASER:
      qppe_pcs_poll_10gbaser (vm, port, qp);
      break;
    case QPPE_PCS_IFACE_USXGMII:
      qppe_pcs_poll_usxgmii (vm, port, qp);
      break;
    case QPPE_PCS_IFACE_2500BASEX:
      qppe_pcs_poll_2500basex (vm, port, qp);
      break;
    default:
      break;
    }
}
