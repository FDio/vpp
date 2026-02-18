/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/linux/sysfs.h>
#include <vlib/file.h>
#include <vlib/log.h>

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>
#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/cryptodev/cryptodev.h>
#include <vlib/pci/pci.h>
#include <vlib/vmbus/vmbus.h>
#include <vlib/stats/stats.h>
#include <rte_ring.h>
#include <rte_vect.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>

#include <dpdk/device/dpdk_priv.h>

dpdk_main_t dpdk_main;
dpdk_config_main_t dpdk_config_main;

#define LINK_STATE_ELOGS	0

/* dev_info.speed_capa -> interface name mapppings */
const struct
{
  u32 link_speed;
  const char *pfx;
} if_name_prefixes[] = {
  /* sorted, higher speed first */
  { RTE_ETH_LINK_SPEED_200G, "TwoHundredGigabitEthernet" },
  { RTE_ETH_LINK_SPEED_100G, "HundredGigabitEthernet" },
  { RTE_ETH_LINK_SPEED_56G, "FiftySixGigabitEthernet" },
  { RTE_ETH_LINK_SPEED_50G, "FiftyGigabitEthernet" },
  { RTE_ETH_LINK_SPEED_40G, "FortyGigabitEthernet" },
  { RTE_ETH_LINK_SPEED_25G, "TwentyFiveGigabitEthernet" },
  { RTE_ETH_LINK_SPEED_20G, "TwentyGigabitEthernet" },
  { RTE_ETH_LINK_SPEED_10G, "TenGigabitEthernet" },
  { RTE_ETH_LINK_SPEED_5G, "FiveGigabitEthernet" },
  { RTE_ETH_LINK_SPEED_2_5G, "TwoDotFiveGigabitEthernet" },
  { RTE_ETH_LINK_SPEED_1G, "GigabitEthernet" },
};

static clib_error_t *
dpdk_set_max_frame_size (vnet_main_t *vnm, vnet_hw_interface_t *hi,
			 u32 frame_size)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);
  int rv;
  u32 mtu;

  mtu = frame_size - xd->driver_frame_overhead;

  rv = rte_eth_dev_set_mtu (xd->port_id, mtu);

  if (rv < 0)
    {
      dpdk_log_err ("[%u] rte_eth_dev_set_mtu failed (mtu %u, rv %d)",
		    xd->port_id, mtu, rv);
      switch (rv)
	{
	case -ENOTSUP:
	  return vnet_error (VNET_ERR_UNSUPPORTED,
			     "dpdk driver doesn't support MTU change");
	case -EBUSY:
	  return vnet_error (VNET_ERR_BUSY, "port is running");
	case -EINVAL:
	  return vnet_error (VNET_ERR_INVALID_VALUE, "invalid MTU");
	default:
	  return vnet_error (VNET_ERR_BUG,
			     "unexpected return value %d returned from "
			     "rte_eth_dev_set_mtu(...)",
			     rv);
	}
    }
  else
    dpdk_log_debug ("[%u] max_frame_size set to %u by setting MTU to %u",
		    xd->port_id, frame_size, mtu);

  return 0;
}

static clib_error_t *
dpdk_set_rss_config (vnet_main_t *vnm __clib_unused, vnet_hw_interface_t *hi,
		     vnet_eth_rss_config_t *cfg)
{
  static const u64 rss_hf_by_hash_bit[] = {
    [VNET_ETH_RSS_T_IPV4_BIT] = RTE_ETH_RSS_IPV4,
    [VNET_ETH_RSS_T_TCP_IPV4_BIT] = RTE_ETH_RSS_NONFRAG_IPV4_TCP,
    [VNET_ETH_RSS_T_UDP_IPV4_BIT] = RTE_ETH_RSS_NONFRAG_IPV4_UDP,
#ifdef RTE_ETH_RSS_L3_SRC_ONLY
    [VNET_ETH_RSS_T_IPV4_SRC_ONLY_BIT] = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_L3_SRC_ONLY,
#else
    [VNET_ETH_RSS_T_IPV4_SRC_ONLY_BIT] = RTE_ETH_RSS_IPV4,
#endif
#ifdef RTE_ETH_RSS_L3_DST_ONLY
    [VNET_ETH_RSS_T_IPV4_DST_ONLY_BIT] = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_L3_DST_ONLY,
#else
    [VNET_ETH_RSS_T_IPV4_DST_ONLY_BIT] = RTE_ETH_RSS_IPV4,
#endif
    [VNET_ETH_RSS_T_IPV6_BIT] = RTE_ETH_RSS_IPV6,
    [VNET_ETH_RSS_T_TCP_IPV6_BIT] = RTE_ETH_RSS_NONFRAG_IPV6_TCP,
    [VNET_ETH_RSS_T_UDP_IPV6_BIT] = RTE_ETH_RSS_NONFRAG_IPV6_UDP,
#ifdef RTE_ETH_RSS_IPV6_EX
    [VNET_ETH_RSS_T_IPV6_EX_BIT] = RTE_ETH_RSS_IPV6_EX,
#endif
#ifdef RTE_ETH_RSS_IPV6_TCP_EX
    [VNET_ETH_RSS_T_TCP_IPV6_EX_BIT] = RTE_ETH_RSS_IPV6_TCP_EX,
#elif defined(RTE_ETH_RSS_NONFRAG_IPV6_TCP_EX)
    [VNET_ETH_RSS_T_TCP_IPV6_EX_BIT] = RTE_ETH_RSS_NONFRAG_IPV6_TCP_EX,
#endif
#ifdef RTE_ETH_RSS_IPV6_UDP_EX
    [VNET_ETH_RSS_T_UDP_IPV6_EX_BIT] = RTE_ETH_RSS_IPV6_UDP_EX,
#elif defined(RTE_ETH_RSS_NONFRAG_IPV6_UDP_EX)
    [VNET_ETH_RSS_T_UDP_IPV6_EX_BIT] = RTE_ETH_RSS_NONFRAG_IPV6_UDP_EX,
#endif
#ifdef RTE_ETH_RSS_L3_SRC_ONLY
    [VNET_ETH_RSS_T_IPV6_SRC_ONLY_BIT] = RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_L3_SRC_ONLY,
#else
    [VNET_ETH_RSS_T_IPV6_SRC_ONLY_BIT] = RTE_ETH_RSS_IPV6,
#endif
#ifdef RTE_ETH_RSS_L3_DST_ONLY
    [VNET_ETH_RSS_T_IPV6_DST_ONLY_BIT] = RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_L3_DST_ONLY,
#else
    [VNET_ETH_RSS_T_IPV6_DST_ONLY_BIT] = RTE_ETH_RSS_IPV6,
#endif
  };
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);
  struct rte_eth_dev_info di;
  struct rte_eth_rss_conf rss_conf = {};
  vnet_eth_rss_hash_t hash;
  vnet_eth_rss_hash_t requested_hash;
  vnet_eth_rss_hash_t bit;
  u64 hf = xd->conf.rss_hf;
  u64 unsupported_hf;
  u64 hfi;
  u32 i;
  int rv;

  if (cfg == 0)
    return vnet_error (VNET_ERR_INVALID_VALUE, "invalid rss config");
  hash = cfg->hash;
  requested_hash = hash;

  if (hash != VNET_ETH_RSS_HASH_NOT_SET)
    {
      hf = 0;
      for (i = 0; i < ARRAY_LEN (rss_hf_by_hash_bit); i++)
	{
	  bit = 1U << i;
	  hfi = rss_hf_by_hash_bit[i];
	  if ((hash & bit) == 0)
	    continue;
	  if (hfi == 0)
	    continue;
	  hf |= hfi;
	  hash &= ~bit;
	}
      if (hash)
	return vnet_error (VNET_ERR_UNSUPPORTED, "rss hash 0x%x not supported", requested_hash);
      if ((rv = rte_eth_dev_info_get (xd->port_id, &di)) != 0)
	return vnet_error (VNET_ERR_BUG, "rte_eth_dev_info_get failed (%d)", rv);
      unsupported_hf = hf & ~di.flow_type_rss_offloads;
      if (unsupported_hf)
	return vnet_error (VNET_ERR_UNSUPPORTED, "rss hash %U not supported",
			   format_vnet_eth_rss_types, requested_hash);
    }

  rss_conf = (struct rte_eth_rss_conf){
    .rss_key = cfg->key_len ? cfg->key : 0,
    .rss_key_len = cfg->key_len,
    .rss_hf = hf,
  };

  rv = rte_eth_dev_rss_hash_update (xd->port_id, &rss_conf);
  if (rv < 0)
    return vnet_error (VNET_ERR_BUG, "rte_eth_dev_rss_hash_update failed (%d)", rv);

  xd->conf.rss_hf = hf;
  return 0;
}

static u32
dpdk_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi, u32 flags)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);
  u32 old = (xd->flags & DPDK_DEVICE_FLAG_PROMISC) != 0;

  switch (flags)
    {
    case ETHERNET_INTERFACE_FLAG_DEFAULT_L3:
      /* set to L3/non-promisc mode */
      dpdk_device_flag_set (xd, DPDK_DEVICE_FLAG_PROMISC, 0);
      break;
    case ETHERNET_INTERFACE_FLAG_ACCEPT_ALL:
      dpdk_device_flag_set (xd, DPDK_DEVICE_FLAG_PROMISC, 1);
      break;
    default:
      return ~0;
    }

  if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
    {
      if (xd->flags & DPDK_DEVICE_FLAG_PROMISC)
	rte_eth_promiscuous_enable (xd->port_id);
      else
	rte_eth_promiscuous_disable (xd->port_id);
    }

  return old;
}

/* The function check_l3cache helps check if Level 3 cache exists or not on current CPUs
  return value 1: exist.
  return value 0: not exist.
*/
static int
check_l3cache ()
{

  struct dirent *dp;
  clib_error_t *err;
  const char *sys_cache_dir = "/sys/devices/system/cpu/cpu0/cache";
  DIR *dir_cache = opendir (sys_cache_dir);

  if (dir_cache == NULL)
    return -1;

  while ((dp = readdir (dir_cache)) != NULL)
    {
      if (dp->d_type == DT_DIR)
	{
	  u8 *p = NULL;
	  int level_cache = -1;

	  p = format (p, "%s/%s/%s%c", sys_cache_dir, dp->d_name, "level", 0);
	  if ((err = clib_sysfs_read ((char *) p, "%d", &level_cache)))
	    clib_error_free (err);

	  if (level_cache == 3)
	    {
	      closedir (dir_cache);
	      return 1;
	    }
	}
    }

  if (dir_cache != NULL)
    closedir (dir_cache);

  return 0;
}

static dpdk_device_config_t *
dpdk_find_startup_config (struct rte_eth_dev_info *di)
{
  dpdk_main_t *dm = &dpdk_main;
  struct rte_pci_device *pci_dev;
  vlib_pci_addr_t pci_addr;
#ifdef __linux__
  struct rte_vmbus_device *vmbus_dev;
  vlib_vmbus_addr_t vmbus_addr;
#endif /* __linux__ */
  uword *p = 0;

  if ((pci_dev = dpdk_get_pci_device (di)))
    {
      pci_addr.domain = pci_dev->addr.domain;
      pci_addr.bus = pci_dev->addr.bus;
      pci_addr.slot = pci_dev->addr.devid;
      pci_addr.function = pci_dev->addr.function;
      p =
	hash_get (dm->conf->device_config_index_by_pci_addr, pci_addr.as_u32);
    }

#ifdef __linux__
  if ((vmbus_dev = dpdk_get_vmbus_device (di)))
    {
      unformat_input_t input_vmbus;
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
      const char *dev_name = rte_dev_name (di->device);
#else
      const char *dev_name = di->device->name;
#endif
      unformat_init_string (&input_vmbus, dev_name, strlen (dev_name));
      if (unformat (&input_vmbus, "%U", unformat_vlib_vmbus_addr, &vmbus_addr))
	p = mhash_get (&dm->conf->device_config_index_by_vmbus_addr,
		       &vmbus_addr);
      unformat_free (&input_vmbus);
    }
#endif /* __linux__ */

  if (p)
    return pool_elt_at_index (dm->conf->dev_confs, p[0]);
  return &dm->conf->default_devconf;
}

/*
 * Initialise the xstats counters for a device
 */
void
dpdk_counters_xstats_init (dpdk_device_t *xd)
{
  int len, ret, i;
  struct rte_eth_xstat_name *xstats_names = 0;

  if (vec_len (xd->xstats_symlinks) > 0)
    {
      /* xstats already initialized. Reset counters */
      vec_foreach_index (i, xd->xstats_symlinks)
	{
	  vlib_stats_remove_entry (xd->xstats_symlinks[i]);
	}
    }
  else
    {
      xd->xstats_counters.stat_segment_name =
	(char *) format (0, "/if/xstats/%d%c", xd->sw_if_index, 0);
      xd->xstats_counters.counters = 0;
    }

  len = rte_eth_xstats_get_names (xd->port_id, 0, 0);
  if (len < 0)
    {
      dpdk_log_err ("[%u] rte_eth_xstats_get_names failed: %d. DPDK xstats "
		    "not configured.",
		    xd->port_id, len);
      return;
    }

  vlib_validate_simple_counter (&xd->xstats_counters, len);
  vlib_zero_simple_counter (&xd->xstats_counters, len);

  vec_validate (xstats_names, len - 1);
  vec_validate (xd->xstats, len - 1);
  vec_validate (xd->xstats_symlinks, len - 1);

  ret = rte_eth_xstats_get_names (xd->port_id, xstats_names, len);
  if (ret >= 0 && ret <= len)
    {
      vec_foreach_index (i, xstats_names)
	{
	  /* There is a bug in the ENA driver where the xstats names are not
	   * unique. */
	  xd->xstats_symlinks[i] = vlib_stats_add_symlink (
	    xd->xstats_counters.stats_entry_index, i, "/interfaces/%U/%s%c",
	    format_vnet_sw_if_index_name, vnet_get_main (), xd->sw_if_index,
	    xstats_names[i].name, 0);
	  if (xd->xstats_symlinks[i] == STAT_SEGMENT_INDEX_INVALID)
	    {
	      xd->xstats_symlinks[i] = vlib_stats_add_symlink (
		xd->xstats_counters.stats_entry_index, i,
		"/interfaces/%U/%s_%d%c", format_vnet_sw_if_index_name,
		vnet_get_main (), xd->sw_if_index, xstats_names[i].name, i, 0);
	    }
	}
    }
  else
    {
      dpdk_log_err ("[%u] rte_eth_xstats_get_names failed: %d. DPDK xstats "
		    "not configured.",
		    xd->port_id, ret);
    }
  vec_free (xstats_names);
}

static clib_error_t *
dpdk_lib_init (dpdk_main_t * dm)
{
  vnet_main_t *vnm = vnet_get_main ();
  u16 port_id;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_device_main_t *vdm = &vnet_device_main;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hi;
  dpdk_device_t *xd;
  char *if_num_fmt;

  /* vlib_buffer_t template */
  vec_validate_aligned (dm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  for (int i = 0; i < tm->n_vlib_mains; i++)
    {
      dpdk_per_thread_data_t *ptd = vec_elt_at_index (dm->per_thread_data, i);
      clib_memset (&ptd->buffer_template, 0, sizeof (vlib_buffer_t));
      vnet_buffer (&ptd->buffer_template)->sw_if_index[VLIB_TX] = (u32) ~ 0;
    }

  if_num_fmt =
    dm->conf->interface_name_format_decimal ? "%d/%d/%d" : "%x/%x/%x";

  /* device config defaults */
  dm->default_port_conf.n_rx_desc = DPDK_NB_RX_DESC_DEFAULT;
  dm->default_port_conf.n_tx_desc = DPDK_NB_TX_DESC_DEFAULT;
  dm->default_port_conf.n_rx_queues = 1;
  dm->default_port_conf.n_tx_queues = tm->n_vlib_mains;
  dm->default_port_conf.rss_hf =
    RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP;
  dm->default_port_conf.max_lro_pkt_size = DPDK_MAX_LRO_SIZE_DEFAULT;

  if ((clib_mem_get_default_hugepage_size () == 2 << 20) &&
      check_l3cache () == 0)
    dm->default_port_conf.n_rx_desc = dm->default_port_conf.n_tx_desc = 512;

  RTE_ETH_FOREACH_DEV (port_id)
    {
      u8 addr[6];
      int rv, q;
      struct rte_eth_dev_info di;
      struct rte_pci_device *pci_dev;
      dpdk_device_config_t *devconf = 0;
      vnet_eth_interface_registration_t eir = {};
      dpdk_driver_t *dr;
      i8 numa_node;

      if (!rte_eth_dev_is_valid_port (port_id))
	continue;

      if ((rv = rte_eth_dev_info_get (port_id, &di)) != 0)
	{
	  dpdk_log_warn ("[%u] failed to get device info. skipping device.",
			 port_id);
	  continue;
	}

      if (di.device == 0)
	{
	  dpdk_log_warn ("[%u] missing device info. Skipping '%s' device",
			 port_id, di.driver_name);
	  continue;
	}

      devconf = dpdk_find_startup_config (&di);

      /* If device is blacklisted, we should skip it */
      if (devconf->is_blacklisted)
	{
	  dpdk_log_notice ("[%d] Device %s blacklisted. Skipping...", port_id,
			   di.driver_name);
	  continue;
	}

      vec_add2_aligned (dm->devices, xd, 1, CLIB_CACHE_LINE_BYTES);
      xd->port_id = port_id;
      xd->device_index = xd - dm->devices;
      xd->per_interface_next_index = ~0;

      clib_memcpy (&xd->conf, &dm->default_port_conf,
		   sizeof (dpdk_port_conf_t));

      /* find driver datea for this PMD */
      if ((dr = dpdk_driver_find (di.driver_name, &xd->if_desc)))
	{
	  xd->driver = dr;
	  xd->supported_flow_actions = dr->supported_flow_actions;
	  xd->conf.disable_rss = dr->mq_mode_none;
	  xd->conf.disable_rx_scatter = dr->disable_rx_scatter;
	  xd->conf.enable_rxq_int = dr->enable_rxq_int;
	  if (dr->use_intel_phdr_cksum)
	    dpdk_device_flag_set (xd, DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM, 1);
	  if (dr->int_unmaskable)
	    dpdk_device_flag_set (xd, DPDK_DEVICE_FLAG_INT_UNMASKABLE, 1);
	  if (dr->need_tx_prepare)
	    dpdk_device_flag_set (xd, DPDK_DEVICE_FLAG_TX_PREPARE, 1);
	}
      else
	dpdk_log_warn ("[%u] unknown driver '%s'", port_id, di.driver_name);

      if (devconf->name)
	{
	  xd->name = devconf->name;
	}
      else
	{
	  if (dr && dr->interface_name_prefix)
	    {
	      /* prefix override by driver */
	      xd->name = format (xd->name, "%s", dr->interface_name_prefix);
	    }
	  else
	    {
	      /* interface name prefix from speed_capa */
	      u64 mask = ~((if_name_prefixes[0].link_speed << 1) - 1);

	      if (di.speed_capa & mask)
		dpdk_log_warn ("[%u] unknown speed capability 0x%x reported",
			       xd->port_id, di.speed_capa & mask);

	      for (int i = 0; i < ARRAY_LEN (if_name_prefixes); i++)
		if (if_name_prefixes[i].link_speed & di.speed_capa)
		  {
		    xd->name =
		      format (xd->name, "%s", if_name_prefixes[i].pfx);
		    break;
		  }
	      if (xd->name == 0)
		xd->name = format (xd->name, "Ethernet");
	    }

	  if (dr && dr->interface_number_from_port_id)
	    xd->name = format (xd->name, "%u", port_id);
	  else if ((pci_dev = dpdk_get_pci_device (&di)))
	    {
	      /* Include domain in name if non-zero (prevents collisions) */
	      if (pci_dev->addr.domain != 0)
		{
		  char *domain_fmt =
		    dm->conf->interface_name_format_decimal ? "-%d/%d/%d/%d" : "-%x/%x/%x/%x";
		  xd->name = format (xd->name, domain_fmt, pci_dev->addr.domain, pci_dev->addr.bus,
				     pci_dev->addr.devid, pci_dev->addr.function);
		}
	      else
		xd->name = format (xd->name, if_num_fmt, pci_dev->addr.bus, pci_dev->addr.devid,
				   pci_dev->addr.function);
	    }
	  else
	    xd->name = format (xd->name, "%u", port_id);

	  /* Handle representor devices that share the same PCI ID */
	  if ((di.switch_info.domain_id !=
	       RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID) &&
	      (di.switch_info.port_id != (uint16_t) -1))
	    xd->name = format (xd->name, "/%d", di.switch_info.port_id);
	}

      /* Check for interface name collision */
      {
	vnet_interface_main_t *im = &vnm->interface_main;

	if (im->hw_interface_by_name)
	  {
	    uword *existing = hash_get_mem (im->hw_interface_by_name, xd->name);
	    if (existing)
	      {
		clib_error_t *error;

		error = clib_error_return (
		  0,
		  "DPDK interface name collision: '%v' (PCI "
		  "%04x:%02x:%02x.%x) "
		  "already exists. "
		  "manually name devices.",
		  xd->name, pci_dev ? pci_dev->addr.domain : 0, pci_dev ? pci_dev->addr.bus : 0,
		  pci_dev ? pci_dev->addr.devid : 0, pci_dev ? pci_dev->addr.function : 0);

		/* Free allocated resources before returning error */
		vec_free (xd->name);
		vec_set_len (dm->devices, vec_len (dm->devices) - 1);

		return error;
	      }
	  }
      }

      /* number of RX and TX queues */
      if (devconf->num_tx_queues > 0)
	{
	  if (di.max_tx_queues < devconf->num_tx_queues)
	    dpdk_log_warn ("[%u] Configured number of TX queues (%u) is "
			   "bigger than maximum supported (%u)",
			   port_id, devconf->num_tx_queues, di.max_tx_queues);
	  xd->conf.n_tx_queues = devconf->num_tx_queues;
	}

      xd->conf.n_tx_queues = clib_min (di.max_tx_queues, xd->conf.n_tx_queues);

      if (devconf->num_rx_queues > 1 &&
	  di.max_rx_queues >= devconf->num_rx_queues)
	{
	  xd->conf.n_rx_queues = devconf->num_rx_queues;
	  if (devconf->rss_fn)
	    {
	      u64 unsupported_bits;
	      xd->conf.rss_hf = devconf->rss_fn;
	      unsupported_bits = xd->conf.rss_hf;
	      unsupported_bits &= ~di.flow_type_rss_offloads;
	      if (unsupported_bits)
		dpdk_log_warn ("Unsupported RSS hash functions: %U",
			       format_dpdk_rss_hf_name, unsupported_bits);
	    }
	  xd->conf.rss_hf &= di.flow_type_rss_offloads;
	  dpdk_log_debug ("[%u] rss_hf: %U", port_id, format_dpdk_rss_hf_name,
			  xd->conf.rss_hf);
	}

#ifndef RTE_VLAN_HLEN
#define RTE_VLAN_HLEN 4
#endif
      xd->driver_frame_overhead =
	RTE_ETHER_HDR_LEN + 2 * RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN;
#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
      q = di.max_rx_pktlen - di.max_mtu;

      /* attempt to protect from bogus value provided by pmd */
      if (q < (2 * xd->driver_frame_overhead) && q > 0 &&
	  di.max_mtu != UINT16_MAX)
	xd->driver_frame_overhead = q;
      dpdk_log_debug ("[%u] min_mtu: %u, max_mtu: %u, min_rx_bufsize: %u, "
		      "max_rx_pktlen: %u, max_lro_pkt_size: %u",
		      xd->port_id, di.min_mtu, di.max_mtu, di.min_rx_bufsize,
		      di.max_rx_pktlen, di.max_lro_pkt_size);
#endif
      dpdk_log_debug ("[%u] driver frame overhead is %u", port_id,
		      xd->driver_frame_overhead);

      /* number of RX and TX tescriptors */
      if (devconf->num_rx_desc)
	xd->conf.n_rx_desc = devconf->num_rx_desc;
      else if (dr && dr->n_rx_desc)
	xd->conf.n_rx_desc = dr->n_rx_desc;

      if (devconf->num_tx_desc)
	xd->conf.n_tx_desc = devconf->num_tx_desc;
      else if (dr && dr->n_tx_desc)
	xd->conf.n_tx_desc = dr->n_tx_desc;

      if (xd->conf.n_tx_desc > di.tx_desc_lim.nb_max)
	{
	  dpdk_log_warn ("[%u] Configured number of TX descriptors (%u) is "
			 "bigger than maximum supported (%u)",
			 port_id, xd->conf.n_tx_desc, di.tx_desc_lim.nb_max);
	  xd->conf.n_tx_desc = di.tx_desc_lim.nb_max;
	}

      dpdk_log_debug (
	"[%u] n_rx_queues: %u n_tx_queues: %u n_rx_desc: %u n_tx_desc: %u",
	port_id, xd->conf.n_rx_queues, xd->conf.n_tx_queues,
	xd->conf.n_rx_desc, xd->conf.n_tx_desc);

      vec_validate_aligned (xd->rx_queues, xd->conf.n_rx_queues - 1,
			    CLIB_CACHE_LINE_BYTES);
      vec_validate_aligned (xd->tx_queues, xd->conf.n_tx_queues - 1,
			    CLIB_CACHE_LINE_BYTES);

      rte_eth_macaddr_get (port_id, (void *) addr);

      /* create interface */
      eir.dev_class_index = dpdk_device_class.index;
      eir.dev_instance = xd->device_index;
      eir.address = addr;
      eir.cb.flag_change = dpdk_flag_change;
      eir.cb.set_max_frame_size = dpdk_set_max_frame_size;
      eir.cb.set_rss_config = dpdk_set_rss_config;
      xd->hw_if_index = vnet_eth_register_interface (vnm, &eir);
      hi = vnet_get_hw_interface (vnm, xd->hw_if_index);
      numa_node = (i8) rte_eth_dev_socket_id (port_id);
      if (numa_node == SOCKET_ID_ANY)
	/* numa_node is not set, default to 0 */
	hi->numa_node = xd->cpu_socket = 0;
      else
	hi->numa_node = xd->cpu_socket = numa_node;
      sw = vnet_get_hw_sw_interface (vnm, xd->hw_if_index);
      xd->sw_if_index = sw->sw_if_index;
      dpdk_log_debug ("[%u] interface %v created", port_id, hi->name);

      if (devconf->tag)
	vnet_set_sw_interface_tag (vnm, devconf->tag, sw->sw_if_index);

      ethernet_set_flags (vnm, xd->hw_if_index,
			  ETHERNET_INTERFACE_FLAG_DEFAULT_L3);

      /* assign worker threads */
      vnet_hw_if_set_input_node (vnm, xd->hw_if_index, dpdk_input_node.index);
      if (devconf->workers)
	{
	  int j;
	  q = 0;
	  clib_bitmap_foreach (j, devconf->workers)
	    {
	      dpdk_rx_queue_t *rxq = vec_elt_at_index (xd->rx_queues, q);
	      rxq->queue_index = vnet_hw_if_register_rx_queue (
		vnm, xd->hw_if_index, q++, vdm->first_worker_thread_index + j);
	    }
	}
      else
	for (q = 0; q < xd->conf.n_rx_queues; q++)
	  {
	    dpdk_rx_queue_t *rxq = vec_elt_at_index (xd->rx_queues, q);
	    rxq->queue_index = vnet_hw_if_register_rx_queue (
	      vnm, xd->hw_if_index, q, VNET_HW_IF_RXQ_THREAD_ANY);
	  }

      for (q = 0; q < xd->conf.n_tx_queues; q++)
	{
	  dpdk_tx_queue_t *txq = vec_elt_at_index (xd->tx_queues, q);
	  txq->queue_index =
	    vnet_hw_if_register_tx_queue (vnm, xd->hw_if_index, q);
	}

      for (q = 0; q < tm->n_vlib_mains; q++)
	{
	  u32 qi = xd->tx_queues[q % xd->conf.n_tx_queues].queue_index;
	  vnet_hw_if_tx_queue_assign_thread (vnm, qi, q);
	}

      if (devconf->tso == DPDK_DEVICE_TSO_ON)
	{
	  /*tcp_udp checksum must be enabled*/
	  if (xd->conf.enable_tcp_udp_checksum == 0)
	    dpdk_log_warn ("[%u] TCP/UDP checksum offload must be enabled",
			   xd->port_id);
	  else if ((di.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO) == 0)
	    dpdk_log_warn ("[%u] TSO not supported by device", xd->port_id);
	  else
	    xd->conf.enable_tso = 1;
	}

      if (devconf->max_lro_pkt_size)
	xd->conf.max_lro_pkt_size = devconf->max_lro_pkt_size;

      if (devconf->disable_rxq_int)
	xd->conf.enable_rxq_int = 0;

      dpdk_device_setup (xd);

      /* rss queues should be configured after dpdk_device_setup() */
      if (devconf->rss_queues)
	{
	  if (vnet_hw_interface_set_rss_queues (vnet_get_main (), hi,
						devconf->rss_queues))
	    dpdk_log_warn ("[%u] Failed to set rss queues", port_id);
	}

      if (vec_len (xd->errors))
	dpdk_log_err ("[%u] setup failed Errors:\n  %U", port_id,
		      format_dpdk_device_errors, xd);
      dpdk_counters_xstats_init (xd);
    }

  for (int i = 0; i < vec_len (dm->devices); i++)
    vnet_hw_if_update_runtime_data (vnm, dm->devices[i].hw_if_index);

  return 0;
}

static void
dpdk_bind_devices_to_uio (dpdk_config_main_t * conf)
{
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *pci_addr = 0;
  int num_whitelisted = vec_len (conf->dev_confs);
  vlib_pci_device_info_t *d = 0;
  vlib_pci_addr_t *addr = 0, *addrs;
  int i;

  addrs = vlib_pci_get_all_dev_addrs ();
  vec_foreach (addr, addrs)
    {
    dpdk_device_config_t * devconf = 0;
    vec_reset_length (pci_addr);
    pci_addr = format (pci_addr, "%U%c", format_vlib_pci_addr, addr, 0);
    if (d)
    {
      vlib_pci_free_device_info (d);
      d = 0;
      }
    d = vlib_pci_get_device_info (vm, addr, &error);
    if (error)
    {
      vlib_log_warn (dpdk_main.log_default, "%U", format_clib_error, error);
      clib_error_free (error);
      continue;
    }

#ifdef __FreeBSD__
    /*
     * The defines for the PCI_CLASS_* types are platform specific and differ
     * on FreeBSD.
     */
    if (d->device_class != PCI_CLASS_NETWORK &&
	d->device_class != PCI_CLASS_PROCESSOR_CO)
      continue;
#else
    if (d->device_class != PCI_CLASS_NETWORK_ETHERNET && d->device_class != PCI_CLASS_PROCESSOR_CO)
      continue;
#endif /* __FreeBSD__ */

    if (num_whitelisted)
      {
	uword * p = hash_get (conf->device_config_index_by_pci_addr, addr->as_u32);

	if (!p)
          {
	  skipped_pci:
	    continue;
	  }

	devconf = pool_elt_at_index (conf->dev_confs, p[0]);
      }

    /* Enforce Device blacklist by vendor and device */
    for (i = 0; i < vec_len (conf->blacklist_by_pci_vendor_and_device); i++)
      {
        u16 vendor, device;
        vendor = (u16)(conf->blacklist_by_pci_vendor_and_device[i] >> 16);
        device = (u16)(conf->blacklist_by_pci_vendor_and_device[i] & 0xFFFF);
        if (d->vendor_id == vendor && d->device_id == device)
          {
            /*
             * Expected case: device isn't whitelisted,
             * so blacklist it...
             */
            if (devconf == 0)
              {
                /* Device is blacklisted */
                pool_get (conf->dev_confs, devconf);
                hash_set (conf->device_config_index_by_pci_addr, addr->as_u32,
                          devconf - conf->dev_confs);
                devconf->pci_addr.as_u32 = addr->as_u32;
		devconf->dev_addr_type = VNET_DEV_ADDR_PCI;
		devconf->is_blacklisted = 1;
		goto skipped_pci;
	      }
	    else /* explicitly whitelisted, ignore the device blacklist  */
	      break;
	  }
      }

    /* virtio */
    if (d->vendor_id == 0x1af4 &&
            (d->device_id == VIRTIO_PCI_LEGACY_DEVICEID_NET ||
             d->device_id == VIRTIO_PCI_MODERN_DEVICEID_NET))
      ;
    /* vmxnet3 */
    else if (d->vendor_id == 0x15ad && d->device_id == 0x07b0)
      {
	/*
	 * For vmxnet3 PCI, unless it is explicitly specified in the whitelist,
	 * the default is to put it in the blacklist.
	 */
	if (devconf == 0)
	  {
	    pool_get (conf->dev_confs, devconf);
	    hash_set (conf->device_config_index_by_pci_addr, addr->as_u32,
		      devconf - conf->dev_confs);
	    devconf->pci_addr.as_u32 = addr->as_u32;
	    devconf->is_blacklisted = 1;
	  }
      }
    /* all Intel network devices */
    else if (d->vendor_id == 0x8086 && d->device_class == PCI_CLASS_NETWORK_ETHERNET)
      ;
    /* all Intel QAT devices VFs */
    else if (d->vendor_id == 0x8086 &&
	     d->device_class == PCI_CLASS_PROCESSOR_CO &&
	     (d->device_id == 0x0443 || d->device_id == 0x18a1 ||
	      d->device_id == 0x19e3 || d->device_id == 0x37c9 ||
	      d->device_id == 0x6f55 || d->device_id == 0x18ef ||
	      d->device_id == 0x4941 || d->device_id == 0x4943 ||
	      d->device_id == 0x4945))
      ;
    /* Cisco VIC */
    else if (d->vendor_id == 0x1137 &&
	     (d->device_id == 0x0043 || d->device_id == 0x0071 ||
	      d->device_id == 0x02b7))
      ;
    /* Chelsio T4/T5 */
    else if (d->vendor_id == 0x1425 && (d->device_id & 0xe000) == 0x4000)
      ;
    /* Amazon Elastic Network Adapter */
    else if (d->vendor_id == 0x1d0f && d->device_id >= 0xec20 && d->device_id <= 0xec21)
      ;
    /* Cavium Network Adapter */
    else if (d->vendor_id == 0x177d && d->device_id == 0x9712)
      ;
    /* Cavium FastlinQ QL41000 Series */
    else if (d->vendor_id == 0x1077 && d->device_id >= 0x8070 && d->device_id <= 0x8090)
      ;
    /* Mellanox CX3, CX3VF */
    else if (d->vendor_id == 0x15b3 && d->device_id >= 0x1003 && d->device_id <= 0x1004)
      {
        continue;
      }
    /* Mellanox CX4, CX4VF, CX4LX, CX4LXVF, CX5, CX5VF, CX5EX, CX5EXVF */
    else if (d->vendor_id == 0x15b3 && d->device_id >= 0x1013 && d->device_id <= 0x101a)
      {
        continue;
      }
    /* Mellanox CX6, CX6VF, CX6DX, CX6DXVF, CX6LX */
    else if (d->vendor_id == 0x15b3 &&
	     (d->device_id >= 0x101b && d->device_id <= 0x101f))
      {
	continue;
      }
    /* Mellanox CX7 */
    else if (d->vendor_id == 0x15b3 && d->device_id == 0x1021)
      {
	continue;
      }
    /* Mellanox BF, BFVF */
    else if (d->vendor_id == 0x15b3 &&
	     (d->device_id >= 0xa2d2 && d->device_id <= 0Xa2d3))
      {
	continue;
      }
    /* Mellanox BF2, BF3 */
    else if (d->vendor_id == 0x15b3 &&
	     (d->device_id == 0xa2d6 || d->device_id == 0xa2dc))
      {
	continue;
      }
    /* Broadcom NetXtreme S, and E series only */
    else if (d->vendor_id == 0x14e4 &&
	((d->device_id >= 0x16c0 &&
		d->device_id != 0x16c6 && d->device_id != 0x16c7 &&
		d->device_id != 0x16dd && d->device_id != 0x16f7 &&
		d->device_id != 0x16fd && d->device_id != 0x16fe &&
		d->device_id != 0x170d && d->device_id != 0x170c &&
		d->device_id != 0x170e && d->device_id != 0x1712 &&
		d->device_id != 0x1713) ||
	(d->device_id == 0x1604 || d->device_id == 0x1605 ||
	 d->device_id == 0x1614 || d->device_id == 0x1606 ||
	 d->device_id == 0x1609 || d->device_id == 0x1614)))
      ;
    /* Google vNIC */
    else if (d->vendor_id == 0x1ae0 && d->device_id == 0x0042)
      ;
    else
      {
        dpdk_log_warn ("Unsupported PCI device 0x%04x:0x%04x found "
		      "at PCI address %s\n", (u16) d->vendor_id, (u16) d->device_id,
		      pci_addr);
        continue;
      }

    error = vlib_pci_bind_to_uio (vm, addr, (char *) conf->uio_driver_name,
				  conf->uio_bind_force);

    if (error)
      {
	if (devconf == 0)
	  {
	    pool_get (conf->dev_confs, devconf);
	    hash_set (conf->device_config_index_by_pci_addr, addr->as_u32,
		      devconf - conf->dev_confs);
	    devconf->pci_addr.as_u32 = addr->as_u32;
	  }
	devconf->dev_addr_type = VNET_DEV_ADDR_PCI;
	devconf->is_blacklisted = 1;
	clib_error_report (error);
      }
  }
  vec_free (pci_addr);
  vlib_pci_free_device_info (d);
}

static void
dpdk_bind_vmbus_devices_to_uio (dpdk_config_main_t * conf)
{
  clib_error_t *error;
  vlib_vmbus_addr_t *addrs, *addr = 0;
  int num_whitelisted = vec_len (conf->dev_confs);
  int i;

  addrs = vlib_vmbus_get_all_dev_addrs ();

  vec_foreach (addr, addrs)
    {
      dpdk_device_config_t *devconf = 0;
      if (num_whitelisted)
	{
	  uword *p =
	    mhash_get (&conf->device_config_index_by_vmbus_addr, addr);
	  if (!p)
	    {
	      /* No devices blacklisted, but have whitelisted. blacklist all
	       * non-whitelisted */
	      pool_get (conf->dev_confs, devconf);
	      mhash_set (&conf->device_config_index_by_vmbus_addr, addr,
			 devconf - conf->dev_confs, 0);
	      devconf->vmbus_addr = *addr;
	      devconf->dev_addr_type = VNET_DEV_ADDR_VMBUS;
	      devconf->is_blacklisted = 1;
	    skipped_vmbus:
	      continue;
	    }

	  devconf = pool_elt_at_index (conf->dev_confs, p[0]);
	}

      /* Enforce Device blacklist by vmbus_addr */
      for (i = 0; i < vec_len (conf->blacklist_by_vmbus_addr); i++)
	{
	  vlib_vmbus_addr_t *a1 = &conf->blacklist_by_vmbus_addr[i];
	  vlib_vmbus_addr_t *a2 = addr;
	  if (memcmp (a1, a2, sizeof (vlib_vmbus_addr_t)) == 0)
	    {
	      if (devconf == 0)
		{
		  /* Device not whitelisted */
		  pool_get (conf->dev_confs, devconf);
		  mhash_set (&conf->device_config_index_by_vmbus_addr, addr,
			     devconf - conf->dev_confs, 0);
		  devconf->vmbus_addr = *addr;
		  devconf->dev_addr_type = VNET_DEV_ADDR_VMBUS;
		  devconf->is_blacklisted = 1;
		  goto skipped_vmbus;
		}
	      else
		{
		  break;
		}
	    }
	}

      error = vlib_vmbus_bind_to_uio (addr);
      if (error)
	{
	  if (devconf == 0)
	    {
	      pool_get (conf->dev_confs, devconf);
	      mhash_set (&conf->device_config_index_by_vmbus_addr, addr,
			 devconf - conf->dev_confs, 0);
	      devconf->vmbus_addr = *addr;
	    }
	  devconf->dev_addr_type = VNET_DEV_ADDR_VMBUS;
	  devconf->is_blacklisted = 1;
	  clib_error_report (error);
	}
    }
}

uword
unformat_max_simd_bitwidth (unformat_input_t *input, va_list *va)
{
  uword *max_simd_bitwidth = va_arg (*va, uword *);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!unformat (input, "%u", max_simd_bitwidth))
	goto error;

      if (*max_simd_bitwidth != DPDK_MAX_SIMD_BITWIDTH_256 &&
	  *max_simd_bitwidth != DPDK_MAX_SIMD_BITWIDTH_512)
	goto error;
    }
  return 1;
error:
  return 0;
}

static clib_error_t *
dpdk_device_config (dpdk_config_main_t *conf, void *addr,
		    dpdk_device_addr_type_t addr_type, unformat_input_t *input,
		    u8 is_default)
{
  clib_error_t *error = 0;
  uword *p;
  dpdk_device_config_t *devconf = 0;
  unformat_input_t sub_input;

  if (is_default)
    {
      devconf = &conf->default_devconf;
    }
  else if (addr_type == VNET_DEV_ADDR_PCI)
    {
      p = hash_get (conf->device_config_index_by_pci_addr,
		    ((vlib_pci_addr_t *) (addr))->as_u32);

      if (!p)
	{
	  pool_get (conf->dev_confs, devconf);
	  hash_set (conf->device_config_index_by_pci_addr,
		    ((vlib_pci_addr_t *) (addr))->as_u32,
		    devconf - conf->dev_confs);
	}
      else
	return clib_error_return (0,
				  "duplicate configuration for PCI address %U",
				  format_vlib_pci_addr, addr);
    }
  else if (addr_type == VNET_DEV_ADDR_VMBUS)
    {
      p = mhash_get (&conf->device_config_index_by_vmbus_addr,
		     (vlib_vmbus_addr_t *) (addr));

      if (!p)
	{
	  pool_get (conf->dev_confs, devconf);
	  mhash_set (&conf->device_config_index_by_vmbus_addr, addr,
		     devconf - conf->dev_confs, 0);
	}
      else
	return clib_error_return (
	  0, "duplicate configuration for VMBUS address %U",
	  format_vlib_vmbus_addr, addr);
    }

  if (addr_type == VNET_DEV_ADDR_PCI)
    {
      devconf->pci_addr.as_u32 = ((vlib_pci_addr_t *) (addr))->as_u32;
      devconf->tso = DPDK_DEVICE_TSO_DEFAULT;
      devconf->dev_addr_type = VNET_DEV_ADDR_PCI;
    }
  else if (addr_type == VNET_DEV_ADDR_VMBUS)
    {
      devconf->vmbus_addr = *((vlib_vmbus_addr_t *) (addr));
      devconf->tso = DPDK_DEVICE_TSO_DEFAULT;
      devconf->dev_addr_type = VNET_DEV_ADDR_VMBUS;
    }

  if (!input)
    return 0;

  unformat_skip_white_space (input);
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "num-rx-queues %u", &devconf->num_rx_queues))
	;
      else if (unformat (input, "num-tx-queues %u", &devconf->num_tx_queues))
	;
      else if (unformat (input, "num-rx-desc %u", &devconf->num_rx_desc))
	;
      else if (unformat (input, "num-tx-desc %u", &devconf->num_tx_desc))
	;
      else if (unformat (input, "name %v", &devconf->name))
	;
      else if (unformat (input, "tag %s", &devconf->tag))
	;
      else if (unformat (input, "workers %U", unformat_bitmap_list,
			 &devconf->workers))
	;
      else
	if (unformat
	    (input, "rss %U", unformat_vlib_cli_sub_input, &sub_input))
	{
	  error = unformat_rss_fn (&sub_input, &devconf->rss_fn);
	  if (error)
	    break;
	}
      else if (unformat (input, "no-rx-interrupts"))
	{
	  devconf->disable_rxq_int = 1;
	}
      else if (unformat (input, "tso on"))
	{
	  devconf->tso = DPDK_DEVICE_TSO_ON;
	}
      else if (unformat (input, "tso off"))
	{
	  devconf->tso = DPDK_DEVICE_TSO_OFF;
	}
      else if (unformat (input, "devargs %s", &devconf->devargs))
	;
      else if (unformat (input, "rss-queues %U",
			 unformat_bitmap_list, &devconf->rss_queues))
	;
      else if (unformat (input, "max-lro-pkt-size %u",
			 &devconf->max_lro_pkt_size))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  break;
	}
    }

  if (error)
    return error;

  if (devconf->workers && devconf->num_rx_queues == 0)
    devconf->num_rx_queues = clib_bitmap_count_set_bits (devconf->workers);
  else if (devconf->workers &&
	   clib_bitmap_count_set_bits (devconf->workers) !=
	   devconf->num_rx_queues)
    error = clib_error_return (0,
			       "%U: number of worker threads must be "
			       "equal to number of rx queues",
			       format_vlib_pci_addr, addr);

  return error;
}

static clib_error_t *
dpdk_log_read_ready (clib_file_t * uf)
{
  unformat_input_t input;
  u8 *line, *s = 0;
  int n, n_try;

  n = n_try = 4096;
  while (n == n_try)
    {
      uword len = vec_len (s);
      vec_resize (s, len + n_try);

      n = read (uf->file_descriptor, s + len, n_try);
      if (n < 0 && errno != EAGAIN)
	return clib_error_return_unix (0, "read");
      vec_set_len (s, len + (n < 0 ? 0 : n));
    }

  unformat_init_vector (&input, s);

  while (unformat_user (&input, unformat_line, &line))
    {
      int skip = 0;
      vec_add1 (line, 0);

      /* unfortunatelly DPDK polutes log with this error messages
       * even when we pass --in-memory which means no secondary process */
      if (strstr ((char *) line, "WARNING! Base virtual address hint"))
	skip = 1;
      else if (strstr ((char *) line, "This may cause issues with mapping "
				      "memory into secondary processes"))
	skip = 1;
      vec_pop (line);
      if (!skip)
	dpdk_log_notice ("%v", line);
      vec_free (line);
    }

  unformat_free (&input);
  return 0;
}

static clib_error_t *
dpdk_set_stat_poll_interval (f64 interval)
{
  if (interval < DPDK_MIN_STATS_POLL_INTERVAL)
    return clib_error_return (0, "wrong stats-poll-interval value");

  dpdk_main.stat_poll_interval = interval;
  return 0;
}

static clib_error_t *
dpdk_set_link_state_poll_interval (f64 interval)
{
  if (interval < DPDK_MIN_LINK_POLL_INTERVAL)
    return clib_error_return (0, "wrong link-state-poll-interval value");

  dpdk_main.link_state_poll_interval = interval;
  return 0;
}

static clib_error_t *
dpdk_config (vlib_main_t * vm, unformat_input_t * input)
{
  dpdk_main_t *dm = &dpdk_main;
  clib_error_t *error = 0;
  dpdk_config_main_t *conf = &dpdk_config_main;
  dpdk_device_config_t *devconf;
  vlib_pci_addr_t pci_addr = { 0 };
  vlib_vmbus_addr_t vmbus_addr = { 0 };
  unformat_input_t sub_input;
#ifdef __linux
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  uword default_hugepage_sz, x;
  u8 file_prefix = 0;
#endif /* __linux__ */
  u8 *s, *tmp = 0;
  int ret, i;
  int num_whitelisted = 0;
  int eal_no_hugetlb = 0;
  u8 no_pci = 0;
  u8 no_vmbus = 0;
  u8 *socket_mem = 0;
  u32 vendor, device, domain, bus, func;
  void *fmt_func;
  void *fmt_addr;
  f64 poll_interval;
  u8 *tracepat = 0;
  u8 *tracedir = 0;

  conf->device_config_index_by_pci_addr = hash_create (0, sizeof (uword));
  mhash_init (&conf->device_config_index_by_vmbus_addr, sizeof (uword),
	      sizeof (vlib_vmbus_addr_t));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* Prime the pump */
      if (unformat (input, "no-hugetlb"))
	{
	  vec_add1 (conf->eal_init_args, (u8 *) "--no-huge");
	  eal_no_hugetlb = 1;
	}
      else if (unformat (input, "telemetry"))
	conf->enable_telemetry = 1;

      else if (unformat (input, "enable-tcp-udp-checksum"))
	{
	  dm->default_port_conf.enable_tcp_udp_checksum = 1;
	  if (unformat (input, "enable-outer-checksum-offload"))
	    dm->default_port_conf.enable_outer_checksum_offload = 1;
	}
      else if (unformat (input, "no-tx-checksum-offload"))
	dm->default_port_conf.disable_tx_checksum_offload = 1;

      else if (unformat (input, "decimal-interface-names"))
	conf->interface_name_format_decimal = 1;

      else if (unformat (input, "no-multi-seg"))
	dm->default_port_conf.disable_multi_seg = 1;
      else if (unformat (input, "enable-lro"))
	dm->default_port_conf.enable_lro = 1;
      else if (unformat (input, "max-simd-bitwidth %U",
			 unformat_max_simd_bitwidth, &conf->max_simd_bitwidth))
	;
      else if (unformat (input, "link-state-poll-interval %f", &poll_interval))
	{
	  error = dpdk_set_link_state_poll_interval (poll_interval);
	  if (error != 0)
	    return error;
	}
      else if (unformat (input, "stats-poll-interval %f", &poll_interval))
	{
	  error = dpdk_set_stat_poll_interval (poll_interval);
	  if (error != 0)
	    return error;
	}
      else if (unformat (input, "dev default %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  error =
	    dpdk_device_config (conf, 0, VNET_DEV_ADDR_ANY, &sub_input, 1);

	  if (error)
	    return error;
	}
      else
	if (unformat
	    (input, "dev %U %U", unformat_vlib_pci_addr, &pci_addr,
	     unformat_vlib_cli_sub_input, &sub_input))
	{
	  error = dpdk_device_config (conf, &pci_addr, VNET_DEV_ADDR_PCI,
				      &sub_input, 0);

	  if (error)
	    return error;

	  num_whitelisted++;
	}
      else if (unformat (input, "dev %U", unformat_vlib_pci_addr, &pci_addr))
	{
	  error =
	    dpdk_device_config (conf, &pci_addr, VNET_DEV_ADDR_PCI, 0, 0);

	  if (error)
	    return error;

	  num_whitelisted++;
	}
      else if (unformat (input, "dev %U %U", unformat_vlib_vmbus_addr,
			 &vmbus_addr, unformat_vlib_cli_sub_input, &sub_input))
	{
	  error = dpdk_device_config (conf, &vmbus_addr, VNET_DEV_ADDR_VMBUS,
				      &sub_input, 0);

	  if (error)
	    return error;

	  num_whitelisted++;
	}
      else if (unformat (input, "dev %U", unformat_vlib_vmbus_addr,
			 &vmbus_addr))
	{
	  error =
	    dpdk_device_config (conf, &vmbus_addr, VNET_DEV_ADDR_VMBUS, 0, 0);

	  if (error)
	    return error;

	  num_whitelisted++;
	}
      else if (unformat (input, "uio-driver %s", &conf->uio_driver_name))
	;
      else if (unformat (input, "uio-bind-force"))
	conf->uio_bind_force = 1;
      else if (unformat (input, "socket-mem %s", &socket_mem))
	;
      else if (unformat (input, "no-pci"))
	{
	  no_pci = 1;
	  tmp = format (0, "--no-pci%c", 0);
	  vec_add1 (conf->eal_init_args, tmp);
	}
      else if (unformat (input, "blacklist %U", unformat_vlib_vmbus_addr,
			 &vmbus_addr))
	{
	  vec_add1 (conf->blacklist_by_vmbus_addr, vmbus_addr);
	}
      else
	if (unformat
	    (input, "blacklist %x:%x:%x.%x", &domain, &bus, &device, &func))
	{
	  tmp = format (0, "-b%c", 0);
	  vec_add1 (conf->eal_init_args, tmp);
	  tmp =
	    format (0, "%04x:%02x:%02x.%x%c", domain, bus, device, func, 0);
	  vec_add1 (conf->eal_init_args, tmp);
	}
      else if (unformat (input, "blacklist %x:%x", &vendor, &device))
	{
	  u32 blacklist_entry;
	  if (vendor > 0xFFFF)
	    return clib_error_return (0, "blacklist PCI vendor out of range");
	  if (device > 0xFFFF)
	    return clib_error_return (0, "blacklist PCI device out of range");
	  blacklist_entry = (vendor << 16) | (device & 0xffff);
	  vec_add1 (conf->blacklist_by_pci_vendor_and_device,
		    blacklist_entry);
	}
      else if (unformat (input, "no-vmbus"))
	{
	  no_vmbus = 1;
	  tmp = format (0, "--no-vmbus%c", 0);
	  vec_add1 (conf->eal_init_args, tmp);
	}

      /*
       * this format "trace-dir %s" must come before "trace %s"
       */
      else if (unformat (input, "trace-dir %s", &tracedir))
	{
	  tmp = format (0, "--trace-dir=%s%c", (char *) tracedir, 0);
	  vec_add1 (conf->eal_init_args, tmp);
	}

      else if (unformat (input, "trace %s", &tracepat))
	{
	  tmp = format (0, "--trace=%s%c", (char *) tracepat, 0);
	  vec_add1 (conf->eal_init_args, tmp);
	}

#define _(a)                                    \
      else if (unformat(input, #a))             \
        {                                       \
          tmp = format (0, "--%s%c", #a, 0);    \
          vec_add1 (conf->eal_init_args, tmp);    \
        }
      foreach_eal_double_hyphen_predicate_arg
#undef _
#ifdef __linux__
#define _(a)                                          \
	else if (unformat(input, #a " %s", &s))	      \
	  {					      \
            if (!strncmp(#a, "file-prefix", 11)) \
              file_prefix = 1;                        \
	    tmp = format (0, "--%s%c", #a, 0);	      \
	    vec_add1 (conf->eal_init_args, tmp);      \
	    vec_add1 (s, 0);			      \
            if (!strncmp(#a, "vdev", 4))              \
              if (strstr((char*)s, "af_packet"))      \
                clib_warning ("af_packet obsoleted. Use CLI 'create host-interface'."); \
	    vec_add1 (conf->eal_init_args, s);	      \
	  }
	foreach_eal_double_hyphen_arg
#undef _
#endif /* __linux__ */
#define _(a,b)						\
	  else if (unformat(input, #a " %s", &s))	\
	    {						\
	      tmp = format (0, "-%s%c", #b, 0);		\
	      vec_add1 (conf->eal_init_args, tmp);	\
	      vec_add1 (s, 0);				\
	      vec_add1 (conf->eal_init_args, s);	\
	    }
	foreach_eal_single_hyphen_arg
#undef _
	else if (unformat (input, "default"))
	;

      else if (unformat_skip_white_space (input))
	;
      else return clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
    }

  if (!conf->uio_driver_name)
    conf->uio_driver_name = format (0, "auto%c", 0);

  if (eal_no_hugetlb == 0)
    {
      vec_add1 (conf->eal_init_args, (u8 *) "--in-memory");

#ifdef __linux__
      /*
       * FreeBSD performs huge page prealloc through a dedicated kernel mode
       * this process is only required on Linux.
       */
      default_hugepage_sz = clib_mem_get_default_hugepage_size ();

      clib_bitmap_foreach (x, tm->cpu_socket_bitmap)
	{
	  clib_error_t *e;
	  uword n_pages;
	  /* preallocate at least 16MB of hugepages per socket,
	    if more is needed it is up to consumer to preallocate more */
	  n_pages = round_pow2 ((uword) 16 << 20, default_hugepage_sz);
	  n_pages /= default_hugepage_sz;

	  if ((e = clib_sysfs_prealloc_hugepages(x, 0, n_pages)))
	    clib_error_report (e);
        }
#endif /* __linux__ */
    }

  /* on/off dpdk's telemetry thread */
  if (conf->enable_telemetry == 0)
    {
      vec_add1 (conf->eal_init_args, (u8 *) "--no-telemetry");
    }

#ifdef __linux__
  if (!file_prefix)
    {
      tmp = format (0, "--file-prefix%c", 0);
      vec_add1 (conf->eal_init_args, tmp);
      tmp = format (0, "vpp%c", 0);
      vec_add1 (conf->eal_init_args, tmp);
    }

  /* Remap main lcore onto DPDK lcore 0 if it exceeds the max lcore index */
  if (tm->main_lcore >= RTE_MAX_LCORE)
    {
      tmp = format (0, "--lcores%c", 0);
      vec_add1 (conf->eal_init_args, tmp);
      tmp = format (0, "0@%u%c", tm->main_lcore, 0);
      vec_add1 (conf->eal_init_args, tmp);
    }
#endif

  if (no_pci == 0 && geteuid () == 0)
    dpdk_bind_devices_to_uio (conf);

  if (no_vmbus == 0 && geteuid () == 0)
    dpdk_bind_vmbus_devices_to_uio (conf);

#define _(x) \
    if (devconf->x == 0 && conf->default_devconf.x > 0) \
      devconf->x = conf->default_devconf.x ;

  pool_foreach (devconf, conf->dev_confs)  {

    /* default per-device config items */
    foreach_dpdk_device_config_item

      /* copy tso config from default device */
      _ (tso)

      /* copy tso config from default device */
      _ (devargs)

      /* copy rss_queues config from default device */
      _ (rss_queues)

      /* assume that default is PCI */
      fmt_func = format_vlib_pci_addr;
    fmt_addr = &devconf->pci_addr;

    if (devconf->dev_addr_type == VNET_DEV_ADDR_VMBUS)
      {
	fmt_func = format_vlib_vmbus_addr;
	fmt_addr = &devconf->vmbus_addr;
      }

    /* add DPDK EAL whitelist/blacklist entry */
    if (num_whitelisted > 0 && devconf->is_blacklisted == 0)
      {
	tmp = format (0, "-a%c", 0);
	vec_add1 (conf->eal_init_args, tmp);
	if (devconf->devargs)
	  {
	    tmp =
	      format (0, "%U,%s%c", fmt_func, fmt_addr, devconf->devargs, 0);
	  }
	  else
	  {
	    tmp = format (0, "%U%c", fmt_func, fmt_addr, 0);
	  }
	  vec_add1 (conf->eal_init_args, tmp);
      }
    else if (num_whitelisted == 0 && devconf->is_blacklisted != 0)
      {
	tmp = format (0, "-b%c", 0);
	vec_add1 (conf->eal_init_args, tmp);
	tmp = format (0, "%U%c", fmt_func, fmt_addr, 0);
	vec_add1 (conf->eal_init_args, tmp);
      }
  }

#undef _

  if (socket_mem)
    clib_warning ("socket-mem argument is deprecated");

  /* NULL terminate the "argv" vector, in case of stupidity */
  vec_add1 (conf->eal_init_args, 0);
  vec_dec_len (conf->eal_init_args, 1);

  /* Set up DPDK eal and packet mbuf pool early. */

  int log_fds[2] = { 0 };
  if (pipe (log_fds) == 0)
    {
      if (fcntl (log_fds[0], F_SETFL, O_NONBLOCK) == 0 &&
	  fcntl (log_fds[1], F_SETFL, O_NONBLOCK) == 0)
	{
	  FILE *f = fdopen (log_fds[1], "a");
	  if (f && rte_openlog_stream (f) == 0)
	    {
	      clib_file_t t = { 0 };
	      t.read_function = dpdk_log_read_ready;
	      t.file_descriptor = log_fds[0];
	      t.description = format (0, "DPDK logging pipe");
	      clib_file_add (&file_main, &t);
	    }
	}
      else
	{
	  close (log_fds[0]);
	  close (log_fds[1]);
	}
    }

  vm = vlib_get_main ();

  /* make copy of args as rte_eal_init tends to mess up with arg array */
  for (i = 1; i < vec_len (conf->eal_init_args); i++)
    conf->eal_init_args_str = format (conf->eal_init_args_str, "%s ",
				      conf->eal_init_args[i]);

  vec_terminate_c_string (conf->eal_init_args_str);

  dpdk_log_notice ("EAL init args: %s", conf->eal_init_args_str);
  ret = rte_eal_init (vec_len (conf->eal_init_args),
		      (char **) conf->eal_init_args);
  if (ret < 0)
    return clib_error_return (0, "rte_eal_init returned %d", ret);

  /* enable the AVX-512 vPMDs in DPDK */
  if (clib_cpu_supports_avx512_bitalg () &&
      conf->max_simd_bitwidth == DPDK_MAX_SIMD_BITWIDTH_DEFAULT)
    rte_vect_set_max_simd_bitwidth (RTE_VECT_SIMD_512);
  else if (conf->max_simd_bitwidth != DPDK_MAX_SIMD_BITWIDTH_DEFAULT)
    rte_vect_set_max_simd_bitwidth (conf->max_simd_bitwidth ==
					DPDK_MAX_SIMD_BITWIDTH_256 ?
				      RTE_VECT_SIMD_256 :
				      RTE_VECT_SIMD_512);

  /* main thread 1st */
  if ((error = dpdk_buffer_pools_create (vm)))
    return error;

  return 0;
}

VLIB_CONFIG_FUNCTION (dpdk_config, "dpdk");

void
dpdk_update_link_state (dpdk_device_t * xd, f64 now)
{
  vnet_main_t *vnm = vnet_get_main ();
  struct rte_eth_link prev_link = xd->link;
  u32 hw_flags = 0;
  u8 hw_flags_chg = 0;
  int __clib_unused rv;

  xd->time_last_link_update = now ? now : xd->time_last_link_update;
  clib_memset (&xd->link, 0, sizeof (xd->link));
  rv = rte_eth_link_get_nowait (xd->port_id, &xd->link);
  ASSERT (rv == 0);

  if (LINK_STATE_ELOGS)
    {
      ELOG_TYPE_DECLARE (e) =
      {
      .format =
	  "update-link-state: sw_if_index %d, admin_up %d,"
	  "old link_state %d new link_state %d",.format_args = "i4i1i1i1",};

      struct
      {
	u32 sw_if_index;
	u8 admin_up;
	u8 old_link_state;
	u8 new_link_state;
      } *ed;
      ed = ELOG_DATA (vlib_get_elog_main (), e);
      ed->sw_if_index = xd->sw_if_index;
      ed->admin_up = (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP) != 0;
      ed->old_link_state = (u8)
	vnet_hw_interface_is_link_up (vnm, xd->hw_if_index);
      ed->new_link_state = (u8) xd->link.link_status;
    }

  hw_flags_chg = ((xd->link.link_duplex != prev_link.link_duplex) ||
		  (xd->link.link_status != prev_link.link_status));

  if (xd->link.link_speed != prev_link.link_speed)
    vnet_hw_interface_set_link_speed (vnm, xd->hw_if_index,
				      (xd->link.link_speed == UINT32_MAX) ?
					      UINT32_MAX :
					      xd->link.link_speed * 1000);

  if (hw_flags_chg)
    {
      if (xd->link.link_status)
	hw_flags |= VNET_HW_INTERFACE_FLAG_LINK_UP;

      switch (xd->link.link_duplex)
	{
	case RTE_ETH_LINK_HALF_DUPLEX:
	  hw_flags |= VNET_HW_INTERFACE_FLAG_HALF_DUPLEX;
	  break;
	case RTE_ETH_LINK_FULL_DUPLEX:
	  hw_flags |= VNET_HW_INTERFACE_FLAG_FULL_DUPLEX;
	  break;
	default:
	  break;
	}

      if (LINK_STATE_ELOGS)
	{
	  ELOG_TYPE_DECLARE (e) =
	  {
	  .format =
	      "update-link-state: sw_if_index %d, new flags %d",.format_args
	      = "i4i4",};

	  struct
	  {
	    u32 sw_if_index;
	    u32 flags;
	  } *ed;
	  ed = ELOG_DATA (vlib_get_elog_main (), e);
	  ed->sw_if_index = xd->sw_if_index;
	  ed->flags = hw_flags;
	}
      vnet_hw_interface_set_flags (vnm, xd->hw_if_index, hw_flags);
    }
}

static uword
dpdk_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  clib_error_t *error;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vlib_worker_thread_barrier_sync (vm);
  error = dpdk_lib_init (dm);

  if (error)
    clib_error_report (error);

  if (dpdk_cryptodev_init)
    {
      error = dpdk_cryptodev_init (vm);
      if (error)
	{
	  vlib_log_warn (dpdk_main.log_cryptodev, "%U", format_clib_error,
			 error);
	  clib_error_free (error);
	}
    }

  vlib_worker_thread_barrier_release (vm);
  tm->worker_thread_release = 1;

  f64 now = vlib_time_now (vm);
  vec_foreach (xd, dm->devices)
  {
    dpdk_update_link_state (xd, now);
  }

  f64 timeout =
    clib_min (dm->link_state_poll_interval, dm->stat_poll_interval);

  while (1)
    {
      f64 min_wait = clib_max (timeout, DPDK_MIN_POLL_INTERVAL);
      vlib_process_wait_for_event_or_clock (vm, min_wait);

      timeout =
	clib_min (dm->link_state_poll_interval, dm->stat_poll_interval);

      if (dm->admin_up_down_in_progress)
	/* skip the poll if an admin up down is in progress (on any interface) */
	continue;

      vec_foreach (xd, dm->devices)
      {
	f64 now = vlib_time_now (vm);
	if ((now - xd->time_last_stats_update) >= dm->stat_poll_interval)
	  dpdk_update_counters (xd, now);
	if ((now - xd->time_last_link_update) >= dm->link_state_poll_interval)
	  dpdk_update_link_state (xd, now);

      }

      now = vlib_time_now (vm);
      vec_foreach (xd, dm->devices)
	{
	  timeout = clib_min (timeout, xd->time_last_stats_update +
					 dm->stat_poll_interval - now);
	  timeout = clib_min (timeout, xd->time_last_link_update +
					 dm->link_state_poll_interval - now);
	}
    }
  return 0;
}

VLIB_REGISTER_NODE (dpdk_process_node,static) = {
    .function = dpdk_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "dpdk-process",
    .process_log2_n_stack_bytes = 17,
};

static clib_error_t *
dpdk_init (vlib_main_t * vm)
{
  dpdk_main_t *dm = &dpdk_main;
  clib_error_t *error = 0;

  /* verify that structs are cacheline aligned */
  STATIC_ASSERT (offsetof (dpdk_device_t, cacheline0) == 0,
		 "Cache line marker must be 1st element in dpdk_device_t");
  STATIC_ASSERT (offsetof (dpdk_device_t, cacheline1) ==
		 CLIB_CACHE_LINE_BYTES,
		 "Data in cache line 0 is bigger than cache line size");
  STATIC_ASSERT (offsetof (frame_queue_trace_t, cacheline0) == 0,
		 "Cache line marker must be 1st element in frame_queue_trace_t");

  dpdk_cli_reference ();

  dm->conf = &dpdk_config_main;

  vec_add1 (dm->conf->eal_init_args, (u8 *) "vnet");

  dm->stat_poll_interval = DPDK_STATS_POLL_INTERVAL;
  dm->link_state_poll_interval = DPDK_LINK_POLL_INTERVAL;

  dm->log_default = vlib_log_register_class ("dpdk", 0);
  dm->log_cryptodev = vlib_log_register_class ("dpdk", "cryptodev");

  return error;
}

VLIB_INIT_FUNCTION (dpdk_init);

static clib_error_t *
dpdk_worker_thread_init (vlib_main_t *vm)
{
  if (rte_thread_register () < 0)
    clib_panic ("dpdk: cannot register thread %u - %s", vm->thread_index,
		rte_strerror (rte_errno));
  return 0;
}

VLIB_WORKER_INIT_FUNCTION (dpdk_worker_thread_init);
