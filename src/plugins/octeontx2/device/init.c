/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Copyright (c) 2019 Marvell International Ltd. */

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/linux/sysfs.h>
#include <vlib/unix/unix.h>
#include <vlib/log.h>

#include <vnet/ethernet/ethernet.h>
#include <octeontx2/buffer.h>
#include <octeontx2/device/octeontx2.h>
#include <vlib/pci/pci.h>
#include <vlib/vmbus/vmbus.h>

#include <rte_ring.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>

#include <octeontx2/device/otx2_priv.h>

#define ETHER_MAX_LEN   1518  /**< Maximum frame len, including CRC. */

otx2_main_t otx2_main;
otx2_config_main_t otx2_config_main;

#define LINK_STATE_ELOGS	0

static u32
otx2_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi, u32 flags)
{
  otx2_main_t *dm = &otx2_main;
  otx2_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);
  u32 old = 0;

  if (ETHERNET_INTERFACE_FLAG_CONFIG_PROMISC (flags))
    {
      old = (xd->flags & OTX2_DEVICE_FLAG_PROMISC) != 0;

      if (flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL)
	xd->flags |= OTX2_DEVICE_FLAG_PROMISC;
      else
	xd->flags &= ~OTX2_DEVICE_FLAG_PROMISC;

      if (xd->flags & OTX2_DEVICE_FLAG_ADMIN_UP)
	{
	  if (xd->flags & OTX2_DEVICE_FLAG_PROMISC)
	    rte_eth_promiscuous_enable (xd->port_id);
	  else
	    rte_eth_promiscuous_disable (xd->port_id);
	}
    }
  else if (ETHERNET_INTERFACE_FLAG_CONFIG_MTU (flags))
    {
      xd->port_conf.rxmode.max_rx_pkt_len = hi->max_packet_bytes;
      otx2_device_setup (xd);
    }
  return old;
}

static void
otx2_device_lock_init (otx2_device_t * xd)
{
  int q;
  vec_validate (xd->lockp, xd->tx_q_used - 1);
  for (q = 0; q < xd->tx_q_used; q++)
    {
      xd->lockp[q] = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
					     CLIB_CACHE_LINE_BYTES);
      clib_memset ((void *) xd->lockp[q], 0, CLIB_CACHE_LINE_BYTES);
    }
}

static int
otx2_port_crc_strip_enabled (otx2_device_t * xd)
{
  return !(xd->port_conf.rxmode.offloads & DEV_RX_OFFLOAD_KEEP_CRC);
}

/* The funciton check_l3cache helps check if Level 3 cache exists or not on current CPUs
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

	  p = format (p, "%s/%s/%s", sys_cache_dir, dp->d_name, "level");
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

static clib_error_t *
otx2_lib_init (otx2_main_t * dm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_device_main_t *vdm = &vnet_device_main;
  vlib_pci_addr_t last_pci_addr;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hi;
  clib_error_t *error;
  u32 last_pci_addr_port = 0;
  otx2_device_t *xd;
  u32 mtu, max_rx_frame;
  u32 nports;
  int i;

  last_pci_addr.as_u32 = ~0;


  nports = rte_eth_dev_count_avail ();

  if (nports < 1)
    {
      otx2_log_notice ("DPDK drivers found no ports...");
    }

  if (CLIB_DEBUG > 0)
    otx2_log_notice ("DPDK drivers found %d ports...", nports);

  if (dm->conf->enable_tcp_udp_checksum)
    dm->buffer_flags_template &= ~(VNET_BUFFER_F_L4_CHECKSUM_CORRECT
				   | VNET_BUFFER_F_L4_CHECKSUM_COMPUTED);

  /* vlib_buffer_t template */
  vec_validate_aligned (dm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      otx2_per_thread_data_t *ptd = vec_elt_at_index (dm->per_thread_data, i);
      clib_memset (&ptd->buffer_template, 0, sizeof (vlib_buffer_t));
      ptd->buffer_template.flags = dm->buffer_flags_template;
      vnet_buffer (&ptd->buffer_template)->sw_if_index[VLIB_TX] = (u32) ~ 0;
      clib_memcpy_fast (ptd->otx2_mempool_by_index,
			otx2_mempool_by_buffer_pool_index,
			sizeof (ptd->otx2_mempool_by_index));
    }

  /* *INDENT-OFF* */
  RTE_ETH_FOREACH_DEV(i)
    {
      u8 addr[6];
      u8 vlan_strip = 0;
      struct rte_eth_dev_info dev_info;
      struct rte_pci_device *pci_dev;
      struct rte_eth_link l;
      otx2_portid_t next_port_id;
      otx2_device_config_t *devconf = 0;
      vlib_pci_addr_t pci_addr;
      uword *p = 0;

      if (!rte_eth_dev_is_valid_port(i))
	continue;

      rte_eth_link_get_nowait (i, &l);
      rte_eth_dev_info_get (i, &dev_info);

      if (dev_info.device == 0)
	{
	  clib_warning ("DPDK bug: missing device info. Skipping %s device",
			dev_info.driver_name);
	  continue;
	}

      pci_dev = otx2_get_pci_device (&dev_info);

      if (pci_dev)
	{
	  pci_addr.domain = pci_dev->addr.domain;
	  pci_addr.bus = pci_dev->addr.bus;
	  pci_addr.slot = pci_dev->addr.devid;
	  pci_addr.function = pci_dev->addr.function;
	  p = hash_get (dm->conf->device_config_index_by_pci_addr,
			pci_addr.as_u32);
	}

      /* Create vnet interface */
      vec_add2_aligned (dm->devices, xd, 1, CLIB_CACHE_LINE_BYTES);
      xd->nb_rx_desc = OTX2_NB_RX_DESC_DEFAULT;
      xd->nb_tx_desc = OTX2_NB_TX_DESC_DEFAULT;
      xd->cpu_socket = (i8) rte_eth_dev_socket_id (i);

      if (p)
	{
	  devconf = pool_elt_at_index (dm->conf->dev_confs, p[0]);
	  xd->name = devconf->name;
	}
      else
	devconf = &dm->conf->default_devconf;

      /* Handle interface naming for devices with multiple ports sharing same PCI ID */
      if (pci_dev &&
	  ((next_port_id = rte_eth_find_next (i + 1)) != RTE_MAX_ETHPORTS))
	{
	  struct rte_eth_dev_info di = { 0 };
	  struct rte_pci_device *next_pci_dev;
	  rte_eth_dev_info_get (next_port_id, &di);
	  next_pci_dev = di.device ? RTE_DEV_TO_PCI (di.device) : 0;
	  if (next_pci_dev &&
	      pci_addr.as_u32 != last_pci_addr.as_u32 &&
	      memcmp (&pci_dev->addr, &next_pci_dev->addr,
		      sizeof (struct rte_pci_addr)) == 0)
	    {
	      xd->interface_name_suffix = format (0, "0");
	      last_pci_addr.as_u32 = pci_addr.as_u32;
	      last_pci_addr_port = i;
	    }
	  else if (pci_addr.as_u32 == last_pci_addr.as_u32)
	    {
	      xd->interface_name_suffix =
		format (0, "%u", i - last_pci_addr_port);
	    }
	  else
	    {
	      last_pci_addr.as_u32 = ~0;
	    }
	}
      else
	last_pci_addr.as_u32 = ~0;

      clib_memcpy (&xd->tx_conf, &dev_info.default_txconf,
		   sizeof (struct rte_eth_txconf));

      if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM)
	{
	  xd->port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_IPV4_CKSUM;
	  xd->flags |= OTX2_DEVICE_FLAG_RX_IP4_CKSUM;
	}

      if (dm->conf->no_multi_seg)
	{
	  xd->port_conf.txmode.offloads &= ~DEV_TX_OFFLOAD_MULTI_SEGS;
	  xd->port_conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;
	  xd->port_conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_SCATTER;
	}
      else
	{
	  xd->port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MULTI_SEGS;
	  xd->port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	  xd->port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_SCATTER;
	  xd->flags |= OTX2_DEVICE_FLAG_MAYBE_MULTISEG;
	}

      xd->tx_q_used = clib_min (dev_info.max_tx_queues, tm->n_vlib_mains);

      if (devconf->num_tx_queues > 0
	  && devconf->num_tx_queues < xd->tx_q_used)
	xd->tx_q_used = clib_min (xd->tx_q_used, devconf->num_tx_queues);

      if (devconf->num_rx_queues > 1
	  && dev_info.max_rx_queues >= devconf->num_rx_queues)
	{
	  xd->rx_q_used = devconf->num_rx_queues;
	  xd->port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	  if (devconf->rss_fn == 0)
	    xd->port_conf.rx_adv_conf.rss_conf.rss_hf =
	      ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP;
	  else
	    {
	      u64 unsupported_bits;
	      xd->port_conf.rx_adv_conf.rss_conf.rss_hf = devconf->rss_fn;
	      unsupported_bits = xd->port_conf.rx_adv_conf.rss_conf.rss_hf;
	      unsupported_bits &= ~dev_info.flow_type_rss_offloads;
	      if (unsupported_bits)
		otx2_log_warn ("Unsupported RSS hash functions: %U",
			       format_otx2_rss_hf_name, unsupported_bits);
	    }
	  xd->port_conf.rx_adv_conf.rss_conf.rss_hf &=
	    dev_info.flow_type_rss_offloads;
	}
      else
	xd->rx_q_used = 1;

      xd->flags |= OTX2_DEVICE_FLAG_PMD;

      /* workaround for drivers not setting driver_name */
      if ((!dev_info.driver_name) && (pci_dev))
	dev_info.driver_name = pci_dev->driver->driver.name;

      ASSERT (dev_info.driver_name);

      if (!xd->pmd)
	{


#define _(s,f) else if (dev_info.driver_name &&                 \
                        !strcmp(dev_info.driver_name, s))       \
                 xd->pmd = VNET_OTX2_PMD_##f;
	  if (0)
	    ;
	  foreach_otx2_pmd
#undef _
	    else
	    xd->pmd = VNET_OTX2_PMD_UNKNOWN;

	  xd->port_type = VNET_OTX2_PORT_TYPE_UNKNOWN;
	  xd->nb_rx_desc = OTX2_NB_RX_DESC_DEFAULT;
	  xd->nb_tx_desc = OTX2_NB_TX_DESC_DEFAULT;

	  switch (xd->pmd)
	    {

	    case VNET_OTX2_PMD_OCTEONTX2:
	      xd->port_type = VNET_OTX2_PORT_TYPE_ETH_VF;
	      if (dm->conf->no_tx_checksum_offload == 0)
		{
	          xd->port_conf.txmode.offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;
	          xd->port_conf.txmode.offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;
	          xd->flags |= OTX2_DEVICE_FLAG_TX_OFFLOAD;
        }
	    break;

	    default:
	      xd->port_type = VNET_OTX2_PORT_TYPE_UNKNOWN;
	    }

	  if (devconf->num_rx_desc)
	    xd->nb_rx_desc = devconf->num_rx_desc;
          else {

            /* If num_rx_desc is not specified by VPP user, the current CPU is working
            with 2M page and has no L3 cache, default num_rx_desc is changed to 512
            from original 1024 to help reduce TLB misses.
            */
            if ((clib_mem_get_default_hugepage_size () == 2 << 20)
              && check_l3cache() == 0)
              xd->nb_rx_desc = 512;
          }

	  if (devconf->num_tx_desc)
	    xd->nb_tx_desc = devconf->num_tx_desc;
          else {

            /* If num_tx_desc is not specified by VPP user, the current CPU is working
            with 2M page and has no L3 cache, default num_tx_desc is changed to 512
            from original 1024 to help reduce TLB misses.
            */
            if ((clib_mem_get_default_hugepage_size () == 2 << 20)
              && check_l3cache() == 0)
              xd->nb_tx_desc = 512;
	  }
       }

	rte_eth_macaddr_get (i, (struct rte_ether_addr *) addr);

      if (xd->tx_q_used < tm->n_vlib_mains)
	otx2_device_lock_init (xd);

      xd->port_id = i;
      xd->device_index = xd - dm->devices;
      xd->per_interface_next_index = ~0;

      /* assign interface to input thread */
      int q;

      error = ethernet_register_interface
	(dm->vnet_main, otx2_device_class.index, xd->device_index,
	 /* ethernet address */ addr,
	 &xd->hw_if_index, otx2_flag_change);
      if (error)
	return error;

      /*
       * Ensure default mtu is not > the mtu read from the hardware.
       * Otherwise rte_eth_dev_configure() will fail and the port will
       * not be available.
       * Calculate max_frame_size and mtu supported by NIC
       */
      if (ETHERNET_MAX_PACKET_BYTES > dev_info.max_rx_pktlen)
	{
	  /*
	   * This device does not support the platforms's max frame
	   * size. Use it's advertised mru instead.
	   */
	  max_rx_frame = dev_info.max_rx_pktlen;
	  mtu = dev_info.max_rx_pktlen - sizeof (ethernet_header_t);
	}
      else
	{
	  /* VPP treats MTU and max_rx_pktlen both equal to
	   * ETHERNET_MAX_PACKET_BYTES, if dev_info.max_rx_pktlen >=
	   * ETHERNET_MAX_PACKET_BYTES + sizeof(ethernet_header_t)
	   */
	  if (dev_info.max_rx_pktlen >= (ETHERNET_MAX_PACKET_BYTES +
					 sizeof (ethernet_header_t)))
	    {
	      mtu = ETHERNET_MAX_PACKET_BYTES;
	      max_rx_frame = ETHERNET_MAX_PACKET_BYTES;

	      /*
	       * Some platforms do not account for Ethernet FCS (4 bytes) in
	       * MTU calculations. To interop with them increase mru but only
	       * if the device's settings can support it.
	       */
	      if (otx2_port_crc_strip_enabled (xd) &&
		  (dev_info.max_rx_pktlen >= (ETHERNET_MAX_PACKET_BYTES +
					      sizeof (ethernet_header_t) +
					      4)))
		{
		  max_rx_frame += 4;
		}
	    }
	  else
	    {
	      max_rx_frame = ETHERNET_MAX_PACKET_BYTES;
	      mtu = ETHERNET_MAX_PACKET_BYTES - sizeof (ethernet_header_t);

	      if (otx2_port_crc_strip_enabled (xd) &&
		  (dev_info.max_rx_pktlen >= (ETHERNET_MAX_PACKET_BYTES + 4)))
		{
		  max_rx_frame += 4;
		}
	    }
	}

      /*Set port rxmode config */
      xd->port_conf.rxmode.max_rx_pkt_len = max_rx_frame;

      sw = vnet_get_hw_sw_interface (dm->vnet_main, xd->hw_if_index);
      xd->sw_if_index = sw->sw_if_index;
      vnet_hw_interface_set_input_node (dm->vnet_main, xd->hw_if_index,
					otx2_input_node.index);

      if (devconf->workers)
	{
	  int i;
	  q = 0;
	  clib_bitmap_foreach (i, devconf->workers, ({
	    vnet_hw_interface_assign_rx_thread (dm->vnet_main, xd->hw_if_index, q++,
					     vdm->first_worker_thread_index + i);
	  }));
	}
      else
	for (q = 0; q < xd->rx_q_used; q++)
	  {
	    vnet_hw_interface_assign_rx_thread (dm->vnet_main, xd->hw_if_index, q,	/* any */
						~1);
	  }

      /*Get vnet hardware interface */
      hi = vnet_get_hw_interface (dm->vnet_main, xd->hw_if_index);

      /*Override default max_packet_bytes and max_supported_bytes set in
       * ethernet_register_interface() above*/
      if (hi)
	{
	  hi->max_packet_bytes = mtu;
	  hi->max_supported_packet_bytes = max_rx_frame;
	  hi->numa_node = xd->cpu_socket;
	}

      if (dm->conf->no_tx_checksum_offload == 0)
	if (xd->flags & OTX2_DEVICE_FLAG_TX_OFFLOAD && hi != NULL)
	  hi->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_TX_L4_CKSUM_OFFLOAD;

      otx2_device_setup (xd);

      if (vec_len (xd->errors))
	otx2_log_err ("setup failed for device %U. Errors:\n  %U",
		      format_otx2_device_name, i,
		      format_otx2_device_errors, xd);
      /*
       * VLAN stripping: default to VLAN strip disabled, unless specified
       * otherwise in the startup config.
       */
      if (devconf->vlan_strip_offload == OTX2_DEVICE_VLAN_STRIP_ON)
	vlan_strip = 1;

      if (vlan_strip)
	{
	  int vlan_off;
	  vlan_off = rte_eth_dev_get_vlan_offload (xd->port_id);
	  vlan_off |= ETH_VLAN_STRIP_OFFLOAD;
          if (vlan_off)
	    xd->port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_STRIP;
	  else
	    xd->port_conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_VLAN_STRIP;
	  if (rte_eth_dev_set_vlan_offload (xd->port_id, vlan_off) == 0)
	    otx2_log_info ("VLAN strip enabled for interface\n");
	  else
	    otx2_log_warn ("VLAN strip cannot be supported by interface\n");
	}

      if (hi)
	hi->max_packet_bytes = xd->port_conf.rxmode.max_rx_pkt_len
	  - sizeof (ethernet_header_t);
      else
	clib_warning ("hi NULL");

      if (dm->conf->no_multi_seg)
	mtu = mtu > ETHER_MAX_LEN ? ETHER_MAX_LEN : mtu;

      rte_eth_dev_set_mtu (xd->port_id, mtu);
    }
  /* *INDENT-ON* */

  return 0;
}

static clib_error_t *
otx2_device_config (otx2_config_main_t * conf, vlib_pci_addr_t pci_addr,
		    unformat_input_t * input, u8 is_default)
{
  clib_error_t *error = 0;
  uword *p;
  otx2_device_config_t *devconf;
  unformat_input_t sub_input;

  if (is_default)
    {
      devconf = &conf->default_devconf;
    }
  else
    {
      p = hash_get (conf->device_config_index_by_pci_addr, pci_addr.as_u32);

      if (!p)
	{
	  pool_get (conf->dev_confs, devconf);
	  hash_set (conf->device_config_index_by_pci_addr, pci_addr.as_u32,
		    devconf - conf->dev_confs);
	}
      else
	return clib_error_return (0,
				  "duplicate configuration for PCI address %U",
				  format_vlib_pci_addr, &pci_addr);
    }

  devconf->pci_addr.as_u32 = pci_addr.as_u32;

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
      else if (unformat (input, "name %s", &devconf->name))
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
      else if (unformat (input, "vlan-strip-offload off"))
	devconf->vlan_strip_offload = OTX2_DEVICE_VLAN_STRIP_OFF;
      else if (unformat (input, "vlan-strip-offload on"))
	devconf->vlan_strip_offload = OTX2_DEVICE_VLAN_STRIP_ON;
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
    error =
      clib_error_return (0,
			 "%U: number of worker threads must be "
			 "equal to number of rx queues", format_vlib_pci_addr,
			 &pci_addr);

  return error;
}

static clib_error_t *
otx2_log_read_ready (clib_file_t * uf)
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
      _vec_len (s) = len + (n < 0 ? 0 : n);
    }

  unformat_init_vector (&input, s);

  while (unformat_user (&input, unformat_line, &line))
    {
      otx2_log_notice ("%v", line);
      vec_free (line);
    }

  unformat_free (&input);
  return 0;
}

static clib_error_t *
otx2_config (vlib_main_t * vm, unformat_input_t * input)
{
  clib_error_t *error = 0;
  otx2_config_main_t *conf = &otx2_config_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  otx2_device_config_t *devconf;
  vlib_pci_addr_t pci_addr;
  unformat_input_t sub_input;
  uword default_hugepage_sz, x;
  u8 *s, *tmp = 0;
  int ret, i;
  int num_whitelisted = 0;
  u8 file_prefix = 0;
  u8 *socket_mem = 0;
  u8 *huge_dir_path = 0;

  huge_dir_path =
    format (0, "%s/hugepages%c", vlib_unix_get_runtime_dir (), 0);

  conf->device_config_index_by_pci_addr = hash_create (0, sizeof (uword));
  /*By default disable multi-seg */
  conf->no_multi_seg = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* Prime the pump */
      if (unformat (input, "no-hugetlb"))
	{
	  vec_add1 (conf->eal_init_args, (u8 *) "--no-huge");
	}

      else if (unformat (input, "enable-tcp-udp-checksum"))
	conf->enable_tcp_udp_checksum = 1;

      else if (unformat (input, "no-tx-checksum-offload"))
	conf->no_tx_checksum_offload = 1;

      else if (unformat (input, "no-multi-seg"))
	conf->no_multi_seg = 0;

      else if (unformat (input, "dev default %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  error =
	    otx2_device_config (conf, (vlib_pci_addr_t) (u32) ~ 1, &sub_input,
				1);

	  if (error)
	    return error;
	}
      else
	if (unformat
	    (input, "dev %U %U", unformat_vlib_pci_addr, &pci_addr,
	     unformat_vlib_cli_sub_input, &sub_input))
	{
	  error = otx2_device_config (conf, pci_addr, &sub_input, 0);

	  if (error)
	    return error;

	  num_whitelisted++;
	}
      else if (unformat (input, "dev %U", unformat_vlib_pci_addr, &pci_addr))
	{
	  error = otx2_device_config (conf, pci_addr, 0, 0);

	  if (error)
	    return error;

	  num_whitelisted++;
	}
      else if (unformat (input, "num-mem-channels %d", &conf->nchannels))
	conf->nchannels_set_manually = 0;
      else if (unformat (input, "num-crypto-mbufs %d",
			 &conf->num_crypto_mbufs))
	;
      else if (unformat (input, "uio-driver %s", &conf->uio_driver_name))
	;
      else if (unformat (input, "num-mbufs %d", &conf->num_mbufs))
	;
      else if (unformat (input, "socket-mem %s", &socket_mem))
	;
#define _(a)                                    \
      else if (unformat(input, #a))             \
        {                                       \
          tmp = format (0, "--%s%c", #a, 0);    \
          vec_add1 (conf->eal_init_args, tmp);    \
        }
      foreach_eal_double_hyphen_predicate_arg
#undef _
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
#define _(a,b)						\
	    else if (unformat(input, #a " %s", &s))	\
	      {						\
		tmp = format (0, "-%s%c", #b, 0);	\
		vec_add1 (conf->eal_init_args, tmp);	\
		vec_add1 (s, 0);			\
		vec_add1 (conf->eal_init_args, s);	\
		conf->a##_set_manually = 1;		\
	      }
	foreach_eal_single_hyphen_mandatory_arg
#undef _
	else if (unformat (input, "default"))
	;

      else if (unformat_skip_white_space (input))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }
  /*By default we require some buffers to be configured */
  if (!conf->num_mbufs)
    {
      conf->num_mbufs = 8192;
    }
  /*Warn user */
  if (!conf->no_multi_seg)
    {
      conf->no_multi_seg = 1;
      clib_warning ("ignoring no-multi-seg option");
    }
  if (!conf->uio_driver_name)
    conf->uio_driver_name = format (0, "auto%c", 0);

  default_hugepage_sz = clib_mem_get_default_hugepage_size ();

  /* *INDENT-OFF* */
  clib_bitmap_foreach (x, tm->cpu_socket_bitmap, (
    {
      clib_error_t *e;
      uword n_pages;
      /* preallocate at least 16MB of hugepages per socket,
	 if more is needed it is up to consumer to preallocate more */
      n_pages = round_pow2 ((uword) 16 << 20, default_hugepage_sz);
      n_pages /= default_hugepage_sz;

      if ((e = clib_sysfs_prealloc_hugepages(x, 0, n_pages)))
	clib_error_report (e);
  }));
  /* *INDENT-ON* */

  if (!file_prefix)
    {
      tmp = format (0, "--file-prefix%c", 0);
      vec_add1 (conf->eal_init_args, tmp);
      tmp = format (0, "vpp%c", 0);
      vec_add1 (conf->eal_init_args, tmp);
    }

  if (error)
    return error;

  /* I'll bet that -c and -n must be the first and second args... */
  if (!conf->coremask_set_manually)
    {
      vlib_thread_registration_t *tr;
      uword *coremask = 0;
      int i;

      /* main thread core */
      coremask = clib_bitmap_set (coremask, tm->main_lcore, 1);

      for (i = 0; i < vec_len (tm->registrations); i++)
	{
	  tr = tm->registrations[i];
	  coremask = clib_bitmap_or (coremask, tr->coremask);
	}

      vec_insert (conf->eal_init_args, 2, 1);
      conf->eal_init_args[1] = (u8 *) "-c";
      tmp = format (0, "%U%c", format_bitmap_hex, coremask, 0);
      conf->eal_init_args[2] = tmp;
      clib_bitmap_free (coremask);
    }

  if (!conf->nchannels_set_manually)
    {
      vec_insert (conf->eal_init_args, 2, 3);
      conf->eal_init_args[3] = (u8 *) "-n";
      tmp = format (0, "%d", conf->nchannels);
      conf->eal_init_args[4] = tmp;
    }

#define _(x) \
    if (devconf->x == 0 && conf->default_devconf.x > 0) \
      devconf->x = conf->default_devconf.x ;

  /* *INDENT-OFF* */
  pool_foreach (devconf, conf->dev_confs, ({

    /* default per-device config items */
    foreach_otx2_device_config_item

    /* copy vlan_strip config from default device */
	if (devconf->vlan_strip_offload == 0 &&
		conf->default_devconf.vlan_strip_offload > 0)
		devconf->vlan_strip_offload =
			conf->default_devconf.vlan_strip_offload;

    /* add DPDK EAL whitelist/blacklist entry */
    if (num_whitelisted > 0)
      {
	tmp = format (0, "-w%c", 0);
	vec_add1 (conf->eal_init_args, tmp);
    /* Pass devargs as vlib_enable=1 to PMD to select VLIB based driver functions instead of
     * regular mbuf based driver functions
     */
	tmp = format (0, "%U,scalar_enable=1,vlib_enable=1%c", format_vlib_pci_addr, &devconf->pci_addr,0);
	vec_add1 (conf->eal_init_args, tmp);
      }
  }));
  /* *INDENT-ON* */

#undef _

  /* set master-lcore */
  tmp = format (0, "--master-lcore%c", 0);
  vec_add1 (conf->eal_init_args, tmp);
  tmp = format (0, "%u%c", tm->main_lcore, 0);
  vec_add1 (conf->eal_init_args, tmp);


  if (socket_mem)
    clib_warning ("socket-mem argument is deprecated");

  /* NULL terminate the "argv" vector, in case of stupidity */
  vec_add1 (conf->eal_init_args, 0);
  _vec_len (conf->eal_init_args) -= 1;

  /* Set up DPDK eal and packet mbuf pool early. */

  int log_fds[2] = { 0 };
  if (pipe (log_fds) == 0)
    {
      if (fcntl (log_fds[1], F_SETFL, O_NONBLOCK) == 0)
	{
	  FILE *f = fdopen (log_fds[1], "a");
	  if (f && rte_openlog_stream (f) == 0)
	    {
	      clib_file_t t = { 0 };
	      t.read_function = otx2_log_read_ready;
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

  otx2_log_warn ("EAL init args: %s", conf->eal_init_args_str);
  ret = rte_eal_init (vec_len (conf->eal_init_args),
		      (char **) conf->eal_init_args);

  /* lazy umount hugepages */
  umount2 ((char *) huge_dir_path, MNT_DETACH);
  rmdir ((char *) huge_dir_path);
  vec_free (huge_dir_path);

  if (ret < 0)
    return clib_error_return (0, "rte_eal_init returned %d", ret);

  /* main thread 1st */
  if ((error = otx2_buffer_pools_create (vm)))
    return error;

done:
  return error;
}

VLIB_CONFIG_FUNCTION (otx2_config, "octeontx2");

void
otx2_update_link_state (otx2_device_t * xd, f64 now)
{
  vnet_main_t *vnm = vnet_get_main ();
  struct rte_eth_link prev_link = xd->link;
  u32 hw_flags = 0;
  u8 hw_flags_chg = 0;

  /* only update link state for PMD interfaces */
  if ((xd->flags & OTX2_DEVICE_FLAG_PMD) == 0)
    return;

  xd->time_last_link_update = now ? now : xd->time_last_link_update;
  clib_memset (&xd->link, 0, sizeof (xd->link));
  rte_eth_link_get_nowait (xd->port_id, &xd->link);

  if (LINK_STATE_ELOGS)
    {
      vlib_main_t *vm = vlib_get_main ();
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
      ed = ELOG_DATA (&vm->elog_main, e);
      ed->sw_if_index = xd->sw_if_index;
      ed->admin_up = (xd->flags & OTX2_DEVICE_FLAG_ADMIN_UP) != 0;
      ed->old_link_state = (u8)
	vnet_hw_interface_is_link_up (vnm, xd->hw_if_index);
      ed->new_link_state = (u8) xd->link.link_status;
    }

  if ((xd->link.link_duplex != prev_link.link_duplex))
    {
      hw_flags_chg = 1;
      switch (xd->link.link_duplex)
	{
	case ETH_LINK_HALF_DUPLEX:
	  hw_flags |= VNET_HW_INTERFACE_FLAG_HALF_DUPLEX;
	  break;
	case ETH_LINK_FULL_DUPLEX:
	  hw_flags |= VNET_HW_INTERFACE_FLAG_FULL_DUPLEX;
	  break;
	default:
	  break;
	}
    }
  if (xd->link.link_speed != prev_link.link_speed)
    vnet_hw_interface_set_link_speed (vnm, xd->hw_if_index,
				      xd->link.link_speed * 1000);

  if (xd->link.link_status != prev_link.link_status)
    {
      hw_flags_chg = 1;

      if (xd->link.link_status)
	hw_flags |= VNET_HW_INTERFACE_FLAG_LINK_UP;
    }

  if (hw_flags_chg)
    {
      if (LINK_STATE_ELOGS)
	{
	  vlib_main_t *vm = vlib_get_main ();

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
	  ed = ELOG_DATA (&vm->elog_main, e);
	  ed->sw_if_index = xd->sw_if_index;
	  ed->flags = hw_flags;
	}
      vnet_hw_interface_set_flags (vnm, xd->hw_if_index, hw_flags);
    }
}

static uword
otx2_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  clib_error_t *error;
  otx2_main_t *dm = &otx2_main;
  otx2_device_t *xd;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  error = otx2_lib_init (dm);

  if (error)
    clib_error_report (error);

  tm->worker_thread_release = 1;

  f64 now = vlib_time_now (vm);
  vec_foreach (xd, dm->devices)
  {
    otx2_update_link_state (xd, now);
  }

  while (1)
    {
      /*
       * check each time through the loop in case intervals are changed
       */
      f64 min_wait = dm->link_state_poll_interval < dm->stat_poll_interval ?
	dm->link_state_poll_interval : dm->stat_poll_interval;

      vlib_process_wait_for_event_or_clock (vm, min_wait);

      if (dm->admin_up_down_in_progress)
	/* skip the poll if an admin up down is in progress (on any interface) */
	continue;

      vec_foreach (xd, dm->devices)
      {
	f64 now = vlib_time_now (vm);
	if ((now - xd->time_last_stats_update) >= dm->stat_poll_interval)
	  otx2_update_counters (xd, now);
	if ((now - xd->time_last_link_update) >= dm->link_state_poll_interval)
	  otx2_update_link_state (xd, now);

      }
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (otx2_process_node,static) = {
    .function = otx2_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "otx2-process",
    .process_log2_n_stack_bytes = 17,
};
/* *INDENT-ON* */

static clib_error_t *
otx2_init (vlib_main_t * vm)
{
  otx2_main_t *dm = &otx2_main;
  clib_error_t *error = 0;

  /* verify that structs are cacheline aligned */
  STATIC_ASSERT (offsetof (otx2_device_t, cacheline0) == 0,
		 "Cache line marker must be 1st element in otx2_device_t");
  STATIC_ASSERT (offsetof (otx2_device_t, cacheline1) ==
		 CLIB_CACHE_LINE_BYTES,
		 "Data in cache line 0 is bigger than cache line size");
  STATIC_ASSERT (offsetof (frame_queue_trace_t, cacheline0) == 0,
		 "Cache line marker must be 1st element in frame_queue_trace_t");
  STATIC_ASSERT (RTE_CACHE_LINE_SIZE == 1 << CLIB_LOG2_CACHE_LINE_BYTES,
		 "OCTEONTX2 CACHE LINE SIZE does not match with 1<<CLIB_LOG2_CACHE_LINE_BYTES");

  dm->vlib_main = vm;
  dm->vnet_main = vnet_get_main ();
  dm->conf = &otx2_config_main;

  dm->conf->nchannels = 4;
  vec_add1 (dm->conf->eal_init_args, (u8 *) "vnet");
  vec_add1 (dm->conf->eal_init_args, (u8 *) "--in-memory");

  /* Default vlib_buffer_t flags, DISABLES tcp/udp checksumming... */
  dm->buffer_flags_template = (VLIB_BUFFER_TOTAL_LENGTH_VALID |
			       VLIB_BUFFER_EXT_HDR_VALID |
			       VNET_BUFFER_F_L4_CHECKSUM_COMPUTED |
			       VNET_BUFFER_F_L4_CHECKSUM_CORRECT);

  dm->stat_poll_interval = OTX2_STATS_POLL_INTERVAL;
  dm->link_state_poll_interval = OTX2_LINK_POLL_INTERVAL;

  dm->log_default = vlib_log_register_class ("otx2", 0);

  return error;
}

VLIB_INIT_FUNCTION (otx2_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
