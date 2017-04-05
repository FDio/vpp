/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

#include <vnet/ethernet/ethernet.h>
#include <dpdk/device/dpdk.h>
#include <vlib/unix/physmem.h>
#include <vlib/pci/pci.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>

#include <dpdk/device/dpdk_priv.h>

dpdk_main_t dpdk_main;

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <dpdk/api/dpdk_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <dpdk/api/dpdk_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <dpdk/api/dpdk_all_api_h.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <dpdk/api/dpdk_all_api_h.h>
#undef vl_api_version

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

#include <vlibapi/api_helper_macros.h>

static void
  vl_api_sw_interface_set_dpdk_hqos_pipe_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_pipe_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_pipe_reply_t *rmp;
  int rv = 0;

  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 subport = ntohl (mp->subport);
  u32 pipe = ntohl (mp->pipe);
  u32 profile = ntohl (mp->profile);
  vnet_hw_interface_t *hw;

  VALIDATE_SW_IF_INDEX (mp);

  /* hw_if & dpdk device */
  hw = vnet_get_sup_hw_interface (dm->vnet_main, sw_if_index);

  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rv = rte_sched_pipe_config (xd->hqos_ht->hqos, subport, pipe, profile);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_PIPE_REPLY);
}

static void *vl_api_sw_interface_set_dpdk_hqos_pipe_t_print
  (vl_api_sw_interface_set_dpdk_hqos_pipe_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_dpdk_hqos_pipe ");

  s = format (s, "sw_if_index %u ", ntohl (mp->sw_if_index));

  s = format (s, "subport %u  pipe %u  profile %u ",
	      ntohl (mp->subport), ntohl (mp->pipe), ntohl (mp->profile));

  FINISH;
}

static void
  vl_api_sw_interface_set_dpdk_hqos_subport_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_subport_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_subport_reply_t *rmp;
  int rv = 0;

  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  struct rte_sched_subport_params p;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 subport = ntohl (mp->subport);
  p.tb_rate = ntohl (mp->tb_rate);
  p.tb_size = ntohl (mp->tb_size);
  p.tc_rate[0] = ntohl (mp->tc_rate[0]);
  p.tc_rate[1] = ntohl (mp->tc_rate[1]);
  p.tc_rate[2] = ntohl (mp->tc_rate[2]);
  p.tc_rate[3] = ntohl (mp->tc_rate[3]);
  p.tc_period = ntohl (mp->tc_period);

  vnet_hw_interface_t *hw;

  VALIDATE_SW_IF_INDEX (mp);

  /* hw_if & dpdk device */
  hw = vnet_get_sup_hw_interface (dm->vnet_main, sw_if_index);

  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rv = rte_sched_subport_config (xd->hqos_ht->hqos, subport, &p);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_SUBPORT_REPLY);
}

static void *vl_api_sw_interface_set_dpdk_hqos_subport_t_print
  (vl_api_sw_interface_set_dpdk_hqos_subport_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_dpdk_hqos_subport ");

  s = format (s, "sw_if_index %u ", ntohl (mp->sw_if_index));

  s =
    format (s,
	    "subport %u  rate %u  bkt_size %u  tc0 %u tc1 %u tc2 %u tc3 %u period %u",
	    ntohl (mp->subport), ntohl (mp->tb_rate), ntohl (mp->tb_size),
	    ntohl (mp->tc_rate[0]), ntohl (mp->tc_rate[1]),
	    ntohl (mp->tc_rate[2]), ntohl (mp->tc_rate[3]),
	    ntohl (mp->tc_period));

  FINISH;
}

static void
  vl_api_sw_interface_set_dpdk_hqos_tctbl_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_tctbl_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_tctbl_reply_t *rmp;
  int rv = 0;

  dpdk_main_t *dm = &dpdk_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_device_t *xd;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 entry = ntohl (mp->entry);
  u32 tc = ntohl (mp->tc);
  u32 queue = ntohl (mp->queue);
  u32 val, i;

  vnet_hw_interface_t *hw;

  VALIDATE_SW_IF_INDEX (mp);

  /* hw_if & dpdk device */
  hw = vnet_get_sup_hw_interface (dm->vnet_main, sw_if_index);

  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  if (tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
      clib_warning ("invalid traffic class !!");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  if (queue >= RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS)
    {
      clib_warning ("invalid queue !!");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  /* Detect the set of worker threads */
  uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");

  if (p == 0)
    {
      clib_warning ("worker thread registration AWOL !!");
      rv = VNET_API_ERROR_INVALID_VALUE_2;
      goto done;
    }

  vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];
  int worker_thread_first = tr->first_index;
  int worker_thread_count = tr->count;

  val = tc * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS + queue;
  for (i = 0; i < worker_thread_count; i++)
    xd->hqos_wt[worker_thread_first + i].hqos_tc_table[entry] = val;

  BAD_SW_IF_INDEX_LABEL;
done:

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_TCTBL_REPLY);
}

static void *vl_api_sw_interface_set_dpdk_hqos_tctbl_t_print
  (vl_api_sw_interface_set_dpdk_hqos_tctbl_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_dpdk_hqos_tctbl ");

  s = format (s, "sw_if_index %u ", ntohl (mp->sw_if_index));

  s = format (s, "entry %u  tc %u  queue %u",
	      ntohl (mp->entry), ntohl (mp->tc), ntohl (mp->queue));

  FINISH;
}

#define foreach_dpdk_plugin_api_msg                                       \
_(SW_INTERFACE_SET_DPDK_HQOS_PIPE, sw_interface_set_dpdk_hqos_pipe)       \
_(SW_INTERFACE_SET_DPDK_HQOS_SUBPORT, sw_interface_set_dpdk_hqos_subport) \
_(SW_INTERFACE_SET_DPDK_HQOS_TCTBL, sw_interface_set_dpdk_hqos_tctbl)

/* Set up the API message handling tables */
static clib_error_t *
dpdk_plugin_api_hookup (vlib_main_t * vm)
{
  dpdk_main_t *dm __attribute__ ((unused)) = &dpdk_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + dm->msg_id_base),     \
                           #n,          \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_dpdk_plugin_api_msg;
#undef _
  return 0;
}

#define vl_msg_name_crc_list
#include <dpdk/api/dpdk_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (dpdk_main_t * dm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + dm->msg_id_base);
  foreach_vl_msg_name_crc_dpdk;
#undef _
}

//  TODO
/*
static void plugin_custom_dump_configure (dpdk_main_t * dm)
{
#define _(n,f) dm->api_main->msg_print_handlers \
  [VL_API_##n + dm->msg_id_base]                \
    = (void *) vl_api_##f##_t_print;
  foreach_dpdk_plugin_api_msg;
#undef _
}
*/
/* force linker to link functions used by vlib and declared weak */
void *vlib_weakly_linked_functions[] = {
  &rte_pktmbuf_init,
  &rte_pktmbuf_pool_init,
};

#define LINK_STATE_ELOGS	0

#define DEFAULT_HUGE_DIR "/run/vpp/hugepages"
#define VPP_RUN_DIR "/run/vpp"

/* Port configuration, mildly modified Intel app values */

static struct rte_eth_conf port_conf_template = {
  .rxmode = {
	     .split_hdr_size = 0,
	     .header_split = 0,		/**< Header Split disabled */
	     .hw_ip_checksum = 0,	/**< IP checksum offload disabled */
	     .hw_vlan_filter = 0,	/**< VLAN filtering disabled */
	     .hw_strip_crc = 0,		/**< CRC stripped by hardware */
	     },
  .txmode = {
	     .mq_mode = ETH_MQ_TX_NONE,
	     },
};

clib_error_t *
dpdk_port_setup (dpdk_main_t * dm, dpdk_device_t * xd)
{
  int rv;
  int j;

  ASSERT (vlib_get_thread_index () == 0);

  if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
    {
      vnet_hw_interface_set_flags (dm->vnet_main, xd->hw_if_index, 0);
      rte_eth_dev_stop (xd->device_index);
    }

  rv = rte_eth_dev_configure (xd->device_index, xd->rx_q_used,
			      xd->tx_q_used, &xd->port_conf);

  if (rv < 0)
    return clib_error_return (0, "rte_eth_dev_configure[%d]: err %d",
			      xd->device_index, rv);

  /* Set up one TX-queue per worker thread */
  for (j = 0; j < xd->tx_q_used; j++)
    {
      rv = rte_eth_tx_queue_setup (xd->device_index, j, xd->nb_tx_desc,
				   xd->cpu_socket, &xd->tx_conf);

      /* retry with any other CPU socket */
      if (rv < 0)
	rv = rte_eth_tx_queue_setup (xd->device_index, j, xd->nb_tx_desc,
				     SOCKET_ID_ANY, &xd->tx_conf);
      if (rv < 0)
	break;
    }

  if (rv < 0)
    return clib_error_return (0, "rte_eth_tx_queue_setup[%d]: err %d",
			      xd->device_index, rv);

  for (j = 0; j < xd->rx_q_used; j++)
    {
      uword tidx = vnet_get_device_input_thread_index (dm->vnet_main,
						       xd->hw_if_index, j);
      unsigned lcore = vlib_worker_threads[tidx].lcore_id;
      u16 socket_id = rte_lcore_to_socket_id (lcore);

      rv = rte_eth_rx_queue_setup (xd->device_index, j, xd->nb_rx_desc,
				   xd->cpu_socket, 0,
				   dm->pktmbuf_pools[socket_id]);

      /* retry with any other CPU socket */
      if (rv < 0)
	rv = rte_eth_rx_queue_setup (xd->device_index, j, xd->nb_rx_desc,
				     SOCKET_ID_ANY, 0,
				     dm->pktmbuf_pools[socket_id]);
      if (rv < 0)
	return clib_error_return (0, "rte_eth_rx_queue_setup[%d]: err %d",
				  xd->device_index, rv);
    }

  if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
    {
      int rv;
      rv = rte_eth_dev_start (xd->device_index);
      if (!rv && xd->default_mac_address)
	rv = rte_eth_dev_default_mac_addr_set (xd->device_index,
					       (struct ether_addr *)
					       xd->default_mac_address);
      if (rv < 0)
	clib_warning ("rte_eth_dev_start %d returned %d",
		      xd->device_index, rv);
    }
  return 0;
}

static u32
dpdk_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi, u32 flags)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);
  u32 old = 0;

  if (ETHERNET_INTERFACE_FLAG_CONFIG_PROMISC (flags))
    {
      old = (xd->flags & DPDK_DEVICE_FLAG_PROMISC) != 0;

      if (flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL)
	xd->flags |= DPDK_DEVICE_FLAG_PROMISC;
      else
	xd->flags &= ~DPDK_DEVICE_FLAG_PROMISC;

      if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
	{
	  if (xd->flags & DPDK_DEVICE_FLAG_PROMISC)
	    rte_eth_promiscuous_enable (xd->device_index);
	  else
	    rte_eth_promiscuous_disable (xd->device_index);
	}
    }
  else if (ETHERNET_INTERFACE_FLAG_CONFIG_MTU (flags))
    {
      int rv;

      xd->port_conf.rxmode.max_rx_pkt_len = hi->max_packet_bytes;

      if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
	rte_eth_dev_stop (xd->device_index);

      rv = rte_eth_dev_configure
	(xd->device_index, xd->rx_q_used, xd->tx_q_used, &xd->port_conf);

      if (rv < 0)
	vlib_cli_output (vlib_get_main (),
			 "rte_eth_dev_configure[%d]: err %d",
			 xd->device_index, rv);

      rte_eth_dev_set_mtu (xd->device_index, hi->max_packet_bytes);

      if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
	{
	  int rv = rte_eth_dev_start (xd->device_index);
	  if (!rv && xd->default_mac_address)
	    rv = rte_eth_dev_default_mac_addr_set (xd->device_index,
						   (struct ether_addr *)
						   xd->default_mac_address);
	  if (rv < 0)
	    clib_warning ("rte_eth_dev_start %d returned %d",
			  xd->device_index, rv);
	}

    }
  return old;
}

void
dpdk_device_lock_init (dpdk_device_t * xd)
{
  int q;
  vec_validate (xd->lockp, xd->tx_q_used - 1);
  for (q = 0; q < xd->tx_q_used; q++)
    {
      xd->lockp[q] = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
					     CLIB_CACHE_LINE_BYTES);
      memset ((void *) xd->lockp[q], 0, CLIB_CACHE_LINE_BYTES);
    }
}

void
dpdk_device_lock_free (dpdk_device_t * xd)
{
  int q;

  for (q = 0; q < vec_len (xd->lockp); q++)
    clib_mem_free ((void *) xd->lockp[q]);
  vec_free (xd->lockp);
  xd->lockp = 0;
}

static clib_error_t *
dpdk_lib_init (dpdk_main_t * dm)
{
  u32 nports;
  u32 nb_desc = 0;
  int i;
  clib_error_t *error;
  vlib_main_t *vm = vlib_get_main ();
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_device_main_t *vdm = &vnet_device_main;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hi;
  dpdk_device_t *xd;
  vlib_pci_addr_t last_pci_addr;
  u32 last_pci_addr_port = 0;
  vlib_thread_registration_t *tr_hqos;
  uword *p_hqos;

  u32 next_hqos_cpu = 0;
  u8 af_packet_port_id = 0;
  u8 bond_ether_port_id = 0;
  last_pci_addr.as_u32 = ~0;

  dm->hqos_cpu_first_index = 0;
  dm->hqos_cpu_count = 0;

  /* find out which cpus will be used for I/O TX */
  p_hqos = hash_get_mem (tm->thread_registrations_by_name, "hqos-threads");
  tr_hqos = p_hqos ? (vlib_thread_registration_t *) p_hqos[0] : 0;

  if (tr_hqos && tr_hqos->count > 0)
    {
      dm->hqos_cpu_first_index = tr_hqos->first_index;
      dm->hqos_cpu_count = tr_hqos->count;
    }

  vec_validate_aligned (dm->devices_by_hqos_cpu, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  nports = rte_eth_dev_count ();
  if (nports < 1)
    {
      clib_warning ("DPDK drivers found no ports...");
    }

  if (CLIB_DEBUG > 0)
    clib_warning ("DPDK drivers found %d ports...", nports);

  /*
   * All buffers are all allocated from the same rte_mempool.
   * Thus they all have the same number of data bytes.
   */
  dm->vlib_buffer_free_list_index =
    vlib_buffer_get_or_create_free_list (vm,
					 VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES,
					 "dpdk rx");

  if (dm->conf->enable_tcp_udp_checksum)
    dm->buffer_flags_template &= ~(IP_BUFFER_L4_CHECKSUM_CORRECT
				   | IP_BUFFER_L4_CHECKSUM_COMPUTED);

  /* vlib_buffer_t template */
  vec_validate_aligned (dm->buffer_templates, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      vlib_buffer_free_list_t *fl;
      vlib_buffer_t *bt = vec_elt_at_index (dm->buffer_templates, i);
      fl = vlib_buffer_get_free_list (vm,
				      VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
      vlib_buffer_init_for_free_list (bt, fl);
      bt->flags = dm->buffer_flags_template;
      bt->current_data = -RTE_PKTMBUF_HEADROOM;
      vnet_buffer (bt)->sw_if_index[VLIB_TX] = (u32) ~ 0;
    }

  for (i = 0; i < nports; i++)
    {
      u8 addr[6];
      u8 vlan_strip = 0;
      int j;
      struct rte_eth_dev_info dev_info;
      clib_error_t *rv;
      struct rte_eth_link l;
      dpdk_device_config_t *devconf = 0;
      vlib_pci_addr_t pci_addr;
      uword *p = 0;

      rte_eth_dev_info_get (i, &dev_info);
      if (dev_info.pci_dev)	/* bonded interface has no pci info */
	{
	  pci_addr.domain = dev_info.pci_dev->addr.domain;
	  pci_addr.bus = dev_info.pci_dev->addr.bus;
	  pci_addr.slot = dev_info.pci_dev->addr.devid;
	  pci_addr.function = dev_info.pci_dev->addr.function;
	  p =
	    hash_get (dm->conf->device_config_index_by_pci_addr,
		      pci_addr.as_u32);
	}

      if (p)
	devconf = pool_elt_at_index (dm->conf->dev_confs, p[0]);
      else
	devconf = &dm->conf->default_devconf;

      /* Create vnet interface */
      vec_add2_aligned (dm->devices, xd, 1, CLIB_CACHE_LINE_BYTES);
      xd->nb_rx_desc = DPDK_NB_RX_DESC_DEFAULT;
      xd->nb_tx_desc = DPDK_NB_TX_DESC_DEFAULT;
      xd->cpu_socket = (i8) rte_eth_dev_socket_id (i);

      /* Handle interface naming for devices with multiple ports sharing same PCI ID */
      if (dev_info.pci_dev)
	{
	  struct rte_eth_dev_info di = { 0 };
	  rte_eth_dev_info_get (i + 1, &di);
	  if (di.pci_dev && pci_addr.as_u32 != last_pci_addr.as_u32 &&
	      memcmp (&dev_info.pci_dev->addr, &di.pci_dev->addr,
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
      if (dm->conf->no_multi_seg)
	{
	  xd->tx_conf.txq_flags |= ETH_TXQ_FLAGS_NOMULTSEGS;
	  port_conf_template.rxmode.jumbo_frame = 0;
	  port_conf_template.rxmode.enable_scatter = 0;
	}
      else
	{
	  xd->tx_conf.txq_flags &= ~ETH_TXQ_FLAGS_NOMULTSEGS;
	  port_conf_template.rxmode.jumbo_frame = 1;
	  port_conf_template.rxmode.enable_scatter = 1;
	  xd->flags |= DPDK_DEVICE_FLAG_MAYBE_MULTISEG;
	}

      clib_memcpy (&xd->port_conf, &port_conf_template,
		   sizeof (struct rte_eth_conf));

      xd->tx_q_used = clib_min (dev_info.max_tx_queues, tm->n_vlib_mains);

      if (devconf->num_tx_queues > 0
	  && devconf->num_tx_queues < xd->tx_q_used)
	xd->tx_q_used = clib_min (xd->tx_q_used, devconf->num_tx_queues);

      if (devconf->num_rx_queues > 1 && dm->use_rss == 0)
	{
	  dm->use_rss = 1;
	}

      if (devconf->num_rx_queues > 1
	  && dev_info.max_rx_queues >= devconf->num_rx_queues)
	{
	  xd->rx_q_used = devconf->num_rx_queues;
	  xd->port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	  if (devconf->rss_fn == 0)
	    xd->port_conf.rx_adv_conf.rss_conf.rss_hf =
	      ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP;
	  else
	    xd->port_conf.rx_adv_conf.rss_conf.rss_hf = devconf->rss_fn;
	}
      else
	xd->rx_q_used = 1;

      xd->flags |= DPDK_DEVICE_FLAG_PMD;

      /* workaround for drivers not setting driver_name */
      if ((!dev_info.driver_name) && (dev_info.pci_dev))
	dev_info.driver_name = dev_info.pci_dev->driver->driver.name;

      ASSERT (dev_info.driver_name);

      if (!xd->pmd)
	{


#define _(s,f) else if (dev_info.driver_name &&                 \
                        !strcmp(dev_info.driver_name, s))       \
                 xd->pmd = VNET_DPDK_PMD_##f;
	  if (0)
	    ;
	  foreach_dpdk_pmd
#undef _
	    else
	    xd->pmd = VNET_DPDK_PMD_UNKNOWN;

	  xd->port_type = VNET_DPDK_PORT_TYPE_UNKNOWN;
	  xd->nb_rx_desc = DPDK_NB_RX_DESC_DEFAULT;
	  xd->nb_tx_desc = DPDK_NB_TX_DESC_DEFAULT;

	  switch (xd->pmd)
	    {
	      /* 1G adapters */
	    case VNET_DPDK_PMD_E1000EM:
	    case VNET_DPDK_PMD_IGB:
	    case VNET_DPDK_PMD_IGBVF:
	      xd->port_type = VNET_DPDK_PORT_TYPE_ETH_1G;
	      break;

	      /* 10G adapters */
	    case VNET_DPDK_PMD_IXGBE:
	    case VNET_DPDK_PMD_IXGBEVF:
	    case VNET_DPDK_PMD_THUNDERX:
	      xd->port_type = VNET_DPDK_PORT_TYPE_ETH_10G;
	      break;
	    case VNET_DPDK_PMD_DPAA2:
	      xd->port_type = VNET_DPDK_PORT_TYPE_ETH_10G;
	      break;

	      /* Cisco VIC */
	    case VNET_DPDK_PMD_ENIC:
	      rte_eth_link_get_nowait (i, &l);
	      xd->flags |= DPDK_DEVICE_FLAG_PMD_SUPPORTS_PTYPE;
	      if (l.link_speed == 40000)
		xd->port_type = VNET_DPDK_PORT_TYPE_ETH_40G;
	      else
		xd->port_type = VNET_DPDK_PORT_TYPE_ETH_10G;
	      break;

	      /* Intel Fortville */
	    case VNET_DPDK_PMD_I40E:
	    case VNET_DPDK_PMD_I40EVF:
	      xd->flags |= DPDK_DEVICE_FLAG_PMD_SUPPORTS_PTYPE;
	      xd->port_type = VNET_DPDK_PORT_TYPE_ETH_40G;

	      switch (dev_info.pci_dev->id.device_id)
		{
		case I40E_DEV_ID_10G_BASE_T:
		case I40E_DEV_ID_SFP_XL710:
		  xd->port_type = VNET_DPDK_PORT_TYPE_ETH_10G;
		  break;
		case I40E_DEV_ID_QSFP_A:
		case I40E_DEV_ID_QSFP_B:
		case I40E_DEV_ID_QSFP_C:
		  xd->port_type = VNET_DPDK_PORT_TYPE_ETH_40G;
		  break;
		case I40E_DEV_ID_VF:
		  rte_eth_link_get_nowait (i, &l);
		  xd->port_type = l.link_speed == 10000 ?
		    VNET_DPDK_PORT_TYPE_ETH_10G : VNET_DPDK_PORT_TYPE_ETH_40G;
		  break;
		default:
		  xd->port_type = VNET_DPDK_PORT_TYPE_UNKNOWN;
		}
	      break;

	    case VNET_DPDK_PMD_CXGBE:
	      switch (dev_info.pci_dev->id.device_id)
		{
		case 0x540d:	/* T580-CR */
		case 0x5410:	/* T580-LP-cr */
		  xd->port_type = VNET_DPDK_PORT_TYPE_ETH_40G;
		  break;
		case 0x5403:	/* T540-CR */
		  xd->port_type = VNET_DPDK_PORT_TYPE_ETH_10G;
		  break;
		default:
		  xd->port_type = VNET_DPDK_PORT_TYPE_UNKNOWN;
		}
	      break;

	    case VNET_DPDK_PMD_MLX5:
	      {
		char *pn_100g[] = { "MCX415A-CCAT", "MCX416A-CCAT",
		  "MCX556A-ECAT", "MCX556A-EDAT", "MCX555A-ECAT",
		  "MCX515A-CCAT", "MCX516A-CCAT", "MCX516A-CDAT", 0
		};
		char *pn_40g[] = { "MCX413A-BCAT", "MCX414A-BCAT",
		  "MCX415A-BCAT", "MCX416A-BCAT", "MCX4131A-BCAT", 0
		};
		char *pn_10g[] = { "MCX4111A-XCAT", "MCX4121A-XCAT", 0 };

		vlib_pci_device_t *pd = vlib_get_pci_device (&pci_addr);
		u8 *pn = 0;
		char **c;
		int found = 0;
		pn = format (0, "%U%c",
			     format_vlib_pci_vpd, pd->vpd_r, "PN", 0);

		if (!pn)
		  break;

		c = pn_100g;
		while (!found && c[0])
		  {
		    if (strncmp ((char *) pn, c[0], strlen (c[0])) == 0)
		      {
			xd->port_type = VNET_DPDK_PORT_TYPE_ETH_100G;
			break;
		      }
		    c++;
		  }

		c = pn_40g;
		while (!found && c[0])
		  {
		    if (strncmp ((char *) pn, c[0], strlen (c[0])) == 0)
		      {
			xd->port_type = VNET_DPDK_PORT_TYPE_ETH_40G;
			break;
		      }
		    c++;
		  }

		c = pn_10g;
		while (!found && c[0])
		  {
		    if (strncmp ((char *) pn, c[0], strlen (c[0])) == 0)
		      {
			xd->port_type = VNET_DPDK_PORT_TYPE_ETH_10G;
			break;
		      }
		    c++;
		  }

		vec_free (pn);
	      }

	      break;
	      /* Intel Red Rock Canyon */
	    case VNET_DPDK_PMD_FM10K:
	      xd->port_type = VNET_DPDK_PORT_TYPE_ETH_SWITCH;
	      break;

	      /* virtio */
	    case VNET_DPDK_PMD_VIRTIO:
	      xd->port_type = VNET_DPDK_PORT_TYPE_ETH_1G;
	      xd->nb_rx_desc = DPDK_NB_RX_DESC_VIRTIO;
	      xd->nb_tx_desc = DPDK_NB_TX_DESC_VIRTIO;
	      break;

	      /* vmxnet3 */
	    case VNET_DPDK_PMD_VMXNET3:
	      xd->port_type = VNET_DPDK_PORT_TYPE_ETH_1G;
	      xd->tx_conf.txq_flags |= ETH_TXQ_FLAGS_NOMULTSEGS;
	      break;

	    case VNET_DPDK_PMD_AF_PACKET:
	      xd->port_type = VNET_DPDK_PORT_TYPE_AF_PACKET;
	      xd->port_id = af_packet_port_id++;
	      break;

	    case VNET_DPDK_PMD_BOND:
	      xd->flags |= DPDK_DEVICE_FLAG_PMD_SUPPORTS_PTYPE;
	      xd->port_type = VNET_DPDK_PORT_TYPE_ETH_BOND;
	      xd->port_id = bond_ether_port_id++;
	      break;

	    default:
	      xd->port_type = VNET_DPDK_PORT_TYPE_UNKNOWN;
	    }

	  if (devconf->num_rx_desc)
	    xd->nb_rx_desc = devconf->num_rx_desc;

	  if (devconf->num_tx_desc)
	    xd->nb_tx_desc = devconf->num_tx_desc;
	}

      /*
       * Ensure default mtu is not > the mtu read from the hardware.
       * Otherwise rte_eth_dev_configure() will fail and the port will
       * not be available.
       */
      if (ETHERNET_MAX_PACKET_BYTES > dev_info.max_rx_pktlen)
	{
	  /*
	   * This device does not support the platforms's max frame
	   * size. Use it's advertised mru instead.
	   */
	  xd->port_conf.rxmode.max_rx_pkt_len = dev_info.max_rx_pktlen;
	}
      else
	{
	  xd->port_conf.rxmode.max_rx_pkt_len = ETHERNET_MAX_PACKET_BYTES;

	  /*
	   * Some platforms do not account for Ethernet FCS (4 bytes) in
	   * MTU calculations. To interop with them increase mru but only
	   * if the device's settings can support it.
	   */
	  if ((dev_info.max_rx_pktlen >= (ETHERNET_MAX_PACKET_BYTES + 4)) &&
	      xd->port_conf.rxmode.hw_strip_crc)
	    {
	      /*
	       * Allow additional 4 bytes (for Ethernet FCS). These bytes are
	       * stripped by h/w and so will not consume any buffer memory.
	       */
	      xd->port_conf.rxmode.max_rx_pkt_len += 4;
	    }
	}

      if (xd->pmd == VNET_DPDK_PMD_AF_PACKET)
	{
	  f64 now = vlib_time_now (vm);
	  u32 rnd;
	  rnd = (u32) (now * 1e6);
	  rnd = random_u32 (&rnd);
	  clib_memcpy (addr + 2, &rnd, sizeof (rnd));
	  addr[0] = 2;
	  addr[1] = 0xfe;
	}
      else
	rte_eth_macaddr_get (i, (struct ether_addr *) addr);

      if (xd->tx_q_used < tm->n_vlib_mains)
	dpdk_device_lock_init (xd);

      xd->device_index = xd - dm->devices;
      ASSERT (i == xd->device_index);
      xd->per_interface_next_index = ~0;

      /* assign interface to input thread */
      dpdk_device_and_queue_t *dq;
      int q;

      if (devconf->hqos_enabled)
	{
	  xd->flags |= DPDK_DEVICE_FLAG_HQOS;

	  if (devconf->hqos.hqos_thread_valid)
	    {
	      int cpu = dm->hqos_cpu_first_index + devconf->hqos.hqos_thread;

	      if (devconf->hqos.hqos_thread >= dm->hqos_cpu_count)
		return clib_error_return (0, "invalid HQoS thread index");

	      vec_add2 (dm->devices_by_hqos_cpu[cpu], dq, 1);
	      dq->device = xd->device_index;
	      dq->queue_id = 0;
	    }
	  else
	    {
	      int cpu = dm->hqos_cpu_first_index + next_hqos_cpu;

	      if (dm->hqos_cpu_count == 0)
		return clib_error_return (0, "no HQoS threads available");

	      vec_add2 (dm->devices_by_hqos_cpu[cpu], dq, 1);
	      dq->device = xd->device_index;
	      dq->queue_id = 0;

	      next_hqos_cpu++;
	      if (next_hqos_cpu == dm->hqos_cpu_count)
		next_hqos_cpu = 0;

	      devconf->hqos.hqos_thread_valid = 1;
	      devconf->hqos.hqos_thread = cpu;
	    }
	}

      vec_validate_aligned (xd->tx_vectors, tm->n_vlib_mains,
			    CLIB_CACHE_LINE_BYTES);
      for (j = 0; j < tm->n_vlib_mains; j++)
	{
	  vec_validate_ha (xd->tx_vectors[j], xd->nb_tx_desc,
			   sizeof (tx_ring_hdr_t), CLIB_CACHE_LINE_BYTES);
	  vec_reset_length (xd->tx_vectors[j]);
	}

      vec_validate_aligned (xd->rx_vectors, xd->rx_q_used,
			    CLIB_CACHE_LINE_BYTES);
      for (j = 0; j < xd->rx_q_used; j++)
	{
	  vec_validate_aligned (xd->rx_vectors[j], VLIB_FRAME_SIZE - 1,
				CLIB_CACHE_LINE_BYTES);
	  vec_reset_length (xd->rx_vectors[j]);
	}

      vec_validate_aligned (xd->d_trace_buffers, tm->n_vlib_mains,
			    CLIB_CACHE_LINE_BYTES);


      /* count the number of descriptors used for this device */
      nb_desc += xd->nb_rx_desc + xd->nb_tx_desc * xd->tx_q_used;

      error = ethernet_register_interface
	(dm->vnet_main, dpdk_device_class.index, xd->device_index,
	 /* ethernet address */ addr,
	 &xd->hw_if_index, dpdk_flag_change);
      if (error)
	return error;

      sw = vnet_get_hw_sw_interface (dm->vnet_main, xd->hw_if_index);
      xd->vlib_sw_if_index = sw->sw_if_index;
      vnet_set_device_input_node (dm->vnet_main, xd->hw_if_index,
				  dpdk_input_node.index);

      if (devconf->workers)
	{
	  int i;
	  q = 0;
	  /* *INDENT-OFF* */
	  clib_bitmap_foreach (i, devconf->workers, ({
	    vnet_device_input_assign_thread (dm->vnet_main, xd->hw_if_index, q++,
					     vdm->first_worker_thread_index + i);
	  }));
	  /* *INDENT-ON* */
	}
      else
	for (q = 0; q < xd->rx_q_used; q++)
	  {
	    vnet_device_input_assign_thread (dm->vnet_main, xd->hw_if_index, q,	/* any */
					     ~1);
	  }

      hi = vnet_get_hw_interface (dm->vnet_main, xd->hw_if_index);

      rv = dpdk_port_setup (dm, xd);

      if (rv)
	return rv;

      if (devconf->hqos_enabled)
	{
	  rv = dpdk_port_setup_hqos (xd, &devconf->hqos);
	  if (rv)
	    return rv;
	}

      /*
       * For cisco VIC vNIC, set default to VLAN strip enabled, unless
       * specified otherwise in the startup config.
       * For other NICs default to VLAN strip disabled, unless specified
       * otherwis in the startup config.
       */
      if (xd->pmd == VNET_DPDK_PMD_ENIC)
	{
	  if (devconf->vlan_strip_offload != DPDK_DEVICE_VLAN_STRIP_OFF)
	    vlan_strip = 1;	/* remove vlan tag from VIC port by default */
	  else
	    clib_warning ("VLAN strip disabled for interface\n");
	}
      else if (devconf->vlan_strip_offload == DPDK_DEVICE_VLAN_STRIP_ON)
	vlan_strip = 1;

      if (vlan_strip)
	{
	  int vlan_off;
	  vlan_off = rte_eth_dev_get_vlan_offload (xd->device_index);
	  vlan_off |= ETH_VLAN_STRIP_OFFLOAD;
	  xd->port_conf.rxmode.hw_vlan_strip = vlan_off;
	  if (rte_eth_dev_set_vlan_offload (xd->device_index, vlan_off) == 0)
	    clib_warning ("VLAN strip enabled for interface\n");
	  else
	    clib_warning ("VLAN strip cannot be supported by interface\n");
	}

      hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] =
	xd->port_conf.rxmode.max_rx_pkt_len - sizeof (ethernet_header_t);

      rte_eth_dev_set_mtu (xd->device_index, hi->max_packet_bytes);
    }

  if (nb_desc > dm->conf->num_mbufs)
    clib_warning ("%d mbufs allocated but total rx/tx ring size is %d\n",
		  dm->conf->num_mbufs, nb_desc);

  return 0;
}

static void
dpdk_bind_devices_to_uio (dpdk_config_main_t * conf)
{
  vlib_pci_main_t *pm = &pci_main;
  clib_error_t *error;
  vlib_pci_device_t *d;
  u8 *pci_addr = 0;
  int num_whitelisted = vec_len (conf->dev_confs);

  /* *INDENT-OFF* */
  pool_foreach (d, pm->pci_devs, ({
    dpdk_device_config_t * devconf = 0;
    vec_reset_length (pci_addr);
    pci_addr = format (pci_addr, "%U%c", format_vlib_pci_addr, &d->bus_address, 0);

    if (d->device_class != PCI_CLASS_NETWORK_ETHERNET && d->device_class != PCI_CLASS_PROCESSOR_CO)
      continue;

    if (num_whitelisted)
      {
	uword * p = hash_get (conf->device_config_index_by_pci_addr, d->bus_address.as_u32);

	if (!p)
	  continue;

	devconf = pool_elt_at_index (conf->dev_confs, p[0]);
      }

    /* virtio */
    if (d->vendor_id == 0x1af4 && d->device_id == 0x1000)
      ;
    /* vmxnet3 */
    else if (d->vendor_id == 0x15ad && d->device_id == 0x07b0)
      ;
    /* all Intel network devices */
    else if (d->vendor_id == 0x8086 && d->device_class == PCI_CLASS_NETWORK_ETHERNET)
      ;
    /* all Intel QAT devices VFs */
    else if (d->vendor_id == 0x8086 && d->device_class == PCI_CLASS_PROCESSOR_CO &&
        (d->device_id == 0x0443 || d->device_id == 0x37c9 || d->device_id == 0x19e3))
      ;
    /* Cisco VIC */
    else if (d->vendor_id == 0x1137 && d->device_id == 0x0043)
      ;
    /* Chelsio T4/T5 */
    else if (d->vendor_id == 0x1425 && (d->device_id & 0xe000) == 0x4000)
      ;
    else
      {
        clib_warning ("Unsupported PCI device 0x%04x:0x%04x found "
		      "at PCI address %s\n", (u16) d->vendor_id, (u16) d->device_id,
		      pci_addr);
        continue;
      }

    error = vlib_pci_bind_to_uio (d, (char *) conf->uio_driver_name);

    if (error)
      {
	if (devconf == 0)
	  {
	    pool_get (conf->dev_confs, devconf);
	    hash_set (conf->device_config_index_by_pci_addr, d->bus_address.as_u32,
		      devconf - conf->dev_confs);
	    devconf->pci_addr.as_u32 = d->bus_address.as_u32;
	  }
	devconf->is_blacklisted = 1;
	clib_error_report (error);
      }
  }));
  /* *INDENT-ON* */
  vec_free (pci_addr);
}

static clib_error_t *
dpdk_device_config (dpdk_config_main_t * conf, vlib_pci_addr_t pci_addr,
		    unformat_input_t * input, u8 is_default)
{
  clib_error_t *error = 0;
  uword *p;
  dpdk_device_config_t *devconf;
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
  devconf->hqos_enabled = 0;
  dpdk_device_config_hqos_default (&devconf->hqos);

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
	devconf->vlan_strip_offload = DPDK_DEVICE_VLAN_STRIP_OFF;
      else if (unformat (input, "vlan-strip-offload on"))
	devconf->vlan_strip_offload = DPDK_DEVICE_VLAN_STRIP_ON;
      else
	if (unformat
	    (input, "hqos %U", unformat_vlib_cli_sub_input, &sub_input))
	{
	  devconf->hqos_enabled = 1;
	  error = unformat_hqos (&sub_input, &devconf->hqos);
	  if (error)
	    break;
	}
      else if (unformat (input, "hqos"))
	{
	  devconf->hqos_enabled = 1;
	}
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
			 "%U: number of worker threadds must be "
			 "equal to number of rx queues", format_vlib_pci_addr,
			 &pci_addr);

  return error;
}

static clib_error_t *
dpdk_config (vlib_main_t * vm, unformat_input_t * input)
{
  clib_error_t *error = 0;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_config_main_t *conf = &dpdk_config_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_device_config_t *devconf;
  vlib_pci_addr_t pci_addr;
  unformat_input_t sub_input;
  u8 *s, *tmp = 0;
  u8 *rte_cmd = 0, *ethname = 0;
  u32 log_level;
  int ret, i;
  int num_whitelisted = 0;
  u8 no_pci = 0;
  u8 no_huge = 0;
  u8 huge_dir = 0;
  u8 file_prefix = 0;
  u8 *socket_mem = 0;

  conf->device_config_index_by_pci_addr = hash_create (0, sizeof (uword));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* Prime the pump */
      if (unformat (input, "no-hugetlb"))
	{
	  vec_add1 (conf->eal_init_args, (u8 *) "no-huge");
	  no_huge = 1;
	}

      else if (unformat (input, "enable-tcp-udp-checksum"))
	conf->enable_tcp_udp_checksum = 1;

      else if (unformat (input, "decimal-interface-names"))
	conf->interface_name_format_decimal = 1;

      else if (unformat (input, "no-multi-seg"))
	conf->no_multi_seg = 1;

      else if (unformat (input, "enable-cryptodev"))
	conf->cryptodev = 1;

      else if (unformat (input, "dev default %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  error =
	    dpdk_device_config (conf, (vlib_pci_addr_t) (u32) ~ 1, &sub_input,
				1);

	  if (error)
	    return error;
	}
      else
	if (unformat
	    (input, "dev %U %U", unformat_vlib_pci_addr, &pci_addr,
	     unformat_vlib_cli_sub_input, &sub_input))
	{
	  error = dpdk_device_config (conf, pci_addr, &sub_input, 0);

	  if (error)
	    return error;

	  num_whitelisted++;
	}
      else if (unformat (input, "dev %U", unformat_vlib_pci_addr, &pci_addr))
	{
	  error = dpdk_device_config (conf, pci_addr, 0, 0);

	  if (error)
	    return error;

	  num_whitelisted++;
	}
      else if (unformat (input, "num-mbufs %d", &conf->num_mbufs))
	;
      else if (unformat (input, "kni %d", &conf->num_kni))
	;
      else if (unformat (input, "uio-driver %s", &conf->uio_driver_name))
	;
      else if (unformat (input, "socket-mem %s", &socket_mem))
	;
      else if (unformat (input, "no-pci"))
	{
	  no_pci = 1;
	  tmp = format (0, "--no-pci%c", 0);
	  vec_add1 (conf->eal_init_args, tmp);
	}
      else if (unformat (input, "poll-sleep %d", &dm->poll_sleep_usec))
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
            if (!strncmp(#a, "huge-dir", 8))          \
              huge_dir = 1;                           \
            else if (!strncmp(#a, "file-prefix", 11)) \
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

  if (!conf->uio_driver_name)
    conf->uio_driver_name = format (0, "uio_pci_generic%c", 0);

  /*
   * Use 1G huge pages if available.
   */
  if (!no_huge && !huge_dir)
    {
      u32 x, *mem_by_socket = 0;
      uword c = 0;
      u8 use_1g = 1;
      u8 use_2m = 1;
      u8 less_than_1g = 1;
      int rv;

      umount (DEFAULT_HUGE_DIR);

      /* Process "socket-mem" parameter value */
      if (vec_len (socket_mem))
	{
	  unformat_input_t in;
	  unformat_init_vector (&in, socket_mem);
	  while (unformat_check_input (&in) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (&in, "%u,", &x))
		;
	      else if (unformat (&in, "%u", &x))
		;
	      else if (unformat (&in, ","))
		x = 0;
	      else
		break;

	      vec_add1 (mem_by_socket, x);

	      if (x > 1023)
		less_than_1g = 0;
	    }
	  /* Note: unformat_free vec_frees(in.buffer), aka socket_mem... */
	  unformat_free (&in);
	  socket_mem = 0;
	}
      else
	{
	  /* *INDENT-OFF* */
	  clib_bitmap_foreach (c, tm->cpu_socket_bitmap, (
	    {
	      vec_validate(mem_by_socket, c);
	      mem_by_socket[c] = 256; /* default per-socket mem */
	    }
	  ));
	  /* *INDENT-ON* */
	}

      /* check if available enough 1GB pages for each socket */
      /* *INDENT-OFF* */
      clib_bitmap_foreach (c, tm->cpu_socket_bitmap, (
        {
	  int pages_avail, page_size, mem;

	  vec_validate(mem_by_socket, c);
	  mem = mem_by_socket[c];

	  page_size = 1024;
	  pages_avail = vlib_sysfs_get_free_hugepages(c, page_size * 1024);

	  if (pages_avail < 0 || page_size * pages_avail < mem)
	    use_1g = 0;

	  page_size = 2;
	  pages_avail = vlib_sysfs_get_free_hugepages(c, page_size * 1024);

	  if (pages_avail < 0 || page_size * pages_avail < mem)
	    use_2m = 0;
      }));
      /* *INDENT-ON* */

      if (mem_by_socket == 0)
	{
	  error = clib_error_return (0, "mem_by_socket NULL");
	  goto done;
	}
      _vec_len (mem_by_socket) = c + 1;

      /* regenerate socket_mem string */
      vec_foreach_index (x, mem_by_socket)
	socket_mem = format (socket_mem, "%s%u",
			     socket_mem ? "," : "", mem_by_socket[x]);
      socket_mem = format (socket_mem, "%c", 0);

      vec_free (mem_by_socket);

      rv = mkdir (VPP_RUN_DIR, 0755);
      if (rv && errno != EEXIST)
	{
	  error = clib_error_return (0, "mkdir '%s' failed errno %d",
				     VPP_RUN_DIR, errno);
	  goto done;
	}

      rv = mkdir (DEFAULT_HUGE_DIR, 0755);
      if (rv && errno != EEXIST)
	{
	  error = clib_error_return (0, "mkdir '%s' failed errno %d",
				     DEFAULT_HUGE_DIR, errno);
	  goto done;
	}

      if (use_1g && !(less_than_1g && use_2m))
	{
	  rv =
	    mount ("none", DEFAULT_HUGE_DIR, "hugetlbfs", 0, "pagesize=1G");
	}
      else if (use_2m)
	{
	  rv = mount ("none", DEFAULT_HUGE_DIR, "hugetlbfs", 0, NULL);
	}
      else
	{
	  return clib_error_return (0, "not enough free huge pages");
	}

      if (rv)
	{
	  error = clib_error_return (0, "mount failed %d", errno);
	  goto done;
	}

      tmp = format (0, "--huge-dir%c", 0);
      vec_add1 (conf->eal_init_args, tmp);
      tmp = format (0, "%s%c", DEFAULT_HUGE_DIR, 0);
      vec_add1 (conf->eal_init_args, tmp);
      if (!file_prefix)
	{
	  tmp = format (0, "--file-prefix%c", 0);
	  vec_add1 (conf->eal_init_args, tmp);
	  tmp = format (0, "vpp%c", 0);
	  vec_add1 (conf->eal_init_args, tmp);
	}
    }

  vec_free (rte_cmd);
  vec_free (ethname);

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

  if (no_pci == 0 && geteuid () == 0)
    dpdk_bind_devices_to_uio (conf);

#define _(x) \
    if (devconf->x == 0 && conf->default_devconf.x > 0) \
      devconf->x = conf->default_devconf.x ;

  /* *INDENT-OFF* */
  pool_foreach (devconf, conf->dev_confs, ({

    /* default per-device config items */
    foreach_dpdk_device_config_item

    /* add DPDK EAL whitelist/blacklist entry */
    if (num_whitelisted > 0 && devconf->is_blacklisted == 0)
      {
	tmp = format (0, "-w%c", 0);
	vec_add1 (conf->eal_init_args, tmp);
	tmp = format (0, "%U%c", format_vlib_pci_addr, &devconf->pci_addr, 0);
	vec_add1 (conf->eal_init_args, tmp);
      }
    else if (num_whitelisted == 0 && devconf->is_blacklisted != 0)
      {
	tmp = format (0, "-b%c", 0);
	vec_add1 (conf->eal_init_args, tmp);
	tmp = format (0, "%U%c", format_vlib_pci_addr, &devconf->pci_addr, 0);
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

  /* set socket-mem */
  tmp = format (0, "--socket-mem%c", 0);
  vec_add1 (conf->eal_init_args, tmp);
  tmp = format (0, "%s%c", socket_mem, 0);
  vec_add1 (conf->eal_init_args, tmp);

  /* NULL terminate the "argv" vector, in case of stupidity */
  vec_add1 (conf->eal_init_args, 0);
  _vec_len (conf->eal_init_args) -= 1;

  /* Set up DPDK eal and packet mbuf pool early. */

  log_level = (CLIB_DEBUG > 0) ? RTE_LOG_DEBUG : RTE_LOG_NOTICE;

  rte_set_log_level (log_level);

  vm = vlib_get_main ();

  /* make copy of args as rte_eal_init tends to mess up with arg array */
  for (i = 1; i < vec_len (conf->eal_init_args); i++)
    conf->eal_init_args_str = format (conf->eal_init_args_str, "%s ",
				      conf->eal_init_args[i]);

  ret =
    rte_eal_init (vec_len (conf->eal_init_args),
		  (char **) conf->eal_init_args);

  /* lazy umount hugepages */
  umount2 (DEFAULT_HUGE_DIR, MNT_DETACH);

  if (ret < 0)
    return clib_error_return (0, "rte_eal_init returned %d", ret);

  /* Dump the physical memory layout prior to creating the mbuf_pool */
  fprintf (stdout, "DPDK physical memory layout:\n");
  rte_dump_physmem_layout (stdout);

  /* main thread 1st */
  error = vlib_buffer_pool_create (vm, conf->num_mbufs, rte_socket_id ());
  if (error)
    return error;

  for (i = 0; i < RTE_MAX_LCORE; i++)
    {
      error = vlib_buffer_pool_create (vm, conf->num_mbufs,
				       rte_lcore_to_socket_id (i));
      if (error)
	return error;
    }

done:
  return error;
}

VLIB_CONFIG_FUNCTION (dpdk_config, "dpdk");

void
dpdk_update_link_state (dpdk_device_t * xd, f64 now)
{
  vnet_main_t *vnm = vnet_get_main ();
  struct rte_eth_link prev_link = xd->link;
  u32 hw_flags = 0;
  u8 hw_flags_chg = 0;

  /* only update link state for PMD interfaces */
  if ((xd->flags & DPDK_DEVICE_FLAG_PMD) == 0)
    return;

  xd->time_last_link_update = now ? now : xd->time_last_link_update;
  memset (&xd->link, 0, sizeof (xd->link));
  rte_eth_link_get_nowait (xd->device_index, &xd->link);

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
      ed->sw_if_index = xd->vlib_sw_if_index;
      ed->admin_up = (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP) != 0;
      ed->old_link_state = (u8)
	vnet_hw_interface_is_link_up (vnm, xd->hw_if_index);
      ed->new_link_state = (u8) xd->link.link_status;
    }

  if ((xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP) &&
      ((xd->link.link_status != 0) ^
       vnet_hw_interface_is_link_up (vnm, xd->hw_if_index)))
    {
      hw_flags_chg = 1;
      hw_flags |= (xd->link.link_status ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
    }

  if (hw_flags_chg || (xd->link.link_duplex != prev_link.link_duplex))
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
  if (hw_flags_chg || (xd->link.link_speed != prev_link.link_speed))
    {
      hw_flags_chg = 1;
      switch (xd->link.link_speed)
	{
	case ETH_SPEED_NUM_10M:
	  hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_10M;
	  break;
	case ETH_SPEED_NUM_100M:
	  hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_100M;
	  break;
	case ETH_SPEED_NUM_1G:
	  hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_1G;
	  break;
	case ETH_SPEED_NUM_10G:
	  hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_10G;
	  break;
	case ETH_SPEED_NUM_40G:
	  hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_40G;
	  break;
	case 0:
	  break;
	default:
	  clib_warning ("unknown link speed %d", xd->link.link_speed);
	  break;
	}
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
	  ed->sw_if_index = xd->vlib_sw_if_index;
	  ed->flags = hw_flags;
	}
      vnet_hw_interface_set_flags (vnm, xd->hw_if_index, hw_flags);
    }
}

static uword
dpdk_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  clib_error_t *error;
  vnet_main_t *vnm = vnet_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  ethernet_main_t *em = &ethernet_main;
  dpdk_device_t *xd;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;

  error = dpdk_lib_init (dm);

  if (error)
    clib_error_report (error);

  tm->worker_thread_release = 1;

  f64 now = vlib_time_now (vm);
  vec_foreach (xd, dm->devices)
  {
    dpdk_update_link_state (xd, now);
  }

  {
    /*
     * Extra set up for bond interfaces:
     *  1. Setup MACs for bond interfaces and their slave links which was set
     *     in dpdk_port_setup() but needs to be done again here to take effect.
     *  2. Set up info for bond interface related CLI support.
     */
    int nports = rte_eth_dev_count ();
    if (nports > 0)
      {
	for (i = 0; i < nports; i++)
	  {
	    xd = &dm->devices[i];
	    ASSERT (i == xd->device_index);
	    if (xd->pmd == VNET_DPDK_PMD_BOND)
	      {
		u8 addr[6];
		u8 slink[16];
		int nlink = rte_eth_bond_slaves_get (i, slink, 16);
		if (nlink > 0)
		  {
		    vnet_hw_interface_t *bhi;
		    ethernet_interface_t *bei;
		    int rv;

		    /* Get MAC of 1st slave link */
		    rte_eth_macaddr_get
		      (slink[0], (struct ether_addr *) addr);

		    /* Set MAC of bounded interface to that of 1st slave link */
		    clib_warning ("Set MAC for bond dev# %d", i);
		    rv = rte_eth_bond_mac_address_set
		      (i, (struct ether_addr *) addr);
		    if (rv)
		      clib_warning ("Set MAC addr failure rv=%d", rv);

		    /* Populate MAC of bonded interface in VPP hw tables */
		    bhi = vnet_get_hw_interface
		      (vnm, dm->devices[i].hw_if_index);
		    bei = pool_elt_at_index
		      (em->interfaces, bhi->hw_instance);
		    clib_memcpy (bhi->hw_address, addr, 6);
		    clib_memcpy (bei->address, addr, 6);

		    /* Init l3 packet size allowed on bonded interface */
		    bhi->max_packet_bytes = ETHERNET_MAX_PACKET_BYTES;
		    bhi->max_l3_packet_bytes[VLIB_RX] =
		      bhi->max_l3_packet_bytes[VLIB_TX] =
		      ETHERNET_MAX_PACKET_BYTES - sizeof (ethernet_header_t);
		    while (nlink >= 1)
		      {		/* for all slave links */
			int slave = slink[--nlink];
			dpdk_device_t *sdev = &dm->devices[slave];
			vnet_hw_interface_t *shi;
			vnet_sw_interface_t *ssi;
			ethernet_interface_t *sei;
			/* Add MAC to all slave links except the first one */
			if (nlink)
			  {
			    clib_warning ("Add MAC for slave dev# %d", slave);
			    rv = rte_eth_dev_mac_addr_add
			      (slave, (struct ether_addr *) addr, 0);
			    if (rv)
			      clib_warning ("Add MAC addr failure rv=%d", rv);
			  }
			/* Set slaves bitmap for bonded interface */
			bhi->bond_info = clib_bitmap_set
			  (bhi->bond_info, sdev->hw_if_index, 1);
			/* Set slave link flags on slave interface */
			shi = vnet_get_hw_interface (vnm, sdev->hw_if_index);
			ssi = vnet_get_sw_interface
			  (vnm, sdev->vlib_sw_if_index);
			sei = pool_elt_at_index
			  (em->interfaces, shi->hw_instance);

			shi->bond_info = VNET_HW_INTERFACE_BOND_INFO_SLAVE;
			ssi->flags |= VNET_SW_INTERFACE_FLAG_BOND_SLAVE;
			clib_memcpy (shi->hw_address, addr, 6);
			clib_memcpy (sei->address, addr, 6);

			/* Set l3 packet size allowed as the lowest of slave */
			if (bhi->max_l3_packet_bytes[VLIB_RX] >
			    shi->max_l3_packet_bytes[VLIB_RX])
			  bhi->max_l3_packet_bytes[VLIB_RX] =
			    bhi->max_l3_packet_bytes[VLIB_TX] =
			    shi->max_l3_packet_bytes[VLIB_RX];

			/* Set max packet size allowed as the lowest of slave */
			if (bhi->max_packet_bytes > shi->max_packet_bytes)
			  bhi->max_packet_bytes = shi->max_packet_bytes;
		      }
		  }
	      }
	  }
      }
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
	  dpdk_update_counters (xd, now);
	if ((now - xd->time_last_link_update) >= dm->link_state_poll_interval)
	  dpdk_update_link_state (xd, now);

      }
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_process_node,static) = {
    .function = dpdk_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "dpdk-process",
    .process_log2_n_stack_bytes = 17,
};
/* *INDENT-ON* */

int
dpdk_set_stat_poll_interval (f64 interval)
{
  if (interval < DPDK_MIN_STATS_POLL_INTERVAL)
    return (VNET_API_ERROR_INVALID_VALUE);

  dpdk_main.stat_poll_interval = interval;

  return 0;
}

int
dpdk_set_link_state_poll_interval (f64 interval)
{
  if (interval < DPDK_MIN_LINK_POLL_INTERVAL)
    return (VNET_API_ERROR_INVALID_VALUE);

  dpdk_main.link_state_poll_interval = interval;

  return 0;
}

clib_error_t *
dpdk_init (vlib_main_t * vm)
{
  dpdk_main_t *dm = &dpdk_main;
  vlib_node_t *ei;
  clib_error_t *error = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  /* verify that structs are cacheline aligned */
  STATIC_ASSERT (offsetof (dpdk_device_t, cacheline0) == 0,
		 "Cache line marker must be 1st element in dpdk_device_t");
  STATIC_ASSERT (offsetof (dpdk_device_t, cacheline1) ==
		 CLIB_CACHE_LINE_BYTES,
		 "Data in cache line 0 is bigger than cache line size");
  STATIC_ASSERT (offsetof (frame_queue_trace_t, cacheline0) == 0,
		 "Cache line marker must be 1st element in frame_queue_trace_t");

  u8 *name;
  name = format (0, "dpdk_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  dm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);
  vec_free (name);

  dm->vlib_main = vm;
  dm->vnet_main = vnet_get_main ();
  dm->conf = &dpdk_config_main;

  error = dpdk_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (dm, &api_main);

//  TODO
//  plugin_custom_dump_configure (dm);

  ei = vlib_get_node_by_name (vm, (u8 *) "ethernet-input");
  if (ei == 0)
    return clib_error_return (0, "ethernet-input node AWOL");

  dm->ethernet_input_node_index = ei->index;

  dm->conf->nchannels = 4;
  dm->conf->num_mbufs = dm->conf->num_mbufs ? dm->conf->num_mbufs : NB_MBUF;
  vec_add1 (dm->conf->eal_init_args, (u8 *) "vnet");

  dm->dpdk_device_by_kni_port_id = hash_create (0, sizeof (uword));
  dm->vu_sw_if_index_by_listener_fd = hash_create (0, sizeof (uword));
  dm->vu_sw_if_index_by_sock_fd = hash_create (0, sizeof (uword));

  /* $$$ use n_thread_stacks since it's known-good at this point */
  vec_validate (dm->recycle, tm->n_thread_stacks - 1);

  /* Default vlib_buffer_t flags, DISABLES tcp/udp checksumming... */
  dm->buffer_flags_template =
    (VLIB_BUFFER_TOTAL_LENGTH_VALID | VLIB_BUFFER_EXT_HDR_VALID
     | IP_BUFFER_L4_CHECKSUM_COMPUTED | IP_BUFFER_L4_CHECKSUM_CORRECT);

  dm->stat_poll_interval = DPDK_STATS_POLL_INTERVAL;
  dm->link_state_poll_interval = DPDK_LINK_POLL_INTERVAL;

  /* init CLI */
  if ((error = vlib_call_init_function (vm, dpdk_cli_init)))
    return error;

  return error;
}

VLIB_INIT_FUNCTION (dpdk_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
