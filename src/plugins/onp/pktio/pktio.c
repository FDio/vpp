/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP pktio implementation.
 */

#include <onp/onp.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <onp/drv/modules/pktio/pktio_priv.h>

clib_error_t *
onp_pktio_link_state_update (onp_pktio_t *od)
{
  cnxk_pktio_link_info_t link_info = { 0 };
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u32 flags = 0;
  int rv = 0;

  rv = cnxk_drv_pktio_link_info_get (vm, od->cnxk_pktio_index, &link_info);
  if (rv)
    {
      onp_pktio_err ("Failed to get link state information of %U device",
		     format_vlib_pci_addr, &od->pktio_pci_addr);
      vnet_hw_interface_set_flags (vnm, od->hw_if_index, 0);
      return 0;
    }

  if (link_info.is_full_duplex)
    flags |= VNET_HW_INTERFACE_FLAG_FULL_DUPLEX;
  else
    flags |= VNET_HW_INTERFACE_FLAG_HALF_DUPLEX;

  if (link_info.is_up)
    flags |= VNET_HW_INTERFACE_FLAG_LINK_UP;

  vnet_hw_interface_set_link_speed (vnm, od->hw_if_index,
				    /* Convert to Kbps */
				    link_info.speed * 1000);

  vnet_hw_interface_set_flags (vnm, od->hw_if_index, flags);

  return 0;
}

static clib_error_t *
onp_pktio_set_max_frame_size (vnet_main_t *vnm, vnet_hw_interface_t *hi,
			      u32 frame_size)
{
  onp_pktio_t *od = onp_get_pktio (hi->dev_instance);
  vlib_main_t *vm = vlib_get_main ();
  int rv;

  rv = cnxk_drv_pktio_mtu_set (vm, od->cnxk_pktio_index, frame_size);
  if (rv)
    return vnet_error (VNET_ERR_BUG, "Failed to set MTU ");

  return 0;
}

u32
onp_pktio_flag_change (vnet_main_t *vnm, vnet_hw_interface_t *hw, u32 flags)
{
  onp_pktio_t *od = onp_get_pktio (hw->dev_instance);
  vlib_main_t *vm = vlib_get_main ();
  int rv;

  switch (flags)
    {
    case ETHERNET_INTERFACE_FLAG_DEFAULT_L3:
      od->pktio_flags &= ~ONP_DEVICE_F_PROMISC;
      break;

    case ETHERNET_INTERFACE_FLAG_ACCEPT_ALL:
      od->pktio_flags |= ONP_DEVICE_F_PROMISC;
      break;

    default:
      return ~0;
    }

  if (od->pktio_flags & ONP_DEVICE_F_ADMIN_UP)
    {
      if (od->pktio_flags & ONP_DEVICE_F_PROMISC)
	rv = cnxk_drv_pktio_promisc_enable (vm, od->cnxk_pktio_index);
      else
	rv = cnxk_drv_pktio_promisc_disable (vm, od->cnxk_pktio_index);

      if (rv)
	onp_pktio_warn ("promisc mode enable/disable not supported");
    }
  return 0;
}

static void
onp_pktio_set_default_config (onp_config_main_t *conf,
			      onp_pktio_config_t *pktioconf,
			      vlib_pci_addr_t pci_addr, u32 is_default)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  onp_pktio_config_t tmp;
  u8 num_worker_cores;

  num_worker_cores =
    vdm->last_worker_thread_index - vdm->first_worker_thread_index + 1;

  /* Set default values to temporary variable */
#define _(name, var, val, min, max, p) tmp.var = val;
  foreach_onp_pktio_config_item;
#undef _
  /*
   * NRXQ and NTXQ default values depends on runtime factors
   * - 1 RQ for each pktio on each worker core
   * - 1 TXQ for each thread
   */
  tmp.n_rx_q = num_worker_cores;
  tmp.n_tx_q = num_worker_cores + 1;

  /* If parameters is less than min_val. override with default values */
#define _(name, var, val, min, max, p)                                        \
  if (pktioconf->is_##var##_configured)                                       \
    {                                                                         \
      if (pktioconf->var < min)                                               \
	{                                                                     \
	  cnxk_pktio_err ("%u value for \"" #name                             \
			  "\" is lesser than %u. Overriding to %ld",          \
			  pktioconf->var, min, tmp.var);                      \
	  pktioconf->is_##var##_configured = 0;                               \
	}                                                                     \
    }
  foreach_onp_pktio_config_item;
#undef _

  /* If parameters is greater than max_val. override with default values */
#define _(name, var, val, min, max, p)                                        \
  if (pktioconf->is_##var##_configured)                                       \
    {                                                                         \
      if (pktioconf->var > max)                                               \
	{                                                                     \
	  pktioconf->is_##var##_configured = 0;                               \
	  cnxk_pktio_err ("%u value for \"" #name                             \
			  "\" is greater than %u. Overriding to %ld",         \
			  pktioconf->var, max, tmp.var);                      \
	}                                                                     \
    }
  foreach_onp_pktio_config_item;
#undef _

  /* Set default values for those which are not passed */
  if (is_default)
    {
      /* clang-format off */
#define _(name, var, val, min, max, p)                                        \
      if (!pktioconf->is_##var##_configured)                                  \
        {                                                                     \
          pktioconf->var = clib_max (tmp.var, min);                           \
          pktioconf->var = clib_min (pktioconf->var, max);                    \
          pktioconf->is_##var##_configured = 1;                               \
        }
      foreach_onp_pktio_config_item;
#undef _
      /* clang-format on */
    }
  else
    {
      /* Set PCI address */
      if (!pktioconf->is_pci_addr_configured &&
	  (pci_addr.as_u32 != ONP_DEV_PCI_ADDR_ANY))
	{
	  pktioconf->pktio_pci_addr.as_u32 = pci_addr.as_u32;
	  pktioconf->is_pci_addr_configured = 1;
	}
	/* clang-format off */
#define _(name, var, val, min, max, p)                                        \
      if (!pktioconf->is_##var##_configured)                                  \
	{                                                                     \
	  if (conf->onp_pktioconf_default.is_##var##_configured)              \
	    pktioconf->var = conf->onp_pktioconf_default.var;                 \
	  else                                                                \
	    {                                                                 \
	      pktioconf->var = clib_max (tmp.var, min);                       \
	      pktioconf->var = clib_min (pktioconf->var, max);                \
	    }                                                                 \
	  pktioconf->is_##var##_configured = 1;                               \
	}
      foreach_onp_pktio_config_item;
#undef _
      /* clang-format on */
    }
}

clib_error_t *
onp_pktio_configs_validate (vlib_main_t *vm, onp_config_main_t *conf)
{
  onp_pktio_config_t *pktioconf;
  vlib_pci_addr_t pci_addr;

  pool_foreach (pktioconf, conf->onp_pktioconfs)
    {
      /* Set fields except pci_addr */
      pci_addr.as_u32 = ONP_DEV_PCI_ADDR_ANY;
      onp_pktio_set_default_config (conf, pktioconf, pci_addr, 0);
    }
  return NULL;
}

clib_error_t *
onp_pktio_config_parse (onp_config_main_t *conf, vlib_pci_addr_t pci_addr,
			unformat_input_t *sub_input, u32 is_default)
{
  onp_main_t *om = onp_get_main ();
  onp_pktio_config_t *pktioconf;
  uword *p;

  /* Check duplicate */
  if (pci_addr.as_u32 && pci_addr.as_u32 != (u32) ONP_DEV_PCI_ADDR_ANY)
    {
      p = hash_get (conf->onp_pktio_config_index_by_pci_addr, pci_addr.as_u32);
      if (p)
	return clib_error_return (0,
				  "Duplicate configuration for PCI address %U",
				  format_vlib_pci_addr, &pci_addr);

      pool_get_zero (conf->onp_pktioconfs, pktioconf);
      hash_set (conf->onp_pktio_config_index_by_pci_addr, pci_addr.as_u32,
		pktioconf - conf->onp_pktioconfs);
    }
  else
    {
      /* Empty PCI address allowed only with dev default {} */
      if (!is_default)
	{
	  return clib_error_return (0,
				    "Invalid PCI addr for default config %U",
				    format_vlib_pci_addr, &pci_addr);
	}
      else
	pktioconf = &conf->onp_pktioconf_default;
    }
  if (sub_input)
    {
      unformat_skip_white_space (sub_input);

      while (unformat_check_input (sub_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (sub_input, "name %s", &pktioconf->name))
	    {
	      if (!is_default)
		{
		  pktioconf->is_name_configured = 1;
		  if (vec_len (pktioconf->name) > ONP_INTF_NAME_MAX_SIZE)
		    return clib_error_return (
		      0, "Interface name '%s' is too long", pktioconf->name);
		}
	    }
	    /* clang-format off */
#define _(name, variable, default_val, min_val, max_val, p)                   \
          else if (unformat (sub_input, #name " %u", &pktioconf->variable))   \
            pktioconf->is_##variable##_configured = 1;
          foreach_onp_pktio_config_item
#undef _
	  else
	    return clib_error_return (0, "unknown pktio input '%U'",
				      format_unformat_error, sub_input);
	  /* clang-format on */
	}
    }

  onp_pktio_set_default_config (conf, pktioconf, pci_addr, is_default);

  if (!is_default)
    om->onp_pktio_count++;

  return 0;
}

clib_error_t *
onp_pktio_early_setup (vlib_main_t *vm, onp_main_t *om,
		       onp_pktio_config_t *pconf, onp_pktio_t **ppktio)
{
  vlib_pci_device_info_t *pci_dev_info;
  cnxk_pktio_capa_t pktio_capa = { 0 };
  vlib_pci_dev_handle_t pci_handle;
  cnxk_pktio_config_t eth_config;
  clib_error_t *error = NULL;
  i32 drv_pktio_index = -1;
  onp_pktio_t *pktio;
  int rv;

  ASSERT (pconf->pktio_pci_addr.as_u32 != ONP_DEV_PCI_ADDR_ANY);

#define _(name, var, val, min, max, p) ASSERT (pconf->var >= min);
  foreach_onp_pktio_config_item;
#undef _

  pci_dev_info = vlib_pci_get_device_info (vm, &pconf->pktio_pci_addr, &error);

  if (pci_dev_info == NULL || error)
    return clib_error_create ("Invalid PCI device information");

  drv_pktio_index =
    cnxk_drv_pktio_init (vm, &pconf->pktio_pci_addr, &pci_handle);
  if (drv_pktio_index < 0)
    return clib_error_create ("cnxk_drv_pktio_init failed");

  rv = cnxk_drv_pktio_capa_get (vm, drv_pktio_index, &pktio_capa);
  if (rv)
    return clib_error_create ("cnxk_drv_pktio_capa_get failed");

  pool_get_zero (om->onp_pktios, pktio);

  /* Allocate all queues at once */
  eth_config.n_rx_queues = pconf->n_rx_q;
  eth_config.n_tx_queues = pconf->n_tx_q;

  if (cnxk_drv_pktio_config (vm, drv_pktio_index, &eth_config))
    return clib_error_create ("cnxk_drv_pktio_config failed");

    /* clang-format off */
#define _(name, var, val, min, max, p)                         \
      pktio->var = pconf->var;

      foreach_onp_pktio_config_item;
#undef _
  /* clang-format on */
  pktio->pktio_pci_addr.as_u32 = pconf->pktio_pci_addr.as_u32;
  pktio->cnxk_pktio_index = drv_pktio_index;
  pktio->onp_pktio_index = pktio - om->onp_pktios;

  ASSERT (pktio->cnxk_pktio_index == pktio->onp_pktio_index);

  if (pconf->is_name_configured)
    clib_memcpy (pktio->name, pconf->name, vec_len (pconf->name));
  else
    {
      u8 *name = NULL;

      name = format (name, "eth%d%c", pktio->onp_pktio_index, 0);
      clib_memcpy (pktio->name, name, vec_len (name));

      vec_free (name);
    }

  pktio->numa_node = vlib_pci_get_numa_node (vm, pci_handle);
  if (ppktio)
    *ppktio = pktio;

  return NULL;
}

clib_error_t *
onp_pktio_setup (vlib_main_t *vm, onp_main_t *om, onp_pktio_config_t *pconf,
		 onp_pktio_t **ppktio)
{
  vnet_eth_interface_registration_t eir = {};
  cnxk_pktio_rxq_conf_t rx_conf = { 0 };
  cnxk_pktio_txq_conf_t tx_conf = { 0 };
  onp_pktio_rxq_t onp_pktio_rxq_config;
  onp_pktio_txq_t onp_pktio_txq_config;
  u8 mac_addr[6], need_multiseg_enable;
  cnxk_pktio_capa_t pktio_capa = { 0 };
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  i32 drv_pktio_index = -1;
  vnet_sw_interface_t *swi;
  vnet_hw_interface_t *hi;
  ethernet_main_t *em;
  onp_pktio_t *pktio;
  u32 buffer_size;
  int rv;

  ASSERT (pconf->pktio_pci_addr.as_u32 != ONP_DEV_PCI_ADDR_ANY);

#define _(name, var, val, min, max, p) ASSERT (pconf->var >= min);
  foreach_onp_pktio_config_item;
#undef _

  ASSERT (ppktio);
  pktio = *ppktio;

  rv = cnxk_drv_pktio_capa_get (vm, pktio->cnxk_pktio_index, &pktio_capa);
  if (rv)
    return clib_error_create ("cnxk_drv_pktio_capa_get failed");

  em = vnet_get_ethernet_main ();
  pktio->vlib_buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, pktio->numa_node);

  ASSERT (om->cnxk_pool_by_buffer_pool_index[pktio->vlib_buffer_pool_index] !=
	  (u8) ~0);
  pktio->cnxk_pool_index =
    om->cnxk_pool_by_buffer_pool_index[pktio->vlib_buffer_pool_index];

  /* TXQ setup */
  drv_pktio_index = pktio->cnxk_pktio_index;
  tx_conf.tx_desc = pktio->n_tx_desc;

  if (vlib_get_n_threads () > 1)
    /*
     * Allocate VLIB_FRAME_SIZE * 2 descriptors for per core.
     * So, a core can submit FRAME SIZE packets to hardware and
     * process next FRAME SIZE until hardware releases first one.
     */
    tx_conf.tx_desc = (vlib_get_n_threads () - 1) * VLIB_FRAME_SIZE * 2;

  /* Enable TX checksum */
  tx_conf.txq_offloads = CNXK_PKTIO_TX_OFF_FLAG_OUTER_CKSUM;
  buffer_size = vlib_buffer_get_default_data_size (vm);
  need_multiseg_enable = (buffer_size <= em->default_mtu);
  if (need_multiseg_enable)
    tx_conf.txq_offloads |= CNXK_PKTIO_TX_OFF_FLAG_MSEG;
  pktio->tx_offload_flags = tx_conf.txq_offloads;

  if (cnxk_drv_pktio_txq_setup (vm, drv_pktio_index, &tx_conf) < 0)
    return clib_error_create ("cnxk_drv_pktio_txq_setup failed");

  if (cnxk_drv_pktio_mac_addr_get (vm, drv_pktio_index, (char *) mac_addr) < 0)
    return clib_error_create ("cnxk_drv_pktio_mac_addr_get failed ");

  /* Create interface */
  eir.dev_class_index = onp_pktio_device_class.index;
  eir.dev_instance = pktio->onp_pktio_index;
  eir.address = mac_addr;
  eir.frame_overhead = pktio_capa.mtu.frame_overhead;
  eir.cb.flag_change = onp_pktio_flag_change;
  eir.cb.set_max_frame_size = onp_pktio_set_max_frame_size;

  pktio->hw_if_index = vnet_eth_register_interface (vnm, &eir);

  swi = vnet_get_hw_sw_interface (vnm, pktio->hw_if_index);
  pktio->sw_if_index = swi->sw_if_index;
  hi = vnet_get_hw_interface (vnm, pktio->hw_if_index);
  hi->caps |= VNET_HW_IF_CAP_MAC_FILTER | VNET_HW_IF_CAP_TX_CKSUM;

  /* Configure RXQ */
  rx_conf.pktio_sw_if_index = pktio->sw_if_index;
  rx_conf.rx_desc = pktio->n_rx_desc;
  rx_conf.vlib_buffer_pool_index = pktio->vlib_buffer_pool_index;
  rx_conf.cnxk_pool_index = pktio->cnxk_pool_index;
  rx_conf.rxq_min_vec_size = pktio->rxq_min_vec_size;
  rx_conf.rxq_max_vec_size = pktio->rxq_max_vec_size;

  onp_pktio_notice ("eth%d rq (min: %u, max: %u)", pktio->onp_pktio_index,
		    rx_conf.rxq_min_vec_size, rx_conf.rxq_max_vec_size);

  /* Enable RX checksum */
  rx_conf.rxq_offloads = CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM;
  if (need_multiseg_enable)
    rx_conf.rxq_offloads |= CNXK_PKTIO_RX_OFF_FLAG_MSEG;

  pktio->rx_offload_flags = rx_conf.rxq_offloads;

  if (cnxk_drv_pktio_rxq_setup (vm, drv_pktio_index, &rx_conf) < 0)
    {
      error = clib_error_return (error, "cnxk_drv_pktio_rxq_setup failed");
      return error;
    }

  if (cnxk_drv_pktio_xstats_count_get (vm, drv_pktio_index,
				       &pktio->xstats_count) < 0)
    return clib_error_create ("cnxk_drv_pktio_xstats_count_get failed");

  if (cnxk_drv_pktio_xstats_names_get (
	vm, drv_pktio_index, pktio->xstats_names, pktio->xstats_count) < 0)
    return clib_error_create ("cnxk_drv_pktio_xstats_names_get failed");

  clib_memset (&onp_pktio_rxq_config, 0, sizeof (onp_pktio_rxq_config));
  /*
   * Ensure onp_pktio_rxqs can accommodate queues that will be initialized
   * later
   */
  vec_validate_init_empty_aligned (pktio->onp_pktio_rxqs, pktio->n_rx_q - 1,
				   onp_pktio_rxq_config,
				   CLIB_CACHE_LINE_BYTES);

  clib_memset (&onp_pktio_txq_config, 0, sizeof (onp_pktio_txq_config));
  vec_validate_init_empty_aligned (pktio->onp_pktio_txqs, pktio->n_tx_q,
				   onp_pktio_txq_config,
				   CLIB_CACHE_LINE_BYTES);

  pktio->init_done_magic_num = ONP_INIT_MAGIC_NUM;

  return NULL;
}

int
onp_pktio_assign_rq_to_node (vlib_main_t *vm, u32 onp_pktio_index,
			     u32 rq_index, u32 thread_index, u32 node_index,
			     int is_assign_node)
{
  onp_pktio_t *pktio = onp_get_pktio (onp_pktio_index);
  cnxk_pktio_rxq_fn_conf_t rx_fn_conf = { 0 };
  vnet_main_t *vnm = vnet_get_main ();

  ASSERT (pktio->init_done_magic_num == ONP_INIT_MAGIC_NUM);

  if (is_assign_node)
    vnet_hw_if_set_input_node (vnm, pktio->hw_if_index, node_index);

  /* Set rss poll burst size from configuration */
  pktio->onp_pktio_rxqs[rq_index].req_burst_size = pktio->rxq_max_vec_size;

  /* Set fast-path function for rx without tracing  */
  rx_fn_conf.offload_flags = pktio->rx_offload_flags;
  cnxk_drv_pktio_rxq_fp_set (vm, pktio->cnxk_pktio_index, rq_index,
			     &rx_fn_conf);
  pktio->onp_pktio_rxqs[rq_index].pktio_recv_func =
    rx_fn_conf.pktio_recv_func_ptr;

  /* Set fast-path function for rx with tracing  */
  rx_fn_conf.offload_flags = pktio->rx_offload_flags;
  rx_fn_conf.fp_flags = CNXK_PKTIO_FP_FLAG_TRACE_EN;
  cnxk_drv_pktio_rxq_fp_set (vm, pktio->cnxk_pktio_index, rq_index,
			     &rx_fn_conf);
  pktio->onp_pktio_rxqs[rq_index].pktio_recv_func_with_trace =
    rx_fn_conf.pktio_recv_func_ptr;

  pktio->onp_pktio_rxqs[rq_index].vnet_hw_rq_index =
    vnet_hw_if_register_rx_queue (vnm, pktio->hw_if_index, rq_index,
				  thread_index);

  /*
   *  TODO:
   *  Driver returns -1 in case of failure.
   *  Handle fail case and remove ALWAYS_ASSERT condition
   */
  ALWAYS_ASSERT (pktio->onp_pktio_rxqs[rq_index].pktio_recv_func);
  ALWAYS_ASSERT (pktio->onp_pktio_rxqs[rq_index].pktio_recv_func_with_trace);

  return 0;
}

/**
 * @param thread_index if not VNET_HW_IF_RXQ_THREAD_ANY, all rq set to single
 * thread_index
 */
int
onp_pktio_assign_and_enable_all_rqs (vlib_main_t *vm, i32 onp_pktio_index,
				     u32 node_index, u32 thread_index,
				     int is_enable)
{
  onp_pktio_t *pktio = onp_get_pktio (onp_pktio_index);
  vnet_main_t *vnm = vnet_get_main ();
  u32 rxq;

  ASSERT (pktio->init_done_magic_num == ONP_INIT_MAGIC_NUM);

  if (is_enable)
    {
      vec_foreach_index (rxq, pktio->onp_pktio_rxqs)
	{
	  onp_pktio_assign_rq_to_node (vm, onp_pktio_index, rxq, thread_index,
				       node_index, !rxq);
	}

      vnet_hw_if_update_runtime_data (vnm, pktio->hw_if_index);
      return 0;
    }
  return -1;
}

int
onp_pktio_txqs_fp_set (vlib_main_t *vm, u32 onp_pktio_index, int is_enable)
{
  onp_pktio_t *pktio = onp_get_pktio (onp_pktio_index);
  cnxk_pktio_txq_fn_conf_t tx_fn_conf = { 0 };
  u32 txq;

  ASSERT (pktio->init_done_magic_num == ONP_INIT_MAGIC_NUM);

  if (is_enable)
    {
      vec_foreach_index (txq, pktio->onp_pktio_txqs)
	{
	  memset (&tx_fn_conf, 0, sizeof (tx_fn_conf));
	  /* Set fast-path function for tx */
	  tx_fn_conf.offload_flags = pktio->tx_offload_flags;
	  cnxk_drv_pktio_txq_fp_set (vm, pktio->cnxk_pktio_index, txq,
				     &tx_fn_conf);
	  pktio->onp_pktio_txqs[txq].pktio_send_func =
	    tx_fn_conf.pktio_send_func_ptr;

	  ALWAYS_ASSERT (pktio->onp_pktio_txqs[txq].pktio_send_func);
	}
    }
  return 0;
}

static int
onp_pktio_flow_add (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_instance,
		    u32 flow_index, uword *private_data)
{
  vnet_flow_t *flow = vnet_get_flow (flow_index);
  int rv = 0;

  rv = cnxk_drv_pktio_flow_update (vnm, op, dev_instance, flow, private_data);
  if (rv)
    {
      onp_pktio_warn ("cnxk_drv_pktio_flow_update failed");
      return VNET_FLOW_ERROR_NOT_SUPPORTED;
    }

  return 0;
}

int
onp_pktio_flow_ops (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_instance,
		    u32 flow_index, uword *private_data)
{

  switch (op)
    {
    case VNET_FLOW_DEV_OP_ADD_FLOW:
      return onp_pktio_flow_add (vnm, op, dev_instance, flow_index,
				 private_data);

    default:
      break;
    }
  return VNET_FLOW_ERROR_NOT_SUPPORTED;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
