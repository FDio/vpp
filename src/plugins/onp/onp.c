/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief OCTEON native plugin implementation.
 */

#include <onp/onp.h>
#include <onp/drv/inc/pool_fp.h>

onp_main_t onp_main;
onp_config_main_t onp_config_main;

const char *
onp_address_to_str (void *p)
{
  Dl_info info = { 0 };

  if (dladdr (p, &info) == 0)
    return 0;

  return info.dli_sname;
}

static clib_error_t *
onp_per_thread_data_init (onp_main_t *om)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  onp_config_main_t *conf = &onp_config_main;
  u16 iter;

  /* vlib_buffer_t template */
  vec_validate_aligned (om->onp_per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  onp_pool_debug ("pktpool refill_deplete_sz is %d",
		  conf->onp_pktpool_refill_deplete_sz);

  for (iter = 0; iter < tm->n_vlib_mains; iter++)
    {
      cnxk_per_thread_data_t *ptd =
	vec_elt_at_index (om->onp_per_thread_data, iter);

      clib_memset (ptd, 0, sizeof (cnxk_per_thread_data_t));

      ptd->buffer_template.flags =
	(VNET_BUFFER_F_L4_CHECKSUM_CORRECT |
	 VNET_BUFFER_F_L4_CHECKSUM_COMPUTED | VLIB_BUFFER_EXT_HDR_VALID);

      vnet_buffer (&ptd->buffer_template)->sw_if_index[VLIB_TX] = (u32) ~0;

      ptd->buffer_template.ref_count = 1;

      ptd->pktio_node_state = 1;

      cnxk_drv_per_thread_data_init (ptd, conf->onp_pktpool_refill_deplete_sz,
				     ONP_MAX_VLIB_BUFFER_POOLS);
    }
  return NULL;
}

/*?
 * Configure the ONP plugin.
 *
 * @anchor pci-dev
 * Devices are identified by <pci-dev> in ONP startup configuration.
 * <pci-dev> is a string of the form
 * @c DDDD:BB:SS.F, where
 * @verbatim
 * DDDD Domain
 * BB   Bus
 * SS   Slot
 * F    Function
 * @endverbatim
 * This is similar to the format used in linux to enumerate PCI devices
 * in the sysfs tree (at @c /sys/bus/pci/devices/).
 *
 * @cfgcmd{dev, <pci-dev> \{ ... \}}
 * White-lists and configures a network device.
 * See @ref onp_syscfg_dev.
 *
 * @cfgcmd{dev, default \{ ... \}}
 * Changes the default settings for all network devices.
 * See @ref onp_syscfg_dev_default.
 *
 * @cfgcmd{num-pkt-bufs, <n>}
 * Sets the number of packet buffers to allocate. The default value is @ref
 * ONP_N_PKT_BUF.
 *
 * @par Example:
 * @verbatim
 * onp {
 *     dev 0000:02:00.0 {
 *         num-rx-queues 3
 *         num-tx-queues 3
 *         num-rx-desc 4096
 *         num-tx-desc 4096
 *     }
 *
 *     num-pkt-bufs 16384
 * }
 * @endverbatim
 *
 * @subsection onp_syscfg_dev dev <pci-dev>
 * Configures the NIX device @ref pci-dev.
 *
 * Parameters:
 *
 * @cfgcmd{num-rx-queues, <n>}
 * Selects the number of receive queues. The default value is the number of
 * VPP worker threads.
 *
 * @cfgcmd{num-tx-queues, <n>}
 * Selects the number of transmit queues. The default value is the number of
 * VPP worker threads.
 *
 * @cfgcmd{num-rx-desc, <n>}
 * Selects the number of descriptors in each receive queue. The default value
 * is @ref ONP_DEFAULT_N_RX_DESC
 *
 * @cfgcmd{num-tx-desc, <n>}
 * Selects the number of descriptors in each transmit queue. The default value
 * is @ref ONP_DEFAULT_N_TX_DESC
 *
 * @par Example:
 * @verbatim
 * dev 0000:02:00.0 {
 *     num-rx-queues 2
 *     num-tx-queues 2
 *     num-rx-desc 4096
 *     num-tx-desc 4096
 * }
 * @endverbatim
 *
 * @subsection onp_syscfg_dev_default dev default
 * Changes default settings for all the network interfaces. This section
 * supports the same set of parameters described in @ref onp_syscfg_dev.
 *
 * @par Example:
 * @verbatim
 * dev default {
 *     num-rx-queues 3
 *     num-tx-queues 3
 *     num-rx-desc 4096
 *     num-tx-desc 4096
 * }
 * @endverbatim
 *
 * @subsection onp_syscfg_num_pkt_buf num-pkt-bufs
 * Sets the number of packet buffers to allocate.
 ?*/
static clib_error_t *
onp_config (vlib_main_t *vm, unformat_input_t *input)
{
  onp_config_main_t *conf = &onp_config_main;
  onp_pktio_config_t *pktioconf = NULL;
  onp_main_t *om = onp_get_main ();
  unformat_input_t sub_input;
  clib_error_t *error = NULL;
  vlib_pci_addr_t pci_addr;
  onp_pktio_t *pktio;

  clib_memset (conf, 0, sizeof (*conf));

  conf->onp_pktio_config_index_by_pci_addr = hash_create (0, sizeof (uword));
  conf->onp_num_pkt_buf = ONP_N_PKT_BUF;
  conf->onp_pktpool_refill_deplete_sz = CNXK_POOL_MAX_REFILL_DEPLTE_COUNT;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "dev %U %U", unformat_vlib_pci_addr, &pci_addr,
		    unformat_vlib_cli_sub_input, &sub_input))
	{
	  error = onp_pktio_config_parse (conf, pci_addr, &sub_input, 0);
	  if (error)
	    return error;
	}

      else if (unformat (input, "dev %U", unformat_vlib_pci_addr, &pci_addr))
	{
	  error = onp_pktio_config_parse (conf, pci_addr, 0, 0);
	  if (error)
	    return error;
	}

      else if (unformat (input, "dev default %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  pci_addr.as_u32 = ONP_DEV_PCI_ADDR_ANY;
	  error = onp_pktio_config_parse (conf, pci_addr, &sub_input, 1);
	  if (error)
	    return error;
	}

      else if (unformat (input, "num-pkt-bufs %d", &conf->onp_num_pkt_buf))
	;

      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  onp_pktio_configs_validate (vm, conf);

  /* Configure early_init pktio */
  vec_foreach (pktioconf, om->onp_conf->onp_pktioconfs)
    {
      error = onp_pktio_early_setup (vm, om, pktioconf, &pktio);
      if (error)
	{
	  clib_error_return (0, "onp_pktio_early_setup failed for pci_add: %u",
			     pktioconf->pktio_pci_addr.as_u32);
	  return (error);
	}
    }
  /* Configure pools */
  if (pool_elts (om->onp_pktios))
    {
      error = onp_buffer_pools_setup (vm);
      if (error)
	{
	  clib_error_return (0, "onp_buffer_pools_setup failed");
	  return error;
	}
    }

  return NULL;
}

VLIB_CONFIG_FUNCTION (onp_config, "onp");

static clib_error_t *
onp_init (vlib_main_t *vm, vlib_node_runtime_t *nrt, vlib_frame_t *frame)
{
  onp_pktio_config_t *pktioconf = NULL;
  onp_main_t *om = onp_get_main ();
  clib_error_t *error = NULL;
  onp_pktio_t *pktio;
  int pktio_index = 0;

  /* Initialize per_thread_data */
  onp_per_thread_data_init (om);
  cnxk_drv_pktpool_set_refill_deplete_counters (
    CNXK_POOL_COUNTER_TYPE_DEFAULT,
    &om->onp_counters.pool[CNXK_POOL_COUNTER_TYPE_DEFAULT].refill_counters,
    &om->onp_counters.pool[CNXK_POOL_COUNTER_TYPE_DEFAULT].deplete_counters);

  /* Configure pktio */
  vec_foreach (pktioconf, om->onp_conf->onp_pktioconfs)
    {
      pktio = &om->onp_pktios[pktio_index];
      error = onp_pktio_setup (vm, om, pktioconf, &pktio);
      if (error)
	{
	  clib_error_return (0, "onp_pktio_setup failed for pci_add: %u",
			     pktioconf->pktio_pci_addr.as_u32);
	  return (error);
	}
      pktio_index++;
    }

  pool_foreach (pktio, om->onp_pktios)
    {
      onp_pktio_txqs_fp_set (vm, pktio->onp_pktio_index, 1);
      onp_pktio_assign_and_enable_all_rqs (vm, pktio->onp_pktio_index,
					   ONP_PKTIO_INPUT_NODE_INDEX,
					   VNET_HW_IF_RXQ_THREAD_ANY, 1);
    }

  om->onp_init_done = 1;
  return error;
}

static uword
onp_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *pktio;
  f64 timeout = 5.0;
  clib_error_t *error;

  error = onp_init (vm, rt, f);

  if (error)
    {
      cnxk_pktio_err ("onp_init failed");
      clib_error_report (error);
      return 0;
    }

  /* Update status before process get suspended */
  vec_foreach (pktio, om->onp_pktios)
    {
      onp_pktio_link_state_update (pktio);
    }

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      vec_foreach (pktio, om->onp_pktios)
	{
	  onp_pktio_link_state_update (pktio);
	}
    }
  return 0;
}

VLIB_REGISTER_NODE (onp_process_node, static) = {
  .function = onp_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "onp-process",
  .process_log2_n_stack_bytes = 18,
};

static clib_error_t *
onp_plugin_init (vlib_main_t *vm)
{
  onp_main_t *om = onp_get_main ();
  clib_error_t *error = 0;

  om->onp_conf = &onp_config_main;

#define _(idx, s, str, v)                                                     \
  om->onp_counters.s##_counters.name = str;                                   \
  om->onp_counters.s##_counters.stat_segment_name = "/onp/" str "_counters";  \
  vlib_validate_simple_counter (&om->onp_counters.s##_counters, 0);           \
  vlib_zero_simple_counter (&om->onp_counters.s##_counters, 0);

  foreach_onp_counters
#undef _

    error = cnxk_plt_model_init ();
  if (error)
    return error;

  return error;
}

VLIB_INIT_FUNCTION (onp_plugin_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Marvell OCTEON native (onp) plugin",
  .default_disabled = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
