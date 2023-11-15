/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP pktio format helper implementation.
 */

#include <onp/onp.h>

#define foreach_onp_pktio_rxq_counter                                         \
  _ (rx_octets, rx_octs)                                                      \
  _ (rx_packets, rx_pkts)                                                     \
  _ (rx_drop_packets, rx_drop_pkts)                                           \
  _ (rx_drop_octs, rx_drop_octs)                                              \
  _ (rx_error_packets, rx_error_pkts)

#define foreach_onp_pktio_txq_counter                                         \
  _ (tx_octets, tx_octs)                                                      \
  _ (tx_packets, tx_pkts)                                                     \
  _ (tx_drop_packets, tx_drop_pkts)                                           \
  _ (tx_drop_octets, tx_drop_octs)

#define foreach_onp_pktio_counter                                             \
  _ (rx_octets, rx_octets)                                                    \
  _ (rx_ucast_packets, rx_ucast_pkts)                                         \
  _ (rx_mcast_packets, rx_mcast_pkts)                                         \
  _ (rx_bcast_packets, rx_bcast_pkts)                                         \
  _ (rx_drop_packets, rx_drop_pkts)                                           \
  _ (rx_drop_octets, rx_drop_octets)                                          \
  _ (rx_drop_bcast_packets, rx_drop_bcast_pkts)                               \
  _ (rx_drop_mcast_packets, rx_drop_mcast_pkts)                               \
  _ (rx_fcs_packets, rx_fcs_pkts)                                             \
  _ (rx_error_packets, rx_err)                                                \
  _ (tx_octets, tx_octets)                                                    \
  _ (tx_ucast_packets, tx_ucast_pkts)                                         \
  _ (tx_mcast_packets, tx_mcast_pkts)                                         \
  _ (tx_bcast_packets, tx_bcast_pkts)                                         \
  _ (tx_drop_packets, tx_drop_pkts)

u8 *
format_onp_pktio (u8 *s, va_list *args)
{
  u8 *xstats_name[CNXK_PKTIO_MAX_XSTATS_COUNT] = { 0 };
  u64 xstats[CNXK_PKTIO_MAX_XSTATS_COUNT] = { 0 };
  u32 hw_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  cnxk_pktio_queue_stats_t qstats;
  cnxk_pktio_stats_t stats;
  u32 indent, xstats_count;
  vlib_main_t *vm;
  onp_pktio_t *op;
  char q_name[64];
  onp_main_t *om;
  int rv, i;
  u16 cpi;

  vm = vlib_get_main ();
  om = onp_get_main ();
  op = pool_elt_at_index (om->onp_pktios, hw_instance);
  cpi = op->cnxk_pktio_index;
  xstats_count = op->xstats_count;
  indent = format_get_indent (s);

  /*
   * roc call returns different set of counters when inline dev is enabled.
   * As a workaround, read stats count and names again.
   * TODO:
   * move this to device probe to avoid multiple reads.
   */

  cnxk_drv_pktio_xstats_count_get (vm, cpi, &xstats_count);

  cnxk_drv_pktio_xstats_names_get (vm, cpi, xstats_name, xstats_count);

  s = format (s, "%-40s%-50s\n", "rxq0_func",
	      onp_address_to_str (op->onp_pktio_rxqs[0].pktio_recv_func));

  s = format (
    s, "%U%-40s%-50s\n", format_white_space, indent, "rxq0_func_w_trace",
    onp_address_to_str (op->onp_pktio_rxqs[0].pktio_recv_func_with_trace));

  s = format (s, "%U%-40s%-50s\n", format_white_space, indent, "txq0_func",
	      onp_address_to_str (op->onp_pktio_txqs[0].pktio_send_func));

  s = format (
    s, "%U%-40s%-50s\n", format_white_space, indent, "txq0_func_w_order",
    onp_address_to_str (op->onp_pktio_txqs[0].pktio_send_func_order));

  s = format (s, "PCI addr %U\n", format_vlib_pci_addr,
	      &op->pktio_pci_addr.as_u32);
  s = format (s, "%UMarvell OCTEON\n", format_white_space, indent);

#define _(name, var, val, min_val, max_val, isprint)                          \
  s = format (s, "%U%-40s%16u\n", format_white_space, indent + 1, #name,      \
	      op->var);

  foreach_onp_pktio_config_item;
#undef _

  /*
   * Display pktio statistics.
   * Increase verbosity when the 'detail' option is specified from CLI (i.e.
   * verbose == 2)
   */

  if (verbose < 2)
    {
      rv = cnxk_drv_pktio_stats_get (vm, cpi, &stats);
      if (rv)
	return s;

	/* clang-format off */
#define _(str, val)                                                           \
      s = format (s, "%U%-40s%16u\n", format_white_space, indent + 1, #str,   \
		  stats.val);
      foreach_onp_pktio_counter;
#undef _
      /* clang-format on */
    }
  else
    {
      for (i = 0; i < op->n_rx_q; i++)
	{
	  rv = cnxk_drv_pktio_queue_stats_get (vm, cpi, i, &qstats, 1);
	  if (rv)
	    return s;

	    /* clang-format off */
#define _(str, val)                                                           \
	  snprintf (q_name, sizeof (q_name), "rxq_%d_%s", i, #str);           \
	  s = format (s, "%U%-40s%16u\n", format_white_space, indent + 1,     \
		      q_name, qstats.val);
	  foreach_onp_pktio_rxq_counter;
#undef _
	  /* clang-format on */
	}

      for (i = op->n_rx_q; i < op->n_rx_q; i++)
	{
	  rv = cnxk_drv_pktio_queue_stats_get (vm, cpi, i, &qstats, 1);
	  if (rv)
	    return s;

	    /* clang-format off */
#define _(str, val)                                                           \
	  snprintf (q_name, sizeof (q_name), "ff_rxq_%d_%s", i, #str);        \
	  s = format (s, "%U%-40s%16u\n", format_white_space, indent + 1,     \
		      q_name, qstats.val);
	  foreach_onp_pktio_rxq_counter;
#undef _
	  /* clang-format on */
	}

      for (i = 0; i < op->n_tx_q; i++)
	{
	  rv = cnxk_drv_pktio_queue_stats_get (vm, cpi, i, &qstats, 0);
	  if (rv)
	    return s;

	    /* clang-format off */
#define _(str, val)                                                           \
	  snprintf (q_name, sizeof (q_name), "txq_%d_%s", i, #str);           \
	  s = format (s, "%U%-40s%16u\n", format_white_space, indent + 1,     \
		      q_name,  qstats.val);
         foreach_onp_pktio_txq_counter;
#undef _
	  /* clang-format on */
	}

      for (i = op->n_tx_q; i < op->n_tx_q; i++)
	{
	  rv = cnxk_drv_pktio_queue_stats_get (vm, cpi, i, &qstats, 0);
	  if (rv)
	    return s;

	    /* clang-format off */
#define _(str, val)                                                           \
	  snprintf (q_name, sizeof (q_name), "ff_txq_%d_%s", i, #str);        \
	  s = format (s, "%U%-40s%16u\n", format_white_space, indent + 1,     \
		      q_name,  qstats.val);
	  foreach_onp_pktio_txq_counter;
#undef _
	  /* clang-format on */
	}

      clib_memset (&xstats, 0, sizeof (xstats));
      rv = cnxk_drv_pktio_xstats_get (vm, cpi, xstats, xstats_count);
      if (rv)
	return s;

      for (i = 0; i < xstats_count; i++)
	{
	  /* Print non-zero extended stats */
	  if (xstats[i] != 0)
	    s = format (s, "%U%-40s%16u\n", format_white_space, indent + 1,
			xstats_name[i], xstats[i]);
	}
    }

  for (i = 0; i < xstats_count; i++)
    vec_free (xstats_name[i]);

  return s;
}

u8 *
format_onp_pktio_name (u8 *s, va_list *args)
{
  onp_main_t *om = onp_get_main ();
  u32 i = va_arg (*args, u32);
  onp_pktio_t *op;

  op = pool_elt_at_index (om->onp_pktios, i);

  s = format (s, "%s", op->name);

  return s;
}

u8 *
format_onp_pktio_rx_trace (u8 *s, va_list *va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 indent = format_get_indent (s);
  vlib_node_t *node;
  onp_rx_trace_t *ot;

  node = va_arg (*va, vlib_node_t *);
  ot = va_arg (*va, onp_rx_trace_t *);

  s = format (s, "Pktio: %u,RQ:%u, Next node: %U\n", ot->pktio_index,
	      ot->queue_index, format_vlib_next_node_name, vm, node->index,
	      ot->next_node_index);

  s = format (s, "%Ubuffer 0x%x: %U\n", format_white_space, indent,
	      ot->buffer_index, format_vnet_buffer, &ot->buffer);
#if CLIB_DEBUG > 0
  s = format (s, "%U%U\n", format_white_space, indent, format_vlib_buffer,
	      &ot->buffer);
#endif
  s = format (s, "%U%U\n", format_white_space, indent,
	      cnxk_drv_pktio_format_rx_trace, ot->pktio_index, ot->driver_data,
	      node, vm, vnm);

  if (vm->trace_main.verbose)
    {
      s = format (s, "%UPacket data\n", format_white_space, indent);

      s = format (s, "%U%U\n", format_white_space, indent + 2, format_hexdump,
		  &ot->data, 256);
    }

  s = format (s, "%U%U", format_white_space, indent,
	      format_ethernet_header_with_length, ot->data, 256);

  return s;
}

u8 *
format_onp_pktio_tx_trace (u8 *s, va_list *va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  CLIB_UNUSED (vnet_main_t * vnm) = vnet_get_main ();
  onp_tx_trace_t *t = va_arg (*va, onp_tx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "SQ: %x, Buffer index 0x%x: %U\n", t->qid, t->buffer_index,
	      format_vnet_buffer, &t->buf);

  if (vm->trace_main.verbose)
    {
      s = format (s, "%UPacket data\n", format_white_space, indent);

      s = format (s, "%U%U\n", format_white_space, indent + 2, format_hexdump,
		  &t->data, 256);
    }

  s = format (s, "%U%U", format_white_space, indent,
	      format_ethernet_header_with_length, t->data, 256);

  return s;
}

u8 *
format_onp_pktio_flow (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  vlib_main_t *vm = vlib_get_main ();
  cnxk_flow_stats_t stats;
  uword private_data;
  vnet_flow_t *flow;
  u32 index;

  index = va_arg (*args, u32);
  private_data = va_arg (*args, uword);

  clib_memset (&stats, 0, sizeof (cnxk_flow_stats_t));

  if (cnxk_drv_pktio_flow_query (vm, dev_instance, private_data, &stats) == 0)
    {
      flow = vnet_get_flow (stats.flow_index);
      if (!flow)
	return s;

      if (flow->index == index)
	{
	  s = format (s, "cnxk flow index: %u\n", private_data);
	  s = format (s, "ONP flow hit count: %lu", stats.hits);
	}
    }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
