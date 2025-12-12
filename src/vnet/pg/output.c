/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* pg_output.c: packet generator output */

#include <vppinfra/string.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/gso/gro_func.h>

static_always_inline void
pg_interface_counter_inline (vlib_main_t *vm, pg_interface_t *pif,
			     uword node_index, u16 n, pg_tx_func_error_t error)
{
  vlib_error_count (vm, node_index, error, n);
  vlib_increment_simple_counter (vnet_main.interface_main.sw_if_counters +
				   VNET_INTERFACE_COUNTER_DROP,
				 vm->thread_index, pif->sw_if_index, n);
}

uword
pg_output (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  pg_main_t *pg = &pg_main;
  u32 *buffers = vlib_frame_vector_args (frame);
  uword n_buffers = frame->n_vectors;
  uword n_left = n_buffers;
  u32 to[GRO_TO_VECTOR_SIZE (n_buffers)];
  uword n_to = 0, n_gso_drop = 0, n_csum_offload_drop = 0;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  pg_interface_t *pif = pool_elt_at_index (pg->interfaces, rd->dev_instance);

  if (PREDICT_FALSE (pif->lockp != 0))
    while (clib_atomic_test_and_set (pif->lockp))
      ;

  if (PREDICT_FALSE (pif->coalesce_enabled))
    {
      n_to = vnet_gro_inline (vm, pif->flow_table, buffers, n_left, to);
      buffers = to;
      n_left = n_to;
    }

  while (n_left > 0)
    {
      n_left--;
      u32 bi0 = buffers[0];
      vlib_buffer_t *b = vlib_get_buffer (vm, bi0);
      buffers++;

      if (PREDICT_FALSE (b->flags & VNET_BUFFER_F_GSO))
	{
	  if (!pif->gso_enabled)
	    {
	      n_gso_drop++;
	    }
	}
      else if (PREDICT_FALSE (b->flags & VNET_BUFFER_F_OFFLOAD))
	{
	  if (!pif->csum_offload_enabled)
	    {
	      n_csum_offload_drop++;
	    }
	}

      if (b->flags & VLIB_BUFFER_IS_TRACED)
	{
	  pg_output_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	  t->mode = pif->mode;
	  t->buffer_index = bi0;
	  clib_memcpy_fast (&t->buffer, b,
			    sizeof (b[0]) - sizeof (b->pre_data));
	  clib_memcpy_fast (t->buffer.pre_data, b->data + b->current_data,
			    sizeof (t->buffer.pre_data));
	}

      if (pif->pcap_file_name != 0)
	pcap_add_buffer (&pif->pcap_main, vm, bi0, ETHERNET_MAX_PACKET_BYTES);
    }
  if (pif->pcap_file_name != 0)
    {
      pcap_packet_type_t pm_pt = pif->pcap_main.packet_type;
      pif->pcap_main.packet_type =
	pg_intf_mode_to_pcap_packet_type (pif->mode);
      pcap_write (&pif->pcap_main);
      pif->pcap_main.packet_type = pm_pt;
    }
  if ((pif->pcap_main.flags & PCAP_MAIN_INIT_DONE)
      && pif->pcap_main.n_packets_captured >=
      pif->pcap_main.n_packets_to_capture)
    pcap_close (&pif->pcap_main);

  if (n_gso_drop)
    pg_interface_counter_inline (vm, pif, node->node_index, n_gso_drop,
				 PG_TX_ERROR_GSO_PACKET_DROP);
  if (n_csum_offload_drop)
    pg_interface_counter_inline (vm, pif, node->node_index,
				 n_csum_offload_drop,
				 PG_TX_ERROR_CSUM_OFFLOAD_PACKET_DROP);

  if (PREDICT_FALSE (pif->coalesce_enabled))
    {
      n_buffers = n_to;
      vlib_buffer_free (vm, to, n_to);
    }
  else
    vlib_buffer_free (vm, vlib_frame_vector_args (frame), n_buffers);
  if (PREDICT_FALSE (pif->lockp != 0))
    clib_atomic_release (pif->lockp);

  return n_buffers;
}
