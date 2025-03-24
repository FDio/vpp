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
/*
 * pg_output.c: packet generator output
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vppinfra/string.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/gso/gro_func.h>

static void
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

      if (b->flags & VNET_BUFFER_F_GSO)
	{
	  if (!pif->gso_enabled)
	    {
	      n_gso_drop++;
	    }
	}
      else if (b->flags & VNET_BUFFER_F_OFFLOAD)
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
