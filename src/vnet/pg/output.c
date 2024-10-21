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

#include <czmq.h>

    // if (pif->pcap_main.n_packets_to_capture)
    // if (PREDICT_TRUE (pif->pcap_main.n_packets_captured < pif->pcap_main.n_packets_to_capture))
    // if (pif->pcap_main.pcap_data)
    // if (vec_len(pif->pcap_main.pcap_data) == 0)
    // {
    //   // Hardcoded Ethernet packet (example with all bytes set to 0x01 for simplicity)
    //   u8 test_packet[64]; // Example 64-byte Ethernet packet
    //   memset(test_packet, 0x01, sizeof(test_packet));

    //   vlib_log_debug(pg->log_class, "Sending test packet of length: %d", sizeof(test_packet));

    //   // Use zsock_send to send the test packet
    //   rc = zsock_send(pif->zmq_socket, "b", test_packet, sizeof(test_packet));
    //   if (rc != 0)
    //   {
    //       vlib_log_debug(pg->log_class, "Failed to send test packet via CZMQ");
    //       return clib_error_return(0, "Failed to send packet via CZMQ");
    //   }

    //   vlib_log_debug(pg->log_class, "Successfully sent test packet of length: %d", sizeof(test_packet));

    //   return error;
    // }

static clib_error_t *
zmq_send_packet (pg_interface_t * pif, vlib_main_t *vm, u8* current_buff, i32 n_left)
{
    pg_main_t *pg = &pg_main;
    pcap_main_t * pm = &pif->pcap_main;
    clib_error_t *error = 0;
    // vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
    // u32 n = vlib_buffer_length_in_chain (vm, b);
    // u8 *packet_data;
    int rc;

    // Check if the CZMQ socket is initialized
    if (!pif->zmq_socket)
    {
        vlib_log_debug(pg->log_class, "CZMQ socket not initialized");
        return clib_error_return(0, "CZMQ socket is not initialized");
    }

    if (!(pm->flags & PCAP_MAIN_INIT_DONE))
    {
      pm->flags |= PCAP_MAIN_INIT_DONE;
      pm->n_packets_captured = 0;
      pm->n_pcap_data_written = 0;
    }


    rc = zsock_send(pif->zmq_socket, "b", current_buff, n_left);
    if (rc != 0)
    {
            error = clib_error_return(0, "Failed to send packet via CZMQ");
            goto done;
    }
    pm->n_pcap_data_written = vec_len(pm->pcap_data);

    // // Send packet data over the CZMQ socket
    // while (vec_len(pm->pcap_data) > pm->n_pcap_data_written)
    // {
    //     i64 n_left = vec_len(pm->pcap_data) - pm->n_pcap_data_written;
        // packet_data = vec_elt_at_index(pm->pcap_data, pm->n_pcap_data_written);

    //     // Use zsock_send to send the packet
    //     rc = zsock_send(pif->zmq_socket, "b", packet_data, n_left);
    //     if (rc != 0)
    //     {
    //         error = clib_error_return(0, "Failed to send packet via CZMQ");
    //         goto done;
    //     }

    //     // Track how much data was sent
    //     pm->n_pcap_data_written += n_left;
    // }

    // Reset the packet buffer if all packets have been sent
    if (pm->n_pcap_data_written >= vec_len(pm->pcap_data))
    {
        vec_reset_length(pm->pcap_data);
        pm->n_pcap_data_written = 0;
    }

done:
    return error;
}


uword
pg_output (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  pg_main_t *pg = &pg_main;
  u32 *buffers = vlib_frame_vector_args (frame);
  uword n_buffers = frame->n_vectors;
  uword n_left = n_buffers;
  u32 to[GRO_TO_VECTOR_SIZE (n_buffers)];
  uword n_to = 0;
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

      if (b->flags & VLIB_BUFFER_IS_TRACED)
	{
	  pg_output_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	  t->buffer_index = bi0;
	  clib_memcpy_fast (&t->buffer, b,
			    sizeof (b[0]) - sizeof (b->pre_data));
	  clib_memcpy_fast (t->buffer.pre_data, b->data + b->current_data,
			    sizeof (t->buffer.pre_data));
	}

      if (pif->pcap_file_name != 0 || pif->zmq_socket_port != 0) {
	     u8* current_buff = pcap_add_buffer (&pif->pcap_main, vm, bi0, ETHERNET_MAX_PACKET_BYTES);
      
        if (pif->zmq_socket != 0)
          {
              vlib_buffer_t *b = vlib_get_buffer (vm, bi0);
              u32 n = vlib_buffer_length_in_chain (vm, b);
              i32 n_packet_size = clib_min (ETHERNET_MAX_PACKET_BYTES, n);
              zmq_send_packet(pif, vm, current_buff, n_packet_size);
          }
      }
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
