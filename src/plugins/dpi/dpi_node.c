/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
*
*/


#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <dpi/dpi.h>

vlib_node_registration_t dpi_scan_node;

typedef struct {
  u32 next_index;
  u32 dpi_id;
  u32 error;
} dpi_rx_trace_t;

static u8 * format_dpi_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dpi_rx_trace_t * t = va_arg (*args, dpi_rx_trace_t *);

  if (t->dpi_id != ~0)
    {
      s = format (s, "DPI scan from dpi_id %d next %d error %d",
                  t->dpi_id, t->next_index, t->error);
    }
  else
    {
      s = format (s, "DPI scan error - dpi_id %d does not exist",
		  t->dpi_id);
    }
  return s;
}

typedef enum {
  IP_DPI_NEXT_DROP,
  IP_DPI_NEXT_DPI,
  IP_DPI_N_NEXT,
} ip_dpi_next_t;

always_inline uword
ip_dpi_inline (vlib_main_t * vm,
			         vlib_node_runtime_t * node,
			         vlib_frame_t * frame,
			         u32 is_ip4)
{
  //dpi_main_t * hsm = &dpi_main;
  u32 * from, *to_next, n_left_from, n_left_to_next, next_index;
  vlib_node_runtime_t * error_node = vlib_node_get_runtime (
      vm, ip4_input_node.index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          vlib_buffer_t * b0, *b1;
          ip4_header_t * ip40, *ip41;
          ip6_header_t * ip60, *ip61;
          udp_header_t * udp0, *udp1;
          tcp_header_t * tcp0, *tcp1;
          u32 bi0, ip_len0, l4_len0, flags0, l4_hdr_len0;
          u32 bi1, ip_len1, l4_len1, flags1, l4_hdr_len1;
          u32 next0 = IP_DPI_NEXT_DROP;
          u32 next1 = IP_DPI_NEXT_DROP;
          i32 len_diff0, len_diff1;
          u8 error0, proto0, l4_good0;
          u8 error1, proto1, l4_good1;

          /* Prefetch next iteration. */
            {
              vlib_buffer_t * p2, *p3;

              p2 = vlib_get_buffer (vm, from[2]);
              p3 = vlib_get_buffer (vm, from[3]);

              vlib_prefetch_buffer_header(p2, LOAD);
              vlib_prefetch_buffer_header(p3, LOAD);

              CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
              CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
            }

          bi0 = to_next[0] = from[0];
          bi1 = to_next[1] = from[1];
          from += 2;
          n_left_from -= 2;
          to_next += 2;
          n_left_to_next -= 2;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);
          if (is_ip4)
            {
              ip40 = vlib_buffer_get_current (b0);
              ip41 = vlib_buffer_get_current (b1);
              ip_len0 = clib_net_to_host_u16 (ip40->length);
              proto0 = ip40->protocol;
              ip_len1 = clib_net_to_host_u16 (ip41->length);
              proto1 = ip41->protocol;
            }
          else
            {
              ip60 = vlib_buffer_get_current (b0);
              ip61 = vlib_buffer_get_current (b1);
              ip_len0 = clib_net_to_host_u16 (ip60->payload_length);
              proto0 = ip60->protocol;
              ip_len1 = clib_net_to_host_u16 (ip61->payload_length);
              proto1 = ip61->protocol;
            }

          /* Setup packet for next IP feature */
          vnet_feature_next (&next0, b0);
          vnet_feature_next (&next1, b1);

          /* Process packet 0 */
          if (proto0 == IP_PROTOCOL_UDP)
            {
              if (is_ip4)
                  udp0 = ip4_next_header (ip40);
              else
                  udp0 = ip6_next_header (ip60);

              l4_len0 = clib_net_to_host_u16 (udp0->length);
              l4_hdr_len0 = sizeof(udp_header_t);
              /* Don't verify UDP checksum for packets with zero checksum. */
              l4_good0 |= udp0->checksum == 0;
            }
          else if (proto0 == IP_PROTOCOL_TCP)
            {
              if (is_ip4)
                  tcp0 = ip4_next_header (ip40);
              else
                  tcp0 = ip6_next_header (ip60);

              l4_len0 = tcp_doff(tcp0) << 2;
              l4_hdr_len0 = sizeof(tcp_header_t);
            }
          else
            goto exit0;

          len_diff0 = ip_len0 - l4_len0;
          flags0 = b0->flags;
          l4_good0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

          /* Verify L4 checksum */
          if (PREDICT_TRUE (l4_good0))
            {
              if ((flags0 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
                {
                  if (is_ip4)
                    flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
                  else
                    flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);

                  l4_good0 =
                      (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
                }
            }

          error0 = l4_good0 ? 0 : IP4_ERROR_UDP_CHECKSUM;
          error0 = (len_diff0 >= 0) ? error0 : IP4_ERROR_UDP_LENGTH;
          next0 = error0 ? IP_DPI_NEXT_DROP
                           : IP_DPI_NEXT_DPI;
          b0->error = error0 ? error_node->errors[error0] : 0;
          vlib_buffer_advance (b0, len_diff0 + l4_hdr_len0);

        exit0:
          /* Process packet 1 */
          if (proto1 == IP_PROTOCOL_UDP)
            {
              if (is_ip4)
                  udp1 = ip4_next_header (ip41);
              else
                  udp1 = ip6_next_header (ip61);

              l4_len1 = clib_net_to_host_u16 (udp1->length);
              l4_hdr_len1 = sizeof(udp_header_t);
              /* Don't verify UDP checksum for packets with zero checksum. */
              l4_good1 |= udp1->checksum == 0;
            }
          else if (proto1 == IP_PROTOCOL_TCP)
            {
              if (is_ip4)
                  tcp1 = ip4_next_header (ip41);
              else
                  tcp1 = ip6_next_header (ip61);

              l4_len1 = tcp_doff(tcp1) << 2;
              l4_hdr_len1 = sizeof(tcp_header_t);
            }
          else
            goto exit1;

          len_diff1 = ip_len1 - l4_len1;
          flags1 = b1->flags;
          l4_good1 = (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

          /* Verify L4 checksum */
          if (PREDICT_TRUE (l4_good1))
            {
              if ((flags1 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
                {
                  if (is_ip4)
                    flags1 = ip4_tcp_udp_validate_checksum (vm, b1);
                  else
                    flags1 = ip6_tcp_udp_icmp_validate_checksum (vm, b1);

                  l4_good1 =
                      (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
                }
            }

          error1 = l4_good1 ? 0 : IP4_ERROR_UDP_CHECKSUM;
          error1 = (len_diff1 >= 0) ? error1 : IP4_ERROR_UDP_LENGTH;
          next1 = error1 ? IP_DPI_NEXT_DROP
                           : IP_DPI_NEXT_DPI;
          b1->error = error1 ? error_node->errors[error1] : 0;
          vlib_buffer_advance (b1, len_diff1 + l4_hdr_len1);

        exit1:
            vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                             to_next, n_left_to_next,
                             bi0, bi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          vlib_buffer_t * b0;
          ip4_header_t * ip40;
          ip6_header_t * ip60;
          udp_header_t * udp0;
          tcp_header_t * tcp0;
          u32 bi0, ip_len0, l4_len0, flags0, l4_hdr_len0;
          u32 next0 = IP_DPI_NEXT_DROP;
          i32 len_diff0;
          u8 error0, proto0, l4_good0;

          bi0 = to_next[0] = from[0];
          from += 1;
          n_left_from -= 1;
          to_next += 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          if (is_ip4)
            {
              ip40 = vlib_buffer_get_current (b0);
              ip_len0 = clib_net_to_host_u16 (ip40->length);
              proto0 = ip40->protocol;
            }
          else
            {
              ip60 = vlib_buffer_get_current (b0);
              ip_len0 = clib_net_to_host_u16 (ip60->payload_length);
              proto0 = ip60->protocol;
            }

          if (proto0 == IP_PROTOCOL_UDP)
            {
              if (is_ip4)
                  udp0 = ip4_next_header (ip40);
              else
                  udp0 = ip6_next_header (ip60);

              l4_len0 = clib_net_to_host_u16 (udp0->length);
              l4_hdr_len0 = sizeof(udp_header_t);
              /* Don't verify UDP checksum for packets with zero checksum. */
              l4_good0 |= udp0->checksum == 0;
            }
          else if (proto0 == IP_PROTOCOL_TCP)
            {
              if (is_ip4)
                  tcp0 = ip4_next_header (ip40);
              else
                  tcp0 = ip6_next_header (ip60);

              l4_len0 = tcp_doff(tcp0) << 2;
              l4_hdr_len0 = sizeof(tcp_header_t);
            }
          else
            goto exit00;

          len_diff0 = ip_len0 - l4_len0;
          flags0 = b0->flags;
          l4_good0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

          /* Verify L4 checksum */
          if (PREDICT_TRUE (l4_good0))
            {
              if ((flags0 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
                {
                  if (is_ip4)
                    flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
                  else
                    flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);

                  l4_good0 =
                      (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
                }
            }

          error0 = l4_good0 ? 0 : IP4_ERROR_UDP_CHECKSUM;
          error0 = (len_diff0 >= 0) ? error0 : IP4_ERROR_UDP_LENGTH;
          next0 = error0 ? IP_DPI_NEXT_DROP
                           : IP_DPI_NEXT_DPI;
          b0->error = error0 ? error_node->errors[error0] : 0;
          vlib_buffer_advance (b0, len_diff0 + l4_hdr_len0);

        exit00:
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
ip4_dpi_bypass (vlib_main_t * vm,
		              vlib_node_runtime_t * node,
		              vlib_frame_t * frame)
{
  return ip_dpi_inline (vm, node, frame, /* is_ip4 */ 1);
}

VLIB_REGISTER_NODE (ip4_dpi_bypass_node) = {
  .function = ip4_dpi_bypass,
  .name = "ip4-dpi-bypass",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP_DPI_N_NEXT,
  .next_nodes = {
    [IP_DPI_NEXT_DROP] = "error-drop",
    [IP_DPI_NEXT_DPI] = "dpi-scan",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_forward_next_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_dpi_bypass_node,ip4_dpi_bypass)

/* Dummy init function to get us linked in. */
clib_error_t * ip4_dpi_init (vlib_main_t * vm)
{ return 0; }

VLIB_INIT_FUNCTION (ip4_dpi_init);

static uword
ip6_dpi_bypass (vlib_main_t * vm,
		              vlib_node_runtime_t * node,
		              vlib_frame_t * frame)
{
  return ip_dpi_inline (vm, node, frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (ip6_dpi_bypass_node) = {
  .function = ip6_dpi_bypass,
  .name = "ip6-dpi-bypass",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP_DPI_N_NEXT,
  .next_nodes = {
    [IP_DPI_NEXT_DROP] = "error-drop",
    [IP_DPI_NEXT_DPI] = "dpi-scan",
  },

  .format_buffer = format_ip6_header,
  .format_trace = format_ip6_forward_next_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_dpi_bypass_node,ip6_dpi_bypass)

always_inline uword
dpi_scan (vlib_main_t * vm,
                vlib_node_runtime_t * node,
                vlib_frame_t * from_frame)
{
  dpi_main_t *hsm = &dpi_main;
  u32 n_left_from, next_index, *from, *to_next;
  //dpi_main_t * hsm = &dpi_main;
  u32 pkts_scanned = 0;
  u32 stats_n_packets, stats_n_bytes;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0 = DPI_SCAN_NEXT_INTERFACE;
          char * p0;
          u32 error0 = 0, len0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          /* Current_data pointing at the header that need to be scanned */
          b0 = vlib_get_buffer (vm, bi0);
          p0 = vlib_buffer_get_current (b0);
          len0 = vlib_buffer_length_in_chain (vm, b0);

          /* Issue a call to hs_scan, which will search the packet
           * for the pattern represented in the database.
           */
          if (hs_scan(hsm->db_block, p0, len0, 0, hsm->scratch, NULL,
                      hsm->pattern) != HS_SUCCESS) {
              next0 = DPI_SCAN_NEXT_DROP;
              error0 = DPI_ERROR_SCAN_FAIL;
              goto exit0;
          }

          vnet_buffer(b0)->sw_if_index[VLIB_TX] =
                      vnet_buffer(b0)->sw_if_index[VLIB_RX];

          pkts_scanned++;
          stats_n_packets += 1;
          stats_n_bytes += len0;

        exit0:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              dpi_rx_trace_t *tr = vlib_add_trace (vm, node, b0,
                                                         sizeof(*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->dpi_id = 0;
            }
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, dpi_scan_node.index, 0,
                               pkts_scanned);


  return from_frame->n_vectors;
}

static char * dpi_error_strings[] = {
#define _(n,s) s,
    foreach_dpi_error
#undef dpi_error
#undef _
};

VLIB_REGISTER_NODE (dpi_scan_node) = {
  .function = dpi_scan,
  .name = "dpi-scan",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = DPI_ERROR_N_ERROR,
  .error_strings = dpi_error_strings,

  .n_next_nodes = DPI_SCAN_N_NEXT,
  .next_nodes = {
#define _(s,n) [DPI_SCAN_NEXT_##s] = n,
    foreach_dpi_scan_next
#undef _
  },

//temp  .format_buffer = format_dpi_header,
  .format_trace = format_dpi_rx_trace,
  // $$$$ .unformat_buffer = unformat_dpi_header,
};

VLIB_NODE_FUNCTION_MULTIARCH (dpi_scan_node, dpi_scan)

/* Dummy init function to get us linked in. */
clib_error_t * ip6_dpi_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip6_dpi_init);
