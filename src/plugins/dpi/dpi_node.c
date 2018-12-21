/*
 * Copyright (c) 2019 Intel and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/dlist.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/flow/flow.h>
#include <vnet/tcp/tcp_packet.h>

#include <dpi/dpi.h>

vlib_node_registration_t dpi4_input_node;
vlib_node_registration_t dpi6_input_node;
vlib_node_registration_t dpi4_flow_input_node;
vlib_node_registration_t dpi6_flow_input_node;


#define foreach_dpi_input_error \
 _(NONE, "no error") \
 _(NO_SUCH_FLOW, "flow not existed")

typedef enum
{
#define _(sym,str) DPI_INPUT_ERROR_##sym,
  foreach_dpi_input_error
#undef _
    DPI_INPUT_N_ERROR,
} dpi_input_error_t;

static char *dpi_input_error_strings[] = {
#define _(sym,string) string,
  foreach_dpi_input_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 flow_id;
  u32 app_id;
  u32 error;
} dpi_rx_trace_t;

/* *INDENT-OFF* */
VNET_FEATURE_INIT (dpi4_input, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "dpi4-input",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (dpi6_input, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "dpi6-input",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
/* *INDENT-on* */

static u8 *
format_dpi_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dpi_rx_trace_t *t = va_arg (*args, dpi_rx_trace_t *);

  if (t->flow_id == ~0)
    return format (s, "DPI error - flow %d does not exist",
           t->flow_id);

  return format (s, "DPI from flow %d app_id %d next %d error %d",
         t->flow_id, t->app_id, t->next_index, t->error);
}



static inline void
parse_ip4_packet_and_lookup (ip4_header_t * ip4, u32 fib_index,
                             dpi4_flow_key_t * key4,
                             int * not_found, u64 * flow_id)
{
  dpi_main_t *dm = &dpi_main;
  u8 protocol = ip4_is_fragment (ip4) ? 0xfe : ip4->protocol;
  u16 src_port = 0;
  u16 dst_port = 0;

  key4->key[0] = ip4->src_address.as_u32 | (((u64) ip4->dst_address.as_u32)<<32);

  if (protocol == IP_PROTOCOL_UDP || protocol == IP_PROTOCOL_TCP)
    {
      /* tcp and udp ports have the same offset */
      udp_header_t * udp = ip4_next_header(ip4);
      src_port = udp->src_port;
      dst_port = udp->dst_port;
    }

  key4->key[1] = (((u64) protocol) << 32)
                | ((u32) src_port << 16)
                | dst_port;
  key4->key[2] = (u64) fib_index;

  key4->value = ~0;
  *not_found = clib_bihash_search_inline_24_8 (&dm->dpi4_flow_by_key, key4);
  *flow_id = key4->value;
}

static inline void
parse_ip6_packet_and_lookup (ip6_header_t * ip6, u32 fib_index,
                             dpi6_flow_key_t * key6,
                             int * not_found, u64 * flow_id)
{
  dpi_main_t *dm = &dpi_main;
  u8 protocol = ip6->protocol;
  u16 src_port = 0;
  u16 dst_port = 0;

  key6->key[0] = ip6->src_address.as_u64[0];
  key6->key[1] = ip6->src_address.as_u64[1];
  key6->key[2] = ip6->dst_address.as_u64[0];
  key6->key[3] = ip6->dst_address.as_u64[1];

  if (protocol == IP_PROTOCOL_UDP || protocol == IP_PROTOCOL_TCP)
    {
      /* tcp and udp ports have the same offset */
      udp_header_t * udp = ip6_next_header(ip6);
      src_port = udp->src_port;
      dst_port = udp->dst_port;
    }

  key6->key[4] = (((u64) protocol) << 32)
                    | ((u32) src_port << 16)
                    | dst_port;
  key6->key[5] = (u64) fib_index;

  key6->value = ~0;
  *not_found = clib_bihash_search_inline_48_8 (&dm->dpi6_flow_by_key, key6);
  *flow_id = key6->value;
}

static inline void
dpi_trim_overlap(u32 left_sn, segment *seg)
{
  int overlap_len;

  overlap_len = left_sn - seg->send_sn;
  /* trim leading overlap bytes */
  seg->data += overlap_len;
  seg->len -= overlap_len;
  seg->send_sn += overlap_len;

  /* trim the right overlap bytes */
  if( seg->next
      && (seg->send_sn+seg->len) > (seg->next->send_sn) )
    {
      overlap_len = (seg->send_sn+seg->len) - (seg->next->send_sn);
      if(seg->len > overlap_len)
        {
          seg->len -= overlap_len;
        }
    }
}

/*
 * re-order out-of-order segments, and handle overlap segments.
 * */
static inline void
dpi_handle_tcp_segments (dpi_flow_entry_t *flow, tcp_stream_t *stream,
                         u32 bi, u8 *pkt, u32 payload_len)
{
  dpi_main_t *dm = &dpi_main;
  u32 send_sn;
  u32 ack_sn;
  u32 next_sn;
  u32 left_sn;
  segment *first_seg = 0;
  segment *seg = 0;
  segment *new_seg = 0;
  tcp_header_t *tcp = (tcp_header_t *)pkt;
  u8 *payload = pkt + tcp_doff(tcp) * 4;

  if((tcp->flags & TCP_FLAG_ACK) == TCP_FLAG_ACK)
    {
      ack_sn = clib_net_to_host_u32(tcp->ack_number);
      if(ack_sn != stream->ack_sn)
        {
          stream->ack_sn = ack_sn;
        }
    }

  send_sn = clib_net_to_host_u32(tcp->seq_number);
  next_sn = send_sn + payload_len;

  /* Handle fully overlapping segments */
  if(SN_GT(stream->send_sn, next_sn))
    {
      flow->consumed = 1;
      return;
    }

  if(SN_LT(stream->send_sn, send_sn))
    {
      /* Store out-of-order segments to segment queue */
      for(seg=stream->seg_queue; seg; seg=seg->next)
        {
          if (send_sn < seg->send_sn )
            break;
        }

      pool_get_aligned (dm->seg_pool, new_seg, CLIB_CACHE_LINE_BYTES);
      new_seg->bi = bi;
      new_seg->send_sn = send_sn;
      new_seg->data = payload;
      new_seg->len = payload_len;

      /* Insert new segment to right position of segment queue */
      if(seg == stream->seg_queue)
        {
          new_seg->next = stream->seg_queue;
          stream->seg_queue = new_seg;
          stream->send_sn = seg->send_sn;
          left_sn = stream->send_sn;
        }
      else
        {
          new_seg->next = seg->next;
          seg->next = new_seg;
          left_sn = seg->send_sn;
        }

      /* trim overlapped packet */
      dpi_trim_overlap(left_sn, new_seg);

      flow->consumed = 1;
    }
  else
    {
      pool_get_aligned(dm->seg_pool, first_seg, CLIB_CACHE_LINE_BYTES);
      first_seg->bi = bi;
      first_seg->send_sn = send_sn;
      first_seg->data = payload;
      first_seg->len = payload_len;
      first_seg->next = stream->seg_queue;

      /* trim overlapped packet */
      dpi_trim_overlap (stream->send_sn, first_seg);

      /* reassemble continuous segments and move forward to scan */
      for (seg = first_seg; seg->next; seg = seg->next)
        {
          if (seg->send_sn + seg->len != seg->next->send_sn)
            break;
        }

      /* left non-continuous segments */
      stream->seg_queue = seg->next;
      stream->send_sn = seg->send_sn + seg->len;

      flow->first_seg = first_seg;
      seg->next = 0;

      /* scan ordered segments */
      for (seg = first_seg; seg; seg = seg->next)
        {
          /* detect layer 7 application for single segment */
          dpi_detect_application (seg->data, seg->len, flow->info);
          if(flow->info->detect_done)
            break;
        }
    }
}

static inline int
dpi_free_segment_queue(vlib_main_t * vm, segment *seg)
{
  segment *tmp;

  while (seg)
    {
      tmp = seg->next;
      vlib_buffer_free_one (vm, seg->bi);
      seg = tmp;
    }

  return (0);
}

static inline int
dpi_handle_tcp_stream (dpi_flow_entry_t *flow, u32 bi,
                       u8 *pkt, u32 payload_len, u8 is_reverse)
{
  tcp_header_t *tcp;
  tcp_stream_t *stream;

  tcp = (tcp_header_t *)pkt;
  if((tcp->flags & (TCP_FLAG_SYN|TCP_FLAG_ACK)) == TCP_FLAG_SYN)
    {
      flow->c2s.send_sn = clib_net_to_host_u32(tcp->seq_number) + 1;
      flow->pkt_dir = DIR_C2S;
      flow->forward_is_c2s = !is_reverse;
      flow->tcp_state = TCP_STATE_SYN;
    }
  else
    {
      /*
        forward_is_c2s | is_reverse
                          0          1
        0                s2c(1)     c2s(0)
        1                c2s(0)     s2c(1)
      */
      flow->pkt_dir = (flow->forward_is_c2s == is_reverse);
    }

  switch(flow->tcp_state)
  {
    case TCP_STATE_SYN:
      {
        if(flow->pkt_dir != DIR_S2C)
          break;

        if((tcp->flags & (TCP_FLAG_SYN|TCP_FLAG_ACK))
              != (TCP_FLAG_SYN|TCP_FLAG_ACK))
          break;

        flow->s2c.send_sn = clib_net_to_host_u32(tcp->seq_number) + 1;
        flow->s2c.ack_sn = clib_net_to_host_u32(tcp->ack_number) + 1;
        flow->tcp_state = TCP_STATE_SYN_ACK;
        break;
      }

    case TCP_STATE_SYN_ACK:
      {
        if(flow->pkt_dir != DIR_C2S)
          break;

        flow->c2s.ack_sn = clib_net_to_host_u32(tcp->ack_number) + 1;
        flow->tcp_state = TCP_STATE_ESTABLISH;
        break;
      }

    case TCP_STATE_ACK:
    case TCP_STATE_ESTABLISH:
    case TCP_STATE_FIN1:
      {
        stream = (flow->pkt_dir == DIR_C2S)? &(flow->c2s) : &(flow->s2c);
        if( (flow->reass_dir == REASS_BOTH)
            || ((flow->pkt_dir==DIR_C2S) && (flow->reass_dir==REASS_C2S))
            || ((flow->pkt_dir==DIR_S2C) && (flow->reass_dir==REASS_S2C)) )
          {
            dpi_handle_tcp_segments(flow, stream, bi, pkt, payload_len);
          }

        break;
      }

    case TCP_STATE_CLOSE:
      {
        /* Free all segments in the queue */
        break;
      }
  }

  return 0;
}

void
dpi_detect_application (u8 *payload, u32 payload_len,
                        dpi_flow_info_t *flow)
{

  /* detect if payload is SSL's payload for default port */
  dpi_search_tcp_ssl(payload, payload_len, flow);

  /* TBD: add detect if is SSL's payload with non default port*/

}

always_inline uword
dpi_input_inline (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame, u32 is_ip4)
{
  dpi_main_t *dm = &dpi_main;
  u32 *from, *to_next, n_left_from, n_left_to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0, next0 = 0;
      vlib_buffer_t *b0;
      ip4_header_t *ip40;
      ip6_header_t *ip60;
      tcp_header_t *tcp0;
      udp_header_t *udp0;
      dpi4_flow_key_t key40;
      dpi6_flow_key_t key60;
      u32 fib_index0 = ~0;
      u64 flow_id0 = ~0;
      u32 flow_index0 = ~0;
      int not_found0 = 0;
      u8 is_reverse0 = 0;
      dpi_flow_entry_t *flow0;
      u32 ip_len0, l4_len0, payload_len0;
      u8 protocol0;
      u8 *l4_pkt0, *payload0;
      u16 dst_port = 0;
      segment *seg = 0;
      segment *prev_seg = 0;

      bi0 = to_next[0] = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      ip_len0 = vlib_buffer_length_in_chain (vm, b0);

      if (is_ip4)
        {
          ip40 = vlib_buffer_get_current (b0);
          ip4_main_t *im4 = &ip4_main;
          fib_index0 = vec_elt (im4->fib_index_by_sw_if_index,
                                vnet_buffer(b0)->sw_if_index[VLIB_RX]);
          parse_ip4_packet_and_lookup(ip40, fib_index0, &key40,
                                      &not_found0, &flow_id0);
        }
      else
        {
          ip60 = vlib_buffer_get_current (b0);
          ip6_main_t *im6 = &ip6_main;
          fib_index0 = vec_elt (im6->fib_index_by_sw_if_index,
                                vnet_buffer(b0)->sw_if_index[VLIB_RX]);
          parse_ip6_packet_and_lookup(ip60, fib_index0, &key60,
                                      &not_found0, &flow_id0);
        }

      if(not_found0)
        {
          /* TBD: create new flow entry dynamically */
        }

      is_reverse0 = (u8)((flow_id0 >> 63) & 0x1);
      flow_index0 = (u32)(flow_id0 & (u32)(~0));
      flow0 = pool_elt_at_index (dm->dpi_flows, flow_index0);

      /* have detected successfully, directly return */
      if(flow0->info->detect_done)
          goto enqueue0;

      /* check layer4 */
      if (is_ip4)
        {
          l4_pkt0 = (u8 *)(ip40 + 1);
          l4_len0 = ip_len0 - sizeof(ip4_header_t);
          protocol0 = ip40->protocol;
        }
      else
        {
          l4_pkt0 = (u8 *)(ip60 + 1);
          l4_len0 = ip_len0 - sizeof(ip6_header_t);
          protocol0 = ip60->protocol;
        }

      if((protocol0 == IP_PROTOCOL_TCP) && (l4_len0 >= 20))
        {
          tcp0 = (tcp_header_t *)l4_pkt0;
          payload_len0 = l4_len0 - tcp_doff(tcp0) * 4;
          payload0 = l4_pkt0 + tcp_doff(tcp0) * 4;
          dst_port = tcp0->dst_port;
        }
      else if ((protocol0 == IP_PROTOCOL_UDP) && (l4_len0 >= 8))
        {
          udp0 = (udp_header_t *)l4_pkt0;
          payload_len0 = l4_len0 - sizeof(udp_header_t);
          payload0 = l4_pkt0 + sizeof(udp_header_t);
          dst_port = udp0->dst_port;
        }
      else
        {
          payload_len0 = l4_len0;
          payload0 = l4_pkt0;
        }

      flow0->info->l4_protocol = protocol0;
      flow0->info->dst_port = dst_port;

      /* TCP stream reassembly and detect a protocol pdu */
      if((protocol0 == IP_PROTOCOL_TCP) && (flow0->reass_en))
        {
          dpi_handle_tcp_stream(flow0, bi0, l4_pkt0, payload_len0, is_reverse0);

          /* This packet has been consumed, retrieve next packet */
          if(flow0->consumed)
            goto trace0;

          /* send out continuous scanned segments */
          seg=flow0->first_seg;
          dpi_enqueue_tcp_segments(seg,vm,node,next_index,to_next,n_left_to_next,bi0,next0);
          flow0->first_seg = 0;

          /* Here detected successfully, send out remaining segments in seg_queue */
          if(flow0->info->detect_done)
            {
              seg=flow0->c2s.seg_queue;
              dpi_enqueue_tcp_segments(seg,vm,node,next_index,to_next,n_left_to_next,bi0,next0);
              flow0->c2s.seg_queue = 0;

              seg=flow0->s2c.seg_queue;
              dpi_enqueue_tcp_segments(seg,vm,node,next_index,to_next,n_left_to_next,bi0,next0);
              flow0->s2c.seg_queue = 0;
            }
          goto trace0;
        }
      else
        {
          /* detect layer 7 application for single packet */
          dpi_detect_application (payload0, payload_len0, flow0->info);
        }

enqueue0:
      to_next[0] = bi0;
      to_next++;
      n_left_to_next--;
      next0 = flow0->next_index;
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                       to_next, n_left_to_next,
                       bi0, next0);

trace0:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
        {
          dpi_rx_trace_t *tr
            = vlib_add_trace (vm, node, b0, sizeof (*tr));
          tr->app_id = flow0->info->app_id;
          tr->next_index = next0;
          tr->error = b0->error;
          tr->flow_id = flow_index0;
        }

      from += 1;
      n_left_from -= 1;
    }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (dpi4_input_node) (vlib_main_t * vm,
                      vlib_node_runtime_t * node,
                      vlib_frame_t * frame)
{
  return dpi_input_inline (vm, node, frame, /* is_ip4 */ 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpi4_input_node) =
{
  .name = "dpi4-input",
  .vector_size = sizeof (u32),
  .n_errors = DPI_INPUT_N_ERROR,
  .error_strings = dpi_input_error_strings,
  .n_next_nodes = DPI_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [DPI_INPUT_NEXT_##s] = n,
    foreach_dpi_input_next
#undef _
  },
  .format_trace = format_dpi_rx_trace,
};

/* *INDENT-ON* */

/* Dummy init function to get us linked in. */
static clib_error_t *
dpi4_input_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (dpi4_input_init);


VLIB_NODE_FN (dpi6_input_node) (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return dpi_input_inline (vm, node, frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpi6_input_node) =
{
  .name = "dpi6-input",
  .vector_size = sizeof (u32),
  .n_errors = DPI_INPUT_N_ERROR,
  .error_strings = dpi_input_error_strings,
  .n_next_nodes = DPI_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [DPI_INPUT_NEXT_##s] = n,
    foreach_dpi_input_next
#undef _
  },
  .format_trace = format_dpi_rx_trace,
};
/* *INDENT-ON* */

/* Dummy init function to get us linked in. */
static clib_error_t *
dpi6_input_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (dpi6_input_init);



#define foreach_dpi_flow_input_next        \
_(DROP, "error-drop")                      \
_(IP4_LOOKUP, "ip4-lookup")

typedef enum
{
#define _(s,n) DPI_FLOW_NEXT_##s,
  foreach_dpi_flow_input_next
#undef _
    DPI_FLOW_N_NEXT,
} dpi_flow_input_next_t;

#define foreach_dpi_flow_error                    \
  _(NONE, "no error")                           \
  _(IP_CHECKSUM_ERROR, "Rx ip checksum errors")             \
  _(IP_HEADER_ERROR, "Rx ip header errors")             \
  _(UDP_CHECKSUM_ERROR, "Rx udp checksum errors")               \
  _(UDP_LENGTH_ERROR, "Rx udp length errors")

typedef enum
{
#define _(f,s) DPI_FLOW_ERROR_##f,
  foreach_dpi_flow_error
#undef _
    DPI_FLOW_N_ERROR,
} dpi_flow_error_t;

static char *dpi_flow_error_strings[] = {
#define _(n,s) s,
  foreach_dpi_flow_error
#undef _
};

static_always_inline u8
dpi_check_ip4 (ip4_header_t * ip4, u16 payload_len)
{
  u16 ip_len = clib_net_to_host_u16 (ip4->length);
  return ip_len > payload_len || ip4->ttl == 0
    || ip4->ip_version_and_header_length != 0x45;
}

static_always_inline u8
dpi_check_ip6 (ip6_header_t * ip6, u16 payload_len)
{
  u16 ip_len = clib_net_to_host_u16 (ip6->payload_length);
  return ip_len > (payload_len - sizeof (ip6_header_t))
    || ip6->hop_limit == 0
    || (ip6->ip_version_traffic_class_and_flow_label >> 28) != 0x6;
}

always_inline uword
dpi_flow_input_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame, u32 is_ip4)
{
  dpi_main_t *dm = &dpi_main;
  u32 *from, *to_next, n_left_from, n_left_to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0 = DPI_FLOW_NEXT_IP4_LOOKUP;
	  vlib_buffer_t *b0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  tcp_header_t *tcp0;
	  udp_header_t *udp0;
	  u32 flow_id0 = ~0;
	  u32 flow_index0 = ~0;
	  u32 is_reverse0 = 0;
	  dpi_flow_entry_t *flow0;
	  u32 ip_len0, l4_len0, payload_len0;
	  u8 protocol0;
	  u8 *l4_pkt0, *payload0;
	  u16 dst_port = 0;
	  segment *seg = 0;
	  segment *prev_seg = 0;

	  bi0 = to_next[0] = from[0];
	  b0 = vlib_get_buffer (vm, bi0);
	  ip_len0 = vlib_buffer_length_in_chain (vm, b0);

	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      dpi_check_ip4 (ip40, ip_len0);
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      dpi_check_ip6 (ip60, ip_len0);
	    }

	  ASSERT (b0->flow_id != 0);
	  flow_id0 = b0->flow_id - dm->flow_id_start;

	  is_reverse0 = (u32) ((flow_id0 >> 31) & 0x1);
	  flow_index0 = (u32) (flow_id0 & (u32) (~(1 << 31)));
	  flow0 = pool_elt_at_index (dm->dpi_flows, flow_index0);

	  /* have detected successfully, directly return */
	  if (flow0->info->detect_done)
	    goto enqueue0;

	  /* check layer4 */
	  if (is_ip4)
	    {
	      l4_pkt0 = (u8 *) (ip40 + 1);
	      l4_len0 = ip_len0 - sizeof (ip4_header_t);
	      protocol0 = ip40->protocol;
	    }
	  else
	    {
	      l4_pkt0 = (u8 *) (ip60 + 1);
	      l4_len0 = ip_len0 - sizeof (ip6_header_t);
	      protocol0 = ip60->protocol;
	    }

	  if ((protocol0 == IP_PROTOCOL_TCP) && (l4_len0 >= 20))
	    {
	      tcp0 = (tcp_header_t *) l4_pkt0;
	      payload_len0 = l4_len0 - tcp_doff (tcp0) * 4;
	      payload0 = l4_pkt0 + tcp_doff (tcp0) * 4;
	      dst_port = tcp0->dst_port;
	    }
	  else if ((protocol0 == IP_PROTOCOL_UDP) && (l4_len0 >= 8))
	    {
	      udp0 = (udp_header_t *) l4_pkt0;
	      payload_len0 = l4_len0 - sizeof (udp_header_t);
	      payload0 = l4_pkt0 + sizeof (udp_header_t);
	      dst_port = udp0->dst_port;
	    }
	  else
	    {
	      payload_len0 = l4_len0;
	      payload0 = l4_pkt0;
	    }

	  flow0->info->l4_protocol = protocol0;
	  flow0->info->dst_port = dst_port;

	  /* TCP stream reassembly and detect a protocol pdu */
	  if ((protocol0 == IP_PROTOCOL_TCP) && (flow0->reass_en))
	    {
	      dpi_handle_tcp_stream (flow0, bi0, l4_pkt0, payload_len0,
				     is_reverse0);

	      /* This packet has been consumed, retrieve next packet */
	      if (flow0->consumed)
		goto trace0;

	      /* send out continuous scanned segments */
	      seg = flow0->first_seg;
	      dpi_enqueue_tcp_segments (seg, vm, node, next_index, to_next,
					n_left_to_next, bi0, next0);
	      flow0->first_seg = 0;

	      /* Here detected successfully, send out remaining segments in seg_queue */
	      if (flow0->info->detect_done)
		{
		  seg = flow0->c2s.seg_queue;
		  dpi_enqueue_tcp_segments (seg, vm, node, next_index,
					    to_next, n_left_to_next, bi0,
					    next0);
		  flow0->c2s.seg_queue = 0;

		  seg = flow0->s2c.seg_queue;
		  dpi_enqueue_tcp_segments (seg, vm, node, next_index,
					    to_next, n_left_to_next, bi0,
					    next0);
		  flow0->s2c.seg_queue = 0;
		}
	      goto trace0;
	    }
	  else
	    {
	      /* detect layer 7 application for single packet */
	      dpi_detect_application (payload0, payload_len0, flow0->info);
	    }

	enqueue0:
	  to_next[0] = bi0;
	  to_next++;
	  n_left_to_next--;
	  next0 = flow0->next_index;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);

	trace0:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      dpi_rx_trace_t *tr
		= vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->app_id = flow0->info->app_id;
	      tr->next_index = next0;
	      tr->error = b0->error;
	      tr->flow_id = flow_index0;
	    }

	  from += 1;
	  n_left_from -= 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}


VLIB_NODE_FN (dpi4_flow_input_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return dpi_flow_input_inline (vm, node, frame, /* is_ip4 */ 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpi4_flow_input_node) = {
  .name = "dpi4-flow-input",
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),

  .format_trace = format_dpi_rx_trace,

  .n_errors = DPI_FLOW_N_ERROR,
  .error_strings = dpi_flow_error_strings,

  .n_next_nodes = DPI_FLOW_N_NEXT,
  .next_nodes = {
#define _(s,n) [DPI_FLOW_NEXT_##s] = n,
    foreach_dpi_flow_input_next
#undef _
  },
};
/* *INDENT-ON* */

/* Dummy init function to get us linked in. */
static clib_error_t *
dpi4_flow_input_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (dpi4_flow_input_init);

VLIB_NODE_FN (dpi6_flow_input_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return dpi_flow_input_inline (vm, node, frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpi6_flow_input_node) = {
  .name = "dpi6-flow-input",
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),

  .format_trace = format_dpi_rx_trace,

  .n_errors = DPI_FLOW_N_ERROR,
  .error_strings = dpi_flow_error_strings,

  .n_next_nodes = DPI_FLOW_N_NEXT,
  .next_nodes = {
#define _(s,n) [DPI_FLOW_NEXT_##s] = n,
    foreach_dpi_flow_input_next
#undef _
  },
};
/* *INDENT-ON* */

/* Dummy init function to get us linked in. */
static clib_error_t *
dpi6_flow_input_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (dpi6_flow_input_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
