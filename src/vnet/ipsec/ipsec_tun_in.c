/*
 * ipsec_tun_protect_in.c : IPSec interface input node
 *
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
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ipsec_io.h>
#include <vnet/ipsec/ipsec_punt.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipsec/ipsec.api_enum.h>
#include <vnet/ip/ip4_input.h>

typedef vl_counter_ipsec_tun_enum_t ipsec_tun_protect_input_error_t;

typedef enum ipsec_tun_next_t_
{
#define _(v, s) IPSEC_TUN_PROTECT_NEXT_##v,
  foreach_ipsec_input_next
#undef _
    IPSEC_TUN_PROTECT_N_NEXT,
} ipsec_tun_next_t;

typedef struct
{
  union
  {
    ipsec4_tunnel_kv_t kv4;
    ipsec6_tunnel_kv_t kv6;
  };
  u8 is_ip6;
  u32 seq;
} ipsec_tun_protect_input_trace_t;

static u8 *
format_ipsec_tun_protect_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_tun_protect_input_trace_t *t =
    va_arg (*args, ipsec_tun_protect_input_trace_t *);

  if (t->is_ip6)
    s = format (s, "IPSec: %U seq %u",
		format_ipsec6_tunnel_kv, &t->kv6, t->seq);
  else
    s = format (s, "IPSec: %U seq %u sa %d",
		format_ipsec4_tunnel_kv, &t->kv4, t->seq);
  return s;
}

always_inline u16
ipsec_ip4_if_no_tunnel (vlib_node_runtime_t * node,
			vlib_buffer_t * b,
			const esp_header_t * esp, const ip4_header_t * ip4)
{
  if (PREDICT_FALSE (0 == esp->spi))
    {
      b->error = node->errors[IPSEC_TUN_ERROR_SPI_0];
      b->punt_reason = ipsec_punt_reason[(ip4->protocol == IP_PROTOCOL_UDP ?
					  IPSEC_PUNT_IP4_SPI_UDP_0 :
					  IPSEC_PUNT_IP4_NO_SUCH_TUNNEL)];
    }
  else
    {
      b->error = node->errors[IPSEC_TUN_ERROR_NO_TUNNEL];
      b->punt_reason = ipsec_punt_reason[IPSEC_PUNT_IP4_NO_SUCH_TUNNEL];
    }
  return VNET_DEVICE_INPUT_NEXT_PUNT;
}

always_inline u16
ipsec_ip6_if_no_tunnel (vlib_node_runtime_t *node, vlib_buffer_t *b,
			const esp_header_t *esp, const ip6_header_t *ip6)
{
  if (PREDICT_FALSE (0 == esp->spi))
    {
      b->error = node->errors[IPSEC_TUN_ERROR_SPI_0];
      b->punt_reason = ipsec_punt_reason[(ip6->protocol == IP_PROTOCOL_UDP ?
						  IPSEC_PUNT_IP6_SPI_UDP_0 :
						  IPSEC_PUNT_IP6_NO_SUCH_TUNNEL)];
    }
  else
    {
      b->error = node->errors[IPSEC_TUN_ERROR_NO_TUNNEL];
      b->punt_reason = ipsec_punt_reason[IPSEC_PUNT_IP6_NO_SUCH_TUNNEL];
    }

  return VNET_DEVICE_INPUT_NEXT_PUNT;
}

always_inline uword
ipsec_tun_protect_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * from_frame, int is_ip6)
{
  ipsec_main_t *im = &ipsec_main;
  vnet_main_t *vnm = im->vnet_main;
  vnet_interface_main_t *vim = &vnm->interface_main;

  int is_trace = node->flags & VLIB_NODE_FLAG_TRACE;
  u32 thread_index = vm->thread_index;

  u32 n_left_from, *from;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  clib_memset_u16 (
    nexts, is_ip6 ? im->esp6_decrypt_next_index : im->esp4_decrypt_next_index,
    n_left_from);

  u64 n_bytes = 0, n_packets = 0;
  u32 n_disabled = 0, n_no_tunnel = 0;

  u32 last_sw_if_index = ~0;
  ipsec_tun_lkup_result_t last_result = {
    .tun_index = ~0
  };
  ipsec4_tunnel_kv_t last_key4;
  ipsec6_tunnel_kv_t last_key6;
  ipsec_tun_lkup_result_t itr0;

  vlib_combined_counter_main_t *rx_counter;
  vlib_combined_counter_main_t *drop_counter;

  if (is_ip6)
    clib_memset (&last_key6, 0xff, sizeof (last_key6));
  else
    last_key4.key = ~0;

  rx_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;
  drop_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_DROP;

  while (n_left_from > 0)
    {
      u32 sw_if_index0, len0, hdr_sz0;
      clib_bihash_kv_24_16_t bkey60 = { 0 };
      clib_bihash_kv_8_16_t bkey40 = { 0 };
      ipsec4_tunnel_kv_t *key40;
      ipsec6_tunnel_kv_t *key60;
      ip4_header_t *ip40;
      ip6_header_t *ip60;
      esp_header_t *esp0;
      u16 buf_rewind0;

      ip40 =
	(ip4_header_t *) (b[0]->data + vnet_buffer (b[0])->l3_hdr_offset);

      key60 = (ipsec6_tunnel_kv_t *) & bkey60;
      key40 = (ipsec4_tunnel_kv_t *) & bkey40;

      if (is_ip6)
	{
	  ip60 = (ip6_header_t *) ip40;
	  if (ip60->protocol == IP_PROTOCOL_UDP)
	    {
	      /* NAT UDP port 4500 case, don't advance any more */
	      esp0 = (esp_header_t *) ((u8 *) ip60 + sizeof (ip6_header_t) +
				       sizeof (udp_header_t));
	      hdr_sz0 = 0;
	      buf_rewind0 = sizeof (ip6_header_t) + sizeof (udp_header_t);

	      const udp_header_t *udp0 =
		(udp_header_t *) ((u8 *) ip60 + sizeof (ip6_header_t));

	      /* length 9 = sizeof(udp_header) + 1 byte of special SPI */
	      if (clib_net_to_host_u16 (udp0->length) == 9 &&
		  esp0->spi_bytes[0] == 0xff)
		{
		  b[0]->error = node->errors[IPSEC_TUN_ERROR_NAT_KEEPALIVE];

		  next[0] = VNET_DEVICE_INPUT_NEXT_IP6_DROP;
		  len0 = 0;

		  vlib_buffer_advance (b[0], -buf_rewind0);
		  goto trace00;
		}
	    }
	  else
	    {
	      esp0 = (esp_header_t *) (ip60 + 1);
	      buf_rewind0 = hdr_sz0 = sizeof (ip6_header_t);
	    }
	}
      else
	{
	  if (ip40->protocol == IP_PROTOCOL_UDP)
	    {
	      /* NAT UDP port 4500 case, don't advance any more */
	      esp0 =
		(esp_header_t *) ((u8 *) ip40 + ip4_header_bytes (ip40) +
				  sizeof (udp_header_t));
	      hdr_sz0 = 0;
	      buf_rewind0 = ip4_header_bytes (ip40) + sizeof (udp_header_t);

	      const udp_header_t *udp0 =
		(udp_header_t *) ((u8 *) ip40 + ip4_header_bytes (ip40));

	      /* length 9 = sizeof(udp_header) + 1 byte of special SPI */
	      if (clib_net_to_host_u16 (udp0->length) == 9 &&
		  esp0->spi_bytes[0] == 0xff)
		{
		  b[0]->error = node->errors[IPSEC_TUN_ERROR_NAT_KEEPALIVE];

		  next[0] = VNET_DEVICE_INPUT_NEXT_IP4_DROP;
		  len0 = 0;

		  vlib_buffer_advance (b[0], -buf_rewind0);
		  goto trace00;
		}
	    }
	  else
	    {
	      esp0 = (esp_header_t *) ((u8 *) ip40 + ip4_header_bytes (ip40));
	      buf_rewind0 = hdr_sz0 = ip4_header_bytes (ip40);
	    }
	}

      /* stats for the tunnel include all the data after the IP header
         just like a norml IP-IP tunnel */
      vlib_buffer_advance (b[0], hdr_sz0);
      len0 = vlib_buffer_length_in_chain (vm, b[0]);

      if (len0 < sizeof (esp_header_t))
	{
	  b[0]->error = node->errors[IPSEC_TUN_ERROR_TOO_SHORT];

	  next[0] = is_ip6 ? VNET_DEVICE_INPUT_NEXT_IP6_DROP :
			     VNET_DEVICE_INPUT_NEXT_IP4_DROP;
	  vlib_buffer_advance (b[0], -buf_rewind0);
	  goto trace00;
	}

      if (is_ip6)
	{
	  key60->key.remote_ip = ip60->src_address;
	  key60->key.spi = esp0->spi;
	  key60->key.__pad = 0;

	  if (memcmp (key60, &last_key6, sizeof (last_key6)) == 0)
	    {
	      clib_memcpy_fast (&itr0, &last_result, sizeof (itr0));
	    }
	  else
	    {
	      int rv =
		clib_bihash_search_inline_24_16 (&im->tun6_protect_by_key,
						 &bkey60);
	      if (!rv)
		{
		  clib_memcpy_fast (&itr0, &bkey60.value, sizeof (itr0));
		  clib_memcpy_fast (&last_result, &bkey60.value,
				    sizeof (last_result));
		  clib_memcpy_fast (&last_key6, key60, sizeof (last_key6));
		}
	      else
		{
		  next[0] = ipsec_ip6_if_no_tunnel (node, b[0], esp0, ip60);
		  vlib_buffer_advance (b[0], -buf_rewind0);
		  n_no_tunnel++;
		  goto trace00;
		}
	    }
	}
      else
	{
	  ipsec4_tunnel_mk_key (key40, &ip40->src_address, esp0->spi);

	  if (key40->key == last_key4.key)
	    {
	      clib_memcpy_fast (&itr0, &last_result, sizeof (itr0));
	    }
	  else
	    {
	      int rv =
		clib_bihash_search_inline_8_16 (&im->tun4_protect_by_key,
						&bkey40);
	      if (!rv)
		{
		  clib_memcpy_fast (&itr0, &bkey40.value, sizeof (itr0));
		  clib_memcpy_fast (&last_result, &bkey40.value,
				    sizeof (last_result));
		  last_key4.key = key40->key;
		}
	      else
		{
		  next[0] = ipsec_ip4_if_no_tunnel (node, b[0], esp0, ip40);
		  vlib_buffer_advance (b[0], -buf_rewind0);
		  n_no_tunnel++;
		  goto trace00;
		}
	    }
	}

      vnet_buffer (b[0])->ipsec.sad_index = itr0.sa_index;
      vnet_buffer (b[0])->ipsec.protect_index = itr0.tun_index;

      sw_if_index0 = itr0.sw_if_index;
      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = sw_if_index0;

      if (PREDICT_FALSE (!vnet_sw_interface_is_admin_up (vnm, sw_if_index0)))
	{
	  vlib_increment_combined_counter
	    (drop_counter, thread_index, sw_if_index0, 1, len0);
	  n_disabled++;
	  b[0]->error = node->errors[IPSEC_TUN_ERROR_DISABLED];
	  next[0] = is_ip6 ? VNET_DEVICE_INPUT_NEXT_IP6_DROP :
			     VNET_DEVICE_INPUT_NEXT_IP4_DROP;
	  goto trace00;
	}
      else
	{
	  if (PREDICT_TRUE (sw_if_index0 == last_sw_if_index))
	    {
	      n_packets++;
	      n_bytes += len0;
	    }
	  else
	    {
	      if (n_packets && !(itr0.flags & IPSEC_PROTECT_ENCAPED))
		{
		  vlib_increment_combined_counter
		    (rx_counter, thread_index, last_sw_if_index,
		     n_packets, n_bytes);
		}

	      last_sw_if_index = sw_if_index0;
	      n_packets = 1;
	      n_bytes = len0;
	    }

	  //IPSEC_TUN_PROTECT_NEXT_DECRYPT;
	  next[0] = is_ip6 ? im->esp6_decrypt_tun_next_index :
			     im->esp4_decrypt_tun_next_index;

	  if (itr0.flags & IPSEC_PROTECT_FEAT)
	    {
	      u32 next32;
	      u8 arc = feature_main.device_input_feature_arc_index;

	      next32 = next[0];
	      vnet_feature_arc_start (arc, sw_if_index0, &next32, b[0]);
	      next[0] = next32;
	    }
	}
    trace00:
      if (PREDICT_FALSE (is_trace))
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ipsec_tun_protect_input_trace_t *tr =
		vlib_add_trace (vm, node, b[0], sizeof (*tr));
	      if (is_ip6)
		clib_memcpy (&tr->kv6, &bkey60, sizeof (tr->kv6));
	      else
		clib_memcpy (&tr->kv4, &bkey40, sizeof (tr->kv4));
	      tr->is_ip6 = is_ip6;
	      tr->seq = (len0 >= sizeof (*esp0) ?
			 clib_host_to_net_u32 (esp0->seq) : ~0);
	    }
	}

      /* next */
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  if (n_packets && !(itr0.flags & IPSEC_PROTECT_ENCAPED))
    vlib_increment_combined_counter (rx_counter,
				     thread_index,
				     last_sw_if_index, n_packets, n_bytes);

  vlib_node_increment_counter (vm, node->node_index, IPSEC_TUN_ERROR_RX,
			       from_frame->n_vectors -
				 (n_disabled + n_no_tunnel));
  vlib_node_increment_counter (vm, node->node_index, IPSEC_TUN_ERROR_NO_TUNNEL,
			       n_no_tunnel);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (ipsec4_tun_input_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return ipsec_tun_protect_input_inline (vm, node, from_frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec4_tun_input_node) = {
  .name = "ipsec4-tun-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_tun_protect_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = IPSEC_TUN_N_ERROR,
  .error_counters = ipsec_tun_error_counters,
  .sibling_of = "device-input",
};
/* *INDENT-ON* */

VLIB_NODE_FN (ipsec6_tun_input_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return ipsec_tun_protect_input_inline (vm, node, from_frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec6_tun_input_node) = {
  .name = "ipsec6-tun-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_tun_protect_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = IPSEC_TUN_N_ERROR,
  .error_counters = ipsec_tun_error_counters,
  .sibling_of = "device-input",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
