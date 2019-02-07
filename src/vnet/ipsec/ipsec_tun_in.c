/*
 * ipsec_if_in.c : IPSec interface input node
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

/* Statistics (not really errors) */
#define foreach_ipsec_if_input_error				  \
_(RX, "good packets received")					  \
_(DISABLED, "ipsec packets received on disabled interface")       \
_(NO_TUNNEL, "no matching tunnel")                                \
_(SPI_0, "SPI 0")

static char *ipsec_if_input_error_strings[] = {
#define _(sym,string) string,
  foreach_ipsec_if_input_error
#undef _
};

typedef enum
{
#define _(sym,str) IPSEC_IF_INPUT_ERROR_##sym,
  foreach_ipsec_if_input_error
#undef _
    IPSEC_IF_INPUT_N_ERROR,
} ipsec_if_input_error_t;


typedef struct
{
  u32 spi;
  u32 seq;
} ipsec_if_input_trace_t;

static u8 *
format_ipsec_if_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_if_input_trace_t *t = va_arg (*args, ipsec_if_input_trace_t *);

  s = format (s, "IPSec: spi %u seq %u", t->spi, t->seq);
  return s;
}

always_inline u16
ipsec_ip4_if_no_tunnel (vlib_node_runtime_t * node,
			vlib_buffer_t * b,
			const esp_header_t * esp,
			const ip4_header_t * ip4, u16 offset)
{
  if (PREDICT_FALSE (0 == esp->spi))
    {
      b->error = node->errors[IPSEC_IF_INPUT_ERROR_SPI_0];
      b->punt_reason =
	ipsec_punt_reason[(ip4->protocol == IP_PROTOCOL_UDP ?
			   IPSEC_PUNT_IP4_SPI_UDP_0 : IPSEC_PUNT_IP4_SPI_0)];
    }
  else
    {
      b->error = node->errors[IPSEC_IF_INPUT_ERROR_NO_TUNNEL];
      b->punt_reason = ipsec_punt_reason[IPSEC_PUNT_IP4_NO_SUCH_TUNNEL];
    }
  vlib_buffer_advance (b, -offset);
  return IPSEC_INPUT_NEXT_PUNT;
}

always_inline u16
ipsec_ip6_if_no_tunnel (vlib_node_runtime_t * node,
			vlib_buffer_t * b,
			const esp_header_t * esp, u16 offset)
{
  if (PREDICT_FALSE (0 == esp->spi))
    {
      b->error = node->errors[IPSEC_IF_INPUT_ERROR_NO_TUNNEL];
      b->punt_reason = ipsec_punt_reason[IPSEC_PUNT_IP6_SPI_0];
    }
  else
    {
      b->error = node->errors[IPSEC_IF_INPUT_ERROR_NO_TUNNEL];
      b->punt_reason = ipsec_punt_reason[IPSEC_PUNT_IP6_NO_SUCH_TUNNEL];
    }
  vlib_buffer_advance (b, -offset);
  return (IPSEC_INPUT_NEXT_PUNT);
}

always_inline uword
ipsec_if_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
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

  clib_memset_u16 (nexts, im->esp4_decrypt_next_index, n_left_from);

  u64 n_bytes = 0, n_packets = 0;
  u32 n_disabled = 0, n_no_tunnel = 0;

  u32 last_sw_if_index = ~0;
  u32 last_tunnel_id = ~0;
  ipsec4_tunnel_key_t last_key4;
  ipsec6_tunnel_key_t last_key6;

  vlib_combined_counter_main_t *rx_counter;
  vlib_combined_counter_main_t *drop_counter;

  if (is_ip6)
    clib_memset (&last_key6, 0xff, sizeof (last_key6));
  else
    last_key4.as_u64 = ~0;

  rx_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;
  drop_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_DROP;

  while (n_left_from > 0)
    {
      u32 sw_if_index0, len0, buf_adv0, iti0;
      ipsec4_tunnel_key_t key40;
      ipsec6_tunnel_key_t key60;
      ipsec_protect_t *itp0;
      ip4_header_t *ip40;
      ip6_header_t *ip60;
      esp_header_t *esp0;

      ip40 = vlib_buffer_get_current (b[0]);

      if (is_ip6)
	{
	  ip60 = (ip6_header_t *) ip40;
	  esp0 = (esp_header_t *) (ip60 + 1);
	  buf_adv0 = sizeof (ip6_header_t);
	}
      else
	{
	  /* NAT UDP port 4500 case, don't advance any more */
	  if (ip40->protocol == IP_PROTOCOL_UDP)
	    {
	      esp0 =
		(esp_header_t *) ((u8 *) ip40 + ip4_header_bytes (ip40) +
				  sizeof (udp_header_t));
	      buf_adv0 = 0;
	    }
	  else
	    {
	      esp0 = (esp_header_t *) ((u8 *) ip40 + ip4_header_bytes (ip40));
	      buf_adv0 = ip4_header_bytes (ip40);
	    }
	}

      /* stats for the tunnel include all the data after the IP header
         just like a norml IP-IP tunnel */
      vlib_buffer_advance (b[0], buf_adv0);
      len0 = vlib_buffer_length_in_chain (vm, b[0]);

      if (is_ip6)
	{
	  key60.remote_ip = ip60->src_address;
	  key60.spi = esp0->spi;

	  if (memcmp (&key60, &last_key6, sizeof (last_key6)) == 0)
	    {
	      iti0 = last_tunnel_id;
	    }
	  else
	    {
	      uword *p = hash_get_mem (im->tun6_protect_by_key, &key60);
	      if (p)
		{
		  iti0 = p[0];
		  last_tunnel_id = iti0;
		  clib_memcpy_fast (&last_key6, &key60, sizeof (key60));
		}
	      else
		{
		  next[0] =
		    ipsec_ip6_if_no_tunnel (node, b[0], esp0, buf_adv0);
		  n_no_tunnel++;
		  goto trace00;
		}
	    }
	}
      else			/* !is_ip6 */
	{
	  key40.remote_ip = ip40->src_address.as_u32;
	  key40.spi = esp0->spi;

	  if (key40.as_u64 == last_key4.as_u64)
	    {
	      iti0 = last_tunnel_id;
	    }
	  else
	    {
	      uword *p = hash_get (im->tun4_protect_by_key, key40.as_u64);
	      if (p)
		{
		  iti0 = p[0];
		  last_tunnel_id = iti0;
		  last_key4.as_u64 = key40.as_u64;
		}
	      else
		{
		  next[0] =
		    ipsec_ip4_if_no_tunnel (node, b[0], esp0, ip40, buf_adv0);
		  n_no_tunnel++;
		  goto trace00;
		}
	    }
	}

      itp0 = pool_elt_at_index (ipsec_protect_pool, iti0);
      vnet_buffer (b[0])->ipsec.sad_index =
	itp0->it_sa[IPSEC_PROTECT_DIR_INBOUND];
      vnet_buffer (b[0])->ipsec.protect_index = iti0;

      sw_if_index0 = itp0->it_sw_if_index;
      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = sw_if_index0;

      if (PREDICT_FALSE (!vnet_sw_interface_is_admin_up (vnm, sw_if_index0)))
	{
	  vlib_increment_combined_counter
	    (drop_counter, thread_index, sw_if_index0, 1, len0);
	  n_disabled++;
	  b[0]->error = node->errors[IPSEC_IF_INPUT_ERROR_DISABLED];
	  next[0] = IPSEC_INPUT_NEXT_DROP;
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
	      if (n_packets)
		{
		  vlib_increment_combined_counter
		    (rx_counter, thread_index, last_sw_if_index,
		     n_packets, n_bytes);
		}

	      last_sw_if_index = sw_if_index0;
	      n_packets = 1;
	      n_bytes = len0;
	    }
	}

    trace00:
      if (PREDICT_FALSE (is_trace))
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ipsec_if_input_trace_t *tr =
		vlib_add_trace (vm, node, b[0], sizeof (*tr));
	      tr->spi = clib_host_to_net_u32 (esp0->spi);
	      tr->seq = clib_host_to_net_u32 (esp0->seq);
	    }
	}

      /* next */
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  if (n_packets)
    {
      vlib_increment_combined_counter (rx_counter,
				       thread_index,
				       last_sw_if_index, n_packets, n_bytes);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       IPSEC_IF_INPUT_ERROR_RX,
			       from_frame->n_vectors - (n_disabled +
							n_no_tunnel));

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (ipsec4_tun_input_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return ipsec_if_input_inline (vm, node, from_frame, 0 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec4_tun_input_node) = {
  .name = "ipsec4-tun-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_if_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_if_input_error_strings),
  .error_strings = ipsec_if_input_error_strings,
  .sibling_of = "ipsec4-input-feature",
};
/* *INDENT-ON* */

VLIB_NODE_FN (ipsec6_tun_input_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return ipsec_if_input_inline (vm, node, from_frame, 1 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec6_tun_input_node) = {
  .name = "ipsec6-tun-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_if_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_if_input_error_strings),
  .error_strings = ipsec_if_input_error_strings,
  .sibling_of = "ipsec6-input-feature",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
