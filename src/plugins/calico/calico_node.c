/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <calico/calico.h>

#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>

typedef struct calico_translation_trace_t_
{
  u32 found;
  calico_session_t session;
} calico_translation_trace_t;

typedef enum calico_translate_next_t_
{
  CALICO_TRANSLATE_NEXT_DROP,
  CALICO_TRANSLATE_N_NEXT,
} calico_translate_next_t;

static u8 *
format_calico_translate_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  calico_translation_trace_t *t =
    va_arg (*args, calico_translation_trace_t *);

  s = format (s, "found:%d %U", t->found, format_calico_session, &t->session);
  return s;
}

static_always_inline void
calico_translate_ip4 (const calico_session_t * session,
		      ip4_header_t * ip4, udp_header_t * udp)
{
  ip4_address_t old_addr, new_addr;
  ip_csum_t sum;

  old_addr = ip4->dst_address;
  new_addr = session->value.cs_ip.ip4;
  ip4->dst_address = new_addr;

  sum = ip4->checksum;
  sum = ip_csum_update (sum, old_addr.as_u32, new_addr.as_u32,
			ip4_header_t, dst_address);
  ip4->checksum = ip_csum_fold (sum);

  if (PREDICT_FALSE (udp->checksum))
    {
      u16 old_port, new_port;

      old_port = udp->dst_port;
      new_port = session->value.cs_port;

      udp->dst_port = new_port;
      sum = udp->checksum;
      sum = ip_csum_update (sum, old_addr.as_u32, new_addr.as_u32,
			    ip4_header_t, dst_address);
      sum = ip_csum_update (sum, old_port, new_port,
			    ip4_header_t /* cheat */ ,
			    length /* changed member */ );
      udp->checksum = ip_csum_fold (sum);
    }
}

static_always_inline void
calico_translate_ip6 (const calico_session_t * session, ip6_header_t * ip6)
{
}

always_inline uword
calico_translate_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * frame, ip_address_family_t af)
{
  vlib_combined_counter_main_t *cm = &calico_translation_counters;
  u32 n_left, *from, thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  f64 now;

  thread_index = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);
  now = vlib_time_now (vm);

  while (n_left)
    {
      const calico_translation_t *ct;
      clib_bihash_kv_40_32_t bkey, bvalue;
      calico_session_t *session, *key;
      const load_balance_t *lb0;
      calico_vip_tx_t *cvip;
      ip_protocol_t iproto;
      udp_header_t *udp0;
      ip4_header_t *ip4;
      ip6_header_t *ip6;
      index_t cti;
      int rv;

      key = (calico_session_t *) & bkey;

      cvip = calico_vip_tx_get (vnet_buffer (b[0])->ip.adj_index[VLIB_TX]);

      key->key.cs_af = af;
      key->key.__cs_pad = 0;

      if (AF_IP4 == af)
	{
	  ip4 = vlib_buffer_get_current (b[0]);
	  iproto = ip4->protocol;
	  udp0 = (udp_header_t *) (ip4 + 1);

	  ip46_address_set_ip4 (&key->key.cs_ip[VLIB_TX], &ip4->dst_address);
	  ip46_address_set_ip4 (&key->key.cs_ip[VLIB_RX], &ip4->src_address);
	}
      else
	{
	  ip6 = vlib_buffer_get_current (b[0]);
	  iproto = ip6->protocol;
	  udp0 = (udp_header_t *) (ip6 + 1);

	  ip46_address_set_ip6 (&key->key.cs_ip[VLIB_TX], &ip6->dst_address);
	  ip46_address_set_ip6 (&key->key.cs_ip[VLIB_RX], &ip6->src_address);
	}

      if (iproto != IP_PROTOCOL_UDP)
	{
	  next[0] = CALICO_TRANSLATE_NEXT_DROP;
	  goto trace;
	}

      ct =
	calico_vip_find_translation (cvip,
				     clib_host_to_net_u16 (udp0->dst_port),
				     iproto);

      if (NULL == ct)
	{
	  next[0] = CALICO_TRANSLATE_NEXT_DROP;
	  goto trace;
	}
      cti = ct - calico_translation_pool;

      key->key.cs_port[VLIB_RX] = udp0->src_port;
      key->key.cs_port[VLIB_TX] = udp0->dst_port;
      key->key.cs_proto = iproto;

      rv =
	clib_bihash_search_inline_2_40_32 (&calico_session_db, &bkey,
					   &bvalue);

      lb0 = load_balance_get (ct->ct_lb.dpoi_index);

      if (!rv)
	{
	  /* session table hit */
	  session = (calico_session_t *) & bvalue;

	  session->value.cs_timestamp = now;
	}
      else
	{
	  /* session table miss */
	  calico_ep_trk_t *trk0;
	  u32 hash_c0, bucket0;
	  const dpo_id_t *dpo0;

	  hash_c0 = (AF_IP4 == af ?
		     ip4_compute_flow_hash (ip4, lb0->lb_hash_config) :
		     ip6_compute_flow_hash (ip6, lb0->lb_hash_config));
	  bucket0 = hash_c0 & lb0->lb_n_buckets_minus_1;
	  dpo0 = load_balance_get_fwd_bucket (lb0, bucket0);

	  /* add the session */
	  session = (calico_session_t *) & bkey;

	  trk0 = &ct->ct_paths[bucket0];

	  ip46_address_copy (&session->value.cs_ip, &trk0->ct_ep.ce_ip.ip);
	  session->value.cs_port = clib_host_to_net_u16 (trk0->ct_ep.ce_port);
	  session->value.cs_lbi = dpo0->dpoi_index;
	  session->value.cs_timestamp = now;

	  clib_bihash_add_del_40_32 (&calico_session_db, &bkey, 1);

	  /* is this the first time we've seen this source address */
	}

      next[0] = ct->ct_lb.dpoi_next_node;
      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = session->value.cs_lbi;

      if (AF_IP4 == af)
	calico_translate_ip4 (session, ip4, udp0);
      else
	calico_translate_ip6 (session, ip6);

      vlib_increment_combined_counter (cm, thread_index, cti, 1,
				       vlib_buffer_length_in_chain (vm,
								    b[0]));

    trace:
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  calico_translation_trace_t *t;

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));

	  t->found = !rv;
	  clib_memcpy (&t->session, session, sizeof (t->session));
	}

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (calico_translate_ip4_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return calico_translate_inline (vm, node, frame, AF_IP4);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (calico_translate_ip4_node) =
{
  .name = "ip4-calico-translate",
  .vector_size = sizeof (u32),
  .format_trace = format_calico_translate_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = CALICO_TRANSLATE_N_NEXT,
  .next_nodes =
  {
    [CALICO_TRANSLATE_NEXT_DROP] = "ip4-drop",
  }
};
/* *INDENT-OFF* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
