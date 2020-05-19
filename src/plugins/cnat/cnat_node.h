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

#ifndef __CNAT_NODE_H__
#define __CNAT_NODE_H__

#include <vlibmemory/api.h>
#include <cnat/cnat_session.h>
#include <cnat/cnat_client.h>

typedef uword (*cnat_node_sub_t) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_buffer_t * b,
				  cnat_node_ctx_t * ctx, int rv,
				  cnat_session_t * session);

/**
 * Inline translation functions
 */

static_always_inline u8
has_ip6_address (ip6_address_t * a)
{
  return ((0 != a->as_u64[0]) || (0 != a->as_u64[1]));
}

static_always_inline void
cnat_ip4_translate_l4 (ip4_header_t * ip4, udp_header_t * udp,
		       u16 * checksum,
		       ip4_address_t new_addr[VLIB_N_DIR],
		       u16 new_port[VLIB_N_DIR])
{
  u16 old_port[VLIB_N_DIR];
  ip4_address_t old_addr[VLIB_N_DIR];
  ip_csum_t sum;

  old_port[VLIB_TX] = udp->dst_port;
  old_port[VLIB_RX] = udp->src_port;
  old_addr[VLIB_TX] = ip4->dst_address;
  old_addr[VLIB_RX] = ip4->src_address;

  sum = *checksum;
  if (new_addr[VLIB_TX].as_u32)
    sum =
      ip_csum_update (sum, old_addr[VLIB_TX].as_u32, new_addr[VLIB_TX].as_u32,
		      ip4_header_t, dst_address);
  if (new_port[VLIB_TX])
    {
      udp->dst_port = new_port[VLIB_TX];
      sum = ip_csum_update (sum, old_port[VLIB_TX], new_port[VLIB_TX],
			    ip4_header_t /* cheat */ ,
			    length /* changed member */ );
    }
  if (new_addr[VLIB_RX].as_u32)
    sum =
      ip_csum_update (sum, old_addr[VLIB_RX].as_u32, new_addr[VLIB_RX].as_u32,
		      ip4_header_t, src_address);

  if (new_port[VLIB_RX])
    {
      udp->src_port = new_port[VLIB_RX];
      sum = ip_csum_update (sum, old_port[VLIB_RX], new_port[VLIB_RX],
			    ip4_header_t /* cheat */ ,
			    length /* changed member */ );
    }
  *checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_ip4_translate_l3 (ip4_header_t * ip4, ip4_address_t new_addr[VLIB_N_DIR])
{
  ip4_address_t old_addr[VLIB_N_DIR];
  ip_csum_t sum;

  old_addr[VLIB_TX] = ip4->dst_address;
  old_addr[VLIB_RX] = ip4->src_address;

  sum = ip4->checksum;
  if (new_addr[VLIB_TX].as_u32)
    {
      ip4->dst_address = new_addr[VLIB_TX];
      sum =
	ip_csum_update (sum, old_addr[VLIB_TX].as_u32,
			new_addr[VLIB_TX].as_u32, ip4_header_t, dst_address);
    }
  if (new_addr[VLIB_RX].as_u32)
    {
      ip4->src_address = new_addr[VLIB_RX];
      sum =
	ip_csum_update (sum, old_addr[VLIB_RX].as_u32,
			new_addr[VLIB_RX].as_u32, ip4_header_t, src_address);
    }
  ip4->checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_tcp_update_session_lifetime (tcp_header_t * tcp, u32 index)
{
  cnat_main_t *cm = &cnat_main;
  if (PREDICT_FALSE (tcp_fin (tcp)))
    {
      cnat_timestamp_set_lifetime (index, CNAT_DEFAULT_TCP_RST_TIMEOUT);
    }

  if (PREDICT_FALSE (tcp_rst (tcp)))
    {
      cnat_timestamp_set_lifetime (index, CNAT_DEFAULT_TCP_RST_TIMEOUT);
    }

  if (PREDICT_FALSE (tcp_syn (tcp) && tcp_ack (tcp)))
    {
      cnat_timestamp_set_lifetime (index, cm->tcp_max_age);
    }
}

static_always_inline void
cnat_translation_ip4 (const cnat_session_t * session,
		      ip4_header_t * ip4, udp_header_t * udp)
{
  tcp_header_t *tcp = (tcp_header_t *) udp;
  ip4_address_t new_addr[VLIB_N_DIR];
  u16 new_port[VLIB_N_DIR];

  new_addr[VLIB_TX] = session->value.cs_ip[VLIB_TX].ip4;
  new_addr[VLIB_RX] = session->value.cs_ip[VLIB_RX].ip4;
  new_port[VLIB_TX] = session->value.cs_port[VLIB_TX];
  new_port[VLIB_RX] = session->value.cs_port[VLIB_RX];

  if (ip4->protocol == IP_PROTOCOL_TCP)
    {
      if (PREDICT_FALSE (tcp->checksum))
	cnat_ip4_translate_l4 (ip4, udp, &tcp->checksum, new_addr, new_port);
      else
	{
	  udp->dst_port = new_port[VLIB_TX];
	  udp->src_port = new_port[VLIB_RX];
	}
      cnat_tcp_update_session_lifetime (tcp, session->value.cs_ts_index);
    }
  else if (ip4->protocol == IP_PROTOCOL_UDP)
    {
      if (PREDICT_FALSE (udp->checksum))
	cnat_ip4_translate_l4 (ip4, udp, &udp->checksum, new_addr, new_port);
      else
	{
	  udp->dst_port = new_port[VLIB_TX];
	  udp->src_port = new_port[VLIB_RX];
	}
    }

  cnat_ip4_translate_l3 (ip4, new_addr);
}

static_always_inline void
cnat_ip6_translate_l3 (ip6_header_t * ip6, ip6_address_t new_addr[VLIB_N_DIR])
{
  if (has_ip6_address (&new_addr[VLIB_TX]))
    ip6_address_copy (&ip6->dst_address, &new_addr[VLIB_TX]);
  if (has_ip6_address (&new_addr[VLIB_RX]))
    ip6_address_copy (&ip6->src_address, &new_addr[VLIB_RX]);
}

static_always_inline void
cnat_ip6_translate_l4 (ip6_header_t * ip6, udp_header_t * udp,
		       u16 * checksum,
		       ip6_address_t new_addr[VLIB_N_DIR],
		       u16 new_port[VLIB_N_DIR])
{
  u16 old_port[VLIB_N_DIR];
  ip6_address_t old_addr[VLIB_N_DIR];
  ip_csum_t sum;

  old_port[VLIB_TX] = udp->dst_port;
  old_port[VLIB_RX] = udp->src_port;
  ip6_address_copy (&old_addr[VLIB_TX], &ip6->dst_address);
  ip6_address_copy (&old_addr[VLIB_RX], &ip6->src_address);

  sum = *checksum;
  if (has_ip6_address (&new_addr[VLIB_TX]))
    {
      sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[0]);
      sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[1]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[0]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[1]);
    }

  if (new_port[VLIB_TX])
    {
      udp->dst_port = new_port[VLIB_TX];
      sum = ip_csum_update (sum, old_port[VLIB_TX], new_port[VLIB_TX],
			    ip4_header_t /* cheat */ ,
			    length /* changed member */ );
    }
  if (has_ip6_address (&new_addr[VLIB_RX]))
    {
      sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[0]);
      sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[1]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[0]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[1]);
    }

  if (new_port[VLIB_RX])
    {
      udp->src_port = new_port[VLIB_RX];
      sum = ip_csum_update (sum, old_port[VLIB_RX], new_port[VLIB_RX],
			    ip4_header_t /* cheat */ ,
			    length /* changed member */ );
    }
  *checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_translation_ip6 (const cnat_session_t * session,
		      ip6_header_t * ip6, udp_header_t * udp)
{
  tcp_header_t *tcp = (tcp_header_t *) udp;
  ip6_address_t new_addr[VLIB_N_DIR];
  u16 new_port[VLIB_N_DIR];

  ip6_address_copy (&new_addr[VLIB_TX], &session->value.cs_ip[VLIB_TX].ip6);
  ip6_address_copy (&new_addr[VLIB_RX], &session->value.cs_ip[VLIB_RX].ip6);
  new_port[VLIB_TX] = session->value.cs_port[VLIB_TX];
  new_port[VLIB_RX] = session->value.cs_port[VLIB_RX];

  if (ip6->protocol == IP_PROTOCOL_TCP)
    {
      if (PREDICT_FALSE (tcp->checksum))
	cnat_ip6_translate_l4 (ip6, udp, &tcp->checksum, new_addr, new_port);
      else
	{
	  udp->dst_port = new_port[VLIB_TX];
	  udp->src_port = new_port[VLIB_RX];
	}
      cnat_tcp_update_session_lifetime (tcp, session->value.cs_ts_index);
    }
  else if (ip6->protocol == IP_PROTOCOL_UDP)
    {
      if (PREDICT_FALSE (udp->checksum))
	cnat_ip6_translate_l4 (ip6, udp, &udp->checksum, new_addr, new_port);
      else
	{
	  udp->dst_port = new_port[VLIB_TX];
	  udp->src_port = new_port[VLIB_RX];
	}
    }

  cnat_ip6_translate_l3 (ip6, new_addr);
}

static_always_inline void
cnat_session_make_key (vlib_buffer_t * b, ip_address_family_t af,
		       clib_bihash_kv_40_48_t * bkey)
{
  udp_header_t *udp;
  cnat_session_t *session = (cnat_session_t *) bkey;
  if (AF_IP4 == af)
    {
      ip4_header_t *ip4;
      ip4 = vlib_buffer_get_current (b);
      udp = (udp_header_t *) (ip4 + 1);
      session->key.cs_af = AF_IP4;
      session->key.__cs_pad[0] = 0;
      session->key.__cs_pad[1] = 0;

      ip46_address_set_ip4 (&session->key.cs_ip[VLIB_TX], &ip4->dst_address);
      ip46_address_set_ip4 (&session->key.cs_ip[VLIB_RX], &ip4->src_address);
      session->key.cs_port[VLIB_RX] = udp->src_port;
      session->key.cs_port[VLIB_TX] = udp->dst_port;
      session->key.cs_proto = ip4->protocol;
    }
  else
    {
      ip6_header_t *ip6;
      ip6 = vlib_buffer_get_current (b);
      udp = (udp_header_t *) (ip6 + 1);
      session->key.cs_af = AF_IP6;
      session->key.__cs_pad[0] = 0;
      session->key.__cs_pad[1] = 0;

      ip46_address_set_ip6 (&session->key.cs_ip[VLIB_TX], &ip6->dst_address);
      ip46_address_set_ip6 (&session->key.cs_ip[VLIB_RX], &ip6->src_address);
      session->key.cs_port[VLIB_RX] = udp->src_port;
      session->key.cs_port[VLIB_TX] = udp->dst_port;
      session->key.cs_proto = ip6->protocol;
    }
}

/**
 * Create NAT sessions
 */

static_always_inline void
cnat_session_create (cnat_session_t * session, cnat_node_ctx_t * ctx,
		     u8 rsession_flags)
{
  cnat_client_t *cc;
  clib_bihash_kv_40_48_t rkey;
  cnat_session_t *rsession = (cnat_session_t *) & rkey;
  clib_bihash_kv_40_48_t *bkey = (clib_bihash_kv_40_48_t *) session;
  clib_bihash_kv_40_48_t rvalue;
  int rv;

  /* create the reverse flow key */
  ip46_address_copy (&rsession->key.cs_ip[VLIB_RX],
		     &session->value.cs_ip[VLIB_TX]);
  ip46_address_copy (&rsession->key.cs_ip[VLIB_TX],
		     &session->value.cs_ip[VLIB_RX]);
  rsession->key.cs_proto = session->key.cs_proto;
  rsession->key.__cs_pad[0] = 0;
  rsession->key.__cs_pad[1] = 0;
  rsession->key.cs_af = ctx->af;
  rsession->key.cs_port[VLIB_RX] = session->value.cs_port[VLIB_TX];
  rsession->key.cs_port[VLIB_TX] = session->value.cs_port[VLIB_RX];

  /* First search for existing reverse session */
  rv = clib_bihash_search_inline_2_40_48 (&cnat_session_db, &rkey, &rvalue);
  if (!rv)
    {
      /* Reverse session already exists
         corresponding client should also exist
         we only need to refcnt the timestamp */
      cnat_session_t *found_rsession = (cnat_session_t *) & rvalue;
      session->value.cs_ts_index = found_rsession->value.cs_ts_index;
      cnat_timestamp_inc_refcnt (session->value.cs_ts_index);
      clib_bihash_add_del_40_48 (&cnat_session_db, bkey, 1 /* is_add */ );
      goto create_rsession;
    }

  session->value.cs_ts_index = cnat_timestamp_new (ctx->now);
  clib_bihash_add_del_40_48 (&cnat_session_db, bkey, 1);

  /* is this the first time we've seen this source address */
  cc = (AF_IP4 == ctx->af ?
	cnat_client_ip4_find (&session->value.cs_ip[VLIB_RX].ip4) :
	cnat_client_ip6_find (&session->value.cs_ip[VLIB_RX].ip6));

  if (NULL == cc)
    {
      u64 r0 = 17;
      if (AF_IP4 == ctx->af)
	r0 = (u64) session->value.cs_ip[VLIB_RX].ip4.as_u32;
      else
	{
	  r0 = r0 * 31 + session->value.cs_ip[VLIB_RX].ip6.as_u64[0];
	  r0 = r0 * 31 + session->value.cs_ip[VLIB_RX].ip6.as_u64[1];
	}

      /* Rate limit */
      if (!throttle_check (&cnat_throttle, ctx->thread_index, r0, ctx->seed))
	{
	  cnat_learn_arg_t l;
	  l.addr.version = ctx->af;
	  ip46_address_copy (&l.addr.ip, &session->value.cs_ip[VLIB_RX]);
	  /* fire client create to the main thread */
	  vl_api_rpc_call_main_thread (cnat_client_learn,
				       (u8 *) & l, sizeof (l));
	}
      else
	{
	  /* Will still need to count those for session refcnt */
	  ip_address_t *addr;
	  clib_spinlock_lock (&cnat_client_db.throttle_pool_lock
			      [ctx->thread_index]);
	  pool_get (cnat_client_db.throttle_pool[ctx->thread_index], addr);
	  addr->version = ctx->af;
	  ip46_address_copy (&addr->ip, &session->value.cs_ip[VLIB_RX]);
	  clib_spinlock_unlock (&cnat_client_db.throttle_pool_lock
				[ctx->thread_index]);
	}
    }
  else
    {
      cnat_client_cnt_session (cc);
    }

create_rsession:
  /* add the reverse flow */
  ip46_address_copy (&rsession->value.cs_ip[VLIB_RX],
		     &session->key.cs_ip[VLIB_TX]);
  ip46_address_copy (&rsession->value.cs_ip[VLIB_TX],
		     &session->key.cs_ip[VLIB_RX]);
  rsession->value.cs_ts_index = session->value.cs_ts_index;
  rsession->value.cs_lbi = INDEX_INVALID;
  rsession->value.flags = rsession_flags;
  rsession->value.cs_port[VLIB_TX] = session->key.cs_port[VLIB_RX];
  rsession->value.cs_port[VLIB_RX] = session->key.cs_port[VLIB_TX];

  clib_bihash_add_del_40_48 (&cnat_session_db, &rkey, 1);
}

always_inline uword
cnat_node_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame,
		  cnat_node_sub_t cnat_sub,
		  ip_address_family_t af, u8 do_trace)
{
  u32 n_left, *from, thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  f64 now;
  u64 seed;

  thread_index = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);
  now = vlib_time_now (vm);
  seed = throttle_seed (&cnat_throttle, thread_index, vlib_time_now (vm));
  cnat_session_t *session[4];
  clib_bihash_kv_40_48_t bkey[4], bvalue[4];
  u64 hash[4];
  int rv[4];

  cnat_node_ctx_t ctx = { now, seed, thread_index, af, do_trace };

  if (n_left >= 8)
    {
      /* Kickstart our state */
      cnat_session_make_key (b[3], af, &bkey[3]);
      cnat_session_make_key (b[2], af, &bkey[2]);
      cnat_session_make_key (b[1], af, &bkey[1]);
      cnat_session_make_key (b[0], af, &bkey[0]);

      hash[3] = clib_bihash_hash_40_48 (&bkey[3]);
      hash[2] = clib_bihash_hash_40_48 (&bkey[2]);
      hash[1] = clib_bihash_hash_40_48 (&bkey[1]);
      hash[0] = clib_bihash_hash_40_48 (&bkey[0]);
    }

  while (n_left >= 8)
    {
      if (n_left >= 12)
	{
	  vlib_prefetch_buffer_header (b[11], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[8], LOAD);
	}

      rv[3] =
	clib_bihash_search_inline_2_with_hash_40_48 (&cnat_session_db,
						     hash[3], &bkey[3],
						     &bvalue[3]);
      session[3] = (cnat_session_t *) (rv[3] ? &bkey[3] : &bvalue[3]);
      next[3] = cnat_sub (vm, node, b[3], &ctx, rv[3], session[3]);

      rv[2] =
	clib_bihash_search_inline_2_with_hash_40_48 (&cnat_session_db,
						     hash[2], &bkey[2],
						     &bvalue[2]);
      session[2] = (cnat_session_t *) (rv[2] ? &bkey[2] : &bvalue[2]);
      next[2] = cnat_sub (vm, node, b[2], &ctx, rv[2], session[2]);

      rv[1] =
	clib_bihash_search_inline_2_with_hash_40_48 (&cnat_session_db,
						     hash[1], &bkey[1],
						     &bvalue[1]);
      session[1] = (cnat_session_t *) (rv[1] ? &bkey[1] : &bvalue[1]);
      next[1] = cnat_sub (vm, node, b[1], &ctx, rv[1], session[1]);

      rv[0] =
	clib_bihash_search_inline_2_with_hash_40_48 (&cnat_session_db,
						     hash[0], &bkey[0],
						     &bvalue[0]);
      session[0] = (cnat_session_t *) (rv[0] ? &bkey[0] : &bvalue[0]);
      next[0] = cnat_sub (vm, node, b[0], &ctx, rv[0], session[0]);

      cnat_session_make_key (b[7], af, &bkey[3]);
      cnat_session_make_key (b[6], af, &bkey[2]);
      cnat_session_make_key (b[5], af, &bkey[1]);
      cnat_session_make_key (b[4], af, &bkey[0]);

      hash[3] = clib_bihash_hash_40_48 (&bkey[3]);
      hash[2] = clib_bihash_hash_40_48 (&bkey[2]);
      hash[1] = clib_bihash_hash_40_48 (&bkey[1]);
      hash[0] = clib_bihash_hash_40_48 (&bkey[0]);

      clib_bihash_prefetch_bucket_40_48 (&cnat_session_db, hash[3]);
      clib_bihash_prefetch_bucket_40_48 (&cnat_session_db, hash[2]);
      clib_bihash_prefetch_bucket_40_48 (&cnat_session_db, hash[1]);
      clib_bihash_prefetch_bucket_40_48 (&cnat_session_db, hash[0]);

      clib_bihash_prefetch_data_40_48 (&cnat_session_db, hash[3]);
      clib_bihash_prefetch_data_40_48 (&cnat_session_db, hash[2]);
      clib_bihash_prefetch_data_40_48 (&cnat_session_db, hash[1]);
      clib_bihash_prefetch_data_40_48 (&cnat_session_db, hash[0]);

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      cnat_session_make_key (b[0], af, &bkey[0]);
      rv[0] = clib_bihash_search_inline_2_40_48 (&cnat_session_db,
						 &bkey[0], &bvalue[0]);

      session[0] = (cnat_session_t *) (rv[0] ? &bkey[0] : &bvalue[0]);
      next[0] = cnat_sub (vm, node, b[0], &ctx, rv[0], session[0]);

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
