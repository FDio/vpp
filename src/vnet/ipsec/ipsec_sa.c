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

#include <sys/random.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/udp/udp_local.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipsec/ipsec.api_enum.h>

/**
 * @brief
 * SA packet & bytes counters
 */
vlib_combined_counter_main_t ipsec_sa_counters = {
  .name = "SA",
  .stat_segment_name = "/net/ipsec/sa",
};
/* Per-SA error counters */
vlib_simple_counter_main_t ipsec_sa_err_counters[IPSEC_SA_N_ERRORS];

ipsec_sa_t *ipsec_sa_pool;

static clib_error_t *
ipsec_call_add_del_callbacks (ipsec_main_t * im, ipsec_sa_t * sa,
			      u32 sa_index, int is_add)
{
  ipsec_ah_backend_t *ab;
  ipsec_esp_backend_t *eb;
  switch (sa->protocol)
    {
    case IPSEC_PROTOCOL_AH:
      ab = pool_elt_at_index (im->ah_backends, im->ah_current_backend);
      if (ab->add_del_sa_sess_cb)
	return ab->add_del_sa_sess_cb (sa_index, is_add);
      break;
    case IPSEC_PROTOCOL_ESP:
      eb = pool_elt_at_index (im->esp_backends, im->esp_current_backend);
      if (eb->add_del_sa_sess_cb)
	return eb->add_del_sa_sess_cb (sa_index, is_add);
      break;
    }
  return 0;
}

void
ipsec_mk_key (ipsec_key_t * key, const u8 * data, u8 len)
{
  memset (key, 0, sizeof (*key));

  if (len > sizeof (key->data))
    key->len = sizeof (key->data);
  else
    key->len = len;

  memcpy (key->data, data, key->len);
}

/**
 * 'stack' (resolve the recursion for) the SA tunnel destination
 */
static void
ipsec_sa_stack (ipsec_sa_t * sa)
{
  ipsec_main_t *im = &ipsec_main;
  dpo_id_t tmp = DPO_INVALID;

  tunnel_contribute_forwarding (&sa->tunnel, &tmp);

  if (IPSEC_PROTOCOL_AH == sa->protocol)
    dpo_stack_from_node ((ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
			  im->ah6_encrypt_node_index :
			  im->ah4_encrypt_node_index), &sa->dpo, &tmp);
  else
    dpo_stack_from_node ((ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
			  im->esp6_encrypt_node_index :
			  im->esp4_encrypt_node_index), &sa->dpo, &tmp);
  dpo_reset (&tmp);
}

void
ipsec_sa_set_async_mode (ipsec_sa_t *sa, int is_enabled)
{
  if (is_enabled)
    {
      sa->crypto_key_index = sa->crypto_async_key_index;
      sa->crypto_enc_op_id = sa->crypto_async_enc_op_id;
      sa->crypto_dec_op_id = sa->crypto_async_dec_op_id;
      sa->integ_key_index = ~0;
      sa->integ_op_id = ~0;
    }
  else
    {
      sa->crypto_key_index = sa->crypto_sync_key_index;
      sa->crypto_enc_op_id = sa->crypto_sync_enc_op_id;
      sa->crypto_dec_op_id = sa->crypto_sync_dec_op_id;
      sa->integ_key_index = sa->integ_sync_key_index;
      sa->integ_op_id = sa->integ_sync_op_id;
    }
}

void
ipsec_sa_set_crypto_alg (ipsec_sa_t * sa, ipsec_crypto_alg_t crypto_alg)
{
  ipsec_main_t *im = &ipsec_main;
  sa->crypto_alg = crypto_alg;
  sa->crypto_iv_size = im->crypto_algs[crypto_alg].iv_size;
  sa->esp_block_align = clib_max (4, im->crypto_algs[crypto_alg].block_align);
  sa->crypto_sync_enc_op_id = im->crypto_algs[crypto_alg].enc_op_id;
  sa->crypto_sync_dec_op_id = im->crypto_algs[crypto_alg].dec_op_id;
  sa->crypto_calg = im->crypto_algs[crypto_alg].alg;
  ASSERT (sa->crypto_iv_size <= ESP_MAX_IV_SIZE);
  ASSERT (sa->esp_block_align <= ESP_MAX_BLOCK_SIZE);
  if (IPSEC_CRYPTO_ALG_IS_GCM (crypto_alg) ||
      IPSEC_CRYPTO_ALG_CTR_AEAD_OTHERS (crypto_alg))
    {
      sa->integ_icv_size = im->crypto_algs[crypto_alg].icv_size;
      ipsec_sa_set_IS_CTR (sa);
      ipsec_sa_set_IS_AEAD (sa);
    }
  else if (IPSEC_CRYPTO_ALG_IS_CTR (crypto_alg))
    {
      ipsec_sa_set_IS_CTR (sa);
    }
  else if (IPSEC_CRYPTO_ALG_IS_NULL_GMAC (crypto_alg))
    {
      sa->integ_icv_size = im->crypto_algs[crypto_alg].icv_size;
      ipsec_sa_set_IS_CTR (sa);
      ipsec_sa_set_IS_AEAD (sa);
      ipsec_sa_set_IS_NULL_GMAC (sa);
    }
}

void
ipsec_sa_set_integ_alg (ipsec_sa_t * sa, ipsec_integ_alg_t integ_alg)
{
  ipsec_main_t *im = &ipsec_main;
  sa->integ_alg = integ_alg;
  sa->integ_icv_size = im->integ_algs[integ_alg].icv_size;
  sa->integ_sync_op_id = im->integ_algs[integ_alg].op_id;
  sa->integ_calg = im->integ_algs[integ_alg].alg;
  ASSERT (sa->integ_icv_size <= ESP_MAX_ICV_SIZE);
}

void
ipsec_sa_set_async_op_ids (ipsec_sa_t * sa)
{
  /* *INDENT-OFF* */
  if (ipsec_sa_is_set_USE_ESN (sa))
    {
#define _(n, s, k)                                                            \
  if (sa->crypto_sync_enc_op_id == VNET_CRYPTO_OP_##n##_ENC)                  \
    sa->crypto_async_enc_op_id = VNET_CRYPTO_OP_##n##_TAG16_AAD12_ENC;        \
  if (sa->crypto_sync_dec_op_id == VNET_CRYPTO_OP_##n##_DEC)                  \
    sa->crypto_async_dec_op_id = VNET_CRYPTO_OP_##n##_TAG16_AAD12_DEC;
      foreach_crypto_aead_alg
#undef _
    }
  else
    {
#define _(n, s, k)                                                            \
  if (sa->crypto_sync_enc_op_id == VNET_CRYPTO_OP_##n##_ENC)                  \
    sa->crypto_async_enc_op_id = VNET_CRYPTO_OP_##n##_TAG16_AAD8_ENC;         \
  if (sa->crypto_sync_dec_op_id == VNET_CRYPTO_OP_##n##_DEC)                  \
    sa->crypto_async_dec_op_id = VNET_CRYPTO_OP_##n##_TAG16_AAD8_DEC;
      foreach_crypto_aead_alg
#undef _
    }

#define _(c, h, s, k, d)                                                      \
  if (sa->crypto_sync_enc_op_id == VNET_CRYPTO_OP_##c##_ENC &&                \
      sa->integ_sync_op_id == VNET_CRYPTO_OP_##h##_HMAC)                      \
    sa->crypto_async_enc_op_id = VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC;     \
  if (sa->crypto_sync_dec_op_id == VNET_CRYPTO_OP_##c##_DEC &&                \
      sa->integ_sync_op_id == VNET_CRYPTO_OP_##h##_HMAC)                      \
    sa->crypto_async_dec_op_id = VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC;
  foreach_crypto_link_async_alg
#undef _
  /* *INDENT-ON* */
}

int
ipsec_sa_update (u32 id, u16 src_port, u16 dst_port, const tunnel_t *tun,
		 bool is_tun)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;
  u32 sa_index;
  uword *p;
  int rv;

  p = hash_get (im->sa_index_by_sa_id, id);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  sa = ipsec_sa_get (p[0]);
  sa_index = sa - ipsec_sa_pool;

  if (is_tun && ipsec_sa_is_set_IS_TUNNEL (sa) &&
      (ip_address_cmp (&tun->t_src, &sa->tunnel.t_src) != 0 ||
       ip_address_cmp (&tun->t_dst, &sa->tunnel.t_dst) != 0))
    {
      /* if the source IP is updated for an inbound SA under a tunnel protect,
       we need to update the tun_protect DB with the new src IP */
      if (ipsec_sa_is_set_IS_INBOUND (sa) &&
	  ip_address_cmp (&tun->t_src, &sa->tunnel.t_src) != 0 &&
	  !ip46_address_is_zero (&tun->t_src.ip))
	{
	  if (ip46_address_is_ip4 (&sa->tunnel.t_src.ip))
	    {
	      ipsec4_tunnel_kv_t old_key, new_key;
	      clib_bihash_kv_8_16_t res,
		*bkey = (clib_bihash_kv_8_16_t *) &old_key;

	      ipsec4_tunnel_mk_key (&old_key, &sa->tunnel.t_src.ip.ip4,
				    clib_host_to_net_u32 (sa->spi));
	      ipsec4_tunnel_mk_key (&new_key, &tun->t_src.ip.ip4,
				    clib_host_to_net_u32 (sa->spi));

	      if (!clib_bihash_search_8_16 (&im->tun4_protect_by_key, bkey,
					    &res))
		{
		  clib_bihash_add_del_8_16 (&im->tun4_protect_by_key, &res, 0);
		  res.key = new_key.key;
		  clib_bihash_add_del_8_16 (&im->tun4_protect_by_key, &res, 1);
		}
	    }
	  else
	    {
	      ipsec6_tunnel_kv_t old_key = {
          .key = {
            .remote_ip =  sa->tunnel.t_src.ip.ip6,
            .spi = clib_host_to_net_u32 (sa->spi),
          },
        }, new_key = {
          .key = {
            .remote_ip = tun->t_src.ip.ip6,
            .spi = clib_host_to_net_u32 (sa->spi),
          }};
	      clib_bihash_kv_24_16_t res,
		*bkey = (clib_bihash_kv_24_16_t *) &old_key;

	      if (!clib_bihash_search_24_16 (&im->tun6_protect_by_key, bkey,
					     &res))
		{
		  clib_bihash_add_del_24_16 (&im->tun6_protect_by_key, &res,
					     0);
		  clib_memcpy (&res.key, &new_key.key, 3);
		  clib_bihash_add_del_24_16 (&im->tun6_protect_by_key, &res,
					     1);
		}
	    }
	}
      tunnel_unresolve (&sa->tunnel);
      tunnel_copy (tun, &sa->tunnel);
      if (!ipsec_sa_is_set_IS_INBOUND (sa))
	{
	  dpo_reset (&sa->dpo);

	  sa->tunnel_flags = sa->tunnel.t_encap_decap_flags;

	  rv = tunnel_resolve (&sa->tunnel, FIB_NODE_TYPE_IPSEC_SA, sa_index);

	  if (rv)
	    {
	      hash_unset (im->sa_index_by_sa_id, sa->id);
	      pool_put (ipsec_sa_pool, sa);
	      return rv;
	    }
	  ipsec_sa_stack (sa);
	  /* generate header templates */
	  if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
	    {
	      tunnel_build_v6_hdr (&sa->tunnel,
				   (ipsec_sa_is_set_UDP_ENCAP (sa) ?
					    IP_PROTOCOL_UDP :
					    IP_PROTOCOL_IPSEC_ESP),
				   &sa->ip6_hdr);
	    }
	  else
	    {
	      tunnel_build_v4_hdr (&sa->tunnel,
				   (ipsec_sa_is_set_UDP_ENCAP (sa) ?
					    IP_PROTOCOL_UDP :
					    IP_PROTOCOL_IPSEC_ESP),
				   &sa->ip4_hdr);
	    }
	}
    }

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    {
      if (dst_port != IPSEC_UDP_PORT_NONE &&
	  dst_port != clib_net_to_host_u16 (sa->udp_hdr.dst_port))
	{
	  if (ipsec_sa_is_set_IS_INBOUND (sa))
	    {
	      ipsec_unregister_udp_port (
		clib_net_to_host_u16 (sa->udp_hdr.dst_port),
		!ipsec_sa_is_set_IS_TUNNEL_V6 (sa));
	      ipsec_register_udp_port (dst_port,
				       !ipsec_sa_is_set_IS_TUNNEL_V6 (sa));
	    }
	  sa->udp_hdr.dst_port = clib_host_to_net_u16 (dst_port);
	}
      if (src_port != IPSEC_UDP_PORT_NONE &&
	  src_port != clib_net_to_host_u16 (sa->udp_hdr.src_port))
	sa->udp_hdr.src_port = clib_host_to_net_u16 (src_port);
    }
  return (0);
}

int
ipsec_sa_add_and_lock (u32 id, u32 spi, ipsec_protocol_t proto,
		       ipsec_crypto_alg_t crypto_alg, const ipsec_key_t *ck,
		       ipsec_integ_alg_t integ_alg, const ipsec_key_t *ik,
		       ipsec_sa_flags_t flags, u32 salt, u16 src_port,
		       u16 dst_port, const tunnel_t *tun, u32 *sa_out_index)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  clib_error_t *err;
  ipsec_sa_t *sa;
  u32 sa_index;
  u64 rand[2];
  uword *p;
  int rv;

  p = hash_get (im->sa_index_by_sa_id, id);
  if (p)
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

  if (getrandom (rand, sizeof (rand), 0) != sizeof (rand))
    return VNET_API_ERROR_INIT_FAILED;

  pool_get_aligned_zero (ipsec_sa_pool, sa, CLIB_CACHE_LINE_BYTES);

  clib_pcg64i_srandom_r (&sa->iv_prng, rand[0], rand[1]);

  fib_node_init (&sa->node, FIB_NODE_TYPE_IPSEC_SA);
  fib_node_lock (&sa->node);
  sa_index = sa - ipsec_sa_pool;

  vlib_validate_combined_counter (&ipsec_sa_counters, sa_index);
  vlib_zero_combined_counter (&ipsec_sa_counters, sa_index);
  for (int i = 0; i < IPSEC_SA_N_ERRORS; i++)
    {
      vlib_validate_simple_counter (&ipsec_sa_err_counters[i], sa_index);
      vlib_zero_simple_counter (&ipsec_sa_err_counters[i], sa_index);
    }

  tunnel_copy (tun, &sa->tunnel);
  sa->id = id;
  sa->spi = spi;
  sa->stat_index = sa_index;
  sa->protocol = proto;
  sa->flags = flags;
  sa->salt = salt;
  sa->thread_index = (vlib_num_workers ()) ? ~0 : 0;
  if (integ_alg != IPSEC_INTEG_ALG_NONE)
    {
      ipsec_sa_set_integ_alg (sa, integ_alg);
      clib_memcpy (&sa->integ_key, ik, sizeof (sa->integ_key));
    }
  ipsec_sa_set_crypto_alg (sa, crypto_alg);
  ipsec_sa_set_async_op_ids (sa);

  clib_memcpy (&sa->crypto_key, ck, sizeof (sa->crypto_key));

  sa->crypto_sync_key_index = vnet_crypto_key_add (
    vm, im->crypto_algs[crypto_alg].alg, (u8 *) ck->data, ck->len);
  if (~0 == sa->crypto_sync_key_index)
    {
      pool_put (ipsec_sa_pool, sa);
      return VNET_API_ERROR_KEY_LENGTH;
    }

  if (integ_alg != IPSEC_INTEG_ALG_NONE)
    {
      sa->integ_sync_key_index = vnet_crypto_key_add (
	vm, im->integ_algs[integ_alg].alg, (u8 *) ik->data, ik->len);
      if (~0 == sa->integ_sync_key_index)
	{
	  pool_put (ipsec_sa_pool, sa);
	  return VNET_API_ERROR_KEY_LENGTH;
	}
    }

  if (sa->crypto_async_enc_op_id && !ipsec_sa_is_set_IS_AEAD (sa))
    sa->crypto_async_key_index =
      vnet_crypto_key_add_linked (vm, sa->crypto_sync_key_index,
				  sa->integ_sync_key_index); // AES-CBC & HMAC
  else
    sa->crypto_async_key_index = sa->crypto_sync_key_index;

  if (im->async_mode)
    {
      ipsec_sa_set_async_mode (sa, 1);
    }
  else if (ipsec_sa_is_set_IS_ASYNC (sa))
    {
      ipsec_sa_set_async_mode (sa, 1 /* is_enabled */);
    }
  else
    {
      ipsec_sa_set_async_mode (sa, 0 /* is_enabled */);
    }

  err = ipsec_check_support_cb (im, sa);
  if (err)
    {
      clib_warning ("%v", err->what);
      pool_put (ipsec_sa_pool, sa);
      return VNET_API_ERROR_UNIMPLEMENTED;
    }

  err = ipsec_call_add_del_callbacks (im, sa, sa_index, 1);
  if (err)
    {
      pool_put (ipsec_sa_pool, sa);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  if (ipsec_sa_is_set_IS_TUNNEL (sa) &&
      AF_IP6 == ip_addr_version (&tun->t_src))
    ipsec_sa_set_IS_TUNNEL_V6 (sa);

  if (ipsec_sa_is_set_IS_TUNNEL (sa) && !ipsec_sa_is_set_IS_INBOUND (sa))
    {
      sa->tunnel_flags = sa->tunnel.t_encap_decap_flags;

      rv = tunnel_resolve (&sa->tunnel, FIB_NODE_TYPE_IPSEC_SA, sa_index);

      if (rv)
	{
	  pool_put (ipsec_sa_pool, sa);
	  return rv;
	}
      ipsec_sa_stack (sa);

      /* generate header templates */
      if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
	{
	  tunnel_build_v6_hdr (&sa->tunnel,
			       (ipsec_sa_is_set_UDP_ENCAP (sa) ?
				  IP_PROTOCOL_UDP :
				  IP_PROTOCOL_IPSEC_ESP),
			       &sa->ip6_hdr);
	}
      else
	{
	  tunnel_build_v4_hdr (&sa->tunnel,
			       (ipsec_sa_is_set_UDP_ENCAP (sa) ?
				  IP_PROTOCOL_UDP :
				  IP_PROTOCOL_IPSEC_ESP),
			       &sa->ip4_hdr);
	}
    }

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    {
      if (dst_port == IPSEC_UDP_PORT_NONE)
	sa->udp_hdr.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
      else
	sa->udp_hdr.dst_port = clib_host_to_net_u16 (dst_port);

      if (src_port == IPSEC_UDP_PORT_NONE)
	sa->udp_hdr.src_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
      else
	sa->udp_hdr.src_port = clib_host_to_net_u16 (src_port);

      if (ipsec_sa_is_set_IS_INBOUND (sa))
	ipsec_register_udp_port (clib_host_to_net_u16 (sa->udp_hdr.dst_port),
				 !ipsec_sa_is_set_IS_TUNNEL_V6 (sa));
    }

  hash_set (im->sa_index_by_sa_id, sa->id, sa_index);

  if (sa_out_index)
    *sa_out_index = sa_index;

  return (0);
}

static void
ipsec_sa_del (ipsec_sa_t * sa)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  u32 sa_index;

  sa_index = sa - ipsec_sa_pool;
  hash_unset (im->sa_index_by_sa_id, sa->id);
  tunnel_unresolve (&sa->tunnel);

  /* no recovery possible when deleting an SA */
  (void) ipsec_call_add_del_callbacks (im, sa, sa_index, 0);

  if (ipsec_sa_is_set_IS_ASYNC (sa))
    {
      if (!ipsec_sa_is_set_IS_AEAD (sa))
	vnet_crypto_key_del (vm, sa->crypto_async_key_index);
    }

  if (ipsec_sa_is_set_UDP_ENCAP (sa) && ipsec_sa_is_set_IS_INBOUND (sa))
    ipsec_unregister_udp_port (clib_net_to_host_u16 (sa->udp_hdr.dst_port),
			       !ipsec_sa_is_set_IS_TUNNEL_V6 (sa));

  if (ipsec_sa_is_set_IS_TUNNEL (sa) && !ipsec_sa_is_set_IS_INBOUND (sa))
    dpo_reset (&sa->dpo);
  vnet_crypto_key_del (vm, sa->crypto_sync_key_index);
  if (sa->integ_alg != IPSEC_INTEG_ALG_NONE)
    vnet_crypto_key_del (vm, sa->integ_sync_key_index);
  pool_put (ipsec_sa_pool, sa);
}

int
ipsec_sa_bind (u32 id, u32 worker, bool bind)
{
  ipsec_main_t *im = &ipsec_main;
  uword *p;
  ipsec_sa_t *sa;

  p = hash_get (im->sa_index_by_sa_id, id);
  if (!p)
    return VNET_API_ERROR_INVALID_VALUE;

  sa = ipsec_sa_get (p[0]);

  if (!bind)
    {
      sa->thread_index = ~0;
      return 0;
    }

  if (worker >= vlib_num_workers ())
    return VNET_API_ERROR_INVALID_WORKER;

  sa->thread_index = vlib_get_worker_thread_index (worker);
  return 0;
}

void
ipsec_sa_unlock (index_t sai)
{
  ipsec_sa_t *sa;

  if (INDEX_INVALID == sai)
    return;

  sa = ipsec_sa_get (sai);

  fib_node_unlock (&sa->node);
}

void
ipsec_sa_lock (index_t sai)
{
  ipsec_sa_t *sa;

  if (INDEX_INVALID == sai)
    return;

  sa = ipsec_sa_get (sai);

  fib_node_lock (&sa->node);
}

index_t
ipsec_sa_find_and_lock (u32 id)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;
  uword *p;

  p = hash_get (im->sa_index_by_sa_id, id);

  if (!p)
    return INDEX_INVALID;

  sa = ipsec_sa_get (p[0]);

  fib_node_lock (&sa->node);

  return (p[0]);
}

int
ipsec_sa_unlock_id (u32 id)
{
  ipsec_main_t *im = &ipsec_main;
  uword *p;

  p = hash_get (im->sa_index_by_sa_id, id);

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  ipsec_sa_unlock (p[0]);

  return (0);
}

void
ipsec_sa_clear (index_t sai)
{
  vlib_zero_combined_counter (&ipsec_sa_counters, sai);
  for (int i = 0; i < IPSEC_SA_N_ERRORS; i++)
    vlib_zero_simple_counter (&ipsec_sa_err_counters[i], sai);
}

void
ipsec_sa_walk (ipsec_sa_walk_cb_t cb, void *ctx)
{
  ipsec_sa_t *sa;

  /* *INDENT-OFF* */
  pool_foreach (sa, ipsec_sa_pool)
    {
      if (WALK_CONTINUE != cb (sa, ctx))
	break;
    }
  /* *INDENT-ON* */
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
ipsec_sa_fib_node_get (fib_node_index_t index)
{
  ipsec_sa_t *sa;

  sa = ipsec_sa_get (index);

  return (&sa->node);
}

static ipsec_sa_t *
ipsec_sa_from_fib_node (fib_node_t *node)
{
  ASSERT (FIB_NODE_TYPE_IPSEC_SA == node->fn_type);
  return (
    (ipsec_sa_t *) (((char *) node) - STRUCT_OFFSET_OF (ipsec_sa_t, node)));
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
ipsec_sa_last_lock_gone (fib_node_t *node)
{
  /*
   * The ipsec SA is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ipsec_sa_del (ipsec_sa_from_fib_node (node));
}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
ipsec_sa_back_walk (fib_node_t *node, fib_node_back_walk_ctx_t *ctx)
{
  ipsec_sa_stack (ipsec_sa_from_fib_node (node));

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * Virtual function table registered by SAs
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t ipsec_sa_vft = {
  .fnv_get = ipsec_sa_fib_node_get,
  .fnv_last_lock = ipsec_sa_last_lock_gone,
  .fnv_back_walk = ipsec_sa_back_walk,
};

/* Init per-SA error counters and node type */
clib_error_t *
ipsec_sa_init (vlib_main_t *vm)
{
  fib_node_register_type (FIB_NODE_TYPE_IPSEC_SA, &ipsec_sa_vft);

#define _(index, val, err, desc)                                              \
  ipsec_sa_err_counters[index].name =                                         \
    (char *) format (0, "SA-" #err "%c", 0);                                  \
  ipsec_sa_err_counters[index].stat_segment_name =                            \
    (char *) format (0, "/net/ipsec/sa/err/" #err "%c", 0);                   \
  ipsec_sa_err_counters[index].counters = 0;
  foreach_ipsec_sa_err
#undef _
    return 0;
}

VLIB_INIT_FUNCTION (ipsec_sa_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
