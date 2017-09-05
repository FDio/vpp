/*
 * Copyright (c) 2016 Intel and/or its affiliates.
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
#include <vnet/ip/ip.h>
#include <vnet/api_errno.h>
#include <vnet/ipsec/ipsec.h>
#include <vlib/node_funcs.h>

#include <dpdk/device/dpdk.h>
#include <dpdk/ipsec/ipsec.h>
#include <dpdk/ipsec/esp.h>

#define DPDK_CRYPTO_NB_SESS_OBJS  20000
#define DPDK_CRYPTO_CACHE_SIZE	  512
#define DPDK_CRYPTO_PRIV_SIZE	  128
#define DPDK_CRYPTO_N_QUEUE_DESC  1024
#define DPDK_CRYPTO_NB_COPS	  (1024 * 4)

static int
add_del_sa_sess (u32 sa_index, u8 is_add)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_worker_main_t *cwm;
  u8 skip_master = vlib_num_workers () > 0;

  /* *INDENT-OFF* */
  vec_foreach (cwm, dcm->workers_main)
    {
      crypto_sa_session_t *sa_sess;
      u8 is_outbound;

      if (skip_master)
	{
	  skip_master = 0;
	  continue;
	}

      for (is_outbound = 0; is_outbound < 2; is_outbound++)
	{
	  if (is_add)
	    {
	      pool_get (cwm->sa_sess_d[is_outbound], sa_sess);
	    }
	  else
	    {
	      u8 dev_id;
	      i32 ret;

	      sa_sess = pool_elt_at_index (cwm->sa_sess_d[is_outbound], sa_index);
	      dev_id = cwm->qp_data[sa_sess->qp_index].dev_id;

	      if (!sa_sess->sess)
		continue;
#if DPDK_NO_AEAD
	      ret = (rte_cryptodev_sym_session_free(dev_id, sa_sess->sess) == NULL);
	      ASSERT (ret);
#else
	      ret = rte_cryptodev_sym_session_clear(dev_id, sa_sess->sess);
	      ASSERT (!ret);

	      ret = rte_cryptodev_sym_session_free(sa_sess->sess);
	      ASSERT (!ret);
#endif
	      memset(sa_sess, 0, sizeof(sa_sess[0]));
	    }
	}
    }
  /* *INDENT-OFF* */

  return 0;
}

static void
update_qp_data (crypto_worker_main_t * cwm,
		u8 cdev_id, u16 qp_id, u8 is_outbound, u16 * idx)
{
  crypto_qp_data_t *qpd;

  /* *INDENT-OFF* */
  vec_foreach_index (*idx, cwm->qp_data)
    {
      qpd = vec_elt_at_index(cwm->qp_data, *idx);

      if (qpd->dev_id == cdev_id && qpd->qp_id == qp_id &&
	  qpd->is_outbound == is_outbound)
	  return;
    }
  /* *INDENT-ON* */

  vec_add2_aligned (cwm->qp_data, qpd, 1, CLIB_CACHE_LINE_BYTES);

  qpd->dev_id = cdev_id;
  qpd->qp_id = qp_id;
  qpd->is_outbound = is_outbound;
}

/*
 * return:
 * 	0: already exist
 * 	1: mapped
 */
static int
add_mapping (crypto_worker_main_t * cwm,
	     u8 cdev_id, u16 qp, u8 is_outbound,
	     const struct rte_cryptodev_capabilities *cipher_cap,
	     const struct rte_cryptodev_capabilities *auth_cap)
{
  u16 qp_index;
  uword key = 0, data, *ret;
  crypto_worker_qp_key_t *p_key = (crypto_worker_qp_key_t *) & key;

  p_key->cipher_algo = (u8) cipher_cap->sym.cipher.algo;
  p_key->auth_algo = (u8) auth_cap->sym.auth.algo;
  p_key->is_outbound = is_outbound;
#if ! DPDK_NO_AEAD
  p_key->is_aead = cipher_cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD;
#endif

  ret = hash_get (cwm->algo_qp_map, key);
  if (ret)
    return 0;

  update_qp_data (cwm, cdev_id, qp, is_outbound, &qp_index);

  data = (uword) qp_index;
  hash_set (cwm->algo_qp_map, key, data);

  return 1;
}

/*
 * return:
 * 	0: already exist
 * 	1: mapped
 */
static int
add_cdev_mapping (crypto_worker_main_t * cwm,
		  struct rte_cryptodev_info *dev_info, u8 cdev_id,
		  u16 qp, u8 is_outbound)
{
  const struct rte_cryptodev_capabilities *i, *j;
  u32 mapped = 0;

  for (i = dev_info->capabilities; i->op != RTE_CRYPTO_OP_TYPE_UNDEFINED; i++)
    {
#if ! DPDK_NO_AEAD
      if (i->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD)
	{
	  struct rte_cryptodev_capabilities none = { 0 };

	  if (check_algo_is_supported (i, NULL) != 0)
	    continue;

	  none.sym.auth.algo = RTE_CRYPTO_AUTH_NULL;

	  mapped |= add_mapping (cwm, cdev_id, qp, is_outbound, i, &none);
	  continue;
	}
#endif
      if (i->sym.xform_type != RTE_CRYPTO_SYM_XFORM_CIPHER)
	continue;

      if (check_algo_is_supported (i, NULL) != 0)
	continue;

      for (j = dev_info->capabilities; j->op != RTE_CRYPTO_OP_TYPE_UNDEFINED;
	   j++)
	{
	  if (j->sym.xform_type != RTE_CRYPTO_SYM_XFORM_AUTH)
	    continue;

	  if (check_algo_is_supported (j, NULL) != 0)
	    continue;

	  mapped |= add_mapping (cwm, cdev_id, qp, is_outbound, i, j);
	}
    }

  return mapped;
}

static int
check_cryptodev_queues ()
{
  u32 n_qs = 0;
  u8 cdev_id;
  u32 n_req_qs = 2;

  if (vlib_num_workers () > 0)
    n_req_qs = vlib_num_workers () * 2;

  for (cdev_id = 0; cdev_id < rte_cryptodev_count (); cdev_id++)
    {
      struct rte_cryptodev_info cdev_info;

      rte_cryptodev_info_get (cdev_id, &cdev_info);

      if (!
	  (cdev_info.feature_flags & RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING))
	continue;

      n_qs += cdev_info.max_nb_queue_pairs;
    }

  if (n_qs >= n_req_qs)
    return 0;
  else
    return -1;
}

static clib_error_t *
dpdk_ipsec_check_support (ipsec_sa_t * sa)
{
  if (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128)
    {
      if (sa->integ_alg != IPSEC_INTEG_ALG_NONE)
	return clib_error_return (0, "unsupported integ-alg %U with "
				  "crypto-alg aes-gcm-128",
				  format_ipsec_integ_alg, sa->integ_alg);
#if DPDK_NO_AEAD
      sa->integ_alg = IPSEC_INTEG_ALG_AES_GCM_128;
#endif
    }
#if DPDK_NO_AEAD
  else if (sa->crypto_alg == IPSEC_CRYPTO_ALG_NONE ||
	   sa->integ_alg == IPSEC_INTEG_ALG_NONE ||
	   sa->integ_alg == IPSEC_INTEG_ALG_AES_GCM_128)
#else
  else if (sa->integ_alg == IPSEC_INTEG_ALG_NONE)
#endif
    return clib_error_return (0,
			      "unsupported integ-alg %U with crypto-alg %U",
			      format_ipsec_integ_alg, sa->integ_alg,
			      format_ipsec_crypto_alg, sa->crypto_alg);

  return 0;
}

static uword
dpdk_ipsec_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		    vlib_frame_t * f)
{
  ipsec_main_t *im = &ipsec_main;
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  struct rte_cryptodev_config dev_conf;
  struct rte_cryptodev_qp_conf qp_conf;
  struct rte_cryptodev_info cdev_info;
  struct rte_mempool *rmp;
  i32 dev_id, ret;
  u32 i, skip_master;
#if ! DPDK_NO_AEAD
  u32 max_sess_size = 0, sess_size;
  i8 socket_id;
#endif

  if (check_cryptodev_queues () < 0)
    {
      clib_warning ("not enough Cryptodevs, default to OpenSSL IPsec");
      return 0;
    }
  dcm->enabled = 1;

  vec_alloc (dcm->workers_main, tm->n_vlib_mains);
  _vec_len (dcm->workers_main) = tm->n_vlib_mains;

  skip_master = vlib_num_workers () > 0;

  fprintf (stdout, "DPDK Cryptodevs info:\n");
  fprintf (stdout, "dev_id\tn_qp\tnb_obj\tcache_size\n");
  /* HW cryptodevs have higher dev_id, use HW first */
  for (dev_id = rte_cryptodev_count () - 1; dev_id >= 0; dev_id--)
    {
      u16 max_nb_qp, qp = 0;

      rte_cryptodev_info_get (dev_id, &cdev_info);

      if (!
	  (cdev_info.feature_flags & RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING))
	continue;

      max_nb_qp = cdev_info.max_nb_queue_pairs;

      for (i = 0; i < tm->n_vlib_mains; i++)
	{
	  u8 is_outbound;
	  crypto_worker_main_t *cwm;
	  uword *map;

	  if (skip_master)
	    {
	      skip_master = 0;
	      continue;
	    }

	  cwm = vec_elt_at_index (dcm->workers_main, i);
	  map = cwm->algo_qp_map;

	  if (!map)
	    {
	      map = hash_create (0, sizeof (crypto_worker_qp_key_t));
	      if (!map)
		{
		  clib_warning ("unable to create hash table for worker %u",
				vlib_mains[i]->thread_index);
		  goto error;
		}
	      cwm->algo_qp_map = map;
	    }

	  for (is_outbound = 0; is_outbound < 2 && qp < max_nb_qp;
	       is_outbound++)
	    qp += add_cdev_mapping (cwm, &cdev_info, dev_id, qp, is_outbound);
	}

      if (qp == 0)
	continue;

      dev_conf.socket_id = rte_cryptodev_socket_id (dev_id);
      dev_conf.nb_queue_pairs = cdev_info.max_nb_queue_pairs;
#if DPDK_NO_AEAD
      dev_conf.session_mp.nb_objs = DPDK_CRYPTO_NB_SESS_OBJS;
      dev_conf.session_mp.cache_size = DPDK_CRYPTO_CACHE_SIZE;
#endif
      ret = rte_cryptodev_configure (dev_id, &dev_conf);
      if (ret < 0)
	{
	  clib_warning ("cryptodev %u config error", dev_id);
	  goto error;
	}

      qp_conf.nb_descriptors = DPDK_CRYPTO_N_QUEUE_DESC;
      for (qp = 0; qp < dev_conf.nb_queue_pairs; qp++)
	{
#if DPDK_NO_AEAD
	  ret = rte_cryptodev_queue_pair_setup (dev_id, qp, &qp_conf,
						dev_conf.socket_id);
#else
	  ret = rte_cryptodev_queue_pair_setup (dev_id, qp, &qp_conf,
						dev_conf.socket_id, NULL);
#endif
	  if (ret < 0)
	    {
	      clib_warning ("cryptodev %u qp %u setup error", dev_id, qp);
	      goto error;
	    }
	}
      vec_validate (dcm->cop_pools, dev_conf.socket_id);

#if ! DPDK_NO_AEAD
      sess_size = rte_cryptodev_get_private_session_size (dev_id);
      if (sess_size > max_sess_size)
	max_sess_size = sess_size;
#endif

      if (!vec_elt (dcm->cop_pools, dev_conf.socket_id))
	{
	  u8 *pool_name = format (0, "crypto_op_pool_socket%u%c",
				  dev_conf.socket_id, 0);

	  rmp = rte_crypto_op_pool_create ((char *) pool_name,
					   RTE_CRYPTO_OP_TYPE_SYMMETRIC,
					   DPDK_CRYPTO_NB_COPS *
					   (1 + vlib_num_workers ()),
					   DPDK_CRYPTO_CACHE_SIZE,
					   DPDK_CRYPTO_PRIV_SIZE,
					   dev_conf.socket_id);

	  if (!rmp)
	    {
	      clib_warning ("failed to allocate %s", pool_name);
	      vec_free (pool_name);
	      goto error;
	    }
	  vec_free (pool_name);
	  vec_elt (dcm->cop_pools, dev_conf.socket_id) = rmp;
	}

      fprintf (stdout, "%u\t%u\t%u\t%u\n", dev_id, dev_conf.nb_queue_pairs,
	       DPDK_CRYPTO_NB_SESS_OBJS, DPDK_CRYPTO_CACHE_SIZE);
    }

#if ! DPDK_NO_AEAD
  /* *INDENT-OFF* */
  vec_foreach_index (socket_id, dcm->cop_pools)
    {
      u8 *pool_name;

      if (!vec_elt (dcm->cop_pools, socket_id))
	continue;

      vec_validate (dcm->sess_h_pools, socket_id);
      pool_name = format (0, "crypto_sess_h_socket%u%c",
			      socket_id, 0);
      rmp =
	rte_mempool_create((i8 *)pool_name, DPDK_CRYPTO_NB_SESS_OBJS,
			   rte_cryptodev_get_header_session_size (),
			   512, 0, NULL, NULL, NULL, NULL,
			   socket_id, 0);
      if (!rmp)
	{
	  clib_warning ("failed to allocate %s", pool_name);
	  vec_free (pool_name);
	  goto error;
	}
      vec_free (pool_name);
      vec_elt (dcm->sess_h_pools, socket_id) = rmp;

      vec_validate (dcm->sess_pools, socket_id);
      pool_name = format (0, "crypto_sess_socket%u%c",
			      socket_id, 0);
      rmp =
	rte_mempool_create((i8 *)pool_name, DPDK_CRYPTO_NB_SESS_OBJS,
			   max_sess_size, 512, 0, NULL, NULL, NULL, NULL,
			   socket_id, 0);
      if (!rmp)
	{
	  clib_warning ("failed to allocate %s", pool_name);
	  vec_free (pool_name);
	  goto error;
	}
      vec_free (pool_name);
      vec_elt (dcm->sess_pools, socket_id) = rmp;
    }
  /* *INDENT-ON* */
#endif

  dpdk_esp_init ();

  /* Add new next node and set as default */
  vlib_node_t *node, *next_node;

  next_node = vlib_get_node_by_name (vm, (u8 *) "dpdk-esp-encrypt");
  ASSERT (next_node);
  node = vlib_get_node_by_name (vm, (u8 *) "ipsec-output-ip4");
  ASSERT (node);
  im->esp_encrypt_node_index = next_node->index;
  im->esp_encrypt_next_index =
    vlib_node_add_next (vm, node->index, next_node->index);

  next_node = vlib_get_node_by_name (vm, (u8 *) "dpdk-esp-decrypt");
  ASSERT (next_node);
  node = vlib_get_node_by_name (vm, (u8 *) "ipsec-input-ip4");
  ASSERT (node);
  im->esp_decrypt_node_index = next_node->index;
  im->esp_decrypt_next_index =
    vlib_node_add_next (vm, node->index, next_node->index);

  im->cb.check_support_cb = dpdk_ipsec_check_support;
  im->cb.add_del_sa_sess_cb = add_del_sa_sess;

  for (i = skip_master; i < tm->n_vlib_mains; i++)
    vlib_node_set_state (vlib_mains[i], dpdk_crypto_input_node.index,
			 VLIB_NODE_STATE_POLLING);

  /* TODO cryptodev counters */

  return 0;

error:
  ;
  crypto_worker_main_t *cwm;
  struct rte_mempool **mp;
  /* *INDENT-OFF* */
  vec_foreach (cwm, dcm->workers_main)
    hash_free (cwm->algo_qp_map);

  vec_foreach (mp, dcm->cop_pools)
    {
      if (mp)
	rte_mempool_free (mp[0]);
    }
  /* *INDENT-ON* */
  vec_free (dcm->workers_main);
  vec_free (dcm->cop_pools);

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_ipsec_process_node,static) = {
    .function = dpdk_ipsec_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "dpdk-ipsec-process",
    .process_log2_n_stack_bytes = 17,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
