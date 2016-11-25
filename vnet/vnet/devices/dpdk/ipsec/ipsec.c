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
#include <vnet/devices/dpdk/dpdk.h>
#include <vnet/devices/dpdk/ipsec/ipsec.h>
#include <vnet/devices/dpdk/ipsec/esp.h>
#include <vnet/ipsec/ipsec.h>

#define DPDK_CRYPTO_NB_OBJS	  2048
#define DPDK_CRYPTO_CACHE_SIZE	  512
#define DPDK_CRYPTO_PRIV_SIZE	  128
#define DPDK_CRYPTO_N_QUEUE_DESC  512
#define DPDK_CRYPTO_NB_COPS	  (1024 * 4)

/*
 * return:
 * -1: 	update failed
 * 0:	already exist
 * 1:	mapped
 */
static int
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
	  return 0;
    }
  /* *INDENT-ON* */

  vec_add2 (cwm->qp_data, qpd, 1);

  qpd->dev_id = cdev_id;
  qpd->qp_id = qp_id;
  qpd->is_outbound = is_outbound;

  return 1;
}

/*
 * return:
 * 	-1: error
 * 	0: already exist
 * 	1: mapped
 */
static int
add_mapping (crypto_worker_main_t * cwm,
	     u8 cdev_id, u16 qp, u8 is_outbound,
	     const struct rte_cryptodev_capabilities *cipher_cap,
	     const struct rte_cryptodev_capabilities *auth_cap)
{
  int mapped;
  u16 qp_index;
  uword key = 0, data, *ret;
  crypto_worker_qp_key_t *p_key = (crypto_worker_qp_key_t *) & key;

  p_key->cipher_algo = (u8) cipher_cap->sym.cipher.algo;
  p_key->auth_algo = (u8) auth_cap->sym.auth.algo;
  p_key->is_outbound = is_outbound;

  ret = hash_get (cwm->algo_qp_map, key);
  if (ret)
    return 0;

  mapped = update_qp_data (cwm, cdev_id, qp, is_outbound, &qp_index);
  if (mapped < 0)
    return -1;

  data = (uword) qp_index;

  ret = hash_set (cwm->algo_qp_map, key, data);
  if (!ret)
    rte_panic ("Failed to insert hash table\n");

  return mapped;
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
      if (i->sym.xform_type != RTE_CRYPTO_SYM_XFORM_CIPHER)
	continue;

      if (check_algo_is_supported (i, NULL) != 0)
	continue;

      for (j = dev_info->capabilities; j->op != RTE_CRYPTO_OP_TYPE_UNDEFINED;
	   j++)
	{
	  int status = 0;

	  if (j->sym.xform_type != RTE_CRYPTO_SYM_XFORM_AUTH)
	    continue;

	  if (check_algo_is_supported (j, NULL) != 0)
	    continue;

	  status = add_mapping (cwm, cdev_id, qp, is_outbound, i, j);
	  if (status == 1)
	    mapped += 1;
	  if (status < 0)
	    return status;
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
dpdk_ipsec_init (vlib_main_t * vm)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  struct rte_cryptodev_config dev_conf;
  struct rte_cryptodev_qp_conf qp_conf;
  struct rte_cryptodev_info cdev_info;
  struct rte_mempool *rmp;
  i32 dev_id, ret;
  u32 i, skip_master;

  if (check_cryptodev_queues () < 0)
    return clib_error_return (0, "not enough cryptodevs for ipsec");

  vec_alloc (dcm->workers_main, tm->n_vlib_mains);
  _vec_len (dcm->workers_main) = tm->n_vlib_mains;

  fprintf (stdout, "DPDK Cryptodevs info:\n");
  fprintf (stdout, "dev_id\tn_qp\tnb_obj\tcache_size\n");
  /* HW cryptodevs have higher dev_id, use HW first */
  for (dev_id = rte_cryptodev_count () - 1; dev_id >= 0; dev_id--)
    {
      u16 max_nb_qp, qp = 0;
      skip_master = vlib_num_workers () > 0;

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
		return clib_error_return (0, "unable to create hash table "
					  "for worker %u",
					  vlib_mains[i]->cpu_index);
	      cwm->algo_qp_map = map;
	    }

	  for (is_outbound = 0; is_outbound < 2 && qp < max_nb_qp;
	       is_outbound++)
	    {
	      int mapped = add_cdev_mapping (cwm, &cdev_info,
					     dev_id, qp, is_outbound);
	      if (mapped > 0)
		qp++;

	      if (mapped < 0)
		return clib_error_return (0,
					  "too many queues for one worker");
	    }
	}

      if (qp == 0)
	continue;

      dev_conf.socket_id = rte_cryptodev_socket_id (dev_id);
      dev_conf.nb_queue_pairs = cdev_info.max_nb_queue_pairs;
      dev_conf.session_mp.nb_objs = DPDK_CRYPTO_NB_OBJS;
      dev_conf.session_mp.cache_size = DPDK_CRYPTO_CACHE_SIZE;

      ret = rte_cryptodev_configure (dev_id, &dev_conf);
      if (ret < 0)
	return clib_error_return (0, "cryptodev %u config error", dev_id);

      qp_conf.nb_descriptors = DPDK_CRYPTO_N_QUEUE_DESC;
      for (qp = 0; qp < dev_conf.nb_queue_pairs; qp++)
	{
	  ret = rte_cryptodev_queue_pair_setup (dev_id, qp, &qp_conf,
						dev_conf.socket_id);
	  if (ret < 0)
	    return clib_error_return (0, "cryptodev %u qp %u setup error",
				      dev_id, qp);
	}
      fprintf (stdout, "%u\t%u\t%u\t%u\n", dev_id, dev_conf.nb_queue_pairs,
	       DPDK_CRYPTO_NB_OBJS, DPDK_CRYPTO_CACHE_SIZE);
    }

  u32 socket_id = rte_socket_id ();

  vec_validate_aligned (dcm->cop_pools, socket_id, CLIB_CACHE_LINE_BYTES);

  /* pool already exists, nothing to do */
  if (dcm->cop_pools[socket_id])
    return 0;

  u8 *pool_name = format (0, "crypto_op_pool_socket%u%c", socket_id, 0);

  rmp = rte_crypto_op_pool_create ((char *) pool_name,
				   RTE_CRYPTO_OP_TYPE_SYMMETRIC,
				   DPDK_CRYPTO_NB_COPS *
				   (1 + vlib_num_workers ()),
				   DPDK_CRYPTO_CACHE_SIZE,
				   DPDK_CRYPTO_PRIV_SIZE, socket_id);
  vec_free (pool_name);

  if (!rmp)
    return clib_error_return (0, "failed to allocate mempool on socket %u",
			      socket_id);
  dcm->cop_pools[socket_id] = rmp;

  dpdk_esp_init ();

  if (vec_len (vlib_mains) == 0)
    vlib_node_set_state (&vlib_global_main, dpdk_crypto_input_node.index,
			 VLIB_NODE_STATE_POLLING);
  else
    for (i = 1; i < tm->n_vlib_mains; i++)
      vlib_node_set_state (vlib_mains[i], dpdk_crypto_input_node.index,
			   VLIB_NODE_STATE_POLLING);

  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (dpdk_ipsec_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
