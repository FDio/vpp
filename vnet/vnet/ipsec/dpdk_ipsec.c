#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/api_errno.h>
#include <vnet/devices/dpdk/dpdk.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/dpdk_ipsec.h>
#include <vnet/ipsec/esp.h>

/*
 * return:
 * 	0: already exist
 * 	1: mapped
 */
static int
add_mapping(uword *map,
	    uint8_t cdev_id, uint16_t qp, uint8_t outbound,
	    const struct rte_cryptodev_capabilities *cipher_cap,
	    const struct rte_cryptodev_capabilities *auth_cap)
{
  uword key, data, *ret;
  ipsec_lcore_qp_key_t *p_key = (ipsec_lcore_qp_key_t *)&key;
  ipsec_qp_data_t *p_data = (ipsec_qp_data_t *)&data;

  p_key->cipher_algo = (uint8_t)cipher_cap->sym.cipher.algo;
  p_key->auth_algo = (uint8_t)auth_cap->sym.auth.algo;
  p_key->outbound = outbound;

  ret = hash_get(map, key);
  if (ret)
	  return 0;

  p_data->dev_id = cdev_id;
  p_data->qp_id = qp;

  ret = hash_set(map, key, data);
  if (!ret)
    rte_panic("Failed to insert hash table\n");

  return 1;
}

static int
check_algo_is_supported(const struct rte_cryptodev_capabilities *cap, char *name)
{
  struct
  {
    uint8_t cipher_algo;
    enum rte_crypto_sym_xform_type type;
    union {
      enum rte_crypto_auth_algorithm auth;
      enum rte_crypto_cipher_algorithm cipher;
    };
    char *name;
  } supported_algo[] = {
      {
	  .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
	  .cipher = RTE_CRYPTO_CIPHER_NULL,
	  .name = "NULL"
      },
      {
	  .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
	  .cipher = RTE_CRYPTO_CIPHER_AES_CBC,
	  .name = "AES_CBC"
      },
      {
	  .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
	  .cipher = RTE_CRYPTO_CIPHER_AES_CTR,
	  .name = "AES_CTR"
      },
      {
	  .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
	  .cipher = RTE_CRYPTO_CIPHER_3DES_CBC,
	  .name = "3DES-CBC"
      },
      {
	  .type = RTE_CRYPTO_SYM_XFORM_AUTH,
	  .auth = RTE_CRYPTO_AUTH_AES_GMAC,
	  .name = "AES-GMAC"
      },
      {
	  .type = RTE_CRYPTO_SYM_XFORM_AUTH,
	  .auth = RTE_CRYPTO_AUTH_SHA1_HMAC,
	  .name = "HMAC-SHA1"
      },
      {
	  .type = RTE_CRYPTO_SYM_XFORM_AUTH,
	  .auth = RTE_CRYPTO_AUTH_AES_XCBC_MAC,
	  .name = "AES-XCBC-MAC"
      },
      {
	  /* tail */
	  .type = RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED
      },
  };
  uint32_t i = 0;

  if (cap->op != RTE_CRYPTO_OP_TYPE_SYMMETRIC)
    return -1;

  while (supported_algo[i]. type != RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED)
    {
      if (cap->sym.xform_type == supported_algo[i].type)
	{
	  if ((cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
	      cap->sym.cipher.algo == supported_algo[i].cipher) ||
	      (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AUTH &&
		  cap->sym.auth.algo == supported_algo[i].auth)) {
	      if (name)
		strcpy(name, supported_algo[i].name);
	      return 0;
	  }
	}

      i ++;
    }

  return -1;
}

/*
 * return:
 * 	0: already exist
 * 	1: mapped
 */
static int
add_cdev_mapping(struct rte_cryptodev_info *dev_info, uint8_t cdev_id,
	uint16_t qp, uint8_t outbound, uword *map)
{
  const struct rte_cryptodev_capabilities *i, *j;
  uint32_t mapped = 0;

  for (i = dev_info->capabilities; i->op != RTE_CRYPTO_OP_TYPE_UNDEFINED; i++)
    {
      if (i->sym.xform_type != RTE_CRYPTO_SYM_XFORM_CIPHER)
	continue;

      if (check_algo_is_supported(i, NULL) != 0)
	continue;

      for (j = dev_info->capabilities; j->op != RTE_CRYPTO_OP_TYPE_UNDEFINED; j++)
	{
	  int status = 0;

	  if (j->sym.xform_type != RTE_CRYPTO_SYM_XFORM_AUTH)
	    continue;

	  if (check_algo_is_supported(j, NULL) != 0)
	    continue;

	  status = add_mapping(map, cdev_id, qp, outbound, i, j);
	  if (status == 1)
	    mapped += 1;
	}
    }

  return mapped;
}

static int
update_qp_data(ipsec_lcore_main_t *lcore_main,
	       u8 cdev_id, u16 qp_id, u8 outbound)
{
  u16 i;

  for (i = 0; i < lcore_main->n_qps; i++)
    {
      if (lcore_main->qp_data[i].dev_id == cdev_id &&
	  lcore_main->qp_data[i].qp_id == qp_id &&
	  lcore_main->qp_data[i].outbound == outbound)
	return 0;
    }

  if (lcore_main->n_qps == MAX_QP_PER_LCORE)
    return -1;

  lcore_main->qp_data[lcore_main->n_qps].dev_id = cdev_id;
  lcore_main->qp_data[lcore_main->n_qps].qp_id = qp_id;
  lcore_main->qp_data[lcore_main->n_qps].outbound = outbound;
  //vec_alloc(lcore_main->qp_data[lcore_main->n_qps].cops, VLIB_FRAME_SIZE);

  lcore_main->n_qps ++;

  return 0;
}

/*
 * check if there is enough sw or hw queues
 * @ret:
 * 	1: use hw cryptodev
 * 	0: use sw cryptodev
 * 	-1: not enough queue in either sw or hw
 */
static int
precheck_cryptodevs()
{
  vlib_thread_main_t * tm = vlib_get_thread_main();
  u32 n_hw_q = 0;
  u32 n_sw_q = 0;
  u8 cdev_id;
  u32 n_req_qs = (tm->n_vlib_mains - 1) * 2;

  for (cdev_id = 0; cdev_id < rte_cryptodev_count(); cdev_id++)
    {
      struct rte_cryptodev_info cdev_info;

      rte_cryptodev_info_get(cdev_id, &cdev_info);

      if (!(cdev_info.feature_flags & RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING))
	continue;

      if ((cdev_info.feature_flags & RTE_CRYPTODEV_FF_HW_ACCELERATED) == 0)
	n_sw_q += cdev_info.max_nb_queue_pairs;
      else
	n_hw_q += cdev_info.max_nb_queue_pairs;
    }

  if (n_hw_q >= n_req_qs)
    return 1;
  else if (n_sw_q >= n_req_qs)
    return 0;
  else
    return -1;
}

static clib_error_t *
dpdk_ipsec_init(vlib_main_t * vm)
{
  dpdk_crypto_main_t * dcm = &dpdk_crypto_main;
  struct rte_cryptodev_config dev_conf;
  struct rte_cryptodev_qp_conf qp_conf;
  struct rte_cryptodev_info cdev_info;
  struct rte_mempool *rmp;
  uint8_t cdev_id;
  int use_hw_dev = 0;
  uint32_t i;
  vlib_thread_main_t * tm = vlib_get_thread_main();

  use_hw_dev = precheck_cryptodevs();
  if (use_hw_dev < 0)
    return clib_error_return(0, "not enough cryptodevs for ipsec");
  if (use_hw_dev > 0)
    clib_warning("Use only HW cryptodevs...\n");
  else
    clib_warning("Use only SW cryptodevs...\n");

  for (i = 1; i < tm->n_vlib_mains; i++)
    {
      printf("set up lcore %u\n", vlib_mains[i]->cpu_index);
      vlib_node_set_state (vlib_mains[i], dpdk_crypto_input_node.index,
			   VLIB_NODE_STATE_POLLING);
    }

  printf("c_id\tn_qp\tnb_obj\tcache_size\n");
  for (cdev_id = 0; cdev_id < rte_cryptodev_count(); cdev_id++)
    {
      uint16_t max_nb_qp, qp = 0;

      rte_cryptodev_info_get(cdev_id, &cdev_info);

      if (!(cdev_info.feature_flags & RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING))
	continue;

      if (use_hw_dev)
	{
	  if ((cdev_info.feature_flags & RTE_CRYPTODEV_FF_HW_ACCELERATED) !=
	      RTE_CRYPTODEV_FF_HW_ACCELERATED)
	    continue;

	  max_nb_qp = cdev_info.max_nb_queue_pairs;
	}
      else
	{
	  if ((cdev_info.feature_flags & RTE_CRYPTODEV_FF_HW_ACCELERATED) ==
	      RTE_CRYPTODEV_FF_HW_ACCELERATED)
	    continue;

	  max_nb_qp = (tm->n_vlib_mains - 1) * 2;
	}

      for (i = 1; i < tm->n_vlib_mains; i++)
	{
	  u8 outbound;
	  ipsec_lcore_main_t *lcore_main;
	  uword *map;

	  if (!dcm->lcores_main[vlib_mains[i]->cpu_index])
	    {
	      dcm->lcores_main[vlib_mains[i]->cpu_index] =
		  calloc(1, sizeof(ipsec_lcore_main_t));
	      ASSERT(dcm->lcores_main[vlib_mains[i]->cpu_index]);
	    }

	  lcore_main = dcm->lcores_main[vlib_mains[i]->cpu_index];
	  map = lcore_main->algo_qp_map;

	  if (!map)
	    {
	      map = hash_create(0, sizeof(ipsec_lcore_qp_key_t));
	      if (!map)
		return clib_error_return(0, "unable to create hash table for lcore %u",
					 vlib_mains[i]->cpu_index);

	      lcore_main->algo_qp_map = map;
	    }

	  for (outbound = 0; outbound < 2 && qp < max_nb_qp; outbound++)
	    {
	      uint32_t mapped = add_cdev_mapping(&cdev_info, cdev_id, qp, outbound, map);

	      if (mapped > 0)
		{
		  if (update_qp_data(lcore_main, cdev_id, qp, outbound) < 0)
		    return clib_error_return(0, "too many queues for one lcore");
		  qp ++;
		}
	    }
	}

      if (qp == 0)
	continue;

      dev_conf.socket_id = rte_cryptodev_socket_id(cdev_id);
      /* XXX So far all cryptodevs support at least 2qp */
      dev_conf.nb_queue_pairs = qp;
      dev_conf.session_mp.nb_objs = 2048;
      dev_conf.session_mp.cache_size = 512;

      if (rte_cryptodev_configure(cdev_id, &dev_conf))
	return clib_error_return(0, "cryptodev %u config error", cdev_id);

      qp_conf.nb_descriptors = 4096;
      for (qp = 0; qp < dev_conf.nb_queue_pairs; qp++)
	if (rte_cryptodev_queue_pair_setup(cdev_id, qp, &qp_conf, dev_conf.socket_id))
	  return clib_error_return(0, "cryptodev %u qp %u setup error", cdev_id, qp);

      printf("%u\t%u\t%u\t%u\n", cdev_id, dev_conf.nb_queue_pairs, 2048, 128);
    }

  /* print mapping results */
  printf("\nlcore\t%10s\t%15s\tdir\tcdev\tqp\n", "cipher", "auth");

  for (i = 1; i < tm->n_vlib_mains; i++)
    {
      uword *map;
      uword key, data;

      map = dcm->lcores_main[vlib_mains[i]->cpu_index]->algo_qp_map;

      hash_foreach (key, data, map, ({
	char cipher_str[15], auth_str[15];
	struct rte_cryptodev_capabilities cap;
	ipsec_lcore_qp_key_t *p_key = (ipsec_lcore_qp_key_t *)&key;
	ipsec_qp_data_t *p_data = (ipsec_qp_data_t *)&data;

	cap.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
	cap.sym.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	cap.sym.cipher.algo = p_key->cipher_algo;
	check_algo_is_supported(&cap, cipher_str);

	cap.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
	cap.sym.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH;
	cap.sym.auth.algo = p_key->auth_algo;
	check_algo_is_supported(&cap, auth_str);

	printf("%u\t%10s\t%15s\t%3s\t%u\t%u\n",
	       vlib_mains[i]->cpu_index,
	       cipher_str,
	       auth_str,
	       p_key->outbound?"out":"in",
	       p_data->dev_id,
	       p_data->qp_id);
      }));
  }

  unsigned socket_id = rte_socket_id();

  vec_validate_aligned(dcm->cop_pools, socket_id, CLIB_CACHE_LINE_BYTES);

  /* pool already exists, nothing to do */
  if (dcm->cop_pools[socket_id])
    return 0;

  u8 * pool_name = format(0, "cop_pool_socket%u%c",socket_id, 0);

  rmp = rte_crypto_op_pool_create(
      (char *) pool_name,           /* pool name */
      RTE_CRYPTO_OP_TYPE_SYMMETRIC, /* crypto op type */
      32 * 1024,                    /* number of cops */
      512,                          /* cache size */
      64,                           /* priv size */
      socket_id);                   /* cpu socket */

  vec_free(pool_name);

  if (!rmp)
    return clib_error_return (0, "failed to allocate mempool on socket %u",
			      socket_id);
  dcm->cop_pools[socket_id] = rmp;

  dpdk_esp_init();

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


