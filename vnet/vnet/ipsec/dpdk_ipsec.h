#ifndef __DPDK_IPSEC_H__
#define __DPDK_IPSEC_H__

#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_config.h>

#define MAX_QP_PER_LCORE 256

typedef struct
{
  u8 cipher_algo;
  u8 auth_algo;
  u8 outbound;
} ipsec_lcore_qp_key_t;

typedef struct
{
  u8 dev_id;
  u16 qp_id;
  u8 outbound;
  u16 n_ops;
  struct rte_crypto_op **cops;
} ipsec_qp_data_t;

typedef struct
{
  uword *algo_qp_map;
  ipsec_qp_data_t qp_data[MAX_QP_PER_LCORE];
  u16 n_qps;
} ipsec_lcore_main_t;

typedef struct {
  struct rte_mempool **cop_pools;
  ipsec_lcore_main_t *lcores_main[RTE_MAX_LCORE];
} dpdk_crypto_main_t;

typedef struct {
  u32 iv[4];
} dpdk_cop_priv_t;

dpdk_crypto_main_t dpdk_crypto_main;

extern vlib_node_registration_t dpdk_crypto_input_node;

always_inline void
ipsec_alloc_cops()
{
  dpdk_crypto_main_t * dcm = &dpdk_crypto_main;
  u32 cpu_index = os_get_cpu_number();
  ipsec_lcore_main_t *lcore_main = dcm->lcores_main[cpu_index];
  unsigned socket_id = rte_socket_id();
  u32 i;

  for (i = 0; i < lcore_main->n_qps; i++)
    {
      u32 l = vec_len (lcore_main->qp_data[i].cops);

      if (PREDICT_FALSE(l < VLIB_FRAME_SIZE))
	{
	  u32 n_alloc;

	  if (PREDICT_FALSE(!lcore_main->qp_data[i].cops))
	    vec_alloc (lcore_main->qp_data[i].cops, VLIB_FRAME_SIZE * 2);

	  n_alloc = rte_crypto_op_bulk_alloc(
	      dcm->cop_pools[socket_id], RTE_CRYPTO_OP_TYPE_SYMMETRIC,
	      &lcore_main->qp_data[i].cops[l], VLIB_FRAME_SIZE * 2 - l);

	  _vec_len (lcore_main->qp_data[i].cops) = l + n_alloc;
	}
    }
}

always_inline void
ipsec_free_cop(ipsec_qp_data_t *qp_data, struct rte_crypto_op *cop)
{
  u32 l = vec_len (qp_data->cops);
  i32 n_dealloc = 0;

  ASSERT(cop);

  if (PREDICT_FALSE(l == 2 * VLIB_FRAME_SIZE))
    {
      rte_mempool_put_bulk(cop->mempool,
			   (void **)&qp_data->cops[VLIB_FRAME_SIZE],
			   VLIB_FRAME_SIZE);
      n_dealloc -= VLIB_FRAME_SIZE;
    }

  qp_data->cops[l + n_dealloc] = cop;

  _vec_len (qp_data->cops) = l + n_dealloc + 1;
}


#endif /* __DPDK_IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
