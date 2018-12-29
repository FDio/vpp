/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/linux/syscall.h>
#include <vnet/plugin/plugin.h>
#include <marvell/pp2/pp2.h>

/* size of DMA memory used by musdk (not used for buffers) */
#define MV_SYS_DMA_MEM_SZ		(2 << 20)
/* number of HIFs reserved (first X) */
#define NUM_HIFS_RSVD			4
/* number of buffer pools reserved (first X) */
#define NUM_BPOOLS_RSVD			7

mrvl_pp2_main_t mrvl_pp2_main;
extern vnet_device_class_t ppa2_device_class;

static void
mrvl_pp2_main_deinit ()
{
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  int i;
  vec_foreach_index (i, ppm->per_thread_data)
  {
    mrvl_pp2_per_thread_data_t *ptd = vec_elt_at_index (ppm->per_thread_data,
							i);
    if (ptd->hif)
      pp2_hif_deinit (ptd->hif);
    vec_free (ptd->descs);
  }
  vec_free (ppm->per_thread_data);
  pp2_deinit ();
  mv_sys_dma_mem_destroy ();
}

static clib_error_t *
mrvl_pp2_main_init ()
{
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *err = 0;
  struct pp2_init_params init_params = { 0 };
  int i, rv;
  u8 *s = 0;

  rv = mv_sys_dma_mem_init (MV_SYS_DMA_MEM_SZ);
  if (rv)
    return clib_error_return (0, "mv_sys_dma_mem_init failed, rv = %u", rv);

  init_params.hif_reserved_map = ((1 << NUM_HIFS_RSVD) - 1);
  init_params.bm_pool_reserved_map = ((1 << NUM_BPOOLS_RSVD) - 1);
  rv = pp2_init (&init_params);
  if (rv)
    {
      err = clib_error_return (0, "mrvl_pp2_init failed, rv = %u", rv);
      goto done;
    }

  vec_validate_aligned (ppm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  vec_foreach_index (i, ppm->per_thread_data)
  {
    mrvl_pp2_per_thread_data_t *ptd = vec_elt_at_index (ppm->per_thread_data,
							i);
    struct pp2_hif_params hif_params = { 0 };
    vec_reset_length (s);
    s = format (s, "hif-%d%c", NUM_HIFS_RSVD + i, 0);
    hif_params.match = (char *) s;
    hif_params.out_size = 2048;	/* FIXME */
    if (pp2_hif_init (&hif_params, &ptd->hif))
      {
	err = clib_error_return (0, "hif '%s' init failed", s);
	goto done;
      }
  }

done:
  if (err)
    mrvl_pp2_main_deinit ();
  vec_free (s);
  return err;
}

static u32
mrvl_pp2_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi,
			  u32 flags)
{
  /* nothing for now */
  return 0;
}

void
mrvl_pp2_delete_if (mrvl_pp2_if_t * ppif)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  mrvl_pp2_outq_t *outq;
  mrvl_pp2_inq_t *inq;
  int i;

  if (ppif->hw_if_index != ~0)
    {
      vec_foreach_index (i, ppif->inqs)
	vnet_hw_interface_unassign_rx_thread (vnm, ppif->hw_if_index, i);
      ethernet_delete_interface (vnm, ppif->hw_if_index);
    }

  if (ppif->ppio)
    {
      pp2_ppio_disable (ppif->ppio);
      pp2_ppio_deinit (ppif->ppio);
    }

  /* *INDENT-OFF* */
  /* free buffers hanging in the tx ring */
  vec_foreach (outq, ppif->outqs)
    {
      while (outq->tail < outq->head)
	{
	  u16 slot = outq->tail & (outq->size - 1);
	  vlib_buffer_free (vm, outq->buffers + slot, 1);
	  outq->tail++;
	}
      vec_free (outq->buffers);
    }
  vec_free (ppif->outqs);

  /* free buffers hangin in the rx buffer pool */
  vec_foreach (inq, ppif->inqs)
    if (inq->bpool)
      {
	u32 n_bufs = 0;
	pp2_bpool_get_num_buffs (inq->bpool, &n_bufs);
	while (n_bufs--)
	  {
	    struct pp2_buff_inf binf;
	    if (pp2_bpool_get_buff (ppm->per_thread_data[0].hif, inq->bpool,
				    &binf) == 0)
	      {
	         u32 bi = binf.cookie;
	         vlib_buffer_free (vm, &bi, 1);
	      }
	  }
	pp2_bpool_deinit (inq->bpool);
      }
  vec_free (ppif->inqs);
  /* *INDENT-ON* */


  pool_put (ppm->interfaces, ppif);

  if (pool_elts (ppm->interfaces) == 0)
    mrvl_pp2_main_deinit ();
}

void
mrvl_pp2_create_if (mrvl_pp2_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  struct pp2_bpool_params bpool_params = { 0 };
  struct pp2_ppio_params ppio_params = { 0 };
  struct pp2_ppio_inq_params inq_params = { 0 };
  vnet_sw_interface_t *sw;
  mrvl_pp2_if_t *ppif = 0;
  u8 pp2_id, port_id, *s = 0;
  eth_addr_t mac_addr;
  u8 n_outqs, n_inqs = 1;
  int i;

  if (tm->n_vlib_mains > PP2_PPIO_MAX_NUM_OUTQS)
    {
      args->rv = VNET_API_ERROR_INIT_FAILED;
      args->error = clib_error_return (0, "number of threads (main + workers)"
				       " is bigger than number of output "
				       "queues (%u)", PP2_PPIO_MAX_NUM_OUTQS);
      return;
    }
  n_outqs = tm->n_vlib_mains;

  /* defaults */
  args->tx_q_sz = args->tx_q_sz ? args->tx_q_sz : 2 * VLIB_FRAME_SIZE;
  args->rx_q_sz = args->rx_q_sz ? args->rx_q_sz : 2 * VLIB_FRAME_SIZE;

  if (vec_len (ppm->per_thread_data) == 0)
    {
      if ((args->error = mrvl_pp2_main_init ()) != 0)
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  return;
	}
    }

  pool_get_zero (ppm->interfaces, ppif);
  ppif->dev_instance = ppif - ppm->interfaces;
  ppif->hw_if_index = ~0;
  vec_validate_aligned (ppif->inqs, n_inqs - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ppif->outqs, n_outqs - 1, CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < n_inqs; i++)
    {
      mrvl_pp2_inq_t *inq = vec_elt_at_index (ppif->inqs, i);
      inq->size = args->rx_q_sz;
    }
  for (i = 0; i < n_outqs; i++)
    {
      mrvl_pp2_outq_t *outq = vec_elt_at_index (ppif->outqs, i);
      outq->size = args->tx_q_sz;
      vec_validate_aligned (outq->buffers, outq->size, CLIB_CACHE_LINE_BYTES);
    }

  if (pp2_netdev_get_ppio_info ((char *) args->name, &pp2_id, &port_id))
    {
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error = clib_error_return (0, "Invalid interface '%s'",
				       args->name);
      goto error;
    }

  /* FIXME bpool bit select per pp */
  s = format (s, "pool-%d:%d%c", pp2_id, pp2_id + 8, 0);
  bpool_params.match = (char *) s;
  bpool_params.buff_len = VLIB_BUFFER_DATA_SIZE;
  /* FIXME +64 ? */
  if (pp2_bpool_init (&bpool_params, &ppif->inqs[0].bpool))
    {
      args->rv = VNET_API_ERROR_INIT_FAILED;
      args->error = clib_error_return (0, "bpool '%s' init failed", s);
      goto error;
    }
  vec_reset_length (s);

  s = format (s, "ppio-%d:%d%c", pp2_id, port_id, 0);
  ppio_params.match = (char *) s;
  ppio_params.type = PP2_PPIO_T_NIC;
  inq_params.size = args->rx_q_sz;
  ppio_params.inqs_params.num_tcs = 1;
  ppio_params.inqs_params.tcs_params[0].pkt_offset = 0;
  ppio_params.inqs_params.tcs_params[0].num_in_qs = n_inqs;
  ppio_params.inqs_params.tcs_params[0].inqs_params = &inq_params;
  ppio_params.inqs_params.tcs_params[0].pools[0][0] = ppif->inqs[0].bpool;
  ppio_params.outqs_params.num_outqs = n_outqs;
  for (i = 0; i < n_outqs; i++)
    {
      ppio_params.outqs_params.outqs_params[i].weight = 1;
      ppio_params.outqs_params.outqs_params[i].size = args->tx_q_sz;
    }
  if (pp2_ppio_init (&ppio_params, &ppif->ppio))
    {
      args->rv = VNET_API_ERROR_INIT_FAILED;
      args->error = clib_error_return (0, "ppio '%s' init failed", s);
      goto error;
    }
  vec_reset_length (s);

  if (pp2_ppio_get_mac_addr (ppif->ppio, mac_addr))
    {
      args->rv = VNET_API_ERROR_INIT_FAILED;
      args->error =
	clib_error_return (0, "%s: pp2_ppio_get_mac_addr failed", s);
      goto error;
    }

  args->error = ethernet_register_interface (vnm, mrvl_pp2_device_class.index,
					     ppif->dev_instance,
					     mac_addr,
					     &ppif->hw_if_index,
					     mrvl_pp2_eth_flag_change);
  if (args->error)
    {
      args->rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto error;
    }

  sw = vnet_get_hw_sw_interface (vnm, ppif->hw_if_index);
  ppif->sw_if_index = sw->sw_if_index;
  ppif->per_interface_next_index = ~0;
  vnet_hw_interface_set_input_node (vnm, ppif->hw_if_index,
				    mrvl_pp2_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, ppif->hw_if_index, 0, ~0);
  vnet_hw_interface_set_rx_mode (vnm, ppif->hw_if_index, 0,
				 VNET_HW_INTERFACE_RX_MODE_POLLING);
  vnet_hw_interface_set_flags (vnm, ppif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  goto done;

error:
  mrvl_pp2_delete_if (ppif);
done:
  vec_free (s);
}

static clib_error_t *
mrvl_pp2_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				  u32 flags)
{
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  mrvl_pp2_if_t *ppif = pool_elt_at_index (ppm->interfaces, hw->dev_instance);
  static clib_error_t *error = 0;
  int is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  int rv;

  if (is_up)
    rv = pp2_ppio_enable (ppif->ppio);
  else
    rv = pp2_ppio_disable (ppif->ppio);

  if (rv)
    return clib_error_return (0, "failed to %s interface",
			      is_up ? "enable" : "disable");

  if (is_up)
    ppif->flags |= MRVL_PP2_IF_F_ADMIN_UP;
  else
    ppif->flags &= ~MRVL_PP2_IF_F_ADMIN_UP;

  return error;
}

static void
mrvl_pp2_clear_interface_counters (u32 instance)
{
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  mrvl_pp2_if_t *ppif = pool_elt_at_index (ppm->interfaces, instance);
  struct pp2_ppio_statistics stats;

  pp2_ppio_get_statistics (ppif->ppio, &stats, 1);
}

static void
mrvl_pp2_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				  u32 node_index)
{
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  mrvl_pp2_if_t *ppif = pool_elt_at_index (ppm->interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ppif->per_interface_next_index = node_index;
      return;
    }

  ppif->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), mrvl_pp2_input_node.index,
			node_index);
}

static char *mrvl_pp2_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_mrvl_pp2_tx_func_error
#undef _
};

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (mrvl_pp2_device_class,) =
{
  .name = "Marvell PPv2 interface",
  .format_device_name = format_mrvl_pp2_interface_name,
  .format_device = format_mrvl_pp2_interface,
  .tx_function = mrvl_pp2_interface_tx,
  .tx_function_n_errors = MRVL_PP2_TX_N_ERROR,
  .tx_function_error_strings = mrvl_pp2_tx_func_error_strings,
  .admin_up_down_function = mrvl_pp2_interface_admin_up_down,
  .clear_counters = mrvl_pp2_clear_interface_counters,
  .rx_redirect_to_node = mrvl_pp2_set_interface_next_node,
};
/* *INDENT-ON* */

static clib_error_t *
mrvl_pp2_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (mrvl_pp2_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
