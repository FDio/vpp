/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <ppv2/ppv2.h>

ppv2_main_t ppv2_main;
extern vnet_device_class_t ppa2_device_class;

static u32
ppv2_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi, u32 flags)
{
  /* nothing for now */
  return 0;
}

static clib_error_t *
ppv2_initialize ()
{
  struct pp2_init_params init_params = { 0 };
  int rv;

  rv = mv_sys_dma_mem_init (40 << 20);
  if (rv)
    return clib_error_return (0, "mv_sys_dma_mem_init failed, rv = %u", rv);

  init_params.hif_reserved_map = MVAPPS_PP2_HIFS_RSRV;
  init_params.bm_pool_reserved_map = MVAPPS_PP2_BPOOLS_RSRV;
  rv = pp2_init (&init_params);
  if (rv)
    return clib_error_return (0, "ppv2_init failed, rv = %u", rv);

  return 0;
}

void
ppv2_delete_if (ppv2_if_t * ppif)
{
  ppv2_main_t *ppm = &ppv2_main;
  ppv2_outq_t *outq;

  if (ppif->ppio)
    {
      pp2_ppio_disable (ppif->ppio);
      pp2_ppio_deinit (ppif->ppio);
    }

  if (ppif->hif)
    pp2_hif_deinit (ppif->hif);

  if (ppif->bpool)
    pp2_bpool_deinit (ppif->bpool);

  vec_free (ppif->inqs);

  vec_foreach (outq, ppif->outqs)
  {
    /* FIXME free buffers */
    vec_free (outq->buffers);
  }
  vec_free (ppif->outqs);

  pool_put (ppm->interfaces, ppif);
}

void
ppv2_create_if (ppv2_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  ppv2_main_t *ppm = &ppv2_main;
  struct pp2_bpool_params bpool_params = { 0 };
  struct pp2_hif_params hif_params = { 0 };
  struct pp2_ppio_params ppio_params = { 0 };
  struct pp2_ppio_inq_params inq_params = { 0 };
  vnet_sw_interface_t *sw;
  ppv2_if_t *ppif = 0;
  u8 pp2_id, port_id, *s = 0;
  eth_addr_t mac_addr;
  u8 n_inqs = 1;
  u8 n_outqs = 1;
  int i;

  /* defaults */
  args->tx_q_sz = args->tx_q_sz ? args->tx_q_sz : 2048;
  args->rx_q_sz = args->rx_q_sz ? args->rx_q_sz : 2048;

  if (ppm->init_ok == 0)
    {
      if ((args->error = ppv2_initialize ()) != 0)
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;;
	  return;
	}
      ppm->init_ok = 1;
    }

  pool_get (ppm->interfaces, ppif);
  memset (ppif, 0, sizeof (*ppif));
  ppif->dev_instance = ppif - ppm->interfaces;
  vec_validate_aligned (ppif->inqs, n_inqs - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ppif->outqs, n_outqs - 1, CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < n_inqs; i++)
    {
      ppv2_inq_t *inq = vec_elt_at_index (ppif->inqs, i);
      inq->size = args->rx_q_sz;
    }
  for (i = 0; i < n_outqs; i++)
    {
      ppv2_outq_t *outq = vec_elt_at_index (ppif->outqs, i);
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
  bpool_params.buff_len = VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES;
  /* FIXME +64 ? */
  if (pp2_bpool_init (&bpool_params, &ppif->bpool))
    {
      args->rv = VNET_API_ERROR_INIT_FAILED;
      args->error = clib_error_return (0, "bpool '%s' init failed", s);
      goto error;
    }
  vec_reset_length (s);

  /* FIXME bit select */
  s = format (s, "hif-%d%c", pp2_id + 4, 0);
  hif_params.match = (char *) s;
  hif_params.out_size = 2048;
  if (pp2_hif_init (&hif_params, &ppif->hif))
    {
      args->rv = VNET_API_ERROR_INIT_FAILED;
      args->error = clib_error_return (0, "hif '%s' init failed", s);
      goto error;
    }
  vec_reset_length (s);

  s = format (s, "ppio-%d:%d%c", pp2_id, port_id, 0);
  ppio_params.match = (char *) s;
  ppio_params.type = PP2_PPIO_T_NIC;
  inq_params.size = 2048;
  ppio_params.inqs_params.num_tcs = 1;
  ppio_params.inqs_params.tcs_params[0].pkt_offset = 0;
  ppio_params.inqs_params.tcs_params[0].num_in_qs = n_inqs;
  ppio_params.inqs_params.tcs_params[0].inqs_params = &inq_params;
  ppio_params.inqs_params.tcs_params[0].pools[0] = ppif->bpool;
  ppio_params.outqs_params.num_outqs = n_outqs;
  ppio_params.outqs_params.outqs_params[0].weight = 1;
  ppio_params.outqs_params.outqs_params[0].size = 2048;
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

  args->error = ethernet_register_interface (vnm, ppv2_device_class.index,
					     ppif->dev_instance,
					     mac_addr,
					     &ppif->hw_if_index,
					     ppv2_eth_flag_change);
  if (args->error)
    {
      args->rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto error;
    }

  sw = vnet_get_hw_sw_interface (vnm, ppif->hw_if_index);
  ppif->sw_if_index = sw->sw_if_index;
  ppif->per_interface_next_index = ~0;
  vnet_hw_interface_set_input_node (vnm, ppif->hw_if_index,
				    ppv2_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, ppif->hw_if_index, 0, ~0);
  vnet_hw_interface_set_rx_mode (vnm, ppif->hw_if_index, 0,
				 VNET_HW_INTERFACE_RX_MODE_POLLING);
  vnet_hw_interface_set_flags (vnm, ppif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  goto done;

error:
  ppv2_delete_if (ppif);
done:
  vec_free (s);
}

static clib_error_t *
ppv2_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  ppv2_main_t *ppm = &ppv2_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  ppv2_if_t *ppif = pool_elt_at_index (ppm->interfaces, hw->dev_instance);
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
    ppif->flags |= PPV2_IF_F_ADMIN_UP;
  else
    ppif->flags &= ~PPV2_IF_F_ADMIN_UP;

  return error;
}

static void
ppv2_clear_interface_counters (u32 instance)
{
  ppv2_main_t *ppm = &ppv2_main;
  ppv2_if_t *ppif = pool_elt_at_index (ppm->interfaces, instance);
  struct pp2_ppio_statistics stats;

  pp2_ppio_get_statistics (ppif->ppio, &stats, 1);
}

static void
ppv2_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			      u32 node_index)
{
  ppv2_main_t *ppm = &ppv2_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  ppv2_if_t *ppif = pool_elt_at_index (ppm->interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ppif->per_interface_next_index = node_index;
      return;
    }

  ppif->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), ppv2_input_node.index, node_index);
}

static char *ppv2_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_ppv2_tx_func_error
#undef _
};

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ppv2_device_class,) =
{
  .name = "Marvell PPv2 interface",
  .format_device_name = format_ppv2_interface_name,
  .format_device = format_ppv2_interface,
  .tx_function = ppv2_interface_tx,
  .tx_function_n_errors = PPV2_TX_N_ERROR,
  .tx_function_error_strings = ppv2_tx_func_error_strings,
  .admin_up_down_function = ppv2_interface_admin_up_down,
  .clear_counters = ppv2_clear_interface_counters,
  .rx_redirect_to_node = ppv2_set_interface_next_node,
};
/* *INDENT-ON* */

static clib_error_t *
ppv2_init (vlib_main_t * vm)
{
  ppv2_main_t *ppm = &ppv2_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vec_validate_aligned (ppm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  return 0;
}

VLIB_INIT_FUNCTION (ppv2_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
