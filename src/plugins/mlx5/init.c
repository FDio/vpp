/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/*
 *   WARNING!
 *   This driver is not intended for production use and it is unsupported.
 *   It is provided for educational use only.
 *   Please use supported DPDK driver instead.
 */


#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <mlx5/mlx5.h>

#define DBG(...) clib_warning(__VA_ARGS__)

mlx5_main_t mlx5_main;

static u32
mlx5_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  clib_warning ("TODO");
  return 0;
}

clib_error_t *
mlx5_init (vlib_main_t * vm)
{
  mlx5_main_t *mm = &mlx5_main;
  clib_error_t *error = 0;

  error = vlib_call_init_function (vm, linux_pci_init);

  if (error)
    return error;

  if (vec_len (mm->devices) == 0)
    return 0;

  error =
    unix_physmem_region_alloc (vm, "mlx5_pool", 256  << 20, 0,
			       VLIB_PHYSMEM_F_INIT_MHEAP,
			       &mm->physmem_region);

  mm->mempage_by_pa = hash_create (0, sizeof (uword));

  return error;
}

VLIB_INIT_FUNCTION (mlx5_init);

static void
mlx5_pci_intr_handler (vlib_pci_device_t * dev)
{
  clib_warning ("int");
}

static clib_error_t *
mlx5_txq_init (vlib_main_t * vm, mlx5_device_t * md, int queue_id)
{
  mlx5_main_t *mm = &mlx5_main;
  clib_error_t *error = 0;
  mlx5_txq_t *txq;
  mlx5_cmdq_t *cmdq = 0;
  u8 cq_ctx[MLX5_CQ_CTX_SZ] = { 0 };
  u8 sq_ctx[MLX5_SQ_CTX_SZ] = { 0 };
  u8 wq_ctx[MLX5_WQ_CTX_SZ] = { 0 };
  int num_pages;

  vec_validate_aligned (md->tx_queues, queue_id, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (md->tx_queues, queue_id);

  /* each wqe is 64 bytes */
  txq->log_wq_stride = 6;
  /* numer of tx slots */
  txq->log_wq_sz = 6;

  txq->last_wqe_counter = 0xffff;
  vec_validate_aligned (txq->enq, (1 << txq->log_wq_sz),
			CLIB_CACHE_LINE_BYTES);

  txq->cq_db =
    vlib_physmem_alloc_aligned (vm, mm->physmem_region, &error, 4096, 4096);
  if (error)
    goto error;

  txq->cq_mem =
    vlib_physmem_alloc_aligned (vm, mm->physmem_region, &error, 4096, 4096);
  if (error)
    goto error;

  txq->sq_db =
    vlib_physmem_alloc_aligned (vm, mm->physmem_region, &error, 4096, 4096);
  if (error)
    goto error;

  num_pages = (1 << txq->log_wq_sz) * (1 << txq->log_wq_stride) / 4096;
  txq->sq_mem =
    vlib_physmem_alloc_aligned (vm, mm->physmem_region, &error, num_pages,
				4096);
  if (error)
    goto error;

  /* for transmit we use collapsed mode for CQ so we need just one CQE slot */
  memset (txq->cq_mem, 0, 64);
  mlx5_set_bits (txq->cq_mem, 0x3c, 0, 0, 1);

  cmdq = mlx5_get_cmdq (md);

  mlx5_set_cq_ctx_field (cq_ctx, cc, 1);
  mlx5_set_cq_ctx_field (cq_ctx, oi, 1);
  mlx5_set_cq_ctx_field (cq_ctx, uar_page, md->uar);
  mlx5_set_cq_ctx_field (cq_ctx, log_cq_size, 0);
  mlx5_set_cq_ctx_field (cq_ctx, c_eqn, md->eqn);
  mlx5_set_cq_ctx_field (cq_ctx, log_page_size, 0);
  mlx5_set_u64 (cq_ctx, 0x38, mlx5_physmem_v2p ((void *) txq->cq_db));

  if ((error = mlx5_cmd_create_cq (cmdq, &txq->cqn, cq_ctx, txq->cq_mem, 1)))
    goto error;

  /* Send Queue */
  mlx5_set_sq_ctx_field (sq_ctx, rlkey, 1);
  mlx5_set_sq_ctx_field (sq_ctx, fre, 1);
  mlx5_set_sq_ctx_field (sq_ctx, flush_in_error_en, 1);
  mlx5_set_sq_ctx_field (sq_ctx, min_wqe_inline_mode, 1);
  mlx5_set_sq_ctx_field (sq_ctx, cqn, txq->cqn);
  mlx5_set_sq_ctx_field (sq_ctx, tis_lst_sz, 1);
  mlx5_set_sq_ctx_field (sq_ctx, tis_num_0, md->tisn);

  /* Work Queue */
  mlx5_set_wq_ctx_field (wq_ctx, wq_type, 1);	/* WQ_CYCLIC */
  mlx5_set_wq_ctx_field (wq_ctx, pd, md->protection_domain);
  mlx5_set_wq_ctx_field (wq_ctx, uar_page, md->uar);
  mlx5_set_u64 (wq_ctx, 0x10, mlx5_physmem_v2p ((void *) txq->sq_db));
  mlx5_set_wq_ctx_field (wq_ctx, log_wq_stride, txq->log_wq_stride);
  mlx5_set_wq_ctx_field (wq_ctx, log_wq_pg_sz, 0);
  mlx5_set_wq_ctx_field (wq_ctx, log_wq_sz, txq->log_wq_sz);

  if ((error = mlx5_cmd_create_sq (cmdq, &txq->sqn, sq_ctx, wq_ctx,
				   txq->sq_mem, num_pages)))
    goto error;

  if ((error = mlx5_cmd_modify_sq (cmdq, txq->sqn, 1)))
    goto error;

error:
  if (cmdq)
    mlx5_put_cmdq (cmdq);
  return error;
}


static clib_error_t *
mlx5_rxq_init (vlib_main_t * vm, mlx5_device_t * md, int queue_id)
{
  mlx5_main_t *mm = &mlx5_main;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  mlx5_rxq_t *rxq;
  mlx5_cmdq_t *cmdq = 0;
  u8 cq_ctx[MLX5_CQ_CTX_SZ] = { 0 };
  u8 rq_ctx[MLX5_RQ_CTX_SZ] = { 0 };
  u8 wq_ctx[MLX5_WQ_CTX_SZ] = { 0 };
  u64 pa;
  u32 n_slots, n_alloc, i;
  vlib_physmem_region_t *pr;
  pr = vlib_physmem_get_region (vm, vm->buffer_main->physmem_region);

  vec_validate_aligned (md->rx_queues, queue_id, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (md->rx_queues, queue_id);

  /* each wqe is 16 bytes */
  rxq->log_wq_stride = 4;
  /* numer of rx slots */
  rxq->log_wq_sz = 6;
  n_slots = 1 << rxq->log_wq_sz;

  /* initial allocation of buffers */
  vec_validate_aligned (rxq->enq, n_slots - 1, CLIB_CACHE_LINE_BYTES);
  n_alloc = vlib_buffer_alloc (vm, rxq->enq, n_slots);
  if (n_alloc != n_slots)
    {
      if (n_alloc)
	vlib_buffer_free (vm, rxq->enq, n_alloc);
      error = clib_error_return (0, "Buffer allocation failure");
      goto error;
    }

  rxq->cq_db =
    vlib_physmem_alloc_aligned (vm, mm->physmem_region, &error, 4096, 4096);
  if (error)
    goto error;

  rxq->cq_mem =
    vlib_physmem_alloc_aligned (vm, mm->physmem_region, &error, 4096, 4096);
  if (error)
    goto error;

  rxq->rq_db =
    vlib_physmem_alloc_aligned (vm, mm->physmem_region, &error, 4096, 4096);
  if (error)
    goto error;

  rxq->rq_mem =
    vlib_physmem_alloc_aligned (vm, mm->physmem_region, &error, 4096, 4096);
  if (error)
    goto error;

  memset (rxq->cq_mem, 0, n_slots * 64);
  memset (rxq->rq_mem, 0, n_slots * (1 << rxq->log_wq_stride));

  for (i = 0; i < n_slots; i++)
    {
      void *wqe = rxq->rq_mem + (i << rxq->log_wq_stride);
      void *cqe = rxq->cq_mem + i * 64;
      vlib_buffer_t *b = vlib_get_buffer (vm, rxq->enq[i]);
      /* init cqe */
      mlx5_set_bits (cqe, 0x3c, 0, 0, 1);	/* ownership */
      /* init wqe */
      mlx5_set_u32 (wqe, 0x00, VLIB_BUFFER_DATA_SIZE);
      mlx5_set_u32 (wqe, 0x04, md->reserved_lkey);
      pa =
	vlib_physmem_virtual_to_physical (vm, pr,
					  vlib_buffer_get_current (b));
      mlx5_set_u64 (wqe, 0x08, pa);
    }

  /* bump dorbell for number of enqueued buffers */
  *rxq->rq_db = clib_host_to_net_u32 (n_slots);

  cmdq = mlx5_get_cmdq (md);

  mlx5_set_cq_ctx_field (cq_ctx, oi, 1);
  mlx5_set_cq_ctx_field (cq_ctx, uar_page, md->uar);
  mlx5_set_cq_ctx_field (cq_ctx, log_cq_size, rxq->log_wq_sz);
  mlx5_set_cq_ctx_field (cq_ctx, c_eqn, md->eqn);
  mlx5_set_cq_ctx_field (cq_ctx, log_page_size, 0);
  mlx5_set_u64 (cq_ctx, 0x38, mlx5_physmem_v2p ((void *) rxq->cq_db));

  if ((error = mlx5_cmd_create_cq (cmdq, &rxq->cqn, cq_ctx, rxq->cq_mem, 1)))
    goto error;

  if ((error = mlx5_cmd_alloc_q_counter (cmdq, &rxq->counter_set_id)))
    goto error;

  /* Receive Queue */
  mlx5_set_rq_ctx_field (rq_ctx, rlkey, 1);
  mlx5_set_rq_ctx_field (rq_ctx, vlan_strip_disable, 1);
  mlx5_set_rq_ctx_field (rq_ctx, cqn, rxq->cqn);
  mlx5_set_rq_ctx_field (rq_ctx, counter_set_id, rxq->counter_set_id);

  /* Work Queue */
  mlx5_set_wq_ctx_field (wq_ctx, wq_type, 1);	/* WQ_CYCLIC */
  mlx5_set_wq_ctx_field (wq_ctx, pd, md->protection_domain);
  mlx5_set_u64 (wq_ctx, 0x10, mlx5_physmem_v2p ((void *) rxq->rq_db));
  mlx5_set_wq_ctx_field (wq_ctx, log_wq_stride, rxq->log_wq_stride);
  mlx5_set_wq_ctx_field (wq_ctx, log_wq_pg_sz, 0);
  mlx5_set_wq_ctx_field (wq_ctx, log_wq_sz, rxq->log_wq_sz);

  fformat (stderr, "%U", format_mlx5_rq_ctx, &rq_ctx);
  if ((error = mlx5_cmd_create_rq (cmdq, &rxq->rqn, rq_ctx, wq_ctx,
				   rxq->rq_mem, 1)))
    goto error;

  if ((error = mlx5_cmd_modify_rq (cmdq, rxq->rqn, 1)))
    goto error;

  vnet_hw_interface_assign_rx_thread (vnm, md->hw_if_index, queue_id, ~0);

error:
  if (cmdq)
    mlx5_put_cmdq (cmdq);
  return error;
}

static clib_error_t *
mlx5_device_init (vlib_main_t * vm, mlx5_device_t * md)
{
  mlx5_main_t *mm = &mlx5_main;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  mlx5_cmdq_t *cmdq = 0;
  u8 hca_cap[MLX5_HCA_CAP_SZ];
  u8 nic_vport_ctx[MLX5_NIC_VPORT_CTX_SZ];
  u8 eq_ctx[MLX5_EQ_CTX_SZ] = { 0 };
  u8 rqt_ctx[MLX5_RQT_CTX_SZ] = { 0 };
  u8 tir_ctx[MLX5_TIR_CTX_SZ] = { 0 };
  u8 ft_ctx[MLX5_FLOW_TABLE_CTX_SZ] = { 0 };
  u8 flow_ctx[MLX5_FLOW_CTX_SZ] = { 0 };
  void *cmdq_mem;
  u8 log_cmdq_stride;
  u8 log_cmdq_size;
  u32 r;
  int i;

  log_cmdq_stride = mlx5_get_bits ((void *) md->hca, 0x14, 3, 0);
  log_cmdq_size = mlx5_get_bits ((void *) md->hca, 0x14, 7, 4);

  /* alloc cmdq */
  cmdq_mem =
    (void *) vlib_physmem_alloc_aligned (vm, mm->physmem_region, &error,
					 64 * (1 << log_cmdq_size),
					 64 * (1 << log_cmdq_stride));

  if (error)
    goto error;

  /* create vector of command queues */
  for (r = 0; r < (1 << log_cmdq_size); r++)
    {
      vec_add2 (md->cmdq, cmdq, 1);
      cmdq->slot = r;
      cmdq->entry = cmdq_mem + r * 64;
      cmdq->hca = md->hca;
      /* FIXME remove: */
      vec_validate (cmdq->in, 4095);
      vec_validate (cmdq->out, 4095);
    }

  mlx5_set_u64 ((void *) md->hca, 0x10, mlx5_physmem_v2p ((void *) cmdq_mem));

  /* wait until initializing bit is reset */
  i = 50;
  do
    {
      vlib_process_suspend (vm, 10e-3);
      r = mlx5_get_bits ((void *) md->hca, 0x1fc, 31, 31);
    }
  while (r && --i);

  if (!i)
    {
      error = clib_error_return (0, "Initialization timeout");
      goto error;
    }


#if 0
  if ((error = vlib_pci_intr_enable (dev)))
    goto error;
#endif


  cmdq = mlx5_get_cmdq (md);

  if ((error = mlx5_cmd_enable_hca (cmdq)))
    goto error;

  if ((error = mlx5_cmd_query_issi (cmdq, 0, &r)))
    goto error;

  if ((r & 0x02) == 0)
    {
      error = clib_error_return (0, "ISSI 1 is not supported by this device");
      goto error;
    }

  if ((error = mlx5_cmd_set_issi (cmdq, 1)))
    goto error;

  r = 0;
  if ((error = mlx5_cmd_query_issi (cmdq, (u16 *) & r, 0)))
    goto error;

  if (r != 1)
    {
      error = clib_error_return (0, "Failed to set ISSI 1");
      goto error;
    }


  /* alloc boot_pages */
  if ((error = mlx5_cmd_query_pages (cmdq, 1 /* boot_pages */ , &r)))
    goto error;

  if ((error = mlx5_cmd_manage_pages (cmdq, (i32) r)))
    goto error;

  /* query general device caps */
  if ((error = mlx5_cmd_query_hca_cap (cmdq, 1 /*is_current */ ,
				       MLX5_HCA_CAP_TYPE_DEVICE, hca_cap)))
    goto error;

  mlx5_set_hca_cap_log_max_qp (hca_cap, 10);
  mlx5_set_hca_cap_log_max_srq (hca_cap, 16);
  mlx5_set_hca_cap_log_max_cq (hca_cap, 16);
  mlx5_set_hca_cap_log_max_mkey (hca_cap, 16);
  //mlx5_set_hca_cap_uar_4k (hca_cap, 1);

  if ((error =
       mlx5_cmd_set_hca_cap (cmdq, MLX5_HCA_CAP_TYPE_DEVICE, hca_cap)))
    goto error;

  /* alloc init_pages */
  if ((error = mlx5_cmd_query_pages (cmdq, 2 /* init_pages */ , &r)))
    goto error;

  if ((error = mlx5_cmd_manage_pages (cmdq, (i32) r)))
    goto error;

  if ((error = mlx5_cmd_init_hca (cmdq)))
    goto error;

  if ((error = mlx5_cmd_query_nic_vport_context (cmdq, nic_vport_ctx)))
    goto error;

  /* copy permanent mac address */
  memcpy (md->perm_addr, nic_vport_ctx + 0xf4 + 2, 6);

  /* alloc regular_pages */
  if ((error = mlx5_cmd_query_pages (cmdq, 3 /* regular_pages */ , &r)))
    goto error;

  if ((error = mlx5_cmd_manage_pages (cmdq, (i32) r)))
    goto error;

  if ((error = mlx5_cmd_alloc_uar (cmdq, &md->uar)))
    goto error;

  /* init Event Queue */
  md->log_eq_size = 6;
  md->eq_physmem = vlib_physmem_alloc_aligned (vm, mm->physmem_region, &error,
					       64 * (1 << md->log_eq_size),
					       4096);
  if (error)
    goto error;

  memset (md->eq_physmem, 0x00, 64 * (1 << md->log_eq_size));
  for (i = 0; i < (1 << md->log_eq_size); i++)
    {
      void *eqe = md->eq_physmem + i * 64;
      mlx5_set_bits (eqe, 0x3c, 0, 0, 1);
    }

  mlx5_set_eq_ctx_field (eq_ctx, uar_page, md->uar);
  mlx5_set_eq_ctx_field (eq_ctx, log_eq_size, md->log_eq_size);
  //mlx5_set_eq_ctx_field (eq_ctx, oi, 1);

  u64 bitmask = (1 << 0x01) | (1 << 0x02) | (1 << 0x03) | (1 << 0x04) |
    (1 << 0x05) | (1 << 0x07) | (1 << 0x08) | (1 << 0x09) | (1 << 0x0b) |
    (1 << 0x0c) | (1 << 0x0d) | (1 << 0x10) | (1 << 0x11) | (1 << 0x12) |
    (1 << 0x13) | (1 << 0x14) | (1 << 0x16) | (1 << 0x17) | (1 << 0x1a) |
    (1 << 0x1b);

  if ((error = mlx5_cmd_create_eq (cmdq, &md->eqn, eq_ctx, bitmask,
				   md->eq_physmem, 1)))
    goto error;

  if ((error = mlx5_cmd_alloc_pd (cmdq, &md->protection_domain)))
    goto error;

  if ((error = mlx5_cmd_alloc_transport_domain (cmdq, &md->transport_domain)))
    goto error;

  if ((error = mlx5_cmd_query_special_contexts (cmdq, &md->reserved_lkey, 0)))
    goto error;

  if ((error = mlx5_cmd_modify_nic_vport_state (cmdq, 0)))
    goto error;

  /* create interface */
  error = ethernet_register_interface (vnm, mlx5_device_class.index,
				       md->device_index,
				       md->perm_addr,
				       &md->hw_if_index, mlx5_flag_change);
  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, md->hw_if_index);
  md->sw_if_index = sw->sw_if_index;
  vnet_hw_interface_set_input_node (vnm, md->hw_if_index,
				    mlx5_input_node.index);

  if ((error = mlx5_cmd_create_tis (cmdq, 0, md->transport_domain,
				    &md->tisn)))
    goto error;

  if ((error =
       mlx5_cmd_create_flow_table (cmdq, MLX5_FLOW_TABLE_TYPE_NIC_RX, ft_ctx,
				   &md->root_rx_flow_table)))
    goto error;

  if ((error = mlx5_cmd_create_flow_group (cmdq, MLX5_FLOW_TABLE_TYPE_NIC_RX,
					   md->root_rx_flow_table, 0, 0, 0, 0,
					   &md->flow_group_id)))
    goto error;

  if ((error = mlx5_txq_init (vm, md, 0)))
    goto error;

  if ((error = mlx5_rxq_init (vm, md, 0)))
    goto error;

  /* Create Receive Queue Table */
  mlx5_set_bits (rqt_ctx, 0x14, 15, 0, 1);	/* rqt_max_size */
  mlx5_set_bits (rqt_ctx, 0x18, 15, 0, 1);	/* rqt_actual_size */
  mlx5_set_bits (rqt_ctx, 0xf0, 23, 0, md->rx_queues[0].rqn);
  if ((error = mlx5_cmd_create_rqt (cmdq, &md->rqtn, rqt_ctx)))
    goto error;

  mlx5_set_tir_ctx_field (tir_ctx, disp_type, 0);
  //mlx5_set_tir_ctx_field (tir_ctx, rx_hash_symmetric, 1);
  mlx5_set_tir_ctx_field (tir_ctx, inline_rqn, md->rx_queues[0].rqn);
  //mlx5_set_tir_ctx_field (tir_ctx, indirect_table, md->rqtn);
  mlx5_set_tir_ctx_field (tir_ctx, transport_domain, md->transport_domain);
  //mlx5_set_tir_ctx_field (tir_ctx, rx_hash_fn, 1);
  if ((error = mlx5_cmd_create_tir (cmdq, &md->tirn, tir_ctx)))
    goto error;

  if ((error = mlx5_cmd_alloc_flow_counter (cmdq, &md->flow_counter_id)))
    goto error;

  mlx5_set_flow_ctx_field (flow_ctx, group_id, md->flow_group_id);
  mlx5_set_flow_ctx_field (flow_ctx, action, (1 << 2) | (1 << 3));	/* bit 2 - FWD_DEST, bit 3 - COUNT */
  mlx5_set_flow_ctx_field (flow_ctx, destination_list_size, 1);
  mlx5_set_flow_ctx_field (flow_ctx, flow_counter_list_size, 1);
  mlx5_set_flow_ctx_field (flow_ctx, destination_type_0, 2);	/* 2 - TIR */
  mlx5_set_flow_ctx_field (flow_ctx, destination_id_0, md->tirn);
  mlx5_set_flow_ctx_field (flow_ctx, flow_counter_id_1, md->flow_counter_id);
  if ((error = mlx5_cmd_set_flow_table_entry (cmdq,
					      MLX5_FLOW_TABLE_TYPE_NIC_RX,
					      md->root_rx_flow_table, 0, 0,
					      flow_ctx)))
    goto error;

  if ((error = mlx5_cmd_set_flow_table_root (cmdq,
					     MLX5_FLOW_TABLE_TYPE_NIC_RX,
					     md->root_rx_flow_table)))
    goto error;

  mlx5_put_cmdq (cmdq);
  return 0;

error:
  if (cmdq)
    mlx5_put_cmdq (cmdq);

  return error;
}

static u8 *
format_mlx5_eqe (u8 * s, va_list * args)
{
  void *eqe = va_arg (*args, void *);
  u8 type = mlx5_get_bits (eqe, 0x00, 23, 16);
  u8 sub_type = mlx5_get_bits (eqe, 0x00, 7, 0);
  void *data = eqe + 0x20;

  if (type == 0x09)
    {
      s = format (s, "Port State Change port=%d sub_type=0x%x",
		  mlx5_get_bits (data, 0x08, 31, 28), sub_type);
    }
  else if (type == 0x16)
    {
      s = format (s, "Port Module module=%d module_status=0x%x "
		  "error_type=0x%x",
		  mlx5_get_bits (data, 0x00, 23, 16),
		  mlx5_get_bits (data, 0x00, 3, 0),
		  mlx5_get_bits (data, 0x04, 11, 8));
    }
  else
    s = format (s, "unknown event (type=0x%02x sub_type=0x%02x data=%U)\n",
		type, sub_type, format_hex_bytes, data, 28);

  return s;
}

static uword
mlx5_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  mlx5_main_t *mm = &mlx5_main;
  mlx5_device_t *md;

  vec_foreach (md, mm->devices)
  {
    clib_error_t *error;
    error = mlx5_device_init (vm, md);
    if (error)
      clib_error_report (error);
  }

  while (1)
    {
      vlib_process_suspend (vm, 3.0);
      vec_foreach (md, mm->devices)
      {
	int i;
	void *eq_db = ((void *) md->hca) + 4096 * md->uar + 0x48;
	for (i = 0; i < (1 << md->log_eq_size); i++)
	  {
	    void *eqe = md->eq_physmem + i * 64;
	    if (mlx5_get_bits (eqe, 0x3c, 0, 0) == 1)
	      continue;

	    clib_warning ("event received on eqe %d: %U",
			  i, format_mlx5_eqe, eqe);
	    memset (eqe, 0, 64);
	    mlx5_set_bits (eqe, 0x3c, 0, 0, 1);
	    *(volatile u32 *) eq_db =
	      clib_host_to_net_u32 (md->eqn << 24 | (i + 1));
	  }
      }
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (mlx5_process_node, static)  = {
  .function = mlx5_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "mlx5-process",
};
/* *INDENT-ON* */

static clib_error_t *
mlx5_pci_init (vlib_main_t * vm, vlib_pci_device_t * dev)
{
  clib_error_t *error = 0;
  mlx5_main_t *mm = &mlx5_main;
  mlx5_device_t *md;
  u32 r;

  /* Device found: make sure we have dma memory. */
  if (PREDICT_FALSE (vm->os_physmem_alloc_aligned == 0))
    unix_physmem_init (vm, 0 /* fail_if_physical_memory_not_present */ );

#if 0
  if (unix_physmem_is_fake (vm))
    return clib_error_return (0, "no physical memory available");
#endif

  vec_add2 (mm->devices, md, 1);
  if ((error = vlib_pci_bus_master_enable (dev)))
    goto error;

  if ((error = vlib_pci_map_resource (dev, 0, (void *) &md->hca)))
    goto error;

  md->pci_device = dev[0];
  md->device_index = md - mm->devices;
  md->per_interface_next_index = ~0;

  md->fw_rev_minor = mlx5_get_bits ((void *) md->hca, 0, 31, 16);
  md->fw_rev_major = mlx5_get_bits ((void *) md->hca, 0, 15, 0);
  md->fw_rev_subminor = mlx5_get_bits ((void *) md->hca, 0x04, 15, 0);
  md->cmd_interface_rev = mlx5_get_bits ((void *) md->hca, 0x04, 31, 16);

  if (md->cmd_interface_rev != 5)
    {
      error = clib_error_return (0, "Unsupported command interface version "
				 "on device %U", format_vlib_pci_addr,
				 &dev->bus_address);
      goto error;
    }

  /* HCA offset 0x1fc bit 31 - initializing */
  r = mlx5_get_u32 ((void *) md->hca, 0x1fc);
  if (r & (1 << 31))
    {
      error = clib_error_return (0, "device %U not ready",
				 format_vlib_pci_addr, &dev->bus_address);
      goto error;
    }

#if 0
  /* HCA offset 0x1010 bits 31:24 - health_syndrome */
  r = mlx5_get_bits ((void *) md->hca, 0x1010, 31, 24);
  if (r)
    {
      error = clib_error_return (0, "device %U health issue (syndrome %x)",
				 format_vlib_pci_addr, &dev->bus_address, r);
      goto error;
    }
#endif

  return 0;
error:
  if (md->cmdq)
    vlib_physmem_free (vm, mm->physmem_region, (void *) md->cmdq);
  memset (md, 0, sizeof (*md));
  _vec_len (mm->devices)--;
  return error;
}

/* *INDENT-OFF* */
PCI_REGISTER_DEVICE (mlx5_pci_device_registration,static) = {
  .init_function = mlx5_pci_init,
  .interrupt_handler = mlx5_pci_intr_handler,
  .supported_devices = {
    { .vendor_id = 0x15b3, .device_id = 0x1013, },
    { .vendor_id = 0x15b3, .device_id = 0x1015, },
    { .vendor_id = 0x15b3, .device_id = 0x1017, },
    { 0 },
  },
};
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    //.default_disabled = 1,
    .description = "Mellanox ConnectX-4/5 Native Driver (experimental)",
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
