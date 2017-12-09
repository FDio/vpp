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

static clib_error_t *
mlx5_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  mlx5_create_if_args_t args;
  u32 tmp;

  memset (&args, 0, sizeof (mlx5_create_if_args_t));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_pci_addr, &args.addr))
	;
      else if (unformat (line_input, "rx-queue-size %u", &tmp))
	args.rxq_size = tmp;
      else if (unformat (line_input, "tx-queue-size %u", &tmp))
	args.txq_size = tmp;
      else if (unformat (line_input, "num-rx-queues %u", &tmp))
	args.rxq_num = tmp;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  mlx5_create_if (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (mlx5_create_command, static) = {
  .path = "create interface mlx5",
  .short_help = "create interface mlx5 <pci-address> "
		"[rx-queue-size <size>] [tx-queue-size <size>] "
		"[num-rx-queues <size>]",
  .function = mlx5_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
mlx5_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  mlx5_main_t *am = &mlx5_main;
  mlx5_device_t *ad;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || mlx5_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not an AVF interface");

  ad = pool_elt_at_index (am->devices, hw->dev_instance);

  mlx5_delete_if (vm, ad);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (mlx5_delete_command, static) = {
  .path = "delete interface mlx5",
  .short_help = "delete interface mlx5 "
    "{<interface> | sw_if_index <sw_idx>}",
  .function = mlx5_delete_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-ON* */
static clib_error_t *
show_mlx5_flow_fn (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  mlx5_main_t *mm = &mlx5_main;
  mlx5_device_t *md;
  clib_error_t *error = 0;

  vec_foreach (md, mm->devices)
  {
    u8 data[64];
    mlx5_cmdq_t *cmdq = mlx5_get_cmdq (md);
    error =
      mlx5_cmd_query_flow_counter (md, cmdq, md->flow_counter_id, 4, 0, data);
    if (error)
      {
	vlib_cli_output (vm, "  Error: %U", format_clib_error, error);
	clib_error_free (error);
      }
    else
      {
	vlib_cli_output (vm, "Flow Counter: %u\n", md->flow_counter_id);
	vlib_cli_output (vm, "  Packets: %15llu\n",
			 mlx5_get_u64 (data, 0x00));
	vlib_cli_output (vm, "  Octets:  %15llu\n",
			 mlx5_get_u64 (data, 0x08));
      }

    mlx5_put_cmdq (cmdq);
  }
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_mlx5_flow, static) =
{
  .path = "show mlx5 flow",
  .short_help = "show mlx5 flow",
  .function = show_mlx5_flow_fn,
};

/* *INDENT-ON* */

static clib_error_t *
show_mlx5_regs_fn (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  mlx5_main_t *mm = &mlx5_main;
  vnet_main_t *vnm = vnet_get_main ();
  mlx5_device_t *md;
  clib_error_t *error = 0;
  u8 pddr[mlx5_sizeof_reg (MLX5_REG_PDDR)];

  vec_foreach (md, mm->devices)
  {
    mlx5_cmdq_t *cmdq = mlx5_get_cmdq (md);
    vlib_cli_output (vm, "\n%U\n%U\n",
		     format_vnet_sw_if_index_name, vnm, md->sw_if_index,
		     format_mlx5_counters, md);

    memset (pddr, 0, sizeof (pddr));
    mlx5_set_bits (pddr, 0, 23, 16, 1);
    mlx5_set_bits (pddr, 4, 7, 0, 3);
    error =
      mlx5_cmd_access_register (md, cmdq, MLX5_REG_RW_READ, MLX5_REG_PDDR, 0,
				pddr);
    mlx5_put_cmdq (cmdq);

    if (error)
      {
	vlib_cli_output (vm, "  Error: %U", format_clib_error, error);
	clib_error_free (error);
      }
    else
      {
	vlib_cli_output (vm, "%U", format_mlx5_pddr_module_info, pddr);
      }

  }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_mlx5_regs, static) =
{
  .path = "show mlx5 register",
  .short_help = "show mlx5 register",
  .function = show_mlx5_regs_fn,
};
/* *INDENT-ON* */


static clib_error_t *
show_mlx5_counters_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  mlx5_main_t *mm = &mlx5_main;
  vnet_main_t *vnm = vnet_get_main ();
  mlx5_device_t *md;

  vec_foreach (md, mm->devices)
  {
    vlib_cli_output (vm, "\n%U\n%U\n",
		     format_vnet_sw_if_index_name, vnm, md->sw_if_index,
		     format_mlx5_counters, md);

  }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_mlx5_counters, static) =
{
  .path = "show mlx5 counters",
  .short_help = "show mlx5 counters",
  .function = show_mlx5_counters_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_mlx5_interface_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  mlx5_main_t *mm = &mlx5_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  mlx5_device_t *md;
  u32 hw_if_index = ~0;
  u32 qid;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat
      (line_input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
    ;

  if (hw_if_index == ~0)
    return clib_error_return (0, "unknown interface `%U`",
			      format_unformat_error, input);

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  md = vec_elt_at_index (mm->devices, hi->dev_instance);

  vlib_cli_output (vm, "firmware version %u.%u.%u",
		   md->fw_rev_major, md->fw_rev_minor, md->fw_rev_subminor);

  mlx5_cmdq_t *cmdq = mlx5_get_cmdq (md);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "caps"))
	{
	  vlib_cli_output (vm, "%U\n", format_mlx5_hca_cap_cur_max, md, cmdq,
			   MLX5_HCA_CAP_TYPE_DEVICE);
	  vlib_cli_output (vm, "%U\n", format_mlx5_hca_cap_cur_max, md, cmdq,
			   MLX5_HCA_CAP_TYPE_NET_OFFLOAD);
	  vlib_cli_output (vm, "%U\n", format_mlx5_hca_cap_cur_max, md, cmdq,
			   MLX5_HCA_CAP_TYPE_QOS);
	}
      else if (unformat (line_input, "nic-vport"))
	{
	  u8 ctx[MLX5_NIC_VPORT_CTX_SZ];
	  u8 *s = 0;
	  s = format (s, "NIC Vport Context:\n");
	  if ((error = mlx5_cmd_query_nic_vport_context (md, cmdq, ctx)))
	    {
	      s = format (s, "  Error: %U", format_clib_error, error);
	      clib_error_free (error);
	    }
	  else
	    {
	      s = format (s, "%U\n", format_mlx5_nic_vport_ctx, ctx);
	    }
	  vlib_cli_output (vm, "%v", s);
	  vec_free (s);

	}
      else if (unformat (line_input, "eq"))
	{
	  u8 eq_ctx[MLX5_EQ_CTX_SZ];
	  u64 bitmask;
	  u8 *s = 0;

	  s = format (s, "Event Queue (qqn %u):\n", md->eqn);
	  if ((error = mlx5_cmd_query_eq (md, cmdq, md->eqn, eq_ctx, &bitmask)))
	    {
	      s = format (s, "  Error: %U", format_clib_error, error);
	      clib_error_free (error);
	    }
	  else
	    {
	      s = format (s, "%U\n", format_mlx5_eq_ctx, eq_ctx);
	      s = format (s, "  bitmask: 0x%lx\n", bitmask);
	    }
	  vlib_cli_output (vm, "%v", s);
	  vec_free (s);
	}

      else if (unformat (line_input, "txq %u", &qid))
	{
	  mlx5_txq_t *txq;
	  u8 cq_ctx[MLX5_CQ_CTX_SZ];
	  u8 sq_ctx[MLX5_CQ_CTX_SZ];
	  u8 wq_ctx[MLX5_WQ_CTX_SZ];
	  u8 *s = 0;

	  if (vec_len (md->tx_queues) <= qid)
	    return clib_error_return (0, "%d is not valid tx queue", qid);
	  txq = vec_elt_at_index (md->tx_queues, qid);

	  s = format (s, "Completion Queue (cqn %u):\n", txq->cqn);
	  if ((error = mlx5_cmd_query_cq (md, cmdq, txq->cqn, cq_ctx)))
	    {
	      s = format (s, "  Error: %U", format_clib_error, error);
	      clib_error_free (error);
	    }
	  else
	    s = format (s, "%U\n", format_mlx5_cq_ctx, cq_ctx);

	  s = format (s, "Send Queue (sqn %u):\n", txq->sqn);
	  if ((error = mlx5_cmd_query_sq (md, cmdq, txq->sqn, sq_ctx, wq_ctx)))
	    {
	      s = format (s, "  Error: %U", format_clib_error, error);
	      clib_error_free (error);
	    }
	  else
	    {
	      s = format (s, "%U\n", format_mlx5_sq_ctx, sq_ctx);
	      s = format (s, "Work Queue:\n");
	      s = format (s, "%U\n", format_mlx5_wq_ctx, wq_ctx);
	    }
	  vlib_cli_output (vm, "%v", s);
	  vec_free (s);
	}
      else if (unformat (line_input, "rxq %u", &qid))
	{
	  mlx5_rxq_t *rxq;
	  u8 cq_ctx[MLX5_CQ_CTX_SZ];
	  u8 rq_ctx[MLX5_CQ_CTX_SZ];
	  u8 wq_ctx[MLX5_WQ_CTX_SZ];
	  u8 *s = 0;
	  mlx5_q_counter_t qcnt;

	  if (vec_len (md->rx_queues) <= qid)
	    return clib_error_return (0, "%d is not valid rx queue", qid);
	  rxq = vec_elt_at_index (md->rx_queues, qid);

	  s = format (s, "Completion Queue (cqn %u):\n", rxq->cqn);
	  if ((error = mlx5_cmd_query_cq (md, cmdq, rxq->cqn, cq_ctx)))
	    {
	      s = format (s, "  Error: %U", format_clib_error, error);
	      clib_error_free (error);
	    }
	  else
	    s =
	      format (s, "%U\ndoorbell data %U\n", format_mlx5_cq_ctx, cq_ctx,
		      format_hexdump, rxq->cq_db, 8);

	  s = format (s, "Receive Queue (rqn %u):\n", rxq->rqn);
	  if ((error = mlx5_cmd_query_rq (md, cmdq, rxq->rqn, rq_ctx, wq_ctx)))
	    {
	      s = format (s, "  Error: %U", format_clib_error, error);
	      clib_error_free (error);
	    }
	  else
	    {
	      s = format (s, "%U\n", format_mlx5_rq_ctx, rq_ctx);
	      s = format (s, "Work Queue:\n");
	      s = format (s, "%U\n", format_mlx5_wq_ctx, wq_ctx);
	    }
	  s =
	    format (s, "Queue Counter (counter_set_id %u):\n",
		    rxq->counter_set_id);
	  if ((error =
	       mlx5_cmd_query_q_counter (md, cmdq, rxq->counter_set_id, 0,
					 &qcnt)))
	    {
	      s = format (s, "  Error: %U", format_clib_error, error);
	      clib_error_free (error);
	    }
	  else
	    {
#define _(a, b) if (qcnt.b) s = format (s, "  %-35s%-12u\n", #b, qcnt.b);
	      foreach_mlx5_q_counter
#undef _
	    }
	  vlib_cli_output (vm, "%v", s);
	  vec_free (s);
	}
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  mlx5_put_cmdq (cmdq);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_mlx5_interface, static) =
{
  .path = "show mlx5 interface",
  .short_help = "show mlx5 queues",
  .function = show_mlx5_interface_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
