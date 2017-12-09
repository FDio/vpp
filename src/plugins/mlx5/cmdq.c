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
#include <vlib/pci/pci.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <mlx5/mlx5.h>

#define DEBUG 0

#if DEBUG
#define DBG(...) clib_warning(__VA_ARGS__)
#else
#define DBG(...)
#endif

#define foreach_mlx5_cmd \
  _(0x100, QUERY_HCA_CAP)						\
  _(0x102, INIT_HCA)							\
  _(0x104, ENABLE_HCA)							\
  _(0x107, QUERY_PAGES)							\
  _(0x108, MANAGE_PAGES)						\
  _(0x109, SET_HCA_CAP)							\
  _(0x10a, QUERY_ISSI)							\
  _(0x10b, SET_ISSI)							\
  _(0x203, QUERY_SPECIAL_CONTEXTS)					\
  _(0x301, CREATE_EQ)							\
  _(0x303, QUERY_EQ)							\
  _(0x304, GEN_EQE)							\
  _(0x400, CREATE_CQ)							\
  _(0x401, DESTROY_CQ)							\
  _(0x402, QUERY_CQ)							\
  _(0x750, QUERY_NIC_VPORT_STATE)					\
  _(0x751, MODIFY_NIC_VPORT_STATE)					\
  _(0x754, QUERY_NIC_VPORT_CONTEXT)					\
  _(0x770, QUERY_VPORT_COUNTER)						\
  _(0x771, ALLOC_Q_COUNTER)						\
  _(0x772, DEALLOC_Q_COUNTER)						\
  _(0x773, QUERY_Q_COUNTER)						\
  _(0x800, ALLOC_PD)							\
  _(0x802, ALLOC_UAR)							\
  _(0x805, ACCESS_REGISTER)						\
  _(0x816, ALLOC_TRANSPORT_DOMAIN)					\
  _(0x900, CREATE_TIR)							\
  _(0x904, CREATE_SQ)							\
  _(0x905, MODIFY_SQ)							\
  _(0x906, DESTROY_SQ)							\
  _(0x907, QUERY_SQ)							\
  _(0x908, CREATE_RQ)							\
  _(0x909, MODIFY_RQ)							\
  _(0x90a, DESTROY_RQ)							\
  _(0x90b, QUERY_RQ)							\
  _(0x912, CREATE_TIS)							\
  _(0x916, CREATE_RQT)							\
  _(0x92f, SET_FLOW_TABLE_ROOT)						\
  _(0x930, CREATE_FLOW_TABLE)						\
  _(0x931, DESTROY_FLOW_TABLE)						\
  _(0x932, QUERY_FLOW_TABLE)						\
  _(0x933, CREATE_FLOW_GROUP)						\
  _(0x934, DESTROY_FLOW_GROUP)						\
  _(0x935, QUERY_FLOW_GROUP)						\
  _(0x936, SET_FLOW_TABLE_ENTRY)					\
  _(0x937, QUERY_FLOW_TABLE_ENTRY)					\
  _(0x938, DELETE_FLOW_TABLE_ENTRY)					\
  _(0x939, ALLOC_FLOW_COUNTER)						\
  _(0x93a, DEALLOC_FLOW_COUNTER)					\
  _(0x93b, QUERY_FLOW_COUNTER)

#define foreach_mlx5_cmd_status \
  _(0x00, OK)								\
  _(0x01, INTERNAL_ERR)							\
  _(0x02, BAD_OP)							\
  _(0x03, BAD_PARAM)							\
  _(0x04, BAD_SYS_STATE)						\
  _(0x05, BAD_RESOURCE)							\
  _(0x06, RESOURCE_BUSY)						\
  _(0x08, EXCEED_LIM)							\
  _(0x09, BAD_RES_STATE)						\
  _(0x0a, BAD_INDEX)							\
  _(0x0f, NO_RESOURCES)							\
  _(0x10, BAD_RESOURCE_STATE)						\
  _(0x40, BAD_SIZE)							\
  _(0x50, BAD_INPUT_LEN)						\
  _(0x51, BAD_OUTPUT_LEN)

typedef enum
{
#define _(a, b) MLX5_CMD_##b = a,
  foreach_mlx5_cmd
#undef _
} mlx5_cmd_t;

static u8 *
format_mlx5_cmd (u8 * s, va_list * args)
{
  u32 cmd = va_arg (*args, u32);
  char *t = 0;

  switch (cmd)
    {
#define _(a, b) case MLX5_CMD_##b: t = #b; break;
      foreach_mlx5_cmd;
#undef _
    default:
      return format (s, "unknown command (0x%x)", cmd);
    }
  return format (s, t);
}

static u8 *
format_mlx5_cmd_status (u8 * s, va_list * args)
{
  u32 cmd = va_arg (*args, u32);
  char *t = 0;

  switch (cmd)
    {
#define _(a, b) case a: t = #b; break;
      foreach_mlx5_cmd_status;
#undef _
    default:
      return format (s, "unknown status (0x%x)", cmd);
    }
  return format (s, t);
}

static clib_error_t *
mlx5_cmdq_mbox_init (vlib_main_t * vm, mlx5_device_t * md, int len, u8 * data,
		     void **ptr)
{
  clib_error_t *err;
  void *physmem;
  int num_blocks;

  len -= 16;
  num_blocks = 1 + (len / 512);

  if (data)
    data += 16;

  if ((err = mlx5_physmem_alloc (vm, md, num_blocks * 1024, 1024, &physmem)))
    return err;

  u8 *mbox = physmem;
  u8 *last_mbox;
  int mbox_slot = 0;

  while (len > 0)
    {
      int to_copy = clib_min (len, 512);
      u64 pa = mlx5_physmem_v2p (md, (void *) mbox);

      /* reset whole mailbox to zero */
      memset (mbox, 0, 0x240);
      /* token, ctrl_signature, signature */
      mlx5_set_bits (mbox, 0x23c, 23, 16, 0xaa);
      /* block number */
      mlx5_set_u32 (mbox, 0x238, mbox_slot);

      if (mbox_slot != 0)
	{
	  /* next_pointer[63:10] */
	  mlx5_set_u64 (last_mbox, 0x230, pa);
	}
      if (data)
	{
	  memcpy (mbox, data, to_copy);
	  data += to_copy;
	}

      last_mbox = mbox;
      mbox += 1024;
      len -= to_copy;
      mbox_slot++;
    }

  *ptr = physmem;
  return 0;
}

static clib_error_t *
mlx5_cmdq_sendmsg (mlx5_device_t * md, mlx5_cmdq_t * cmdq)
{
  vlib_main_t *vm = vlib_get_main ();
  u8 status;
  int i;
  void *p = cmdq->entry;
  void *mbox_in = 0;
  void *mbox_out = 0;
  clib_error_t *error = 0;
  u32 r;

  memset (p, 0, 0x40);
  mlx5_set_bits (p, 0x00, 31, 24, 0x07);	/* type */
  mlx5_set_u32 (p, 0x04, vec_len (cmdq->in));	/* input length */
  mlx5_set_u32 (p, 0x38, vec_len (cmdq->out));	/* input length */
  mlx5_set_bits (p, 0x3c, 31, 24, 0xaa);	/* token */
  mlx5_set_bits (p, 0x3c, 0, 0, 0x01);	/* ownership bit = hardware */

  /* copy up to first 16 bytes of input data */
  memcpy (p + 0x10, cmdq->in, clib_min (vec_len (cmdq->in), 16));

  mlx5_log_debug (md, "cmd %U, in_bytes %u, out_bytes %u",
		  format_mlx5_cmd, (u32) mlx5_get_bits (p, 0x10, 31, 16),
		  vec_len (cmdq->in), vec_len (cmdq->out));

  if (vec_len (cmdq->in) > 16)
    {
      error =
	mlx5_cmdq_mbox_init (vm, md, vec_len (cmdq->in), cmdq->in, &mbox_in);
      if (error)
	goto done;

      /* set input mailbox pointer[63:9] */
      mlx5_set_u64 (p, 0x08, mlx5_physmem_v2p (md, mbox_in));
    }

  if (vec_len (cmdq->out) > 16)
    {
      error = mlx5_cmdq_mbox_init (vm, md, vec_len (cmdq->out), 0, &mbox_out);
      if (error)
	goto done;

      /* set output mailbox pointer[63:9] */
      mlx5_set_u64 (p, 0x30, mlx5_physmem_v2p (md, mbox_out));
    }

  /* ring dorbell */
  mlx5_set_u32 ((void *) cmdq->hca, 0x18, 1 << cmdq->slot);

  i = 500;
  while (((r = mlx5_get_u32 (p, 0x3c)) & 1) && i--)
    vlib_process_suspend (vm, 1e-3);

  if (r & 1)
    {
      error = clib_error_return (0, "%U failed (timeout)",
				 format_mlx5_cmd,
				 (u32) mlx5_get_bits (p, 0x10, 31, 16));
      goto done;
    }

  DBG ("%U[%d,%d] op_mod 0x%02x ",
       format_mlx5_cmd, (u32) mlx5_get_bits (p, 0x10, 31, 16),
       mlx5_get_u32 (p, 0x04),
       mlx5_get_u32 (p, 0x38), mlx5_get_bits (p, 0x14, 15, 0));

  if ((status = (u8) (mlx5_get_bits (p, 0x20, 31, 24))))
    {
      error = clib_error_return (0, "%U failed (cqe_status 0x%02x, "
				 "cmd_status %U syndrome 0x%08x)",
				 format_mlx5_cmd,
				 mlx5_get_bits (p, 0x10, 31, 16),
				 mlx5_get_bits (p, 0x3c, 7, 1),
				 format_mlx5_cmd_status, status,
				 mlx5_get_bits (p, 0x14, 31, 0));
      goto done;
    }

  if ((i = mlx5_get_bits ((void *) cmdq->hca, 0x1010, 31, 24)))
    clib_warning ("health_syndrome: %02x", i);

  /* copy up to first 16 bytes of output data */
  memcpy (cmdq->out, p + 0x20, clib_min (vec_len (cmdq->out), 16));

  if (vec_len (cmdq->out) > 16)
    {
      int left = vec_len (cmdq->out) - 16;
      u8 *ptr = cmdq->out + 16;
      u8 *mbox = mbox_out;
      while (left > 0)
	{
	  int to_copy = clib_min (left, 512);
	  memcpy (ptr, mbox, to_copy);
	  left -= to_copy;
	  ptr += to_copy;
	  mbox += 1024;
	}
    }

done:
  if (mbox_in)
    vlib_physmem_free (vm, mbox_in);
  if (mbox_out)
    vlib_physmem_free (vm, mbox_out);

  return error;
}

static void
mlx5_cmdq_prepare (mlx5_device_t * md, mlx5_cmdq_t * cmdq, int in_len,
		   int out_len, u16 opcode, u16 op_mod)
{
  vec_reset_length (cmdq->in);
  vec_reset_length (cmdq->out);
  vec_resize (cmdq->in, in_len);
  vec_resize (cmdq->out, out_len);
  memset (cmdq->in, 0, in_len);
  mlx5_set_bits (cmdq->in, 0x00, 31, 16, opcode);
  mlx5_set_bits (cmdq->in, 0x04, 15, 0, op_mod);
}

clib_error_t *
mlx5_cmd_query_hca_cap (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			int is_current, u8 type, u8 * data)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, MLX5_HCA_CAP_SZ + 0x10,
		     MLX5_CMD_QUERY_HCA_CAP, (type << 1) | (is_current != 0));

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  clib_memcpy (data, cmdq->out + 0x10, MLX5_HCA_CAP_SZ);

  return 0;
}

clib_error_t *
mlx5_cmd_init_hca (mlx5_device_t * md, mlx5_cmdq_t * cmdq)
{
  mlx5_cmdq_prepare (md, cmdq, 8, 12, MLX5_CMD_INIT_HCA, 0);
  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_enable_hca (mlx5_device_t * md, mlx5_cmdq_t * cmdq)
{
  mlx5_cmdq_prepare (md, cmdq, 8, 12, MLX5_CMD_ENABLE_HCA, 0);
  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_query_pages (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u16 type,
		      u32 * num_pages)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, 16, MLX5_CMD_QUERY_PAGES, type);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (num_pages)
    *num_pages = mlx5_get_u32 (cmdq->out, 0x0c);

  mlx5_log_debug (md, "cmd MLX5_CMD_QUERY_PAGES, type = %u, num_pages = %d",
		  type, mlx5_get_u32 (cmdq->out, 0x0c));

  return 0;
}

clib_error_t *
mlx5_cmd_manage_pages (mlx5_device_t * md, mlx5_cmdq_t * cmdq, i32 num_pages)
{
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error = 0;
  int i;
  int num_alloc = num_pages > 0 ? num_pages : 0;
  int num_free = num_pages > 0 ? 0 : -num_pages;
  u32 output_num_entries;

  mlx5_cmdq_prepare (md, cmdq, 16 + num_alloc * 8, 16 + num_free * 8,
		     MLX5_CMD_MANAGE_PAGES, num_pages > 0 ? 1 : 2);
  mlx5_set_u32 (cmdq->in, 0x0c, num_pages > 0 ? num_alloc : num_free);

  for (i = 0; i < num_alloc; i++)
    {
      void *page;

      if ((error = mlx5_physmem_alloc (vm, md, 4096, 4096, &page)))
	return error;

      mlx5_set_u64 (cmdq->in, 0x10 + i * 8, mlx5_physmem_v2p (md, page));
    }

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  output_num_entries = mlx5_get_u32 (cmdq->out, 0x08);

  for (i = 0; i < output_num_entries; i++)
    {
      u64 pa = mlx5_get_u64 (cmdq->out, 0x10 + i * 8);
      clib_error ("fixme pa->va %llx", pa);
      //FIXME vlib_physmem_free (vm, pa);
    }

  mlx5_log_debug (md, "cmd MLX5_CMD_MANAGE_PAGES, num_pages %u, "
		  "output_num_entries %u, totol_pages %u", num_pages,
		  output_num_entries, 0);

  return error;
}

clib_error_t *
mlx5_cmd_set_hca_cap (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u8 type,
		      u8 * data)
{
  mlx5_cmdq_prepare (md, cmdq, 0x10 + MLX5_HCA_CAP_SZ, 0x10,
		     MLX5_CMD_SET_HCA_CAP, (type << 1));

  clib_memcpy (cmdq->in + 0x10, data, MLX5_HCA_CAP_SZ);

  return mlx5_cmdq_sendmsg (md, cmdq);
}


clib_error_t *
mlx5_cmd_query_issi (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
		     u16 * current_issi, u32 * supported_issi)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 8, 112, MLX5_CMD_QUERY_ISSI, 0);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (current_issi)
    *current_issi = (u16) mlx5_get_u32 (cmdq->out, 0x08);
  if (supported_issi)
    *supported_issi = mlx5_get_u32 (cmdq->out, 0x6C);
  DBG ("current_issi = %u supported_issi = 0x%x",
       mlx5_get_u32 (cmdq->out, 0x08), mlx5_get_u32 (cmdq->out, 0x6C));
  return 0;
}

clib_error_t *
mlx5_cmd_set_issi (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u16 current_issi)
{
  mlx5_cmdq_prepare (md, cmdq, 16, 16, MLX5_CMD_SET_ISSI, 0);
  mlx5_set_bits (cmdq->in, 0x08, 15, 0, current_issi);
  DBG ("current_issi = %u", current_issi);
  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_query_special_contexts (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
				 u32 * resd_lkey, u32 * null_mkey)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, 32, MLX5_CMD_QUERY_SPECIAL_CONTEXTS, 0);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (resd_lkey)
    *resd_lkey = mlx5_get_u32 (cmdq->out, 0x0c);
  if (null_mkey)
    *null_mkey = mlx5_get_u32 (cmdq->out, 0x10);

  return 0;
}

clib_error_t *
mlx5_cmd_create_eq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u8 * eqn,
		    void *ctx, u64 bitmask, void *physmem, int num_pages)
{
  clib_error_t *error = 0;

  mlx5_cmdq_prepare (md, cmdq, 0x110 + num_pages * 8, 16, MLX5_CMD_CREATE_EQ,
		     0);
  if (ctx)
    memcpy (cmdq->out + 0x10, ctx, MLX5_EQ_CTX_SZ);
  mlx5_set_u64 (cmdq->in, 0x58, bitmask);
  mlx5_set_u64 (cmdq->in, 0x110, mlx5_physmem_v2p (md, physmem));	/* eq page address */

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  *eqn = mlx5_get_bits (cmdq->out, 0x08, 7, 0);

  return 0;
}

clib_error_t *
mlx5_cmd_query_eq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u8 eq_number,
		   u8 * ctx, u64 * bitmask)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, 0x118, MLX5_CMD_QUERY_EQ, 0);
  mlx5_set_u32 (cmdq->in, 0x08, eq_number);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (bitmask)
    *bitmask = mlx5_get_u64 (cmdq->out, 0x58);

  if (ctx)
    memcpy (ctx, cmdq->out + 0x10, MLX5_EQ_CTX_SZ);

  return 0;
}

clib_error_t *
mlx5_cmd_gen_eqe (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u8 eqn, u8 type,
		  u8 sub_type)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 0x50, 0x10, MLX5_CMD_GEN_EQE, 0);
  mlx5_set_u32 (cmdq->in, 0x08, eqn);
  mlx5_set_bits (cmdq->in, 0x10 + 0x00, 23, 16, type);
  mlx5_set_bits (cmdq->in, 0x10 + 0x00, 7, 0, sub_type);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  return 0;
}

clib_error_t *
mlx5_cmd_create_cq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 * cqn,
		    void *ctx, void *physmem, int num_pages)
{
  clib_error_t *error = 0;

  mlx5_cmdq_prepare (md, cmdq, 0x110 + num_pages * 8, 16, MLX5_CMD_CREATE_CQ,
		     0);
  memcpy (cmdq->in + 0x10, ctx, MLX5_CQ_CTX_SZ);
  mlx5_set_u64 (cmdq->in, 0x110, mlx5_physmem_v2p (md, physmem));

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  *cqn = mlx5_get_bits (cmdq->out, 0x08, 23, 0);

  return 0;
}

clib_error_t *
mlx5_cmd_destroy_cq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 cqn)
{
  mlx5_cmdq_prepare (md, cmdq, 0x10, 0x10, MLX5_CMD_DESTROY_CQ, 0);
  mlx5_set_bits (cmdq->in, 0x08, 23, 0, cqn);

  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_query_cq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 cqn, u8 * ctx)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, 0x118, MLX5_CMD_QUERY_CQ, 0);
  mlx5_set_bits (cmdq->in, 0x08, 23, 0, cqn);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (ctx)
    memcpy (ctx, cmdq->out + 0x10, MLX5_CQ_CTX_SZ);

  return 0;
}


clib_error_t *
mlx5_cmd_query_nic_vport_state (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
				mlx5_nic_vport_state_t * state)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, 16, MLX5_CMD_QUERY_NIC_VPORT_STATE, 0);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;
  state->admin_state = mlx5_get_bits (cmdq->out, 0x0c, 7, 4);
  state->state = mlx5_get_bits (cmdq->out, 0x0c, 3, 0);
  state->max_tx_speed = mlx5_get_bits (cmdq->out, 0x0c, 31, 16);

  DBG ("state = %u admin_state = %u max_tx_speed %u",
       state->state, state->admin_state, state->max_tx_speed);

  return 0;
}

clib_error_t *
mlx5_cmd_modify_nic_vport_state (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
				 u8 state)
{
  mlx5_cmdq_prepare (md, cmdq, 16, 16, MLX5_CMD_MODIFY_NIC_VPORT_STATE, 0);
  mlx5_set_bits (cmdq->in, 0x0c, 7, 4, state);
  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_query_nic_vport_context (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
				  u8 * ctx)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, MLX5_NIC_VPORT_CTX_SZ + 16,
		     MLX5_CMD_QUERY_NIC_VPORT_CONTEXT, 0);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (ctx)
    memcpy (ctx, cmdq->out + 0x10, MLX5_NIC_VPORT_CTX_SZ);

  return 0;
}

/*
   mlx5_cmd_query_vport_counter
   */

clib_error_t *
mlx5_cmd_alloc_q_counter (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			  u8 * counter_set_id)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, 16, MLX5_CMD_ALLOC_Q_COUNTER, 0);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (counter_set_id)
    *counter_set_id = mlx5_get_bits (cmdq->out, 0x08, 7, 0);
  return 0;
}

clib_error_t *
mlx5_cmd_dealloc_q_counter (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			    u8 counter_set_id)
{
  mlx5_cmdq_prepare (md, cmdq, 16, 16, MLX5_CMD_DEALLOC_Q_COUNTER, 0);
  mlx5_set_bits (cmdq->in, 0x08, 7, 0, counter_set_id);

  return mlx5_cmdq_sendmsg (md, cmdq);
}


clib_error_t *
mlx5_cmd_query_q_counter (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			  u8 counter_set_id, int clear,
			  mlx5_q_counter_t * cnt)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 0x20, 0x100, MLX5_CMD_QUERY_Q_COUNTER, 0);
  if (clear)
    mlx5_set_bits (cmdq->in, 0x18, 31, 31, 1);
  mlx5_set_bits (cmdq->in, 0x1c, 7, 0, counter_set_id);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;
#define _(a, b) cnt->b = mlx5_get_u32 (cmdq->out, a);
  foreach_mlx5_q_counter
#undef _
    return 0;
}

clib_error_t *
mlx5_cmd_alloc_pd (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 * pd)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, 16, MLX5_CMD_ALLOC_PD, 0);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (pd)
    *pd = mlx5_get_u32 (cmdq->out, 0x08);
  return 0;
}

clib_error_t *
mlx5_cmd_alloc_uar (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 * uar)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, 16, MLX5_CMD_ALLOC_UAR, 0);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (uar)
    *uar = mlx5_get_u32 (cmdq->out, 0x08);
  return 0;
}

clib_error_t *
mlx5_cmd_access_register (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			  mlx5_reg_rw_t rw, u16 register_id, u32 argument,
			  u8 * data)
{
  clib_error_t *error;
  int data_size = mlx5_sizeof_reg (register_id);

  if (data_size == 0)
    return clib_error_return (0, "Unknown register %x", register_id);

  if (rw == MLX5_REG_RW_READ)
    {
      mlx5_cmdq_prepare (md, cmdq, data_size + 16, 16 + data_size,
			 MLX5_CMD_ACCESS_REGISTER, 1);
    }
  else
    {
      mlx5_cmdq_prepare (md, cmdq, 16 + data_size, 16,
			 MLX5_CMD_ACCESS_REGISTER, 0);
    }
  clib_memcpy (cmdq->in + 16, data, data_size);

  mlx5_set_bits (cmdq->in, 0x08, 15, 0, register_id);
  mlx5_set_u32 (cmdq->in, 0x0c, argument);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (rw == MLX5_REG_RW_READ)
    clib_memcpy (data, cmdq->out + 16, data_size);

  return 0;
}

clib_error_t *
mlx5_cmd_alloc_transport_domain (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
				 u32 * td)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, 16, MLX5_CMD_ALLOC_TRANSPORT_DOMAIN, 0);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (td)
    *td = mlx5_get_u32 (cmdq->out, 0x08);
  DBG ("transport_domain = %u", mlx5_get_u32 (cmdq->out, 0x08));
  return 0;
}

clib_error_t *
mlx5_cmd_create_tir (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 * tirn,
		     void *ctx)
{
  clib_error_t *error = 0;

  mlx5_cmdq_prepare (md, cmdq, 0x20 + MLX5_TIR_CTX_SZ, 16,
		     MLX5_CMD_CREATE_TIR, 0);
  memcpy (cmdq->in + 0x20, ctx, MLX5_TIR_CTX_SZ);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  *tirn = mlx5_get_bits (cmdq->out, 0x08, 23, 0);
  return 0;
}


clib_error_t *
mlx5_cmd_create_sq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 * sqn,
		    void *sq_ctx, void *wq_ctx, void *physmem, int num_pages)
{
  clib_error_t *error = 0;

  mlx5_cmdq_prepare (md, cmdq, 0x118, 16, MLX5_CMD_CREATE_SQ, 0);
  memcpy (cmdq->in + 0x20, sq_ctx, MLX5_SQ_CTX_SZ);
  memcpy (cmdq->in + 0x50, wq_ctx, MLX5_WQ_CTX_SZ);
  mlx5_set_u64 (cmdq->in, 0x50 + 0xc0, mlx5_physmem_v2p (md, physmem));

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    goto error;

  *sqn = mlx5_get_bits (cmdq->out, 0x08, 23, 0);
  return 0;

error:
  return error;
}

clib_error_t *
mlx5_cmd_modify_sq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 sqn, u8 state)
{
  mlx5_cmdq_prepare (md, cmdq, 0x118, 0x10, MLX5_CMD_MODIFY_SQ, 0);
  //mlx5_set_bits (cmdq->in, 0x08, 31, 28, sq->state);
  mlx5_set_bits (cmdq->in, 0x08, 23, 0, sqn);
  mlx5_set_bits (cmdq->in, 0x20 + 0x00, 23, 20, state);

  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_destroy_sq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 sqn)
{
  mlx5_cmdq_prepare (md, cmdq, 0x10, 0x10, MLX5_CMD_DESTROY_SQ, 0);
  mlx5_set_bits (cmdq->in, 0x08, 23, 0, sqn);

  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_query_sq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 sqn,
		   u8 * sq_ctx, u8 * wq_ctx)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, 0x118, MLX5_CMD_QUERY_SQ, 0);
  mlx5_set_u32 (cmdq->in, 0x08, sqn);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (sq_ctx)
    memcpy (sq_ctx, cmdq->out + 0x20, MLX5_SQ_CTX_SZ);

  if (wq_ctx)
    memcpy (wq_ctx, cmdq->out + 0x20 + MLX5_SQ_CTX_SZ, MLX5_WQ_CTX_SZ);

  return 0;
}

clib_error_t *
mlx5_cmd_create_rq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 * rqn,
		    void *rq_ctx, void *wq_ctx, void *physmem, int num_pages)
{
  clib_error_t *error = 0;

  mlx5_cmdq_prepare (md, cmdq, 0x118, 16, MLX5_CMD_CREATE_RQ, 0);
  memcpy (cmdq->in + 0x20, rq_ctx, MLX5_RQ_CTX_SZ);
  memcpy (cmdq->in + 0x50, wq_ctx, MLX5_WQ_CTX_SZ);
  mlx5_set_u64 (cmdq->in, 0x50 + 0xc0, mlx5_physmem_v2p (md, physmem));

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  *rqn = mlx5_get_bits (cmdq->out, 0x08, 23, 0);
  return 0;
}

clib_error_t *
mlx5_cmd_modify_rq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 rqn, u8 state)
{
  mlx5_cmdq_prepare (md, cmdq, 0x118, 0x10, MLX5_CMD_MODIFY_RQ, 0);
  //mlx5_set_bits (cmdq->in, 0x08, 31, 28, rq->state);
  mlx5_set_bits (cmdq->in, 0x08, 23, 0, rqn);
  mlx5_set_bits (cmdq->in, 0x20 + 0x00, 23, 20, state);

  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_destroy_rq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 rqn)
{
  mlx5_cmdq_prepare (md, cmdq, 0x10, 0x10, MLX5_CMD_DESTROY_RQ, 0);
  mlx5_set_bits (cmdq->in, 0x08, 23, 0, rqn);

  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_query_rq (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 rqn,
		   u8 * rq_ctx, u8 * wq_ctx)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 16, 0x118, MLX5_CMD_QUERY_RQ, 0);
  mlx5_set_u32 (cmdq->in, 0x08, rqn);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (rq_ctx)
    memcpy (rq_ctx, cmdq->out + 0x20, MLX5_RQ_CTX_SZ);

  if (wq_ctx)
    memcpy (wq_ctx, cmdq->out + 0x20 + MLX5_RQ_CTX_SZ, MLX5_WQ_CTX_SZ);

  return 0;
}

clib_error_t *
mlx5_cmd_create_tis (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u8 prio, u32 td,
		     u32 * tisn)
{
  clib_error_t *error;
  mlx5_cmdq_prepare (md, cmdq, 0x20 + 0x100, 0x10, MLX5_CMD_CREATE_TIS, 0);
  mlx5_set_u32 (cmdq->in, 0x20 + 0x00, (prio & 0x0f) << 16);
  mlx5_set_u32 (cmdq->in, 0x20 + 0x24, td & 0xFFFFFF);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (tisn)
    *tisn = mlx5_get_u32 (cmdq->out, 0x08);

  DBG ("tisn = %u", mlx5_get_u32 (cmdq->out, 0x08));
  return 0;
}

clib_error_t *
mlx5_cmd_create_rqt (mlx5_device_t * md, mlx5_cmdq_t * cmdq, u32 * rqtn,
		     void *ctx)
{
  clib_error_t *error = 0;

  mlx5_cmdq_prepare (md, cmdq, 0x20 + MLX5_RQT_CTX_SZ, 16,
		     MLX5_CMD_CREATE_RQT, 0);
  memcpy (cmdq->in + 0x20, ctx, MLX5_RQT_CTX_SZ);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  *rqtn = mlx5_get_bits (cmdq->out, 0x08, 23, 0);

  return 0;
}

clib_error_t *
mlx5_cmd_create_flow_table (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			    u8 table_type, void *ctx, u32 * table_id)
{
  clib_error_t *error = 0;

  mlx5_cmdq_prepare (md, cmdq, 0x10 + MLX5_FLOW_TABLE_CTX_SZ, 16,
		     MLX5_CMD_CREATE_FLOW_TABLE, 0);
  mlx5_set_bits (cmdq->in, 0x10, 31, 24, table_type);
  memcpy (cmdq->in + 0x10, ctx, MLX5_FLOW_TABLE_CTX_SZ);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  *table_id = mlx5_get_bits (cmdq->out, 0x08, 23, 0);

  return 0;
}

clib_error_t *
mlx5_cmd_destroy_flow_table (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			     u8 table_type, u32 table_id)
{
  mlx5_cmdq_prepare (md, cmdq, 0x40, 0x10, MLX5_CMD_DESTROY_FLOW_TABLE, 0);
  mlx5_set_bits (cmdq->in, 0x10, 31, 24, table_type);
  mlx5_set_bits (cmdq->in, 0x14, 23, 0, table_id);

  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_set_flow_table_root (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			      u8 table_type, u32 table_id)
{
  mlx5_cmdq_prepare (md, cmdq, 0x40, 0x10, MLX5_CMD_SET_FLOW_TABLE_ROOT, 0);
  mlx5_set_bits (cmdq->in, 0x10, 31, 24, table_type);
  mlx5_set_bits (cmdq->in, 0x14, 23, 0, table_id);

  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_create_flow_group (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			    u8 table_type, u32 table_id, u32 start_flow_index,
			    u32 end_flow_index, u8 match_criteria_enable,
			    u8 * match_criteria, u32 * group_id)
{
  clib_error_t *error = 0;

  mlx5_cmdq_prepare (md, cmdq, 0x400, 16, MLX5_CMD_CREATE_FLOW_GROUP, 0);
  mlx5_set_bits (cmdq->in, 0x10, 31, 24, table_type);
  mlx5_set_bits (cmdq->in, 0x14, 23, 0, table_id);
  mlx5_set_bits (cmdq->in, 0x1c, 31, 0, start_flow_index);
  mlx5_set_bits (cmdq->in, 0x1c, 31, 0, end_flow_index);
  mlx5_set_bits (cmdq->in, 0x3c, 7, 0, match_criteria_enable);

  if (match_criteria)
    memcpy (cmdq->in + 0x40, match_criteria, 512);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (group_id)
    *group_id = mlx5_get_bits (cmdq->out, 0x08, 23, 0);

  return 0;
}

clib_error_t *
mlx5_cmd_set_flow_table_entry (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			       u8 table_type, u32 table_id,
			       u8 modify_enable_mask, u32 flow_index,
			       u8 * ctx)
{
  mlx5_cmdq_prepare (md, cmdq, 0x40 + MLX5_FLOW_CTX_SZ, 16,
		     MLX5_CMD_SET_FLOW_TABLE_ENTRY, 0);
  mlx5_set_bits (cmdq->in, 0x10, 31, 24, table_type);
  mlx5_set_bits (cmdq->in, 0x14, 23, 0, table_id);
  mlx5_set_bits (cmdq->in, 0x18, 7, 0, modify_enable_mask);
  mlx5_set_bits (cmdq->in, 0x20, 31, 0, flow_index);

  if (ctx)
    memcpy (cmdq->in + 0x40, ctx, MLX5_FLOW_CTX_SZ);

  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_alloc_flow_counter (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			     u16 * flow_counter_id)
{
  clib_error_t *error = 0;

  mlx5_cmdq_prepare (md, cmdq, 0x10, 0x10, MLX5_CMD_ALLOC_FLOW_COUNTER, 0);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (flow_counter_id)
    *flow_counter_id = mlx5_get_bits (cmdq->out, 0x08, 15, 0);

  return 0;
}

clib_error_t *
mlx5_cmd_dealloc_flow_counter (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			       u16 flow_counter_id)
{
  mlx5_cmdq_prepare (md, cmdq, 0x10, 0x10, MLX5_CMD_DEALLOC_FLOW_COUNTER, 0);
  mlx5_set_bits (cmdq->in, 0x08, 15, 0, flow_counter_id);

  return mlx5_cmdq_sendmsg (md, cmdq);
}

clib_error_t *
mlx5_cmd_query_flow_counter (mlx5_device_t * md, mlx5_cmdq_t * cmdq,
			     u16 flow_counter_id, u16 num_of_counters,
			     int clear, u8 * counters)
{
  clib_error_t *error = 0;

  mlx5_cmdq_prepare (md, cmdq, 0x20, 0x10 + 0x10 * num_of_counters,
		     MLX5_CMD_QUERY_FLOW_COUNTER, 0);
  if (clear)
    mlx5_set_bits (cmdq->in, 0x18, 31, 31, 1);
  mlx5_set_bits (cmdq->in, 0x18, 15, 0, num_of_counters);
  mlx5_set_bits (cmdq->in, 0x1c, 15, 0, flow_counter_id);

  if ((error = mlx5_cmdq_sendmsg (md, cmdq)))
    return error;

  if (counters)
    memcpy (counters, cmdq->out + 0x10, num_of_counters * 0x10);

  return 0;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
