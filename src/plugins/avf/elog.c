/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <avf/avf.h>

static uword *register_name_by_addr = 0;

void
avf_elog_aq_enq_req (avf_device_t *ad, avf_aq_desc_t *d)
{
  if (d->opcode == 0x801) /* send_to_pf */
    {
      ELOG_TYPE_DECLARE (el) = {
	.format = "avf[%d] aq_enq_req: send_to_pf flags 0x%x datalen %d "
	  "v_opcode %s (%d)",
	.format_args = "i4i2i2t2i2",
	.n_enum_strings = VIRTCHNL_N_OPS,
	.enum_strings = {
#define _(v, n) [v] = #n,
	      foreach_virtchnl_op
#undef _
	  },
      };

      struct
      {
	u32 dev_instance;
	u16 flags;
	u16 datalen;
	u16 v_opcode;
	u16 v_opcode_val;
      } * ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->flags = d->flags;
      ed->datalen = d->datalen;
      ed->v_opcode = ed->v_opcode_val = d->v_opcode;
    }
  else
    {
      ELOG_TYPE_DECLARE (el) = {
	.format = "avf[%d] aq_enq_req: opcode 0x%x flags 0x%x datalen %d",
	.format_args = "i4i2i2i2"
      };

      struct
      {
	u32 dev_instance;
	u16 opcode;
	u16 flags;
	u16 datalen;
      } * ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->opcode = d->opcode;
      ed->flags = d->flags;
      ed->datalen = d->datalen;
    }
}

void
avf_elog_aq_enq_resp (avf_device_t *ad, avf_aq_desc_t *d)
{
  ELOG_TYPE_DECLARE (el) = { .format =
			       "avf[%d] aq_enq_resp: flags 0x%x retval %d",
			     .format_args = "i4i2i2" };

  struct
  {
    u32 dev_instance;
    u16 flags;
    u16 retval;
  } * ed;

  ed = ELOG_DATA (&vlib_global_main.elog_main, el);
  ed->dev_instance = ad->dev_instance;
  ed->flags = d->flags;
  ed->retval = d->retval;
}

void
avf_elog_arq_desc (avf_device_t *ad, avf_aq_desc_t *d)
{
  if (d->opcode == 0x802)
    {
      ELOG_TYPE_DECLARE (el) = {
	.format = "avf[%d] arq_desc: msg_from_pf flags 0x%x retval %d "
	  "v_opcode %s (%d) v_retval %d",
	.format_args = "i4i2i2t2i2i2",
	.n_enum_strings = VIRTCHNL_N_OPS,
	.enum_strings = {
#define _(v, n) [v] = #n,
	      foreach_virtchnl_op
#undef _
	  },
      };

      struct
      {
	u32 dev_instance;
	u16 flags;
	u16 retval;
	u16 v_opcode;
	u16 v_opcode_val;
	u16 v_retval;
      } * ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->flags = d->flags;
      ed->retval = d->retval;
      ed->v_opcode = ed->v_opcode_val = d->v_opcode;
      ed->v_retval = d->v_retval;
    }
  else
    {
      ELOG_TYPE_DECLARE (
	el) = { .format = "avf[%d] arq_desc: flags 0x%x retval %d opcode 0x%x",
		.format_args = "i4i2i2i2" };

      struct
      {
	u32 dev_instance;
	u16 flags;
	u16 retval;
	u16 opcode;
      } * ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->flags = d->flags;
      ed->retval = d->retval;
      ed->opcode = d->opcode;
    }
}

void
avf_elog_reg (avf_device_t *ad, u32 addr, u32 val, int is_read)
{
  uword *p;
  ELOG_TYPE_DECLARE (el) = {
    .format = "avf[%d] reg: %s %s [0x%04x] val 0x%08x",
    .format_args = "i4s4s4i4i4",
  };

  struct
  {
    u32 dev_instance;
    char rw[4];
    char reg_name[24];
    u32 addr;
    u32 val;
  } * ed;

  ed = ELOG_DATA (&vlib_global_main.elog_main, el);
  ed->dev_instance = ad->dev_instance;
  ed->addr = addr;
  ed->val = val;
  ed->rw[0] = is_read ? 'r' : 'w';
  ed->rw[1] = 0;

  p = hash_get (register_name_by_addr, addr);
  strncpy (ed->reg_name, p ? (char *) p[0] : "unknown", 24);
  ed->reg_name[23] = 0;
}

void
avf_elog_init (void)
{
  if (register_name_by_addr)
    return;

  register_name_by_addr = hash_create (0, sizeof (uword));

  hash_set (register_name_by_addr, AVFINT_ICR0, "AVFINT_ICR0");
  hash_set (register_name_by_addr, AVFINT_ICR0_ENA1, "INT_ICR0_ENA1");
  hash_set (register_name_by_addr, AVFINT_DYN_CTL0, "INT_DYN_CTL0");
  hash_set (register_name_by_addr, AVF_ARQBAH, "ARQBAH");
  hash_set (register_name_by_addr, AVF_ATQH, "ATQH");
  hash_set (register_name_by_addr, AVF_ATQLEN, "ATQLEN");
  hash_set (register_name_by_addr, AVF_ARQBAL, "ARQBAL");
  hash_set (register_name_by_addr, AVF_ARQT, "ARQT");
  hash_set (register_name_by_addr, AVF_ARQH, "ARQH");
  hash_set (register_name_by_addr, AVF_ATQBAH, "ATQBAH");
  hash_set (register_name_by_addr, AVF_ATQBAL, "ATQBAL");
  hash_set (register_name_by_addr, AVF_ARQLEN, "ARQLEN");
  hash_set (register_name_by_addr, AVF_ATQT, "ATQT");
  hash_set (register_name_by_addr, AVFGEN_RSTAT, "GEN_RSTAT");

  for (int i = 0; i < 16; i++)
    {
      hash_set (register_name_by_addr, AVFINT_DYN_CTLN (i),
		format (0, "INT_DYN_CTLN(%u)%c", i, 0));
      hash_set (register_name_by_addr, AVF_QTX_TAIL (i),
		format (0, "QTX_TAIL(%u)%c", i, 0));
      hash_set (register_name_by_addr, AVF_QRX_TAIL (i),
		format (0, "QRX_TAIL(%u)%c", i, 0));
    }
}
