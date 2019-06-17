/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <avf/avf.h>

void
avf_elog_aq_enq_req (avf_device_t * ad, avf_aq_desc_t * d)
{
  if (d->opcode == 0x801)	/* send_to_pf */
    {
      /* *INDENT-OFF* */
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
      /* *INDENT-ON* */

      struct
      {
	u32 dev_instance;
	u16 flags;
	u16 datalen;
	u16 v_opcode;
	u16 v_opcode_val;
      } *ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->flags = d->flags;
      ed->datalen = d->datalen;
      ed->v_opcode = ed->v_opcode_val = d->v_opcode;
    }
  else
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (el) = {
	.format = "avf[%d] aq_enq_req: opcode 0x%x flags 0x%x datalen %d",
	.format_args = "i4i2i2i2"
      };
      /* *INDENT-ON* */

      struct
      {
	u32 dev_instance;
	u16 opcode;
	u16 flags;
	u16 datalen;
      } *ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->opcode = d->opcode;
      ed->flags = d->flags;
      ed->datalen = d->datalen;
    }
}

void
avf_elog_aq_enq_resp (avf_device_t * ad, avf_aq_desc_t * d)
{
  /* *INDENT-OFF* */
  ELOG_TYPE_DECLARE (el) = {
    .format = "avf[%d] aq_enq_resp: flags 0x%x retval %d",
    .format_args = "i4i2i2"
  };
  /* *INDENT-ON* */

  struct
  {
    u32 dev_instance;
    u16 flags;
    u16 retval;
  } *ed;

  ed = ELOG_DATA (&vlib_global_main.elog_main, el);
  ed->dev_instance = ad->dev_instance;
  ed->flags = d->flags;
  ed->retval = d->retval;
}

void
avf_elog_arq_desc (avf_device_t * ad, avf_aq_desc_t * d)
{
  if (d->opcode == 0x802)
    {
      /* *INDENT-OFF* */
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
      /* *INDENT-ON* */

      struct
      {
	u32 dev_instance;
	u16 flags;
	u16 retval;
	u16 v_opcode;
	u16 v_opcode_val;
	u16 v_retval;
      } *ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->flags = d->flags;
      ed->retval = d->retval;
      ed->v_opcode = ed->v_opcode_val = d->v_opcode;
      ed->v_retval = d->v_retval;
    }
  else
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (el) = {
	.format = "avf[%d] arq_desc: flags 0x%x retval %d opcode 0x%x",
	.format_args = "i4i2i2i2"
      };
      /* *INDENT-ON* */

      struct
      {
	u32 dev_instance;
	u16 flags;
	u16 retval;
	u16 opcode;
      } *ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->flags = d->flags;
      ed->retval = d->retval;
      ed->opcode = d->opcode;
    }
}

void
avf_elog_reg (avf_device_t * ad, u32 addr, u32 val, int is_read)
{
  /* *INDENT-OFF* */
  ELOG_TYPE_DECLARE (el) = {
    .format = "avf[%d] reg: %s %s (0x%04x) val 0x%08x",
    .format_args = "i4s4t4i4i4",
    .n_enum_strings = 18,
    .enum_strings = {
       "unknown", "INT_ICR0", "INT_ICR0_ENA1", "INT_DYN_CTL0",
       "ARQBAH", "ATQH", "ATQLEN", "ARQBAL", "ARQT", "ARQH",
       "ATQBAH", "ATQBAL", "ARQLEN", "ATQT", "GEN_RSTAT",
       "INT_DYN_CTLN(x)", "AVF_QTX_TAIL(x)", "AVF_QRX_TAIL(x)",
     },
  };
  /* *INDENT-ON* */
  struct
  {
    u32 dev_instance;
    char rw[4];
    u32 str;
    u32 addr;
    u32 val;
  } *ed;
  ed = ELOG_DATA (&vlib_global_main.elog_main, el);
  ed->dev_instance = ad->dev_instance;
  ed->addr = addr;
  ed->val = val;
  ed->rw[0] = is_read ? 'r' : 'w';
  ed->rw[1] = 0;
  ed->str = 0;
  if (addr == AVFINT_ICR0)
    ed->str = 1;
  else if (addr == AVFINT_ICR0_ENA1)
    ed->str = 2;
  else if (addr == AVFINT_DYN_CTL0)
    ed->str = 3;
  else if (addr == AVF_ARQBAH)
    ed->str = 4;
  else if (addr == AVF_ATQH)
    ed->str = 5;
  else if (addr == AVF_ATQLEN)
    ed->str = 6;
  else if (addr == AVF_ARQBAL)
    ed->str = 7;
  else if (addr == AVF_ARQT)
    ed->str = 8;
  else if (addr == AVF_ARQH)
    ed->str = 9;
  else if (addr == AVF_ATQBAH)
    ed->str = 10;
  else if (addr == AVF_ATQBAL)
    ed->str = 11;
  else if (addr == AVF_ARQLEN)
    ed->str = 12;
  else if (addr == AVF_ATQT)
    ed->str = 13;
  else if (addr == AVFGEN_RSTAT)
    ed->str = 14;

  if (ed->str == 0)
    for (int i = 0; i < 16; i++)
      {
	if (addr == AVFINT_DYN_CTLN (i))
	  ed->str = 15;
	if (addr == AVF_QTX_TAIL (i))
	  ed->str = 16;
	if (addr == AVF_QRX_TAIL (i))
	  ed->str = 17;
      }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
