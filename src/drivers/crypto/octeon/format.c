/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/dev/dev.h>
#include <octeon_common.h>
#include <crypto.h>

#define foreach_oct_cpt_eng_cap                                                                    \
  _ (mul)                                                                                          \
  _ (sha1_sha2)                                                                                    \
  _ (chacha20)                                                                                     \
  _ (zuc_snow3g)                                                                                   \
  _ (sha3)                                                                                         \
  _ (aes)                                                                                          \
  _ (kasumi)                                                                                       \
  _ (des)                                                                                          \
  _ (crc)                                                                                          \
  _ (mmul)                                                                                         \
  _ (sm3)                                                                                          \
  _ (sm4)                                                                                          \
  _ (zuc256_snow5g)                                                                                \
  _ (sg_ver2)                                                                                      \
  _ (sm2)                                                                                          \
  _ (pdcp_chain_zuc256)                                                                            \
  _ (tls)                                                                                          \
  _ (eddsa)

static u8 *
format_oct_cpt_eng_caps (u8 *s, va_list *args)
{
  union cpt_eng_caps *c = va_arg (*args, union cpt_eng_caps *);

#define _(n)                                                                                       \
  if (c->n)                                                                                        \
    s = format (s, " " #n);
  foreach_oct_cpt_eng_cap;
#undef _

  return s;
}

u8 *
format_oct_cpt_dev_info (u8 *s, va_list *args)
{
  __clib_unused vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *eng_names[CPT_MAX_ENG_TYPES] = {
    [CPT_ENG_TYPE_AE] = "AE",
    [CPT_ENG_TYPE_SE] = "SE",
    [CPT_ENG_TYPE_IE] = "IE",
    [CPT_ENG_TYPE_RE] = "RE",
  };
  u32 indent = format_get_indent (s);
  oct_crypto_device_t *cd = vnet_dev_get_data (dev);
  struct roc_cpt *rc = cd->roc_cpt;

  if (rc == 0)
    return s;

  s = format (s, "CPT revision %u, %u LFs in use, %u available", rc->cpt_revision, rc->nb_lf,
	      rc->nb_lf_avail);

  for (u32 t = CPT_ENG_TYPE_AE; t < CPT_MAX_ENG_TYPES; t++)
    {
      if (rc->hw_caps[t].u == 0)
	continue;

      s = format_newline (s, indent);
      s = format (s, "%s engines: group %u, capabilities:%U", eng_names[t], rc->eng_grp[t],
		  format_oct_cpt_eng_caps, rc->hw_caps + t);
      s = format_word_wrap_last_line_with_indent (s, 100, 2);
    }

  return s;
}

u8 *
format_oct_cpt_queue_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_crypto_queue_t *cq = va_arg (*args, vnet_dev_crypto_queue_t *);
  oct_crypto_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  u32 indent = format_get_indent (s);
  struct roc_cpt_lf *lf = q->lf;
  union cpt_lf_inprog inprog;

  if (lf == 0)
    return s;

  s = format (s, "lf %u, %u requests in flight, %u frames", lf->lf_id,
	      (u16) (q->elt_tail - q->elt_head), (u16) (q->frame_tail - q->frame_head));
  s = format_newline (s, indent);
  s = format (s, "elt head %u tail %u, frame head %u tail %u", q->elt_head, q->elt_tail,
	      q->frame_head, q->frame_tail);

  if (a->debug == 0)
    return s;

  s = format_newline (s, indent);
#ifdef PLATFORM_OCTEON9
  s = format (s, "pf_func 0x%x, lmt base 0x%lx, io addr 0x%lx", lf->pf_func, lf->lmt_base,
	      lf->io_addr);
#else
  s = format (s, "pf_func 0x%x, lmt base 0x%lx, io addr 0x%lx", lf->pf_func, q->lmtline.lmt_base,
	      q->lmtline.io_addr);
#endif
  s = format_newline (s, indent);
  s = format (s, "meta %p", q->meta);

  inprog.u = plt_read64 (lf->rbase + CPT_LF_INPROG);
  s = format_newline (s, indent);
  s = format (s, "hw: inflight %u, eena %u, grb cnt %u, gwb cnt %u, ctl 0x%lx, q size 0x%lx",
	      inprog.s.inflight, inprog.s.eena, inprog.s.grb_cnt, inprog.s.gwb_cnt,
	      plt_read64 (lf->rbase + CPT_LF_CTL), plt_read64 (lf->rbase + CPT_LF_Q_SIZE));

  return s;
}

u8 *
format_oct_cpt_enq_trace (u8 *s, va_list *args)
{
  __clib_unused vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  __clib_unused vlib_node_t *node = va_arg (*args, vlib_node_t *);
  oct_crypto_enq_trace_t *t = va_arg (*args, oct_crypto_enq_trace_t *);
  struct cpt_inst_s *i = &t->inst;
  u32 indent = format_get_indent (s);

  s = format (s, "lf %u slot %u", t->lf_id, t->slot);
  s = format_newline (s, indent);
  s =
    format (s, "opcode major 0x%x minor 0x%x param1 0x%x param2 0x%x dlen %u", i->w4.s.opcode_major,
	    i->w4.s.opcode_minor, i->w4.s.param1, i->w4.s.param2, i->w4.s.dlen);
  s = format_newline (s, indent);
  s = format (s, "dptr 0x%lx gather_sz %u rptr 0x%lx scatter_sz %u", (u64) i->w5.s.dptr,
	      i->w5.s.gather_sz, (u64) i->w6.s.rptr, i->w6.s.scatter_sz);
  s = format_newline (s, indent);
  s =
    format (s, "cptr 0x%lx ctx_val %u egrp %u", (u64) i->w7.s.cptr, i->w7.s.ctx_val, i->w7.s.egrp);
  s = format_newline (s, indent);
  s = format (s, "res_addr 0x%lx meta_sz %u cq_ena %u doneint %u", (u64) i->res_addr, i->meta_sz,
	      i->cq_ena, i->w0.cn10k.doneint);
  s = format_newline (s, indent);
  s = format (s, "nixtxl %u nixtx_addr 0x%lx", i->w0.cn10k.nixtxl, (u64) i->w0.cn10k.nixtx_addr);
  s = format_newline (s, indent);
  s = format (s, "tag 0x%x tt %u grp %u rvu_pf_func 0x%x qord %u wqe_ptr 0x%lx", i->w2.s.tag,
	      i->w2.s.tt, i->w2.s.grp, i->w2.s.rvu_pf_func, i->w3.s.qord, (u64) i->w3.s.wqe_ptr);
  return s;
}

static u8 *
format_oct_cpt_compcode (u8 *s, va_list *args)
{
  u32 c = va_arg (*args, u32);
  static const char *names[] = {
    [CPT_COMP_NOT_DONE] = "not-done", [CPT_COMP_GOOD] = "good",	  [CPT_COMP_FAULT] = "fault",
    [CPT_COMP_SWERR] = "swerr",	      [CPT_COMP_HWERR] = "hwerr", [CPT_COMP_INSTERR] = "insterr",
    [CPT_COMP_WARN] = "warn",
  };

  if (c < ARRAY_LEN (names) && names[c])
    return format (s, "%s", names[c]);
  return format (s, "0x%x", c);
}

u8 *
format_oct_cpt_deq_trace (u8 *s, va_list *args)
{
  __clib_unused vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  __clib_unused vlib_node_t *node = va_arg (*args, vlib_node_t *);
  oct_crypto_deq_trace_t *t = va_arg (*args, oct_crypto_deq_trace_t *);
  struct cpt_cn10k_res_s *r = &t->res.cn10k;
  u32 indent = format_get_indent (s);

  s = format (s, "lf %u slot %u", t->lf_id, t->slot);
  s = format_newline (s, indent);
  s = format (s, "compcode %U uc_compcode 0x%x doneint %u rlen %u", format_oct_cpt_compcode,
	      r->compcode, r->uc_compcode, r->doneint, r->rlen);
  s = format_newline (s, indent);
  return format (s, "spi 0x%x esn 0x%lx", r->spi, r->esn);
}
