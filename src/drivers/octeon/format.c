/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#include "vlib/pci/pci.h"
#include "vnet/error.h"
#include "vppinfra/error.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <octeon.h>

u8 *
format_oct_port_status (u8 *s, va_list *args)
{
  return s;
}

u8 *
format_oct_nix_rx_cqe_desc (u8 *s, va_list *args)
{
  oct_nix_rx_cqe_desc_t *d = va_arg (*args, oct_nix_rx_cqe_desc_t *);
  u32 indent = format_get_indent (s);
  typeof (d->hdr) *h = &d->hdr;
  typeof (d->parse.f) *p = &d->parse.f;
  typeof (d->sg0) *sg0 = &d->sg0;
  typeof (d->sg0) *sg1 = &d->sg1;

  s = format (s, "hdr: cqe_type %u nude %u qid %u tag 0x%x", h->cqe_type,
	      h->node, h->q, h->tag);
  s = format (s, "\n%Uparse:", format_white_space, indent);
#define _(n, f) s = format (s, " " #n " " f, p->n)
  _ (chan, "%u");
  _ (errcode, "%u");
  _ (errlev, "%u");
  _ (desc_sizem1, "%u");
  _ (pkt_lenm1, "%u");
  _ (pkind, "%u");
  s = format (s, "\n%U ", format_white_space, indent);
  _ (nix_idx, "%u");
  _ (color, "%u");
  _ (flow_key_alg, "%u");
  _ (eoh_ptr, "%u");
  _ (match_id, "0x%x");
  s = format (s, "\n%U ", format_white_space, indent);
  _ (wqe_aura, "0x%x");
  _ (pb_aura, "0x%x");
  _ (imm_copy, "%u");
  _ (express, "%u");
  _ (wqwd, "%u");
  _ (l2m, "%u");
  _ (l2b, "%u");
  _ (l3m, "%u");
  _ (l3b, "%u");
#undef _
  s = format (s, "\n%U  ", format_white_space, indent);
  s = format (s, "layer:     a    b    c    d    e    f    g    h");
  s = format (s, "\n%U  ", format_white_space, indent);
  s = format (s, "type:    %3u  %3u  %3u  %3u  %3u  %3u  %3u  %3u", p->latype,
	      p->lbtype, p->lctype, p->ldtype, p->letype, p->lftype, p->lgtype,
	      p->lhtype);
  s = format (s, "\n%U  ", format_white_space, indent);
  s = format (
    s, "flags:  0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x",
    p->laflags, p->lbflags, p->lcflags, p->ldflags, p->leflags, p->lfflags,
    p->lgflags, p->lhflags);
  s = format (s, "\n%U  ", format_white_space, indent);
  s = format (s, "ptr:     %3u  %3u  %3u  %3u  %3u  %3u  %3u  %3u", p->laptr,
	      p->lbptr, p->lcptr, p->ldptr, p->leptr, p->lfptr, p->lgptr,
	      p->lhptr);

  if (sg0->subdc != 0x4)
    return format (s, "\n%Usg0: unexpected subdc %x", format_white_space,
		   indent, sg0->subdc);

  s = format (s,
	      "\n%Usg0: segs %u seg1_sz %u seg2_sz %u seg3_sz %u seg1 "
	      "%p seg2 %p seg3 %p",
	      format_white_space, indent, sg0->segs, sg0->seg1_size,
	      sg0->seg2_size, sg0->seg3_size, d->segs0[0], d->segs0[1],
	      d->segs0[2]);

  if (sg1->subdc != 0x4 && sg1->subdc != 0)
    return format (s, "\n%Usg1: unexpected subdc %x", format_white_space,
		   indent, sg1->subdc);

  if (sg1->subdc == 4)
    s = format (s,
		"\n%Usg1: segs %u seg1_sz %u seg2_sz %u seg3_sz %u seg1 "
		"%p seg2 %p seg3 %p",
		format_white_space, indent, sg1->segs, sg1->seg1_size,
		sg1->seg2_size, sg1->seg3_size, d->segs1[0], d->segs1[1],
		d->segs1[2]);

  return s;
}

u8 *
format_oct_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  oct_rx_trace_t *t = va_arg (*args, oct_rx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "octeon-rx: next-node %U sw_if_index %u",
	      format_vlib_next_node_name, vm, node->index, t->next_index,
	      t->sw_if_index);
  s = format (s, "\n%U%U", format_white_space, indent + 2,
	      format_oct_nix_rx_cqe_desc, &t->desc);
  return s;
}

u8 *
format_oct_tx_trace (u8 *s, va_list *args)
{
  va_arg (*args, vlib_main_t *);
  va_arg (*args, vlib_node_t *);
  oct_tx_trace_t *t = va_arg (*args, oct_tx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "octeon-tx: sw_if_index %u", t->sw_if_index);
  s = format (s, "\n%Uhdr[0]:", format_white_space, indent + 2);
#define _(n, f) s = format (s, " " #n " " f, t->desc.hdr_w0.n)
  _ (total, "%u");
  _ (df, "%u");
  _ (aura, "0x%x");
  _ (sizem1, "%u");
  _ (pnc, "%u");
  _ (sq, "%u");
#undef _
  s = format (s, "\n%Uhdr[1]:", format_white_space, indent + 2);
#define _(n, f) s = format (s, " " #n " " f, t->desc.hdr_w1.n)
  _ (ol3ptr, "%u");
  _ (ol4ptr, "%u");
  _ (il3ptr, "%u");
  _ (il4ptr, "%u");
  _ (ol3type, "%u");
  _ (ol4type, "%u");
  _ (il3type, "%u");
  _ (il4type, "%u");
  _ (sqe_id, "%u");
#undef _

  foreach_int (j, 0, 4)
    {
      s = format (s, "\n%Usg[%u]:", format_white_space, indent + 2, j);
#define _(n, f) s = format (s, " " #n " " f, t->desc.sg[j].n)
      _ (subdc, "%u");
      _ (segs, "%u");
      _ (seg1_size, "%u");
      _ (seg2_size, "%u");
      _ (seg3_size, "%u");
      _ (i1, "%u");
      _ (i2, "%u");
      _ (i3, "%u");
      _ (ld_type, "%u");
#undef _
      for (int i = 1; i < 4; i++)
	s = format (s, "\n%Usg[%u]: %p", format_white_space, indent + 2, i + j,
		    t->desc.sg[i + j]);
    }

  return s;
}

u8 *
format_oct_port_flow (u8 *s, va_list *args)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  u32 flow_index = va_arg (*args, u32);
  uword private_data = va_arg (*args, uword);
  u64 hits;

  if (flow_index == ~0)
    return s;

  if (oct_flow_query (vm, port, flow_index, private_data, &hits) ==
      VNET_DEV_OK)
    s = format (s, "flow (%u) hit count: %lu", flow_index, hits);

  return s;
}
