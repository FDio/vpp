/* SPDX-License-Identifier: Apache-2.0 */
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/interface_funcs.h>
#include <dev_atlantic/atlantic.h>

u8 *
format_atl_rx_desc (u8 *s, va_list *args)
{
  const atl_rx_desc_t *d = va_arg (*args, const atl_rx_desc_t *);
  u32 indent = format_get_indent (s) + 2;

#define _(b) ((b) ? '+' : '-')

  s = format (s, "buf 0x%016llx hdr 0x%016llx type 0x%08x rss 0x%08x",
	      d->buf_addr, d->hdr_addr, d->type, d->rss_hash);

  s = format (s,
	      "\n%Uflags rss_type 0x%x ether 0x%x proto 0x%x vlan1%c "
	      "vlan2%c l4csum%c",
	      format_white_space, indent, d->rss_type, d->ether_type, d->proto,
	      _ (d->vlan1), _ (d->vlan2), _ (d->l4_csum));

  s = format (s,
	      "\n%Ustatus dd%c eop%c macerr%c v4_sum_ng%c l4_sum_err%c "
	      "l4_sum_ok%c len %u vlan 0x%x next %u",
	      format_white_space, indent, _ (d->dd), _ (d->eop), _ (d->macerr),
	      _ (d->v4_sum_ng), _ (d->l4_sum_err), _ (d->l4_sum_ok),
	      d->pkt_len, d->vlan, d->next_desc_ptr);

#undef _

  return s;
}

u8 *
atl_rx_trace (u8 *s, va_list *args)
{
  __clib_unused vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  __clib_unused vlib_node_t *node = va_arg (*args, vlib_node_t *);
  atl_rx_trace_t *t = va_arg (*args, atl_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi =
    vnet_get_sup_hw_interface_api_visible_or_null (vnm, t->sw_if_index);

  s = format (
    s, "atl: %v (%u) qid %u buffer %u", hi ? hi->name : (u8 *) "(unknown)",
    hi ? hi->hw_if_index : t->sw_if_index, t->queue_id, t->buffer_index);

  s = format (s, "\n%Udesc: %U", format_white_space, format_get_indent (s) + 2,
	      format_atl_rx_desc, &t->desc);
  return s;
}

u8 *
atl_tx_trace (u8 *s, va_list *args)
{
  __clib_unused vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  __clib_unused vlib_node_t *node = va_arg (*args, vlib_node_t *);
  atl_tx_trace_t *t = va_arg (*args, atl_tx_trace_t *);

  s = format (s, "sw_if_index %u queue %u buffer %u", t->sw_if_index,
	      t->queue_id, t->buffer_index);
  s = format (s, "\n%U%U", format_white_space, format_get_indent (s) + 2,
	      format_atl_tx_desc, &t->desc);
  return s;
}

u8 *
format_atl_tx_desc (u8 *s, va_list *args)
{
  const atl_tx_desc_t *d = va_arg (*args, const atl_tx_desc_t *);
  u32 indent = format_get_indent (s) + 2;

#define _(b) ((b) ? '+' : '-')

  s =
    format (s, "addr 0x%016llx len %u ctx_en %u", d->addr, d->len, d->ctx_en);
  s = format (s,
	      "\n%Uflags type_txd%c type_txc%c dd%c eop%c vlan%c fcs%c "
	      "ip4csum%c l4csum%c wb%c blen %u",
	      format_white_space, indent, _ (d->type_txd), _ (d->type_txc),
	      _ (d->dd), _ (d->eop), _ (d->vlan), _ (d->fcs), _ (d->ip4csum),
	      _ (d->l4csum), _ (d->wb), d->blen);

#undef _

  return s;
}
