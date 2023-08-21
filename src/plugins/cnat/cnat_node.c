#include <cnat/cnat_node.h>

u8 *
format_cnat_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cnat_trace_element_t *t = va_arg (*args, cnat_trace_element_t *);
  u32 indent = format_get_indent (s);
  vnet_main_t *vnm = vnet_get_main ();

  if (t->flow_state == CNAT_LOOKUP_IS_ERR)
    s = format (s, "session lookup error");
  else if (t->flow_state == CNAT_LOOKUP_IS_RETURN)
    s = format (s, "return session");
  else if (t->flow_state == CNAT_LOOKUP_IS_NEW)
    s = format (s, "new session");
  else if (t->flow_state == CNAT_LOOKUP_IS_OK)
    s = format (s, "session found");
  else
    s = format (s, "weird flow_state %d", t->flow_state);

  s = format (s, "\n%Uin:%U out:%U ", format_white_space, indent,
	      format_vnet_sw_if_index_name, vnm, t->sw_if_index[VLIB_RX],
	      format_vnet_sw_if_index_name, vnm, t->sw_if_index[VLIB_TX]);

  s = format (s, "\n%U%U", format_white_space, indent, format_cnat_timestamp,
	      &t->ts, indent);

  if (t->flags & CNAT_TRACE_REWRITE_FOUND)
    s = format (s, "\n%U%U", format_white_space, indent, format_cnat_rewrite,
		&t->rw);

  return s;
}
