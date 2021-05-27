
static u8 *
format_fa_5tuple (u8 *s, va_list *args)
{
  fa_5tuple_t *p5t = va_arg (*args, fa_5tuple_t *);
  void *paddr0;
  void *paddr1;
  void *format_address_func;
  void *ip_af;
  void *ip_frag_txt =
    p5t->pkt.is_nonfirst_fragment ? " non-initial fragment" : "";

  if (p5t->pkt.is_ip6)
    {
      ip_af = "ip6";
      format_address_func = format_ip6_address;
      paddr0 = &p5t->ip6_addr[0];
      paddr1 = &p5t->ip6_addr[1];
    }
  else
    {
      ip_af = "ip4";
      format_address_func = format_ip4_address;
      paddr0 = &p5t->ip4_addr[0];
      paddr1 = &p5t->ip4_addr[1];
    }

  s =
    format (s, "lc_index %d l3 %s%s ", p5t->pkt.lc_index, ip_af, ip_frag_txt);
  s = format (s, "%U -> %U ", format_address_func, paddr0, format_address_func,
	      paddr1);
  s = format (s, "%U ", format_fa_session_l4_key, &p5t->l4);
  s = format (s, "tcp flags (%s) %02x rsvd %x",
	      p5t->pkt.tcp_flags_valid ? "valid" : "invalid",
	      p5t->pkt.tcp_flags, p5t->pkt.flags_reserved);
  return s;
}

#ifndef CLIB_MARCH_VARIANT
u8 *
format_acl_plugin_5tuple (u8 *s, va_list *args)
{
  return format_fa_5tuple (s, args);
}
#endif

/* packet trace format function */
static u8 *
format_acl_plugin_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  acl_fa_trace_t *t = va_arg (*args, acl_fa_trace_t *);

  s = format (s,
	      "acl-plugin: lc_index: %d, sw_if_index %d, next index %d, "
	      "action: %d, match: acl %d rule %d trace_bits %08x\n"
	      "  pkt info %016llx %016llx %016llx %016llx %016llx %016llx",
	      t->lc_index, t->sw_if_index, t->next_index, t->action,
	      t->match_acl_in_index, t->match_rule_index, t->trace_bitmap,
	      t->packet_info[0], t->packet_info[1], t->packet_info[2],
	      t->packet_info[3], t->packet_info[4], t->packet_info[5]);

  /* Now also print out the packet_info in a form usable by humans */
  s = format (s, "\n   %U", format_fa_5tuple, t->packet_info);
  return s;
}

static char *acl_fa_error_strings[] = {
#define _(sym, string) string,
  foreach_acl_fa_error
#undef _
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
