/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <fastacl/fastacl.h>
#include <fastacl/fastacl_format.h>

static u8 *
format_si_scaled (u8 *s, f64 v, const char *unit, int *scaled)
{
  *scaled = 1;
  if (v >= 1e9)
    return format (s, "%.2f G%s", v / 1e9, unit);
  if (v >= 1e6)
    return format (s, "%.2f M%s", v / 1e6, unit);
  if (v >= 1e3)
    return format (s, "%.1f K%s", v / 1e3, unit);
  *scaled = 0;
  return s;
}

u8 *
format_fastacl_pps (u8 *s, va_list *args)
{
  f64 v = va_arg (*args, f64);
  int scaled;
  u8 *r = format_si_scaled (s, v, "pps", &scaled);
  return scaled ? r : format (s, "%.1f pps", v);
}

u8 *
format_fastacl_bps (u8 *s, va_list *args)
{
  f64 v = va_arg (*args, f64);
  int scaled;
  u8 *r = format_si_scaled (s, v, "bps", &scaled);
  return scaled ? r : format (s, "%.1f bps", v);
}

u8 *
format_fastacl_count_si (u8 *s, va_list *args)
{
  u64 v = va_arg (*args, u64);
  int scaled;
  u8 *r = format_si_scaled (s, (f64) v, "", &scaled);
  return scaled ? r : format (s, "%llu", v);
}

u8 *
format_fastacl_bytes_si (u8 *s, va_list *args)
{
  u64 v = va_arg (*args, u64);
  int scaled;
  u8 *r = format_si_scaled (s, (f64) v, "B", &scaled);
  return scaled ? r : format (s, "%llu B", v);
}

static u8 *
format_fastacl_rates (u8 *s, va_list *args)
{
  fastacl_rate_snapshot_t *snap = va_arg (*args, fastacl_rate_snapshot_t *);
  u8 *pps = format (0, "%U", format_fastacl_pps, snap->pps);
  u8 *l3 = format (0, "%U", format_fastacl_bps, snap->l3_bps);
  u8 *l1 = format (0, "%U", format_fastacl_bps, snap->l1_bps);

  s = format (s, "%-12v %-14v %-14v", pps, l3, l1);

  vec_free (pps);
  vec_free (l3);
  vec_free (l1);
  return s;
}

const char *
fastacl_action_type_name (u8 type)
{
  switch (type)
    {
    case FASTACL_ACTION_TYPE_DROP:
      return "drop";
    case FASTACL_ACTION_TYPE_PERMIT:
      return "permit";
    default:
      return "unknown";
    }
}

static u8 *
format_fastacl_prefix (u8 *s, va_list *args)
{
  fastacl_match_t *m = va_arg (*args, fastacl_match_t *);
  u32 flag = va_arg (*args, u32);
  int is_dst = flag == FASTACL_MATCH_DST_PREFIX;
  ip46_address_t *a = is_dst ? &m->dst_addr : &m->src_addr;
  u8 plen = is_dst ? m->dst_prefix_len : m->src_prefix_len;
  ip46_type_t type = (m->flags & FASTACL_MATCH_IS_IP6) ? IP46_TYPE_IP6 : IP46_TYPE_IP4;

  if (!(m->flags & flag))
    return format (s, "*");
  return format (s, "%U/%u", format_ip46_address, a, type, plen);
}

static u8 *
format_fastacl_proto (u8 *s, va_list *args)
{
  fastacl_match_t *m = va_arg (*args, fastacl_match_t *);

  if (!(m->flags & FASTACL_MATCH_PROTO))
    return format (s, "*");
  return format (s, "%u", m->proto);
}

static u8 *
format_fastacl_range (u8 *s, const char *label, u32 lo, u32 hi)
{
  if (lo == hi)
    return format (s, "%s=%u ", label, lo);
  return format (s, "%s=%u-%u ", label, lo, hi);
}

static u8 *
format_fastacl_fragment (u8 *s, fastacl_match_t *m)
{
  if (m->fragment_mask && m->fragment_mask != m->fragment_flags)
    return format (s, "frag=0x%02x/0x%02x ", m->fragment_flags, m->fragment_mask);
  return format (s, "frag=0x%02x ", m->fragment_flags);
}

static u8 *
format_fastacl_match_extra (u8 *s, va_list *args)
{
  fastacl_match_t *m = va_arg (*args, fastacl_match_t *);
  u32 len0 = vec_len (s);

  if (m->flags & FASTACL_MATCH_DST_PORT)
    s = format_fastacl_range (s, "dp", m->dst_port_min, m->dst_port_max);
  if (m->flags & FASTACL_MATCH_SRC_PORT)
    s = format_fastacl_range (s, "sp", m->src_port_min, m->src_port_max);
  if (m->flags & FASTACL_MATCH_EITHER_PORT)
    s = format_fastacl_range (s, "ep", m->either_port_min, m->either_port_max);
  if (m->flags & FASTACL_MATCH_ICMP_TYPE)
    s = format (s, "icmp-t=%u ", m->icmp_type);
  if (m->flags & FASTACL_MATCH_ICMP_CODE)
    s = format (s, "icmp-c=%u ", m->icmp_code);
  if (m->flags & FASTACL_MATCH_TCP_FLAGS)
    s = format (s, "fl=0x%02x/0x%02x ", m->tcp_flags_value, m->tcp_flags_mask);
  if (m->flags & FASTACL_MATCH_PKT_LEN)
    s = format_fastacl_range (s, "len", m->pkt_len_min, m->pkt_len_max);
  if (m->flags & FASTACL_MATCH_DSCP)
    s = format (s, "dscp=%u ", m->dscp);
  if (m->flags & FASTACL_MATCH_FRAGMENT)
    s = format_fastacl_fragment (s, m);
  if (vec_len (s) == len0)
    s = format (s, "*");
  return s;
}

void
fastacl_show_one_rule (vlib_main_t *vm, fastacl_rule_t *rule)
{
  fastacl_match_t *m = &rule->match;

  vlib_cli_output (vm,
		   "%-8u %-8u %-20U %-20U %-8U %-32U %-12s %-12llu "
		   "%-12llu %U",
		   rule->index, rule->order, format_fastacl_prefix, m, FASTACL_MATCH_DST_PREFIX,
		   format_fastacl_prefix, m, FASTACL_MATCH_SRC_PREFIX, format_fastacl_proto, m,
		   format_fastacl_match_extra, m, fastacl_action_type_name (rule->action.type),
		   rule->packet_count, rule->byte_count, format_fastacl_rates, &rule->rate_snap);
}
