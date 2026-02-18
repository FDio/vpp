/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <soft-rss/soft_rss.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/vec.h>
#include <vnet/interface.h>
#include <strings.h>

static const char *const soft_rss_type_strings[SOFT_RSS_N_TYPES] = {
#define _(sym, str) [SOFT_RSS_TYPE_##sym] = str,
  foreach_soft_rss_type
#undef _
};

u8 *
format_soft_rss_type (u8 *s, va_list *args)
{
  soft_rss_type_t type = (soft_rss_type_t) va_arg (*args, int);
  const char *name = 0;

  if ((u32) type < ARRAY_LEN (soft_rss_type_strings))
    name = soft_rss_type_strings[type];

  if (!name)
    return format (s, "unknown(%u)", (u32) type);

  return format (s, "%s", name);
}

uword
unformat_soft_rss_type (unformat_input_t *input, va_list *args)
{
  soft_rss_type_t *type = va_arg (*args, soft_rss_type_t *);
  u8 *value = 0;

  if (!unformat (input, "%s", &value))
    return 0;

  for (u32 i = 0; i < ARRAY_LEN (soft_rss_type_strings); i++)
    if (soft_rss_type_strings[i] &&
	!strcasecmp ((char *) value, soft_rss_type_strings[i]))
      {
	*type = (soft_rss_type_t) i;
	vec_free (value);
	return 1;
      }

  vec_free (value);
  return 0;
}

u8 *
format_soft_rss_reta (u8 *s, va_list *args)
{
  const u8 *reta = va_arg (*args, const u8 *);
  u32 len = va_arg (*args, u32);
  u32 indent = format_get_indent (s);

  for (u32 i = 0; i < len; i++)
    {
      s = format (s, "%3u", reta[i]);
      if (i % 16 == 15)
	s = format (s, "\n%U", format_white_space, indent);
    }

  return s;
}

u8 *
format_soft_rss_if (u8 *s, va_list *args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  u32 sw_if_index = va_arg (*args, u32);
  u32 indent = format_get_indent (s);
  soft_rss_rt_data_t *rt = va_arg (*args, soft_rss_rt_data_t *);

  s = format (s, "%U:", format_vnet_sw_if_index_name, vnm, sw_if_index);
  s = format_newline (s, indent + 2);
  s = format (s, "status: %s", rt->enabled ? "enabled" : "disabled");
  s = format_newline (s, indent + 2);
  s = format (s, "ipv4-type: %U", format_soft_rss_type, rt->ipv4_type);
  s = format_newline (s, indent + 2);
  s = format (s, "ipv6-type: %U", format_soft_rss_type, rt->ipv6_type);
  s = format_newline (s, indent + 2);
  s = format (s, "match-offset: %u", rt->match_offset);
  s = format_newline (s, indent + 2);
  s = format (s, "reta size: %u", rt->reta_mask + 1);
  s = format_newline (s, indent + 2);
  s = format (s, "reta: %U", format_soft_rss_reta, rt->reta, rt->reta_mask + 1);

  s = format_newline (s, indent + 2);
  s = format (s, "match4:");
  for (soft_rss_rt_match_t *m = rt->match4; m < rt->match4 + rt->n_match4; m++)
    {
      s = format_newline (s, indent + 4);
      s = format (s, "[%u] mask %U match %U key-offset %u key-length %u", m - rt->match4,
		  format_hex_bytes, &m->mask, sizeof (m->mask), format_hex_bytes, &m->match,
		  sizeof (m->match), m->key_start, m->key_len);
    }
  s = format_newline (s, indent + 2);
  s = format (s, "match6:");
  for (soft_rss_rt_match_t *m = rt->match6; m < rt->match6 + rt->n_match6; m++)
    {
      s = format_newline (s, indent + 4);
      s = format (s, "[%u] mask %U match %U key-offset %u key-length %u", m - rt->match6,
		  format_hex_bytes, &m->mask, sizeof (m->mask), format_hex_bytes, &m->match,
		  sizeof (m->match), m->key_start, m->key_len);
    }

  return s;
}

u8 *
format_soft_rss_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  soft_rss_trace_t *t = va_arg (*args, soft_rss_trace_t *);

  s = format (s, "soft-rss: sw_if_index %u, hash 0x%04x, thread %u",
	      t->sw_if_index, t->hash, t->thread_index);
  return s;
}

u8 *
format_soft_rss_handoff_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  soft_rss_handoff_trace_t *t = va_arg (*args, soft_rss_handoff_trace_t *);

  s = format (s, "soft-rss-handoff: sw_if_index %u, next %u", t->sw_if_index,
	      t->next_index);
  return s;
}
