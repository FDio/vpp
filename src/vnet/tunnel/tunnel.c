/*
 * tunnel.h: shared definitions for tunnels.
 *
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
 */

#include <vnet/tunnel/tunnel.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>

const u8 TUNNEL_ENCAP_DECAP_FLAG_MASK = (
#define _(a, b, c) TUNNEL_ENCAP_DECAP_FLAG_##a |
  foreach_tunnel_encap_decap_flag
#undef _
  0);
const u8 TUNNEL_FLAG_MASK = (
#define _(a, b, c) TUNNEL_FLAG_##a |
  foreach_tunnel_flag
#undef _
  0);

u8 *
format_tunnel_mode (u8 * s, va_list * args)
{
  tunnel_mode_t mode = va_arg (*args, int);

  switch (mode)
    {
#define _(n, v) case TUNNEL_MODE_##n:       \
        s = format (s, "%s", v);            \
        break;
      foreach_tunnel_mode
#undef _
    }

  return (s);
}

uword
unformat_tunnel_mode (unformat_input_t * input, va_list * args)
{
  tunnel_mode_t *m = va_arg (*args, tunnel_mode_t *);

  if (unformat (input, "p2p"))
    *m = TUNNEL_MODE_P2P;
  else if (unformat (input, "p2mp") || unformat (input, "mp"))
    *m = TUNNEL_MODE_MP;
  else
    return 0;
  return 1;
}

u8 *
format_tunnel_encap_decap_flags (u8 * s, va_list * args)
{
  tunnel_encap_decap_flags_t f = va_arg (*args, int);

  if (f == TUNNEL_ENCAP_DECAP_FLAG_NONE)
    s = format (s, "none");

#define _(a, b, c)                                                            \
  else if (f & TUNNEL_ENCAP_DECAP_FLAG_##a) s = format (s, "%s ", b);
  foreach_tunnel_encap_decap_flag
#undef _
    return (s);
}

uword
unformat_tunnel_encap_decap_flags (unformat_input_t * input, va_list * args)
{
  tunnel_encap_decap_flags_t *f =
    va_arg (*args, tunnel_encap_decap_flags_t *);
#define _(a,b,c) if (unformat(input, b)) {\
  *f |= TUNNEL_ENCAP_DECAP_FLAG_##a;\
  return 1;\
  }
  foreach_tunnel_encap_decap_flag;
#undef _
  return 0;
}

u8 *
format_tunnel_flags (u8 *s, va_list *args)
{
  tunnel_flags_t f = va_arg (*args, int);

  if (f == TUNNEL_FLAG_NONE)
    s = format (s, "none");

#define _(a, b, c) else if (f & TUNNEL_FLAG_##a) s = format (s, "%s ", c);
  foreach_tunnel_flag
#undef _
    return (s);
}

uword
unformat_tunnel_flags (unformat_input_t *input, va_list *args)
{
  tunnel_flags_t *f = va_arg (*args, tunnel_flags_t *);
#define _(a, b, c)                                                            \
  if (unformat (input, c))                                                    \
    {                                                                         \
      *f |= TUNNEL_FLAG_##a;                                                  \
      return 1;                                                               \
    }
  foreach_tunnel_flag;
#undef _
  return 0;
}

ip_address_family_t
tunnel_get_af (const tunnel_t *t)
{
  return (ip_addr_version (&t->t_src));
}

void
tunnel_copy (const tunnel_t *src, tunnel_t *dst)
{
  ip_address_copy (&dst->t_dst, &src->t_dst);
  ip_address_copy (&dst->t_src, &src->t_src);

  dst->t_encap_decap_flags = src->t_encap_decap_flags;
  dst->t_flags = src->t_flags;
  dst->t_mode = src->t_mode;
  dst->t_table_id = src->t_table_id;
  dst->t_dscp = src->t_dscp;
  dst->t_hop_limit = src->t_hop_limit;
  dst->t_fib_index = src->t_fib_index;

  dst->t_flags &= ~TUNNEL_FLAG_RESOLVED;
  dst->t_fib_entry_index = FIB_NODE_INDEX_INVALID;
  dst->t_sibling = ~0;
}

u8 *
format_tunnel (u8 *s, va_list *args)
{
  const tunnel_t *t = va_arg (*args, tunnel_t *);
  u32 indent = va_arg (*args, u32);

  s = format (s, "%Utable-ID:%d [%U->%U] hop-limit:%d %U %U [%U] [%U]",
	      format_white_space, indent, t->t_table_id, format_ip_address,
	      &t->t_src, format_ip_address, &t->t_dst, t->t_hop_limit,
	      format_tunnel_mode, t->t_mode, format_ip_dscp, t->t_dscp,
	      format_tunnel_flags, t->t_flags, format_tunnel_encap_decap_flags,
	      t->t_encap_decap_flags);
  if (t->t_flags & TUNNEL_FLAG_RESOLVED)
    s = format (s, " [resolved via fib-entry: %d]", t->t_fib_entry_index);

  return (s);
}

uword
unformat_tunnel (unformat_input_t *input, va_list *args)
{
  tunnel_t *t = va_arg (*args, tunnel_t *);

  if (!unformat (input, "tunnel"))
    return (0);

  unformat (input, "src %U", unformat_ip_address, &t->t_src);
  unformat (input, "dst %U", unformat_ip_address, &t->t_dst);
  unformat (input, "table-id:%d", &t->t_table_id);
  unformat (input, "hop-limit:%d", &t->t_hop_limit);
  unformat (input, "%U", unformat_ip_dscp, &t->t_dscp);
  unformat (input, "%U", unformat_tunnel_encap_decap_flags,
	    &t->t_encap_decap_flags);
  unformat (input, "%U", unformat_tunnel_flags, &t->t_flags);
  unformat (input, "%U", unformat_tunnel_mode, &t->t_mode);

  ASSERT (!"Check not 4 and 6");

  return (1);
}

int
tunnel_resolve (tunnel_t *t, fib_node_type_t child_type, index_t child_index)
{
  fib_prefix_t pfx;

  ip_address_to_fib_prefix (&t->t_dst, &pfx);

  t->t_fib_index = fib_table_find (pfx.fp_proto, t->t_table_id);

  if (t->t_fib_index == ~((u32) 0))
    return VNET_API_ERROR_NO_SUCH_FIB;

  t->t_fib_entry_index = fib_entry_track (t->t_fib_index, &pfx, child_type,
					  child_index, &t->t_sibling);

  t->t_flags |= TUNNEL_FLAG_RESOLVED;

  return (0);
}

void
tunnel_unresolve (tunnel_t *t)
{
  if (t->t_flags & TUNNEL_FLAG_RESOLVED)
    fib_entry_untrack (t->t_fib_entry_index, t->t_sibling);

  t->t_flags &= ~TUNNEL_FLAG_RESOLVED;
}

void
tunnel_contribute_forwarding (const tunnel_t *t, dpo_id_t *dpo)
{
  fib_forward_chain_type_t fct;

  fct = fib_forw_chain_type_from_fib_proto (
    ip_address_family_to_fib_proto (ip_addr_version (&t->t_src)));

  fib_entry_contribute_forwarding (t->t_fib_entry_index, fct, dpo);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
