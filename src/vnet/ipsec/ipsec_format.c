/*
 * decap.c : IPSec tunnel support
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>
#include <vnet/fib/fib_table.h>

#include <vnet/ipsec/ipsec.h>

u8 *
format_ipsec_policy_action (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  char *t = 0;

  switch (i)
    {
#define _(v,f,str) case IPSEC_POLICY_ACTION_##f: t = str; break;
      foreach_ipsec_policy_action
#undef _
    default:
      s = format (s, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

u8 *
format_ipsec_policy_type (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  char *t = 0;

  switch (i)
    {
#define _(f,str) case IPSEC_SPD_POLICY_##f: t = str; break;
      foreach_ipsec_spd_policy_type
#undef _
    default:
      s = format (s, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

uword
unformat_ipsec_policy_action (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = IPSEC_POLICY_ACTION_##f;
  foreach_ipsec_policy_action
#undef _
    else
    return 0;
  return 1;
}

u8 *
format_ipsec_crypto_alg (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v,f,str) case IPSEC_CRYPTO_ALG_##f: t = (u8 *) str; break;
      foreach_ipsec_crypto_alg
#undef _
    default:
      s = format (s, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

uword
unformat_ipsec_crypto_alg (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = IPSEC_CRYPTO_ALG_##f;
  foreach_ipsec_crypto_alg
#undef _
    else
    return 0;
  return 1;
}

u8 *
format_ipsec_integ_alg (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v,f,str) case IPSEC_INTEG_ALG_##f: t = (u8 *) str; break;
      foreach_ipsec_integ_alg
#undef _
    default:
      s = format (s, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

uword
unformat_ipsec_integ_alg (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = IPSEC_INTEG_ALG_##f;
  foreach_ipsec_integ_alg
#undef _
    else
    return 0;
  return 1;
}

u8 *
format_ipsec_replay_window (u8 * s, va_list * args)
{
  u64 w = va_arg (*args, u64);
  u8 i;

  for (i = 0; i < 64; i++)
    {
      s = format (s, "%u", w & (1ULL << i) ? 1 : 0);
    }

  return s;
}

u8 *
format_ipsec_policy (u8 * s, va_list * args)
{
  u32 pi = va_arg (*args, u32);
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  vlib_counter_t counts;

  p = pool_elt_at_index (im->policies, pi);

  s = format (s, "  [%d] priority %d action %U type %U protocol ",
	      pi, p->priority,
	      format_ipsec_policy_action, p->policy,
	      format_ipsec_policy_type, p->type);
  if (p->protocol)
    {
      s = format (s, "%U", format_ip_protocol, p->protocol);
    }
  else
    {
      s = format (s, "any");
    }
  if (p->policy == IPSEC_POLICY_ACTION_PROTECT)
    {
      s = format (s, " sa %u", p->sa_id);
    }

  s = format (s, "\n     local addr range %U - %U port range %u - %u",
	      format_ip46_address, &p->laddr.start, IP46_TYPE_ANY,
	      format_ip46_address, &p->laddr.stop, IP46_TYPE_ANY,
	      clib_net_to_host_u16 (p->lport.start),
	      clib_net_to_host_u16 (p->lport.stop));
  s = format (s, "\n     remote addr range %U - %U port range %u - %u",
	      format_ip46_address, &p->raddr.start, IP46_TYPE_ANY,
	      format_ip46_address, &p->raddr.stop, IP46_TYPE_ANY,
	      clib_net_to_host_u16 (p->rport.start),
	      clib_net_to_host_u16 (p->rport.stop));

  vlib_get_combined_counter (&ipsec_spd_policy_counters, pi, &counts);
  s = format (s, "\n     packets %u bytes %u", counts.packets, counts.bytes);

  return (s);
}

u8 *
format_ipsec_spd (u8 * s, va_list * args)
{
  u32 si = va_arg (*args, u32);
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_t *spd;
  u32 *i;

  if (pool_is_free_index (im->spds, si))
    {
      s = format (s, "No such SPD index: %d", si);
      goto done;
    }

  spd = pool_elt_at_index (im->spds, si);

  s = format (s, "spd %u", spd->id);

#define _(v, n)                                                 \
  s = format (s, "\n %s:", n);                                  \
  vec_foreach(i, spd->policies[IPSEC_SPD_POLICY_##v])           \
  {                                                             \
    s = format (s, "\n %U", format_ipsec_policy, *i);           \
  }
  foreach_ipsec_spd_policy_type;
#undef _

done:
  return (s);
}

u8 *
format_ipsec_key (u8 * s, va_list * args)
{
  ipsec_key_t *key = va_arg (*args, ipsec_key_t *);

  return (format (s, "%U", format_hex_bytes, key->data, key->len));
}

uword
unformat_ipsec_key (unformat_input_t * input, va_list * args)
{
  ipsec_key_t *key = va_arg (*args, ipsec_key_t *);
  u8 *data;

  if (unformat (input, "%U", unformat_hex_string, &data))
    {
      ipsec_mk_key (key, data, vec_len (data));
      vec_free (data);
    }
  else
    return 0;
  return 1;
}

u8 *
format_ipsec_sa_flags (u8 * s, va_list * args)
{
  ipsec_sa_flags_t flags = va_arg (*args, int);

  if (0)
    ;
#define _(v, f, str) else if (flags & IPSEC_SA_FLAG_##f) s = format(s, "%s ", str);
  foreach_ipsec_sa_flags
#undef _
    return (s);
}

u8 *
format_ipsec_sa (u8 * s, va_list * args)
{
  u32 sai = va_arg (*args, u32);
  ipsec_format_flags_t flags = va_arg (*args, ipsec_format_flags_t);
  ipsec_main_t *im = &ipsec_main;
  vlib_counter_t counts;
  u32 tx_table_id;
  ipsec_sa_t *sa;

  if (pool_is_free_index (im->sad, sai))
    {
      s = format (s, "No such SA index: %d", sai);
      goto done;
    }

  sa = pool_elt_at_index (im->sad, sai);

  s = format (s, "[%d] sa 0x%x spi %u mode %s%s protocol %s %U",
	      sai, sa->id, sa->spi,
	      ipsec_sa_is_set_IS_TUNNEL (sa) ? "tunnel" : "transport",
	      ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ? "-ip6" : "",
	      sa->protocol ? "esp" : "ah", format_ipsec_sa_flags, sa->flags);

  if (!(flags & IPSEC_FORMAT_DETAIL))
    goto done;

  s = format (s, "\n   salt 0x%x", clib_net_to_host_u32 (sa->salt));
  s = format (s, "\n   seq %u seq-hi %u", sa->seq, sa->seq_hi);
  s = format (s, "\n   last-seq %u last-seq-hi %u window %U",
	      sa->last_seq, sa->last_seq_hi,
	      format_ipsec_replay_window, sa->replay_window);
  s = format (s, "\n   crypto alg %U",
	      format_ipsec_crypto_alg, sa->crypto_alg);
  if (sa->crypto_alg)
    s = format (s, " key %U", format_ipsec_key, &sa->crypto_key);
  s = format (s, "\n   integrity alg %U",
	      format_ipsec_integ_alg, sa->integ_alg);
  if (sa->integ_alg)
    s = format (s, " key %U", format_ipsec_key, &sa->integ_key);

  vlib_get_combined_counter (&ipsec_sa_counters, sai, &counts);
  s = format (s, "\n   packets %u bytes %u", counts.packets, counts.bytes);

  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    {
      tx_table_id = fib_table_get_table_id (sa->tx_fib_index,
					    FIB_PROTOCOL_IP4);
      s = format (s, "\n   table-ID %d tunnel src %U dst %U",
		  tx_table_id,
		  format_ip46_address, &sa->tunnel_src_addr, IP46_TYPE_ANY,
		  format_ip46_address, &sa->tunnel_dst_addr, IP46_TYPE_ANY);
      if (!ipsec_sa_is_set_IS_INBOUND (sa))
	{
	  s =
	    format (s, "\n    resovle via fib-entry: %d",
		    sa->fib_entry_index);
	  s = format (s, "\n    stacked on:");
	  s =
	    format (s, "\n      %U", format_dpo_id,
		    &sa->dpo[IPSEC_PROTOCOL_ESP], 6);
	}
    }

done:
  return (s);
}

u8 *
format_ipsec_tunnel (u8 * s, va_list * args)
{
  ipsec_main_t *im = &ipsec_main;
  u32 ti = va_arg (*args, u32);
  vnet_hw_interface_t *hi;
  ipsec_tunnel_if_t *t;

  if (pool_is_free_index (im->tunnel_interfaces, ti))
    {
      s = format (s, "No such tunnel index: %d", ti);
      goto done;
    }

  t = pool_elt_at_index (im->tunnel_interfaces, ti);

  if (t->hw_if_index == ~0)
    goto done;

  hi = vnet_get_hw_interface (im->vnet_main, t->hw_if_index);

  s = format (s, "%s\n", hi->name);

  s = format (s, "   out-bound sa: ");
  s = format (s, "%U\n", format_ipsec_sa, t->output_sa_index,
	      IPSEC_FORMAT_BRIEF);

  s = format (s, "    in-bound sa: ");
  s = format (s, "%U\n", format_ipsec_sa, t->input_sa_index,
	      IPSEC_FORMAT_BRIEF);

done:
  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
