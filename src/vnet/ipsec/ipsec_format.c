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
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipsec/ipsec_itf.h>

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
  ipsec_crypto_alg_t *r = va_arg (*args, ipsec_crypto_alg_t *);

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
  ipsec_integ_alg_t *r = va_arg (*args, ipsec_integ_alg_t *);

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

static u8 *
format_ipsec_policy_with_suffix (u8 *s, va_list *args, u8 *suffix)
{
  u32 pi = va_arg (*args, u32);
  ip46_type_t ip_type = IP46_TYPE_IP4;
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  vlib_counter_t counts;

  p = pool_elt_at_index (im->policies, pi);

  s = format (s, "  [%d] priority %d action %U type %U protocol ",
	      pi, p->priority,
	      format_ipsec_policy_action, p->policy,
	      format_ipsec_policy_type, p->type);
  if (p->protocol != IPSEC_POLICY_PROTOCOL_ANY)
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
  if (suffix)
    s = format (s, " %s", suffix);

  if (p->is_ipv6)
    {
      ip_type = IP46_TYPE_IP6;
    }

  s = format (s, "\n     local addr range %U - %U port range %u - %u",
	      format_ip46_address, &p->laddr.start, ip_type,
	      format_ip46_address, &p->laddr.stop, ip_type,
	      p->lport.start, p->lport.stop);
  s = format (s, "\n     remote addr range %U - %U port range %u - %u",
	      format_ip46_address, &p->raddr.start, ip_type,
	      format_ip46_address, &p->raddr.stop, ip_type,
	      p->rport.start, p->rport.stop);

  vlib_get_combined_counter (&ipsec_spd_policy_counters, pi, &counts);
  s = format (s, "\n     packets %u bytes %u", counts.packets, counts.bytes);

  return (s);
}

u8 *
format_ipsec_policy (u8 *s, va_list *args)
{
  return format_ipsec_policy_with_suffix (s, args, 0);
}

u8 *
format_ipsec_fp_policy (u8 *s, va_list *args)
{
  return format_ipsec_policy_with_suffix (s, args, (u8 *) "<fast-path>");
}

/**
 * @brief Context when walking the fp bihash  table. We need to filter
 * only those policies that are of given type as we walk the table.
 */
typedef struct ipsec_spd_policy_ctx_t_
{
  u32 *policies;
  ipsec_spd_policy_type_t t;
} ipsec_fp_walk_ctx_t;

static int
ipsec_fp_table_walk_ip4_cb (clib_bihash_kv_16_8_t *kvp, void *arg)
{
  ipsec_fp_walk_ctx_t *ctx = (ipsec_fp_walk_ctx_t *) arg;
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;

  ipsec_fp_lookup_value_t *val = (ipsec_fp_lookup_value_t *) &kvp->value;

  u32 *policy_id;

  vec_foreach (policy_id, val->fp_policies_ids)
    {
      p = pool_elt_at_index (im->policies, *policy_id);
      if (p->type == ctx->t)
	vec_add1 (ctx->policies, *policy_id);
    }

  return BIHASH_WALK_CONTINUE;
}

static int
ipsec_fp_table_walk_ip6_cb (clib_bihash_kv_40_8_t *kvp, void *arg)
{
  ipsec_fp_walk_ctx_t *ctx = (ipsec_fp_walk_ctx_t *) arg;
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;

  ipsec_fp_lookup_value_t *val = (ipsec_fp_lookup_value_t *) &kvp->value;

  u32 *policy_id;

  vec_foreach (policy_id, val->fp_policies_ids)
    {
      p = pool_elt_at_index (im->policies, *policy_id);
      if (p->type == ctx->t)
	vec_add1 (ctx->policies, *policy_id);
    }

  return BIHASH_WALK_CONTINUE;
}

u8 *
format_ipsec_fp_policies (u8 *s, va_list *args)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_t *spd = va_arg (*args, ipsec_spd_t *);
  ipsec_spd_policy_type_t t = va_arg (*args, ipsec_spd_policy_type_t);
  u32 *i;
  ipsec_fp_walk_ctx_t ctx = {
    .policies = 0,
    .t = t,
  };

  u32 ip4_in_lookup_hash_idx = spd->fp_spd.ip4_in_lookup_hash_idx;
  u32 ip4_out_lookup_hash_idx = spd->fp_spd.ip4_out_lookup_hash_idx;
  u32 ip6_in_lookup_hash_idx = spd->fp_spd.ip6_in_lookup_hash_idx;
  u32 ip6_out_lookup_hash_idx = spd->fp_spd.ip6_out_lookup_hash_idx;

  switch (t)
    {
    case IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT:
    case IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS:
    case IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD:
      if (INDEX_INVALID != ip4_in_lookup_hash_idx)
	{
	  clib_bihash_16_8_t *bihash_table = pool_elt_at_index (
	    im->fp_ip4_lookup_hashes_pool, ip4_in_lookup_hash_idx);

	  clib_bihash_foreach_key_value_pair_16_8 (
	    bihash_table, ipsec_fp_table_walk_ip4_cb, &ctx);
	}

      break;

    case IPSEC_SPD_POLICY_IP6_INBOUND_PROTECT:
    case IPSEC_SPD_POLICY_IP6_INBOUND_BYPASS:
    case IPSEC_SPD_POLICY_IP6_INBOUND_DISCARD:
      if (INDEX_INVALID != ip6_in_lookup_hash_idx)
	{
	  clib_bihash_40_8_t *bihash_table = pool_elt_at_index (
	    im->fp_ip6_lookup_hashes_pool, ip6_in_lookup_hash_idx);

	  clib_bihash_foreach_key_value_pair_40_8 (
	    bihash_table, ipsec_fp_table_walk_ip6_cb, &ctx);
	}

      break;
    case IPSEC_SPD_POLICY_IP4_OUTBOUND:
      if (INDEX_INVALID != ip4_out_lookup_hash_idx)
	{
	  clib_bihash_16_8_t *bihash_table = pool_elt_at_index (
	    im->fp_ip4_lookup_hashes_pool, ip4_out_lookup_hash_idx);

	  clib_bihash_foreach_key_value_pair_16_8 (
	    bihash_table, ipsec_fp_table_walk_ip4_cb, &ctx);
	}

      break;
    case IPSEC_SPD_POLICY_IP6_OUTBOUND:
      if (INDEX_INVALID != ip6_out_lookup_hash_idx)
	{
	  clib_bihash_40_8_t *bihash_table = pool_elt_at_index (
	    im->fp_ip6_lookup_hashes_pool, ip6_out_lookup_hash_idx);

	  clib_bihash_foreach_key_value_pair_40_8 (
	    bihash_table, ipsec_fp_table_walk_ip6_cb, &ctx);
	}

      break;
    default:
      break;
    }

  vec_foreach (i, ctx.policies)
    {
      s = format (s, "\n %U", format_ipsec_fp_policy, *i);
    }

  vec_free (ctx.policies);

  return s;
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

#define _(v, n)                                                               \
  s = format (s, "\n %s:", n);                                                \
  vec_foreach (i, spd->policies[IPSEC_SPD_POLICY_##v])                        \
    {                                                                         \
      s = format (s, "\n %U", format_ipsec_policy, *i);                       \
    }                                                                         \
  s = format (s, "\n %U", format_ipsec_fp_policies, spd, IPSEC_SPD_POLICY_##v);
  foreach_ipsec_spd_policy_type;
#undef _

done:
  return (s);
}

u8 *
format_ipsec_out_spd_flow_cache (u8 *s, va_list *args)
{
  ipsec_main_t *im = &ipsec_main;

  s = format (s, "\nipv4-outbound-spd-flow-cache-entries: %u",
	      im->ipsec4_out_spd_flow_cache_entries);

  return (s);
}

u8 *
format_ipsec_in_spd_flow_cache (u8 *s, va_list *args)
{
  ipsec_main_t *im = &ipsec_main;

  s = format (s, "\nipv4-inbound-spd-flow-cache-entries: %u",
	      im->ipsec4_in_spd_flow_cache_entries);

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

#define _(v, f, str) if (flags & IPSEC_SA_FLAG_##f) s = format(s, "%s ", str);
  foreach_ipsec_sa_flags
#undef _
    return (s);
}

u8 *
format_ipsec_sa (u8 * s, va_list * args)
{
  u32 sai = va_arg (*args, u32);
  ipsec_format_flags_t flags = va_arg (*args, ipsec_format_flags_t);
  vlib_counter_t counts;
  counter_t lost;
  ipsec_sa_t *sa;

  if (pool_is_free_index (ipsec_sa_pool, sai))
    {
      s = format (s, "No such SA index: %d", sai);
      goto done;
    }

  sa = ipsec_sa_get (sai);

  s = format (s, "[%d] sa %u (0x%x) spi %u (0x%08x) protocol:%s flags:[%U]",
	      sai, sa->id, sa->id, sa->spi, sa->spi,
	      sa->protocol ? "esp" : "ah", format_ipsec_sa_flags, sa->flags);

  if (!(flags & IPSEC_FORMAT_DETAIL))
    goto done;

  s = format (s, "\n   locks %d", sa->node.fn_locks);
  s = format (s, "\n   salt 0x%x", clib_net_to_host_u32 (sa->salt));
  s = format (s, "\n   thread-index:%d", sa->thread_index);
  s = format (s, "\n   seq %u seq-hi %u", sa->seq, sa->seq_hi);
  s = format (s, "\n   window %U", format_ipsec_replay_window,
	      sa->replay_window);
  s = format (s, "\n   crypto alg %U",
	      format_ipsec_crypto_alg, sa->crypto_alg);
  if (sa->crypto_alg && (flags & IPSEC_FORMAT_INSECURE))
    s = format (s, " key %U", format_ipsec_key, &sa->crypto_key);
  else
    s = format (s, " key [redacted]");
  s = format (s, "\n   integrity alg %U",
	      format_ipsec_integ_alg, sa->integ_alg);
  if (sa->integ_alg && (flags & IPSEC_FORMAT_INSECURE))
    s = format (s, " key %U", format_ipsec_key, &sa->integ_key);
  else
    s = format (s, " key [redacted]");
  s = format (s, "\n   UDP:[src:%d dst:%d]",
	      clib_host_to_net_u16 (sa->udp_hdr.src_port),
	      clib_host_to_net_u16 (sa->udp_hdr.dst_port));

  vlib_get_combined_counter (&ipsec_sa_counters, sai, &counts);
  lost = vlib_get_simple_counter (&ipsec_sa_lost_counters, sai);
  s = format (s, "\n   tx/rx:[packets:%Ld bytes:%Ld], lost:[packets:%Ld]",
	      counts.packets, counts.bytes, lost);

  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    s = format (s, "\n%U", format_tunnel, &sa->tunnel, 3);

done:
  return (s);
}

u8 *
format_ipsec_tun_protect_index (u8 * s, va_list * args)
{
  u32 itpi = va_arg (*args, index_t);
  ipsec_tun_protect_t *itp;

  if (pool_is_free_index (ipsec_tun_protect_pool, itpi))
    return (format (s, "No such tunnel index: %d", itpi));

  itp = pool_elt_at_index (ipsec_tun_protect_pool, itpi);

  return (format (s, "%U", format_ipsec_tun_protect, itp));
}

u8 *
format_ipsec_tun_protect_flags (u8 * s, va_list * args)
{
  ipsec_protect_flags_t flags = va_arg (*args, int);

  if (IPSEC_PROTECT_NONE == flags)
    s = format (s, "none");
#define _(a,b,c)                                \
  else if (flags & IPSEC_PROTECT_##a)           \
    s = format (s, "%s", c);                    \
  foreach_ipsec_protect_flags
#undef _

  return (s);
}

u8 *
format_ipsec_tun_protect (u8 * s, va_list * args)
{
  ipsec_tun_protect_t *itp = va_arg (*args, ipsec_tun_protect_t *);
  u32 sai;

  s = format (s, "%U flags:[%U]", format_vnet_sw_if_index_name,
	      vnet_get_main (), itp->itp_sw_if_index,
	      format_ipsec_tun_protect_flags, itp->itp_flags);
  if (!ip_address_is_zero (itp->itp_key))
    s = format (s, ": %U", format_ip_address, itp->itp_key);
  s = format (s, "\n output-sa:");
  s = format (s, "\n  %U", format_ipsec_sa, itp->itp_out_sa,
	      IPSEC_FORMAT_BRIEF);

  s = format (s, "\n input-sa:");
  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SAI(itp, sai,
  ({
  s = format (s, "\n  %U", format_ipsec_sa, sai, IPSEC_FORMAT_BRIEF);
  }));
  /* *INDENT-ON* */

  return (s);
}

u8 *
format_ipsec4_tunnel_kv (u8 * s, va_list * args)
{
  ipsec4_tunnel_kv_t *kv = va_arg (*args, ipsec4_tunnel_kv_t *);
  ip4_address_t ip;
  u32 spi;

  ipsec4_tunnel_extract_key (kv, &ip, &spi);

  s = format (s, "remote:%U spi:%u (0x%08x) sa:%d tun:%d",
	      format_ip4_address, &ip,
	      clib_net_to_host_u32 (spi),
	      clib_net_to_host_u32 (spi),
	      kv->value.sa_index, kv->value.tun_index);

  return (s);
}

u8 *
format_ipsec6_tunnel_kv (u8 * s, va_list * args)
{
  ipsec6_tunnel_kv_t *kv = va_arg (*args, ipsec6_tunnel_kv_t *);

  s = format (s, "remote:%U spi:%u (0x%08x) sa:%d tun:%d",
	      format_ip6_address, &kv->key.remote_ip,
	      clib_net_to_host_u32 (kv->key.spi),
	      clib_net_to_host_u32 (kv->key.spi),
	      kv->value.sa_index, kv->value.tun_index);

  return (s);
}

u8 *
format_ipsec_itf (u8 * s, va_list * a)
{
  index_t ii = va_arg (*a, index_t);
  ipsec_itf_t *itf;

  itf = ipsec_itf_get (ii);
  s = format (s, "[%d] %U %U",
	      ii, format_vnet_sw_if_index_name, vnet_get_main (),
	      itf->ii_sw_if_index, format_tunnel_mode, itf->ii_mode);

  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
