/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#include <vnet/ip/ip_types_api.h>
#include <vlibmemory/api.h>
#include <fastacl/fastacl.h>
#include <fastacl/fastacl_aclb.h>
#include <acl/acl.api_enum.h>
#include <acl/acl.api_types.h>

#define vl_msg_name_crc_list
#include <acl/acl.api.h>
#undef vl_msg_name_crc_list

static u16
aclb_add_replace_msg_id (void)
{
  char *name = 0;

#define _(id, n, crc)                                                                              \
  if (id == VL_API_ACL_ADD_REPLACE)                                                                \
    name = #n "_" #crc;
  foreach_vl_msg_name_crc_acl;
#undef _
  return vl_msg_api_get_msg_index ((u8 *) name);
}

static void
aclb_encode_rule (vl_api_acl_rule_t *a, const acl_rule_t *r)
{
  ip46_type_t type = r->is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4;

  a->is_permit = r->is_permit;
  ip_address_encode (&r->src, type, &a->src_prefix.address);
  ip_address_encode (&r->dst, type, &a->dst_prefix.address);
  a->src_prefix.len = r->src_prefixlen;
  a->dst_prefix.len = r->dst_prefixlen;
  a->proto = r->proto;
  a->srcport_or_icmptype_first = clib_host_to_net_u16 (r->src_port_or_type_first);
  a->srcport_or_icmptype_last = clib_host_to_net_u16 (r->src_port_or_type_last);
  a->dstport_or_icmpcode_first = clib_host_to_net_u16 (r->dst_port_or_code_first);
  a->dstport_or_icmpcode_last = clib_host_to_net_u16 (r->dst_port_or_code_last);
  a->tcp_flags_mask = r->tcp_flags_mask;
  a->tcp_flags_value = r->tcp_flags_value;
}

static int
aclb_add_replace (fastacl_aclb_t *ab, u32 *acl_index, const acl_rule_t *rules)
{
  u32 n = vec_len (rules);
  u32 len = sizeof (vl_api_acl_add_replace_t) + n * sizeof (vl_api_acl_rule_t);
  msgbuf_t *mb = clib_mem_alloc (sizeof (msgbuf_t) + len);
  vl_api_acl_add_replace_t *mp = (vl_api_acl_add_replace_t *) mb->data;
  vl_api_acl_add_replace_reply_t *rmp;
  void (*handler) (void *);
  uword reply;
  int rv;

  clib_memset (mb, 0, sizeof (msgbuf_t) + len);
  mb->data_len = clib_host_to_net_u32 (len);
  mp->_vl_msg_id = clib_host_to_net_u16 (ab->add_replace_msg_id);
  mp->client_index = ab->api_client;
  mp->acl_index = clib_host_to_net_u32 (*acl_index);
  strncpy ((char *) mp->tag, "fastacl", sizeof (mp->tag) - 1);
  mp->count = clib_host_to_net_u32 (n);
  for (u32 i = 0; i < n; i++)
    aclb_encode_rule (&mp->r[i], &rules[i]);
  handler = vl_api_get_msg_data (vlibapi_get_main (), ab->add_replace_msg_id)->handler;
  handler (mp);
  clib_mem_free (mb);
  if (svm_queue_sub (ab->api_reply_q, (u8 *) &reply, SVM_Q_NOWAIT, 0))
    return VNET_API_ERROR_UNSPECIFIED;
  rmp = (vl_api_acl_add_replace_reply_t *) reply;
  VL_MSG_API_UNPOISON (rmp);
  rv = (i32) clib_net_to_host_u32 (rmp->retval);
  if (!rv)
    *acl_index = clib_net_to_host_u32 (rmp->acl_index);
  vl_msg_api_free (rmp);
  return rv;
}

clib_error_t *
fastacl_aclb_init (fastacl_main_t *fsm)
{
  fastacl_aclb_t *ab = &fsm->aclb;
  clib_error_t *err;
  u32 *acls = 0;
  int lc, rv;

  if (ab->inited)
    return 0;
  if ((err = acl_plugin_exports_init (&ab->methods)))
    return err;
  ab->add_replace_msg_id = aclb_add_replace_msg_id ();
  if (!vl_api_get_msg_data (vlibapi_get_main (), ab->add_replace_msg_id))
    return clib_error_return (0, "ACL plugin has no acl_add_replace handler");
  if (!ab->api_reply_q)
    {
      ab->api_reply_q = svm_queue_alloc_and_init (4, sizeof (uword), 0);
      ab->api_client = vl_api_memclnt_create_internal ("fastacl", ab->api_reply_q);
    }
  lc = ab->methods.get_lookup_context_index (
    ab->methods.register_user_module ("fastacl", "instance", 0), 0, 0);
  if (lc < 0)
    return clib_error_return (0, "no ACL lookup context (%d)", lc);
  ab->acl_index = ~0;
  if ((rv = aclb_add_replace (ab, &ab->acl_index, 0)))
    return clib_error_return (0, "cannot create the ACL (%d)", rv);
  ab->lc_index = lc;
  vec_add1 (acls, ab->acl_index);
  ab->methods.set_acl_vec_for_context (ab->lc_index, acls);
  vec_free (acls);
  ab->rule_by_key = hash_create_mem (0, sizeof (fastacl_aclb_key_t), sizeof (uword));
  ab->inited = 1;
  return 0;
}

static void
aclb_key (fastacl_aclb_key_t *k, u32 order, const fastacl_match_t *match)
{
  clib_memset (k, 0, sizeof (*k));
  k->order = order;
  k->match = *match;
}

u32
fastacl_aclb_rule_find (fastacl_main_t *fsm, u32 order, const fastacl_match_t *match)
{
  fastacl_aclb_key_t k;
  uword *p;

  aclb_key (&k, order, match);
  p = hash_get_mem (fsm->aclb.rule_by_key, &k);
  return p ? (u32) p[0] : ~0u;
}

static int
aclb_range_and (u16 *lo, u16 *hi, u16 olo, u16 ohi)
{
  *lo = clib_max (*lo, olo);
  *hi = clib_min (*hi, ohi);
  return *lo <= *hi;
}

static void
aclb_emit (fastacl_aclb_build_t *bld, u32 rule_index, u8 recheck, acl_rule_t *r, u16 slo, u16 shi,
	   u16 dlo, u16 dhi)
{
  r->src_port_or_type_first = slo;
  r->src_port_or_type_last = shi;
  r->dst_port_or_code_first = dlo;
  r->dst_port_or_code_last = dhi;
  vec_add1 (bld->rules, *r);
  vec_add1 (bld->ace_to_rule, rule_index);
  vec_add1 (bld->ace_recheck, recheck);
}

static void
aclb_emit_l4 (fastacl_aclb_build_t *bld, u32 rule_index, u8 recheck, const fastacl_match_t *m,
	      acl_rule_t *r)
{
  u16 slo = 0, shi = 65535, dlo = 0, dhi = 65535, lo, hi;

  if (m->flags & FASTACL_MATCH_ICMP_BITS)
    {
      if (m->flags & FASTACL_MATCH_ICMP_TYPE)
	slo = shi = m->icmp_type;
      if (m->flags & FASTACL_MATCH_ICMP_CODE)
	dlo = dhi = m->icmp_code;
      aclb_emit (bld, rule_index, recheck, r, slo, shi, dlo, dhi);
      return;
    }
  if (m->flags & FASTACL_MATCH_SRC_PORT)
    aclb_range_and (&slo, &shi, m->src_port_min, m->src_port_max);
  if (m->flags & FASTACL_MATCH_DST_PORT)
    aclb_range_and (&dlo, &dhi, m->dst_port_min, m->dst_port_max);
  if (!(m->flags & FASTACL_MATCH_EITHER_PORT))
    {
      aclb_emit (bld, rule_index, recheck, r, slo, shi, dlo, dhi);
      return;
    }
  lo = slo;
  hi = shi;
  if (aclb_range_and (&lo, &hi, m->either_port_min, m->either_port_max))
    aclb_emit (bld, rule_index, recheck, r, lo, hi, dlo, dhi);
  lo = dlo;
  hi = dhi;
  if (aclb_range_and (&lo, &hi, m->either_port_min, m->either_port_max))
    aclb_emit (bld, rule_index, recheck, r, slo, shi, lo, hi);
}

static int
aclb_proto_fits (u32 flags, u8 proto)
{
  if ((flags & FASTACL_MATCH_PORT_BITS) && proto != IP_PROTOCOL_TCP && proto != IP_PROTOCOL_UDP)
    return 0;
  if ((flags & FASTACL_MATCH_ICMP_BITS) && proto != IP_PROTOCOL_ICMP && proto != IP_PROTOCOL_ICMP6)
    return 0;
  if ((flags & FASTACL_MATCH_TCP_FLAGS) && proto != IP_PROTOCOL_TCP)
    return 0;
  return 1;
}

static void
aclb_expand_family (fastacl_aclb_build_t *bld, u32 rule_index, const fastacl_match_t *m, int is_ip6)
{
  u8 recheck = (m->flags & FASTACL_ACLB_RECHECK_FLAGS) != 0;
  u8 protos[2], n_protos = 0;
  acl_rule_t r = { .is_permit = 1, .is_ipv6 = is_ip6 };

  if (m->flags & FASTACL_MATCH_DST_PREFIX)
    {
      r.dst = m->dst_addr;
      r.dst_prefixlen = m->dst_prefix_len;
    }
  if (m->flags & FASTACL_MATCH_SRC_PREFIX)
    {
      r.src = m->src_addr;
      r.src_prefixlen = m->src_prefix_len;
    }
  if (m->flags & FASTACL_MATCH_TCP_FLAGS)
    {
      r.tcp_flags_value = m->tcp_flags_value;
      r.tcp_flags_mask = m->tcp_flags_mask;
    }

  if (m->flags & FASTACL_MATCH_PROTO)
    protos[n_protos++] = m->proto;
  else if (m->flags & FASTACL_MATCH_TCP_FLAGS)
    protos[n_protos++] = IP_PROTOCOL_TCP;
  else if (m->flags & FASTACL_MATCH_PORT_BITS)
    {
      protos[n_protos++] = IP_PROTOCOL_TCP;
      protos[n_protos++] = IP_PROTOCOL_UDP;
    }
  else if (m->flags & FASTACL_MATCH_ICMP_BITS)
    protos[n_protos++] = is_ip6 ? IP_PROTOCOL_ICMP6 : IP_PROTOCOL_ICMP;
  else
    protos[n_protos++] = 0;

  for (int i = 0; i < n_protos; i++)
    if (aclb_proto_fits (m->flags, protos[i]))
      {
	r.proto = protos[i];
	aclb_emit_l4 (bld, rule_index, recheck, m, &r);
      }
}

static void
aclb_expand (fastacl_aclb_build_t *bld, u32 rule_index, const fastacl_match_t *m)
{
  if (!(m->flags & FASTACL_MATCH_IS_IP6))
    aclb_expand_family (bld, rule_index, m, 0);
  if ((m->flags & FASTACL_MATCH_IS_IP6) || !(m->flags & FASTACL_MATCH_ADDR_BITS))
    aclb_expand_family (bld, rule_index, m, 1);
}

static void
aclb_rebuild (fastacl_main_t *fsm)
{
  fastacl_aclb_t *ab = &fsm->aclb;
  fastacl_aclb_build_t bld = {};
  fastacl_rule_t *rule;
  u32 *order = 0, *ri;
  int rv;

  pool_foreach (rule, fsm->rules)
    vec_add1 (order, rule->index);
  vec_sort_with_function (order, fastacl_rule_order_cmp);
  vec_foreach (ri, order)
    aclb_expand (&bld, *ri, &pool_elt_at_index (fsm->rules, *ri)->match);
  vec_free (order);

  rv = aclb_add_replace (ab, &ab->acl_index, bld.rules);
  if (rv)
    vlib_log_err (fsm->log_class, "ACL replace failed: %d", rv);
  else
    {
      u32 *to_rule = ab->ace_to_rule;
      u8 *recheck = ab->ace_recheck;

      ab->ace_to_rule = bld.ace_to_rule;
      ab->ace_recheck = bld.ace_recheck;
      bld.ace_to_rule = to_rule;
      bld.ace_recheck = recheck;
    }
  vec_free (bld.rules);
  vec_free (bld.ace_to_rule);
  vec_free (bld.ace_recheck);
}

static void
aclb_sync (fastacl_main_t *fsm)
{
  if (fsm->aclb.inited && !fsm->aclb.bulk)
    aclb_rebuild (fsm);
}

void
fastacl_aclb_rule_added (fastacl_main_t *fsm, u32 rule_index)
{
  fastacl_aclb_t *ab = &fsm->aclb;
  fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, rule_index);
  fastacl_aclb_key_t *k = clib_mem_alloc (sizeof (*k));

  aclb_key (k, rule->order, &rule->match);
  hash_set_mem (ab->rule_by_key, k, rule_index);
  aclb_sync (fsm);
}

void
fastacl_aclb_rule_removed (fastacl_main_t *fsm, u32 order, const fastacl_match_t *match)
{
  fastacl_aclb_t *ab = &fsm->aclb;
  fastacl_aclb_key_t k;
  hash_pair_t *hp;
  void *stored;

  aclb_key (&k, order, match);
  if (!(hp = hash_get_pair_mem (ab->rule_by_key, &k)))
    return;
  stored = uword_to_pointer (hp->key, void *);
  hash_unset_mem (ab->rule_by_key, &k);
  clib_mem_free (stored);
  aclb_sync (fsm);
}

void
fastacl_aclb_rules_cleared (fastacl_main_t *fsm)
{
  fastacl_aclb_t *ab = &fsm->aclb;
  hash_pair_t *hp;

  if (!ab->inited)
    return;
  hash_foreach_pair (hp, ab->rule_by_key,
		     ({ clib_mem_free (uword_to_pointer (hp->key, void *)); }));
  hash_free (ab->rule_by_key);
  ab->rule_by_key = hash_create_mem (0, sizeof (fastacl_aclb_key_t), sizeof (uword));
  aclb_sync (fsm);
}

void
fastacl_aclb_bulk_begin (fastacl_main_t *fsm)
{
  fsm->aclb.bulk = 1;
}

void
fastacl_aclb_bulk_end (fastacl_main_t *fsm)
{
  fsm->aclb.bulk = 0;
  aclb_sync (fsm);
}

int
fastacl_aclb_check (fastacl_aclb_check_ctx_t *c, u32 ace_index)
{
  fastacl_aclb_t *ab = &c->fsm->aclb;
  const fastacl_parsed_t *p = c->p;
  fastacl_match_t *m;

  m = &pool_elt_at_index (c->fsm->rules, ab->ace_to_rule[ace_index])->match;
  return fastacl_match_fields (m, p->pkt_proto, p->l4_src_port, p->l4_dst_port, p->l4, p->l4_bytes,
			       p->ip_len, p->pkt_dscp, p->pkt_frag_flags);
}
