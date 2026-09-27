/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#ifndef __included_fastacl_aclb_h__
#define __included_fastacl_aclb_h__

#include <vppinfra/hash.h>
#include <svm/queue.h>
#include <acl/exports.h>
#include <fastacl/fastacl_types.h>

#define FASTACL_ACLB_RECHECK_FLAGS                                                                 \
  (FASTACL_MATCH_PKT_LEN | FASTACL_MATCH_DSCP | FASTACL_MATCH_FRAGMENT)

typedef ip4_header_t fastacl_aclb_ip4_t __attribute__ ((aligned (1)));
typedef ip6_header_t fastacl_aclb_ip6_t __attribute__ ((aligned (1)));

typedef struct
{
  u32 order;
  fastacl_match_t match;
} fastacl_aclb_key_t;

typedef struct
{
  acl_plugin_methods_t methods;
  svm_queue_t *api_reply_q;
  u32 api_client;
  u16 add_replace_msg_id;
  u32 lc_index;
  u32 acl_index;
  u32 *ace_to_rule;
  u8 *ace_recheck;
  uword *rule_by_key;
  u8 inited;
  u8 bulk;
} fastacl_aclb_t;

typedef struct
{
  acl_rule_t *rules;
  u32 *ace_to_rule;
  u8 *ace_recheck;
} fastacl_aclb_build_t;

typedef struct
{
  fastacl_main_t *fsm;
  const fastacl_parsed_t *p;
  u8 exact;
} fastacl_aclb_check_ctx_t;

clib_error_t *fastacl_aclb_init (fastacl_main_t *fsm);
u32 fastacl_aclb_rule_find (fastacl_main_t *fsm, u32 order, const fastacl_match_t *match);
void fastacl_aclb_rule_added (fastacl_main_t *fsm, u32 rule_index);
void fastacl_aclb_rule_removed (fastacl_main_t *fsm, u32 order, const fastacl_match_t *match);
void fastacl_aclb_rules_cleared (fastacl_main_t *fsm);
void fastacl_aclb_bulk_begin (fastacl_main_t *fsm);
void fastacl_aclb_bulk_end (fastacl_main_t *fsm);
int fastacl_aclb_check (fastacl_aclb_check_ctx_t *c, u32 ace_index);

static_always_inline int
fastacl_aclb_fill_5tuple (const fastacl_parsed_t *p, fa_5tuple_t *t)
{
  u8 proto = p->pkt_proto;
  u16 need = 0;

  clib_memset (t, 0, sizeof (*t));
  if (p->is_ip6)
    {
      const fastacl_aclb_ip6_t *ip6 = (const fastacl_aclb_ip6_t *) p->ip0;
      t->ip6_addr[0] = ip6->src_address;
      t->ip6_addr[1] = ip6->dst_address;
    }
  else
    {
      const fastacl_aclb_ip4_t *ip4 = (const fastacl_aclb_ip4_t *) p->ip0;
      t->ip4_addr[0] = ip4->src_address;
      t->ip4_addr[1] = ip4->dst_address;
    }
  t->l4.proto = proto;
  t->pkt.is_ip6 = p->is_ip6;
  t->pkt.l4_valid = 1;
  if (p->pkt_frag_flags & FASTACL_FRAG_ISF)
    return 0;
  if (proto == IP_PROTOCOL_TCP || proto == IP_PROTOCOL_UDP)
    {
      need = proto == IP_PROTOCOL_TCP ? FASTACL_L4_TCP_FLAGS_BYTES : FASTACL_L4_PORTS_BYTES;
      t->l4.port[0] = p->l4_src_port;
      t->l4.port[1] = p->l4_dst_port;
      if (proto == IP_PROTOCOL_TCP && p->l4_bytes >= FASTACL_L4_TCP_FLAGS_BYTES)
	{
	  t->pkt.tcp_flags = ((tcp_header_t *) p->l4)->flags;
	  t->pkt.tcp_flags_valid = 1;
	}
    }
  else if (proto == IP_PROTOCOL_ICMP || proto == IP_PROTOCOL_ICMP6)
    {
      need = FASTACL_L4_ICMP_CODE_BYTES;
      if (p->l4_bytes >= need)
	{
	  t->l4.port[0] = ((icmp46_header_t *) p->l4)->type;
	  t->l4.port[1] = ((icmp46_header_t *) p->l4)->code;
	}
    }
  return p->l4_bytes >= need;
}

#endif /* __included_fastacl_aclb_h__ */
