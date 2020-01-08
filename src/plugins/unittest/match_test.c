/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vnet/match/match_set_dp.h>
#include <vnet/match/match_engine.h>

// this is included only so we can access the poools
#include <vnet/match/engines/classifier/match_classifier.h>

#include <vnet/ethernet/packet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/ip.h>

static int match_test_do_debug;

#define MATCH_TEST_I(_cond, _comment, _args...)                  \
({                                                               \
  int _evald = (_cond);                                          \
  if (!(_evald)) {                                               \
    vlib_cli_output(vm, "FAIL:%s:%d: " _comment "\n",            \
                    engine, __LINE__, ##_args);                  \
    res = 1;                                                     \
  } else {                                                       \
    if (match_test_do_debug)                                     \
      fformat(stderr, "PASS:%d: " _comment "\n",                 \
              __LINE__, ##_args);                                \
  }                                                              \
  res;                                                           \
})
#define MATCH_TEST(_cond, _comment, _args...)			\
{								\
  if (MATCH_TEST_I(_cond, _comment, ##_args)) {                 \
    ASSERT(0);                                                  \
    res = 1;                                                    \
  }								\
}

#define MATCH_TEST_HIT(_comment, _cond, _act, _exp,_args...)            \
{                                                                       \
  bool _matched = _cond;                                                \
  MATCH_TEST(_matched,                                                  \
             "hit; " _comment,                                          \
             _act, _exp, ##_args);                                      \
  MATCH_TEST(_act == _exp,                                              \
             "%llx != %llx; " _comment,                                 \
             _act, _exp, ##_args);                                      \
}

#define MATCH_TEST_MISS(_comment, _cond, _args...)                      \
{                                                                       \
  bool _matched = _cond;                                                \
  MATCH_TEST(!_matched, "miss; " _comment, ##_args);                    \
}

#define MATCH_PRINT(vm, _args...)                       \
{                                                       \
  vlib_cli_output(vm, ##_args);                         \
}

static void
eth_set (match_orientation_t mo,
	 ethernet_header_t * e, const mac_address_t * mac)
{
  clib_memcpy ((MATCH_SRC == mo ?
		e->src_address : e->dst_address), mac->bytes, 6);
}

static void
udp_set (match_orientation_t mo, udp_header_t * u, u16 port)
{
  if (MATCH_SRC == mo)
    u->src_port = port;
  else
    u->dst_port = port;
}

static void
ip6_set (match_orientation_t mo,
	 ip6_header_t * ip6, const match_ip_prefix_t * mip)
{
  ip6_address_t *a = (MATCH_SRC == mo ?
		      &ip6->src_address : &ip6->dst_address);

  a->as_u64[0] = ip_prefix_v6 (&mip->mip_ip).as_u64[0];
  a->as_u64[0] |= ~ip6_main.fib_masks[mip->mip_ip.len].as_u64[0];
  a->as_u64[1] = ip_prefix_v6 (&mip->mip_ip).as_u64[1];
  a->as_u64[1] |= ~ip6_main.fib_masks[mip->mip_ip.len].as_u64[1];
}

static void
ip6_seta (match_orientation_t mo,
	  ip6_header_t * ip6, const ip_address_t * ipa)
{
  ip6_address_t *a = (MATCH_SRC == mo ?
		      &ip6->src_address : &ip6->dst_address);

  *a = ip_addr_v6 (ipa);
}

static void
ip4_set (match_orientation_t mo,
	 ip4_header_t * ip4, const match_ip_prefix_t * mip)
{
  ip4_address_t *a = (MATCH_SRC == mo ?
		      &ip4->src_address : &ip4->dst_address);

  a->as_u32 = ip_prefix_v4 (&mip->mip_ip).as_u32;
  a->as_u32 |= ~ip4_main.fib_masks[mip->mip_ip.len];
}

static void
ip4_seta (match_orientation_t mo,
	  ip4_header_t * ip4, const ip_address_t * ipa)
{
  ip4_address_t *a = (MATCH_SRC == mo ?
		      &ip4->src_address : &ip4->dst_address);

  *a = ip_addr_v4 (ipa);
}

static void
arp_set (match_orientation_t mo,
	 ethernet_arp_header_t * arp,
	 const match_ip_prefix_t * mip, const mac_address_t * mac)
{
  u8 who = (MATCH_SRC == mo ? ARP_SENDER : ARP_TARGET);

  arp->ip4_over_ethernet[who].ip4.as_u32 = ip_prefix_v4 (&mip->mip_ip).as_u32;
  arp->ip4_over_ethernet[who].ip4.as_u32 |=
    ~ip4_main.fib_masks[mip->mip_ip.len];
  mac_address_copy (&arp->ip4_over_ethernet[who].mac, mac);
}

static void
match_test_engine_set (const char *engine, u32 priority)
{
  match_semantic_t msem;
  match_type_t mtype;
  u32 len;

  for (msem = 0; msem < MATCH_N_SEMANTICS; msem++)
    for (mtype = 0; mtype < MATCH_N_TYPES; mtype++)
      for (len = 0; len < MATCH_ENGINE_LEN_LOG2S; len++)
	match_engine_set_priority (engine, msem, mtype, len, priority);
}

#define FIRST_HEADER(_t, _n)                    \
({                                              \
  clib_memcpy(_t, &_n, sizeof(_n));             \
  (void*)_t;                                    \
})

#define PUSH_HEADER(_t, _n)                     \
({                                              \
  void * _p = _t + 1;                           \
  clib_memcpy(_p, &_n, sizeof(_n));             \
  _p;                                           \
})

const static match_port_range_t MATCH_PORT_RANGE_ANY = {
  .mpr_begin = 0,
  .mpr_end = 0xffff,
};

static int
match_test_mask_n_tuple_ip4 (vlib_main_t * vm, const char *engine)
{
  match_handle_t handle1, handle2;
  u8 *list_name, *set_name;
  match_result_t mres;
  match_set_app_t app;
  match_rule_t rule1;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  int res;
  f64 now;

  now = vlib_time_now (vm);
  mres = res = 0;
  match_test_engine_set (engine, 1);

  /*
   * start with a rule that does exact match on ip source only
   */
  /* *INDENT-OFF* */
  ip_prefix_t ipp_10_10_10_10_s_32 = {
    .addr = {
      .ip = {
        .ip4.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a),
      },
      .version = AF_IP4,
    },
    .len = 32,
  };
  /* *INDENT-ON* */
  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");

  memset (&rule1, 0, sizeof (rule1));
  rule1.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule1.mr_result = 0xdeadbeef1;
  match_ip_prefix_set (&rule1.mr_mask_n_tuple.mnt_src_ip,
		       &ipp_10_10_10_10_s_32);

  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule1);

  msi = match_set_create_and_lock (set_name,
				   MATCH_TYPE_MASK_N_TUPLE,
				   MATCH_BOTH, ETHERNET_TYPE_IP4, NULL);

  handle1 = match_set_list_add (msi, &list, 0);

  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);

  // a packet whose source address matches the rule
  b = clib_mem_alloc (sizeof (*b) + 1024);
  memset (b, 0, sizeof (*b));

  ethernet_header_t *e, eth = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4),
  };
  ip4_header_t *i, ip4 = {
    .ip_version_and_header_length = 0x45,
    .protocol = IP_PROTOCOL_UDP,
    .src_address = ip_prefix_v4 (&ipp_10_10_10_10_s_32),
  };
  udp_header_t *u, udp = {
    .src_port = 3,
  };
  void *h;

  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip4);
  u = PUSH_HEADER (i, udp);

  MATCH_TEST_HIT ("match hit src /32",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 0xdeadbeef1);

  // modify the packet so it does not match the rule
  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a01);
  MATCH_TEST_MISS ("match miss src /32",
		   match_match_one (vm, b, 0, sizeof (eth), &app, now,
				    &mres));

  /*
   * replace the list with one with 2 rules the second will match the packet
   * against a longer mask
   */
  match_rule_t rule2;

  /* *INDENT-OFF*/
  ip_prefix_t ipp_10_10_10_0_s_24 = {
    .addr = {
      .ip = {
        .ip4.as_u32 = clib_host_to_net_u32 (0x0a0a0a00),
      },
      .version = AF_IP4,
    },
    .len = 24,
  };
  /* *INDENT-ON*/
  memset (&rule2, 0, sizeof (rule2));
  rule2.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule2.mr_result = 0xdeadbeef2;
  match_ip_prefix_set (&rule2.mr_mask_n_tuple.mnt_src_ip,
		       &ipp_10_10_10_0_s_24);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule1);
  match_list_push_back (&list, &rule2);
  match_set_list_replace (msi, handle1, &list, 0);

  MATCH_TEST_HIT ("match hit src /24",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 0xdeadbeef2);

  // modify the packet so it misses both rules
  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0101);
  MATCH_TEST_MISS ("match miss src /24",
		   match_match_one (vm, b, 0, sizeof (eth), &app, now,
				    &mres));

  /*
   * replace the list with one with 3 rules the second will match the packet
   * against a longer mask
   */
  match_rule_t rule3;

  /* *INDENT-OFF* */
  ip_prefix_t ipp_10_0_0_0_s_10 = {
    .addr = {
      .ip = {
        .ip4.as_u32 = clib_host_to_net_u32 (0x0a000000),
      },
      .version = AF_IP4,
    },
    .len = 10,
  };
  /* *INDENT-ON* */
  memset (&rule3, 0, sizeof (rule2));
  rule3.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule3.mr_result = 0xddeeff;
  match_ip_prefix_set (&rule3.mr_mask_n_tuple.mnt_src_ip, &ipp_10_0_0_0_s_10);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule1);
  match_list_push_back (&list, &rule2);
  match_list_push_back (&list, &rule3);
  match_set_list_replace (msi, handle1, &list, 0);


  MATCH_TEST_HIT ("match hit src /10",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 0xddeeff);

  // modify the packet so it misses all rules
  i->src_address.as_u32 = clib_host_to_net_u32 (0x01010101);
  MATCH_TEST_MISS ("match miss src /10",
		   match_match_one (vm, b, 0, sizeof (eth), &app, now,
				    &mres));

  /*
   * Add a rule that will match both src and dst IP
   */
  match_rule_t rule4;

  memset (&rule4, 0, sizeof (rule3));
  rule4.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule4.mr_result = 4;
  match_ip_prefix_set (&rule4.mr_mask_n_tuple.mnt_src_ip,
		       &ipp_10_10_10_0_s_24);
  match_ip_prefix_set (&rule4.mr_mask_n_tuple.mnt_dst_ip,
		       &ipp_10_10_10_0_s_24);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule4);
  match_list_push_back (&list, &rule1);
  match_list_push_back (&list, &rule2);
  match_list_push_back (&list, &rule3);
  match_set_list_replace (msi, handle1, &list, 0);

  // set packet to match on both src and dst
  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a01);
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a01);
  MATCH_TEST_HIT ("match hit both src,dst /32",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 4);

  // modify the packet so it only hits on src
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x01010101);
  MATCH_TEST_HIT ("match hit src src,dst /32",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 0xdeadbeef2);

  // modify the packet so it misses all rules
  i->src_address.as_u32 = clib_host_to_net_u32 (0x01010101);
  MATCH_TEST_MISS ("match miss src,dst /32",
		   match_match_one (vm, b, 0, sizeof (eth), &app, now,
				    &mres));

  /*
   * A rule that matches all UDP traffic.
   */
  ip_prefix_t ipp_0_s_0 = { };
  match_rule_t rule5;

  memset (&rule5, 0, sizeof (rule3));
  rule5.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule5.mr_result = 5;
  rule5.mr_mask_n_tuple.mnt_ip_proto = IP_PROTOCOL_UDP;
  rule5.mr_mask_n_tuple.mnt_src_port = MATCH_PORT_RANGE_ANY;
  rule5.mr_mask_n_tuple.mnt_dst_port = MATCH_PORT_RANGE_ANY;
  match_ip_prefix_set (&rule5.mr_mask_n_tuple.mnt_src_ip, &ipp_0_s_0);
  match_ip_prefix_set (&rule5.mr_mask_n_tuple.mnt_dst_ip, &ipp_0_s_0);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule5);
  match_list_push_back (&list, &rule4);
  match_set_list_replace (msi, handle1, &list, 0);

  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);

  MATCH_TEST_HIT ("match hit udp only",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 5);

  /*
   * A rule that matches one udp port, that is better than one that
   * matches on any
   */
  match_rule_t rule6;

  memset (&rule6, 0, sizeof (rule3));
  rule6.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule6.mr_result = 6;
  rule6.mr_mask_n_tuple.mnt_ip_proto = IP_PROTOCOL_UDP;
  rule6.mr_mask_n_tuple.mnt_src_port.mpr_begin = 2000;
  rule6.mr_mask_n_tuple.mnt_src_port.mpr_end = 2000;
  rule6.mr_mask_n_tuple.mnt_dst_port = MATCH_PORT_RANGE_ANY;
  match_ip_prefix_set (&rule6.mr_mask_n_tuple.mnt_src_ip, &ipp_0_s_0);
  match_ip_prefix_set (&rule6.mr_mask_n_tuple.mnt_dst_ip, &ipp_0_s_0);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule6);
  match_list_push_back (&list, &rule5);
  match_list_push_back (&list, &rule4);
  match_set_list_replace (msi, handle1, &list, 0);

  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);
  u->src_port = clib_host_to_net_u16 (2000);
  MATCH_TEST_HIT ("match hit udp specifc",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 6);

  u->src_port = 2;
  MATCH_TEST_HIT ("match hit udp specifc, any",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 5);

  /*
   * A rule that matches a range of UDP ports.
   *  specific < range < any
   */
  match_rule_t rule7;

  memset (&rule7, 0, sizeof (rule3));
  rule7.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule7.mr_result = 7;
  rule7.mr_mask_n_tuple.mnt_ip_proto = IP_PROTOCOL_UDP;
  rule7.mr_mask_n_tuple.mnt_src_port.mpr_begin = 1000;
  rule7.mr_mask_n_tuple.mnt_src_port.mpr_end = 40000;
  rule7.mr_mask_n_tuple.mnt_dst_port = MATCH_PORT_RANGE_ANY;
  match_ip_prefix_set (&rule7.mr_mask_n_tuple.mnt_src_ip, &ipp_0_s_0);
  match_ip_prefix_set (&rule7.mr_mask_n_tuple.mnt_dst_ip, &ipp_0_s_0);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule6);
  match_list_push_back (&list, &rule7);
  match_list_push_back (&list, &rule5);
  match_list_push_back (&list, &rule4);
  match_set_list_replace (msi, handle1, &list, 0);

  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);

  u->src_port = clib_host_to_net_u16 (2000);
  MATCH_TEST_HIT ("match hit udp specifc w/ range",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 6);

  u->src_port = clib_host_to_net_u16 (22222);
  MATCH_TEST_HIT ("match hit udp range",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 7);

  u->src_port = 2;
  MATCH_TEST_HIT ("match hit udp specifc, any",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 5);

  /*
   * A rule that matches a range of TCP ports.
   *  we'll put this is a separate list
   */
  match_rule_t rule8;

  memset (&rule8, 0, sizeof (rule3));
  rule8.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule8.mr_result = 8;
  rule8.mr_mask_n_tuple.mnt_ip_proto = IP_PROTOCOL_TCP;
  rule8.mr_mask_n_tuple.mnt_src_port.mpr_begin = 1000;
  rule8.mr_mask_n_tuple.mnt_src_port.mpr_end = 40000;
  rule8.mr_mask_n_tuple.mnt_dst_port = MATCH_PORT_RANGE_ANY;
  match_ip_prefix_set (&rule8.mr_mask_n_tuple.mnt_src_ip, &ipp_0_s_0);
  match_ip_prefix_set (&rule8.mr_mask_n_tuple.mnt_dst_ip, &ipp_0_s_0);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule8);
  handle2 = match_set_list_add (msi, &list, 1);

  tcp_header_t *t = (tcp_header_t *) u;

  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0b0b);
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x0a0a0b0b);
  i->protocol = IP_PROTOCOL_TCP;
  t->src_port = clib_host_to_net_u16 (2000);
  MATCH_TEST_HIT ("match hit tcp specifc w/ range",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 8);

  i->protocol = IP_PROTOCOL_UDP;
  t->src_port = clib_host_to_net_u16 (2000);
  MATCH_TEST_HIT ("match hit udp specifc w/ range",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 6);

  /*
   * A rule that matches a range of TCP ports and flags
   */
  match_rule_t rule9;

  memset (&rule9, 0, sizeof (rule3));
  rule9.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule9.mr_result = 9;
  rule9.mr_mask_n_tuple.mnt_ip_proto = IP_PROTOCOL_TCP;
  rule9.mr_mask_n_tuple.mnt_src_port.mpr_begin = 1000;
  rule9.mr_mask_n_tuple.mnt_src_port.mpr_end = 40000;
  rule9.mr_mask_n_tuple.mnt_dst_port = MATCH_PORT_RANGE_ANY;
  rule9.mr_mask_n_tuple.mnt_tcp.mtf_flags = 0x4;
  rule9.mr_mask_n_tuple.mnt_tcp.mtf_mask = 0x7;
  match_ip_prefix_set (&rule9.mr_mask_n_tuple.mnt_src_ip, &ipp_0_s_0);
  match_ip_prefix_set (&rule9.mr_mask_n_tuple.mnt_dst_ip, &ipp_0_s_0);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule9);
  match_list_push_back (&list, &rule8);
  match_set_list_replace (msi, handle2, &list, 1);

  i->protocol = IP_PROTOCOL_TCP;
  t->src_port = clib_host_to_net_u16 (2000);

  // flags exact match
  t->flags = 0x4;
  MATCH_TEST_HIT ("match hit tcp specifc flags",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 9);

  // no flags => miss
  t->flags = 0;
  MATCH_TEST_HIT ("match miss tcp flags",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 8);

  // extra flags set => miss
  t->flags = 0x7;
  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres);
  MATCH_TEST_HIT ("match miss tcp flags",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 8);

  // flags set not in mask => hit
  t->flags = 0xc;
  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres);
  MATCH_TEST_HIT ("match hit tcp specifc flags",
		  match_match_one (vm, b, 0, sizeof (eth), &app, now, &mres),
		  mres, 9);

  /*
   * cleanup
   */
  match_set_unapply (msi, &app);
  match_set_list_del (msi, &handle1);
  match_set_list_del (msi, &handle2);
  match_set_unlock (&msi);

  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);
  clib_mem_free (b);

  return (res);
}

static int
match_test_mask_n_tuple_ip6 (vlib_main_t * vm, const char *engine)
{
  match_handle_t handle[10];
  u8 *list_name, *set_name;
  match_set_app_t app;
  match_result_t mres;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  u64 j, k;
  int res;
  f64 now;

  now = vlib_time_now (vm);
#define LIST_SIZE 0x4
  res = 0;

  match_test_engine_set (engine, 1);

  /*
   * start with a rule that does exact match on ip source only
   */
  /* *INDENT-OFF* */
  ip_prefix_t ipp = {
    .addr = {
      .ip = {
        .ip6 = {
          .as_u64[0] = clib_host_to_net_u64 (0xfd01000000000000),
        },
      },
      .version = AF_IP6,
    },
    .len = 128,
  };
  /* *INDENT-ON* */

  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");

  // a packet Eth->IP6->udp->garbage...
  b = clib_mem_alloc (sizeof (*b) + 1024);
  memset (b, 0, sizeof (*b) + 1024);

  ip6_header_t *i, ip6 = {
    .ip_version_traffic_class_and_flow_label =
      clib_host_to_net_u32 (0x6 << 28),
    .protocol = IP_PROTOCOL_ICMP6,
    .src_address = ip_prefix_v6 (&ipp),
    .dst_address = ip_prefix_v6 (&ipp),
  };
  icmp46_header_t *p, icmp = {
  };
  void *h;

  h = vlib_buffer_get_current (b);
  i = FIRST_HEADER (h, ip6);
  p = PUSH_HEADER (i, icmp);

  msi = match_set_create_and_lock (set_name,
				   MATCH_TYPE_MASK_N_TUPLE,
				   MATCH_BOTH, ETHERNET_TYPE_IP6, NULL);

  // add lists, each with successively shorter mask prefixes upto /64
  for (k = 0; k < 8; k++)
    {
      match_list_init (&list, list_name, 0);

      for (j = 0; j < LIST_SIZE; j++)
	{
	  match_rule_t rule1;

	  memset (&rule1, 0, sizeof (rule1));
	  ipp.addr.ip.ip6.as_u64[1] =
	    clib_host_to_net_u64 ((j + 1) << (k * 8));
	  ipp.len = 128 - (k * 8);

	  rule1.mr_type = MATCH_TYPE_MASK_N_TUPLE;
	  rule1.mr_result = k * j;
	  match_ip_prefix_set (&rule1.mr_mask_n_tuple.mnt_src_ip, &ipp);
	  match_ip_prefix_set (&rule1.mr_mask_n_tuple.mnt_dst_ip, &ipp);

	  match_list_push_back (&list, &rule1);
	}

      handle[k] = match_set_list_add (msi, &list, k);
    }

  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);

  // match each rule in turn
  for (k = 0; k < 8; k++)
    {
      for (j = 0; j < LIST_SIZE; j++)
	{
	  i->src_address.as_u64[1] =
	    i->dst_address.as_u64[1] =
	    clib_host_to_net_u64 ((j + 1) << (k * 8));


	  MATCH_TEST_HIT ("match hit src /128",
			  match_match_one (vm, b, 0, 0, &app, now, &mres),
			  mres, k * j);
	}
    }

  // modify the packet so it does not match the rule
  i->src_address.as_u64[0] = clib_host_to_net_u64 (0xfd02000000000000);
  MATCH_TEST_MISS ("match miss src /128",
		   match_match_one (vm, b, 0, 0, &app, now, &mres));

  // add some /64s
  match_list_init (&list, list_name, 0);

  for (j = 0; j < LIST_SIZE; j++)
    {
      match_rule_t rule1;

      memset (&rule1, 0, sizeof (rule1));
      ipp.addr.ip.ip6.as_u64[0] =
	clib_host_to_net_u64 (0xfd02000000000000 + j + 1);
      ipp.addr.ip.ip6.as_u64[1] = 0;
      ipp.len = 64;

      rule1.mr_type = MATCH_TYPE_MASK_N_TUPLE;
      rule1.mr_result = k * j;
      match_ip_prefix_set (&rule1.mr_mask_n_tuple.mnt_src_ip, &ipp);
      match_ip_prefix_set (&rule1.mr_mask_n_tuple.mnt_dst_ip, &ipp);

      match_list_push_back (&list, &rule1);
    }

  handle[8] = match_set_list_add (msi, &list, k);

  // match each rule in turn
  // we do this 'a lot of times' to test we're not leaking in the DP
  int ii;

  for (ii = 0; ii < 0xfffff; ii++)
    {
      for (j = 0; j < LIST_SIZE; j++)
	{
	  i->src_address.as_u64[1] = i->dst_address.as_u64[1] = 0;
	  i->src_address.as_u64[0] =
	    i->dst_address.as_u64[0] =
	    clib_host_to_net_u64 (0xfd02000000000000 + j + 1);

	  MATCH_TEST_HIT ("match hit src /64",
			  match_match_one (vm, b, 0, 0, &app, now, &mres),
			  mres, k * j);
	}
    }

  /*
   * now some rules with ICMP matches
   */
  match_rule_t rule_any, rule_type, rule_type_code;

  memset (&rule_any, 0, sizeof (rule_any));
  ipp.addr.ip.ip6.as_u64[0] = clib_host_to_net_u64 (0xfd03000000000000);
  ipp.addr.ip.ip6.as_u64[1] = 0;
  ipp.len = 64;

  rule_any.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule_any.mr_result = 0xaaaa;
  rule_any.mr_mask_n_tuple.mnt_ip_proto = IP_PROTOCOL_ICMP6;
  match_ip_prefix_set (&rule_any.mr_mask_n_tuple.mnt_src_ip, &ipp);
  match_ip_prefix_set (&rule_any.mr_mask_n_tuple.mnt_dst_ip, &ipp);
  rule_any.mr_mask_n_tuple.mnt_icmp_type.mitr_begin = 0;
  rule_any.mr_mask_n_tuple.mnt_icmp_type.mitr_end = 0xff;
  rule_any.mr_mask_n_tuple.mnt_icmp_code.micr_begin = 0;
  rule_any.mr_mask_n_tuple.mnt_icmp_code.micr_end = 0xff;

  clib_memcpy (&rule_type, &rule_any, sizeof (rule_type));
  clib_memcpy (&rule_type_code, &rule_any, sizeof (rule_type_code));

  rule_type.mr_result = 0xaaab;
  rule_type_code.mr_result = 0xaaac;

  rule_type.mr_mask_n_tuple.mnt_icmp_type.mitr_begin =
    rule_type.mr_mask_n_tuple.mnt_icmp_type.mitr_end = 1;
  rule_type_code.mr_mask_n_tuple.mnt_icmp_type.mitr_begin =
    rule_type_code.mr_mask_n_tuple.mnt_icmp_type.mitr_end = 1;
  rule_type_code.mr_mask_n_tuple.mnt_icmp_code.micr_begin =
    rule_type_code.mr_mask_n_tuple.mnt_icmp_code.micr_end = 3;

  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule_type_code);
  match_list_push_back (&list, &rule_type);
  match_list_push_back (&list, &rule_any);
  handle[9] = match_set_list_add (msi, &list, 9);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  i->src_address.as_u64[1] = i->dst_address.as_u64[1] = 0;
  i->src_address.as_u64[0] =
    i->dst_address.as_u64[0] = clib_host_to_net_u64 (0xfd03000000000000);

  // exact match type and code
  p->type = 1;
  p->code = 3;
  MATCH_TEST_HIT ("match hit ICMP exact type&code",
		  match_match_one (vm, b, 0, 0, &app, now, &mres),
		  mres, 0xaaac);

  // exact match type and any code
  p->type = 1;
  p->code = 4;
  MATCH_TEST_HIT ("match hit ICMP exact type, anycode",
		  match_match_one (vm, b, 0, 0, &app, now, &mres),
		  mres, 0xaaab);

  // any match type and any code
  p->type = 4;
  p->code = 4;
  MATCH_TEST_HIT ("match hit ICMP any type&code",
		  match_match_one (vm, b, 0, 0, &app, now, &mres),
		  mres, 0xaaaa);

  // remove all the other list and run the ICMP packet tests again
  for (k = 0; k < 9; k++)
    match_set_list_del (msi, &handle[k]);

  // this time add an IPv6 Fragmentation header
  ip6_frag_hdr_t *f, frag = {
    .next_hdr = IP_PROTOCOL_ICMP6,
  };
  h = vlib_buffer_get_current (b);
  i = FIRST_HEADER (h, ip6);
  f = PUSH_HEADER (i, frag);
  p = PUSH_HEADER (f, icmp);

  i->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
  i->src_address.as_u64[1] = i->dst_address.as_u64[1] = 0;
  i->src_address.as_u64[0] =
    i->dst_address.as_u64[0] = clib_host_to_net_u64 (0xfd03000000000000);

  // exact match type and code
  p->type = 1;
  p->code = 3;
  MATCH_TEST_HIT ("match hit ICMP exact type&code",
		  match_match_one (vm, b, 0, 0, &app, now, &mres),
		  mres, 0xaaac);

  // exact match type and any code
  p->type = 1;
  p->code = 4;
  MATCH_TEST_HIT ("match hit ICMP exact type, anycode",
		  match_match_one (vm, b, 0, 0, &app, now, &mres),
		  mres, 0xaaab);

  // any match type and any code
  p->type = 4;
  p->code = 4;
  MATCH_TEST_HIT ("match hit ICMP any type&code",
		  match_match_one (vm, b, 0, 0, &app, now, &mres),
		  mres, 0xaaaa);

  match_set_list_del (msi, &handle[9]);

  /*
   * cleanup
   */
  match_set_unapply (msi, &app);
  match_set_unlock (&msi);

  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);
  clib_mem_free (b);

  return (res);
}

static match_rule_t *
match_test_mask_ip_mac_mk_v4 (match_list_t * list,
			      match_orientation_t mo, ethernet_type_t etype)
{
  match_rule_t *rule, *rules = NULL;
  i32 rr, ip_len, mac_len;

  for (ip_len = 32; ip_len > 0; ip_len -= 4)
    {
      for (mac_len = 0; mac_len < 6; mac_len++)
	{
	  for (rr = 1; rr < 16; rr++)
	    {
              /* *INDENT-OFF* */
	      ip_prefix_t ipp = {
		.addr = {
                  .version = AF_IP4,
                  .ip.ip4 = {
                    .as_u32 =
                    clib_host_to_net_u32 (0x01020304),
                  },
                },
		.len = ip_len,
	      };
	      match_mac_mask_t mmm = {
		.mmm_mac = {
                  .bytes = {
                    rr, 0x11, 0x22, 0x33, 0x44, 0x55,
                  },
                },
		.mmm_mask = {
                  .bytes = {
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                  },
                },
	      };
	      int m;
              /* *INDENT-ON* */
	      ipp.addr.ip.ip4.as_u8[0] = rr << 4;

	      for (m = 0; m < mac_len; m++)
		{
		  mmm.mmm_mask.bytes[5 - m] = 0;
		  mmm.mmm_mac.bytes[5 - m] = 0;
		}
	      vec_add2 (rules, rule, 1);

	      rule->mr_proto = etype;
	      rule->mr_orientation = mo;
	      rule->mr_type = MATCH_TYPE_MASK_IP_MAC;
	      rule->mr_result = rule - rules;
	      rule->mr_mask_ip_mac.mmim_mac = mmm;
	      match_ip_prefix_set (&rule->mr_mask_ip_mac.mmim_ip, &ipp);

	      match_list_push_back (list, rule);
	    }
	}
    }
  return (rules);
}

static match_rule_t *
match_test_mask_ip_mk_v4 (match_list_t * list,
			  match_orientation_t mo, ethernet_type_t etype)
{
  match_rule_t *rule, *rules = NULL;
  i32 rr, ip_len;

  for (ip_len = 32; ip_len > 0; ip_len -= 4)
    {
      for (rr = 0; rr < 16; rr++)
	{
          /* *INDENT-OFF* */
          ip_prefix_t ipp = {
            .addr = {
              .version = AF_IP4,
              .ip.ip4 = {
                .as_u32 = clib_host_to_net_u32 (0x01020304),
              },
            },
            .len = ip_len,
          };
          /* *INDENT-ON* */
	  ipp.addr.ip.ip4.as_u8[0] = rr << 4;

	  vec_add2 (rules, rule, 1);

	  rule->mr_proto = etype;
	  rule->mr_orientation = mo;
	  rule->mr_type = MATCH_TYPE_MASK_IP;
	  rule->mr_result = rule - rules;
	  match_ip_prefix_set (&rule->mr_mask_ip, &ipp);

	  match_list_push_back (list, rule);
	}
    }
  return (rules);
}

static match_rule_t *
match_test_exact_ip_mk_v4 (match_list_t * list,
			   match_orientation_t mo,
			   ethernet_type_t etype, u16 begin)
{
  match_rule_t *rule, *rules = NULL;
  i32 rr;

  for (rr = begin; rr < begin + 16; rr++)
    {
      /* *INDENT-OFF* */
      ip_address_t ipa = {
        .version = AF_IP4,
        .ip.ip4 = {
          .as_u32 = clib_host_to_net_u32 (0x01020304),
        },
      };
      /* *INDENT-ON* */
      ipa.ip.ip4.as_u16[0] = rr;

      vec_add2 (rules, rule, 1);

      rule->mr_proto = etype;
      rule->mr_orientation = mo;
      rule->mr_type = MATCH_TYPE_EXACT_IP;
      rule->mr_result = rule - rules;
      ip_address_copy (&rule->mr_exact_ip, &ipa);

      match_list_push_back (list, rule);
    }
  return (rules);
}

static match_rule_t *
match_test_exact_ip_l4_mk_v4 (match_list_t * list,
			      match_orientation_t mo, ethernet_type_t etype)
{
  match_rule_t *rule, *rules = NULL;
  u8 itype, icode;
  i32 rr;

  for (rr = 0; rr < 16; rr++)
    {
      for (itype = 0; itype <= 8; itype++)
	{
	  for (icode = 0; icode <= 8; icode++)
	    {
              /* *INDENT-OFF* */
              ip_address_t ipa = {
                .version = AF_IP4,
                .ip.ip4 = {
                  .as_u32 = clib_host_to_net_u32 (0x01020304),
                },
              };
              /* *INDENT-ON* */
	      ipa.ip.ip4.as_u8[0] = rr << 4;

	      vec_add2 (rules, rule, 1);

	      rule->mr_proto = etype;
	      rule->mr_orientation = mo;
	      rule->mr_type = MATCH_TYPE_EXACT_IP_L4;
	      rule->mr_result = rule - rules;
	      ip_address_copy (&rule->mr_exact_ip_l4.meil_ip, &ipa);
	      rule->mr_exact_ip_l4.meil_proto = IP_PROTOCOL_ICMP;

	      rule->mr_exact_ip_l4.meil_l4.ml_icmp.mi_type = itype;
	      rule->mr_exact_ip_l4.meil_l4.ml_icmp.mi_code = icode;

	      match_list_push_back (list, rule);
	    }
	}
    }
  return (rules);
}

static match_rule_t *
match_test_mask_ip_mac_mk_v6 (match_list_t * list, match_orientation_t mo)
{
  match_rule_t *rule, *rules = NULL;
  i32 rr, ip_len, mac_len;

  for (ip_len = 128; ip_len > 0; ip_len -= 16)
    {
      for (mac_len = 0; mac_len < 6; mac_len++)
	{
	  for (rr = 0; rr < 16; rr++)
	    {
              /* *INDENT-OFF* */
	      ip_prefix_t ipp = {
		.addr = {
                  .version = AF_IP6,
                  .ip.ip6 = {
                    .as_u64[0] = clib_host_to_net_u64 (0x1112131415161718),
                    .as_u64[1] = clib_host_to_net_u64 (0x2122232425262728),
                  },
                },
		.len = ip_len,
	      };
	      match_mac_mask_t mmm = {
		.mmm_mac = {
                  .bytes = {
                    rr, 0x11, 0x22, 0x33, 0x44, 0x55,
                  },
                },
		.mmm_mask = {
                  .bytes = {
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                  },
		},
	      };
	      int m;
              /* *INDENT-ON* */

	      ipp.addr.ip.ip6.as_u8[0] = rr;

	      for (m = 0; m < mac_len; m++)
		{
		  mmm.mmm_mask.bytes[5 - m] = 0;
		  mmm.mmm_mac.bytes[5 - m] = 0;
		}

	      vec_add2 (rules, rule, 1);

	      rule->mr_proto = ETHERNET_TYPE_IP6;
	      rule->mr_orientation = mo;
	      rule->mr_type = MATCH_TYPE_MASK_IP_MAC;
	      rule->mr_mask_ip_mac.mmim_mac = mmm;
	      rule->mr_result = rule - rules;
	      match_ip_prefix_set (&rule->mr_mask_ip_mac.mmim_ip, &ipp);

	      match_list_push_back (list, rule);
	    }
	}
    }
  return (rules);
}

static match_rule_t *
match_test_mask_ip_mk_v6 (match_list_t * list, match_orientation_t mo)
{
  match_rule_t *rule, *rules = NULL;
  i32 rr, ip_len;

  for (ip_len = 128; ip_len > 0; ip_len -= 16)
    {
      for (rr = 0; rr < 16; rr++)
	{
          /* *INDENT-OFF* */
          ip_prefix_t ipp = {
            .addr = {
              .version = AF_IP6,
              .ip.ip6 = {
                .as_u64[0] = clib_host_to_net_u64 (0x1112131415161718),
                .as_u64[1] = clib_host_to_net_u64 (0x2122232425262728),
              },
            },
            .len = ip_len,
          };
          /* *INDENT-ON* */

	  ipp.addr.ip.ip6.as_u8[0] = rr;

	  vec_add2 (rules, rule, 1);

	  rule->mr_proto = ETHERNET_TYPE_IP6;
	  rule->mr_orientation = mo;
	  rule->mr_type = MATCH_TYPE_MASK_IP;
	  rule->mr_result = rule - rules;
	  match_ip_prefix_set (&rule->mr_mask_ip, &ipp);

	  match_list_push_back (list, rule);
	}
    }
  return (rules);
}

static match_rule_t *
match_test_exact_ip_mk_v6 (match_list_t * list, match_orientation_t mo)
{
  match_rule_t *rule, *rules = NULL;
  i32 rr;

  for (rr = 0; rr < 16; rr++)
    {
      /* *INDENT-OFF* */
      ip_address_t ipa = {
        .version = AF_IP6,
        .ip.ip6 = {
          .as_u64[0] = clib_host_to_net_u64 (0x1112131415161718),
          .as_u64[1] = clib_host_to_net_u64 (0x2122232425262728),
        },
      };
      /* *INDENT-ON* */

      ipa.ip.ip6.as_u8[0] = rr;

      vec_add2 (rules, rule, 1);

      rule->mr_proto = ETHERNET_TYPE_IP6;
      rule->mr_orientation = mo;
      rule->mr_type = MATCH_TYPE_EXACT_IP;
      rule->mr_result = rule - rules;
      ip_address_copy (&rule->mr_exact_ip, &ipa);

      match_list_push_back (list, rule);
    }
  return (rules);
}

static match_rule_t *
match_test_exact_ip_l4_mk_v6 (match_list_t * list, match_orientation_t mo)
{
  match_rule_t *rule, *rules = NULL;
  i32 rr, port;

  for (rr = 0; rr < 16; rr++)
    {
      for (port = 1024; port < 2048; port++)
	{
          /* *INDENT-OFF* */
          ip_address_t ipa = {
            .version = AF_IP6,
            .ip.ip6 = {
              .as_u64[0] = clib_host_to_net_u64 (0x1112131415161718),
              .as_u64[1] = clib_host_to_net_u64 (0x2122232425262728),
            },
          };
          /* *INDENT-ON* */

	  ipa.ip.ip6.as_u8[0] = rr;

	  vec_add2 (rules, rule, 1);

	  rule->mr_proto = ETHERNET_TYPE_IP6;
	  rule->mr_orientation = mo;
	  rule->mr_type = MATCH_TYPE_EXACT_IP;
	  rule->mr_result = rule - rules;
	  ip_address_copy (&rule->mr_exact_ip_l4.meil_ip, &ipa);
	  rule->mr_exact_ip_l4.meil_proto = IP_PROTOCOL_UDP;
	  rule->mr_exact_ip_l4.meil_l4.ml_port = clib_host_to_net_u16 (port);

	  match_list_push_back (list, rule);
	}
    }
  return (rules);
}

static int
match_test_mask_ip4_mac (vlib_main_t * vm,
			 match_orientation_t mo, const char *engine)
{
  u8 *list_name, *set_name;
  match_handle_t handle1;
  match_result_t mres;
  match_set_app_t app;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  int res;
  f64 now;

  now = vlib_time_now (vm);
  res = 0;

  match_test_engine_set (engine, 1);

  // a packet whose source address matches the rule
  b = clib_mem_alloc (sizeof (*b) + 1024);
  memset (b, 0, sizeof (*b));

  /* *INDENT-OFF* */
  ethernet_header_t *e, eth = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4),
    .src_address = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    },
  };
  ip4_header_t *i, ip4 = {
    .ip_version_and_header_length = 0x45,
    .protocol = IP_PROTOCOL_UDP,
  };
  udp_header_t udp = {
    .src_port = 3,
  };
  void *h;
  /* *INDENT-ON* */

  /*
   * start with a rule that does exact match on ip source only
   */
  match_rule_t *rules, *rule;

  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");
  match_list_init (&list, list_name, 0);

  rules = match_test_mask_ip_mac_mk_v4 (&list, mo, ETHERNET_TYPE_IP4);
  msi = match_set_create_and_lock (set_name, MATCH_TYPE_MASK_IP_MAC,
				   mo, ETHERNET_TYPE_IP4, NULL);
  handle1 = match_set_list_add (msi, &list, 0);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);

  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip4);
  PUSH_HEADER (i, udp);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  vec_foreach (rule, rules)
  {
    ip4_set (mo, i, &rule->mr_mask_ip_mac.mmim_ip);
    eth_set (mo, e, &rule->mr_mask_ip_mac.mmim_mac.mmm_mac);

    MATCH_TEST_HIT ("match mask-src-ip-mac hit /32",
		    match_match_one (vm, b, 0, sizeof (eth), &app, now,
				     &mres), mres, rule - rules);
  }

  // modify the packet so it does not match any rules
  if (MATCH_SRC == mo)
    i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a01);
  else
    i->dst_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a01);
  MATCH_TEST_MISS ("match mask-src-ip-mac miss /32",
		   match_match_one (vm, b, 0, sizeof (eth), &app, now,
				    &mres));

  /*
   * redo the v4 rules with application at v4
   */
  match_set_unapply (msi, &app);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);

  h = vlib_buffer_get_current (b);
  eth.type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip4);
  PUSH_HEADER (i, udp);
  b->current_data = sizeof (*e);

  vec_foreach (rule, rules)
  {
    ip4_set (mo, i, &rule->mr_mask_ip_mac.mmim_ip);
    eth_set (mo, e, &rule->mr_mask_ip_mac.mmim_mac.mmm_mac);

    MATCH_TEST_HIT ("match mask-src-ip-mac hit /32",
		    match_match_one (vm, b, -(i16) sizeof (eth), 0, &app, now,
				     &mres), mres, rule - rules);
  }

  match_set_list_del (msi, &handle1);
  match_set_unapply (msi, &app);
  match_set_unlock (&msi);

  /*
   * redo the v4 rules with application for ARP packets at etherent
   */
  msi = match_set_create_and_lock (set_name,
				   MATCH_TYPE_MASK_IP_MAC,
				   mo, ETHERNET_TYPE_ARP, NULL);
  vec_reset_length (rules);
  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  rules = match_test_mask_ip_mac_mk_v4 (&list, mo, ETHERNET_TYPE_ARP);
  handle1 = match_set_list_add (msi, &list, 0);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);
  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  ethernet_arp_header_t *a, arph = {
  };
  b->current_data = 0;
  h = vlib_buffer_get_current (b);
  eth.type = clib_host_to_net_u16 (ETHERNET_TYPE_ARP);
  e = FIRST_HEADER (h, eth);
  a = PUSH_HEADER (e, arph);

  vec_foreach (rule, rules)
  {
    arp_set (mo, a, &rule->mr_mask_ip_mac.mmim_ip,
	     &rule->mr_mask_ip_mac.mmim_mac.mmm_mac);
    eth_set (mo, e, &rule->mr_mask_ip_mac.mmim_mac.mmm_mac);


    MATCH_TEST_HIT ("match mask-src-ip-mac hit /32 arp",
		    match_match_one (vm, b, 0, sizeof (eth), &app, now,
				     &mres), mres, rule - rules);
  }

  match_set_list_del (msi, &handle1);
  match_set_unapply (msi, &app);

  match_set_unlock (&msi);
  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);
  vec_free (rules);
  clib_mem_free (b);

  return (res);
}

static int
match_test_mask_ip6_mac (vlib_main_t * vm,
			 match_orientation_t mo, const char *engine)
{
  u8 *list_name, *set_name;
  match_handle_t handle1;
  match_result_t mres;
  match_set_app_t app;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  int res;
  f64 now;

  now = vlib_time_now (vm);
  res = 0;

  match_test_engine_set (engine, 1);

  // a packet whose source address matches the rule
  b = clib_mem_alloc (sizeof (*b) + 1024);
  memset (b, 0, sizeof (*b) + 1024);

  /* *INDENT-OFF* */
  mac_address_t mac = {
    .bytes = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    },
  };
  ethernet_header_t *e, eth = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP6),
  };
  ip6_header_t *i, ip6 = {
    .ip_version_traffic_class_and_flow_label =
      clib_host_to_net_u32 (0x6 << 28),
    .protocol = IP_PROTOCOL_UDP,
  };
  udp_header_t *u, udp = {
  };
  void *h;
  /* *INDENT-ON* */

  match_rule_t *rules, *rule;

  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");
  match_list_init (&list, list_name, 0);

  rules = match_test_mask_ip_mac_mk_v6 (&list, mo);
  msi = match_set_create_and_lock (set_name,
				   MATCH_TYPE_MASK_IP_MAC,
				   mo, ETHERNET_TYPE_IP6, NULL);
  handle1 = match_set_list_add (msi, &list, 0);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip6);
  u = PUSH_HEADER (i, udp);
  eth_set (mo, e, &mac);
  udp_set (mo, u, 3);

  vec_foreach (rule, rules)
  {
    ip6_set (mo, i, &rule->mr_mask_ip_mac.mmim_ip);
    eth_set (mo, e, &rule->mr_mask_ip_mac.mmim_mac.mmm_mac);

    MATCH_TEST_HIT ("match mask-src-ip-mac hit src /128",
		    match_match_one (vm, b, 0, sizeof (eth), &app, now,
				     &mres), mres, rule - rules);
  }

  /*
   * redo ipv6 with application at v6 with 1 tag
   */
  match_set_unapply (msi, &app);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_1_TAG, &app);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  ethernet_vlan_header_t *ev, evh = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP6),
  };
  b->current_data = 0;
  eth.type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  ev = PUSH_HEADER (e, evh);
  i = PUSH_HEADER (ev, ip6);
  PUSH_HEADER (i, udp);
  i16 l3_offset = sizeof (eth) + sizeof (evh);
  b->current_data = l3_offset;

  vec_foreach (rule, rules)
  {
    ip6_set (mo, i, &rule->mr_mask_ip_mac.mmim_ip);
    eth_set (mo, e, &rule->mr_mask_ip_mac.mmim_mac.mmm_mac);

    MATCH_TEST_HIT ("match mask-src-ip-mac hit src /128",
		    match_match_one (vm, b, -l3_offset, 0, &app, now, &mres),
		    mres, rule - rules);
  }
  match_set_unapply (msi, &app);

  /*
   * Again with 1 and 2 tags
   */
  match_set_unapply (msi, &app);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST,
		   (MATCH_SET_TAG_FLAG_1_TAG |
		    MATCH_SET_TAG_FLAG_2_TAG), &app);

  b->current_data = 0;
  eth.type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
  evh.type = clib_host_to_net_u16 (ETHERNET_TYPE_IP6);
  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  ev = PUSH_HEADER (e, evh);
  i = PUSH_HEADER (ev, ip6);
  PUSH_HEADER (i, udp);
  l3_offset = sizeof (eth) + sizeof (evh);
  b->current_data = l3_offset;

  vec_foreach (rule, rules)
  {
    ip6_set (mo, i, &rule->mr_mask_ip_mac.mmim_ip);
    eth_set (mo, e, &rule->mr_mask_ip_mac.mmim_mac.mmm_mac);

    MATCH_TEST_HIT ("match mask-src-ip-mac hit src /128 1 tag of 2",
		    match_match_one (vm, b, -l3_offset, 0, &app, now, &mres),
		    mres, rule - rules);
  }

  ethernet_vlan_header_t *ev2, evh2 = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP6),
  };
  b->current_data = 0;
  eth.type = clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD);
  evh.type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  ev = PUSH_HEADER (e, evh);
  ev2 = PUSH_HEADER (ev, evh2);
  i = PUSH_HEADER (ev2, ip6);
  PUSH_HEADER (i, udp);
  l3_offset = sizeof (eth) + 2 * sizeof (evh);
  b->current_data = l3_offset;

  vec_foreach (rule, rules)
  {
    ip6_set (mo, i, &rule->mr_mask_ip_mac.mmim_ip);
    eth_set (mo, e, &rule->mr_mask_ip_mac.mmim_mac.mmm_mac);

    MATCH_TEST_HIT ("match mask-src-ip-mac hit src /128 2 tag of 2",
		    match_match_one (vm, b, -l3_offset, 0, &app, now, &mres),
		    mres, rule - rules);
  }

  match_set_list_del (msi, &handle1);
  match_set_unapply (msi, &app);

  match_set_unlock (&msi);
  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);
  vec_free (rules);
  clib_mem_free (b);

  return (res);
}

static int
match_test_mask_ip6 (vlib_main_t * vm,
		     match_orientation_t mo, const char *engine)
{
  u8 *list_name, *set_name;
  match_handle_t handle1;
  match_result_t mres;
  match_set_app_t app;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  int res;
  f64 now;

  now = vlib_time_now (vm);
  res = 0;

  match_test_engine_set (engine, 1);

  // a packet whose source address matches the rule
  b = clib_mem_alloc (sizeof (*b) + 1024);
  memset (b, 0, sizeof (*b) + 1024);

  /* *INDENT-OFF* */
  mac_address_t mac = {
    .bytes = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    },
  };
  ethernet_header_t *e, eth = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP6),
  };
  ip6_header_t *i, ip6 = {
    .ip_version_traffic_class_and_flow_label =
      clib_host_to_net_u32 (0x6 << 28),
    .protocol = IP_PROTOCOL_UDP,
  };
  udp_header_t *u, udp = {
  };
  void *h;
  /* *INDENT-ON* */

  match_rule_t *rules, *rule;

  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");
  match_list_init (&list, list_name, 0);

  rules = match_test_mask_ip_mk_v6 (&list, mo);
  msi = match_set_create_and_lock (set_name,
				   MATCH_TYPE_MASK_IP,
				   mo, ETHERNET_TYPE_IP6, NULL);
  handle1 = match_set_list_add (msi, &list, 0);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip6);
  u = PUSH_HEADER (i, udp);
  eth_set (mo, e, &mac);
  udp_set (mo, u, 3);

  vec_foreach (rule, rules)
  {
    ip6_set (mo, i, &rule->mr_mask_ip_mac.mmim_ip);

    MATCH_TEST_HIT ("match mask-ip6 hit %U /%d",
		    match_match_one (vm, b, 0, sizeof (eth), &app, now,
				     &mres), mres, rule - rules);
  }

  match_set_list_del (msi, &handle1);
  match_set_unapply (msi, &app);

  match_set_unlock (&msi);
  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);
  vec_free (rules);
  clib_mem_free (b);

  return (res);
}

static int
match_test_mask_ip4 (vlib_main_t * vm,
		     match_orientation_t mo, const char *engine)
{
  u8 *list_name, *set_name;
  match_handle_t handle1;
  match_result_t mres;
  match_set_app_t app;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  int res;
  f64 now;

  now = vlib_time_now (vm);
  res = 0;

  match_test_engine_set (engine, 1);

  // a packet whose source address matches the rule
  b = clib_mem_alloc (sizeof (*b) + 1024);
  memset (b, 0, sizeof (*b) + 1024);

  /* *INDENT-OFF* */
  mac_address_t mac = {
    .bytes = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    },
  };
  ethernet_header_t *e, eth = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4),
  };
  ip4_header_t *i, ip4 = {
    .ip_version_and_header_length = 0x45,
    .protocol = IP_PROTOCOL_UDP,
  };
  udp_header_t *u, udp = {
  };
  void *h;
  /* *INDENT-ON* */

  match_rule_t *rules, *rule;

  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");
  match_list_init (&list, list_name, 0);

  rules = match_test_mask_ip_mk_v4 (&list, mo, ETHERNET_TYPE_IP4);
  msi = match_set_create_and_lock (set_name,
				   MATCH_TYPE_MASK_IP,
				   mo, ETHERNET_TYPE_IP4, NULL);
  handle1 = match_set_list_add (msi, &list, 0);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip4);
  u = PUSH_HEADER (i, udp);
  eth_set (mo, e, &mac);
  udp_set (mo, u, 3);

  vec_foreach (rule, rules)
  {
    ip4_set (mo, i, &rule->mr_mask_ip_mac.mmim_ip);

    MATCH_TEST_HIT ("match mask-ip4 hit %U /%d",
		    match_match_one (vm, b, 0, sizeof (eth), &app, now,
				     &mres), mres, rule - rules,
		    format_match_orientation, mo,
		    rule->mr_mask_ip_mac.mmim_ip.mip_ip.len);
  }

  match_set_list_del (msi, &handle1);
  match_set_unapply (msi, &app);

  match_set_unlock (&msi);
  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);
  vec_free (rules);
  clib_mem_free (b);

  return (res);
}

static int
match_test_exact_ip6 (vlib_main_t * vm,
		      match_orientation_t mo, const char *engine)
{
  u8 *list_name, *set_name;
  match_handle_t handle1;
  match_result_t mres;
  match_set_app_t app;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  int res;
  f64 now;

  now = vlib_time_now (vm);
  res = 0;

  match_test_engine_set (engine, 1);

  // a packet whose source address matches the rule
  b = clib_mem_alloc (sizeof (*b) + 1024);
  memset (b, 0, sizeof (*b) + 1024);

  /* *INDENT-OFF* */
  mac_address_t mac = {
    .bytes = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    },
  };
  ethernet_header_t *e, eth = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP6),
  };
  ip6_header_t *i, ip6 = {
    .ip_version_traffic_class_and_flow_label =
      clib_host_to_net_u32 (0x6 << 28),
    .protocol = IP_PROTOCOL_UDP,
  };
  udp_header_t *u, udp = {
  };
  void *h;
  /* *INDENT-ON* */

  match_rule_t *rules, *rule;

  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");
  match_list_init (&list, list_name, 0);

  rules = match_test_exact_ip_mk_v6 (&list, mo);
  msi = match_set_create_and_lock (set_name,
				   MATCH_TYPE_EXACT_IP,
				   mo, ETHERNET_TYPE_IP6, NULL);
  handle1 = match_set_list_add (msi, &list, 0);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip6);
  u = PUSH_HEADER (i, udp);
  eth_set (mo, e, &mac);
  udp_set (mo, u, 3);

  vec_foreach (rule, rules)
  {
    ip6_seta (mo, i, &rule->mr_exact_ip);

    MATCH_TEST_HIT ("match exact-ip6 hit %U",
		    match_match_one (vm, b, 0, sizeof (eth), &app, now,
				     &mres), mres, rule - rules,
		    format_match_orientation, mo);
  }

  match_set_list_del (msi, &handle1);
  match_set_unapply (msi, &app);

  match_set_unlock (&msi);
  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);
  vec_free (rules);
  clib_mem_free (b);

  return (res);
}

static int
match_test_exact_ip4 (vlib_main_t * vm,
		      match_orientation_t mo, const char *engine)
{
  u8 *list_name, *set_name;
  match_handle_t handle1;
  match_result_t mres;
  match_set_app_t app;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  int res;
  f64 now;

  now = vlib_time_now (vm);
  res = 0;

  match_test_engine_set (engine, 1);

  // a packet whose source address matches the rule
  b = clib_mem_alloc (sizeof (*b) + 1024);
  memset (b, 0, sizeof (*b) + 1024);

  /* *INDENT-OFF* */
  mac_address_t mac = {
    .bytes = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    },
  };
  ethernet_header_t *e, eth = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4),
  };
  ip4_header_t *i, ip4 = {
    .ip_version_and_header_length = 0x45,
    .protocol = IP_PROTOCOL_UDP,
  };
  udp_header_t *u, udp = {
  };
  void *h;
  /* *INDENT-ON* */

  match_rule_t *rules, *rule;

  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");
  match_list_init (&list, list_name, 0);

  rules = match_test_exact_ip_mk_v4 (&list, mo, ETHERNET_TYPE_IP4, 0);
  msi = match_set_create_and_lock (set_name,
				   MATCH_TYPE_EXACT_IP,
				   mo, ETHERNET_TYPE_IP4, NULL);
  handle1 = match_set_list_add (msi, &list, 0);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip4);
  u = PUSH_HEADER (i, udp);
  eth_set (mo, e, &mac);
  udp_set (mo, u, 3);

  vec_foreach (rule, rules)
  {
    ip4_seta (mo, i, &rule->mr_exact_ip);

    MATCH_TEST_HIT ("match exact-ip4 hit %U",
		    match_match_one (vm, b, 0, sizeof (eth), &app, now,
				     &mres), mres, rule - rules,
		    format_match_orientation, mo);
  }

  match_set_list_del (msi, &handle1);
  match_set_unapply (msi, &app);

  match_set_unlock (&msi);
  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);
  vec_free (rules);
  clib_mem_free (b);

  return (res);
}

static int
match_test_exact_ip6_l4 (vlib_main_t * vm,
			 match_orientation_t mo, const char *engine)
{
  u8 *list_name, *set_name;
  match_handle_t handle1;
  match_result_t mres;
  match_set_app_t app;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  int res;
  f64 now;

  now = vlib_time_now (vm);
  res = 0;

  match_test_engine_set (engine, 1);

  // a packet whose source address matches the rule
  b = clib_mem_alloc (sizeof (*b) + 1024);
  memset (b, 0, sizeof (*b) + 1024);

  /* *INDENT-OFF* */
  mac_address_t mac = {
    .bytes = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    },
  };
  ethernet_header_t *e, eth = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP6),
  };
  ip6_header_t *i, ip6 = {
    .ip_version_traffic_class_and_flow_label =
      clib_host_to_net_u32 (0x6 << 28),
    .protocol = IP_PROTOCOL_UDP,
  };
  udp_header_t *u, udp = {
  };
  void *h;
  /* *INDENT-ON* */

  match_rule_t *rules, *rule;

  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");
  match_list_init (&list, list_name, 0);

  rules = match_test_exact_ip_l4_mk_v6 (&list, mo);
  msi = match_set_create_and_lock (set_name,
				   MATCH_TYPE_EXACT_IP_L4,
				   mo, ETHERNET_TYPE_IP6, NULL);
  handle1 = match_set_list_add (msi, &list, 0);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip6);
  u = PUSH_HEADER (i, udp);
  eth_set (mo, e, &mac);

  vec_foreach (rule, rules)
  {
    ip6_seta (mo, i, &rule->mr_exact_ip);
    udp_set (mo, u, rule->mr_exact_ip_l4.meil_l4.ml_port);

    MATCH_TEST_HIT ("match exact-ip6-l4 hit %U",
		    match_match_one (vm, b, 0, sizeof (eth), &app, now,
				     &mres), mres, rule - rules,
		    format_match_orientation, mo);
  }

  match_set_list_del (msi, &handle1);
  match_set_unapply (msi, &app);

  match_set_unlock (&msi);
  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);
  vec_free (rules);
  clib_mem_free (b);

  return (res);
}


static int
match_test_exact_ip4_l4 (vlib_main_t * vm,
			 match_orientation_t mo, const char *engine)
{
  u8 *list_name, *set_name;
  match_handle_t handle1;
  match_result_t mres;
  match_set_app_t app;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  int res;
  f64 now;

  now = vlib_time_now (vm);
  res = 0;

  match_test_engine_set (engine, 1);

  // a packet whose source address matches the rule
  b = clib_mem_alloc (sizeof (*b) + 1024);
  memset (b, 0, sizeof (*b) + 1024);

  /* *INDENT-OFF* */
  mac_address_t mac = {
    .bytes = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    },
  };
  ethernet_header_t *e, eth = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4),
  };
  ip4_header_t *i, ip4 = {
    .ip_version_and_header_length = 0x45,
    .protocol = IP_PROTOCOL_ICMP,
  };
  icmp46_header_t *ic, icmp = {
  };
  void *h;
  /* *INDENT-ON* */

  match_rule_t *rules, *rule;

  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");
  match_list_init (&list, list_name, 0);

  rules = match_test_exact_ip_l4_mk_v4 (&list, mo, ETHERNET_TYPE_IP4);
  msi = match_set_create_and_lock (set_name,
				   MATCH_TYPE_EXACT_IP_L4,
				   mo, ETHERNET_TYPE_IP4, NULL);
  handle1 = match_set_list_add (msi, &list, 0);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip4);
  ic = PUSH_HEADER (i, icmp);
  eth_set (mo, e, &mac);

  vec_foreach (rule, rules)
  {
    ip4_seta (mo, i, &rule->mr_exact_ip_l4.meil_ip);
    ic->type = rule->mr_exact_ip_l4.meil_l4.ml_icmp.mi_type;
    ic->code = rule->mr_exact_ip_l4.meil_l4.ml_icmp.mi_code;

    MATCH_TEST_HIT ("match exact-ip4-l4 hit %U",
		    match_match_one (vm, b, 0, sizeof (eth), &app, now,
				     &mres), mres, rule - rules,
		    format_match_orientation, mo);
  }

  match_set_list_del (msi, &handle1);
  match_set_unapply (msi, &app);

  match_set_unlock (&msi);
  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);
  vec_free (rules);
  clib_mem_free (b);

  return (res);
}

static int
match_test_sets_ip4 (vlib_main_t * vm, const char *engine)
{
#define N_SETS 4
  match_handle_t handle, handles[N_SETS];
  u8 *list_name, *set_name;
  index_t msis[N_SETS];
  match_result_t mres;
  match_set_app_t app;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  int res, ii;
  f64 now;

  now = vlib_time_now (vm);
  res = 0;

  match_test_engine_set (engine, 1);

  // a packet whose source address matches the rule
  b = clib_mem_alloc (sizeof (*b) + 1024);
  memset (b, 0, sizeof (*b) + 1024);

  /* *INDENT-OFF* */
  mac_address_t mac = {
    .bytes = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    },
  };
  ethernet_header_t *e, eth = {
    .type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4),
  };
  ip4_header_t *i, ip4 = {
    .ip_version_and_header_length = 0x45,
    .protocol = IP_PROTOCOL_ICMP,
  };
  icmp46_header_t icmp = {
  };
  void *h;
  /* *INDENT-ON* */

  match_rule_t *rules[N_SETS], *rs, *rd;;

  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");

  // create 4 sets to use in the rules
  for (ii = 0; ii < N_SETS; ii++)
    {
      match_list_init (&list, list_name, 0);

      rules[ii] = match_test_exact_ip_mk_v4 (&list, MATCH_BOTH,
					     ETHERNET_TYPE_IP4, ii * 32);
      msis[ii] = match_set_create_and_lock (set_name,
					    MATCH_TYPE_EXACT_IP,
					    (ii % 2 ? MATCH_DST : MATCH_SRC),
					    ETHERNET_TYPE_IP4, NULL);
      handles[ii] = match_set_list_add (msis[ii], &list, 0);
      match_list_free (&list);
    }

  match_list_init (&list, list_name, 0);

  // now create a set that uses these sets
  match_rule_t rule1;
  memset (&rule1, 0, sizeof (rule1));

  rule1.mr_type = MATCH_TYPE_SETS;
  rule1.mr_result = 1;
  rule1.mr_sets.mss_set[MATCH_SRC] = msis[0];
  rule1.mr_sets.mss_set[MATCH_DST] = msis[1];
  match_list_push_back (&list, &rule1);
  rule1.mr_sets.mss_set[MATCH_SRC] = msis[2];
  rule1.mr_sets.mss_set[MATCH_DST] = msis[3];
  rule1.mr_result = 2;
  match_list_push_back (&list, &rule1);

  msi = match_set_create_and_lock (set_name,
				   MATCH_TYPE_SETS,
				   MATCH_BOTH, ETHERNET_TYPE_IP4, NULL);
  handle = match_set_list_add (msi, &list, 0);
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, MATCH_SET_TAG_FLAG_0_TAG, &app);
  match_list_free (&list);

  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip4);
  PUSH_HEADER (i, icmp);
  eth_set (MATCH_DST, e, &mac);
  eth_set (MATCH_SRC, e, &mac);

  // test each set pair
  vec_foreach (rs, rules[0])
  {
    vec_foreach (rd, rules[1])
    {
      ip4_seta (MATCH_SRC, i, &rs->mr_exact_ip_l4.meil_ip);
      ip4_seta (MATCH_DST, i, &rd->mr_exact_ip_l4.meil_ip);

      MATCH_TEST_HIT ("match sets hit 1",
		      match_match_one (vm, b, 0, sizeof (eth), &app, now,
				       &mres), mres, 1);
    }
  }
  vec_foreach (rs, rules[2])
  {
    vec_foreach (rd, rules[3])
    {
      ip4_seta (MATCH_SRC, i, &rs->mr_exact_ip_l4.meil_ip);
      ip4_seta (MATCH_DST, i, &rd->mr_exact_ip_l4.meil_ip);

      MATCH_TEST_HIT ("match sets hit 2",
		      match_match_one (vm, b, 0, sizeof (eth), &app, now,
				       &mres), mres, 2);
    }
  }
  // opposite direction should miss
  vec_foreach (rs, rules[3])
  {
    vec_foreach (rd, rules[2])
    {
      ip4_seta (MATCH_SRC, i, &rs->mr_exact_ip_l4.meil_ip);
      ip4_seta (MATCH_DST, i, &rd->mr_exact_ip_l4.meil_ip);

    MATCH_TEST_MISS ("match sets miss opposite",
		       match_match_one (vm, b, 0, sizeof (eth), &app, now,
					  &mres))}
  }
  // different sets should miss
  vec_foreach (rs, rules[0])
  {
    vec_foreach (rd, rules[3])
    {
      ip4_seta (MATCH_SRC, i, &rs->mr_exact_ip_l4.meil_ip);
      ip4_seta (MATCH_DST, i, &rd->mr_exact_ip_l4.meil_ip);

    MATCH_TEST_MISS ("match sets miss mismatch",
		       match_match_one (vm, b, 0, sizeof (eth), &app, now,
					  &mres))}
  }

  // update one of the sets used in the rules
  vec_free (rules[0]);
  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  rules[0] = match_test_exact_ip_mk_v4 (&list, MATCH_BOTH,
					ETHERNET_TYPE_IP4, 128);
  match_set_list_replace (msis[0], handles[0], &list, 0);
  match_list_free (&list);

  // re-test the set pair
  vec_foreach (rs, rules[0])
  {
    vec_foreach (rd, rules[1])
    {
      ip4_seta (MATCH_SRC, i, &rs->mr_exact_ip_l4.meil_ip);
      ip4_seta (MATCH_DST, i, &rd->mr_exact_ip_l4.meil_ip);

      MATCH_TEST_HIT ("match sets hit post change",
		      match_match_one (vm, b, 0, sizeof (eth), &app, now,
				       &mres), mres, 1);
    }
  }

  // cleanup
  match_set_list_del (msi, &handle);
  match_set_unapply (msi, &app);
  match_set_unlock (&msi);

  for (ii = 0; ii < N_SETS; ii++)
    {
      match_set_list_del (msis[ii], &handles[ii]);
      match_set_unlock (&msis[ii]);
      vec_free (rules[ii]);
    }

  vec_free (list_name);
  vec_free (set_name);
  clib_mem_free (b);

  return (res);
}

static clib_error_t *
match_test (vlib_main_t * vm,
	    unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  match_orientation_t mo;
  int res = 0;

  if (unformat (input, "debug"))
    match_test_do_debug = 1;

  for (mo = MATCH_SRC; mo <= MATCH_DST; mo++)
    {
      res |= match_test_exact_ip6 (vm, mo, "linear");
      res |= match_test_exact_ip4 (vm, mo, "linear");
      res |= match_test_exact_ip6_l4 (vm, mo, "linear");
      res |= match_test_exact_ip4_l4 (vm, mo, "linear");
      res |= match_test_mask_ip6 (vm, mo, "linear");
      res |= match_test_mask_ip4 (vm, mo, "linear");
      res |= match_test_mask_ip4_mac (vm, mo, "linear");
      res |= match_test_mask_ip4_mac (vm, mo, "classifier");
      res |= match_test_mask_ip6_mac (vm, mo, "linear");
      res |= match_test_mask_ip6_mac (vm, mo, "classifier");
    }

  res |= match_test_mask_n_tuple_ip4 (vm, "turbo");
  res |= match_test_mask_n_tuple_ip4 (vm, "linear");
  res |= match_test_mask_n_tuple_ip4 (vm, "classifier");

  res |= match_test_mask_n_tuple_ip6 (vm, "turbo");
  res |= match_test_mask_n_tuple_ip6 (vm, "linear");
  res |= match_test_mask_n_tuple_ip6 (vm, "classifier");

  res |= match_test_sets_ip4 (vm, "linear");

  // check for leaks
  if (0 != pool_elts (match_set_pool) ||
      0 != pool_elts (match_set_entry_pool) ||
      0 != pool_elts (match_classifier_mask_class_pool) ||
      0 != pool_elts (match_classifier_rule_pool) ||
      0 != pool_elts (match_classifier_list_pool) ||
      0 != pool_elts (match_classifier_clash_pool) ||
      0 != pool_elts (match_classifier_clash_head_pool) ||
      0 != pool_elts (match_classifier_engine_pool))
    return clib_error_return (0, "Match Unit Test Failed - memory leak");

  if (res)
    return clib_error_return (0, "Match Unit Test Failed");
  else
    return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_match_command, static) =
{
  .path = "test match",
  .short_help = "match unit tests",
  .function = match_test,
};
/* *INDENT-ON* */

clib_error_t *
match_test_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (match_test_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
