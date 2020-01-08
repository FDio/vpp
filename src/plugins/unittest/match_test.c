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

#include <vnet/ethernet/packet.h>
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
    res = 1;                                                    \
  }								\
}

#define MATCH_TEST_HIT(_comment, _res, _data, _list, _rule)       \
{                                                                 \
  MATCH_TEST((_res)->msr_pos.msp_list_index == _list,             \
             _comment " list:%d != %d",                           \
             (_res)->msr_pos.msp_list_index, _list);              \
  MATCH_TEST((_res)->msr_pos.msp_rule_index == _rule,             \
             _comment " rule:%d != %d",                           \
             (_res)->msr_pos.msp_rule_index, _rule);              \
  MATCH_TEST((_res)->msr_user_ctx == _data,                       \
             _comment " user:0x%x", (_res)->msr_user_ctx);        \
}

#define MATCH_TEST_MISS(_comment, _res)                             \
{                                                                   \
  MATCH_TEST((_res)->msr_pos.msp_list_index == MATCH_RESULT_MISS,   \
             _comment " list:%d != MISS",                           \
             (_res)->msr_pos.msp_list_index);                       \
  MATCH_TEST((_res)->msr_pos.msp_rule_index == MATCH_RESULT_MISS,   \
             _comment " rule:%d != MISS",                           \
             (_res)->msr_pos.msp_rule_index);                       \
}

/* #define MATCH_PRINT(vm, _args...)                       \ */
/* {                                                       \ */
/*   void *_old_heap = clib_mem_set_heap (vm->heap_base);  \ */
/*   vlib_cli_output(vm, ##_args);                         \ */
/*   clib_mem_set_heap (_old_heap);                        \ */
/* } */
#define MATCH_PRINT(vm, _args...)                       \
{                                                       \
  vlib_cli_output(vm, ##_args);                         \
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
  match_set_result_t mres;
  match_set_app_t app;
  void *data1, *data2;
  match_rule_t rule1;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  int res;

  res = 0;
  data1 = (void *) 0xdd;
  data2 = (void *) 0xcc;
  match_test_engine_set (engine, 1);

  /*
   * start with a rule that does exact match on ip source only
   */
  ip_prefix_t ipp_10_10_10_10_s_32 = {
    .addr = {
	     .ip = {
		    .ip4.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a),
		    },
	     .version = AF_IP4,
	     },
    .len = 32,
  };
  list_name = format (NULL, "foo");
  set_name = format (NULL, "bar");

  memset (&rule1, 0, sizeof (rule1));
  rule1.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  match_ip_prefix_set (&rule1.mr_mask_n_tuple.mnt_src_ip,
		       &ipp_10_10_10_10_s_32);

  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule1);

  msi = match_set_create_and_lock (set_name, MATCH_TYPE_MASK_N_TUPLE, NULL);

  handle1 = match_set_list_add (msi, &list, 0, data1);

  match_set_apply (msi, MATCH_SEMANTIC_FIRST, VNET_LINK_ETHERNET,
		   MATCH_SET_TAG_FLAG_0_TAG, &app);

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

  vnet_buffer (b)->l2.l2_len = sizeof (eth);
  h = vlib_buffer_get_current (b);
  e = FIRST_HEADER (h, eth);
  i = PUSH_HEADER (e, ip4);
  u = PUSH_HEADER (i, udp);

  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit src /32", &mres, data1, 0, 0);

  // modify the packet so it does not match the rule
  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a01);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_MISS ("match miss src /32", &mres);

  /*
   * replace the list with one with 2 rules the second will match the packet
   * against a longer mask
   */
  match_rule_t rule2;

  ip_prefix_t ipp_10_10_10_0_s_24 = {
    .addr = {
	     .ip = {
		    .ip4.as_u32 = clib_host_to_net_u32 (0x0a0a0a00),
		    }
	     ,
	     .version = AF_IP4,
	     }
    ,
    .len = 24,
  };
  memset (&rule2, 0, sizeof (rule2));
  rule2.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  match_ip_prefix_set (&rule2.mr_mask_n_tuple.mnt_src_ip,
		       &ipp_10_10_10_0_s_24);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule1);
  match_list_push_back (&list, &rule2);
  match_set_list_replace (msi, handle1, &list, 0, data1);

  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit src /24", &mres, data1, 0, 1);

  // modify the packet so it misses both rules
  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0101);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_MISS ("match miss src /24", &mres);

  /*
   * replace the list with one with 3 rules the second will match the packet
   * against a longer mask
   */
  match_rule_t rule3;

  ip_prefix_t ipp_10_0_0_0_s_10 = {
    .addr = {
	     .ip = {
		    .ip4.as_u32 = clib_host_to_net_u32 (0x0a000000),
		    }
	     ,
	     .version = AF_IP4,
	     }
    ,
    .len = 10,
  };
  memset (&rule3, 0, sizeof (rule2));
  rule3.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  match_ip_prefix_set (&rule3.mr_mask_n_tuple.mnt_src_ip, &ipp_10_0_0_0_s_10);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule1);
  match_list_push_back (&list, &rule2);
  match_list_push_back (&list, &rule3);
  match_set_list_replace (msi, handle1, &list, 0, data1);

  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit src /10", &mres, data1, 0, 2);

  // modify the packet so it misses all rules
  i->src_address.as_u32 = clib_host_to_net_u32 (0x01010101);

  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_MISS ("match miss src /10", &mres);

  /*
   * Add a rule that will match both src and dst IP
   */
  match_rule_t rule4;

  memset (&rule4, 0, sizeof (rule3));
  rule4.mr_type = MATCH_TYPE_MASK_N_TUPLE;
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
  match_set_list_replace (msi, handle1, &list, 0, data1);


  // set packet to match on both src and dst
  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a01);
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a01);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit both src,dst /32", &mres, data1, 0, 0);

  // modify the packet so it only hits on src
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x01010101);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit src src,dst /32", &mres, data1, 0, 2);

  // modify the packet so it misses all rules
  i->src_address.as_u32 = clib_host_to_net_u32 (0x01010101);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_MISS ("match miss src,dst /32", &mres);

  /*
   * A rule that matches all UDP traffic.
   */
  ip_prefix_t ipp_0_s_0 = { };
  match_rule_t rule5;

  memset (&rule5, 0, sizeof (rule3));
  rule5.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule5.mr_mask_n_tuple.mnt_ip_proto = IP_PROTOCOL_UDP;
  rule5.mr_mask_n_tuple.mnt_src_port = MATCH_PORT_RANGE_ANY;
  rule5.mr_mask_n_tuple.mnt_dst_port = MATCH_PORT_RANGE_ANY;
  match_ip_prefix_set (&rule5.mr_mask_n_tuple.mnt_src_ip, &ipp_0_s_0);
  match_ip_prefix_set (&rule5.mr_mask_n_tuple.mnt_dst_ip, &ipp_0_s_0);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule5);
  match_list_push_back (&list, &rule4);
  match_set_list_replace (msi, handle1, &list, 0, data1);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit udp only", &mres, data1, 0, 0);

  /*
   * A rule that matches one udp port, that is better than one that
   * matches on any
   */
  match_rule_t rule6;

  memset (&rule6, 0, sizeof (rule3));
  rule6.mr_type = MATCH_TYPE_MASK_N_TUPLE;
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
  match_set_list_replace (msi, handle1, &list, 0, data1);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);
  u->src_port = clib_host_to_net_u16 (2000);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit udp specifc", &mres, data1, 0, 0);

  u->src_port = 2;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit udp specifc, any", &mres, data1, 0, 1);

  /*
   * A rule that matches a range of UDP ports.
   *  specific < range < any
   */
  match_rule_t rule7;

  memset (&rule7, 0, sizeof (rule3));
  rule7.mr_type = MATCH_TYPE_MASK_N_TUPLE;
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
  match_set_list_replace (msi, handle1, &list, 0, data1);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x0a0a0a0a);

  u->src_port = clib_host_to_net_u16 (2000);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit udp specifc w/ range", &mres, data1, 0, 0);

  u->src_port = clib_host_to_net_u16 (22222);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit udp range", &mres, data1, 0, 1);

  u->src_port = 2;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit udp specifc, any", &mres, data1, 0, 2);

  /*
   * A rule that matches a range of TCP ports.
   *  we'll put this is a separate list
   */
  match_rule_t rule8;

  memset (&rule8, 0, sizeof (rule3));
  rule8.mr_type = MATCH_TYPE_MASK_N_TUPLE;
  rule8.mr_mask_n_tuple.mnt_ip_proto = IP_PROTOCOL_TCP;
  rule8.mr_mask_n_tuple.mnt_src_port.mpr_begin = 1000;
  rule8.mr_mask_n_tuple.mnt_src_port.mpr_end = 40000;
  rule8.mr_mask_n_tuple.mnt_dst_port = MATCH_PORT_RANGE_ANY;
  match_ip_prefix_set (&rule8.mr_mask_n_tuple.mnt_src_ip, &ipp_0_s_0);
  match_ip_prefix_set (&rule8.mr_mask_n_tuple.mnt_dst_ip, &ipp_0_s_0);

  match_list_free (&list);
  match_list_init (&list, list_name, 0);
  match_list_push_back (&list, &rule8);
  handle2 = match_set_list_add (msi, &list, 1, data2);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  tcp_header_t *t = (tcp_header_t *) u;

  i->src_address.as_u32 = clib_host_to_net_u32 (0x0a0a0b0b);
  i->dst_address.as_u32 = clib_host_to_net_u32 (0x0a0a0b0b);
  i->protocol = IP_PROTOCOL_TCP;
  t->src_port = clib_host_to_net_u16 (2000);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit tcp specifc w/ range", &mres, data2, 1, 0);

  i->protocol = IP_PROTOCOL_UDP;
  t->src_port = clib_host_to_net_u16 (2000);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit udp specifc w/ range", &mres, data1, 0, 0);

  /*
   * A rule that matches a range of TCP ports and flags
   */
  match_rule_t rule9;

  memset (&rule9, 0, sizeof (rule3));
  rule9.mr_type = MATCH_TYPE_MASK_N_TUPLE;
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
  match_set_list_replace (msi, handle2, &list, 1, data2);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  i->protocol = IP_PROTOCOL_TCP;
  t->src_port = clib_host_to_net_u16 (2000);

  // flags exact match
  t->flags = 0x4;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit tcp specifc flags", &mres, data2, 1, 0);

  // no flags => miss
  t->flags = 0;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match miss tcp flags", &mres, data2, 1, 1);

  // extra flags set => miss
  t->flags = 0x7;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match miss tcp flags", &mres, data2, 1, 1);

  // flags set not in mask => hit
  t->flags = 0xc;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit tcp specifc flags", &mres, data2, 1, 0);

  /*
   * cleanup
   */
  //cleanup:
  match_set_unapply (msi, &app);
  match_set_list_del (msi, &handle1);
  match_set_list_del (msi, &handle2);
  match_set_unlock (&msi);

  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);

  return (res);
}

static int
match_test_mask_n_tuple_ip6 (vlib_main_t * vm, const char *engine)
{
  match_handle_t handle[10];
  u8 *list_name, *set_name;
  match_set_result_t mres;
  match_set_app_t app;
  void *data1;
  match_list_t list;
  vlib_buffer_t *b;
  index_t msi;
  u64 j, k;
  int res;

#define LIST_SIZE 0x4
  res = 0;
  data1 = (void *) 0xdd;

  match_test_engine_set (engine, 1);

  /*
   * start with a rule that does exact match on ip source only
   */
  ip_prefix_t ipp = {
    .addr = {
	     .ip = {
		    .ip6 = {
			    .as_u64[0] =
			    clib_host_to_net_u64 (0xfd01000000000000),
			    },
		    },
	     .version = AF_IP6,
	     },
    .len = 128,
  };

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

  msi = match_set_create_and_lock (set_name, MATCH_TYPE_MASK_N_TUPLE, NULL);

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
	  match_ip_prefix_set (&rule1.mr_mask_n_tuple.mnt_src_ip, &ipp);
	  match_ip_prefix_set (&rule1.mr_mask_n_tuple.mnt_dst_ip, &ipp);

	  match_list_push_back (&list, &rule1);
	}

      handle[k] = match_set_list_add (msi, &list, k, data1);
    }

  // in constrast to the IP4 tests, we apply this a IP layer
  match_set_apply (msi, MATCH_SEMANTIC_FIRST, VNET_LINK_IP6,
		   MATCH_SET_TAG_FLAG_0_TAG, &app);
  //MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  // match each rule in turn
  for (k = 0; k < 8; k++)
    {
      for (j = 0; j < LIST_SIZE; j++)
	{
	  i->src_address.as_u64[1] =
	    i->dst_address.as_u64[1] =
	    clib_host_to_net_u64 ((j + 1) << (k * 8));

	  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
	  MATCH_TEST_HIT ("match hit src /128", &mres, data1, k, j);
	}
    }

  // modify the packet so it does not match the rule
  i->src_address.as_u64[0] = clib_host_to_net_u64 (0xfd02000000000000);
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_MISS ("match miss src /128", &mres);

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
      match_ip_prefix_set (&rule1.mr_mask_n_tuple.mnt_src_ip, &ipp);
      match_ip_prefix_set (&rule1.mr_mask_n_tuple.mnt_dst_ip, &ipp);

      match_list_push_back (&list, &rule1);
    }

  handle[8] = match_set_list_add (msi, &list, k, data1);

  // match each rule in turn
  for (j = 0; j < LIST_SIZE; j++)
    {
      i->src_address.as_u64[1] = i->dst_address.as_u64[1] = 0;
      i->src_address.as_u64[0] =
	i->dst_address.as_u64[0] =
	clib_host_to_net_u64 (0xfd02000000000000 + j + 1);

      match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
      MATCH_TEST_HIT ("match hit src /64", &mres, data1, 8, j);
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
  rule_any.mr_mask_n_tuple.mnt_ip_proto = IP_PROTOCOL_ICMP6;
  match_ip_prefix_set (&rule_any.mr_mask_n_tuple.mnt_src_ip, &ipp);
  match_ip_prefix_set (&rule_any.mr_mask_n_tuple.mnt_dst_ip, &ipp);
  rule_any.mr_mask_n_tuple.mnt_icmp_type.mitr_begin = 0;
  rule_any.mr_mask_n_tuple.mnt_icmp_type.mitr_end = 0xff;
  rule_any.mr_mask_n_tuple.mnt_icmp_code.micr_begin = 0;
  rule_any.mr_mask_n_tuple.mnt_icmp_code.micr_end = 0xff;

  clib_memcpy (&rule_type, &rule_any, sizeof (rule_type));
  clib_memcpy (&rule_type_code, &rule_any, sizeof (rule_type_code));

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
  handle[9] = match_set_list_add (msi, &list, 9, data1);

  // MATCH_PRINT(vm, "%U", format_match_set, msi, 1);

  i->src_address.as_u64[1] = i->dst_address.as_u64[1] = 0;
  i->src_address.as_u64[0] =
    i->dst_address.as_u64[0] = clib_host_to_net_u64 (0xfd03000000000000);

  // exact match type and code
  p->type = 1;
  p->code = 3;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit ICMP exact type&code", &mres, data1, 9, 0);

  // exact match type and any code
  p->type = 1;
  p->code = 4;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit ICMP exact type, anycode", &mres, data1, 9, 1);

  // any match type and any code
  p->type = 4;
  p->code = 4;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit ICMP any type&code", &mres, data1, 9, 2);

  // remove all the other list and run the ICMP packet tests again
  for (k = 0; k < 9; k++)
    match_set_list_del (msi, &handle[k]);

  // exact match type and code
  p->type = 1;
  p->code = 3;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit ICMP exact type&code", &mres, data1, 0, 0);

  // exact match type and any code
  p->type = 1;
  p->code = 4;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit ICMP exact type, anycode", &mres, data1, 0, 1);

  // any match type and any code
  p->type = 4;
  p->code = 4;
  match_match_one (vm, b, &app, vlib_time_now (vm), &mres);
  MATCH_TEST_HIT ("match hit ICMP any type&code", &mres, data1, 0, 2);

  match_set_list_del (msi, &handle[9]);

  /*
   * cleanup
   */
  match_set_unapply (msi, &app);
  match_set_unlock (&msi);

  match_list_free (&list);
  vec_free (list_name);
  vec_free (set_name);

  return (res);
}


static clib_error_t *
match_test (vlib_main_t * vm,
	    unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  // our own heap - we can test for memory leaks
  // void *old_heap, *test_heap;
  // clib_mem_usage_t usage;
  int res = 0;

  if (unformat (input, "debug"))
    match_test_do_debug = 1;

  /* test_heap = mheap_alloc_with_lock (0 /\* use VM *\/ , */
  /*                                    1 << 21, */
  /*                                    1 /\* locked *\/ ); */
  /* mheap_trace (test_heap, VLIB_ENABLE); */
  /* old_heap = clib_mem_set_heap (test_heap); */

  res |= match_test_mask_n_tuple_ip6 (vm, "turbo");
  res |= match_test_mask_n_tuple_ip6 (vm, "linear");
  res |= match_test_mask_n_tuple_ip6 (vm, "classifier");

  res |= match_test_mask_n_tuple_ip4 (vm, "turbo");
  res |= match_test_mask_n_tuple_ip4 (vm, "linear");
  res |= match_test_mask_n_tuple_ip4 (vm, "classifier");

  /*
   * restore heap and check for leaks
   */
  /* clib_mem_set_heap (old_heap); */

  /* mheap_usage (test_heap, &usage); */

  /* if (usage.object_count != 0) */
  /*   return clib_error_return(0, "Match Unit Test Failed - memory leak"); */

  if (res)
    return clib_error_return (0, "Match Unit Test Failed");
  else
    return (NULL);
}

VLIB_CLI_COMMAND (test_match_command, static) =
{
.path = "test match",.short_help = "match unit tests",.function =
    match_test,};

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
