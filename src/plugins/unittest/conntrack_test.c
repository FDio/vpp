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

#include <vnet/conntrack/conntrack.h>
#include <vnet/conntrack/conntrack_dp.h>

static int conn_test_do_debug;

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


#define CONN_TEST_I(_cond, _comment, _args...)                   \
({                                                               \
  int _evald = (_cond);                                          \
  if (!(_evald)) {                                               \
    vlib_cli_output(vm, "FAIL:%d: " _comment "\n",               \
                    __LINE__, ##_args);                          \
    res = 1;                                                     \
  } else {                                                       \
    if (conn_test_do_debug)                                      \
      fformat(stderr, "PASS:%d: " _comment "\n",                 \
              __LINE__, ##_args);                                \
  }                                                              \
  res;                                                           \
})
#define CONN_TEST(_cond, _comment, _args...)			\
{								\
  if (CONN_TEST_I(_cond, _comment, ##_args)) {                  \
    ASSERT(0);                                                  \
    res = 1;                                                    \
  }								\
}

static int
conn_test_ip4 (vlib_main_t * vm, conn_user_t cu)
{
  conn_db_id_t cid;
  index_t cdbi, conni, conni2;
  conn_hash_t chash;
  int res, ii, jj;
  conn_owner_t owner1, owner2;
  u32 thread_index, seed;
  const u32 N_CONNS = 120;

  seed = vlib_time_now (vm);
  thread_index = 0;
  res = 0;
  cid = 10;

  cdbi = conn_track_add_or_lock (cu, cid, NULL, AF_IP4, N_CONNS,
				 CONN_DB_FLAG_NONE);
  owner1 = conn_track_owner_add (cdbi);
  owner2 = conn_track_owner_add (cdbi);

  /* *INDENT-OFF* */
  conn_hdr_ip4_t hdr = {
    .ch4_ip = {
      .ip_version_and_header_length = 0x45,
      .protocol = IP_PROTOCOL_UDP,
      .src_address.as_u32 = clib_host_to_net_u32 (0x0a000001),
      .dst_address.as_u32 = clib_host_to_net_u32 (0x0a000002),
    },
    .ch4_l4 = {
      .src_port = clib_host_to_net_u16 ((u16)25),
      .dst_port = clib_host_to_net_u16 ((u16)3000),
    },
  };
  /* *INDENT-ON* */

  conni = conn_track_ip4_find (cdbi, thread_index, &hdr.ch4_ip,
			       &chash, vlib_time_now (vm));

  CONN_TEST (INDEX_INVALID == conni, "first conn not found");

  conni = conn_track_ip4_add (cdbi, thread_index, owner1, &hdr.ch4_ip,
			      chash, vlib_time_now (vm));

  CONN_TEST (INDEX_INVALID != conni, "first conn added");

  conni2 = conn_track_ip4_find (cdbi, thread_index, &hdr.ch4_ip,
				&chash, vlib_time_now (vm));

  CONN_TEST (conni2 == conni, "first conn found");

  // add 127 new connections, with both owners
  for (ii = 1; ii < 64; ii++)
    {
      hdr.ch4_l4.dst_port = clib_host_to_net_u16 ((u16) ii);

      conni = conn_track_ip4_add (cdbi, thread_index, owner1,
				  &hdr.ch4_ip, chash, vlib_time_now (vm));
      CONN_TEST (INDEX_INVALID != conni, "%d conn added", ii);
    }
  for (; ii < 128; ii++)
    {
      hdr.ch4_l4.dst_port = clib_host_to_net_u16 ((u16) ii);

      conni = conn_track_ip4_add (cdbi, thread_index, owner2,
				  &hdr.ch4_ip, chash, vlib_time_now (vm));
      CONN_TEST (INDEX_INVALID != conni, "%d conn added", ii);
    }

  // fire in many 'packets' that match the last 127 entries but not the first
  // one that was added. both directions
  f64 now = 7.5;
  for (ii = 1; ii < 128; ii++)
    {
      hdr.ch4_ip.src_address.as_u32 = clib_host_to_net_u32 (0x0a000001);
      hdr.ch4_ip.dst_address.as_u32 = clib_host_to_net_u32 (0x0a000002);
      hdr.ch4_l4.dst_port = clib_host_to_net_u16 ((u16) ii);
      hdr.ch4_l4.src_port = clib_host_to_net_u16 ((u16) 25);

      conni =
	conn_track_ip4_find (cdbi, thread_index, &hdr.ch4_ip, &chash, now);
      CONN_TEST (INDEX_INVALID != conni, "%d forward conn found", ii);

      hdr.ch4_ip.dst_address.as_u32 = clib_host_to_net_u32 (0x0a000001);
      hdr.ch4_ip.src_address.as_u32 = clib_host_to_net_u32 (0x0a000002);
      hdr.ch4_l4.src_port = clib_host_to_net_u16 ((u16) ii);
      hdr.ch4_l4.dst_port = clib_host_to_net_u16 ((u16) 25);

      conni =
	conn_track_ip4_find (cdbi, thread_index, &hdr.ch4_ip, &chash, now);
      CONN_TEST (INDEX_INVALID != conni, "%d reverse conn found", ii);
    }

  // the first connection that was added should have risen to the top of
  // the sieve so that when the next connection is added it is the one
  // that is replaced
  hdr.ch4_ip.src_address.as_u32 = clib_host_to_net_u32 (0x0a000001);
  hdr.ch4_ip.dst_address.as_u32 = clib_host_to_net_u32 (0x0a000002);
  hdr.ch4_l4.src_port = clib_host_to_net_u16 ((u16) 25);
  hdr.ch4_l4.dst_port = clib_host_to_net_u16 ((u16) 0);
  conni = conn_track_ip4_add (cdbi, thread_index, owner2, &hdr.ch4_ip,
			      chash, vlib_time_now (vm));

  CONN_TEST (INDEX_INVALID != conni, "%d conn added", ii);

  // we cant find the original
  hdr.ch4_l4.dst_port = clib_host_to_net_u16 (3000);

  conni2 = conn_track_ip4_find (cdbi, thread_index, &hdr.ch4_ip,
				&chash, vlib_time_now (vm));
  CONN_TEST (INDEX_INVALID == conni2, "original overwritten");

  // shake the sieve again, this time get port 55 to rise to the top
  hdr.ch4_ip.src_address.as_u32 = clib_host_to_net_u32 (0x0a000001);
  hdr.ch4_ip.dst_address.as_u32 = clib_host_to_net_u32 (0x0a000002);
  hdr.ch4_l4.src_port = clib_host_to_net_u16 ((u16) 25);
  for (jj = 0; jj < 0xffff; jj++)
    {
      u16 port = random_u32 (&seed) & 0x7f;
      if (port == 55)
	continue;

      hdr.ch4_l4.dst_port = clib_host_to_net_u16 (port);

      conni = conn_track_ip4_find (cdbi, thread_index, &hdr.ch4_ip,
				   &chash, vlib_time_now (vm));
      CONN_TEST (INDEX_INVALID != conni, "%d forward conn found", ii);
    }

  // flush everything from owner1
  conn_track_owner_flush (cdbi, owner1);

  for (ii = 1; ii < 64; ii++)
    {
      hdr.ch4_l4.dst_port = clib_host_to_net_u16 ((u16) ii);
      conni = conn_track_ip4_find (cdbi, thread_index, &hdr.ch4_ip,
				   &chash, vlib_time_now (vm));
      CONN_TEST (INDEX_INVALID == conni, "%d forward conn found", ii);
    }
  for (; ii < 128; ii++)
    {
      hdr.ch4_l4.dst_port = clib_host_to_net_u16 ((u16) ii);
      conni = conn_track_ip4_find (cdbi, thread_index, &hdr.ch4_ip,
				   &chash, vlib_time_now (vm));
      CONN_TEST (INDEX_INVALID != conni, "%d forward conn found", ii);
    }

  // flush everything from owner2
  conn_track_owner_flush (cdbi, owner2);

  for (ii = 0; ii < 128; ii++)
    {
      hdr.ch4_l4.dst_port = clib_host_to_net_u16 ((u16) ii);
      conni = conn_track_ip4_find (cdbi, thread_index, &hdr.ch4_ip,
				   &chash, vlib_time_now (vm));
      CONN_TEST (INDEX_INVALID == conni, "%d forward conn found", ii);
    }

  // clean-up
  conn_db_unlock (&cdbi);

  return (res);
}

static int
conn_test_ip6 (vlib_main_t * vm, conn_user_t cu)
{
  conn_db_id_t cid;
  index_t cdbi, conni;
  conn_hash_t chash;
  int res, ii, jj;
  conn_owner_t owner1;
  u32 thread_index;
  u8 *tag;
  const u32 N_CONNS = 3;

  thread_index = 0;
  res = 0;
  cid = 10;
  tag = format (NULL, "foo");

  cdbi = conn_track_add_or_lock (cu, cid, tag, AF_IP6, N_CONNS,
				 CONN_DB_FLAG_NONE);
  owner1 = conn_track_owner_add (cdbi);

  /* *INDENT-OFF* */
  conn_hdr_ip6_t hdr = {
    .ch6_ip = {
      .ip_version_traffic_class_and_flow_label =
      clib_host_to_net_u32 (0x6 << 28),
      .protocol = IP_PROTOCOL_UDP,
      .src_address = {
        .as_u64 = {
          [0] = clib_host_to_net_u64 (0xaa00000000000000),
          [1] = clib_host_to_net_u64 (0x0000000000000001),
        },
      },
      .dst_address = {
        .as_u64 = {
          [0] = clib_host_to_net_u64 (0xab00000000000000),
          [1] = clib_host_to_net_u64 (0x0000000000000001),
        },
      },
    },
    .ch6_l4 = {
      .src_port = clib_host_to_net_u16 ((u16)25),
      .dst_port = clib_host_to_net_u16 ((u16)3000),
    },
  };
  /* *INDENT-ON* */

  conni = conn_track_ip6_find (cdbi, thread_index, &hdr.ch6_ip,
			       &chash, vlib_time_now (vm));
  CONN_TEST (INDEX_INVALID == conni, "%d first conn not found");

  // add the number of supported connections
  for (ii = 0; ii <= N_CONNS; ii++)
    {
      hdr.ch6_l4.dst_port = clib_host_to_net_u16 ((u16) ii);

      conni = conn_track_ip6_add (cdbi, thread_index, owner1,
				  &hdr.ch6_ip, chash, vlib_time_now (vm));
      CONN_TEST (INDEX_INVALID != conni, "%d conn added", ii);
    }

  // send pakets to match conn ports=1-3
  for (ii = 1; ii < 4; ii++)
    {
      hdr.ch6_l4.dst_port = clib_host_to_net_u16 ((u16) ii);
      for (jj = 0; jj < 8; jj++)
	{
	  conni = conn_track_ip6_find (cdbi, thread_index,
				       &hdr.ch6_ip, &chash,
				       vlib_time_now (vm));
	  CONN_TEST (INDEX_INVALID != conni, "%d conn added", ii);
	}
    }

  // conn/port 0 should be at the top of the sieve
  // so that wehn we add the next port, it's the one that is reused
  hdr.ch6_l4.dst_port = clib_host_to_net_u16 ((u16) 4);

  conni = conn_track_ip6_add (cdbi, thread_index, owner1,
			      &hdr.ch6_ip, chash, vlib_time_now (vm));
  CONN_TEST (INDEX_INVALID != conni, "%d conn added", 4);

  for (ii = 1; ii < 5; ii++)
    {
      hdr.ch6_l4.dst_port = clib_host_to_net_u16 ((u16) ii);
      conni = conn_track_ip6_find (cdbi, thread_index,
				   &hdr.ch6_ip, &chash, vlib_time_now (vm));
      CONN_TEST (INDEX_INVALID != conni, "%d conn added", ii);
    }

  // send pakets to match conn ports=2-4
  for (ii = 2; ii <= 4; ii++)
    {
      hdr.ch6_l4.dst_port = clib_host_to_net_u16 ((u16) ii);
      for (jj = 0; jj < 8; jj++)
	{
	  conni = conn_track_ip6_find (cdbi, thread_index,
				       &hdr.ch6_ip, &chash,
				       vlib_time_now (vm));
	  CONN_TEST (INDEX_INVALID != conni, "%d conn added", ii);
	}
    }

  // conn/port 1 should be at the top of the sieve
  // so that wehn we add the next port, it's the one that is reused
  hdr.ch6_l4.dst_port = clib_host_to_net_u16 ((u16) 5);

  conni = conn_track_ip6_add (cdbi, thread_index, owner1,
			      &hdr.ch6_ip, chash, vlib_time_now (vm));
  CONN_TEST (INDEX_INVALID != conni, "%d conn added", 5);

  for (ii = 0; ii <= 1; ii++)
    {
      hdr.ch6_l4.dst_port = clib_host_to_net_u16 ((u16) ii);
      conni = conn_track_ip6_find (cdbi, thread_index,
				   &hdr.ch6_ip, &chash, vlib_time_now (vm));
      CONN_TEST (INDEX_INVALID == conni, "%d conn added", ii);
    }
  for (ii = 2; ii <= 5; ii++)
    {
      hdr.ch6_l4.dst_port = clib_host_to_net_u16 ((u16) ii);
      conni = conn_track_ip6_find (cdbi, thread_index,
				   &hdr.ch6_ip, &chash, vlib_time_now (vm));
      CONN_TEST (INDEX_INVALID != conni, "%d conn added", ii);
    }


  vlib_cli_output (vm, "%U", format_conn_db, cdbi, 2);

  // cleanup - no flush
  conn_db_unlock (&cdbi);

  return (res);
}

static clib_error_t *
conn_test (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  conn_user_t cu;
  int res;

  if (unformat (input, "debug"))
    conn_test_do_debug = 1;

  cu = conn_track_user_add ("test");

  res = conn_test_ip4 (vm, cu);
  res |= conn_test_ip6 (vm, cu);

  // check for leaks
  if (0 != pool_elts (conn_db_pool))
    return clib_error_return (0, "Conn Unit Test Failed - memory leak");

  if (res)
    return clib_error_return (0, "Conn Unit Test Failed");
  else
    return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_conn_command, static) =
{
  .path = "test conntrack",
  .short_help = "conntrack unit tests",
  .function = conn_test,
};
/* *INDENT-ON* */

clib_error_t *
conn_test_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (conn_test_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
