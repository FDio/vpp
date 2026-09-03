/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/*
 * Unit tests for the TEIB in-process consumer API.
 *
 * Overlay interfaces and the next-hop table are created by the python driver and
 * handed in as arguments rather than built here.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/teib/teib.h>
#include <vnet/fib/fib_table.h>

#define TEIB_TEST_I(_cond, _comment, _args...)                                                     \
  ({                                                                                               \
    int _evald = (_cond);                                                                          \
    if (!(_evald))                                                                                 \
      {                                                                                            \
	fformat (stderr, "FAIL:%d: " _comment "\n", __LINE__, ##_args);                            \
	res = 1;                                                                                   \
      }                                                                                            \
    res;                                                                                           \
  })

/* An address in an interface's own subnet, as the peers the python driver adds
 * are. The driver configures 172.16.<sw_if_index>.1/24 and hands .2 and .3 to
 * remote hosts, so the hosts here are taken from the top of the subnet. Only
 * the last octet is replaced, so this needs the prefix to be no longer than a
 * /24. */
static void
teib_test_mk_peer (u32 sw_if_index, u8 host, ip_address_t *peer)
{
  ip4_address_t v4 = *ip4_interface_first_address (&ip4_main, sw_if_index, 0);

  v4.as_u8[3] = host;

  clib_memset (peer, 0, sizeof (*peer));
  ip_address_set (peer, &v4, AF_IP4);
}

/* the IPv6 counterpart; the driver configures fd01:<sw_if_index>::1/64. Not a
 * link-local address: those take a different path out of TEIB, into the
 * ip6-ll table, which is not what the cases below are about. */
static void
teib_test_mk_peer6 (u32 sw_if_index, u8 host, ip_address_t *peer)
{
  ip6_address_t v6 = *ip6_interface_first_address (&ip6_main, sw_if_index);

  v6.as_u8[15] = host;

  clib_memset (peer, 0, sizeof (*peer));
  ip_address_set (peer, &v6, AF_IP6);
}

/*
 * teib_entry_find() and each of the entry's four accessors.
 *
 * The next-hop goes into a non-default table, because a lost FIB index would
 * still be right by accident for the default one.
 */
static int
teib_test_find_hit_miss (u32 sw_if_index, u32 nh_table_id)
{
  /* the next-hop is in the underlay, so it needs no relation to the overlay
   * interface and does not have to be routable */
  ip4_address_t v4_nh = { .as_u32 = clib_host_to_net_u32 (0x0a630001) }; /* 10.99.0.1 */
  ip_address_t peer, absent, nh;
  const teib_entry_t *te;
  bool added = false;
  fib_prefix_t got;
  u32 nh_fib_index;
  int res = 0;

  teib_test_mk_peer (sw_if_index, 128, &peer);
  teib_test_mk_peer (sw_if_index, 129, &absent);
  ip_address_set (&nh, &v4_nh, AF_IP4);

  nh_fib_index = fib_table_find (FIB_PROTOCOL_IP4, nh_table_id);

  if (0 != teib_entry_add (sw_if_index, &peer, nh_table_id, &nh))
    {
      TEIB_TEST_I (0, "add an entry");
      goto done;
    }
  added = true;

  te = teib_entry_find (sw_if_index, &peer);
  if (NULL == te)
    {
      TEIB_TEST_I (0, "find hits the entry that was added");
      goto done;
    }

  /* the next-hop comes back as a prefix; ip4_address_compare() takes it
   * without a const, so read the snapshot into a value */
  got = *teib_entry_get_nh (te);

  TEIB_TEST_I (sw_if_index == teib_entry_get_sw_if_index (te), "hit's interface");
  TEIB_TEST_I (0 == ip_address_cmp (&peer, teib_entry_get_peer (te)), "hit's peer");
  TEIB_TEST_I (FIB_PROTOCOL_IP4 == got.fp_proto, "hit's next-hop protocol");
  TEIB_TEST_I (32 == got.fp_len, "hit's next-hop prefix length");
  TEIB_TEST_I (0 == ip4_address_compare (&got.fp_addr.ip4, &v4_nh), "hit's next-hop address");
  TEIB_TEST_I (nh_fib_index == teib_entry_get_fib_index (te), "hit's next-hop FIB index");
  TEIB_TEST_I (fib_table_find (FIB_PROTOCOL_IP4, 0) != teib_entry_get_fib_index (te),
	       "hit's next-hop FIB index is not the default table's");

  /* another peer on the same interface is a miss */
  TEIB_TEST_I (NULL == teib_entry_find (sw_if_index, &absent), "miss on a peer never added");

  /* and deleting the entry turns the hit into a miss */
  if (0 != teib_entry_del (sw_if_index, &peer))
    {
      TEIB_TEST_I (0, "delete the entry");
      goto done;
    }
  added = false;

  TEIB_TEST_I (NULL == teib_entry_find (sw_if_index, &peer), "miss on a peer that was deleted");

done:
  if (added)
    teib_entry_del (sw_if_index, &peer);

  return (res);
}

typedef struct teib_test_walk_ctx_t_
{
  /** the interface being walked */
  u32 sw_if_index;
  u32 n_visited;
  /** visits of an entry that is not on the interface being walked */
  u32 n_other_itf;
} teib_test_walk_ctx_t;

static walk_rc_t
teib_test_walk_one (index_t tei, void *arg)
{
  teib_test_walk_ctx_t *ctx = arg;

  ctx->n_visited++;

  if (ctx->sw_if_index != teib_entry_get_sw_if_index (teib_entry_get (tei)))
    ctx->n_other_itf++;

  return (WALK_CONTINUE);
}

static void
teib_test_walk (u32 sw_if_index, teib_test_walk_ctx_t *ctx)
{
  clib_memset (ctx, 0, sizeof (*ctx));
  ctx->sw_if_index = sw_if_index;

  teib_walk_itf (sw_if_index, teib_test_walk_one, ctx);
}

/*
 * teib_walk_itf() visits the entries on one interface and no others.
 *
 * The counting happens in the caller's own context, so a walk that dropped the
 * context on the way to the callback would leave the counts at zero.
 */
static int
teib_test_walk_itf (u32 sw_if_index1, u32 sw_if_index2, u32 nh_table_id)
{
  ip4_address_t v4_nh = { .as_u32 = clib_host_to_net_u32 (0x0a630001) }; /* 10.99.0.1 */
  struct
  {
    u32 sw_if_index;
    ip_address_t peer;
  } entries[3];
  teib_test_walk_ctx_t ctx1, ctx2;
  u32 i, n_added = 0;
  ip_address_t nh;
  int res = 0;

  /* two entries on one interface and one on the other, so that a walk which
   * did not filter would show up as a count and not just as a wrong entry */
  entries[0].sw_if_index = sw_if_index1;
  entries[1].sw_if_index = sw_if_index1;
  entries[2].sw_if_index = sw_if_index2;

  teib_test_mk_peer (sw_if_index1, 131, &entries[0].peer);
  teib_test_mk_peer (sw_if_index1, 132, &entries[1].peer);
  teib_test_mk_peer (sw_if_index2, 131, &entries[2].peer);

  ip_address_set (&nh, &v4_nh, AF_IP4);

  for (i = 0; i < ARRAY_LEN (entries); i++)
    {
      if (0 != teib_entry_add (entries[i].sw_if_index, &entries[i].peer, nh_table_id, &nh))
	{
	  TEIB_TEST_I (0, "add entry %d", i);
	  goto done;
	}
      n_added++;
    }

  teib_test_walk (sw_if_index1, &ctx1);
  teib_test_walk (sw_if_index2, &ctx2);

  TEIB_TEST_I (2 == ctx1.n_visited, "walk of the first interface visits its 2 entries, got %d",
	       ctx1.n_visited);
  TEIB_TEST_I (0 == ctx1.n_other_itf, "walk of the first interface visits nothing else");
  TEIB_TEST_I (1 == ctx2.n_visited, "walk of the second interface visits its 1 entry, got %d",
	       ctx2.n_visited);
  TEIB_TEST_I (0 == ctx2.n_other_itf, "walk of the second interface visits nothing else");

  /* and with the entries gone both walks visit nothing */
  while (n_added > 0)
    {
      n_added--;
      if (0 != teib_entry_del (entries[n_added].sw_if_index, &entries[n_added].peer))
	TEIB_TEST_I (0, "delete entry %d", n_added);
    }

  teib_test_walk (sw_if_index1, &ctx1);
  teib_test_walk (sw_if_index2, &ctx2);

  TEIB_TEST_I (0 == ctx1.n_visited, "walk of the first interface with no entries left");
  TEIB_TEST_I (0 == ctx2.n_visited, "walk of the second interface with no entries left");

done:
  while (n_added-- > 0)
    teib_entry_del (entries[n_added].sw_if_index, &entries[n_added].peer);

  return (res);
}

/*
 * teib_entry_find_46() finds an entry from a key in the ip46 form that the
 * tunnel consumers hold, for either address family.
 */
static int
teib_test_find_46 (u32 sw_if_index, u32 nh_table_id)
{
  ip4_address_t v4_nh = { .as_u32 = clib_host_to_net_u32 (0x0a630001) }; /* 10.99.0.1 */
  ip6_address_t v6_nh = { .as_u64 = { clib_host_to_net_u64 (0x20010db899000000),
				      clib_host_to_net_u64 (0x0000000000000001) } };
  ip_address_t peer4, peer6, absent, nh4, nh6;
  bool added4 = false, added6 = false;
  const teib_entry_t *te;
  ip46_address_t key;
  int res = 0;

  teib_test_mk_peer (sw_if_index, 133, &peer4);
  teib_test_mk_peer (sw_if_index, 134, &absent);
  teib_test_mk_peer6 (sw_if_index, 133, &peer6);

  ip_address_set (&nh4, &v4_nh, AF_IP4);
  ip_address_set (&nh6, &v6_nh, AF_IP6);

  if (0 != teib_entry_add (sw_if_index, &peer4, nh_table_id, &nh4))
    {
      TEIB_TEST_I (0, "add an entry with an IPv4 peer");
      goto done;
    }
  added4 = true;

  /* the next-hop's own family picks the table to resolve it in, and the driver
   * only makes a non-default table for IPv4, so this next-hop is in the
   * default one */
  if (0 != teib_entry_add (sw_if_index, &peer6, 0, &nh6))
    {
      TEIB_TEST_I (0, "add an entry with an IPv6 peer");
      goto done;
    }
  added6 = true;

  ip_address_to_46 (&peer4, &key);
  te = teib_entry_find_46 (sw_if_index, FIB_PROTOCOL_IP4, &key);
  if (NULL == te)
    TEIB_TEST_I (0, "find_46 hits the entry with an IPv4 peer");
  else
    {
      TEIB_TEST_I (sw_if_index == teib_entry_get_sw_if_index (te), "IPv4 hit's interface");
      TEIB_TEST_I (0 == ip_address_cmp (&peer4, teib_entry_get_peer (te)), "IPv4 hit's peer");
    }

  ip_address_to_46 (&peer6, &key);
  te = teib_entry_find_46 (sw_if_index, FIB_PROTOCOL_IP6, &key);
  if (NULL == te)
    TEIB_TEST_I (0, "find_46 hits the entry with an IPv6 peer");
  else
    {
      TEIB_TEST_I (sw_if_index == teib_entry_get_sw_if_index (te), "IPv6 hit's interface");
      TEIB_TEST_I (0 == ip_address_cmp (&peer6, teib_entry_get_peer (te)), "IPv6 hit's peer");
    }

  ip_address_to_46 (&absent, &key);
  TEIB_TEST_I (NULL == teib_entry_find_46 (sw_if_index, FIB_PROTOCOL_IP4, &key),
	       "find_46 misses a peer never added");

done:
  if (added4)
    teib_entry_del (sw_if_index, &peer4);
  if (added6)
    teib_entry_del (sw_if_index, &peer6);

  return (res);
}

static clib_error_t *
teib_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index1, sw_if_index2, nh_table_id;
  clib_error_t *error = NULL;
  int res = 0;

  sw_if_index1 = ~0;
  sw_if_index2 = ~0;
  nh_table_id = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "two interfaces required");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "nh-table-id %d", &nh_table_id))
	;
      /* the interfaces are positional, so each one only fills the next slot */
      else if (~0 == sw_if_index1 && unformat (line_input, "%U", unformat_vnet_sw_interface,
					       vnet_get_main (), &sw_if_index1))
	;
      else if (~0 == sw_if_index2 && unformat (line_input, "%U", unformat_vnet_sw_interface,
					       vnet_get_main (), &sw_if_index2))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index1 || ~0 == sw_if_index2)
    {
      error = clib_error_return (0, "two interfaces required");
      goto done;
    }

  /* the driver's job, not something under test: the cases derive their peers
   * from the interfaces' own addresses */
  if (NULL == ip4_interface_first_address (&ip4_main, sw_if_index1, 0) ||
      NULL == ip4_interface_first_address (&ip4_main, sw_if_index2, 0))
    {
      error = clib_error_return (0, "both interfaces need an IPv4 address");
      goto done;
    }
  if (NULL == ip6_interface_first_address (&ip6_main, sw_if_index1))
    {
      error = clib_error_return (0, "the first interface needs an IPv6 address");
      goto done;
    }

  /* the default table would make the checks on an entry's FIB index pass on a
   * zeroed field, so insist on a table that is neither default nor missing */
  if (0 == nh_table_id)
    {
      error = clib_error_return (0, "a non-default nh-table-id is required");
      goto done;
    }
  if (~0 == fib_table_find (FIB_PROTOCOL_IP4, nh_table_id))
    {
      error = clib_error_return (0, "no such IPv4 table %d", nh_table_id);
      goto done;
    }

  res += teib_test_find_hit_miss (sw_if_index1, nh_table_id);
  res += teib_test_walk_itf (sw_if_index1, sw_if_index2, nh_table_id);
  res += teib_test_find_46 (sw_if_index1, nh_table_id);

done:
  unformat_free (line_input);

  if (error)
    return error;

  fflush (NULL);

  if (res)
    return clib_error_return (0, "TEIB Unit Test Failed");

  return NULL;
}

VLIB_CLI_COMMAND (test_teib_command, static) = {
  .path = "test teib",
  .short_help = "test teib <interface-1> <interface-2> nh-table-id <ID> - "
		"teib unit tests - DO NOT RUN ON A LIVE SYSTEM",
  .function = teib_test,
};
