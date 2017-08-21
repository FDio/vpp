/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief NAT64 DB
 */
#ifndef __included_nat64_db_h__
#define __included_nat64_db_h__

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_48_8.h>
#include <nat/nat.h>


typedef struct
{
  union
  {
    struct
    {
      ip46_address_t addr;
      u32 fib_index;
      u16 port;
      u8 proto;
      u8 rsvd;
    };
    u64 as_u64[3];
  };
} nat64_db_bib_entry_key_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip6_address_t in_addr;
  u16 in_port;
  ip4_address_t out_addr;
  u16 out_port;
  u32 fib_index;
  u32 ses_num;
  u8 proto;
  u8 is_static;
}) nat64_db_bib_entry_t;
/* *INDENT-ON* */

typedef struct
{
  /* BIBs */
/* *INDENT-OFF* */
#define _(N, i, n, s) \
  nat64_db_bib_entry_t *_##n##_bib;
  foreach_snat_protocol
#undef _
/* *INDENT-ON* */
  nat64_db_bib_entry_t *_unk_proto_bib;

  /* BIB lookup */
  clib_bihash_24_8_t in2out;
  clib_bihash_24_8_t out2in;
} nat64_db_bib_t;

typedef struct
{
  union
  {
    struct
    {
      ip46_address_t l_addr;
      ip46_address_t r_addr;
      u32 fib_index;
      u16 l_port;
      u16 r_port;
      u8 proto;
      u8 rsvd[7];
    };
    u64 as_u64[6];
  };
} nat64_db_st_entry_key_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip6_address_t in_r_addr;
  ip4_address_t out_r_addr;
  u16 r_port;
  u32 bibe_index;
  u32 expire;
  u8 proto;
  u8 tcp_state;
}) nat64_db_st_entry_t;
/* *INDENT-ON* */

typedef struct
{
  /* session tables */
/* *INDENT-OFF* */
#define _(N, i, n, s) \
  nat64_db_st_entry_t *_##n##_st;
  foreach_snat_protocol
#undef _
/* *INDENT-ON* */
  nat64_db_st_entry_t *_unk_proto_st;

  /* session lookup */
  clib_bihash_48_8_t in2out;
  clib_bihash_48_8_t out2in;
} nat64_db_st_t;

typedef struct
{
  nat64_db_bib_t bib;
  nat64_db_st_t st;
} nat64_db_t;

/**
 * @brief Initialize NAT64 DB.
 *
 * @param db NAT64 DB.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_db_init (nat64_db_t * db);

/**
 * @brief Create new NAT64 BIB entry.
 *
 * @param db NAT64 DB.
 * @param in_addr Inside IPv6 address.
 * @param out_addr Outside IPv4 address.
 * @param in_port Inside port number.
 * @param out_port Outside port number.
 * @param fib_index FIB index.
 * @param proto L4 protocol.
 * @param is_static 1 if static, 0 if dynamic.
 *
 * @returns BIB entry on success, 0 otherwise.
 */
nat64_db_bib_entry_t *nat64_db_bib_entry_create (nat64_db_t * db,
						 ip6_address_t * in_addr,
						 ip4_address_t * out_addr,
						 u16 in_port, u16 out_port,
						 u32 fib_index,
						 u8 proto, u8 is_static);

/**
 * @brief Free NAT64 BIB entry.
 *
 * @param db NAT64 DB.
 * @param bibe BIB entry.
 */
void nat64_db_bib_entry_free (nat64_db_t * db, nat64_db_bib_entry_t * bibe);

/**
 * @brief Call back function when walking NAT64 BIB, non-zero
 * return value stop walk.
 */
typedef int (*nat64_db_bib_walk_fn_t) (nat64_db_bib_entry_t * bibe,
				       void *ctx);
/**
 * @brief Walk NAT64 BIB.
 *
 * @param db NAT64 DB.
 * @param proto BIB L4 protocol:
 *  - 255 all BIBs
 *  - 6 TCP BIB
 *  - 17 UDP BIB
 *  - 1/58 ICMP BIB
 *  - otherwise "unknown" protocol BIB
 * @param fn The function to invoke on each entry visited.
 * @param ctx A context passed in the visit function.
 */
void nat64_db_bib_walk (nat64_db_t * db, u8 proto,
			nat64_db_bib_walk_fn_t fn, void *ctx);

/**
 * @brief Find NAT64 BIB entry.
 *
 * @param db NAT64 DB.
 * @param addr IP address.
 * @param port Port number.
 * @param proto L4 protocol.
 * @param fib_index FIB index.
 * @param is_ip6 1 if find by IPv6 (inside) address, 0 by IPv4 (outside).
 *
 * @return BIB entry if found.
 */
nat64_db_bib_entry_t *nat64_db_bib_entry_find (nat64_db_t * db,
					       ip46_address_t * addr,
					       u16 port,
					       u8 proto,
					       u32 fib_index, u8 is_ip6);

/**
 * @brief Get BIB entry by index and protocol.
 *
 * @param db NAT64 DB.
 * @param proto L4 protocol.
 * @param bibe_index BIB entry index.
 *
 * @return BIB entry if found.
 */
nat64_db_bib_entry_t *nat64_db_bib_entry_by_index (nat64_db_t * db,
						   u8 proto, u32 bibe_index);
/**
 * @brief Create new NAT64 session table entry.
 *
 * @param db NAT64 DB.
 * @param bibe Corresponding BIB entry.
 * @param in_r_addr Inside IPv6 address of the remote host.
 * @param out_r_addr Outside IPv4 address of the remote host.
 * @param r_port Remote host port number.
 *
 * @returns BIB entry on success, 0 otherwise.
 */
nat64_db_st_entry_t *nat64_db_st_entry_create (nat64_db_t * db,
					       nat64_db_bib_entry_t * bibe,
					       ip6_address_t * in_r_addr,
					       ip4_address_t * out_r_addr,
					       u16 r_port);

/**
 * @brief Free NAT64 session table entry.
 *
 * @param db NAT64 DB.
 * @param ste Session table entry.
 */
void nat64_db_st_entry_free (nat64_db_t * db, nat64_db_st_entry_t * ste);

/**
 * @brief Find NAT64 session table entry.
 *
 * @param db NAT64 DB.
 * @param l_addr Local host address.
 * @param r_addr Remote host address.
 * @param l_port Local host port number.
 * @param r_port Remote host port number.
 * @param proto L4 protocol.
 * @param fib_index FIB index.
 * @param is_ip6 1 if find by IPv6 (inside) address, 0 by IPv4 (outside).
 *
 * @return BIB entry if found.
 */
nat64_db_st_entry_t *nat64_db_st_entry_find (nat64_db_t * db,
					     ip46_address_t * l_addr,
					     ip46_address_t * r_addr,
					     u16 l_port, u16 r_port,
					     u8 proto,
					     u32 fib_index, u8 is_ip6);

/**
 * @brief Call back function when walking NAT64 session table, non-zero
 * return value stop walk.
 */
typedef int (*nat64_db_st_walk_fn_t) (nat64_db_st_entry_t * ste, void *ctx);

/**
 * @brief Walk NAT64 session table.
 *
 * @param db NAT64 DB.
 * @param proto L4 protocol:
 *  - 255 all session tables
 *  - 6 TCP session table
 *  - 17 UDP session table
 *  - 1/58 ICMP session table
 *  - otherwise "unknown" protocol session table
 * @param fn The function to invoke on each entry visited.
 * @param ctx A context passed in the visit function.
 */
void nat64_db_st_walk (nat64_db_t * db, u8 proto,
		       nat64_db_st_walk_fn_t fn, void *ctx);

/**
 * @brief Free expired session entries in session tables.
 *
 * @param db NAT64 DB.
 * @param now Current time.
 */
void nad64_db_st_free_expired (nat64_db_t * db, u32 now);

/**
 * @brief Free sessions using specific outside address.
 *
 * @param db NAT64 DB.
 * @param out_addr Outside address to match.
 */
void nat64_db_free_out_addr (nat64_db_t * db, ip4_address_t * out_addr);

#endif /* __included_nat64_db_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
