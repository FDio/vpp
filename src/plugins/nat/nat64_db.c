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
#include <nat/nat64_db.h>
#include <nat/nat_ipfix_logging.h>
#include <nat/nat_inlines.h>
#include <vnet/fib/fib_table.h>

int
nat64_db_init (nat64_db_t * db, u32 bib_buckets, u32 bib_memory_size,
	       u32 st_buckets, u32 st_memory_size,
	       nat64_db_free_addr_port_function_t free_addr_port_cb)
{
  clib_bihash_init_24_8 (&db->bib.in2out, "bib-in2out", bib_buckets,
			 bib_memory_size);

  clib_bihash_init_24_8 (&db->bib.out2in, "bib-out2in", bib_buckets,
			 bib_memory_size);

  clib_bihash_init_48_8 (&db->st.in2out, "st-in2out", st_buckets,
			 st_memory_size);

  clib_bihash_init_48_8 (&db->st.out2in, "st-out2in", st_buckets,
			 st_memory_size);

  db->free_addr_port_cb = free_addr_port_cb;
  db->bib.limit = 10 * bib_buckets;
  db->bib.bib_entries_num = 0;
  db->st.limit = 10 * st_buckets;
  db->st.st_entries_num = 0;
  db->addr_free = 0;

  return 0;
}

nat64_db_bib_entry_t *
nat64_db_bib_entry_create (nat64_db_t * db, ip6_address_t * in_addr,
			   ip4_address_t * out_addr, u16 in_port,
			   u16 out_port, u32 fib_index, u8 proto,
			   u8 is_static)
{
  nat64_db_bib_entry_t *bibe;
  nat64_db_bib_entry_key_t bibe_key;
  clib_bihash_kv_24_8_t kv;
  fib_table_t *fib;

  if (db->bib.bib_entries_num >= db->bib.limit)
    {
      db->free_addr_port_cb (db, out_addr, out_port, proto);
      nat_ipfix_logging_max_bibs (db->bib.limit);
      return 0;
    }

  /* create pool entry */
  switch (ip_proto_to_snat_proto (proto))
    {
/* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      pool_get (db->bib._##n##_bib, bibe); \
      kv.value = bibe - db->bib._##n##_bib; \
      break;
      foreach_snat_protocol
#undef _
/* *INDENT-ON* */
    default:
      pool_get (db->bib._unk_proto_bib, bibe);
      kv.value = bibe - db->bib._unk_proto_bib;
      break;
    }

  db->bib.bib_entries_num++;

  clib_memset (bibe, 0, sizeof (*bibe));
  bibe->in_addr.as_u64[0] = in_addr->as_u64[0];
  bibe->in_addr.as_u64[1] = in_addr->as_u64[1];
  bibe->in_port = in_port;
  bibe->out_addr.as_u32 = out_addr->as_u32;
  bibe->out_port = out_port;
  bibe->fib_index = fib_index;
  bibe->proto = proto;
  bibe->is_static = is_static;

  /* create hash lookup */
  bibe_key.addr.as_u64[0] = bibe->in_addr.as_u64[0];
  bibe_key.addr.as_u64[1] = bibe->in_addr.as_u64[1];
  bibe_key.fib_index = bibe->fib_index;
  bibe_key.port = bibe->in_port;
  bibe_key.proto = bibe->proto;
  bibe_key.rsvd = 0;
  kv.key[0] = bibe_key.as_u64[0];
  kv.key[1] = bibe_key.as_u64[1];
  kv.key[2] = bibe_key.as_u64[2];
  clib_bihash_add_del_24_8 (&db->bib.in2out, &kv, 1);

  clib_memset (&bibe_key.addr, 0, sizeof (bibe_key.addr));
  bibe_key.addr.ip4.as_u32 = bibe->out_addr.as_u32;
  bibe_key.fib_index = 0;
  bibe_key.port = bibe->out_port;
  kv.key[0] = bibe_key.as_u64[0];
  kv.key[1] = bibe_key.as_u64[1];
  kv.key[2] = bibe_key.as_u64[2];
  clib_bihash_add_del_24_8 (&db->bib.out2in, &kv, 1);

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  nat_ipfix_logging_nat64_bib (in_addr, out_addr, proto, in_port, out_port,
			       fib->ft_table_id, 1);
  return bibe;
}

void
nat64_db_bib_entry_free (nat64_db_t * db, nat64_db_bib_entry_t * bibe)
{
  nat64_db_bib_entry_key_t bibe_key;
  clib_bihash_kv_24_8_t kv;
  nat64_db_bib_entry_t *bib;
  u32 *ste_to_be_free = 0, *ste_index, bibe_index;
  nat64_db_st_entry_t *st, *ste;
  fib_table_t *fib;

  switch (ip_proto_to_snat_proto (bibe->proto))
    {
/* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      bib = db->bib._##n##_bib; \
      st = db->st._##n##_st; \
      break;
      foreach_snat_protocol
#undef _
/* *INDENT-ON* */
    default:
      bib = db->bib._unk_proto_bib;
      st = db->st._unk_proto_st;
      break;
    }

  db->bib.bib_entries_num--;

  bibe_index = bibe - bib;

  /* delete ST entries for static BIB entry */
  if (bibe->is_static)
    {
      pool_foreach (ste, st, (
			       {
			       if (ste->bibe_index == bibe_index)
			       vec_add1 (ste_to_be_free, ste - st);}
		    ));
      vec_foreach (ste_index, ste_to_be_free)
	nat64_db_st_entry_free (db, pool_elt_at_index (st, ste_index[0]));
      vec_free (ste_to_be_free);
    }

  /* delete hash lookup */
  bibe_key.addr.as_u64[0] = bibe->in_addr.as_u64[0];
  bibe_key.addr.as_u64[1] = bibe->in_addr.as_u64[1];
  bibe_key.fib_index = bibe->fib_index;
  bibe_key.port = bibe->in_port;
  bibe_key.proto = bibe->proto;
  bibe_key.rsvd = 0;
  kv.key[0] = bibe_key.as_u64[0];
  kv.key[1] = bibe_key.as_u64[1];
  kv.key[2] = bibe_key.as_u64[2];
  clib_bihash_add_del_24_8 (&db->bib.in2out, &kv, 0);

  clib_memset (&bibe_key.addr, 0, sizeof (bibe_key.addr));
  bibe_key.addr.ip4.as_u32 = bibe->out_addr.as_u32;
  bibe_key.fib_index = 0;
  bibe_key.port = bibe->out_port;
  kv.key[0] = bibe_key.as_u64[0];
  kv.key[1] = bibe_key.as_u64[1];
  kv.key[2] = bibe_key.as_u64[2];
  clib_bihash_add_del_24_8 (&db->bib.out2in, &kv, 0);

  if (!db->addr_free)
    db->free_addr_port_cb (db, &bibe->out_addr, bibe->out_port, bibe->proto);

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  nat_ipfix_logging_nat64_bib (&bibe->in_addr, &bibe->out_addr, bibe->proto,
			       bibe->in_port, bibe->out_port,
			       fib->ft_table_id, 0);

  /* delete from pool */
  pool_put (bib, bibe);

}

nat64_db_bib_entry_t *
nat64_db_bib_entry_find (nat64_db_t * db, ip46_address_t * addr, u16 port,
			 u8 proto, u32 fib_index, u8 is_ip6)
{
  nat64_db_bib_entry_t *bibe = 0;
  nat64_db_bib_entry_key_t bibe_key;
  clib_bihash_kv_24_8_t kv, value;
  nat64_db_bib_entry_t *bib;

  switch (ip_proto_to_snat_proto (proto))
    {
/* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      bib = db->bib._##n##_bib; \
      break;
      foreach_snat_protocol
#undef _
/* *INDENT-ON* */
    default:
      bib = db->bib._unk_proto_bib;
      break;
    }

  bibe_key.addr.as_u64[0] = addr->as_u64[0];
  bibe_key.addr.as_u64[1] = addr->as_u64[1];
  bibe_key.fib_index = fib_index;
  bibe_key.port = port;
  bibe_key.proto = proto;
  bibe_key.rsvd = 0;

  kv.key[0] = bibe_key.as_u64[0];
  kv.key[1] = bibe_key.as_u64[1];
  kv.key[2] = bibe_key.as_u64[2];

  if (!clib_bihash_search_24_8
      (is_ip6 ? &db->bib.in2out : &db->bib.out2in, &kv, &value))
    bibe = pool_elt_at_index (bib, value.value);

  return bibe;
}

void
nat64_db_bib_walk (nat64_db_t * db, u8 proto,
		   nat64_db_bib_walk_fn_t fn, void *ctx)
{
  nat64_db_bib_entry_t *bib, *bibe;

  if (proto == 255)
    {
    /* *INDENT-OFF* */
    #define _(N, i, n, s) \
      bib = db->bib._##n##_bib; \
      pool_foreach (bibe, bib, ({ \
        if (fn (bibe, ctx)) \
          return; \
      }));
      foreach_snat_protocol
    #undef _
      bib = db->bib._unk_proto_bib;
      pool_foreach (bibe, bib, ({
        if (fn (bibe, ctx))
          return;
      }));
    /* *INDENT-ON* */
    }
  else
    {
      switch (ip_proto_to_snat_proto (proto))
	{
    /* *INDENT-OFF* */
    #define _(N, i, n, s) \
        case SNAT_PROTOCOL_##N: \
          bib = db->bib._##n##_bib; \
          break;
          foreach_snat_protocol
    #undef _
    /* *INDENT-ON* */
	default:
	  bib = db->bib._unk_proto_bib;
	  break;
	}

      /* *INDENT-OFF* */
      pool_foreach (bibe, bib,
      ({
        if (fn (bibe, ctx))
          return;
      }));
      /* *INDENT-ON* */
    }
}

nat64_db_bib_entry_t *
nat64_db_bib_entry_by_index (nat64_db_t * db, u8 proto, u32 bibe_index)
{
  nat64_db_bib_entry_t *bib;

  switch (ip_proto_to_snat_proto (proto))
    {
/* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      bib = db->bib._##n##_bib; \
      break;
      foreach_snat_protocol
#undef _
/* *INDENT-ON* */
    default:
      bib = db->bib._unk_proto_bib;
      break;
    }

  return pool_elt_at_index (bib, bibe_index);
}

void
nat64_db_st_walk (nat64_db_t * db, u8 proto,
		  nat64_db_st_walk_fn_t fn, void *ctx)
{
  nat64_db_st_entry_t *st, *ste;

  if (proto == 255)
    {
    /* *INDENT-OFF* */
    #define _(N, i, n, s) \
      st = db->st._##n##_st; \
      pool_foreach (ste, st, ({ \
        if (fn (ste, ctx)) \
          return; \
      }));
      foreach_snat_protocol
    #undef _
      st = db->st._unk_proto_st;
      pool_foreach (ste, st, ({
        if (fn (ste, ctx))
          return;
      }));
    /* *INDENT-ON* */
    }
  else
    {
      switch (ip_proto_to_snat_proto (proto))
	{
    /* *INDENT-OFF* */
    #define _(N, i, n, s) \
        case SNAT_PROTOCOL_##N: \
          st = db->st._##n##_st; \
          break;
          foreach_snat_protocol
    #undef _
    /* *INDENT-ON* */
	default:
	  st = db->st._unk_proto_st;
	  break;
	}

      /* *INDENT-OFF* */
      pool_foreach (ste, st,
      ({
        if (fn (ste, ctx))
          return;
      }));
      /* *INDENT-ON* */
    }
}

nat64_db_st_entry_t *
nat64_db_st_entry_create (nat64_db_t * db, nat64_db_bib_entry_t * bibe,
			  ip6_address_t * in_r_addr,
			  ip4_address_t * out_r_addr, u16 r_port)
{
  nat64_db_st_entry_t *ste;
  nat64_db_bib_entry_t *bib;
  nat64_db_st_entry_key_t ste_key;
  clib_bihash_kv_48_8_t kv;
  fib_table_t *fib;

  if (db->st.st_entries_num >= db->st.limit)
    {
      nat_ipfix_logging_max_sessions (db->st.limit);
      return 0;
    }

  /* create pool entry */
  switch (ip_proto_to_snat_proto (bibe->proto))
    {
/* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      pool_get (db->st._##n##_st, ste); \
      kv.value = ste - db->st._##n##_st; \
      bib = db->bib._##n##_bib; \
      break;
      foreach_snat_protocol
#undef _
/* *INDENT-ON* */
    default:
      pool_get (db->st._unk_proto_st, ste);
      kv.value = ste - db->st._unk_proto_st;
      bib = db->bib._unk_proto_bib;
      break;
    }

  db->st.st_entries_num++;

  clib_memset (ste, 0, sizeof (*ste));
  ste->in_r_addr.as_u64[0] = in_r_addr->as_u64[0];
  ste->in_r_addr.as_u64[1] = in_r_addr->as_u64[1];
  ste->out_r_addr.as_u32 = out_r_addr->as_u32;
  ste->r_port = r_port;
  ste->bibe_index = bibe - bib;
  ste->proto = bibe->proto;

  /* increment session number for BIB entry */
  bibe->ses_num++;

  /* create hash lookup */
  clib_memset (&ste_key, 0, sizeof (ste_key));
  ste_key.l_addr.as_u64[0] = bibe->in_addr.as_u64[0];
  ste_key.l_addr.as_u64[1] = bibe->in_addr.as_u64[1];
  ste_key.r_addr.as_u64[0] = ste->in_r_addr.as_u64[0];
  ste_key.r_addr.as_u64[1] = ste->in_r_addr.as_u64[1];
  ste_key.fib_index = bibe->fib_index;
  ste_key.l_port = bibe->in_port;
  ste_key.r_port = ste->r_port;
  ste_key.proto = ste->proto;
  kv.key[0] = ste_key.as_u64[0];
  kv.key[1] = ste_key.as_u64[1];
  kv.key[2] = ste_key.as_u64[2];
  kv.key[3] = ste_key.as_u64[3];
  kv.key[4] = ste_key.as_u64[4];
  kv.key[5] = ste_key.as_u64[5];
  clib_bihash_add_del_48_8 (&db->st.in2out, &kv, 1);

  clib_memset (&ste_key, 0, sizeof (ste_key));
  ste_key.l_addr.ip4.as_u32 = bibe->out_addr.as_u32;
  ste_key.r_addr.ip4.as_u32 = ste->out_r_addr.as_u32;
  ste_key.l_port = bibe->out_port;
  ste_key.r_port = ste->r_port;
  ste_key.proto = ste->proto;
  kv.key[0] = ste_key.as_u64[0];
  kv.key[1] = ste_key.as_u64[1];
  kv.key[2] = ste_key.as_u64[2];
  kv.key[3] = ste_key.as_u64[3];
  kv.key[4] = ste_key.as_u64[4];
  kv.key[5] = ste_key.as_u64[5];
  clib_bihash_add_del_48_8 (&db->st.out2in, &kv, 1);

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  nat_ipfix_logging_nat64_session (&bibe->in_addr, &bibe->out_addr,
				   bibe->proto, bibe->in_port, bibe->out_port,
				   &ste->in_r_addr, &ste->out_r_addr,
				   ste->r_port, ste->r_port, fib->ft_table_id,
				   1);

  return ste;
}

void
nat64_db_st_entry_free (nat64_db_t * db, nat64_db_st_entry_t * ste)
{
  nat64_db_st_entry_t *st;
  nat64_db_bib_entry_t *bib, *bibe;
  nat64_db_st_entry_key_t ste_key;
  clib_bihash_kv_48_8_t kv;
  fib_table_t *fib;

  switch (ip_proto_to_snat_proto (ste->proto))
    {
/* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      st = db->st._##n##_st; \
      bib = db->bib._##n##_bib; \
      break;
      foreach_snat_protocol
#undef _
/* *INDENT-ON* */
    default:
      st = db->st._unk_proto_st;
      bib = db->bib._unk_proto_bib;
      break;
    }

  bibe = pool_elt_at_index (bib, ste->bibe_index);

  db->st.st_entries_num--;

  /* delete hash lookup */
  clib_memset (&ste_key, 0, sizeof (ste_key));
  ste_key.l_addr.as_u64[0] = bibe->in_addr.as_u64[0];
  ste_key.l_addr.as_u64[1] = bibe->in_addr.as_u64[1];
  ste_key.r_addr.as_u64[0] = ste->in_r_addr.as_u64[0];
  ste_key.r_addr.as_u64[1] = ste->in_r_addr.as_u64[1];
  ste_key.fib_index = bibe->fib_index;
  ste_key.l_port = bibe->in_port;
  ste_key.r_port = ste->r_port;
  ste_key.proto = ste->proto;
  kv.key[0] = ste_key.as_u64[0];
  kv.key[1] = ste_key.as_u64[1];
  kv.key[2] = ste_key.as_u64[2];
  kv.key[3] = ste_key.as_u64[3];
  kv.key[4] = ste_key.as_u64[4];
  kv.key[5] = ste_key.as_u64[5];
  clib_bihash_add_del_48_8 (&db->st.in2out, &kv, 0);

  clib_memset (&ste_key, 0, sizeof (ste_key));
  ste_key.l_addr.ip4.as_u32 = bibe->out_addr.as_u32;
  ste_key.r_addr.ip4.as_u32 = ste->out_r_addr.as_u32;
  ste_key.l_port = bibe->out_port;
  ste_key.r_port = ste->r_port;
  ste_key.proto = ste->proto;
  kv.key[0] = ste_key.as_u64[0];
  kv.key[1] = ste_key.as_u64[1];
  kv.key[2] = ste_key.as_u64[2];
  kv.key[3] = ste_key.as_u64[3];
  kv.key[4] = ste_key.as_u64[4];
  kv.key[5] = ste_key.as_u64[5];
  clib_bihash_add_del_48_8 (&db->st.out2in, &kv, 0);

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  nat_ipfix_logging_nat64_session (&bibe->in_addr, &bibe->out_addr,
				   bibe->proto, bibe->in_port, bibe->out_port,
				   &ste->in_r_addr, &ste->out_r_addr,
				   ste->r_port, ste->r_port, fib->ft_table_id,
				   0);

  /* delete from pool */
  pool_put (st, ste);

  /* decrement session number for BIB entry */
  bibe->ses_num--;

  /* delete BIB entry if last session and dynamic */
  if (!bibe->is_static && !bibe->ses_num)
    nat64_db_bib_entry_free (db, bibe);
}

nat64_db_st_entry_t *
nat64_db_st_entry_find (nat64_db_t * db, ip46_address_t * l_addr,
			ip46_address_t * r_addr, u16 l_port, u16 r_port,
			u8 proto, u32 fib_index, u8 is_ip6)
{
  nat64_db_st_entry_t *ste = 0;
  nat64_db_st_entry_t *st;
  nat64_db_st_entry_key_t ste_key;
  clib_bihash_kv_48_8_t kv, value;

  switch (ip_proto_to_snat_proto (proto))
    {
/* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      st = db->st._##n##_st; \
      break;
      foreach_snat_protocol
#undef _
/* *INDENT-ON* */
    default:
      st = db->st._unk_proto_st;
      break;
    }

  clib_memset (&ste_key, 0, sizeof (ste_key));
  ste_key.l_addr.as_u64[0] = l_addr->as_u64[0];
  ste_key.l_addr.as_u64[1] = l_addr->as_u64[1];
  ste_key.r_addr.as_u64[0] = r_addr->as_u64[0];
  ste_key.r_addr.as_u64[1] = r_addr->as_u64[1];
  ste_key.fib_index = fib_index;
  ste_key.l_port = l_port;
  ste_key.r_port = r_port;
  ste_key.proto = proto;
  kv.key[0] = ste_key.as_u64[0];
  kv.key[1] = ste_key.as_u64[1];
  kv.key[2] = ste_key.as_u64[2];
  kv.key[3] = ste_key.as_u64[3];
  kv.key[4] = ste_key.as_u64[4];
  kv.key[5] = ste_key.as_u64[5];

  if (!clib_bihash_search_48_8
      (is_ip6 ? &db->st.in2out : &db->st.out2in, &kv, &value))
    ste = pool_elt_at_index (st, value.value);

  return ste;
}

u32
nat64_db_st_entry_get_index (nat64_db_t * db, nat64_db_st_entry_t * ste)
{
  nat64_db_st_entry_t *st;

  switch (ip_proto_to_snat_proto (ste->proto))
    {
/* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      st = db->st._##n##_st; \
      break;
      foreach_snat_protocol
#undef _
/* *INDENT-ON* */
    default:
      st = db->st._unk_proto_st;
      return (u32) ~ 0;
    }

  return ste - st;
}

nat64_db_st_entry_t *
nat64_db_st_entry_by_index (nat64_db_t * db, u8 proto, u32 ste_index)
{
  nat64_db_st_entry_t *st;

  switch (ip_proto_to_snat_proto (proto))
    {
/* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      st = db->st._##n##_st; \
      break;
      foreach_snat_protocol
#undef _
/* *INDENT-ON* */
    default:
      st = db->st._unk_proto_st;
      break;
    }

  return pool_elt_at_index (st, ste_index);
}

void
nad64_db_st_free_expired (nat64_db_t * db, u32 now)
{
  u32 *ste_to_be_free = 0, *ste_index;
  nat64_db_st_entry_t *st, *ste;

/* *INDENT-OFF* */
#define _(N, i, n, s) \
  st = db->st._##n##_st; \
  pool_foreach (ste, st, ({\
    if (i == SNAT_PROTOCOL_TCP && !ste->tcp_state) \
      continue; \
    if (ste->expire < now) \
      vec_add1 (ste_to_be_free, ste - st); \
  })); \
  vec_foreach (ste_index, ste_to_be_free) \
    nat64_db_st_entry_free (db, pool_elt_at_index(st, ste_index[0])); \
  vec_free (ste_to_be_free); \
  ste_to_be_free = 0;
  foreach_snat_protocol
#undef _
  st = db->st._unk_proto_st;
  pool_foreach (ste, st, ({
    if (ste->expire < now)
      vec_add1 (ste_to_be_free, ste - st);
  }));
  vec_foreach (ste_index, ste_to_be_free)
    nat64_db_st_entry_free (db, pool_elt_at_index(st, ste_index[0]));
  vec_free (ste_to_be_free);
/* *INDENT-ON* */
}

void
nat64_db_free_out_addr (nat64_db_t * db, ip4_address_t * out_addr)
{
  u32 *ste_to_be_free = 0, *ste_index;
  nat64_db_st_entry_t *st, *ste;
  nat64_db_bib_entry_t *bibe;

  db->addr_free = 1;
/* *INDENT-OFF* */
#define _(N, i, n, s) \
  st = db->st._##n##_st; \
  pool_foreach (ste, st, ({ \
    bibe = pool_elt_at_index (db->bib._##n##_bib, ste->bibe_index); \
    if (bibe->out_addr.as_u32 == out_addr->as_u32) \
      vec_add1 (ste_to_be_free, ste - st); \
  })); \
  vec_foreach (ste_index, ste_to_be_free) \
    nat64_db_st_entry_free (db, pool_elt_at_index(st, ste_index[0])); \
  vec_free (ste_to_be_free); \
  ste_to_be_free = 0;
  foreach_snat_protocol
#undef _
  st = db->st._unk_proto_st;
  pool_foreach (ste, st, ({
    bibe = pool_elt_at_index (db->bib._unk_proto_bib, ste->bibe_index);
    if (bibe->out_addr.as_u32 == out_addr->as_u32)
      vec_add1 (ste_to_be_free, ste - st);
  }));
  vec_foreach (ste_index, ste_to_be_free)
    nat64_db_st_entry_free (db, pool_elt_at_index(st, ste_index[0]));
  vec_free (ste_to_be_free);
  db->addr_free = 0;
/* *INDENT-ON* */
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
