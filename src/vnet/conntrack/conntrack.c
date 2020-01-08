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

#include <vnet/udp/udp_packet.h>

static conn_user_t conn_user;

typedef struct conn_user_reg_t_
{
  const char *cur_name;
  conn_user_t cur_user;
} conn_user_reg_t;

static conn_user_reg_t *conn_user_regs;

typedef struct conn_db_db_key_t_
{
  union
  {
    struct
    {
      conn_user_t cddk_user;
      conn_db_id_t cddk_id;
    };
    u64 cddk_u64;
  };
} conn_db_db_key_t;

/* *INDENT-OFF* */
static const conn_hdr_ip4_t CONN_IP4_MASK = {
  .ch4_ip = {
    .src_address.as_u32 = 0xffffffff,
    .dst_address.as_u32 = 0xffffffff,
    .protocol = 0xff,
  },
  .ch4_l4 = {
    .src_port = 0xffff,
    .dst_port = 0xffff,
  },
};

static const conn_hdr_ip6_t CONN_IP6_MASK = {
  .ch6_ip = {
    .src_address = {
      .as_u64 = {
        [0] = 0xffffffffffffffff,
        [1] = 0xffffffffffffffff,
      },
    },
    .dst_address = {
      .as_u64 = {
        [0] = 0xffffffffffffffff,
        [1] = 0xffffffffffffffff,
      },
    },
    .protocol = 0xff,
  },
  .ch6_l4 = {
    .src_port = 0xffff,
    .dst_port = 0xffff,
  },
};
/* *INDENT-ON* */

static u8 *conn_masks[N_AF];

conn_db_t *conn_db_pool;

/* DB of all the conn DB - anything you can do i can do meta ...*/
static uword *conn_db_db;

static index_t
conn_db_db_find (conn_user_t user, conn_db_id_t id)
{
  uword *p;

  conn_db_db_key_t key = {
    .cddk_user = user,
    .cddk_id = id,
  };

  p = hash_get (conn_db_db, key.cddk_u64);

  if (p)
    return p[0];
  return (INDEX_INVALID);
}

static u32
conn_get_n_workers (void)
{
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();

  return (thread_main->n_vlib_mains);
}

static void
conn_age_sieve_init (conn_age_sieve_t * sieve,
		     conn_t * conn, u32 start, u32 n_conns)
{
  conn_age_sieve_bucket_t *bucket;
  u32 bi;

  vec_validate (sieve->cas_buckets, n_conns - 1);
  sieve->cas_size = n_conns;
  sieve->cas_mask = n_conns - 1;
  sieve->cas_head = sieve->cas_size - 1;
  sieve->cas_tail = 0;

  vec_foreach_index (bi, sieve->cas_buckets)
  {
    bucket = &sieve->cas_buckets[bi];
    bucket->casb_time = 0;
    bucket->casb_conn = start++;

    conn->c_sieve_slot = bi;
    conn++;
  }
}

static void
conn_age_sieve_destroy (conn_age_sieve_t * sieve)
{
  vec_free (sieve->cas_buckets);
}

u8 *
format_conn_dir (u8 * s, va_list * a)
{
  conn_dir_t dir = va_arg (*a, int);

  if (0)
    ;
#define _(a,b)                                  \
  else if (dir == CONN_DIR_##a)                 \
    s = format (s, "%s", b);
  foreach_conn_dir
#undef _
    return (s);
}

static u8 *
format_conn_hdr_ip4 (u8 * s, va_list * a)
{
  conn_hdr_ip4_t *hdr;

  hdr = va_arg (*a, conn_hdr_ip4_t *);

  s = format (s, "%U,%U %U %d,%d",
	      format_ip4_address, &hdr->ch4_ip.src_address,
	      format_ip4_address, &hdr->ch4_ip.dst_address,
	      format_ip_protocol, hdr->ch4_ip.protocol,
	      clib_host_to_net_u16 (hdr->ch4_l4.src_port),
	      clib_host_to_net_u16 (hdr->ch4_l4.dst_port));

  return (s);
}

static u8 *
format_conn_hdr_ip6 (u8 * s, va_list * a)
{
  conn_hdr_ip6_t *hdr;

  hdr = va_arg (*a, conn_hdr_ip6_t *);

  s = format (s, "%U,%U %U %d,%d",
	      format_ip6_address, &hdr->ch6_ip.src_address,
	      format_ip6_address, &hdr->ch6_ip.dst_address,
	      format_ip_protocol, hdr->ch6_ip.protocol,
	      clib_host_to_net_u16 (hdr->ch6_l4.src_port),
	      clib_host_to_net_u16 (hdr->ch6_l4.dst_port));

  return (s);
}

static u8 *
format_conn_flags (u8 * s, va_list * a)
{
  conn_flags_t conn_flags;

  conn_flags = va_arg (*a, conn_flags_t);

#define _(a,b,c)                                \
  if (conn_flags & CONN_FLAG_##a)               \
  s = format (s, "%s ", c);
  foreach_conn_flag
#undef _
    return (s);
}

static u8 *
format_conn (u8 * s, va_list * a)
{
  vnet_classify_table_t *vc_table;
  vnet_classify_entry_t *vc_entry;
  conn_db_t *conn_db;
  conn_dir_t dir;
  index_t conni;
  conn_t *conn;
  u32 indent;
  u64 hash;

  conn_db = va_arg (*a, conn_db_t *);
  conni = va_arg (*a, index_t);
  indent = va_arg (*a, u32);

  conn = conn_get (conn_db, conni);
  vc_table = vnet_classify_table_get (conn_db->cd_table);

  s = format (s, "[%d] slot:%d owner:%d flags:[%U]",
	      conni, conn->c_sieve_slot, conn->c_owner,
	      format_conn_flags, conn->c_flags);

  FOR_EACH_CONN_DIR (dir)
  {
    s = format (s, "\n%U%U: key:",
		format_white_space, indent + 2, format_conn_dir, dir);
    if (AF_IP4 == conn_db->cd_af)
      s = format (s, "[%U]", format_conn_hdr_ip4, &conn->c_keys[dir]);
    else
      s = format (s, "[%U]", format_conn_hdr_ip6, &conn->c_keys[dir]);

    hash = vnet_classify_hash_packet (vc_table, (u8 *) & conn->c_keys[dir]);
    vc_entry =
      vnet_classify_find_entry (vc_table, (u8 *) & conn->c_keys[dir], hash,
				0);

    s =
      format (s, " thread:%d last-seen:%0.4f", vc_entry->metadata,
	      vc_entry->last_heard);
  }
  return (s);
}

static u8 *
format_conn_age_sieve_bucket (u8 * s, va_list * a)
{
  conn_age_sieve_bucket_t *bucket;

  bucket = va_arg (*a, conn_age_sieve_bucket_t *);

  s = format (s, "%d, %0.5f", bucket->casb_conn, bucket->casb_time);

  return (s);
}

static u8 *
format_conn_age_sieve (u8 * s, va_list * a)
{
  conn_age_sieve_t *sieve;
  u32 indent, ii;

  sieve = va_arg (*a, conn_age_sieve_t *);
  indent = va_arg (*a, u32);

  s = format (s, "%Uhead:%d tail:%d size:%d",
	      format_white_space, indent,
	      sieve->cas_head, sieve->cas_tail, sieve->cas_size);
  vec_foreach_index (ii, sieve->cas_buckets)
  {
    if (!(ii % 8))
      s = format (s, "\n%U", format_white_space, indent);
    s =
      format (s, "[%U] ", format_conn_age_sieve_bucket,
	      &sieve->cas_buckets[ii]);
  }

  return (s);
}

static u32
conn_vnet_classifier_table_add (const void *mask,
				u32 n_sessions, uword user_ctx)
{
  vnet_classify_main_t *vcm = &vnet_classify_main;
  u32 memory_size = 2 << 22;
  u32 nbuckets;
  u32 table_index = ~0;

  memory_size = (n_sessions * 128 *
		 (sizeof (vnet_classify_entry_t) + vec_len (mask)));
  nbuckets = max_pow2 (n_sessions) * 2;

  /* *INDENT-OFF* */
  if (vnet_classify_add_del_table (vcm, mask, nbuckets, memory_size,
                                   // no skip, the packet's current needs to be in the
                                   // correct location.
                                   0,
				   vec_len(mask) / VNET_CLASSIFY_VECTOR_SIZE,
                                   // next_table_index,
                                   ~0,
				   // miss_next_index,
                                   0,
				   &table_index,
                                   CLASSIFY_FLAG_USE_CURR_DATA,
                                   //  offset
                                   0,
                                   // is_add,
				   1,
                                   // delete_chain
				   0))
    ASSERT (0);
  /* *INDENT-ON* */

  vnet_classify_table_t *vct;

  vct = pool_elt_at_index (vcm->tables, table_index);
  vct->user_ctx = user_ctx;

  return (table_index);
}

conn_user_t
conn_track_user_add (const char *user)
{
  conn_user_reg_t reg = {
    .cur_name = strdup (user),
    .cur_user = conn_user++,
  };

  vec_add1 (conn_user_regs, reg);

  return (reg.cur_user);
}

index_t
conn_track_add_or_lock (conn_user_t user,
			conn_db_id_t id,
			u8 * tag,
			ip_address_family_t af,
			u32 n_conns_per_thread, conn_db_flags_t flags)
{
  u32 n_workers, start, ti;
  conn_db_t *conn_db;
  index_t cdbi;
  conn_t *conn;

  cdbi = conn_db_db_find (user, id);
  n_workers = conn_get_n_workers ();

  if (INDEX_INVALID == cdbi)
    {
      pool_get_zero (conn_db_pool, conn_db);

      cdbi = conn_db - conn_db_pool;
      conn_db->cd_max = max_pow2 (n_conns_per_thread);
      conn_db->cd_id = id;
      conn_db->cd_af = af;
      conn_db->cd_tag = vec_dup (tag);

      vec_validate (conn_db->cd_conns, (n_workers * conn_db->cd_max) - 1);
      vec_foreach (conn, conn_db->cd_conns) conn->c_flags |= CONN_FLAG_STALE;

      vec_validate (conn_db->cd_per_thread, n_workers - 1);
      ti = start = 0;

      vec_foreach_index (ti, conn_db->cd_per_thread)
      {
	conn = &conn_db->cd_conns[start];
	conn->c_thread = ti;

	conn_age_sieve_init (&conn_db->cd_per_thread[ti].cdpt_sieve,
			     conn, start, conn_db->cd_max);

	start += conn_db->cd_max;
      }

      conn_db->cd_mask = conn_masks[conn_db->cd_af];

      conn_db->cd_table = conn_vnet_classifier_table_add
	(conn_db->cd_mask, CONN_N_DIR * n_workers * conn_db->cd_max, 0);

      hash_set (conn_db_db, conn_db->cd_id, cdbi);
    }
  else
    {
      conn_db = pool_elt_at_index (conn_db_pool, cdbi);
    }

  conn_db->cd_locks++;

  return (cdbi);
}

void
conn_db_unlock (index_t * cdbip)
{
  conn_db_t *conn_db;
  index_t cdbi;

  cdbi = *cdbip;
  conn_db = pool_elt_at_index (conn_db_pool, cdbi);

  conn_db->cd_locks--;

  if (0 == conn_db->cd_locks)
    {
      conn_db_per_thread_t *per_thread;
      clib_bitmap_t **owner;

      vec_foreach (per_thread, conn_db->cd_per_thread)
      {
	conn_age_sieve_destroy (&per_thread->cdpt_sieve);
      }

      vec_free (conn_db->cd_per_thread);
      vec_free (conn_db->cd_conns);

      vec_foreach (owner, conn_db->cd_owners) clib_bitmap_free (*owner);

      vec_free (conn_db->cd_owners);
      vnet_classify_delete_table_index (&vnet_classify_main,
					conn_db->cd_table, 0);

      hash_unset (conn_db_db, conn_db->cd_id);
      pool_put (conn_db_pool, conn_db);
    }

  *cdbip = INDEX_INVALID;
}

conn_owner_t
conn_track_owner_add (index_t cdbi)
{
  conn_owner_t owner;
  conn_db_t *conn_db;

  conn_db = pool_elt_at_index (conn_db_pool, cdbi);
  owner = vec_len (conn_db->cd_owners);

  vec_validate (conn_db->cd_owners, owner);
  clib_bitmap_validate (conn_db->cd_owners[owner], conn_db->cd_max - 1);

  return (owner);
}

static void
conn_stale (conn_db_t * conn_db, index_t conni)
{
  conn_t *conn;

  conn = conn_get (conn_db, conni);

  conn->c_flags |= CONN_FLAG_STALE;
}

void
conn_track_owner_flush (index_t cdbi, conn_owner_t owner)
{
  conn_db_t *conn_db;
  u32 conni;

  conn_db = pool_elt_at_index (conn_db_pool, cdbi);

  clib_bitmap_foreach (conni, conn_db->cd_owners[owner], (
							   {
							   conn_stale
							   (conn_db, conni);
							   }));

  clib_bitmap_zero (conn_db->cd_owners[owner]);
}

static u8 *
format_conn_db_per_thread (u8 * s, va_list * a)
{
  conn_db_per_thread_t *per_thread;
  u32 indent;

  per_thread = va_arg (*a, conn_db_per_thread_t *);
  indent = va_arg (*a, u32);

  s = format (s, "%Un_adds:%d",
	      format_white_space, indent, per_thread->cdpt_n_adds);
  s = format (s, "\n%U", format_conn_age_sieve,
	      &per_thread->cdpt_sieve, indent + 2);

  return (s);
}

u8 *
format_conn_db (u8 * s, va_list * a)
{
  conn_db_t *conn_db;
  index_t cdbi;
  u32 indent, i;

  cdbi = va_arg (*a, index_t);
  indent = va_arg (*a, u32);

  conn_db = pool_elt_at_index (conn_db_pool, cdbi);

  s = format (s, "%U[%d] %v %U table:%d max:%d",
	      format_white_space, indent, cdbi, conn_db->cd_tag,
	      format_ip_address_family, conn_db->cd_af,
	      conn_db->cd_table, conn_db->cd_max);

  vec_foreach_index (i, conn_db->cd_per_thread)
  {
    s = format (s, "\n%U[thread:%d]", format_white_space, indent + 2, i);
    s = format (s, "\n%U", format_conn_db_per_thread,
		&conn_db->cd_per_thread[i], indent + 4);
  }

  s = format (s, "\n%Uowners:", format_white_space, indent);
  vec_foreach_index (i, conn_db->cd_owners)
    s = format (s, "\n%U[%d] %U",
		format_white_space, indent + 2, i,
		format_bitmap_hex, conn_db->cd_owners[i]);

  s = format (s, "\n%Uconnections: (now:%0.4f)", format_white_space, indent,
	      vlib_time_now (vlib_get_main ()));
  vec_foreach_index (i, conn_db->cd_conns)
    s = format (s, "\n%U%U",
		format_white_space, indent + 2,
		format_conn, conn_db, i, indent + 2);

  /* s = format (s, "\n%U%U", */
  /*             format_white_space, indent + 2, */
  /*             format_vnet_classify_table, */
  /*             &vnet_classify_main, 1, conn_db->cd_table); */

  return (s);
}

static clib_error_t *
conn_db_show (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  conn_user_t user;
  conn_db_id_t id;
  index_t cdbi;

  cdbi = id = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "user %d id %d", &user, &id))
	;
      else if (unformat (input, "index %d", &cdbi))
	;
      else
	break;
    }

  if (~0 == id && INDEX_INVALID == cdbi)
    return (clib_error_return (0, "specify either a DB ID or index"));

  if (~0 != id)
    cdbi = conn_db_db_find (user, id);

  if (INDEX_INVALID == cdbi)
    return (clib_error_return (0, "specify either a valid DB ID or index"));

  if (pool_is_free_index (conn_db_pool, cdbi))
    return (clib_error_return (0, "no such DB, index:%d", cdbi));

  vlib_cli_output (vm, "%U", format_conn_db, cdbi, 0);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_conn_db, static) =
{
  .path = "show conntrack db",
  .short_help = "show conntrack db <id %d|index %d>",
  .function = conn_db_show,
};
/* *INDENT-ON* */

static clib_error_t *
conn_user_show (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  conn_user_reg_t *reg;

  vec_foreach (reg, conn_user_regs)
  {
    conn_db_db_key_t key;
    index_t cdbi;
    u8 *s = NULL;

    vlib_cli_output (vm, "user:%s id:%d", reg->cur_name, reg->cur_user);

      /* *INDENT-OFF* */
      hash_foreach (key.cddk_u64, cdbi, conn_db_db,
      ({
        if (key.cddk_user == reg->cur_user)
          s = format (s, "%d ", cdbi);
      }));
      /* *INDENT-ON* */
    vlib_cli_output (vm, "  DBS: %v", s);
  }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_conn_user, static) =
{
  .path = "show conntrack users",
  .short_help = "show conntrack users",
  .function = conn_user_show,
};
/* *INDENT-ON* */

clib_error_t *
conn_init (vlib_main_t * vm)
{
  vec_validate (conn_masks[AF_IP4], sizeof (CONN_IP4_MASK) - 1);
  clib_memcpy (conn_masks[AF_IP4], &CONN_IP4_MASK, sizeof (CONN_IP4_MASK));
  vec_validate (conn_masks[AF_IP6], sizeof (CONN_IP6_MASK) - 1);
  clib_memcpy (conn_masks[AF_IP6], &CONN_IP6_MASK, sizeof (CONN_IP6_MASK));

  return (NULL);
}

VLIB_INIT_FUNCTION (conn_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
