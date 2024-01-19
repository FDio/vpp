/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/fib/fib_table.h>
#include <vnet/dpo/drop_dpo.h>

#include <cnat/cnat_client.h>
#include <cnat/cnat_translation.h>

cnat_client_t *cnat_client_pool;
cnat_client_db_t cnat_client_db;
dpo_type_t cnat_client_dpo;
fib_source_t cnat_fib_source;

static u32 cnat_client_node_ip4_cnat_tx;
static u32 cnat_client_node_ip6_cnat_tx;
static u32 cnat_client_node_ip4_cnat_return;
static u32 cnat_client_node_ip6_cnat_return;

static_always_inline u8
cnat_client_is_clone (cnat_client_t * cc)
{
  return (FIB_NODE_INDEX_INVALID == cc->cc_fei);
}

static void
cnat_client_db_remove (cnat_client_t *cc, u32 fib_index)
{
  clib_bihash_kv_24_8_t bkey;
  if (ip_addr_version (&cc->cc_ip) == AF_IP4)
    {
      bkey.key[0] = ip_addr_v4 (&cc->cc_ip).as_u32;
      bkey.key[1] = 0;
      bkey.key[2] = fib_index;
    }
  else
    {
      bkey.key[0] = ip_addr_v6 (&cc->cc_ip).as_u64[0];
      bkey.key[1] = ip_addr_v6 (&cc->cc_ip).as_u64[1];
      bkey.key[2] = fib_index;
    }

  clib_bihash_add_del_24_8 (&cnat_client_db.cc_ip_id_hash, &bkey, 0 /* del */);
}

static void
cnat_client_db_add (cnat_client_t *cc, u32 fib_index)
{
  index_t cci;

  cci = cc - cnat_client_pool;

  clib_bihash_kv_24_8_t bkey;
  bkey.value = cci;
  if (ip_addr_version (&cc->cc_ip) == AF_IP4)
    {
      bkey.key[0] = ip_addr_v4 (&cc->cc_ip).as_u32;
      bkey.key[1] = 0;
      bkey.key[2] = fib_index;
    }
  else
    {
      bkey.key[0] = ip_addr_v6 (&cc->cc_ip).as_u64[0];
      bkey.key[1] = ip_addr_v6 (&cc->cc_ip).as_u64[1];
      bkey.key[2] = fib_index;
    }

  clib_bihash_add_del_24_8 (&cnat_client_db.cc_ip_id_hash, &bkey, 1 /* add */);
}

static void
cnat_client_destroy (cnat_client_t *cc, u32 fib_index)
{
  ASSERT (!cnat_client_is_clone (cc));

  if (cc->flags & CNAT_TR_FLAG_NO_CLIENT)
    cnat_client_db_remove (cc, fib_index);
  else
    {
      ASSERT (fib_entry_is_sourced (cc->cc_fei, cnat_fib_source));
      fib_table_entry_delete_index (cc->cc_fei, cnat_fib_source);

      cnat_client_db_remove (cc, fib_index);
      dpo_reset (&cc->cc_parent);
    }
  pool_put (cnat_client_pool, cc);
}

void
cnat_client_free_by_ip (ip4_address_t *ip4, ip6_address_t *ip6, u8 af, u32 fib_index,
			int is_session)
{
  cnat_client_t *cc;
  cc =
    (AF_IP4 == af ? cnat_client_ip4_find (ip4, fib_index) : cnat_client_ip6_find (ip6, fib_index));
  ASSERT (NULL != cc);

  if (0 == cc->tr_refcnt && (!is_session || 0 == cnat_client_uncnt_session (cc)))
    cnat_client_destroy (cc, fib_index);
}

void
cnat_client_throttle_pool_process (void)
{
  /* This processes ips stored in the throttle pool
     to update session refcounts
     and should be called before cnat_client_free_by_ip */
  cnat_client_t *cc;
  cnat_client_learn_args_t *args, *del_vec = NULL;
  u32 refcnt;

  vec_reset_length (del_vec);
  clib_spinlock_lock (&cnat_client_db.throttle_lock);
  hash_foreach_mem (args, refcnt, cnat_client_db.throttle_mem, {
    cc = (AF_IP4 == args->addr.version ?
	    cnat_client_ip4_find (&ip_addr_v4 (&args->addr), args->fib_index) :
	    cnat_client_ip6_find (&ip_addr_v6 (&args->addr), args->fib_index));
    /* Client might not already be created */
    if (NULL != cc)
      {
	cnat_client_t *ccp = cnat_client_get (cc->parent_cci);
	clib_atomic_add_fetch (&ccp->session_refcnt, refcnt);
	vec_add1 (del_vec, *args);
      }
  });
  vec_foreach (args, del_vec)
    hash_unset_mem_free (&cnat_client_db.throttle_mem, args);
  clib_spinlock_unlock (&cnat_client_db.throttle_lock);
}

void
cnat_client_translation_added (index_t cci)
{
  cnat_client_t *cc;
  if (INDEX_INVALID == cci)
    return;

  cc = cnat_client_get (cci);
  cc->tr_refcnt++;
}

void
cnat_client_translation_deleted (index_t cci, u32 fib_index)
{
  cnat_client_t *cc;
  if (INDEX_INVALID == cci)
    return;

  cc = cnat_client_get (cci);
  cc->tr_refcnt--;

  if (0 == cc->tr_refcnt && 0 == cc->session_refcnt)
    cnat_client_destroy (cc, fib_index);
}

index_t
cnat_client_add_pfx (const ip_address_t *pfx, u8 pfx_len, u32 fib_index, u8 flags)
{
  cnat_client_t *cc;
  dpo_id_t tmp = DPO_INVALID;
  fib_node_index_t fei;
  dpo_proto_t dproto;
  fib_prefix_t fib_pfx;
  index_t cci;
  u32 fib_flags;

  /* check again if we need this client */
  cc = (AF_IP4 == pfx->version ? cnat_client_ip4_find (&pfx->ip.ip4, fib_index) :
				 cnat_client_ip6_find (&pfx->ip.ip6, fib_index));

  if (NULL != cc)
    return (cc - cnat_client_pool);


  pool_get_aligned (cnat_client_pool, cc, CLIB_CACHE_LINE_BYTES);
  cc->cc_locks = 1;
  cci = cc - cnat_client_pool;
  cc->parent_cci = cci;
  cc->flags = flags;
  cc->tr_refcnt = 0;
  cc->session_refcnt = 0;

  ip_address_copy (&cc->cc_ip, pfx);
  cnat_client_db_add (cc, fib_index);

  if (flags & CNAT_TR_FLAG_NO_CLIENT)
    return (cci);

  ip_address_to_fib_prefix (&cc->cc_ip, &fib_pfx);
  fib_pfx.fp_len = pfx_len;

  dproto = fib_proto_to_dpo (fib_pfx.fp_proto);
  dpo_set (&tmp, cnat_client_dpo, dproto, cci);
  dpo_stack (cnat_client_dpo, dproto, &cc->cc_parent, drop_dpo_get (dproto));

  fib_flags = FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT;
  fib_flags |=
    (flags & CNAT_TR_FLAG_EXCLUSIVE) ? FIB_ENTRY_FLAG_EXCLUSIVE : FIB_ENTRY_FLAG_INTERPOSE;

  fei = fib_table_entry_special_dpo_add (fib_index, &fib_pfx, cnat_fib_source, fib_flags, &tmp);

  cc = pool_elt_at_index (cnat_client_pool, cci);
  cc->cc_fei = fei;

  return (cci);
}

index_t
cnat_client_add (const ip_address_t *ip, u32 fib_index, u8 flags)
{
  u8 pfx_len = AF_IP4 == ip_addr_version (ip) ? 32 : 128;
  return cnat_client_add_pfx (ip, pfx_len, fib_index, flags);
}

void
cnat_client_learn (const cnat_client_learn_args_t *args)
{
  /* RPC call to add a client from the dataplane */
  index_t cci;
  cnat_client_t *cc;
  cci = cnat_client_add (&args->addr, args->fib_index, 0 /* flags */);
  cc = pool_elt_at_index (cnat_client_pool, cci);
  cnat_client_cnt_session (cc);
  /* Process throttled calls if any */
  cnat_client_throttle_pool_process ();
}

/**
 * Interpose a policy DPO
 */
static void
cnat_client_dpo_interpose (const dpo_id_t * original,
			   const dpo_id_t * parent, dpo_id_t * clone)
{
  cnat_client_t *cc, *cc_clone;

  pool_get_zero (cnat_client_pool, cc_clone);
  cc = cnat_client_get (original->dpoi_index);

  cc_clone->cc_fei = FIB_NODE_INDEX_INVALID;
  cc_clone->parent_cci = cc->parent_cci;
  cc_clone->flags = cc->flags;
  ip_address_copy (&cc_clone->cc_ip, &cc->cc_ip);

  /* stack the clone on the FIB provided parent */
  dpo_stack (cnat_client_dpo, original->dpoi_proto, &cc_clone->cc_parent,
	     parent);

  /* return the clone */
  dpo_set (clone,
	   cnat_client_dpo,
	   original->dpoi_proto, cc_clone - cnat_client_pool);
}

static u32 *
cnat_client_dpo_get_next_node (const dpo_id_t *dpo)
{
  const cnat_client_t *cc = cnat_client_get (dpo->dpoi_index);
  u32 *nodes = 0;
  bool is_return = cc->flags & CNAT_TR_FLAG_RETURN_ONLY;
  u32 n, r;
  switch (dpo->dpoi_proto)
    {
    case DPO_PROTO_IP4:
      n = cnat_client_node_ip4_cnat_tx;
      r = cnat_client_node_ip4_cnat_return;
      break;
    case DPO_PROTO_IP6:
      n = cnat_client_node_ip6_cnat_tx;
      r = cnat_client_node_ip6_cnat_return;
      break;
    default:
      return 0;
    }

  vec_add1 (nodes, is_return ? r : n);
  return nodes;
}

int
cnat_client_purge (void)
{
  int rv = 0, rrv = 0;
  if ((rv = pool_elts (cnat_client_pool)))
    clib_warning ("len(cnat_client_pool) isnt 0 but %d", rv);
  rrv |= rv;
  if ((rv = hash_elts (cnat_client_db.throttle_mem)))
    clib_warning ("len(throttle_mem) isnt 0 but %d", rv);
  rrv |= rv;
  return (rrv);
}

u8 *
format_cnat_client (u8 * s, va_list * args)
{
  index_t cci = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);

  cnat_client_t *cc = pool_elt_at_index (cnat_client_pool, cci);

  s = format (s, "[%d] cnat-client:[%U] tr:%d sess:%d locks:%u", cci,
	      format_ip_address, &cc->cc_ip, cc->tr_refcnt, cc->session_refcnt,
	      cc->cc_locks);

  if (cc->flags & CNAT_TR_FLAG_EXCLUSIVE)
    s = format (s, " exclusive");

  if (cnat_client_is_clone (cc))
    s = format (s, "\n%Uclone of [%d]\n%U%U",
		format_white_space, indent + 2, cc->parent_cci,
		format_white_space, indent + 2,
		format_dpo_id, &cc->cc_parent, indent + 4);

  return (s);
}


static clib_error_t *
cnat_client_show (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t cci;

  cci = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &cci))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (INDEX_INVALID == cci)
    {
      pool_foreach_index (cci, cnat_client_pool)
        vlib_cli_output(vm, "%U", format_cnat_client, cci, 0);

      vlib_cli_output (vm, "%d clients", pool_elts (cnat_client_pool));
    }
  else
    {
      vlib_cli_output (vm, "Invalid policy ID:%d", cci);
    }

  return (NULL);
}

VLIB_CLI_COMMAND (cnat_client_show_cmd_node, static) = {
  .path = "show cnat client",
  .function = cnat_client_show,
  .short_help = "show cnat client",
  .is_mp_safe = 1,
};

const static char *const cnat_client_dpo_ip4_nodes[] = {
  "ip4-cnat-tx",
  NULL,
};

const static char *const cnat_client_dpo_ip6_nodes[] = {
  "ip6-cnat-tx",
  NULL,
};

const static char *const *const cnat_client_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = cnat_client_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = cnat_client_dpo_ip6_nodes,
};

static void
cnat_client_dpo_lock (dpo_id_t * dpo)
{
  cnat_client_t *cc;

  cc = cnat_client_get (dpo->dpoi_index);

  cc->cc_locks++;
}

static void
cnat_client_dpo_unlock (dpo_id_t * dpo)
{
  cnat_client_t *cc;

  cc = cnat_client_get (dpo->dpoi_index);

  cc->cc_locks--;

  if (0 == cc->cc_locks)
    {
      ASSERT (cnat_client_is_clone (cc));
      dpo_reset (&cc->cc_parent);
      pool_put (cnat_client_pool, cc);
    }
}

u8 *
format_cnat_client_dpo (u8 * s, va_list * ap)
{
  index_t cci = va_arg (*ap, index_t);
  u32 indent = va_arg (*ap, u32);

  s = format (s, "%U", format_cnat_client, cci, indent);

  return (s);
}

const static dpo_vft_t cnat_client_dpo_vft = {
  .dv_lock = cnat_client_dpo_lock,
  .dv_unlock = cnat_client_dpo_unlock,
  .dv_format = format_cnat_client_dpo,
  .dv_mk_interpose = cnat_client_dpo_interpose,
  .dv_get_next_node = cnat_client_dpo_get_next_node,
};

static clib_error_t *
cnat_client_init (vlib_main_t * vm)
{
  cnat_main_t *cm = &cnat_main;

  cnat_client_node_ip4_cnat_tx = vlib_get_node_by_name (vm, (u8 *) "ip4-cnat-tx")->index;
  cnat_client_node_ip6_cnat_tx = vlib_get_node_by_name (vm, (u8 *) "ip6-cnat-tx")->index;
  cnat_client_node_ip4_cnat_return = vlib_get_node_by_name (vm, (u8 *) "ip4-cnat-return")->index;
  cnat_client_node_ip6_cnat_return = vlib_get_node_by_name (vm, (u8 *) "ip6-cnat-return")->index;

  cnat_client_dpo = dpo_register_new_type (&cnat_client_dpo_vft,
					   cnat_client_dpo_nodes);

  clib_bihash_init_24_8 (&cnat_client_db.cc_ip_id_hash, "CNat client DB", cm->client_hash_buckets,
			 cm->client_hash_memory);

  cnat_fib_source = fib_source_allocate ("cnat", CNAT_FIB_SOURCE_PRIORITY,
					 FIB_SOURCE_BH_SIMPLE);

  clib_spinlock_init (&cnat_client_db.throttle_lock);
  cnat_client_db.throttle_mem =
    hash_create_mem (0, sizeof (cnat_client_learn_args_t), sizeof (uword));

  return (NULL);
}

VLIB_INIT_FUNCTION (cnat_client_init);
