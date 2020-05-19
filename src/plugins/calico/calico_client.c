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

#include <vnet/fib/fib_table.h>
#include <vnet/dpo/drop_dpo.h>

#include <calico/calico_client.h>
#include <calico/calico_translation.h>

calico_client_t *calico_client_pool;

calico_client_db_t calico_client_db;

dpo_type_t calico_client_dpo;

static_always_inline u8
calico_client_is_clone (calico_client_t * cc)
{
  return (FIB_NODE_INDEX_INVALID == cc->cc_fei);
}

static void
calico_client_db_remove (calico_client_t * cc)
{
  if (ip_addr_version (&cc->cc_ip) == AF_IP4)
    hash_unset (calico_client_db.crd_cip4, ip_addr_v4 (&cc->cc_ip).as_u32);
  else
    hash_unset_mem_free (&calico_client_db.crd_cip6,
			 &ip_addr_v6 (&cc->cc_ip));
}

static void
calico_client_destroy (index_t cci)
{
  calico_client_t *cc;

  cc = calico_client_get (cci);

  ASSERT (!calico_client_is_clone (cc));
  if (!(cc->flags & CALICO_FLAG_EXCLUSIVE))
    {
      ASSERT (fib_entry_is_sourced (cc->cc_fei, calico_fib_source));
      fib_table_entry_delete_index (cc->cc_fei, calico_fib_source);
      ASSERT (!fib_entry_is_sourced (cc->cc_fei, calico_fib_source));
    }
  calico_client_db_remove (cc);
  dpo_reset (&cc->cc_parent);
  pool_put (calico_client_pool, cc);
}

void
calico_client_free_by_ip (ip46_address_t * ip, u8 af)
{
  calico_client_t *cc;
  cc = (AF_IP4 == af ?
	calico_client_ip4_find (&ip->ip4) :
	calico_client_ip6_find (&ip->ip6));
  ASSERT (NULL != cc);
  if ((0 == calico_client_uncnt_session (cc))
      && (cc->flags & CALICO_FLAG_EXPIRES))
    calico_client_destroy (cc - calico_client_pool);
}

void
calico_client_throttle_pool_process ()
{
  /* This processes ips stored in the throttle pool
     to update session refcounts
     and should be called before calico_client_free_by_ip */
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  calico_client_t *cc;
  int nthreads;
  u32 *del_vec = NULL, *ai;
  ip_address_t *addr;
  nthreads = tm->n_threads + 1;
  for (int i = 0; i < nthreads; i++)
    {
      vec_reset_length (del_vec);
      clib_spinlock_lock (&calico_client_db.throttle_pool_lock[i]);
      /* *INDENT-OFF* */
      pool_foreach(addr, calico_client_db.throttle_pool[i], ({
	cc = (AF_IP4 == addr->version ?
	      calico_client_ip4_find (&ip_addr_v4(addr)) :
	      calico_client_ip6_find (&ip_addr_v6(addr)));
	/* Client might not already be created */
	if (NULL != cc)
	  {
	    calico_client_cnt_session (cc);
	    vec_add1(del_vec, addr - calico_client_db.throttle_pool[i]);
	  }
      }));
      /* *INDENT-ON* */
      vec_foreach (ai, del_vec)
      {
	/* Free session */
	addr = pool_elt_at_index (calico_client_db.throttle_pool[i], *ai);
	pool_put (calico_client_db.throttle_pool[i], addr);
      }
      clib_spinlock_unlock (&calico_client_db.throttle_pool_lock[i]);
    }
}

void
calico_client_add_translation (index_t cci, u16 port, ip_protocol_t proto,
			       index_t cti)
{
  calico_client_t *cc;
  calico_add_translation (cci, port, proto, cti);
  cc = calico_client_get (cci);
  ASSERT (!(cc->flags & CALICO_FLAG_EXPIRES));
  cc->tr_refcnt++;
}

void
calico_client_remove_translation (index_t cci, u16 port, ip_protocol_t proto)
{
  calico_client_t *cc;
  calico_remove_translation (cci, port, proto);

  cc = calico_client_get (cci);
  ASSERT (!(cc->flags & CALICO_FLAG_EXPIRES));
  cc->tr_refcnt--;

  if (0 == cc->tr_refcnt)
    calico_client_destroy (cci);
}

static void
calico_client_db_add (calico_client_t * cc)
{
  index_t cci;

  cci = cc - calico_client_pool;

  if (ip_addr_version (&cc->cc_ip) == AF_IP4)
    hash_set (calico_client_db.crd_cip4, ip_addr_v4 (&cc->cc_ip).as_u32, cci);
  else
    hash_set_mem_alloc (&calico_client_db.crd_cip6,
			&ip_addr_v6 (&cc->cc_ip), cci);
}


index_t
calico_client_add (const ip_address_t * ip, u8 flags)
{
  calico_client_t *cc;
  dpo_id_t tmp = DPO_INVALID;
  fib_node_index_t fei;
  dpo_proto_t dproto;
  fib_prefix_t pfx;
  index_t cci;
  u32 fib_flags;

  /* check again if we need this client */
  cc = (AF_IP4 == ip->version ?
	calico_client_ip4_find (&ip->ip.ip4) :
	calico_client_ip6_find (&ip->ip.ip6));

  if (NULL != cc)
    return (cc - calico_client_pool);


  pool_get_aligned (calico_client_pool, cc, CLIB_CACHE_LINE_BYTES);
  cc->cc_locks = 1;
  cci = cc - calico_client_pool;
  cc->parent_cci = cci;
  cc->flags = flags;

  ip_address_copy (&cc->cc_ip, ip);
  calico_client_db_add (cc);

  ip_address_to_fib_prefix (&cc->cc_ip, &pfx);

  dproto = fib_proto_to_dpo (pfx.fp_proto);
  dpo_set (&tmp, calico_client_dpo, dproto, cci);
  dpo_stack (calico_client_dpo, dproto, &cc->cc_parent,
	     drop_dpo_get (dproto));

  fib_flags = FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT;
  fib_flags |= (flags & CALICO_FLAG_EXCLUSIVE) ?
    FIB_ENTRY_FLAG_EXCLUSIVE : FIB_ENTRY_FLAG_INTERPOSE;

  fei = fib_table_entry_special_dpo_add (CALICO_FIB_TABLE,
					 &pfx, calico_fib_source, fib_flags,
					 &tmp);

  cc = pool_elt_at_index (calico_client_pool, cci);
  cc->cc_fei = fei;

  return (cci);
}

void
calico_client_learn (const calico_learn_arg_t * l)
{
  /* RPC call to add a client from the dataplane */
  index_t cci;
  calico_client_t *cc;
  cci = calico_client_add (&l->addr, CALICO_FLAG_EXPIRES);
  cc = pool_elt_at_index (calico_client_pool, cci);
  calico_client_cnt_session (cc);
  /* Process throttled calls if any */
  calico_client_throttle_pool_process ();
}

/**
 * Interpose a policy DPO
 */
static void
calico_client_dpo_interpose (const dpo_id_t * original,
			     const dpo_id_t * parent, dpo_id_t * clone)
{
  calico_client_t *cc, *cc_clone;

  pool_get_zero (calico_client_pool, cc_clone);
  cc = calico_client_get (original->dpoi_index);

  cc_clone->cc_fei = FIB_NODE_INDEX_INVALID;
  cc_clone->parent_cci = cc->parent_cci;
  cc_clone->flags = cc->flags;
  ip_address_copy (&cc_clone->cc_ip, &cc->cc_ip);

  /* stack the clone on the FIB provided parent */
  dpo_stack (calico_client_dpo, original->dpoi_proto, &cc_clone->cc_parent,
	     parent);

  /* return the clone */
  dpo_set (clone,
	   calico_client_dpo,
	   original->dpoi_proto, cc_clone - calico_client_pool);
}

int
calico_client_purge (void)
{
  /* purge all the clients */
  void *ckey;
  index_t cci, *ccip, *ccis = NULL;

  /* *INDENT-OFF* */
  hash_foreach (ckey, cci, calico_client_db.crd_cip4,
  ({
    vec_add1(ccis, cci);
  }));
  hash_foreach_mem (ckey, cci, calico_client_db.crd_cip6,
  ({
    vec_add1(ccis, cci);
  }));
  /* *INDENT-ON* */

  vec_foreach (ccip, ccis) calico_client_destroy (*ccip);

  ASSERT (0 == hash_elts (calico_client_db.crd_cip6));
  ASSERT (0 == hash_elts (calico_client_db.crd_cip4));
  ASSERT (0 == pool_elts (calico_client_pool));

  vec_free (ccis);

  return (0);
}

u8 *
format_calico_client (u8 * s, va_list * args)
{
  index_t cci = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);

  calico_client_t *cc = pool_elt_at_index (calico_client_pool, cci);

  s = format (s, "[%d] calico-client:[%U] tr:%d sess:%d", cci,
	      format_ip_address, &cc->cc_ip,
	      cc->tr_refcnt, cc->session_refcnt);
  if (cc->flags & CALICO_FLAG_EXPIRES)
    s = format (s, " expires");

  if (cc->flags & CALICO_FLAG_EXCLUSIVE)
    s = format (s, " exclusive");

  if (calico_client_is_clone (cc))
    s = format (s, "\n%Uclone of [%d]\n%U%U",
		format_white_space, indent + 2, cc->parent_cci,
		format_white_space, indent + 2,
		format_dpo_id, &cc->cc_parent, indent + 4);

  return (s);
}


static clib_error_t *
calico_client_show (vlib_main_t * vm,
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
      /* *INDENT-OFF* */
      pool_foreach_index(cci, calico_client_pool, ({
        vlib_cli_output(vm, "%U", format_calico_client, cci, 0);
      }))
      /* *INDENT-ON* */

      vlib_cli_output (vm, "%d clients", pool_elts (calico_client_pool));
      vlib_cli_output (vm, "%d timestamps", pool_elts (calico_timestamps));
    }
  else
    {
      vlib_cli_output (vm, "Invalid policy ID:%d", cci);
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_client_show_cmd_node, static) = {
  .path = "show calico client",
  .function = calico_client_show,
  .short_help = "show calico client",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

const static char *const calico_client_dpo_ip4_nodes[] = {
  "ip4-calico-tx",
  NULL,
};

const static char *const calico_client_dpo_ip6_nodes[] = {
  "ip6-calico-tx",
  NULL,
};

const static char *const *const calico_client_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = calico_client_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = calico_client_dpo_ip6_nodes,
};

static void
calico_client_dpo_lock (dpo_id_t * dpo)
{
  calico_client_t *cc;

  cc = calico_client_get (dpo->dpoi_index);

  cc->cc_locks++;
}

static void
calico_client_dpo_unlock (dpo_id_t * dpo)
{
  calico_client_t *cc;

  cc = calico_client_get (dpo->dpoi_index);

  cc->cc_locks--;

  if (0 == cc->cc_locks)
    {
      ASSERT (calico_client_is_clone (cc));
      pool_put (calico_client_pool, cc);
    }
}

u8 *
format_calico_client_dpo (u8 * s, va_list * ap)
{
  index_t cci = va_arg (*ap, index_t);
  u32 indent = va_arg (*ap, u32);

  s = format (s, "%U", format_calico_client, cci, indent);

  return (s);
}

const static dpo_vft_t calico_client_dpo_vft = {
  .dv_lock = calico_client_dpo_lock,
  .dv_unlock = calico_client_dpo_unlock,
  .dv_format = format_calico_client_dpo,
  .dv_mk_interpose = calico_client_dpo_interpose,
};

static clib_error_t *
calico_client_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int nthreads = tm->n_threads + 1;
  int i;
  calico_client_dpo = dpo_register_new_type (&calico_client_dpo_vft,
					     calico_client_dpo_nodes);

  calico_client_db.crd_cip6 = hash_create_mem (0,
					       sizeof (ip6_address_t),
					       sizeof (uword));

  vec_validate (calico_client_db.throttle_pool, nthreads);
  vec_validate (calico_client_db.throttle_pool_lock, nthreads);
  for (i = 0; i < nthreads; i++)
    clib_spinlock_init (&calico_client_db.throttle_pool_lock[i]);

  return (NULL);
}

VLIB_INIT_FUNCTION (calico_client_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
