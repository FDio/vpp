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

calico_client_t *calico_client_pool;

calico_client_db_t calico_client_db;

dpo_type_t calico_client_dpo;

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

  ASSERT (FIB_NODE_INDEX_INVALID != cc->cc_fei);
  ASSERT (fib_entry_is_sourced (cc->cc_fei, calico_fib_source));
  fib_table_entry_delete_index (cc->cc_fei, calico_fib_source);
  ASSERT (!fib_entry_is_sourced (cc->cc_fei, calico_fib_source));
  calico_client_db_remove (cc);
  dpo_reset (&cc->cc_parent);
  pool_put (calico_client_pool, cc);
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

void
calico_client_learn (const calico_client_learn_t * l)
{
  calico_client_t *cc;

  /* check again if we need this */
  cc = (AF_IP4 == l->cl_af ?
	calico_client_ip4_find (&l->cl_ip.ip4) :
	calico_client_ip6_find (&l->cl_ip.ip6));

  if (NULL == cc)
    {
      dpo_id_t tmp = DPO_INVALID;
      fib_node_index_t fei;
      dpo_proto_t dproto;
      fib_prefix_t pfx;
      index_t cci;

      pool_get_aligned (calico_client_pool, cc, CLIB_CACHE_LINE_BYTES);
      cc->cc_locks = 1;
      cc->cc_ts_index =
	calico_timestamp_new (vlib_time_now (vlib_get_main ()));
      cci = cc - calico_client_pool;
      cc->index = cci;

      ip_addr_version (&cc->cc_ip) = l->cl_af;
      ip46_address_copy (&ip_addr_46 (&cc->cc_ip), &l->cl_ip);
      calico_client_db_add (cc);

      ip_address_to_fib_prefix (&cc->cc_ip, &pfx);

      dproto = fib_proto_to_dpo (pfx.fp_proto);
      dpo_set (&tmp, calico_client_dpo, dproto, cci);
      dpo_stack (calico_client_dpo, dproto, &cc->cc_parent,
		 drop_dpo_get (dproto));

      fei = fib_table_entry_special_dpo_add
	(CALICO_FIB_TABLE,
	 &pfx,
	 calico_fib_source,
	 (FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT | FIB_ENTRY_FLAG_INTERPOSE), &tmp);

      cc = pool_elt_at_index (calico_client_pool, cci);
      cc->cc_fei = fei;
    }
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
  cc_clone->index = cc_clone - calico_client_pool;
  cc_clone->cc_ts_index = cc->cc_ts_index;
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

  s = format (s, "[%d] calico-client:[%U] age:%f", cci,
	      format_ip_address, &cc->cc_ip,
	      calico_timestamp_get (cc->cc_ts_index));
  s = format (s, "\n%U%U", format_white_space, indent + 2,
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
      ip4_address_t *ip4;
      ip6_address_t *ip6;

      /* *INDENT-OFF* */
      hash_foreach(ip4, cci, calico_client_db.crd_cip4,
      ({
        vlib_cli_output(vm, "%U", format_calico_client, cci, 0);
      }));
      hash_foreach_mem (ip6, cci, calico_client_db.crd_cip6,
      ({
        vlib_cli_output(vm, "%U", format_calico_client, cci, 0);
      }));
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

void
calico_client_scan (f64 now)
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

  vec_foreach (ccip, ccis)
  {
    calico_client_t *cc = pool_elt_at_index (calico_client_pool, *ccip);
    if ((now - CALICO_SESSION_MAX_AGE) >
	calico_timestamp_get (cc->cc_ts_index))
      {
	calico_client_destroy (*ccip);
      }
  }

  vec_free (ccis);
}

const static char *const calico_client_dpo_ip4_nodes[] = {
  "ip4-calico-rx",
  NULL,
};

const static char *const calico_client_dpo_ip6_nodes[] = {
  "ip6-calico-rx",
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
      ASSERT (cc->cc_fei == FIB_NODE_INDEX_INVALID);
      calico_timestamp_free (cc->cc_ts_index);
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
  calico_client_dpo = dpo_register_new_type (&calico_client_dpo_vft,
					     calico_client_dpo_nodes);

  calico_client_db.crd_cip6 = hash_create_mem (0,
					       sizeof (ip6_address_t),
					       sizeof (uword));

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
