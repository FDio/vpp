/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <plugins/l3span/l3_span.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_path_list.h>
#include <plugins/l3span/l3_span_dpo.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

/**
 * Span, i.e. replicate, traffic destined to a given prefix to a [set of] collectors.
 * A collector is simply a FIB path desribing where the traffic should be sent,
 * plus any encapsulation.
 */

/**
 * Pool of all L3 spans
 */
static l3_span_t *l3_span_pool;

/**
 * DB of span objects key'd on prefix
 */
clib_bihash_24_8_t l3_span_db;

typedef clib_bihash_kv_24_8_t l3_span_key_t;

static void
l3_span_mk_key (u32 fib_index, const fib_prefix_t * pfx, l3_span_key_t * key)
{
  key->key[0] = pfx->fp_addr.as_u64[0];
  key->key[1] = pfx->fp_addr.as_u64[1];
  key->key[2] = pfx->fp_len;
  key->key[2] = (key->key[2] << 16);
  key->key[2] |= pfx->fp_proto;
  key->key[2] = (key->key[2] << 32);
  key->key[2] |= fib_index;

}

static l3_span_t *
l3_span_find (u32 fib_index, const fib_prefix_t * pfx)
{
  l3_span_key_t key;
  int rv;

  l3_span_mk_key (fib_index, pfx, &key);

  rv = BV (clib_bihash_search_inline) (&l3_span_db, &key);

  if (0 == rv)
    {
      return pool_elt_at_index (l3_span_pool, key.value);
    }

  return (NULL);
}

static void
l3_span_add (l3_span_t * l3s)
{
  l3_span_key_t key;

  l3_span_mk_key (l3s->l3s_fib_index, &l3s->l3s_pfx, &key);
  key.value = (l3s - l3_span_pool);

  BV (clib_bihash_add_del) (&l3_span_db, &key, 1);
}

static void
l3_span_remove (l3_span_t * l3s)
{
  l3_span_key_t key;

  l3_span_mk_key (l3s->l3s_fib_index, &l3s->l3s_pfx, &key);

  BV (clib_bihash_add_del) (&l3_span_db, &key, 0);
}

static index_t
l3_span_get_index (l3_span_t * l3s)
{
  return (l3s - l3_span_pool);
}


void
l3_span_path_add (u32 fib_index,
		  const fib_prefix_t * pfx, const fib_route_path_t * rpath)
{
  l3_span_t *l3s;

  l3s = l3_span_find (fib_index, pfx);

  if (NULL == l3s)
    {
      pool_get (l3_span_pool, l3s);
      l3s->l3s_fib_index = fib_index;
      l3s->l3s_pfx = *pfx;
      l3s->l3s_pl =
	fib_path_list_create (FIB_PATH_LIST_ATTRIBUTE_NO_URPF, rpath);
      fib_path_list_lock (l3s->l3s_pl);

      l3_span_add (l3s);

      /*
       * Lock the table into which we are about to add routes
       */
      fib_table_lock (fib_index, pfx->fp_proto, FIB_SOURCE_PLUGIN_HI);

      /*
       * Construct the original L3 span DPO
       */
      l3_span_dpo_create_and_lock (fib_proto_to_dpo (pfx->fp_proto),
				   l3s->l3s_pl,
				   l3_span_get_index (l3s), &l3s->l3s_dpo);

      /*
       * source the corresponding FIB entry with the interpose source
       * and pass our new DPO.
       * Use the cover inherit flag so that this affects all more specifc
       * prefixs in the sub-tree.
       */
      l3s->l3s_fei = fib_table_entry_special_dpo_add (l3s->l3s_fib_index,
						      &l3s->l3s_pfx,
						      FIB_SOURCE_PLUGIN_HI,
						      (FIB_ENTRY_FLAG_COVERED_INHERIT
						       |
						       FIB_ENTRY_FLAG_INTERPOSE),
						      &l3s->l3s_dpo);
    }
  else
    {
      fib_node_index_t old_pl;

      /*
       * and the new path to the path-list.
       */
      old_pl = l3s->l3s_pl;
      l3s->l3s_pl = fib_path_list_copy_and_path_add (l3s->l3s_pl,
						     FIB_PATH_LIST_ATTRIBUTE_NO_URPF,
						     rpath);

      fib_path_list_lock (l3s->l3s_pl);
      fib_path_list_unlock (old_pl);

      /*
       * update the DPO with the new path-list.
       * then poke the FIB entry we source to recalculate its forwarding
       * so that updated L3 span DPOs get interposed
       */
      l3_span_dpo_update (l3s->l3s_dpo.dpoi_index, l3s->l3s_pl);
      fib_entry_recalculate_forwarding (l3s->l3s_fei);
    }

}

void
l3_span_path_remove (u32 fib_index,
		     const fib_prefix_t * pfx, const fib_route_path_t * rpaths)
{
  const fib_route_path_t *rpath;
  fib_node_index_t old_pl;
  l3_span_t *l3s;

  l3s = l3_span_find (fib_index, pfx);

  if (NULL == l3s)
    {
      return;
    }

  old_pl = l3s->l3s_pl;

  vec_foreach(rpath, rpaths)
    {
      l3s->l3s_pl =
        fib_path_list_copy_and_path_remove (l3s->l3s_pl,
                                            FIB_PATH_LIST_ATTRIBUTE_NO_URPF,
                                            rpath);
    }

  fib_path_list_unlock (old_pl);

  if (FIB_NODE_INDEX_INVALID == l3s->l3s_pl)
    {
      /*
       * unsource the route and unlock the Span DPO
       */
      fib_table_entry_special_remove (l3s->l3s_fib_index,
				      &l3s->l3s_pfx, FIB_SOURCE_PLUGIN_HI);
      dpo_reset (&l3s->l3s_dpo);

      /*
       * unlock the table now we have removed the route
       */
      fib_table_unlock (fib_index, pfx->fp_proto, FIB_SOURCE_PLUGIN_HI);

      /*
       * remove the config
       */
      l3_span_remove (l3s);
    }
  else
    {
      /*
       * lock the path list we are now using
       */
      fib_path_list_lock (l3s->l3s_pl);

      /*
       * update the DPO with the new path-list.
       * then poke the FIB entry we source to recalculate its forwarding
       * so that updated L3 span DPOs get interposed
       */
      l3_span_dpo_update (l3s->l3s_dpo.dpoi_index, l3s->l3s_pl);
      fib_entry_recalculate_forwarding (l3s->l3s_fei);
    }
}

static u8 *
format_l3_span (u8 * s, va_list * args)
{
  l3_span_t *l3s = va_arg (*args, l3_span_t*);

  s = format (s, "[@%d]: ", (l3s - l3_span_pool));
  s = format (s, "%U\n", format_fib_prefix, &l3s->l3s_pfx);
  s = fib_path_list_format (l3s->l3s_pl, s);

  return (s);
}

static int
l3_span_walk_show_one (const l3_span_t *l3s, void *arg)
{
  vlib_main_t *vm = arg;

  vlib_cli_output (vm, "%U", format_l3_span, l3s);

  return (1);
}

static clib_error_t *
l3_span_show (vlib_main_t * vm,
	      unformat_input_t * main_input,
              vlib_cli_command_t * cmd)
{
  index_t l3sdi;

  l3_span_walk(l3_span_walk_show_one, vm);

  vlib_cli_output (vm, "\n");
  /* *INDENT-OFF* */
  pool_foreach_index(l3sdi, l3_span_dpo_pool,
  ({
    vlib_cli_output (vm, "\n%U", format_l3_span_dpo, l3sdi, 2);
  }));
  /* *INDENT-ON* */

  return (NULL);
}

/**
 * User context when walking the hash table
 */
typedef struct l3_span_walk_ctx_t_
{
  l3_span_walk_t l3swc_cb;
  void * l3swc_ctx;
} l3_span_walk_ctx_t;

static void
l3_span_walk_one (BVT (clib_bihash_kv) * kvp, void *arg)
{
  l3_span_walk_ctx_t *wctx = arg;
  l3_span_t *l3s;

  l3s = pool_elt_at_index (l3_span_pool, kvp->value);

  wctx->l3swc_cb(l3s, wctx->l3swc_ctx);
}

/**
 * Walk the L3 span entries
 */
void
l3_span_walk (l3_span_walk_t cb,
              void *ctx)
{
  l3_span_walk_ctx_t wctx = {
    .l3swc_cb = cb,
    .l3swc_ctx = ctx,
  };

  BV (clib_bihash_foreach_key_value_pair) (&l3_span_db,
					   l3_span_walk_one,
                                           &wctx);
}


static clib_error_t *
l3_span_cli (vlib_main_t * vm,
	     unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_route_path_t *rpaths = NULL, rpath;
  u32 table_id, is_del, payload_proto;
  clib_error_t *error = NULL;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_MAX,
  };
  u32 fib_index;

  is_del = 0;
  table_id = 0;
  memset (&pfx, 0, sizeof (pfx));

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      memset (&rpath, 0, sizeof (rpath));

      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "%U/%d",
			 unformat_ip4_address, &pfx.fp_addr.ip4, &pfx.fp_len))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	}
      else if (unformat (line_input, "%U/%d",
			 unformat_ip6_address, &pfx.fp_addr.ip6, &pfx.fp_len))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	}
      else if (unformat (line_input, "via %U",
			 unformat_fib_route_path, &rpath, &payload_proto))
	{
	  vec_add1 (rpaths, rpath);
	}
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "add"))
	is_del = 0;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (pfx.fp_proto == FIB_PROTOCOL_MAX)
    {
      error =
	clib_error_return (0, "expected ip4/ip6 destination address/length.");
      goto done;
    }

  if (!is_del && vec_len (rpaths) == 0)
    {
      error = clib_error_return (0, "expected paths.");
      goto done;
    }

  if (~0 == table_id)
    {
      /*
       * if no table_id is passed we will manipulate the default
       */
      fib_index = 0;
    }
  else
    {
      fib_index = fib_table_find (pfx.fp_proto, table_id);

      if (~0 == fib_index)
	{
	  error = clib_error_return (0, "Nonexistent table id %d", table_id);
	  goto done;
	}
    }

  if (is_del)
    l3_span_path_remove (fib_index, &pfx, rpaths);
  else
    l3_span_path_add (fib_index, &pfx, rpaths);

done:
  vec_free (rpaths);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l3_span_command, static) = {
  .path = "l3-span",
  .short_help = "l3-span [add|del] <dst-ip-addr>/<width> [table <table-id>] [via <next-hop-ip-addr> [<interface>] [udp-encap-id %d] [out-labels ...]",
  .function = l3_span_cli,
  .is_mp_safe = 1,
};
VLIB_CLI_COMMAND (l3_span_show_command, static) = {
  .path = "show l3-span",
  .short_help = "show l3-span",
  .function = l3_span_show,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
l3_span_init (vlib_main_t * vm)
{
  BV (clib_bihash_init) (&l3_span_db, "L3 Span Table", 64, 0xffff);

  l3_span_dpo_module_init ();
  return (NULL);
}

VLIB_INIT_FUNCTION (l3_span_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "L3 Span",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
