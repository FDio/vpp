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

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
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
typedef struct l3_span_t_
{
  /**
   * The FIB index the prefix is in
   */
  u32 l3s_fib_index;

  /**
   * The destination prefix to span
   */
  fib_prefix_t l3s_pfx;

  /**
   * The path list descrbing where to spane the traffi to
   */
  fib_node_index_t l3s_pl;

  /**
   * Sibling index on the path-list
   */
  u32 l3s_pl_sibling;

  /**
   * The FIB entry index sourced
   */
  fib_node_index_t l3s_fei;

  /**
   * The L3 Span DPO from which we clone those that
   * are interposed in the FIB graph
   */
  dpo_id_t l3s_dpo;
} l3_span_t;

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


static void
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
      fib_table_lock (fib_index, pfx->fp_proto, FIB_SOURCE_INTERPOSE);

      /*
       * Construct the original L3 span DPO
       */
      l3_span_dpo_create_and_lock (fib_proto_to_dpo (pfx->fp_proto),
				   l3s->l3s_pl,
				   l3_span_get_index (l3s), &l3s->l3s_dpo);

      /*
       * source the corresponding FIB entry with the interpose source
       * and pass our new DPO.
       */
      l3s->l3s_fei = fib_table_entry_special_dpo_add (l3s->l3s_fib_index,
						      &l3s->l3s_pfx,
						      FIB_SOURCE_INTERPOSE,
						      FIB_ENTRY_FLAG_NONE,
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

static void
l3_span_path_remove (u32 fib_index,
		     const fib_prefix_t * pfx, const fib_route_path_t * rpath)
{
  fib_node_index_t old_pl;
  l3_span_t *l3s;

  l3s = l3_span_find (fib_index, pfx);

  if (NULL == l3s)
    {
      return;
    }

  old_pl = l3s->l3s_pl;
  l3s->l3s_pl = fib_path_list_copy_and_path_remove (l3s->l3s_pl,
						    FIB_PATH_LIST_ATTRIBUTE_NO_URPF,
						    rpath);

  fib_path_list_unlock (old_pl);

  if (FIB_NODE_INDEX_INVALID == l3s->l3s_pl)
    {
      /*
       * unsource the route and unlock the Span DPO
       */
      fib_table_entry_special_remove (l3s->l3s_fib_index,
				      &l3s->l3s_pfx, FIB_SOURCE_INTERPOSE);
      dpo_reset (&l3s->l3s_dpo);

      /*
       * unlock the table now we have removed the route
       */
      fib_table_lock (fib_index, pfx->fp_proto, FIB_SOURCE_INTERPOSE);

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
  index_t index = va_arg (*args, index_t);
  l3_span_t *l3s;

  l3s = pool_elt_at_index (l3_span_pool, index);

  s = format (s, "[@%d]: ", index);
  s = format (s, "%U\n", format_fib_prefix, &l3s->l3s_pfx);
  s = fib_path_list_format (l3s->l3s_pl, s);

  return (s);
}

static void
l3_span_walk_show_one (BVT (clib_bihash_kv) * kvp, void *arg)
{
  vlib_main_t *vm = arg;

  vlib_cli_output (vm, "%U", format_l3_span, kvp->value);
}

static clib_error_t *
l3_span_show (vlib_main_t * vm,
	      unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  BV (clib_bihash_foreach_key_value_pair) (&l3_span_db,
					   l3_span_walk_show_one, vm);

  return (NULL);
}

static clib_error_t *
l3_span_cli (vlib_main_t * vm,
	     unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_route_path_t *rpaths = NULL, rpath;
  u32 table_id, is_del, udp_encap_id;
  clib_error_t *error = NULL;
  mpls_label_t out_label;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_MAX,
  };
  vnet_main_t *vnm;
  u32 fib_index;

  vnm = vnet_get_main ();
  is_del = 0;
  table_id = 0;
  memset (&pfx, 0, sizeof (pfx));
  out_label = MPLS_LABEL_INVALID;

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      memset (&rpath, 0, sizeof (rpath));

      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "out-labels"))
	{
	  if (vec_len (rpaths) == 0)
	    {
	      error = clib_error_return (0, "Paths then labels");
	      goto done;
	    }
	  else
	    {
	      while (unformat (line_input, "%U",
			       unformat_mpls_unicast_label, &out_label))
		{
		  vec_add1 (rpaths[vec_len (rpaths) - 1].frp_label_stack,
			    out_label);
		}
	    }
	}
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
      else if (unformat (line_input, "via %U %U",
			 unformat_ip4_address,
			 &rpath.frp_addr.ip4,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index))
	{
	  rpath.frp_weight = 1;
	  rpath.frp_proto = DPO_PROTO_IP4;
	  vec_add1 (rpaths, rpath);
	}

      else if (unformat (line_input, "via %U %U",
			 unformat_ip6_address,
			 &rpath.frp_addr.ip6,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index))
	{
	  rpath.frp_weight = 1;
	  rpath.frp_proto = DPO_PROTO_IP6;
	  vec_add1 (rpaths, rpath);
	}
      else if (unformat (line_input, "via %U next-hop-table %d",
			 unformat_ip4_address,
			 &rpath.frp_addr.ip4, &rpath.frp_fib_index))
	{
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_proto = DPO_PROTO_IP4;
	  vec_add1 (rpaths, rpath);
	}
      else if (unformat (line_input, "via %U next-hop-table %d",
			 unformat_ip6_address,
			 &rpath.frp_addr.ip6, &rpath.frp_fib_index))
	{
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_proto = DPO_PROTO_IP6;
	  vec_add1 (rpaths, rpath);
	}
      else if (unformat (line_input, "via %U",
			 unformat_ip4_address, &rpath.frp_addr.ip4))
	{
	  /*
	   * the recursive next-hops are by default in the same table
	   * as the prefix
	   */
	  rpath.frp_fib_index = table_id;
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_proto = DPO_PROTO_IP4;
	  vec_add1 (rpaths, rpath);
	}
      else if (unformat (line_input, "via %U",
			 unformat_ip6_address, &rpath.frp_addr.ip6))
	{
	  rpath.frp_fib_index = table_id;
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_proto = DPO_PROTO_IP6;
	  vec_add1 (rpaths, rpath);
	}
      else if (unformat (line_input, "via udp-encap %d", &udp_encap_id))
	{
	  rpath.frp_udp_encap_id = udp_encap_id;
	  rpath.frp_flags |= FIB_ROUTE_PATH_UDP_ENCAP;
	  rpath.frp_proto = fib_proto_to_dpo (pfx.fp_proto);
	  vec_add1 (rpaths, rpath);
	}
      else if (pfx.fp_proto != FIB_PROTOCOL_MAX &&
	       unformat (line_input, "via %U",
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index))
	{
	  rpath.frp_weight = 1;
	  rpath.frp_proto = fib_proto_to_dpo (pfx.fp_proto);
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
