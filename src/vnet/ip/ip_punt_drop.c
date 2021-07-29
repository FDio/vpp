/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/ip/ip.h>
#include <vnet/ip/ip_punt_drop.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_table.h>

ip_punt_redirect_cfg_t ip_punt_redirect_cfg;

u8 *
format_ip_punt_redirect_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_punt_redirect_trace_t *t = va_arg (*args, ip_punt_redirect_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 table_id;

  if (INDEX_INVALID != t->rx_sw_if_index)
    s = format (s, "rx if %U\n", format_vnet_sw_if_index_name, vnm,
		t->rx_sw_if_index);

  if (INDEX_INVALID != t->fib_index)
    {
      table_id = fib_table_get_table_id (t->fib_index, t->fproto);
      s = format (s, "table_id %u\n", table_id);
    }

  if (INDEX_INVALID == t->rrxi)
    s = format (s, "not found");
  else
    s = format (s, "via redirect:%d", t->rrxi);

  return s;
}

static void
ip_punt_redirect_stack (ip_punt_redirect_rx_t * ipr)
{
  dpo_id_t dpo = DPO_INVALID;
  vlib_node_t *pnode;

  fib_path_list_contribute_forwarding (ipr->pl,
				       ipr->payload_type,
				       FIB_PATH_LIST_FWD_FLAG_COLLAPSE, &dpo);

  if (FIB_PROTOCOL_IP4 == ipr->fproto)
    pnode =
      vlib_get_node_by_name (vlib_get_main (), (u8 *) "ip4-punt-redirect");
  else
    pnode =
      vlib_get_node_by_name (vlib_get_main (), (u8 *) "ip6-punt-redirect");

  dpo_stack_from_node (pnode->index, &ipr->dpo, &dpo);
  dpo_reset (&dpo);
}

index_t
ip_punt_redirect_find (fib_protocol_t fproto, u32 rx_sw_if_index, u32 table_id)
{
  clib_bihash_kv_16_8_t bkey, bvalue;
  u32 fib_index = table_id;
  int rv;

  if (INDEX_INVALID != table_id)
    fib_index = fib_table_find (fproto, table_id);

  bkey.key[0] = fproto;
  bkey.key[1] = (u64) rx_sw_if_index << 32 | fib_index;
  rv = clib_bihash_search_inline_2_16_8 (&ip_punt_redirect_cfg.punt_db, &bkey,
					 &bvalue);

  if (rv)
    return (INDEX_INVALID);

  return bvalue.value;
}

void
ip_punt_redirect_add (fib_protocol_t fproto, u32 rx_sw_if_index, u32 table_id,
		      fib_forward_chain_type_t ct, fib_route_path_t *rpaths)
{
  ip_punt_redirect_rx_t *ipr;
  clib_bihash_kv_16_8_t bkey;
  u32 fib_index = table_id;
  index_t ipri;

  if (INDEX_INVALID != table_id)
    fib_index = fib_table_find (fproto, table_id);

  pool_get (ip_punt_redirect_cfg.pool, ipr);
  ipri = ipr - ip_punt_redirect_cfg.pool;

  bkey.key[0] = fproto;
  bkey.key[1] = (u64) rx_sw_if_index << 32 | fib_index;
  bkey.value = ipri;

  clib_bihash_add_del_16_8 (&ip_punt_redirect_cfg.punt_db, &bkey, 1);

  if (rx_sw_if_index != (u32) ~0)
    ip_punt_redirect_cfg.used_sw_if_indexes++;
  if (fib_index != (u32) ~0)
    ip_punt_redirect_cfg.used_table_ids++;

  fib_node_init (&ipr->node, FIB_NODE_TYPE_IP_PUNT_REDIRECT);
  ipr->fproto = fproto;
  ipr->payload_type = ct;

  ipr->pl = fib_path_list_create (FIB_PATH_LIST_FLAG_NO_URPF, rpaths);

  ipr->sibling = fib_path_list_child_add (ipr->pl,
					  FIB_NODE_TYPE_IP_PUNT_REDIRECT,
					  ipri);

  ip_punt_redirect_stack (ipr);
}

void
ip_punt_redirect_del (fib_protocol_t fproto, u32 rx_sw_if_index, u32 table_id)
{
  ip_punt_redirect_rx_t *ipr;
  clib_bihash_kv_16_8_t bkey;
  u32 fib_index = table_id;
  u32 ipri;

  if (INDEX_INVALID != table_id)
    fib_index = fib_table_find (fproto, table_id);

  ipri = ip_punt_redirect_find (fproto, rx_sw_if_index, fib_index);

  if (INDEX_INVALID == ipri)
    return;

  ipr = ip_punt_redirect_get (ipri);

  fib_path_list_child_remove (ipr->pl, ipr->sibling);
  dpo_reset (&ipr->dpo);
  pool_put (ip_punt_redirect_cfg.pool, ipr);

  bkey.key[0] = fproto;
  bkey.key[1] = (u64) rx_sw_if_index << 32 | fib_index;
  bkey.value = ipri;
  clib_bihash_add_del_16_8 (&ip_punt_redirect_cfg.punt_db, &bkey, 0);

  if (rx_sw_if_index != (u32) ~0)
    ip_punt_redirect_cfg.used_sw_if_indexes--;
  if (fib_index != (u32) ~0)
    ip_punt_redirect_cfg.used_table_ids--;
}

typedef struct format_ip_punt_redirect_arg_t_
{
  u8 *s;
  int idx;
} format_ip_punt_redirect_arg_t;

walk_rc_t
format_ip_punt_redirect_cb (u32 rx_sw_if_index, u32 table_id,
			    const ip_punt_redirect_rx_t *rx, void *_arg)
{
  format_ip_punt_redirect_arg_t *arg = (format_ip_punt_redirect_arg_t *) _arg;
  vnet_main_t *vnm = vnet_get_main ();
  u8 *s = arg->s;

  s = format (s, "[%d] %U", arg->idx++, format_fib_protocol, rx->fproto);

  if (INDEX_INVALID != table_id)
    s = format (s, " table %u", table_id);

  if (INDEX_INVALID != rx_sw_if_index)
    s = format (s, " rx %U via:\n", format_vnet_sw_if_index_name, vnm,
		rx_sw_if_index);

  if (INDEX_INVALID == rx_sw_if_index && INDEX_INVALID == table_id)
    s = format (s, " default");

  s = format (s, " via:\n");
  s = format (s, " %U", format_fib_path_list, rx->pl, 2);
  s = format (s, " forwarding\n", format_dpo_id, &rx->dpo, 0);
  s = format (s, "  %U\n", format_dpo_id, &rx->dpo, 0);

  arg->s = s;

  return (WALK_CONTINUE);
}

u8 *
format_ip_punt_redirect (u8 *s, va_list *args)
{
  format_ip_punt_redirect_arg_t _arg = { 0 }, *arg = &_arg;
  arg->s = s;

  ip_punt_redirect_walk (FIB_PROTOCOL_NONE, format_ip_punt_redirect_cb, arg);

  return (s);
}

static int
ip_punt_redirect_walk_cb (clib_bihash_kv_16_8_t *kvp, void *arg)
{
  ip_punt_redirect_walk_ctx_t *pctx = (ip_punt_redirect_walk_ctx_t *) arg;
  ip_punt_redirect_rx_t *rx;
  u32 rx_sw_if_index, fib_index, table_id = INDEX_INVALID;

  if (pctx->fproto != FIB_PROTOCOL_NONE && kvp->key[0] != pctx->fproto)
    return (BIHASH_WALK_CONTINUE);

  rx = ip_punt_redirect_get (kvp->value);

  rx_sw_if_index = kvp->key[1] >> 32;
  fib_index = kvp->key[1] & 0xffffffff;

  if (INDEX_INVALID != fib_index)
    table_id = fib_table_get_table_id (fib_index, pctx->fproto);

  pctx->cb (rx_sw_if_index, table_id, rx, pctx->ctx);

  return (BIHASH_WALK_CONTINUE);
}

void
ip_punt_redirect_walk (fib_protocol_t fproto, ip_punt_redirect_walk_cb_t cb,
		       void *ctx)
{
  ip_punt_redirect_walk_ctx_t _pctx, *pctx = &_pctx;
  pctx->fproto = fproto;
  pctx->cb = cb;
  pctx->ctx = ctx;
  clib_bihash_foreach_key_value_pair_16_8 (&ip_punt_redirect_cfg.punt_db,
					   ip_punt_redirect_walk_cb, pctx);
}

static fib_node_t *
ip_punt_redirect_get_node (fib_node_index_t index)
{
  ip_punt_redirect_rx_t *ipr = ip_punt_redirect_get (index);
  return (&(ipr->node));
}

static ip_punt_redirect_rx_t *
ip_punt_redirect_get_from_node (fib_node_t * node)
{
  return ((ip_punt_redirect_rx_t *) (((char *) node) -
				     STRUCT_OFFSET_OF (ip_punt_redirect_rx_t,
						       node)));
}

static void
ip_punt_redirect_last_lock_gone (fib_node_t * node)
{
  /*
   * the lifetime of the entry is managed by the table.
   */
  ASSERT (0);
}

/*
 * A back walk has reached this BIER entry
 */
static fib_node_back_walk_rc_t
ip_punt_redirect_back_walk_notify (fib_node_t * node,
				   fib_node_back_walk_ctx_t * ctx)
{
  /*
   * re-populate the ECMP tables with new choices
   */
  ip_punt_redirect_rx_t *ipr = ip_punt_redirect_get_from_node (node);

  ip_punt_redirect_stack (ipr);

  /*
   * no need to propagate further up the graph, since there's nothing there
   */
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The BIER fmask's graph node virtual function table
 */
static const fib_node_vft_t ip_punt_redirect_vft = {
  .fnv_get = ip_punt_redirect_get_node,
  .fnv_last_lock = ip_punt_redirect_last_lock_gone,
  .fnv_back_walk = ip_punt_redirect_back_walk_notify,
};

static clib_error_t *
ip_punt_drop_init (vlib_main_t * vm)
{
  fib_node_register_type (FIB_NODE_TYPE_IP_PUNT_REDIRECT,
			  &ip_punt_redirect_vft);

  clib_bihash_init_16_8 (&ip_punt_redirect_cfg.punt_db, "Punt DB", 1024,
			 2 << 20);

  ip_punt_redirect_cfg.used_table_ids = 0;
  ip_punt_redirect_cfg.used_sw_if_indexes = 0;

  ip4_punt_policer_cfg.fq_index =
    vlib_frame_queue_main_init (ip4_punt_policer_node.index, 0);
  ip6_punt_policer_cfg.fq_index =
    vlib_frame_queue_main_init (ip6_punt_policer_node.index, 0);

  return (NULL);
}

static clib_error_t *
ip_punt_config (vlib_main_t *vm, unformat_input_t *input)
{
  ip_punt_redirect_cfg.punt_hash_memory = IP_PUNT_DEFAULT_HASH_MEMORY;
  ip_punt_redirect_cfg.punt_hash_buckets = IP_PUNT_DEFAULT_HASH_BUCKETS;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "session-db-buckets %u",
		    &ip_punt_redirect_cfg.punt_hash_buckets))
	;
      else if (unformat (input, "session-db-memory %U", unformat_memory_size,
			 &ip_punt_redirect_cfg.punt_hash_memory))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (ip_punt_config, "punt");
VLIB_INIT_FUNCTION (ip_punt_drop_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
