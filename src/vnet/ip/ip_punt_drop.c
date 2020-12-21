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

ip_punt_redirect_cfg_t ip_punt_redirect_cfg;

u8 *
format_ip_punt_redirect_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_punt_redirect_trace_t *t = va_arg (*args, ip_punt_redirect_trace_t *);

  if (INDEX_INVALID == t->rrxi)
    s = format (s, "ignore");
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
ip_punt_redirect_find (fib_protocol_t fproto, u32 rx_sw_if_index)
{
  index_t *rxs;

  rxs = ip_punt_redirect_cfg.redirect_by_rx_sw_if_index[fproto];

  if (vec_len (rxs) <= rx_sw_if_index)
    return (INDEX_INVALID);

  return rxs[rx_sw_if_index];
}

void
ip_punt_redirect_add (fib_protocol_t fproto,
		      u32 rx_sw_if_index,
		      fib_forward_chain_type_t ct, fib_route_path_t * rpaths)
{
  ip_punt_redirect_rx_t *ipr;
  index_t ipri;

  if (~0 == rx_sw_if_index)
    rx_sw_if_index = 0;

  vec_validate_init_empty (ip_punt_redirect_cfg.redirect_by_rx_sw_if_index
			   [fproto], rx_sw_if_index, INDEX_INVALID);

  pool_get (ip_punt_redirect_cfg.pool, ipr);
  ipri = ipr - ip_punt_redirect_cfg.pool;

  ip_punt_redirect_cfg.redirect_by_rx_sw_if_index[fproto][rx_sw_if_index] =
    ipri;

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
ip_punt_redirect_del (fib_protocol_t fproto, u32 rx_sw_if_index)
{
  ip_punt_redirect_rx_t *ipr;
  index_t *rxs;

  if (~0 == rx_sw_if_index)
    rx_sw_if_index = 0;

  rxs = ip_punt_redirect_cfg.redirect_by_rx_sw_if_index[fproto];

  if ((vec_len (rxs) <= rx_sw_if_index) ||
      (INDEX_INVALID == rxs[rx_sw_if_index]))
    return;

  ipr = ip_punt_redirect_get (rxs[rx_sw_if_index]);

  fib_path_list_child_remove (ipr->pl, ipr->sibling);
  dpo_reset (&ipr->dpo);
  pool_put (ip_punt_redirect_cfg.pool, ipr);

  rxs[rx_sw_if_index] = INDEX_INVALID;
}

u8 *
format_ip_punt_redirect (u8 * s, va_list * args)
{
  fib_protocol_t fproto = va_arg (*args, int);
  ip_punt_redirect_rx_t *rx;
  index_t *rxs;
  u32 rx_sw_if_index;
  vnet_main_t *vnm = vnet_get_main ();

  rxs = ip_punt_redirect_cfg.redirect_by_rx_sw_if_index[fproto];

  vec_foreach_index (rx_sw_if_index, rxs)
  {
    if (INDEX_INVALID == rxs[rx_sw_if_index])
      continue;

    rx = ip_punt_redirect_get (rxs[rx_sw_if_index]);

    s = format (s, " rx %U via:\n",
		format_vnet_sw_interface_name, vnm,
		vnet_get_sw_interface (vnm, rx_sw_if_index));
    s = format (s, " %U", format_fib_path_list, rx->pl, 2);
    s = format (s, " forwarding\n", format_dpo_id, &rx->dpo, 0);
    s = format (s, "  %U\n", format_dpo_id, &rx->dpo, 0);
  }

  return (s);
}

void
ip_punt_redirect_walk (fib_protocol_t fproto,
		       ip_punt_redirect_walk_cb_t cb, void *ctx)
{
  ip_punt_redirect_rx_t *rx;
  u32 ii, rx_sw_if_index;
  index_t *rxs;

  rxs = ip_punt_redirect_cfg.redirect_by_rx_sw_if_index[fproto];

  vec_foreach_index (ii, rxs)
  {
    if (INDEX_INVALID == rxs[ii])
      continue;

    rx = ip_punt_redirect_get (rxs[ii]);

    rx_sw_if_index = (ii == 0 ? ~0 : ii);
    cb (rx_sw_if_index, rx, ctx);
  }
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

  return (NULL);
}

VLIB_INIT_FUNCTION (ip_punt_drop_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
