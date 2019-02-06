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

#include <vnet/ipsec/ipsec.h>
#include <vnet/fib/fib_table.h>

static clib_error_t *
ipsec_call_add_del_callbacks (ipsec_main_t * im, ipsec_sa_t * sa,
			      u32 sa_index, int is_add)
{
  ipsec_ah_backend_t *ab;
  ipsec_esp_backend_t *eb;
  switch (sa->protocol)
    {
    case IPSEC_PROTOCOL_AH:
      ab = pool_elt_at_index (im->ah_backends, im->ah_current_backend);
      if (ab->add_del_sa_sess_cb)
	return ab->add_del_sa_sess_cb (sa_index, is_add);
      break;
    case IPSEC_PROTOCOL_ESP:
      eb = pool_elt_at_index (im->esp_backends, im->esp_current_backend);
      if (eb->add_del_sa_sess_cb)
	return eb->add_del_sa_sess_cb (sa_index, is_add);
      break;
    }
  return 0;
}

/**
 * 'stack' (resolve the recursion for) the SA tunnel destination
 */
void
ipsec_sa_stack (ipsec_sa_t * sa)
{
  fib_forward_chain_type_t fct;
  dpo_id_t tmp = DPO_INVALID;
  vlib_node_t *node;

  fct = fib_forw_chain_type_from_fib_proto ((sa->is_tunnel_ip6 ?
					     FIB_PROTOCOL_IP6 :
					     FIB_PROTOCOL_IP4));

  fib_entry_contribute_forwarding (sa->fib_entry_index, fct, &tmp);

  node = vlib_get_node_by_name (vlib_get_main (),
				(sa->is_tunnel_ip6 ?
				 (u8 *) "ah6-encrypt" :
				 (u8 *) "ah4-encrypt"));
  dpo_stack_from_node (node->index, &sa->dpo, &tmp);
}

int
ipsec_add_del_sa (vlib_main_t * vm, ipsec_sa_t * new_sa, int is_add)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa = 0;
  uword *p;
  u32 sa_index;
  clib_error_t *err;

  clib_warning ("id %u spi %u", new_sa->id, new_sa->spi);

  p = hash_get (im->sa_index_by_sa_id, new_sa->id);
  if (p && is_add)
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
  if (!p && !is_add)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (!is_add)			/* delete */
    {
      sa_index = p[0];
      sa = pool_elt_at_index (im->sad, sa_index);
      if (ipsec_is_sa_used (sa_index))
	{
	  clib_warning ("sa_id %u used in policy", sa->id);
	  return VNET_API_ERROR_SYSCALL_ERROR_1;	/* sa used in policy */
	}
      hash_unset (im->sa_index_by_sa_id, sa->id);
      err = ipsec_call_add_del_callbacks (im, sa, sa_index, 0);
      if (err)
	return VNET_API_ERROR_SYSCALL_ERROR_1;
      if (sa->is_tunnel)
	{
	  fib_entry_child_remove (sa->fib_entry_index, sa->sibling);
	  fib_table_entry_special_remove
	    (sa->tx_fib_index,
	     fib_entry_get_prefix (sa->fib_entry_index), FIB_SOURCE_RR);
	  dpo_reset (&sa->dpo);
	}
      pool_put (im->sad, sa);
    }
  else				/* create new SA */
    {
      pool_get (im->sad, sa);
      clib_memcpy (sa, new_sa, sizeof (*sa));
      fib_node_init (&sa->node, FIB_NODE_TYPE_IPSEC_SA);
      sa_index = sa - im->sad;
      hash_set (im->sa_index_by_sa_id, sa->id, sa_index);
      err = ipsec_call_add_del_callbacks (im, sa, sa_index, 1);
      if (err)
	return VNET_API_ERROR_SYSCALL_ERROR_1;

      if (sa->is_tunnel)
	{
	  fib_prefix_t pfx = {
	    .fp_addr = sa->tunnel_dst_addr,
	    .fp_len = (sa->is_tunnel_ip6 ? 128 : 32),
	    .fp_proto = (sa->is_tunnel_ip6 ?
			 FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4),
	  };
	  sa->fib_entry_index = fib_table_entry_special_add (sa->tx_fib_index,
							     &pfx,
							     FIB_SOURCE_RR,
							     FIB_ENTRY_FLAG_NONE);
	  sa->sibling = fib_entry_child_add (sa->fib_entry_index,
					     FIB_NODE_TYPE_IPSEC_SA,
					     sa_index);
	  ipsec_sa_stack (sa);
	}
    }
  return 0;
}

u8
ipsec_is_sa_used (u32 sa_index)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_tunnel_if_t *t;
  ipsec_policy_t *p;

  /* *INDENT-OFF* */
  pool_foreach(p, im->policies, ({
     if (p->policy == IPSEC_POLICY_ACTION_PROTECT)
       {
         if (p->sa_index == sa_index)
           return 1;
       }
  }));

  pool_foreach(t, im->tunnel_interfaces, ({
    if (t->input_sa_index == sa_index)
      return 1;
    if (t->output_sa_index == sa_index)
      return 1;
  }));
  /* *INDENT-ON* */

  return 0;
}

int
ipsec_set_sa_key (vlib_main_t * vm, ipsec_sa_t * sa_update)
{
  ipsec_main_t *im = &ipsec_main;
  uword *p;
  u32 sa_index;
  ipsec_sa_t *sa = 0;
  clib_error_t *err;

  p = hash_get (im->sa_index_by_sa_id, sa_update->id);
  if (!p)
    return VNET_API_ERROR_SYSCALL_ERROR_1;	/* no such sa-id */

  sa_index = p[0];
  sa = pool_elt_at_index (im->sad, sa_index);

  /* new crypto key */
  if (0 < sa_update->crypto_key_len)
    {
      clib_memcpy (sa->crypto_key, sa_update->crypto_key,
		   sa_update->crypto_key_len);
      sa->crypto_key_len = sa_update->crypto_key_len;
    }

  /* new integ key */
  if (0 < sa_update->integ_key_len)
    {
      clib_memcpy (sa->integ_key, sa_update->integ_key,
		   sa_update->integ_key_len);
      sa->integ_key_len = sa_update->integ_key_len;
    }

  if (0 < sa_update->crypto_key_len || 0 < sa_update->integ_key_len)
    {
      err = ipsec_call_add_del_callbacks (im, sa, sa_index, 0);
      if (err)
	return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  return 0;
}

u32
ipsec_get_sa_index_by_sa_id (u32 sa_id)
{
  ipsec_main_t *im = &ipsec_main;
  uword *p = hash_get (im->sa_index_by_sa_id, sa_id);
  if (!p)
    return ~0;

  return p[0];
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
ipsec_sa_fib_node_get (fib_node_index_t index)
{
  ipsec_main_t *im;
  ipsec_sa_t *sa;

  im = &ipsec_main;
  sa = pool_elt_at_index (im->sad, index);

  return (&sa->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
ipsec_sa_last_lock_gone (fib_node_t * node)
{
  /*
   * The ipsec SA is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

static ipsec_sa_t *
ipsec_sa_from_fib_node (fib_node_t * node)
{
  ASSERT (FIB_NODE_TYPE_IPSEC_SA == node->fn_type);
  return ((ipsec_sa_t *) (((char *) node) -
			  STRUCT_OFFSET_OF (ipsec_sa_t, node)));

}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
ipsec_sa_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  ipsec_sa_stack (ipsec_sa_from_fib_node (node));

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * Virtual function table registered by MPLS GRE tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t ipsec_sa_vft = {
  .fnv_get = ipsec_sa_fib_node_get,
  .fnv_last_lock = ipsec_sa_last_lock_gone,
  .fnv_back_walk = ipsec_sa_back_walk,
};

/* force inclusion from application's main.c */
clib_error_t *
ipsec_sa_interface_init (vlib_main_t * vm)
{
  fib_node_register_type (FIB_NODE_TYPE_IPSEC_SA, &ipsec_sa_vft);

  return 0;
}

VLIB_INIT_FUNCTION (ipsec_sa_interface_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
