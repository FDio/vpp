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
#include <vnet/ipsec/esp.h>
#include <vnet/udp/udp.h>
#include <vnet/fib/fib_table.h>

/**
 * @brief
 * SA packet & bytes counters
 */
vlib_combined_counter_main_t ipsec_sa_counters = {
  .name = "SA",
  .stat_segment_name = "/net/ipsec/sa",
};


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

void
ipsec_mk_key (ipsec_key_t * key, const u8 * data, u8 len)
{
  memset (key, 0, sizeof (*key));

  if (len > sizeof (key->data))
    key->len = sizeof (key->data);
  else
    key->len = len;

  memcpy (key->data, data, key->len);
}

/**
 * 'stack' (resolve the recursion for) the SA tunnel destination
 */
static void
ipsec_sa_stack (ipsec_sa_t * sa)
{
  ipsec_main_t *im = &ipsec_main;
  fib_forward_chain_type_t fct;
  dpo_id_t tmp = DPO_INVALID;

  fct =
    fib_forw_chain_type_from_fib_proto ((ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
					 FIB_PROTOCOL_IP6 :
					 FIB_PROTOCOL_IP4));

  fib_entry_contribute_forwarding (sa->fib_entry_index, fct, &tmp);

  dpo_stack_from_node ((ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
			im->ah6_encrypt_node_index :
			im->ah4_encrypt_node_index),
		       &sa->dpo[IPSEC_PROTOCOL_AH], &tmp);
  dpo_stack_from_node ((ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
			im->esp6_encrypt_node_index :
			im->esp4_encrypt_node_index),
		       &sa->dpo[IPSEC_PROTOCOL_ESP], &tmp);
  dpo_reset (&tmp);
}

void
ipsec_sa_set_crypto_alg (ipsec_sa_t * sa, ipsec_crypto_alg_t crypto_alg)
{
  ipsec_main_t *im = &ipsec_main;
  sa->crypto_alg = crypto_alg;
  sa->crypto_iv_size = im->crypto_algs[crypto_alg].iv_size;
  sa->crypto_block_size = im->crypto_algs[crypto_alg].block_size;
  sa->crypto_enc_op_id = im->crypto_algs[crypto_alg].enc_op_id;
  sa->crypto_dec_op_id = im->crypto_algs[crypto_alg].dec_op_id;
  sa->crypto_calg = im->crypto_algs[crypto_alg].alg;
  ASSERT (sa->crypto_iv_size <= ESP_MAX_IV_SIZE);
  ASSERT (sa->crypto_block_size <= ESP_MAX_BLOCK_SIZE);
  if (IPSEC_CRYPTO_ALG_IS_GCM (crypto_alg))
    {
      sa->integ_icv_size = im->crypto_algs[crypto_alg].icv_size;
      ipsec_sa_set_IS_AEAD (sa);
    }
}

void
ipsec_sa_set_integ_alg (ipsec_sa_t * sa, ipsec_integ_alg_t integ_alg)
{
  ipsec_main_t *im = &ipsec_main;
  sa->integ_alg = integ_alg;
  sa->integ_icv_size = im->integ_algs[integ_alg].icv_size;
  sa->integ_op_id = im->integ_algs[integ_alg].op_id;
  sa->integ_calg = im->integ_algs[integ_alg].alg;
  ASSERT (sa->integ_icv_size <= ESP_MAX_ICV_SIZE);
}

int
ipsec_sa_add (u32 id,
	      u32 spi,
	      ipsec_protocol_t proto,
	      ipsec_crypto_alg_t crypto_alg,
	      const ipsec_key_t * ck,
	      ipsec_integ_alg_t integ_alg,
	      const ipsec_key_t * ik,
	      ipsec_sa_flags_t flags,
	      u32 tx_table_id,
	      u32 salt,
	      const ip46_address_t * tun_src,
	      const ip46_address_t * tun_dst, u32 * sa_out_index)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  clib_error_t *err;
  ipsec_sa_t *sa;
  u32 sa_index;
  uword *p;

  p = hash_get (im->sa_index_by_sa_id, id);
  if (p)
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

  pool_get_aligned_zero (im->sad, sa, CLIB_CACHE_LINE_BYTES);

  fib_node_init (&sa->node, FIB_NODE_TYPE_IPSEC_SA);
  sa_index = sa - im->sad;

  vlib_validate_combined_counter (&ipsec_sa_counters, sa_index);
  vlib_zero_combined_counter (&ipsec_sa_counters, sa_index);

  sa->id = id;
  sa->spi = spi;
  sa->stat_index = sa_index;
  sa->protocol = proto;
  sa->flags = flags;
  sa->salt = salt;
  ipsec_sa_set_integ_alg (sa, integ_alg);
  clib_memcpy (&sa->integ_key, ik, sizeof (sa->integ_key));
  ipsec_sa_set_crypto_alg (sa, crypto_alg);
  clib_memcpy (&sa->crypto_key, ck, sizeof (sa->crypto_key));
  ip46_address_copy (&sa->tunnel_src_addr, tun_src);
  ip46_address_copy (&sa->tunnel_dst_addr, tun_dst);

  sa->crypto_key_index = vnet_crypto_key_add (vm,
					      im->crypto_algs[crypto_alg].alg,
					      (u8 *) ck->data, ck->len);
  sa->integ_key_index = vnet_crypto_key_add (vm,
					     im->integ_algs[integ_alg].alg,
					     (u8 *) ik->data, ik->len);

  err = ipsec_check_support_cb (im, sa);
  if (err)
    {
      clib_warning ("%s", err->what);
      pool_put (im->sad, sa);
      return VNET_API_ERROR_UNIMPLEMENTED;
    }

  err = ipsec_call_add_del_callbacks (im, sa, sa_index, 1);
  if (err)
    {
      pool_put (im->sad, sa);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  if (ipsec_sa_is_set_IS_TUNNEL (sa) && !ipsec_sa_is_set_IS_INBOUND (sa))
    {
      fib_protocol_t fproto = (ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ?
			       FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
      fib_prefix_t pfx = {
	.fp_addr = sa->tunnel_dst_addr,
	.fp_len = (ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ? 128 : 32),
	.fp_proto = fproto,
      };
      sa->tx_fib_index = fib_table_find (fproto, tx_table_id);
      if (sa->tx_fib_index == ~((u32) 0))
	{
	  pool_put (im->sad, sa);
	  return VNET_API_ERROR_NO_SUCH_FIB;
	}

      sa->fib_entry_index = fib_table_entry_special_add (sa->tx_fib_index,
							 &pfx,
							 FIB_SOURCE_RR,
							 FIB_ENTRY_FLAG_NONE);
      sa->sibling = fib_entry_child_add (sa->fib_entry_index,
					 FIB_NODE_TYPE_IPSEC_SA, sa_index);
      ipsec_sa_stack (sa);

      /* generate header templates */
      if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
	{
	  sa->ip6_hdr.ip_version_traffic_class_and_flow_label = 0x60;
	  sa->ip6_hdr.hop_limit = 254;
	  sa->ip6_hdr.src_address.as_u64[0] =
	    sa->tunnel_src_addr.ip6.as_u64[0];
	  sa->ip6_hdr.src_address.as_u64[1] =
	    sa->tunnel_src_addr.ip6.as_u64[1];
	  sa->ip6_hdr.dst_address.as_u64[0] =
	    sa->tunnel_dst_addr.ip6.as_u64[0];
	  sa->ip6_hdr.dst_address.as_u64[1] =
	    sa->tunnel_dst_addr.ip6.as_u64[1];
	  if (ipsec_sa_is_set_UDP_ENCAP (sa))
	    sa->ip6_hdr.protocol = IP_PROTOCOL_UDP;
	  else
	    sa->ip6_hdr.protocol = IP_PROTOCOL_IPSEC_ESP;
	}
      else
	{
	  sa->ip4_hdr.ip_version_and_header_length = 0x45;
	  sa->ip4_hdr.ttl = 254;
	  sa->ip4_hdr.src_address.as_u32 = sa->tunnel_src_addr.ip4.as_u32;
	  sa->ip4_hdr.dst_address.as_u32 = sa->tunnel_dst_addr.ip4.as_u32;

	  if (ipsec_sa_is_set_UDP_ENCAP (sa))
	    sa->ip4_hdr.protocol = IP_PROTOCOL_UDP;
	  else
	    sa->ip4_hdr.protocol = IP_PROTOCOL_IPSEC_ESP;
	  sa->ip4_hdr.checksum = ip4_header_checksum (&sa->ip4_hdr);
	}
    }

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    {
      sa->udp_hdr.src_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
      sa->udp_hdr.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
    }

  hash_set (im->sa_index_by_sa_id, sa->id, sa_index);

  if (sa_out_index)
    *sa_out_index = sa_index;

  return (0);
}

u32
ipsec_sa_del (u32 id)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa = 0;
  uword *p;
  u32 sa_index;
  clib_error_t *err;

  p = hash_get (im->sa_index_by_sa_id, id);

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  sa_index = p[0];
  sa = pool_elt_at_index (im->sad, sa_index);
  if (ipsec_is_sa_used (sa_index))
    {
      clib_warning ("sa_id %u used in policy", sa->id);
      /* sa used in policy */
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  hash_unset (im->sa_index_by_sa_id, sa->id);
  err = ipsec_call_add_del_callbacks (im, sa, sa_index, 0);
  if (err)
    return VNET_API_ERROR_SYSCALL_ERROR_2;

  if (ipsec_sa_is_set_IS_TUNNEL (sa) && !ipsec_sa_is_set_IS_INBOUND (sa))
    {
      fib_entry_child_remove (sa->fib_entry_index, sa->sibling);
      fib_table_entry_special_remove
	(sa->tx_fib_index,
	 fib_entry_get_prefix (sa->fib_entry_index), FIB_SOURCE_RR);
      dpo_reset (&sa->dpo[IPSEC_PROTOCOL_AH]);
      dpo_reset (&sa->dpo[IPSEC_PROTOCOL_ESP]);
    }
  vnet_crypto_key_del (vm, sa->crypto_key_index);
  vnet_crypto_key_del (vm, sa->integ_key_index);
  pool_put (im->sad, sa);
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
ipsec_set_sa_key (u32 id, const ipsec_key_t * ck, const ipsec_key_t * ik)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  uword *p;
  u32 sa_index;
  ipsec_sa_t *sa = 0;
  clib_error_t *err;

  p = hash_get (im->sa_index_by_sa_id, id);
  if (!p)
    return VNET_API_ERROR_SYSCALL_ERROR_1;	/* no such sa-id */

  sa_index = p[0];
  sa = pool_elt_at_index (im->sad, sa_index);

  /* new crypto key */
  if (ck)
    {
      clib_memcpy (&sa->crypto_key, ck, sizeof (sa->crypto_key));
      vnet_crypto_key_modify (vm, sa->crypto_key_index, sa->crypto_calg,
			      (u8 *) ck->data, ck->len);
    }

  /* new integ key */
  if (ik)
    {
      clib_memcpy (&sa->integ_key, 0, sizeof (sa->integ_key));
      vnet_crypto_key_modify (vm, sa->integ_key_index, sa->integ_calg,
			      (u8 *) ik->data, ik->len);
    }

  if (ck || ik)
    {
      err = ipsec_call_add_del_callbacks (im, sa, sa_index, 0);
      if (err)
	{
	  clib_error_free (err);
	  return VNET_API_ERROR_SYSCALL_ERROR_1;
	}
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

void
ipsec_sa_walk (ipsec_sa_walk_cb_t cb, void *ctx)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;

  /* *INDENT-OFF* */
  pool_foreach (sa, im->sad,
  ({
    if (WALK_CONTINUE != cb(sa, ctx))
      break;
  }));
  /* *INDENT-ON* */
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
