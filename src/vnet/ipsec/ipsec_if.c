/*
 * ipsec_if.c : IPSec interface support
 *
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib.h>
#include <vnet/udp/udp.h>
#include <vnet/adj/adj_midchain.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>

void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);

static u8 *
format_ipsec_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  ipsec_main_t *im = &ipsec_main;
  ipsec_tunnel_if_t *t = im->tunnel_interfaces + dev_instance;

  return format (s, "ipsec%d", t->show_instance);
}

/* Statistics (not really errors) */
#define foreach_ipsec_if_tx_error    \
_(TX, "good packets transmitted")

static void
ipsec_if_tunnel_stack (adj_index_t ai)
{
  ipsec_main_t *ipm = &ipsec_main;
  ipsec_tunnel_if_t *it;
  ip_adjacency_t *adj;
  u32 sw_if_index;

  adj = adj_get (ai);
  sw_if_index = adj->rewrite_header.sw_if_index;

  if ((vec_len (ipm->ipsec_if_by_sw_if_index) <= sw_if_index) ||
      (~0 == ipm->ipsec_if_by_sw_if_index[sw_if_index]))
    return;

  it = pool_elt_at_index (ipm->tunnel_interfaces,
			  ipm->ipsec_if_by_sw_if_index[sw_if_index]);

  if (!vnet_hw_interface_is_link_up (vnet_get_main (), it->hw_if_index))
    {
      adj_midchain_delegate_unstack (ai);
    }
  else
    {
      ipsec_sa_t *sa;

      sa = ipsec_sa_get (it->output_sa_index);

      /* *INDENT-OFF* */
      fib_prefix_t pfx = {
	.fp_addr = sa->tunnel_dst_addr,
	.fp_len = (ipsec_sa_is_set_IS_TUNNEL_V6(sa) ? 128 : 32),
	.fp_proto = (ipsec_sa_is_set_IS_TUNNEL_V6(sa) ?
                     FIB_PROTOCOL_IP6 :
                     FIB_PROTOCOL_IP4),
      };
      /* *INDENT-ON* */

      adj_midchain_delegate_stack (ai, sa->tx_fib_index, &pfx);
    }
}

/**
 * @brief Call back when restacking all adjacencies on a GRE interface
 */
static adj_walk_rc_t
ipsec_if_adj_walk_cb (adj_index_t ai, void *ctx)
{
  ipsec_if_tunnel_stack (ai);

  return (ADJ_WALK_RC_CONTINUE);
}

static void
ipsec_if_tunnel_restack (ipsec_tunnel_if_t * it)
{
  fib_protocol_t proto;

  /*
   * walk all the adjacencies on th GRE interface and restack them
   */
  FOR_EACH_FIB_IP_PROTOCOL (proto)
  {
    adj_nbr_walk (it->sw_if_index, proto, ipsec_if_adj_walk_cb, NULL);
  }
}

static clib_error_t *
ipsec_admin_up_down_function (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  ipsec_main_t *im = &ipsec_main;
  clib_error_t *err = 0;
  ipsec_tunnel_if_t *t;
  vnet_hw_interface_t *hi;
  ipsec_sa_t *sa;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  t = pool_elt_at_index (im->tunnel_interfaces, hi->hw_instance);
  t->flags = flags;

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    {
      sa = pool_elt_at_index (im->sad, t->input_sa_index);

      err = ipsec_check_support_cb (im, sa);
      if (err)
	return err;

      err = ipsec_add_del_sa_sess_cb (im, t->input_sa_index, 1);
      if (err)
	return err;

      sa = pool_elt_at_index (im->sad, t->output_sa_index);

      err = ipsec_check_support_cb (im, sa);
      if (err)
	return err;

      err = ipsec_add_del_sa_sess_cb (im, t->output_sa_index, 1);
      if (err)
	return err;

      vnet_hw_interface_set_flags (vnm, hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, hw_if_index, 0 /* down */ );
      sa = pool_elt_at_index (im->sad, t->input_sa_index);
      err = ipsec_add_del_sa_sess_cb (im, t->input_sa_index, 0);
      if (err)
	return err;
      sa = pool_elt_at_index (im->sad, t->output_sa_index);
      err = ipsec_add_del_sa_sess_cb (im, t->output_sa_index, 0);
      if (err)
	return err;
    }

  ipsec_if_tunnel_restack (t);

  return (NULL);
}

static u8 *
ipsec_if_build_rewrite (vnet_main_t * vnm,
			u32 sw_if_index,
			vnet_link_t link_type, const void *dst_address)
{
  return (NULL);
}

static void
ipsec_if_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  adj_nbr_midchain_update_rewrite
    (ai, NULL, NULL, ADJ_FLAG_MIDCHAIN_IP_STACK,
     ipsec_if_build_rewrite (vnm, sw_if_index, adj_get_link_type (ai), NULL));

  ipsec_if_tunnel_stack (ai);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ipsec_device_class) =
{
  .name = "IPSec",
  .format_device_name = format_ipsec_name,
  .admin_up_down_function = ipsec_admin_up_down_function,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (ipsec_hw_class) =
{
  .name = "IPSec",
  .build_rewrite = default_build_rewrite,
  .update_adjacency = ipsec_if_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

static int
ipsec_add_del_tunnel_if_rpc_callback (ipsec_add_del_tunnel_args_t * a)
{
  vnet_main_t *vnm = vnet_get_main ();
  ASSERT (vlib_get_thread_index () == 0);

  return ipsec_add_del_tunnel_if_internal (vnm, a, NULL);
}

int
ipsec_add_del_tunnel_if (ipsec_add_del_tunnel_args_t * args)
{
  vl_api_rpc_call_main_thread (ipsec_add_del_tunnel_if_rpc_callback,
			       (u8 *) args, sizeof (*args));
  return 0;
}

static u32
ipsec_tun_mk_input_sa_id (u32 ti)
{
  return (0x80000000 | ti);
}

static u32
ipsec_tun_mk_output_sa_id (u32 ti)
{
  return (0xc0000000 | ti);
}

static void
ipsec_tunnel_feature_set (ipsec_main_t * im, ipsec_tunnel_if_t * t, u8 enable)
{
  u8 arc;

  arc = vnet_get_feature_arc_index ("ip4-output");

  vnet_feature_enable_disable_with_index (arc,
					  im->esp4_encrypt_tun_feature_index,
					  t->sw_if_index, enable,
					  &t->output_sa_index,
					  sizeof (t->output_sa_index));

  arc = vnet_get_feature_arc_index ("ip6-output");

  vnet_feature_enable_disable_with_index (arc,
					  im->esp6_encrypt_tun_feature_index,
					  t->sw_if_index, enable,
					  &t->output_sa_index,
					  sizeof (t->output_sa_index));
}

int
ipsec_add_del_tunnel_if_internal (vnet_main_t * vnm,
				  ipsec_add_del_tunnel_args_t * args,
				  u32 * sw_if_index)
{
  ipsec_tunnel_if_t *t;
  ipsec_main_t *im = &ipsec_main;
  vnet_hw_interface_t *hi = NULL;
  u32 hw_if_index = ~0;
  uword *p;
  u32 dev_instance;
  ipsec_key_t crypto_key, integ_key;
  ipsec_sa_flags_t flags;
  int rv;
  int is_ip6 = args->is_ip6;
  ipsec4_tunnel_key_t key4;
  ipsec6_tunnel_key_t key6;

  if (!is_ip6)
    {
      key4.remote_ip = args->remote_ip.ip4.as_u32;
      key4.spi = clib_host_to_net_u32 (args->remote_spi);
      p = hash_get (im->ipsec4_if_pool_index_by_key, key4.as_u64);
    }
  else
    {
      key6.remote_ip = args->remote_ip.ip6;
      key6.spi = clib_host_to_net_u32 (args->remote_spi);
      p = hash_get_mem (im->ipsec6_if_pool_index_by_key, &key6);
    }

  if (args->is_add)
    {
      /* check if same src/dst pair exists */
      if (p)
	return VNET_API_ERROR_INVALID_VALUE;

      pool_get_aligned_zero (im->tunnel_interfaces, t, CLIB_CACHE_LINE_BYTES);

      dev_instance = t - im->tunnel_interfaces;
      if (args->renumber)
	t->show_instance = args->show_instance;
      else
	t->show_instance = dev_instance;

      if (hash_get (im->ipsec_if_real_dev_by_show_dev, t->show_instance))
	{
	  pool_put (im->tunnel_interfaces, t);
	  return VNET_API_ERROR_INSTANCE_IN_USE;
	}

      hash_set (im->ipsec_if_real_dev_by_show_dev, t->show_instance,
		dev_instance);

      flags = IPSEC_SA_FLAG_IS_TUNNEL;
      if (args->is_ip6)
	flags |= IPSEC_SA_FLAG_IS_TUNNEL_V6;
      if (args->udp_encap)
	flags |= IPSEC_SA_FLAG_UDP_ENCAP;
      if (args->esn)
	flags |= IPSEC_SA_FLAG_USE_ESN;
      if (args->anti_replay)
	flags |= IPSEC_SA_FLAG_USE_ANTI_REPLAY;

      ipsec_mk_key (&crypto_key,
		    args->remote_crypto_key, args->remote_crypto_key_len);
      ipsec_mk_key (&integ_key,
		    args->remote_integ_key, args->remote_integ_key_len);

      rv = ipsec_sa_add (ipsec_tun_mk_input_sa_id (dev_instance),
			 args->remote_spi,
			 IPSEC_PROTOCOL_ESP,
			 args->crypto_alg,
			 &crypto_key,
			 args->integ_alg,
			 &integ_key,
			 (flags | IPSEC_SA_FLAG_IS_INBOUND),
			 args->tx_table_id,
			 args->salt,
			 &args->remote_ip,
			 &args->local_ip, &t->input_sa_index);

      if (rv)
	return VNET_API_ERROR_INVALID_SRC_ADDRESS;

      ipsec_mk_key (&crypto_key,
		    args->local_crypto_key, args->local_crypto_key_len);
      ipsec_mk_key (&integ_key,
		    args->local_integ_key, args->local_integ_key_len);

      rv = ipsec_sa_add (ipsec_tun_mk_output_sa_id (dev_instance),
			 args->local_spi,
			 IPSEC_PROTOCOL_ESP,
			 args->crypto_alg,
			 &crypto_key,
			 args->integ_alg,
			 &integ_key,
			 flags,
			 args->tx_table_id,
			 args->salt,
			 &args->local_ip,
			 &args->remote_ip, &t->output_sa_index);

      if (rv)
	return VNET_API_ERROR_INVALID_DST_ADDRESS;

      /* copy the key */
      if (is_ip6)
	hash_set_mem_alloc (&im->ipsec6_if_pool_index_by_key, &key6,
			    t - im->tunnel_interfaces);
      else
	hash_set (im->ipsec4_if_pool_index_by_key, key4.as_u64,
		  t - im->tunnel_interfaces);

      hw_if_index = vnet_register_interface (vnm, ipsec_device_class.index,
					     t - im->tunnel_interfaces,
					     ipsec_hw_class.index,
					     t - im->tunnel_interfaces);

      hi = vnet_get_hw_interface (vnm, hw_if_index);

      t->hw_if_index = hw_if_index;
      t->sw_if_index = hi->sw_if_index;

      /* Standard default jumbo MTU. */
      vnet_sw_interface_set_mtu (vnm, t->sw_if_index, 9000);

      /* Add the new tunnel to the DB of tunnels per sw_if_index ... */
      vec_validate_init_empty (im->ipsec_if_by_sw_if_index, t->sw_if_index,
			       ~0);
      im->ipsec_if_by_sw_if_index[t->sw_if_index] = dev_instance;

      ipsec_tunnel_feature_set (im, t, 1);

      /*1st interface, register protocol */
      if (pool_elts (im->tunnel_interfaces) == 1)
	{
	  ip4_register_protocol (IP_PROTOCOL_IPSEC_ESP,
				 ipsec4_if_input_node.index);
	  ip6_register_protocol (IP_PROTOCOL_IPSEC_ESP,
				 ipsec6_if_input_node.index);
	}

    }
  else
    {
      u32 ti;

      /* check if exists */
      if (!p)
	return VNET_API_ERROR_INVALID_VALUE;

      ti = p[0];
      t = pool_elt_at_index (im->tunnel_interfaces, ti);
      hi = vnet_get_hw_interface (vnm, t->hw_if_index);
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 0);	/* admin down */

      ipsec_tunnel_feature_set (im, t, 0);
      vnet_delete_hw_interface (vnm, t->hw_if_index);

      if (is_ip6)
	hash_unset_mem_free (&im->ipsec6_if_pool_index_by_key, &key6);
      else
	hash_unset (im->ipsec4_if_pool_index_by_key, key4.as_u64);

      hash_unset (im->ipsec_if_real_dev_by_show_dev, t->show_instance);
      im->ipsec_if_by_sw_if_index[t->sw_if_index] = ~0;

      pool_put (im->tunnel_interfaces, t);

      /* delete input and output SA */
      ipsec_sa_del (ipsec_tun_mk_input_sa_id (ti));
      ipsec_sa_del (ipsec_tun_mk_output_sa_id (ti));
    }

  if (sw_if_index)
    *sw_if_index = hi->sw_if_index;

  return 0;
}

int
ipsec_add_del_ipsec_gre_tunnel (vnet_main_t * vnm,
				const ipsec_gre_tunnel_add_del_args_t * args)
{
  ipsec_tunnel_if_t *t = 0;
  ipsec_main_t *im = &ipsec_main;
  uword *p;
  ipsec_sa_t *sa;
  ipsec4_tunnel_key_t key;
  u32 isa, osa;

  p = hash_get (im->sa_index_by_sa_id, args->local_sa_id);
  if (!p)
    return VNET_API_ERROR_INVALID_VALUE;
  osa = p[0];
  sa = pool_elt_at_index (im->sad, p[0]);
  ipsec_sa_set_IS_GRE (sa);

  p = hash_get (im->sa_index_by_sa_id, args->remote_sa_id);
  if (!p)
    return VNET_API_ERROR_INVALID_VALUE;
  isa = p[0];
  sa = pool_elt_at_index (im->sad, p[0]);
  ipsec_sa_set_IS_GRE (sa);

  /* we form the key from the input/remote SA whose tunnel is srouce
   * at the remote end */
  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    {
      key.remote_ip = sa->tunnel_src_addr.ip4.as_u32;
      key.spi = clib_host_to_net_u32 (sa->spi);
    }
  else
    {
      key.remote_ip = args->src.as_u32;
      key.spi = clib_host_to_net_u32 (sa->spi);
    }

  p = hash_get (im->ipsec4_if_pool_index_by_key, key.as_u64);

  if (args->is_add)
    {
      /* check if same src/dst pair exists */
      if (p)
	return VNET_API_ERROR_INVALID_VALUE;

      pool_get_aligned (im->tunnel_interfaces, t, CLIB_CACHE_LINE_BYTES);
      clib_memset (t, 0, sizeof (*t));

      t->input_sa_index = isa;
      t->output_sa_index = osa;
      t->hw_if_index = ~0;
      hash_set (im->ipsec4_if_pool_index_by_key, key.as_u64,
		t - im->tunnel_interfaces);

      /*1st interface, register protocol */
      if (pool_elts (im->tunnel_interfaces) == 1)
	{
	  ip4_register_protocol (IP_PROTOCOL_IPSEC_ESP,
				 ipsec4_if_input_node.index);
	  /* TBD, GRE IPSec6
	   *
	   ip6_register_protocol (IP_PROTOCOL_IPSEC_ESP,
	   ipsec6_if_input_node.index);
	   */
	}
    }
  else
    {
      /* check if exists */
      if (!p)
	return VNET_API_ERROR_INVALID_VALUE;

      t = pool_elt_at_index (im->tunnel_interfaces, p[0]);
      hash_unset (im->ipsec4_if_pool_index_by_key, key.as_u64);
      pool_put (im->tunnel_interfaces, t);
    }
  return 0;
}

int
ipsec_set_interface_key (vnet_main_t * vnm, u32 hw_if_index,
			 ipsec_if_set_key_type_t type, u8 alg, u8 * key)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  vnet_hw_interface_t *hi;
  ipsec_tunnel_if_t *t;
  ipsec_sa_t *sa;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  t = pool_elt_at_index (im->tunnel_interfaces, hi->dev_instance);

  if (hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP)
    return VNET_API_ERROR_SYSCALL_ERROR_1;

  if (type == IPSEC_IF_SET_KEY_TYPE_LOCAL_CRYPTO)
    {
      sa = pool_elt_at_index (im->sad, t->output_sa_index);
      ipsec_sa_set_crypto_alg (sa, alg);
      ipsec_mk_key (&sa->crypto_key, key, vec_len (key));
      sa->crypto_calg = im->crypto_algs[alg].alg;
      vnet_crypto_key_modify (vm, sa->crypto_key_index, sa->crypto_calg,
			      key, vec_len (key));
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG)
    {
      sa = pool_elt_at_index (im->sad, t->output_sa_index);
      ipsec_sa_set_integ_alg (sa, alg);
      ipsec_mk_key (&sa->integ_key, key, vec_len (key));
      sa->integ_calg = im->integ_algs[alg].alg;
      vnet_crypto_key_modify (vm, sa->integ_key_index, sa->integ_calg,
			      key, vec_len (key));
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO)
    {
      sa = pool_elt_at_index (im->sad, t->input_sa_index);
      ipsec_sa_set_crypto_alg (sa, alg);
      ipsec_mk_key (&sa->crypto_key, key, vec_len (key));
      sa->crypto_calg = im->crypto_algs[alg].alg;
      vnet_crypto_key_modify (vm, sa->crypto_key_index, sa->crypto_calg,
			      key, vec_len (key));
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG)
    {
      sa = pool_elt_at_index (im->sad, t->input_sa_index);
      ipsec_sa_set_integ_alg (sa, alg);
      ipsec_mk_key (&sa->integ_key, key, vec_len (key));
      sa->integ_calg = im->integ_algs[alg].alg;
      vnet_crypto_key_modify (vm, sa->integ_key_index, sa->integ_calg,
			      key, vec_len (key));
    }
  else
    return VNET_API_ERROR_INVALID_VALUE;

  return 0;
}


int
ipsec_set_interface_sa (vnet_main_t * vnm, u32 hw_if_index, u32 sa_id,
			u8 is_outbound)
{
  ipsec_main_t *im = &ipsec_main;
  vnet_hw_interface_t *hi;
  ipsec_tunnel_if_t *t;
  ipsec_sa_t *sa, *old_sa;
  u32 sa_index, old_sa_index;
  uword *p;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  t = pool_elt_at_index (im->tunnel_interfaces, hi->dev_instance);

  sa_index = ipsec_get_sa_index_by_sa_id (sa_id);
  if (sa_index == ~0)
    {
      clib_warning ("SA with ID %u not found", sa_id);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  if (ipsec_is_sa_used (sa_index))
    {
      clib_warning ("SA with ID %u is already in use", sa_id);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  sa = pool_elt_at_index (im->sad, sa_index);

  if (!is_outbound)
    {
      old_sa_index = t->input_sa_index;
      old_sa = pool_elt_at_index (im->sad, old_sa_index);

      if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ^
	  ipsec_sa_is_set_IS_TUNNEL_V6 (old_sa))
	{
	  clib_warning ("IPsec interface SA endpoints type can't be changed");
	  return VNET_API_ERROR_INVALID_VALUE;
	}

      if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
	{
	  ipsec6_tunnel_key_t key;

	  /* unset old inbound hash entry. packets should stop arriving */
	  key.remote_ip = old_sa->tunnel_src_addr.ip6;
	  key.spi = clib_host_to_net_u32 (old_sa->spi);

	  p = hash_get_mem (im->ipsec6_if_pool_index_by_key, &key);
	  if (p)
	    hash_unset_mem_free (&im->ipsec6_if_pool_index_by_key, &key);

	  /* set new inbound SA, then set new hash entry */
	  t->input_sa_index = sa_index;
	  key.remote_ip = sa->tunnel_src_addr.ip6;
	  key.spi = clib_host_to_net_u32 (sa->spi);

	  hash_set_mem_alloc (&im->ipsec6_if_pool_index_by_key, &key,
			      hi->dev_instance);
	}
      else
	{
	  ipsec4_tunnel_key_t key;

	  /* unset old inbound hash entry. packets should stop arriving */
	  key.remote_ip = old_sa->tunnel_src_addr.ip4.as_u32;
	  key.spi = clib_host_to_net_u32 (old_sa->spi);

	  p = hash_get (im->ipsec4_if_pool_index_by_key, key.as_u64);
	  if (p)
	    hash_unset (im->ipsec4_if_pool_index_by_key, key.as_u64);

	  /* set new inbound SA, then set new hash entry */
	  t->input_sa_index = sa_index;
	  key.remote_ip = sa->tunnel_src_addr.ip4.as_u32;
	  key.spi = clib_host_to_net_u32 (sa->spi);

	  hash_set (im->ipsec4_if_pool_index_by_key, key.as_u64,
		    hi->dev_instance);
	}
    }
  else
    {
      old_sa_index = t->output_sa_index;
      old_sa = pool_elt_at_index (im->sad, old_sa_index);

      if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ^
	  ipsec_sa_is_set_IS_TUNNEL_V6 (old_sa))
	{
	  clib_warning ("IPsec interface SA endpoints type can't be changed");
	  return VNET_API_ERROR_INVALID_VALUE;
	}

      /*
       * re-enable the feature to get the new SA in
       * the workers are stopped so no packets are sent in the clear
       */
      ipsec_tunnel_feature_set (im, t, 0);
      t->output_sa_index = sa_index;
      ipsec_tunnel_feature_set (im, t, 1);
    }

  /* remove sa_id to sa_index mapping on old SA */
  if (ipsec_get_sa_index_by_sa_id (old_sa->id) == old_sa_index)
    hash_unset (im->sa_index_by_sa_id, old_sa->id);

  if (ipsec_add_del_sa_sess_cb (im, old_sa_index, 0))
    {
      clib_warning ("IPsec backend add/del callback returned error");
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  ipsec_sa_del (old_sa->id);

  return 0;
}

clib_error_t *
ipsec_tunnel_if_init (vlib_main_t * vm)
{
  ipsec_main_t *im = &ipsec_main;

  /* initialize the ipsec-if ip4 hash */
  im->ipsec4_if_pool_index_by_key =
    hash_create (0, sizeof (ipsec4_tunnel_key_t));
  /* initialize the ipsec-if ip6 hash */
  im->ipsec6_if_pool_index_by_key = hash_create_mem (0,
						     sizeof
						     (ipsec6_tunnel_key_t),
						     sizeof (uword));
  im->ipsec_if_real_dev_by_show_dev = hash_create (0, sizeof (uword));

  udp_register_dst_port (vm, UDP_DST_PORT_ipsec, ipsec4_if_input_node.index,
			 1);
  return 0;
}

VLIB_INIT_FUNCTION (ipsec_tunnel_if_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
