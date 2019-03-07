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

static char *ipsec_if_tx_error_strings[] = {
#define _(sym,string) string,
  foreach_ipsec_if_tx_error
#undef _
};

typedef enum
{
#define _(sym,str) IPSEC_IF_OUTPUT_ERROR_##sym,
  foreach_ipsec_if_tx_error
#undef _
    IPSEC_IF_TX_N_ERROR,
} ipsec_if_tx_error_t;

typedef struct
{
  u32 spi;
  u32 seq;
} ipsec_if_tx_trace_t;

u8 *
format_ipsec_if_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_if_tx_trace_t *t = va_arg (*args, ipsec_if_tx_trace_t *);

  s = format (s, "IPSec: spi %u seq %u", t->spi, t->seq);
  return s;
}

static void
ipsec_output_trace (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame, const ipsec_tunnel_if_t * t0)
{
  ipsec_main_t *im = &ipsec_main;
  u32 *from, n_left;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left > 0)
    {
      vlib_buffer_t *b0;

      b0 = vlib_get_buffer (vm, from[0]);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  ipsec_if_tx_trace_t *tr =
	    vlib_add_trace (vm, node, b0, sizeof (*tr));
	  ipsec_sa_t *sa0 = pool_elt_at_index (im->sad, t0->output_sa_index);
	  tr->spi = sa0->spi;
	  tr->seq = sa0->seq;
	}

      from += 1;
      n_left -= 1;
    }
}

VNET_DEVICE_CLASS_TX_FN (ipsec_device_class) (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * frame)
{
  ipsec_main_t *im = &ipsec_main;
  u32 *from, n_left;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  const ipsec_tunnel_if_t *t0;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE];

  from = vlib_frame_vector_args (frame);
  t0 = pool_elt_at_index (im->tunnel_interfaces, rd->dev_instance);
  n_left = frame->n_vectors;
  b = bufs;

  /* All going to encrypt */
  clib_memset (nexts, 0, sizeof (nexts));

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ipsec_output_trace (vm, node, frame, t0);

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left >= 8)
    {
      /* Prefetch the buffer header for the N+2 loop iteration */
      vlib_prefetch_buffer_header (b[4], STORE);
      vlib_prefetch_buffer_header (b[5], STORE);
      vlib_prefetch_buffer_header (b[6], STORE);
      vlib_prefetch_buffer_header (b[7], STORE);

      vnet_buffer (b[0])->ipsec.sad_index = t0->output_sa_index;
      vnet_buffer (b[1])->ipsec.sad_index = t0->output_sa_index;
      vnet_buffer (b[2])->ipsec.sad_index = t0->output_sa_index;
      vnet_buffer (b[3])->ipsec.sad_index = t0->output_sa_index;

      n_left -= 4;
      b += 4;
    }
  while (n_left > 0)
    {
      vnet_buffer (b[0])->ipsec.sad_index = t0->output_sa_index;

      n_left -= 1;
      b += 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
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

  return /* no error */ 0;
}


/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ipsec_device_class) =
{
  .name = "IPSec",
  .format_device_name = format_ipsec_name,
  .format_tx_trace = format_ipsec_if_tx_trace,
  .tx_function_n_errors = IPSEC_IF_TX_N_ERROR,
  .tx_function_error_strings = ipsec_if_tx_error_strings,
  .admin_up_down_function = ipsec_admin_up_down_function,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (ipsec_hw_class) =
{
  .name = "IPSec",
  .build_rewrite = default_build_rewrite,
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
  u32 slot;
  ipsec_key_t crypto_key, integ_key;
  ipsec_sa_flags_t flags;
  int rv;

  u64 key = ((u64) args->remote_ip.ip4.as_u32 << 32 |
	     (u64) clib_host_to_net_u32 (args->remote_spi));
  p = hash_get (im->ipsec_if_pool_index_by_key, key);

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
      if (args->udp_encap)
	flags |= IPSEC_SA_FLAG_UDP_ENCAP;
      if (args->esn)
	flags |= IPSEC_SA_FLAG_USE_EXTENDED_SEQ_NUM;
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
			 flags,
			 args->tx_table_id,
			 &args->remote_ip,
			 &args->local_ip, &t->input_sa_index);

      if (rv)
	return VNET_API_ERROR_UNIMPLEMENTED;

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
			 &args->local_ip,
			 &args->remote_ip, &t->output_sa_index);

      if (rv)
	return VNET_API_ERROR_UNIMPLEMENTED;

      hash_set (im->ipsec_if_pool_index_by_key, key,
		t - im->tunnel_interfaces);

      hw_if_index = vnet_register_interface (vnm, ipsec_device_class.index,
					     t - im->tunnel_interfaces,
					     ipsec_hw_class.index,
					     t - im->tunnel_interfaces);

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      /* add esp4 as the next-node-index of this tx-node */

      slot = vlib_node_add_next_with_slot
	(vnm->vlib_main, hi->tx_node_index, im->esp4_encrypt_node_index, 0);

      ASSERT (slot == 0);

      t->hw_if_index = hw_if_index;
      t->sw_if_index = hi->sw_if_index;

      vnet_feature_enable_disable ("interface-output", "ipsec-if-output",
				   hi->sw_if_index, 1, 0, 0);

      /*1st interface, register protocol */
      if (pool_elts (im->tunnel_interfaces) == 1)
	ip4_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec_if_input_node.index);

    }
  else
    {
      /* check if exists */
      if (!p)
	return VNET_API_ERROR_INVALID_VALUE;

      t = pool_elt_at_index (im->tunnel_interfaces, p[0]);
      hi = vnet_get_hw_interface (vnm, t->hw_if_index);
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 0);	/* admin down */

      vnet_feature_enable_disable ("interface-output", "ipsec-if-output",
				   hi->sw_if_index, 0, 0, 0);

      vnet_delete_hw_interface (vnm, t->hw_if_index);

      hash_unset (im->ipsec_if_pool_index_by_key, key);
      hash_unset (im->ipsec_if_real_dev_by_show_dev, t->show_instance);

      pool_put (im->tunnel_interfaces, t);

      /* delete input and output SA */
      ipsec_sa_del (ipsec_tun_mk_input_sa_id (p[0]));
      ipsec_sa_del (ipsec_tun_mk_output_sa_id (p[0]));
    }

  if (sw_if_index)
    *sw_if_index = hi->sw_if_index;

  return 0;
}

int
ipsec_add_del_ipsec_gre_tunnel (vnet_main_t * vnm,
				ipsec_add_del_ipsec_gre_tunnel_args_t * args)
{
  ipsec_tunnel_if_t *t = 0;
  ipsec_main_t *im = &ipsec_main;
  uword *p;
  ipsec_sa_t *sa;
  u64 key;
  u32 isa, osa;

  p = hash_get (im->sa_index_by_sa_id, args->local_sa_id);
  if (!p)
    return VNET_API_ERROR_INVALID_VALUE;
  isa = p[0];

  p = hash_get (im->sa_index_by_sa_id, args->remote_sa_id);
  if (!p)
    return VNET_API_ERROR_INVALID_VALUE;
  osa = p[0];
  sa = pool_elt_at_index (im->sad, p[0]);

  if (sa->is_tunnel)
    key = ((u64) sa->tunnel_dst_addr.ip4.as_u32 << 32 |
	   (u64) clib_host_to_net_u32 (sa->spi));
  else
    key = ((u64) args->remote_ip.as_u32 << 32 |
	   (u64) clib_host_to_net_u32 (sa->spi));

  p = hash_get (im->ipsec_if_pool_index_by_key, key);

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
      hash_set (im->ipsec_if_pool_index_by_key, key,
		t - im->tunnel_interfaces);

      /*1st interface, register protocol */
      if (pool_elts (im->tunnel_interfaces) == 1)
	ip4_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec_if_input_node.index);
    }
  else
    {
      /* check if exists */
      if (!p)
	return VNET_API_ERROR_INVALID_VALUE;

      t = pool_elt_at_index (im->tunnel_interfaces, p[0]);
      hash_unset (im->ipsec_if_pool_index_by_key, key);
      pool_put (im->tunnel_interfaces, t);
    }
  return 0;
}

int
ipsec_set_interface_key (vnet_main_t * vnm, u32 hw_if_index,
			 ipsec_if_set_key_type_t type, u8 alg, u8 * key)
{
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
      sa->crypto_alg = alg;
      ipsec_mk_key (&sa->crypto_key, key, vec_len (key));
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG)
    {
      sa = pool_elt_at_index (im->sad, t->output_sa_index);
      sa->integ_alg = alg;
      ipsec_mk_key (&sa->integ_key, key, vec_len (key));
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO)
    {
      sa = pool_elt_at_index (im->sad, t->input_sa_index);
      sa->crypto_alg = alg;
      ipsec_mk_key (&sa->crypto_key, key, vec_len (key));
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG)
    {
      sa = pool_elt_at_index (im->sad, t->input_sa_index);
      sa->integ_alg = alg;
      ipsec_mk_key (&sa->integ_key, key, vec_len (key));
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
  if (sa->is_tunnel_ip6)
    {
      clib_warning ("IPsec interface not supported with IPv6 endpoints");
      return VNET_API_ERROR_UNIMPLEMENTED;
    }

  if (!is_outbound)
    {
      u64 key;

      old_sa_index = t->input_sa_index;
      old_sa = pool_elt_at_index (im->sad, old_sa_index);

      /* unset old inbound hash entry. packets should stop arriving */
      key = ((u64) old_sa->tunnel_src_addr.ip4.as_u32 << 32 |
	     (u64) clib_host_to_net_u32 (old_sa->spi));
      p = hash_get (im->ipsec_if_pool_index_by_key, key);
      if (p)
	hash_unset (im->ipsec_if_pool_index_by_key, key);

      /* set new inbound SA, then set new hash entry */
      t->input_sa_index = sa_index;
      key = ((u64) sa->tunnel_src_addr.ip4.as_u32 << 32 |
	     (u64) clib_host_to_net_u32 (sa->spi));
      hash_set (im->ipsec_if_pool_index_by_key, key, hi->dev_instance);
    }
  else
    {
      old_sa_index = t->output_sa_index;
      old_sa = pool_elt_at_index (im->sad, old_sa_index);
      t->output_sa_index = sa_index;
    }

  /* remove sa_id to sa_index mapping on old SA */
  if (ipsec_get_sa_index_by_sa_id (old_sa->id) == old_sa_index)
    hash_unset (im->sa_index_by_sa_id, old_sa->id);

  if (ipsec_add_del_sa_sess_cb (im, old_sa_index, 0))
    {
      clib_warning ("IPsec backend add/del callback returned error");
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  pool_put (im->sad, old_sa);

  return 0;
}

clib_error_t *
ipsec_tunnel_if_init (vlib_main_t * vm)
{
  ipsec_main_t *im = &ipsec_main;

  im->ipsec_if_pool_index_by_key = hash_create (0, sizeof (uword));
  im->ipsec_if_real_dev_by_show_dev = hash_create (0, sizeof (uword));

  udp_register_dst_port (vm, UDP_DST_PORT_ipsec, ipsec_if_input_node.index,
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
