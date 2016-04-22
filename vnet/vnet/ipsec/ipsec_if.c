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

#include <vnet/ipsec/ipsec.h>

static u8 * format_ipsec_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "ipsec%d", dev_instance);
}

static uword dummy_interface_tx (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

VNET_DEVICE_CLASS (ipsec_device_class,static) = {
  .name = "IPSec",
  .format_device_name = format_ipsec_name,
  .format_tx_trace = format_ipsec_if_output_trace,
  .tx_function = dummy_interface_tx,
};

VNET_HW_INTERFACE_CLASS (ipsec_hw_class) = {
  .name = "IPSec",
};

u32
ipsec_add_del_tunnel_if (vnet_main_t * vnm, ipsec_add_del_tunnel_args_t * args)
{
  ipsec_tunnel_if_t * t;
  ipsec_main_t * im = &ipsec_main;
  vnet_hw_interface_t * hi;
  u32 hw_if_index = ~0;
  uword *p;
  ipsec_sa_t * sa;

  u64 key = (u64) args->remote_ip.as_u32 << 32 | (u64) args->remote_spi;
  p = hash_get (im->ipsec_if_pool_index_by_key, key);

  if (args->is_add)
    {
      /* check if same src/dst pair exists */
      if (p)
        return VNET_API_ERROR_INVALID_VALUE;

      pool_get_aligned (im->tunnel_interfaces, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      pool_get (im->sad, sa);
      memset (sa, 0, sizeof (*sa));
      t->input_sa_index = sa - im->sad;
      sa->spi = args->remote_spi;
      sa->tunnel_src_addr.ip4.as_u32 = args->remote_ip.as_u32;
      sa->tunnel_dst_addr.ip4.as_u32 = args->local_ip.as_u32;
      sa->is_tunnel = 1;
      sa->use_esn = args->esn;
      sa->use_anti_replay = args->anti_replay;

      pool_get (im->sad, sa);
      memset (sa, 0, sizeof (*sa));
      t->output_sa_index = sa - im->sad;
      sa->spi = args->local_spi;
      sa->tunnel_src_addr.ip4.as_u32 = args->local_ip.as_u32;
      sa->tunnel_dst_addr.ip4.as_u32 = args->remote_ip.as_u32;
      sa->is_tunnel = 1;
      sa->seq = 1;
      sa->use_esn = args->esn;
      sa->use_anti_replay = args->anti_replay;

      hash_set (im->ipsec_if_pool_index_by_key, key, t - im->tunnel_interfaces);

      if (vec_len (im->free_tunnel_if_indices) > 0)
        {
          hw_if_index =
            im->free_tunnel_if_indices[vec_len(im->free_tunnel_if_indices)-1];
          _vec_len (im->free_tunnel_if_indices) -= 1;
        }
      else
        {
          hw_if_index = vnet_register_interface(vnm, ipsec_device_class.index,
                                                t - im->tunnel_interfaces,
                                                ipsec_hw_class.index,
                                                t - im->tunnel_interfaces);

          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->output_node_index = ipsec_if_output_node.index;
        }
      t->hw_if_index = hw_if_index;

      /*1st interface, register protocol */
      if (pool_elts(im->tunnel_interfaces) == 1)
        ip4_register_protocol(IP_PROTOCOL_IPSEC_ESP, ipsec_if_input_node.index);

      return hw_if_index;
    }
  else
    {
      /* check if exists */
      if (!p)
        return VNET_API_ERROR_INVALID_VALUE;

      t = pool_elt_at_index(im->tunnel_interfaces, p[0]);
      hi = vnet_get_hw_interface (vnm, t->hw_if_index);
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 0); /* admin down */
      vec_add1 (im->free_tunnel_if_indices, t->hw_if_index);

      /* delete input and output SA */
      sa = pool_elt_at_index(im->sad, t->input_sa_index);
      pool_put (im->sad, sa);
      sa = pool_elt_at_index(im->sad, t->output_sa_index);
      pool_put (im->sad, sa);

      hash_unset (im->ipsec_if_pool_index_by_key, key);
      pool_put (im->tunnel_interfaces, t);
    }
  return 0;
}

int
ipsec_set_interface_key(vnet_main_t * vnm, u32 hw_if_index,
                        ipsec_if_set_key_type_t type, u8 alg, u8 * key)
{
  ipsec_main_t * im = &ipsec_main;
  vnet_hw_interface_t * hi;
  ipsec_tunnel_if_t * t;
  ipsec_sa_t * sa;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  t = pool_elt_at_index (im->tunnel_interfaces, hi->dev_instance);

  if (type == IPSEC_IF_SET_KEY_TYPE_LOCAL_CRYPTO)
    {
      sa = pool_elt_at_index(im->sad, t->output_sa_index);
      sa->crypto_alg = alg;
      sa->crypto_key_len = vec_len(key);
      clib_memcpy(sa->crypto_key, key, vec_len(key));
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG)
    {
      sa = pool_elt_at_index(im->sad, t->output_sa_index);
      sa->integ_alg = alg;
      sa->integ_key_len = vec_len(key);
      clib_memcpy(sa->integ_key, key, vec_len(key));
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO)
    {
      sa = pool_elt_at_index(im->sad, t->input_sa_index);
      sa->crypto_alg = alg;
      sa->crypto_key_len = vec_len(key);
      clib_memcpy(sa->crypto_key, key, vec_len(key));
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG)
    {
      sa = pool_elt_at_index(im->sad, t->input_sa_index);
      sa->integ_alg = alg;
      sa->integ_key_len = vec_len(key);
      clib_memcpy(sa->integ_key, key, vec_len(key));
    }
  else
    return VNET_API_ERROR_INVALID_VALUE;

  return 0;
}


clib_error_t *
ipsec_tunnel_if_init (vlib_main_t * vm)
{
  ipsec_main_t * im = &ipsec_main;

  im->ipsec_if_pool_index_by_key = hash_create (0, sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (ipsec_tunnel_if_init);

