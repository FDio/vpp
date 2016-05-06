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
#include <vnet/nsh-vxlan-gpe/nsh_vxlan_gpe.h>

nsh_vxlan_gpe_main_t nsh_vxlan_gpe_main;

static u8 * format_gpe_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case NSH_VXLAN_GPE_INPUT_NEXT_DROP:
      return format (s, "drop");
    case NSH_VXLAN_GPE_INPUT_NEXT_IP4_INPUT:
      return format (s, "ip4");
    case NSH_VXLAN_GPE_INPUT_NEXT_IP6_INPUT:
      return format (s, "ip6");
    case NSH_VXLAN_GPE_INPUT_NEXT_ETHERNET_INPUT:
      return format (s, "ethernet");
    case NSH_VXLAN_GPE_INPUT_NEXT_NSH_VXLAN_GPE_ENCAP:
      return format (s, "nsh-vxlan-gpe");
    default:
      return format (s, "unknown %d", next_index);
    }
  return s;
}


//  alagalah deprecate 

u8 * format_nsh_vxlan_gpe_tunnel (u8 * s, va_list * args)
{
  nsh_vxlan_gpe_tunnel_t * t = va_arg (*args, nsh_vxlan_gpe_tunnel_t *);
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;

  s = format (s, 
              "[%d] %U (src) %U (dst) fibs: encap %d, decap %d",
              t - ngm->tunnels,
              format_ip4_address, &t->src,
              format_ip4_address, &t->dst,
              t->encap_fib_index,
              t->decap_fib_index);
  s = format (s, " decap next %U\n", format_gpe_decap_next, t->decap_next_index);
  s = format (s, "  vxlan VNI %d ", t->vni);
  s = format (s, "nsh ver %d ", (t->nsh_hdr.ver_o_c>>6));
  if (t->nsh_hdr.ver_o_c & NSH_O_BIT)
      s = format (s, "O-set ");

  if (t->nsh_hdr.ver_o_c & NSH_C_BIT)
      s = format (s, "C-set ");

  s = format (s, "len %d (%d bytes) md_type %d next_protocol %d\n",
              t->nsh_hdr.length, t->nsh_hdr.length * 4, t->nsh_hdr.md_type, t->nsh_hdr.next_protocol);
  
  s = format (s, "  service path %d service index %d\n",
              (t->nsh_hdr.nsp_nsi>>NSH_NSP_SHIFT) & NSH_NSP_MASK,
              t->nsh_hdr.nsp_nsi & NSH_NSI_MASK);

  s = format (s, "  c1 %d c2 %d c3 %d c4 %d\n",
              t->nsh_hdr.c1, t->nsh_hdr.c2, t->nsh_hdr.c3, t->nsh_hdr.c4);

  return s;
}
// alagalah end

u8 * format_vxlan_gpe_tunnel (u8 * s, va_list * args)
{
  vxlan_gpe_tunnel_t * t = va_arg (*args, vxlan_gpe_tunnel_t *);
  vxlan_gpe_main_t * gm = &vxlan_gpe_main;

  s = format (s, 
              "[%d] %U (local) %U (remote) fibs: encap %d, decap %d",
              t - gm->tunnels,
              format_ip4_address, &t->local,
              format_ip4_address, &t->remote,
              t->encap_fib_index,
              t->decap_fib_index);
  s = format (s, "  vxlan VNI %d ", t->vni);

  return s;
}

// alagalah move to NSH folder and node 
u8 * format_nsh_header (u8 * s, va_list * args)
{
  nsh_header_t * nsh = va_arg (*args, nsh_header_t *);

  s = format (s, "nsh ver %d ", (nsh->ver_o_c>>6));
  if (nsh->ver_o_c & NSH_O_BIT)
      s = format (s, "O-set ");

  if (nsh->ver_o_c & NSH_C_BIT)
      s = format (s, "C-set ");

  s = format (s, "len %d (%d bytes) md_type %d next_protocol %d\n",
              nsh->length, nsh->length * 4, nsh->md_type, nsh->next_protocol);
  
  s = format (s, "  service path %d service index %d\n",
              (nsh->nsp_nsi>>NSH_NSP_SHIFT) & NSH_NSP_MASK,
              nsh->nsp_nsi & NSH_NSI_MASK);

  s = format (s, "  c1 %d c2 %d c3 %d c4 %d\n",
              nsh->c1, nsh->c2, nsh->c3, nsh->c4);

  return s;
}
// alagalah end

// alagalah - deprecate start
static u8 * format_nsh_vxlan_gpe_name (u8 * s, va_list * args)
{
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;
  u32 i = va_arg (*args, u32);
  u32 show_dev_instance = ~0;

  if (i < vec_len (ngm->dev_inst_by_real))
    show_dev_instance = ngm->dev_inst_by_real[i];

  if (show_dev_instance != ~0)
    i = show_dev_instance;

  return format (s, "nsh_vxlan_gpe_tunnel%d", i);
}
// alagalah end

static u8 * format_vxlan_gpe_name (u8 * s, va_list * args)
{
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;
  u32 i = va_arg (*args, u32);
  u32 show_dev_instance = ~0;

  if (i < vec_len (ngm->dev_inst_by_real))
    show_dev_instance = ngm->dev_inst_by_real[i];

  if (show_dev_instance != ~0)
    i = show_dev_instance;

  return format (s, "vxlan_gpe_tunnel%d", i);
}

static int vxlan_gpe_name_renumber (vnet_hw_interface_t * hi,
                                        u32 new_dev_instance)
{
  vxlan_gpe_main_t * gm = &vxlan_gpe_main;

  vec_validate_init_empty (gm->dev_inst_by_real, hi->dev_instance, ~0);

  gm->dev_inst_by_real [hi->dev_instance] = new_dev_instance;

  return 0;
}

//alagalah deprecated
static int nsh_vxlan_gpe_name_renumber (vnet_hw_interface_t * hi,
                                        u32 new_dev_instance)
{
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;

  vec_validate_init_empty (ngm->dev_inst_by_real, hi->dev_instance, ~0);

  ngm->dev_inst_by_real [hi->dev_instance] = new_dev_instance;

  return 0;
}
//alagalah end

static uword dummy_interface_tx (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

static uword dummy_set_rewrite (vnet_main_t * vnm,
                                u32 sw_if_index,
                                u32 l3_type,
                                void * dst_address,
                                void * rewrite,
                                uword max_rewrite_bytes)
{
  return 0;
}

//alagalah deprecated
VNET_DEVICE_CLASS (nsh_vxlan_gpe_device_class,static) = {
  .name = "NSH_VXLAN_GPE",
  .format_device_name = format_nsh_vxlan_gpe_name,
  .format_tx_trace = format_nsh_vxlan_gpe_encap_trace,
  .tx_function = dummy_interface_tx,
  .name_renumber = nsh_vxlan_gpe_name_renumber,
};

static u8 * format_nsh_vxlan_gpe_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

VNET_HW_INTERFACE_CLASS (nsh_vxlan_gpe_hw_class) = {
  .name = "NSH_VXLAN_GPE",
  .format_header = format_nsh_vxlan_gpe_header_with_length,
  .set_rewrite = dummy_set_rewrite,
};
//alagalah end

VNET_DEVICE_CLASS (vxlan_gpe_device_class,static) = {
  .name = "VXLAN_GPE",
  .format_device_name = format_vxlan_gpe_name,
  .format_tx_trace = format_vxlan_gpe_encap_trace,
  .tx_function = dummy_interface_tx,
  .name_renumber = vxlan_gpe_name_renumber,
};

static u8 * format_vxlan_gpe_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

VNET_HW_INTERFACE_CLASS (vxlan_gpe_hw_class) = {
  .name = "VXLAN_GPE",
  .format_header = format_vxlan_gpe_header_with_length,
  .set_rewrite = dummy_set_rewrite,
};


#define foreach_gpe_copy_field                  \
_(local.as_u32)                                 \
_(remote.as_u32)				\
_(vni)                                          \
_(next_protocol)                                \
_(encap_fib_index)                              \
_(decap_fib_index)                              

#define foreach_copy_field			\
_(src.as_u32)                                   \
_(dst.as_u32)                                   \
_(vni)                                          \
_(encap_fib_index)                              \
_(decap_fib_index)                              \
_(decap_next_index)

#define foreach_copy_nshhdr_field               \
_(ver_o_c)					\
_(length)					\
_(md_type)					\
_(next_protocol)				\
_(nsp_nsi)					\
_(c1)						\
_(c2)						\
_(c3)						\
_(c4)						
/* alagalah TODO - temp killing tlvs as its causing me pain */

#define foreach_32bit_field			\
_(nsp_nsi)                                      \
_(c1)                                           \
_(c2)                                           \
_(c3)                                           \
_(c4)

//alagalah deprecate
static int nsh_vxlan_gpe_rewrite (nsh_vxlan_gpe_tunnel_t * t)
{
  u8 *rw = 0;
  ip4_header_t * ip0;
  nsh_header_t * nsh0;
  ip4_vxlan_gpe_and_nsh_header_t * h0;
  int len;

  len = sizeof (*h0) + vec_len(&t->nsh_hdr.tlvs[0])*4;

  vec_validate_aligned (rw, len-1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip4_vxlan_gpe_and_nsh_header_t *) rw;

  /* Fixed portion of the (outer) ip4 header */
  ip0 = &h0->ip4;
  ip0->ip_version_and_header_length = 0x45;
  ip0->ttl = 254;
  ip0->protocol = IP_PROTOCOL_UDP;

  /* we fix up the ip4 header length and checksum after-the-fact */
  ip0->src_address.as_u32 = t->src.as_u32;
  ip0->dst_address.as_u32 = t->dst.as_u32;
  ip0->checksum = ip4_header_checksum (ip0);

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (4790);
  h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_vxlan_gpe);

  /* VXLAN header. Are we having fun yet? */
  h0->vxlan.flags = VXLAN_GPE_FLAGS_I | VXLAN_GPE_FLAGS_P;
  h0->vxlan.ver_res = VXLAN_GPE_VERSION;
  h0->vxlan.next_protocol = VXLAN_GPE_NEXTPROTOCOL_NSH;
  h0->vxlan.vni_res = clib_host_to_net_u32 (t->vni<<8);

  /* NSH header */
  nsh0 = &h0->nsh;
  nsh0->ver_o_c = t->nsh_hdr.ver_o_c;
  nsh0->md_type = t->nsh_hdr.md_type;
  nsh0->next_protocol = t->nsh_hdr.next_protocol;
  nsh0->nsp_nsi = t->nsh_hdr.nsp_nsi;
  nsh0->c1 = t->nsh_hdr.c1;
  nsh0->c2 = t->nsh_hdr.c2;
  nsh0->c3 = t->nsh_hdr.c3;
  nsh0->c4 = t->nsh_hdr.c4;
  
  /* Endian swap 32-bit fields */
#define _(x) nsh0->x = clib_host_to_net_u32(nsh0->x);
  foreach_32bit_field;
#undef _

  /* fix nsh header length */

  t->nsh_hdr.length = 6;
  nsh0->length = t->nsh_hdr.length;

  t->rewrite = rw;
  return (0);
}

// alagalah deprecate 
int vnet_nsh_vxlan_gpe_add_del_tunnel 
(vnet_nsh_vxlan_gpe_add_del_tunnel_args_t *a, u32 * sw_if_indexp)
{
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;
  nsh_vxlan_gpe_tunnel_t *t = 0;
  vnet_main_t * vnm = ngm->vnet_main;
  vnet_hw_interface_t * hi;
  uword * p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  int rv;
  nsh_vxlan_gpe_tunnel_key_t key, *key_copy;
  hash_pair_t *hp;
  
  key.src = a->src.as_u32; 
  key.vni = clib_host_to_net_u32 (a->vni << 8);
  key.nsp_nsi = clib_host_to_net_u32(a->nsh_hdr.nsp_nsi);
  key.pad = 0;

  p = hash_get_mem (ngm->nsh_vxlan_gpe_tunnel_by_key, &key);
  
  if (a->is_add)
    {
      /* adding a tunnel: tunnel must not already exist */
      if (p) 
        return VNET_API_ERROR_INVALID_VALUE;
      
      if (a->decap_next_index >= NSH_VXLAN_GPE_INPUT_N_NEXT)
        return VNET_API_ERROR_INVALID_DECAP_NEXT;
      
      pool_get_aligned (ngm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));
      
      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _

      /* copy from arg structure */
#define _(x) t->nsh_hdr.x = a->nsh_hdr.x;
      foreach_copy_nshhdr_field;
#undef _
      
      
      t->nsh_hdr.tlvs[0] = 0;

      rv = nsh_vxlan_gpe_rewrite (t);

      if (rv)
        {
          pool_put (ngm->tunnels, t);
          return rv;
        }

      key_copy = clib_mem_alloc (sizeof (*key_copy));
      clib_memcpy (key_copy, &key, sizeof (*key_copy));

      hash_set_mem (ngm->nsh_vxlan_gpe_tunnel_by_key, key_copy, 
                    t - ngm->tunnels);



      if (vec_len (ngm->free_nsh_vxlan_gpe_tunnel_hw_if_indices) > 0)
        {
          hw_if_index = ngm->free_nsh_vxlan_gpe_tunnel_hw_if_indices
            [vec_len (ngm->free_nsh_vxlan_gpe_tunnel_hw_if_indices)-1];
          _vec_len (ngm->free_nsh_vxlan_gpe_tunnel_hw_if_indices) -= 1;
          
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->dev_instance = t - ngm->tunnels;
          hi->hw_instance = hi->dev_instance;
        }
      else
        {
          hw_if_index = vnet_register_interface
            (vnm, nsh_vxlan_gpe_device_class.index, t - ngm->tunnels,
             nsh_vxlan_gpe_hw_class.index, t - ngm->tunnels);
          hi = vnet_get_hw_interface (vnm, hw_if_index);
      //alagalah todo removed "nsh_" - conflicts since encap.c not in Makefile.am
          hi->output_node_index = vxlan_gpe_encap_node.index;
        }
      
      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index = hi->sw_if_index;
      
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 
                                   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
    }
  else
    {
      /* deleting a tunnel: tunnel must exist */
      if (!p) 
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (ngm->tunnels, p[0]);

      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */);
      vec_add1 (ngm->free_nsh_vxlan_gpe_tunnel_hw_if_indices, t->hw_if_index);

      hp = hash_get_pair (ngm->nsh_vxlan_gpe_tunnel_by_key, &key);
      key_copy = (void *)(hp->key);
      hash_unset_mem (ngm->nsh_vxlan_gpe_tunnel_by_key, &key);
      clib_mem_free (key_copy);

      vec_free (t->rewrite);
      pool_put (ngm->tunnels, t);
    }

  if (sw_if_indexp)
      *sw_if_indexp = sw_if_index;

  return 0;
}
//alagalah end

static int vxlan_gpe_rewrite (vxlan_gpe_tunnel_t * t)
{
  u8 *rw = 0;
  ip4_header_t * ip0;
  ip4_vxlan_gpe_header_t * h0;
  int len;

  len = sizeof (*h0);

  vec_validate_aligned (rw, len-1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip4_vxlan_gpe_header_t *) rw;

  /* Fixed portion of the (outer) ip4 header */
  ip0 = &h0->ip4;
  ip0->ip_version_and_header_length = 0x45;
  ip0->ttl = 254;
  ip0->protocol = IP_PROTOCOL_UDP;

  /* we fix up the ip4 header length and checksum after-the-fact */
  ip0->src_address.as_u32 = t->local.as_u32; // alagalah local? remote?
  ip0->dst_address.as_u32 = t->remote.as_u32; // alagalah local? remote?
  ip0->checksum = ip4_header_checksum (ip0);

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (4790);
  h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_vxlan_gpe);

  /* VXLAN header. Are we having fun yet? */
  h0->vxlan.flags = VXLAN_GPE_FLAGS_I | VXLAN_GPE_FLAGS_P;
  h0->vxlan.ver_res = VXLAN_GPE_VERSION;
  h0->vxlan.next_protocol = ~0; // alagalah TODO VXLAN_NEXT_PROTOCOL_NSH Don't think we should set this? ~0 ?
  h0->vxlan.vni_res = clib_host_to_net_u32 (t->vni<<8);

  t->rewrite = rw;
  return (0);
}

int vnet_vxlan_gpe_add_del_tunnel 
(vnet_vxlan_gpe_add_del_tunnel_args_t *a, u32 * sw_if_indexp)
{
  vxlan_gpe_main_t * gm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t = 0;
  vnet_main_t * vnm = gm->vnet_main;
  vnet_hw_interface_t * hi;
  uword * p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  int rv;
  vxlan_gpe_tunnel_key_t key, *key_copy;
  hash_pair_t *hp;
  
  key.local = a->local.as_u32; 
  key.remote = a->remote.as_u32; 
  key.vni = clib_host_to_net_u32 (a->vni << 8);
  key.pad = 0;

  p = hash_get_mem (gm->vxlan_gpe_tunnel_by_key, &key);
  
  if (a->is_add)
    {
      /* adding a tunnel: tunnel must not already exist */
      if (p) 
        return VNET_API_ERROR_INVALID_VALUE;
      
      if (a->decap_next_index >= NSH_VXLAN_GPE_INPUT_N_NEXT)
        return VNET_API_ERROR_INVALID_DECAP_NEXT;
      
      pool_get_aligned (gm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));
      
      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_gpe_copy_field;
#undef _

      rv = vxlan_gpe_rewrite (t);

      if (rv)
        {
          pool_put (gm->tunnels, t);
          return rv;
        }

      key_copy = clib_mem_alloc (sizeof (*key_copy));
      clib_memcpy (key_copy, &key, sizeof (*key_copy));

      hash_set_mem (gm->vxlan_gpe_tunnel_by_key, key_copy, 
                    t - gm->tunnels);
      
      if (vec_len (gm->free_vxlan_gpe_tunnel_hw_if_indices) > 0)
        {
          hw_if_index = gm->free_vxlan_gpe_tunnel_hw_if_indices
            [vec_len (gm->free_vxlan_gpe_tunnel_hw_if_indices)-1];
          _vec_len (gm->free_vxlan_gpe_tunnel_hw_if_indices) -= 1;
          
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->dev_instance = t - gm->tunnels;
          hi->hw_instance = hi->dev_instance;
        }
      else 
        {
          hw_if_index = vnet_register_interface
            (vnm, vxlan_gpe_device_class.index, t - gm->tunnels,
             vxlan_gpe_hw_class.index, t - gm->tunnels);
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->output_node_index = vxlan_gpe_encap_node.index;
        }
      
      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index = hi->sw_if_index;
      
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 
                                   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
    }
  else
    {
      /* deleting a tunnel: tunnel must exist */
      if (!p) 
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (gm->tunnels, p[0]);

      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */);
      vec_add1 (gm->free_vxlan_gpe_tunnel_hw_if_indices, t->hw_if_index);

      hp = hash_get_pair (gm->vxlan_gpe_tunnel_by_key, &key);
      key_copy = (void *)(hp->key);
      hash_unset_mem (gm->vxlan_gpe_tunnel_by_key, &key);
      clib_mem_free (key_copy);

      vec_free (t->rewrite);
      pool_put (gm->tunnels, t);
    }

  if (sw_if_indexp)
      *sw_if_indexp = sw_if_index;

  return 0;
}

static u32 fib_index_from_fib_id (u32 fib_id)
{
  ip4_main_t * im = &ip4_main;
  uword * p;

  p = hash_get (im->fib_index_by_table_id, fib_id);
  if (!p)
    return ~0;

  return p[0];
}

static uword unformat_gpe_decap_next (unformat_input_t * input, va_list * args)
{
  u32 * result = va_arg (*args, u32 *);
  u32 tmp;
  
  if (unformat (input, "drop"))
    *result = NSH_VXLAN_GPE_INPUT_NEXT_DROP;
  else if (unformat (input, "ip4"))
    *result = NSH_VXLAN_GPE_INPUT_NEXT_IP4_INPUT;
  else if (unformat (input, "ip6"))
    *result = NSH_VXLAN_GPE_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, "ethernet"))
    *result = NSH_VXLAN_GPE_INPUT_NEXT_ETHERNET_INPUT;
  else if (unformat (input, "nsh-vxlan-gpe"))
    *result = NSH_VXLAN_GPE_INPUT_NEXT_NSH_VXLAN_GPE_ENCAP;
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static uword unformat_nsh_map_next (unformat_input_t * input, va_list * args)
{
  u32 * result = va_arg (*args, u32 *);
  
  if (unformat (input, "drop"))
    *result = NSH_INPUT_NEXT_DROP;
  else if (unformat (input, "decap"))
    *result = 99; // alagalah wrong but working this out NSH_INPUT_NEXT_NEXTPROTO_LOOKUP;
  else if (unformat (input, "map"))
    *result = 66; // alagalah wrong but working this out NSH_INPUT_NEXT_REENCAP;
  else
    return 0;
  return 1;
}

// alagalah deprecate - start

static clib_error_t *
nsh_vxlan_gpe_add_del_tunnel_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  ip4_address_t src, dst;
  u8 is_add = 1;
  u8 src_set = 0;
  u8 dst_set = 0;
  u32 encap_fib_index = 0;
  u32 decap_fib_index = 0;
  u8 ver_o_c = 0;
  u8 length = 0;
  u8 md_type = 0;
  u8 next_protocol = 1; /* default: ip4 */
  u32 decap_next_index = NSH_VXLAN_GPE_INPUT_NEXT_IP4_INPUT;
  u32 nsp;
  u8 nsp_set = 0;
  u32 nsi;
  u8 nsi_set = 0;
  u32 vni;
  u8 vni_set = 0;
  u32 nsp_nsi;
  u32 c1 = 0;
  u32 c2 = 0;
  u32 c3 = 0;
  u32 c4 = 0;
  u32 *tlvs = 0;
  u32 tmp;
  int rv;
  vnet_nsh_vxlan_gpe_add_del_tunnel_args_t _a, * a = &_a;
  
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "src %U", 
                       unformat_ip4_address, &src))
      src_set = 1;
    else if (unformat (line_input, "dst %U",
                       unformat_ip4_address, &dst))
      dst_set = 1;
    else if (unformat (line_input, "encap-vrf-id %d", &tmp))
      {
        encap_fib_index = fib_index_from_fib_id (tmp);
        if (encap_fib_index == ~0)
          return clib_error_return (0, "nonexistent encap fib id %d", tmp);
      }
    else if (unformat (line_input, "decap-vrf-id %d", &tmp))
      {
        decap_fib_index = fib_index_from_fib_id (tmp);
        if (decap_fib_index == ~0)
          return clib_error_return (0, "nonexistent decap fib id %d", tmp);
      }
    else if (unformat (line_input, "decap-next %U", unformat_gpe_decap_next, 
                       &decap_next_index))
      ;
    else if (unformat (line_input, "vni %d", &vni))
      vni_set = 1;
    else if (unformat (line_input, "version %d", &tmp))
      ver_o_c |= (tmp & 3) << 6;
    else if (unformat (line_input, "o-bit %d", &tmp))
      ver_o_c |= (tmp & 1) << 5;
    else if (unformat (line_input, "c-bit %d", &tmp))
      ver_o_c |= (tmp & 1) << 4;
    else if (unformat (line_input, "md-type %d", &tmp))
      md_type = tmp;
    else if (unformat(line_input, "next-ip4"))
      next_protocol = 1;
    else if (unformat(line_input, "next-ip6"))
      next_protocol = 2;
    else if (unformat(line_input, "next-ethernet"))
      next_protocol = 3;
    else if (unformat(line_input, "next-nsh"))
      next_protocol = 4;
    else if (unformat (line_input, "c1 %d", &c1))
      ;
    else if (unformat (line_input, "c2 %d", &c2))
      ;
    else if (unformat (line_input, "c3 %d", &c3))
      ;
    else if (unformat (line_input, "c4 %d", &c4))
      ;
    else if (unformat (line_input, "nsp %d", &nsp))
      nsp_set = 1;
    else if (unformat (line_input, "nsi %d", &nsi))
      nsi_set = 1;
    // alagalah TODO TLV only allowed with MD2
    else if (unformat (line_input, "tlv %x"))
        vec_add1 (tlvs, tmp);
    else 
      return clib_error_return (0, "parse error: '%U'", 
                                format_unformat_error, line_input);
  }

  unformat_free (line_input);

  if (src_set == 0)
    return clib_error_return (0, "tunnel src address not specified");

  if (dst_set == 0)
    return clib_error_return (0, "tunnel dst address not specified");

  if (vni_set == 0)
    return clib_error_return (0, "vni not specified");

  if (nsp_set == 0)
    return clib_error_return (0, "nsp not specified");
  
  if (nsi_set == 0)
    return clib_error_return (0, "nsi not specified");

  nsp_nsi = (nsp<<8) | nsi;
  
  memset (a, 0, sizeof (*a));

  a->is_add = is_add;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _

#define _(x) a->nsh_hdr.x = x;
  foreach_copy_nshhdr_field;
#undef _
  
  a->nsh_hdr.tlvs[0] = 0 ; // alagalah TODO FIX ME this shouldn't be set 0

  rv = vnet_nsh_vxlan_gpe_add_del_tunnel (a, 0 /* hw_if_indexp */);

  switch(rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_DECAP_NEXT:
      return clib_error_return (0, "invalid decap-next...");

    case VNET_API_ERROR_TUNNEL_EXIST:
      return clib_error_return (0, "tunnel already exists...");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "tunnel does not exist...");

    default:
      return clib_error_return 
        (0, "vnet_nsh_vxlan_gpe_add_del_tunnel returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_nsh_vxlan_gpe_tunnel_command, static) = {
  .path = "nsh vxlan tunnel",
  .short_help = 
  "nsh vxlan tunnel src <ip4-addr> dst <ip4-addr>" 
  "    c1 <nn> c2 <nn> c3 <nn> c4 <nn> spi <nn> si <nn> vni <nn>\n"
  "    [encap-vrf-id <nn>] [decap-vrf-id <nn>] [o-bit <1|0>] [c-bit <1|0>]\n"
  "    [md-type <nn>][next-ip4][next-ip6][next-ethernet][next-nsh]\n"
  "    [tlv <xx>][decap-next [ip4|ip6|ethernet|nsh-vxlan-gpe]][del]\n",
  .function = nsh_vxlan_gpe_add_del_tunnel_command_fn,
};

// alagalah deprecate -- end

static clib_error_t *
vxlan_gpe_add_del_tunnel_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  ip4_address_t local, remote;
  u8 local_set = 0;
  u8 remote_set = 0;
  u32 encap_fib_index = 0;
  u32 decap_fib_index = 0;
  u8 next_protocol = 1; /* default: ip4 */
  u32 decap_next_index = NSH_VXLAN_GPE_INPUT_NEXT_IP4_INPUT; // alagalah - rename after deprecate
  u32 vni;
  u8 vni_set = 0;
  int rv;
  u32 tmp;
  vnet_vxlan_gpe_add_del_tunnel_args_t _a, * a = &_a;
  
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "local %U", 
                       unformat_ip4_address, &local))
      local_set = 1;
    else if (unformat (line_input, "remote %U",
                       unformat_ip4_address, &remote))
      remote_set = 1;
    else if (unformat (line_input, "encap-vrf-id %d", &tmp))
      {
        encap_fib_index = fib_index_from_fib_id (tmp);
        if (encap_fib_index == ~0)
          return clib_error_return (0, "nonexistent encap fib id %d", tmp);
      }
    else if (unformat (line_input, "decap-vrf-id %d", &tmp))
      {
        decap_fib_index = fib_index_from_fib_id (tmp);
        if (decap_fib_index == ~0)
          return clib_error_return (0, "nonexistent decap fib id %d", tmp);
      }
    else if (unformat (line_input, "decap-next %U", unformat_gpe_decap_next, 
                       &decap_next_index))
      ;
    else if (unformat (line_input, "vni %d", &vni))
      vni_set = 1;
    else if (unformat(line_input, "next-ip4"))
      next_protocol = 1;
    else if (unformat(line_input, "next-ip6"))
      next_protocol = 2;
    else if (unformat(line_input, "next-ethernet"))
      next_protocol = 3;
    else if (unformat(line_input, "next-nsh"))
      next_protocol = 4;
    else 
      return clib_error_return (0, "parse error: '%U'", 
                                format_unformat_error, line_input);
  }

  unformat_free (line_input);

  if (local_set == 0)
    return clib_error_return (0, "tunnel local address not specified");

  if (remote_set == 0)
    return clib_error_return (0, "tunnel remote address not specified");

  if (vni_set == 0)
    return clib_error_return (0, "vni not specified");

  memset (a, 0, sizeof (*a));

  a->is_add = is_add;

#define _(x) a->x = x;
  foreach_gpe_copy_field;
#undef _

  rv = vnet_vxlan_gpe_add_del_tunnel (a, 0 /* hw_if_indexp */);

  switch(rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_DECAP_NEXT:
      return clib_error_return (0, "invalid decap-next...");

    case VNET_API_ERROR_TUNNEL_EXIST:
      return clib_error_return (0, "tunnel already exists...");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "tunnel does not exist...");

    default:
      return clib_error_return 
        (0, "vnet_vxlan_gpe_add_del_tunnel returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_vxlan_gpe_tunnel_command, static) = {
  .path = "vxlangpe tunnel",
  .short_help = 
  "vxlangpe tunnel local <ip4-addr> remote <ip4-addr>"
  "    vni <nn> [next-ip4][next-ip6][next-ethernet][next-nsh]\n"
  "    [encap-vrf-id <nn>] [decap-vrf-id <nn>]"
  "    [del]\n",
  .function = vxlan_gpe_add_del_tunnel_command_fn,
};


static clib_error_t *
nsh_add_del_map_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  u32 nsh_map_next = ~0 ; //alagalah TODO fix this routine
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "stuff %U", unformat_nsh_map_next, 
                       &nsh_map_next))
      ;
    else 
      return clib_error_return (0, "parse error: '%U'", 
                                format_unformat_error, line_input);
  }
  (void)is_add;
  (void)nsh_map_next;
  return 0;
}


VLIB_CLI_COMMAND (create_nsh_map_command, static) = {
  .path = "nsh map",
  .short_help = 
  "nsh map nsp <nn> nsi <nn>}\n"
  "    [md-type <nn>] [tlv <xx>] [del]\n",
  .function = nsh_add_del_map_command_fn,
};

int vnet_nsh_add_del_entry (vnet_nsh_add_del_entry_args_t * args)
{
  return 0;
}

static clib_error_t *
nsh_add_del_entry_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  u8 ver_o_c = 0;
  u8 length = 0;
  u8 md_type = 0;
  u8 next_protocol = 1; /* default: ip4 */
  u32 nsp;
  u8 nsp_set = 0;
  u32 nsi;
  u8 nsi_set = 0;
  u32 nsp_nsi;
  u32 c1 = 0;
  u32 c2 = 0;
  u32 c3 = 0;
  u32 c4 = 0;
  u32 *tlvs = 0;
  u32 tmp;
  int rv;
  vnet_nsh_add_del_entry_args_t _a, * a = &_a;
  
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "version %d", &tmp))
      ver_o_c |= (tmp & 3) << 6;
    else if (unformat (line_input, "o-bit %d", &tmp))
      ver_o_c |= (tmp & 1) << 5;
    else if (unformat (line_input, "c-bit %d", &tmp))
      ver_o_c |= (tmp & 1) << 4;
    else if (unformat (line_input, "md-type %d", &tmp))
      md_type = tmp;
    else if (unformat(line_input, "next-ip4"))
      next_protocol = 1;
    else if (unformat(line_input, "next-ip6"))
      next_protocol = 2;
    else if (unformat(line_input, "next-ethernet"))
      next_protocol = 3;
    else if (unformat (line_input, "c1 %d", &c1))
      ;
    else if (unformat (line_input, "c2 %d", &c2))
      ;
    else if (unformat (line_input, "c3 %d", &c3))
      ;
    else if (unformat (line_input, "c4 %d", &c4))
      ;
    else if (unformat (line_input, "nsp %d", &nsp))
      nsp_set = 1;
    else if (unformat (line_input, "nsi %d", &nsi))
      nsi_set = 1;
    else if (unformat (line_input, "tlv %x"))
        vec_add1 (tlvs, tmp);
    else 
      return clib_error_return (0, "parse error: '%U'", 
                                format_unformat_error, line_input);
  }

  unformat_free (line_input);

  if (nsp_set == 0)
    return clib_error_return (0, "nsp not specified");
  
  if (nsi_set == 0)
    return clib_error_return (0, "nsi not specified");

  nsp_nsi = (nsp<<8) | nsi;
  
  memset (a, 0, sizeof (*a));

  a->is_add = is_add;

#define _(x) a->nsh.x = x;
  foreach_copy_nshhdr_field;
#undef _
  
  a->nsh.tlvs[0] = 0 ; // alagalah TODO FIX ME this shouldn't be set 0

  rv = vnet_nsh_add_del_entry (a);

  switch(rv)
    {
    case 0:
      break;
    default:
      return clib_error_return 
        (0, "vnet_nsh_add_del_entry returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_nsh_entry_command, static) = {
  .path = "nsh entry",
  .short_help = 
  "nsh entry {nsp <nn> nsi <nn>}\n"
  "    c1 <nn> c2 <nn> c3 <nn> c4 <nn> \n"
  "    [md-type <nn>] [tlv <xx>] [del]\n",
  .function = nsh_add_del_entry_command_fn,
};


//alagalah deprecate show_nsh_vxlan_gpe_tunnel_command_fn - start

static clib_error_t *
show_nsh_vxlan_gpe_tunnel_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;
  nsh_vxlan_gpe_tunnel_t * t;
  
  if (pool_elts (ngm->tunnels) == 0)
    vlib_cli_output (vm, "No nsh-vxlan-gpe tunnels configured...");

  pool_foreach (t, ngm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_nsh_vxlan_gpe_tunnel, t);
  }));
  
  return 0;
}

VLIB_CLI_COMMAND (show_nsh_vxlan_gpe_tunnel_command, static) = {
    .path = "show nsh vxlan tunnel",
    .function = show_nsh_vxlan_gpe_tunnel_command_fn,
};
//alagalah deprecate show_nsh_vxlan_gpe_tunnel_command_fn - end

clib_error_t *nsh_vxlan_gpe_init (vlib_main_t *vm)
{
  nsh_vxlan_gpe_main_t *ngm = &nsh_vxlan_gpe_main;
  
  ngm->vnet_main = vnet_get_main();
  ngm->vlib_main = vm;
  
  ngm->nsh_vxlan_gpe_tunnel_by_key 
    = hash_create_mem (0, sizeof(nsh_vxlan_gpe_tunnel_key_t), sizeof (uword));


  ngm->nsh_vxlan_gpe_tunnel_by_key 
    = hash_create_mem (0, sizeof(vxlan_gpe_tunnel_key_t), sizeof (uword));

// alagalah todo commented out for build
//  udp_register_dst_port (vm, UDP_DST_PORT_vxlan_gpe, 
//                         nsh_vxlan_gpe_input_node.index, 1 /* is_ip4 */);
  return 0;
}

// alagalah todo commented out for build
//VLIB_INIT_FUNCTION(nsh_vxlan_gpe_init);
  
clib_error_t *vxlan_gpe_init (vlib_main_t *vm)
{
  vxlan_gpe_main_t *gm = &vxlan_gpe_main;
  
  gm->vnet_main = vnet_get_main();
  gm->vlib_main = vm;
  
  gm->vxlan_gpe_tunnel_by_key 
    = hash_create_mem (0, sizeof(vxlan_gpe_tunnel_key_t), sizeof (uword));

  udp_register_dst_port (vm, UDP_DST_PORT_vxlan_gpe, 
                         vxlan_gpe_input_node.index, 1 /* is_ip4 */);
  return 0;
}

VLIB_INIT_FUNCTION(vxlan_gpe_init);
