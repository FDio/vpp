;;; tunnel-c-skel.el - tunnel encap cli / api

(require 'skeleton)

(define-skeleton skel-tunnel-c
"Insert a tunnel cli/api implementation"
nil
'(setq encap_stack (skeleton-read "encap_stack (e.g ip4_udp_lisp): "))
'(setq ENCAP_STACK (upcase encap_stack))
'(setq encap-stack (replace-regexp-in-string "_" "-" encap_stack))
"
#include <vnet/" encap-stack "/" encap_stack" .h>

" encap_stack "_main_t " encap_stack "_main;

static u8 * format_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case " ENCAP_STACK "_INPUT_NEXT_DROP:
      return format (s, \"drop\");
    case " ENCAP_STACK "_INPUT_NEXT_IP4_INPUT:
      return format (s, \"ip4\");
    case " ENCAP_STACK "_INPUT_NEXT_IP6_INPUT:
      return format (s, \"ip6\");
    case " ENCAP_STACK "_INPUT_NEXT_" ENCAP_STACK "_ENCAP:
      return format (s, \"" encap-stack "\");
    default:
      return format (s, \"unknown %d\", next_index);
    }
  return s;
}

u8 * format_" encap_stack "_tunnel (u8 * s, va_list * args)
{
  " encap_stack "_tunnel_t * t = va_arg (*args, " encap_stack "_tunnel_t *);
  " encap_stack "_main_t * ngm = &" encap_stack "_main;

  s = format (s, 
              \"[%d] %U (src) %U (dst) fibs: encap %d, decap %d\",
              t - ngm->tunnels,
              format_ip4_address, &t->src,
              format_ip4_address, &t->dst,
              t->encap_fib_index,
              t->decap_fib_index);

  s = format (s, \" decap next %U\\n\", format_decap_next, t->decap_next_index);
  /* FIXME: add protocol details */
  return s;
}

static u8 * format_" encap_stack "_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, \"" encap_stack "_tunnel%d\", dev_instance);
}

static uword dummy_interface_tx (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  clib_warning (\"you shouldn't be here, leaking buffers...\");
  return frame->n_vectors;
}

VNET_DEVICE_CLASS (" encap_stack "_device_class,static) = {
  .name = "" ENCAP_STACK "",
  .format_device_name = format_" encap_stack "_name,
  .format_tx_trace = format_" encap_stack "_encap_trace,
  .tx_function = dummy_interface_tx,
};

static uword dummy_set_rewrite (vnet_main_t * vnm,
                                u32 sw_if_index,
                                u32 l3_type,
                                void * dst_address,
                                void * rewrite,
                                uword max_rewrite_bytes)
{
  return 0;
}

u8 * format_" encap_stack "_header_with_length (u8 * s, va_list * args)
{
  " encap_stack "_header_t * h = va_arg (*args, " encap_stack "_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, \"" encap-stack "header truncated\");

  /* FIXME: pretty-print an " encap_stack " header */

  return s;
}

VNET_HW_INTERFACE_CLASS (" encap_stack "_hw_class) = {
  .name = \"" ENCAP_STACK "\",
  .format_header = format_" encap_stack "_header_with_length,
  .set_rewrite = dummy_set_rewrite,
};

#define foreach_copy_field                      \
_(src.as_u32)                                   \
_(dst.as_u32)                                   \
_(encap_fib_index)                              \
_(decap_fib_index)                              \
_(decap_next_index)                             \
_(FIXME_ADD_ALL_COPY_FIELDS )

static int " encap_stack "_rewrite (" encap_stack "_tunnel_t * t)
{
  u8 *rw = 0;
  ip4_header_t * ip0;
  " encap_stack "_header_t * h0;
  int len;

  len = sizeof (*h0);

  vec_validate_aligned (rw, len-1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip4_udp_" encap_stack "_header_t *) rw;

  /* FIXME: build the actual header here... */

  /* Fixed portion of the (outer) ip4 header */
  ip0 = &h0->ip4;
  ip0->ip_version_and_header_length = 0x45;
  ip0->ttl = 254;
  ip0->protocol = IP_PROTOCOL_UDP;

  /* we'll fix up the ip4 header length and checksum after-the-fact */
  ip0->src_address.as_u32 = t->src.as_u32;
  ip0->dst_address.as_u32 = t->dst.as_u32;
  ip0->checksum = ip4_header_checksum (ip0);

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (4341);
  h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_" encap_stack ");

  /* $$$ build a <mumble> tunnel header here */
  
  t->rewrite = rw;
  return (0);
}

int vnet_" encap_stack "_add_del_tunnel 
(vnet_" encap_stack "_add_del_tunnel_args_t *a, u32 * hw_if_indexp)
{
  " encap_stack "_main_t * ngm = &" encap_stack "_main;
  " encap_stack "_tunnel_t *t = 0;
  vnet_main_t * vnm = ngm->vnet_main;
  vnet_hw_interface_t * hi;
  uword * p;
  u32 hw_if_index = ~0;
  int rv;
  " encap_stack "_tunnel_key_t key, *key_copy;
  hash_pair_t *hp;
  
  key.FIXME = clib_host_to_net_XXX(FIXME);

  p = hash_get_mem (ngm->" encap_stack "_tunnel_by_key, &key);
  
  if (a->is_add)
    {
      /* adding a tunnel: tunnel must not already exist */
      if (p) 
        return VNET_API_ERROR_INVALID_VALUE;
      
      pool_get_aligned (ngm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));
      
      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _
      
      rv = " encap_stack "_rewrite (t);

      if (rv)
        {
          pool_put (ngm->tunnels, t);
          return rv;
        }

      /* $$$$ use a simple hash if you can ... */
      key_copy = clib_mem_alloc (sizeof (*key_copy));
      clib_memcpy (key_copy, &key, sizeof (*key_copy));

      hash_set_mem (ngm->" encap_stack "_tunnel_by_key, key_copy, 
                    t - ngm->tunnels);
      
      /* 
       * interface freelist / recycle shtik
       * This simple implementation rapidly reuses freed tunnel interfaces.
       * Consider whether to refcount, etc. etc.
       */ 
      if (vec_len (ngm->free_" encap_stack "_tunnel_hw_if_indices) > 0)
        {
          hw_if_index = ngm->free_" encap_stack "_tunnel_hw_if_indices
            [vec_len (ngm->free_" encap_stack "_tunnel_hw_if_indices)-1];
          _vec_len (ngm->free_" encap_stack "_tunnel_hw_if_indices) -= 1;
          
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->dev_instance = t - ngm->tunnels;
          hi->hw_instance = hi->dev_instance;
        }
      else 
        {
          hw_if_index = vnet_register_interface
            (vnm, " encap_stack "_device_class.index, t - ngm->tunnels,
             " encap_stack "_hw_class.index, t - ngm->tunnels);
          hi = vnet_get_hw_interface (vnm, hw_if_index);
          hi->output_node_index = " encap_stack "_encap_node.index;
        }
      
      t->hw_if_index = hw_if_index;
      
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 
                                   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
    }
  else
    {
      /* deleting a tunnel: tunnel must exist */
      if (!p) 
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (ngm->tunnels, p[0]);

      vnet_sw_interface_set_flags (vnm, t->hw_if_index, 0 /* down */);
      vec_add1 (ngm->free_" encap_stack "_tunnel_hw_if_indices, t->hw_if_index);

      hp = hash_get_pair (ngm->" encap_stack "_tunnel_by_key, &key);
      key_copy = (void *)(hp->key);
      hash_unset_mem (ngm->" encap_stack "_tunnel_by_key, &key);
      clib_mem_free (key_copy);

      vec_free (t->rewrite);
      pool_put (ngm->tunnels, t);
    }

  if (hw_if_indexp)
      *hw_if_indexp = hw_if_index;

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

static uword unformat_decap_next (unformat_input_t * input, va_list * args)
{
  u32 * result = va_arg (*args, u32 *);
  u32 tmp;
  
  if (unformat (input, \"drop\"))
    *result = " ENCAP_STACK "_INPUT_NEXT_DROP;
  else if (unformat (input, \"ip4\"))
    *result = " ENCAP_STACK "_INPUT_NEXT_IP4_INPUT;
  else if (unformat (input, \"ip6\"))
    *result = " ENCAP_STACK "_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, \"ethernet\"))
    *result = " ENCAP_STACK "_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, \"" encap-stack "\"))
    *result = " ENCAP_STACK "_INPUT_NEXT_" ENCAP_STACK "_ENCAP;
  else if (unformat (input, \"%d\", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static clib_error_t *
" encap_stack "_add_del_tunnel_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  clib_error_t *error = 0;
  ip4_address_t src, dst;
  u8 is_add = 1;
  u8 src_set = 0;
  u8 dst_set = 0;
  u32 encap_fib_index = 0;
  u32 decap_fib_index = 0;
  u8 next_protocol = " ENCAP_STACK "_NEXT_PROTOCOL_IP4;
  u32 decap_next_index = " ENCAP_STACK "_INPUT_NEXT_IP4_INPUT;
  u8 flags = " ENCAP_STACK "_FLAGS_P;
  u8 ver_res = 0;
  u8 res = 0;
  u32 iid = 0;
  u8 iid_set = 0;
  u32 tmp;
  int rv;
  vnet_" encap_stack "_add_del_tunnel_args_t _a, * a = &_a;
  
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, \"del\"))
      is_add = 0;
    else if (unformat (line_input, \"src %U\", 
                       unformat_ip4_address, &src))
      src_set = 1;
    else if (unformat (line_input, \"dst %U\",
                       unformat_ip4_address, &dst))
      dst_set = 1;
    else if (unformat (line_input, \"encap-vrf-id %d\", &tmp))
      {
        encap_fib_index = fib_index_from_fib_id (tmp);
        if (encap_fib_index == ~0)
          {
            unformat_free (line_input);
            return clib_error_return (0, \"nonexistent encap fib id %d\", tmp);
          }
      }
    else if (unformat (line_input, \"decap-vrf-id %d\", &tmp))
      {
        decap_fib_index = fib_index_from_fib_id (tmp);
        if (decap_fib_index == ~0)
          {
            unformat_free (line_input);
            return clib_error_return (0, \"nonexistent decap fib id %d\", tmp);
          }
      }
    else if (unformat (line_input, \"decap-next %U\", unformat_decap_next, 
                       &decap_next_index))
      ;
    else if (unformat(line_input, \"next-ip4\"))
      next_protocol = 1;
    else if (unformat(line_input, \"next-ip6\"))
      next_protocol = 2;
    else if (unformat(line_input, \"next-ethernet\"))
      next_protocol = 3;
    else if (unformat(line_input, \"next-nsh\"))
      next_protocol = 4;
    /* 
     * $$$ allow the user to specify anything they want 
     * in the " ENCAP_STACK " header
     */
    else 
      {
        error = clib_error_return (0, \"parse error: '%U'\",
                                   format_unformat_error, line_input);
        unformat_free (line_input);
        return error;
      }
  }

  unformat_free (line_input);

  if (src_set == 0)
    return clib_error_return (0, \"tunnel src address not specified\");

  if (dst_set == 0)
    return clib_error_return (0, \"tunnel dst address not specified\");

  memset (a, 0, sizeof (*a));

  a->is_add = is_add;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _
  
  rv = vnet_" encap_stack "_add_del_tunnel (a, 0 /* hw_if_indexp */);

  switch(rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, \"tunnel already exists...\");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, \"tunnel does not exist...\");

    default:
      return clib_error_return 
        (0, \"vnet_" encap_stack "_add_del_tunnel returned %d\", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_" encap_stack "_tunnel_command, static) = {
  .path = \"lisp gpe tunnel\",
  .short_help = 
  \"<mumble> tunnel src <ip4-addr> dst <ip4-addr>\\n\"
  \"    [encap-fib-id <nn>] [decap-fib-id <nn>]\\n\"
  \"    [decap-next [ip4|ip6|ethernet|nsh-encap|<nn>]][del]\\n\",
  .function = " encap_stack "_add_del_tunnel_command_fn,
};

static clib_error_t *
show_" encap_stack "_tunnel_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  " encap_stack "_main_t * ngm = &" encap_stack "_main;
  " encap_stack "_tunnel_t * t;
  
  if (pool_elts (ngm->tunnels) == 0)
    vlib_cli_output (vm, \"No lisp-gpe tunnels configured...\");

  pool_foreach (t, ngm->tunnels,
  ({
    vlib_cli_output (vm, \"%U\", format_" encap_stack "_tunnel);
  }));
  
  return 0;
}

VLIB_CLI_COMMAND (show_" encap_stack "_tunnel_command, static) = {
    .path = \"show lisp gpe tunnel\",
    .function = show_" encap_stack "_tunnel_command_fn,
};

clib_error_t *" encap_stack "_init (vlib_main_t *vm)
{
  " encap_stack "_main_t *ngm = &" encap_stack "_main;
  
  ngm->vnet_main = vnet_get_main();
  ngm->vlib_main = vm;
  
  ngm->" encap_stack "_tunnel_by_key 
    = hash_create_mem (0, sizeof(" encap_stack "_tunnel_key_t), sizeof (uword));

  /* YMMV, register with the local netstack */
  udp_register_dst_port (vm, UDP_DST_PORT_" encap_stack ", 
                         " encap_stack "_input_node.index, 1 /* is_ip4 */);
  return 0;
}

VLIB_INIT_FUNCTION(" encap_stack "_init);

")
  
