;;; tunnel-h-skel.el - tunnel encap header file skeleton

(require 'skeleton)

(define-skeleton skel-tunnel-h
"Insert a tunnel encap header file"
nil
'(setq encap_stack (skeleton-read "encap_stack (e.g ip4_udp_lisp): "))
'(setq ENCAP_STACK (upcase encap_stack))
'(setq encap-stack (replace-regexp-in-string "_" "-" encap_stack))
"
#ifndef included_vnet_" encap_stack "_h
#define included_vnet_" encap_stack "_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/" encap-stack "/" encap_stack "_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/udp.h>

/* Encap stack built in encap.c */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;             /* 20 bytes */
  udp_header_t udp;             /* 8 bytes */
  " encap_stack "_header_t lisp;       /* 8 bytes */
}) " encap_stack "_header_t;

typedef CLIB_PACKED(struct {
  /* 
   * Key fields: 
   * all fields in NET byte order
   */
  union {
    struct {
      u32 FIXME_NET_BYTE_ORDER;
    };
    u64 as_u64[1];
  };
}) " encap_stack "_tunnel_key_t;

typedef struct {
  /* Rewrite string. $$$$ maybe: embed vnet_rewrite header */
  u8 * rewrite;

  /* decap next index */
  u32 decap_next_index;

  /* tunnel src and dst addresses */
  ip4_address_t src;
  ip4_address_t dst;

  /* FIB indices */
  u32 encap_fib_index;          /* tunnel partner lookup here */
  u32 decap_fib_index;          /* inner IP lookup here */

  /* vnet intfc hw/sw_if_index */
  u32 hw_if_index;

  /* encap header fields in HOST byte order */
  u32 FIXME;
} " encap_stack "_tunnel_t;

#define foreach_" encap_stack "_input_next        \\
_(DROP, \"error-drop\")                           \\
_(IP4_INPUT, \"ip4-input\")                       \\
_(IP6_INPUT, \"ip6-input\")                       \\
_(ETHERNET_INPUT, \"ethernet-input\")             \\
_(" ENCAP_STACK "_ENCAP, \"" encap-stack "-encap\")

typedef enum {
#define _(s,n) " ENCAP_STACK "_INPUT_NEXT_##s,
  foreach_" encap_stack "_input_next
#undef _
  " ENCAP_STACK "_INPUT_N_NEXT,
} " encap_stack "_input_next_t;

typedef enum {
#define " encap_stack "_error(n,s) " ENCAP_STACK "_ERROR_##n,
#include <vnet/" encap-stack "/" encap_stack "_error.def>
#undef " encap_stack "_error
  " ENCAP_STACK "_N_ERROR,
} " encap_stack "_input_error_t;

typedef struct {
  /* vector of encap tunnel instances */
  " encap_stack "_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword * " encap_stack "_tunnel_by_key;

  /* Free vlib hw_if_indices */
  u32 * free_" encap_stack "_tunnel_hw_if_indices;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} " encap_stack "_main_t;

" encap_stack "_main_t " encap_stack "_main;

vlib_node_registration_t " encap_stack "_input_node;
vlib_node_registration_t " encap_stack "_encap_node;

u8 * format_" encap_stack "_encap_trace (u8 * s, va_list * args);
u8 * format_" encap_stack "_header_with_length (u8 * s, va_list * args);

typedef struct {
  u8 is_add;
  ip4_address_t src, dst;
  u32 encap_fib_index;
  u32 decap_fib_index;
  u32 decap_next_index;
  /* encap fields in HOST byte order */
  u8 FIXME_HOST_BYTE_ORDER;
} vnet_" encap_stack "_add_del_tunnel_args_t;

int vnet_" encap_stack "_add_del_tunnel 
(vnet_" encap_stack "_add_del_tunnel_args_t *a, u32 * hw_if_indexp);

u8 * format_" encap_stack "_header_with_length (u8 * s, va_list * args);

#endif /* included_vnet_" encap_stack "_h */

")
