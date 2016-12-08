#include <vppinfra/types.h>
#include <vlibmemory/api.h>
#include <vlib/vlib.h>
#include <vlib/buffer.h>
#include <vnet/ip/format.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/udp_packet.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/udp.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/bfd/bfd_debug.h>
#include <vnet/bfd/bfd_udp.h>
#include <vnet/bfd/bfd_main.h>
#include <vnet/bfd/bfd_api.h>

typedef struct
{
  bfd_main_t *bfd_main;
  /* hashmap - bfd session index by bfd key - used for CLI/API lookup, where
   * discriminator is unknown */
  mhash_t bfd_session_idx_by_bfd_key;
} bfd_udp_main_t;

static vlib_node_registration_t bfd_udp4_input_node;
static vlib_node_registration_t bfd_udp6_input_node;

bfd_udp_main_t bfd_udp_main;

void bfd_udp_transport_to_buffer (vlib_main_t *vm, vlib_buffer_t *b,
                                  bfd_udp_session_t *bus)
{
  udp_header_t *udp;
  u16 udp_length, ip_length;
  bfd_udp_key_t *key = &bus->key;

  b->flags |= VNET_BUFFER_LOCALLY_ORIGINATED;
  if (ip46_address_is_ip4 (&key->local_addr))
    {
      ip4_header_t *ip4;
      const size_t data_size = sizeof (*ip4) + sizeof (*udp);
      vlib_buffer_advance (b, -data_size);
      ip4 = vlib_buffer_get_current (b);
      udp = (udp_header_t *)(ip4 + 1);
      memset (ip4, 0, data_size);
      ip4->ip_version_and_header_length = 0x45;
      ip4->ttl = 255;
      ip4->protocol = IP_PROTOCOL_UDP;
      ip4->src_address.as_u32 = key->local_addr.ip4.as_u32;
      ip4->dst_address.as_u32 = key->peer_addr.ip4.as_u32;

      udp->src_port = clib_host_to_net_u16 (50000); /* FIXME */
      udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_bfd4);

      /* fix ip length, checksum and udp length */
      ip_length = vlib_buffer_length_in_chain (vm, b);

      ip4->length = clib_host_to_net_u16 (ip_length);
      ip4->checksum = ip4_header_checksum (ip4);

      udp_length = ip_length - (sizeof (*ip4));
      udp->length = clib_host_to_net_u16 (udp_length);
    }
  else
    {
      BFD_ERR ("not implemented");
      abort ();
    }
}

void bfd_add_udp_transport (vlib_main_t *vm, vlib_buffer_t *b,
                            bfd_udp_session_t *bus)
{
  vnet_buffer (b)->ip.adj_index[VLIB_RX] = bus->adj_index;
  vnet_buffer (b)->ip.adj_index[VLIB_TX] = bus->adj_index;
  bfd_udp_transport_to_buffer (vm, b, bus);
}

static bfd_session_t *bfd_lookup_session (bfd_udp_main_t *bum,
                                          const bfd_udp_key_t *key)
{
  uword *p = mhash_get (&bum->bfd_session_idx_by_bfd_key, key);
  if (p)
    {
      return bfd_find_session_by_idx (bum->bfd_main, *p);
    }
  return 0;
}

static vnet_api_error_t
bfd_udp_add_session_internal (bfd_udp_main_t *bum, u32 sw_if_index,
                              u32 desired_min_tx_us, u32 required_min_rx_us,
                              u8 detect_mult, const ip46_address_t *local_addr,
                              const ip46_address_t *peer_addr)
{
  vnet_sw_interface_t *sw_if =
      vnet_get_sw_interface (vnet_get_main (), sw_if_index);
  /* get a pool entry and if we end up not needing it, give it back */
  bfd_transport_t t = BFD_TRANSPORT_UDP4;
  if (!ip46_address_is_ip4 (local_addr))
    {
      t = BFD_TRANSPORT_UDP6;
    }
  bfd_session_t *bs = bfd_get_session (bum->bfd_main, t);
  bfd_udp_session_t *bus = &bs->udp;
  memset (bus, 0, sizeof (*bus));
  bfd_udp_key_t *key = &bus->key;
  key->sw_if_index = sw_if->sw_if_index;
  key->local_addr.as_u64[0] = local_addr->as_u64[0];
  key->local_addr.as_u64[1] = local_addr->as_u64[1];
  key->peer_addr.as_u64[0] = peer_addr->as_u64[0];
  key->peer_addr.as_u64[1] = peer_addr->as_u64[1];
  const bfd_session_t *tmp = bfd_lookup_session (bum, key);
  if (tmp)
    {
      BFD_ERR ("duplicate bfd-udp session, existing bs_idx=%d", tmp->bs_idx);
      bfd_put_session (bum->bfd_main, bs);
      return VNET_API_ERROR_BFD_EEXIST;
    }
  key->sw_if_index = sw_if->sw_if_index;
  mhash_set (&bum->bfd_session_idx_by_bfd_key, key, bs->bs_idx, NULL);
  BFD_DBG ("session created, bs_idx=%u, sw_if_index=%d, local=%U, peer=%U",
           bs->bs_idx, key->sw_if_index, format_ip46_address, &key->local_addr,
           IP46_TYPE_ANY, format_ip46_address, &key->peer_addr, IP46_TYPE_ANY);
  if (BFD_TRANSPORT_UDP4 == t)
    {
      bus->adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_IP4,
                                            &key->peer_addr, key->sw_if_index);
      BFD_DBG ("adj_nbr_add_or_lock(FIB_PROTOCOL_IP4, VNET_LINK_IP4, %U, %d) "
               "returns %d",
               format_ip46_address, &key->peer_addr, IP46_TYPE_ANY,
               key->sw_if_index, bus->adj_index);
    }
  else
    {
      bus->adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP6, VNET_LINK_IP6,
                                            &key->peer_addr, key->sw_if_index);
      BFD_DBG ("adj_nbr_add_or_lock(FIB_PROTOCOL_IP6, VNET_LINK_IP6, %U, %d) "
               "returns %d",
               format_ip46_address, &key->peer_addr, IP46_TYPE_ANY,
               key->sw_if_index, bus->adj_index);
    }
  bs->config_desired_min_tx_us = desired_min_tx_us;
  bs->required_min_rx_us = required_min_rx_us;
  bs->local_detect_mult = detect_mult;
  bfd_session_start (bum->bfd_main, bs);
  return 0;
}

static vnet_api_error_t
bfd_udp_validate_api_input (u32 sw_if_index, const ip46_address_t *local_addr,
                            const ip46_address_t *peer_addr)
{
  vnet_sw_interface_t *sw_if =
      vnet_get_sw_interface (vnet_get_main (), sw_if_index);
  u8 local_ip_valid = 0;
  ip_interface_address_t *ia = NULL;
  if (!sw_if)
    {
      BFD_ERR ("got NULL sw_if");
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }
  if (ip46_address_is_ip4 (local_addr))
    {
      if (!ip46_address_is_ip4 (peer_addr))
        {
          BFD_ERR ("IP family mismatch");
          return VNET_API_ERROR_INVALID_ARGUMENT;
        }
      ip4_main_t *im = &ip4_main;

      /* *INDENT-OFF* */
      foreach_ip_interface_address (
          &im->lookup_main, ia, sw_if_index, 0 /* honor unnumbered */, ({
            ip4_address_t *x =
                ip_interface_address_get_address (&im->lookup_main, ia);
            if (x->as_u32 == local_addr->ip4.as_u32)
              {
                /* valid address for this interface */
                local_ip_valid = 1;
                break;
              }
          }));
      /* *INDENT-ON* */
    }
  else
    {
      if (ip46_address_is_ip4 (peer_addr))
        {
          BFD_ERR ("IP family mismatch");
          return VNET_API_ERROR_INVALID_ARGUMENT;
        }
      ip6_main_t *im = &ip6_main;
      /* *INDENT-OFF* */
      foreach_ip_interface_address (
          &im->lookup_main, ia, sw_if_index, 0 /* honor unnumbered */, ({
            ip6_address_t *x =
                ip_interface_address_get_address (&im->lookup_main, ia);
            if (local_addr->ip6.as_u64[0] == x->as_u64[0] &&
                local_addr->ip6.as_u64[1] == x->as_u64[1])
              {
                /* valid address for this interface */
                local_ip_valid = 1;
                break;
              }
          }));
      /* *INDENT-ON* */
    }

  if (!local_ip_valid)
    {
      BFD_ERR ("address not found on interface");
      return VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE;
    }

  return 0;
}

vnet_api_error_t bfd_udp_add_session (u32 sw_if_index, u32 desired_min_tx_us,
                                      u32 required_min_rx_us, u8 detect_mult,
                                      const ip46_address_t *local_addr,
                                      const ip46_address_t *peer_addr)
{
  vnet_api_error_t rv =
      bfd_udp_validate_api_input (sw_if_index, local_addr, peer_addr);
  if (rv)
    {
      return rv;
    }
  if (detect_mult < 1)
    {
      BFD_ERR ("detect_mult < 1");
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }
  if (desired_min_tx_us < 1)
    {
      BFD_ERR ("desired_min_tx_us < 1");
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }
  return bfd_udp_add_session_internal (&bfd_udp_main, sw_if_index,
                                       desired_min_tx_us, required_min_rx_us,
                                       detect_mult, local_addr, peer_addr);
}

vnet_api_error_t bfd_udp_del_session (u32 sw_if_index,
                                      const ip46_address_t *local_addr,
                                      const ip46_address_t *peer_addr)
{
  vnet_api_error_t rv =
      bfd_udp_validate_api_input (sw_if_index, local_addr, peer_addr);
  if (rv)
    {
      return rv;
    }
  bfd_udp_main_t *bum = &bfd_udp_main;
  vnet_sw_interface_t *sw_if =
      vnet_get_sw_interface (vnet_get_main (), sw_if_index);
  bfd_udp_key_t key;
  memset (&key, 0, sizeof (key));
  key.sw_if_index = sw_if->sw_if_index;
  key.local_addr.as_u64[0] = local_addr->as_u64[0];
  key.local_addr.as_u64[1] = local_addr->as_u64[1];
  key.peer_addr.as_u64[0] = peer_addr->as_u64[0];
  key.peer_addr.as_u64[1] = peer_addr->as_u64[1];
  bfd_session_t *tmp = bfd_lookup_session (bum, &key);
  if (tmp)
    {
      BFD_DBG ("free bfd-udp session, bs_idx=%d", tmp->bs_idx);
      mhash_unset (&bum->bfd_session_idx_by_bfd_key, &key, NULL);
      adj_unlock (tmp->udp.adj_index);
      bfd_put_session (bum->bfd_main, tmp);
    }
  else
    {
      BFD_ERR ("no such session");
      return VNET_API_ERROR_BFD_NOENT;
    }
  return 0;
}

typedef enum {
  BFD_UDP_INPUT_NEXT_NORMAL,
  BFD_UDP_INPUT_NEXT_REPLY,
  BFD_UDP_INPUT_N_NEXT,
} bfd_udp_input_next_t;

/* Packet counters */
#define foreach_bfd_udp_error(F)           \
  F (NONE, "good bfd packets (processed)") \
  F (BAD, "invalid bfd packets")           \
  F (DISABLED, "bfd packets received on disabled interfaces")

#define F(sym, string) static char BFD_UDP_ERR_##sym##_STR[] = string;
foreach_bfd_udp_error (F);
#undef F

static char *bfd_udp_error_strings[] = {
#define F(sym, string) BFD_UDP_ERR_##sym##_STR,
  foreach_bfd_udp_error (F)
#undef F
};

typedef enum {
#define F(sym, str) BFD_UDP_ERROR_##sym,
  foreach_bfd_udp_error (F)
#undef F
      BFD_UDP_N_ERROR,
} bfd_udp_error_t;

static void bfd_udp4_find_headers (vlib_buffer_t *b, const ip4_header_t **ip4,
                                   const udp_header_t **udp)
{
  /* sanity check first */
  const i32 start = vnet_buffer (b)->ip.start_of_ip_header;
  if (start < 0 && start < sizeof (b->pre_data))
    {
      BFD_ERR ("Start of ip header is before pre_data, ignoring");
      *ip4 = NULL;
      *udp = NULL;
      return;
    }
  *ip4 = (ip4_header_t *)(b->data + start);
  if ((u8 *)*ip4 > (u8 *)vlib_buffer_get_current (b))
    {
      BFD_ERR ("Start of ip header is beyond current data, ignoring");
      *ip4 = NULL;
      *udp = NULL;
      return;
    }
  *udp = (udp_header_t *)((*ip4) + 1);
}

static bfd_udp_error_t bfd_udp4_verify_transport (const ip4_header_t *ip4,
                                                  const udp_header_t *udp,
                                                  const bfd_session_t *bs)
{
  const bfd_udp_session_t *bus = &bs->udp;
  const bfd_udp_key_t *key = &bus->key;
  if (ip4->src_address.as_u32 != key->peer_addr.ip4.as_u32)
    {
      BFD_ERR ("IP src addr mismatch, got %U, expected %U", format_ip4_address,
               ip4->src_address.as_u32, format_ip4_address,
               key->peer_addr.ip4.as_u32);
      return BFD_UDP_ERROR_BAD;
    }
  if (ip4->dst_address.as_u32 != key->local_addr.ip4.as_u32)
    {
      BFD_ERR ("IP dst addr mismatch, got %U, expected %U", format_ip4_address,
               ip4->dst_address.as_u32, format_ip4_address,
               key->local_addr.ip4.as_u32);
      return BFD_UDP_ERROR_BAD;
    }
  const u8 expected_ttl = 255;
  if (ip4->ttl != expected_ttl)
    {
      BFD_ERR ("IP unexpected TTL value %d, expected %d", ip4->ttl,
               expected_ttl);
      return BFD_UDP_ERROR_BAD;
    }
  if (clib_net_to_host_u16 (udp->src_port) < 49152 ||
      clib_net_to_host_u16 (udp->src_port) > 65535)
    {
      BFD_ERR ("Invalid UDP src port %d, out of range <49152,65535>",
               udp->src_port);
    }
  return BFD_UDP_ERROR_NONE;
}

typedef struct
{
  u32 bs_idx;
  bfd_pkt_t pkt;
} bfd_rpc_update_t;

static void bfd_rpc_update_session_cb (const bfd_rpc_update_t *a)
{
  bfd_consume_pkt (bfd_udp_main.bfd_main, &a->pkt, a->bs_idx);
}

static void bfd_rpc_update_session (u32 bs_idx, const bfd_pkt_t *pkt)
{
  /* packet length was already verified to be correct by the caller */
  const u32 data_size = sizeof (bfd_rpc_update_t) -
                        STRUCT_SIZE_OF (bfd_rpc_update_t, pkt) +
                        pkt->head.length;
  u8 data[data_size];
  bfd_rpc_update_t *update = (bfd_rpc_update_t *)data;
  update->bs_idx = bs_idx;
  clib_memcpy (&update->pkt, pkt, pkt->head.length);
  vl_api_rpc_call_main_thread (bfd_rpc_update_session_cb, data, data_size);
}

static bfd_udp_error_t bfd_udp4_scan (vlib_main_t *vm, vlib_node_runtime_t *rt,
                                      vlib_buffer_t *b, bfd_session_t **bs_out)
{
  const bfd_pkt_t *pkt = vlib_buffer_get_current (b);
  if (sizeof (*pkt) > b->current_length)
    {
      BFD_ERR (
          "Payload size %d too small to hold bfd packet of minimum size %d",
          b->current_length, sizeof (*pkt));
      return BFD_UDP_ERROR_BAD;
    }
  const ip4_header_t *ip4;
  const udp_header_t *udp;
  bfd_udp4_find_headers (b, &ip4, &udp);
  if (!ip4 || !udp)
    {
      BFD_ERR ("Couldn't find ip4 or udp header");
      return BFD_UDP_ERROR_BAD;
    }
  if (!bfd_verify_pkt_common (pkt))
    {
      return BFD_UDP_ERROR_BAD;
    }
  bfd_session_t *bs = NULL;
  if (pkt->your_disc)
    {
      BFD_DBG ("Looking up BFD session using discriminator %u",
               pkt->your_disc);
      bs = bfd_find_session_by_disc (bfd_udp_main.bfd_main, pkt->your_disc);
    }
  else
    {
      bfd_udp_key_t key;
      memset (&key, 0, sizeof (key));
      key.sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      key.local_addr.ip4.as_u32 = ip4->dst_address.as_u32;
      key.peer_addr.ip4.as_u32 = ip4->src_address.as_u32;
      BFD_DBG ("Looking up BFD session using key (sw_if_index=%u, local=%U, "
               "peer=%U)",
               key.sw_if_index, format_ip4_address, key.local_addr.ip4.as_u8,
               format_ip4_address, key.peer_addr.ip4.as_u8);
      bs = bfd_lookup_session (&bfd_udp_main, &key);
    }
  if (!bs)
    {
      BFD_ERR ("BFD session lookup failed - no session matches BFD pkt");
      return BFD_UDP_ERROR_BAD;
    }
  BFD_DBG ("BFD session found, bs_idx=%d", bs->bs_idx);
  if (!bfd_verify_pkt_session (pkt, b->current_length, bs))
    {
      return BFD_UDP_ERROR_BAD;
    }
  bfd_udp_error_t err;
  if (BFD_UDP_ERROR_NONE != (err = bfd_udp4_verify_transport (ip4, udp, bs)))
    {
      return err;
    }
  bfd_rpc_update_session (bs->bs_idx, pkt);
  *bs_out = bs;
  return BFD_UDP_ERROR_NONE;
}

static bfd_udp_error_t bfd_udp6_scan (vlib_main_t *vm, vlib_buffer_t *b)
{
  /* TODO */
  return BFD_UDP_ERROR_BAD;
}

/*
 * Process a frame of bfd packets
 * Expect 1 packet / frame
 */
static uword bfd_udp_input (vlib_main_t *vm, vlib_node_runtime_t *rt,
                            vlib_frame_t *f, int is_ipv6)
{
  u32 n_left_from, *from;
  bfd_input_trace_t *t0;

  from = vlib_frame_vector_args (f); /* array of buffer indices */
  n_left_from = f->n_vectors;        /* number of buffer indices */

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0, error0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      bfd_session_t *bs = NULL;

      /* If this pkt is traced, snapshot the data */
      if (b0->flags & VLIB_BUFFER_IS_TRACED)
        {
          int len;
          t0 = vlib_add_trace (vm, rt, b0, sizeof (*t0));
          len = (b0->current_length < sizeof (t0->data)) ? b0->current_length
                                                         : sizeof (t0->data);
          t0->len = len;
          clib_memcpy (t0->data, vlib_buffer_get_current (b0), len);
        }

      /* scan this bfd pkt. error0 is the counter index to bmp */
      if (is_ipv6)
        {
          error0 = bfd_udp6_scan (vm, b0);
        }
      else
        {
          error0 = bfd_udp4_scan (vm, rt, b0, &bs);
        }
      b0->error = rt->errors[error0];

      next0 = BFD_UDP_INPUT_NEXT_NORMAL;
      if (BFD_UDP_ERROR_NONE == error0)
        {
          /* if everything went fine, check for poll bit, if present, re-use
             the buffer and based on (now updated) session parameters, send the
             final packet back */
          const bfd_pkt_t *pkt = vlib_buffer_get_current (b0);
          if (bfd_pkt_get_poll (pkt))
            {
              bfd_send_final (vm, b0, bs);
              if (is_ipv6)
                {
                  vlib_node_increment_counter (vm, bfd_udp6_input_node.index,
                                               b0->error, 1);
                }
              else
                {
                  vlib_node_increment_counter (vm, bfd_udp4_input_node.index,
                                               b0->error, 1);
                }
              next0 = BFD_UDP_INPUT_NEXT_REPLY;
            }
        }
      vlib_set_next_frame_buffer (vm, rt, next0, bi0);

      from += 1;
      n_left_from -= 1;
    }

  return f->n_vectors;
}

static uword bfd_udp4_input (vlib_main_t *vm, vlib_node_runtime_t *rt,
                             vlib_frame_t *f)
{
  return bfd_udp_input (vm, rt, f, 0);
}

/*
 * bfd input graph node declaration
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (bfd_udp4_input_node, static) = {
  .function = bfd_udp4_input,
  .name = "bfd-udp4-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = BFD_UDP_N_ERROR,
  .error_strings = bfd_udp_error_strings,

  .format_trace = bfd_input_format_trace,

  .n_next_nodes = BFD_UDP_INPUT_N_NEXT,
  .next_nodes =
      {
              [BFD_UDP_INPUT_NEXT_NORMAL] = "error-drop",
              [BFD_UDP_INPUT_NEXT_REPLY] = "ip4-lookup",
      },
};
/* *INDENT-ON* */

static uword bfd_udp6_input (vlib_main_t *vm, vlib_node_runtime_t *rt,
                             vlib_frame_t *f)
{
  return bfd_udp_input (vm, rt, f, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (bfd_udp6_input_node, static) = {
  .function = bfd_udp6_input,
  .name = "bfd-udp6-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = BFD_UDP_N_ERROR,
  .error_strings = bfd_udp_error_strings,

  .format_trace = bfd_input_format_trace,

  .n_next_nodes = BFD_UDP_INPUT_N_NEXT,
  .next_nodes =
      {
              [BFD_UDP_INPUT_NEXT_NORMAL] = "error-drop",
              [BFD_UDP_INPUT_NEXT_REPLY] = "ip6-lookup",
      },
};
/* *INDENT-ON* */

static clib_error_t *bfd_sw_interface_up_down (vnet_main_t *vnm,
                                               u32 sw_if_index, u32 flags)
{
  // vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!(flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
    {
      /* TODO */
    }
  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (bfd_sw_interface_up_down);

static clib_error_t *bfd_hw_interface_up_down (vnet_main_t *vnm,
                                               u32 hw_if_index, u32 flags)
{
  if (flags & VNET_HW_INTERFACE_FLAG_LINK_UP)
    {
      /* TODO */
    }
  return 0;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (bfd_hw_interface_up_down);

/*
 * setup function
 */
static clib_error_t *bfd_udp_init (vlib_main_t *vm)
{
  mhash_init (&bfd_udp_main.bfd_session_idx_by_bfd_key, sizeof (uword),
              sizeof (bfd_udp_key_t));
  bfd_udp_main.bfd_main = &bfd_main;
  udp_register_dst_port (vm, UDP_DST_PORT_bfd4, bfd_udp4_input_node.index, 1);
  udp_register_dst_port (vm, UDP_DST_PORT_bfd6, bfd_udp6_input_node.index, 0);
  return 0;
}

VLIB_INIT_FUNCTION (bfd_udp_init);
