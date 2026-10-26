/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Intel Corporation
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/devices/devices.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip_punt_drop.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ipsec/ipsec_punt.h>
#include <vnet/udp/udp.h>
#include <vnet/fib/fib_table.h>

#include "fcp_route.h"

static vlib_log_class_t fcp_logger;

#define FCP_DBG(...)  vlib_log_debug (fcp_logger, __VA_ARGS__)
#define FCP_INFO(...) vlib_log_info (fcp_logger, __VA_ARGS__)
#define FCP_WARN(...) vlib_log_warn (fcp_logger, __VA_ARGS__)
#define FCP_ERR(...)  vlib_log_err (fcp_logger, __VA_ARGS__)

typedef struct
{
  u32 phy_sw_if_index;
  u32 host_sw_if_index;
  u32 hw_if_index;
  u32 host_if_index;
  u32 file_index;
  int fd;
  char name[IFNAMSIZ];
  u8 original_mac[6];
  short original_flags;
  int original_mtu;
} fcp_pair_t;

static fcp_pair_t *fcp_pairs;
static u32 *fcp_by_phy;
vnet_device_class_t fcp_device_class;
vlib_node_registration_t fcp_input_node;
static u32 fcp_pair_index (u32 sw_if_index);

static clib_error_t *
fcp_sync_link (vnet_main_t *vnm, u32 phy_sw_if_index)
{
  u32 index = fcp_pair_index (phy_sw_if_index);
  clib_error_t *err = NULL;
  if (index == ~0)
    return NULL;

  fcp_pair_t *pair = pool_elt_at_index (fcp_pairs, index);
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, phy_sw_if_index);
  u32 mtu = sw->mtu[VNET_MTU_L3];
  if (mtu &&
      mtu + sizeof (ethernet_header_t) > vlib_buffer_get_default_data_size (vlib_get_main ()))
    {
      FCP_ERR ("sync_state: tap %s MTU %u exceeds one VPP buffer", pair->name, mtu);
      return clib_error_return (0, "freebsd-cp TAP MTU exceeds one VPP buffer");
    }
  struct ifreq ifr = {};
  int sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      FCP_ERR ("sync_state: tap %s socket: %s", pair->name, strerror (errno));
      return clib_error_return_unix (0, "freebsd-cp link socket");
    }

  strlcpy (ifr.ifr_name, pair->name, sizeof (ifr.ifr_name));
  if (ioctl (sock, SIOCGIFFLAGS, &ifr) < 0)
    goto error;
  short flags =
    (ifr.ifr_flags & ~IFF_UP) | ((sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? IFF_UP : 0);
  if (flags != ifr.ifr_flags)
    {
      ifr.ifr_flags = flags;
      if (ioctl (sock, SIOCSIFFLAGS, &ifr) < 0)
	goto error;
    }

  if (mtu)
    {
      if (ioctl (sock, SIOCGIFMTU, &ifr) < 0)
	goto error;
      if (ifr.ifr_mtu != mtu)
	{
	  ifr.ifr_mtu = mtu;
	  if (ioctl (sock, SIOCSIFMTU, &ifr) < 0)
	    goto error;
	}
    }
  close (sock);
  FCP_DBG ("sync_state: tap %s flags %u mtu %u", pair->name, flags, mtu);
  return NULL;

error:
  err = clib_error_return_unix (0, "freebsd-cp TAP state");
  FCP_ERR ("sync_state: tap %s: %U", pair->name, format_clib_error, err);
  close (sock);
  return err;
}

static clib_error_t *
fcp_admin_change (vnet_main_t *vnm, u32 sw_if_index, u32 flags)
{
  return fcp_sync_link (vnm, sw_if_index);
}
VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (fcp_admin_change);

static clib_error_t *
fcp_mtu_change (vnet_main_t *vnm, u32 sw_if_index, u32 mtu)
{
  return fcp_sync_link (vnm, sw_if_index);
}
VNET_SW_INTERFACE_MTU_CHANGE_FUNCTION (fcp_mtu_change);

static void
fcp_sync_ip4 (u32 sw_if_index, const ip4_address_t *address, u32 prefix, u32 is_del)
{
  u32 index = fcp_pair_index (sw_if_index);
  if (index == ~0 || fcp_route_processing ())
    return;
  fcp_pair_t *pair = pool_elt_at_index (fcp_pairs, index);
  FCP_DBG ("ip4_addr_%s: tap %s %U/%u", is_del ? "del" : "add", pair->name, format_ip4_address,
	   address, prefix);
  int sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      FCP_WARN ("ip4_addr_%s: tap %s: socket: %s", is_del ? "del" : "add", pair->name,
		strerror (errno));
      return;
    }

  int rv;
  if (is_del)
    {
      struct ifreq ifr = {};
      struct sockaddr_in addr = {
	.sin_len = sizeof (addr),
	.sin_family = AF_INET,
      };
      strlcpy (ifr.ifr_name, pair->name, sizeof (ifr.ifr_name));
      clib_memcpy_fast (&addr.sin_addr, address, sizeof (addr.sin_addr));
      clib_memcpy_fast (&ifr.ifr_addr, &addr, sizeof (addr));
      rv = ioctl (sock, SIOCDIFADDR, &ifr);
    }
  else
    {
      struct in_aliasreq req = {};
      strlcpy (req.ifra_name, pair->name, sizeof (req.ifra_name));
      req.ifra_addr.sin_len = sizeof (req.ifra_addr);
      req.ifra_addr.sin_family = AF_INET;
      clib_memcpy_fast (&req.ifra_addr.sin_addr, address, sizeof (req.ifra_addr.sin_addr));
      req.ifra_mask.sin_len = sizeof (req.ifra_mask);
      req.ifra_mask.sin_family = AF_INET;
      req.ifra_mask.sin_addr.s_addr = clib_host_to_net_u32 (prefix ? ~0U << (32 - prefix) : 0);
      rv = ioctl (sock, SIOCAIFADDR, &req);
    }
  if (rv < 0 && errno != EEXIST && errno != EADDRNOTAVAIL)
    {
      FCP_WARN ("ip4_addr_%s: tap %s: %s", is_del ? "del" : "add", pair->name, strerror (errno));
      clib_unix_warning ("freebsd-cp IPv4 TAP address");
    }
  close (sock);
}

static void
fcp_sync_ip6 (u32 sw_if_index, const ip6_address_t *address, u32 prefix, u32 is_del)
{
  u32 index = fcp_pair_index (sw_if_index);
  if (index == ~0 || fcp_route_processing ())
    return;
  fcp_pair_t *pair = pool_elt_at_index (fcp_pairs, index);
  FCP_DBG ("ip6_addr_%s: tap %s %U/%u", is_del ? "del" : "add", pair->name, format_ip6_address,
	   address, prefix);
  int sock = socket (AF_INET6, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      FCP_WARN ("ip6_addr_%s: tap %s: socket: %s", is_del ? "del" : "add", pair->name,
		strerror (errno));
      return;
    }

  int rv;
  if (is_del)
    {
      struct in6_ifreq req = {};
      strlcpy (req.ifr_name, pair->name, sizeof (req.ifr_name));
      req.ifr_ifru.ifru_addr.sin6_len = sizeof (req.ifr_ifru.ifru_addr);
      req.ifr_ifru.ifru_addr.sin6_family = AF_INET6;
      clib_memcpy_fast (&req.ifr_ifru.ifru_addr.sin6_addr, address,
			sizeof (req.ifr_ifru.ifru_addr.sin6_addr));
      rv = ioctl (sock, SIOCDIFADDR_IN6, &req);
    }
  else
    {
      struct in6_aliasreq req = {};
      strlcpy (req.ifra_name, pair->name, sizeof (req.ifra_name));
      req.ifra_addr.sin6_len = sizeof (req.ifra_addr);
      req.ifra_addr.sin6_family = AF_INET6;
      clib_memcpy_fast (&req.ifra_addr.sin6_addr, address, sizeof (req.ifra_addr.sin6_addr));
      req.ifra_prefixmask.sin6_len = sizeof (req.ifra_prefixmask);
      req.ifra_prefixmask.sin6_family = AF_INET6;
      for (u32 bit = 0; bit < prefix; bit++)
	req.ifra_prefixmask.sin6_addr.s6_addr[bit / 8] |= 0x80 >> (bit % 8);
      req.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
      req.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
      rv = ioctl (sock, SIOCAIFADDR_IN6, &req);
    }
  if (rv < 0 && errno != EEXIST && errno != EADDRNOTAVAIL)
    {
      FCP_WARN ("ip6_addr_%s: tap %s: %s", is_del ? "del" : "add", pair->name, strerror (errno));
      clib_unix_warning ("freebsd-cp IPv6 TAP address");
    }
  close (sock);
}

static void
fcp_ip4_addr_change (ip4_main_t *im, uword opaque, u32 sw_if_index, ip4_address_t *address,
		     u32 prefix, u32 addr_index, u32 is_del)
{
  fcp_sync_ip4 (sw_if_index, address, prefix, is_del);
}

static void
fcp_ip6_addr_change (ip6_main_t *im, uword opaque, u32 sw_if_index, ip6_address_t *address,
		     u32 prefix, u32 addr_index, u32 is_del)
{
  fcp_sync_ip6 (sw_if_index, address, prefix, is_del);
}

static void
fcp_sync_existing_addresses (u32 sw_if_index)
{
  ip_interface_address_t *ia;
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;

  foreach_ip_interface_address (
    lm4, ia, sw_if_index, 1, ({
      fcp_sync_ip4 (sw_if_index, ip_interface_address_get_address (lm4, ia), ia->address_length, 0);
    }));
  foreach_ip_interface_address (
    lm6, ia, sw_if_index, 1, ({
      fcp_sync_ip6 (sw_if_index, ip_interface_address_get_address (lm6, ia), ia->address_length, 0);
    }));
}

static clib_error_t *
fcp_sync_init (vlib_main_t *vm)
{
  fcp_logger = vlib_log_register_class ("freebsd-cp", "interface");
  ip4_add_del_interface_address_callback_t cb4 = {
    .function = fcp_ip4_addr_change,
  };
  ip6_add_del_interface_address_callback_t cb6 = {
    .function = fcp_ip6_addr_change,
  };
  vec_add1 (ip4_main.add_del_interface_address_callbacks, cb4);
  vec_add1 (ip6_main.add_del_interface_address_callbacks, cb6);
  return NULL;
}
VLIB_INIT_FUNCTION (fcp_sync_init) = {
  .runs_after = VLIB_INITS ("vnet_interface_init"),
};

static u32
fcp_pair_index (u32 sw_if_index)
{
  if (sw_if_index >= vec_len (fcp_by_phy))
    return ~0;
  return fcp_by_phy[sw_if_index];
}

u32
fcp_phy_for_host (u32 host_if_index)
{
  fcp_pair_t *pair;
  pool_foreach (pair, fcp_pairs)
    if (pair->host_if_index == host_if_index)
      return pair->phy_sw_if_index;
  return ~0;
}

static u8 *
format_fcp_name (u8 *s, va_list *args)
{
  u32 index = va_arg (*args, u32);
  fcp_pair_t *pair = pool_elt_at_index (fcp_pairs, index);
  return format (s, "freebsd-cp-%s", pair->name);
}

typedef struct
{
  bool is_xc;
  u32 phy_sw_if_index;
  u32 host_sw_if_index;
} fcp_punt_xc_trace_t;

static u8 *
format_fcp_punt_xc_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  fcp_punt_xc_trace_t *t = va_arg (*args, fcp_punt_xc_trace_t *);

  if (t->is_xc)
    return format (s, "fcp-xc: %u -> %u", t->host_sw_if_index, t->phy_sw_if_index);
  return format (s, "fcp-punt: %u -> %u", t->phy_sw_if_index, t->host_sw_if_index);
}

VNET_DEVICE_CLASS_TX_FN (fcp_device_class)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_interface_output_runtime_t *runtime = (void *) node->runtime_data;
  fcp_pair_t *pair = pool_elt_at_index (fcp_pairs, runtime->dev_instance);
  u32 *buffers = vlib_frame_vector_args (frame);

  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffers[i]);
      struct iovec iov[16];
      u32 count = 0;
      u32 length = 0;
      ethernet_header_t *eth = vlib_buffer_get_current (b);

      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  fcp_punt_xc_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	  t->is_xc = false;
	  t->phy_sw_if_index = pair->phy_sw_if_index;
	  t->host_sw_if_index = pair->host_sw_if_index;
	}

      if (b->current_length < sizeof (*eth) ||
	  eth->type == clib_host_to_net_u16 (ETHERNET_TYPE_VLAN) ||
	  eth->type == clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD))
	continue;

      do
	{
	  if (count == ARRAY_LEN (iov))
	    break;
	  iov[count].iov_base = vlib_buffer_get_current (b);
	  iov[count].iov_len = b->current_length;
	  length += b->current_length;
	  count++;
	  if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	    break;
	  b = vlib_get_buffer (vm, b->next_buffer);
	}
      while (1);

      if (count && !(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  ssize_t written = writev (pair->fd, iov, count);
	  if (written != length && errno != EAGAIN)
	    {
	      FCP_WARN ("tap %s writev: %s", pair->name, strerror (errno));
	      clib_unix_warning ("freebsd-cp tap writev");
	    }
	}
    }

  vlib_buffer_free (vm, buffers, frame->n_vectors);
  return frame->n_vectors;
}

static clib_error_t *
fcp_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_set_flags (
    vnm, hw_if_index,
    (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
  return 0;
}

VNET_DEVICE_CLASS (fcp_device_class) = {
  .name = "freebsd-cp-tap",
  .format_device_name = format_fcp_name,
  .format_tx_trace = format_fcp_punt_xc_trace,
  .admin_up_down_function = fcp_admin_up_down,
};

static clib_error_t *
fcp_read_ready (clib_file_t *file)
{
  vlib_node_set_interrupt_pending (vlib_get_main (), fcp_input_node.index);
  return 0;
}

VLIB_NODE_FN (fcp_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 received = 0;
  u32 n_trace = vlib_get_trace_count (vm, node);
  fcp_pair_t *pair;

  pool_foreach (pair, fcp_pairs)
    {
      while (received < VLIB_FRAME_SIZE)
	{
	  u32 buffer_index;
	  vlib_buffer_t *b;
	  ethernet_header_t *eth;
	  ssize_t length;

	  if (vlib_buffer_alloc (vm, &buffer_index, 1) != 1)
	    break;
	  b = vlib_get_buffer (vm, buffer_index);
	  length =
	    read (pair->fd, vlib_buffer_get_current (b), vlib_buffer_get_default_data_size (vm));
	  if (length <= 0)
	    {
	      vlib_buffer_free (vm, &buffer_index, 1);
	      break;
	    }
	  b->current_length = length;
	  eth = vlib_buffer_get_current (b);
	  if (length < sizeof (*eth) || eth->type == clib_host_to_net_u16 (ETHERNET_TYPE_VLAN) ||
	      eth->type == clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD))
	    {
	      vlib_buffer_free (vm, &buffer_index, 1);
	      continue;
	    }

	  vnet_buffer (b)->sw_if_index[VLIB_RX] = pair->host_sw_if_index;
	  vnet_buffer (b)->sw_if_index[VLIB_TX] = pair->phy_sw_if_index;
	  if (PREDICT_FALSE (n_trace > 0 && vlib_trace_buffer (vm, node, 0, b, 0)))
	    {
	      vlib_set_trace_count (vm, node, --n_trace);
	      fcp_punt_xc_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	      t->is_xc = true;
	      t->phy_sw_if_index = pair->phy_sw_if_index;
	      t->host_sw_if_index = pair->host_sw_if_index;
	    }
	  vlib_buffer_enqueue_to_single_next (vm, node, &buffer_index, 0, 1);
	  received++;
	}
    }

  return received;
}

VLIB_REGISTER_NODE (fcp_input_node) = {
  .name = "freebsd-cp-input",
  .format_trace = format_fcp_punt_xc_trace,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_next_nodes = 1,
  .next_nodes = { [0] = "interface-output" },
};

#define foreach_fcp_arp                                                                            \
  _ (DROP, "error-drop")                                                                           \
  _ (IO, "interface-output")

typedef enum
{
#define _(sym, str) FCP_ARP_NEXT_##sym,
  foreach_fcp_arp
#undef _
    FCP_ARP_N_NEXT,
} fcp_arp_next_t;

typedef struct
{
  u32 rx_sw_if_index;
  u16 arp_opcode;
} fcp_arp_trace_t;

static u8 *
format_fcp_arp_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  fcp_arp_trace_t *t = va_arg (*args, fcp_arp_trace_t *);

  return format (s, "rx-sw-if-index: %u opcode: %u", t->rx_sw_if_index, t->arp_opcode);
}

VLIB_NODE_FN (fcp_arp_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *buffers = vlib_frame_vector_args (frame);
  u32 copies[VLIB_FRAME_SIZE];
  u32 count = 0;

  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffers[i]);
      u32 pair_index = fcp_pair_index (vnet_buffer (b)->sw_if_index[VLIB_RX]);
      u32 next = FCP_ARP_NEXT_DROP;
      vnet_feature_next (&next, b);
      ethernet_arp_header_t *arp = vlib_buffer_get_current (b);
      if (pair_index != ~0 && arp->opcode == clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply))
	{
	  uword offset = (u8 *) vlib_buffer_get_current (b) - (u8 *) ethernet_buffer_get_header (b);
	  vlib_buffer_advance (b, -(i32) offset);
	  vlib_buffer_t *copy = vlib_buffer_copy (vm, b);
	  vlib_buffer_advance (b, offset);
	  if (copy)
	    {
	      vnet_buffer (copy)->sw_if_index[VLIB_TX] =
		pool_elt_at_index (fcp_pairs, pair_index)->host_sw_if_index;
	      copies[count++] = vlib_get_buffer_index (vm, copy);
	    }
	}
      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  fcp_arp_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	  t->rx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	  t->arp_opcode = clib_net_to_host_u16 (arp->opcode);
	}
      vlib_buffer_enqueue_to_single_next (vm, node, &buffers[i], next, 1);
    }

  if (count)
    vlib_buffer_enqueue_to_single_next (vm, node, copies, FCP_ARP_NEXT_IO, count);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (fcp_arp_node) = {
  .name = "freebsd-cp-arp",
  .format_trace = format_fcp_arp_trace,
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = FCP_ARP_N_NEXT,
  .next_nodes = { [FCP_ARP_NEXT_DROP] = "error-drop", [FCP_ARP_NEXT_IO] = "interface-output" },
};

VNET_FEATURE_INIT (fcp_arp_feature, static) = {
  .arc_name = "arp",
  .node_name = "freebsd-cp-arp",
  .runs_before = VNET_FEATURES ("arp-reply"),
};

#define foreach_fcp_ipsec_punt                                                                     \
  _ (DROP, "error-drop")                                                                           \
  _ (IO, "interface-output")

typedef enum
{
#define _(sym, str) FCP_IPSEC_PUNT_NEXT_##sym,
  foreach_fcp_ipsec_punt
#undef _
    FCP_IPSEC_PUNT_N_NEXT,
} fcp_ipsec_punt_next_t;

VLIB_NODE_FN (fcp_ipsec_punt_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *buffers = vlib_frame_vector_args (frame);

  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffers[i]);
      u32 pair_index = fcp_pair_index (vnet_buffer (b)->sw_if_index[VLIB_RX]);
      u32 next = FCP_IPSEC_PUNT_NEXT_DROP;

      if (pair_index != ~0)
	{
	  fcp_pair_t *pair = pool_elt_at_index (fcp_pairs, pair_index);
	  uword offset = (u8 *) vlib_buffer_get_current (b) - (u8 *) ethernet_buffer_get_header (b);
	  vlib_buffer_advance (b, -(i32) offset);
	  vnet_buffer (b)->sw_if_index[VLIB_TX] = pair->host_sw_if_index;
	  next = FCP_IPSEC_PUNT_NEXT_IO;
	}

      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  fcp_punt_xc_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	  t->is_xc = false;
	  t->phy_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	  t->host_sw_if_index =
	    pair_index == ~0 ? ~0 : pool_elt_at_index (fcp_pairs, pair_index)->host_sw_if_index;
	}

      vlib_buffer_enqueue_to_single_next (vm, node, &buffers[i], next, 1);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (fcp_ipsec_punt_node) = {
  .name = "freebsd-cp-ipsec-punt",
  .format_trace = format_fcp_punt_xc_trace,
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = FCP_IPSEC_PUNT_N_NEXT,
  .next_nodes = { [FCP_IPSEC_PUNT_NEXT_DROP] = "error-drop",
		  [FCP_IPSEC_PUNT_NEXT_IO] = "interface-output" },
};

static clib_error_t *
fcp_punt_init (vlib_main_t *vm)
{
  vlib_punt_hdl_t punt_hdl = vlib_punt_client_register ("freebsd-cp");

  if (vlib_punt_register (punt_hdl, ipsec_punt_reason[IPSEC_PUNT_IP4_SPI_UDP_0],
			  "freebsd-cp-ipsec-punt"))
    return clib_error_return (0, "freebsd-cp IPsec punt registration failed");
  if (vlib_punt_register (punt_hdl, ipsec_punt_reason[IPSEC_PUNT_IP6_SPI_UDP_0],
			  "freebsd-cp-ipsec-punt"))
    {
      vlib_punt_unregister (punt_hdl, ipsec_punt_reason[IPSEC_PUNT_IP4_SPI_UDP_0],
			    "freebsd-cp-ipsec-punt");
      return clib_error_return (0, "freebsd-cp IPsec punt registration failed");
    }

  udp_punt_unknown (vm, 1, 1);
  udp_punt_unknown (vm, 0, 1);
  return NULL;
}

VLIB_INIT_FUNCTION (fcp_punt_init) = {
  .runs_after = VLIB_INITS ("ipsec_punt_init", "udp_init"),
};

static int
fcp_create (vlib_main_t *vm, u32 phy_sw_if_index, const char *name)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw = vnet_get_sw_interface_or_null (vnm, phy_sw_if_index);
  vnet_hw_interface_t *hw;
  struct ifaddrs *addrs, *ifa;
  struct ifreq ifr = {};
  fcp_pair_t *pair;
  u8 mac[6];
  u8 phy_mac[6];
  int fd, sock, rv = VNET_API_ERROR_INVALID_INTERFACE;

  if (!sw || vnet_sw_interface_is_sub (vnm, phy_sw_if_index) ||
      fcp_pair_index (phy_sw_if_index) != ~0 || !name || strncmp (name, "tap", 3) ||
      strlen (name) >= IFNAMSIZ || !if_nametoindex (name))
    {
      FCP_ERR ("pair_create: invalid interface or TAP name '%s'", name ? name : "(null)");
      return rv;
    }
  if (fcp_phy_for_host (if_nametoindex (name)) != ~0)
    {
      FCP_ERR ("pair_create: TAP %s is already paired", name);
      return VNET_API_ERROR_VALUE_EXIST;
    }

  hw = vnet_get_sup_hw_interface (vnm, phy_sw_if_index);
  if (hw->hw_class_index != ethernet_hw_interface_class.index)
    {
      FCP_ERR ("pair_create: %U is not an Ethernet interface", format_vnet_sw_if_index_name, vnm,
	       phy_sw_if_index);
      return rv;
    }

  if (getifaddrs (&addrs) < 0)
    {
      FCP_ERR ("pair_create: getifaddrs: %s", strerror (errno));
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  for (ifa = addrs; ifa; ifa = ifa->ifa_next)
    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK && strcmp (ifa->ifa_name, name) == 0)
      {
	struct sockaddr_dl *dl = (struct sockaddr_dl *) ifa->ifa_addr;
	if (dl->sdl_alen == sizeof (mac))
	  break;
      }
  if (!ifa)
    {
      FCP_ERR ("pair_create: cannot get MAC address for TAP %s", name);
      freeifaddrs (addrs);
      return rv;
    }
  clib_memcpy_fast (mac, LLADDR ((struct sockaddr_dl *) ifa->ifa_addr), sizeof (mac));
  freeifaddrs (addrs);

  char path[sizeof ("/dev/") + IFNAMSIZ];
  snprintf (path, sizeof (path), "/dev/%s", name);
  fd = open (path, O_RDWR | O_NONBLOCK);
  if (fd < 0)
    {
      FCP_ERR ("pair_create: open %s: %s", path, strerror (errno));
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    goto fail;
  strlcpy (ifr.ifr_name, name, sizeof (ifr.ifr_name));
  if (ioctl (sock, SIOCGIFMTU, &ifr) < 0 ||
      ifr.ifr_mtu + sizeof (ethernet_header_t) > vlib_buffer_get_default_data_size (vm))
    {
      close (sock);
      goto fail;
    }
  int original_mtu = ifr.ifr_mtu;
  if (ioctl (sock, SIOCGIFFLAGS, &ifr) < 0)
    {
      close (sock);
      goto fail;
    }
  short original_flags = ifr.ifr_flags;
  if (vec_len (hw->hw_address) != sizeof (mac))
    {
      close (sock);
      goto fail;
    }
  clib_memcpy_fast (phy_mac, hw->hw_address, sizeof (phy_mac));
  ifr.ifr_addr.sa_family = AF_LINK;
  ifr.ifr_addr.sa_len = sizeof (mac);
  clib_memcpy_fast (ifr.ifr_addr.sa_data, phy_mac, sizeof (phy_mac));
  if (ioctl (sock, SIOCSIFLLADDR, &ifr) < 0)
    {
      close (sock);
      goto fail;
    }
  if (ioctl (sock, SIOCGIFFLAGS, &ifr) < 0)
    {
      close (sock);
      goto fail;
    }
  ifr.ifr_flags = (ifr.ifr_flags & ~IFF_UP) | IFF_PROMISC |
		  ((sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? IFF_UP : 0);
  if (ioctl (sock, SIOCSIFFLAGS, &ifr) < 0)
    {
      ifr.ifr_addr.sa_family = AF_LINK;
      ifr.ifr_addr.sa_len = sizeof (mac);
      clib_memcpy_fast (ifr.ifr_addr.sa_data, mac, sizeof (mac));
      ioctl (sock, SIOCSIFLLADDR, &ifr);
      close (sock);
      goto fail;
    }
  close (sock);

  pool_get_zero (fcp_pairs, pair);
  pair->fd = fd;
  clib_memcpy_fast (pair->original_mac, mac, sizeof (mac));
  pair->original_flags = original_flags;
  pair->original_mtu = original_mtu;
  pair->host_if_index = if_nametoindex (name);
  strlcpy (pair->name, name, sizeof (pair->name));
  pair->phy_sw_if_index = phy_sw_if_index;
  vnet_eth_interface_registration_t registration = {
    .dev_class_index = fcp_device_class.index,
    .dev_instance = pair - fcp_pairs,
    .address = phy_mac,
  };
  pair->hw_if_index = vnet_eth_register_interface (vnm, &registration);
  pair->host_sw_if_index = vnet_get_hw_sw_interface (vnm, pair->hw_if_index)->sw_if_index;
  vec_validate_init_empty (fcp_by_phy, phy_sw_if_index, ~0);
  fcp_by_phy[phy_sw_if_index] = pair - fcp_pairs;

  clib_file_t file = {
    .read_function = fcp_read_ready,
    .file_descriptor = fd,
    .private_data = pair - fcp_pairs,
    .description = format (0, "freebsd-cp %s", name),
  };
  pair->file_index = clib_file_add (&file_main, &file);

  fib_route_path_t *paths = NULL;
  fib_route_path_t path_entry = {
    .frp_flags = FIB_ROUTE_PATH_DVR,
    .frp_proto = DPO_PROTO_IP4,
    .frp_sw_if_index = pair->host_sw_if_index,
    .frp_weight = 1,
    .frp_fib_index = ~0,
  };
  vec_add1 (paths, path_entry);
  ip4_punt_redirect_add_paths (phy_sw_if_index, paths);
  paths[0].frp_proto = DPO_PROTO_IP6;
  ip6_punt_redirect_add_paths (phy_sw_if_index, paths);
  vec_free (paths);
  vnet_feature_enable_disable ("arp", "freebsd-cp-arp", phy_sw_if_index, 1, NULL, 0);
  vnet_sw_interface_set_flags (vnm, pair->host_sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  fcp_route_dump (pair->host_if_index);
  fcp_sync_existing_addresses (phy_sw_if_index);
  clib_error_t *sync_error = fcp_sync_link (vnm, phy_sw_if_index);
  if (sync_error)
    {
      FCP_WARN ("create: tap %s link sync failed: %U", pair->name, format_clib_error, sync_error);
      clib_warning ("%U", format_clib_error, sync_error);
      clib_error_free (sync_error);
    }
  FCP_INFO ("pair create: %U <-> %s", format_vnet_sw_if_index_name, vnm, phy_sw_if_index,
	    pair->name);
  return 0;

fail:
  FCP_ERR ("pair_create: setup failed for TAP %s: %s", name, strerror (errno));
  close (fd);
  return VNET_API_ERROR_SYSCALL_ERROR_1;
}

static int
fcp_delete (u32 phy_sw_if_index)
{
  u32 index = fcp_pair_index (phy_sw_if_index);
  if (index == ~0)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  fcp_pair_t *pair = pool_elt_at_index (fcp_pairs, index);
  vnet_main_t *vnm = vnet_get_main ();

  FCP_INFO ("pair delete: %U <-> %s", format_vnet_sw_if_index_name, vnm, phy_sw_if_index,
	    pair->name);
  fcp_route_cleanup (pair->host_if_index);
  fcp_by_phy[phy_sw_if_index] = ~0;
  vnet_feature_enable_disable ("arp", "freebsd-cp-arp", phy_sw_if_index, 0, NULL, 0);
  ip4_punt_redirect_del (phy_sw_if_index);
  ip6_punt_redirect_del (phy_sw_if_index);
  vnet_hw_interface_set_flags (vnm, pair->hw_if_index, 0);
  ethernet_delete_interface (vnm, pair->hw_if_index);
  clib_file_del_by_index (&file_main, pair->file_index);
  int sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock >= 0)
    {
      struct ifreq ifr = {};
      strlcpy (ifr.ifr_name, pair->name, sizeof (ifr.ifr_name));
      ifr.ifr_addr.sa_family = AF_LINK;
      ifr.ifr_addr.sa_len = sizeof (pair->original_mac);
      clib_memcpy_fast (ifr.ifr_addr.sa_data, pair->original_mac, sizeof (pair->original_mac));
      ioctl (sock, SIOCSIFLLADDR, &ifr);
      ifr.ifr_flags = pair->original_flags;
      ioctl (sock, SIOCSIFFLAGS, &ifr);
      ifr.ifr_mtu = pair->original_mtu;
      ioctl (sock, SIOCSIFMTU, &ifr);
      close (sock);
    }
  pool_put (fcp_pairs, pair);
  return 0;
}

static clib_error_t *
fcp_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  if (!is_add && fcp_pair_index (sw_if_index) != ~0)
    fcp_delete (sw_if_index);
  return NULL;
}
VNET_SW_INTERFACE_ADD_DEL_FUNCTION (fcp_interface_add_del);

static clib_error_t *
fcp_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 *name = NULL;
  u8 *ns = NULL;
  int rv;

  if (cmd->path[0] == 's')
    {
      fcp_pair_t *pair;
      pool_foreach (pair, fcp_pairs)
	vlib_cli_output (vm, "%U <-> %s (VPP %U)", format_vnet_sw_if_index_name, vnm,
			 pair->phy_sw_if_index, pair->name, format_vnet_sw_if_index_name, vnm,
			 pair->host_sw_if_index);
      return NULL;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "host-if %s", &name))
	;
      else if (unformat (input, "netns %s", &ns))
	;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	{
	  vec_free (name);
	  vec_free (ns);
	  return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
	}
    }
  if (ns)
    {
      vec_free (name);
      vec_free (ns);
      return clib_error_return (0, "only the default network context is supported");
    }
  if (strcmp (cmd->path, "fcp create") == 0)
    rv = sw_if_index == ~0 || !name ? VNET_API_ERROR_INVALID_VALUE :
				      fcp_create (vm, sw_if_index, (char *) name);
  else
    rv = sw_if_index == ~0 || name ? VNET_API_ERROR_INVALID_VALUE : fcp_delete (sw_if_index);
  vec_free (name);
  return rv ? clib_error_return (0, "freebsd-cp operation failed (%d)", rv) : NULL;
}

VLIB_CLI_COMMAND (fcp_create_command, static) = {
  .path = "fcp create",
  .short_help = "fcp create <interface> host-if <existing-tapN>",
  .function = fcp_cli,
};
VLIB_CLI_COMMAND (fcp_delete_command, static) = {
  .path = "fcp delete",
  .short_help = "fcp delete <interface>",
  .function = fcp_cli,
};
VLIB_CLI_COMMAND (fcp_show_command, static) = {
  .path = "show fcp",
  .short_help = "show fcp",
  .function = fcp_cli,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "FreeBSD control plane interface pairs",
};
