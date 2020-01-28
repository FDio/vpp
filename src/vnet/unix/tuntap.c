/*
 *------------------------------------------------------------------
 * tuntap.c - kernel stack (reverse) punt/inject path
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */
/**
 * @file
 * @brief  TunTap Kernel stack (reverse) punt/inject path.
 *
 * This driver runs in one of two distinct modes:
 * - "punt/inject" mode, where we send pkts not otherwise processed
 * by the forwarding to the Linux kernel stack, and
 *
 * - "normal interface" mode, where we treat the Linux kernel stack
 * as a peer.
 *
 * By default, we select punt/inject mode.
 */

#include <fcntl.h>		/* for open */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>		/* for iovec */
#include <netinet/in.h>

#include <linux/if_arp.h>
#include <linux/if_tun.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>

static vnet_device_class_t tuntap_dev_class;
static vnet_hw_interface_class_t tuntap_interface_class;

static void tuntap_punt_frame (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame);
static void tuntap_nopunt_frame (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame);

typedef struct
{
  u32 sw_if_index;
  u8 is_v6;
  u8 addr[16];
} subif_address_t;

/**
 * @brief TUNTAP per thread struct
 */
typedef struct
{
  /** Vector of VLIB rx buffers to use.  We allocate them in blocks
     of VLIB_FRAME_SIZE (256). */
  u32 *rx_buffers;

  /** Vector of iovecs for readv/writev calls. */
  struct iovec *iovecs;
} tuntap_per_thread_t;

/**
 * @brief TUNTAP node main state
 */
typedef struct
{
  /** per thread variables */
  tuntap_per_thread_t *threads;

  /** File descriptors for /dev/net/tun and provisioning socket. */
  int dev_net_tun_fd, dev_tap_fd;

  /** Create a "tap" [ethernet] encaps device */
  int is_ether;

  /** 1 if a "normal" routed intfc, 0 if a punt/inject interface */

  int have_normal_interface;

  /** tap device destination MAC address. Required, or Linux drops pkts */
  u8 ether_dst_mac[6];

  /** Interface MTU in bytes and # of default sized buffers. */
  u32 mtu_bytes, mtu_buffers;

  /** Linux interface name for tun device. */
  char *tun_name;

  /** Pool of subinterface addresses */
  subif_address_t *subifs;

  /** Hash for subif addresses */
  mhash_t subif_mhash;

  /** Unix file index */
  u32 clib_file_index;

  /** For the "normal" interface, if configured */
  u32 hw_if_index, sw_if_index;

} tuntap_main_t;

static tuntap_main_t tuntap_main = {
  .tun_name = "vnet",

  /** Suitable defaults for an Ethernet-like tun/tap device */
  .mtu_bytes = 4096 + 256,
};

/**
 * @brief tuntap_tx
 * @node tuntap-tx
 *
 * Output node, writes the buffers comprising the incoming frame
 * to the tun/tap device, aka hands them to the Linux kernel stack.
 *
 * @param *vm - vlib_main_t
 * @param *node - vlib_node_runtime_t
 * @param *frame - vlib_frame_t
 *
 * @return rc - uword
 *
 */
static uword
tuntap_tx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *buffers = vlib_frame_vector_args (frame);
  uword n_packets = frame->n_vectors;
  tuntap_main_t *tm = &tuntap_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  u32 n_bytes = 0;
  int i;
  u16 thread_index = vm->thread_index;

  for (i = 0; i < n_packets; i++)
    {
      struct iovec *iov;
      vlib_buffer_t *b;
      uword l;

      b = vlib_get_buffer (vm, buffers[i]);

      if (tm->is_ether && (!tm->have_normal_interface))
	{
	  vlib_buffer_reset (b);
	  clib_memcpy_fast (vlib_buffer_get_current (b), tm->ether_dst_mac,
			    6);
	}

      /* Re-set iovecs if present. */
      if (tm->threads[thread_index].iovecs)
	_vec_len (tm->threads[thread_index].iovecs) = 0;

      /** VLIB buffer chain -> Unix iovec(s). */
      vec_add2 (tm->threads[thread_index].iovecs, iov, 1);
      iov->iov_base = b->data + b->current_data;
      iov->iov_len = l = b->current_length;

      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  do
	    {
	      b = vlib_get_buffer (vm, b->next_buffer);

	      vec_add2 (tm->threads[thread_index].iovecs, iov, 1);

	      iov->iov_base = b->data + b->current_data;
	      iov->iov_len = b->current_length;
	      l += b->current_length;
	    }
	  while (b->flags & VLIB_BUFFER_NEXT_PRESENT);
	}

      if (writev (tm->dev_net_tun_fd, tm->threads[thread_index].iovecs,
		  vec_len (tm->threads[thread_index].iovecs)) < l)
	clib_unix_warning ("writev");

      n_bytes += l;
    }

  /* Update tuntap interface output stats. */
  vlib_increment_combined_counter (im->combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_TX,
				   vm->thread_index,
				   tm->sw_if_index, n_packets, n_bytes);


  /** The normal interface path flattens the buffer chain */
  if (tm->have_normal_interface)
    vlib_buffer_free_no_next (vm, buffers, n_packets);
  else
    vlib_buffer_free (vm, buffers, n_packets);

  return n_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tuntap_tx_node,static) = {
  .function = tuntap_tx,
  .name = "tuntap-tx",
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = 4,
};
/* *INDENT-ON* */

/**
 * @brief TUNTAP receive node
 * @node tuntap-rx
 *
 * @param *vm - vlib_main_t
 * @param *node - vlib_node_runtime_t
 * @param *frame - vlib_frame_t
 *
 * @return rc - uword
 *
 */
static uword
tuntap_rx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  tuntap_main_t *tm = &tuntap_main;
  vlib_buffer_t *b;
  u32 bi;
  const uword buffer_size = vlib_buffer_get_default_data_size (vm);
  u16 thread_index = vm->thread_index;

  /** Make sure we have some RX buffers. */
  {
    uword n_left = vec_len (tm->threads[thread_index].rx_buffers);
    uword n_alloc;

    if (n_left < VLIB_FRAME_SIZE / 2)
      {
	if (!tm->threads[thread_index].rx_buffers)
	  vec_alloc (tm->threads[thread_index].rx_buffers, VLIB_FRAME_SIZE);

	n_alloc =
	  vlib_buffer_alloc (vm,
			     tm->threads[thread_index].rx_buffers + n_left,
			     VLIB_FRAME_SIZE - n_left);
	_vec_len (tm->threads[thread_index].rx_buffers) = n_left + n_alloc;
      }
  }

  /** Allocate RX buffers from end of rx_buffers.
     Turn them into iovecs to pass to readv. */
  {
    uword i_rx = vec_len (tm->threads[thread_index].rx_buffers) - 1;
    vlib_buffer_t *b;
    word i, n_bytes_left, n_bytes_in_packet;

    /** We should have enough buffers left for an MTU sized packet. */
    ASSERT (vec_len (tm->threads[thread_index].rx_buffers) >=
	    tm->mtu_buffers);

    vec_validate (tm->threads[thread_index].iovecs, tm->mtu_buffers - 1);
    for (i = 0; i < tm->mtu_buffers; i++)
      {
	b =
	  vlib_get_buffer (vm,
			   tm->threads[thread_index].rx_buffers[i_rx - i]);
	tm->threads[thread_index].iovecs[i].iov_base = b->data;
	tm->threads[thread_index].iovecs[i].iov_len = buffer_size;
      }

    n_bytes_left =
      readv (tm->dev_net_tun_fd, tm->threads[thread_index].iovecs,
	     tm->mtu_buffers);
    n_bytes_in_packet = n_bytes_left;
    if (n_bytes_left <= 0)
      {
	if (errno != EAGAIN)
	  clib_unix_warning ("readv %d", n_bytes_left);
	return 0;
      }

    bi = tm->threads[thread_index].rx_buffers[i_rx];

    while (1)
      {
	b = vlib_get_buffer (vm, tm->threads[thread_index].rx_buffers[i_rx]);
	b->flags = 0;
	b->current_data = 0;
	b->current_length =
	  n_bytes_left < buffer_size ? n_bytes_left : buffer_size;

	n_bytes_left -= buffer_size;

	if (n_bytes_left <= 0)
	  {
	    break;
	  }

	i_rx--;
	b->flags |= VLIB_BUFFER_NEXT_PRESENT;
	b->next_buffer = tm->threads[thread_index].rx_buffers[i_rx];
      }

    /** Interface counters for tuntap interface. */
    vlib_increment_combined_counter
      (vnet_main.interface_main.combined_sw_if_counters
       + VNET_INTERFACE_COUNTER_RX,
       thread_index, tm->sw_if_index, 1, n_bytes_in_packet);

    _vec_len (tm->threads[thread_index].rx_buffers) = i_rx;
  }

  b = vlib_get_buffer (vm, bi);

  {
    u32 next_index;
    uword n_trace = vlib_get_trace_count (vm, node);

    vnet_buffer (b)->sw_if_index[VLIB_RX] = tm->sw_if_index;
    vnet_buffer (b)->sw_if_index[VLIB_TX] = (u32) ~ 0;

    /*
     * Turn this on if you run into
     * "bad monkey" contexts, and you want to know exactly
     * which nodes they've visited...
     */
    if (VLIB_BUFFER_TRACE_TRAJECTORY)
      b->pre_data[0] = 0;

    b->error = node->errors[0];

    if (tm->is_ether)
      {
	next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      }
    else
      switch (b->data[0] & 0xf0)
	{
	case 0x40:
	  next_index = VNET_DEVICE_INPUT_NEXT_IP4_INPUT;
	  break;
	case 0x60:
	  next_index = VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
	  break;
	default:
	  next_index = VNET_DEVICE_INPUT_NEXT_DROP;
	  break;
	}

    /* The linux kernel couldn't care less if our interface is up */
    if (tm->have_normal_interface)
      {
	vnet_main_t *vnm = vnet_get_main ();
	vnet_sw_interface_t *si;
	si = vnet_get_sw_interface (vnm, tm->sw_if_index);
	if (!(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
	  next_index = VNET_DEVICE_INPUT_NEXT_DROP;
      }

    vnet_feature_start_device_input_x1 (tm->sw_if_index, &next_index, b);

    vlib_set_next_frame_buffer (vm, node, next_index, bi);

    if (PREDICT_FALSE (n_trace > 0 && vlib_trace_buffer (vm, node, next_index, b,	/* follow_chain */
							 1)))
      vlib_set_trace_count (vm, node, n_trace - 1);
  }

  return 1;
}

/**
 * @brief TUNTAP_RX error strings
 */
static char *tuntap_rx_error_strings[] = {
  "unknown packet type",
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tuntap_rx_node,static) = {
  .function = tuntap_rx,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .name = "tuntap-rx",
  .sibling_of = "device-input",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = 4,
  .n_errors = 1,
  .error_strings = tuntap_rx_error_strings,
};
/* *INDENT-ON* */

/**
 * @brief Gets called when file descriptor is ready from epoll.
 *
 * @param *uf - clib_file_t
 *
 * @return error - clib_error_t
 */
static clib_error_t *
tuntap_read_ready (clib_file_t * uf)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_set_interrupt_pending (vm, tuntap_rx_node.index);
  return 0;
}

/**
 * @brief Clean up the tun/tap device
 *
 * @param *vm - vlib_main_t
 *
 * @return error - clib_error_t
 *
 */
static clib_error_t *
tuntap_exit (vlib_main_t * vm)
{
  tuntap_main_t *tm = &tuntap_main;
  struct ifreq ifr;
  int sfd;

  /* Not present. */
  if (!tm->dev_net_tun_fd || tm->dev_net_tun_fd < 0)
    return 0;

  sfd = socket (AF_INET, SOCK_STREAM, 0);
  if (sfd < 0)
    clib_unix_warning ("provisioning socket");

  clib_memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, tm->tun_name, sizeof (ifr.ifr_name) - 1);

  /* get flags, modify to bring down interface... */
  if (ioctl (sfd, SIOCGIFFLAGS, &ifr) < 0)
    clib_unix_warning ("SIOCGIFFLAGS");

  ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);

  if (ioctl (sfd, SIOCSIFFLAGS, &ifr) < 0)
    clib_unix_warning ("SIOCSIFFLAGS");

  /* Turn off persistence */
  if (ioctl (tm->dev_net_tun_fd, TUNSETPERSIST, 0) < 0)
    clib_unix_warning ("TUNSETPERSIST");
  close (tm->dev_tap_fd);
  if (tm->dev_net_tun_fd >= 0)
    close (tm->dev_net_tun_fd);
  if (sfd >= 0)
    close (sfd);

  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (tuntap_exit);

/**
 * @brief CLI function for tun/tap config
 *
 * @param *vm - vlib_main_t
 * @param *input - unformat_input_t
 *
 * @return error - clib_error_t
 *
 */
static clib_error_t *
tuntap_config (vlib_main_t * vm, unformat_input_t * input)
{
  tuntap_main_t *tm = &tuntap_main;
  clib_error_t *error = 0;
  struct ifreq ifr;
  u8 *name;
  int flags = IFF_TUN | IFF_NO_PI;
  int is_enabled = 0, is_ether = 0, have_normal_interface = 0;
  const uword buffer_size = vlib_buffer_get_default_data_size (vm);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "mtu %d", &tm->mtu_bytes))
	;
      else if (unformat (input, "enable"))
	is_enabled = 1;
      else if (unformat (input, "disable"))
	is_enabled = 0;
      else if (unformat (input, "ethernet") || unformat (input, "ether"))
	is_ether = 1;
      else if (unformat (input, "have-normal-interface") ||
	       unformat (input, "have-normal"))
	have_normal_interface = 1;
      else if (unformat (input, "name %s", &name))
	tm->tun_name = (char *) name;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  tm->dev_net_tun_fd = -1;
  tm->dev_tap_fd = -1;

  if (is_enabled == 0)
    return 0;

  if (geteuid ())
    {
      clib_warning ("tuntap disabled: must be superuser");
      return 0;
    }

  tm->is_ether = is_ether;
  tm->have_normal_interface = have_normal_interface;

  if (is_ether)
    flags = IFF_TAP | IFF_NO_PI;

  if ((tm->dev_net_tun_fd = open ("/dev/net/tun", O_RDWR)) < 0)
    {
      error = clib_error_return_unix (0, "open /dev/net/tun");
      goto done;
    }

  clib_memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, tm->tun_name, sizeof (ifr.ifr_name) - 1);
  ifr.ifr_flags = flags;
  if (ioctl (tm->dev_net_tun_fd, TUNSETIFF, (void *) &ifr) < 0)
    {
      error = clib_error_return_unix (0, "ioctl TUNSETIFF");
      goto done;
    }

  /* Make it persistent, at least until we split. */
  if (ioctl (tm->dev_net_tun_fd, TUNSETPERSIST, 1) < 0)
    {
      error = clib_error_return_unix (0, "TUNSETPERSIST");
      goto done;
    }

  /* Open a provisioning socket */
  if ((tm->dev_tap_fd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0)
    {
      error = clib_error_return_unix (0, "socket");
      goto done;
    }

  /* Find the interface index. */
  {
    struct ifreq ifr;
    struct sockaddr_ll sll;

    clib_memset (&ifr, 0, sizeof (ifr));
    strncpy (ifr.ifr_name, tm->tun_name, sizeof (ifr.ifr_name) - 1);
    if (ioctl (tm->dev_tap_fd, SIOCGIFINDEX, &ifr) < 0)
      {
	error = clib_error_return_unix (0, "ioctl SIOCGIFINDEX");
	goto done;
      }

    /* Bind the provisioning socket to the interface. */
    clib_memset (&sll, 0, sizeof (sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons (ETH_P_ALL);

    if (bind (tm->dev_tap_fd, (struct sockaddr *) &sll, sizeof (sll)) < 0)
      {
	error = clib_error_return_unix (0, "bind");
	goto done;
      }
  }

  /* non-blocking I/O on /dev/tapX */
  {
    int one = 1;
    if (ioctl (tm->dev_net_tun_fd, FIONBIO, &one) < 0)
      {
	error = clib_error_return_unix (0, "ioctl FIONBIO");
	goto done;
      }
  }

  tm->mtu_buffers = (tm->mtu_bytes + (buffer_size - 1)) / buffer_size;

  ifr.ifr_mtu = tm->mtu_bytes;
  if (ioctl (tm->dev_tap_fd, SIOCSIFMTU, &ifr) < 0)
    {
      error = clib_error_return_unix (0, "ioctl SIOCSIFMTU");
      goto done;
    }

  /* get flags, modify to bring up interface... */
  if (ioctl (tm->dev_tap_fd, SIOCGIFFLAGS, &ifr) < 0)
    {
      error = clib_error_return_unix (0, "ioctl SIOCGIFFLAGS");
      goto done;
    }

  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

  if (ioctl (tm->dev_tap_fd, SIOCSIFFLAGS, &ifr) < 0)
    {
      error = clib_error_return_unix (0, "ioctl SIOCSIFFLAGS");
      goto done;
    }

  if (is_ether)
    {
      if (ioctl (tm->dev_tap_fd, SIOCGIFHWADDR, &ifr) < 0)
	{
	  error = clib_error_return_unix (0, "ioctl SIOCGIFHWADDR");
	  goto done;
	}
      else
	clib_memcpy_fast (tm->ether_dst_mac, ifr.ifr_hwaddr.sa_data, 6);
    }

  if (have_normal_interface)
    {
      vnet_main_t *vnm = vnet_get_main ();
      error = ethernet_register_interface
	(vnm, tuntap_dev_class.index, 0 /* device instance */ ,
	 tm->ether_dst_mac /* ethernet address */ ,
	 &tm->hw_if_index, 0 /* flag change */ );
      if (error)
	clib_error_report (error);
      tm->sw_if_index = tm->hw_if_index;
      vm->os_punt_frame = tuntap_nopunt_frame;
    }
  else
    {
      vnet_main_t *vnm = vnet_get_main ();
      vnet_hw_interface_t *hi;

      vm->os_punt_frame = tuntap_punt_frame;

      tm->hw_if_index = vnet_register_interface
	(vnm, tuntap_dev_class.index, 0 /* device instance */ ,
	 tuntap_interface_class.index, 0);
      hi = vnet_get_hw_interface (vnm, tm->hw_if_index);
      tm->sw_if_index = hi->sw_if_index;

      /* Interface is always up. */
      vnet_hw_interface_set_flags (vnm, tm->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      vnet_sw_interface_set_flags (vnm, tm->sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
    }

  {
    clib_file_t template = { 0 };
    template.read_function = tuntap_read_ready;
    template.file_descriptor = tm->dev_net_tun_fd;
    template.description = format (0, "vnet tuntap");
    tm->clib_file_index = clib_file_add (&file_main, &template);
  }

done:
  if (error)
    {
      if (tm->dev_net_tun_fd >= 0)
	close (tm->dev_net_tun_fd);
      if (tm->dev_tap_fd >= 0)
	close (tm->dev_tap_fd);
    }

  return error;
}

VLIB_CONFIG_FUNCTION (tuntap_config, "tuntap");

/**
 * @brief Add or Del IP4 address to tun/tap interface
 *
 * @param *im - ip4_main_t
 * @param opaque - uword
 * @param sw_if_index - u32
 * @param *address - ip4_address_t
 * @param is_delete - u32
 *
 */
void
tuntap_ip4_add_del_interface_address (ip4_main_t * im,
				      uword opaque,
				      u32 sw_if_index,
				      ip4_address_t * address,
				      u32 address_length,
				      u32 if_address_index, u32 is_delete)
{
  tuntap_main_t *tm = &tuntap_main;
  struct ifreq ifr;
  subif_address_t subif_addr, *ap;
  uword *p;

  /** Tuntap disabled, or using a "normal" interface. */
  if (tm->have_normal_interface || tm->dev_tap_fd < 0)
    return;

  /* if the address is being applied to an interface that is not in
   * the same table/VRF as this tap, then ignore it.
   * If we don't do this overlapping address spaces in the different tables
   * breaks the linux host's routing tables */
  if (fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
					   sw_if_index) !=
      fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, tm->sw_if_index))
    return;

  /** See if we already know about this subif */
  clib_memset (&subif_addr, 0, sizeof (subif_addr));
  subif_addr.sw_if_index = sw_if_index;
  clib_memcpy_fast (&subif_addr.addr, address, sizeof (*address));

  p = mhash_get (&tm->subif_mhash, &subif_addr);

  if (p)
    ap = pool_elt_at_index (tm->subifs, p[0]);
  else
    {
      pool_get (tm->subifs, ap);
      *ap = subif_addr;
      mhash_set (&tm->subif_mhash, ap, ap - tm->subifs, 0);
    }

  /* Use subif pool index to select alias device. */
  clib_memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name),
	    "%s:%d", tm->tun_name, (int) (ap - tm->subifs));

  /* the tuntap punt/inject is enabled for IPv4 RX so long as
   * any vpp interface has an IPv4 address.
   * this is also ref counted.
   */
  ip4_sw_interface_enable_disable (tm->sw_if_index, !is_delete);

  if (!is_delete)
    {
      struct sockaddr_in *sin;

      sin = (struct sockaddr_in *) &ifr.ifr_addr;

      /* Set ipv4 address, netmask. */
      sin->sin_family = AF_INET;
      clib_memcpy_fast (&sin->sin_addr.s_addr, address, 4);
      if (ioctl (tm->dev_tap_fd, SIOCSIFADDR, &ifr) < 0)
	clib_unix_warning ("ioctl SIOCSIFADDR");

      sin->sin_addr.s_addr = im->fib_masks[address_length];
      if (ioctl (tm->dev_tap_fd, SIOCSIFNETMASK, &ifr) < 0)
	clib_unix_warning ("ioctl SIOCSIFNETMASK");
    }
  else
    {
      mhash_unset (&tm->subif_mhash, &subif_addr, 0 /* old value ptr */ );
      pool_put (tm->subifs, ap);
    }

  /* get flags, modify to bring up interface... */
  if (ioctl (tm->dev_tap_fd, SIOCGIFFLAGS, &ifr) < 0)
    clib_unix_warning ("ioctl SIOCGIFFLAGS");

  if (is_delete)
    ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
  else
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

  if (ioctl (tm->dev_tap_fd, SIOCSIFFLAGS, &ifr) < 0)
    clib_unix_warning ("ioctl SIOCSIFFLAGS");
}

/**
 * @brief workaround for a known include file bug.
 * including @c <linux/ipv6.h> causes multiple definitions if
 * @c <netinet/in.h is also included.
 */
struct in6_ifreq
{
  struct in6_addr ifr6_addr;
  u32 ifr6_prefixlen;
  int ifr6_ifindex;
};

/**
 * @brief Add or Del tun/tap interface address.
 *
 * Both the v6 interface address API and the way ifconfig
 * displays subinterfaces differ from their v4 counterparts.
 * The code given here seems to work but YMMV.
 *
 * @param *im - ip6_main_t
 * @param opaque - uword
 * @param sw_if_index - u32
 * @param *address - ip6_address_t
 * @param address_length - u32
 * @param if_address_index - u32
 * @param is_delete - u32
 */
void
tuntap_ip6_add_del_interface_address (ip6_main_t * im,
				      uword opaque,
				      u32 sw_if_index,
				      ip6_address_t * address,
				      u32 address_length,
				      u32 if_address_index, u32 is_delete)
{
  tuntap_main_t *tm = &tuntap_main;
  struct ifreq ifr;
  struct in6_ifreq ifr6;
  subif_address_t subif_addr, *ap;
  uword *p;

  /* Tuntap disabled, or using a "normal" interface. */
  if (tm->have_normal_interface || tm->dev_tap_fd < 0)
    return;

  /* if the address is being applied to an interface that is not in
   * the same table/VRF as this tap, then ignore it.
   * If we don't do this overlapping address spaces in the different tables
   * breaks the linux host's routing tables */
  if (fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6,
					   sw_if_index) !=
      fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, tm->sw_if_index))
    return;

  /* See if we already know about this subif */
  clib_memset (&subif_addr, 0, sizeof (subif_addr));
  subif_addr.sw_if_index = sw_if_index;
  subif_addr.is_v6 = 1;
  clib_memcpy_fast (&subif_addr.addr, address, sizeof (*address));

  p = mhash_get (&tm->subif_mhash, &subif_addr);

  if (p)
    ap = pool_elt_at_index (tm->subifs, p[0]);
  else
    {
      pool_get (tm->subifs, ap);
      *ap = subif_addr;
      mhash_set (&tm->subif_mhash, ap, ap - tm->subifs, 0);
    }

  /* Use subif pool index to select alias device. */
  clib_memset (&ifr, 0, sizeof (ifr));
  clib_memset (&ifr6, 0, sizeof (ifr6));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name),
	    "%s:%d", tm->tun_name, (int) (ap - tm->subifs));

  /* the tuntap punt/inject is enabled for IPv6 RX so long as
   * any vpp interface has an IPv6 address.
   * this is also ref counted.
   */
  ip6_sw_interface_enable_disable (tm->sw_if_index, !is_delete);

  if (!is_delete)
    {
      int sockfd = socket (AF_INET6, SOCK_STREAM, 0);
      if (sockfd < 0)
	clib_unix_warning ("get ifindex socket");

      if (ioctl (sockfd, SIOGIFINDEX, &ifr) < 0)
	clib_unix_warning ("get ifindex");

      ifr6.ifr6_ifindex = ifr.ifr_ifindex;
      ifr6.ifr6_prefixlen = address_length;
      clib_memcpy_fast (&ifr6.ifr6_addr, address, 16);

      if (ioctl (sockfd, SIOCSIFADDR, &ifr6) < 0)
	clib_unix_warning ("set address");

      if (sockfd >= 0)
	close (sockfd);
    }
  else
    {
      int sockfd = socket (AF_INET6, SOCK_STREAM, 0);
      if (sockfd < 0)
	clib_unix_warning ("get ifindex socket");

      if (ioctl (sockfd, SIOGIFINDEX, &ifr) < 0)
	clib_unix_warning ("get ifindex");

      ifr6.ifr6_ifindex = ifr.ifr_ifindex;
      ifr6.ifr6_prefixlen = address_length;
      clib_memcpy_fast (&ifr6.ifr6_addr, address, 16);

      if (ioctl (sockfd, SIOCDIFADDR, &ifr6) < 0)
	clib_unix_warning ("del address");

      if (sockfd >= 0)
	close (sockfd);

      mhash_unset (&tm->subif_mhash, &subif_addr, 0 /* old value ptr */ );
      pool_put (tm->subifs, ap);
    }
}

/**
 * @brief TX the tun/tap frame
 *
 * @param *vm - vlib_main_t
 * @param *node - vlib_node_runtime_t
 * @param *frame - vlib_frame_t
 *
 */
static void
tuntap_punt_frame (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  tuntap_tx (vm, node, frame);
  vlib_frame_free (vm, node, frame);
}

/**
 * @brief Free the tun/tap frame
 *
 * @param *vm - vlib_main_t
 * @param *node - vlib_node_runtime_t
 * @param *frame - vlib_frame_t
 *
 */
static void
tuntap_nopunt_frame (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *buffers = vlib_frame_vector_args (frame);
  uword n_packets = frame->n_vectors;
  vlib_buffer_free (vm, buffers, n_packets);
  vlib_frame_free (vm, node, frame);
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (tuntap_interface_class,static) = {
  .name = "tuntap",
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

/**
 * @brief Format tun/tap interface name
 *
 * @param *s - u8 - formatter string
 * @param *args - va_list
 *
 * @return *s - u8 - formatted string
 *
 */
static u8 *
format_tuntap_interface_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);

  s = format (s, "tuntap-%d", i);
  return s;
}

/**
 * @brief TX packet out tun/tap
 *
 * @param *vm - vlib_main_t
 * @param *node - vlib_node_runtime_t
 * @param *frame - vlib_frame_t
 *
 * @return n_buffers - uword - Packets transmitted
 *
 */
static uword
tuntap_intfc_tx (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  tuntap_main_t *tm = &tuntap_main;
  u32 *buffers = vlib_frame_vector_args (frame);
  uword n_buffers = frame->n_vectors;

  /* Normal interface transmit happens only on the normal interface... */
  if (tm->have_normal_interface)
    return tuntap_tx (vm, node, frame);

  vlib_buffer_free (vm, buffers, n_buffers);
  return n_buffers;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (tuntap_dev_class,static) = {
  .name = "tuntap",
  .tx_function = tuntap_intfc_tx,
  .format_device_name = format_tuntap_interface_name,
};
/* *INDENT-ON* */

/**
 * @brief tun/tap node init
 *
 * @param *vm - vlib_main_t
 *
 * @return error - clib_error_t
 *
 */
static clib_error_t *
tuntap_init (vlib_main_t * vm)
{
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  ip4_add_del_interface_address_callback_t cb4;
  ip6_add_del_interface_address_callback_t cb6;
  tuntap_main_t *tm = &tuntap_main;
  vlib_thread_main_t *m = vlib_get_thread_main ();

  mhash_init (&tm->subif_mhash, sizeof (u32), sizeof (subif_address_t));

  cb4.function = tuntap_ip4_add_del_interface_address;
  cb4.function_opaque = 0;
  vec_add1 (im4->add_del_interface_address_callbacks, cb4);

  cb6.function = tuntap_ip6_add_del_interface_address;
  cb6.function_opaque = 0;
  vec_add1 (im6->add_del_interface_address_callbacks, cb6);
  vec_validate_aligned (tm->threads, m->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (tuntap_init) =
{
  .runs_after = VLIB_INITS("ip4_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
