/*
 *------------------------------------------------------------------
 * af_packet.c - linux kernel packet interface
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vnet/devices/af_packet/af_packet.h>

#define foreach_af_packet_tx_func_error               \
_(FRAME_NOT_READY, "tx frame not ready")              \
_(TXRING_EAGAIN,   "tx sendto temporary failure")     \
_(TXRING_FATAL,    "tx sendto fatal failure")         \
_(TXRING_OVERRUN,  "tx ring overrun")

typedef enum
{
#define _(f,s) AF_PACKET_TX_ERROR_##f,
  foreach_af_packet_tx_func_error
#undef _
    AF_PACKET_TX_N_ERROR,
} af_packet_tx_func_error_t;

static char *af_packet_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_af_packet_tx_func_error
#undef _
};


static u8 *
format_af_packet_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif = pool_elt_at_index (apm->interfaces, i);

  s = format (s, "host-%s", apif->host_if_name);
  return s;
}

static u8 *
format_af_packet_device (u8 * s, va_list * args)
{
  s = format (s, "Linux PACKET socket interface");
  return s;
}

static u8 *
format_af_packet_tx_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");
  return s;
}

static uword
af_packet_interface_tx (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  af_packet_main_t *apm = &af_packet_main;
  u32 *buffers = vlib_frame_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_sent = 0;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  af_packet_if_t *apif =
    pool_elt_at_index (apm->interfaces, rd->dev_instance);
  int block = 0;
  u32 block_size = apif->tx_req->tp_block_size;
  u32 frame_size = apif->tx_req->tp_frame_size;
  u32 frame_num = apif->tx_req->tp_frame_nr;
  u8 *block_start = apif->tx_ring + block * block_size;
  u32 tx_frame = apif->next_tx_frame;
  struct tpacket2_hdr *tph;
  u32 frame_not_ready = 0;

  clib_spinlock_lock_if_init (&apif->lockp);

  while (n_left > 0)
    {
      u32 len;
      u32 offset = 0;
      vlib_buffer_t *b0;
      n_left--;
      u32 bi = buffers[0];
      buffers++;

      tph = (struct tpacket2_hdr *) (block_start + tx_frame * frame_size);

      if (PREDICT_FALSE
	  (tph->tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING)))
	{
	  frame_not_ready++;
	  goto next;
	}

      do
	{
	  b0 = vlib_get_buffer (vm, bi);
	  len = b0->current_length;
	  clib_memcpy ((u8 *) tph +
		       TPACKET_ALIGN (sizeof (struct tpacket2_hdr)) + offset,
		       vlib_buffer_get_current (b0), len);
	  offset += len;
	}
      while ((bi =
	      (b0->flags & VLIB_BUFFER_NEXT_PRESENT) ? b0->next_buffer : 0));

      tph->tp_len = tph->tp_snaplen = offset;
      tph->tp_status = TP_STATUS_SEND_REQUEST;
      n_sent++;
    next:
      tx_frame = (tx_frame + 1) % frame_num;

      /* check if we've exhausted the ring */
      if (PREDICT_FALSE (frame_not_ready + n_sent == frame_num))
	break;
    }

  CLIB_MEMORY_BARRIER ();

  if (PREDICT_TRUE (n_sent))
    {
      apif->next_tx_frame = tx_frame;

      if (PREDICT_FALSE (sendto (apif->fd, NULL, 0,
				 MSG_DONTWAIT, NULL, 0) == -1))
	{
	  /* Uh-oh, drop & move on, but count whether it was fatal or not.
	   * Note that we have no reliable way to properly determine the
	   * disposition of the packets we just enqueued for delivery.
	   */
	  vlib_error_count (vm, node->node_index,
			    unix_error_is_fatal (errno) ?
			    AF_PACKET_TX_ERROR_TXRING_FATAL :
			    AF_PACKET_TX_ERROR_TXRING_EAGAIN, n_sent);
	}
    }

  clib_spinlock_unlock_if_init (&apif->lockp);

  if (PREDICT_FALSE (frame_not_ready))
    vlib_error_count (vm, node->node_index,
		      AF_PACKET_TX_ERROR_FRAME_NOT_READY, frame_not_ready);

  if (PREDICT_FALSE (frame_not_ready + n_sent == frame_num))
    vlib_error_count (vm, node->node_index, AF_PACKET_TX_ERROR_TXRING_OVERRUN,
		      n_left);

  vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);
  return frame->n_vectors;
}

static void
af_packet_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				   u32 node_index)
{
  af_packet_main_t *apm = &af_packet_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_packet_if_t *apif =
    pool_elt_at_index (apm->interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      apif->per_interface_next_index = node_index;
      return;
    }

  apif->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), af_packet_input_node.index,
			node_index);
}

static void
af_packet_clear_hw_interface_counters (u32 instance)
{
  /* Nothing for now */
}

static clib_error_t *
af_packet_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				   u32 flags)
{
  af_packet_main_t *apm = &af_packet_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_packet_if_t *apif =
    pool_elt_at_index (apm->interfaces, hw->dev_instance);
  u32 hw_flags;
  int rv, fd = socket (AF_UNIX, SOCK_DGRAM, 0);
  struct ifreq ifr;

  if (0 > fd)
    {
      clib_unix_warning ("af_packet_%s could not open socket",
			 apif->host_if_name);
      return 0;
    }

  /* if interface is a bridge ignore */
  if (apif->host_if_index < 0)
    goto error;			/* no error */

  /* use host_if_index in case host name has changed */
  ifr.ifr_ifindex = apif->host_if_index;
  if ((rv = ioctl (fd, SIOCGIFNAME, &ifr)) < 0)
    {
      clib_unix_warning ("af_packet_%s ioctl could not retrieve eth name",
			 apif->host_if_name);
      goto error;
    }

  apif->is_admin_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if ((rv = ioctl (fd, SIOCGIFFLAGS, &ifr)) < 0)
    {
      clib_unix_warning ("af_packet_%s error: %d",
			 apif->is_admin_up ? "up" : "down", rv);
      goto error;
    }

  if (apif->is_admin_up)
    {
      hw_flags = VNET_HW_INTERFACE_FLAG_LINK_UP;
      ifr.ifr_flags |= IFF_UP;
    }
  else
    {
      hw_flags = 0;
      ifr.ifr_flags &= ~IFF_UP;
    }

  if ((rv = ioctl (fd, SIOCSIFFLAGS, &ifr)) < 0)
    {
      clib_unix_warning ("af_packet_%s error: %d",
			 apif->is_admin_up ? "up" : "down", rv);
      goto error;
    }

  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

error:
  if (0 <= fd)
    close (fd);

  return 0;			/* no error */
}

static clib_error_t *
af_packet_subif_add_del_function (vnet_main_t * vnm,
				  u32 hw_if_index,
				  struct vnet_sw_interface_t *st, int is_add)
{
  /* Nothing for now */
  return 0;
}

static clib_error_t *af_packet_set_mac_address_function
  (struct vnet_hw_interface_t *hi, char *address)
{
  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif =
    pool_elt_at_index (apm->interfaces, hi->dev_instance);
  int rv, fd = socket (AF_UNIX, SOCK_DGRAM, 0);
  struct ifreq ifr;

  if (0 > fd)
    {
      clib_unix_warning ("af_packet_%s could not open socket",
			 apif->host_if_name);
      return 0;
    }

  /* if interface is a bridge ignore */
  if (apif->host_if_index < 0)
    goto error;			/* no error */

  /* use host_if_index in case host name has changed */
  ifr.ifr_ifindex = apif->host_if_index;
  if ((rv = ioctl (fd, SIOCGIFNAME, &ifr)) < 0)
    {
      clib_unix_warning
	("af_packet_%s ioctl could not retrieve eth name, error: %d",
	 apif->host_if_name, rv);
      goto error;
    }

  clib_memcpy (ifr.ifr_hwaddr.sa_data, address, 6);
  ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

  if ((rv = ioctl (fd, SIOCSIFHWADDR, &ifr)) < 0)
    {
      clib_unix_warning ("af_packet_%s ioctl could not set mac, error: %d",
			 apif->host_if_name, rv);
      goto error;
    }

error:

  if (0 <= fd)
    close (fd);

  return 0;			/* no error */
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (af_packet_device_class) = {
  .name = "af-packet",
  .tx_function = af_packet_interface_tx,
  .format_device_name = format_af_packet_device_name,
  .format_device = format_af_packet_device,
  .format_tx_trace = format_af_packet_tx_trace,
  .tx_function_n_errors = AF_PACKET_TX_N_ERROR,
  .tx_function_error_strings = af_packet_tx_func_error_strings,
  .rx_redirect_to_node = af_packet_set_interface_next_node,
  .clear_counters = af_packet_clear_hw_interface_counters,
  .admin_up_down_function = af_packet_interface_admin_up_down,
  .subif_add_del_function = af_packet_subif_add_del_function,
  .mac_addr_change_function = af_packet_set_mac_address_function,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (af_packet_device_class,
				   af_packet_interface_tx)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
