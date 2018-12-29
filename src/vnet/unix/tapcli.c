/*
 *------------------------------------------------------------------
 * tapcli.c - dynamic tap interface hookup
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
 * @brief  dynamic tap interface hookup
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

#include <vnet/ethernet/ethernet.h>

#include <vnet/feature/feature.h>
#include <vnet/devices/devices.h>
#include <vnet/unix/tuntap.h>
#include <vnet/unix/tapcli.h>

static vnet_device_class_t tapcli_dev_class;
static vnet_hw_interface_class_t tapcli_interface_class;
static vlib_node_registration_t tapcli_rx_node;

static void tapcli_nopunt_frame (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame);
/**
 * @brief Struct for the tapcli interface
 */
typedef struct
{
  u32 unix_fd;
  u32 clib_file_index;
  u32 provision_fd;
  /** For counters */
  u32 sw_if_index;
  u32 hw_if_index;
  u32 is_promisc;
  struct ifreq ifr;
  u32 per_interface_next_index;
  /** for delete */
  u8 active;
} tapcli_interface_t;

/**
 * @brief Struct for RX trace
 */
typedef struct
{
  u16 sw_if_index;
} tapcli_rx_trace_t;

/**
 * @brief Function to format TAP CLI trace
 *
 * @param *s - u8 - formatting string
 * @param *va - va_list
 *
 * @return *s - u8 - formatted string
 *
 */
u8 *
format_tapcli_rx_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  vnet_main_t *vnm = vnet_get_main ();
  tapcli_rx_trace_t *t = va_arg (*va, tapcli_rx_trace_t *);
  s = format (s, "%U", format_vnet_sw_if_index_name, vnm, t->sw_if_index);
  return s;
}

/**
 * @brief TAPCLI per thread struct
 */
typedef struct
{
  /** Vector of VLIB rx buffers to use.  We allocate them in blocks
     of VLIB_FRAME_SIZE (256). */
  u32 *rx_buffers;

  /** Vector of iovecs for readv/writev calls. */
  struct iovec *iovecs;
} tapcli_per_thread_t;

/**
 * @brief TAPCLI main state struct
 */
typedef struct
{
  /** per thread variables */
  tapcli_per_thread_t *threads;

  /** tap device destination MAC address. Required, or Linux drops pkts */
  u8 ether_dst_mac[6];

  /** Interface MTU in bytes and # of default sized buffers. */
  u32 mtu_bytes, mtu_buffers;

  /** Vector of tap interfaces */
  tapcli_interface_t *tapcli_interfaces;

  /** Vector of deleted tap interfaces */
  u32 *tapcli_inactive_interfaces;

  /** Bitmap of tap interfaces with pending reads */
  uword *pending_read_bitmap;

  /** Hash table to find tapcli interface given hw_if_index */
  uword *tapcli_interface_index_by_sw_if_index;

  /** Hash table to find tapcli interface given unix fd */
  uword *tapcli_interface_index_by_unix_fd;

  /** renumbering table */
  u32 *show_dev_instance_by_real_dev_instance;

  /** 1 => disable CLI */
  int is_disabled;

  /** convenience - vlib_main_t */
  vlib_main_t *vlib_main;
  /** convenience - vnet_main_t */
  vnet_main_t *vnet_main;
} tapcli_main_t;

static tapcli_main_t tapcli_main;

/**
 * @brief tapcli TX node function
 * @node tap-cli-tx
 *
 * Output node, writes the buffers comprising the incoming frame
 * to the tun/tap device, aka hands them to the Linux kernel stack.
 *
 * @param *vm - vlib_main_t
 * @param *node - vlib_node_runtime_t
 * @param *frame - vlib_frame_t
 *
 * @return n_packets - uword
 *
 */
static uword
tapcli_tx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *buffers = vlib_frame_vector_args (frame);
  uword n_packets = frame->n_vectors;
  tapcli_main_t *tm = &tapcli_main;
  tapcli_interface_t *ti;
  int i;
  u16 thread_index = vm->thread_index;

  for (i = 0; i < n_packets; i++)
    {
      struct iovec *iov;
      vlib_buffer_t *b;
      uword l;
      vnet_hw_interface_t *hw;
      uword *p;
      u32 tx_sw_if_index;

      b = vlib_get_buffer (vm, buffers[i]);

      tx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
      if (tx_sw_if_index == (u32) ~ 0)
	tx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

      ASSERT (tx_sw_if_index != (u32) ~ 0);

      /* Use the sup intfc to finesse vlan subifs */
      hw = vnet_get_sup_hw_interface (tm->vnet_main, tx_sw_if_index);
      tx_sw_if_index = hw->sw_if_index;

      p = hash_get (tm->tapcli_interface_index_by_sw_if_index,
		    tx_sw_if_index);
      if (p == 0)
	{
	  clib_warning ("sw_if_index %d unknown", tx_sw_if_index);
	  /* $$$ leak, but this should never happen... */
	  continue;
	}
      else
	ti = vec_elt_at_index (tm->tapcli_interfaces, p[0]);

      /* Re-set iovecs if present. */
      if (tm->threads[thread_index].iovecs)
	_vec_len (tm->threads[thread_index].iovecs) = 0;

      /* VLIB buffer chain -> Unix iovec(s). */
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

      if (writev (ti->unix_fd, tm->threads[thread_index].iovecs,
		  vec_len (tm->threads[thread_index].iovecs)) < l)
	clib_unix_warning ("writev");
    }

  vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);

  return n_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tapcli_tx_node,static) = {
  .function = tapcli_tx,
  .name = "tapcli-tx",
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = 4,
};
/* *INDENT-ON* */

/**
 * @brief Dispatch tapcli RX node function for node tap_cli_rx
 *
 *
 * @param *vm - vlib_main_t
 * @param *node - vlib_node_runtime_t
 * @param *ti - tapcli_interface_t
 *
 * @return n_packets - uword
 *
 */
static uword
tapcli_rx_iface (vlib_main_t * vm,
		 vlib_node_runtime_t * node, tapcli_interface_t * ti)
{
  tapcli_main_t *tm = &tapcli_main;
  const uword buffer_size = VLIB_BUFFER_DATA_SIZE;
  u32 n_trace = vlib_get_trace_count (vm, node);
  u8 set_trace = 0;
  u16 thread_index = vm->thread_index;
  vnet_main_t *vnm;
  vnet_sw_interface_t *si;
  u8 admin_down;
  u32 next = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u32 n_left_to_next, next_index;
  u32 *to_next;

  vnm = vnet_get_main ();
  si = vnet_get_sw_interface (vnm, ti->sw_if_index);
  admin_down = !(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

  while (n_left_to_next)
    {				// Fill at most one vector
      vlib_buffer_t *b_first, *b, *prev;
      u32 bi_first, bi;
      word n_bytes_in_packet;
      int j, n_bytes_left;

      if (PREDICT_FALSE (vec_len (tm->threads[thread_index].rx_buffers) <
			 tm->mtu_buffers))
	{
	  uword len = vec_len (tm->threads[thread_index].rx_buffers);
	  _vec_len (tm->threads[thread_index].rx_buffers) +=
	    vlib_buffer_alloc (vm, &tm->threads[thread_index].rx_buffers[len],
			       VLIB_FRAME_SIZE - len);
	  if (PREDICT_FALSE
	      (vec_len (tm->threads[thread_index].rx_buffers) <
	       tm->mtu_buffers))
	    {
	      vlib_node_increment_counter (vm, tapcli_rx_node.index,
					   TAPCLI_ERROR_BUFFER_ALLOC,
					   tm->mtu_buffers -
					   vec_len (tm->threads
						    [thread_index].
						    rx_buffers));
	      break;
	    }
	}

      uword i_rx = vec_len (tm->threads[thread_index].rx_buffers) - 1;

      /* Allocate RX buffers from end of rx_buffers.
         Turn them into iovecs to pass to readv. */
      vec_validate (tm->threads[thread_index].iovecs, tm->mtu_buffers - 1);
      for (j = 0; j < tm->mtu_buffers; j++)
	{
	  b =
	    vlib_get_buffer (vm,
			     tm->threads[thread_index].rx_buffers[i_rx - j]);
	  tm->threads[thread_index].iovecs[j].iov_base = b->data;
	  tm->threads[thread_index].iovecs[j].iov_len = buffer_size;
	}

      n_bytes_left = readv (ti->unix_fd, tm->threads[thread_index].iovecs,
			    tm->mtu_buffers);
      n_bytes_in_packet = n_bytes_left;
      if (n_bytes_left <= 0)
	{
	  if (errno != EAGAIN)
	    {
	      vlib_node_increment_counter (vm, tapcli_rx_node.index,
					   TAPCLI_ERROR_READ, 1);
	    }
	  break;
	}

      bi_first = tm->threads[thread_index].rx_buffers[i_rx];
      b = b_first = vlib_get_buffer (vm,
				     tm->threads[thread_index].
				     rx_buffers[i_rx]);
      prev = NULL;

      while (1)
	{
	  b->current_length =
	    n_bytes_left < buffer_size ? n_bytes_left : buffer_size;
	  n_bytes_left -= buffer_size;

	  if (prev)
	    {
	      prev->next_buffer = bi;
	      prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
	    }
	  prev = b;

	  /* last segment */
	  if (n_bytes_left <= 0)
	    break;

	  i_rx--;
	  bi = tm->threads[thread_index].rx_buffers[i_rx];
	  b = vlib_get_buffer (vm, bi);
	}

      _vec_len (tm->threads[thread_index].rx_buffers) = i_rx;

      b_first->total_length_not_including_first_buffer =
	(n_bytes_in_packet >
	 buffer_size) ? n_bytes_in_packet - buffer_size : 0;
      b_first->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b_first);

      vnet_buffer (b_first)->sw_if_index[VLIB_RX] = ti->sw_if_index;
      vnet_buffer (b_first)->sw_if_index[VLIB_TX] = (u32) ~ 0;

      b_first->error = node->errors[TAPCLI_ERROR_NONE];
      next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      next_index = (ti->per_interface_next_index != ~0) ?
	ti->per_interface_next_index : next_index;
      next_index = admin_down ? VNET_DEVICE_INPUT_NEXT_DROP : next_index;

      to_next[0] = bi_first;
      to_next++;
      n_left_to_next--;

      vnet_feature_start_device_input_x1 (ti->sw_if_index, &next_index,
					  b_first);

      vlib_validate_buffer_enqueue_x1 (vm, node, next,
				       to_next, n_left_to_next,
				       bi_first, next_index);

      /* Interface counters for tapcli interface. */
      if (PREDICT_TRUE (!admin_down))
	{
	  vlib_increment_combined_counter (vnet_main.interface_main.
					   combined_sw_if_counters +
					   VNET_INTERFACE_COUNTER_RX,
					   thread_index, ti->sw_if_index, 1,
					   n_bytes_in_packet);

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      vlib_trace_buffer (vm, node, next_index,
				 b_first, /* follow_chain */ 1);
	      n_trace--;
	      set_trace = 1;
	      tapcli_rx_trace_t *t0 =
		vlib_add_trace (vm, node, b_first, sizeof (*t0));
	      t0->sw_if_index = si->sw_if_index;
	    }
	}
    }
  vlib_put_next_frame (vm, node, next, n_left_to_next);
  if (set_trace)
    vlib_set_trace_count (vm, node, n_trace);
  return VLIB_FRAME_SIZE - n_left_to_next;
}

/**
 * @brief tapcli RX node function
 * @node tap-cli-rx
 *
 * Input node from the Kernel tun/tap device
 *
 * @param *vm - vlib_main_t
 * @param *node - vlib_node_runtime_t
 * @param *frame - vlib_frame_t
 *
 * @return n_packets - uword
 *
 */
static uword
tapcli_rx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  tapcli_main_t *tm = &tapcli_main;
  static u32 *ready_interface_indices;
  tapcli_interface_t *ti;
  int i;
  u32 total_count = 0;

  vec_reset_length (ready_interface_indices);
  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, tm->pending_read_bitmap,
  ({
    vec_add1 (ready_interface_indices, i);
  }));
  /* *INDENT-ON* */

  if (vec_len (ready_interface_indices) == 0)
    return 0;

  for (i = 0; i < vec_len (ready_interface_indices); i++)
    {
      tm->pending_read_bitmap =
	clib_bitmap_set (tm->pending_read_bitmap,
			 ready_interface_indices[i], 0);

      ti =
	vec_elt_at_index (tm->tapcli_interfaces, ready_interface_indices[i]);
      total_count += tapcli_rx_iface (vm, node, ti);
    }
  return total_count;		//This might return more than 256.
}

/** TAPCLI error strings */
static char *tapcli_rx_error_strings[] = {
#define _(sym,string) string,
  foreach_tapcli_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tapcli_rx_node, static) = {
  .function = tapcli_rx,
  .name = "tapcli-rx",
  .sibling_of = "device-input",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = 4,
  .n_errors = TAPCLI_N_ERROR,
  .error_strings = tapcli_rx_error_strings,
  .format_trace = format_tapcli_rx_trace,
};
/* *INDENT-ON* */


/**
 * @brief Gets called when file descriptor is ready from epoll.
 *
 * @param *uf - clib_file_t
 *
 * @return error - clib_error_t
 *
 */
static clib_error_t *
tapcli_read_ready (clib_file_t * uf)
{
  vlib_main_t *vm = vlib_get_main ();
  tapcli_main_t *tm = &tapcli_main;
  uword *p;

  /** Schedule the rx node */
  vlib_node_set_interrupt_pending (vm, tapcli_rx_node.index);

  p = hash_get (tm->tapcli_interface_index_by_unix_fd, uf->file_descriptor);

  /** Mark the specific tap interface ready-to-read */
  if (p)
    tm->pending_read_bitmap = clib_bitmap_set (tm->pending_read_bitmap,
					       p[0], 1);
  else
    clib_warning ("fd %d not in hash table", uf->file_descriptor);

  return 0;
}

/**
 * @brief CLI function for TAPCLI configuration
 *
 * @param *vm - vlib_main_t
 * @param *input - unformat_input_t
 *
 * @return error - clib_error_t
 *
 */
static clib_error_t *
tapcli_config (vlib_main_t * vm, unformat_input_t * input)
{
  tapcli_main_t *tm = &tapcli_main;
  const uword buffer_size = VLIB_BUFFER_DATA_SIZE;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "mtu %d", &tm->mtu_bytes))
	;
      else if (unformat (input, "disable"))
	tm->is_disabled = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (tm->is_disabled)
    return 0;

  if (geteuid ())
    {
      clib_warning ("tapcli disabled: must be superuser");
      tm->is_disabled = 1;
      return 0;
    }

  tm->mtu_buffers = (tm->mtu_bytes + (buffer_size - 1)) / buffer_size;

  return 0;
}

/**
 * @brief Renumber TAPCLI interface
 *
 * @param *hi - vnet_hw_interface_t
 * @param new_dev_instance - u32
 *
 * @return rc - int
 *
 */
static int
tap_name_renumber (vnet_hw_interface_t * hi, u32 new_dev_instance)
{
  tapcli_main_t *tm = &tapcli_main;

  vec_validate_init_empty (tm->show_dev_instance_by_real_dev_instance,
			   hi->dev_instance, ~0);

  tm->show_dev_instance_by_real_dev_instance[hi->dev_instance] =
    new_dev_instance;

  return 0;
}

VLIB_CONFIG_FUNCTION (tapcli_config, "tapcli");

/**
 * @brief Free "no punt" frame
 *
 * @param *vm - vlib_main_t
 * @param *node - vlib_node_runtime_t
 * @param *frame - vlib_frame_t
 *
 */
static void
tapcli_nopunt_frame (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *buffers = vlib_frame_vector_args (frame);
  uword n_packets = frame->n_vectors;
  vlib_buffer_free (vm, buffers, n_packets);
  vlib_frame_free (vm, node, frame);
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (tapcli_interface_class,static) = {
  .name = "tapcli",
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

/**
 * @brief Formatter for TAPCLI interface name
 *
 * @param *s - formatter string
 * @param *args - va_list
 *
 * @return *s - formatted string
 *
 */
static u8 *
format_tapcli_interface_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u32 show_dev_instance = ~0;
  tapcli_main_t *tm = &tapcli_main;

  if (i < vec_len (tm->show_dev_instance_by_real_dev_instance))
    show_dev_instance = tm->show_dev_instance_by_real_dev_instance[i];

  if (show_dev_instance != ~0)
    i = show_dev_instance;

  s = format (s, "tapcli-%d", i);
  return s;
}

/**
 * @brief Modify interface flags for TAPCLI interface
 *
 * @param *vnm - vnet_main_t
 * @param *hw - vnet_hw_interface_t
 * @param flags - u32
 *
 * @return rc - u32
 *
 */
static u32
tapcli_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  tapcli_main_t *tm = &tapcli_main;
  tapcli_interface_t *ti;

  ti = vec_elt_at_index (tm->tapcli_interfaces, hw->dev_instance);

  if (flags & ETHERNET_INTERFACE_FLAG_MTU)
    {
      const uword buffer_size = VLIB_BUFFER_DATA_SIZE;
      tm->mtu_bytes = hw->max_packet_bytes;
      tm->mtu_buffers = (tm->mtu_bytes + (buffer_size - 1)) / buffer_size;
    }
  else
    {
      struct ifreq ifr;
      u32 want_promisc;

      memcpy (&ifr, &ti->ifr, sizeof (ifr));

      /* get flags, modify to bring up interface... */
      if (ioctl (ti->provision_fd, SIOCGIFFLAGS, &ifr) < 0)
	{
	  clib_unix_warning ("Couldn't get interface flags for %s", hw->name);
	  return 0;
	}

      want_promisc = (flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL) != 0;

      if (want_promisc == ti->is_promisc)
	return 0;

      if (flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL)
	ifr.ifr_flags |= IFF_PROMISC;
      else
	ifr.ifr_flags &= ~(IFF_PROMISC);

      /* get flags, modify to bring up interface... */
      if (ioctl (ti->provision_fd, SIOCSIFFLAGS, &ifr) < 0)
	{
	  clib_unix_warning ("Couldn't set interface flags for %s", hw->name);
	  return 0;
	}

      ti->is_promisc = want_promisc;
    }

  return 0;
}

/**
 * @brief Setting the TAP interface's next processing node
 *
 * @param *vnm - vnet_main_t
 * @param hw_if_index - u32
 * @param node_index - u32
 *
 */
static void
tapcli_set_interface_next_node (vnet_main_t * vnm,
				u32 hw_if_index, u32 node_index)
{
  tapcli_main_t *tm = &tapcli_main;
  tapcli_interface_t *ti;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);

  ti = vec_elt_at_index (tm->tapcli_interfaces, hw->dev_instance);

  /** Shut off redirection */
  if (node_index == ~0)
    {
      ti->per_interface_next_index = node_index;
      return;
    }

  ti->per_interface_next_index =
    vlib_node_add_next (tm->vlib_main, tapcli_rx_node.index, node_index);
}

/**
 * @brief Set link_state == admin_state otherwise things like ip6 neighbor discovery breaks
 *
 * @param *vnm - vnet_main_t
 * @param hw_if_index - u32
 * @param flags - u32
 *
 * @return error - clib_error_t
 */
static clib_error_t *
tapcli_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  uword is_admin_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  u32 hw_flags;

  if (is_admin_up)
    hw_flags = VNET_HW_INTERFACE_FLAG_LINK_UP;
  else
    hw_flags = 0;

  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (tapcli_dev_class,static) = {
  .name = "tapcli",
  .tx_function = tapcli_tx,
  .format_device_name = format_tapcli_interface_name,
  .rx_redirect_to_node = tapcli_set_interface_next_node,
  .name_renumber = tap_name_renumber,
  .admin_up_down_function = tapcli_interface_admin_up_down,
};
/* *INDENT-ON* */

/**
 * @brief Dump TAP interfaces
 *
 * @param **out_tapids - tapcli_interface_details_t
 *
 * @return rc - int
 *
 */
int
vnet_tap_dump_ifs (tapcli_interface_details_t ** out_tapids)
{
  tapcli_main_t *tm = &tapcli_main;
  tapcli_interface_t *ti;

  tapcli_interface_details_t *r_tapids = NULL;
  tapcli_interface_details_t *tapid = NULL;

  vec_foreach (ti, tm->tapcli_interfaces)
  {
    if (!ti->active)
      continue;
    vec_add2 (r_tapids, tapid, 1);
    tapid->sw_if_index = ti->sw_if_index;
    strncpy ((char *) tapid->dev_name, ti->ifr.ifr_name,
	     sizeof (ti->ifr.ifr_name) - 1);
  }

  *out_tapids = r_tapids;

  return 0;
}

/**
 * @brief Get tap interface from inactive interfaces or create new
 *
 * @return interface - tapcli_interface_t
 *
 */
static tapcli_interface_t *
tapcli_get_new_tapif ()
{
  tapcli_main_t *tm = &tapcli_main;
  tapcli_interface_t *ti = NULL;

  int inactive_cnt = vec_len (tm->tapcli_inactive_interfaces);
  // if there are any inactive ifaces
  if (inactive_cnt > 0)
    {
      // take last
      u32 ti_idx = tm->tapcli_inactive_interfaces[inactive_cnt - 1];
      if (vec_len (tm->tapcli_interfaces) > ti_idx)
	{
	  ti = vec_elt_at_index (tm->tapcli_interfaces, ti_idx);
	  clib_warning ("reusing tap interface");
	}
      // "remove" from inactive list
      _vec_len (tm->tapcli_inactive_interfaces) -= 1;
    }

  // ti was not retrieved from inactive ifaces - create new
  if (!ti)
    vec_add2 (tm->tapcli_interfaces, ti, 1);

  return ti;
}

typedef struct
{
  ip6_address_t addr;
  u32 mask_width;
  unsigned int ifindex;
} ip6_ifreq_t;

/**
 * @brief Connect a TAP interface
 *
 * @param vm - vlib_main_t
 * @param ap - vnet_tap_connect_args_t
 *
 * @return rc - int
 *
 */
int
vnet_tap_connect (vlib_main_t * vm, vnet_tap_connect_args_t * ap)
{
  tapcli_main_t *tm = &tapcli_main;
  tapcli_interface_t *ti = NULL;
  struct ifreq ifr;
  int flags;
  int dev_net_tun_fd;
  int dev_tap_fd = -1;
  clib_error_t *error;
  u8 hwaddr[6];
  int rv = 0;

  if (tm->is_disabled)
    {
      return VNET_API_ERROR_FEATURE_DISABLED;
    }

  flags = IFF_TAP | IFF_NO_PI;

  if ((dev_net_tun_fd = open ("/dev/net/tun", O_RDWR)) < 0)
    return VNET_API_ERROR_SYSCALL_ERROR_1;

  clib_memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, (char *) ap->intfc_name, sizeof (ifr.ifr_name) - 1);
  ifr.ifr_flags = flags;
  if (ioctl (dev_net_tun_fd, TUNSETIFF, (void *) &ifr) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      goto error;
    }

  /* Open a provisioning socket */
  if ((dev_tap_fd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_3;
      goto error;
    }

  /* Find the interface index. */
  {
    struct ifreq ifr;
    struct sockaddr_ll sll;

    clib_memset (&ifr, 0, sizeof (ifr));
    strncpy (ifr.ifr_name, (char *) ap->intfc_name,
	     sizeof (ifr.ifr_name) - 1);
    if (ioctl (dev_tap_fd, SIOCGIFINDEX, &ifr) < 0)
      {
	rv = VNET_API_ERROR_SYSCALL_ERROR_4;
	goto error;
      }

    /* Bind the provisioning socket to the interface. */
    clib_memset (&sll, 0, sizeof (sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons (ETH_P_ALL);

    if (bind (dev_tap_fd, (struct sockaddr *) &sll, sizeof (sll)) < 0)
      {
	rv = VNET_API_ERROR_SYSCALL_ERROR_5;
	goto error;
      }
  }

  /* non-blocking I/O on /dev/tapX */
  {
    int one = 1;
    if (ioctl (dev_net_tun_fd, FIONBIO, &one) < 0)
      {
	rv = VNET_API_ERROR_SYSCALL_ERROR_6;
	goto error;
      }
  }
  ifr.ifr_mtu = tm->mtu_bytes;
  if (ioctl (dev_tap_fd, SIOCSIFMTU, &ifr) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_7;
      goto error;
    }

  /* get flags, modify to bring up interface... */
  if (ioctl (dev_tap_fd, SIOCGIFFLAGS, &ifr) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_8;
      goto error;
    }

  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

  if (ioctl (dev_tap_fd, SIOCSIFFLAGS, &ifr) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_9;
      goto error;
    }

  if (ap->ip4_address_set)
    {
      struct sockaddr_in sin;
      /* ip4: mask defaults to /24 */
      u32 mask = clib_host_to_net_u32 (0xFFFFFF00);

      clib_memset (&sin, 0, sizeof (sin));
      sin.sin_family = AF_INET;
      /* sin.sin_port = 0; */
      sin.sin_addr.s_addr = ap->ip4_address->as_u32;
      memcpy (&ifr.ifr_ifru.ifru_addr, &sin, sizeof (sin));

      if (ioctl (dev_tap_fd, SIOCSIFADDR, &ifr) < 0)
	{
	  rv = VNET_API_ERROR_SYSCALL_ERROR_10;
	  goto error;
	}

      if (ap->ip4_mask_width > 0 && ap->ip4_mask_width < 33)
	{
	  mask = ~0;
	  mask <<= (32 - ap->ip4_mask_width);
	}

      mask = clib_host_to_net_u32 (mask);
      sin.sin_family = AF_INET;
      sin.sin_port = 0;
      sin.sin_addr.s_addr = mask;
      memcpy (&ifr.ifr_ifru.ifru_addr, &sin, sizeof (sin));

      if (ioctl (dev_tap_fd, SIOCSIFNETMASK, &ifr) < 0)
	{
	  rv = VNET_API_ERROR_SYSCALL_ERROR_10;
	  goto error;
	}
    }

  if (ap->ip6_address_set)
    {
      struct ifreq ifr2;
      ip6_ifreq_t ifr6;
      int sockfd6;

      sockfd6 = socket (AF_INET6, SOCK_DGRAM, IPPROTO_IP);
      if (sockfd6 < 0)
	{
	  rv = VNET_API_ERROR_SYSCALL_ERROR_10;
	  goto error;
	}

      clib_memset (&ifr2, 0, sizeof (ifr));
      strncpy (ifr2.ifr_name, (char *) ap->intfc_name,
	       sizeof (ifr2.ifr_name) - 1);
      if (ioctl (sockfd6, SIOCGIFINDEX, &ifr2) < 0)
	{
	  close (sockfd6);
	  rv = VNET_API_ERROR_SYSCALL_ERROR_4;
	  goto error;
	}

      memcpy (&ifr6.addr, ap->ip6_address, sizeof (ip6_address_t));
      ifr6.mask_width = ap->ip6_mask_width;
      ifr6.ifindex = ifr2.ifr_ifindex;

      if (ioctl (sockfd6, SIOCSIFADDR, &ifr6) < 0)
	{
	  close (sockfd6);
	  clib_unix_warning ("ifr6");
	  rv = VNET_API_ERROR_SYSCALL_ERROR_10;
	  goto error;
	}
      close (sockfd6);
    }

  ti = tapcli_get_new_tapif ();
  ti->per_interface_next_index = ~0;

  if (ap->hwaddr_arg != 0)
    clib_memcpy (hwaddr, ap->hwaddr_arg, 6);
  else
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (hwaddr + 2, &rnd, sizeof (rnd));
      hwaddr[0] = 2;
      hwaddr[1] = 0xfe;
    }

  error = ethernet_register_interface
    (tm->vnet_main,
     tapcli_dev_class.index,
     ti - tm->tapcli_interfaces /* device instance */ ,
     hwaddr /* ethernet address */ ,
     &ti->hw_if_index, tapcli_flag_change);

  if (error)
    {
      clib_error_report (error);
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto error;
    }

  {
    clib_file_t template = { 0 };
    template.read_function = tapcli_read_ready;
    template.file_descriptor = dev_net_tun_fd;
    ti->clib_file_index = clib_file_add (&file_main, &template);
    ti->unix_fd = dev_net_tun_fd;
    ti->provision_fd = dev_tap_fd;
    clib_memcpy (&ti->ifr, &ifr, sizeof (ifr));
  }

  {
    vnet_hw_interface_t *hw;
    hw = vnet_get_hw_interface (tm->vnet_main, ti->hw_if_index);
    hw->min_supported_packet_bytes = TAP_MTU_MIN;
    hw->max_supported_packet_bytes = TAP_MTU_MAX;
    vnet_sw_interface_set_mtu (tm->vnet_main, hw->sw_if_index, 9000);
    ti->sw_if_index = hw->sw_if_index;
    if (ap->sw_if_indexp)
      *(ap->sw_if_indexp) = hw->sw_if_index;
  }

  ti->active = 1;

  hash_set (tm->tapcli_interface_index_by_sw_if_index, ti->sw_if_index,
	    ti - tm->tapcli_interfaces);

  hash_set (tm->tapcli_interface_index_by_unix_fd, ti->unix_fd,
	    ti - tm->tapcli_interfaces);

  return rv;

error:
  close (dev_net_tun_fd);
  if (dev_tap_fd >= 0)
    close (dev_tap_fd);

  return rv;
}

/**
 * @brief Renumber a TAP interface
 *
 * @param *vm - vlib_main_t
 * @param *intfc_name - u8
 * @param *hwaddr_arg - u8
 * @param *sw_if_indexp - u32
 * @param renumber - u8
 * @param custom_dev_instance - u32
 *
 * @return rc - int
 *
 */
int
vnet_tap_connect_renumber (vlib_main_t * vm, vnet_tap_connect_args_t * ap)
{
  int rv = vnet_tap_connect (vm, ap);

  if (!rv && ap->renumber)
    vnet_interface_name_renumber (*(ap->sw_if_indexp),
				  ap->custom_dev_instance);

  return rv;
}

/**
 * @brief Disconnect TAP CLI interface
 *
 * @param *ti - tapcli_interface_t
 *
 * @return rc - int
 *
 */
static int
tapcli_tap_disconnect (tapcli_interface_t * ti)
{
  int rv = 0;
  vnet_main_t *vnm = vnet_get_main ();
  tapcli_main_t *tm = &tapcli_main;
  u32 sw_if_index = ti->sw_if_index;

  // bring interface down
  vnet_sw_interface_set_flags (vnm, sw_if_index, 0);

  if (ti->clib_file_index != ~0)
    {
      clib_file_del (&file_main, file_main.file_pool + ti->clib_file_index);
      ti->clib_file_index = ~0;
    }
  else
    close (ti->unix_fd);

  hash_unset (tm->tapcli_interface_index_by_unix_fd, ti->unix_fd);
  hash_unset (tm->tapcli_interface_index_by_sw_if_index, ti->sw_if_index);
  close (ti->provision_fd);
  ti->unix_fd = -1;
  ti->provision_fd = -1;

  return rv;
}

/**
 * @brief Delete TAP interface
 *
 * @param *vm - vlib_main_t
 * @param sw_if_index - u32
 *
 * @return rc - int
 *
 */
int
vnet_tap_delete (vlib_main_t * vm, u32 sw_if_index)
{
  int rv = 0;
  tapcli_main_t *tm = &tapcli_main;
  tapcli_interface_t *ti;
  uword *p = NULL;

  p = hash_get (tm->tapcli_interface_index_by_sw_if_index, sw_if_index);
  if (p == 0)
    {
      clib_warning ("sw_if_index %d unknown", sw_if_index);
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }
  ti = vec_elt_at_index (tm->tapcli_interfaces, p[0]);

  // inactive
  ti->active = 0;
  tapcli_tap_disconnect (ti);
  // add to inactive list
  vec_add1 (tm->tapcli_inactive_interfaces, ti - tm->tapcli_interfaces);

  // reset renumbered iface
  if (p[0] < vec_len (tm->show_dev_instance_by_real_dev_instance))
    tm->show_dev_instance_by_real_dev_instance[p[0]] = ~0;

  ethernet_delete_interface (tm->vnet_main, ti->hw_if_index);
  return rv;
}

/**
 * @brief CLI function to delete TAP interface
 *
 * @param *vm - vlib_main_t
 * @param *input - unformat_input_t
 * @param *cmd - vlib_cli_command_t
 *
 * @return error - clib_error_t
 *
 */
static clib_error_t *
tap_delete_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  tapcli_main_t *tm = &tapcli_main;
  u32 sw_if_index = ~0;

  if (tm->is_disabled)
    {
      return clib_error_return (0, "device disabled...");
    }

  if (unformat (input, "%U", unformat_vnet_sw_interface, tm->vnet_main,
		&sw_if_index))
    ;
  else
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);


  int rc = vnet_tap_delete (vm, sw_if_index);

  if (!rc)
    {
      vlib_cli_output (vm, "Deleted.");
    }
  else
    {
      vlib_cli_output (vm, "Error during deletion of tap interface. (rc: %d)",
		       rc);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tap_delete_command, static) = {
    .path = "tap delete",
    .short_help = "tap delete <vpp-tap-intfc-name>",
    .function = tap_delete_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief Modifies tap interface - can result in new interface being created
 *
 * @param *vm - vlib_main_t
 * @param orig_sw_if_index - u32
 * @param *intfc_name - u8
 * @param *hwaddr_arg - u8
 * @param *sw_if_indexp - u32
 * @param renumber - u8
 * @param custom_dev_instance - u32
 *
 * @return rc - int
 *
 */
int
vnet_tap_modify (vlib_main_t * vm, vnet_tap_connect_args_t * ap)
{
  int rv = vnet_tap_delete (vm, ap->orig_sw_if_index);

  if (rv)
    return rv;

  rv = vnet_tap_connect_renumber (vm, ap);

  return rv;
}

/**
 * @brief CLI function to modify TAP interface
 *
 * @param *vm - vlib_main_t
 * @param *input - unformat_input_t
 * @param *cmd - vlib_cli_command_t
 *
 * @return error - clib_error_t
 *
 */
static clib_error_t *
tap_modify_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *intfc_name;
  tapcli_main_t *tm = &tapcli_main;
  u32 sw_if_index = ~0;
  u32 new_sw_if_index = ~0;
  int user_hwaddr = 0;
  u8 hwaddr[6];
  vnet_tap_connect_args_t _a, *ap = &_a;

  if (tm->is_disabled)
    {
      return clib_error_return (0, "device disabled...");
    }

  if (unformat (input, "%U", unformat_vnet_sw_interface, tm->vnet_main,
		&sw_if_index))
    ;
  else
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  if (unformat (input, "%s", &intfc_name))
    ;
  else
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  if (unformat (input, "hwaddr %U", unformat_ethernet_address, &hwaddr))
    user_hwaddr = 1;


  clib_memset (ap, 0, sizeof (*ap));
  ap->orig_sw_if_index = sw_if_index;
  ap->intfc_name = intfc_name;
  ap->sw_if_indexp = &new_sw_if_index;
  if (user_hwaddr)
    ap->hwaddr_arg = hwaddr;

  int rc = vnet_tap_modify (vm, ap);

  if (!rc)
    {
      vlib_cli_output (vm, "Modified %U for Linux tap '%s'",
		       format_vnet_sw_if_index_name, tm->vnet_main,
		       *(ap->sw_if_indexp), ap->intfc_name);
    }
  else
    {
      vlib_cli_output (vm,
		       "Error during modification of tap interface. (rc: %d)",
		       rc);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tap_modify_command, static) = {
    .path = "tap modify",
    .short_help = "tap modify <vpp-tap-intfc-name> <linux-intfc-name> [hwaddr <addr>]",
    .function = tap_modify_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief CLI function to connect TAP interface
 *
 * @param *vm - vlib_main_t
 * @param *input - unformat_input_t
 * @param *cmd - vlib_cli_command_t
 *
 * @return error - clib_error_t
 *
 */
static clib_error_t *
tap_connect_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *intfc_name = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_tap_connect_args_t _a, *ap = &_a;
  tapcli_main_t *tm = &tapcli_main;
  u8 hwaddr[6];
  u8 *hwaddr_arg = 0;
  u32 sw_if_index;
  ip4_address_t ip4_address;
  int ip4_address_set = 0;
  ip6_address_t ip6_address;
  int ip6_address_set = 0;
  u32 ip4_mask_width = 0;
  u32 ip6_mask_width = 0;
  clib_error_t *error = NULL;

  if (tm->is_disabled)
    return clib_error_return (0, "device disabled...");

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "hwaddr %U", unformat_ethernet_address,
		    &hwaddr))
	hwaddr_arg = hwaddr;

      /* It is here for backward compatibility */
      else if (unformat (line_input, "hwaddr random"))
	;

      else if (unformat (line_input, "address %U/%d",
			 unformat_ip4_address, &ip4_address, &ip4_mask_width))
	ip4_address_set = 1;

      else if (unformat (line_input, "address %U/%d",
			 unformat_ip6_address, &ip6_address, &ip6_mask_width))
	ip6_address_set = 1;

      else if (unformat (line_input, "%s", &intfc_name))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (intfc_name == 0)
    {
      error = clib_error_return (0, "interface name must be specified");
      goto done;
    }

  clib_memset (ap, 0, sizeof (*ap));

  ap->intfc_name = intfc_name;
  ap->hwaddr_arg = hwaddr_arg;
  if (ip4_address_set)
    {
      ap->ip4_address = &ip4_address;
      ap->ip4_mask_width = ip4_mask_width;
      ap->ip4_address_set = 1;
    }
  if (ip6_address_set)
    {
      ap->ip6_address = &ip6_address;
      ap->ip6_mask_width = ip6_mask_width;
      ap->ip6_address_set = 1;
    }

  ap->sw_if_indexp = &sw_if_index;

  int rv = vnet_tap_connect (vm, ap);

  switch (rv)
    {
    case VNET_API_ERROR_SYSCALL_ERROR_1:
      error = clib_error_return (0, "Couldn't open /dev/net/tun");
      goto done;

    case VNET_API_ERROR_SYSCALL_ERROR_2:
      error =
	clib_error_return (0, "Error setting flags on '%s'", intfc_name);
      goto done;

    case VNET_API_ERROR_SYSCALL_ERROR_3:
      error = clib_error_return (0, "Couldn't open provisioning socket");
      goto done;

    case VNET_API_ERROR_SYSCALL_ERROR_4:
      error = clib_error_return (0, "Couldn't get if_index");
      goto done;

    case VNET_API_ERROR_SYSCALL_ERROR_5:
      error = clib_error_return (0, "Couldn't bind provisioning socket");
      goto done;

    case VNET_API_ERROR_SYSCALL_ERROR_6:
      error = clib_error_return (0, "Couldn't set device non-blocking flag");
      goto done;

    case VNET_API_ERROR_SYSCALL_ERROR_7:
      error = clib_error_return (0, "Couldn't set device MTU");
      goto done;

    case VNET_API_ERROR_SYSCALL_ERROR_8:
      error = clib_error_return (0, "Couldn't get interface flags");
      goto done;

    case VNET_API_ERROR_SYSCALL_ERROR_9:
      error = clib_error_return (0, "Couldn't set intfc admin state up");
      goto done;

    case VNET_API_ERROR_SYSCALL_ERROR_10:
      error = clib_error_return (0, "Couldn't set intfc address/mask");
      goto done;

    case VNET_API_ERROR_INVALID_REGISTRATION:
      error = clib_error_return (0, "Invalid registration");
      goto done;

    case 0:
      break;

    default:
      error = clib_error_return (0, "Unknown error: %d", rv);
      goto done;
    }

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		   vnet_get_main (), sw_if_index);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tap_connect_command, static) = {
    .path = "tap connect",
    .short_help =
        "tap connect <intfc-name> [address <ip-addr>/mw] [hwaddr <addr>]",
    .function = tap_connect_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief TAPCLI main init
 *
 * @param *vm - vlib_main_t
 *
 * @return error - clib_error_t
 *
 */
clib_error_t *
tapcli_init (vlib_main_t * vm)
{
  tapcli_main_t *tm = &tapcli_main;
  vlib_thread_main_t *m = vlib_get_thread_main ();
  tapcli_per_thread_t *thread;

  tm->vlib_main = vm;
  tm->vnet_main = vnet_get_main ();
  tm->mtu_bytes = TAP_MTU_DEFAULT;
  tm->tapcli_interface_index_by_sw_if_index = hash_create (0, sizeof (uword));
  tm->tapcli_interface_index_by_unix_fd = hash_create (0, sizeof (uword));
  vm->os_punt_frame = tapcli_nopunt_frame;
  vec_validate_aligned (tm->threads, m->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_foreach (thread, tm->threads)
  {
    thread->iovecs = 0;
    thread->rx_buffers = 0;
    vec_alloc (thread->rx_buffers, VLIB_FRAME_SIZE);
    vec_reset_length (thread->rx_buffers);
  }

  return 0;
}

VLIB_INIT_FUNCTION (tapcli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
