/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/linux/sysfs.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <af_xdp/af_xdp.h>
#include <af_xdp/xsk_common.h>

#define foreach_af_xdp_tx_func_error              \
_(_EAGAIN,         "sendto EAGAIN")               \
_(_EBUSY,          "sendto EBUSY")                \
_(_FATAL,          "sendto fatal failure")        \
_(_TXRING_OVERRUN, "TX ring overrun")             \
_(_MPOOL_EXHAUS,   "mempool exhausted")

typedef enum
{
#define _(f,s) AF_XDP_TX_ERROR_##f,
  foreach_af_xdp_tx_func_error
#undef _
    AF_XDP_TX_N_ERROR,
} af_xdp_tx_func_error_t;

static char *af_xdp_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_af_xdp_tx_func_error
#undef _
};

static_always_inline af_xdp_tx_func_error_t
sendto_tx_error (word _errno)
{
  switch (_errno)
    {
    case EAGAIN:
      return AF_XDP_TX_ERROR__EAGAIN;
    case EBUSY:
      return AF_XDP_TX_ERROR__EBUSY;
    }

  return AF_XDP_TX_ERROR__FATAL;
}

af_xdp_main_t af_xdp_main;

static struct xsk_umem_info *
xsk_umem_init (u64 size)
{
  af_xdp_main_t *am = &af_xdp_main;
  struct xsk_umem_info *umem;
  struct xsk_umem_config cfg = {
    .fill_size = PROD_RING_NUM_FRAMES,
    .comp_size = CONS_RING_NUM_FRAMES,
    .frame_size = FRAME_SIZE,
    .frame_headroom = FRAME_HEADROOM,
  };
  void *buff;
  int rv;

  umem = calloc (1, sizeof (*umem));
  if (!umem)
    {
      vlib_log_err (am->log_class, "not enough memory");
      return NULL;
    }

  buff = clib_mem_alloc_aligned (size, clib_mem_get_page_size ());

  rv = xsk_umem__create (&umem->umem, buff, size, &umem->fq, &umem->cq, &cfg);
  if (rv)
    {
      clib_mem_free (buff);
      free (umem);
      vlib_log_err (am->log_class, "failed to create umem, errno: "
		    "%d \"%s\"", -rv, strerror (-rv));
      return NULL;
    }

  umem->buffer = buff;
  return umem;
}

static void
xsk_umem_destroy (struct xsk_umem_info **umem)
{
  af_xdp_main_t *am = &af_xdp_main;
  int rv;

  if (NULL == umem || NULL == *umem)
    return;

  struct xsk_umem_info *u = *umem;

  if ((rv = xsk_umem__delete (u->umem)))
    vlib_log_err (am->log_class, "failed to delete umem, errno: "
		  "%d \"%s\"", -rv, strerror (-rv));

  clib_mem_free (u->buffer);
  free (u);
  *umem = NULL;
}

static int
xskmap_fd_by_prog_fd (int prog_fd)
{
  af_xdp_main_t *am = &af_xdp_main;
  u32 i, *map_ids, num_maps, prog_len = sizeof (struct bpf_prog_info);
  u32 map_len = sizeof (struct bpf_map_info);
  struct bpf_prog_info prog_info = { };
  struct bpf_map_info map_info;
  int fd, rv;
  int xskmap_fd = -ENOENT;

  rv = bpf_obj_get_info_by_fd (prog_fd, &prog_info, &prog_len);
  if (rv)
    {
      vlib_log_err (am->log_class, "failed to get bpf prog info by fd");
      return xskmap_fd;
    }

  num_maps = prog_info.nr_map_ids;

  map_ids = calloc (prog_info.nr_map_ids, sizeof (*map_ids));
  if (!map_ids)
    {
      vlib_log_err (am->log_class, "not enough memory");
      return -ENOMEM;
    }

  memset (&prog_info, 0, prog_len);
  prog_info.nr_map_ids = num_maps;
  prog_info.map_ids = (u64) map_ids;

  rv = bpf_obj_get_info_by_fd (prog_fd, &prog_info, &prog_len);
  if (rv)
    {
      vlib_log_err (am->log_class, "failed to get map ids");
      goto end;
    }

  for (i = 0; i < prog_info.nr_map_ids; i++)
    {
      fd = bpf_map_get_fd_by_id (map_ids[i]);
      if (fd < 0)
	continue;

      rv = bpf_obj_get_info_by_fd (fd, &map_info, &map_len);
      if (rv)
	{
	  close (fd);
	  continue;
	}

      if (!strcmp (map_info.name, XSKMAP_NAME))
	{
	  xskmap_fd = fd;
	  break;
	}

      close (fd);
    }

end:
  free (map_ids);
  return xskmap_fd;
}

static struct xsk_socket_info *
xsk_socket_init (const af_xdp_create_if_args_t * args, u32 ifindex)
{
  af_xdp_main_t *am = &af_xdp_main;
  struct xsk_socket_config cfg;
  struct xsk_socket_info *xsk;
  struct xsk_umem_info *umem;
  u32 libbpf_flags = 0;
  u32 idx;
  u32 i;
  int rv;

  xsk = calloc (1, sizeof (*xsk));
  if (!xsk)
    {
      vlib_log_err (am->log_class, "not enough memory");
      goto error_calloc;
    }

  if (!(umem = xsk_umem_init (UMEM_NUM_FRAMES * FRAME_SIZE)))
    goto error_calloc;

  xsk->xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

  if (args->custom_xdp)
    libbpf_flags |= XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

  if (args->force_zerocopy_bind)
    xsk->bind_flags |= XDP_ZEROCOPY;
  else if (args->force_copy_bind)
    xsk->bind_flags |= XDP_COPY;

  xsk->umem = umem;
  xsk->xskmap_key = args->key;
  xsk->queue_id = args->queue_id;

  cfg.rx_size = CONS_RING_NUM_FRAMES;
  cfg.tx_size = PROD_RING_NUM_FRAMES;
  cfg.libbpf_flags = libbpf_flags;
  cfg.xdp_flags = xsk->xdp_flags;
  cfg.bind_flags = xsk->bind_flags;
  rv = xsk_socket__create (&xsk->xsk, (const char *) args->ifname,
			   args->queue_id, umem->umem, &xsk->rx, &xsk->tx,
			   &cfg);
  if (rv)
    {
      vlib_log_err (am->log_class, "failed to create xdp socket, errno: "
		    "%d \"%s\"", -rv, strerror (-rv));
      goto error_socket_create;
    }
  xsk->sfd = xsk_socket__fd (xsk->xsk);

  rv = bpf_get_link_xdp_id (ifindex, &xsk->prog_id, xsk->xdp_flags);
  if (rv)
    {
      vlib_log_err (am->log_class, "bpf_get_link_xdp_id failed, errno: "
		    "%d \"%s\"", -rv, strerror (-rv));
      goto error_get_id;
    }
  else if (!xsk->prog_id && args->custom_xdp)
    {
      vlib_log_err (am->log_class, "no xdp program is loaded on interface "
		    "\"%s\"", args->ifname);
      goto error_get_id;
    }

  xsk->prog_fd = bpf_prog_get_fd_by_id (xsk->prog_id);
  if ((xsk->xskmap_fd = xskmap_fd_by_prog_fd (xsk->prog_fd)) < 0)
    goto error_get_id;

  if (args->custom_xdp)
    if (bpf_map_update_elem (xsk->xskmap_fd, &args->key, &xsk->sfd, 0))
      {
	vlib_log_err (am->log_class, "failed to update xsks_map element");
	goto error_get_id;
      }

  /* Initialize umem frame allocation */
  for (i = 0; i < UMEM_RX_NUM_FRAMES; i++)
    xsk->umem_rx_frame_addr[i] = i * FRAME_SIZE;
  xsk->umem_rx_frame_free = UMEM_RX_NUM_FRAMES;

  for (i = 0; i < UMEM_TX_NUM_FRAMES; i++)
    xsk->umem_tx_frame_addr[i] = (UMEM_RX_NUM_FRAMES + i) * FRAME_SIZE;
  xsk->umem_tx_frame_free = UMEM_TX_NUM_FRAMES;

  rv = xsk_ring_prod__reserve (&xsk->umem->fq, PROD_RING_NUM_FRAMES, &idx);
  if (rv != PROD_RING_NUM_FRAMES)
    {
      vlib_log_err (am->log_class, "failed to reserve fill queue, errno: "
		    "%d \"%s\"", -rv, strerror (-rv));
      goto error_get_id;
    }

  for (i = 0; i < PROD_RING_NUM_FRAMES; i++)
    *xsk_ring_prod__fill_addr (&xsk->umem->fq, idx++) =
      xsk_alloc_umem_rx_frame (xsk);

  xsk_ring_prod__submit (&xsk->umem->fq, PROD_RING_NUM_FRAMES);

  return xsk;

error_get_id:
  xsk_socket__delete (xsk->xsk);
error_socket_create:
  xsk_umem_destroy (&umem);
  free (xsk);
error_calloc:
  return NULL;
}

static void
xsk_socket_destroy (struct xsk_socket_info **xsk)
{
  if (NULL == xsk || NULL == *xsk)
    return;

  struct xsk_socket_info *s = *xsk;

  xsk_socket__delete (s->xsk);
  xsk_umem_destroy (&s->umem);
  free (s);
  *xsk = NULL;
}

static u32
af_xdp_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  clib_error_t *error;
  u8 *s;
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);

  if (flags & ETHERNET_INTERFACE_FLAG_MTU)
    {
      s = format (0, "/sys/class/net/%s/mtu%c", ad->ifname, 0);

      error = clib_sysfs_write ((char *) s, "%d", hw->max_packet_bytes);
      vec_free (s);

      if (error)
	{
	  vlib_log_err (am->log_class,
			"sysfs write failed to change MTU: %U",
			format_clib_error, error);
	  clib_error_free (error);
	  return VNET_API_ERROR_SYSCALL_ERROR_1;
	}
    }

  return 0;
}

static void
remove_xdp_program (const u8 * ifname, u32 ifindex, u32 xdp_flags,
		    u32 prog_id)
{
  af_xdp_main_t *am = &af_xdp_main;
  u32 curr_prog_id = 0;
  int rv;

  if (bpf_get_link_xdp_id (ifindex, &curr_prog_id, xdp_flags))
    {
      vlib_log_err (am->log_class, "failed to get current xdp program id");
      return;
    }

  if (prog_id == curr_prog_id)
    {
      if ((rv = bpf_set_link_xdp_fd (ifindex, -1, xdp_flags)) < 0)
	vlib_log_err (am->log_class, "failed to set link fd, "
		      "errno: %d \"%s\"", -rv, strerror (-rv));
    }
  else if (!curr_prog_id)
    vlib_log_err (am->log_class, "couldn't find a prog id on interface "
		  "\"%s\"", ifname);
  else
    vlib_log_info (am->log_class, "xdp program on interface \"%s\" changed, "
		   "not removing", ifname);
}

void
af_xdp_delete_if (vlib_main_t * vm, af_xdp_device_t * ad)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_xdp_main_t *am = &af_xdp_main;

  u32 xdp_flags = ad->xsk->xdp_flags;
  u32 prog_id = ad->xsk->prog_id;
  int xskmap_fd = ad->xsk->xskmap_fd;
  u32 xskmap_key = ad->xsk->xskmap_key;

  if (ad->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, ad->hw_if_index, 0);
      ethernet_delete_interface (vnm, ad->hw_if_index);
    }

  if (ad->clib_file_index != ~0)
    {
      clib_file_del (&file_main, file_main.file_pool + ad->clib_file_index);
      ad->clib_file_index = ~0;
    }

  xsk_socket_destroy (&ad->xsk);

  /* if attached to custom loaded xdp program, we usually don't want to
   * remove it, just delete the socket fd from xskmap (by the key)
   */
  if (ad->custom_xdp)
    {
      if (bpf_map_delete_elem (xskmap_fd, &xskmap_key))
	vlib_log_err (am->log_class,
		      "failed to delete xdp socket from xskmap");
    }
  else
    remove_xdp_program (ad->ifname, ad->ifindex, xdp_flags, prog_id);

  vec_free (ad->ifname);
  ad->ifname = NULL;
  clib_error_free (ad->error);
  clib_memset (ad, 0, sizeof (*ad));
  pool_put (am->devices, ad);
}

static clib_error_t *
af_xdp_fd_read_ready (clib_file_t * uf)
{
  af_xdp_main_t *am = &af_xdp_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 idx = uf->private_data;
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, idx);

  am->pending_input_bitmap =
    clib_bitmap_set (am->pending_input_bitmap, idx, 1);

  /* Schedule the rx node */
  vnet_device_input_set_interrupt_pending (vnm, ad->hw_if_index,
					   ad->xsk->queue_id);

  return 0;
}

clib_error_t *
get_hwaddr (const u8 * ifname, u8 hwaddr[6])
{
  clib_error_t *error = 0;

  int fd;
  struct ifreq ifr;

  memset (&ifr, 0, sizeof (ifr));

  fd = socket (AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy (ifr.ifr_name, (const char *) ifname, IFNAMSIZ - 1);

  if (0 == ioctl (fd, SIOCGIFHWADDR, &ifr))
    clib_memcpy (hwaddr, ifr.ifr_hwaddr.sa_data, 6);
  else
    error = clib_error_return (error, "failed to get hwaddr of '%s'", ifname);

  close (fd);

  return error;
}

void
af_xdp_create_if (vlib_main_t * vm, af_xdp_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad;
  clib_error_t *error = 0;
  u32 ifindex;
  struct xsk_socket_info *xsk;
  clib_file_t cfile = { 0 };
  struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

  if (setrlimit (RLIMIT_MEMLOCK, &r))
    {
      vlib_log_err (am->log_class, "setrlimit failed, errno: %d \"%s\"",
		    errno, strerror (errno));
      return;
    }
  if ((ifindex = if_nametoindex ((char *) args->ifname)) == 0)
    {
      args->rv = VNET_API_ERROR_NO_MATCHING_INTERFACE;
      args->error = clib_error_return (error, "failed to get ifindex of '%s'",
				       args->ifname);
      return;
    }
  if (!(xsk = xsk_socket_init (args, ifindex)))
    return;

  pool_get (am->devices, ad);

  ad->xsk = xsk;
  ad->ifname = vec_dup (args->ifname);
  ad->ifindex = ifindex;
  ad->custom_xdp = args->custom_xdp;
  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = ~0;

  cfile.read_function = af_xdp_fd_read_ready;
  cfile.file_descriptor = xsk_socket__fd (ad->xsk->xsk);
  cfile.private_data = ad->dev_instance;
  cfile.flags = UNIX_FILE_EVENT_EDGE_TRIGGERED;
  cfile.description = format (0, "%U", format_af_xdp_device_name,
			      ad->dev_instance);
  ad->clib_file_index = clib_file_add (&file_main, &cfile);

  error = get_hwaddr (args->ifname, ad->hwaddr);
  if (error)
    goto error;

  error = ethernet_register_interface (vnm, af_xdp_device_class.index,
				       ad->dev_instance, ad->hwaddr,
				       &ad->hw_if_index, af_xdp_flag_change);

  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, ad->hw_if_index);
  args->sw_if_index = ad->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, ad->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, ad->hw_if_index,
				    af_xdp_input_node.index);

  vnet_hw_interface_assign_rx_thread (vnm, ad->hw_if_index, args->queue_id,
				      ~0 /* any cpu */ );
  vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

  vnet_hw_interface_set_rx_mode (vnm, ad->hw_if_index, args->queue_id,
				 VNET_HW_INTERFACE_RX_MODE_INTERRUPT);

  return;

error:
  af_xdp_delete_if (vm, ad);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  vlib_log_err (am->log_class, "%U", format_clib_error, args->error);
}

static clib_error_t *
af_xdp_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = vec_elt_at_index (am->devices, hw->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (ad->flags & AF_XDP_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      ad->flags |= AF_XDP_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ad->flags &= ~AF_XDP_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static void
af_xdp_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				u32 node_index)
{
  af_xdp_main_t *am = &af_xdp_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ad->per_interface_next_index = node_index;
      return;
    }

  ad->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), af_xdp_input_node.index,
			node_index);
}

static_always_inline int
kick_tx (struct xsk_socket_info *xsk)
{
  int rv, retries;

  /* In SKB_MODE packet transmission is synchronous, and the kernel
   * transmits only 16 packets for a single sendmsg syscall.
   * So, we have to kick the kernel (n_packets / 16) times to be sure that
   * all packets are transmitted.
   */
#define DIV_BY_16(n) ((n) >> 4)
#define DIV_KERN_TX_BATCH_SIZE(n) DIV_BY_16(n)

  retries = DIV_KERN_TX_BATCH_SIZE (xsk->outstanding_tx);

kick_again:
  /* This causes system call into kernel's xsk_sendmsg, and
   * xsk_generic_xmit (skb mode) or xsk_async_xmit (driver mode).
   */
  rv = sendto (xsk_socket__fd (xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

  if (rv < 0)
    {
      if (errno == EAGAIN && retries--)
	goto kick_again;

      rv = errno;
    }

  /* No error, or too many retries on EAGAIN. */
  return rv;

#undef DIV_BY_16
#undef DIV_KERN_TX_BATCH_SIZE
}

static_always_inline void
drain_cq (struct xsk_socket_info *xsk)
{
  u32 completed;
  u32 idx_cq;
  u32 i;

  if (!xsk->outstanding_tx)
    return;

  /* Collect/free completed TX buffers */
  completed = xsk_ring_cons__peek (&xsk->umem->cq,
				   CONS_RING_NUM_FRAMES, &idx_cq);

  if (completed)
    {
      for (i = 0; i < completed; i++)
	xsk_free_umem_tx_frame (xsk,
				*xsk_ring_cons__comp_addr (&xsk->umem->cq,
							   idx_cq++));

      xsk_ring_cons__release (&xsk->umem->cq, completed);
      xsk->outstanding_tx -= completed;
    }
}

static_always_inline u32
txq_enq (vlib_main_t * vm, struct xsk_socket_info *xsk, vlib_frame_t * frame)
{
  u32 n_vectors = frame->n_vectors;
  u32 *buffers = vlib_frame_vector_args (frame);
  u64 addr;
  u32 len, buf_len, bi;
  vlib_buffer_t *b0;
  u32 n_sent = 0;
  u32 tx_idx = xsk->reserved_tx_idx;
  u32 tx_frames = xsk->reserved_tx_frames;
  u8 *pkt;

  while (n_vectors-- && tx_frames--)
    {
      len = 0;
      bi = buffers[0];

      addr = xsk_alloc_umem_tx_frame (xsk);
      pkt = xsk_umem__get_data (xsk->umem->buffer, addr);

      do
	{
	  b0 = vlib_get_buffer (vm, bi);
	  buf_len = b0->current_length;
	  clib_memcpy_fast (pkt + len, vlib_buffer_get_current (b0), buf_len);
	  len += buf_len;
	}
      while ((bi = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) ?
	      b0->next_buffer : 0));

      xsk_ring_prod__tx_desc (&xsk->tx, tx_idx)->addr = addr;
      xsk_ring_prod__tx_desc (&xsk->tx, tx_idx)->len = len;

      buffers++;
      n_sent++;
      tx_idx++;
    }

  xsk->reserved_tx_idx = tx_idx;
  xsk->reserved_tx_frames -= n_sent;

  return n_sent;
}

VNET_DEVICE_CLASS_TX_FN (af_xdp_device_class) (vlib_main_t * vm,
					       vlib_node_runtime_t * node,
					       vlib_frame_t * frame)
{
  af_xdp_main_t *am = &af_xdp_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, rd->dev_instance);
  struct xsk_socket_info *xsk = ad->xsk;

  u32 n_sent;
  int _errno;
  u32 batch_size;
  u32 tx_idx;
  u32 free_frames;

  drain_cq (xsk);

  free_frames = xsk_umem_free_tx_frames (xsk);
  if (PREDICT_TRUE (free_frames > frame->n_vectors))
    batch_size = frame->n_vectors;
  else
    {
      batch_size = free_frames;
      vlib_error_count (vm, node->node_index, AF_XDP_TX_ERROR__MPOOL_EXHAUS,
			frame->n_vectors - free_frames);
    }

  if (PREDICT_FALSE (!xsk->reserved_tx_frames))
    xsk->reserved_tx_frames =
      xsk_ring_prod__reserve (&xsk->tx, batch_size, &xsk->reserved_tx_idx);
  else
    xsk->reserved_tx_frames +=
      xsk_ring_prod__reserve (&xsk->tx, batch_size - xsk->reserved_tx_frames,
			      &tx_idx);

  if (PREDICT_FALSE (xsk->reserved_tx_frames != batch_size))
    vlib_error_count (vm, node->node_index, AF_XDP_TX_ERROR__TXRING_OVERRUN,
		      batch_size - xsk->reserved_tx_frames);

  n_sent = txq_enq (vm, xsk, frame);

  xsk_ring_prod__submit (&xsk->tx, n_sent);

  xsk->outstanding_tx += n_sent;

  if (PREDICT_FALSE (_errno = kick_tx (xsk)))
    vlib_error_count (vm, node->node_index, sendto_tx_error (_errno), 1);

  vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);

  return n_sent;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (af_xdp_device_class,) =
{
  .name = "AF_XDP interface",
  .format_device = format_af_xdp_device,
  .format_device_name = format_af_xdp_device_name,
  .admin_up_down_function = af_xdp_interface_admin_up_down,
  .rx_redirect_to_node = af_xdp_set_interface_next_node,
  .tx_function_n_errors = AF_XDP_TX_N_ERROR,
  .tx_function_error_strings = af_xdp_tx_func_error_strings,
};
/* *INDENT-ON* */

clib_error_t *
af_xdp_init (vlib_main_t * vm)
{
  af_xdp_main_t *am = &af_xdp_main;

  /// move to interface creation
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vec_validate_aligned (am->rx_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  am->log_class = vlib_log_register_class ("af_xdp", 0);
  vlib_log_debug (am->log_class, "initialized");

  return 0;
}

VLIB_INIT_FUNCTION (af_xdp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
