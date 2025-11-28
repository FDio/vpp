/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2025 Cisco and/or its affiliates.
 */

#define _GNU_SOURCE
#include <tap/if_tun.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <net/if_arp.h>

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vppinfra/linux/netns.h>
#include <vnet/devices/netlink.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>

#include <tap/internal.h>
#include <tap/inline.h>

tap_main_t tap_main;

#define TUN_MAX_PACKET_BYTES	 65355
#define TUN_MIN_PACKET_BYTES	 64
#define TUN_DEFAULT_PACKET_BYTES 1500
#define TAP_MAX_INSTANCE	 8192

#define _IOCTL(fd, a, ...)                                                    \
  if (ioctl (fd, a, __VA_ARGS__) < 0)                                         \
    {                                                                         \
      err = clib_error_return_unix (0, "ioctl(" #a ")");                      \
      log_err (tif, "%U", format_clib_error, err);                            \
      goto error;                                                             \
    }

VNET_HW_INTERFACE_CLASS (tun_device_hw_interface_class, static) = {
  .name = "tun",
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
  .tx_hash_fn_type = VNET_HASH_FN_TYPE_IP,
};

static u32
virtio_eth_flag_change (vnet_main_t *vnm, vnet_hw_interface_t *hi, u32 flags)
{
  /* nothing for now */
  // TODO On MTU change call vnet_netlink_set_if_mtu
  return 0;
}

static clib_error_t *
virtio_eth_set_max_frame_size (vnet_main_t *vnm, vnet_hw_interface_t *hi,
			       u32 frame_size)
{
  /* nothing for now */
  return 0;
}

static void
tap_vring_fill (vlib_main_t *vm, tap_if_t *tif, vnet_virtio_vring_t *vring)
{
  u16 hdr_sz = VIRTIO_NET_HDR_SZ;

  vnet_virtio_vring_desc_t dt = {
    .len = vlib_buffer_get_default_data_size (vm) + hdr_sz,
    .flags = VRING_DESC_F_WRITE,
  };

  u16 n_alloc = vlib_buffer_alloc_from_pool (
    vm, vring->buffers, vring->queue_size, vring->buffer_pool_index);

  for (u16 i = 0; i < n_alloc; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, vring->buffers[i]);
      dt.addr = pointer_to_uword (b->data - hdr_sz);
      vring->desc[i] = dt;
      vring->avail->ring[i] = i;
    }

  vring->avail->idx = n_alloc;
  vring->desc_next = 0;
  vring->desc_in_use = n_alloc;
  if (vring->queue_size != n_alloc)
    log_warn (tif,
	      "failed to initially fill vring %u with buffers (requersted "
	      "%u, provided %u)",
	      vring->queue_index, vring->queue_size, n_alloc);
}

static clib_error_t *
call_read_ready (clib_file_t *uf)
{
  vnet_main_t *vnm = vnet_get_main ();
  u64 b;

  ssize_t size __clib_unused = read (uf->file_descriptor, &b, sizeof (b));
  vnet_hw_if_rx_queue_set_int_pending (vnm, uf->private_data);

  return 0;
}

static void
tap_vring_set_rx_queues (vlib_main_t *vm, tap_if_t *tif)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_virtio_vring_t *vring;

  vnet_hw_if_set_input_node (vnm, tif->hw_if_index, tap_input_node.index);

  vec_foreach (vring, tif->rxq_vrings)
    {
      vring->queue_index = vnet_hw_if_register_rx_queue (
	vnm, tif->hw_if_index, RX_QUEUE_ACCESS (vring->queue_id),
	VNET_HW_IF_RXQ_THREAD_ANY);

      vring->buffer_pool_index = 0;

      clib_file_t f = {
	.read_function = call_read_ready,
	.flags = UNIX_FILE_EVENT_EDGE_TRIGGERED,
	.file_descriptor = vring->call_fd,
	.private_data = vring->queue_index,
	.description = format (0, "%U vring %u", format_tx_node_name,
			       tif->dev_instance, vring->queue_id),
      };

      vring->call_file_index = clib_file_add (&file_main, &f);
      vnet_hw_if_set_rx_queue_file_index (vnm, vring->queue_index,
					  vring->call_file_index);
      vnet_hw_if_set_rx_queue_mode (vnm, vring->queue_index,
				    VNET_HW_IF_RX_MODE_POLLING);
      tap_vring_fill (vm, tif, vring);
    }
  vnet_hw_if_update_runtime_data (vnm, tif->hw_if_index);
}

static void
tap_vring_set_tx_queues (tap_if_t *tif)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_virtio_vring_t *vring;
  uword n_threads = vlib_get_n_threads ();
  u8 consistent = tif->consistent_qp;

  vec_foreach (vring, tif->txq_vrings)
    {
      vring->queue_index = vnet_hw_if_register_tx_queue (
	vnm, tif->hw_if_index, TX_QUEUE_ACCESS (vring->queue_id));
    }

  if (tif->num_txqs == 0)
    {
      log_err (tif, "Interface %U has 0 txq", format_vnet_hw_if_index_name,
	       vnm, tif->hw_if_index);
      return;
    }

  for (u32 j = 0; j < n_threads; j++)
    {
      u32 qi = tif->txq_vrings[j % tif->num_txqs].queue_index;
      vnet_hw_if_tx_queue_assign_thread (vnm, qi,
					 (j + consistent) % n_threads);
    }

  vnet_hw_if_update_runtime_data (vnm, tif->hw_if_index);
}

static void
tap_set_packet_coalesce (tap_if_t *tif)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, tif->hw_if_index);
  vnet_virtio_vring_t *vring;
  tif->packet_coalesce = 1;
  vec_foreach (vring, tif->txq_vrings)
    gro_flow_table_init (&vring->flow_table, (!tif->is_tun),
			 hw->tx_node_index);
}

static void
tap_vring_free (vlib_main_t *vm, tap_if_t *tif, u32 idx)
{
  const u8 is_tx = idx & 1;
  vnet_virtio_vring_t *vring =
    is_tx ? vec_elt_at_index (tif->txq_vrings, TX_QUEUE_ACCESS (idx)) :
	    vec_elt_at_index (tif->rxq_vrings, RX_QUEUE_ACCESS (idx));

  if (!is_tx)
    clib_file_del_by_index (&file_main, vring->call_file_index);

  close (vring->kick_fd);
  if (!is_tx)
    close (vring->call_fd);

  if (vring->used)
    {
      u16 used = vring->desc_in_use;
      if (used && vring->queue_size)
	{
	  u16 start = vring->last_used_idx & (vring->queue_size - 1);
	  vlib_buffer_free_from_ring (vm, vring->buffers, start,
				      vring->queue_size, used);
	}
      clib_mem_free (vring->used);
    }
  if (vring->desc)
    clib_mem_free (vring->desc);
  if (vring->avail)
    clib_mem_free (vring->avail);
  vec_free (vring->buffers);
  if (is_tx)
    gro_flow_table_free (vring->flow_table);
}

static void
tap_free (vlib_main_t *vm, tap_if_t *tif)
{
  tap_main_t *tm = &tap_main;
  clib_error_t *err = 0;
  int i;

  tap_pre_input_node_disable (vm, tif);

  vec_foreach_index (i, tif->vhost_fds)
    if (tif->vhost_fds[i] != -1)
      close (tif->vhost_fds[i]);
  vec_foreach_index (i, tif->rxq_vrings)
    tap_vring_free (vm, tif, RX_QUEUE (i));
  vec_foreach_index (i, tif->txq_vrings)
    tap_vring_free (vm, tif, TX_QUEUE (i));

  if (tif->tap_fds)
    {
      _IOCTL (tif->tap_fds[0], TUNSETPERSIST, (void *) (uintptr_t) 0);
      log_dbg (tif, "TUNSETPERSIST: unset");
    }
error:
  vec_foreach_index (i, tif->tap_fds)
    close (tif->tap_fds[i]);

  vec_free (tif->tap_fds);
  vec_free (tif->vhost_fds);
  vec_free (tif->rxq_vrings);
  vec_free (tif->txq_vrings);
  vec_free (tif->host_if_name);
  vec_free (tif->initial_if_name);
  vec_free (tif->net_ns);
  vec_free (tif->host_bridge);
  clib_error_free (tif->error);

  tm->tap_ids = clib_bitmap_set (tm->tap_ids, tif->id, 0);
  pool_put (tm->interfaces, tif);
}

static clib_error_t *
tap_vring_init (tap_if_t *tif, u16 idx, u16 sz)
{
  vnet_virtio_vring_t *vring;
  int i;

  if (!is_pow2 (sz))
    return clib_error_return (0, "ring size must be power of 2");

  if (sz > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (sz == 0)
    sz = 256;

  if (idx % 2)
    {
      vec_validate_aligned (tif->txq_vrings, TX_QUEUE_ACCESS (idx),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (tif->txq_vrings, TX_QUEUE_ACCESS (idx));
    }
  else
    {
      vec_validate_aligned (tif->rxq_vrings, RX_QUEUE_ACCESS (idx),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (tif->rxq_vrings, RX_QUEUE_ACCESS (idx));
    }
  i = sizeof (vnet_virtio_vring_desc_t) * sz;
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->desc = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (vring->desc, 0, i);

  i = sizeof (vnet_virtio_vring_avail_t) + sz * sizeof (vring->avail->ring[0]);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->avail = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (vring->avail, 0, i);
  // tell kernel that we don't need interrupt
  vring->avail->flags = VRING_AVAIL_F_NO_INTERRUPT;

  i = sizeof (vnet_virtio_vring_used_t) +
      sz * sizeof (vnet_virtio_vring_used_elem_t);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->used = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (vring->used, 0, i);

  vring->queue_id = idx;
  ASSERT (vring->buffers == 0);
  vec_validate_aligned (vring->buffers, sz, CLIB_CACHE_LINE_BYTES);

  if (idx & 1)
    {
      clib_memset_u32 (vring->buffers, ~0, sz);
      // tx path: suppress the interrupts from kernel
      vring->call_fd = -1;
    }
  else
    vring->call_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);

  vring->total_packets = 0;
  vring->queue_size = sz;
  vring->kick_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  log_dbg (tif, "vring %u size %u call_fd %d kick_fd %d", idx,
	   vring->queue_size, vring->call_fd, vring->kick_fd);

  return 0;
}

static void
tap_template_update (tap_if_t *tif)
{
  vlib_buffer_template_t *bt = &tif->buffer_template;
  vlib_buffer_t *bt_buf = (vlib_buffer_t *) bt;

  ASSERT (tif->is_tun == 0);

  if (tif->feature_arc_enabled)
    {
      tif->next_index = (u16) tif->feature_arc_next_index;
      bt->current_config_index = tif->feature_arc_config_index;
      vnet_buffer (bt_buf)->feature_arc_index = tif->feature_arc_index;
      return;
    }

  bt->current_config_index = 0;
  vnet_buffer (bt_buf)->feature_arc_index = 0;

  tif->next_index = tif->per_interface_next_index != ~0 ?
		      tif->per_interface_next_index :
		      VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
}

__clib_export void
tap_create_if (vlib_main_t *vm, tap_create_if_args_t *args)
{
  vlib_thread_main_t *thm = vlib_get_thread_main ();
  vnet_main_t *vnm = vnet_get_main ();
  tap_main_t *tm = &tap_main;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;
  vnet_hw_if_caps_change_t cc;
  int i, num_vhost_queues;
  int old_netns_fd = -1;
  struct ifreq get_ifr = { .ifr_flags = 0 };
  size_t hdrsz;
  tap_if_t *tif = 0;
  clib_error_t *err = 0;
  unsigned int tap_features;
  int tfd = -1, qfd = -1, vfd = -1, nfd = -1;
  char *host_if_name = 0;
  unsigned int offload = 0;
  int sndbuf;
  u8 is_tun = (args->tap_flags & TAP_FLAG_TUN) != 0;

  struct ifreq ifr = {
    .ifr_flags = IFF_NO_PI | IFF_VNET_HDR | (is_tun ? IFF_TUN : IFF_TAP),
  };

  if (args->id != ~0)
    {
      if (clib_bitmap_get (tm->tap_ids, args->id))
	{
	  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
	  args->error = clib_error_return (0, "interface already exists");
	  return;
	}
    }
  else
    {
      args->id = clib_bitmap_next_clear (tm->tap_ids, args->auto_id_offset %
							TAP_MAX_INSTANCE);
    }

  if (args->id > TAP_MAX_INSTANCE)
    {
      args->rv = VNET_API_ERROR_UNSPECIFIED;
      args->error = clib_error_return (0, "cannot find free interface id");
      return;
    }

  pool_get_zero (tm->interfaces, tif);
  tif->is_tun = is_tun;
  tif->dev_instance = tif - tm->interfaces;
  tif->id = args->id;
  tif->num_txqs = clib_max (args->num_tx_queues, thm->n_vlib_mains);
  tif->num_rxqs = clib_max (args->num_rx_queues, 1);

  if (args->if_name)
    CLIB_SWAP (args->if_name, tif->initial_if_name);

  if (args->tap_flags & TAP_FLAG_ATTACH)
    {
      if (args->host_if_name == NULL)
	{
	  args->rv = VNET_API_ERROR_NO_MATCHING_INTERFACE;
	  err = clib_error_return (0, "host_if_name is not provided");
	  goto error;
	}
    }

  if (args->tap_flags & TAP_FLAG_CONSISTENT_QP)
    tif->consistent_qp = 1;

  /* if namespace is specified, all further netlink messages should be executed
   * after we change our net namespace */
  if (args->host_namespace)
    {
      old_netns_fd = clib_netns_open (NULL /* self */);
      if ((nfd = clib_netns_open (args->host_namespace)) == -1)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
	  args->error = clib_error_return_unix (0, "clib_netns_open '%s'",
						args->host_namespace);
	  goto error;
	}
      if (clib_setns (nfd) == -1)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
	  args->error =
	    clib_error_return_unix (0, "setns '%s'", args->host_namespace);
	  goto error;
	}
    }

  if (args->host_if_name != NULL)
    {
      host_if_name = (char *) args->host_if_name;
      clib_memcpy (ifr.ifr_name, host_if_name,
		   clib_min (IFNAMSIZ, vec_len (host_if_name)));
    }

  if ((tfd = open ("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      args->error = clib_error_return_unix (0, "open '/dev/net/tun'");
      goto error;
    }
  vec_add1 (tif->tap_fds, tfd);
  log_dbg (tif, "open tap fd %d", tfd);

  _IOCTL (tfd, TUNGETFEATURES, &tap_features);
  log_dbg (tif, "TUNGETFEATURES: 0x%lx %U", tap_features,
	   format_if_tun_features, tap_features);
  if ((tap_features & IFF_VNET_HDR) == 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      args->error = clib_error_return (0, "vhost-net backend not available");
      goto error;
    }

  if ((tap_features & IFF_MULTI_QUEUE) == 0)
    {
      if (tif->num_rxqs > 1)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
	  args->error = clib_error_return (0, "multiqueue not supported");
	  goto error;
	}
      tif->num_rxqs = tif->num_txqs = 1;
    }
  else
    ifr.ifr_flags |= IFF_MULTI_QUEUE;

  hdrsz = sizeof (vnet_virtio_net_hdr_v1_t);
  if (args->tap_flags & TAP_FLAG_GSO)
    {
      offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
      tif->gso_enabled = 1;
    }
  else if (args->tap_flags & TAP_FLAG_CSUM_OFFLOAD)
    {
      offload = TUN_F_CSUM;
      tif->csum_offload_enabled = 1;
    }

  _IOCTL (tfd, TUNSETIFF, (void *) &ifr);
  log_dbg (tif, "TUNSETIFF fd %d name %s flags 0x%x", tfd,
	   ifr.ifr_ifrn.ifrn_name, ifr.ifr_flags);

  tif->ifindex = if_nametoindex (ifr.ifr_ifrn.ifrn_name);
  log_dbg (tif, "ifindex %d", tif->ifindex);

  if (!args->host_if_name)
    host_if_name = ifr.ifr_ifrn.ifrn_name;
  else
    host_if_name = (char *) args->host_if_name;

  /*
   * unset the persistence when attaching to existing
   * interface
   */
  if (args->tap_flags & TAP_FLAG_ATTACH)
    {
      _IOCTL (tfd, TUNSETPERSIST, (void *) (uintptr_t) 0);
      log_dbg (tif, "TUNSETPERSIST: unset");
    }

  /* set the persistence */
  if (args->tap_flags & TAP_FLAG_PERSIST)
    {
      _IOCTL (tfd, TUNSETPERSIST, (void *) (uintptr_t) 1);
      log_dbg (tif, "TUNSETPERSIST: set");

      /* verify persistence is set, read the flags */
      _IOCTL (tfd, TUNGETIFF, (void *) &get_ifr);
      log_dbg (tif, "TUNGETIFF: 0x%lx %U", get_ifr.ifr_flags,
	       format_if_tun_features, get_ifr.ifr_flags);
      if ((get_ifr.ifr_flags & IFF_PERSIST) == 0)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
	  args->error = clib_error_return (0, "persistence not supported");
	  goto error;
	}
    }

  /* create additional queues on the linux side.
   * we create as many linux queue pairs as we have rx queues
   */
  for (i = 1; i < tif->num_rxqs; i++)
    {
      if ((qfd = open ("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
	  args->error = clib_error_return_unix (0, "open '/dev/net/tun'");
	  goto error;
	}
      vec_add1 (tif->tap_fds, qfd);
      _IOCTL (qfd, TUNSETIFF, (void *) &ifr);
      log_dbg (tif, "TUNSETIFF fd %d name %s flags 0x%x", qfd,
	       ifr.ifr_ifrn.ifrn_name, ifr.ifr_flags);
    }

  /*
   * From kernel 4.20, xdp support has been added in tun_sendmsg.
   * If sndbuf == INT_MAX, vhost batches the packet and processes
   * them using xdp data path for tun driver. It assumes packets
   * are ethernet frames (It needs to be fixed).
   * To avoid xdp data path in tun driver, sndbuf value should
   * be < INT_MAX.
   */
  sndbuf = INT_MAX - is_tun ? 1 : 0;

  for (i = 0; i < tif->num_rxqs; i++)
    {
      log_dbg (tif, "TUNSETVNETHDRSZ: fd %d vnet_hdr_sz %u", tif->tap_fds[i],
	       hdrsz);
      _IOCTL (tif->tap_fds[i], TUNSETVNETHDRSZ, &hdrsz);

      log_dbg (tif, "TUNSETSNDBUF: fd %d sndbuf %d", tif->tap_fds[i], sndbuf);
      _IOCTL (tif->tap_fds[i], TUNSETSNDBUF, &sndbuf);

      log_dbg (tif, "TUNSETOFFLOAD: fd %d 0x%lx %U", tif->tap_fds[i], offload,
	       format_if_tun_offloads, offload);
      _IOCTL (tif->tap_fds[i], TUNSETOFFLOAD, offload);

      if (fcntl (tif->tap_fds[i], F_SETFL, O_NONBLOCK) < 0)
	{
	  err = clib_error_return_unix (0, "fcntl(tfd, F_SETFL, O_NONBLOCK)");
	  log_err (tif, "set nonblocking: %U", format_clib_error, err);
	  goto error;
	}
    }

  /* open as many vhost-net fds as required and set ownership */
  num_vhost_queues = clib_max (tif->num_rxqs, tif->num_txqs);
  for (i = 0; i < num_vhost_queues; i++)
    {
      if ((vfd = open ("/dev/vhost-net", O_RDWR | O_NONBLOCK)) < 0)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_1;
	  args->error = clib_error_return_unix (0, "open '/dev/vhost-net'");
	  goto error;
	}
      vec_add1 (tif->vhost_fds, vfd);
      log_dbg (tif, "open vhost-net fd %d qpair %u", vfd, i);
      _IOCTL (vfd, VHOST_SET_OWNER, 0);
      log_dbg (tif, "VHOST_SET_OWNER: fd %u", vfd);
    }

  _IOCTL (tif->vhost_fds[0], VHOST_GET_FEATURES, &tif->remote_features);
  log_dbg (tif, "VHOST_GET_FEATURES: 0x%lx\n%U", tif->remote_features,
	   format_virtio_features, tif->remote_features);

  if ((tif->remote_features & VIRTIO_NET_F_MRG_RXBUF_BIT) == 0)
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      args->error = clib_error_return (0, "vhost-net backend doesn't support "
					  "VIRTIO_NET_F_MRG_RXBUF feature");
      goto error;
    }

  if ((tif->remote_features & VIRTIO_RING_F_INDIRECT_DESC_BIT) == 0)
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      args->error =
	clib_error_return (0, "vhost-net backend doesn't support "
			      "VIRTIO_RING_F_INDIRECT_DESC feature");
      goto error;
    }

  if ((tif->remote_features & VIRTIO_F_VERSION_1_BIT) == 0)
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      args->error = clib_error_return (0, "vhost-net backend doesn't support "
					  "VIRTIO_F_VERSION_1 features");
      goto error;
    }

  tif->features |= VIRTIO_NET_F_MRG_RXBUF_BIT;
  tif->features |= VIRTIO_F_VERSION_1_BIT;
  tif->features |= VIRTIO_RING_F_INDIRECT_DESC_BIT;

  if (!tif->is_tun)
    {
      if (ethernet_mac_address_is_zero (args->host_mac_addr.bytes))
	ethernet_mac_address_generate (args->host_mac_addr.bytes);
      args->error =
	vnet_netlink_set_link_addr (tif->ifindex, args->host_mac_addr.bytes);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}

      if (args->host_bridge)
	{
	  args->error = vnet_netlink_set_link_master (
	    tif->ifindex, (char *) args->host_bridge);
	  if (args->error)
	    {
	      args->rv = VNET_API_ERROR_NETLINK_ERROR;
	      goto error;
	    }
	}
    }

  if (args->host_ip4_prefix_len)
    {
      args->error = vnet_netlink_add_ip4_addr (
	tif->ifindex, &args->host_ip4_addr, args->host_ip4_prefix_len);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }

  if (args->host_ip6_prefix_len)
    {
      args->error = vnet_netlink_add_ip6_addr (
	tif->ifindex, &args->host_ip6_addr, args->host_ip6_prefix_len);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }

  args->error = vnet_netlink_set_link_state (tif->ifindex, 1 /* UP */);
  if (args->error)
    {
      args->rv = VNET_API_ERROR_NETLINK_ERROR;
      goto error;
    }

  if (args->host_ip4_gw_set)
    {
      args->error = vnet_netlink_add_ip4_route (0, 0, &args->host_ip4_gw);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }

  if (args->host_ip6_gw_set)
    {
      args->error = vnet_netlink_add_ip6_route (0, 0, &args->host_ip6_gw);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }

  if (args->host_mtu_set)
    {
      args->error =
	vnet_netlink_set_link_mtu (tif->ifindex, args->host_mtu_size);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }

  /* switch back to old net namespace */
  if (args->host_namespace)
    {
      if (clib_setns (old_netns_fd) == -1)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
	  args->error =
	    clib_error_return_unix (0, "setns '%s'", args->host_namespace);
	  goto error;
	}
    }

  for (i = 0; i < num_vhost_queues; i++)
    {
      if (i < tif->num_rxqs &&
	  (args->error = tap_vring_init (tif, RX_QUEUE (i), args->rx_ring_sz)))
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  goto error;
	}

      if (i < tif->num_txqs &&
	  (args->error = tap_vring_init (tif, TX_QUEUE (i), args->tx_ring_sz)))
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  goto error;
	}
    }

  for (i = 0; i < num_vhost_queues; i++)
    {
      int fd = tif->vhost_fds[i];
      _IOCTL (fd, VHOST_SET_FEATURES, &tif->features);
      log_dbg (tif, "VHOST_SET_FEATURES: fd %u 0x%lx\n%U", fd, tif->features,
	       format_virtio_features, tif->features);
      _IOCTL (fd, VHOST_SET_MEM_TABLE, tm->vhost_mem);
      log_dbg (tif, "VHOST_SET_MEM_TABLE: fd %u", fd);
    }

  /* finish initializing queue pair */
  for (i = 0; i < num_vhost_queues * 2; i++)
    {
      vhost_vring_addr_t addr = { 0 };
      vhost_vring_state_t state = { 0 };
      vhost_vring_file_t file = { 0 };
      vnet_virtio_vring_t *vring;
      u16 qp = i >> 1;
      int fd = tif->vhost_fds[qp];

      if (i & 1)
	{
	  if (qp >= tif->num_txqs)
	    continue;
	  vring = vec_elt_at_index (tif->txq_vrings, qp);
	}
      else
	{
	  if (qp >= tif->num_rxqs)
	    continue;
	  vring = vec_elt_at_index (tif->rxq_vrings, qp);
	}

      addr.index = state.index = file.index = vring->queue_id & 1;
      state.num = vring->queue_size;
      log_dbg (tif, "VHOST_SET_VRING_NUM fd %d index %u num %u", fd,
	       state.index, state.num);
      _IOCTL (fd, VHOST_SET_VRING_NUM, &state);

      addr.flags = 0;
      addr.desc_user_addr = pointer_to_uword (vring->desc);
      addr.avail_user_addr = pointer_to_uword (vring->avail);
      addr.used_user_addr = pointer_to_uword (vring->used);

      log_dbg (tif,
	       "VHOST_SET_VRING_ADDR fd %d index %u flags 0x%x "
	       "desc_user_addr 0x%lx avail_user_addr 0x%lx "
	       "used_user_addr 0x%lx",
	       fd, addr.index, addr.flags, addr.desc_user_addr,
	       addr.avail_user_addr, addr.used_user_addr);
      _IOCTL (fd, VHOST_SET_VRING_ADDR, &addr);

      file.fd = vring->call_fd;
      log_dbg (tif, "VHOST_SET_VRING_CALL fd %d index %u call_fd %d", fd,
	       file.index, file.fd);
      _IOCTL (fd, VHOST_SET_VRING_CALL, &file);

      file.fd = vring->kick_fd;
      log_dbg (tif, "VHOST_SET_VRING_KICK fd %d index %u kick_fd %d", fd,
	       file.index, file.fd);
      _IOCTL (fd, VHOST_SET_VRING_KICK, &file);

      file.fd = tif->tap_fds[qp % tif->num_rxqs];
      log_dbg (tif, "VHOST_NET_SET_BACKEND fd %d index %u tap_fd %d", fd,
	       file.index, file.fd);
      _IOCTL (fd, VHOST_NET_SET_BACKEND, &file);
    }

  if (!tif->is_tun)
    {
      if (!args->mac_addr_set)
	ethernet_mac_address_generate (args->mac_addr.bytes);

      clib_memcpy (tif->mac_addr, args->mac_addr.bytes, 6);
      if (args->host_bridge)
	tif->host_bridge = format (0, "%s%c", args->host_bridge, 0);
    }
  tif->host_if_name = format (0, "%s%c", host_if_name, 0);
  if (args->host_namespace)
    tif->net_ns = format (0, "%s%c", args->host_namespace, 0);
  tif->host_mtu_size = args->host_mtu_size;
  tif->tap_flags = args->tap_flags;
  clib_memcpy (tif->host_mac_addr, args->host_mac_addr.bytes, 6);
  tif->host_ip4_prefix_len = args->host_ip4_prefix_len;
  tif->host_ip6_prefix_len = args->host_ip6_prefix_len;
  if (args->host_ip4_prefix_len)
    clib_memcpy (&tif->host_ip4_addr, &args->host_ip4_addr, 4);
  if (args->host_ip6_prefix_len)
    clib_memcpy (&tif->host_ip6_addr, &args->host_ip6_addr, 16);

  if (!tif->is_tun)
    {
      vnet_eth_interface_registration_t eir = {};

      eir.dev_class_index = tap_device_class.index;
      eir.dev_instance = tif->dev_instance;
      eir.address = tif->mac_addr;
      eir.cb.flag_change = virtio_eth_flag_change;
      eir.cb.set_max_frame_size = virtio_eth_set_max_frame_size;
      tif->hw_if_index = vnet_eth_register_interface (vnm, &eir);
    }
  else
    {
      tif->hw_if_index = vnet_register_interface (
	vnm, tap_device_class.index, tif->dev_instance /* device instance */,
	tun_device_hw_interface_class.index, tif->dev_instance);
    }
  tm->tap_ids = clib_bitmap_set (tm->tap_ids, tif->id, 1);
  sw = vnet_get_hw_sw_interface (vnm, tif->hw_if_index);
  tif->sw_if_index = sw->sw_if_index;
  args->sw_if_index = tif->sw_if_index;
  args->rv = 0;
  hw = vnet_get_hw_interface (vnm, tif->hw_if_index);
  cc.mask = VNET_HW_IF_CAP_INT_MODE | VNET_HW_IF_CAP_TCP_GSO |
	    VNET_HW_IF_CAP_TX_IP4_CKSUM | VNET_HW_IF_CAP_TX_TCP_CKSUM |
	    VNET_HW_IF_CAP_TX_UDP_CKSUM | VNET_HW_IF_CAP_TX_FIXED_OFFSET;
  cc.val = VNET_HW_IF_CAP_INT_MODE | VNET_HW_IF_CAP_TX_FIXED_OFFSET;

  if (args->tap_flags & TAP_FLAG_GSO)
    cc.val |= VNET_HW_IF_CAP_TCP_GSO | VNET_HW_IF_CAP_TX_IP4_CKSUM |
	      VNET_HW_IF_CAP_TX_TCP_CKSUM | VNET_HW_IF_CAP_TX_UDP_CKSUM;
  else if (args->tap_flags & TAP_FLAG_CSUM_OFFLOAD)
    cc.val |= VNET_HW_IF_CAP_TX_IP4_CKSUM | VNET_HW_IF_CAP_TX_TCP_CKSUM |
	      VNET_HW_IF_CAP_TX_UDP_CKSUM;

  if ((args->tap_flags & TAP_FLAG_GSO) &&
      (args->tap_flags & TAP_FLAG_GRO_COALESCE))
    tap_set_packet_coalesce (tif);

  if (tif->is_tun)
    {
      hw->min_frame_size = TUN_MIN_PACKET_BYTES;
      vnet_hw_interface_set_mtu (
	vnm, hw->hw_if_index,
	args->host_mtu_size ? args->host_mtu_size : TUN_DEFAULT_PACKET_BYTES);
    }

  vnet_hw_if_change_caps (vnm, tif->hw_if_index, &cc);
  tap_pre_input_node_enable (vm, tif);
  tap_vring_set_rx_queues (vm, tif);
  tap_vring_set_tx_queues (tif);

  tif->per_interface_next_index = ~0;
  tif->feature_arc_config_index = ~0;
  tif->feature_arc_next_index = ~0;

  u8 buffer_pool_index = 0;
  vlib_buffer_template_t *bt = &tif->buffer_template;

  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, buffer_pool_index);
  tif->buffer_template = bp->buffer_template;
  vnet_buffer (bt)->sw_if_index[VLIB_RX] = tif->sw_if_index;
  vnet_buffer (bt)->sw_if_index[VLIB_TX] = ~0;
  bt->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
  bt->current_data = is_tun ? TUN_DATA_OFFSET : 0;
  tap_template_update (tif);

  vnet_hw_interface_set_flags (vnm, tif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  /*
   * Host tun/tap driver link carrier state is "up" at creation. The
   * driver never changes this unless the backend (VPP) changes it using
   * TUNSETCARRIER ioctl(). See tap_set_carrier().
   */
  tif->host_carrier_up = 1;

  goto done;

error:
  if (err)
    {
      ASSERT (args->error == 0);
      args->error = err;
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
    }

  log_err (tif, "%U", format_clib_error, args->error);
  tap_free (vm, tif);
done:
  if (old_netns_fd != -1)
    {
      /* in case we errored with a switched netns */
      clib_setns (old_netns_fd);
      close (old_netns_fd);
    }
  if (nfd != -1)
    close (nfd);
}

__clib_export int
tap_delete_if (vlib_main_t *vm, u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  tap_main_t *tm = &tap_main;
  tap_if_t *tif;
  vnet_hw_interface_t *hw;

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  if (hw == NULL || tap_device_class.index != hw->dev_class_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  tif = pool_elt_at_index (tm->interfaces, hw->dev_instance);

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, tif->hw_if_index, 0);
  vnet_sw_interface_set_flags (vnm, tif->sw_if_index, 0);

  if (!tif->is_tun)
    ethernet_delete_interface (vnm, tif->hw_if_index);
  else
    vnet_delete_hw_interface (vnm, tif->hw_if_index);
  tif->hw_if_index = ~0;

  tap_free (vm, tif);

  return 0;
}

int
tap_dump_ifs (tap_interface_details_t **out_tapids)
{
  vnet_main_t *vnm = vnet_get_main ();
  tap_main_t *tm = &tap_main;
  tap_if_t *tif;
  vnet_virtio_vring_t *vring;
  vnet_hw_interface_t *hi;
  tap_interface_details_t *r_tapids = NULL;
  tap_interface_details_t *tapid = NULL;

  pool_foreach (tif, tm->interfaces)
    {
      vec_add2 (r_tapids, tapid, 1);
      clib_memset (tapid, 0, sizeof (*tapid));
      tapid->id = tif->id;
      tapid->sw_if_index = tif->sw_if_index;
      hi = vnet_get_hw_interface (vnm, tif->hw_if_index);
      clib_memcpy (tapid->dev_name, hi->name,
		   MIN (ARRAY_LEN (tapid->dev_name) - 1, vec_len (hi->name)));
      vring = vec_elt_at_index (tif->rxq_vrings, RX_QUEUE_ACCESS (0));
      tapid->rx_ring_sz = vring->queue_size;
      vring = vec_elt_at_index (tif->txq_vrings, TX_QUEUE_ACCESS (0));
      tapid->tx_ring_sz = vring->queue_size;
      tapid->tap_flags = tif->tap_flags;
      clib_memcpy (&tapid->host_mac_addr, tif->host_mac_addr, 6);
      if (tif->host_if_name)
	{
	  clib_memcpy (tapid->host_if_name, tif->host_if_name,
		       MIN (ARRAY_LEN (tapid->host_if_name) - 1,
			    vec_len (tif->host_if_name)));
	}
      if (tif->net_ns)
	{
	  clib_memcpy (tapid->host_namespace, tif->net_ns,
		       MIN (ARRAY_LEN (tapid->host_namespace) - 1,
			    vec_len (tif->net_ns)));
	}
      if (tif->host_bridge)
	{
	  clib_memcpy (tapid->host_bridge, tif->host_bridge,
		       MIN (ARRAY_LEN (tapid->host_bridge) - 1,
			    vec_len (tif->host_bridge)));
	}
      if (tif->host_ip4_prefix_len)
	clib_memcpy (tapid->host_ip4_addr.as_u8, &tif->host_ip4_addr, 4);
      tapid->host_ip4_prefix_len = tif->host_ip4_prefix_len;
      if (tif->host_ip6_prefix_len)
	clib_memcpy (tapid->host_ip6_addr.as_u8, &tif->host_ip6_addr, 16);
      tapid->host_ip6_prefix_len = tif->host_ip6_prefix_len;
      tapid->host_mtu_size = tif->host_mtu_size;
    }

  *out_tapids = r_tapids;

  return 0;
}

/*
 * Set host tap/tun interface carrier state so it will appear to host
 * applications that the interface's link state changed.
 *
 * If the kernel we're building against does not have support for the
 * TUNSETCARRIER ioctl command, do nothing.
 */
__clib_export int
tap_set_carrier (u32 hw_if_index, u32 carrier_up)
{
  int ret = 0;
#ifdef TUNSETCARRIER
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  tap_main_t *tm = &tap_main;
  tap_if_t *tif;
  int *fd;

  tif = pool_elt_at_index (tm->interfaces, hi->dev_instance);
  vec_foreach (fd, tif->tap_fds)
    {
      ret = ioctl (*fd, TUNSETCARRIER, &carrier_up);
      if (ret < 0)
	{
	  clib_warning ("ioctl (TUNSETCARRIER) returned %d", ret);
	  break;
	}
    }
  if (!ret)
    tif->host_carrier_up = (carrier_up != 0);
#endif

  return ret;
}

/*
 * Set host tap/tun interface speed in Mbps.
 */
__clib_export int
tap_set_speed (u32 hw_if_index, u32 speed)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  tap_main_t *tm = &tap_main;
  tap_if_t *tif;
  int old_netns_fd = -1;
  int nfd = -1;
  int ctl_fd = -1;
  struct ifreq ifr;
  struct ethtool_cmd ecmd;
  int ret = -1;

  tif = pool_elt_at_index (tm->interfaces, hi->dev_instance);

  if (tif->net_ns)
    {
      old_netns_fd = clib_netns_open (NULL /* self */);
      if ((nfd = clib_netns_open (tif->net_ns)) == -1)
	{
	  clib_warning ("Cannot open netns");
	  goto done;
	}
      if (clib_setns (nfd) == -1)
	{
	  clib_warning ("Cannot set ns");
	  goto done;
	}
    }

  if ((ctl_fd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      clib_warning ("Cannot open control socket");
      goto done;
    }

  ecmd.cmd = ETHTOOL_GSET;
  clib_memset (&ifr, 0, sizeof (ifr));
  clib_memcpy (ifr.ifr_name, tif->host_if_name,
	       strlen ((const char *) tif->host_if_name));
  ifr.ifr_data = (void *) &ecmd;
  if ((ret = ioctl (ctl_fd, SIOCETHTOOL, &ifr)) < 0)
    {
      clib_warning ("Cannot get device settings");
      goto done;
    }

  if (ethtool_cmd_speed (&ecmd) != speed)
    {
      ecmd.cmd = ETHTOOL_SSET;
      ethtool_cmd_speed_set (&ecmd, speed);
      if ((ret = ioctl (ctl_fd, SIOCETHTOOL, &ifr)) < 0)
	{
	  clib_warning ("Cannot set device settings");
	  goto done;
	}
    }

done:
  if (old_netns_fd != -1)
    {
      if (clib_setns (old_netns_fd) == -1)
	{
	  clib_warning ("Cannot set old ns");
	}
      close (old_netns_fd);
    }
  if (nfd != -1)
    close (nfd);
  if (ctl_fd != -1)
    close (ctl_fd);

  return ret;
}

__clib_export unsigned int
tap_get_ifindex (vlib_main_t *vm, u32 sw_if_index)
{
  tap_main_t *tm = &tap_main;
  tap_if_t *tif;

  pool_foreach (tif, tm->interfaces)
    {
      if (tif->sw_if_index == sw_if_index)
	return tif->ifindex;
    }

  return ~0;
}

__clib_export int
tap_is_tun (vlib_main_t *vm, u32 sw_if_index)
{
  tap_main_t *tm = &tap_main;
  tap_if_t *tif;

  pool_foreach (tif, tm->interfaces)
    {
      if (tif->sw_if_index == sw_if_index)
	return tif->is_tun;
    }

  return 0;
}

static void
tap_feature_update (u32 sw_if_index, u8 arc_index, u8 is_enable, void *data)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_feature_main_t *fm = &feature_main;
  tap_main_t *tm = &tap_main;
  vnet_hw_interface_t *hw;
  tap_if_t *tif;
  vnet_feature_config_main_t *cm;
  u32 config_index = ~0;
  u32 next_index = ~0;

  if (arc_index != fm->device_input_feature_arc_index)
    return;

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!hw || hw->dev_class_index != tap_device_class.index)
    return;

  tif = pool_elt_at_index (tm->interfaces, hw->dev_instance);

  cm = &fm->feature_config_mains[arc_index];
  if (sw_if_index < vec_len (cm->config_index_by_sw_if_index))
    config_index = cm->config_index_by_sw_if_index[sw_if_index];

  if (config_index != ~0)
    vnet_get_config_data (&cm->config_main, &config_index, &next_index, 0);

  tif->feature_arc_config_index = config_index;
  tif->feature_arc_next_index = next_index;
  tif->feature_arc_index = arc_index;
  tif->feature_arc_enabled = is_enable ? 1 : 0;
  tap_template_update (tif);
}

static void
tap_set_interface_next_node (vnet_main_t *vnm, u32 hw_if_index, u32 node_index)
{
  tap_main_t *tm = &tap_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  tap_if_t *tif = pool_elt_at_index (tm->interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    tif->per_interface_next_index = node_index;
  else
    tif->per_interface_next_index =
      vlib_node_add_next (vlib_get_main (), tap_input_node.index, node_index);

  tap_template_update (tif);
}

static void
tap_clear_hw_interface_counters (u32 instance)
{
  /* Nothing for now */
}

static clib_error_t *
tap_interface_rx_mode_change (vnet_main_t *vnm, u32 hw_if_index, u32 qid,
			      vnet_hw_if_rx_mode mode)
{
  tap_main_t *tm = &tap_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  tap_if_t *tif = pool_elt_at_index (tm->interfaces, hw->dev_instance);
  vnet_virtio_vring_t *rx_vring = vec_elt_at_index (tif->rxq_vrings, qid);

  if (mode == VNET_HW_IF_RX_MODE_POLLING)
    rx_vring->avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
  else
    rx_vring->avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;

  return 0;
}

static clib_error_t *
tap_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  tap_main_t *tm = &tap_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  tap_if_t *tif = pool_elt_at_index (tm->interfaces, hw->dev_instance);

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    {
      tif->admin_up = 1;
      vnet_hw_interface_set_flags (vnm, tif->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    {
      tif->admin_up = 0;
      vnet_hw_interface_set_flags (vnm, tif->hw_if_index, 0);
    }
  return 0;
}

static char *tap_tx_func_error_strings[] = {
#define _(n, s) s,
  foreach_tap_tx_func_error
#undef _
};

VNET_DEVICE_CLASS (tap_device_class) = {
  .name = "tap",
  .format_device_name = format_tx_node_name,
  .format_device = format_tap_device,
  .format_tx_trace = format_tap_tx_trace,
  .tx_function_n_errors = VIRTIO_TX_N_ERROR,
  .tx_function_error_strings = tap_tx_func_error_strings,
  .rx_redirect_to_node = tap_set_interface_next_node,
  .clear_counters = tap_clear_hw_interface_counters,
  .admin_up_down_function = tap_interface_admin_up_down,
  .rx_mode_change_function = tap_interface_rx_mode_change,
};

static clib_error_t *
tap_init (vlib_main_t *vm)
{
  tap_main_t *tm = &tap_main;
  clib_error_t *error = 0;
  vlib_physmem_main_t *vpm = &vm->physmem_main;

  tm->log_default = vlib_log_register_class ("tap", 0);
  vlib_log_debug (tm->log_default, "initialized");

  /* setup features and memtable */
  tm->vhost_mem =
    clib_mem_alloc (sizeof (vhost_memory_t) + sizeof (vhost_memory_region_t));
  *tm->vhost_mem = (vhost_memory_t){
    .nregions = 1,
  };
  tm->vhost_mem->regions[0] = (vhost_memory_region_t){
    .memory_size = vpm->max_size,
    .guest_phys_addr = vpm->base_addr,
    .userspace_addr = vpm->base_addr,
  };

  for (u32 i = 0; i < tm->vhost_mem->nregions; i++)
    vlib_log_debug (tm->log_default,
		    "memtable region %u memory_size 0x%lx "
		    "guest_phys_addr 0x%lx userspace_addr 0x%lx",
		    i, tm->vhost_mem->regions[0].memory_size,
		    tm->vhost_mem->regions[0].guest_phys_addr,
		    tm->vhost_mem->regions[0].userspace_addr);

  vnet_feature_register (tap_feature_update, NULL);

  return error;
}

VLIB_INIT_FUNCTION (tap_init);
