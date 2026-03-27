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
#include <errno.h>
#include <limits.h>

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vppinfra/linux/netns.h>
#include <vnet/devices/netlink.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>

#include <tap/internal.h>

tap_main_t tap_main;

#define TUN_MAX_PACKET_BYTES	 65355
#define TUN_MIN_PACKET_BYTES	 64
#define TUN_DEFAULT_PACKET_BYTES 1500
#define TAP_MAX_INSTANCE	 8192

const static u64 virtio_features = VIRTIO_NET_F_MRG_RXBUF_BIT |
				   VIRTIO_F_VERSION_1_BIT |
				   VIRTIO_RING_F_INDIRECT_DESC_BIT;

#ifndef SIOCETHTOOL
#define SIOCETHTOOL 0x8946
#endif

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
  /* Get the ethernet interface to manipulate STATUS_L3 flag.
   * STATUS_L3 tells ethernet-input to skip software DMAC checks.
   */
  ethernet_interface_t *ei = ethernet_get_interface (&ethernet_main, hi->hw_if_index);

  switch (flags)
    {
    case ETHERNET_INTERFACE_FLAG_ACCEPT_ALL:
      /* Promiscuous mode: skip software L3 DMAC check.
       * Setting STATUS_L3 tells ethernet-input to accept all packets
       * regardless of destination MAC address.
       */
      if (ei)
	ei->flags |= ETHERNET_INTERFACE_FLAG_STATUS_L3;
      return 0;

    case ETHERNET_INTERFACE_FLAG_DEFAULT_L3:
      /* Default L3 mode: enable software L3 DMAC check.
       * Clearing STATUS_L3 tells ethernet-input to validate DMAC
       * against the interface MAC and secondary MACs.
       */
      if (ei)
	ei->flags &= ~ETHERNET_INTERFACE_FLAG_STATUS_L3;
      return 0;
    default:
      return ~0;
    }
  // TODO On MTU change call vnet_netlink_set_if_mtu
}

static clib_error_t *
virtio_eth_set_max_frame_size (vnet_main_t *vnm, vnet_hw_interface_t *hi,
			       u32 frame_size)
{
  /* nothing for now */
  return 0;
}

static void
tap_vring_fill (vlib_main_t *vm, tap_if_t *tif, tap_rxq_t *rxq)
{
  const u16 hdr_sz = VIRTIO_NET_HDR_SZ;
  int rv;

  vnet_virtio_vring_desc_t dt = {
    .len = vlib_buffer_get_default_data_size (vm) + hdr_sz - rxq->offset,
    .flags = VRING_DESC_F_WRITE,
  };

  u16 n_alloc = vlib_buffer_alloc_from_pool (vm, rxq->buffers, rxq->queue_size,
					     rxq->buffer_pool_index);

  for (u16 i = 0; i < n_alloc; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, rxq->buffers[i]);
      dt.addr = pointer_to_uword (b->data - hdr_sz + rxq->offset);
      rxq->desc[i] = dt;
      rxq->avail->ring[i] = i;
    }

  rxq->desc_next = 0;
  rxq->desc_in_use = n_alloc;
  if (rxq->queue_size != n_alloc)
    log_warn (tif,
	      "failed to initially fill rxq %u with buffers (requested "
	      "%u, provided %u)",
	      rxq->queue_index, rxq->queue_size, n_alloc);
  else
    log_dbg (tif, "rxq %u initially filled with %u buffers", rxq->queue_index,
	     n_alloc);

  __atomic_store_n (&rxq->avail->idx, n_alloc, __ATOMIC_RELEASE);
  rv = write (rxq->kick_fd, &(u64){ 1 }, sizeof (u64));
  if (rv != sizeof (u64))
    log_err (tif, "failed to send initial kick to rxq %u (fd %d)",
	     rxq->queue_id, rxq->kick_fd);
  else
    log_dbg (tif, "initial kick sent to rxq %u (fd %d)", rxq->queue_id,
	     rxq->kick_fd);
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
  tap_rxq_t *rxq;

  vnet_hw_if_set_input_node (vnm, tif->hw_if_index, tap_input_node.index);

  vec_foreach (rxq, tif->rx_queues)
    {
      rxq->queue_index = vnet_hw_if_register_rx_queue (
	vnm, tif->hw_if_index, rxq->queue_id, VNET_HW_IF_RXQ_THREAD_ANY);

      rxq->buffer_pool_index = 0;

      clib_file_t f = {
	.read_function = call_read_ready,
	.flags = UNIX_FILE_EVENT_EDGE_TRIGGERED,
	.file_descriptor = rxq->call_fd,
	.private_data = rxq->queue_index,
	.description = format (0, "%U vring %u", format_tx_node_name,
			       tif->dev_instance, rxq->queue_id),
      };

      rxq->call_file_index = clib_file_add (&file_main, &f);
      vnet_hw_if_set_rx_queue_file_index (vnm, rxq->queue_index,
					  rxq->call_file_index);
      vnet_hw_if_set_rx_queue_mode (vnm, rxq->queue_index,
				    VNET_HW_IF_RX_MODE_POLLING);
      tap_vring_fill (vm, tif, rxq);
    }
  vnet_hw_if_update_runtime_data (vnm, tif->hw_if_index);
}

static void
tap_vring_set_tx_queues (tap_if_t *tif)
{
  vnet_main_t *vnm = vnet_get_main ();
  tap_txq_t *txq;
  uword n_threads = vlib_get_n_threads ();
  u8 consistent = tif->consistent_qp;

  vec_foreach (txq, tif->tx_queues)
    {
      txq->queue_index =
	vnet_hw_if_register_tx_queue (vnm, tif->hw_if_index, txq->queue_id);
    }

  if (vec_len (tif->tx_queues) == 0)
    {
      log_err (tif, "Interface %U has 0 txq", format_vnet_hw_if_index_name,
	       vnm, tif->hw_if_index);
      return;
    }

  for (u32 j = 0; j < n_threads; j++)
    {
      u32 qi = tif->tx_queues[j % vec_len (tif->tx_queues)].queue_index;
      vnet_hw_if_tx_queue_assign_thread (vnm, qi,
					 (j + consistent) % n_threads);
    }

  vnet_hw_if_update_runtime_data (vnm, tif->hw_if_index);
}

static void
tap_rxq_free (vlib_main_t *vm, tap_if_t *tif, u32 queue_id)
{
  tap_rxq_t *rxq = tap_get_rx_queue (tif, queue_id);

  clib_file_del_by_index (&file_main, rxq->call_file_index);

  close (rxq->kick_fd);
  close (rxq->call_fd);

  if (rxq->used)
    {
      u16 used = rxq->desc_in_use;
      if (used && rxq->queue_size)
	{
	  u16 start = rxq->last_used_idx & (rxq->queue_size - 1);
	  vlib_buffer_free_from_ring (vm, rxq->buffers, start, rxq->queue_size,
				      used);
	}
      clib_mem_free (rxq->used);
    }
  if (rxq->desc)
    clib_mem_free (rxq->desc);
  if (rxq->avail)
    clib_mem_free (rxq->avail);
  vec_free (rxq->buffers);
}

static void
tap_txq_free (tap_if_t *tif, u32 queue_id)
{
  tap_txq_t *txq = tap_get_tx_queue (tif, queue_id);

  close (txq->kick_fd);

  if (txq->used)
    clib_mem_free (txq->used);
  if (txq->desc)
    clib_mem_free (txq->desc);
  if (txq->avail)
    clib_mem_free (txq->avail);
  vec_free (txq->buffers);
  gro_flow_table_free (txq->flow_table);
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
  vec_foreach_index (i, tif->rx_queues)
    tap_rxq_free (vm, tif, i);
  vec_foreach_index (i, tif->tx_queues)
    tap_txq_free (tif, i);

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
  vec_free (tif->rx_queues);
  vec_free (tif->tx_queues);
  vec_free (tif->host_if_name);
  vec_free (tif->name);
  vec_free (tif->net_ns);
  vec_free (tif->host_bridge);
  clib_error_free (tif->error);

  tm->tap_ids = clib_bitmap_set (tm->tap_ids, tif->id, 0);
  pool_put (tm->interfaces, tif);
}

static clib_error_t *
tap_rxq_init (tap_if_t *tif, u16 idx, u16 sz)
{
  tap_rxq_t *rxq;
  int i;

  if (!is_pow2 (sz))
    return clib_error_return (0, "ring size must be power of 2");

  if (sz > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (sz == 0)
    sz = 256;

  vec_validate_aligned (tif->rx_queues, idx, CLIB_CACHE_LINE_BYTES);
  rxq = tap_get_rx_queue (tif, idx);

  i = sizeof (vnet_virtio_vring_desc_t) * sz;
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);

  rxq->offset = tif->is_tun ? TUN_DATA_OFFSET : 0;
  rxq->desc = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);

  i = sizeof (vnet_virtio_vring_avail_t) + sz * sizeof (rxq->avail->ring[0]);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  rxq->avail = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (rxq->avail, 0, i);
  rxq->avail->flags = VRING_AVAIL_F_NO_INTERRUPT;

  i = sizeof (vnet_virtio_vring_used_t) +
      sz * sizeof (vnet_virtio_vring_used_elem_t);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  rxq->used = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (rxq->used, 0, i);

  rxq->queue_id = idx;
  ASSERT (rxq->buffers == 0);
  vec_validate_aligned (rxq->buffers, sz, CLIB_CACHE_LINE_BYTES);

  rxq->call_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  rxq->desc_next = 0;
  rxq->total_packets = 0;
  rxq->queue_size = sz;
  rxq->kick_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  log_dbg (tif, "rxq %u size %u call_fd %d kick_fd %d", idx, rxq->queue_size,
	   rxq->call_fd, rxq->kick_fd);

  return 0;
}

static clib_error_t *
tap_tx_vring_init (tap_if_t *tif, u16 idx, u16 sz)
{
  tap_txq_t *txq;
  int i;

  if (!is_pow2 (sz))
    return clib_error_return (0, "ring size must be power of 2");

  if (sz > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (sz == 0)
    sz = 256;

  vec_validate_aligned (tif->tx_queues, idx, CLIB_CACHE_LINE_BYTES);
  txq = tap_get_tx_queue (tif, idx);

  i = sizeof (vnet_virtio_vring_desc_t) * sz;
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);

  txq->desc = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  for (u32 di = 0; di < sz; di++)
    txq->desc[di] = (vnet_virtio_vring_desc_t){ .next = di - 1 };
  txq->desc_freelist_head = sz - 1;

  i = sizeof (vnet_virtio_vring_avail_t) + sz * sizeof (txq->avail->ring[0]);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  txq->avail = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (txq->avail, 0, i);
  txq->avail->flags = VRING_AVAIL_F_NO_INTERRUPT;

  i = sizeof (vnet_virtio_vring_used_t) +
      sz * sizeof (vnet_virtio_vring_used_elem_t);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  txq->used = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (txq->used, 0, i);

  txq->queue_id = idx;
  ASSERT (txq->buffers == 0);
  vec_validate_aligned (txq->buffers, sz, CLIB_CACHE_LINE_BYTES);

  txq->desc_next = 0;
  txq->total_packets = 0;
  txq->queue_size = sz;
  txq->kick_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  log_dbg (tif, "txq %u size %u kick_fd %d", idx, txq->queue_size,
	   txq->kick_fd);

  return 0;
}

static void
tap_template_update (tap_if_t *tif)
{
  vlib_buffer_template_t *bt = &tif->buffer_template;
  vlib_buffer_t *bt_buf = (vlib_buffer_t *) bt;

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
  u8 is_tun = (args->tap_flags & TAP_FLAG_TUN) != 0;

  struct ifreq ifr = {
    .ifr_flags = IFF_NO_PI | IFF_VNET_HDR | (is_tun ? IFF_TUN : IFF_TAP),
  };

  ASSERT (vlib_worker_thread_barrier_held ());

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
  u16 n_txqs = clib_max (args->num_tx_queues, thm->n_vlib_mains);
  u16 n_rxqs = clib_max (args->num_rx_queues, 1);

  if (args->if_name)
    CLIB_SWAP (args->if_name, tif->name);

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
      if (n_rxqs > 1)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
	  args->error = clib_error_return (0, "multiqueue not supported");
	  goto error;
	}
      n_rxqs = n_txqs = 1;
    }
  else
    ifr.ifr_flags |= IFF_MULTI_QUEUE;

  hdrsz = sizeof (vnet_virtio_net_hdr_v1_t);
  if (args->tap_flags & TAP_FLAG_GSO)
    {
      offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
      tif->gso_enabled = 1;
      tif->csum_offload_enabled = 1;
    }
  else if (args->tap_flags & TAP_FLAG_CSUM_OFFLOAD)
    {
      offload = TUN_F_CSUM;
      tif->csum_offload_enabled = 1;
    }

  _IOCTL (tfd, TUNSETIFF, (void *) &ifr);
  log_dbg (tif, "TUNSETIFF fd %d name %s flags %U (0x%x)", tfd,
	   ifr.ifr_ifrn.ifrn_name, format_if_tun_features, ifr.ifr_flags,
	   ifr.ifr_flags);

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
  for (i = 1; i < n_rxqs; i++)
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

  for (i = 0; i < n_rxqs; i++)
    {
      int sndbuf = INT_MAX - (is_tun ? 1 : 0);
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
  num_vhost_queues = clib_max (n_rxqs, n_txqs);
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
      /* Try to set vhost worker mode to kthread for better performance.
       * IMPORTANT: This IOCTL must be called BEFORE VHOST_SET_OWNER.
       * Only available on kernel >= 6.12 with
       * CONFIG_VHOST_ENABLE_FORK_OWNER_CONTROL=y */
      u8 fork_mode = VHOST_FORK_OWNER_KTHREAD;
      if (ioctl (vfd, VHOST_SET_FORK_FROM_OWNER, &fork_mode) == 0)
	{
	  if (i == 0)
	    log_dbg (tif,
		     "VHOST_SET_FORK_FROM_OWNER: fd %u mode %d (kthread mode "
		     "requested)",
		     vfd, fork_mode);
	}
      else if (errno == ENOTTY || errno == EINVAL)
	{
	  /* IOCTL not supported by this kernel, continue with default worker
	   * mode */
	  if (i == 0)
	    log_dbg (tif, "VHOST_SET_FORK_FROM_OWNER not supported, using "
			  "default worker mode (task)");
	}
      else
	{
	  /* Unexpected error, log warning but continue */
	  if (i == 0)
	    log_warn (
	      tif, "VHOST_SET_FORK_FROM_OWNER failed (continuing with default "
		   "mode)");
	}
      _IOCTL (vfd, VHOST_SET_OWNER, 0);
      log_dbg (tif, "VHOST_SET_OWNER: fd %u", vfd);
    }

  _IOCTL (tif->vhost_fds[0], VHOST_GET_FEATURES, &tif->remote_features);
  log_dbg (tif, "VHOST_GET_FEATURES: 0x%lx\n%U", tif->remote_features,
	   format_virtio_features, tif->remote_features);

  if ((tif->remote_features & virtio_features) != virtio_features)
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      args->error = clib_error_return (
	0,
	"vhost-net backend doesn't support following mandatory features:\n %U",
	format_virtio_features,
	(tif->remote_features & virtio_features) ^ virtio_features);
      goto error;
    }

  tif->features = virtio_features;

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
      if (i < n_rxqs &&
	  (args->error = tap_rxq_init (tif, i, args->rx_ring_sz)))
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  goto error;
	}

      if (i < n_txqs &&
	  (args->error = tap_tx_vring_init (tif, i, args->tx_ring_sz)))
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
  for (i = 0; i < num_vhost_queues; i++)
    {
      int fd = tif->vhost_fds[i];
      tap_rxq_t *rxq = (i < n_rxqs) ? tap_get_rx_queue (tif, i) : 0;
      tap_txq_t *txq = (i < n_txqs) ? tap_get_tx_queue (tif, i) : 0;
      vhost_vring_addr_t addr = { 0 };
      vhost_vring_state_t state = { 0 };
      vhost_vring_file_t file = { 0 };

      if (rxq)
	{
	  addr.index = state.index = file.index = 0;
	  state.num = rxq->queue_size;
	  log_dbg (tif, "VHOST_SET_VRING_NUM rxq %u fd %d index %u num %u",
		   rxq->queue_id, fd, state.index, state.num);
	  _IOCTL (fd, VHOST_SET_VRING_NUM, &state);

	  addr.flags = 0;
	  addr.desc_user_addr = pointer_to_uword (rxq->desc);
	  addr.avail_user_addr = pointer_to_uword (rxq->avail);
	  addr.used_user_addr = pointer_to_uword (rxq->used);

	  log_dbg (tif,
		   "VHOST_SET_VRING_ADDR rxq %u fd %d index %u flags 0x%x "
		   "desc_user_addr 0x%lx avail_user_addr 0x%lx "
		   "used_user_addr 0x%lx",
		   rxq->queue_id, fd, addr.index, addr.flags,
		   addr.desc_user_addr, addr.avail_user_addr,
		   addr.used_user_addr);
	  _IOCTL (fd, VHOST_SET_VRING_ADDR, &addr);

	  file.fd = rxq->call_fd;
	  log_dbg (tif,
		   "VHOST_SET_VRING_CALL rxq %u fd %d index %u call_fd %d",
		   rxq->queue_id, fd, file.index, file.fd);
	  _IOCTL (fd, VHOST_SET_VRING_CALL, &file);

	  file.fd = rxq->kick_fd;
	  log_dbg (tif,
		   "VHOST_SET_VRING_KICK rxq %u fd %d index %u kick_fd %d",
		   rxq->queue_id, fd, file.index, file.fd);
	  _IOCTL (fd, VHOST_SET_VRING_KICK, &file);

	  file.fd = tif->tap_fds[i % n_rxqs];
	  log_dbg (tif,
		   "VHOST_NET_SET_BACKEND rxq %u fd %d index %u tap_fd %d",
		   rxq->queue_id, fd, file.index, file.fd);
	  _IOCTL (fd, VHOST_NET_SET_BACKEND, &file);
	}

      if (txq)
	{
	  addr.index = state.index = file.index = 1;
	  state.num = txq->queue_size;
	  log_dbg (tif, "VHOST_SET_VRING_NUM txq %u fd %d index %u num %u",
		   txq->queue_id, fd, state.index, state.num);
	  _IOCTL (fd, VHOST_SET_VRING_NUM, &state);

	  addr.flags = 0;
	  addr.desc_user_addr = pointer_to_uword (txq->desc);
	  addr.avail_user_addr = pointer_to_uword (txq->avail);
	  addr.used_user_addr = pointer_to_uword (txq->used);

	  log_dbg (tif,
		   "VHOST_SET_VRING_ADDR txq %u fd %d index %u flags 0x%x "
		   "desc_user_addr 0x%lx avail_user_addr 0x%lx "
		   "used_user_addr 0x%lx",
		   txq->queue_id, fd, addr.index, addr.flags,
		   addr.desc_user_addr, addr.avail_user_addr,
		   addr.used_user_addr);
	  _IOCTL (fd, VHOST_SET_VRING_ADDR, &addr);

	  file.fd = txq->kick_fd;
	  log_dbg (tif,
		   "VHOST_SET_VRING_KICK txq %u fd %d index %u kick_fd %d",
		   txq->queue_id, fd, file.index, file.fd);
	  _IOCTL (fd, VHOST_SET_VRING_KICK, &file);

	  file.fd = tif->tap_fds[i % n_rxqs];
	  log_dbg (tif,
		   "VHOST_NET_SET_BACKEND txq %u fd %d index %u tap_fd %d",
		   txq->queue_id, fd, file.index, file.fd);
	  _IOCTL (fd, VHOST_NET_SET_BACKEND, &file);
	}
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
    {
      tap_txq_t *txq;
      tif->packet_coalesce = 1;
      vec_foreach (txq, tif->tx_queues)
	gro_flow_table_init (&txq->flow_table, (!tif->is_tun),
			     hw->tx_node_index);
    }

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
  if (is_tun)
    {
      bt->current_data = TUN_DATA_OFFSET;
      bt->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
      vnet_buffer (bt)->l3_hdr_offset = TUN_DATA_OFFSET;
    }
  else
    {
      bt->current_data = 0;
    }
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

  tap_free (vm, tif);

  return 0;
}

int
tap_dump_ifs (tap_interface_details_t **out_tapids)
{
  vnet_main_t *vnm = vnet_get_main ();
  tap_main_t *tm = &tap_main;
  tap_if_t *tif;
  tap_rxq_t *rxq;
  tap_txq_t *txq;
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
      rxq = tap_get_rx_queue (tif, 0);
      tapid->rx_ring_sz = rxq->queue_size;
      txq = tap_get_tx_queue (tif, 0);
      tapid->tx_ring_sz = txq->queue_size;
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
 */
__clib_export int
tap_set_carrier (u32 hw_if_index, u32 carrier_up)
{
  int ret = 0;
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
  tap_rxq_t *rxq = tap_get_rx_queue (tif, qid);

  if (mode == VNET_HW_IF_RX_MODE_POLLING)
    rxq->avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
  else
    rxq->avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;

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
  .tx_function_n_errors = TAP_TX_N_ERROR,
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
