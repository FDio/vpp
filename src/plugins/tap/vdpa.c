/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <vlib/vlib.h>
#include <vlib/file.h>
#include <tap/internal.h>

#define TAP_VDPA_DEFAULT_RING_SZ 256
#define TAP_VDPA_CVQ_SZ		 4

#define _IOCTL(fd, a, ...)                                                                         \
  if (ioctl (fd, a, __VA_ARGS__) < 0)                                                              \
    return clib_error_return_unix (0, "ioctl(" #a ")");

static clib_error_t *
tap_vdpa_set_status (tap_if_t *tif, int fd, u8 status)
{
  u8 rv;

  _IOCTL (fd, VHOST_VDPA_SET_STATUS, &status);
  _IOCTL (fd, VHOST_VDPA_GET_STATUS, &rv);

  if (rv != status)
    return clib_error_return (0, "device status 0x%x, expected 0x%x", rv, status);

  log_dbg (tif, "status 0x%x", status);
  return 0;
}

static clib_error_t *
tap_vdpa_iotlb_msg (int fd, u8 type, u64 iova, u64 uaddr, u64 size)
{
  vhost_msg_v2_t msg = {
    .type = VHOST_IOTLB_MSG_V2,
    .iotlb = {
      .iova = iova,
      .size = size,
      .uaddr = uaddr,
      .perm = VHOST_ACCESS_RW,
      .type = type,
    },
  };

  if (write (fd, &msg, sizeof (msg)) != sizeof (msg))
    return clib_error_return_unix (0, "iotlb msg type %u iova 0x%lx", type, iova);
  return 0;
}

/* mlx5_vdpa derives its MTT page size from the map sizes, so map one
 * physmem page per message to keep translation pages aligned to iova */
static clib_error_t *
tap_vdpa_dma_map (vlib_main_t *vm, tap_if_t *tif, int fd, int batch)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  u64 start = pointer_to_uword (pm->base);
  u64 page_sz = 1ULL << pm->def_log2_page_sz;
  u64 size = vec_len (pm->pages) * page_sz;
  struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
  vhost_vdpa_iova_range_t range;
  clib_error_t *err;

  _IOCTL (fd, VHOST_VDPA_GET_IOVA_RANGE, &range);

  if (start < range.first || start + size - 1 > range.last)
    return clib_error_return (0,
			      "physmem 0x%lx-0x%lx outside of device iova "
			      "range 0x%lx-0x%lx",
			      start, start + size - 1, range.first, range.last);

  /* vhost-vdpa accounts pinned pages against RLIMIT_MEMLOCK */
  if (setrlimit (RLIMIT_MEMLOCK, &rl) < 0)
    log_warn (tif, "failed to raise RLIMIT_MEMLOCK");

  if (batch && (err = tap_vdpa_iotlb_msg (fd, VHOST_IOTLB_BATCH_BEGIN, 0, 0, 0)))
    return err;

  for (u64 off = 0; off < size; off += page_sz)
    if ((err = tap_vdpa_iotlb_msg (fd, VHOST_IOTLB_UPDATE, start + off, start + off, page_sz)))
      return err;

  if (batch && (err = tap_vdpa_iotlb_msg (fd, VHOST_IOTLB_BATCH_END, 0, 0, 0)))
    return err;

  log_dbg (tif, "iotlb map iova 0x%lx size 0x%lx page size 0x%lx%s", start, size, page_sz,
	   batch ? " batch" : "");
  return 0;
}

static clib_error_t *
tap_vdpa_vring_init (tap_if_t *tif, int fd, u32 index, u16 size, vnet_virtio_vring_desc_t *desc,
		     vnet_virtio_vring_avail_t *avail, vnet_virtio_vring_used_t *used, int kick_fd,
		     int call_fd, u8 enable)
{
  vhost_vring_state_t state = { .index = index, .num = size };
  vhost_vring_addr_t addr = {
    .index = index,
    .desc_user_addr = pointer_to_uword (desc),
    .avail_user_addr = pointer_to_uword (avail),
    .used_user_addr = pointer_to_uword (used),
  };
  vhost_vring_file_t file = { .index = index, .fd = kick_fd };

  _IOCTL (fd, VHOST_SET_VRING_NUM, &state);
  state.num = 0;
  _IOCTL (fd, VHOST_SET_VRING_BASE, &state);
  _IOCTL (fd, VHOST_SET_VRING_ADDR, &addr);
  _IOCTL (fd, VHOST_SET_VRING_KICK, &file);
  file.fd = call_fd;
  _IOCTL (fd, VHOST_SET_VRING_CALL, &file);
  state.num = enable;
  _IOCTL (fd, VHOST_VDPA_SET_VRING_ENABLE, &state);

  log_dbg (tif, "vq %u size %u kick_fd %d call_fd %d desc %p avail %p used %p", index, size,
	   kick_fd, call_fd, desc, avail, used);
  return 0;
}

typedef struct
{
  vnet_virtio_vring_desc_t desc[TAP_VDPA_CVQ_SZ];
  u16 avail[2 + TAP_VDPA_CVQ_SZ];
  u32 used[1 + 2 * TAP_VDPA_CVQ_SZ];
} tap_vdpa_ring_t;

typedef struct
{
  tap_vdpa_ring_t cvq;
  tap_vdpa_ring_t idle;
  u8 hdr[2];
  u8 data[16];
  u8 ack;
} tap_vdpa_cvq_t;

static clib_error_t *
tap_vdpa_cvq_cmd (tap_if_t *tif, u8 class, u8 cmd, const void *data, u16 len)
{
  tap_vdpa_cvq_t *c = tif->vdpa_cvq;
  vnet_virtio_vring_desc_t *desc = c->cvq.desc;
  vnet_virtio_vring_avail_t *avail = (vnet_virtio_vring_avail_t *) c->cvq.avail;
  vnet_virtio_vring_used_t *used = (vnet_virtio_vring_used_t *) c->cvq.used;
  u16 idx = avail->idx;
  f64 timeout = unix_time_now () + 1;

  ASSERT (len <= sizeof (c->data));
  c->hdr[0] = class;
  c->hdr[1] = cmd;
  clib_memcpy (c->data, data, len);
  c->ack = ~0;
  desc[0] = (vnet_virtio_vring_desc_t) {
    .addr = pointer_to_uword (c->hdr),
    .len = sizeof (c->hdr),
    .flags = VRING_DESC_F_NEXT,
    .next = 1,
  };
  desc[1] = (vnet_virtio_vring_desc_t) {
    .addr = pointer_to_uword (c->data),
    .len = len,
    .flags = VRING_DESC_F_NEXT,
    .next = 2,
  };
  desc[2] = (vnet_virtio_vring_desc_t) {
    .addr = pointer_to_uword (&c->ack),
    .len = sizeof (c->ack),
    .flags = VRING_DESC_F_WRITE,
  };
  avail->ring[idx & (TAP_VDPA_CVQ_SZ - 1)] = 0;
  __atomic_store_n (&avail->idx, idx + 1, __ATOMIC_RELEASE);

  if (write (tif->vdpa_cvq_kick_fd, &(u64) { 1 }, sizeof (u64)) != sizeof (u64))
    return clib_error_return_unix (0, "control queue kick");

  while (__atomic_load_n (&used->idx, __ATOMIC_ACQUIRE) == idx)
    {
      if (unix_time_now () > timeout)
	return clib_error_return (0, "control command %u/%u timed out", class, cmd);
      unix_sleep (1e-4);
    }

  if (c->ack != VIRTIO_NET_OK)
    return clib_error_return (0, "control command %u/%u failed (ack %u)", class, cmd, c->ack);

  log_dbg (tif, "control command %u/%u done", class, cmd);
  return 0;
}

static u16 *
tap_vdpa_notify_map (tap_if_t *tif, int fd, u32 index)
{
  uword page_sz = clib_mem_get_page_size ();
  void *p = mmap (0, page_sz, PROT_WRITE, MAP_SHARED, fd, index * page_sz);

  if (p == MAP_FAILED)
    {
      log_dbg (tif, "vq %u notification area not mappable, using kick fd", index);
      return 0;
    }

  log_dbg (tif, "vq %u notification area mapped at %p", index, p);
  return p;
}

static clib_error_t *
tap_vdpa_link_read (tap_if_t *tif)
{
  u8 cfg_buf[sizeof (vhost_vdpa_config_t) + 2] __clib_aligned (8)
  = {};
  vhost_vdpa_config_t *cfg = (vhost_vdpa_config_t *) cfg_buf;
  u16 status;

  if ((tif->features & VIRTIO_NET_F_STATUS_BIT) == 0)
    {
      tif->vdpa_link_up = 1;
      return 0;
    }

  cfg->off = 6;
  cfg->len = sizeof (status);
  _IOCTL (tif->vhost_fds[0], VHOST_VDPA_GET_CONFIG, cfg);
  clib_memcpy (&status, cfg->buf, sizeof (status));
  tif->vdpa_link_up = (status & VIRTIO_NET_S_LINK_UP) != 0;
  log_dbg (tif, "link %s", tif->vdpa_link_up ? "up" : "down");
  return 0;
}

void
tap_vdpa_set_link_flags (tap_if_t *tif)
{
  u32 flags = tif->admin_up && tif->vdpa_link_up ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnet_get_main (), tif->hw_if_index, flags);
}

static clib_error_t *
tap_vdpa_config_ready (clib_file_t *f)
{
  tap_if_t *tif = pool_elt_at_index (tap_main.interfaces, f->private_data);
  clib_error_t *err;
  u64 b;

  if (read (f->file_descriptor, &b, sizeof (b)) != sizeof (b))
    return 0;

  if ((err = tap_vdpa_link_read (tif)))
    log_err (tif, "%U", format_clib_error, err);
  else
    tap_vdpa_set_link_flags (tif);
  clib_error_free (err);
  return 0;
}

static clib_error_t *
tap_vdpa_config_call_init (tap_if_t *tif, int fd)
{
  int efd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  clib_file_t f = {
    .read_function = tap_vdpa_config_ready,
    .file_descriptor = efd,
    .private_data = tif->dev_instance,
    .description = format (0, "%U config", format_tap_log_name, tif),
  };

  if (efd < 0)
    return clib_error_return_unix (0, "eventfd");

  if (ioctl (fd, VHOST_VDPA_SET_CONFIG_CALL, &efd) < 0)
    {
      close (efd);
      vec_free (f.description);
      return clib_error_return_unix (0, "ioctl(VHOST_VDPA_SET_CONFIG_CALL)");
    }

  tif->vdpa_config_fd = efd;
  tif->vdpa_config_file_index = clib_file_add (&file_main, &f);
  return 0;
}

clib_error_t *
tap_vdpa_set_mac (tap_if_t *tif, const u8 *mac)
{
  if ((tif->features & VIRTIO_NET_F_CTRL_MAC_ADDR_BIT) == 0)
    return clib_error_return (0, "device doesn't support changing the MAC address");

  return tap_vdpa_cvq_cmd (tif, VIRTIO_NET_CTRL_MAC, VIRTIO_NET_CTRL_MAC_ADDR_SET, mac, 6);
}

clib_error_t *
tap_vdpa_init (vlib_main_t *vm, tap_if_t *tif, tap_create_if_args_t *args)
{
  const u64 required = VIRTIO_F_VERSION_1_BIT | VIRTIO_F_ACCESS_PLATFORM_BIT;
  u64 optional = VIRTIO_RING_F_INDIRECT_DESC_BIT | VIRTIO_NET_F_MAC_BIT | VIRTIO_NET_F_STATUS_BIT |
		 VIRTIO_NET_F_MRG_RXBUF_BIT;
  u64 offloads = 0, backend_features;
  u8 cfg_buf[sizeof (vhost_vdpa_config_t) + 8] __clib_aligned (8)
  = {};
  vhost_vdpa_config_t *cfg = (vhost_vdpa_config_t *) cfg_buf;
  const u64 mq = VIRTIO_NET_F_MQ_BIT | VIRTIO_NET_F_CTRL_VQ_BIT;
  u32 device_id, n_vqs;
  u16 max_ring_sz, rx_sz, tx_sz, max_pairs = 1;
  u8 set_mac = 0;
  u16 n_pairs = clib_max (1, clib_max (args->num_rx_queues, args->num_tx_queues));
  clib_error_t *err;
  int fd;

  tif->host_if_name = format (0, "%v%c", args->vdpa_path, 0);
  tif->vdpa_config_fd = -1;

  fd = open ((char *) tif->host_if_name, O_RDWR | O_CLOEXEC);
  if (fd < 0)
    return clib_error_return_unix (0, "open '%s'", tif->host_if_name);
  vec_add1 (tif->vhost_fds, fd);

  _IOCTL (fd, VHOST_VDPA_GET_DEVICE_ID, &device_id);
  if (device_id != VIRTIO_ID_NET)
    return clib_error_return (0, "not a virtio-net device (id %u)", device_id);

  _IOCTL (fd, VHOST_VDPA_GET_VQS_COUNT, &n_vqs);
  if (n_vqs < 2)
    return clib_error_return (0, "device has %u virtqueues", n_vqs);

  _IOCTL (fd, VHOST_VDPA_GET_VRING_NUM, &max_ring_sz);
  rx_sz = args->rx_ring_sz ? args->rx_ring_sz : clib_min (TAP_VDPA_DEFAULT_RING_SZ, max_ring_sz);
  tx_sz = args->tx_ring_sz ? args->tx_ring_sz : clib_min (TAP_VDPA_DEFAULT_RING_SZ, max_ring_sz);
  if (rx_sz > max_ring_sz || tx_sz > max_ring_sz)
    return clib_error_return (0, "ring size must be %u or lower", max_ring_sz);

  _IOCTL (fd, VHOST_SET_OWNER, 0);

  _IOCTL (fd, VHOST_GET_BACKEND_FEATURES, &backend_features);
  if ((backend_features & (1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2)) == 0)
    return clib_error_return (0, "iotlb v2 messages not supported");
  backend_features &=
    (1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2) | (1ULL << VHOST_BACKEND_F_IOTLB_BATCH);
  _IOCTL (fd, VHOST_SET_BACKEND_FEATURES, &backend_features);

  _IOCTL (fd, VHOST_GET_FEATURES, &tif->remote_features);
  log_dbg (tif, "device features 0x%lx\n%U", tif->remote_features, format_virtio_features,
	   tif->remote_features);

  if ((tif->remote_features & required) != required)
    return clib_error_return (0, "device doesn't support following mandatory features:\n %U",
			      format_virtio_features, (tif->remote_features & required) ^ required);

  if (args->tap_flags & TAP_FLAG_GSO)
    {
      offloads = VIRTIO_NET_F_CSUM_BIT | VIRTIO_NET_F_HOST_TSO4_BIT | VIRTIO_NET_F_HOST_TSO6_BIT;
      tif->gso_enabled = 1;
      tif->csum_offload_enabled = 1;
    }
  else if (args->tap_flags & TAP_FLAG_CSUM_OFFLOAD)
    {
      offloads = VIRTIO_NET_F_CSUM_BIT;
      tif->csum_offload_enabled = 1;
    }

  if ((tif->remote_features & offloads) != offloads)
    return clib_error_return (0, "device doesn't support offloads:\n %U", format_virtio_features,
			      (tif->remote_features & offloads) ^ offloads);

  if (tif->csum_offload_enabled)
    optional |= VIRTIO_NET_F_GUEST_CSUM_BIT;

  if (tif->remote_features & VIRTIO_NET_F_CTRL_VQ_BIT)
    optional |= VIRTIO_NET_F_CTRL_VQ_BIT | VIRTIO_NET_F_CTRL_MAC_ADDR_BIT;

  /* mlx5_vdpa instantiates all data vqs and fails to start with unused ones
   * unless MQ is negotiated, so negotiate it whenever offered */
  if ((tif->remote_features & mq) == mq)
    {
      cfg->off = 8;
      cfg->len = sizeof (max_pairs);
      _IOCTL (fd, VHOST_VDPA_GET_CONFIG, cfg);
      clib_memcpy (&max_pairs, cfg->buf, sizeof (max_pairs));
      optional |= mq;
    }
  else if (n_vqs > 3)
    return clib_error_return (0, "device has %u vqs but doesn't support multiqueue", n_vqs);

  if (n_pairs > max_pairs)
    return clib_error_return (0, "device supports up to %u queue pairs", max_pairs);

  tif->features = required | offloads | (tif->remote_features & optional);

  if ((err = tap_vdpa_set_status (tif, fd, 0)) ||
      (err = tap_vdpa_set_status (tif, fd, VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER)))
    return err;

  _IOCTL (fd, VHOST_SET_FEATURES, &tif->features);
  log_dbg (tif, "features 0x%lx\n%U", tif->features, format_virtio_features, tif->features);

  err = tap_vdpa_set_status (
    tif, fd, VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER | VIRTIO_CONFIG_S_FEATURES_OK);
  if (err)
    return err;

  for (u16 i = 0; i < n_pairs; i++)
    if ((err = tap_rxq_init (tif, i, rx_sz)) || (err = tap_tx_vring_init (tif, i, tx_sz)))
      return err;

  if (tif->features & VIRTIO_NET_F_CTRL_VQ_BIT)
    {
      tif->vdpa_cvq =
	vlib_physmem_alloc_aligned (vm, sizeof (tap_vdpa_cvq_t), CLIB_CACHE_LINE_BYTES);
      if (tif->vdpa_cvq == 0)
	return clib_error_return (0, "control queue alloc failed");
      clib_memset (tif->vdpa_cvq, 0, sizeof (tap_vdpa_cvq_t));
      tif->vdpa_cvq_kick_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
    }

  err =
    tap_vdpa_dma_map (vm, tif, fd, (backend_features & (1ULL << VHOST_BACKEND_F_IOTLB_BATCH)) != 0);
  if (err)
    return err;

  for (u16 i = 0; i < n_pairs; i++)
    {
      tap_rxq_t *rxq = tap_get_rx_queue (tif, i);
      tap_txq_t *txq = tap_get_tx_queue (tif, i);

      err = tap_vdpa_vring_init (tif, fd, 2 * i, rxq->queue_size, rxq->desc, rxq->avail, rxq->used,
				 rxq->kick_fd, rxq->call_fd, 1);
      if (err)
	return err;
      rxq->notify = tap_vdpa_notify_map (tif, fd, 2 * i);
      rxq->notify_data = 2 * i;

      err = tap_vdpa_vring_init (tif, fd, 2 * i + 1, txq->queue_size, txq->desc, txq->avail,
				 txq->used, txq->kick_fd, -1, 1);
      if (err)
	return err;
      txq->notify = tap_vdpa_notify_map (tif, fd, 2 * i + 1);
      txq->notify_data = 2 * i + 1;
    }

  if (tif->vdpa_cvq)
    {
      tap_vdpa_cvq_t *c = tif->vdpa_cvq;

      err = tap_vdpa_vring_init (tif, fd, 2 * max_pairs, TAP_VDPA_CVQ_SZ, c->cvq.desc,
				 (vnet_virtio_vring_avail_t *) c->cvq.avail,
				 (vnet_virtio_vring_used_t *) c->cvq.used, tif->vdpa_cvq_kick_fd,
				 -1, 1);
      if (err)
	return err;

      /* mlx5_vdpa creates hw objects for all data vqs on DRIVER_OK, so vqs
       * beyond the active pairs need a valid (empty) ring */
      for (u16 i = 2 * n_pairs; i < 2 * max_pairs; i++)
	{
	  err = tap_vdpa_vring_init (tif, fd, i, TAP_VDPA_CVQ_SZ, c->idle.desc,
				     (vnet_virtio_vring_avail_t *) c->idle.avail,
				     (vnet_virtio_vring_used_t *) c->idle.used, -1, -1, 0);
	  if (err)
	    return err;
	}
    }

  if (tif->features & VIRTIO_NET_F_MAC_BIT)
    {
      cfg->off = 0;
      cfg->len = 8;
      _IOCTL (fd, VHOST_VDPA_GET_CONFIG, cfg);

      if (!args->mac_addr_set)
	{
	  clib_memcpy (args->mac_addr.bytes, cfg->buf, 6);
	  args->mac_addr_set = 1;
	}
      else if (memcmp (args->mac_addr.bytes, cfg->buf, 6))
	set_mac = 1;
    }

  if ((tif->features & VIRTIO_NET_F_STATUS_BIT) && (err = tap_vdpa_config_call_init (tif, fd)))
    return err;

  if ((err = tap_vdpa_link_read (tif)))
    return err;

  err = tap_vdpa_set_status (tif, fd,
			     VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER |
			       VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_S_DRIVER_OK);
  if (err)
    return err;

  if (n_pairs > 1 &&
      (err = tap_vdpa_cvq_cmd (tif, VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, &n_pairs,
			       sizeof (n_pairs))))
    return err;

  return set_mac ? tap_vdpa_set_mac (tif, args->mac_addr.bytes) : 0;
}

void
tap_vdpa_free (vlib_main_t *vm, tap_if_t *tif)
{
  if (tif->is_vdpa == 0)
    return;

  if (tif->vdpa_config_fd >= 0)
    {
      clib_file_del_by_index (&file_main, tif->vdpa_config_file_index);
      tif->vdpa_config_fd = -1;
    }

  if (tif->vdpa_cvq)
    {
      close (tif->vdpa_cvq_kick_fd);
      vlib_physmem_free (vm, tif->vdpa_cvq);
      tif->vdpa_cvq = 0;
    }
}
