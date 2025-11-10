/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef _DEV_VIRTIO_VIRTIO_H_
#define _DEV_VIRTIO_VIRTIO_H_

#include <vnet/devices/virtio/virtio_std.h>
#include <vnet/devices/virtio/vhost_std.h>
#include <dev_virtio/buffering.h>
#include <vnet/gso/gro.h>
#include <vnet/gso/hdr_offset_parser.h>
#include <vnet/interface.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#define TX_QUEUE(X)	   ((X * 2) + 1)
#define RX_QUEUE(X)	   (X * 2)
#define TX_QUEUE_ACCESS(X) (X / 2)
#define RX_QUEUE_ACCESS(X) (X / 2)

#define VIRTIO_NUM_RX_DESC 256
#define VIRTIO_NUM_TX_DESC 256

#define VIRTIO_EVENT_START_TIMER 1
#define VIRTIO_EVENT_STOP_TIMER	 2

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lockp;
  union
  {
    struct
    {
      vnet_virtio_vring_desc_t *desc;
      vnet_virtio_vring_used_t *used;
      vnet_virtio_vring_avail_t *avail;
    };
    struct
    {
      vnet_virtio_vring_packed_desc_t *packed_desc;
      vnet_virtio_vring_desc_event_t *driver_event;
      vnet_virtio_vring_desc_event_t *device_event;
    };
  };
  u32 *buffers;
  u16 queue_size;
  u16 queue_id;
  u32 queue_index;
  u16 desc_in_use;
  u16 desc_next;
  u16 last_used_idx;
  struct
  {
    u16 avail_wrap_counter;
    u16 used_wrap_counter;
    u16 queue_notify_offset;
  };
#define VRING_TX_OUT_OF_ORDER 1
#define VRING_TX_SCHEDULED    2
  u16 flags;
  u8 buffer_pool_index;
  vnet_hw_if_rx_mode mode;
  virtio_vring_buffering_t *buffering;
  u64 total_packets;
} vnet_virtio_vring_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 features;
  u32 flags;
  u8 gso_enabled;
  u8 csum_offload_enabled;
  u8 rss_enabled;
  u8 is_packed;
  u8 packet_buffering;
  struct
  {
    u32 pci_dev_handle;
    u32 msix_enabled;
  };
  u16 virtio_net_hdr_sz;

  u32 hw_if_index;
  u32 sw_if_index;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u32 buffering_size;
  u32 numa_node;
  u64 remote_features;

  /* error */
  clib_error_t *error;
  union
  {
    struct
    {
      u32 mac_addr32;
      u16 mac_addr16;
    };
    u8 mac_addr[6];
  };
  struct /* native virtio */
  {
    void *bar;
    vnet_virtio_vring_t *cxq_vring;
    u32 bar_id;
    u32 notify_off_multiplier;
    u16 common_offset;
    u16 notify_offset;
    u16 device_offset;
    u16 isr_offset;
    u16 max_queue_pairs;
    u16 msix_table_size;
    u8 support_int_mode; /* support interrupt mode */
    u8 status;
  };
  u16 n_rx_vectors;
  u32 dev_index; /* dev index */
} virtio_if_t;

typedef struct
{
  u32 dev_instance;
} virtio_device_t;

typedef struct
{
  u32 buffering_if_count;
  virtio_if_t *interfaces;
} virtio_main_t;

#define foreach_virtio_arg_type                                               \
  _ (1, BUFFERING)                                                            \
  _ (2, BUFFERING_SIZE)                                                       \
  _ (3, PACKED)                                                               \
  _ (4, RSS)                                                                  \
  _ (5, GSO)                                                                  \
  _ (6, CSUM)                                                                 \
  _ (7, END)

typedef enum
{
#define _(b, n) VIRTIO_DEV_ARG_##n = (b),
  foreach_virtio_arg_type
#undef _
} virtio_arg_type_t;

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  u16 ring;
  u16 len;
  vnet_virtio_net_hdr_v1_t hdr;
} virtio_input_trace_t;

typedef struct
{
  u32 buffer_index;
  u32 sw_if_index;
  generic_header_offset_t gho;
  vlib_buffer_t buffer;
} virtio_tx_trace_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
} virtio_port_t;

typedef struct
{
  vnet_virtio_vring_t vring;
} virtio_txq_t;

typedef struct
{
  vnet_virtio_vring_t vring;
} virtio_rxq_t;

/* format.c */
format_function_t format_virtio_rx_trace;
format_function_t format_virtio_tx_trace;
format_function_t format_virtio_port_status;
format_function_t format_virtio_rx_queue_format_info;
format_function_t format_virtio_tx_queue_format_info;

/* port.c */
void virtio_msix_n_handler (vlib_main_t *vm, vnet_dev_t *dev, u16 line);
vnet_dev_rv_t virtio_port_init (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t virtio_port_start (vlib_main_t *, vnet_dev_port_t *);
void virtio_port_stop (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t virtio_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				      vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t
virtio_port_cfg_change_validate (vlib_main_t *, vnet_dev_port_t *,
				 vnet_dev_port_cfg_change_req_t *);

/* queue.c */
vnet_dev_rv_t virtio_rx_queue_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t virtio_tx_queue_alloc (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t virtio_rx_queue_start (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t virtio_tx_queue_start (vlib_main_t *, vnet_dev_tx_queue_t *);
void virtio_rx_queue_stop (vlib_main_t *, vnet_dev_rx_queue_t *);
void virtio_tx_queue_stop (vlib_main_t *, vnet_dev_tx_queue_t *);
void virtio_rx_queue_free (vlib_main_t *, vnet_dev_rx_queue_t *);
void virtio_tx_queue_free (vlib_main_t *, vnet_dev_tx_queue_t *);

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, virtio_log.class, "%U" f,                   \
	    format_vnet_dev_log, (dev),                                       \
	    clib_string_skip_prefix (__func__, "virtio_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, virtio_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, virtio_log.class, "%U: " f,                \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_warning(dev, f, ...)                                              \
  vlib_log (VLIB_LOG_LEVEL_WARNING, virtio_log.class, "%U: " f,               \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_error(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_ERR, virtio_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)

#define foreach_virtio_tx_node_counter                                        \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")

typedef enum
{
#define _(f, n, s, d) VIRTIO_TX_NODE_##f,
  foreach_virtio_tx_node_counter
#undef _
} virtio_tx_node_counter_t;

#define foreach_virtio_rx_node_counter                                        \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "buffer alloc error")                 \
  _ (FULL_RX_QUEUE, full_rx_queue, ERROR, "full rx queue (driver tx drop)")   \
  _ (UNKNOWN, uknown, ERROR, "unknown")

typedef enum
{
#define _(f, n, s, d) VIRTIO_INPUT_ERROR_##f,
  foreach_virtio_rx_node_counter
#undef _
} virtio_rx_node_counter_t;

extern virtio_main_t virtio_main;

extern void virtio_vring_fill (vlib_main_t *vm, virtio_if_t *vif,
			       vnet_virtio_vring_t *vring,
			       vlib_node_runtime_t *node);
void virtio_vring_free_rx (vlib_main_t *vm, vnet_dev_t *dev,
			   vnet_virtio_vring_t *vring);
void virtio_vring_free_tx (vlib_main_t *vm, vnet_dev_t *dev,
			   vnet_virtio_vring_t *vring);
extern void virtio_set_net_hdr_size (virtio_if_t *vif);
clib_error_t *virtio_set_packet_buffering (vnet_dev_tx_queue_t *txq, u16 size);
extern void virtio_pci_notify_queue (vlib_main_t *vm, virtio_if_t *vif,
				     u16 queue_id, u16 queue_notify_offset);
extern void virtio_pre_input_node_enable (vlib_main_t *vm, virtio_if_t *vif);
extern void virtio_pre_input_node_disable (vlib_main_t *vm, virtio_if_t *vif);

static_always_inline void
virtio_kick (vlib_main_t *vm, vnet_virtio_vring_t *vring, virtio_if_t *vif)
{
  virtio_pci_notify_queue (vm, vif, vring->queue_id,
			   vring->queue_notify_offset);
}

static_always_inline u8
virtio_txq_is_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    return (vring->flags & VRING_TX_SCHEDULED);
  return 1;
}

static_always_inline void
virtio_txq_set_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    vring->flags |= VRING_TX_SCHEDULED;
}

static_always_inline void
virtio_txq_clear_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    vring->flags &= ~VRING_TX_SCHEDULED;
}

static_always_inline void
vnet_virtio_vring_init (vnet_virtio_vring_t *vring, u16 queue_size, void *p,
			u32 align)
{
  vring->queue_size = queue_size;
  vring->desc = p;
  vring->avail =
    (vnet_virtio_vring_avail_t *) ((char *) p +
				   queue_size *
				     sizeof (vnet_virtio_vring_desc_t));
  vring->used =
    (vnet_virtio_vring_used_t
       *) ((char *) p + ((sizeof (vnet_virtio_vring_desc_t) * queue_size +
			  sizeof (u16) * (3 + queue_size) + align - 1) &
			 ~(align - 1)));
  vring->avail->flags = VRING_AVAIL_F_NO_INTERRUPT;
}

static_always_inline u16
vnet_virtio_vring_size (u16 queue_size, u32 align)
{
  return ((sizeof (vnet_virtio_vring_desc_t) * queue_size +
	   sizeof (u16) * (3 + queue_size) + align - 1) &
	  ~(align - 1)) +
	 sizeof (u16) * 3 +
	 sizeof (vnet_virtio_vring_used_elem_t) * queue_size;
}

static_always_inline virtio_if_t *
virtio_vnet_dev_get_if (vnet_dev_t *dev)
{
  virtio_main_t *vim = &virtio_main;
  virtio_device_t *vd = vnet_dev_get_data (dev);
  virtio_if_t *vif = pool_elt_at_index (vim->interfaces, vd->dev_instance);

  return vif;
}

static_always_inline virtio_if_t *
virtio_vnet_dev_get_if_valid (vnet_dev_t *dev)
{
  virtio_main_t *vim = &virtio_main;
  virtio_device_t *vd = vnet_dev_get_data (dev);
  virtio_if_t *vif;

  if (pool_is_free_index (vim->interfaces, vd->dev_instance))
    return 0;
  vif = pool_elt_at_index (vim->interfaces, vd->dev_instance);

  return vif;
}

#endif /* _DEV_VIRTIO_VIRTIO_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
