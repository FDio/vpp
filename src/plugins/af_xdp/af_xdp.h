/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef _AF_XDP_H_
#define _AF_XDP_H_

#include <vlib/log.h>
#include <vnet/interface.h>
#include <xdp/xsk.h>
#include <linux/if_xdp.h>
#include <linux/bpf.h>

/* Fallback definitions for older kernel headers */
#ifndef XDP_PKT_CONTD
#define XDP_PKT_CONTD (1 << 0)
#endif

#ifndef XDP_USE_SG
#define XDP_USE_SG (1 << 4)
#endif

#ifndef BPF_F_XDP_HAS_FRAGS
#define BPF_F_XDP_HAS_FRAGS (1U << 5)
#endif

#define AF_XDP_NUM_RX_QUEUES_ALL ((u16) -1)

#define af_xdp_log(lvl, dev, f, ...)                                                               \
  vlib_log (lvl, af_xdp_main.log_class, "%v: " f, (dev)->name, ##__VA_ARGS__)

#define foreach_af_xdp_device_flags                                                                \
  _ (0, INITIALIZED, "initialized")                                                                \
  _ (1, ERROR, "error")                                                                            \
  _ (2, ADMIN_UP, "admin-up")                                                                      \
  _ (3, LINK_UP, "link-up")                                                                        \
  _ (4, ZEROCOPY, "zero-copy")                                                                     \
  _ (5, SYSCALL_LOCK, "syscall-lock")                                                              \
  _ (6, MULTIBUF, "multi-buffer")

enum
{
#define _(a, b, c) AF_XDP_DEVICE_F_##b = (1 << a),
  foreach_af_xdp_device_flags
#undef _
};

#define af_xdp_device_error(dev, fmt, ...)                                                         \
  if (!(dev)->error)                                                                               \
    {                                                                                              \
      clib_error_t *err_ = clib_error_return_unix (0, fmt, ##__VA_ARGS__);                         \
      if (!clib_atomic_bool_cmp_and_swap (&(dev)->error, 0, err_))                                 \
	clib_error_free (err_);                                                                    \
    }

typedef enum
{
  AF_XDP_RXQ_MODE_UNKNOWN,
  AF_XDP_RXQ_MODE_POLLING,
  AF_XDP_RXQ_MODE_INTERRUPT,
} __clib_packed af_xdp_rxq_mode_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* fields below are accessed in data-plane (hot) */

  clib_spinlock_t syscall_lock;
  struct xsk_ring_cons rx;
  struct xsk_ring_prod fq;
  int xsk_fd;

  /* fields below are accessed in control-plane only (cold) */

  uword file_index;
  u32 queue_index;
  af_xdp_rxq_mode_t mode;
} af_xdp_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* fields below are accessed in data-plane (hot) */

  clib_spinlock_t lock;
  clib_spinlock_t syscall_lock;
  struct xsk_ring_prod tx;
  struct xsk_ring_cons cq;
  int xsk_fd;
  u32 n_tx_desc; /* number of descriptors to submit (for multi-buffer) */

  /* fields below are accessed in control-plane only (cold) */

  u32 queue_index;
} af_xdp_txq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* fields below are accessed in data-plane (hot) */

  af_xdp_rxq_t *rxqs;
  af_xdp_txq_t *txqs;
  vlib_buffer_t *buffer_template;
  u32 per_interface_next_index;
  u32 sw_if_index;
  u32 hw_if_index;
  u32 flags;
  u8 pool; /* buffer pool index */
  u8 txq_num;

  /* fields below are accessed in control-plane only (cold) */

  char *name;
  char *linux_ifname;
  u32 dev_instance;
  u8 hwaddr[6];

  u8 rxq_num;

  char *netns;

  struct xsk_umem **umem;
  struct xsk_socket **xsk;

  struct bpf_object *bpf_obj;
  unsigned linux_ifindex;

  /* error */
  clib_error_t *error;
} af_xdp_device_t;

typedef struct
{
  af_xdp_device_t *devices;
  vlib_log_class_t log_class;
  u16 msg_id_base;
} af_xdp_main_t;

extern af_xdp_main_t af_xdp_main;

typedef enum
{
  AF_XDP_MODE_AUTO = 0,
  AF_XDP_MODE_COPY = 1,
  AF_XDP_MODE_ZERO_COPY = 2,
} af_xdp_mode_t;

typedef enum
{
  AF_XDP_CREATE_FLAGS_NO_SYSCALL_LOCK = 1,
} af_xdp_create_flag_t;

typedef struct
{
  char *linux_ifname;
  char *name;
  char *prog;
  char *netns;
  af_xdp_mode_t mode;
  af_xdp_create_flag_t flags;
  u32 rxq_size;
  u32 txq_size;
  u32 rxq_num;

  /* return */
  int rv;
  u32 sw_if_index;
  clib_error_t *error;
} af_xdp_create_if_args_t;

void af_xdp_create_if (vlib_main_t *vm, af_xdp_create_if_args_t *args);
void af_xdp_delete_if (vlib_main_t *vm, af_xdp_device_t *ad);

void af_xdp_device_input_refill (af_xdp_device_t *ad);

extern vlib_node_registration_t af_xdp_input_node;
extern vnet_device_class_t af_xdp_device_class;

/* format.c */
format_function_t format_af_xdp_device;
format_function_t format_af_xdp_device_name;
format_function_t format_af_xdp_input_trace;

/* unformat.c */
unformat_function_t unformat_af_xdp_create_if_args;

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
} af_xdp_input_trace_t;

#define foreach_af_xdp_tx_func_error                                                               \
  _ (NO_FREE_SLOTS, "no free tx slots")                                                            \
  _ (SYSCALL_REQUIRED, "syscall required")                                                         \
  _ (SYSCALL_FAILURES, "syscall failures")

typedef enum
{
#define _(f, s) AF_XDP_TX_ERROR_##f,
  foreach_af_xdp_tx_func_error
#undef _
    AF_XDP_TX_N_ERROR,
} af_xdp_tx_func_error_t;

#endif /* _AF_XDP_H_ */
