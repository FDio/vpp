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

#ifndef _AF_XDP_H_
#define _AF_XDP_H_

#include <vlib/log.h>
#include <vnet/interface.h>
#include <bpf/xsk.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_8_16.h>

#define AF_XDP_NUM_RX_QUEUES_ALL        ((u16)-1)

#define af_xdp_log(lvl, dev, f, ...) \
  vlib_log(lvl, af_xdp_main.log_class, "%v: " f, (dev)->name, ##__VA_ARGS__)

#define foreach_af_xdp_device_flags                                           \
  _ (0, INITIALIZED, "initialized")                                           \
  _ (1, ERROR, "error")                                                       \
  _ (2, ADMIN_UP, "admin-up")                                                 \
  _ (3, LINK_UP, "link-up")                                                   \
  _ (4, ZEROCOPY, "zero-copy")

enum
{
#define _(a, b, c) AF_XDP_DEVICE_F_##b = (1 << a),
  foreach_af_xdp_device_flags
#undef _
};

#define af_xdp_device_error(dev, fmt, ...) \
  if (!(dev)->error) \
    { \
      clib_error_t *err_ = clib_error_return_unix (0, fmt, ## __VA_ARGS__); \
      if (!clib_atomic_bool_cmp_and_swap (&(dev)->error, 0, err_)) \
        clib_error_free(err_); \
    }

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* fields below are accessed in data-plane (hot) */

  struct xsk_ring_cons rx;
  struct xsk_ring_prod fq;
  int xsk_fd;

  /* fields below are accessed in control-plane only (cold) */

  uword file_index;
  u32 queue_index;
  u8 is_polling;
} af_xdp_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* fields below are accessed in data-plane (hot) */

  clib_spinlock_t lock;
  struct xsk_ring_prod tx;
  struct xsk_ring_cons cq;
  int xsk_fd;
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
  u8 pool;			/* buffer pool index */
  u8 txq_num;

  /* fields below are accessed in control-plane only (cold) */

  char *name;
  char *linux_ifname;
  u32 dev_instance;
  u8 hwaddr[6];

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
  clib_bihash_8_8_t bhash;
  clib_bihash_8_16_t bhashlog;
} af_xdp_main_t;

extern af_xdp_main_t af_xdp_main;

typedef enum
{
  AF_XDP_MODE_AUTO = 0,
  AF_XDP_MODE_COPY = 1,
  AF_XDP_MODE_ZERO_COPY = 2,
} af_xdp_mode_t;

typedef struct
{
  char *linux_ifname;
  char *name;
  char *prog;
  af_xdp_mode_t mode;
  u32 rxq_size;
  u32 txq_size;
  u32 rxq_num;

  /* return */
  int rv;
  u32 sw_if_index;
  clib_error_t *error;
} af_xdp_create_if_args_t;

void af_xdp_create_if (vlib_main_t * vm, af_xdp_create_if_args_t * args);
void af_xdp_delete_if (vlib_main_t * vm, af_xdp_device_t * ad);

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

#define foreach_af_xdp_tx_func_error \
_(NO_FREE_SLOTS, "no free tx slots") \
_(SENDTO_REQUIRED, "sendto required") \
_(SENDTO_FAILURES, "sendto failures")

typedef enum
{
#define _(f,s) AF_XDP_TX_ERROR_##f,
  foreach_af_xdp_tx_func_error
#undef _
    AF_XDP_TX_N_ERROR,
} af_xdp_tx_func_error_t;

#endif /* _AF_XDP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
