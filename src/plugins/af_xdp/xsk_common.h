/*
 * xsk_defs.h - linux xdp interface
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 */

#ifndef xsk_defs
#define xsk_defs

#include <bpf/xsk.h>

#include <stdbool.h>
#include <sys/socket.h>
//#include <linux/if_xdp.h>
// temporarily use custom copy, i.e. <af_xdp/if_xdp.h>
// (see CMakeLists for details)
#include <af_xdp/if_xdp.h>

#define XSKMAP_NAME "xsks_map"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define FRAME_SIZE           XSK_UMEM__DEFAULT_FRAME_SIZE
#define FRAME_HEADROOM       0

#define PROD_RING_NUM_FRAMES XSK_RING_PROD__DEFAULT_NUM_DESCS
#define CONS_RING_NUM_FRAMES XSK_RING_CONS__DEFAULT_NUM_DESCS

#define UMEM_NUM_FRAMES (4 * (PROD_RING_NUM_FRAMES + CONS_RING_NUM_FRAMES))
#define UMEM_RX_NUM_FRAMES   (UMEM_NUM_FRAMES / 2)
#define UMEM_TX_NUM_FRAMES   (UMEM_NUM_FRAMES / 2)

#define RX_BATCH_SIZE VLIB_FRAME_SIZE

#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info
{
  struct xsk_ring_prod fq;
  struct xsk_ring_cons cq;
  struct xsk_umem *umem;
  void *buffer;
};

struct xsk_socket_info
{
  struct xsk_ring_cons rx;
  struct xsk_ring_prod tx;
  struct xsk_umem_info *umem;
  struct xsk_socket *xsk;

  /* keep them separated to avoid locking of umem for concurent RX/TX */
  u64 umem_rx_frame_addr[UMEM_RX_NUM_FRAMES];
  u32 umem_rx_frame_free;
  u64 umem_tx_frame_addr[UMEM_TX_NUM_FRAMES];
  u32 umem_tx_frame_free;

  u32 reserved_tx_frames;
  u32 reserved_tx_idx;
  u32 outstanding_tx;

  u32 xdp_flags;
  u32 bind_flags;
  u32 prog_id;
  int prog_fd;
  int sfd;
  int xskmap_fd;
  u32 xskmap_key;
  u32 queue_id;
};

static_always_inline u64
xsk_alloc_umem_rx_frame (struct xsk_socket_info *xsk)
{
  u64 frame;
  if (xsk->umem_rx_frame_free == 0)
    return INVALID_UMEM_FRAME;

  frame = xsk->umem_rx_frame_addr[--xsk->umem_rx_frame_free];
  xsk->umem_rx_frame_addr[xsk->umem_rx_frame_free] = INVALID_UMEM_FRAME;
  return frame;
}

static_always_inline void
xsk_free_umem_rx_frame (struct xsk_socket_info *xsk, u64 frame)
{
  ASSERT (xsk->umem_rx_frame_free < UMEM_RX_NUM_FRAMES);

  xsk->umem_rx_frame_addr[xsk->umem_rx_frame_free++] = frame;
}

static_always_inline u64
xsk_umem_free_rx_frames (const struct xsk_socket_info *xsk)
{
  return xsk->umem_rx_frame_free;
}

static_always_inline u64
xsk_alloc_umem_tx_frame (struct xsk_socket_info * xsk)
{
  u64 frame;
  if (xsk->umem_tx_frame_free == 0)
    return INVALID_UMEM_FRAME;

  frame = xsk->umem_tx_frame_addr[--xsk->umem_tx_frame_free];
  xsk->umem_tx_frame_addr[xsk->umem_tx_frame_free] = INVALID_UMEM_FRAME;
  return frame;
}

static_always_inline void
xsk_free_umem_tx_frame (struct xsk_socket_info *xsk, u64 frame)
{
  ASSERT (xsk->umem_tx_frame_free < UMEM_TX_NUM_FRAMES);

  xsk->umem_tx_frame_addr[xsk->umem_tx_frame_free++] = frame;
}

static_always_inline u64
xsk_umem_free_tx_frames (const struct xsk_socket_info *xsk)
{
  return xsk->umem_tx_frame_free;
}

#endif /* xsk_defs */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
