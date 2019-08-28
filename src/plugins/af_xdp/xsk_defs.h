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


#define PIN_BASEDIR "/sys/fs/bpf"
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

// TODO play with following constants while performance testing
// DPDK AF_XDP PMD has different sizes, for example BATCH_SIZE has 32

/* Most should be power of two */
#define NUM_FRAMES             (4 * 1024)
#define FRAME_SIZE             2048
#define BATCH_SIZE               16

#define DEFAULT_COMP_RING_SIZE 1024
#define DEFAULT_COMP_RING_MASK (DEFAULT_COMP_RING_SIZE - 1)

#define DEFAULT_FILL_RING_SIZE 1024
#define DEFAULT_FILL_RING_MASK (DEFAULT_FILL_RING_SIZE - 1)

#define DEFAULT_RX_RING_SIZE   1024
#define DEFAULT_RX_RING_MASK   (DEFAULT_RX_RING_SIZE - 1)

#define DEFAULT_TX_RING_SIZE   1024
#define DEFAULT_TX_RING_MASK   (DEFAULT_TX_RING_SIZE - 1)

////////////

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
  ///
  unsigned long rx_npkts;
  unsigned long tx_npkts;
  unsigned long prev_rx_npkts;
  unsigned long prev_tx_npkts;
  ///
  u64 umem_frame_addr[NUM_FRAMES];
  u32 umem_frame_free;

  u32 outstanding_tx;
};

/// probably locking needed, split for rx and tx parts to avoid locking
static inline u64
xsk_alloc_umem_frame (struct xsk_socket_info *xsk)
{
  u64 frame;
  if (xsk->umem_frame_free == 0)
    return INVALID_UMEM_FRAME;

  frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
  xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
  return frame;
}

static inline void
xsk_free_umem_frame (struct xsk_socket_info *xsk, u64 frame)
{
//      assert(xsk->umem_frame_free < NUM_FRAMES);

  if (PREDICT_TRUE (xsk->umem_frame_free < NUM_FRAMES))
    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
  // else log weird error
}

static inline u64
xsk_umem_free_frames (struct xsk_socket_info *xsk)
{
  return xsk->umem_frame_free;
}




////////////

//struct xdp_umem_uqueue
//{
//  u32 cached_prod;
//  u32 cached_cons;
//  u32 size;
//  u32 *producer;
//  u32 *consumer;
//  u64 *ring;
//  void *map;
//  u64 map_size;
//};
//
//struct xdp_umem
//{
//  char *frames;
//  struct xdp_umem_uqueue fq;
//  struct xdp_umem_uqueue cq;
//  int fd;
//};
//
//struct xdp_uqueue
//{
//  u32 cached_prod;
//  u32 cached_cons;
//  u32 size;
//  u32 *producer;
//  u32 *consumer;
//  struct xdp_desc *ring;
//  void *map;
//  u64 map_size;
//};
//
//struct xsk_info
//{
//  struct xdp_uqueue rx;
//  struct xdp_uqueue tx;
//  int sfd;
//  struct xdp_umem *umem;
//  u32 outstanding_tx;
//};
//
///// TODO consider use CLIB memory barriers
//#define barrier() __asm__ __volatile__("": : :"memory")
//#ifdef __aarch64__
//#define u_smp_rmb() __asm__ __volatile__("dmb ishld": : :"memory")
//#define u_smp_wmb() __asm__ __volatile__("dmb ishst": : :"memory")
//#else
//#define u_smp_rmb() barrier()
//#define u_smp_wmb() barrier()
//#endif
//
//static inline u32
//umem_nb_free (struct xdp_umem_uqueue *q, u32 nb)
//{
//  u32 free_entries = q->cached_cons - q->cached_prod;
//
//  if (free_entries >= nb)
//    return free_entries;
//
//  /* Refresh the local tail pointer */
//  q->cached_cons = *q->consumer + q->size;
//
//  return q->cached_cons - q->cached_prod;
//}
//
//static inline u32
//xq_nb_free (struct xdp_uqueue *q, u32 ndescs)
//{
//  u32 free_entries = q->cached_cons - q->cached_prod;
//
//  if (free_entries >= ndescs)
//    return free_entries;
//
//  /* Refresh the local tail pointer */
//  q->cached_cons = *q->consumer + q->size;
//  return q->cached_cons - q->cached_prod;
//}
//
//static inline u32
//umem_nb_avail (struct xdp_umem_uqueue *q, u32 nb)
//{
//  u32 entries = q->cached_prod - q->cached_cons;
//
//  if (entries == 0)
//    {
//      q->cached_prod = *q->producer;
//      entries = q->cached_prod - q->cached_cons;
//    }
//
//  return (entries > nb) ? nb : entries;
//}
//
//static inline u32
//xq_nb_avail (struct xdp_uqueue *q, u32 ndescs)
//{
//  u32 entries = q->cached_prod - q->cached_cons;
//
//  if (entries == 0)
//    {
//      q->cached_prod = *q->producer;
//      entries = q->cached_prod - q->cached_cons;
//    }
//
//  return (entries > ndescs) ? ndescs : entries;
//}
//
//static inline int
//umem_fill_to_kernel_ex (struct xdp_umem_uqueue *fq,
//                      struct xdp_desc *d, size_t nb)
//{
//  u32 i;
//
//  if (umem_nb_free (fq, nb) < nb)
//    return ENOSPC;
//
//  for (i = 0; i < nb; i++)
//    {
//      u32 idx = fq->cached_prod++ & DEFAULT_FILL_RING_MASK;
//
//      fq->ring[idx] = d[i].addr;
//    }
//
//  u_smp_wmb ();
//
//  *fq->producer = fq->cached_prod;
//
//  return 0;
//}
//
//static inline int
//umem_fill_to_kernel (struct xdp_umem_uqueue *fq, u64 * d, size_t nb)
//{
//  u32 i;
//
//  if (umem_nb_free (fq, nb) < nb)
//    return ENOSPC;
//
//  for (i = 0; i < nb; i++)
//    {
//      u32 idx = fq->cached_prod++ & DEFAULT_FILL_RING_MASK;
//
//      fq->ring[idx] = d[i];
//    }
//
//  u_smp_wmb ();
//
//  *fq->producer = fq->cached_prod;
//
//  return 0;
//}
//
//static inline size_t
//umem_complete_from_kernel (struct xdp_umem_uqueue *cq, size_t nb)
//{
//  u32 entries = umem_nb_avail (cq, nb);
//
//  u_smp_rmb ();
//
//  cq->cached_cons += entries;
//
//  if (entries > 0)
//    {
//      u_smp_wmb ();
//
//      *cq->consumer = cq->cached_cons;
//    }
//
//  return entries;
//}
//
//static inline void *
//xq_get_data (struct xsk_info *xsk, u64 addr)
//{
//  return &xsk->umem->frames[addr];
//}

#endif /* xsk_defs */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
