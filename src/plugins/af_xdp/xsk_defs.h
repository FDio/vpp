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
#define NUM_FRAMES           131072
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

struct xdp_umem_uqueue
{
  u32 cached_prod;
  u32 cached_cons;
  u32 size;
  u32 *producer;
  u32 *consumer;
  u64 *ring;
  void *map;
  u64 map_size;
};

struct xdp_umem
{
  char *frames;
  struct xdp_umem_uqueue fq;
  struct xdp_umem_uqueue cq;
  int fd;
};

struct xdp_uqueue
{
  u32 cached_prod;
  u32 cached_cons;
  u32 size;
  u32 *producer;
  u32 *consumer;
  struct xdp_desc *ring;
  void *map;
  u64 map_size;
};

struct xsk_info
{
  struct xdp_uqueue rx;
  struct xdp_uqueue tx;
  int sfd;
  struct xdp_umem *umem;
  u32 outstanding_tx;
};

/// TODO consider use CLIB memory barriers
#define barrier() __asm__ __volatile__("": : :"memory")
#ifdef __aarch64__
#define u_smp_rmb() __asm__ __volatile__("dmb ishld": : :"memory")
#define u_smp_wmb() __asm__ __volatile__("dmb ishst": : :"memory")
#else
#define u_smp_rmb() barrier()
#define u_smp_wmb() barrier()
#endif

static inline u32
umem_nb_free (struct xdp_umem_uqueue *q, u32 nb)
{
  u32 free_entries = q->cached_cons - q->cached_prod;

  if (free_entries >= nb)
    return free_entries;

  /* Refresh the local tail pointer */
  q->cached_cons = *q->consumer + q->size;

  return q->cached_cons - q->cached_prod;
}

static inline u32
xq_nb_free (struct xdp_uqueue *q, u32 ndescs)
{
  u32 free_entries = q->cached_cons - q->cached_prod;

  if (free_entries >= ndescs)
    return free_entries;

  /* Refresh the local tail pointer */
  q->cached_cons = *q->consumer + q->size;
  return q->cached_cons - q->cached_prod;
}

static inline u32
umem_nb_avail (struct xdp_umem_uqueue *q, u32 nb)
{
  u32 entries = q->cached_prod - q->cached_cons;

  if (entries == 0)
    {
      q->cached_prod = *q->producer;
      entries = q->cached_prod - q->cached_cons;
    }

  return (entries > nb) ? nb : entries;
}

static inline u32
xq_nb_avail (struct xdp_uqueue *q, u32 ndescs)
{
  u32 entries = q->cached_prod - q->cached_cons;

  if (entries == 0)
    {
      q->cached_prod = *q->producer;
      entries = q->cached_prod - q->cached_cons;
    }

  return (entries > ndescs) ? ndescs : entries;
}

static inline int
umem_fill_to_kernel_ex (struct xdp_umem_uqueue *fq,
			struct xdp_desc *d, size_t nb)
{
  u32 i;

  if (umem_nb_free (fq, nb) < nb)
    return ENOSPC;

  for (i = 0; i < nb; i++)
    {
      u32 idx = fq->cached_prod++ & DEFAULT_FILL_RING_MASK;

      fq->ring[idx] = d[i].addr;
    }

  u_smp_wmb ();

  *fq->producer = fq->cached_prod;

  return 0;
}

static inline int
umem_fill_to_kernel (struct xdp_umem_uqueue *fq, u64 * d, size_t nb)
{
  u32 i;

  if (umem_nb_free (fq, nb) < nb)
    return ENOSPC;

  for (i = 0; i < nb; i++)
    {
      u32 idx = fq->cached_prod++ & DEFAULT_FILL_RING_MASK;

      fq->ring[idx] = d[i];
    }

  u_smp_wmb ();

  *fq->producer = fq->cached_prod;

  return 0;
}

static inline size_t
umem_complete_from_kernel (struct xdp_umem_uqueue *cq, size_t nb)
{
  u32 entries = umem_nb_avail (cq, nb);

  u_smp_rmb ();

  cq->cached_cons += entries;

  if (entries > 0)
    {
      u_smp_wmb ();

      *cq->consumer = cq->cached_cons;
    }

  return entries;
}

static inline void *
xq_get_data (struct xsk_info *xsk, u64 addr)
{
  return &xsk->umem->frames[addr];
}

static inline int
kick_tx (struct xsk_info *xsk_info)
{
  int ret, retries;

  /* In SKB_MODE packet transmission is synchronous, and the kernel xmits
   * only TX_BATCH_SIZE(16) packets for a single sendmsg syscall.
   * So, we have to kick the kernel (n_packets / 16) times to be sure that
   * all packets are transmitted. */
#define DIV_KERN_TX_BATCH_SIZE(n) ((n) >> 4)

// TODO
//    retries = (xdpmode == XDP_COPY)
//              ? xsk_info->outstanding_tx / KERNEL_TX_BATCH_SIZE
//              : 0;

  retries = DIV_KERN_TX_BATCH_SIZE (xsk_info->outstanding_tx);

kick_retry:
  /* This causes system call into kernel's xsk_sendmsg, and
   * xsk_generic_xmit (skb mode) or xsk_async_xmit (driver mode).
   */
  ret = sendto (xsk_info->sfd, NULL, 0, MSG_DONTWAIT, NULL, 0);

  if (ret < 0)
    {
      if (retries-- && errno == EAGAIN)
	goto kick_retry;

      if (errno == EBUSY || errno == ENOBUFS ||
	  errno == EOPNOTSUPP || errno == ENXIO)
	return errno;
    }
  /* No error, or too many retries on EAGAIN. */
  return 0;

#undef DIV_KERN_TX_BATCH_SIZE
}

static inline int
complete_tx (struct xsk_info *xsk, size_t nb)
{
  unsigned int rcvd;
  int ret = 0;

  if (PREDICT_FALSE (!xsk->outstanding_tx))
    return ret;

  ret = kick_tx (xsk);

  rcvd = umem_complete_from_kernel (&xsk->umem->cq, nb);
  if (rcvd > 0)
    xsk->outstanding_tx -= rcvd;

  return ret;
}

#endif /* xsk_defs */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
