/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _AVF_H_
#define _AVF_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/types.h>
#include <dev_avf/virtchnl.h>

#define AVF_RXQ_SZ  512
#define AVF_TXQ_SZ  512
#define AVF_ITR_INT 250

typedef struct avf_adminq_mem_t avf_adminq_mem_t;

typedef struct
{
  u8 adminq_active : 1;
  void *bar0;

  u16 vsi_id;
  u32 vf_cap_flags;
  u32 rss_key_size;
  u32 rss_lut_size;

  /* Admin queues */
  avf_adminq_mem_t *aq_mem;
  u16 atq_next_slot;
  u16 arq_next_slot;
  virtchnl_pf_event_t *events;

} avf_device_t;

typedef struct
{
  void *x;
} avf_port_t;

typedef struct
{
  u32 *buffer_indices;
} avf_txq_t;

typedef struct
{
  u32 *buffer_indices;
  u16 head;
  u16 tail;
} avf_rxq_t;

/* adminq.c */
vnet_dev_rv_t avf_aq_alloc (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t avf_aq_init (vlib_main_t *, vnet_dev_t *);
void avf_aq_deinit (vlib_main_t *, vnet_dev_t *);
void avf_aq_free (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t avf_aq_pf_send_and_recv (vlib_main_t *, vnet_dev_t *,
				       virtchnl_ops_t, void *, u16, void *,
				       u16);

/* virtchnl.c */
vnet_dev_rv_t avf_vc_op_version (vlib_main_t *, vnet_dev_t *,
				 virtchnl_version_info_t *);
vnet_dev_rv_t avf_vc_op_get_vf_resources (vlib_main_t *, vnet_dev_t *,
					  virtchnl_vf_resource_t *);

/* format.c */
format_function_t format_avf_vf_cap_flags;

/* inline funcs */

static inline u32
avf_get_u32 (void *start, int offset)
{
  return *(u32 *) (((u8 *) start) + offset);
}

static inline void
avf_reg_write (avf_device_t *ad, u32 addr, u32 val)
{
  __atomic_store_n ((u32 *) ((u8 *) ad->bar0 + addr), val, __ATOMIC_RELEASE);
}

static inline u32
avf_reg_read (avf_device_t *ad, u32 addr)
{
  u32 val = *(volatile u32 *) (ad->bar0 + addr);
  return val;
}

static inline void
avf_reg_flush (avf_device_t *ad)
{
  avf_reg_read (ad, AVFGEN_RSTAT);
  asm volatile("" ::: "memory");
}

static inline uword
avf_dma_addr (vlib_main_t *vm, vnet_dev_t *dev, void *p)
{
  return (dev->va_dma) ? pointer_to_uword (p) : vlib_physmem_get_pa (vm, p);
}

#endif /* _AVF_H_ */
