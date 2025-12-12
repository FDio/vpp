
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

/* mdata.h - Buffer metadata change tracker */

#ifndef __included_mdata_h__
#define __included_mdata_h__

#include <vnet/vnet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

/** @file mdata.h
 * buffer metadata change tracker definitions
 */

typedef struct
{
  /** Node index, ~0 means no data from this run */
  u32 node_index;
  /** buffer metadata, cast to vlib_buffer_t as needed */
  u8 mdata[128];
} mdata_t;

typedef struct
{
  /** API message ID base */
  u16 msg_id_base;

  /** Per-thread buffer metadata before calling node fcn */
  mdata_t **before_per_thread;

  /** Spinlock to protect modified metadata by node */
  clib_spinlock_t modify_lock;

  /** Modified metadata by node */
  mdata_t *modifies;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} mdata_main_t;

extern mdata_main_t mdata_main;

#endif /* __included_mdata_h__ */
