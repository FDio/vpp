/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _CNXK_MBOX_H_
#define _CNXK_MBOX_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_cnxk/cnxk.h>

typedef struct cnxk_mbox_config
{
  u8 bar;
  u32 bar_offset;
  u32 intr_offset;
  u32 tx_start, rx_start;
  u32 rx_size, tx_size;
} cnxk_mbox_config_t;

typedef struct
{
  u64 msg_size;
  u16 num_msgs;
  u8 _unused[6];
} cnxk_mbox_hdr_t;
STATIC_ASSERT_SIZEOF (cnxk_mbox_hdr_t, 16);

#define MBOX_REQ_SIG 0xdead
#define MBOX_RSP_SIG 0xbeef
#define MBOX_VERSION 0x000b

typedef struct
{
  u16 pcifunc;
  u16 id;
  u16 sig;
  u16 ver;
  u16 next_msgoff;
  u8 _unused[2];
  int rc;
  u8 msg[];
} cnxk_mbox_msghdr_t;
STATIC_ASSERT_SIZEOF (cnxk_mbox_msghdr_t, 16);

typedef struct cnxk_mbox
{
  u8 mbox_bar;
  u8 reg_bar;
  u16 mbox_offset;
  u16 reg_offset;
} cnxk_mbox_t;

cnxk_mbox_t *cnxk_mbox_init (vlib_main_t *, vnet_dev_t *);
void cnxk_mbox_free (vlib_main_t *, vnet_dev_t *, cnxk_mbox_t *);
int cnxk_mbox_msg (vlib_main_t *, vnet_dev_t *, cnxk_mbox_t *, u16 msg_id,
		   void *req, u16 req_sz, void *resp, u16 resp_sz);

#endif /* _CNXK_MBOX_H_ */
