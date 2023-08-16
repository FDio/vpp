/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dev_cnxk/cnxk.h>
#include <dev_cnxk/mbox.h>
#include <dev_cnxk/bar.h>

VLIB_REGISTER_LOG_CLASS (cnxk_log, static) = {
  .class_name = "dev_cnxk",
  .subclass_name = "mbox",
};

#define log_debug(id, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, cnxk_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_info(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_INFO, cnxk_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_notice(id, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, cnxk_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_warn(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_WARNING, cnxk_log.class, "%U: " f,                 \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_err(id, f, ...)                                                   \
  vlib_log (VLIB_LOG_LEVEL_ERR, cnxk_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)

#define RVU_PF_PFAF_MBOX0 (0xC00)
#define RVU_PF_PFAF_MBOX1 (0xC08)
#define MBOX_DOWN_MSG	  1
#define MBOX_UP_MSG	  2

cnxk_mbox_config_t mbox_configs[] = {
  [CNXK_DEVICE_TYPE_CPT_VF] = { .bar = 2,
				.bar_offset = 0xc0000,
				.intr_offset = 0x20 },
  [CNXK_DEVICE_TYPE_RVU_PF] = { .bar = 4, .intr_offset = 0xc20,
      .rx_start = 46 * 1024,
      .tx_start = 0,
      .rx_size = 16 * 1024,
      .tx_size = 46 * 1024,
  },
};

typedef struct
{
  u16 sclk_freq;
  u16 rclk_freq;
} cnxk_msg_ready_resp_t;

typedef struct
{
  u8 nix_fixed_txschq_mapping;
  u8 nix_shaping;      /* Is shaping and coloring supported */
  u8 npc_hash_extract; /* Is hash extract supported */
} cnxk_msg_get_hw_cap_resp_t;

typedef struct
{
  u16 vwqe_delay;
  u16 max_mtu;
  u16 min_mtu;
  u32 rpm_dwrr_mtu;
  u32 sdp_dwrr_mtu;
  u32 lbk_dwrr_mtu;
  u32 rsvd32[1];
  u64 rsvd[15];
} cnxk_msg_get_nix_hw_info_resp_t;

vnet_dev_rv_t
cnxk_mbox_req (vlib_main_t *vm, vnet_dev_t *dev, u16 msg_id, void *req,
	       u16 req_sz, void *resp, u16 resp_sz)
{
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  cnxk_mbox_t *mbox = cd->mbox;
  u8 *base = cnxk_bar_get_ptr (dev, mbox->mbox_bar);
  cnxk_mbox_hdr_t *txhdr = (cnxk_mbox_hdr_t *) (base + 0);
  cnxk_mbox_hdr_t *rxhdr = (cnxk_mbox_hdr_t *) (base + 46 * 1024);
  cnxk_mbox_msghdr_t *req_msg_hdr = (cnxk_mbox_msghdr_t *) (txhdr + 1);
  cnxk_mbox_msghdr_t *resp_msg_hdr = (cnxk_mbox_msghdr_t *) (rxhdr + 1);

  *req_msg_hdr = (cnxk_mbox_msghdr_t){
    .sig = MBOX_REQ_SIG,
    .ver = MBOX_VERSION,
    .id = msg_id,
  };

  *resp_msg_hdr = (cnxk_mbox_msghdr_t){};
  rxhdr->num_msgs = 0;
  txhdr->msg_size = sizeof (cnxk_mbox_msghdr_t) + round_pow2 (req_sz, 16);
  txhdr->num_msgs = 1;
  // asm volatile("dmb oshst" ::: "memory");

  cnxk_bar_reg64_write (dev, mbox->reg_bar, mbox->reg_offset, MBOX_DOWN_MSG);
  vlib_process_suspend (vm, 1);

  fformat (stderr, "YYYYYY %U\n", format_hexdump, rxhdr, 64);

  if (resp && resp_sz)
    clib_memcpy (resp, resp_msg_hdr->msg, resp_sz);

  return VNET_DEV_OK;
}

cnxk_mbox_t *
cnxk_mbox_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  cnxk_mbox_t *mbox;

  mbox = clib_mem_alloc_aligned (sizeof (*mbox), 128);
  cd->mbox = mbox;
  mbox->mbox_bar = mbox_configs[cd->type].bar;
  mbox->reg_bar = 2;
  mbox->reg_offset = RVU_PF_PFAF_MBOX1;

  cnxk_msg_ready_resp_t rr;
  cnxk_mbox_req (vm, dev, 1, 0, 0, &rr, sizeof (rr));
  __builtin_dump_struct (&rr, &printf);

  cnxk_msg_get_hw_cap_resp_t r2;
  cnxk_mbox_req (vm, dev, 8, 0, 0, &r2, sizeof (r2));
  __builtin_dump_struct (&r2, &printf);

  cnxk_msg_get_nix_hw_info_resp_t r3;
  cnxk_mbox_req (vm, dev, 0x801c, 0, 0, &r3, sizeof (r3));
  __builtin_dump_struct (&r3, &printf);

  return mbox;
}

void
cnxk_mbox_free (vlib_main_t *vm, vnet_dev_t *dev, cnxk_mbox_t *mbox)
{
  if (mbox)
    clib_mem_free (mbox);
}

