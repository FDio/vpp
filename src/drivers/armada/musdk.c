/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <stdint.h>
#include <string.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <musdk.h>
#include <musdk_internal.h>
#include <pp2/pp2.h>

#include <endian.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "musdk",
};

#define NOT_IN_USE		(-1)
#define usleep_range(us, range) usleep (us)

#define udelay(us) usleep (us)

#define PP2_MAX_BUF_STR_LEN 256

#define RETRIES_EXCEEDED (15000)

static void *
mem_calloc (size_t count, size_t size)
{
  size_t bytes;
  void *p;

  if (__builtin_mul_overflow (count, size, &bytes))
    return NULL;

  p = clib_mem_alloc (bytes);
  memset (p, 0, bytes);

  return p;
}

enum mv_pp2x_qos_tbl_sel
{
  MVPP2_QOS_TBL_SEL_PRI = 0,
  MVPP2_QOS_TBL_SEL_DSCP,
};

enum mv_pp2x_qos_src_tbl
{
  MVPP2_QOS_SRC_ACTION_TBL = 0,
  MVPP2_QOS_SRC_DSCP_PBIT_TBL,
};

enum mv_pp2x_cls_lkp_type
{
  MVPP2_CLS_LKP_HASH = 0,
  MVPP2_CLS_LKP_VLAN_PRI,
  MVPP2_CLS_LKP_DSCP_PRI,
  MVPP2_CLS_LKP_DEFAULT,
};

enum mv_pp2x_color_action_type
{
  /* Do not update color */
  MVPP2_COLOR_ACTION_TYPE_NO_UPDT = 0,
  /* Do not update color and lock */
  MVPP2_COLOR_ACTION_TYPE_NO_UPDT_LOCK,
  /* Update to green */
  MVPP2_COLOR_ACTION_TYPE_GREEN,
  /* Update to green and lock */
  MVPP2_COLOR_ACTION_TYPE_GREEN_LOCK,
  /* Update to yellow */
  MVPP2_COLOR_ACTION_TYPE_YELLOW,
  /* Update to yellow */
  MVPP2_COLOR_ACTION_TYPE_YELLOW_LOCK,
  /* Update to red */
  MVPP2_COLOR_ACTION_TYPE_RED,
  /* Update to red and lock */
  MVPP2_COLOR_ACTION_TYPE_RED_LOCK,
};

enum mv_pp2x_general_action_type
{
  /* The field will be not updated */
  MVPP2_ACTION_TYPE_NO_UPDT,
  /* The field will be not updated and lock */
  MVPP2_ACTION_TYPE_NO_UPDT_LOCK,
  /* The field will be updated */
  MVPP2_ACTION_TYPE_UPDT,
  /* The field will be updated and lock */
  MVPP2_ACTION_TYPE_UPDT_LOCK,
};

struct mv_pp2x_cls_c2_qos_entry
{
  u32 tbl_id;
  u32 tbl_sel;
  u32 tbl_line;
  u32 data;
};

enum mv_pp22_rss_access_sel
{
  MVPP22_RSS_ACCESS_POINTER,
  MVPP22_RSS_ACCESS_TBL,
};

struct mv_pp22_rss_tbl_ptr
{
  u8 rxq_idx;
  u8 rss_tbl_ptr;
};

struct mv_pp22_rss_tbl_entry
{
  u8 tbl_id;
  u8 tbl_line;
  u8 width;
  u8 rxq;
};

union mv_pp22_rss_access_entry
{
  struct mv_pp22_rss_tbl_ptr pointer;
  struct mv_pp22_rss_tbl_entry entry;
};

struct mv_pp22_rss_entry
{
  enum mv_pp22_rss_access_sel sel;
  union mv_pp22_rss_access_entry u;
};

struct pp2_cls_db_prs_t
{
  struct mv_pp2x_prs_shadow *prs_shadow;
};

struct rss_tbl_map_t
{
  u16 hw_tbl;
  u16 num_in_q;
};

struct pp2_cls_db_rss_t
{
  u32 num_musdk_tbls;					/* number of RSS tables required by MUSDK */
  struct rss_tbl_map_t rss_tbl_map[MVPP22_RSS_TBL_NUM]; /* RSS table mapping for MUSDK RSS tables */
};

struct pp2_cls_db_t
{
  struct pp2_cls_db_prs_t prs_db; /* PP2_CLS module PARSER db	*/
  struct pp2_cls_db_rss_t rss_db; /* PP2_CLS module RSS db		*/
};

static int
pp2_cls_db_rss_get_hw_tbl_from_in_q (vnet_dev_t *dev, mvpp2_device_t *md, u8 num_in_q)
{
  int i;

  for (i = 0; i < MVPP22_RSS_TBL_NUM; i++)
    {
      log_debug (dev, "%d num_in_q %d, %d\n", i, md->cls_db->rss_db.rss_tbl_map[i].num_in_q,
		 num_in_q);
      if (md->cls_db->rss_db.rss_tbl_map[i].num_in_q == num_in_q)
	return md->cls_db->rss_db.rss_tbl_map[i].hw_tbl;
    }

  return -1;
}

static u16
pp2_cls_db_rss_num_musdk_tbl_get (mvpp2_device_t *md)
{
  return md->cls_db->rss_db.num_musdk_tbls;
}

static void
pp2_cls_db_rss_num_musdk_tbl_set (mvpp2_device_t *md, u16 num_musdk_tbl)
{
  md->cls_db->rss_db.num_musdk_tbls = num_musdk_tbl;
}

static int
pp2_cls_db_rss_tbl_map_get_next_free_idx (mvpp2_device_t *md)
{
  int i;

  for (i = 0; i < MVPP22_RSS_TBL_NUM; i++)
    if (md->cls_db->rss_db.rss_tbl_map[i].num_in_q == 0)
      return i;

  return i;
}

static int
pp2_cls_db_rss_tbl_map_set (mvpp2_device_t *md, u16 idx, u16 hw_tbl, u16 num_in_q)
{
  if (idx > MVPP22_RSS_TBL_NUM || hw_tbl > MVPP22_RSS_TBL_NUM)
    return -EINVAL;

  md->cls_db->rss_db.rss_tbl_map[idx].hw_tbl = hw_tbl;
  md->cls_db->rss_db.rss_tbl_map[idx].num_in_q = num_in_q;

  return 0;
}

static int mv_pp2x_cls_c2_color_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int from);
static int mv_pp2x_cls_c2_hw_write (uintptr_t hif_base, int index, struct mv_pp2x_cls_c2_entry *c2);
static vnet_dev_rv_t mv_pp2x_cls_c2_hw_read (vnet_dev_t *dev, uintptr_t hif_base, int index,
					     struct mv_pp2x_cls_c2_entry *c2);

static u8
pp2_cls_c2_tcam_port_get (struct mv_pp2x_cls_c2_entry *c2)
{
  return ((c2->tcam.words[4] >> 8) & 0xFF);
}

static u8
pp2_cls_c2_tcam_lkp_type_get (struct mv_pp2x_cls_c2_entry *c2)
{
  return (c2->tcam.words[4] & MVPP2_CLS_C2_HEK_LKP_TYPE_MASK);
}

static void
mv_pp2x_c2_sw_clear (struct mv_pp2x_cls_c2_entry *c2)
{
  *c2 = (struct mv_pp2x_cls_c2_entry) {};
}

static u32
pp2_port_id (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  return mp->id;
}

static inline bool
mv_check_eaddr_bc (const u8 *eaddr)
{
  return (*(const u16 *) (eaddr + 0) & *(const u16 *) (eaddr + 2) & *(const u16 *) (eaddr + 4)) ==
	 0xffff;
}

static inline bool
mv_eaddr_identical (const u8 *eaddr1, const u8 *eaddr2)
{
  const u16 *e1_16 = (const u16 *) eaddr1;
  const u16 *e2_16 = (const u16 *) eaddr2;

  return ((e1_16[0] ^ e2_16[0]) | (e1_16[1] ^ e2_16[1]) | (e1_16[2] ^ e2_16[2])) == 0;
}

static inline bool
mv_check_eaddr_mc (const u8 *eaddr)
{
  u16 e_16 = *(const u16 *) eaddr;

  return 0x01 & (e_16 >> ((sizeof (e_16) * 8) - 8));
}

static inline int
mv_check_eaddr_zero (const u8 *eaddr)
{
  return !(eaddr[0] | eaddr[1] | eaddr[2] | eaddr[3] | eaddr[4] | eaddr[5]);
}

static inline int
mv_check_eaddr_valid (const u8 *addr)
{
  return !mv_check_eaddr_mc (addr) && !mv_check_eaddr_zero (addr);
}

static inline void
mv_cp_eaddr (u8 *dest, const u8 *source)
{
  u16 *dst_16 = (u16 *) dest;
  const u16 *src_16 = (const u16 *) source;

  dst_16[0] = src_16[0];
  dst_16[1] = src_16[1];
  dst_16[2] = src_16[2];
}

static int
pp2_cls_c3_cpu_done (uintptr_t hif_base)
{
  u32 reg_val;

  reg_val = mvpp2_reg_read (hif_base, MVPP2_CLS3_STATE_REG);
  reg_val &= MVPP2_CLS3_STATE_CPU_DONE_MASK;
  reg_val >>= MVPP2_CLS3_STATE_CPU_DONE;
  return reg_val;
}

static vnet_dev_rv_t
mv_pp2x_range_validate (vnet_dev_t *dev, int value, int min, int max)
{
  if (((value) > (max)) || ((value) < (min)))
    {
      log_err (dev, "%s: value 0x%X (%d) is out of range [0x%X , 0x%X].\n", __func__, (value),
	       (value), (min), (max));
      return VNET_DEV_ERR_INVALID_ARG;
    }
  return VNET_DEV_OK;
}
enum mv_pp2x_prs_lookup
{
  MVPP2_PRS_LU_MH,
  MVPP2_PRS_LU_MAC,
  MVPP2_PRS_LU_DSA,
  MVPP2_PRS_LU_VLAN,
  MVPP2_PRS_LU_VID,
  MVPP2_PRS_LU_L2,
  MVPP2_PRS_LU_PPPOE,
  MVPP2_PRS_LU_IP4,
  MVPP2_PRS_LU_IP6,
  MVPP2_PRS_LU_FLOWS,
  MVPP2_PRS_LU_LAST,
};

enum mv_pp2x_tag_type
{
  MVPP2_TAG_TYPE_NONE = 0,
  MVPP2_TAG_TYPE_MH = 1,
  MVPP2_TAG_TYPE_DSA = 2,
  MVPP2_TAG_TYPE_EDSA = 3,
  MVPP2_TAG_TYPE_VLAN = 4,
  MVPP2_TAG_TYPE_LAST = 5
};

static void
mv_pp2x_prs_tcam_data_byte_get (struct mv_pp2x_prs_entry *pe, unsigned int offs,
				unsigned char *byte, unsigned char *enable)
{
  *byte = pe->tcam.byte[TCAM_DATA_BYTE (offs)];
  *enable = pe->tcam.byte[TCAM_DATA_MASK (offs)];
}

static bool
mv_pp2x_prs_mac_range_equals (struct mv_pp2x_prs_entry *pe, const u8 *da, const u8 *mask)
{
  unsigned char tcam_byte, tcam_mask;
  int index;

  for (index = 0; index < ETH_ALEN; index++)
    {
      mv_pp2x_prs_tcam_data_byte_get (pe, index, &tcam_byte, &tcam_mask);
      if (tcam_mask != mask[index])
	return false;

      if ((tcam_mask & tcam_byte) != (da[index] & mask[index]))
	return false;
    }

  return true;
}

struct mv_pp2x_prs_shadow
{
  u32 valid;			     /* Entry is valid or not */
  int lu;			     /* Lookup ID */
  u32 ri;			     /* Result info */
  u32 ri_mask;			     /* Result info mask*/
  union mv_pp2x_prs_tcam_entry tcam; /* TCAM */
  u32 valid_in_kernel;		     /* Used for restoring kernel parser at deinit */
  u32 prs_mac_range_start;
  u32 prs_mac_range_end;
};

struct pp2_cls_c3_shadow_hash_entry
{
  /* valid if size > 0 */
  /* size include the extension*/
  int ext_ptr;
  int size;
};

static struct pp2_cls_c3_shadow_hash_entry pp2_cls_c3_shadow_tbl[MVPP2_CLS_C3_HASH_TBL_SIZE];
static int pp2_cls_c3_shadow_ext_tbl[MVPP2_CLS_C3_EXT_TBL_SIZE];

static void
mv_pp2x_prs_sram_bits_set (struct mv_pp2x_prs_entry *pe, int bit_num, int val)
{
  pe->sram.byte[SRAM_BIT_TO_BYTE (bit_num)] |= (val << (bit_num % 8));
}

static void
mv_pp2x_prs_sram_bits_clear (struct mv_pp2x_prs_entry *pe, int bit_num, int val)
{
  pe->sram.byte[SRAM_BIT_TO_BYTE (bit_num)] &= ~(val << (bit_num % 8));
}

static void mv_pp2x_prs_clear_active_vlans (vnet_dev_port_t *port, uint32_t *vlans);
static int mv_pp2x_prs_mac_da_accept (vnet_dev_port_t *port, const u8 *da, bool add);

static void
mv_pp2x_prs_shadow_set (mvpp2_device_t *md, int index, int lu)
{
  md->cls_db->prs_db.prs_shadow[index].valid = true;
  md->cls_db->prs_db.prs_shadow[index].lu = lu;
}

static void
mv_pp2x_prs_shadow_ri_set (mvpp2_device_t *md, int index, unsigned int ri, unsigned int ri_mask)
{
  md->cls_db->prs_db.prs_shadow[index].ri_mask = ri_mask;
  md->cls_db->prs_db.prs_shadow[index].ri = ri;
}

static void
mv_pp2x_prs_sram_next_lu_set (struct mv_pp2x_prs_entry *pe, unsigned int lu)
{
  int sram_next_off = MVPP2_PRS_SRAM_NEXT_LU_OFFS;

  mv_pp2x_prs_sram_bits_clear (pe, sram_next_off, MVPP2_PRS_SRAM_NEXT_LU_MASK);
  mv_pp2x_prs_sram_bits_set (pe, sram_next_off, lu);
}

static void
mv_pp2x_prs_sram_shift_set (struct mv_pp2x_prs_entry *pe, int shift, unsigned int op)
{
  /* Set sign */
  if (shift < 0)
    {
      mv_pp2x_prs_sram_bits_set (pe, MVPP2_PRS_SRAM_SHIFT_SIGN_BIT, 1);
      shift = 0 - shift;
    }
  else
    {
      mv_pp2x_prs_sram_bits_clear (pe, MVPP2_PRS_SRAM_SHIFT_SIGN_BIT, 1);
    }

  /* Set value */
  pe->sram.byte[SRAM_BIT_TO_BYTE (MVPP2_PRS_SRAM_SHIFT_OFFS)] = (unsigned char) shift;

  /* Reset and set operation */
  mv_pp2x_prs_sram_bits_clear (pe, MVPP2_PRS_SRAM_OP_SEL_SHIFT_OFFS,
			       MVPP2_PRS_SRAM_OP_SEL_SHIFT_MASK);
  mv_pp2x_prs_sram_bits_set (pe, MVPP2_PRS_SRAM_OP_SEL_SHIFT_OFFS, op);

  /* Set base offset as current */
  mv_pp2x_prs_sram_bits_clear (pe, MVPP2_PRS_SRAM_OP_SEL_BASE_OFFS, 1);
}

static void
mv_pp2x_prs_tcam_data_byte_set (struct mv_pp2x_prs_entry *pe, unsigned int offs, unsigned char byte,
				unsigned char enable)
{
  pe->tcam.byte[TCAM_DATA_BYTE (offs)] = byte;
  pe->tcam.byte[TCAM_DATA_MASK (offs)] = enable;
}

static void
mv_pp2x_prs_tcam_lu_set (struct mv_pp2x_prs_entry *pe, unsigned int lu)
{
  unsigned int offset = MVPP2_PRS_TCAM_LU_BYTE;
  unsigned int enable_off = MVPP2_PRS_TCAM_EN_OFFS (MVPP2_PRS_TCAM_LU_BYTE);

  pe->tcam.byte[HW_BYTE_OFFS (offset)] = lu;
  pe->tcam.byte[HW_BYTE_OFFS (enable_off)] = MVPP2_PRS_LU_MASK;
}

static unsigned int
mv_pp2x_prs_tcam_port_map_get (struct mv_pp2x_prs_entry *pe)
{
  int enable_off = HW_BYTE_OFFS (MVPP2_PRS_TCAM_EN_OFFS (MVPP2_PRS_TCAM_PORT_BYTE));

  return ~(pe->tcam.byte[enable_off]) & MVPP2_PRS_PORT_MASK;
}

static void
mv_pp2x_prs_tcam_port_map_set (struct mv_pp2x_prs_entry *pe, unsigned int ports)
{
  unsigned char port_mask = MVPP2_PRS_PORT_MASK;
  int enable_off = HW_BYTE_OFFS (MVPP2_PRS_TCAM_EN_OFFS (MVPP2_PRS_TCAM_PORT_BYTE));

  pe->tcam.byte[HW_BYTE_OFFS (MVPP2_PRS_TCAM_PORT_BYTE)] = 0;
  pe->tcam.byte[enable_off] &= ~port_mask;
  pe->tcam.byte[enable_off] |= ~ports & MVPP2_PRS_PORT_MASK;
}

static void
mv_pp2x_prs_tcam_port_set (struct mv_pp2x_prs_entry *pe, unsigned int port, bool add)
{
  int enable_off = HW_BYTE_OFFS (MVPP2_PRS_TCAM_EN_OFFS (MVPP2_PRS_TCAM_PORT_BYTE));

  if (add)
    pe->tcam.byte[enable_off] &= ~(1 << port);
  else
    pe->tcam.byte[enable_off] |= 1 << port;
}

static int pp2_cls_c3_hit_cntrs_clear_all (vnet_dev_t *dev, uintptr_t hif_base);
static void pp2_port_egress_enable (vnet_dev_port_t *port);
static void pp2_port_ingress_enable (vnet_dev_port_t *port);
static void pp2_port_uc_mac_addr_remove (vnet_dev_port_t *port, const uint8_t *addr);
static int pp2_prs_port_update (vnet_dev_port_t *port, u32 add, u32 tid, u32 ri, u32 ri_mask);

static int mvpp2x_prs_mac_da_range_find (vnet_dev_t *dev, mvpp2_device_t *md, uintptr_t hif_base,
					 int pmap, const u8 *da, const u8 *mask, int udf_type);
static int pp2_c2_config_default_queue (vnet_dev_port_t *port, u16 queue);
static int pp2_cls_mng_qos_tbl_dflt_set (vnet_dev_port_t *port, u16 queue);
static void pp2_port_egress_disable_qmask (vnet_dev_port_t *port, uint32_t q_mask);
static void pp2_port_egress_enable_qmask (vnet_dev_port_t *port, uint32_t q_mask);
static int pp2_rss_musdk_map_get (vnet_dev_port_t *port);

static int mv_pp2x_cls_c2_qos_tbl_fill_array (vnet_dev_port_t *port, u8 tbl_sel,
					      uint8_t tc_values[]);
static int pp2_c2_config_queue (struct mv_pp2x_cls_c2_entry *c2, u16 queue, int from);

static inline u32
pp2_port_isr_rx_group_read (vnet_dev_port_t *port, int sub_group)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int val;
  uintptr_t hif_base = mp->hif_base;

  val = (pp2_port_id (port) << MVPP22_ISR_RXQ_GROUP_INDEX_GROUP_OFFSET) | sub_group;
  mvpp2_reg_write (hif_base, MVPP22_ISR_RXQ_GROUP_INDEX_REG, val);

  return mvpp2_reg_read (hif_base, MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG);
}

static inline void
pp2_port_isr_rx_group_write (vnet_dev_port_t *port, int sub_group, int start_queue,
			     int num_rx_queues)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int val;
  uintptr_t hif_base = mp->hif_base;

  val = (pp2_port_id (port) << MVPP22_ISR_RXQ_GROUP_INDEX_GROUP_OFFSET) | sub_group;
  mvpp2_reg_write (hif_base, MVPP22_ISR_RXQ_GROUP_INDEX_REG, val);

  val = (num_rx_queues << MVPP22_ISR_RXQ_SUB_GROUP_SIZE_OFFSET) | start_queue;

  mvpp2_reg_write (hif_base, MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG, val);
}

static vnet_dev_rv_t mv_pp2x_cls_c2_qos_color_set (vnet_dev_t *dev,
						   struct mv_pp2x_cls_c2_qos_entry *qos, int color);
static int mv_pp2x_cls_c2_qos_hw_write (mvpp2_device_t *md, struct mv_pp2x_cls_c2_qos_entry *qos);
static int mv_pp2x_cls_c2_qos_queue_set (struct mv_pp2x_cls_c2_qos_entry *qos, uint8_t queue);
static int mv_pp2x_cls_c2_queue_high_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue,
					  int from);
static int mv_pp2x_cls_c2_queue_low_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue,
					 int from);
static int mv_pp2x_cls_c2_rss_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int rss_en);

int
mv_pp22_rss_tbl_entry_set (vnet_dev_t *dev, mvpp2_device_t *md, struct mv_pp22_rss_entry *rss)
{
  unsigned int reg_val = 0;

  if (!rss || rss->sel > MVPP22_RSS_ACCESS_TBL)
    return -EINVAL;

  if (rss->sel == MVPP22_RSS_ACCESS_POINTER)
    {
      if (rss->u.pointer.rss_tbl_ptr >= MVPP22_RSS_TBL_NUM)
	return -EINVAL;
      /* Write index */
      reg_val |= rss->u.pointer.rxq_idx << MVPP22_RSS_IDX_RXQ_NUM_OFF;
      mvpp2_reg_write (md->pp_base, MVPP22_RSS_IDX_REG, reg_val);
      log_debug (dev, "rss queue %d, reg_val %x", rss->u.pointer.rxq_idx, reg_val);
      /* Write entry */
      reg_val = 0;
      reg_val &= (~MVPP22_RSS_RXQ2RSS_TBL_POINT_MASK);
      reg_val |= rss->u.pointer.rss_tbl_ptr << MVPP22_RSS_RXQ2RSS_TBL_POINT_OFF;
      mvpp2_reg_write (md->pp_base, MVPP22_RSS_RXQ2RSS_TBL_REG, reg_val);
      log_debug (dev, ", table %d, reg_val %x\n", rss->u.pointer.rss_tbl_ptr, reg_val);
    }
  else if (rss->sel == MVPP22_RSS_ACCESS_TBL)
    {
      if (rss->u.entry.tbl_id >= MVPP22_RSS_TBL_NUM ||
	  rss->u.entry.tbl_line >= MVPP22_RSS_TBL_LINE_NUM ||
	  rss->u.entry.width > MVPP22_RSS_WIDTH_MAX)
	return -EINVAL;
      /* Write index */
      reg_val |= (rss->u.entry.tbl_line << MVPP22_RSS_IDX_ENTRY_NUM_OFF |
		  rss->u.entry.tbl_id << MVPP22_RSS_IDX_TBL_NUM_OFF);
      mvpp2_reg_write (md->pp_base, MVPP22_RSS_IDX_REG, reg_val);
      /* Write entry */
      reg_val &= (~MVPP22_RSS_TBL_ENTRY_MASK);
      reg_val |= (rss->u.entry.rxq << MVPP22_RSS_TBL_ENTRY_OFF);
      mvpp2_reg_write (md->pp_base, MVPP22_RSS_TBL_ENTRY_REG, reg_val);
      reg_val &= (~MVPP22_RSS_WIDTH_MASK);
      reg_val |= (rss->u.entry.width << MVPP22_RSS_WIDTH_OFF);
      mvpp2_reg_write (md->pp_base, MVPP22_RSS_WIDTH_REG, reg_val);
    }
  return 0;
}

int
pp2_rss_c2_enable (vnet_dev_port_t *port, int en)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  int index;
  int c2_status;
  int rc;
  u8 port_id;
  struct mv_pp2x_cls_c2_entry c2;

  c2_status = mvpp2_reg_read (md->pp_base, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      log_err (dev, "c2 is off\n");
      return -EINVAL;
    }

  mv_pp2x_c2_sw_clear (&c2);

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mv_pp2x_cls_c2_hw_read (dev, md->pp_base, index, &c2);
      port_id = pp2_cls_c2_tcam_port_get (&c2);

      if (c2.inv == 0 && port_id == (1 << pp2_port_id (port)))
	{
	  /* Set RSS */
	  rc = mv_pp2x_cls_c2_rss_set (&c2, MVPP2_ACTION_TYPE_UPDT_LOCK, en);
	  if (rc)
	    return rc;
	  mv_pp2x_cls_c2_hw_write (md->pp_base, index, &c2);

	  mv_pp2x_c2_sw_clear (&c2);
	  mv_pp2x_cls_c2_hw_read (dev, md->pp_base, index, &c2);
	}
    }
  return 0;
}

static int
pp2_rss_hw_tbl_set (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct mv_pp22_rss_entry rss_entry;
  int i;
  int entry_idx;
  u16 width;
  int hw_tbl;

  memset (&rss_entry, 0, sizeof (struct mv_pp22_rss_entry));
  rss_entry.sel = MVPP22_RSS_ACCESS_TBL;

  for (i = 0; i < mp->num_tcs; i++)
    {
      if (mp->tc.tc_config.num_in_qs == 1)
	continue;

      hw_tbl = pp2_cls_db_rss_get_hw_tbl_from_in_q (dev, md, mp->tc.tc_config.num_in_qs);
      if (hw_tbl < 0)
	{
	  log_err (dev, "%s RSS table index not found\n", __func__);
	  return -EFAULT;
	}
      rss_entry.u.entry.tbl_id = hw_tbl;

      width = max_log2 (mp->tc.tc_config.num_in_qs);
      log_debug (dev, "setting rss table %d, width %d\n", rss_entry.u.entry.tbl_id, width);
      rss_entry.u.entry.width = width;

      for (entry_idx = 0; entry_idx < MVPP22_RSS_TBL_LINE_NUM; entry_idx++)
	{
	  rss_entry.u.entry.tbl_line = entry_idx;
	  rss_entry.u.entry.rxq = entry_idx % mp->tc.tc_config.num_in_qs;
	  if (mv_pp22_rss_tbl_entry_set (dev, md, &rss_entry))
	    return -1;
	}
    }
  return 0;
}

/* The function allocate a rss table for each phisical rxq,
 * they have same cos priority
 */
static int
pp22_cls_rss_rxq_set (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int i, j;
  struct mv_pp22_rss_entry rss_entry;
  int hw_tbl;

  memset (&rss_entry, 0, sizeof (struct mv_pp22_rss_entry));
  rss_entry.sel = MVPP22_RSS_ACCESS_POINTER;

  for (i = 0; i < mp->num_tcs; i++)
    {
      if (mp->tc.tc_config.num_in_qs == 1)
	continue;

      /* Set the table index to be used according to rss_map */
      hw_tbl = pp2_cls_db_rss_get_hw_tbl_from_in_q (dev, md, mp->tc.tc_config.num_in_qs);
      if (hw_tbl < 0)
	{
	  log_err (dev, "%s RSS table index not found %d. Check mvpp2x_sysfs.ko module is loaded\n",
		   __func__, mp->tc.tc_config.num_in_qs);
	  return -EFAULT;
	}
      rss_entry.u.pointer.rss_tbl_ptr = hw_tbl;

      for (j = 0; j < mp->tc.tc_config.num_in_qs; j++)
	{
	  rss_entry.u.pointer.rxq_idx = mp->tc.tc_config.first_rxq + j;
	  log_debug (dev, "%d rxq_idx %d rss_tbl %d\n", j, rss_entry.u.pointer.rxq_idx,
		     rss_entry.u.pointer.rss_tbl_ptr);
	  if (mv_pp22_rss_tbl_entry_set (dev, md, &rss_entry))
	    return -EFAULT;
	}
    }
  return 0;
}

static int
pp2_rss_enable (vnet_dev_port_t *port, int en)
{
  int rc;

  rc = pp2_rss_c2_enable (port, en);
  if (rc)
    return -EINVAL;

  return 0;
}

static inline u32
cm3_read (uintptr_t base, u32 offset)
{
  return mvpp2_reg_read (base, offset);
}

static inline bool
mv_check_eaddr_uc (const u8 *addr)
{
  return !mv_check_eaddr_mc (addr);
}

static int
parse_hex (char *str, u8 *addr, size_t size)
{
  int len = 0;

  while (*str && (len < 2 * size))
    {
      int tmp;

      if (str[1] == 0)
	return -1;
      if (sscanf (str, "%02x", &tmp) != 1)
	return -1;
      addr[len] = tmp;
      len++;
      str += 2;
    }
  return len;
}

static int
pp2_c2_set_default_coloring (vnet_dev_port_t *port, int clear)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int index;
  int c2_status;
  int rc;
  u8 port_id;
  struct mv_pp2x_cls_c2_entry c2;
  enum mv_pp2x_color_action_type color_action = 0;

  c2_status = mvpp2_reg_read (md->pp_base, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      log_err (dev, "c2 is off\n");
      return -EINVAL;
    }

  if (clear)
    color_action = MVPP2_COLOR_ACTION_TYPE_GREEN;
  else
    {
      switch (mp->tc.tc_config.default_color)
	{
	case PP2_PPIO_COLOR_GREEN:
	  color_action = MVPP2_COLOR_ACTION_TYPE_GREEN;
	  break;
	case PP2_PPIO_COLOR_YELLOW:
	  color_action = MVPP2_COLOR_ACTION_TYPE_YELLOW;
	  break;
	case PP2_PPIO_COLOR_RED:
	  color_action = MVPP2_COLOR_ACTION_TYPE_RED;
	  break;
	}
    }

  mv_pp2x_c2_sw_clear (&c2);

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mv_pp2x_cls_c2_hw_read (dev, md->pp_base, index, &c2);
      port_id = pp2_cls_c2_tcam_port_get (&c2);

      if (c2.inv == 0 && port_id == (1 << pp2_port_id (port)))
	{
	  rc = mv_pp2x_cls_c2_color_set (&c2, color_action, MVPP2_QOS_SRC_ACTION_TBL);
	  if (rc)
	    return rc;

	  mv_pp2x_cls_c2_hw_write (md->pp_base, index, &c2);
	}
    }

  return 0;
}

static u32
pp2_prs_eth_start_hdr_get (vnet_dev_port_t *port)
{
  u32 reg_val;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  uintptr_t hif_base = md->pp_base;
  u32 ret = 0;

  reg_val = mvpp2_reg_read (hif_base, MVPP2_MH_REG (pp2_port_id (port)));
  if (reg_val & MVPP2_DSA_NON_EXTENDED)
    ret = MVPP2_TAG_TYPE_DSA;
  else if (reg_val & MVPP2_DSA_EXTENDED)
    ret = MVPP2_TAG_TYPE_EDSA;
  else
    ret = MVPP2_TAG_TYPE_NONE;

  return ret;
}

static int
pp2_prs_eth_start_hdr_set (vnet_dev_port_t *port, enum pp2_ppio_eth_start_hdr eth_start_hdr)
{
  vnet_dev_t *dev = port->dev;
  u32 reg_val;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  uintptr_t hif_base = md->pp_base;

  reg_val = mvpp2_reg_read (hif_base, MVPP2_MH_REG (pp2_port_id (port)));
  reg_val &= ~(MVPP2_DSA_EN_MASK | MVPP2_MH_EN_MASK);

  switch (eth_start_hdr)
    {
    case PP2_PPIO_HDR_ETH:
    case PP2_PPIO_HDR_ETH_CUSTOM:
      break;
    case PP2_PPIO_HDR_ETH_DSA:
      reg_val |= MVPP2_DSA_NON_EXTENDED;
      break;
    case PP2_PPIO_HDR_ETH_EXT_DSA:
      reg_val |= MVPP2_DSA_EXTENDED;
      break;
    default:
      log_err (dev, "invalid eth_start_hdr, eth_start_hdr = %d\n", eth_start_hdr);
      return -EINVAL;
    }

  /* Write to register */
  mvpp2_reg_write (hif_base, MVPP2_MH_REG (pp2_port_id (port)), reg_val);

  return 0;
}

static int
pp2_prs_tcam_first_free (vnet_dev_t *dev, mvpp2_device_t *md, unsigned char start,
			 unsigned char end)
{
  int tid;

  if (start > end)
    CLIB_SWAP (start, end);

  for (tid = start; tid <= end; tid++)
    {
      if (!md->cls_db->prs_db.prs_shadow[tid].valid)
	return tid;
    }
  log_err (dev, "Out of TCAM Entries !!\n");
  return -EINVAL;
}

static int
mv_pp2x_prs_hw_read (uintptr_t hif_base, struct mv_pp2x_prs_entry *pe)
{
  int i;

  if (pe->index > MVPP2_PRS_TCAM_SRAM_SIZE - 1)
    return -EINVAL;

  /* Write tcam index - indirect access */
  mvpp2_reg_write (hif_base, MVPP2_PRS_TCAM_IDX_REG, pe->index);

  pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] =
    mvpp2_reg_read (hif_base, MVPP2_PRS_TCAM_DATA_REG (MVPP2_PRS_TCAM_INV_WORD));
  if (pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] & MVPP2_PRS_TCAM_INV_MASK)
    return MVPP2_PRS_TCAM_ENTRY_INVALID;

  for (i = 0; i < MVPP2_PRS_TCAM_WORDS; i++)
    pe->tcam.word[i] = mvpp2_reg_read (hif_base, MVPP2_PRS_TCAM_DATA_REG (i));

  /* Write sram index - indirect access */
  mvpp2_reg_write (hif_base, MVPP2_PRS_SRAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_SRAM_WORDS; i++)
    pe->sram.word[i] = mvpp2_reg_read (hif_base, MVPP2_PRS_SRAM_DATA_REG (i));

  return 0;
}

static int
mv_pp2x_prs_hw_write (uintptr_t hif_base, struct mv_pp2x_prs_entry *pe)
{
  int i;

  if (pe->index > MVPP2_PRS_TCAM_SRAM_SIZE - 1)
    return -EINVAL;

  /* Clear entry invalidation bit */
  pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] &= ~MVPP2_PRS_TCAM_INV_MASK;

  /* Write sram index - indirect access */
  mvpp2_reg_write (hif_base, MVPP2_PRS_SRAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_SRAM_WORDS; i++)
    mvpp2_reg_write (hif_base, MVPP2_PRS_SRAM_DATA_REG (i), pe->sram.word[i]);

  /* Write tcam index - indirect access */
  mvpp2_reg_write (hif_base, MVPP2_PRS_TCAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_TCAM_WORDS; i++)
    mvpp2_reg_write (hif_base, MVPP2_PRS_TCAM_DATA_REG (i), pe->tcam.word[i]);

  return 0;
}

static int
mv_pp2x_prs_sram_ri_get (struct mv_pp2x_prs_entry *pe)
{
  return pe->sram.word[MVPP2_PRS_SRAM_RI_WORD];
}

static int
mv_pp2x_prs_sram_ri_mask_get (struct mv_pp2x_prs_entry *pe)
{
  return pe->sram.word[MVPP2_PRS_SRAM_RI_CTRL_WORD];
}

static void
mv_pp2x_prs_sram_ri_update (struct mv_pp2x_prs_entry *pe, unsigned int bits, unsigned int mask)
{
  unsigned int i;

  for (i = 0; i < MVPP2_PRS_SRAM_RI_CTRL_BITS; i++)
    {
      int ri_off = MVPP2_PRS_SRAM_RI_OFFS;

      if (!(mask & BIT (i)))
	continue;

      if (bits & BIT (i))
	mv_pp2x_prs_sram_bits_set (pe, ri_off + i, 1);
      else
	mv_pp2x_prs_sram_bits_clear (pe, ri_off + i, 1);

      mv_pp2x_prs_sram_bits_set (pe, MVPP2_PRS_SRAM_RI_CTRL_OFFS + i, 1);
    }
}

static int
mv_pp2x_prs_tcam_invalid_get (struct mv_pp2x_prs_entry *pe)
{
  return ((pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] & MVPP2_PRS_TCAM_INV_MASK) >>
	  MVPP2_PRS_TCAM_INV_OFFS);
}

static int
mv_pp2x_prs_tcam_lu_get (struct mv_pp2x_prs_entry *pe)
{
  return pe->tcam.byte[HW_BYTE_OFFS (MVPP2_PRS_TCAM_LU_BYTE)];
}

static int
mv_pp2x_prs_shadow_update (vnet_dev_t *dev, mvpp2_device_t *md)
{
  static int i, j, invalid, mac_range_start = -1, mac_range_end = -1;
  struct mv_pp2x_prs_entry pe;
  struct mv_pp2x_prs_shadow *prs_shadow;
  uintptr_t hif_base = md->pp_base;

  if (!md->cls_db->prs_db.prs_shadow)
    {
      md->cls_db->prs_db.prs_shadow =
	mem_calloc (MVPP2_PRS_TCAM_SRAM_SIZE, sizeof (struct mv_pp2x_prs_shadow));
      if (!md->cls_db->prs_db.prs_shadow)
	return -ENOMEM;
    }

  prs_shadow = md->cls_db->prs_db.prs_shadow;

  for (i = 0; i < MVPP2_PRS_TCAM_SRAM_SIZE; i++)
    {
      pe.index = i;
      mv_pp2x_prs_hw_read (hif_base, &pe);
      prs_shadow[i].ri = mv_pp2x_prs_sram_ri_get (&pe);
      prs_shadow[i].ri_mask = mv_pp2x_prs_sram_ri_mask_get (&pe);
      prs_shadow[i].lu = mv_pp2x_prs_tcam_lu_get (&pe);
      for (j = 0; j < MVPP2_PRS_TCAM_WORDS; j++)
	prs_shadow[i].tcam.word[j] = pe.tcam.word[j];
      invalid = mv_pp2x_prs_tcam_invalid_get (&pe);
      prs_shadow[i].valid = invalid ? 0 : 1;
      prs_shadow[i].valid_in_kernel = invalid ? 0 : 1;

      /* Dynamically find the mac_range from hw_parser configuration */
      if (!invalid && mac_range_start == -1 && prs_shadow[i].lu == MVPP2_PRS_LU_MAC &&
	  i >= MVPP2_PE_FIRST_FREE_TID)
	mac_range_start = i;
      if (!invalid && mac_range_start != -1 && mac_range_end == -1 &&
	  prs_shadow[i].lu != MVPP2_PRS_LU_MAC)
	mac_range_end = i - 1;
    }
  prs_shadow->prs_mac_range_start = (u32) mac_range_start;
  prs_shadow->prs_mac_range_end = (u32) mac_range_end;
  log_debug (dev, "%s: mac_start:%u, mac_end:%u\n", __func__, prs_shadow->prs_mac_range_start,
	     prs_shadow->prs_mac_range_end);
  return 0;
}

static void
pp2_cls_c3_shadow_init (void)
{
  /* clear hash shadow and extension shadow */
  int index;

  for (index = 0; index < MVPP2_CLS_C3_HASH_TBL_SIZE; index++)
    {
      pp2_cls_c3_shadow_tbl[index].size = 0;
      pp2_cls_c3_shadow_tbl[index].ext_ptr = NOT_IN_USE;
    }

  for (index = 0; index < MVPP2_CLS_C3_EXT_TBL_SIZE; index++)
    pp2_cls_c3_shadow_ext_tbl[index] = NOT_IN_USE;
}

static int
pp2_cls_mng_set_coloring (vnet_dev_port_t *port, int clear)
{
  vnet_dev_t *dev = port->dev;
  int rc;

  rc = pp2_c2_set_default_coloring (port, clear);
  if (rc)
    {
      log_err (dev, "%s(%d) pp2_c2_set_default_coloring fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  return 0;
}

static int
pp2_prs_eth_start_header_set (vnet_dev_port_t *port, enum pp2_ppio_eth_start_hdr mode)
{
  u32 type;
  int rc;
  u32 nri = 0, ri_mask = 0;

  rc = pp2_prs_eth_start_hdr_set (port, mode);
  if (rc)
    return -EFAULT;

  /*Get MH register configured mode */
  type = pp2_prs_eth_start_hdr_get (port);

  /* Configure parser DSA entries */
  switch (type)
    {
    case MVPP2_TAG_TYPE_EDSA:
      /* Add port to EDSA entries */
      pp2_prs_port_update (port, true, MVPP2_PE_EDSA_TAGGED, nri, ri_mask);
      pp2_prs_port_update (port, true, MVPP2_PE_EDSA_UNTAGGED, nri, ri_mask);

      /* Remove port from DSA entries */
      pp2_prs_port_update (port, false, MVPP2_PE_DSA_TAGGED, nri, ri_mask);
      pp2_prs_port_update (port, false, MVPP2_PE_DSA_UNTAGGED, nri, ri_mask);

      pp2_prs_port_update (port, false, MVPP2_PE_MH_SKIP_PRS, nri, ri_mask);

      break;
    case MVPP2_TAG_TYPE_DSA:
      /* Add port to DSA entries */
      pp2_prs_port_update (port, true, MVPP2_PE_DSA_TAGGED, nri, ri_mask);
      pp2_prs_port_update (port, true, MVPP2_PE_DSA_UNTAGGED, nri, ri_mask);

      /* Remove port from EDSA entries */
      pp2_prs_port_update (port, false, MVPP2_PE_EDSA_TAGGED, nri, ri_mask);
      pp2_prs_port_update (port, false, MVPP2_PE_EDSA_UNTAGGED, nri, ri_mask);

      pp2_prs_port_update (port, false, MVPP2_PE_MH_SKIP_PRS, nri, ri_mask);

      break;
    case MVPP2_TAG_TYPE_MH:
    case MVPP2_TAG_TYPE_NONE:
      /* Remove port form EDSA and DSA entries */
      pp2_prs_port_update (port, false, MVPP2_PE_DSA_TAGGED, nri, ri_mask);
      pp2_prs_port_update (port, false, MVPP2_PE_DSA_UNTAGGED, nri, ri_mask);
      pp2_prs_port_update (port, false, MVPP2_PE_EDSA_TAGGED, nri, ri_mask);
      pp2_prs_port_update (port, false, MVPP2_PE_EDSA_UNTAGGED, nri, ri_mask);

      pp2_prs_port_update (port, false, MVPP2_PE_MH_SKIP_PRS, nri, ri_mask);
      if (mode == PP2_PPIO_HDR_ETH_CUSTOM)
	pp2_prs_port_update (port, true, MVPP2_PE_MH_SKIP_PRS, nri, ri_mask);

      break;
    default:
      if ((type < 0) || (type > MVPP2_TAG_TYPE_EDSA))
	return -EINVAL;
    }

  return 0;
}

static int
mv_pp2x_cls_c2_hw_inv (uintptr_t hif_base, int index)
{
  if (!hif_base || index >= MVPP2_CLS_C2_TCAM_SIZE)
    return -EINVAL;

  /* write index reg */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* set invalid bit */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_INV_REG, (1 << MVPP2_CLS2_TCAM_INV_INVALID_OFF));

  /* trigger */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_DATA_REG (4), 0);

  return 0;
}

static int
pp2_cls_c3_init (vnet_dev_t *dev, uintptr_t hif_base)
{
  int rc;

  pp2_cls_c3_shadow_init ();
  rc = pp2_cls_c3_hit_cntrs_clear_all (dev, hif_base);
  return rc;
}

static void
pp2_cls_c3_shadow_clear (int index)
{
  int ext_ptr;

  pp2_cls_c3_shadow_tbl[index].size = 0;
  ext_ptr = pp2_cls_c3_shadow_tbl[index].ext_ptr;

  if (ext_ptr != NOT_IN_USE)
    pp2_cls_c3_shadow_ext_tbl[ext_ptr] = NOT_IN_USE;

  pp2_cls_c3_shadow_tbl[index].ext_ptr = NOT_IN_USE;
}

int
pp2_cls_mng_eth_start_header_params_set (vnet_dev_port_t *port,
					 enum pp2_ppio_eth_start_hdr eth_start_hdr)
{
  vnet_dev_t *dev = port->dev;
  int rc;

  rc = pp2_prs_eth_start_header_set (port, eth_start_hdr);
  if (rc)
    {
      log_err (dev, "%s(%d) pp2_prs_eth_start_header_set fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  return 0;
}

int
pp2_cls_mng_modify_default_flows (vnet_dev_port_t *port, int clear)
{
  vnet_dev_t *dev = port->dev;
  int rc;

  rc = pp2_cls_mng_set_coloring (port, clear);
  if (rc)
    {
      log_err (dev, "%s(%d) pp2_cls_mng_set_coloring fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  return 0;
}

static int
pp2_cls_prs_init (vnet_dev_t *dev, mvpp2_device_t *md)
{
  int rc;
  uintptr_t hif_base = md->pp_base;
  u32 val;

  /* Check if tcam table enabled*/
  val = mvpp2_reg_read (hif_base, MVPP2_PRS_TCAM_CTRL_REG);
  if (val != MVPP2_PRS_TCAM_EN_MASK)
    {
      log_err (dev, "Can't initialize logical port: parser not initialized yet\n");
      return -EFAULT;
    }

  /* Update MUSDK parser shadow table from kernel configuration */
  rc = mv_pp2x_prs_shadow_update (dev, md);
  if (rc)
    return -EFAULT;

  return 0;
}

vnet_dev_rv_t
pp2_ppio_add_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  char ifname[IFNAMSIZ];
  mvpp2_uc_addr_t *uc_addr;
  int rc;

  if (mv_check_eaddr_mc (addr))
    {
      struct ifreq s;
      int i;

      if (mp->num_added_mc_addr == PP2_PPIO_MAX_MC_ADDR)
	{
	  log_err (dev, "PORT: reached multicast address limit (%d)\n", PP2_PPIO_MAX_MC_ADDR);
	  return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	}

      mvpp2_port_ifname (port, ifname);
      strcpy (s.ifr_name, ifname);
      s.ifr_hwaddr.sa_family = AF_UNSPEC;
      for (i = 0; i < ETH_ALEN; i++)
	s.ifr_hwaddr.sa_data[i] = addr[i];

      rc = mvpp2_netdev_ioctl (dev, SIOCADDMULTI, &s);
      if (rc)
	{
	  log_err (dev, "PORT: unable to add mac sddress\n");
	  return VNET_DEV_ERR_INTERNAL;
	}
      mp->num_added_mc_addr++;

      log_debug (dev, "PORT: Ethernet address %x:%x:%x:%x:%x:%x added to mc list\n", addr[0],
		 addr[1], addr[2], addr[3], addr[4], addr[5]);
      log_debug (dev, "num_mc:%d\n", mp->num_added_mc_addr);
    }
  else if (mv_check_eaddr_uc (addr))
    {
      int fd;
      char buf[PP2_MAX_BUF_STR_LEN];
      char da[PP2_MAX_BUF_STR_LEN];

      if (vec_len (mp->added_uc_addrs) == PP2_PPIO_MAX_UC_ADDR)
	{
	  log_err (dev, "PORT: reached unicast address limit (%d)\n", PP2_PPIO_MAX_UC_ADDR);
	  return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	}

      mvpp2_port_ifname (port, ifname);
      strcpy (buf, ifname);
      sprintf (da, " %x:%x:%x:%x:%x:%x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
      strcat (buf, da);
      fd = open ("/sys/devices/platform/pp2/debug/uc_filter_add", O_WRONLY);
      if (fd == -1)
	{
	  log_debug (dev, "PORT: unable to open sysfs, updating prs_table internally instead\n");
	  mv_pp2x_prs_mac_da_accept (port, addr, true);
	}
      else
	{
	  rc = write (fd, &buf, strlen (buf) + 1);
	  close (fd);
	  if (rc < 0)
	    {
	      log_err (dev, "PORT: unable to write to sysfs\n");
	      return VNET_DEV_ERR_INTERNAL;
	    }
	}

      vec_add2 (mp->added_uc_addrs, uc_addr, 1);
      mv_cp_eaddr (uc_addr->addr, addr);

      log_debug (dev, "PORT: Ethernet address %x:%x:%x:%x:%x:%x added\n", addr[0], addr[1], addr[2],
		 addr[3], addr[4], addr[5]);
      log_debug (dev, "num_uc:%d\n", vec_len (mp->added_uc_addrs));
    }
  else
    {
      log_err (dev, "PORT: Ethernet address is not unicast/multicast. Request ignored\n");
      return VNET_DEV_ERR_INVALID_ARG;
    }
  return VNET_DEV_OK;
}

int
pp2_port_flush_mac_addrs (vnet_dev_port_t *port, u32 uc, u32 mc)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  char ifname[IFNAMSIZ];
  int rc;
  u8 mac[ETH_ALEN];

  mvpp2_port_ifname (port, ifname);

  if (mc)
    {
      char buf[PP2_MAX_BUF_STR_LEN];
      char name[IFNAMSIZ];
      char addr_str[PP2_MAX_BUF_STR_LEN];
      FILE *fp = fopen ("/proc/net/dev_mcast", "r");
      int len = 0;
      int st;

      if (!fp)
	return -EACCES;

      while (fgets (buf, sizeof (buf), fp))
	{
	  if (sscanf (buf, "%*d%s%*d%d%s", name, &st, addr_str) != 3)
	    {
	      log_err (dev, "address not found in file\n");
	      return -EFAULT;
	    }

	  if ((strcmp (ifname, name)) || (!st))
	    continue;

	  len = parse_hex (addr_str, mac, ETH_ALEN);
	  if (len != ETH_ALEN)
	    {
	      log_err (dev, "len parsing error\n");
	      return -EFAULT;
	    }

	  rc = pp2_ppio_remove_mac_addr (port, mac);
	  if (rc)
	    return rc;
	}
      fclose (fp);
    }

  if (uc)
    {
      int fd;
      char buf[PP2_MAX_BUF_STR_LEN];

      strcpy (buf, ifname);
      fd = open ("/sys/devices/platform/pp2/debug/uc_filter_flush", O_WRONLY);
      if (fd == -1)
	{
	  log_debug (dev, "PORT: unable to open sysfs, updating prs_table internally instead\n");
	  while (vec_len (mp->added_uc_addrs))
	    pp2_ppio_remove_mac_addr (port, mp->added_uc_addrs[0].addr);
	  mvpp2_netdev_clear_kernel_unicast (port);
	}
      else
	{
	  rc = write (fd, &buf, strlen (buf) + 1);
	  close (fd);
	  if (rc < 0)
	    {
	      log_err (dev, "PORT: unable to write to sysfs\n");
	      return -EFAULT;
	    }
	  vec_reset_length (mp->added_uc_addrs);
	}
    }
  return 0;
}

vnet_dev_rv_t
pp2_ppio_remove_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  char ifname[IFNAMSIZ];
  int rc;

  mvpp2_port_ifname (port, ifname);

  if (mv_check_eaddr_mc (addr))
    {
      struct ifreq s;
      int i;

      strcpy (s.ifr_name, ifname);
      s.ifr_hwaddr.sa_family = AF_UNSPEC;
      for (i = 0; i < ETH_ALEN; i++)
	s.ifr_hwaddr.sa_data[i] = addr[i];

      rc = mvpp2_netdev_ioctl (dev, SIOCDELMULTI, &s);
      if (rc)
	{
	  log_err (dev, "PORT: unable to remove mac sddress\n");
	  return VNET_DEV_ERR_INTERNAL;
	}
      mp->num_added_mc_addr--;
      log_debug (dev, "PORT: Ethernet address %x:%x:%x:%x:%x:%x removed from mc list\n", addr[0],
		 addr[1], addr[2], addr[3], addr[4], addr[5]);
      log_debug (dev, "num_mc:%d\n", mp->num_added_mc_addr);
    }
  else if (mv_check_eaddr_uc (addr))
    {
      int fd;
      char buf[PP2_MAX_BUF_STR_LEN];
      char da[PP2_MAX_BUF_STR_LEN];

      strcpy (buf, ifname);
      sprintf (da, " %x:%x:%x:%x:%x:%x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
      strcat (buf, da);
      fd = open ("/sys/devices/platform/pp2/debug/uc_filter_del", O_WRONLY);
      if (fd == -1)
	{
	  log_debug (dev, "PORT: unable to open sysfs, updating prs_table internally instead\n");
	  mv_pp2x_prs_mac_da_accept (port, addr, false);
	}
      else
	{
	  rc = write (fd, &buf, strlen (buf) + 1);
	  close (fd);
	  if (rc < 0)
	    {
	      log_err (dev, "PORT: unable to write to sysfs\n");
	      return VNET_DEV_ERR_INTERNAL;
	    }
	}

      pp2_port_uc_mac_addr_remove (port, addr);

      log_debug (dev, "PORT: Ethernet address %x:%x:%x:%x:%x:%x removed\n", addr[0], addr[1],
		 addr[2], addr[3], addr[4], addr[5]);
      log_debug (dev, "num_uc:%d\n", vec_len (mp->added_uc_addrs));
    }
  else
    {
      log_err (dev, "PORT: Ethernet address is not unicast/multicast. Request ignored\n");
      return VNET_DEV_ERR_INVALID_ARG;
    }
  return VNET_DEV_OK;
}

vnet_dev_rv_t
pp2_ppio_set_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
{
  vnet_dev_t *dev = port->dev;
  int rc = 0;
  struct ifreq s;
  int i;

  if (!mv_check_eaddr_valid (addr))
    {
      log_err (dev, "PORT: not a valid eth address\n");
      return VNET_DEV_ERR_INVALID_ARG;
    }

  mvpp2_port_ifname (port, s.ifr_name);
  s.ifr_hwaddr.sa_family = ARPHRD_ETHER;

  for (i = 0; i < ETH_ALEN; i++)
    s.ifr_hwaddr.sa_data[i] = addr[i];

  rc = mvpp2_netdev_ioctl (dev, SIOCSIFHWADDR, &s);
  if (rc)
    return VNET_DEV_ERR_INTERNAL;

  return VNET_DEV_OK;
}

vnet_dev_rv_t
pp2_ppio_set_promisc (vnet_dev_port_t *port, int en)
{
  vnet_dev_t *dev = port->dev;
  int rc;
  struct ifreq s;

  mvpp2_port_ifname (port, s.ifr_name);
  rc = mvpp2_netdev_ioctl (dev, SIOCGIFFLAGS, &s);
  if (rc)
    {
      log_err (dev, "PORT: unable to read promisc mode from HW\n");
      return VNET_DEV_ERR_INTERNAL;
    }

  if (en)
    s.ifr_flags |= IFF_PROMISC;
  else
    s.ifr_flags &= ~IFF_PROMISC;

  rc = mvpp2_netdev_ioctl (dev, SIOCSIFFLAGS, &s);
  if (rc)
    {
      log_err (dev, "PORT: unable to set promisc mode to HW\n");
      return VNET_DEV_ERR_INTERNAL;
    }
  return VNET_DEV_OK;
}

void
pp2_port_clear_prs_vlans (vnet_dev_port_t *port)
{
  uint32_t vlans[MVPP2_PRS_VLAN_FILT_MAX] = { 0 };
  int i;

  mv_pp2x_prs_clear_active_vlans (port, vlans);
  for (i = 0; (i < MVPP2_PRS_VLAN_FILT_MAX) && (vlans[i] != 0); i++)
    mvpp2_netdev_clear_vlan (port, vlans[i]);
  mvpp2_netdev_set_vlan_filtering (port, 0);
}

static void
pp2_port_start_dev (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  mvpp2_gop_max_rx_size_set (port);
  mvpp2_tx_sched_config (port);
  log_debug (dev, "start_dev: tx_port_num %d", MVPP2_MAX_TCONT + pp2_port_id (port));
  pp2_port_egress_enable (port);
  pp2_port_ingress_enable (port);
}

static vnet_dev_rv_t
mv_pp2x_ptr_validate (vnet_dev_t *dev, const void *ptr)
{
  if (!ptr)
    {
      log_err (dev, "%s: null pointer.\n", __func__);
      return VNET_DEV_ERR_INVALID_ARG;
    }
  return VNET_DEV_OK;
}
static int
pp2_cls_c3_hit_cntr_clear_done (uintptr_t hif_base)
{
  u32 reg_val;

  reg_val = mvpp2_reg_read (hif_base, MVPP2_CLS3_STATE_REG);
  reg_val &= MVPP2_CLS3_STATE_CLEAR_CTR_DONE_MASK;
  reg_val >>= MVPP2_CLS3_STATE_CLEAR_CTR_DONE;
  return reg_val;
}
static int
pp2_cls_c3_hw_del (vnet_dev_t *dev, uintptr_t hif_base, int index)
{
  u32 reg_val = 0;
  int iter = 0;

  if (mv_pp2x_range_validate (dev, index, 0, MVPP2_CLS3_HASH_OP_TBL_ADDR_MAX))
    return -EINVAL;

  reg_val |= (index << MVPP2_CLS3_HASH_OP_TBL_ADDR);
  reg_val |= (1 << MVPP2_CLS3_HASH_OP_DEL);
  reg_val &= ~MVPP2_CLS3_MISS_PTR_MASK; /*set miss bit to 1*/

  /*trigger del operation*/
  mvpp2_reg_write (hif_base, MVPP2_CLS3_HASH_OP_REG, reg_val);

  /* wait to cpu access done bit */
  while (!pp2_cls_c3_cpu_done (hif_base))
    if (++iter >= RETRIES_EXCEEDED)
      {
	log_err (dev, "%s:Error - retries exceeded.\n", __func__);
	return -EBUSY;
      }

  /* delete form shadow and extension shadow if exist */
  pp2_cls_c3_shadow_clear (index);

  return 0;
}
static int
pp2_cls_c3_hw_del_all (vnet_dev_t *dev, uintptr_t hif_base)
{
  int index, status;

  for (index = 0; index < MVPP2_CLS_C3_HASH_TBL_SIZE; index++)
    {
      status = pp2_cls_c3_hw_del (dev, hif_base, index);
      if (status != 0)
	return status;
    }
  return 0;
}
static int
pp2_cls_c3_hit_cntrs_clear_all (vnet_dev_t *dev, uintptr_t hif_base)
{
  int iter = 0;

  mvpp2_reg_write (hif_base, MVPP2_CLS3_CLEAR_COUNTERS_REG, MVPP2_CLS3_CLEAR_ALL);
  /* wait to clear het counters done bit */
  while (!pp2_cls_c3_hit_cntr_clear_done (hif_base))
    if (++iter >= RETRIES_EXCEEDED)
      {
	log_err (dev, "%s:Error - retries exceeded.\n", __func__);
	return -EBUSY;
      }

  return 0;
}
static int
pp2_cls_c3_reset (vnet_dev_t *dev, mvpp2_device_t *md)
{
  int rc = 0;
  uintptr_t hif_base = md->pp_base;

  log_debug (dev, "reached\n");

  /* clear all C3 HW entries */
  rc = pp2_cls_c3_hw_del_all (dev, hif_base);
  if (rc)
    {
      log_err (dev, "fail to delete C3 HW entries\n");
      return rc;
    }
  log_debug (dev, "PP2_CLS C3 HW entries deleted\n");

  /* clear all C3 HW counters */
  rc = pp2_cls_c3_hit_cntrs_clear_all (dev, hif_base);
  if (rc)
    {
      log_err (dev, "fail to clear C3 HW counters\n");
      return rc;
    }
  log_debug (dev, "PP2_CLS C3 HW counters cleared\n");

  /* init PP2_CLS C3 HAL */
  rc = pp2_cls_c3_init (dev, hif_base);
  if (rc)
    {
      log_err (dev, "fail to init PP2_CLS C3 DB\n");
      return rc;
    }
  log_debug (dev, "PP2_CLS C3 DB initialized\n");

  return 0;
}
static int
pp2_cls_c2_reset (mvpp2_device_t *md)
{
  int index;
  uintptr_t hif_base = md->pp_base;

  /* Clear all TCAM entry, except last one added by LSP */
  for (index = MVPP2_C2_FIRST_ENTRY; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    mv_pp2x_cls_c2_hw_inv (hif_base, index);

  return 0;
}
static vnet_dev_rv_t
mv_pp2x_cls_hw_cls_enable (vnet_dev_t *dev, uintptr_t hif_base, uint32_t en)
{
  if (mv_pp2x_range_validate (dev, en, 0, 1) != VNET_DEV_OK)
    return VNET_DEV_ERR_INVALID_ARG;

  /* Enable classifier */
  mvpp2_reg_write (hif_base, MVPP2_CLS_MODE_REG, en);

  return VNET_DEV_OK;
}
static int
pp2_cls_db_mem_alloc_init (mvpp2_device_t *md)
{
  /* Allocation for per-instance database */
  md->cls_db = clib_mem_alloc (sizeof (*md->cls_db));
  *md->cls_db = (struct pp2_cls_db_t) {};

  return 0;
}

static int
pp2_cls_db_init (vnet_dev_t *dev, mvpp2_device_t *md)
{
  int ret_code;

  /* Each database can be initialized only once */
  if (md->cls_db)
    {
      log_err (dev, "Classifier database alraedy initialized.");
      return -EINVAL;
    }

  /* Allocation for pp2_cls db */
  ret_code = pp2_cls_db_mem_alloc_init (md);

  if (ret_code != 0)
    {
      log_err (dev, "Failed to allocate memory for PP2_CLS DB\n");
      return -ENOMEM;
    }

  return 0;
}

static int
pp2_cls_c3_start (vnet_dev_t *dev, mvpp2_device_t *md)
{
  if (pp2_cls_c3_reset (dev, md))
    {
      log_err (dev, "PP2_CLS C3 start failed\n");
      return -EIO;
    }
  log_debug (dev, "PP2_CLS C3 started\n");

  return 0;
}

static int
pp2_cls_c2_start (vnet_dev_t *dev, mvpp2_device_t *md)
{
  if (pp2_cls_c2_reset (md))
    {
      log_err (dev, "MVPP2 C2 start failed\n");
      return -EINVAL;
    }

  return 0;
}

static vnet_dev_rv_t
pp2_cls_init (vnet_dev_t *dev, mvpp2_device_t *md)
{
  uintptr_t hif_base = md->pp_base;

  return mv_pp2x_cls_hw_cls_enable (dev, hif_base, true);
}

void
pp2_cls_mng_init (vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  if (md->cls_db)
    return; /*Already initialized*/

  pp2_cls_db_init (dev, md);
  pp2_cls_prs_init (dev, md);
  pp2_cls_init (dev, md);
  pp2_cls_c2_start (dev, md);
  pp2_cls_c3_start (dev, md);
}

vnet_dev_rv_t
pp2_ppio_enable (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "pp2_ppio_enable: %u\n", pp2_port_id (port));

  mvpp2_netdev_set_enable (port, 1);
  vlib_process_suspend (vm, 0.5);
  pp2_port_start_dev (port);
  return VNET_DEV_OK;
}

static inline void
cm3_write (uintptr_t base, u32 offset, u32 data)
{
  mvpp2_reg_write (base, offset, data);
}

static void
mv_pp2x_prs_clear_active_vlans (vnet_dev_port_t *port, uint32_t *vlans)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  struct mv_pp2x_prs_shadow *prs_shadow = md->cls_db->prs_db.prs_shadow;
  int index = 0;
  int tid;

  for (tid = MVPP2_PRS_VID_PORT_FIRST (pp2_port_id (port));
       tid <= MVPP2_PRS_VID_PORT_LAST (pp2_port_id (port)); tid++)
    {
      if (prs_shadow[tid].valid && prs_shadow[tid].lu == MVPP2_PRS_LU_VID)
	{
	  vlans[index++] = ((prs_shadow[tid].tcam.byte[TCAM_DATA_BYTE (2)] & 0xF) << 8) +
			   prs_shadow[tid].tcam.byte[TCAM_DATA_BYTE (3)];
	  prs_shadow[tid].valid = false;
	}
    }
}

static void
mv_pp2x_prs_hw_inv (uintptr_t hif_base, int index)
{
  /* Write index - indirect access */
  mvpp2_reg_write (hif_base, MVPP2_PRS_TCAM_IDX_REG, index);
  mvpp2_reg_write (hif_base, MVPP2_PRS_TCAM_DATA_REG (MVPP2_PRS_TCAM_INV_WORD),
		   MVPP2_PRS_TCAM_INV_MASK);
}

static int
mv_pp2x_prs_mac_da_accept (vnet_dev_port_t *port, const u8 *da, bool add)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  unsigned char mask[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  unsigned int pmap, len, ri;
  struct mv_pp2x_prs_shadow *prs_shadow = md->cls_db->prs_db.prs_shadow;
  struct mv_pp2x_prs_entry pe;
  int tid;

  memset (&pe, 0, sizeof (pe));

  /* Scan TCAM and see if entry with this <MAC DA, port> already exist */
  tid = mvpp2x_prs_mac_da_range_find (dev, md, mp->hif_base, BIT (pp2_port_id (port)), da, mask, 0);

  /* No such entry */
  if (tid < 0)
    {
      if (!add)
	return 0;

      /* Create new TCAM entry */
      /* Go through the all entries from first to last */
      tid = pp2_prs_tcam_first_free (dev, md, prs_shadow->prs_mac_range_start,
				     prs_shadow->prs_mac_range_end);
      if (tid < 0)
	return tid;

      pe.index = tid;

      /* Mask all ports */
      mv_pp2x_prs_tcam_port_map_set (&pe, 0);
    }
  else
    {
      pe.index = tid;
      mv_pp2x_prs_hw_read (mp->hif_base, &pe);
    }

  mv_pp2x_prs_tcam_lu_set (&pe, MVPP2_PRS_LU_MAC);

  /* Update port mask */
  mv_pp2x_prs_tcam_port_set (&pe, pp2_port_id (port), add);

  /* Invalidate the entry if no ports are left enabled */
  pmap = mv_pp2x_prs_tcam_port_map_get (&pe);
  if (pmap == 0)
    {
      if (add)
	return -EINVAL;

      mv_pp2x_prs_hw_inv (mp->hif_base, pe.index);
      prs_shadow[pe.index].valid = false;
      return 0;
    }

  /* Continue - set next lookup */
  mv_pp2x_prs_sram_next_lu_set (&pe, MVPP2_PRS_LU_DSA);

  /* Set match on DA */
  len = ETH_ALEN;
  while (len--)
    mv_pp2x_prs_tcam_data_byte_set (&pe, len, da[len], 0xff);

  /* Set result info bits */
  if (mv_check_eaddr_bc (da))
    {
      ri = MVPP2_PRS_RI_L2_BCAST;
    }
  else if (mv_check_eaddr_mc (da))
    {
      ri = MVPP2_PRS_RI_L2_MCAST;
    }
  else
    {
      ri = MVPP2_PRS_RI_L2_UCAST;

      /* These mac_addresses are not the MAC-TO-ME address */
      /* ri |= MVPP2_PRS_RI_MAC_ME_MASK; */
    }

  mv_pp2x_prs_sram_ri_update (&pe, ri, MVPP2_PRS_RI_L2_CAST_MASK | MVPP2_PRS_RI_MAC_ME_MASK);

  mv_pp2x_prs_shadow_ri_set (md, pe.index, ri,
			     MVPP2_PRS_RI_L2_CAST_MASK | MVPP2_PRS_RI_MAC_ME_MASK);

  /* Shift to ethertype */
  mv_pp2x_prs_sram_shift_set (&pe, 2 * ETH_ALEN, MVPP2_PRS_SRAM_OP_SEL_SHIFT_ADD);

  /* Update shadow table and hw entry */
  mv_pp2x_prs_shadow_set (md, pe.index, MVPP2_PRS_LU_MAC);
  mv_pp2x_prs_hw_write (mp->hif_base, &pe);

  return 0;
}

void
pp2_cls_mng_config_default_cos_queue (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  pp2_c2_config_default_queue (port, mp->first_rxq);
  pp2_cls_mng_qos_tbl_dflt_set (port, mp->first_rxq);
}

void
pp2_cls_mng_rss_port_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int rc, i;
  u32 num_queues = 0;

  mp->rss_en = true;

  /* Check total number of TC's and number of in_queues per TC do
   * not exceed maximum number of HW queues in port
   */
  for (i = 0; i < mp->num_tcs; i++)
    num_queues += mp->tc.tc_config.num_in_qs;

  if (num_queues > PP2_PPIO_MAX_NUM_TCS)
    {
      log_err (dev,
	       "not enough hw queues to allocate %d TC's and RSS. Needed %d queues, available %d\n",
	       mp->num_tcs, num_queues, PP2_PPIO_MAX_NUM_TCS);
      log_err (dev, "RSS is set to disabled\n");
      mp->rss_en = false;
    }

  if (mp->hash_type == PP2_PPIO_HASH_T_NONE)
    mp->rss_en = false;
  else
    {
      /* calculate the required musdk rss table map (not including the kernel rss map) */
      rc = pp2_rss_musdk_map_get (port);
      if (rc)
	{
	  log_err (dev, "Error in pp2_rss_musdk_map_get\n");
	  log_err (dev, "RSS is set to disabled\n");
	  mp->rss_en = false;
	}
    }

  if (mp->rss_en == true)
    {
      /* bind rxq to rss table for this port */
      if (pp22_cls_rss_rxq_set (port))
	{
	  log_err (dev, "cannot allocate rss table for rxq\n");
	  log_err (dev, "RSS is set to disabled\n");
	  mp->rss_en = false;
	}

      /* Init RSS table */
      if (pp2_rss_hw_tbl_set (port))
	{
	  log_err (dev, "cannot init rss hw table\n");
	  log_err (dev, "RSS is set to disabled\n");
	  mp->rss_en = false;
	}
    }

  /* Enable or disable RSS*/
  if (pp2_rss_enable (port, mp->rss_en))
    {
      log_err (dev, "cannot enable rss\n");
      return;
    }
}

static void
pp2_port_uc_mac_addr_remove (vnet_dev_port_t *port, const uint8_t *addr)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  uword i;

  vec_foreach_index (i, mp->added_uc_addrs)
    if (mv_eaddr_identical (mp->added_uc_addrs[i].addr, addr))
      {
	vec_del1 (mp->added_uc_addrs, i);
	log_debug (dev, "removed %x:%x:%x:%x:%x:%x from port\n", addr[0], addr[1], addr[2], addr[3],
		   addr[4], addr[5]);
	return;
      }
}

static int
pp2_prs_port_update (vnet_dev_port_t *port, u32 add, u32 tid, u32 ri, u32 ri_mask)
{
  vnet_dev_t *dev = port->dev;
  struct mv_pp2x_prs_entry pe;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  uintptr_t hif_base = md->pp_base;

  if (!md->cls_db->prs_db.prs_shadow[tid].valid)
    {
      log_err (dev, "parser logical port special field DSA mode: entry not found\n");
      return -EFAULT;
    }

  pe.index = tid;
  mv_pp2x_prs_hw_read (hif_base, &pe);

  /* update UDF7 */
  mv_pp2x_prs_sram_ri_update (&pe, ri, ri_mask);

  /* Update port mask */
  mv_pp2x_prs_tcam_port_set (&pe, pp2_port_id (port), add);

  mv_pp2x_prs_hw_write (hif_base, &pe);

  return 0;
}

void
pp2_port_defaults_set (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 tx_port_num, val, queue, ptxq;
  uintptr_t hif_base = mp->hif_base;

  /* Disable Legacy WRR, Disable EJP, Release from reset */
  tx_port_num = MVPP2_MAX_TCONT + pp2_port_id (port);
  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_CMD_1_REG, 0x0);

  /* Close bandwidth for all queues */
  for (queue = 0; queue < MVPP2_MAX_TXQ; queue++)
    {
      ptxq = (MVPP2_MAX_TCONT + pp2_port_id (port)) * MVPP2_MAX_TXQ + queue;
      mvpp2_reg_write (hif_base, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (ptxq), 0x0);
    }

  /* Set refill period to 1 usec, refill tokens
   * and bucket size to maximum
   */
  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_PERIOD_REG,
		   PP2_TCLK_FREQ / 1000000); /* USEC_PER_SEC */
  val = mvpp2_reg_read (hif_base, MVPP2_TXP_SCHED_REFILL_REG);
  val &= ~MVPP2_TXP_REFILL_PERIOD_ALL_MASK;
  val |= MVPP2_TXP_REFILL_PERIOD_MASK (1);
  val |= MVPP2_TXP_REFILL_TOKENS_ALL_MASK;
  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_REFILL_REG, val);
  val = MVPP2_TXP_TOKEN_SIZE_MAX;
  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, val);

  /* Set MaximumLowLatencyPacketSize value to 256 */
  /* Set GemPortIdSrcSel from classifier */
  mvpp2_reg_write (hif_base, MVPP2_RX_CTRL_REG (pp2_port_id (port)),
		   MVPP2_RX_USE_PSEUDO_FOR_CSUM_MASK | MVPP2_RX_LOW_LATENCY_PKT_SIZE (256) |
		     MVPP2_RX_GEM_PORT_ID_SRC_SEL (2));

  /* Disable Rx cache snoop */
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

      queue = rxq->hw_id;
      val = mvpp2_reg_read (hif_base, MVPP2_RXQ_CONFIG_REG (queue));
      /* Coherent */
      val |= MVPP2_SNOOP_PKT_SIZE_MASK;
      val |= MVPP2_SNOOP_BUF_HDR_MASK;
      mvpp2_reg_write (hif_base, MVPP2_RXQ_CONFIG_REG (queue), val);
    }
  /* As default, mask all interrupts to all present cpus */
  pp2_port_interrupts_disable (port);
}

void
pp2_port_egress_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 q_mask = 0;
  uintptr_t hif_base = mp->hif_base;

  q_mask = (mvpp2_reg_read (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG) & MVPP2_TXP_SCHED_ENQ_MASK);
  pp2_port_egress_disable_qmask (port, q_mask);
}

static void
pp2_port_egress_enable (vnet_dev_port_t *port)
{
  u32 q_mask = 0;

  foreach_vnet_dev_port_tx_queue (q, port)
    q_mask |= 1 << q->queue_id;
  pp2_port_egress_enable_qmask (port, q_mask);
}

void
pp2_port_ingress_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 val;
  uintptr_t hif_base = mp->hif_base;

  /* RXQs disable */
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
      u32 qid = rxq->hw_id;

      val = mvpp2_reg_read (hif_base, MVPP2_RXQ_CONFIG_REG (qid));
      val |= MVPP2_RXQ_DISABLE_MASK;
      mvpp2_reg_write (hif_base, MVPP2_RXQ_CONFIG_REG (qid), val);
    }
}

static void
pp2_port_ingress_enable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 val;
  uintptr_t hif_base = mp->hif_base;

  /* RXQs enable */
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
      u32 qid = rxq->hw_id;

      val = mvpp2_reg_read (hif_base, MVPP2_RXQ_CONFIG_REG (qid));
      val &= ~MVPP2_RXQ_DISABLE_MASK;
      mvpp2_reg_write (hif_base, MVPP2_RXQ_CONFIG_REG (qid), val);
    }
}

static int
mvpp2x_prs_mac_da_range_find (vnet_dev_t *dev, mvpp2_device_t *md, uintptr_t hif_base, int pmap,
			      const u8 *da, const u8 *mask, int udf_type)
{
  struct mv_pp2x_prs_entry pe;
  int tid;
  struct mv_pp2x_prs_shadow *prs_shadow = md->cls_db->prs_db.prs_shadow;

  /* Go through all entries with MVPP2_PRS_LU_MAC */
  for (tid = prs_shadow->prs_mac_range_start; tid <= prs_shadow->prs_mac_range_end; tid++)
    {
      unsigned int entry_pmap;

      if (!prs_shadow[tid].valid || prs_shadow[tid].lu != MVPP2_PRS_LU_MAC)
	continue;
      pe.index = tid;
      mv_pp2x_prs_hw_read (hif_base, &pe);
      entry_pmap = mv_pp2x_prs_tcam_port_map_get (&pe);

      if (mv_pp2x_prs_mac_range_equals (&pe, da, mask))
	{
	  log_debug (dev, "maps: %d:%d\n", entry_pmap, pmap);
	  if (entry_pmap == pmap)
	    return tid;
	}
    }

  return -ENOENT;
}

static int
pp2_c2_config_default_queue (vnet_dev_port_t *port, u16 queue)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  int index;
  int c2_status;
  int rc;
  u8 port_id, lkp_type;
  struct mv_pp2x_cls_c2_entry c2;

  c2_status = mvpp2_reg_read (md->pp_base, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      log_err (dev, "c2 is off\n");
      return -EINVAL;
    }

  mv_pp2x_c2_sw_clear (&c2);

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mv_pp2x_cls_c2_hw_read (dev, md->pp_base, index, &c2);
      port_id = pp2_cls_c2_tcam_port_get (&c2);
      lkp_type = pp2_cls_c2_tcam_lkp_type_get (&c2);

      if (c2.inv != 0 || port_id != (1 << pp2_port_id (port)))
	continue;

      if (lkp_type == MVPP2_CLS_LKP_DEFAULT)
	{
	  rc = pp2_c2_config_queue (&c2, queue, MVPP2_QOS_SRC_ACTION_TBL);
	  if (rc)
	    return -EFAULT;

	  log_debug (dev, "Writing index %#x, queue %d, from %d\n", index, queue,
		     MVPP2_QOS_SRC_ACTION_TBL);
	  mv_pp2x_cls_c2_hw_write (md->pp_base, index, &c2);
	}
      else if (lkp_type == MVPP2_CLS_LKP_DSCP_PRI || lkp_type == MVPP2_CLS_LKP_VLAN_PRI)
	{
	  rc = pp2_c2_config_queue (&c2, queue, MVPP2_QOS_SRC_DSCP_PBIT_TBL);
	  if (rc)
	    return -EFAULT;

	  log_debug (dev, "Writing index %#x, queue %d, from %d\n", index, queue,
		     MVPP2_QOS_SRC_DSCP_PBIT_TBL);
	  mv_pp2x_cls_c2_hw_write (md->pp_base, index, &c2);
	}
    }
  return 0;
}

static int
pp2_cls_mng_qos_tbl_dflt_set (vnet_dev_port_t *port, u16 queue)
{
  vnet_dev_t *dev = port->dev;
  int rc = 0;
  u32 i;
  u8 tc_array[MVPP2_QOS_TBL_LINE_NUM_DSCP];

  for (i = 0; i < MV_DSCP_NUM; i++)
    tc_array[i] = queue;

  rc = mv_pp2x_cls_c2_qos_tbl_fill_array (port, MVPP2_QOS_TBL_SEL_DSCP, tc_array);
  if (rc)
    {
      log_err (dev, "mv_pp2x_cls_c2_qos_tbl_fill_array failed\n");
      return -EINVAL;
    }

  rc = mv_pp2x_cls_c2_qos_tbl_fill_array (port, MVPP2_QOS_TBL_SEL_PRI, tc_array);
  if (rc)
    {
      log_err (dev, "mv_pp2x_cls_c2_qos_tbl_fill_array failed\n");
      return -EINVAL;
    }
  return 0;
}

void
pp2_port_clear_fc_isr (vnet_dev_port_t *port)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int hif_id;
  uintptr_t hif_base;

  for (hif_id = 0; hif_id < PP2_MAX_NUM_USED_INTERRUPTS; hif_id++)
    {
      /* Configure Group/Subgroup */
      mp->saved_rx_isr[hif_id] = pp2_port_isr_rx_group_read (port, hif_id);
      pp2_port_isr_rx_group_write (port, hif_id, 0, 0);

      hif_base = mvpp2_hif_base (md, hif_id);

      /* Configure RX Exceptions Interrupt Mask */
      mvpp2_reg_write (hif_base, MVPP2_RX_EX_INT_CAUSE_MASK_REG (pp2_port_id (port)), 0);
    }
}

static void
pp2_port_egress_disable_qmask (vnet_dev_port_t *port, uint32_t q_mask)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  volatile u32 tmo;
  u32 val = 0;
  u32 tx_port_num = MVPP2_MAX_TCONT + pp2_port_id (port);
  uintptr_t hif_base = mp->hif_base;

  /* Issue stop command for active channels only */
  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  if (q_mask)
    mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG, q_mask << MVPP2_TXP_SCHED_DISQ_OFFSET);

  /* TXQs disable. Wait for all Tx activity to terminate. */
  tmo = 0;
  do
    {
      if (tmo >= MVPP2_TX_DISABLE_TIMEOUT_MSEC)
	{
	  log_warn (dev, "Port: Egress disable timeout = 0x%08X\n", val);
	  break;
	}
      /* Sleep for 1 millisecond */
      usleep_range (1000, 2000);
      tmo++;
      val = mvpp2_reg_read (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG);
    }
  while (val & q_mask);
}

static void
pp2_port_egress_enable_qmask (vnet_dev_port_t *port, uint32_t q_mask)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 tx_port_num = MVPP2_MAX_TCONT + pp2_port_id (port);
  uintptr_t hif_base = mp->hif_base;

  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG, q_mask);
  log_debug (dev, "Port: Egress enable tx_port_num=%u q_mask=0x%X\n", tx_port_num, q_mask);
}

void
pp2_port_interrupts_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  u32 mask = 0;
  uintptr_t hif_base = mp->hif_base;

  foreach_vnet_dev_port_rx_queue (q, port)
    mask |= 1 << md->threads[q->rx_thread_index].hif_id;

  mvpp2_reg_write (hif_base, MVPP2_ISR_ENABLE_REG (pp2_port_id (port)),
		   MVPP2_ISR_DISABLE_INTERRUPT (mask));
}

void
pp2_port_rxqs_fc_state_reset (vnet_dev_port_t *port)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  int cm3_state;
  u32 val;
  uintptr_t base = md->cm3_base;

  /* Remove Flow control enable bit to prevent race between FW and Kernel
   * If Flow control were enabled, it would be re-enabled.
   */
  val = cm3_read (base, MSS_CP_FC_COM_REG);
  cm3_state = (val & FLOW_CONTROL_ENABLE_BIT);
  val &= ~FLOW_CONTROL_ENABLE_BIT;
  cm3_write (base, MSS_CP_FC_COM_REG, val);

  /* Notify Firmware that Flow control config space ready for update */
  val = cm3_read (base, MSS_CP_FC_COM_REG);
  val |= FLOW_CONTROL_UPD_COM_BIT;
  val |= cm3_state;
  cm3_write (base, MSS_CP_FC_COM_REG, val);
}

static int
pp2_rss_musdk_map_get (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u16 req_tbls = 0, used_tbls, avail_tbls;
  int i, idx, req_ind[MVPP22_RSS_TBL_NUM] = { 0 };
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  int hw_tbl;
  u16 num_in_q;

  used_tbls = pp2_cls_db_rss_num_musdk_tbl_get (md);
  avail_tbls = MVPP22_RSS_TBL_NUM - used_tbls;

  /* Calculate number of TC's which require RSS */
  for (i = 0; i < mp->num_tcs; i++)
    {
      if (mp->tc.tc_config.num_in_qs == 1)
	continue;

      hw_tbl = pp2_cls_db_rss_get_hw_tbl_from_in_q (dev, md, mp->tc.tc_config.num_in_qs);
      /* New hw_tbl required for this TC */
      if (hw_tbl < 0)
	{
	  if (req_tbls >= avail_tbls)
	    {
	      log_err (dev, "%s:Out of RSS tables\n", __func__);
	      goto rollback;
	    }
	  /* entry in rss_tbl_map is empty. Fill dB with new values */
	  idx = pp2_cls_db_rss_tbl_map_get_next_free_idx (md);
	  if (idx == MVPP22_RSS_TBL_NUM)
	    {
	      /* This should never happen */
	      log_err (dev, "%s: Unable to allocate new RSS table\n", __func__);
	      goto rollback;
	    }
	  pp2_cls_db_rss_tbl_map_set (md, idx, idx, mp->tc.tc_config.num_in_qs);
	  req_ind[req_tbls] = idx;
	  req_tbls++;
	  hw_tbl = idx;
	  num_in_q = mp->tc.tc_config.num_in_qs;
	  log_debug (dev, "%s: rss_db_ind:%d, rss_hw_tbl_id:%d, num_in_q:%d\n", __func__, idx,
		     hw_tbl, num_in_q);
	}
    }

  pp2_cls_db_rss_num_musdk_tbl_set (md, (used_tbls + req_tbls));

  return 0;
rollback:
  for (i = 0; i < req_tbls; i++)
    pp2_cls_db_rss_tbl_map_set (md, req_ind[i], 0, 0);
  return -ENOSPC;
}

static int
mv_pp2x_cls_c2_qos_tbl_fill_array (vnet_dev_port_t *port, u8 tbl_sel, uint8_t tc_values[])
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct mv_pp2x_cls_c2_qos_entry qos_entry;
  u32 pri, line_num;
  u8 queue;
  enum pp2_ppio_color color;
  int rc;

  if (tbl_sel == MVPP2_QOS_TBL_SEL_PRI)
    line_num = MVPP2_QOS_TBL_LINE_NUM_PRI;
  else
    line_num = MVPP2_QOS_TBL_LINE_NUM_DSCP;

  memset (&qos_entry, 0, sizeof (struct mv_pp2x_cls_c2_qos_entry));
  qos_entry.tbl_id = pp2_port_id (port);
  qos_entry.tbl_sel = tbl_sel;

  /* Fill the QoS dscp/pbit table */
  for (pri = 0; pri < line_num; pri++)
    {
      qos_entry.tbl_line = pri;
      /* map cos queue to physical queue */
      /* Physical queue contains 2 parts: port ID and CPU ID,
       * CPU ID will be used in RSS
       */
      queue = mp->tc.tc_config.first_rxq;
      color = mp->tc.tc_config.default_color;
      log_debug (dev, "tc_val[%d] %d, queue %d, color %d\n", pri, tc_values[pri], queue,
		 (int) color);

      rc = mv_pp2x_cls_c2_qos_queue_set (&qos_entry, queue);
      if (rc)
	{
	  log_err (dev, "mv_pp2x_cls_c2_qos_queue_set failed\n");
	  return -EFAULT;
	}

      if (mv_pp2x_cls_c2_qos_color_set (dev, &qos_entry, color) != VNET_DEV_OK)
	{
	  log_info (dev, "mv_pp2x_cls_c2_qos_color_set failed\n");
	  return -EFAULT;
	}

      rc = mv_pp2x_cls_c2_qos_hw_write (md, &qos_entry);
      if (rc)
	{
	  log_err (dev, "mv_pp2x_cls_c2_qos_hw_write failed\n");
	  return -EFAULT;
	}
    }
  return 0;
}

static int
pp2_c2_config_queue (struct mv_pp2x_cls_c2_entry *c2, u16 queue, int from)
{
  int q_low, q_high;
  int rc;

  q_high = ((u16) queue) >> MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS;
  q_low = ((u16) queue) & ((1 << MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS) - 1);

  rc = mv_pp2x_cls_c2_queue_low_set (c2, MVPP2_ACTION_TYPE_UPDT_LOCK, q_low, from);
  if (rc)
    return rc;
  rc = mv_pp2x_cls_c2_queue_high_set (c2, MVPP2_ACTION_TYPE_UPDT_LOCK, q_high, from);
  if (rc)
    return rc;

  return 0;
}

void
pp2_port_restore_fc_isr (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int hif_id, start_queue, num_rx_queues;

  for (hif_id = 0; hif_id < PP2_MAX_NUM_USED_INTERRUPTS; hif_id++)
    {
      /* Configure Group/Subgroup */
      start_queue = mp->saved_rx_isr[hif_id] & MVPP22_ISR_RXQ_SUB_GROUP_STARTQ_MASK;
      num_rx_queues = (mp->saved_rx_isr[hif_id] & MVPP22_ISR_RXQ_SUB_GROUP_SIZE_MASK) >>
		      MVPP22_ISR_RXQ_SUB_GROUP_SIZE_OFFSET;

      pp2_port_isr_rx_group_write (port, hif_id, start_queue, num_rx_queues);
    }
}

static vnet_dev_rv_t
mv_pp2x_cls_c2_qos_color_set (vnet_dev_t *dev, struct mv_pp2x_cls_c2_qos_entry *qos, int color)
{
  if (mv_pp2x_ptr_validate (dev, qos) != VNET_DEV_OK)
    return VNET_DEV_ERR_INVALID_ARG;

  qos->data &= ~MVPP2_CLS2_QOS_TBL_COLOR_MASK;
  qos->data |= color << MVPP2_CLS2_QOS_TBL_COLOR_OFF;

  return VNET_DEV_OK;
}

static int
mv_pp2x_cls_c2_qos_hw_write (mvpp2_device_t *md, struct mv_pp2x_cls_c2_qos_entry *qos)
{
  unsigned int reg_val = 0;

  if (!qos || qos->tbl_sel > MVPP2_QOS_TBL_SEL_DSCP)
    return -EINVAL;

  if (qos->tbl_sel == MVPP2_QOS_TBL_SEL_DSCP)
    {
      /*dscp */
      if (qos->tbl_id >= MVPP2_QOS_TBL_NUM_DSCP || qos->tbl_line >= MVPP2_QOS_TBL_LINE_NUM_DSCP)
	return -EINVAL;
    }
  else
    {
      /*pri */
      if (qos->tbl_id >= MVPP2_QOS_TBL_NUM_PRI || qos->tbl_line >= MVPP2_QOS_TBL_LINE_NUM_PRI)
	return -EINVAL;
    }
  /* write index reg */
  reg_val |= (qos->tbl_line << MVPP2_CLS2_DSCP_PRI_INDEX_LINE_OFF);
  reg_val |= (qos->tbl_sel << MVPP2_CLS2_DSCP_PRI_INDEX_SEL_OFF);
  reg_val |= (qos->tbl_id << MVPP2_CLS2_DSCP_PRI_INDEX_TBL_ID_OFF);
  mvpp2_reg_write (md->pp_base, MVPP2_CLS2_DSCP_PRI_INDEX_REG, reg_val);

  /* write data reg */
  mvpp2_reg_write (md->pp_base, MVPP2_CLS2_QOS_TBL_REG, qos->data);

  return 0;
}

static int
mv_pp2x_cls_c2_qos_queue_set (struct mv_pp2x_cls_c2_qos_entry *qos, uint8_t queue)
{
  if (!qos)
    return -EINVAL;

  qos->data &= ~MVPP2_CLS2_QOS_TBL_QUEUENUM_MASK;
  qos->data |= (((uint32_t) queue) << MVPP2_CLS2_QOS_TBL_QUEUENUM_OFF);
  return 0;
}

static int
mv_pp2x_cls_c2_queue_high_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue, int from)
{
  if (!c2 || cmd > MVPP2_ACTION_TYPE_UPDT_LOCK || queue >= (1 << MVPP2_CLS2_ACT_QOS_ATTR_QH_BITS))
    return -EINVAL;

  /*set command */
  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_QH_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_QH_OFF);

  /*set modify High queue value */
  c2->sram.regs.qos_attr &= ~MVPP2_CLS2_ACT_QOS_ATTR_QH_MASK;
  c2->sram.regs.qos_attr |=
    ((queue << MVPP2_CLS2_ACT_QOS_ATTR_QH_OFF) & MVPP2_CLS2_ACT_QOS_ATTR_QH_MASK);

  if (from == 1)
    c2->sram.regs.action_tbl |= (1 << MVPP2_CLS2_ACT_DATA_TBL_HIGH_Q_OFF);
  else
    c2->sram.regs.action_tbl &= ~(1 << MVPP2_CLS2_ACT_DATA_TBL_HIGH_Q_OFF);

  return 0;
}

static int
mv_pp2x_cls_c2_queue_low_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue, int from)
{
  if (!c2 || cmd > MVPP2_ACTION_TYPE_UPDT_LOCK || queue >= (1 << MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS))
    return -EINVAL;

  /*set command */
  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_QL_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_QL_OFF);

  /*set modify Low queue value */
  c2->sram.regs.qos_attr &= ~MVPP2_CLS2_ACT_QOS_ATTR_QL_MASK;
  c2->sram.regs.qos_attr |=
    ((queue << MVPP2_CLS2_ACT_QOS_ATTR_QL_OFF) & MVPP2_CLS2_ACT_QOS_ATTR_QL_MASK);

  if (from == 1)
    c2->sram.regs.action_tbl |= (1 << MVPP2_CLS2_ACT_DATA_TBL_LOW_Q_OFF);
  else
    c2->sram.regs.action_tbl &= ~(1 << MVPP2_CLS2_ACT_DATA_TBL_LOW_Q_OFF);

  return 0;
}

static int
mv_pp2x_cls_c2_rss_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int rss_en)
{
  if (!c2 || cmd > MVPP2_ACTION_TYPE_UPDT_LOCK ||
      rss_en >= (1 << MVPP2_CLS2_ACT_DUP_ATTR_RSSEN_BITS))
    return -EINVAL;

  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_RSS_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_RSS_OFF);

  c2->sram.regs.rss_attr &= ~MVPP2_CLS2_ACT_DUP_ATTR_RSSEN_MASK;
  c2->sram.regs.rss_attr |= (rss_en << MVPP2_CLS2_ACT_DUP_ATTR_RSSEN_OFF);

  return 0;
}

static vnet_dev_rv_t
mv_pp2x_cls_c2_hw_read (vnet_dev_t *dev, uintptr_t hif_base, int index,
			struct mv_pp2x_cls_c2_entry *c2)
{
  unsigned int reg_val = 0;
  int tcm_idx;

  if (mv_pp2x_ptr_validate (dev, c2) != VNET_DEV_OK)
    return VNET_DEV_ERR_INVALID_ARG;

  c2->index = index;

  /* write index reg */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* read invalid bit */
  reg_val = mvpp2_reg_read (hif_base, MVPP2_CLS2_TCAM_INV_REG);

  c2->inv = (reg_val & MVPP2_CLS2_TCAM_INV_INVALID_MASK) >> MVPP2_CLS2_TCAM_INV_INVALID_OFF;

  if (c2->inv)
    return VNET_DEV_OK;

  for (tcm_idx = 0; tcm_idx < MVPP2_CLS_C2_TCAM_WORDS; tcm_idx++)
    c2->tcam.words[tcm_idx] = mvpp2_reg_read (hif_base, MVPP2_CLS2_TCAM_DATA_REG (tcm_idx));

  c2->sram.regs.action_tbl = mvpp2_reg_read (hif_base, MVPP2_CLS2_ACT_DATA_REG);
  c2->sram.regs.actions = mvpp2_reg_read (hif_base, MVPP2_CLS2_ACT_REG);
  c2->sram.regs.qos_attr = mvpp2_reg_read (hif_base, MVPP2_CLS2_ACT_QOS_ATTR_REG);
  c2->sram.regs.hwf_attr = mvpp2_reg_read (hif_base, MVPP2_CLS2_ACT_HWF_ATTR_REG);
  c2->sram.regs.rss_attr = mvpp2_reg_read (hif_base, MVPP2_CLS2_ACT_DUP_ATTR_REG);
  c2->sram.regs.seq_attr = mvpp2_reg_read (hif_base, MVPP21_CLS2_ACT_SEQ_ATTR_REG);

  return VNET_DEV_OK;
}

int
mv_pp2x_cls_c2_hw_write (uintptr_t hif_base, int index, struct mv_pp2x_cls_c2_entry *c2)
{
  int tcm_idx;

  if (!c2 || index >= MVPP2_CLS_C2_TCAM_SIZE)
    return -EINVAL;

  c2->index = index;

  /* write index reg */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* write valid bit */
  c2->inv = 0;
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_INV_REG,
		   ((c2->inv) << MVPP2_CLS2_TCAM_INV_INVALID_OFF));

  for (tcm_idx = 0; tcm_idx < MVPP2_CLS_C2_TCAM_WORDS; tcm_idx++)
    mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_DATA_REG (tcm_idx), c2->tcam.words[tcm_idx]);

  /* write action_tbl CLSC2_ACT_DATA */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_ACT_DATA_REG, c2->sram.regs.action_tbl);

  /* write actions CLSC2_ACT */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_ACT_REG, c2->sram.regs.actions);

  /* write qos_attr CLSC2_ATTR0 */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_ACT_QOS_ATTR_REG, c2->sram.regs.qos_attr);

  /* write hwf_attr CLSC2_ATTR1 */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_ACT_HWF_ATTR_REG, c2->sram.regs.hwf_attr);

  /* write rss_attr CLSC2_ATTR2 */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_ACT_DUP_ATTR_REG, c2->sram.regs.rss_attr);

  return 0;
}

int
mv_pp2x_cls_c2_color_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int from)
{
  if (!c2 || cmd > MVPP2_COLOR_ACTION_TYPE_RED_LOCK)
    return -EINVAL;

  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_COLOR_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_COLOR_OFF);

  if (from == 1)
    c2->sram.regs.action_tbl |= (1 << MVPP2_CLS2_ACT_DATA_TBL_COLOR_OFF);
  else
    c2->sram.regs.action_tbl &= ~(1 << MVPP2_CLS2_ACT_DATA_TBL_COLOR_OFF);

  return 0;
}
