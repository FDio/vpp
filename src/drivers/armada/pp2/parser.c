/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <string.h>
#include <stdbool.h>
#include <pp2/pp2.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "parser",
};

#define PP2_MAX_BUF_STR_LEN 256

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
  MVPP2_TAG_TYPE_LAST = 5,
};

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

static void
mv_pp2x_prs_shadow_set (mvpp2_device_t *md, int index, int lu)
{
  md->prs_shadow[index].valid = true;
  md->prs_shadow[index].lu = lu;
}

static void
mv_pp2x_prs_shadow_ri_set (mvpp2_device_t *md, int index, unsigned int ri, unsigned int ri_mask)
{
  md->prs_shadow[index].ri_mask = ri_mask;
  md->prs_shadow[index].ri = ri;
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

static u32
mvpp2_prs_eth_start_hdr_get (vnet_dev_port_t *port)
{
  u32 reg_val;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  uintptr_t hif_base = md->pp_base;
  u32 ret = 0;

  reg_val = mvpp2_reg_read (hif_base, MVPP2_MH_REG (mvpp2_port_id (port)));
  if (reg_val & MVPP2_DSA_NON_EXTENDED)
    ret = MVPP2_TAG_TYPE_DSA;
  else if (reg_val & MVPP2_DSA_EXTENDED)
    ret = MVPP2_TAG_TYPE_EDSA;
  else
    ret = MVPP2_TAG_TYPE_NONE;

  return ret;
}

static int
mvpp2_prs_eth_start_hdr_set (vnet_dev_port_t *port,
			     enum mvpp2_port_eth_start_hdr eth_start_hdr)
{
  vnet_dev_t *dev = port->dev;
  u32 reg_val;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  uintptr_t hif_base = md->pp_base;

  reg_val = mvpp2_reg_read (hif_base, MVPP2_MH_REG (mvpp2_port_id (port)));
  reg_val &= ~(MVPP2_DSA_EN_MASK | MVPP2_MH_EN_MASK);

  switch (eth_start_hdr)
    {
    case MVPP2_PORT_HDR_ETH:
    case MVPP2_PORT_HDR_ETH_CUSTOM:
      break;
    case MVPP2_PORT_HDR_ETH_DSA:
      reg_val |= MVPP2_DSA_NON_EXTENDED;
      break;
    case MVPP2_PORT_HDR_ETH_EXT_DSA:
      reg_val |= MVPP2_DSA_EXTENDED;
      break;
    default:
      log_err (dev, "invalid eth_start_hdr, eth_start_hdr = %d\n", eth_start_hdr);
      return -EINVAL;
    }

  /* Write to register */
  mvpp2_reg_write (hif_base, MVPP2_MH_REG (mvpp2_port_id (port)), reg_val);

  return 0;
}

static int
mvpp2_prs_tcam_first_free (vnet_dev_t *dev, mvpp2_device_t *md, unsigned char start,
			   unsigned char end)
{
  int tid;

  if (start > end)
    CLIB_SWAP (start, end);

  for (tid = start; tid <= end; tid++)
    {
      if (!md->prs_shadow[tid].valid)
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
  struct mv_pp2x_prs_entry pe = {};
  struct mv_pp2x_prs_shadow *prs_shadow;
  uintptr_t hif_base = md->pp_base;

  if (!md->prs_shadow)
    {
      uword size = MVPP2_PRS_TCAM_SRAM_SIZE * sizeof (struct mv_pp2x_prs_shadow);

      md->prs_shadow = clib_mem_alloc (size);
      clib_memset (md->prs_shadow, 0, size);
    }

  prs_shadow = md->prs_shadow;

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

static int
mvpp2_prs_port_update (vnet_dev_port_t *port, u32 add, u32 tid, u32 ri, u32 ri_mask)
{
  vnet_dev_t *dev = port->dev;
  struct mv_pp2x_prs_entry pe;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  uintptr_t hif_base = md->pp_base;

  if (!md->prs_shadow[tid].valid)
    {
      log_err (dev, "parser logical port special field DSA mode: entry not found\n");
      return -EFAULT;
    }

  pe.index = tid;
  mv_pp2x_prs_hw_read (hif_base, &pe);

  /* update UDF7 */
  mv_pp2x_prs_sram_ri_update (&pe, ri, ri_mask);

  /* Update port mask */
  mv_pp2x_prs_tcam_port_set (&pe, mvpp2_port_id (port), add);

  mv_pp2x_prs_hw_write (hif_base, &pe);

  return 0;
}

static int
mvpp2_prs_eth_start_header_set (vnet_dev_port_t *port,
				enum mvpp2_port_eth_start_hdr mode)
{
  u32 type;
  int rc;
  u32 nri = 0, ri_mask = 0;

  rc = mvpp2_prs_eth_start_hdr_set (port, mode);
  if (rc)
    return -EFAULT;

  /*Get MH register configured mode */
  type = mvpp2_prs_eth_start_hdr_get (port);

  /* Configure parser DSA entries */
  switch (type)
    {
    case MVPP2_TAG_TYPE_EDSA:
      /* Add port to EDSA entries */
      mvpp2_prs_port_update (port, true, MVPP2_PE_EDSA_TAGGED, nri, ri_mask);
      mvpp2_prs_port_update (port, true, MVPP2_PE_EDSA_UNTAGGED, nri, ri_mask);

      /* Remove port from DSA entries */
      mvpp2_prs_port_update (port, false, MVPP2_PE_DSA_TAGGED, nri, ri_mask);
      mvpp2_prs_port_update (port, false, MVPP2_PE_DSA_UNTAGGED, nri, ri_mask);

      mvpp2_prs_port_update (port, false, MVPP2_PE_MH_SKIP_PRS, nri, ri_mask);

      break;
    case MVPP2_TAG_TYPE_DSA:
      /* Add port to DSA entries */
      mvpp2_prs_port_update (port, true, MVPP2_PE_DSA_TAGGED, nri, ri_mask);
      mvpp2_prs_port_update (port, true, MVPP2_PE_DSA_UNTAGGED, nri, ri_mask);

      /* Remove port from EDSA entries */
      mvpp2_prs_port_update (port, false, MVPP2_PE_EDSA_TAGGED, nri, ri_mask);
      mvpp2_prs_port_update (port, false, MVPP2_PE_EDSA_UNTAGGED, nri, ri_mask);

      mvpp2_prs_port_update (port, false, MVPP2_PE_MH_SKIP_PRS, nri, ri_mask);

      break;
    case MVPP2_TAG_TYPE_MH:
    case MVPP2_TAG_TYPE_NONE:
      /* Remove port form EDSA and DSA entries */
      mvpp2_prs_port_update (port, false, MVPP2_PE_DSA_TAGGED, nri, ri_mask);
      mvpp2_prs_port_update (port, false, MVPP2_PE_DSA_UNTAGGED, nri, ri_mask);
      mvpp2_prs_port_update (port, false, MVPP2_PE_EDSA_TAGGED, nri, ri_mask);
      mvpp2_prs_port_update (port, false, MVPP2_PE_EDSA_UNTAGGED, nri, ri_mask);

      mvpp2_prs_port_update (port, false, MVPP2_PE_MH_SKIP_PRS, nri, ri_mask);
      if (mode == MVPP2_PORT_HDR_ETH_CUSTOM)
	mvpp2_prs_port_update (port, true, MVPP2_PE_MH_SKIP_PRS, nri, ri_mask);

      break;
    default:
      if ((type < 0) || (type > MVPP2_TAG_TYPE_EDSA))
	return -EINVAL;
    }

  return 0;
}

int
mvpp2_parser_eth_start_header_set (
  vnet_dev_port_t *port, enum mvpp2_port_eth_start_hdr eth_start_hdr)
{
  vnet_dev_t *dev = port->dev;
  int rc;

  rc = mvpp2_prs_eth_start_header_set (port, eth_start_hdr);
  if (rc)
    {
      log_err (dev, "%s(%d) mvpp2_prs_eth_start_header_set fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  return 0;
}

vnet_dev_rv_t
mvpp2_parser_init (vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  int rc;
  uintptr_t hif_base = md->pp_base;
  u32 val;

  /* Check if tcam table enabled*/
  val = mvpp2_reg_read (hif_base, MVPP2_PRS_TCAM_CTRL_REG);
  if (val != MVPP2_PRS_TCAM_EN_MASK)
    {
      log_err (dev, "Can't initialize logical port: parser not initialized yet\n");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  /* Update driver parser shadow table from kernel configuration */
  rc = mv_pp2x_prs_shadow_update (dev, md);
  if (rc)
    return VNET_DEV_ERR_INIT_FAILED;

  return VNET_DEV_OK;
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
mvpp2x_prs_mac_da_range_find (vnet_dev_t *dev, mvpp2_device_t *md, uintptr_t hif_base, int pmap,
			      const u8 *da, const u8 *mask, int udf_type)
{
  struct mv_pp2x_prs_entry pe;
  int tid;
  struct mv_pp2x_prs_shadow *prs_shadow = md->prs_shadow;

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
mv_pp2x_prs_mac_da_accept (vnet_dev_port_t *port, const u8 *da, bool add)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  unsigned char mask[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  unsigned int pmap, len, ri;
  struct mv_pp2x_prs_shadow *prs_shadow = md->prs_shadow;
  struct mv_pp2x_prs_entry pe;
  int tid;

  /* Scan TCAM and see if entry with this <MAC DA, port> already exist */
  tid =
    mvpp2x_prs_mac_da_range_find (dev, md, mp->hif_base, BIT (mvpp2_port_id (port)), da, mask, 0);

  /* No such entry */
  if (tid < 0)
    {
      if (!add)
	return 0;

      /* Create new TCAM entry */
      /* Go through the all entries from first to last */
      tid = mvpp2_prs_tcam_first_free (dev, md, prs_shadow->prs_mac_range_start,
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
  mv_pp2x_prs_tcam_port_set (&pe, mvpp2_port_id (port), add);

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

vnet_dev_rv_t
mvpp2_port_add_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
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

      if (mp->num_added_mc_addr == MVPP2_PORT_MAX_MC_ADDR)
	{
	  log_err (dev, "PORT: reached multicast address limit (%d)\n",
		   MVPP2_PORT_MAX_MC_ADDR);
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

      if (vec_len (mp->added_uc_addrs) == MVPP2_PORT_MAX_UC_ADDR)
	{
	  log_err (dev, "PORT: reached unicast address limit (%d)\n",
		   MVPP2_PORT_MAX_UC_ADDR);
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

static void
mvpp2_port_uc_mac_addr_remove (vnet_dev_port_t *port, const uint8_t *addr)
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

vnet_dev_rv_t
mvpp2_port_remove_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
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

      mvpp2_port_uc_mac_addr_remove (port, addr);

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

int
mvpp2_port_flush_mac_addrs (vnet_dev_port_t *port, u32 uc, u32 mc)
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

	  rc = mvpp2_port_remove_mac_addr (port, mac);
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
	    mvpp2_port_remove_mac_addr (port, mp->added_uc_addrs[0].addr);
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
mvpp2_port_set_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
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
mvpp2_port_set_promisc (vnet_dev_port_t *port, int en)
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

static void
mv_pp2x_prs_clear_active_vlans (vnet_dev_port_t *port, uint32_t *vlans)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  struct mv_pp2x_prs_shadow *prs_shadow = md->prs_shadow;
  int index = 0;
  int tid;

  for (tid = MVPP2_PRS_VID_PORT_FIRST (mvpp2_port_id (port));
       tid <= MVPP2_PRS_VID_PORT_LAST (mvpp2_port_id (port)); tid++)
    {
      if (prs_shadow[tid].valid && prs_shadow[tid].lu == MVPP2_PRS_LU_VID)
	{
	  vlans[index++] = ((prs_shadow[tid].tcam.byte[TCAM_DATA_BYTE (2)] & 0xF) << 8) +
			   prs_shadow[tid].tcam.byte[TCAM_DATA_BYTE (3)];
	  prs_shadow[tid].valid = false;
	}
    }
}

void
mvpp2_port_clear_prs_vlans (vnet_dev_port_t *port)
{
  uint32_t vlans[MVPP2_PRS_VLAN_FILT_MAX] = {};
  int i;

  mv_pp2x_prs_clear_active_vlans (port, vlans);
  for (i = 0; (i < MVPP2_PRS_VLAN_FILT_MAX) && (vlans[i] != 0); i++)
    mvpp2_netdev_clear_vlan (port, vlans[i]);
  mvpp2_netdev_set_vlan_filtering (port, 0);
}
