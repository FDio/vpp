/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <pp2/pp2.h>

#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "parser",
};

#define PP2_MAX_BUF_STR_LEN 256

struct mvpp2_parser_shadow
{
  u32 valid;			     /* Entry is valid or not */
  int lu;			     /* Lookup ID */
  union mv_pp2x_prs_tcam_entry tcam; /* TCAM */
  u32 prs_mac_range_start;
  u32 prs_mac_range_end;
};

typedef struct
{
  u32 index;
  union mv_pp2x_prs_tcam_entry tcam;
  union mv_pp2x_prs_sram_entry sram;
} mvpp2_parser_entry_t;

static inline int
mv_check_eaddr_bc (const u8 *eaddr)
{
  return (*(const u16 *) (eaddr + 0) & *(const u16 *) (eaddr + 2) & *(const u16 *) (eaddr + 4)) ==
	 0xffff;
}

static inline int
mv_eaddr_identical (const u8 *eaddr1, const u8 *eaddr2)
{
  const u16 *e1_16 = (const u16 *) eaddr1;
  const u16 *e2_16 = (const u16 *) eaddr2;

  return ((e1_16[0] ^ e2_16[0]) | (e1_16[1] ^ e2_16[1]) | (e1_16[2] ^ e2_16[2])) == 0;
}

static inline int
mv_check_eaddr_mc (const u8 *eaddr)
{
  return eaddr[0] & 1;
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
mv_pp2x_prs_tcam_data_byte_get (mvpp2_parser_entry_t *pe, unsigned int offs, unsigned char *byte,
				unsigned char *enable)
{
  *byte = pe->tcam.byte[TCAM_DATA_BYTE (offs)];
  *enable = pe->tcam.byte[TCAM_DATA_MASK (offs)];
}

static int
mv_pp2x_prs_mac_range_equals (mvpp2_parser_entry_t *pe, const u8 *da, const u8 *mask)
{
  unsigned char tcam_byte, tcam_mask;
  int index;

  for (index = 0; index < ETH_ALEN; index++)
    {
      mv_pp2x_prs_tcam_data_byte_get (pe, index, &tcam_byte, &tcam_mask);
      if (tcam_mask != mask[index])
	return 0;

      if ((tcam_mask & tcam_byte) != (da[index] & mask[index]))
	return 0;
    }

  return 1;
}

static void
mv_pp2x_prs_sram_bits_set (mvpp2_parser_entry_t *pe, int bit_num, int val)
{
  pe->sram.byte[SRAM_BIT_TO_BYTE (bit_num)] |= (val << (bit_num % 8));
}

static void
mv_pp2x_prs_sram_bits_clear (mvpp2_parser_entry_t *pe, int bit_num, int val)
{
  pe->sram.byte[SRAM_BIT_TO_BYTE (bit_num)] &= ~(val << (bit_num % 8));
}

static void
mv_pp2x_prs_shadow_set (mvpp2_device_t *md, int index, int lu)
{
  md->prs_shadow[index].valid = 1;
  md->prs_shadow[index].lu = lu;
}

static void
mv_pp2x_prs_sram_next_lu_set (mvpp2_parser_entry_t *pe, unsigned int lu)
{
  int sram_next_off = MVPP2_PRS_SRAM_NEXT_LU_OFFS;

  mv_pp2x_prs_sram_bits_clear (pe, sram_next_off, MVPP2_PRS_SRAM_NEXT_LU_MASK);
  mv_pp2x_prs_sram_bits_set (pe, sram_next_off, lu);
}

static void
mv_pp2x_prs_sram_shift_set (mvpp2_parser_entry_t *pe, int shift, unsigned int op)
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
mv_pp2x_prs_tcam_data_byte_set (mvpp2_parser_entry_t *pe, unsigned int offs, unsigned char byte,
				unsigned char enable)
{
  pe->tcam.byte[TCAM_DATA_BYTE (offs)] = byte;
  pe->tcam.byte[TCAM_DATA_MASK (offs)] = enable;
}

static void
mv_pp2x_prs_tcam_lu_set (mvpp2_parser_entry_t *pe, unsigned int lu)
{
  unsigned int offset = MVPP2_PRS_TCAM_LU_BYTE;
  unsigned int enable_off = MVPP2_PRS_TCAM_EN_OFFS (MVPP2_PRS_TCAM_LU_BYTE);

  pe->tcam.byte[HW_BYTE_OFFS (offset)] = lu;
  pe->tcam.byte[HW_BYTE_OFFS (enable_off)] = MVPP2_PRS_LU_MASK;
}

static unsigned int
mv_pp2x_prs_tcam_port_map_get (mvpp2_parser_entry_t *pe)
{
  int enable_off = HW_BYTE_OFFS (MVPP2_PRS_TCAM_EN_OFFS (MVPP2_PRS_TCAM_PORT_BYTE));

  return ~(pe->tcam.byte[enable_off]) & MVPP2_PRS_PORT_MASK;
}

static void
mv_pp2x_prs_tcam_port_map_set (mvpp2_parser_entry_t *pe, unsigned int ports)
{
  unsigned char port_mask = MVPP2_PRS_PORT_MASK;
  int enable_off = HW_BYTE_OFFS (MVPP2_PRS_TCAM_EN_OFFS (MVPP2_PRS_TCAM_PORT_BYTE));

  pe->tcam.byte[HW_BYTE_OFFS (MVPP2_PRS_TCAM_PORT_BYTE)] = 0;
  pe->tcam.byte[enable_off] &= ~port_mask;
  pe->tcam.byte[enable_off] |= ~ports & MVPP2_PRS_PORT_MASK;
}

static void
mv_pp2x_prs_tcam_port_set (mvpp2_parser_entry_t *pe, unsigned int port, int add)
{
  int enable_off = HW_BYTE_OFFS (MVPP2_PRS_TCAM_EN_OFFS (MVPP2_PRS_TCAM_PORT_BYTE));

  if (add)
    pe->tcam.byte[enable_off] &= ~(1 << port);
  else
    pe->tcam.byte[enable_off] |= 1 << port;
}

static inline int
mv_check_eaddr_uc (const u8 *addr)
{
  return !mv_check_eaddr_mc (addr);
}

static int
parse_hex (char *str, u8 *addr, size_t size)
{
  int len = 0;

  while (*str && len < size)
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
  log_err (dev, "Out of TCAM Entries !!");
  return -EINVAL;
}

static int
mv_pp2x_prs_hw_read (vnet_dev_t *dev, mvpp2_parser_entry_t *pe)
{
  int i;

  if (pe->index > MVPP2_PRS_TCAM_SRAM_SIZE - 1)
    return -EINVAL;

  /* Write tcam index - indirect access */
  mvpp2_dev_reg_wr (dev, MVPP2_PRS_TCAM_IDX_REG, pe->index);

  pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] =
    mvpp2_dev_reg_rd (dev, MVPP2_PRS_TCAM_DATA_REG (MVPP2_PRS_TCAM_INV_WORD));
  if (pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] & MVPP2_PRS_TCAM_INV_MASK)
    return MVPP2_PRS_TCAM_ENTRY_INVALID;

  for (i = 0; i < MVPP2_PRS_TCAM_WORDS; i++)
    pe->tcam.word[i] = mvpp2_dev_reg_rd (dev, MVPP2_PRS_TCAM_DATA_REG (i));

  /* Write sram index - indirect access */
  mvpp2_dev_reg_wr (dev, MVPP2_PRS_SRAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_SRAM_WORDS; i++)
    pe->sram.word[i] = mvpp2_dev_reg_rd (dev, MVPP2_PRS_SRAM_DATA_REG (i));

  return 0;
}

vnet_dev_rv_t
mvpp2_parser_hw_entry_read (vnet_dev_t *dev, u32 index, union mv_pp2x_prs_tcam_entry *tcam,
			    union mv_pp2x_prs_sram_entry *sram)
{
  mvpp2_parser_entry_t pe = {
    .index = index,
  };

  ASSERT (tcam && sram);

  if (mv_pp2x_prs_hw_read (dev, &pe))
    return VNET_DEV_ERR_NO_SUCH_ENTRY;

  *tcam = pe.tcam;
  *sram = pe.sram;
  return VNET_DEV_OK;
}

static int
mv_pp2x_prs_hw_write (vnet_dev_t *dev, mvpp2_parser_entry_t *pe)
{
  int i;

  if (pe->index > MVPP2_PRS_TCAM_SRAM_SIZE - 1)
    return -EINVAL;

  /* Clear entry invalidation bit */
  pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] &= ~MVPP2_PRS_TCAM_INV_MASK;

  log_debug (
    dev, "program parser entry %u: tcam %08x %08x %08x %08x %08x %08x, sram %08x %08x %08x %08x",
    pe->index, pe->tcam.word[0], pe->tcam.word[1], pe->tcam.word[2], pe->tcam.word[3],
    pe->tcam.word[4], pe->tcam.word[5], pe->sram.word[0], pe->sram.word[1], pe->sram.word[2],
    pe->sram.word[3]);

  /* Write sram index - indirect access */
  mvpp2_dev_reg_wr (dev, MVPP2_PRS_SRAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_SRAM_WORDS; i++)
    mvpp2_dev_reg_wr (dev, MVPP2_PRS_SRAM_DATA_REG (i), pe->sram.word[i]);

  /* Write tcam index - indirect access */
  mvpp2_dev_reg_wr (dev, MVPP2_PRS_TCAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_TCAM_WORDS; i++)
    mvpp2_dev_reg_wr (dev, MVPP2_PRS_TCAM_DATA_REG (i), pe->tcam.word[i]);

  return 0;
}

static void
mv_pp2x_prs_sram_ri_update (mvpp2_parser_entry_t *pe, unsigned int bits, unsigned int mask)
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
mv_pp2x_prs_tcam_invalid_get (mvpp2_parser_entry_t *pe)
{
  return ((pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] & MVPP2_PRS_TCAM_INV_MASK) >>
	  MVPP2_PRS_TCAM_INV_OFFS);
}

static int
mv_pp2x_prs_tcam_lu_get (mvpp2_parser_entry_t *pe)
{
  return pe->tcam.byte[HW_BYTE_OFFS (MVPP2_PRS_TCAM_LU_BYTE)];
}

static int
mv_pp2x_prs_shadow_update (vnet_dev_t *dev, mvpp2_device_t *md)
{
  mvpp2_parser_entry_t pe = {};
  mvpp2_parser_shadow_t *prs_shadow;
  int mac_range_start = -1;
  int mac_range_end = -1;
  int i, j, invalid;

  if (!md->prs_shadow)
    {
      uword size = MVPP2_PRS_TCAM_SRAM_SIZE * sizeof (mvpp2_parser_shadow_t);

      md->prs_shadow = clib_mem_alloc (size);
      clib_memset (md->prs_shadow, 0, size);
    }

  prs_shadow = md->prs_shadow;

  for (i = 0; i < MVPP2_PRS_TCAM_SRAM_SIZE; i++)
    {
      pe.index = i;
      mv_pp2x_prs_hw_read (dev, &pe);
      prs_shadow[i].lu = mv_pp2x_prs_tcam_lu_get (&pe);
      for (j = 0; j < MVPP2_PRS_TCAM_WORDS; j++)
	prs_shadow[i].tcam.word[j] = pe.tcam.word[j];
      invalid = mv_pp2x_prs_tcam_invalid_get (&pe);
      prs_shadow[i].valid = invalid ? 0 : 1;

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
  log_debug (dev, "%s: mac_start:%u, mac_end:%u", __func__, prs_shadow->prs_mac_range_start,
	     prs_shadow->prs_mac_range_end);
  return 0;
}

int
mvpp2_parser_eth_start_header_set (vnet_dev_port_t *port,
				   enum mvpp2_port_eth_start_hdr eth_start_hdr)
{
  vnet_dev_t *dev = port->dev;
  mvpp22_mh_reg_t mh;

  ASSERT (eth_start_hdr == MVPP2_PORT_HDR_ETH);
  mh.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_MH_REG (mvpp2_port_id (port)));
  mh.mh_enable = 0;
  mh.dsa_mode = 0;
  log_debug (dev, "program port %u eth start-header: mh %08x", mvpp2_port_id (port), mh.as_u32);
  mvpp2_dev_reg_wr (dev, MVPP2_MH_REG (mvpp2_port_id (port)), mh.as_u32);

  return 0;
}

vnet_dev_rv_t
mvpp2_parser_init (vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  int rc;
  u32 val;

  /* Check if tcam table enabled*/
  val = mvpp2_dev_reg_rd (dev, MVPP2_PRS_TCAM_CTRL_REG);
  if (val != MVPP2_PRS_TCAM_EN_MASK)
    {
      log_err (dev, "Can't initialize logical port: parser not initialized yet");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  /* Update driver parser shadow table from kernel configuration */
  rc = mv_pp2x_prs_shadow_update (dev, md);
  if (rc)
    return VNET_DEV_ERR_INIT_FAILED;

  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_parser_get_filter_counts (vnet_dev_port_t *port, u32 *n_uc, u32 *n_mc)
{
  mvpp2_parser_entry_t pe = {};
  u32 port_mask = 1 << mvpp2_port_id (port);
  u8 addr[ETH_ALEN];
  u8 mask;
  u32 i;
  u32 tid;

  ASSERT (n_uc && n_mc);

  *n_uc = *n_mc = 0;
  for (tid = 0; tid < MVPP2_PRS_TCAM_SRAM_SIZE; tid++)
    {
      pe.index = tid;
      if (mv_pp2x_prs_hw_read (port->dev, &pe) ||
	  mv_pp2x_prs_tcam_lu_get (&pe) != MVPP2_PRS_LU_MAC ||
	  !(mv_pp2x_prs_tcam_port_map_get (&pe) & port_mask))
	continue;

      for (i = 0; i < ETH_ALEN; i++)
	{
	  mv_pp2x_prs_tcam_data_byte_get (&pe, i, addr + i, &mask);
	  if (mask != 0xff)
	    break;
	}
      if (mask != 0xff || mv_check_eaddr_bc (addr))
	continue;

      if (mv_check_eaddr_mc (addr))
	(*n_mc)++;
      else
	(*n_uc)++;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_parser_get_promisc (vnet_dev_port_t *port, int *enabled)
{
  mvpp2_parser_entry_t pe = {
    .index = MVPP2_PE_MAC_UC_PROMISCUOUS,
  };

  ASSERT (enabled);

  if (mv_pp2x_prs_hw_read (port->dev, &pe))
    return VNET_DEV_ERR_INVALID_DATA;

  *enabled = !!(mv_pp2x_prs_tcam_port_map_get (&pe) & BIT (mvpp2_port_id (port)));
  return VNET_DEV_OK;
}

static void
mv_pp2x_prs_hw_inv (vnet_dev_t *dev, int index)
{
  log_debug (dev, "invalidate parser entry %u", index);

  /* Write index - indirect access */
  mvpp2_dev_reg_wr (dev, MVPP2_PRS_TCAM_IDX_REG, index);
  mvpp2_dev_reg_wr (dev, MVPP2_PRS_TCAM_DATA_REG (MVPP2_PRS_TCAM_INV_WORD),
		    MVPP2_PRS_TCAM_INV_MASK);
}

static int
mvpp2x_prs_mac_da_range_find (vnet_dev_t *dev, mvpp2_device_t *md, int pmap, const u8 *da,
			      const u8 *mask, int udf_type)
{
  mvpp2_parser_entry_t pe;
  int tid;
  mvpp2_parser_shadow_t *prs_shadow = md->prs_shadow;

  /* Go through all entries with MVPP2_PRS_LU_MAC */
  for (tid = prs_shadow->prs_mac_range_start; tid <= prs_shadow->prs_mac_range_end; tid++)
    {
      unsigned int entry_pmap;

      if (!prs_shadow[tid].valid || prs_shadow[tid].lu != MVPP2_PRS_LU_MAC)
	continue;
      pe.index = tid;
      mv_pp2x_prs_hw_read (dev, &pe);
      entry_pmap = mv_pp2x_prs_tcam_port_map_get (&pe);

      if (mv_pp2x_prs_mac_range_equals (&pe, da, mask))
	{
	  log_debug (dev, "maps: %d:%d", entry_pmap, pmap);
	  if (entry_pmap == pmap)
	    return tid;
	}
    }

  return -ENOENT;
}

static int
mv_pp2x_prs_mac_da_accept (vnet_dev_port_t *port, const u8 *da, int add)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  unsigned char mask[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  unsigned int pmap, len, ri;
  mvpp2_parser_shadow_t *prs_shadow = md->prs_shadow;
  mvpp2_parser_entry_t pe;
  int tid;

  /* Scan TCAM and see if entry with this <MAC DA, port> already exist */
  tid = mvpp2x_prs_mac_da_range_find (dev, md, BIT (mvpp2_port_id (port)), da, mask, 0);

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
      mv_pp2x_prs_hw_read (dev, &pe);
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

      mv_pp2x_prs_hw_inv (dev, pe.index);
      prs_shadow[pe.index].valid = 0;
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

  /* Shift to ethertype */
  mv_pp2x_prs_sram_shift_set (&pe, 2 * ETH_ALEN, MVPP2_PRS_SRAM_OP_SEL_SHIFT_ADD);

  /* Update shadow table and hw entry */
  mv_pp2x_prs_shadow_set (md, pe.index, MVPP2_PRS_LU_MAC);
  mv_pp2x_prs_hw_write (dev, &pe);

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
	  log_err (dev, "reached multicast address limit (%d)", MVPP2_PORT_MAX_MC_ADDR);
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
	  log_err (dev, "unable to add mac sddress");
	  return VNET_DEV_ERR_INTERNAL;
	}
      mp->num_added_mc_addr++;

      log_debug (dev, "eth address %x:%x:%x:%x:%x:%x added to mc list", addr[0], addr[1], addr[2],
		 addr[3], addr[4], addr[5]);
      log_debug (dev, "num_mc:%d", mp->num_added_mc_addr);
    }
  else if (mv_check_eaddr_uc (addr))
    {
      if (vec_len (mp->added_uc_addrs) == MVPP2_PORT_MAX_UC_ADDR)
	{
	  log_err (dev, "reached unicast address limit (%d)", MVPP2_PORT_MAX_UC_ADDR);
	  return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	}

      mv_pp2x_prs_mac_da_accept (port, addr, 1);

      vec_add2 (mp->added_uc_addrs, uc_addr, 1);
      mv_cp_eaddr (uc_addr->addr, addr);

      log_debug (dev, "eth address %x:%x:%x:%x:%x:%x added", addr[0], addr[1], addr[2], addr[3],
		 addr[4], addr[5]);
      log_debug (dev, "num_uc:%d", vec_len (mp->added_uc_addrs));
    }
  else
    {
      log_err (dev, "eth address is not unicast/multicast. Request ignored");
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
	log_debug (dev, "removed %x:%x:%x:%x:%x:%x from port", addr[0], addr[1], addr[2], addr[3],
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
	  log_err (dev, "unable to remove mac sddress");
	  return VNET_DEV_ERR_INTERNAL;
	}
      mp->num_added_mc_addr--;
      log_debug (dev, "eth address %x:%x:%x:%x:%x:%x removed from mc list", addr[0], addr[1],
		 addr[2], addr[3], addr[4], addr[5]);
      log_debug (dev, "num_mc:%d", mp->num_added_mc_addr);
    }
  else if (mv_check_eaddr_uc (addr))
    {
      mv_pp2x_prs_mac_da_accept (port, addr, 0);

      mvpp2_port_uc_mac_addr_remove (port, addr);

      log_debug (dev, "eth address %x:%x:%x:%x:%x:%x removed", addr[0], addr[1], addr[2], addr[3],
		 addr[4], addr[5]);
      log_debug (dev, "num_uc:%d", vec_len (mp->added_uc_addrs));
    }
  else
    {
      log_err (dev, "eth address is not unicast/multicast. Request ignored");
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
	      log_err (dev, "address not found in file");
	      return -EFAULT;
	    }

	  if ((strcmp (ifname, name)) || (!st))
	    continue;

	  len = parse_hex (addr_str, mac, ETH_ALEN);
	  if (len != ETH_ALEN)
	    {
	      log_err (dev, "len parsing error");
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
      while (vec_len (mp->added_uc_addrs))
	mvpp2_port_remove_mac_addr (port, mp->added_uc_addrs[0].addr);
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
      log_err (dev, "not a valid eth address");
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
      log_err (dev, "unable to read promisc mode from HW");
      return VNET_DEV_ERR_INTERNAL;
    }

  if (en)
    s.ifr_flags |= IFF_PROMISC;
  else
    s.ifr_flags &= ~IFF_PROMISC;

  rc = mvpp2_netdev_ioctl (dev, SIOCSIFFLAGS, &s);
  if (rc)
    {
      log_err (dev, "unable to set promisc mode to HW");
      return VNET_DEV_ERR_INTERNAL;
    }
  return VNET_DEV_OK;
}

static void
mv_pp2x_prs_clear_active_vlans (vnet_dev_port_t *port, uint32_t *vlans)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_parser_shadow_t *prs_shadow = md->prs_shadow;
  int index = 0;
  int tid;

  for (tid = MVPP2_PRS_VID_PORT_FIRST (mvpp2_port_id (port));
       tid <= MVPP2_PRS_VID_PORT_LAST (mvpp2_port_id (port)); tid++)
    {
      if (prs_shadow[tid].valid && prs_shadow[tid].lu == MVPP2_PRS_LU_VID)
	{
	  vlans[index++] = ((prs_shadow[tid].tcam.byte[TCAM_DATA_BYTE (2)] & 0xF) << 8) +
			   prs_shadow[tid].tcam.byte[TCAM_DATA_BYTE (3)];
	  prs_shadow[tid].valid = 0;
	}
    }
}

vnet_dev_rv_t
mvpp2_port_clear_prs_vlans (vnet_dev_port_t *port)
{
  uint32_t vlans[MVPP2_PRS_VLAN_FILT_MAX] = {};
  int i;

  mv_pp2x_prs_clear_active_vlans (port, vlans);
  for (i = 0; (i < MVPP2_PRS_VLAN_FILT_MAX) && (vlans[i] != 0); i++)
    mvpp2_netdev_clear_vlan (port, vlans[i]);
  return mvpp2_netdev_set_vlan_filtering (port, 0);
}
