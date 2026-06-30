/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Marvell.
 */

#include <stdint.h>
#include <assert.h>
#include <string.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <musdk.h>
#include <musdk_internal.h>
#include <pp2/pp2_regs.h>
#include <pp2/pp2.h>

#include <endian.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "musdk",
};

#define ARP_PROTO 0x806 /* Address Resolution packet	*/
#define PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_MASK                                                     \
  (0x00000001 << PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_OFFS)
#define PP2_GMAC_PORT_CTRL1_REG		     (0x0004)
#define PP2_GMAC_PORT_STATUS0_FULLDX_MASK    (0x00000001 << PP2_GMAC_PORT_STATUS0_FULLDX_OFFS)
#define PP2_GMAC_PORT_STATUS0_GMIISPEED_MASK (0x00000001 << PP2_GMAC_PORT_STATUS0_GMIISPEED_OFFS)
#define PP2_GMAC_PORT_STATUS0_LINKUP_MASK    (0x00000001 << PP2_GMAC_PORT_STATUS0_LINKUP_OFFS)
#define PP2_GMAC_PORT_STATUS0_MIISPEED_MASK  (0x00000001 << PP2_GMAC_PORT_STATUS0_MIISPEED_OFFS)
#define PP2_GMAC_PORT_STATUS0_PORTRXPAUSE_MASK                                                     \
  (0x00000001 << PP2_GMAC_PORT_STATUS0_PORTRXPAUSE_OFFS)
#define PP2_GMAC_PORT_STATUS0_PORTTXPAUSE_MASK                                                     \
  (0x00000001 << PP2_GMAC_PORT_STATUS0_PORTTXPAUSE_OFFS)
#define PP2_GMAC_PORT_STATUS0_REG	     (0x0010)
#define PP2_GMAC_PORT_STATUS0_RXFCEN_MASK    (0x00000001 << PP2_GMAC_PORT_STATUS0_RXFCEN_OFFS)
#define PP2_GMAC_PORT_STATUS0_TXFCEN_MASK    (0x00000001 << PP2_GMAC_PORT_STATUS0_TXFCEN_OFFS)
#define PP2_XLG_MAC_CTRL0_RXFCEN_MASK	     (0x00000001 << PP2_XLG_MAC_CTRL0_RXFCEN_OFFS)
#define PP2_XLG_MAC_CTRL0_TXFCEN_MASK	     (0x00000001 << PP2_XLG_MAC_CTRL0_TXFCEN_OFFS)
#define PP2_XLG_MAC_CTRL1_MACLOOPBACKEN_MASK (0x00000001 << PP2_XLG_MAC_CTRL1_MACLOOPBACKEN_OFFS)
#define PP2_XLG_MAC_CTRL1_XGMIILOOPBACKEN_MASK                                                     \
  (0x00000001 << PP2_XLG_MAC_CTRL1_XGMIILOOPBACKEN_OFFS)
#define PP2_XLG_MAC_CTRL3_MACMODESELECT_MASK (0x00000007 << PP2_XLG_MAC_CTRL3_MACMODESELECT_OFFS)
#define PP2_XLG_MAC_CTRL3_MACMODESELECT_OFFS 13
#define PP2_XLG_MAC_PORT_STATUS_LINKSTATUS_MASK                                                    \
  (0x00000001 << PP2_XLG_MAC_PORT_STATUS_LINKSTATUS_OFFS)
#define PP2_XLG_MAC_PORT_STATUS_PORTRXPAUSE_MASK                                                   \
  (0x00000001 << PP2_XLG_MAC_PORT_STATUS_PORTRXPAUSE_OFFS)
#define PP2_XLG_MAC_PORT_STATUS_PORTTXPAUSE_MASK                                                   \
  (0x00000001 << PP2_XLG_MAC_PORT_STATUS_PORTTXPAUSE_OFFS)
#define PP2_XLG_MAC_PORT_STATUS_REG (0x000c)
#define PP2_XLG_PORT_MAC_CTRL0_REG  (0x0000)
#define PP2_XLG_PORT_MAC_CTRL3_REG  (0x001c)
#define PPPOE_PROTO		    0x8864 /* PPPoE packet	*/

#define PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_OFFS	 5
#define PP2_GMAC_PORT_STATUS0_FULLDX_OFFS	 3
#define PP2_GMAC_PORT_STATUS0_GMIISPEED_OFFS	 1
#define PP2_GMAC_PORT_STATUS0_LINKUP_OFFS	 0
#define PP2_GMAC_PORT_STATUS0_MIISPEED_OFFS	 2
#define PP2_GMAC_PORT_STATUS0_PORTRXPAUSE_OFFS	 6
#define PP2_GMAC_PORT_STATUS0_PORTTXPAUSE_OFFS	 7
#define PP2_GMAC_PORT_STATUS0_RXFCEN_OFFS	 4
#define PP2_GMAC_PORT_STATUS0_TXFCEN_OFFS	 5
#define PP2_XLG_MAC_CTRL0_RXFCEN_OFFS		 7
#define PP2_XLG_MAC_CTRL0_TXFCEN_OFFS		 8
#define PP2_XLG_MAC_CTRL1_MACLOOPBACKEN_OFFS	 13
#define PP2_XLG_MAC_CTRL1_XGMIILOOPBACKEN_OFFS	 14
#define PP2_XLG_MAC_PORT_STATUS_LINKSTATUS_OFFS	 0
#define PP2_XLG_MAC_PORT_STATUS_PORTRXPAUSE_OFFS 6
#define PP2_XLG_MAC_PORT_STATUS_PORTTXPAUSE_OFFS 7

#define MVPP2_C3_DEFAULT_SEARCH_DEPTH (3) /* default cuckoo search depth	*/

#define PP2_BUFFER_OFFSET_GRAN (32)

#define PP2_ETHADDR_LEN (6)

#define PP2_MAX_PACKET_OFFSET (7 * 32)

#define PP2_PACKET_DEF_OFFSET (L1_CACHE_LINE_BYTES)

#define PP2_TCLK_FREQ 333000000

#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

#define roundup_pow_of_two(n) (1 << fls (n - 1))

#define mvlog2(n) (fls (n) - 1)

#define MSS_CP_CM3_BUF_POOL_BASE 0x40

#define MSS_CP_CM3_BUF_POOL_OFFS 4

#define MSS_CP_FC_COM_REG 0

#define MVPP2_C2_LOGIC_IDX_BASE 1000

#define NOT_IN_USE (-1)

#define PP2_BUFFER_OFFSET (32)

#define MVPP2_CLS_FL_RND_SIZE (25) /* max rule hits per CLS round	*/

#define RND_HIT_CNT(cnt, r) (cnt[r].c2 + cnt[r].c3 + cnt[r].c4)

#define WAY_MAX (1)

#define fls(n) ((sizeof (n) <= 4) ? fls_32 (n) : fls_64 (n))

#define HW_BYTE_OFFS(_offs_) (_offs_)

#define IS_ALIGNED(val, align) (((val) & ((typeof (val)) (align) - 1)) == 0)

#define likely(x) __builtin_expect (!!(x), 1)

#define WORD_BYTES		   (4)
#define BYTE_MASK		   (0xFF)
#define MSS_CP_CM3_RXQ_ASS_OFFS	   4
#define MSS_CP_CM3_RXQ_ASS_PER_REG 4
#define IN_USE			   (1)
#define DWORD_BITS_LEN		   (32)

#define KEY_PRT_ID(ext_mode) ((ext_mode == 1) ? (99) : (107))
#define KEY_PRT_ID_MASK(ext_mode)                                                                  \
  (((1 << KEY_CTRL_PRT_ID_BITS) - 1) << (KEY_PRT_ID (ext_mode) % 32))

#define KEY_PRT_ID_TYPE(ext_mode) ((ext_mode == 1) ? (97) : (105))
#define KEY_PRT_ID_TYPE_MASK(ext_mode)                                                             \
  ((KEY_CTRL_PRT_ID_TYPE_MAX) << (KEY_PRT_ID_TYPE (ext_mode) % 32))

#define KEY_LKP_TYPE(ext_mode) ((ext_mode == 1) ? (91) : (99))
#define KEY_LKP_TYPE_MASK(ext_mode)                                                                \
  (((1 << KEY_CTRL_LKP_TYPE_BITS) - 1) << (KEY_LKP_TYPE (ext_mode) % 32))

#define KEY_L4_INFO(ext_mode)	   ((ext_mode == 1) ? (88) : (96))
#define KEY_L4_INFO_MASK(ext_mode) (((1 << KEY_CTRL_L4_BITS) - 1) << (KEY_L4_INFO (ext_mode) % 32))

#define MSS_CP_CM3_RXQ_ASS_BASE 0x80
#define MSS_CP_CM3_RXQ_ASS_PQ_BASE(queue)                                                          \
  (((queue) / MSS_CP_CM3_RXQ_ASS_PER_REG) * MSS_CP_CM3_RXQ_ASS_OFFS)
#define MSS_CP_CM3_RXQ_TR_BASE	   0x200
#define MSS_CP_CM3_RXQ_TR_OFFS	   4
#define MVPP2_C3_INVALID_ENTRY_NUM (0x1FFF) /* invalid C3 entry number	*/
#define MVPP2_C3_MAX_HASH_KEY_SIZE (MVPP2_CLS_C3_EXT_HEK_WORDS * WORD_BYTES) /* max key size */
#define MVPP2_MEMBER_NUM(array)	   ARRAY_SIZE (array)
#define MV_VLAN_PRIO_MASK	   0xe000 /* Priority Code Point */
#define MV_VLAN_PRIO_SHIFT	   13
#define MV_XT_DSCP_MAX		   0x3f /* 00111111 */

#define BITS_PER_BYTE		      (8)
#define FEATSTRS_MAX		      64
#define MSS_CP_CM3_RXQ_ASS_REG(queue) (MSS_CP_CM3_RXQ_ASS_BASE + MSS_CP_CM3_RXQ_ASS_PQ_BASE (queue))
#define MSS_CP_CM3_RXQ_TRESH_REG(queue)                                                            \
  (MSS_CP_CM3_RXQ_TR_BASE + ((queue) * MSS_CP_CM3_RXQ_TR_OFFS))
#define MV_DSCP_NUM	       (1 + MV_XT_DSCP_MAX)
#define MVPP2_CLS_DEF_SEQ_CTRL 0
#define MVPP2_TXP_MAX_CONFIGURABLE_BUCKET_SIZE                                                     \
  (MVPP2_TXP_TOKEN_SIZE_MAX - MVPP2_TXP_REFILL_TOKENS_MAX)
#define MVPP2_TXQ_MAX_CONFIGURABLE_BUCKET_SIZE                                                     \
  (MVPP2_TXQ_TOKEN_SIZE_MAX - MVPP2_TXQ_REFILL_TOKENS_MAX)
#define MV_VLAN_PRIO_NUM       (1 + (MV_VLAN_PRIO_MASK >> MV_VLAN_PRIO_SHIFT))
#define NOT_SUPPORTED_YET      255
#define PP2_AMPLIFY_FACTOR_MTU (3)
#define PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_MASK                                                    \
  (0x00001fff << PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_OFFS)
#define PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_OFFS 2
#define PP2_GMAC_PORT_CTRL0_REG			(0x0000)
#define PP2_WRR_WEIGHT_UNIT			(256)
#define PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_MASK	(0x00001fff << PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_OFFS)
#define PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_OFFS	0
#define PP2_XLG_PORT_MAC_CTRL1_REG		(0x0004)
#define usleep_range(us, range)			usleep (us)

#define lower_32_bits(n)	       ((u32) (n))
#define PP2_ETH_PORT_TXQ_PREFETCH      PP2_TXQ_PREFETCH_16
#define PP2_LOOPBACK_PORT_TXQ_PREFETCH PP2_TXQ_PREFETCH_64
#define PP2_TXQ_PREFETCH_16	       (16)
#define PP2_TXQ_PREFETCH_32	       (32)
#define PP2_TXQ_PREFETCH_64	       (64)
#define SRAM_BIT_IN_WORD(_bit_)	       HW_BYTE_OFFS ((_bit_) % 32)
#define SRAM_BIT_TO_BYTE(_bit_)	       HW_BYTE_OFFS ((_bit_) / 8)
#define SRAM_BIT_TO_WORD(_bit_)	       HW_BYTE_OFFS ((_bit_) / 32)
#define TCAM_DATA_BYTE(_offs_)	       (HW_BYTE_OFFS (TCAM_DATA_BYTE_OFFS_LE (_offs_)))
#define TCAM_DATA_MASK(_offs_)	       (HW_BYTE_OFFS (TCAM_DATA_MASK_OFFS_LE (_offs_)))
#define udelay(us)		       usleep (us)
#define upper_32_bits(n)	       ((u32) (((n) >> 16) >> 16))

#define TCAM_DATA_BYTE_OFFS_LE(_offs_) (((_offs_) - ((_offs_) % 2)) * 2 + ((_offs_) % 2))
#define TCAM_DATA_MASK_OFFS_LE(_offs_) (((_offs_) * 2) - ((_offs_) % 2) + 2)

#define LUID_IS_LSP_RESERVED(luid) (NULL)

#define MV_ETH_ETYPE_LEN 2

#define PP2_MAX_BUF_STR_LEN 256

#define PP2_PORT_MIN_MTU (68)
#define MAX_LOOKUP	 3

#define MAX_PROTO_NUM 3
#ifndef swap
#define swap(a, b)                                                                                 \
  do                                                                                               \
    {                                                                                              \
      typeof (a) __tmp = (a);                                                                      \
      (a) = (b);                                                                                   \
      (b) = __tmp;                                                                                 \
    }                                                                                              \
  while (0)
#endif
#define PP2_PPIO_MAX_MC_ADDR 21

#define PP2_PPIO_MAX_UC_ADDR 4

#define TXD_BUFMODE_MASK (0x00000080)

#define TXD_BUF_VIRT_HI_MASK (0x000000FF)

#define TXD_POOL_ID_MASK (0x000F0000)

#define PORT_STRING "pp_port_%d:%d"

#define HUGE_PAGE_MAX_PAGE_COUNT    64
#define MVCONF_DMA_PHYS_ADDR_T_SIZE 64
#define __iomem
#ifndef BUG
#define BUG abort
#endif /* !BUG */

#define unlikely(x) __builtin_expect (!!(x), 0)

#define PP2_NUM_ETH_PPIO      3
#define PP2_NUM_PORTS	      4
#define PP2_MAX_NUM_PACKPROCS 4
#define PP2_HW_PORT_NUM_RXQS  32
#define MVPP2_C2_FIRST_ENTRY  16 /* reserve 0-15 entries for kernel usage */
#define INT_32_MAX_DEC_STR_SZ 10 /* max num of decimal digits in 32-bit integer */
#ifndef ARRAY_SIZE
/**
 * TODO
 *
 * @param[in]	_arr	TODO
 *
 * @return	TODO
 */
#define ARRAY_SIZE(_arr) (sizeof (_arr) / sizeof ((_arr)[0]))
#endif /* !ARRAY_SIZE */
#define MV_ERROR			  (-1)
#define MVPP2_TOKEN_PERIOD_400_CORE_CLOCK (400) /* 400 core clock		*/
#define MVPP2_TOKEN_PERIOD_480_CORE_CLOCK (480) /* 480 core clock		*/
#define MVPP2_TOKEN_PERIOD_600_CORE_CLOCK (600) /* 600 core clock		*/
#define MVPP2_TOKEN_PERIOD_800_CORE_CLOCK (800) /* 800 core clock		*/
#define MV_OK				  (0)
#define RETRIES_EXCEEDED		  (15000)
#define MAX_FILE_NAME_LEN		  64
#define PP2_BPOOL_NUM_POOLS		  16
#define PP2_LPBK_PORT_TXQ_SIZE		  4096
#define PP2_MAX_NUM_USED_INTERRUPTS	  4
#define PP2_DUMMY_POOL_BUF_SIZE		  64
#define DUMMY_PKT_OFFS			  64
#define DUMMY_PKT_EFEC_OFFS		  (DUMMY_PKT_OFFS + MV_MH_SIZE)
#define TXD_ERR_SUM_MASK		  0x04000000
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

struct pp2_cls_db_t;
struct mv_pp2x_cls_c2_entry;
struct netdev_featstrs;
struct pp2_cls_c3_entry;
struct pp2_cls_c3_hash_pair;
struct mv_pp2x_cls_c2_qos_entry;
struct mv_pp2x_prs_shadow;
struct mv_pp2x_cls_shadow;
struct mv_pp2x_c2_shadow;
struct ethtool_gstrings;

enum pp2_port_speed
{
  PP2_PORT_SPEED_AN,
  PP2_PORT_SPEED_10,
  PP2_PORT_SPEED_100,
  PP2_PORT_SPEED_1000,
  PP2_PORT_SPEED_2500,
  PP2_PORT_SPEED_10000,
};

enum pp2_port_duplex
{
  PP2_PORT_DUPLEX_AN,
  PP2_PORT_DUPLEX_HALF,
  PP2_PORT_DUPLEX_FULL,
};

enum pp2_port_fc
{
  PP2_PORT_FC_AN_NO,
  PP2_PORT_FC_AN_SYM,
  PP2_PORT_FC_AN_ASYM,
  PP2_PORT_FC_DISABLE,
  PP2_PORT_FC_ENABLE,
  PP2_PORT_FC_ACTIVE,
};

struct pp2_port_link_status
{
  int linkup;
  enum pp2_port_speed speed;
  enum pp2_port_duplex duplex;
  enum pp2_phy_interface phy_mode;
  enum pp2_port_fc rx_fc;
  enum pp2_port_fc tx_fc;
};

#define PP2_PPIO_DESC_NUM_FRAGS 16 /* TODO: check if there is HW limitation */
enum pp2_lb_type
{
  PP2_DISABLE_LB,
  PP2_RX_2_TX_LB,
  PP2_TX_2_RX_LB,	  /* on SERDES level - analog loopback */
  PP2_TX_2_RX_DIGITAL_LB, /* on SERDES level - digital loopback */
};

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

struct pp2_cls_c3_hash_pair
{
  u16 pair_num;
  u16 old_idx[MVPP2_CLS_C3_MAX_SEARCH_DEPTH];
  u16 new_idx[MVPP2_CLS_C3_MAX_SEARCH_DEPTH];
};

struct pp2_cls_c3_entry
{
  u32 index;
  u32 ext_index;

  struct
  {
    union
    {
      u32 words[MVPP2_CLS_C3_EXT_HEK_WORDS];
      u8 bytes[MVPP2_CLS_C3_EXT_HEK_WORDS * 4];
    } hek;
    u32 key_ctrl; /*0x1C10*/
  } key;
  union
  {
    u32 words[MVPP2_CLS_C3_SRAM_WORDS];
    struct
    {
      u32 actions;    /*0x1D40*/
      u32 qos_attr;   /*0x1D44*/
      u32 hwf_attr;   /*0x1D48*/
      u32 dup_attr;   /*0x1D4C*/
      u32 seq_l_attr; /*0x1D50*/
      u32 seq_h_attr; /*0x1D54*/
    } regs;
  } sram;
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

struct netdev_featstrs
{
  char *s[FEATSTRS_MAX];
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
  u32 num_musdk_tbls;	     /* number of RSS tables required by MUSDK */
  u32 num_kernel_rsrvd_tbls; /* number of RSS tables reserved by kernel */
  struct rss_tbl_map_t rss_tbl_map[MVPP22_RSS_TBL_NUM]; /* RSS table mapping for MUSDK RSS tables */
};

struct pp2_cls_db_t
{
  struct pp2_cls_db_prs_t prs_db; /* PP2_CLS module PARSER db	*/
  struct pp2_cls_db_rss_t rss_db; /* PP2_CLS module RSS db		*/
};

static u8 pp2_get_num_inst (vnet_dev_t *dev);

static inline bool mv_check_eaddr_mc (const u8 *eaddr);
static inline int mv_check_eaddr_valid (const u8 *addr);
static inline void mv_cp_eaddr (u8 *dest, const u8 *source);
static int mv_pp2x_cls_c2_color_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int from);
static u8 pp2_cls_c2_tcam_port_get (struct mv_pp2x_cls_c2_entry *c2);
static int mv_pp2x_cls_c2_hw_write (uintptr_t hif_base, int index, struct mv_pp2x_cls_c2_entry *c2);
static int mv_pp2x_cls_c2_hw_read (vnet_dev_t *dev, uintptr_t hif_base, int index,
				   struct mv_pp2x_cls_c2_entry *c2);
static void mv_pp2x_c2_sw_clear (struct mv_pp2x_cls_c2_entry *c2);

static int pp2_gop_gmac_link_status (mvpp2_device_t *md, int mac_num,
				     struct pp2_port_link_status *pstatus);
static int pp2_gop_xlg_mac_link_status (mvpp2_device_t *md, int mac_num,
					struct pp2_port_link_status *pstatus);
static void pp2_port_mac_set_loopback (vnet_dev_port_t *port, int en);

#define BM_TYPE_SHORT_BUF_POOL (0x00)
#define BM_TYPE_LONG_BUF_POOL  (0x01)

typedef enum
{
  PP2_TRAFFIC_NONE,
  PP2_TRAFFIC_INGRESS,
  PP2_TRAFFIC_EGRESS,
  PP2_TRAFFIC_INGRESS_EGRESS,
} pp2_traffic_mode;

#define MV_DEFAULT_MTU	   1500
#define MV_MTU_TO_MRU(mtu) ((mtu) + MV_MH_SIZE + MV_VLAN_TAG_LEN + MV_ETH_HLEN + MV_ETH_FCS_LEN)

static u32
pp2_port_id (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  return mp->id;
}

static_always_inline mvpp2_rxq_t *
pp2_port_rxq_get (vnet_dev_port_t *port, u32 queue_id)
{
  vnet_dev_rx_queue_t *q;

  q = vnet_dev_get_port_rx_queue_by_id (port, queue_id);
  ASSERT (q);
  return vnet_dev_get_rx_queue_data (q);
}

static_always_inline u16
pp2_port_mru (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  return mp->port_mru;
}

static_always_inline u16
pp2_port_mtu (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  return mp->port_mtu;
}

static inline u32 fls_32 (u32 x);
static inline u32 fls_64 (u64 x);

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

struct mv_pp2x_prs_entry;

static void mv_pp2x_prs_tcam_data_byte_get (struct mv_pp2x_prs_entry *pe, unsigned int offs,
					    unsigned char *byte, unsigned char *enable);

static bool mv_pp2x_prs_mac_range_equals (struct mv_pp2x_prs_entry *pe, const u8 *da,
					  const u8 *mask);

static inline uint32_t
pp2_reg_read (uintptr_t hif_base, uint32_t offset)
{
  volatile u32 *addr = (void *) (hif_base + offset);
  u32 value;

  value = le32toh (__atomic_load_n (addr, __ATOMIC_RELAXED));
  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static int
pp2_cls_c3_cpu_done (uintptr_t hif_base)
{
  u32 reg_val;

  reg_val = pp2_reg_read (hif_base, MVPP2_CLS3_STATE_REG);
  reg_val &= MVPP2_CLS3_STATE_CPU_DONE_MASK;
  reg_val >>= MVPP2_CLS3_STATE_CPU_DONE;
  return reg_val;
}

static inline void
pp2_reg_write (uintptr_t hif_base, uint32_t offset, uint32_t data)
{
  volatile u32 *addr = (void *) (hif_base + offset);

  asm volatile ("dsb st" : : : "memory");
  __atomic_store_n (addr, htole32 (data), __ATOMIC_RELAXED);
}

static int
mv_pp2x_range_validate (vnet_dev_t *dev, int value, int min, int max)
{
  if (((value) > (max)) || ((value) < (min)))
    {
      log_err (dev, "%s: value 0x%X (%d) is out of range [0x%X , 0x%X].\n", __func__, (value),
	       (value), (min), (max));
      return MV_ERROR;
    }
  return 0;
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

union mv_pp2x_prs_tcam_entry
{
  u32 word[MVPP2_PRS_TCAM_WORDS];
  u8 byte[MVPP2_PRS_TCAM_WORDS * 4];
};

union mv_pp2x_prs_sram_entry
{
  u32 word[MVPP2_PRS_SRAM_WORDS];
  u8 byte[MVPP2_PRS_SRAM_WORDS * 4];
};

struct mv_pp2x_prs_entry
{
  u32 index;
  union mv_pp2x_prs_tcam_entry tcam;
  union mv_pp2x_prs_sram_entry sram;
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

struct mv_pp2x_cls_c2_entry
{
  u32 index;
  u32 inv;
  union
  {
    u32 words[MVPP2_CLS_C2_TCAM_WORDS];
    u8 bytes[MVPP2_CLS_C2_TCAM_WORDS * 4];
  } tcam;
  union
  {
    u32 words[MVPP2_CLS_C2_SRAM_WORDS];
    struct
    {
      u32 action_tbl; /* 0x1B30 */
      u32 actions;    /* 0x1B60 */
      u32 qos_attr;   /* 0x1B64*/
      u32 hwf_attr;   /* 0x1B68 */
      u32 rss_attr;   /* 0x1B6C */
      u32 seq_attr;   /* 0x1B70 */
    } regs;
  } sram;
};

struct pp2_cls_c3_shadow_hash_entry
{
  /* valid if size > 0 */
  /* size include the extension*/
  int ext_ptr;
  int size;
};

static const struct pp2_mac_data hc_gop_mac_data[12] = { {
							   .phy_mode = 18,
							   .mac = { [5] = 1, },
							 },
							 {
							   .gop_index = 2,
							   .phy_mode = 7,
							   .mac = { [5] = 2, },
							 },
							 {
							   .gop_index = 3,
							   .phy_mode = 7,
							   .mac = { [5] = 3, },
							 },
							 {
							   .phy_mode = 18,
							   .mac = { [5] = 4, },
							 },
							 {
							   .gop_index = 2,
							   .phy_mode = 7,
							   .mac = { [5] = 5, },
							 },
							 {
							   .gop_index = 3,
							   .phy_mode = 7,
							   .mac = { [5] = 6, },
							 },
							 {
							   .phy_mode = 18,
							   .mac = { [5] = 7, },
							 },
							 {
							   .gop_index = 2,
							   .phy_mode = 7,
							   .mac = { [5] = 8, },
							 },
							 {
							   .gop_index = 3,
							   .phy_mode = 7,
							   .mac = { [5] = 9, },
							 },
							 {
							   .phy_mode = 18,
							   .mac = { [5] = 0xa, },
							 },
							 {
							   .gop_index = 2,
							   .phy_mode = 7,
							   .mac = { [5] = 0xb, },
							 },
							 {
							   .gop_index = 3,
							   .phy_mode = 7,
							   .mac = { [5] = 0xc, },
							 },

};

static int mv_pp2x_ptr_validate (vnet_dev_t *dev, const void *ptr);

static struct pp2_cls_c3_shadow_hash_entry pp2_cls_c3_shadow_tbl[MVPP2_CLS_C3_HASH_TBL_SIZE];
static int pp2_cls_c3_shadow_ext_tbl[MVPP2_CLS_C3_EXT_TBL_SIZE];
static inline u32 cm3_read (uintptr_t base, u32 offset);
static inline bool mv_check_eaddr_uc (const u8 *addr);
static int mv_netdev_ioctl (vnet_dev_t *dev, u32 ctl, struct ifreq *s);
static int parse_hex (char *str, u8 *addr, size_t size);

static void mv_pp2x_prs_sram_bits_set (struct mv_pp2x_prs_entry *pe, int bit_num, int val);
static void mv_pp2x_prs_sram_bits_clear (struct mv_pp2x_prs_entry *pe, int bit_num, int val);

static inline void cm3_write (uintptr_t base, u32 offset, u32 data);
static void mv_pp2x_cls_oversize_rxq_set (vnet_dev_port_t *port);
static void mv_pp2x_prs_clear_active_vlans (vnet_dev_port_t *port, uint32_t *vlans);
static void mv_pp2x_prs_hw_inv (uintptr_t hif_base, int index);
static int mv_pp2x_prs_mac_da_accept (vnet_dev_port_t *port, const u8 *da, bool add);
static void mv_pp2x_prs_shadow_set (mvpp2_device_t *md, int index, int lu);
static void mv_pp2x_prs_sram_next_lu_set (struct mv_pp2x_prs_entry *pe, unsigned int lu);
static void mv_pp2x_prs_tcam_data_byte_set (struct mv_pp2x_prs_entry *pe, unsigned int offs,
					    unsigned char byte, unsigned char enable);
static void mv_pp2x_prs_tcam_lu_set (struct mv_pp2x_prs_entry *pe, unsigned int lu);
static void mv_pp2x_prs_tcam_port_map_set (struct mv_pp2x_prs_entry *pe, unsigned int ports);
static int pp2_cls_c3_hit_cntrs_clear_all (vnet_dev_t *dev, uintptr_t hif_base);
static void pp2_cls_mng_config_default_cos_queue (vnet_dev_port_t *port);
static void pp2_cls_mng_rss_port_init (vnet_dev_port_t *port);
static int pp2_port_clear_kernel_unicast (vnet_dev_port_t *port);
static int pp2_port_clear_vlan (vnet_dev_port_t *port, u16 vlan);
static int pp2_port_config_txsched (vnet_dev_port_t *port);
static void pp2_port_defaults_set (vnet_dev_port_t *port);
static void pp2_port_egress_disable (vnet_dev_port_t *port);
static void pp2_port_egress_enable (vnet_dev_port_t *port);
static void pp2_port_ingress_disable (vnet_dev_port_t *port);
static void pp2_port_ingress_enable (vnet_dev_port_t *port);
static void pp2_port_mac_max_rx_size_set (vnet_dev_port_t *port);
static void pp2_port_rxqs_create (vnet_dev_port_t *port);
static void pp2_port_rxqs_init (vnet_dev_port_t *port);
static int pp2_port_set_outq_state (vnet_dev_port_t *port, mvpp2_txq_t *txq, int en);
static int pp2_port_set_vlan_filtering (vnet_dev_port_t *port, int enable);
static void pp2_port_stop_dev (vlib_main_t *vm, vnet_dev_port_t *port);
static void pp2_port_txqs_create (vnet_dev_port_t *port);
static void pp2_port_uc_mac_addr_remove (vnet_dev_port_t *port, const uint8_t *addr);
static int pp2_prs_port_update (vnet_dev_port_t *port, u32 add, u32 tid, u32 ri, u32 ri_mask);
static void pp2_txq_init (vnet_dev_port_t *port, mvpp2_txq_t *txq);

static int mv_netdev_feature_set (vnet_dev_t *dev, const char *netdev, const char *featstr,
				  int val);
static int mvpp2x_prs_mac_da_range_find (vnet_dev_t *dev, mvpp2_device_t *md, uintptr_t hif_base,
					 int pmap, const u8 *da, const u8 *mask, int udf_type);
static void mv_pp2x_prs_shadow_ri_set (mvpp2_device_t *md, int index, unsigned int ri,
				       unsigned int ri_mask);
static void mv_pp2x_prs_sram_shift_set (struct mv_pp2x_prs_entry *pe, int shift, unsigned int op);
static unsigned int mv_pp2x_prs_tcam_port_map_get (struct mv_pp2x_prs_entry *pe);
static void mv_pp2x_prs_tcam_port_set (struct mv_pp2x_prs_entry *pe, unsigned int port, bool add);
static int pp2_c2_config_default_queue (vnet_dev_port_t *port, u16 queue);
static int pp2_cls_mng_qos_tbl_dflt_set (vnet_dev_port_t *port, u16 queue);
static int pp2_gop_gmac_max_rx_size_set (mvpp2_device_t *md, int mac_num, int max_rx_size);
static int pp2_gop_xlg_mac_max_rx_size_set (mvpp2_device_t *md, int mac_num, int max_rx_size);
static void pp2_port_clear_fc_isr (vnet_dev_port_t *port);
static void pp2_port_egress_disable_qmask (vnet_dev_port_t *port, uint32_t q_mask);
static void pp2_port_egress_enable_qmask (vnet_dev_port_t *port, uint32_t q_mask);
static void pp2_port_interrupts_disable (vnet_dev_port_t *port);
static void pp2_port_rxqs_deinit (vnet_dev_port_t *port);
static void pp2_port_rxqs_destroy (vnet_dev_port_t *port);
static void pp2_port_rxqs_fc_state_reset (vnet_dev_port_t *port);
static void pp2_port_txqs_deinit (vnet_dev_port_t *port);
static void pp2_port_txqs_destroy (vnet_dev_port_t *port);
static void pp2_port_txsched_set_mtu (vnet_dev_port_t *port);
static int pp2_rss_musdk_map_get (vnet_dev_port_t *port);
static void pp2_rxq_init (vnet_dev_port_t *port, mvpp2_rxq_t *rxq);
static uint32_t pp2_txq_pend_desc_num_get (vnet_dev_port_t *port, mvpp2_txq_t *txq);
static int pp2_txsched_queue_arbitration_set (vnet_dev_port_t *port, u8 txq,
					      enum pp2_ppio_outq_sched_mode mode, u8 weight);
static void pp2_txsched_remap_weights (vnet_dev_port_t *port, u8 remapped_weights[]);

static void mv_netdev_clean_featstrs (struct netdev_featstrs *fs);
static int mv_netdev_set_feature_ioctl (vnet_dev_t *dev, int fd, struct ifreq *ifr, int bit,
					int val);
static int mv_pp2x_cls_c2_qos_tbl_fill_array (vnet_dev_port_t *port, u8 tbl_sel,
					      uint8_t tc_values[]);
static int pp2_c2_config_queue (struct mv_pp2x_cls_c2_entry *c2, u16 queue, int from);
static u8 pp2_cls_c2_tcam_lkp_type_get (struct mv_pp2x_cls_c2_entry *c2);
static int pp2_cls_db_rss_get_hw_tbl_from_in_q (vnet_dev_t *dev, mvpp2_device_t *md, u8 num_in_q);
static u16 pp2_cls_db_rss_kernel_rsvd_tbl_get (mvpp2_device_t *md);
static u16 pp2_cls_db_rss_num_musdk_tbl_get (mvpp2_device_t *md);
static void pp2_cls_db_rss_num_musdk_tbl_set (mvpp2_device_t *md, u16 num_musdk_tbl);
static int pp2_cls_db_rss_tbl_map_get_next_free_idx (mvpp2_device_t *md);
static int pp2_cls_db_rss_tbl_map_set (mvpp2_device_t *md, u16 idx, u16 hw_tbl, u16 num_in_q);
static inline uint32_t pp2_gop_gmac_read (mvpp2_device_t *md, int mac_num, uint32_t offset);
static inline void pp2_gop_gmac_write (mvpp2_device_t *md, int mac_num, u32 offset, uint32_t data);
static inline uint32_t pp2_gop_xlg_mac_read (mvpp2_device_t *md, int mac_num, uint32_t offset);
static inline void pp2_gop_xlg_mac_write (mvpp2_device_t *md, int mac_num, u32 offset,
					  uint32_t data);
static inline u32 pp2_port_isr_rx_group_read (vnet_dev_port_t *port, int sub_group);
static inline void pp2_port_isr_rx_group_write (vnet_dev_port_t *port, int sub_group,
						int start_queue, int num_rx_queues);
static void pp2_port_restore_fc_isr (vnet_dev_port_t *port);
static void pp2_rxq_deinit (vnet_dev_port_t *port, mvpp2_rxq_t *rxq);
static void pp2_rxq_offset_set (vnet_dev_port_t *port, int prxq, int offset);
static void pp2_txq_deinit (mvpp2_txq_t *txq);
static int pp2_txsched_queue_fixed_prio_set (vnet_dev_port_t *port, u8 txq);
static int pp2_txsched_queue_wrr_set (vnet_dev_port_t *port, u8 txq, u8 weight);
static u8 pp2_txsched_rational_weight_remap (u32 weight, u32 min, u32 max);
static struct pp2_tc *pp2_rxq_tc_get (vnet_dev_port_t *port, uint32_t id);
static int mv_netdev_get_featstrs (vnet_dev_t *dev, int fd, struct ifreq *ifr,
				   struct netdev_featstrs *fs);
static int pp2_rss_enable (vnet_dev_port_t *port, int en);
static int pp2_rss_hw_tbl_set (vnet_dev_port_t *port);
static int pp22_cls_rss_rxq_set (vnet_dev_port_t *port);

static int pp2_gop_gmac_loopback_cfg (mvpp2_device_t *md, int mac_num, enum pp2_lb_type type);
static int pp2_gop_xlg_mac_loopback_cfg (mvpp2_device_t *md, int mac_num, enum pp2_lb_type type);
static int mv_pp2x_cls_c2_qos_color_set (vnet_dev_t *dev, struct mv_pp2x_cls_c2_qos_entry *qos,
					 int color);
static int mv_pp2x_cls_c2_qos_hw_write (mvpp2_device_t *md, struct mv_pp2x_cls_c2_qos_entry *qos);
static int mv_pp2x_cls_c2_qos_queue_set (struct mv_pp2x_cls_c2_qos_entry *qos, uint8_t queue);
static int mv_pp2x_cls_c2_queue_high_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue,
					  int from);
static int mv_pp2x_cls_c2_queue_low_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue,
					 int from);
static int mv_pp2x_cls_c2_rss_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int rss_en);
static inline uint32_t pp2_gop_gen_read (uintptr_t base, uint32_t offset);
static inline void pp2_gop_gen_write (uintptr_t base, uint32_t offset, uint32_t data);
static void pp2_rxq_resid_pkts (vnet_dev_port_t *port, mvpp2_rxq_t *rxq);

static int
mv_netdev_get_featstrs (vnet_dev_t *dev, int fd, struct ifreq *ifr, struct netdev_featstrs *fs)
{
  struct ethtool_sset_info *sset_cmd;
  struct ethtool_gstrings *gstrs;
  int32_t len;
  char *s;
  int i, ret;

  sset_cmd = mem_calloc (1, sizeof (*sset_cmd) + sizeof (sset_cmd->data[0]));
  sset_cmd->cmd = ETHTOOL_GSSET_INFO;
  sset_cmd->sset_mask = 1 << ETH_SS_FEATURES;

  ifr->ifr_data = (char *) sset_cmd;
  ret = ioctl (fd, SIOCETHTOOL, ifr);
  if (ret)
    {
      log_err (dev, "Could not get feature count (%s)\n", strerror (errno));
      clib_mem_free (sset_cmd);
      return -1;
    }

  memcpy (&len, sset_cmd->data, sizeof (len));
  clib_mem_free (sset_cmd);
  if (len < 0 || len > FEATSTRS_MAX)
    {
      log_err (dev, "invalid feature count %d\n", len);
      return -1;
    }

  gstrs = mem_calloc (1, sizeof (struct ethtool_gstrings) + len * ETH_GSTRING_LEN);
  gstrs->cmd = ETHTOOL_GSTRINGS;
  gstrs->string_set = ETH_SS_FEATURES;
  gstrs->len = len;

  ifr->ifr_data = (char *) gstrs;
  ret = ioctl (fd, SIOCETHTOOL, ifr);
  if (ret)
    {
      log_err (dev, "Could not get feature strings (%s)\n", strerror (errno));
      clib_mem_free (gstrs);
      return -1;
    }

  s = (char *) gstrs->data;
  for (i = 0; i < len; i++)
    {
      s[ETH_GSTRING_LEN - 1] = '\0';

      fs->s[i] = clib_mem_alloc (strlen (s) + 1);
      strcpy (fs->s[i], s);

      s += ETH_GSTRING_LEN;
    }
  clib_mem_free (gstrs);

  return 0;
}

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
      pp2_reg_write (md->pp_base, MVPP22_RSS_IDX_REG, reg_val);
      log_debug (dev, "rss queue %d, reg_val %x", rss->u.pointer.rxq_idx, reg_val);
      /* Write entry */
      reg_val = 0;
      reg_val &= (~MVPP22_RSS_RXQ2RSS_TBL_POINT_MASK);
      reg_val |= rss->u.pointer.rss_tbl_ptr << MVPP22_RSS_RXQ2RSS_TBL_POINT_OFF;
      pp2_reg_write (md->pp_base, MVPP22_RSS_RXQ2RSS_TBL_REG, reg_val);
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
      pp2_reg_write (md->pp_base, MVPP22_RSS_IDX_REG, reg_val);
      /* Write entry */
      reg_val &= (~MVPP22_RSS_TBL_ENTRY_MASK);
      reg_val |= (rss->u.entry.rxq << MVPP22_RSS_TBL_ENTRY_OFF);
      pp2_reg_write (md->pp_base, MVPP22_RSS_TBL_ENTRY_REG, reg_val);
      reg_val &= (~MVPP22_RSS_WIDTH_MASK);
      reg_val |= (rss->u.entry.width << MVPP22_RSS_WIDTH_OFF);
      pp2_reg_write (md->pp_base, MVPP22_RSS_WIDTH_REG, reg_val);
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

  c2_status = pp2_reg_read (md->pp_base, MVPP2_CLS2_TCAM_CTRL_REG);
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

      width = mvlog2 (roundup_pow_of_two (mp->tc.tc_config.num_in_qs));
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

static int pp2_c2_set_default_coloring (vnet_dev_port_t *port, int clear);
static int pp2_gop_port_link_status (vnet_dev_t *dev, mvpp2_device_t *md, struct pp2_mac_data *mac,
				     struct pp2_port_link_status *pstatus);
static int pp2_port_check_mtu_valid (vnet_dev_t *dev, u32 mtu);
static u32 pp2_prs_eth_start_hdr_get (vnet_dev_port_t *port);
static int pp2_prs_eth_start_hdr_set (vnet_dev_port_t *port,
				      enum pp2_ppio_eth_start_hdr eth_start_hdr);
static int pp2_prs_tcam_first_free (vnet_dev_t *dev, mvpp2_device_t *md, unsigned char start,
				    unsigned char end);
static int mv_pp2x_prs_hw_read (uintptr_t hif_base, struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_hw_write (uintptr_t hif_base, struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_sram_ri_get (struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_sram_ri_mask_get (struct mv_pp2x_prs_entry *pe);
static void mv_pp2x_prs_sram_ri_update (struct mv_pp2x_prs_entry *pe, unsigned int bits,
					unsigned int mask);
static int mv_pp2x_prs_tcam_invalid_get (struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_tcam_lu_get (struct mv_pp2x_prs_entry *pe);

static inline u32
cm3_read (uintptr_t base, u32 offset)
{
  return pp2_reg_read (base, offset);
}

static inline bool
mv_check_eaddr_uc (const u8 *addr)
{
  return !mv_check_eaddr_mc (addr);
}

static int
mv_netdev_ioctl (vnet_dev_t *dev, u32 ctl, struct ifreq *s)
{
  int rc;
  int fd;

  fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd == -1)
    {
      log_err (dev, "can't open socket: errno %d", errno);
      return -EFAULT;
    }

  rc = ioctl (fd, ctl, (char *) s);
  if (rc == -1)
    {
      log_err (dev, "ioctl request failed: errno %d\n", errno);
      close (fd);
      return -EFAULT;
    }
  close (fd);
  return 0;
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

  c2_status = pp2_reg_read (md->pp_base, MVPP2_CLS2_TCAM_CTRL_REG);
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

static int
pp2_gop_port_link_status (vnet_dev_t *dev, mvpp2_device_t *md, struct pp2_mac_data *mac,
			  struct pp2_port_link_status *pstatus)
{
  int port_num = mac->gop_index;

  switch (mac->phy_mode)
    {
    case PP2_PHY_INTERFACE_MODE_RGMII:
    case PP2_PHY_INTERFACE_MODE_SGMII:
    case PP2_PHY_INTERFACE_MODE_QSGMII:
      pp2_gop_gmac_link_status (md, port_num, pstatus);
      break;
    case PP2_PHY_INTERFACE_MODE_XAUI:
    case PP2_PHY_INTERFACE_MODE_RXAUI:
    case PP2_PHY_INTERFACE_MODE_KR:
      pp2_gop_xlg_mac_link_status (md, port_num, pstatus);
      break;
    default:
      log_err (dev, "%s: Wrong port mode (%d)", __func__, mac->phy_mode);
      return -1;
    }

  /* update phy interface */
  pstatus->phy_mode = mac->phy_mode;

  return 0;
}

static int
pp2_port_check_mtu_valid (vnet_dev_t *dev, u32 mtu)
{
  /* Validate MTU */
  if (mtu < PP2_PORT_MIN_MTU)
    {
      log_err (dev, "PORT: cannot change MTU to less than %u bytes\n", PP2_PORT_MIN_MTU);
      return -EINVAL;
    }

  return 0;
}

vnet_dev_rv_t
pp2_ppio_set_loopback (vnet_dev_port_t *port, int en)
{
  pp2_port_mac_set_loopback (port, en);
  return VNET_DEV_OK;
}

static u32
pp2_prs_eth_start_hdr_get (vnet_dev_port_t *port)
{
  u32 reg_val;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  uintptr_t hif_base = md->pp_base;
  u32 ret = 0;

  reg_val = pp2_reg_read (hif_base, MVPP2_MH_REG (pp2_port_id (port)));
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

  reg_val = pp2_reg_read (hif_base, MVPP2_MH_REG (pp2_port_id (port)));
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
  pp2_reg_write (hif_base, MVPP2_MH_REG (pp2_port_id (port)), reg_val);

  return 0;
}

static int
pp2_prs_tcam_first_free (vnet_dev_t *dev, mvpp2_device_t *md, unsigned char start,
			 unsigned char end)
{
  int tid;

  if (start > end)
    swap (start, end);

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
  pp2_reg_write (hif_base, MVPP2_PRS_TCAM_IDX_REG, pe->index);

  pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] =
    pp2_reg_read (hif_base, MVPP2_PRS_TCAM_DATA_REG (MVPP2_PRS_TCAM_INV_WORD));
  if (pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] & MVPP2_PRS_TCAM_INV_MASK)
    return MVPP2_PRS_TCAM_ENTRY_INVALID;

  for (i = 0; i < MVPP2_PRS_TCAM_WORDS; i++)
    pe->tcam.word[i] = pp2_reg_read (hif_base, MVPP2_PRS_TCAM_DATA_REG (i));

  /* Write sram index - indirect access */
  pp2_reg_write (hif_base, MVPP2_PRS_SRAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_SRAM_WORDS; i++)
    pe->sram.word[i] = pp2_reg_read (hif_base, MVPP2_PRS_SRAM_DATA_REG (i));

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
  pp2_reg_write (hif_base, MVPP2_PRS_SRAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_SRAM_WORDS; i++)
    pp2_reg_write (hif_base, MVPP2_PRS_SRAM_DATA_REG (i), pe->sram.word[i]);

  /* Write tcam index - indirect access */
  pp2_reg_write (hif_base, MVPP2_PRS_TCAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_TCAM_WORDS; i++)
    pp2_reg_write (hif_base, MVPP2_PRS_TCAM_DATA_REG (i), pe->tcam.word[i]);

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
pp2_cls_db_rss_init (mvpp2_device_t *md)
{
  if (!md->cls_db)
    return -EINVAL;

  /* Clear RSS db */
  memset (&md->cls_db->rss_db, 0, sizeof (struct pp2_cls_db_rss_t));

  return 0;
}

static void
pp2_cls_db_rss_kernel_rsvd_tbl_set (mvpp2_device_t *md, u16 kernel_rss_tbl)
{
  md->cls_db->rss_db.num_kernel_rsrvd_tbls = kernel_rss_tbl;
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
  pp2_reg_write (hif_base, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* set invalid bit */
  pp2_reg_write (hif_base, MVPP2_CLS2_TCAM_INV_REG, (1 << MVPP2_CLS2_TCAM_INV_INVALID_OFF));

  /* trigger */
  pp2_reg_write (hif_base, MVPP2_CLS2_TCAM_DATA_REG (4), 0);

  return 0;
}

static int
populate_tc_pools (vnet_dev_t *dev, mvpp2_bpool_t *param_pools[][PP2_PPIO_TC_CLUSTER_MAX_POOLS],
		   mvpp2_bpool_t *pools[][PP2_PPIO_TC_CLUSTER_MAX_POOLS])
{
  u8 index = 0, j, k;
  bool param_pool_exist;
  mvpp2_bpool_t *temp_pool;

  /* check pool0/pool1 */

  for (j = 0; j < MV_SYS_DMA_MAX_NUM_MEM_ID; j++)
    {
      index = 0;
      param_pool_exist = false;
      for (k = 0; k < PP2_PPIO_TC_CLUSTER_MAX_POOLS; k++)
	{
	  if (param_pools[j][k])
	    {
	      param_pool_exist = true;
	      pools[j][index] = param_pools[j][k];
	      if (!pools[j][index])
		{
		  log_err (dev, "%s: pool_id[%d] has no matching struct\n", __func__,
			   param_pools[j][k]->id);
		  return -1;
		}
	      index++;
	    }
	}
      /* Set pool with smallest buf_size first */
      if (index == 2)
	{
	  if (pools[j][0]->buf_sz > pools[j][1]->buf_sz)
	    {
	      temp_pool = pools[j][0];
	      pools[j][0] = pools[j][1];
	      pools[j][1] = temp_pool;
	    }
	}
      else if (index == 1)
	{
	  pools[j][1] = pools[j][0]; /* Both small and long pool are the same one */
	}
      else if (param_pool_exist)
	{
	  log_err (dev, "%s: pool_params do not exist\n", __func__);
	  return -1;
	}
    }
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

static int
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

static int
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
  val = pp2_reg_read (hif_base, MVPP2_PRS_TCAM_CTRL_REG);
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

static int
pp2_cls_rss_init (mvpp2_device_t *md)
{
  int rc;

  rc = pp2_cls_db_rss_init (md);
  if (rc)
    return rc;

  pp2_cls_db_rss_kernel_rsvd_tbl_set (md, 0);

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

      rc = mv_netdev_ioctl (dev, SIOCADDMULTI, &s);
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

static int
pp2_port_flush_mac_addrs (vnet_dev_port_t *port, uint32_t uc, uint32_t mc)
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
	  pp2_port_clear_kernel_unicast (port);
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

      rc = mv_netdev_ioctl (dev, SIOCDELMULTI, &s);
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

static int
pp2_port_set_enable (vnet_dev_port_t *port, uint32_t en)
{
  vnet_dev_t *dev = port->dev;
  int rc;
  struct ifreq s;

  mvpp2_port_ifname (port, s.ifr_name);
  log_debug (dev, "pp2_port_set_enable: port %d ifname %s enable %d\n", pp2_port_id (port),
	     s.ifr_name, en);
  rc = mv_netdev_ioctl (dev, SIOCGIFFLAGS, &s);
  if (rc)
    {
      log_err (dev, "PORT: unable to read port enabled\n");
      return rc;
    }

  if (en)
    s.ifr_flags |= IFF_UP;
  else
    s.ifr_flags &= ~IFF_UP;

  rc = mv_netdev_ioctl (dev, SIOCSIFFLAGS, &s);
  if (rc)
    {
      log_err (dev, "PORT: unable to set port enabled\n");
      return rc;
    }
  return 0;
}

vnet_dev_rv_t
pp2_ppio_set_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
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

  rc = mv_netdev_ioctl (dev, SIOCSIFHWADDR, &s);
  if (rc)
    return VNET_DEV_ERR_INTERNAL;

  mv_cp_eaddr (mp->mac_data.mac, (const uint8_t *) addr);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
pp2_port_set_priv_flags (vnet_dev_port_t *port, u32 val)
{
  vnet_dev_t *dev = port->dev;
  struct ifreq ifr;
  struct ethtool_value param;
  int rc;

  mvpp2_port_ifname (port, ifr.ifr_name);

  param.cmd = ETHTOOL_SPFLAGS;
  param.data = val;
  ifr.ifr_data = (char *) &param;
  rc = mv_netdev_ioctl (dev, SIOCETHTOOL, &ifr);
  if (rc)
    {
      log_err (dev, "PORT: unable to set priv_flags\n");
      return VNET_DEV_ERR_INTERNAL;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
pp2_ppio_set_promisc (vnet_dev_port_t *port, int en)
{
  vnet_dev_t *dev = port->dev;
  int rc;
  struct ifreq s;

  mvpp2_port_ifname (port, s.ifr_name);
  rc = mv_netdev_ioctl (dev, SIOCGIFFLAGS, &s);
  if (rc)
    {
      log_err (dev, "PORT: unable to read promisc mode from HW\n");
      return VNET_DEV_ERR_INTERNAL;
    }

  if (en)
    s.ifr_flags |= IFF_PROMISC;
  else
    s.ifr_flags &= ~IFF_PROMISC;

  rc = mv_netdev_ioctl (dev, SIOCSIFFLAGS, &s);
  if (rc)
    {
      log_err (dev, "PORT: unable to set promisc mode to HW\n");
      return VNET_DEV_ERR_INTERNAL;
    }
  return VNET_DEV_OK;
}

static int
pp2_port_set_rx_pause (vnet_dev_port_t *port, int en)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct ifreq ifr;
  struct ethtool_pauseparam param;
  int rc;

  if (mp->rx_pause_en == en)
    return 0;

  memset (&param, 0, sizeof (param));
  mvpp2_port_ifname (port, ifr.ifr_name);

  param.cmd = ETHTOOL_SPAUSEPARAM;
  param.rx_pause = en;
  param.tx_pause = mp->tx_pause_en;
  param.autoneg = 1;
  ifr.ifr_data = (char *) &param;
  rc = mv_netdev_ioctl (dev, SIOCETHTOOL, &ifr);
  if (rc)
    {
      log_err (dev, "PORT: unable to %s rx pause\n", (en) ? "enable" : "disable");
      return rc;
    }

  mp->rx_pause_en = en;
  log_debug (dev, "PORT: rx pause is %s\n", (en) ? "enabled" : "disabled");
  return VNET_DEV_OK;
}

static void
pp2_port_clear_prs_vlans (vnet_dev_port_t *port)
{
  uint32_t vlans[MVPP2_PRS_VLAN_FILT_MAX] = { 0 };
  int i;

  mv_pp2x_prs_clear_active_vlans (port, vlans);
  for (i = 0; (i < MVPP2_PRS_VLAN_FILT_MAX) && (vlans[i] != 0); i++)
    pp2_port_clear_vlan (port, vlans[i]);
  pp2_port_set_vlan_filtering (port, 0);
}

static void
pp2_port_init (vnet_dev_port_t *port) /* port init from probe slowpath */
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int err;

  /* Disable port transmission */
  pp2_port_egress_disable (port);

  /* Allocate and associated TXQs to this port */
  pp2_port_txqs_create (port);
  /* Allocate and associated RXQs to this port */
  pp2_port_rxqs_create (port);

  /* Disable port reception */
  pp2_port_ingress_disable (port);

  /* Port default configuration */
  pp2_port_defaults_set (port);

  /* Provide an initial MTU */
  mp->port_mtu = MV_DEFAULT_MTU;

  err = pp2_port_check_mtu_valid (dev, pp2_port_mtu (port));
  if (unlikely (err))
    {
      log_err (dev, "%s MTU error\n", __func__);
      return;
    }

  /* Provide an initial MRU */
  mp->port_mru = MV_MTU_TO_MRU (pp2_port_mtu (port));

  /* TODO: Below fn_call is incorrect.
   * Should mask Interrupts:
   *  - For MUSDK_NIC ports for all cpu_slots, including kernel
   *  - For other ports, only for MUSDK cpu_slots (hif_map)
   */
#if 0
	pp2_port_interrupts_mask(port);
#endif

  memset (&mp->stats, 0, sizeof (mp->stats));

  /* Initialize RSS */
  pp2_cls_mng_rss_port_init (port);

  /* Set initial cos value */
  pp2_cls_mng_config_default_cos_queue (port);
}

static void
pp2_port_start_dev (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  if ((mp->t_mode & PP2_TRAFFIC_INGRESS) == PP2_TRAFFIC_INGRESS)
    pp2_port_mac_max_rx_size_set (port);

  if ((mp->t_mode & PP2_TRAFFIC_EGRESS) == PP2_TRAFFIC_EGRESS)
    pp2_port_config_txsched (port);

  log_debug (dev, "start_dev: tx_port_num %d, traffic mode %s%s\n",
	     MVPP2_MAX_TCONT + pp2_port_id (port),
	     ((mp->t_mode & PP2_TRAFFIC_INGRESS) == PP2_TRAFFIC_INGRESS) ? " ingress " : "",
	     ((mp->t_mode & PP2_TRAFFIC_EGRESS) == PP2_TRAFFIC_EGRESS) ? " egress " : "");

  if ((mp->t_mode & PP2_TRAFFIC_EGRESS) == PP2_TRAFFIC_EGRESS)
    pp2_port_egress_enable (port);

  if ((mp->t_mode & PP2_TRAFFIC_INGRESS) == PP2_TRAFFIC_INGRESS)
    pp2_port_ingress_enable (port);
}

vnet_dev_rv_t
pp2_ppio_disable (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  /* Stop new packets from arriving to RXQs */
  log_debug (dev, "pp2_port_stop: %u\n", pp2_port_id (port));

  pp2_port_stop_dev (vm, port);

  pp2_port_set_enable (port, 0);
  return VNET_DEV_OK;
}

static void
pp2_port_txqs_init (vnet_dev_port_t *port)
{
  foreach_vnet_dev_port_tx_queue (q, port)
    {
      mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);

      pp2_txq_init (port, txq);
      pp2_port_set_outq_state (port, txq, true);
    }
}

static inline uint32_t
pp2_rxq_received (vnet_dev_port_t *port, const int rxq_id)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 val = pp2_reg_read (mp->hif_base, MVPP2_RXQ_STATUS_REG (rxq_id));

  return (val & MVPP2_RXQ_OCCUPIED_MASK);
}

static int
mv_pp2x_ptr_validate (vnet_dev_t *dev, const void *ptr)
{
  if (!ptr)
    {
      log_err (dev, "%s: null pointer.\n", __func__);
      return MV_ERROR;
    }
  return 0;
}
static int
pp2_cls_c3_hit_cntr_clear_done (uintptr_t hif_base)
{
  u32 reg_val;

  reg_val = pp2_reg_read (hif_base, MVPP2_CLS3_STATE_REG);
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
  pp2_reg_write (hif_base, MVPP2_CLS3_HASH_OP_REG, reg_val);

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

  pp2_reg_write (hif_base, MVPP2_CLS3_CLEAR_COUNTERS_REG, MVPP2_CLS3_CLEAR_ALL);
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
static int
mv_pp2x_cls_hw_cls_enable (vnet_dev_t *dev, uintptr_t hif_base, uint32_t en)
{
  if (mv_pp2x_range_validate (dev, en, 0, 1) == MV_ERROR)
    return -EINVAL;

  /* Enable classifier */
  pp2_reg_write (hif_base, MVPP2_CLS_MODE_REG, en);

  return 0;
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

static int
pp2_cls_init (vnet_dev_t *dev, mvpp2_device_t *md)
{
  uintptr_t hif_base = md->pp_base;

  return mv_pp2x_cls_hw_cls_enable (dev, hif_base, true);
}

static void
pp2_cls_mng_init (vnet_dev_t *dev, mvpp2_device_t *md)
{
  if (md->cls_db)
    return; /*Already initialized*/

  pp2_cls_db_init (dev, md);
  pp2_cls_prs_init (dev, md);
  pp2_cls_init (dev, md);
  pp2_cls_c2_start (dev, md);
  pp2_cls_c3_start (dev, md);
  pp2_cls_rss_init (md);
}

static int
pp2_get_hw_data (vnet_dev_t *dev, mvpp2_device_t *md)
{
  int err = 0;
  int uio_num;
  u32 i;
  uintptr_t mem_base;

  err = mvpp2_uio_init (dev, &uio_num);
  if (err)
    {
      log_err (dev, " No device found\n");
      return err;
    }

  /* Map the whole physical Packet Processor physical address */
  err = mvpp2_uio_map (dev, uio_num, "pp", &md->pp_map_size, (void **) (&mem_base));
  if (err)
    {
      mvpp2_uio_deinit (dev);
      return err;
    }
  md->pp_base = mem_base;

  err = mvpp2_uio_map (dev, uio_num, "mspg", &md->mspg_map_size, (void **) (&mem_base));
  if (err)
    {
      mvpp2_uio_deinit (dev);
      return err;
    }
  md->gop_hw_mspg = mem_base;

  /* Map the Cm3 physical address */
  err = mvpp2_uio_map (dev, uio_num, "cm3", &md->cm3_map_size, (void **) (&mem_base));
  if (err)
    {
      /* Not all systems support cm3 */
      log_warn (dev, "tx_pause not supported\n");
      err = 0;
    }
  else
    {
      md->cm3_base = mem_base;
    }

  /**
   * Only memory maps aligned with PAGE_SIZE (ARM64 arch 0x1000) can be
   * mapped. Hence, the registers base address lower than PAGE_SIZE
   * alignment will be computed here and not extracted from device tree.
   */

  md->gop_hw_gmac.base = md->gop_hw_mspg + 0xE00;
  md->gop_hw_gmac.obj_size = 0x1000;

  md->gop_hw_xlg_mac.base = md->gop_hw_mspg + 0xF00;
  md->gop_hw_xlg_mac.obj_size = 0x1000;

  /* Get MAC data for all available ethernet ports (not loopback port) based on dts GOP entries */
  /* TODO: Revise this after GOP dev tree support */
  for (i = 0; i < PP2_NUM_ETH_PPIO; i++)
    {
      struct pp2_mac_data *mac = md->mac_data + i;
      u32 id = i + (md->pp_id * PP2_NUM_ETH_PPIO);

      /* TBD(DevTree): replace with data read from Device tree */
      mac->gop_index = hc_gop_mac_data[id].gop_index;
      mac->flags = hc_gop_mac_data[id].flags;
      mac->phy_addr = hc_gop_mac_data[id].phy_addr;
      mac->phy_mode = hc_gop_mac_data[id].phy_mode;
      mac->force_link = hc_gop_mac_data[id].force_link;
      mac->autoneg = hc_gop_mac_data[id].autoneg;
      mac->link = hc_gop_mac_data[id].link;
      mac->duplex = hc_gop_mac_data[id].duplex;
      mac->speed = hc_gop_mac_data[id].speed;
      memcpy (&mac->mac, &hc_gop_mac_data[id].mac, PP2_ETHADDR_LEN);
    }

  return err;
}

static int
pp2_port_open (mvpp2_device_t *md, struct pp2_ppio_params *param, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  char ifname[IFNAMSIZ];
  u32 i, j, k, first_rxq, num_in_qs;
  u32 total_num_in_qs = 0;
  u8 port_id = mp->id;
  int rc;

  if (port_id < PP2_NUM_ETH_PPIO)
    mp->mac_data = md->mac_data[port_id];

  mvpp2_port_ifname (port, ifname);
  log_debug (dev, "pp2_port_open: pp2_id(%d), port_id(%d), ifname(%s)\n", md->pp_id, port_id,
	     ifname);

  /* Setup port based on client params
   * TODO: Traffic Mgr and CoS stuff not implemented yet, so only
   * the first parameter of the array is used
   */

  first_rxq = pp2_port_id (port) * PP2_HW_PORT_NUM_RXQS;

  mp->first_rxq = first_rxq;
  ASSERT (param->inqs_params.num_tcs == 1);
  mp->num_tcs = param->inqs_params.num_tcs;
  for (i = 0; i < mp->num_tcs; i++)
    {
      u16 tc_pkt_offset = param->inqs_params.tcs_params[i].pkt_offset;
      u8 tc_used_mem_id_pool_mask = 0;
      num_in_qs = param->inqs_params.tcs_params[i].num_in_qs;
      for (j = 0; j < num_in_qs; j++)
	{
	  struct pp2_rxq *rx_q = &(mp->tc.rx_qs[j]);
	  struct pp2_ppio_inq_params *inqs_params =
	    &(param->inqs_params.tcs_params[i].inqs_params[j]);

	  rx_q->ring_size = inqs_params->size;
	  rx_q->tc_pools_mem_id_index = inqs_params->tc_pools_mem_id_index;
	  tc_used_mem_id_pool_mask |= (1 << inqs_params->tc_pools_mem_id_index);
	}
      if (tc_pkt_offset > PP2_MAX_PACKET_OFFSET)
	{
	  log_err (dev, "port %s: tc[%d] pkt_offset[%u] too large\n", ifname, i, tc_pkt_offset);
	  return -EINVAL;
	}
      if (tc_pkt_offset % PP2_BUFFER_OFFSET_GRAN)
	{
	  log_err (dev, "port %s: tc[%d] pkt_offset[%u] must be multiple of %d\n", ifname, i,
		   tc_pkt_offset, PP2_BUFFER_OFFSET_GRAN);
	  return -EINVAL;
	}
      if (tc_pkt_offset)
	mp->tc.tc_config.pkt_offset = tc_pkt_offset;
      else
	mp->tc.tc_config.pkt_offset = PP2_PACKET_DEF_OFFSET;
      mp->tc.first_log_rxq = total_num_in_qs;
      mp->tc.tc_config.num_in_qs = num_in_qs;
      mp->tc.tc_config.default_color = param->inqs_params.tcs_params[i].default_color;
      /*To support RSS, each TC must start at natural rxq boundary */
      first_rxq = roundup (first_rxq, roundup_pow_of_two (num_in_qs));
      mp->tc.tc_config.first_rxq = first_rxq;
      rc = populate_tc_pools (dev, param->inqs_params.tcs_params[i].pools, mp->tc.tc_config.pools);
      if (rc)
	return -EINVAL;
      for (j = 0; j < MV_SYS_DMA_MAX_NUM_MEM_ID; j++)
	{
	  if ((1 << j) & tc_used_mem_id_pool_mask)
	    if (mp->tc.tc_config.pools[j][0] == NULL)
	      {
		log_err (dev, "Pool for mem_id(%d) was not configured\n", j);
		return -EINVAL;
	      }
	}
      total_num_in_qs += num_in_qs;
      first_rxq += num_in_qs;
    }
  foreach_vnet_dev_port_tx_queue (q, port)
    {
      u32 qid = q->queue_id;

      mp->txq_config[qid].size = param->outqs_params.outqs_params[qid].size;
      mp->txq_config[qid].sched_mode = param->outqs_params.outqs_params[qid].sched_mode;
      mp->txq_config[qid].weight = param->outqs_params.outqs_params[qid].weight;
    }

  mp->hash_type = param->inqs_params.hash_type;

  log_debug (dev, "PORT: ID %u (on PP%u):\n", pp2_port_id (port), md->pp_id);
  log_debug (dev, "PORT: PHY\n");

  log_debug (dev, "PORT: TXQs %u\n", param->outqs_params.num_outqs);
  log_debug (dev, "PORT: RXQs %u\n", total_num_in_qs);
  log_debug (dev, "PORT: First Phy RXQ %u\n", mp->first_rxq);
  log_debug (dev, "PORT: Hash type %u\n", mp->hash_type);

  for (i = 0; i < mp->num_tcs; i++)
    {
      log_debug (dev, "PORT: TC%u\n", i);
      log_debug (dev, "PORT: TC RXQs %u\n", mp->tc.tc_config.num_in_qs);
      log_debug (dev, "PORT: TC First Log RXQ %u\n", mp->tc.first_log_rxq);
      log_debug (dev, "PORT: TC First Phy RXQ %u\n", mp->tc.tc_config.first_rxq);
      log_debug (dev, "PORT: TC PKT Offset %u\n", mp->tc.tc_config.pkt_offset);
      for (j = 0; j < mp->tc.tc_config.num_in_qs; j++)
	{
	  log_debug (dev, "PORT: TC RXQ#%u size = %u tc_pool_pair = %u\n", j,
		     mp->tc.rx_qs[j].ring_size, mp->tc.rx_qs[j].tc_pools_mem_id_index);
	}
      for (j = 0; j < MV_SYS_DMA_MAX_NUM_MEM_ID; j++)
	for (k = 0; k < PP2_PPIO_TC_CLUSTER_MAX_POOLS; k++)
	  if (mp->tc.tc_config.pools[j][k])
	    log_debug (dev, "PORT: TC Pool#%u = %u\n", j, mp->tc.tc_config.pools[j][k]->id);
    }

  /* Assing a CPU slot to avoid send hif_base as argument further */
  mp->hif_base = md->pp_base;

  rc = pp2_port_set_priv_flags (port, MVPP22_F_IF_MUSDK_PRIV);
  if (rc)
    return rc;
  /* Assign and initialize port private data and hardware */
  pp2_port_init (port);

  pp2_port_clear_prs_vlans (port);
  pp2_port_flush_mac_addrs (port, 1, 1);

  /* Set default tx pause state as disabled */
  mp->tx_pause_en = 0;

  /* set_rx_pause requires a change of state */
  mp->rx_pause_en = 1;
  /* disable RX pause on init */
  pp2_port_set_rx_pause (port, 0);

  return 0;
}

vnet_dev_rv_t
pp2_ppio_enable (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  log_debug (dev, "pp2_ppio_enable: %u\n", pp2_port_id (port));
  mp->t_mode = PP2_TRAFFIC_INGRESS_EGRESS;

  pp2_port_set_enable (port, 1);
  vlib_process_suspend (vm, 0.5);
  pp2_port_start_dev (port);
  return 0;
}

static u8
pp2_get_num_inst (vnet_dev_t *dev)
{
  u8 i, pp2_num_inst = 0;

  for (i = 0; i < PP2_MAX_NUM_PACKPROCS; i++)
    pp2_num_inst += mvpp2_uio_exists (dev, i);
  log_debug (dev, "pp2_num_inst=%d\n", pp2_num_inst);

  return pp2_num_inst;
}

static void
pp2_loopback_egress_disable (uintptr_t hif_base)
{
  u32 q_mask;
  u32 val;
  u32 tmo = 0;

  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, PP2_LOOPBACK_PORT + MVPP2_MAX_TCONT);
  q_mask = pp2_reg_read (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG) & MVPP2_TXP_SCHED_ENQ_MASK;
  if (q_mask)
    pp2_reg_write (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG, q_mask << MVPP2_TXP_SCHED_DISQ_OFFSET);

  do
    {
      if (tmo++ >= MVPP2_TX_DISABLE_TIMEOUT_MSEC)
	break;
      usleep_range (1000, 2000);
      val = pp2_reg_read (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG);
    }
  while (val & q_mask);
}

static int
pp2_loopback_init (mvpp2_device_t *md)
{
  uintptr_t hif_base = md->pp_base;
  uintptr_t desc_phys;
  u32 desc, mtu, pref_buf_size, ptxq, val;

  pp2_loopback_egress_disable (hif_base);

  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, PP2_LOOPBACK_PORT + MVPP2_MAX_TCONT);
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_CMD_1_REG, 0);
  for (u32 qid = 0; qid < MVPP2_MAX_TXQ; qid++)
    {
      ptxq = (MVPP2_MAX_TCONT + PP2_LOOPBACK_PORT) * MVPP2_MAX_TXQ + qid;
      pp2_reg_write (hif_base, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (ptxq), 0);
    }
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PERIOD_REG, PP2_TCLK_FREQ / 1000000);
  val = pp2_reg_read (hif_base, MVPP2_TXP_SCHED_REFILL_REG);
  val &= ~MVPP2_TXP_REFILL_PERIOD_ALL_MASK;
  val |= MVPP2_TXP_REFILL_PERIOD_MASK (1) | MVPP2_TXP_REFILL_TOKENS_ALL_MASK;
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_REFILL_REG, val);
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, MVPP2_TXP_TOKEN_SIZE_MAX);
  pp2_reg_write (hif_base, MVPP2_RX_CTRL_REG (PP2_LOOPBACK_PORT),
		 MVPP2_RX_USE_PSEUDO_FOR_CSUM_MASK | MVPP2_RX_LOW_LATENCY_PKT_SIZE (256) |
		   MVPP2_RX_GEM_PORT_ID_SRC_SEL (2));

  md->lbk_desc_virt_arr = vlib_physmem_alloc_aligned (
    vlib_get_main (), PP2_LPBK_PORT_TXQ_SIZE * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN);
  if (!md->lbk_desc_virt_arr)
    return -ENOMEM;
  desc_phys = vlib_physmem_get_pa (vlib_get_main (), md->lbk_desc_virt_arr);

  pp2_reg_write (hif_base, MVPP2_TXQ_NUM_REG, PP2_LOOPBACK_TXQ_ID);
  pp2_reg_write (hif_base, MVPP2_TXQ_DESC_ADDR_LOW_REG,
		 ((u32) desc_phys) >> MVPP2_TXQ_DESC_ADDR_LOW_SHIFT);
  pp2_reg_write (hif_base, MVPP22_TXQ_DESC_ADDR_HIGH_REG,
		 (desc_phys >> 32) & MVPP22_TXQ_DESC_ADDR_HIGH_MASK);
  pp2_reg_write (hif_base, MVPP2_TXQ_DESC_SIZE_REG,
		 PP2_LPBK_PORT_TXQ_SIZE & MVPP2_TXQ_DESC_SIZE_MASK);
  pp2_reg_write (hif_base, MVPP2_TXQ_INDEX_REG, 0);
  pp2_reg_write (hif_base, MVPP2_TXQ_RSVD_CLR_REG,
		 PP2_LOOPBACK_TXQ_ID << MVPP2_TXQ_RSVD_CLR_OFFSET);
  val = pp2_reg_read (hif_base, MVPP2_TXQ_PENDING_REG) & ~MVPP2_TXQ_PENDING_MASK;
  pp2_reg_write (hif_base, MVPP2_TXQ_PENDING_REG, val);

  pref_buf_size = PP2_LOOPBACK_PORT_TXQ_PREFETCH == PP2_TXQ_PREFETCH_64 ? MVPP2_PREF_BUF_SIZE_64 :
									  MVPP2_PREF_BUF_SIZE_16;
  desc = PP2_LOOPBACK_PORT * MVPP2_MAX_TXQ * PP2_ETH_PORT_TXQ_PREFETCH;
  pp2_reg_write (hif_base, MVPP2_TXQ_PREF_BUF_REG,
		 MVPP2_PREF_BUF_PTR (desc) | pref_buf_size |
		   MVPP2_PREF_BUF_THRESH (PP2_TXQ_PREFETCH_16 / 2));
  for (u32 i = 0; i < MVPP2_NUM_HIFS; i++)
    pp2_reg_read (mvpp2_hif_base (md, i), MVPP22_TXQ_SENT_REG (PP2_LOOPBACK_TXQ_ID));

  mtu = 3 * (MV_DEFAULT_MTU + ETH_HLEN) * 8;
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, MVPP2_TX_PORT_NUM (PP2_LOOPBACK_PORT));
  val = pp2_reg_read (hif_base, MVPP2_TXP_SCHED_MTU_REG);
  val = (val & ~MVPP2_TXP_MTU_MAX) | clib_min (mtu, MVPP2_TXP_MTU_MAX);
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_MTU_REG, val);
  val = pp2_reg_read (hif_base, MVPP2_TXP_SCHED_REFILL_REG);
  val &= ~(MVPP2_TXP_REFILL_TOKENS_ALL_MASK | MVPP2_TXP_REFILL_PERIOD_ALL_MASK);
  val |= MVPP2_TXP_REFILL_TOKENS_MASK (MVPP2_TXP_REFILL_TOKENS_MAX) |
	 MVPP2_TXP_REFILL_PERIOD_MASK (MVPP2_TXP_REFILL_PERIOD_MIN);
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_REFILL_REG, val);
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, MVPP2_TXP_MAX_CONFIGURABLE_BUCKET_SIZE);
  pp2_reg_write (hif_base, MVPP2_TXQ_SCHED_REFILL_REG (0),
		 MVPP2_TXQ_REFILL_TOKENS_MASK (MVPP2_TXQ_REFILL_TOKENS_MAX) |
		   MVPP2_TXQ_REFILL_PERIOD_MASK (MVPP2_TXQ_REFILL_PERIOD_MIN));
  pp2_reg_write (hif_base, MVPP2_TXQ_SCHED_TOKEN_SIZE_REG (0),
		 MVPP2_TXQ_MAX_CONFIGURABLE_BUCKET_SIZE);

  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG, 1);
  md->lbk_is_initialized = 1;
  return 0;
}

void
pp2_loopback_deinit (mvpp2_device_t *md)
{
  uintptr_t hif_base = md->pp_base;
  u32 val;

  if (!md->lbk_is_initialized)
    return;

  pp2_loopback_egress_disable (hif_base);
  val =
    pp2_reg_read (hif_base, MVPP2_TX_PORT_FLUSH_REG) | MVPP2_TX_PORT_FLUSH_MASK (PP2_LOOPBACK_PORT);
  pp2_reg_write (hif_base, MVPP2_TX_PORT_FLUSH_REG, val);
  pp2_reg_write (hif_base, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (PP2_LOOPBACK_TXQ_ID), 0);
  pp2_reg_write (hif_base, MVPP2_TXQ_NUM_REG, PP2_LOOPBACK_TXQ_ID);
  pp2_reg_write (hif_base, MVPP2_TXQ_DESC_ADDR_LOW_REG, 0);
  pp2_reg_write (hif_base, MVPP2_TXQ_DESC_SIZE_REG, 0);
  for (u32 i = 0; i < MVPP2_NUM_HIFS; i++)
    pp2_reg_read (mvpp2_hif_base (md, i), MVPP22_TXQ_SENT_REG (PP2_LOOPBACK_TXQ_ID));
  val &= ~MVPP2_TX_PORT_FLUSH_MASK (PP2_LOOPBACK_PORT);
  pp2_reg_write (hif_base, MVPP2_TX_PORT_FLUSH_REG, val);
  vlib_physmem_free (vlib_get_main (), md->lbk_desc_virt_arr);
  md->lbk_desc_virt_arr = 0;
  md->lbk_is_initialized = 0;
}

vnet_dev_rv_t
pp2_device_init (vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  uintptr_t hif_base;
  int rc;

  if (md->pp_id >= pp2_get_num_inst (dev))
    return VNET_DEV_ERR_INVALID_DEVICE_ID;
  rc = pp2_get_hw_data (dev, md);
  if (rc)
    return VNET_DEV_ERR_INIT_FAILED;

  hif_base = md->pp_base;
  pp2_bm_flush_pools (dev, hif_base, md->bm_pool_reserved_map);
  pp2_cls_mng_init (dev, md);

  rc = pp2_loopback_init (md);
  if (rc)
    goto error;
  return VNET_DEV_OK;

error:
  pp2_loopback_deinit (md);
  mvpp2_uio_deinit (dev);
  return VNET_DEV_ERR_INIT_FAILED;
}

vnet_dev_rv_t
pp2_ppio_get_link_info (vnet_dev_port_t *port, struct pp2_ppio_link_info *link_info)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int rc;
  struct pp2_port_link_status pstatus;

  rc = pp2_gop_port_link_status (dev, md, &mp->mac_data, &pstatus);
  if (rc)
    return VNET_DEV_ERR_INTERNAL;

  link_info->up = pstatus.linkup;
  link_info->speed = (enum mv_net_link_speed) pstatus.speed;
  link_info->duplex = (enum mv_net_link_duplex) pstatus.duplex;
  link_info->phy_mode = (enum mv_net_phy_mode) pstatus.phy_mode;

  return VNET_DEV_OK;
}

vnet_dev_rv_t
pp2_ppio_init (vnet_dev_port_t *port, struct pp2_ppio_params *params)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  int port_id = params->id;
  int pp2_id = params->pp2_id;
  int rc;

  if (port_id >= PP2_NUM_ETH_PPIO)
    {
      log_err (dev, "[%s] Invalid ppio.\n", __func__);
      return VNET_DEV_ERR_INVALID_PORT_ID;
    }
  if (pp2_id != md->pp_id)
    {
      log_err (dev, "[%s] Invalid pp2 instance.\n", __func__);
      return VNET_DEV_ERR_INVALID_DEVICE_ID;
    }

  ASSERT (mp->id == port_id);
  rc = pp2_port_open (md, params, port);
  if (rc)
    {
      log_err (dev, "[%s] ppio init failed.\n", __func__);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  mv_pp2x_cls_oversize_rxq_set (port);
  pp2_port_rxqs_init (port);
  pp2_port_txqs_init (port);

  rc = pp2_cls_mng_eth_start_header_params_set (port, params->eth_start_hdr);
  if (rc)
    {
      log_err (dev, "[%s] ppio init failed while initialize ethernet start header\n", __func__);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  rc = pp2_cls_mng_modify_default_flows (port, false);
  if (rc)
    {
      log_err (dev, "[%s] ppio init failed while modify default flows\n", __func__);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  pp2_ppio_set_loopback (port, false);
  pp2_ppio_set_promisc (port, false);

  mp->is_open = true;

  return VNET_DEV_OK;
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

static inline void
cm3_write (uintptr_t base, u32 offset, u32 data)
{
  pp2_reg_write (base, offset, data);
}

static void
mv_pp2x_cls_oversize_rxq_set (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  uintptr_t hif_base = mp->hif_base;

  pp2_reg_write (hif_base, MVPP2_CLS_OVERSIZE_RXQ_LOW_REG (pp2_port_id (port)), mp->first_rxq);
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
  pp2_reg_write (hif_base, MVPP2_PRS_TCAM_IDX_REG, index);
  pp2_reg_write (hif_base, MVPP2_PRS_TCAM_DATA_REG (MVPP2_PRS_TCAM_INV_WORD),
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

static void
mv_pp2x_prs_shadow_set (mvpp2_device_t *md, int index, int lu)
{
  md->cls_db->prs_db.prs_shadow[index].valid = true;
  md->cls_db->prs_db.prs_shadow[index].lu = lu;
}

static void
mv_pp2x_prs_sram_next_lu_set (struct mv_pp2x_prs_entry *pe, unsigned int lu)
{
  int sram_next_off = MVPP2_PRS_SRAM_NEXT_LU_OFFS;

  mv_pp2x_prs_sram_bits_clear (pe, sram_next_off, MVPP2_PRS_SRAM_NEXT_LU_MASK);
  mv_pp2x_prs_sram_bits_set (pe, sram_next_off, lu);
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
pp2_cls_mng_config_default_cos_queue (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  pp2_c2_config_default_queue (port, mp->first_rxq);
  pp2_cls_mng_qos_tbl_dflt_set (port, mp->first_rxq);
}

static void
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

static int
pp2_port_clear_kernel_unicast (vnet_dev_port_t *port)
{
  char ifname[IFNAMSIZ];
  char name[IFNAMSIZ];
  char command[PP2_MAX_BUF_STR_LEN], full_name[32];
  struct dirent *dent;
  char *dir;
  DIR *d;
  int rc;
  u8 id;

  d = opendir ("/sys/class/net/");
  if (!d)
    return -EACCES;
  mvpp2_port_ifname (port, ifname);

  while (1)
    {
      dent = readdir (d);
      if (!dent)
	break;
      dir = dent->d_name;

      if (!strcmp (dir, ".") || !strcmp (dir, ".."))
	continue;

      if (sscanf (dir, "%[^.].%02hhu", name, &id) != 2)
	continue;

      if (strcmp (ifname, name))
	continue;

      sprintf (full_name, "%s.%u\n", name, id);
      sprintf (command, "ip -d link show %s | grep macvlan", full_name);
      rc = system (command);
      if (rc == 0)
	/* mac interface found */
	/* same function can be used to remove macvlan interface */
	pp2_port_clear_vlan (port, id);
    }

  return 0;
}

static int
pp2_port_clear_vlan (vnet_dev_port_t *port, u16 vlan)
{
  vnet_dev_t *dev = port->dev;
  char ifname[IFNAMSIZ];
  int rc;
  char buf[PP2_MAX_BUF_STR_LEN];

  /* build manually the system command */
  /* [TODO] check other alternatives for setting vlan id */
  mvpp2_port_ifname (port, ifname);
  sprintf (buf, "ip link delete %s.%d", ifname, vlan);
  rc = system (buf);
  if (rc != 0)
    {
      log_err (dev, "clear vlan operation failed\n");
      return rc;
    }

  return 0;
}

static int
pp2_port_config_txsched (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 n_tx_queues = 0;
  int rc;
  u32 reg_val;
  u8 remapped_weights[MVPP2_MAX_TXQ];

  /* Set port MTU (which is used later in the initialization) */
  pp2_port_txsched_set_mtu (port);

  pp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG,
		 MVPP2_TX_PORT_NUM (pp2_port_id (port)));

  reg_val = pp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_REFILL_REG);
  reg_val &= ~(MVPP2_TXP_REFILL_TOKENS_ALL_MASK | MVPP2_TXP_REFILL_PERIOD_ALL_MASK);
  reg_val |= MVPP2_TXP_REFILL_TOKENS_MASK (MVPP2_TXP_REFILL_TOKENS_MAX);
  reg_val |= MVPP2_TXP_REFILL_PERIOD_MASK (MVPP2_TXP_REFILL_PERIOD_MIN);
  pp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_REFILL_REG, reg_val);
  pp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_TOKEN_SIZE_REG,
		 MVPP2_TXP_MAX_CONFIGURABLE_BUCKET_SIZE);

  pp2_txsched_remap_weights (port, remapped_weights);

  foreach_vnet_dev_port_tx_queue (q, port)
    n_tx_queues++;

  /* Set TXQ scheduler defaults, arbitration mode and WRR weight. */
  foreach_vnet_dev_port_tx_queue (q, port)
    { /* This only works in logical ports post reprioritization */
      u32 txq = q->queue_id;

      reg_val = pp2_reg_read (mp->hif_base, MVPP2_TXQ_SCHED_REFILL_REG (txq));
      reg_val &= ~(MVPP2_TXQ_REFILL_TOKENS_ALL_MASK | MVPP2_TXQ_REFILL_PERIOD_ALL_MASK);
      reg_val |= MVPP2_TXQ_REFILL_TOKENS_MASK (MVPP2_TXQ_REFILL_TOKENS_MAX);
      reg_val |= MVPP2_TXQ_REFILL_PERIOD_MASK (MVPP2_TXQ_REFILL_PERIOD_MIN);
      pp2_reg_write (mp->hif_base, MVPP2_TXQ_SCHED_REFILL_REG (txq), reg_val);
      pp2_reg_write (mp->hif_base, MVPP2_TXQ_SCHED_TOKEN_SIZE_REG (txq),
		     MVPP2_TXQ_MAX_CONFIGURABLE_BUCKET_SIZE);

      if (n_tx_queues > 1)
	{
	  rc = pp2_txsched_queue_arbitration_set (port, txq, mp->txq_config[txq].sched_mode,
						  remapped_weights[txq]);
	  if (rc)
	    return rc;
	}
    }

  return 0;
}

static int
pp2_port_set_vlan_filtering (vnet_dev_port_t *port, int enable)
{
  vnet_dev_t *dev = port->dev;
  char ifname[IFNAMSIZ];
  const char *featstr = "rx-vlan-filter";
  int rc;

  mvpp2_port_ifname (port, ifname);
  rc = mv_netdev_feature_set (dev, ifname, featstr, enable);
  if (rc != 0)
    {
      if (enable)
	log_err (dev, "failed to enable vlan filtering\n");
      else
	log_err (dev, "failed to disable vlan filtering\n");

      return rc;
    }

  return 0;
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

static void
pp2_port_defaults_set (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 tx_port_num, val, queue, ptxq;
  uintptr_t hif_base = mp->hif_base;

  /* Disable Legacy WRR, Disable EJP, Release from reset */
  tx_port_num = MVPP2_MAX_TCONT + pp2_port_id (port);
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_CMD_1_REG, 0x0);

  /* Close bandwidth for all queues */
  for (queue = 0; queue < MVPP2_MAX_TXQ; queue++)
    {
      ptxq = (MVPP2_MAX_TCONT + pp2_port_id (port)) * MVPP2_MAX_TXQ + queue;
      pp2_reg_write (hif_base, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (ptxq), 0x0);
    }

  /* Set refill period to 1 usec, refill tokens
   * and bucket size to maximum
   */
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PERIOD_REG, PP2_TCLK_FREQ / 1000000); /* USEC_PER_SEC */
  val = pp2_reg_read (hif_base, MVPP2_TXP_SCHED_REFILL_REG);
  val &= ~MVPP2_TXP_REFILL_PERIOD_ALL_MASK;
  val |= MVPP2_TXP_REFILL_PERIOD_MASK (1);
  val |= MVPP2_TXP_REFILL_TOKENS_ALL_MASK;
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_REFILL_REG, val);
  val = MVPP2_TXP_TOKEN_SIZE_MAX;
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, val);

  /* Set MaximumLowLatencyPacketSize value to 256 */
  /* Set GemPortIdSrcSel from classifier */
  pp2_reg_write (hif_base, MVPP2_RX_CTRL_REG (pp2_port_id (port)),
		 MVPP2_RX_USE_PSEUDO_FOR_CSUM_MASK | MVPP2_RX_LOW_LATENCY_PKT_SIZE (256) |
		   MVPP2_RX_GEM_PORT_ID_SRC_SEL (2));

  /* Disable Rx cache snoop */
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

      queue = rxq->id;
      val = pp2_reg_read (hif_base, MVPP2_RXQ_CONFIG_REG (queue));
      /* Coherent */
      val |= MVPP2_SNOOP_PKT_SIZE_MASK;
      val |= MVPP2_SNOOP_BUF_HDR_MASK;
      pp2_reg_write (hif_base, MVPP2_RXQ_CONFIG_REG (queue), val);
    }
  /* As default, mask all interrupts to all present cpus */
  pp2_port_interrupts_disable (port);
}

void
pp2_port_deinit (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  pp2_port_flush_mac_addrs (port, 1, 1);
  vec_free (mp->added_uc_addrs);

  /* Reset/disable TXQs/RXQs from hardware */
  pp2_port_rxqs_deinit (port);
  pp2_port_txqs_deinit (port);

  /* Deallocate TXQs/RXQs for this port */
  pp2_port_txqs_destroy (port);
  pp2_port_rxqs_destroy (port);
}

static void
pp2_port_egress_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 q_mask = 0;
  uintptr_t hif_base = mp->hif_base;

  q_mask = (pp2_reg_read (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG) & MVPP2_TXP_SCHED_ENQ_MASK);
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

static void
pp2_port_ingress_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 val;
  uintptr_t hif_base = mp->hif_base;

  /* RXQs disable */
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
      u32 qid = rxq->id;

      val = pp2_reg_read (hif_base, MVPP2_RXQ_CONFIG_REG (qid));
      val |= MVPP2_RXQ_DISABLE_MASK;
      pp2_reg_write (hif_base, MVPP2_RXQ_CONFIG_REG (qid), val);
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
      u32 qid = rxq->id;

      val = pp2_reg_read (hif_base, MVPP2_RXQ_CONFIG_REG (qid));
      val &= ~MVPP2_RXQ_DISABLE_MASK;
      pp2_reg_write (hif_base, MVPP2_RXQ_CONFIG_REG (qid), val);
    }
}

static void
pp2_port_mac_max_rx_size_set (vnet_dev_port_t *port)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int mac_num = mp->mac_data.gop_index;
  uint32_t pp2_version;

  /* GOP#0 and GOP#2 (In PP23/CP115) can support both XLG and GMAC;
   * MUSDK cannot know that on the fly so always configure both of them;
   * All the rest support only GMAC
   */
  pp2_version = pp2_reg_read (mp->hif_base, MVPP2_VER_ID_REG);
  pp2_gop_gmac_max_rx_size_set (md, mac_num, pp2_port_mru (port));
  if ((mac_num == 0) || ((mac_num == 2) && (pp2_version == MVPP2_VER_PP23)))
    pp2_gop_xlg_mac_max_rx_size_set (md, mac_num, pp2_port_mru (port));
}

static void
pp2_port_rxqs_create (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 qid, tc, id = 0;

  for (tc = 0; tc < mp->num_tcs; tc++)
    {
      struct pp2_ppio_tc_config *tc_cfg = &(mp->tc.tc_config);

      for (qid = 0; qid < mp->tc.tc_config.num_in_qs; qid++)
	{
	  mvpp2_rxq_t *rxq = pp2_port_rxq_get (port, id);
	  u8 mem_index = mp->tc.rx_qs[qid].tc_pools_mem_id_index;
	  u32 tmp_bpool_id;

	  rxq->id = tc_cfg->first_rxq + qid;
	  rxq->log_id = mp->tc.first_log_rxq + qid;
	  rxq->desc_total = mp->tc.rx_qs[qid].ring_size;
	  rxq->desc_received = 0;
	  rxq->desc_next_idx = 0;

	  tmp_bpool_id = tc_cfg->pools[mem_index][BM_TYPE_SHORT_BUF_POOL]->id;
	  rxq->bm_pool_id[BM_TYPE_SHORT_BUF_POOL] = tmp_bpool_id;

	  tmp_bpool_id = tc_cfg->pools[mem_index][BM_TYPE_LONG_BUF_POOL]->id;
	  rxq->bm_pool_id[BM_TYPE_LONG_BUF_POOL] = tmp_bpool_id;

	  log_debug (dev, "pp2_port_rxqs_create: port[%d:%d] tc%d rxq%d mem_index(%d)\n", md->pp_id,
		     pp2_port_id (port), tc, rxq->id, mem_index);

	  /* Double check of queue index */
	  if (rxq->log_id != id)
	    {
	      log_err (dev, "%s invalid log_id %d value (should be %d)\n", __func__, rxq->log_id,
		       id);
	      return;
	    }
	  id++;
	}
    }
}

static void
pp2_port_rxqs_init (vnet_dev_port_t *port)
{
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

      pp2_rxq_init (port, rxq);
    }

  pp2_port_rxqs_fc_state_reset (port);
  pp2_port_clear_fc_isr (port);
}

static int
pp2_port_set_outq_state (vnet_dev_port_t *port, mvpp2_txq_t *txq, int en)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  uintptr_t hif_base = mp->hif_base;
  int tx_port_num = MVPP2_MAX_TCONT + pp2_port_id (port);
  u32 val = 0, mask;

  /* TODO: add lock to protect MVPP2_TXP_SCHED_PORT_INDEX_REG */
  /* Get active channels mask */
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  val = (pp2_reg_read (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG) & MVPP2_TXP_SCHED_ENQ_MASK);
  mask = 1 << txq->log_id;

  if (en)
    {
      if (!(val & mask))
	{
	  /* Enable transmit packets to aggregation queue */
	  txq->disabled = 0;

	  /* Enable Tx queue */
	  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
	  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG, mask);
	}
    }
  else
    {
      if (val & mask)
	{
	  u32 delay = 0;
	  u32 pending;

	  /* Disable transmit packets to aggregation queue */
	  txq->disabled = 1;

	  /* Flush Tx queue */
	  do
	    {
	      if (delay >= MVPP2_TX_PENDING_TIMEOUT_USEC)
		{
		  log_warn (dev, "Port%u: TXQ=%u clean timed out\n", pp2_port_id (port),
			    txq->log_id);
		  break;
		}
	      /* Sleep for 1 microsecond */
	      udelay (1);
	      delay++;
	      pending = pp2_txq_pend_desc_num_get (port, txq);
	      log_debug (dev, "pp2_txq_clean: Port%u: TXQ=%u pending: %d\n", pp2_port_id (port),
			 txq->log_id, pending);
	    }
	  while (pending);

	  /* Disable Tx queue */
	  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
	  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG, mask << MVPP2_TXP_SCHED_DISQ_OFFSET);
	}
    }

  return 0;
}

static void
pp2_port_stop_dev (vlib_main_t *vm, vnet_dev_port_t *port)
{
  /* Stop new packets from arriving to RXQs */
  pp2_port_ingress_disable (port);

  vlib_process_suspend (vm, 0.01);

  /* Disable interrupts on all CPUs */
  pp2_port_interrupts_disable (port);
  pp2_port_egress_disable (port);
}

static void
pp2_port_txqs_create (vnet_dev_port_t *port)
{
  foreach_vnet_dev_port_tx_queue (q, port)
    {
      mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);
      u32 qid = q->queue_id;

      txq->id = (MVPP2_MAX_TCONT + pp2_port_id (port)) * MVPP2_MAX_TXQ + qid;
      txq->log_id = qid;
      txq->disabled = 0;
      for (u32 i = 0; i < ARRAY_LEN (txq->desc_rsrvd); i++)
	txq->desc_rsrvd[i] = 0;
    }
}

static void
pp2_txq_init (vnet_dev_port_t *port, mvpp2_txq_t *txq)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  void *desc_mem;
  uintptr_t hif_base;
  u32 j, val, desc_per_txq, pref_buf_size, desc;

  hif_base = mp->hif_base;
  txq->hif_base = hif_base;

  desc_per_txq = PP2_ETH_PORT_TXQ_PREFETCH;

  /* FS_A8K Table 1542: The SWF ring size + a prefetch size for HWF */
  txq->desc_total = mp->txq_config[txq->log_id].size;
  if (vnet_dev_dma_mem_alloc (vlib_get_main (), port->dev,
			      txq->desc_total * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN,
			      &desc_mem) != VNET_DEV_OK)
    desc_mem = 0;

  if (unlikely (!desc_mem))
    {
      log_err (dev, "PP: cannot allocate egress descriptor array\n");
      return;
    }
  txq->desc_virt_arr = desc_mem;
  txq->desc_phys_arr = vnet_dev_get_dma_addr (vlib_get_main (), port->dev, txq->desc_virt_arr);
  if (!IS_ALIGNED (txq->desc_phys_arr, MVPP2_DESC_Q_ALIGN))
    {
      log_err (dev, "PP: egress descriptor array must be %u-byte aligned\n", MVPP2_DESC_Q_ALIGN);
      vnet_dev_dma_mem_free (vlib_get_main (), port->dev, txq->desc_virt_arr);
      return;
    }

  log_debug (dev, "port[%d:%d] tx desc_phys_addr(0x%lx)\n", md->pp_id, pp2_port_id (port),
	     txq->desc_phys_arr);

  /* Set Tx descriptors queue starting address - indirect access */
  pp2_reg_write (hif_base, MVPP2_TXQ_NUM_REG, txq->id);
  pp2_reg_write (hif_base, MVPP2_TXQ_DESC_ADDR_LOW_REG,
		 ((uint32_t) txq->desc_phys_arr) >> MVPP2_TXQ_DESC_ADDR_LOW_SHIFT);
  pp2_reg_write (hif_base, MVPP22_TXQ_DESC_ADDR_HIGH_REG,
		 (txq->desc_phys_arr >> 32) & MVPP22_TXQ_DESC_ADDR_HIGH_MASK);
  pp2_reg_write (hif_base, MVPP2_TXQ_DESC_SIZE_REG, txq->desc_total & MVPP2_TXQ_DESC_SIZE_MASK);
  pp2_reg_write (hif_base, MVPP2_TXQ_INDEX_REG, 0x0);
  pp2_reg_write (hif_base, MVPP2_TXQ_RSVD_CLR_REG, txq->id << MVPP2_TXQ_RSVD_CLR_OFFSET);
  val = pp2_reg_read (hif_base, MVPP2_TXQ_PENDING_REG);
  val &= ~MVPP2_TXQ_PENDING_MASK;
  pp2_reg_write (hif_base, MVPP2_TXQ_PENDING_REG, val);

  /* Calculate base address in prefetch buffer. We reserve 16 descriptors
   * for each existing TXQ.
   * - TCONTS for PON port must be continuous from 0 to MVPP2_MAX_TCONT
   * - GBE ports assumed to be continious from 0 to MVPP2_MAX_PORTS
   */
  if (desc_per_txq == PP2_TXQ_PREFETCH_64)
    pref_buf_size = MVPP2_PREF_BUF_SIZE_64;
  else if (desc_per_txq == PP2_TXQ_PREFETCH_32)
    pref_buf_size = MVPP2_PREF_BUF_SIZE_32;
  else if (desc_per_txq == PP2_TXQ_PREFETCH_16)
    pref_buf_size = MVPP2_PREF_BUF_SIZE_16;
  else
    pref_buf_size = MVPP2_PREF_BUF_SIZE_4;

  /* Since the loopback port is the last port, below calc. is always correct */
  desc =
    (pp2_port_id (port) * MVPP2_MAX_TXQ * PP2_ETH_PORT_TXQ_PREFETCH) + (txq->log_id * desc_per_txq);

  /* Set desc prefetch threshold to 8 units of 2 descriptors */
  pp2_reg_write (hif_base, MVPP2_TXQ_PREF_BUF_REG,
		 MVPP2_PREF_BUF_PTR (desc) | pref_buf_size |
		   MVPP2_PREF_BUF_THRESH (PP2_TXQ_PREFETCH_16 / 2));

  /* Lastly, clear all ETH_TXQS for all future DM-IFs */
  for (j = 0; j < MVPP2_NUM_HIFS; j++)
    {
      hif_base = mvpp2_hif_base (md, j);
      pp2_reg_read (hif_base, MVPP22_TXQ_SENT_REG (txq->id));
    }
}

static inline u32
fls_32 (u32 x)
{
  return x ? (32 - __builtin_clz (x)) : 0;
}

static inline u32
fls_64 (u64 x)
{
  return upper_32_bits (x) ? fls_32 (upper_32_bits (x)) : fls_32 (lower_32_bits (x));
}

static int
mv_netdev_feature_set (vnet_dev_t *dev, const char *netdev, const char *featstr, int val)
{
  struct netdev_featstrs fs = { 0 };
  struct ifreq ifr = { 0 };
  int fbit;
  int fd;
  int ret;
  int i;

  fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd == -1)
    {
      log_err (dev, "can't open socket: errno %d", errno);
      return -EFAULT;
    }

  sprintf (ifr.ifr_name, "%s", netdev);

  if (mv_netdev_get_featstrs (dev, fd, &ifr, &fs))
    {
      close (fd);
      return -EFAULT;
    }

  for (i = 0; i < FEATSTRS_MAX; i++)
    {
      if (fs.s[i] == NULL)
	continue;

      if (strcmp (fs.s[i], featstr))
	continue;

      fbit = i;
      break;
    }

  if (i == FEATSTRS_MAX)
    {
      log_err (dev, "failed to find feature %s\n", featstr);
      close (fd);
      mv_netdev_clean_featstrs (&fs);
      return -ENOENT;
    }

  ret = mv_netdev_set_feature_ioctl (dev, fd, &ifr, fbit, !!val);

  close (fd);
  mv_netdev_clean_featstrs (&fs);

  if (ret)
    return -EIO;

  return 0;
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

static void
mv_pp2x_prs_shadow_ri_set (mvpp2_device_t *md, int index, unsigned int ri, unsigned int ri_mask)
{
  md->cls_db->prs_db.prs_shadow[index].ri_mask = ri_mask;
  md->cls_db->prs_db.prs_shadow[index].ri = ri;
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

static unsigned int
mv_pp2x_prs_tcam_port_map_get (struct mv_pp2x_prs_entry *pe)
{
  int enable_off = HW_BYTE_OFFS (MVPP2_PRS_TCAM_EN_OFFS (MVPP2_PRS_TCAM_PORT_BYTE));

  return ~(pe->tcam.byte[enable_off]) & MVPP2_PRS_PORT_MASK;
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

  c2_status = pp2_reg_read (md->pp_base, MVPP2_CLS2_TCAM_CTRL_REG);
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

static int
pp2_gop_gmac_max_rx_size_set (mvpp2_device_t *md, int mac_num, int max_rx_size)
{
  u32 reg_val;

  reg_val = pp2_gop_gmac_read (md, mac_num, PP2_GMAC_PORT_CTRL0_REG);
  reg_val &= ~PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_MASK;
  reg_val |= (((max_rx_size - MV_MH_SIZE) / 2) << PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_OFFS);
  pp2_gop_gmac_write (md, mac_num, PP2_GMAC_PORT_CTRL0_REG, reg_val);

  return 0;
}

static int
pp2_gop_xlg_mac_max_rx_size_set (mvpp2_device_t *md, int mac_num, int max_rx_size)
{
  u32 reg_val;

  reg_val = pp2_gop_xlg_mac_read (md, mac_num, PP2_XLG_PORT_MAC_CTRL1_REG);
  reg_val &= ~PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_MASK;
  reg_val |= (((max_rx_size - MV_MH_SIZE) / 2) << PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_OFFS);
  pp2_gop_xlg_mac_write (md, mac_num, PP2_XLG_PORT_MAC_CTRL1_REG, reg_val);

  return 0;
}

static void
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
      pp2_reg_write (hif_base, MVPP2_RX_EX_INT_CAUSE_MASK_REG (pp2_port_id (port)), 0);
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
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  if (q_mask)
    pp2_reg_write (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG, q_mask << MVPP2_TXP_SCHED_DISQ_OFFSET);

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
      val = pp2_reg_read (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG);
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

  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG, q_mask);
  log_debug (dev, "Port: Egress enable tx_port_num=%u q_mask=0x%X\n", tx_port_num, q_mask);
}

static void
pp2_port_interrupts_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  u32 mask = 0;
  uintptr_t hif_base = mp->hif_base;

  foreach_vnet_dev_port_rx_queue (q, port)
    mask |= 1 << md->threads[q->rx_thread_index].hif_id;

  pp2_reg_write (hif_base, MVPP2_ISR_ENABLE_REG (pp2_port_id (port)),
		 MVPP2_ISR_DISABLE_INTERRUPT (mask));
}

static void
pp2_port_rxqs_deinit (vnet_dev_port_t *port)
{
  pp2_port_restore_fc_isr (port);
  pp2_port_rxqs_fc_state_reset (port);

  foreach_vnet_dev_port_rx_queue (q, port)
    pp2_rxq_deinit (port, vnet_dev_get_rx_queue_data (q));
}

static void
pp2_port_rxqs_destroy (vnet_dev_port_t *port)
{
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

      vnet_dev_dma_mem_free (vlib_get_main (), port->dev, rxq->hw_descs);
      rxq->hw_descs = 0;
    }
}

static void
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

static void
pp2_port_txq_deinit (vnet_dev_port_t *port, mvpp2_txq_t *txq)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  pp2_port_set_outq_state (port, txq, false);
  pp2_txq_deinit (txq);

  for (u32 j = 0; j < MVPP2_NUM_HIFS; j++)
    pp2_reg_read (mvpp2_hif_base (md, j), MVPP22_TXQ_SENT_REG (txq->id));
}

static void
pp2_port_txqs_deinit (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  uintptr_t hif_base = mp->hif_base;
  u32 val;

  val = pp2_reg_read (hif_base, MVPP2_TX_PORT_FLUSH_REG);

  /* Reset Tx ports and clear Tx queues */
  val |= MVPP2_TX_PORT_FLUSH_MASK (pp2_port_id (port));
  pp2_reg_write (hif_base, MVPP2_TX_PORT_FLUSH_REG, val);

  foreach_vnet_dev_port_tx_queue (q, port)
    pp2_port_txq_deinit (port, vnet_dev_get_tx_queue_data (q));

  val &= ~MVPP2_TX_PORT_FLUSH_MASK (pp2_port_id (port));
  pp2_reg_write (hif_base, MVPP2_TX_PORT_FLUSH_REG, val);
}

static void
pp2_port_txqs_destroy (vnet_dev_port_t *port)
{
  foreach_vnet_dev_port_tx_queue (q, port)
    {
      mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);

      vnet_dev_dma_mem_free (vlib_get_main (), port->dev, txq->desc_virt_arr);
      txq->desc_virt_arr = 0;
    }
}

static void
pp2_port_txsched_set_mtu (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 val, mtu;
  u32 tx_port_num;
  uintptr_t hif_base = mp->hif_base;

  mtu = (pp2_port_mtu (port) + ETH_HLEN) * 8;

  /* WA for wrong Token bucket update: Set MTU value = 3*real MTU value */
  mtu = 3 * mtu;

  if (mtu > MVPP2_TXP_MTU_MAX)
    mtu = MVPP2_TXP_MTU_MAX;

  /* Indirect access to registers */
  tx_port_num = MVPP2_TX_PORT_NUM (pp2_port_id (port));
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);

  /* Set MTU */
  val = pp2_reg_read (hif_base, MVPP2_TXP_SCHED_MTU_REG);
  val &= ~MVPP2_TXP_MTU_MAX;
  val |= mtu;
  pp2_reg_write (hif_base, MVPP2_TXP_SCHED_MTU_REG, val);
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

  used_tbls = pp2_cls_db_rss_kernel_rsvd_tbl_get (md) + pp2_cls_db_rss_num_musdk_tbl_get (md);
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
	  pp2_cls_db_rss_tbl_map_set (md, idx, pp2_cls_db_rss_kernel_rsvd_tbl_get (md) + idx,
				      mp->tc.tc_config.num_in_qs);
	  req_ind[req_tbls] = idx;
	  req_tbls++;
	  hw_tbl = pp2_cls_db_rss_kernel_rsvd_tbl_get (md) + idx;
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

static void
pp2_rxq_init (vnet_dev_port_t *port, mvpp2_rxq_t *rxq)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  void *desc_mem;
  u32 val;
  uintptr_t hif_base;
  struct pp2_tc *tc;

  hif_base = mp->hif_base;

  if (vnet_dev_dma_mem_alloc (vlib_get_main (), port->dev,
			      rxq->desc_total * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN,
			      &desc_mem) != VNET_DEV_OK)
    {
      log_err (dev, "PP: cannot allocate ingress descriptor array\n");
      return;
    }
  rxq->hw_descs = desc_mem;
  rxq->desc_phys_arr = vnet_dev_get_dma_addr (vlib_get_main (), port->dev, rxq->hw_descs);
  if (!IS_ALIGNED (rxq->desc_phys_arr, MVPP2_DESC_Q_ALIGN))
    {
      log_err (dev, "PP: ingress descriptor array must be %u-byte aligned\n", MVPP2_DESC_Q_ALIGN);
      vnet_dev_dma_mem_free (vlib_get_main (), port->dev, rxq->hw_descs);
      return;
    }
  log_debug (dev, "port[%d:%d] rxq[%d], desc_phys_addr(0x%lx)\n", md->pp_id, pp2_port_id (port),
	     rxq->id, rxq->desc_phys_arr);

  /* Zero occupied and non-occupied counters - direct access */
  pp2_reg_write (hif_base, MVPP2_RXQ_STATUS_REG (rxq->id), 0x0);

  /* Set Rx descriptors queue starting address - indirect access */
  pp2_reg_write (hif_base, MVPP2_RXQ_NUM_REG, rxq->id);

  pp2_reg_write (hif_base, MVPP2_RXQ_DESC_ADDR_REG, (rxq->desc_phys_arr >> MVPP22_DESC_ADDR_SHIFT));
  pp2_reg_write (hif_base, MVPP2_RXQ_DESC_SIZE_REG, rxq->desc_total);
  pp2_reg_write (hif_base, MVPP2_RXQ_INDEX_REG, 0x0);

  tc = pp2_rxq_tc_get (port, rxq->id);
  if (!tc)
    {
      log_err (dev, "port(%d) phy_rxq(%d), not found in tc range\n", pp2_port_id (port), rxq->id);
      return;
    }
  /* Set Offset */
  pp2_rxq_offset_set (port, rxq->id, tc->tc_config.pkt_offset);

  pp2_bm_pool_assign (port, rxq->bm_pool_id[BM_TYPE_SHORT_BUF_POOL], rxq->id,
		      BM_TYPE_SHORT_BUF_POOL);
  pp2_bm_pool_assign (port, rxq->bm_pool_id[BM_TYPE_LONG_BUF_POOL], rxq->id, BM_TYPE_LONG_BUF_POOL);
  log_debug (dev, "port[%d:%d] rxq[%d], short_pool(%d), long_pool(%d)\n", md->pp_id,
	     pp2_port_id (port), rxq->id, rxq->bm_pool_id[BM_TYPE_SHORT_BUF_POOL],
	     rxq->bm_pool_id[BM_TYPE_LONG_BUF_POOL]);

  /* Add number of descriptors ready for receiving packets */
  val = (0 | (rxq->desc_total << MVPP2_RXQ_NUM_NEW_OFFSET));
  pp2_reg_write (hif_base, MVPP2_RXQ_STATUS_UPDATE_REG (rxq->id), val);
}

static uint32_t
pp2_txq_pend_desc_num_get (vnet_dev_port_t *port, mvpp2_txq_t *txq)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 val;
  uintptr_t hif_base = mp->hif_base;

  pp2_reg_write (hif_base, MVPP2_TXQ_NUM_REG, txq->id);
  val = pp2_reg_read (hif_base, MVPP2_TXQ_PENDING_REG);

  return val & MVPP2_TXQ_PENDING_MASK;
}

static int
pp2_txsched_queue_arbitration_set (vnet_dev_port_t *port, u8 txq,
				   enum pp2_ppio_outq_sched_mode mode, u8 weight)
{
  vnet_dev_t *dev = port->dev;
  if (mode == PP2_PPIO_SCHED_M_WRR)
    return pp2_txsched_queue_wrr_set (port, txq, weight);

  if (mode == PP2_PPIO_SCHED_M_SP)
    return pp2_txsched_queue_fixed_prio_set (port, txq);

  log_err (dev, "%s Error: Invalid egress arbitration mode on p%dq%d: %d.\n", __func__,
	   pp2_port_id (port), txq, (int) mode);

  return -EINVAL;
}

static void
pp2_txsched_remap_weights (vnet_dev_port_t *port, u8 remapped_weights[])
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 hw_min, user_min = 0xff, user_max = 0x0;
  u32 mtu;
  int txPortNum;
  int accommodating_dynamic_range; /* Can user requested range be met after MTU restriction */

  txPortNum = MVPP2_TX_PORT_NUM (pp2_port_id (port));
  pp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, txPortNum);

  /* Weight * 256 bytes * 8 bits must be larger then MTU [bits] */
  mtu = pp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_MTU_REG);
  mtu /= PP2_AMPLIFY_FACTOR_MTU;
  mtu /= BITS_PER_BYTE; /* move to bytes */
  mtu = ALIGN (mtu, PP2_WRR_WEIGHT_UNIT);
  hw_min = mtu / PP2_WRR_WEIGHT_UNIT;

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      u32 txq = q->queue_id;

      if (mp->txq_config[txq].sched_mode == PP2_PPIO_SCHED_M_WRR)
	{

	  if (mp->txq_config[txq].weight == 0)
	    mp->txq_config[txq].weight = 1;

	  if (mp->txq_config[txq].weight > user_max)
	    user_max = mp->txq_config[txq].weight;

	  if (mp->txq_config[txq].weight < user_min)
	    user_min = mp->txq_config[txq].weight;
	}
    }

  if (user_min > user_max) /* WRR unused */
    return;

  if ((user_max / user_min) < (MVPP2_TXQ_WRR_WEIGHT_MAX / hw_min))
    accommodating_dynamic_range = 1;
  else
    accommodating_dynamic_range = 0;

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      u32 txq = q->queue_id;

      if (mp->txq_config[txq].sched_mode == PP2_PPIO_SCHED_M_WRR)
	{

	  if (accommodating_dynamic_range)
	    remapped_weights[txq] = mp->txq_config[txq].weight * hw_min / user_min;
	  else
	    remapped_weights[txq] = pp2_txsched_rational_weight_remap (
	      mp->txq_config[txq].weight, hw_min, MVPP2_TXQ_WRR_WEIGHT_MAX);
	}
    }
}

static void
mv_netdev_clean_featstrs (struct netdev_featstrs *fs)
{
  int i;

  for (i = 0; i < FEATSTRS_MAX; i++)
    {
      if (fs->s[i] == NULL)
	continue;
      clib_mem_free (fs->s[i]);
      fs->s[i] = NULL;
    }
}

static int
mv_netdev_set_feature_ioctl (vnet_dev_t *dev, int fd, struct ifreq *ifr, int bit, int val)
{
  struct ethtool_sfeatures *cmd;
  int word = bit / 32;
  int sbit = bit % 32;
  int ret;

  cmd = mem_calloc (1, sizeof (*cmd) + 2 * sizeof (cmd->features[0]));
  cmd->cmd = ETHTOOL_SFEATURES;
  cmd->size = 2;

  ifr->ifr_data = (char *) cmd;

  cmd->features[word].valid |= 1 << sbit;
  cmd->features[word].requested = val << sbit;

  ret = ioctl (fd, SIOCETHTOOL, ifr);
  if (ret)
    {
      if (ret < 0)
	log_err (dev, "Error setting bit (%s)\n", strerror (errno));
      else
	log_err (dev, "Error setting bit (%d)\n", ret);
      clib_mem_free (cmd);
      return -1;
    }

  clib_mem_free (cmd);
  return 0;
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

      mv_pp2x_cls_c2_qos_color_set (dev, &qos_entry, color);
      if (rc)
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

static u8
pp2_cls_c2_tcam_lkp_type_get (struct mv_pp2x_cls_c2_entry *c2)
{
  return (c2->tcam.words[4] & MVPP2_CLS_C2_HEK_LKP_TYPE_MASK);
}

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
pp2_cls_db_rss_kernel_rsvd_tbl_get (mvpp2_device_t *md)
{
  return md->cls_db->rss_db.num_kernel_rsrvd_tbls;
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
    {
      if (md->cls_db->rss_db.rss_tbl_map[i].num_in_q == 0)
	return i;
    }

  return i;
}

static int
pp2_cls_db_rss_tbl_map_set (mvpp2_device_t *md, u16 idx, u16 hw_tbl, u16 num_in_q)
{
  if (idx > MVPP22_RSS_TBL_NUM)
    return -EINVAL;

  if (hw_tbl > MVPP22_RSS_TBL_NUM)
    return -EINVAL;

  md->cls_db->rss_db.rss_tbl_map[idx].hw_tbl = hw_tbl;
  md->cls_db->rss_db.rss_tbl_map[idx].num_in_q = num_in_q;

  return 0;
}

static inline uint32_t
pp2_gop_gmac_read (mvpp2_device_t *md, int mac_num, uint32_t offset)
{
  return (pp2_gop_gen_read (md->gop_hw_gmac.base, mac_num * md->gop_hw_gmac.obj_size + offset));
}

static inline void
pp2_gop_gmac_write (mvpp2_device_t *md, int mac_num, u32 offset, uint32_t data)
{
  pp2_gop_gen_write (md->gop_hw_gmac.base, mac_num * md->gop_hw_gmac.obj_size + offset, data);
}

static inline uint32_t
pp2_gop_xlg_mac_read (mvpp2_device_t *md, int mac_num, uint32_t offset)
{
  return (
    pp2_gop_gen_read (md->gop_hw_xlg_mac.base, mac_num * md->gop_hw_xlg_mac.obj_size + offset));
}

static inline void
pp2_gop_xlg_mac_write (mvpp2_device_t *md, int mac_num, u32 offset, uint32_t data)
{
  pp2_gop_gen_write (md->gop_hw_xlg_mac.base, mac_num * md->gop_hw_xlg_mac.obj_size + offset, data);
}

static inline u32
pp2_port_isr_rx_group_read (vnet_dev_port_t *port, int sub_group)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int val;
  uintptr_t hif_base = mp->hif_base;

  val = (pp2_port_id (port) << MVPP22_ISR_RXQ_GROUP_INDEX_GROUP_OFFSET) | sub_group;
  pp2_reg_write (hif_base, MVPP22_ISR_RXQ_GROUP_INDEX_REG, val);

  return pp2_reg_read (hif_base, MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG);
}

static inline void
pp2_port_isr_rx_group_write (vnet_dev_port_t *port, int sub_group, int start_queue,
			     int num_rx_queues)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int val;
  uintptr_t hif_base = mp->hif_base;

  val = (pp2_port_id (port) << MVPP22_ISR_RXQ_GROUP_INDEX_GROUP_OFFSET) | sub_group;
  pp2_reg_write (hif_base, MVPP22_ISR_RXQ_GROUP_INDEX_REG, val);

  val = (num_rx_queues << MVPP22_ISR_RXQ_SUB_GROUP_SIZE_OFFSET) | start_queue;

  pp2_reg_write (hif_base, MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG, val);
}

static void
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

static void
pp2_rxq_deinit (vnet_dev_port_t *port, mvpp2_rxq_t *rxq)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  uintptr_t hif_base = mp->hif_base;

  pp2_rxq_resid_pkts (port, rxq);

  /* Clear Rx descriptors queue starting address and size;
   * free descriptor number
   */
  pp2_reg_write (hif_base, MVPP2_RXQ_STATUS_REG (rxq->id), 0);
  pp2_reg_write (hif_base, MVPP2_RXQ_NUM_REG, rxq->id);
  pp2_reg_write (hif_base, MVPP2_RXQ_DESC_ADDR_REG, 0);
  pp2_reg_write (hif_base, MVPP2_RXQ_DESC_SIZE_REG, 0);
}

static void
pp2_rxq_offset_set (vnet_dev_port_t *port, int prxq, int offset)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 val;
  uintptr_t hif_base = mp->hif_base;

  /* Convert offset from bytes to units of 32 bytes */
  offset = offset >> 5;

  val = pp2_reg_read (hif_base, MVPP2_RXQ_CONFIG_REG (prxq));
  val &= ~MVPP2_RXQ_PACKET_OFFSET_MASK;

  /* Offset is in */
  val |= ((offset << MVPP2_RXQ_PACKET_OFFSET_OFFS) & MVPP2_RXQ_PACKET_OFFSET_MASK);

  pp2_reg_write (hif_base, MVPP2_RXQ_CONFIG_REG (prxq), val);
}

static struct pp2_tc *
pp2_rxq_tc_get (vnet_dev_port_t *port, uint32_t id)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u8 i;

  for (i = 0; i < mp->num_tcs; i++)
    {
      u8 first_rxq = mp->tc.tc_config.first_rxq;

      if (id >= first_rxq && id < (first_rxq + mp->tc.tc_config.num_in_qs))
	return &mp->tc;
    }
  return NULL;
}

static void
pp2_txq_deinit (mvpp2_txq_t *txq)
{
  /* Set minimum bandwidth for disabled TXQs */
  pp2_reg_write (txq->hif_base, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (txq->id), 0);

  /* Set Tx descriptors queue starting address and size */
  pp2_reg_write (txq->hif_base, MVPP2_TXQ_NUM_REG, txq->id);
  pp2_reg_write (txq->hif_base, MVPP2_TXQ_DESC_ADDR_LOW_REG, 0);
  pp2_reg_write (txq->hif_base, MVPP2_TXQ_DESC_SIZE_REG, 0);
}

static int
pp2_txsched_queue_fixed_prio_set (vnet_dev_port_t *port, u8 txq)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 regVal;
  int txPortNum;

  txPortNum = MVPP2_TX_PORT_NUM (pp2_port_id (port));
  pp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, txPortNum);

  regVal = pp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_FIXED_PRIO_REG);
  regVal |= (1 << txq);
  pp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_FIXED_PRIO_REG, regVal);

  return 0;
}

static int
pp2_txsched_queue_wrr_set (vnet_dev_port_t *port, u8 txq, u8 weight)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 regVal;
  int txPortNum;

  txPortNum = MVPP2_TX_PORT_NUM (pp2_port_id (port));
  pp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, txPortNum);

  regVal = pp2_reg_read (mp->hif_base, MVPP2_TXQ_SCHED_WRR_REG (txq));

  regVal &= ~MVPP2_TXQ_WRR_WEIGHT_ALL_MASK;
  regVal |= MVPP2_TXQ_WRR_WEIGHT_MASK (weight);
  pp2_reg_write (mp->hif_base, MVPP2_TXQ_SCHED_WRR_REG (txq), regVal);

  regVal = pp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_FIXED_PRIO_REG);
  regVal &= ~(1 << txq);
  pp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_FIXED_PRIO_REG, regVal);

  return 0;
}

static u8
pp2_txsched_rational_weight_remap (u32 weight, u32 min, u32 max)
{
  /* The solution for minimum weight of 1 contains square roots, but doesn't for minimum weight of
   * 0, so we offset the parameters by -1 and offset the result back.
   */
  weight -= 1;
  min -= 1;
  max -= 1;
  return ((min * max * max + min - max) * weight + min * max * (max - 1)) /
	   ((min * max + min - max) * weight + max * (max - 1)) +
	 1;
}

static int
mv_pp2x_cls_c2_qos_color_set (vnet_dev_t *dev, struct mv_pp2x_cls_c2_qos_entry *qos, int color)
{
  if (mv_pp2x_ptr_validate (dev, qos) == MV_ERROR)
    return MV_ERROR;

  qos->data &= ~MVPP2_CLS2_QOS_TBL_COLOR_MASK;
  qos->data |= color << MVPP2_CLS2_QOS_TBL_COLOR_OFF;

  return 0;
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
  pp2_reg_write (md->pp_base, MVPP2_CLS2_DSCP_PRI_INDEX_REG, reg_val);

  /* write data reg */
  pp2_reg_write (md->pp_base, MVPP2_CLS2_QOS_TBL_REG, qos->data);

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

static inline uint32_t
pp2_gop_gen_read (uintptr_t base, uint32_t offset)
{
  return pp2_reg_read (base, offset);
}

static inline void
pp2_gop_gen_write (uintptr_t base, uint32_t offset, uint32_t data)
{
  pp2_reg_write (base, offset, data);
}

static void
pp2_rxq_resid_pkts (vnet_dev_port_t *port, mvpp2_rxq_t *rxq)
{
  vnet_dev_t *dev = port->dev;
  u32 rx_resid = pp2_rxq_received (port, rxq->id);

  if (!rx_resid)
    return;

  log_warn (dev, "RXQ has %u residual packets\n", rx_resid);

  /* Cleanup for dangling RXDs can be done here by getting
   * the BM-IF associated to the BM poool associated to this
   * RXQ, but it would not be correct.
   *
   * No indirect access to BM pools assigned to this RXQ.
   * Client should handle cleanup before/after destroying the
   * interface
   */
}

void
mv_pp2x_c2_sw_clear (struct mv_pp2x_cls_c2_entry *c2)
{
  memset (c2, 0, sizeof (struct mv_pp2x_cls_c2_entry));
}

int
mv_pp2x_cls_c2_hw_read (vnet_dev_t *dev, uintptr_t hif_base, int index,
			struct mv_pp2x_cls_c2_entry *c2)
{
  unsigned int reg_val = 0;
  int tcm_idx;

  if (mv_pp2x_ptr_validate (dev, c2) == MV_ERROR)
    return MV_ERROR;

  c2->index = index;

  /* write index reg */
  pp2_reg_write (hif_base, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* read invalid bit */
  reg_val = pp2_reg_read (hif_base, MVPP2_CLS2_TCAM_INV_REG);

  c2->inv = (reg_val & MVPP2_CLS2_TCAM_INV_INVALID_MASK) >> MVPP2_CLS2_TCAM_INV_INVALID_OFF;

  if (c2->inv)
    return 0;

  for (tcm_idx = 0; tcm_idx < MVPP2_CLS_C2_TCAM_WORDS; tcm_idx++)
    c2->tcam.words[tcm_idx] = pp2_reg_read (hif_base, MVPP2_CLS2_TCAM_DATA_REG (tcm_idx));

  c2->sram.regs.action_tbl = pp2_reg_read (hif_base, MVPP2_CLS2_ACT_DATA_REG);
  c2->sram.regs.actions = pp2_reg_read (hif_base, MVPP2_CLS2_ACT_REG);
  c2->sram.regs.qos_attr = pp2_reg_read (hif_base, MVPP2_CLS2_ACT_QOS_ATTR_REG);
  c2->sram.regs.hwf_attr = pp2_reg_read (hif_base, MVPP2_CLS2_ACT_HWF_ATTR_REG);
  c2->sram.regs.rss_attr = pp2_reg_read (hif_base, MVPP2_CLS2_ACT_DUP_ATTR_REG);
  c2->sram.regs.seq_attr = pp2_reg_read (hif_base, MVPP21_CLS2_ACT_SEQ_ATTR_REG);

  return 0;
}

u8
pp2_cls_c2_tcam_port_get (struct mv_pp2x_cls_c2_entry *c2)
{
  return ((c2->tcam.words[4] >> 8) & 0xFF);
}

int
mv_pp2x_cls_c2_hw_write (uintptr_t hif_base, int index, struct mv_pp2x_cls_c2_entry *c2)
{
  int tcm_idx;

  if (!c2 || index >= MVPP2_CLS_C2_TCAM_SIZE)
    return -EINVAL;

  c2->index = index;

  /* write index reg */
  pp2_reg_write (hif_base, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* write valid bit */
  c2->inv = 0;
  pp2_reg_write (hif_base, MVPP2_CLS2_TCAM_INV_REG, ((c2->inv) << MVPP2_CLS2_TCAM_INV_INVALID_OFF));

  for (tcm_idx = 0; tcm_idx < MVPP2_CLS_C2_TCAM_WORDS; tcm_idx++)
    pp2_reg_write (hif_base, MVPP2_CLS2_TCAM_DATA_REG (tcm_idx), c2->tcam.words[tcm_idx]);

  /* write action_tbl CLSC2_ACT_DATA */
  pp2_reg_write (hif_base, MVPP2_CLS2_ACT_DATA_REG, c2->sram.regs.action_tbl);

  /* write actions CLSC2_ACT */
  pp2_reg_write (hif_base, MVPP2_CLS2_ACT_REG, c2->sram.regs.actions);

  /* write qos_attr CLSC2_ATTR0 */
  pp2_reg_write (hif_base, MVPP2_CLS2_ACT_QOS_ATTR_REG, c2->sram.regs.qos_attr);

  /* write hwf_attr CLSC2_ATTR1 */
  pp2_reg_write (hif_base, MVPP2_CLS2_ACT_HWF_ATTR_REG, c2->sram.regs.hwf_attr);

  /* write rss_attr CLSC2_ATTR2 */
  pp2_reg_write (hif_base, MVPP2_CLS2_ACT_DUP_ATTR_REG, c2->sram.regs.rss_attr);

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

int
pp2_gop_gmac_link_status (mvpp2_device_t *md, int mac_num, struct pp2_port_link_status *pstatus)
{
  u32 reg_val;

  reg_val = pp2_gop_gmac_read (md, mac_num, PP2_GMAC_PORT_STATUS0_REG);

  if (reg_val & PP2_GMAC_PORT_STATUS0_GMIISPEED_MASK)
    pstatus->speed = PP2_PORT_SPEED_1000;
  else if (reg_val & PP2_GMAC_PORT_STATUS0_MIISPEED_MASK)
    pstatus->speed = PP2_PORT_SPEED_100;
  else
    pstatus->speed = PP2_PORT_SPEED_10;

  if (reg_val & PP2_GMAC_PORT_STATUS0_LINKUP_MASK)
    pstatus->linkup = 1 /*TRUE*/;
  else
    pstatus->linkup = 0 /*FALSE*/;

  if (reg_val & PP2_GMAC_PORT_STATUS0_FULLDX_MASK)
    pstatus->duplex = PP2_PORT_DUPLEX_FULL;
  else
    pstatus->duplex = PP2_PORT_DUPLEX_HALF;

  if (reg_val & PP2_GMAC_PORT_STATUS0_PORTTXPAUSE_MASK)
    pstatus->tx_fc = PP2_PORT_FC_ACTIVE;
  else if (reg_val & PP2_GMAC_PORT_STATUS0_TXFCEN_MASK)
    pstatus->tx_fc = PP2_PORT_FC_ENABLE;
  else
    pstatus->tx_fc = PP2_PORT_FC_DISABLE;

  if (reg_val & PP2_GMAC_PORT_STATUS0_PORTRXPAUSE_MASK)
    pstatus->rx_fc = PP2_PORT_FC_ACTIVE;
  else if (reg_val & PP2_GMAC_PORT_STATUS0_RXFCEN_MASK)
    pstatus->rx_fc = PP2_PORT_FC_ENABLE;
  else
    pstatus->rx_fc = PP2_PORT_FC_DISABLE;

  return 0;
}

int
pp2_gop_xlg_mac_link_status (mvpp2_device_t *md, int mac_num, struct pp2_port_link_status *pstatus)
{
  u32 reg_val;
  u32 mac_mode;
  u32 fc_en;

  reg_val = pp2_gop_xlg_mac_read (md, mac_num, PP2_XLG_PORT_MAC_CTRL3_REG);
  mac_mode =
    (reg_val & PP2_XLG_MAC_CTRL3_MACMODESELECT_MASK) >> PP2_XLG_MAC_CTRL3_MACMODESELECT_OFFS;

  /* speed  and duplex */
  switch (mac_mode)
    {
    case 0:
      pstatus->speed = PP2_PORT_SPEED_1000;
      pstatus->duplex = PP2_PORT_DUPLEX_AN;
      break;
    case 1:
      pstatus->speed = PP2_PORT_SPEED_10000;
      pstatus->duplex = PP2_PORT_DUPLEX_FULL;
      break;
    default:
      return -1;
    }

  /* link status */
  reg_val = pp2_gop_xlg_mac_read (md, mac_num, PP2_XLG_MAC_PORT_STATUS_REG);
  if (reg_val & PP2_XLG_MAC_PORT_STATUS_LINKSTATUS_MASK)
    pstatus->linkup = 1 /*TRUE*/;
  else
    pstatus->linkup = 0 /*FALSE*/;

  /* flow control status */
  fc_en = pp2_gop_xlg_mac_read (md, mac_num, PP2_XLG_PORT_MAC_CTRL0_REG);
  if (reg_val & PP2_XLG_MAC_PORT_STATUS_PORTTXPAUSE_MASK)
    pstatus->tx_fc = PP2_PORT_FC_ACTIVE;
  else if (fc_en & PP2_XLG_MAC_CTRL0_TXFCEN_MASK)
    pstatus->tx_fc = PP2_PORT_FC_ENABLE;
  else
    pstatus->tx_fc = PP2_PORT_FC_DISABLE;

  if (reg_val & PP2_XLG_MAC_PORT_STATUS_PORTRXPAUSE_MASK)
    pstatus->rx_fc = PP2_PORT_FC_ACTIVE;
  else if (fc_en & PP2_XLG_MAC_CTRL0_RXFCEN_MASK)
    pstatus->rx_fc = PP2_PORT_FC_ENABLE;
  else
    pstatus->rx_fc = PP2_PORT_FC_DISABLE;

  return 0;
}

static void
pp2_port_mac_set_loopback (vnet_dev_port_t *port, int en)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int mac_num = mp->mac_data.gop_index;
  enum pp2_lb_type lb = (en) ? PP2_TX_2_RX_LB : PP2_DISABLE_LB;
  uint32_t pp2_version;

  /* GOP#0 and GOP#2 (In PP23/CP115) can support both XLG and GMAC;
   * MUSDK cannot know that on the fly so always configure both of them;
   * All the rest support only GMAC
   */
  pp2_version = pp2_reg_read (mp->hif_base, MVPP2_VER_ID_REG);
  pp2_gop_gmac_loopback_cfg (md, mac_num, lb);
  if ((mac_num == 0) || ((mac_num == 2) && (pp2_version == MVPP2_VER_PP23)))
    pp2_gop_xlg_mac_loopback_cfg (md, mac_num, lb);
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

static int
pp2_gop_gmac_loopback_cfg (mvpp2_device_t *md, int mac_num, enum pp2_lb_type type)
{
  u32 reg_addr;
  u32 val;

  reg_addr = PP2_GMAC_PORT_CTRL1_REG;
  val = pp2_gop_gmac_read (md, mac_num, reg_addr);
  switch (type)
    {
    case PP2_DISABLE_LB:
      val &= ~PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_MASK;
      break;
    case PP2_TX_2_RX_LB:
      val |= PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_MASK;
      break;
    case PP2_RX_2_TX_LB:
    default:
      return -1;
    }
  pp2_gop_gmac_write (md, mac_num, reg_addr, val);

  return 0;
}

int
pp2_gop_xlg_mac_loopback_cfg (mvpp2_device_t *md, int mac_num, enum pp2_lb_type type)
{
  u32 reg_addr;
  u32 val;

  reg_addr = PP2_XLG_PORT_MAC_CTRL1_REG;
  val = pp2_gop_xlg_mac_read (md, mac_num, reg_addr);
  switch (type)
    {
    case PP2_DISABLE_LB:
      val &= ~PP2_XLG_MAC_CTRL1_MACLOOPBACKEN_MASK;
      val &= ~PP2_XLG_MAC_CTRL1_XGMIILOOPBACKEN_MASK;
      break;
    case PP2_RX_2_TX_LB:
      val &= ~PP2_XLG_MAC_CTRL1_MACLOOPBACKEN_MASK;
      val |= PP2_XLG_MAC_CTRL1_XGMIILOOPBACKEN_MASK;
      break;
    case PP2_TX_2_RX_LB:
      val |= PP2_XLG_MAC_CTRL1_MACLOOPBACKEN_MASK;
      val |= PP2_XLG_MAC_CTRL1_XGMIILOOPBACKEN_MASK;
      break;
    default:
      return -1;
    }
  pp2_gop_xlg_mac_write (md, mac_num, reg_addr, val);
  return 0;
}
