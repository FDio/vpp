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
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wimplicit-enum-enum-cast"
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
#pragma clang diagnostic ignored "-Wsometimes-uninitialized"
#pragma clang diagnostic ignored "-Wtautological-constant-out-of-range-compare"
#pragma clang diagnostic ignored "-Wunused-result"

typedef int32_t s32;

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

static u32 pp2_port_id (struct pp2_port *port);

#define LPBK_PORT(x) (pp2_port_id (x) == PP2_LOOPBACK_PORT)

#define mdelay(ms) usleep (ms * 1000)

#define MVPP2_C3_DEFAULT_SEARCH_DEPTH (3) /* default cuckoo search depth	*/

#define NOT_LPBK_PORT(x) (!LPBK_PORT (x))

#define PP2_BUFFER_OFFSET_GRAN (32)

#define PP2_ETHADDR_LEN (6)

#define PP2_MAX_PACKET_OFFSET (7 * 32)

#define PP2_NUM_PKT_PROC 4 /**< Maximum number of packet processors */

#define PP2_PACKET_DEF_OFFSET (L1_CACHE_LINE_BYTES)

#define PP2_REGSPACE_SIZE (0x10000)

#define PP2_TCLK_FREQ 333000000

#define pr_info(fmt, ...) mv_print (MV_DBG_L_INFO, fmt, ##__VA_ARGS__)

#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

#define roundup_pow_of_two(n) (1 << fls (n - 1))

#define mvlog2(n) (fls (n) - 1)

#define MSS_CP_CM3_BUF_POOL_BASE 0x40

#define MSS_CP_CM3_BUF_POOL_OFFS 4

#define MSS_CP_FC_COM_REG 0

#define MVPP2_C2_LOGIC_IDX_BASE 1000

#define NOT_IN_USE (-1)

#define PP2_BPPE_UNIT_SIZE (8)

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

#define LIST_FOR_EACH_OBJECT(_pos, _type, _head, _member)                                          \
  for (_pos = LIST_OBJECT (LIST_FIRST (_head), _type, _member); &_pos->_member != (_head);         \
       _pos = LIST_OBJECT (LIST_FIRST (&_pos->_member), _type, _member))
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

#define LIST_FIRST_OBJECT(_lst, _type, _member) LIST_OBJECT ((_lst)->next, _type, _member)

#define LUID_IS_LSP_RESERVED(luid) (NULL)

#define mb() dsb (sy)

#define MV_ETH_ETYPE_LEN 2

#define PP2_MAX_BUF_STR_LEN 256

#define PP2_NETDEV_PATH "/sys/class/net/"

#define PP2_PORT_MIN_MTU		    (68)
#define PP2_TX_FIFO_THRS_MIN_SUBSTRACTION   (256)
#define PP2_PORT_TX_FIFO_KB_TO_THRESH(fifo) ((fifo) * 1024 - PP2_TX_FIFO_THRS_MIN_SUBSTRACTION)

#define PP2_PORT_FLAGS_L4_CHKSUM (0x1)

#define PP2_PORT_FLAGS_LOOPBACK (0x2)
#define MAX_LOOKUP		3

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

#define readl_relaxed mv_readl_relaxed

#define TXD_BUFMODE_MASK (0x00000080)

#define TXD_BUF_VIRT_HI_MASK (0x000000FF)

#define TXD_POOL_ID_MASK (0x000F0000)

#define PORT_STRING "pp_port_%d:%d"

#define writel_relaxed		    mv_writel_relaxed
#define HUGE_PAGE_MAX_PAGE_COUNT    64
#define MVCONF_DMA_PHYS_ADDR_T_SIZE 64
#define __iomem
#define MVCONF_DBG_LEVEL 0
#ifndef log_fmt
#define log_fmt(fmt, ...) fmt, ##__VA_ARGS__
#endif

#define MV_DBG_L_CRIT 2
#define MV_DBG_L_ERR  3
#define MV_DBG_L_WARN 4
#define MV_DBG_L_INFO 6

#ifndef MVCONF_SYSLOG
#define mv_print(_level, fmt, ...)                                                                 \
  do                                                                                               \
    {                                                                                              \
      if ((_level) <= (MVCONF_DBG_LEVEL))                                                          \
	{                                                                                          \
	  struct timespec spec;                                                                    \
	  clock_gettime (CLOCK_BOOTTIME, &spec);                                                   \
	  printf ("[%5lu.%06lu] ", spec.tv_sec, spec.tv_nsec / 1000);                              \
	  printf (log_fmt (fmt, ##__VA_ARGS__));                                                   \
	}                                                                                          \
    }                                                                                              \
  while (0)
#else /* MVCONF_SYSLOG */

#define mv_print(_level, fmt, ...) syslog (_level, log_fmt (fmt, ##__VA_ARGS__))

#endif /* MVCONF_SYSLOG */

#ifndef pr_crit
#define pr_crit(fmt, ...) mv_print (MV_DBG_L_CRIT, "[CRITICAL] " fmt, ##__VA_ARGS__)
#endif /* !pr_crit */
#ifndef pr_err
#define pr_err(fmt, ...) mv_print (MV_DBG_L_ERR, "[ERROR] " fmt, ##__VA_ARGS__)
#endif /* !pr_err */
#ifndef pr_warn
#define pr_warn(fmt, ...) mv_print (MV_DBG_L_WARN, "[WARN] " fmt, ##__VA_ARGS__)
#endif /* !pr_warn */
#ifndef pr_debug
#ifdef DEBUG
#define pr_debug(fmt, ...) mv_print (MV_DBG_L_DBG, "[DBG] " fmt, ##__VA_ARGS__)
#else
#define pr_debug(...)
#endif /* DEBUG */
#endif /* !pr_debug */

#ifndef BUG
#define BUG abort
#endif /* !BUG */

#ifndef BUG_ON
#define BUG_ON(_cond)                                                                              \
  do                                                                                               \
    {                                                                                              \
      if (_cond)                                                                                   \
	{                                                                                          \
	  pr_crit ("[%s:%d] found BUG!\n", __FILE__, __LINE__);                                    \
	  BUG ();                                                                                  \
	}                                                                                          \
    }                                                                                              \
  while (0)
#endif /* !BUG_ON */

#define unlikely(x) __builtin_expect (!!(x), 0)

#define PP2_NUM_ETH_PPIO      3
#define PP2_NUM_PORTS	      4
#define PP2_NUM_REGSPACES     9
#define PP2_MAX_NUM_PACKPROCS 4
#define PP2_HW_PORT_NUM_RXQS  32
#define PP2_LOOPBACK_PORT     3
#define PP2_DEFAULT_REGSPACE  0
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
#define UIO_PP2_STRING			  "pp"
#define PP2_BPOOL_NUM_POOLS		  16
#define PP2_MAX_NUM_PUT_BUFFS		  8192
#define PP2_LPBK_PORT_TXQ_SIZE		  4096
#define PP2_LPBK_PORT_NUM_TXQ		  1
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

  p = clib_mem_alloc_or_null (bytes);
  if (p)
    memset (p, 0, bytes);

  return p;
}

#define dsb(opt)  ({ asm volatile ("dsb " #opt : : : "memory"); })
#define rmb()	  dsb (ld)
#define __iormb() rmb ()
#define wmb()	  dsb (st)
#define __iowmb() wmb ()

#define MVPP2_MEMSET_ZERO(STRUCT) memset (&(STRUCT), 0, sizeof ((STRUCT)))

#define GET_HW_BASE(pool) ((struct base_addr *) (pool)->internal_param)
#define SET_HW_BASE(pool, base)                                                                    \
  {                                                                                                \
    (pool)->internal_param = (base);                                                               \
  }

struct sys_iomem;
struct sys_iomem_params
{
  const char *devname;
  int index;
};

struct pp2_cls_db_t;
struct mv_pp2x_cls_c2_entry;
struct pp2_inst;
struct pp2_port;
struct netdev_featstrs;
struct pp2_cls_c3_entry;
struct pp2_cls_c3_hash_pair;
struct mv_pp2x_cls_c2_qos_entry;
struct mv_pp2x_prs_shadow;
struct mv_pp2x_cls_shadow;
struct mv_pp2x_c2_shadow;
struct ethtool_gstrings;

enum pp2_phy_interface
{
  PP2_PHY_INTERFACE_MODE_NA,
  PP2_PHY_INTERFACE_MODE_MII,
  PP2_PHY_INTERFACE_MODE_GMII,
  PP2_PHY_INTERFACE_MODE_SGMII,
  PP2_PHY_INTERFACE_MODE_TBI,
  PP2_PHY_INTERFACE_MODE_REVMII,
  PP2_PHY_INTERFACE_MODE_RMII,
  PP2_PHY_INTERFACE_MODE_RGMII,
  PP2_PHY_INTERFACE_MODE_RGMII_ID,
  PP2_PHY_INTERFACE_MODE_RGMII_RXID,
  PP2_PHY_INTERFACE_MODE_RGMII_TXID,
  PP2_PHY_INTERFACE_MODE_RTBI,
  PP2_PHY_INTERFACE_MODE_SMII,
  PP2_PHY_INTERFACE_MODE_XGMII,
  PP2_PHY_INTERFACE_MODE_MOCA,
  PP2_PHY_INTERFACE_MODE_QSGMII,
  PP2_PHY_INTERFACE_MODE_XAUI,
  PP2_PHY_INTERFACE_MODE_RXAUI,
  PP2_PHY_INTERFACE_MODE_KR,
  PP2_PHY_INTERFACE_MODE_MAX,
};

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

struct pp2_mac_data
{
  u8 gop_index;
  unsigned long flags;
  int phy_addr;
  enum pp2_phy_interface phy_mode;
  bool force_link;
  unsigned int autoneg;
  unsigned int link;
  unsigned int duplex;
  unsigned int speed;
  u8 mac[MV_ETH_ALEN];
};

struct pp2_mac_unit_desc
{
  struct base_addr base;
  unsigned int obj_size;
};

struct gop_hw
{
  struct pp2_mac_unit_desc gmac;
  struct pp2_mac_unit_desc xlg_mac;
  struct base_addr mspg;
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

struct list
{
  struct list *next;
  struct list *prev;
};

#define LIST_FIRST(_lst) (_lst)->next
#define LIST_LAST(_lst)	 (_lst)->prev
#define LIST_PREV	 LIST_LAST
#define LIST_NEXT	 LIST_FIRST
#define LIST_INIT(_lst)	 { &(_lst), &(_lst) }
#define INIT_LIST(_lst)	 LIST_FIRST (_lst) = LIST_LAST (_lst) = (_lst)

static inline int
list_is_empty (struct list *lst)
{
  return (LIST_FIRST (lst) == lst);
}

static inline void
list_del (struct list *ent)
{
  LIST_PREV (LIST_NEXT (ent)) = LIST_PREV (ent);
  LIST_NEXT (LIST_PREV (ent)) = LIST_NEXT (ent);
}

static inline void
list_add_to_tail (struct list *new_lst, struct list *head)
{
  LIST_NEXT (LIST_PREV (head)) = new_lst;
  LIST_PREV (new_lst) = LIST_PREV (head);
  LIST_NEXT (new_lst) = head;
  LIST_PREV (head) = new_lst;
}
#define PTR2INT(_p)		      ((uintptr_t) (_p))
#define MEMBER_OFFSET(_type, _member) (PTR2INT (&((_type *) 0)->_member))
#define LIST_OBJECT(_lst, _type, _member)                                                          \
  ((_type *) ((char *) (_lst) - MEMBER_OFFSET (_type, _member)))
#define LIST_FOR_EACH(_pos, _head)                                                                 \
  for (_pos = LIST_FIRST (_head); _pos != (_head); _pos = LIST_NEXT (_pos))

#define PP2_PPIO_DESC_NUM_FRAGS 16 /* TODO: check if there is HW limitation */
struct sys_iomem
{
  char *name;
  uint32_t owners;
  int index;
  struct mem_uio uio;
  struct list node;
};

static struct list iomem_maps_lst = LIST_INIT (iomem_maps_lst);
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

static inline int pp2_is_init (void);
static u8 pp2_get_num_inst (void);

static inline bool mv_check_eaddr_mc (const u8 *eaddr);
static inline int mv_check_eaddr_valid (const u8 *addr);
static inline void mv_cp_eaddr (u8 *dest, const u8 *source);
static int mv_pp2x_cls_c2_color_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int from);
static u8 pp2_cls_c2_tcam_port_get (struct mv_pp2x_cls_c2_entry *c2);
static int mv_pp2x_cls_c2_hw_write (uintptr_t cpu_slot, int index, struct mv_pp2x_cls_c2_entry *c2);
static int mv_pp2x_cls_c2_hw_read (uintptr_t cpu_slot, int index, struct mv_pp2x_cls_c2_entry *c2);
static void mv_pp2x_c2_sw_clear (struct mv_pp2x_cls_c2_entry *c2);

static int pp2_gop_gmac_link_status (struct gop_hw *gop, int mac_num,
				     struct pp2_port_link_status *pstatus);
static int pp2_gop_xlg_mac_link_status (struct gop_hw *gop, int mac_num,
					struct pp2_port_link_status *pstatus);
static int pp2_port_remove_vlan (struct pp2_port *port, u16 vlan);
static void pp2_port_mac_set_loopback (struct pp2_port *port, int en);

#define BM_TYPE_SHORT_BUF_POOL (0x00)
#define BM_TYPE_LONG_BUF_POOL  (0x01)

struct pp2_rx_queue
{
  u32 id;
  u32 log_id;
  u32 desc_total;
  uintptr_t desc_phys_arr;
  struct pp2_desc *desc_virt_arr;
  u32 bm_pool_id[PP2_PPIO_TC_CLUSTER_MAX_POOLS];
};

struct pp2_ppio_tc_config
{
  u16 pkt_offset;
  u8 num_in_qs;
  u8 first_rxq;
  struct pp2_bm_pool *pools[MV_SYS_DMA_MAX_NUM_MEM_ID][PP2_PPIO_TC_CLUSTER_MAX_POOLS];
  enum pp2_ppio_color default_color;
};

struct pp2_rxq
{
  u32 ring_size;
  u8 tc_pools_mem_id_index;
};

struct pp2_tc
{
  u32 first_log_rxq;
  struct pp2_rxq rx_qs[PP2_HW_PORT_NUM_RXQS];
  struct pp2_ppio_tc_config tc_config;
};

struct pp2_txq_config
{
  u16 size;
  enum pp2_ppio_outq_sched_mode sched_mode;
  u16 weight;
};

enum port_status
{
  PP2_PORT_DISABLED,
  PP2_PORT_KERNEL,
  PP2_PORT_LAST,
};

typedef enum
{
  PP2_TRAFFIC_NONE,
  PP2_TRAFFIC_INGRESS,
  PP2_TRAFFIC_EGRESS,
  PP2_TRAFFIC_INGRESS_EGRESS,
} pp2_traffic_mode;

struct pp2_port
{
  vnet_dev_port_t *dev_port;
  mvpp2_port_t *vpp_port;
  bool is_open;
  u32 flags;
  u32 num_rx_queues;
  u32 num_tx_queues;
  struct pp2_txq_config txq_config[PP2_PPIO_MAX_NUM_OUTQS];
  u32 num_tcs;
  u32 first_rxq;
  u32 use_mac_lb;
  u32 t_mode;
  struct pp2_inst *parent;
  uintptr_t cpu_slot;
  struct pp2_tx_queue **txqs;
  struct pp2_rx_queue **rxqs;
  struct pp2_tc tc[PP2_PPIO_MAX_NUM_TCS];
  enum pp2_ppio_hash_type hash_type;
  int rss_en;
  struct pp2_mac_data mac_data;
  char linux_name[16];
  u32 tx_fifo_size;
  struct list added_uc_addr;
  u32 num_added_uc_addr;
  u32 num_added_mc_addr;
  u32 rxq_flow_cntrl_mask;
  int tx_pause_en;
  int rx_pause_en;
  u32 num_vlans;
  uint64_t vlan_ids[64];
  u8 vlan_enable;
  u32 saved_rx_isr[PP2_MAX_NUM_USED_INTERRUPTS];
};

struct pp2_hw
{
  struct base_addr base[PP2_NUM_REGSPACES];
  struct gop_hw gop;
  struct base_addr cm3_base;
  u32 tclk;
  struct mv_pp2x_prs_shadow *prs_shadow;
  phys_addr_t phy_address_base;
};

struct pp2_inst
{
  u32 id;
  struct pp2_hw hw;
  u32 num_ports;
  struct pp2_port *ports[PP2_NUM_PORTS];
  struct pp2_bm_pool *bm_pools[PP2_BPOOL_NUM_POOLS];
  u32 num_dm_ifs;
  struct pp2_dm_if *dm_ifs[PP2_NUM_REGSPACES];
  struct pp2 *parent;
  struct sys_iomem *pp2_sys_iomem;
  struct pp2_cls_db_t *cls_db;
};

#define MV_DEFAULT_MTU	   1500
#define MV_MTU_TO_MRU(mtu) ((mtu) + MV_MH_SIZE + MV_VLAN_TAG_LEN + MV_ETH_HLEN + MV_ETH_FCS_LEN)

static u32
pp2_port_id (struct pp2_port *port)
{
  if (port->vpp_port)
    return port->vpp_port->id;

  for (u32 id = 0; id < PP2_NUM_PORTS; id++)
    if (port->parent->ports[id] == port)
      return id;

  ASSERT (0);
  return ~0;
}

static_always_inline uintptr_t
pp2_default_cpu_slot (struct pp2_inst *inst)
{
  return inst->hw.base[PP2_DEFAULT_REGSPACE].va;
}

static_always_inline u16
pp2_port_mru (struct pp2_port *port)
{
  return port->vpp_port ? port->vpp_port->port_mru : MV_MTU_TO_MRU (MV_DEFAULT_MTU);
}

static_always_inline u16
pp2_port_mtu (struct pp2_port *port)
{
  return port->vpp_port ? port->vpp_port->port_mtu : MV_DEFAULT_MTU;
}

struct pp2_common_cfg
{
  u16 hif_slot_map;
};

struct pp2
{
  struct pp2_init_params init;
  struct pp2_common_cfg pp2_common;
  u32 num_pp2_inst;
  struct pp2_inst *pp2_inst[PP2_MAX_NUM_PACKPROCS];
};

struct netdev_if_params
{
  char if_name[16];
  u32 admin_status;
  u8 ppio_id;
  u8 pp_id;
};

static struct pp2 *pp2_ptr;
static struct netdev_if_params netdev_params[PP2_MAX_NUM_PACKPROCS * 3];
static struct pp2_hif pp2_hif[PP2_NUM_REGSPACES];

static inline u32 fls_32 (u32 x);
static inline u32 fls_64 (u64 x);

static inline u32
__raw_mv_readl (const volatile void __iomem *addr)
{
  u32 val;

  asm volatile ("ldr %w0, [%1]" : "=r"(val) : "r"(addr));
  return val;
}

static inline void
__raw_mv_writel (u32 val, volatile void __iomem *addr)
{
  asm volatile ("str %w0, [%1]" : : "r"(val), "r"(addr));
}

#define mv_readl_relaxed(c)                                                                        \
  ({                                                                                               \
    u32 __r = le32toh (__raw_mv_readl (c));                                                        \
    __r;                                                                                           \
  })
#define readl(c)                                                                                   \
  ({                                                                                               \
    u32 __v = mv_readl_relaxed (c);                                                                \
    __iormb ();                                                                                    \
    __v;                                                                                           \
  })
#define mv_writel_relaxed(v, c) ((void) __raw_mv_writel (htole32 (v), (c)))
#define writel(v, c)                                                                               \
  ({                                                                                               \
    __iowmb ();                                                                                    \
    mv_writel_relaxed ((v), (c));                                                                  \
  })

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
pp2_reg_read (uintptr_t cpu_slot, uint32_t offset)
{
  uintptr_t addr = cpu_slot + offset;

  return readl ((void *) addr);
}

static int
pp2_cls_c3_cpu_done (uintptr_t cpu_slot)
{
  u32 reg_val;

  reg_val = pp2_reg_read (cpu_slot, MVPP2_CLS3_STATE_REG);
  reg_val &= MVPP2_CLS3_STATE_CPU_DONE_MASK;
  reg_val >>= MVPP2_CLS3_STATE_CPU_DONE;
  return reg_val;
}

static inline void
pp2_reg_write (uintptr_t cpu_slot, uint32_t offset, uint32_t data)
{
  uintptr_t addr = cpu_slot + offset;

  writel (data, (void *) addr);
}

static int
mv_pp2x_range_validate (int value, int min, int max)
{
  if (((value) > (max)) || ((value) < (min)))
    {
      pr_err ("%s: value 0x%X (%d) is out of range [0x%X , 0x%X].\n", __func__, (value), (value),
	      (min), (max));
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

struct port_uc_addr_node
{
  struct list list_node;
  u8 addr[ETH_ALEN];
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

static struct pp2_mac_data hc_gop_mac_data[12] = { {
						     .gop_index = 0,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 18,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 1 },
						   },
						   {
						     .gop_index = 2,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 7,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 2 },
						   },
						   {
						     .gop_index = 3,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 7,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 3 },
						   },
						   {
						     .gop_index = 0,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 18,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 4 },
						   },
						   {
						     .gop_index = 2,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 7,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 5 },
						   },
						   {
						     .gop_index = 3,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 7,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 6 },
						   },
						   {
						     .gop_index = 0,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 18,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 7 },
						   },
						   {
						     .gop_index = 2,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 7,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 8 },
						   },
						   {
						     .gop_index = 3,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 7,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 9 },
						   },
						   {
						     .gop_index = 0,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 18,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 0xa },
						   },
						   {
						     .gop_index = 2,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 7,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 0xb },
						   },
						   {
						     .gop_index = 3,
						     .flags = 0,
						     .phy_addr = 0,
						     .phy_mode = 7,
						     .force_link = 0,
						     .autoneg = 0,
						     .link = 0,
						     .duplex = 0,
						     .speed = 0,
						     .mac = { 0, 0, 0, 0, 0, 0xc },
						   }

};

static int mv_pp2x_ptr_validate (const void *ptr);

static struct pp2_cls_c3_shadow_hash_entry pp2_cls_c3_shadow_tbl[MVPP2_CLS_C3_HASH_TBL_SIZE];
static int pp2_cls_c3_shadow_ext_tbl[MVPP2_CLS_C3_EXT_TBL_SIZE];
static inline u32 cm3_read (uintptr_t base, u32 offset);
static inline bool mv_check_eaddr_uc (const u8 *addr);
static int mv_netdev_ioctl (u32 ctl, struct ifreq *s);
static int parse_hex (char *str, u8 *addr, size_t size);

static void mv_pp2x_prs_sram_bits_set (struct mv_pp2x_prs_entry *pe, int bit_num, int val);
static void mv_pp2x_prs_sram_bits_clear (struct mv_pp2x_prs_entry *pe, int bit_num, int val);

static inline void cm3_write (uintptr_t base, u32 offset, u32 data);
static void mv_pp2x_cls_oversize_rxq_set (struct pp2_port *port);
static void mv_pp2x_prs_clear_active_vlans (struct pp2_port *port, uint32_t *vlans);
static void mv_pp2x_prs_hw_inv (uintptr_t cpu_slot, int index);
static int mv_pp2x_prs_mac_da_accept (struct pp2_port *port, const u8 *da, bool add);
static void mv_pp2x_prs_shadow_set (struct pp2_inst *inst, int index, int lu);
static void mv_pp2x_prs_sram_next_lu_set (struct mv_pp2x_prs_entry *pe, unsigned int lu);
static void mv_pp2x_prs_tcam_data_byte_set (struct mv_pp2x_prs_entry *pe, unsigned int offs,
					    unsigned char byte, unsigned char enable);
static void mv_pp2x_prs_tcam_lu_set (struct mv_pp2x_prs_entry *pe, unsigned int lu);
static void mv_pp2x_prs_tcam_port_map_set (struct mv_pp2x_prs_entry *pe, unsigned int ports);
static int pp2_cls_c3_hit_cntrs_clear_all (uintptr_t cpu_slot);
static void pp2_cls_mng_config_default_cos_queue (struct pp2_port *port);
static void pp2_cls_mng_rss_port_init (struct pp2_port *port);
static int pp2_get_devtree_port_data (struct netdev_if_params *netdev_params);
static int pp2_netdev_if_info_get (struct netdev_if_params *netdev_params);
static int pp2_port_clear_kernel_unicast (struct pp2_port *port);
static int pp2_port_clear_vlan (struct pp2_port *port, u16 vlan);
static int pp2_port_config_txsched (struct pp2_port *port);
static void pp2_port_defaults_set (struct pp2_port *port);
static void pp2_port_deinit (struct pp2_port *port);
static void pp2_port_egress_disable (struct pp2_port *port);
static void pp2_port_egress_enable (struct pp2_port *port);
static void pp2_port_ingress_disable (struct pp2_port *port);
static void pp2_port_ingress_enable (struct pp2_port *port);
static void pp2_port_mac_max_rx_size_set (struct pp2_port *port);
static int pp2_port_remove_mac_addr (struct pp2_port *port, const uint8_t *addr);
static void pp2_port_rxqs_create (struct pp2_port *port);
static void pp2_port_rxqs_init (struct pp2_port *port);
static int pp2_port_set_outq_state (struct pp2_port *port, struct pp2_tx_queue *txq, int en);
static int pp2_port_set_vlan_filtering (struct pp2_port *port, int enable);
static void pp2_port_stop_dev (struct pp2_port *port);
static void pp2_port_txqs_create (struct pp2_port *port);
static int pp2_port_uc_mac_addr_list_remove (struct pp2_port *port, const uint8_t *addr);
static int pp2_prs_port_update (struct pp2_port *port, u32 add, u32 tid, u32 ri, u32 ri_mask);
static inline uint32_t pp2_relaxed_reg_read (uintptr_t cpu_slot, uint32_t offset);
static void pp2_txq_init (struct pp2_port *port, struct pp2_tx_queue *txq);

static int mv_netdev_feature_set (const char *netdev, const char *featstr, int val);
static int mvpp2x_prs_mac_da_range_find (struct pp2_inst *inst, uintptr_t cpu_slot, int pmap,
					 const u8 *da, const u8 *mask, int udf_type);
static void mv_pp2x_prs_shadow_ri_set (struct pp2_inst *inst, int index, unsigned int ri,
				       unsigned int ri_mask);
static void mv_pp2x_prs_sram_shift_set (struct mv_pp2x_prs_entry *pe, int shift, unsigned int op);
static unsigned int mv_pp2x_prs_tcam_port_map_get (struct mv_pp2x_prs_entry *pe);
static void mv_pp2x_prs_tcam_port_set (struct mv_pp2x_prs_entry *pe, unsigned int port, bool add);
static int pp2_c2_config_default_queue (struct pp2_port *port, u16 queue);
static int pp2_cls_mng_qos_tbl_dflt_set (struct pp2_port *port, u16 queue);
static int pp2_gop_gmac_max_rx_size_set (struct gop_hw *gop, int mac_num, int max_rx_size);
static int pp2_gop_xlg_mac_max_rx_size_set (struct gop_hw *gop, int mac_num, int max_rx_size);
static void pp2_port_clear_fc_isr (struct pp2_port *port);
static void pp2_port_egress_disable_qmask (struct pp2_port *port, uint32_t q_mask);
static void pp2_port_egress_enable_qmask (struct pp2_port *port, uint32_t q_mask);
static void pp2_port_interrupts_disable (struct pp2_port *port);
static void pp2_port_rxqs_deinit (struct pp2_port *port);
static void pp2_port_rxqs_destroy (struct pp2_port *port);
static void pp2_port_rxqs_fc_state_reset (struct pp2_port *port);
static void pp2_port_txqs_deinit (struct pp2_port *port);
static void pp2_port_txqs_destroy (struct pp2_port *port);
static void pp2_port_txsched_set_mtu (struct pp2_port *port);
static int pp2_rss_musdk_map_get (struct pp2_port *port);
static void pp2_rxq_init (struct pp2_port *port, struct pp2_rx_queue *rxq);
static uint32_t pp2_txq_pend_desc_num_get (struct pp2_port *port, struct pp2_tx_queue *txq);
static int pp2_txsched_queue_arbitration_set (struct pp2_port *port, u8 txq,
					      enum pp2_ppio_outq_sched_mode mode, u8 weight);
static void pp2_txsched_remap_weights (struct pp2_port *port, u8 remapped_weights[]);

static void mv_netdev_clean_featstrs (struct netdev_featstrs *fs);
static int mv_netdev_set_feature_ioctl (int fd, struct ifreq *ifr, int bit, int val);
static int mv_pp2x_cls_c2_qos_tbl_fill_array (struct pp2_port *port, u8 tbl_sel,
					      uint8_t tc_values[]);
static int pp2_c2_config_queue (struct mv_pp2x_cls_c2_entry *c2, u16 queue, int from);
static u8 pp2_cls_c2_tcam_lkp_type_get (struct mv_pp2x_cls_c2_entry *c2);
static int pp2_cls_db_rss_get_hw_tbl_from_in_q (struct pp2_inst *inst, u8 num_in_q);
static u16 pp2_cls_db_rss_kernel_rsvd_tbl_get (struct pp2_inst *inst);
static u16 pp2_cls_db_rss_num_musdk_tbl_get (struct pp2_inst *inst);
static void pp2_cls_db_rss_num_musdk_tbl_set (struct pp2_inst *inst, u16 num_musdk_tbl);
static int pp2_cls_db_rss_tbl_map_get_next_free_idx (struct pp2_inst *inst);
static int pp2_cls_db_rss_tbl_map_set (struct pp2_inst *inst, u16 idx, u16 hw_tbl, u16 num_in_q);
static inline uint32_t pp2_gop_gmac_read (struct gop_hw *gop, int mac_num, uint32_t offset);
static inline void pp2_gop_gmac_write (struct gop_hw *gop, int mac_num, u32 offset, uint32_t data);
static inline uint32_t pp2_gop_xlg_mac_read (struct gop_hw *gop, int mac_num, uint32_t offset);
static inline void pp2_gop_xlg_mac_write (struct gop_hw *gop, int mac_num, u32 offset,
					  uint32_t data);
static inline u16 pp2_hif_map_get (void);
static inline u32 pp2_port_isr_rx_group_read (struct pp2_port *port, int sub_group);
static inline void pp2_port_isr_rx_group_write (struct pp2_port *port, int sub_group,
						int start_queue, int num_rx_queues);
static void pp2_port_restore_fc_isr (struct pp2_port *port);
static void pp2_rxq_deinit (struct pp2_port *port, struct pp2_rx_queue *rxq);
static void pp2_rxq_offset_set (struct pp2_port *port, int prxq, int offset);
static void pp2_txq_deinit (struct pp2_port *port, struct pp2_tx_queue *txq);
static int pp2_txsched_queue_fixed_prio_set (struct pp2_port *port, u8 txq);
static int pp2_txsched_queue_wrr_set (struct pp2_port *port, u8 txq, u8 weight);
static u8 pp2_txsched_rational_weight_remap (u32 weight, u32 min, u32 max);
static struct pp2_tc *pp2_rxq_tc_get (struct pp2_port *port, uint32_t id);
static int mv_netdev_get_featstrs (int fd, struct ifreq *ifr, struct netdev_featstrs *fs);
static int pp2_rss_enable (struct pp2_port *port, int en);
static int pp2_rss_hw_tbl_set (struct pp2_port *port);
static int pp22_cls_rss_rxq_set (struct pp2_port *port);

static int pp2_gop_gmac_loopback_cfg (struct gop_hw *gop, int mac_num, enum pp2_lb_type type);
static int pp2_gop_xlg_mac_loopback_cfg (struct gop_hw *gop, int mac_num, enum pp2_lb_type type);
static int mv_pp2x_cls_c2_qos_color_set (struct mv_pp2x_cls_c2_qos_entry *qos, int color);
static int mv_pp2x_cls_c2_qos_hw_write (struct pp2_hw *hw, struct mv_pp2x_cls_c2_qos_entry *qos);
static int mv_pp2x_cls_c2_qos_queue_set (struct mv_pp2x_cls_c2_qos_entry *qos, uint8_t queue);
static int mv_pp2x_cls_c2_queue_high_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue,
					  int from);
static int mv_pp2x_cls_c2_queue_low_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue,
					 int from);
static int mv_pp2x_cls_c2_rss_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int rss_en);
static inline uint32_t pp2_gop_gen_read (uintptr_t base, uint32_t offset);
static inline void pp2_gop_gen_write (uintptr_t base, uint32_t offset, uint32_t data);
static void pp2_rxq_resid_pkts (struct pp2_port *port, struct pp2_rx_queue *rxq);

static int
mv_netdev_get_featstrs (int fd, struct ifreq *ifr, struct netdev_featstrs *fs)
{
  struct
  {
    struct ethtool_sset_info hdr;
    uint32_t buf[1];
  } sset_cmd = { 0 };
  struct
  {
    struct ethtool_gstrings gs;
    char data[0];
  } *gstrs;
  int32_t len;
  char *s;
  int i, ret;

  sset_cmd.hdr.cmd = ETHTOOL_GSSET_INFO;
  sset_cmd.hdr.sset_mask = 1 << ETH_SS_FEATURES;

  ifr->ifr_data = &sset_cmd;
  ret = ioctl (fd, SIOCETHTOOL, ifr);
  if (ret)
    {
      pr_err ("Could not get feature count (%s)\n", strerror (errno));
      return -1;
    }

  memcpy (&len, sset_cmd.hdr.data, sizeof (int32_t));
  if (len < 0 || len > FEATSTRS_MAX)
    {
      pr_err ("invalid feature count %d\n", len);
      return -1;
    }

  gstrs = mem_calloc (1, sizeof (struct ethtool_gstrings) + len * ETH_GSTRING_LEN);
  gstrs->gs.cmd = ETHTOOL_GSTRINGS;
  gstrs->gs.string_set = ETH_SS_FEATURES;
  gstrs->gs.len = len;

  ifr->ifr_data = gstrs;
  ret = ioctl (fd, SIOCETHTOOL, ifr);
  if (ret)
    {
      pr_err ("Could not get feature strings (%s)\n", strerror (errno));
      clib_mem_free (gstrs);
      return -1;
    }

  s = gstrs->data;
  for (i = 0; i < len; i++)
    {
      s[ETH_GSTRING_LEN - 1] = '\0';

      fs->s[i] = clib_mem_alloc_or_null (strlen (s) + 1);
      if (fs->s[i] == NULL)
	{
	  pr_err ("Failed to allocate feature strings\n");
	  mv_netdev_clean_featstrs (fs);
	  clib_mem_free (gstrs);
	  return -1;
	}
      strcpy (fs->s[i], s);

      s += ETH_GSTRING_LEN;
    }
  clib_mem_free (gstrs);

  return 0;
}

int
mv_pp22_rss_tbl_entry_set (struct pp2_hw *hw, struct mv_pp22_rss_entry *rss)
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
      pp2_reg_write (hw->base[0].va, MVPP22_RSS_IDX_REG, reg_val);
      pr_debug ("rss queue %d, reg_val %x", rss->u.pointer.rxq_idx, reg_val);
      /* Write entry */
      reg_val = 0;
      reg_val &= (~MVPP22_RSS_RXQ2RSS_TBL_POINT_MASK);
      reg_val |= rss->u.pointer.rss_tbl_ptr << MVPP22_RSS_RXQ2RSS_TBL_POINT_OFF;
      pp2_reg_write (hw->base[0].va, MVPP22_RSS_RXQ2RSS_TBL_REG, reg_val);
      pr_debug (", table %d, reg_val %x\n", rss->u.pointer.rss_tbl_ptr, reg_val);
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
      pp2_reg_write (hw->base[0].va, MVPP22_RSS_IDX_REG, reg_val);
      /* Write entry */
      reg_val &= (~MVPP22_RSS_TBL_ENTRY_MASK);
      reg_val |= (rss->u.entry.rxq << MVPP22_RSS_TBL_ENTRY_OFF);
      pp2_reg_write (hw->base[0].va, MVPP22_RSS_TBL_ENTRY_REG, reg_val);
      reg_val &= (~MVPP22_RSS_WIDTH_MASK);
      reg_val |= (rss->u.entry.width << MVPP22_RSS_WIDTH_OFF);
      pp2_reg_write (hw->base[0].va, MVPP22_RSS_WIDTH_REG, reg_val);
    }
  return 0;
}
int
pp2_rss_c2_enable (struct pp2_port *port, int en)
{
  int index;
  int c2_status;
  int rc;
  u8 port_id;
  struct mv_pp2x_cls_c2_entry c2;
  struct pp2_hw *hw = &port->parent->hw;

  c2_status = pp2_reg_read (hw->base[0].va, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      pr_err ("c2 is off\n");
      return -EINVAL;
    }

  mv_pp2x_c2_sw_clear (&c2);

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mv_pp2x_cls_c2_hw_read (hw->base[0].va, index, &c2);
      port_id = pp2_cls_c2_tcam_port_get (&c2);

      if (c2.inv == 0 && port_id == (1 << pp2_port_id (port)))
	{
	  /* Set RSS */
	  rc = mv_pp2x_cls_c2_rss_set (&c2, MVPP2_ACTION_TYPE_UPDT_LOCK, en);
	  if (rc)
	    return rc;
	  mv_pp2x_cls_c2_hw_write (hw->base[0].va, index, &c2);

	  mv_pp2x_c2_sw_clear (&c2);
	  mv_pp2x_cls_c2_hw_read (hw->base[0].va, index, &c2);
	}
    }
  return 0;
}

static int
pp2_rss_hw_tbl_set (struct pp2_port *port)
{
  struct mv_pp22_rss_entry rss_entry;
  int i;
  int entry_idx;
  u16 width;
  struct pp2_inst *inst = port->parent;
  int hw_tbl;

  memset (&rss_entry, 0, sizeof (struct mv_pp22_rss_entry));
  rss_entry.sel = MVPP22_RSS_ACCESS_TBL;

  for (i = 0; i < port->num_tcs; i++)
    {
      if (port->tc[i].tc_config.num_in_qs == 1)
	continue;

      hw_tbl = pp2_cls_db_rss_get_hw_tbl_from_in_q (inst, port->tc[i].tc_config.num_in_qs);
      if (hw_tbl < 0)
	{
	  pr_err ("%s RSS table index not found\n", __func__);
	  return -EFAULT;
	}
      rss_entry.u.entry.tbl_id = hw_tbl;

      width = mvlog2 (roundup_pow_of_two (port->tc[i].tc_config.num_in_qs));
      pr_debug ("setting rss table %d, width %d\n", rss_entry.u.entry.tbl_id, width);
      rss_entry.u.entry.width = width;

      for (entry_idx = 0; entry_idx < MVPP22_RSS_TBL_LINE_NUM; entry_idx++)
	{
	  rss_entry.u.entry.tbl_line = entry_idx;
	  rss_entry.u.entry.rxq = entry_idx % port->tc[i].tc_config.num_in_qs;
	  if (mv_pp22_rss_tbl_entry_set (&port->parent->hw, &rss_entry))
	    return -1;
	}
    }
  return 0;
}

/* The function allocate a rss table for each phisical rxq,
 * they have same cos priority
 */
static int
pp22_cls_rss_rxq_set (struct pp2_port *port)
{
  int i, j;
  struct mv_pp22_rss_entry rss_entry;
  struct pp2_inst *inst = port->parent;
  int hw_tbl;

  memset (&rss_entry, 0, sizeof (struct mv_pp22_rss_entry));
  rss_entry.sel = MVPP22_RSS_ACCESS_POINTER;

  for (i = 0; i < port->num_tcs; i++)
    {
      if (port->tc[i].tc_config.num_in_qs == 1)
	continue;

      /* Set the table index to be used according to rss_map */
      hw_tbl = pp2_cls_db_rss_get_hw_tbl_from_in_q (inst, port->tc[i].tc_config.num_in_qs);
      if (hw_tbl < 0)
	{
	  pr_err ("%s RSS table index not found %d. Check mvpp2x_sysfs.ko module is loaded\n",
		  __func__, port->tc[i].tc_config.num_in_qs);
	  return -EFAULT;
	}
      rss_entry.u.pointer.rss_tbl_ptr = hw_tbl;

      for (j = 0; j < port->tc[i].tc_config.num_in_qs; j++)
	{
	  rss_entry.u.pointer.rxq_idx = port->tc[i].tc_config.first_rxq + j;
	  pr_debug ("%d rxq_idx %d rss_tbl %d\n", j, rss_entry.u.pointer.rxq_idx,
		    rss_entry.u.pointer.rss_tbl_ptr);
	  if (mv_pp22_rss_tbl_entry_set (&port->parent->hw, &rss_entry))
	    return -EFAULT;
	}
    }
  return 0;
}

static int
pp2_rss_enable (struct pp2_port *port, int en)
{
  int rc;

  rc = pp2_rss_c2_enable (port, en);
  if (rc)
    return -EINVAL;

  return 0;
}

static int pp2_c2_set_default_coloring (struct pp2_port *port, int clear);
static int pp2_gop_port_link_status (struct gop_hw *gop, struct pp2_mac_data *mac,
				     struct pp2_port_link_status *pstatus);
static int pp2_port_check_mtu_valid (struct pp2_port *port, uint32_t mtu);
static int pp2_port_clear_all_vlans (struct pp2_port *port);
static inline uint32_t pp2_port_get_tx_fifo (struct pp2_port *port);
static int pp2_port_set_loopback (struct pp2_port *port, int en);
static u32 pp2_prs_eth_start_hdr_get (struct pp2_port *port);
static int pp2_prs_eth_start_hdr_set (struct pp2_port *port,
				      enum pp2_ppio_eth_start_hdr eth_start_hdr);
static int pp2_prs_tcam_first_free (struct pp2_inst *inst, unsigned char start, unsigned char end);
static int mv_pp2x_prs_hw_read (uintptr_t cpu_slot, struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_hw_write (uintptr_t cpu_slot, struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_sram_ri_get (struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_sram_ri_mask_get (struct mv_pp2x_prs_entry *pe);
static void mv_pp2x_prs_sram_ri_update (struct mv_pp2x_prs_entry *pe, unsigned int bits,
					unsigned int mask);
static int mv_pp2x_prs_tcam_invalid_get (struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_tcam_lu_get (struct mv_pp2x_prs_entry *pe);

static inline u32
cm3_read (uintptr_t base, u32 offset)
{

  uintptr_t addr = base + offset;

  return readl ((void *) addr);
}

static inline bool
mv_check_eaddr_uc (const u8 *addr)
{
  return !mv_check_eaddr_mc (addr);
}

static int
mv_netdev_ioctl (u32 ctl, struct ifreq *s)
{
  int rc;
  int fd;

  fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd == -1)
    {
      pr_err ("can't open socket: errno %d", errno);
      return -EFAULT;
    }

  rc = ioctl (fd, ctl, (char *) s);
  if (rc == -1)
    {
      pr_err ("ioctl request failed: errno %d\n", errno);
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
pp2_c2_set_default_coloring (struct pp2_port *port, int clear)
{
  int index;
  int c2_status;
  int rc;
  u8 port_id;
  struct mv_pp2x_cls_c2_entry c2;
  struct pp2_hw *hw = &port->parent->hw;
  enum mv_pp2x_color_action_type color_action = 0;

  c2_status = pp2_reg_read (hw->base[0].va, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      pr_err ("c2 is off\n");
      return -EINVAL;
    }

  if (clear)
    color_action = MVPP2_COLOR_ACTION_TYPE_GREEN;
  else
    {
      switch (port->tc[0].tc_config.default_color)
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
      mv_pp2x_cls_c2_hw_read (hw->base[0].va, index, &c2);
      port_id = pp2_cls_c2_tcam_port_get (&c2);

      if (c2.inv == 0 && port_id == (1 << pp2_port_id (port)))
	{
	  rc = mv_pp2x_cls_c2_color_set (&c2, color_action, MVPP2_QOS_SRC_ACTION_TBL);
	  if (rc)
	    return rc;

	  mv_pp2x_cls_c2_hw_write (hw->base[0].va, index, &c2);
	}
    }

  return 0;
}

static int
pp2_gop_port_link_status (struct gop_hw *gop, struct pp2_mac_data *mac,
			  struct pp2_port_link_status *pstatus)
{
  int port_num = mac->gop_index;

  switch (mac->phy_mode)
    {
    case PP2_PHY_INTERFACE_MODE_RGMII:
    case PP2_PHY_INTERFACE_MODE_SGMII:
    case PP2_PHY_INTERFACE_MODE_QSGMII:
      pp2_gop_gmac_link_status (gop, port_num, pstatus);
      break;
    case PP2_PHY_INTERFACE_MODE_XAUI:
    case PP2_PHY_INTERFACE_MODE_RXAUI:
    case PP2_PHY_INTERFACE_MODE_KR:
      pp2_gop_xlg_mac_link_status (gop, port_num, pstatus);
      break;
    default:
      pr_err ("%s: Wrong port mode (%d)", __func__, mac->phy_mode);
      return -1;
    }

  /* update phy interface */
  pstatus->phy_mode = mac->phy_mode;

  return 0;
}

static int
pp2_port_check_mtu_valid (struct pp2_port *port, uint32_t mtu)
{
  u32 tx_fifo_threshold;

  /* Validate MTU */
  if (mtu < PP2_PORT_MIN_MTU)
    {
      pr_err ("PORT: cannot change MTU to less than %u bytes\n", PP2_PORT_MIN_MTU);
      return -EINVAL;
    }

  /* checksum offlaod is not relevant for loopback port,
   * so skipping the check
   */
  if (LPBK_PORT (port))
    return 0;

  /* Check MTU can be l4_checksummed */
  tx_fifo_threshold = PP2_PORT_TX_FIFO_KB_TO_THRESH (port->tx_fifo_size);
  if (MVPP2_MTU_PKT_SIZE (mtu) > tx_fifo_threshold)
    {
      port->flags &= ~PP2_PORT_FLAGS_L4_CHKSUM;
      pr_debug ("PORT: mtu=%u, mtu_pkt_size=%u, tx_fifo_thresh=%u, port discontinues "
		"hw_l4_checksum support\n",
		mtu, MVPP2_MTU_PKT_SIZE (mtu), tx_fifo_threshold);
    }
  else
    {
      port->flags |= PP2_PORT_FLAGS_L4_CHKSUM;
    }

  /* Buffer_pool sizes are not relevant for mtu, only mru. */

  return 0;
}

static int
pp2_port_clear_all_vlans (struct pp2_port *port)
{
  int vidx, vbit, rc;
  uint16_t vlan_id;

  for (vlan_id = 0; vlan_id < 4095; vlan_id++)
    {
      vidx = vlan_id / 64;
      vbit = vlan_id % 64;

      /* Each bit corresponds to a VLAN id */
      if (port->vlan_ids[vidx] & (UINT64_C (1) << vbit))
	{
	  rc = pp2_port_remove_vlan (port, vlan_id);
	  if (rc)
	    return rc;
	}
    }

  return 0;
}

static inline uint32_t
pp2_port_get_tx_fifo (struct pp2_port *port)
{
  return (MVPP22_TX_FIFO_SIZE_MASK &
	  pp2_reg_read (port->cpu_slot, MVPP22_TX_FIFO_SIZE_REG (pp2_port_id (port))));
}

static int
pp2_port_set_loopback (struct pp2_port *port, int en)
{
  pp2_port_mac_set_loopback (port, en);

  if (en)
    port->flags |= PP2_PORT_FLAGS_LOOPBACK;
  else
    port->flags &= ~PP2_PORT_FLAGS_LOOPBACK;

  return 0;
}

static u32
pp2_prs_eth_start_hdr_get (struct pp2_port *port)
{
  u32 reg_val;
  struct pp2_inst *inst = port->parent;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);
  u32 ret = 0;

  reg_val = pp2_reg_read (cpu_slot, MVPP2_MH_REG (pp2_port_id (port)));
  if (reg_val & MVPP2_DSA_NON_EXTENDED)
    ret = MVPP2_TAG_TYPE_DSA;
  else if (reg_val & MVPP2_DSA_EXTENDED)
    ret = MVPP2_TAG_TYPE_EDSA;
  else
    ret = MVPP2_TAG_TYPE_NONE;

  return ret;
}

static int
pp2_prs_eth_start_hdr_set (struct pp2_port *port, enum pp2_ppio_eth_start_hdr eth_start_hdr)
{
  u32 reg_val;
  struct pp2_inst *inst = port->parent;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  reg_val = pp2_reg_read (cpu_slot, MVPP2_MH_REG (pp2_port_id (port)));
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
      pr_err ("invalid eth_start_hdr, eth_start_hdr = %d\n", eth_start_hdr);
      return -EINVAL;
    }

  /* Write to register */
  pp2_reg_write (cpu_slot, MVPP2_MH_REG (pp2_port_id (port)), reg_val);

  return 0;
}

static int
pp2_prs_tcam_first_free (struct pp2_inst *inst, unsigned char start, unsigned char end)
{
  int tid;

  if (start > end)
    swap (start, end);

  if (end >= MVPP2_PRS_TCAM_SRAM_SIZE)
    end = MVPP2_PRS_TCAM_SRAM_SIZE - 1;

  for (tid = start; tid <= end; tid++)
    {
      if (!inst->cls_db->prs_db.prs_shadow[tid].valid)
	return tid;
    }
  pr_err ("Out of TCAM Entries !!\n");
  return -EINVAL;
}

static int
mv_pp2x_prs_hw_read (uintptr_t cpu_slot, struct mv_pp2x_prs_entry *pe)
{
  int i;

  if (pe->index > MVPP2_PRS_TCAM_SRAM_SIZE - 1)
    return -EINVAL;

  /* Write tcam index - indirect access */
  pp2_reg_write (cpu_slot, MVPP2_PRS_TCAM_IDX_REG, pe->index);

  pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] =
    pp2_reg_read (cpu_slot, MVPP2_PRS_TCAM_DATA_REG (MVPP2_PRS_TCAM_INV_WORD));
  if (pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] & MVPP2_PRS_TCAM_INV_MASK)
    return MVPP2_PRS_TCAM_ENTRY_INVALID;

  for (i = 0; i < MVPP2_PRS_TCAM_WORDS; i++)
    pe->tcam.word[i] = pp2_reg_read (cpu_slot, MVPP2_PRS_TCAM_DATA_REG (i));

  /* Write sram index - indirect access */
  pp2_reg_write (cpu_slot, MVPP2_PRS_SRAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_SRAM_WORDS; i++)
    pe->sram.word[i] = pp2_reg_read (cpu_slot, MVPP2_PRS_SRAM_DATA_REG (i));

  return 0;
}

static int
mv_pp2x_prs_hw_write (uintptr_t cpu_slot, struct mv_pp2x_prs_entry *pe)
{
  int i;

  if (pe->index > MVPP2_PRS_TCAM_SRAM_SIZE - 1)
    return -EINVAL;

  /* Clear entry invalidation bit */
  pe->tcam.word[MVPP2_PRS_TCAM_INV_WORD] &= ~MVPP2_PRS_TCAM_INV_MASK;

  /* Write sram index - indirect access */
  pp2_reg_write (cpu_slot, MVPP2_PRS_SRAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_SRAM_WORDS; i++)
    pp2_reg_write (cpu_slot, MVPP2_PRS_SRAM_DATA_REG (i), pe->sram.word[i]);

  /* Write tcam index - indirect access */
  pp2_reg_write (cpu_slot, MVPP2_PRS_TCAM_IDX_REG, pe->index);
  for (i = 0; i < MVPP2_PRS_TCAM_WORDS; i++)
    pp2_reg_write (cpu_slot, MVPP2_PRS_TCAM_DATA_REG (i), pe->tcam.word[i]);

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
mv_pp2x_prs_shadow_update (struct pp2_inst *inst)
{
  static int i, j, invalid, mac_range_start = -1, mac_range_end = -1;
  struct mv_pp2x_prs_entry pe;
  struct mv_pp2x_prs_shadow *prs_shadow;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  if (!inst->cls_db->prs_db.prs_shadow)
    {
      inst->cls_db->prs_db.prs_shadow =
	mem_calloc (MVPP2_PRS_TCAM_SRAM_SIZE, sizeof (struct mv_pp2x_prs_shadow));
      if (!inst->cls_db->prs_db.prs_shadow)
	return -ENOMEM;
    }

  prs_shadow = inst->cls_db->prs_db.prs_shadow;

  for (i = 0; i < MVPP2_PRS_TCAM_SRAM_SIZE; i++)
    {
      pe.index = i;
      mv_pp2x_prs_hw_read (cpu_slot, &pe);
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
  pr_debug ("%s: mac_start:%u, mac_end:%u\n", __func__, prs_shadow->prs_mac_range_start,
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
pp2_cls_db_rss_init (struct pp2_inst *inst)
{
  if (!inst->cls_db)
    return -EINVAL;

  /* Clear RSS db */
  memset (&inst->cls_db->rss_db, 0, sizeof (struct pp2_cls_db_rss_t));

  return 0;
}

static void
pp2_cls_db_rss_kernel_rsvd_tbl_set (struct pp2_inst *inst, u16 kernel_rss_tbl)
{
  inst->cls_db->rss_db.num_kernel_rsrvd_tbls = kernel_rss_tbl;
}

static int
pp2_cls_mng_set_coloring (struct pp2_port *port, int clear)
{
  int rc;

  rc = pp2_c2_set_default_coloring (port, clear);
  if (rc)
    {
      pr_err ("%s(%d) pp2_c2_set_default_coloring fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  return 0;
}

static void
pp2_dm_aggr_queue_config (struct pp2_dm_if *dm_if, uintptr_t addr, u32 size)
{
  pp2_reg_write (dm_if->cpu_slot, MVPP2_AGGR_TXQ_INIT (dm_if->id), 0x01);
  pp2_reg_write (dm_if->cpu_slot, MVPP2_AGGR_TXQ_DESC_ADDR_REG (dm_if->id),
		 addr >> MVPP22_DESC_ADDR_SHIFT);
  pp2_reg_write (dm_if->cpu_slot, MVPP2_AGGR_TXQ_DESC_SIZE_REG (dm_if->id), size);
}

static int
pp2_prs_eth_start_header_set (struct pp2_port *port, enum pp2_ppio_eth_start_hdr mode)
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
mv_pp2x_cls_c2_hw_inv (uintptr_t cpu_slot, int index)
{
  if (!cpu_slot || index >= MVPP2_CLS_C2_TCAM_SIZE)
    return -EINVAL;

  /* write index reg */
  pp2_reg_write (cpu_slot, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* set invalid bit */
  pp2_reg_write (cpu_slot, MVPP2_CLS2_TCAM_INV_REG, (1 << MVPP2_CLS2_TCAM_INV_INVALID_OFF));

  /* trigger */
  pp2_reg_write (cpu_slot, MVPP2_CLS2_TCAM_DATA_REG (4), 0);

  return 0;
}

static int
populate_tc_pools (struct pp2_inst *pp2_inst,
		   struct pp2_bpool *param_pools[][PP2_PPIO_TC_CLUSTER_MAX_POOLS],
		   struct pp2_bm_pool *pools[][PP2_PPIO_TC_CLUSTER_MAX_POOLS])
{
  u8 index = 0, j, k;
  bool param_pool_exist;
  struct pp2_bm_pool *temp_pool;

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
	      if (param_pools[j][k]->pp2_id != pp2_inst->id)
		{
		  pr_err ("%s: pool_ppid[%d] does not match pp2_id[%d]\n", __func__,
			  param_pools[j][k]->pp2_id, pp2_inst->id);
		  return -1;
		}
	      pools[j][index] = pp2_inst->bm_pools[param_pools[j][k]->id];
	      if (!pools[j][index])
		{
		  pr_err ("%s: pool_id[%d] has no matching struct\n", __func__,
			  param_pools[j][k]->id);
		  return -1;
		}
	      index++;
	    }
	}
      /* Set pool with smallest buf_size first */
      if (index == 2)
	{
	  if (pools[j][0]->bm_pool_buf_sz > pools[j][1]->bm_pool_buf_sz)
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
	  pr_err ("%s: pool_params do not exist\n", __func__);
	  return -1;
	}
    }
  return 0;
}

static int
pp2_cls_c3_init (uintptr_t cpu_slot)
{
  int rc;

  pp2_cls_c3_shadow_init ();
  rc = pp2_cls_c3_hit_cntrs_clear_all (cpu_slot);
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
pp2_cls_mng_eth_start_header_params_set (struct pp2_port *port,
					 enum pp2_ppio_eth_start_hdr eth_start_hdr)
{
  int rc;

  rc = pp2_prs_eth_start_header_set (port, eth_start_hdr);
  if (rc)
    {
      pr_err ("%s(%d) pp2_prs_eth_start_header_set fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  return 0;
}

static int
pp2_cls_mng_modify_default_flows (struct pp2_port *port, int clear)
{
  int rc;

  rc = pp2_cls_mng_set_coloring (port, clear);
  if (rc)
    {
      pr_err ("%s(%d) pp2_cls_mng_set_coloring fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  return 0;
}

static int
pp2_cls_prs_init (struct pp2_inst *inst)
{
  int rc;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);
  u32 val;

  /* Check if tcam table enabled*/
  val = pp2_reg_read (cpu_slot, MVPP2_PRS_TCAM_CTRL_REG);
  if (val != MVPP2_PRS_TCAM_EN_MASK)
    {
      pr_err ("Can't initialize logical port: parser not initialized yet\n");
      return -EFAULT;
    }

  /* Update MUSDK parser shadow table from kernel configuration */
  rc = mv_pp2x_prs_shadow_update (inst);
  if (rc)
    return -EFAULT;

  return 0;
}

static int
pp2_cls_rss_init (struct pp2_inst *inst)
{
  int rc;

  rc = pp2_cls_db_rss_init (inst);
  if (rc)
    return rc;

  pp2_cls_db_rss_kernel_rsvd_tbl_set (inst, 0);

  return 0;
}

static void
pp2_dm_if_deinit (vlib_main_t *vm, struct pp2 *pp2, uint32_t dm_id, uint32_t pp2_id)
{
  struct pp2_dm_if *dm_if;
  struct pp2_inst *inst;

  inst = pp2->pp2_inst[pp2_id];
  dm_if = inst->dm_ifs[dm_id];

  if (!dm_if)
    return;

  /* Reset the aggregation queue under this DM object */
  pp2_dm_aggr_queue_config (dm_if, 0, 0);
  pr_debug ("DM: (AQ%u)(PP%u) destroyed\n", dm_if->id, inst->id);
  vlib_physmem_free (vm, dm_if->desc_virt_arr);
  if (dm_if)
    clib_mem_free (dm_if);
  inst->num_dm_ifs--;
  inst->dm_ifs[dm_id] = NULL;
}

struct pp2_dm_if *
pp2_dm_if_get (struct pp2_port *port, struct pp2_hif *hif)
{
  return port->parent->dm_ifs[hif->regspace_slot];
}

struct pp2_tx_queue *
pp2_port_txq_get (struct pp2_port *port, uint8_t out_qid)
{
  return port->txqs[out_qid];
}

int
musdk_is_init (void)
{
  return pp2_is_init ();
}

u32
musdk_num_instances (void)
{
  return pp2_ptr->num_pp2_inst;
}

u16
musdk_reserved_pool_map (void)
{
  return pp2_ptr->init.bm_pool_reserved_map;
}

uintptr_t
musdk_cpu_slot (u32 pp2_id, u32 regspace)
{
  return pp2_ptr->pp2_inst[pp2_id]->hw.base[regspace].va;
}

uintptr_t
musdk_cm3_base (u32 pp2_id)
{
  return pp2_ptr->pp2_inst[pp2_id]->hw.cm3_base.va;
}

struct base_addr *
musdk_regspaces (u32 pp2_id)
{
  return pp2_ptr->pp2_inst[pp2_id]->hw.base;
}

struct pp2_bm_pool *
musdk_pool_slot_get (u32 pp2_id, u32 pool_id)
{
  return pp2_ptr->pp2_inst[pp2_id]->bm_pools[pool_id];
}

void
musdk_pool_slot_set (u32 pp2_id, u32 pool_id, struct pp2_bm_pool *pool)
{
  pp2_ptr->pp2_inst[pp2_id]->bm_pools[pool_id] = pool;
}

void
musdk_release_descs (u32 pp2_id, u16 num_buffs, u32 dm_if_index, struct pp2_ppio_desc descs[])
{
  struct pp2_port *port = pp2_ptr->pp2_inst[pp2_id]->ports[PP2_LOOPBACK_PORT];
  u16 sent = 0;

  do
    sent += pp2_port_enqueue (port, port->parent->dm_ifs[dm_if_index], 0, num_buffs - sent,
			      descs + sent, 0);
  while (sent != num_buffs);
}

uintptr_t
musdk_port_cpu_slot (struct pp2_port *port)
{
  return port->cpu_slot;
}

u32
musdk_port_pp2_id (struct pp2_port *port)
{
  return port->parent->id;
}

u32
musdk_port_id (struct pp2_port *port)
{
  return pp2_port_id (port);
}

int
musdk_port_fd (struct pp2_port *port)
{
  return port->vpp_port->uio_port_fd;
}

void
musdk_port_fd_set (struct pp2_port *port, int fd)
{
  port->vpp_port->uio_port_fd = fd;
}

static int
pp2_dm_if_init (vlib_main_t *vm, struct pp2 *pp2, uint32_t dm_id, uint32_t pp2_id, u32 num_desc)
{
  struct pp2_inst *inst;
  struct pp2_dm_if *dm_if;

  /* Identify parent packet processor instance */
  inst = pp2->pp2_inst[pp2_id];

  dm_if = mem_calloc (1, sizeof (struct pp2_dm_if));
  if (unlikely (!dm_if))
    {
      pr_err ("DM: cannot allocate DM object\n");
      return -ENOMEM;
    }
  dm_if->id = dm_id;
  dm_if->desc_total = num_desc;

  dm_if->desc_virt_arr =
    vlib_physmem_alloc_aligned (vm, num_desc * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN);
  if (unlikely (!dm_if->desc_virt_arr))
    {
      pr_err ("DM: cannot allocate DM region\n");
      if (dm_if)
	clib_mem_free (dm_if);
      return -ENOMEM;
    }
  dm_if->desc_phys_arr = vlib_physmem_get_pa (vm, dm_if->desc_virt_arr);
  if (!IS_ALIGNED (dm_if->desc_phys_arr, MVPP2_DESC_Q_ALIGN))
    {
      pr_err ("DM: Descriptor array must be %u-byte aligned\n", MVPP2_DESC_Q_ALIGN);
      vlib_physmem_free (vm, dm_if->desc_virt_arr);
      if (dm_if)
	clib_mem_free (dm_if);
      return -EPERM;
    }
  /* Get register address space slot for this DM object */
  dm_if->cpu_slot = inst->hw.base[dm_id].va;

  /* Initialize the aggregation queue under this DM object */
  pp2_dm_aggr_queue_config (dm_if, dm_if->desc_phys_arr, dm_if->desc_total);
  dm_if->desc_next_idx = pp2_reg_read (dm_if->cpu_slot, MVPP2_AGGR_TXQ_INDEX_REG (dm_if->id));

  /* Save this DM object in its packet processor unique slot */
  dm_if->parent = inst;
  inst->dm_ifs[dm_id] = dm_if;
  inst->num_dm_ifs++;

  pr_debug ("DM:(AQ%u)(PP%u) created\n", dm_id, pp2_id);

  return 0;
}

static int
pp2_netdev_if_admin_status_get (u32 pp_id, u32 ppio_id, u32 *admin_status)
{
  int i;

  /* Retrieve netdev if information, only for first time */
  pp2_netdev_if_info_get (netdev_params);

  for (i = 0; i < PP2_MAX_NUM_PACKPROCS * PP2_NUM_ETH_PPIO; i++)
    {
      if (netdev_params[i].pp_id == pp_id && netdev_params[i].ppio_id == ppio_id)
	{
	  *admin_status = netdev_params[i].admin_status;
	  return 0;
	}
    }
  return -EFAULT;
}

static int
pp2_netdev_if_info_get (struct netdev_if_params *netdev_params)
{
  FILE *fp;
  char path[PP2_MAX_BUF_STR_LEN];
  char subpath[PP2_MAX_BUF_STR_LEN];
  char buf[PP2_MAX_BUF_STR_LEN];
  u32 i, idx = 0;
  int if_dup = false;
  struct ifaddrs *ifap, *ifa;
  static int first_time = true;

  if (!first_time)
    return 0;

  if (!netdev_params)
    return -EFAULT;

  /* Step 1: check in dtb the status of the port */
  pp2_get_devtree_port_data (netdev_params);

  /* Step 2: parse through netdev if devices and get the if name  */
  /*check in uevent file OF_NODE=ppv22 exists */
  if (getifaddrs (&ifap) != 0)
    {
      pr_err ("unable to get netdev if info");
      return -EFAULT;
    }

  for (ifa = ifap; ifa; ifa = ifa->ifa_next)
    {
      /* Filter already parsed interfaces, since getifaddrs linked list contains entries
       * for the same interface and different family types
       */
      for (i = 0; i < PP2_MAX_NUM_PACKPROCS * PP2_NUM_ETH_PPIO; i++)
	{
	  if (strcmp (netdev_params[i].if_name, ifa->ifa_name) == 0)
	    {
	      if_dup = true;
	      break;
	    }
	}

      if (if_dup)
	{
	  if_dup = false;
	  continue;
	}

      sprintf (path, PP2_NETDEV_PATH);
      sprintf (subpath, "%s/device/uevent", ifa->ifa_name);

      strcat (path, subpath);
      fp = fopen (path, "r");
      if (!fp)
	{
	  pr_debug ("%s is probably not a pp2 interface. skipping\n", ifa->ifa_name);
	  continue;
	}
      while (fgets (buf, PP2_MAX_BUF_STR_LEN, fp))
	{
	  if (strncmp ("DRIVER=mvpp2", buf, 12) == 0)
	    {
	      while (netdev_params[idx].admin_status == PP2_PORT_DISABLED)
		idx++;
	      strcpy (netdev_params[idx].if_name, ifa->ifa_name);
	      idx++;
	    }
	}
      fclose (fp);
    }
  freeifaddrs (ifap);

  first_time = false;

  return 0;
}

static int
pp2_port_add_mac_addr (struct pp2_port *port, const uint8_t *addr)
{
  int rc;
  struct port_uc_addr_node *uc_addr_node;

  if (mv_check_eaddr_mc (addr))
    {
      struct ifreq s;
      int i;

      if (port->num_added_mc_addr == PP2_PPIO_MAX_MC_ADDR)
	{
	  pr_err ("PORT: reached multicast address limit (%d)\n", PP2_PPIO_MAX_MC_ADDR);
	  return -ENOSPC;
	}

      strcpy (s.ifr_name, port->linux_name);
      s.ifr_hwaddr.sa_family = AF_UNSPEC;
      for (i = 0; i < ETH_ALEN; i++)
	s.ifr_hwaddr.sa_data[i] = addr[i];

      rc = mv_netdev_ioctl (SIOCADDMULTI, &s);
      if (rc)
	{
	  pr_err ("PORT: unable to add mac sddress\n");
	  return rc;
	}
      port->num_added_mc_addr++;

      pr_debug ("PORT: Ethernet address %x:%x:%x:%x:%x:%x added to mc list\n", addr[0], addr[1],
		addr[2], addr[3], addr[4], addr[5]);
      pr_debug ("num_mc:%d\n", port->num_added_mc_addr);
    }
  else if (mv_check_eaddr_uc (addr))
    {
      int fd;
      char buf[PP2_MAX_BUF_STR_LEN];
      char da[PP2_MAX_BUF_STR_LEN];

      if (port->num_added_uc_addr == PP2_PPIO_MAX_UC_ADDR)
	{
	  pr_err ("PORT: reached unicast address limit (%d)\n", PP2_PPIO_MAX_UC_ADDR);
	  return -ENOSPC;
	}
      uc_addr_node = clib_mem_alloc_or_null (sizeof (*uc_addr_node));
      if (!uc_addr_node)
	return -ENOMEM;
      mv_cp_eaddr (uc_addr_node->addr, addr);

      strcpy (buf, port->linux_name);
      sprintf (da, " %x:%x:%x:%x:%x:%x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
      strcat (buf, da);
      fd = open ("/sys/devices/platform/pp2/debug/uc_filter_add", O_WRONLY);
      if (fd == -1)
	{
	  pr_debug ("PORT: unable to open sysfs, updating prs_table internally instead\n");
	  mv_pp2x_prs_mac_da_accept (port, addr, true);
	}
      else
	{
	  rc = write (fd, &buf, strlen (buf) + 1);
	  close (fd);
	  if (rc < 0)
	    {
	      pr_err ("PORT: unable to write to sysfs\n");
	      if (uc_addr_node)
		clib_mem_free (uc_addr_node);
	      return -EFAULT;
	    }
	}

      /* Add uc_address to list */
      list_add_to_tail (&uc_addr_node->list_node, &port->added_uc_addr);
      port->num_added_uc_addr++;

      pr_debug ("PORT: Ethernet address %x:%x:%x:%x:%x:%x added to uc list\n", addr[0], addr[1],
		addr[2], addr[3], addr[4], addr[5]);
      pr_debug ("num_uc:%d\n", port->num_added_uc_addr);
    }
  else
    {
      pr_err ("PORT: Ethernet address is not unicast/multicast. Request ignored\n");
    }
  return 0;
}

static int
pp2_port_flush_mac_addrs (struct pp2_port *port, uint32_t uc, uint32_t mc)
{
  int rc;
  u8 mac[ETH_ALEN];
  struct port_uc_addr_node *uc_addr_node;

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
	      pr_err ("address not found in file\n");
	      return -EFAULT;
	    }

	  if ((strcmp (port->linux_name, name)) || (!st))
	    continue;

	  len = parse_hex (addr_str, mac, ETH_ALEN);
	  if (len != ETH_ALEN)
	    {
	      pr_err ("len parsing error\n");
	      return -EFAULT;
	    }

	  rc = pp2_port_remove_mac_addr (port, mac);
	  if (rc)
	    return rc;
	}
      fclose (fp);
    }

  if (uc)
    {
      int fd;
      char buf[PP2_MAX_BUF_STR_LEN];

      strcpy (buf, port->linux_name);
      fd = open ("/sys/devices/platform/pp2/debug/uc_filter_flush", O_WRONLY);
      if (fd == -1)
	{
	  pr_debug ("PORT: unable to open sysfs, updating prs_table internally instead\n");
	  while (!list_is_empty (&port->added_uc_addr))
	    {
	      uc_addr_node =
		LIST_FIRST_OBJECT ((&port->added_uc_addr), struct port_uc_addr_node, list_node);
	      pp2_port_remove_mac_addr (port, uc_addr_node->addr);
	    }
	  pp2_port_clear_kernel_unicast (port);
	}
      else
	{
	  rc = write (fd, &buf, strlen (buf) + 1);
	  close (fd);
	  if (rc < 0)
	    {
	      pr_err ("PORT: unable to write to sysfs\n");
	      return -EFAULT;
	    }
	}
    }
  return 0;
}

static int
pp2_port_link_info (struct pp2_port *port, struct pp2_port_link_status *pstatus)
{
  struct gop_hw *gop = &port->parent->hw.gop;

  return pp2_gop_port_link_status (gop, &port->mac_data, pstatus);
}

static int
pp2_port_remove_mac_addr (struct pp2_port *port, const uint8_t *addr)
{
  int rc;

  if (mv_check_eaddr_mc (addr))
    {
      struct ifreq s;
      int i;

      strcpy (s.ifr_name, port->linux_name);
      s.ifr_hwaddr.sa_family = AF_UNSPEC;
      for (i = 0; i < ETH_ALEN; i++)
	s.ifr_hwaddr.sa_data[i] = addr[i];

      rc = mv_netdev_ioctl (SIOCDELMULTI, &s);
      if (rc)
	{
	  pr_err ("PORT: unable to remove mac sddress\n");
	  return rc;
	}
      port->num_added_mc_addr--;
      pr_debug ("PORT: Ethernet address %x:%x:%x:%x:%x:%x removed from mc list\n", addr[0], addr[1],
		addr[2], addr[3], addr[4], addr[5]);
      pr_debug ("num_mc:%d\n", port->num_added_mc_addr);
    }
  else if (mv_check_eaddr_uc (addr))
    {
      int fd;
      char buf[PP2_MAX_BUF_STR_LEN];
      char da[PP2_MAX_BUF_STR_LEN];

      strcpy (buf, port->linux_name);
      sprintf (da, " %x:%x:%x:%x:%x:%x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
      strcat (buf, da);
      fd = open ("/sys/devices/platform/pp2/debug/uc_filter_del", O_WRONLY);
      if (fd == -1)
	{
	  pr_debug ("PORT: unable to open sysfs, updating prs_table internally instead\n");
	  mv_pp2x_prs_mac_da_accept (port, addr, false);
	}
      else
	{
	  rc = write (fd, &buf, strlen (buf) + 1);
	  close (fd);
	  if (rc < 0)
	    {
	      pr_err ("PORT: unable to write to sysfs\n");
	      return -EFAULT;
	    }
	}

      pp2_port_uc_mac_addr_list_remove (port, addr);
      port->num_added_uc_addr--;

      pr_debug ("PORT: Ethernet address %x:%x:%x:%x:%x:%x removed from uc list\n", addr[0], addr[1],
		addr[2], addr[3], addr[4], addr[5]);
      pr_debug ("num_uc:%d\n", port->num_added_uc_addr);
    }
  else
    {
      pr_err ("PORT: Ethernet address is not unicast/multicast. Request ignored\n");
    }
  return 0;
}

static int
pp2_port_set_enable (struct pp2_port *port, uint32_t en)
{
  int rc;
  struct ifreq s;

  strcpy (s.ifr_name, port->linux_name);
  pr_debug ("pp2_port_set_enable : pp2_port_id (port) %d, port->linux_name: %s, enable(%d)\n",
	    pp2_port_id (port), port->linux_name, en);
  rc = mv_netdev_ioctl (SIOCGIFFLAGS, &s);
  if (rc)
    {
      pr_err ("PORT: unable to read port enabled\n");
      return rc;
    }

  if (en)
    s.ifr_flags |= IFF_UP;
  else
    s.ifr_flags &= ~IFF_UP;

  rc = mv_netdev_ioctl (SIOCSIFFLAGS, &s);
  if (rc)
    {
      pr_err ("PORT: unable to set port enabled\n");
      return rc;
    }
  return 0;
}

static int
pp2_port_set_mac_addr (struct pp2_port *port, const uint8_t *addr)
{
  int rc = 0;
  struct ifreq s;
  int i;

  if (!mv_check_eaddr_valid (addr))
    {
      pr_err ("PORT: not a valid eth address\n");
      return -EINVAL;
    }

  strcpy (s.ifr_name, port->linux_name);
  s.ifr_hwaddr.sa_family = ARPHRD_ETHER;

  for (i = 0; i < ETH_ALEN; i++)
    s.ifr_hwaddr.sa_data[i] = addr[i];

  rc = mv_netdev_ioctl (SIOCSIFHWADDR, &s);
  if (rc)
    return rc;

  mv_cp_eaddr (port->mac_data.mac, (const uint8_t *) addr);
  return 0;
}

static int
pp2_port_set_priv_flags (struct pp2_port *port, u32 val)
{
  struct ifreq ifr;
  struct ethtool_value param;
  int rc;

  strcpy (ifr.ifr_name, port->linux_name);

  param.cmd = ETHTOOL_SPFLAGS;
  param.data = val;
  ifr.ifr_data = &param;
  rc = mv_netdev_ioctl (SIOCETHTOOL, &ifr);
  if (rc)
    {
      pr_err ("PORT: unable to set priv_flags\n");
      return rc;
    }

  return 0;
}

static int
pp2_port_set_promisc (struct pp2_port *port, uint32_t en)
{
  int rc;
  struct ifreq s;

  strcpy (s.ifr_name, port->linux_name);
  rc = mv_netdev_ioctl (SIOCGIFFLAGS, &s);
  if (rc)
    {
      pr_err ("PORT: unable to read promisc mode from HW\n");
      return rc;
    }

  if (en)
    s.ifr_flags |= IFF_PROMISC;
  else
    s.ifr_flags &= ~IFF_PROMISC;

  rc = mv_netdev_ioctl (SIOCSIFFLAGS, &s);
  if (rc)
    {
      pr_err ("PORT: unable to set promisc mode to HW\n");
      return rc;
    }
  return 0;
}

static int
pp2_port_set_rx_pause (struct pp2_port *port, int en)
{
  struct ifreq ifr;
  struct ethtool_pauseparam param;
  int rc;

  if (port->rx_pause_en == en)
    return 0;

  memset (&param, 0, sizeof (param));
  strcpy (ifr.ifr_name, port->linux_name);

  param.cmd = ETHTOOL_SPAUSEPARAM;
  param.rx_pause = en;
  param.tx_pause = port->tx_pause_en;
  param.autoneg = 1;
  ifr.ifr_data = &param;
  rc = mv_netdev_ioctl (SIOCETHTOOL, &ifr);
  if (rc)
    {
      pr_err ("PORT: unable to %s rx pause\n", (en) ? "enable" : "disable");
      return rc;
    }

  port->rx_pause_en = en;
  pr_debug ("PORT: rx pause is %s\n", (en) ? "enabled" : "disabled");
  return 0;
}

static int
pp2_ppio_flush_vlan (struct pp2_port *port)
{
  int rc;

  rc = pp2_port_clear_all_vlans (port);
  return rc;
}

static int
pp2_ppio_set_loopback (struct pp2_port *port, int en)
{
  int rc;

  rc = pp2_port_set_loopback (port, en);
  return rc;
}

static inline uint32_t
pp2_relaxed_reg_read (uintptr_t cpu_slot, uint32_t offset)
{
  uintptr_t addr = cpu_slot + offset;

  return readl_relaxed ((void *) addr);
}

static void
sys_iomem_deinit (struct sys_iomem *iomem)
{
  bool device_exists = false;
  struct list *pos;
  struct sys_iomem *liomem_node;

  /* Check if requested iomem device is actually initialized */
  if (!list_is_empty (&iomem_maps_lst))
    {
      LIST_FOR_EACH (pos, &iomem_maps_lst)
      {
	liomem_node = LIST_OBJECT (pos, struct sys_iomem, node);
	if (strcmp (liomem_node->name, iomem->name) == 0 && liomem_node->index == iomem->index)
	  {
	    device_exists = true;
	  }
      }
    }

  if (!device_exists)
    {
      pr_err ("requested iomem device to deinit wasn't initialized\n");
      return;
    }

  iomem->owners--;

  if (iomem->owners)
    return;

  /* Remove from list of iomem devices */
  list_del (&iomem->node);

  iomem_uio_iodestroy (&iomem->uio);
  clib_mem_free (iomem->name);
  clib_mem_free (iomem);
}

static int
sys_iomem_map (struct sys_iomem *iomem, const char *name, phys_addr_t *pa, void **va)
{
  return iomem_uio_iomap (&iomem->uio, name, pa, va);
}

static int
sys_iomem_unmap (struct sys_iomem *iomem, const char *name)
{
  return iomem_uio_iounmap (&iomem->uio, name);
}

static void
pp2_port_clear_prs_vlans (struct pp2_port *port)
{
  uint32_t vlans[MVPP2_PRS_VLAN_FILT_MAX] = { 0 };
  int i;

  mv_pp2x_prs_clear_active_vlans (port, vlans);
  for (i = 0; (i < MVPP2_PRS_VLAN_FILT_MAX) && (vlans[i] != 0); i++)
    pp2_port_clear_vlan (port, vlans[i]);
  pp2_port_set_vlan_filtering (port, 0);
}

static void
pp2_port_close (struct pp2_port *port)
{
  struct pp2_inst *inst;
  if (!port)
    return;

  inst = port->parent;
  pp2_port_deinit (port);
  inst->num_ports--;

  /* Close uio_device file, returns ownership to Linux */
  if (NOT_LPBK_PORT (port))
    pp2_port_set_priv_flags (port, 0);
}

static void
pp2_port_config_inq (struct pp2_port *port)
{
  /* Port's classifier configuration */
  mv_pp2x_cls_oversize_rxq_set (port);
  /* Initialize hardware internals for RXQs */
  pp2_port_rxqs_init (port);
}

static void
pp2_port_init (struct pp2_port *port) /* port init from probe slowpath */
{
  int err;

  /* Disable port transmission */
  pp2_port_egress_disable (port);

  /* Allocate TXQ slots for this port */
  port->txqs = mem_calloc (1, sizeof (struct pp2_tx_queue *) * port->num_tx_queues);
  if (unlikely (!port->txqs))
    {
      pr_err ("%s out of memory txqs alloc\n", __func__);
      return;
    }

  /* Allocate RXQ slots for this port */
  port->rxqs = mem_calloc (1, sizeof (struct pp2_rx_queue *) * port->num_rx_queues);
  if (unlikely (!port->rxqs))
    {
      pr_err ("%s out of memory rxqs alloc\n", __func__);
      return;
    }

  /* Allocate and associated TXQs to this port */
  pp2_port_txqs_create (port);
  /* Allocate and associated RXQs to this port */
  pp2_port_rxqs_create (port);

  /* Disable port reception */
  pp2_port_ingress_disable (port);

  /* Port default configuration */
  pp2_port_defaults_set (port);

  /* Provide an initial MTU */
  port->flags = PP2_PORT_FLAGS_L4_CHKSUM;
  if (port->vpp_port)
    port->vpp_port->port_mtu = MV_DEFAULT_MTU;

  /* Get tx_fifo_size from hw_register, value was configured by Linux */
  port->tx_fifo_size = pp2_port_get_tx_fifo (port);

  err = pp2_port_check_mtu_valid (port, pp2_port_mtu (port));
  if (unlikely (err))
    {
      pr_err ("%s MTU error\n", __func__);
      return;
    }

  /* Provide an initial MRU */
  if (port->vpp_port)
    port->vpp_port->port_mru = MV_MTU_TO_MRU (pp2_port_mtu (port));

  /* TODO: Below fn_call is incorrect.
   * Should mask Interrupts:
   *  - For MUSDK_NIC ports for all cpu_slots, including kernel
   *  - For other ports, only for MUSDK cpu_slots (hif_map)
   */
#if 0
	pp2_port_interrupts_mask(port);
#endif

  if (port->vpp_port)
    memset (&port->vpp_port->stats, 0, sizeof (port->vpp_port->stats));

  /* Initialize RSS */
  pp2_cls_mng_rss_port_init (port);

  /* Set initial cos value */
  pp2_cls_mng_config_default_cos_queue (port);
}

static uint32_t
pp2_port_outq_status (struct pp2_dm_if *dm_if, uint32_t outq_physid)
{
  u32 cnt;
  /* Reading status reg resets transmitted descriptor counter */
  cnt = pp2_relaxed_reg_read (dm_if->cpu_slot, MVPP22_TXQ_SENT_REG (outq_physid));
  return (cnt & MVPP22_TRANSMITTED_COUNT_MASK) >> MVPP22_TRANSMITTED_COUNT_OFFSET;
}

static void
pp2_port_start_dev (struct pp2_port *port)
{
  if ((port->t_mode & PP2_TRAFFIC_INGRESS) == PP2_TRAFFIC_INGRESS)
    pp2_port_mac_max_rx_size_set (port);

  if ((port->t_mode & PP2_TRAFFIC_EGRESS) == PP2_TRAFFIC_EGRESS)
    pp2_port_config_txsched (port);

  pr_debug ("start_dev: tx_port_num %d, traffic mode %s%s\n", MVPP2_MAX_TCONT + pp2_port_id (port),
	    ((port->t_mode & PP2_TRAFFIC_INGRESS) == PP2_TRAFFIC_INGRESS) ? " ingress " : "",
	    ((port->t_mode & PP2_TRAFFIC_EGRESS) == PP2_TRAFFIC_EGRESS) ? " egress " : "");

  if ((port->t_mode & PP2_TRAFFIC_EGRESS) == PP2_TRAFFIC_EGRESS)
    pp2_port_egress_enable (port);

  if ((port->t_mode & PP2_TRAFFIC_INGRESS) == PP2_TRAFFIC_INGRESS)
    pp2_port_ingress_enable (port);
}

static void
pp2_port_stop (struct pp2_port *port)
{
  /* Stop new packets from arriving to RXQs */
  pr_debug ("pp2_port_stop: %s\n", port->linux_name);

  pp2_port_stop_dev (port);

  /* For non-loopback port, ifconfig down the interface in Linux */
  if (NOT_LPBK_PORT (port))
    pp2_port_set_enable (port, 0);
}

static void
pp2_port_txqs_init (struct pp2_port *port)
{
  u32 qid;

  for (qid = 0; qid < port->num_tx_queues; qid++)
    {
      struct pp2_tx_queue *txq = port->txqs[qid];

      pp2_txq_init (port, txq);
      pp2_port_set_outq_state (port, txq, true);
    }
}

static inline uint32_t
pp2_rxq_received (struct pp2_port *port, const int rxq_id)
{
  u32 val = pp2_reg_read (port->cpu_slot, MVPP2_RXQ_STATUS_REG (rxq_id));

  return (val & MVPP2_RXQ_OCCUPIED_MASK);
}

static int
mv_pp2x_ptr_validate (const void *ptr)
{
  if (!ptr)
    {
      pr_err ("%s: null pointer.\n", __func__);
      return MV_ERROR;
    }
  return 0;
}
static int
pp2_cls_c3_hit_cntr_clear_done (uintptr_t cpu_slot)
{
  u32 reg_val;

  reg_val = pp2_reg_read (cpu_slot, MVPP2_CLS3_STATE_REG);
  reg_val &= MVPP2_CLS3_STATE_CLEAR_CTR_DONE_MASK;
  reg_val >>= MVPP2_CLS3_STATE_CLEAR_CTR_DONE;
  return reg_val;
}
static int
pp2_cls_c3_hw_del (uintptr_t cpu_slot, int index)
{
  u32 reg_val = 0;
  int iter = 0;

  if (mv_pp2x_range_validate (index, 0, MVPP2_CLS3_HASH_OP_TBL_ADDR_MAX))
    return -EINVAL;

  reg_val |= (index << MVPP2_CLS3_HASH_OP_TBL_ADDR);
  reg_val |= (1 << MVPP2_CLS3_HASH_OP_DEL);
  reg_val &= ~MVPP2_CLS3_MISS_PTR_MASK; /*set miss bit to 1*/

  /*trigger del operation*/
  pp2_reg_write (cpu_slot, MVPP2_CLS3_HASH_OP_REG, reg_val);

  /* wait to cpu access done bit */
  while (!pp2_cls_c3_cpu_done (cpu_slot))
    if (++iter >= RETRIES_EXCEEDED)
      {
	pr_err ("%s:Error - retries exceeded.\n", __func__);
	return -EBUSY;
      }

  /* delete form shadow and extension shadow if exist */
  pp2_cls_c3_shadow_clear (index);

  return 0;
}
static int
pp2_cls_c3_hw_del_all (uintptr_t cpu_slot)
{
  int index, status;

  for (index = 0; index < MVPP2_CLS_C3_HASH_TBL_SIZE; index++)
    {
      status = pp2_cls_c3_hw_del (cpu_slot, index);
      if (status != 0)
	return status;
    }
  return 0;
}
static int
pp2_cls_c3_hit_cntrs_clear_all (uintptr_t cpu_slot)
{
  int iter = 0;

  pp2_reg_write (cpu_slot, MVPP2_CLS3_CLEAR_COUNTERS_REG, MVPP2_CLS3_CLEAR_ALL);
  /* wait to clear het counters done bit */
  while (!pp2_cls_c3_hit_cntr_clear_done (cpu_slot))
    if (++iter >= RETRIES_EXCEEDED)
      {
	pr_err ("%s:Error - retries exceeded.\n", __func__);
	return -EBUSY;
      }

  return 0;
}
static int
pp2_cls_c3_reset (struct pp2_inst *inst)
{
  int rc = 0;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  pr_debug ("reached\n");

  /* clear all C3 HW entries */
  rc = pp2_cls_c3_hw_del_all (cpu_slot);
  if (rc)
    {
      pr_err ("fail to delete C3 HW entries\n");
      return rc;
    }
  pr_debug ("PP2_CLS C3 HW entries deleted\n");

  /* clear all C3 HW counters */
  rc = pp2_cls_c3_hit_cntrs_clear_all (cpu_slot);
  if (rc)
    {
      pr_err ("fail to clear C3 HW counters\n");
      return rc;
    }
  pr_debug ("PP2_CLS C3 HW counters cleared\n");

  /* init PP2_CLS C3 HAL */
  rc = pp2_cls_c3_init (cpu_slot);
  if (rc)
    {
      pr_err ("fail to init PP2_CLS C3 DB\n");
      return rc;
    }
  pr_debug ("PP2_CLS C3 DB initialized\n");

  return 0;
}
static int
pp2_cls_c2_reset (struct pp2_inst *inst)
{
  int index;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  /* Clear all TCAM entry, except last one added by LSP */
  for (index = MVPP2_C2_FIRST_ENTRY; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    mv_pp2x_cls_c2_hw_inv (cpu_slot, index);

  return 0;
}
static int
mv_pp2x_cls_hw_cls_enable (uintptr_t cpu_slot, uint32_t en)
{
  if (mv_pp2x_range_validate (en, 0, 1) == MV_ERROR)
    return -EINVAL;

  /* Enable classifier */
  pp2_reg_write (cpu_slot, MVPP2_CLS_MODE_REG, en);

  return 0;
}
static int
pp2_cls_db_mem_alloc_init (struct pp2_inst *inst)
{
  /* Allocation for per-instance database */
  inst->cls_db = clib_mem_alloc_or_null (sizeof (*inst->cls_db));
  if (!inst->cls_db)
    goto fail1;

  /* Erase DB */
  MVPP2_MEMSET_ZERO (*inst->cls_db);

  return 0;

fail1:
  pr_err ("PP2_CLS DB memory allocation failed\n");
  return -ENOMEM;
}

static int
pp2_cls_db_init (struct pp2_inst *inst)
{
  int ret_code;

  /* Each database can be initialized only once */
  if (inst->cls_db)
    {
      pr_err ("Classifier database alraedy initialized.");
      return -EINVAL;
    }

  /* Allocation for pp2_cls db */
  ret_code = pp2_cls_db_mem_alloc_init (inst);

  if (ret_code != 0)
    {
      pr_err ("Failed to allocate memory for PP2_CLS DB\n");
      return -ENOMEM;
    }

  return 0;
}

static int
sys_iomem_init (struct sys_iomem_params *params, struct sys_iomem **iomem)
{
  struct sys_iomem *liomem;
  int err;
  struct list *pos;
  struct sys_iomem *liomem_node;

  /* Check if requested iomem device already initialized */
  if (!list_is_empty (&iomem_maps_lst))
    {
      LIST_FOR_EACH (pos, &iomem_maps_lst)
      {
	liomem_node = LIST_OBJECT (pos, struct sys_iomem, node);
	if (strcmp (liomem_node->name, params->devname) == 0 && liomem_node->index == params->index)
	  {
	    pr_debug ("requested iomem device already initialized\n");
	    liomem_node->owners++;
	    *iomem = liomem_node;
	    return 0;
	  }
      }
    }

  liomem = clib_mem_alloc_or_null (sizeof (struct sys_iomem));
  if (!liomem)
    {
      pr_err ("no mem for IOMEM obj!\n");
      return -ENOMEM;
    }
  memset (liomem, 0, sizeof (struct sys_iomem));

  liomem->owners = 1;

  liomem->name = clib_mem_alloc_or_null (strlen (params->devname) + 1);
  if (!liomem->name)
    {
      pr_err ("no mem for IOMEM-name obj!\n");
      return -ENOMEM;
    }
  memcpy (liomem->name, params->devname, strlen (params->devname));
  liomem->name[strlen (params->devname)] = '\0';
  liomem->index = params->index;

  err = iomem_uio_ioinit (&liomem->uio, liomem->name, liomem->index);
  if (err)
    {
      clib_mem_free (liomem->name);
      clib_mem_free (liomem);
      return err;
    }

  /* add to list: name & index */
  list_add_to_tail (&liomem->node, &iomem_maps_lst);

  *iomem = liomem;
  return 0;
}

static int
pp2_cls_c3_start (struct pp2_inst *inst)
{
  if (pp2_cls_c3_reset (inst))
    {
      pr_err ("PP2_CLS C3 start failed\n");
      return -EIO;
    }
  pr_debug ("PP2_CLS C3 started\n");

  return 0;
}

static int
pp2_cls_c2_start (struct pp2_inst *inst)
{
  if (pp2_cls_c2_reset (inst))
    {
      pr_err ("MVPP2 C2 start failed\n");
      return -EINVAL;
    }

  return 0;
}

static int
pp2_cls_init (struct pp2_inst *inst)
{
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  return mv_pp2x_cls_hw_cls_enable (cpu_slot, true);
}

static void
pp2_cls_mng_init (struct pp2_inst *inst)
{
  if (inst->cls_db)
    return; /*Already initialized*/

  pp2_cls_db_init (inst);
  pp2_cls_prs_init (inst);
  pp2_cls_init (inst);
  pp2_cls_c2_start (inst);
  pp2_cls_c3_start (inst);
  pp2_cls_rss_init (inst);
}

static int
pp2_get_hw_data (struct pp2_inst *inst)
{
  int err = 0;
  u32 i, reg_id;
  uintptr_t mem_base;
  struct pp2_hw *hw = &inst->hw;
  struct sys_iomem_params iomem_params;
  struct sys_iomem *pp2_sys_iomem;

  hw->tclk = PP2_TCLK_FREQ;
  iomem_params.devname = UIO_PP2_STRING;
  iomem_params.index = inst->id;

  err = sys_iomem_init (&iomem_params, &pp2_sys_iomem);
  inst->pp2_sys_iomem = pp2_sys_iomem;
  if (err)
    {
      pr_err (" No device found\n");
      return err;
    }

  /* Map the whole physical Packet Processor physical address */
  err = sys_iomem_map (pp2_sys_iomem, "pp", &hw->phy_address_base, (void **) (&mem_base));
  if (err)
    {
      sys_iomem_deinit (pp2_sys_iomem);
      return err;
    }
  /* Assign each CPU (thread) slot its mapped address space. */

  for (reg_id = 0; reg_id < ARRAY_SIZE (hw->base); reg_id++)
    hw->base[reg_id].va = mem_base + (reg_id * PP2_REGSPACE_SIZE);

  err = sys_iomem_map (pp2_sys_iomem, "mspg", &hw->gop.mspg.pa, (void **) (&mem_base));
  if (err)
    {
      sys_iomem_unmap (pp2_sys_iomem, "pp");
      sys_iomem_deinit (pp2_sys_iomem);
      return err;
    }
  hw->gop.mspg.va = mem_base;

  /* Map the Cm3 physical address */
  err = sys_iomem_map (pp2_sys_iomem, "cm3", &hw->cm3_base.pa, (void **) (&mem_base));
  if (err)
    {
      /* Not all systems support cm3 */
      pr_warn ("tx_pause not supported\n");
      err = 0;
    }
  else
    {
      hw->cm3_base.va = mem_base;
    }

  /**
   * Only memory maps aligned with PAGE_SIZE (ARM64 arch 0x1000) can be
   * mapped. Hence, the registers base address lower than PAGE_SIZE
   * alignment will be computed here and not extracted from device tree.
   */

  hw->gop.gmac.base.va = hw->gop.mspg.va + 0xE00;
  hw->gop.gmac.base.pa = hw->gop.mspg.pa + 0xE00;
  hw->gop.gmac.obj_size = 0x1000;

  hw->gop.xlg_mac.base.va = hw->gop.mspg.va + 0xF00;
  hw->gop.xlg_mac.base.pa = hw->gop.mspg.pa + 0xF00;
  hw->gop.xlg_mac.obj_size = 0x1000;

  /* Get MAC data for all available ethernet ports (not loopback port) based on dts GOP entries */
  /* TODO: Revise this after GOP dev tree support */
  for (i = 0; i < PP2_NUM_ETH_PPIO; i++)
    {
      struct pp2_port *port = inst->ports[i];
      struct pp2_mac_data *mac = &port->mac_data;
      u32 id = pp2_port_id (port) + (inst->id * PP2_NUM_ETH_PPIO);

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
sys_iomem_exists (struct sys_iomem_params *params)
{
  return iomem_uio_io_exists (params->devname, params->index);
}

static int
pp2_port_open (struct pp2 *pp2, struct pp2_ppio_params *param, u8 pp2_id, u8 port_id,
	       struct pp2_port **port_hdl)
{
  u32 i, j, k, first_rxq, num_in_qs;
  u32 total_num_in_qs = 0;
  struct pp2_inst *inst;
  struct pp2_port *port;
  struct pp2_hw *hw;
  int rc;
  inst = pp2->pp2_inst[pp2_id];

  /* Get the internal port handle */
  port = inst->ports[port_id];
  port->parent = inst;

  INIT_LIST (&port->added_uc_addr);

  /* Assign linux name to port */
  pp2_netdev_get_ifname (pp2_id, port_id, port->linux_name);
  pr_debug ("pp2_port_open: pp2_id(%d), port_id(%d), port->linux_name(%s)\n", pp2_id, port_id,
	    port->linux_name);

  /* Setup port based on client params
   * TODO: Traffic Mgr and CoS stuff not implemented yet, so only
   * the first parameter of the array is used
   */

  first_rxq = pp2_port_id (port) * PP2_HW_PORT_NUM_RXQS;

  port->first_rxq = first_rxq;
  port->num_tcs = param->inqs_params.num_tcs;
  for (i = 0; i < port->num_tcs; i++)
    {
      u16 tc_pkt_offset = param->inqs_params.tcs_params[i].pkt_offset;
      u8 tc_used_mem_id_pool_mask = 0;
      num_in_qs = param->inqs_params.tcs_params[i].num_in_qs;
      for (j = 0; j < num_in_qs; j++)
	{
	  struct pp2_rxq *rx_q = &(port->tc[i].rx_qs[j]);
	  struct pp2_ppio_inq_params *inqs_params =
	    &(param->inqs_params.tcs_params[i].inqs_params[j]);

	  rx_q->ring_size = inqs_params->size;
	  rx_q->tc_pools_mem_id_index = inqs_params->tc_pools_mem_id_index;
	  tc_used_mem_id_pool_mask |= (1 << inqs_params->tc_pools_mem_id_index);
	}
      if (tc_pkt_offset > PP2_MAX_PACKET_OFFSET)
	{
	  pr_err ("port %s: tc[%d] pkt_offset[%u] too large\n", port->linux_name, i, tc_pkt_offset);
	  return -EINVAL;
	}
      if (tc_pkt_offset % PP2_BUFFER_OFFSET_GRAN)
	{
	  pr_err ("port %s: tc[%d] pkt_offset[%u] must be multiple of %d\n", port->linux_name, i,
		  tc_pkt_offset, PP2_BUFFER_OFFSET_GRAN);
	  return -EINVAL;
	}
      if (tc_pkt_offset)
	port->tc[i].tc_config.pkt_offset = tc_pkt_offset;
      else
	port->tc[i].tc_config.pkt_offset = PP2_PACKET_DEF_OFFSET;
      port->tc[i].first_log_rxq = total_num_in_qs;
      port->tc[i].tc_config.num_in_qs = num_in_qs;
      port->tc[i].tc_config.default_color = param->inqs_params.tcs_params[i].default_color;
      /*To support RSS, each TC must start at natural rxq boundary */
      first_rxq = roundup (first_rxq, roundup_pow_of_two (num_in_qs));
      port->tc[i].tc_config.first_rxq = first_rxq;
      rc = populate_tc_pools (inst, param->inqs_params.tcs_params[i].pools,
			      port->tc[i].tc_config.pools);
      if (rc)
	return -EINVAL;
      for (j = 0; j < MV_SYS_DMA_MAX_NUM_MEM_ID; j++)
	{
	  if ((1 << j) & tc_used_mem_id_pool_mask)
	    if (port->tc[i].tc_config.pools[j][0] == NULL)
	      {
		pr_err ("Pool for mem_id(%d) was not configured\n", j);
		return -EINVAL;
	      }
	}
      total_num_in_qs += num_in_qs;
      first_rxq += num_in_qs;
    }
  port->num_rx_queues = total_num_in_qs;
  port->num_tx_queues = param->outqs_params.num_outqs;
  for (i = 0; i < port->num_tx_queues; i++)
    {
      port->txq_config[i].size = param->outqs_params.outqs_params[i].size;
      port->txq_config[i].sched_mode = param->outqs_params.outqs_params[i].sched_mode;
      port->txq_config[i].weight = param->outqs_params.outqs_params[i].weight;
    }

  port->hash_type = param->inqs_params.hash_type;

  if (LPBK_PORT (port))
    port->use_mac_lb = true;
  else
    port->use_mac_lb = false;

  pr_debug ("PORT: ID %u (on PP%u):\n", pp2_port_id (port), pp2_id);
  pr_debug ("PORT: %s\n", port->use_mac_lb ? "LOOPBACK" : "PHY");

  pr_debug ("PORT: TXQs %u\n", port->num_tx_queues);
  pr_debug ("PORT: RXQs %u\n", port->num_rx_queues);
  pr_debug ("PORT: First Phy RXQ %u\n", port->first_rxq);
  pr_debug ("PORT: Hash type %u\n", port->hash_type);

  for (i = 0; i < port->num_tcs; i++)
    {
      pr_debug ("PORT: TC%u\n", i);
      pr_debug ("PORT: TC RXQs %u\n", port->tc[i].tc_config.num_in_qs);
      pr_debug ("PORT: TC First Log RXQ %u\n", port->tc[i].first_log_rxq);
      pr_debug ("PORT: TC First Phy RXQ %u\n", port->tc[i].tc_config.first_rxq);
      pr_debug ("PORT: TC PKT Offset %u\n", port->tc[i].tc_config.pkt_offset);
      for (j = 0; j < port->tc[i].tc_config.num_in_qs; j++)
	{
	  pr_debug ("PORT: TC RXQ#%u size = %u tc_pool_pair = %u\n", j,
		    port->tc[i].rx_qs[j].ring_size, port->tc[i].rx_qs[j].tc_pools_mem_id_index);
	}
      for (j = 0; j < MV_SYS_DMA_MAX_NUM_MEM_ID; j++)
	for (k = 0; k < PP2_PPIO_TC_CLUSTER_MAX_POOLS; k++)
	  if (port->tc[i].tc_config.pools[j][k])
	    pr_debug ("PORT: TC Pool#%u = %u\n", j, port->tc[i].tc_config.pools[j][k]->bm_pool_id);
    }

  /* Assing a CPU slot to avoid send cpu_slot as argument further */
  hw = &inst->hw;
  port->cpu_slot = hw->base[PP2_DEFAULT_REGSPACE].va;

  port->num_vlans = 0;
  port->vlan_enable = 0;

  /* For MUSDK Ethernet ports, call uio_open to request port ownership from Linux */
  if (NOT_LPBK_PORT (port))
    {
      rc = pp2_port_set_priv_flags (port, MVPP22_F_IF_MUSDK_PRIV);
      if (rc)
	return rc;
    }
  /* Assign and initialize port private data and hardware */
  pp2_port_init (port);

  inst->num_ports++;

  /* At this point, the port is default allocated and configured */
  *port_hdl = port;

  if (!NOT_LPBK_PORT (port))
    return 0;

  pp2_port_clear_prs_vlans (port);
  pp2_port_flush_mac_addrs (port, 1, 1);

  /* Set default tx pause state as disabled */
  port->tx_pause_en = 0;

  /* set_rx_pause requires a change of state */
  port->rx_pause_en = 1;
  /* disable RX pause on init */
  pp2_port_set_rx_pause (port, 0);

  return 0;
}

static void
pp2_port_config_outq (struct pp2_port *port)
{
  /* TX FIFO Init to default 3KB size. Default with minimum threshold */
  /* TODO: change according to port type! */
  /* pp2_port_tx_fifo_config(port, PP2_TX_FIFO_SIZE_3KB, PP2_TX_FIFO_THRS_3KB); */
  /* Initialize hardware internals for TXQs */

  pp2_port_txqs_init (port);
}

static void
pp2_port_start (struct pp2_port *port, pp2_traffic_mode t_mode) /* Open from slowpath */
{

  pr_debug ("pp2_port_start: %s\n", port->linux_name);
  port->t_mode = t_mode;

  /* For non-loopback port, admin_up interface in Linux. Takes care of Phy/MAC. */
  if (NOT_LPBK_PORT (port))
    pp2_port_set_enable (port, 1);
  mdelay (500);
  pp2_port_start_dev (port);
}

static void
pp2_destroy (struct pp2_inst *inst)
{
  u32 i;

  sys_iomem_unmap (inst->pp2_sys_iomem, "pp");
  sys_iomem_unmap (inst->pp2_sys_iomem, "mspg");
  sys_iomem_deinit (inst->pp2_sys_iomem);

  /* No dangling handles */
  for (i = 0; i < PP2_NUM_PORTS; i++)
    if (inst->ports[i])
      clib_mem_free (inst->ports[i]);
  for (i = 0; i < PP2_NUM_REGSPACES; i++)
    if (inst->dm_ifs[i])
      clib_mem_free (inst->dm_ifs[i]);
  for (i = 0; i < PP2_BPOOL_NUM_POOLS; i++)
    if (inst->bm_pools[i])
      clib_mem_free (inst->bm_pools[i]);
  if (inst)
    clib_mem_free (inst);
}

static void
pp2_inst_init (struct pp2_inst *inst)
{
  uintptr_t cpu_slot;
  struct pp2_hw *hw = &inst->hw;

  /* Master thread initializes common part of HW.
   * This will probably get deprecated by KS driver for the initialization
   * part, but keep it for now
   */
  cpu_slot = hw->base[PP2_DEFAULT_REGSPACE].va;

  /* Clear BM */
  pp2_bm_flush_pools (cpu_slot, inst->parent->init.bm_pool_reserved_map);

  pp2_cls_mng_init (inst);

  /* GOP early activation */
  /* TODO: Revise after device tree adaptation */
}

static struct pp2_inst *
pp2_inst_create (struct pp2 *pp2, uint32_t pp2_id)
{
  u32 i;
  struct pp2_inst *inst;

  if (unlikely (!pp2))
    {
      pr_err ("Invalid ppdk handle\n");
      return NULL;
    }

  inst = mem_calloc (1, sizeof (struct pp2_inst));
  if (unlikely (!inst))
    {
      pr_err ("%s out of memory pp2_inst alloc\n", __func__);
      return NULL;
    }
  memset (inst, 0, sizeof (struct pp2_inst));

  /* Early allocate and get MAC data for available ports since GOP
   * sub-system needs to be initialized once per packet processor
   * Later, when ports get opened/started, only per-MAC
   * initializations shall be done
   */
  for (i = 0; i < PP2_NUM_PORTS; i++)
    {
      struct pp2_port *port = mem_calloc (1, sizeof (struct pp2_port));

      if (unlikely (!port))
	{
	  pr_err ("%s out of memory pp2_port alloc\n", __func__);
	  break;
	}
      inst->ports[i] = port;
      port->parent = inst;
    }

  inst->parent = pp2;
  inst->id = pp2_id;

  /* Get static device tree data */
  if (pp2_get_hw_data (inst))
    {
      pr_err ("cannot populate hardware data\n");
      for (i = 0; i < PP2_NUM_PORTS; i++)
	if (inst->ports[i])
	  clib_mem_free (inst->ports[i]);
      if (inst)
	clib_mem_free (inst);
      return NULL;
    }

  return inst;
}

static u8
pp2_get_num_inst (void)
{
  u8 i, pp2_num_inst = 0;
  struct sys_iomem_params iomem_params;

  iomem_params.devname = UIO_PP2_STRING;
  for (i = 0; i < PP2_MAX_NUM_PACKPROCS; i++)
    {
      iomem_params.index = i;
      pp2_num_inst += sys_iomem_exists (&iomem_params);
    }
  pr_debug ("pp2_num_inst=%d\n", pp2_num_inst);

  return pp2_num_inst;
}

int
pp2_init (struct pp2_init_params *params)
{
  u32 pp2_id, lp_pp2_id, pp2_num_inst, i;
  int rc;

  pp2_ptr = mem_calloc (1, sizeof (struct pp2));
  if (unlikely (!pp2_ptr))
    {
      pr_err ("%s out of memory pp2 alloc\n", __func__);
      return -ENOMEM;
    }
  memcpy (&pp2_ptr->init, params, sizeof (*params));
  pp2_ptr->pp2_common.hif_slot_map = 0;
  /* TODO: Check first_inq params are valid */

  pp2_num_inst = pp2_get_num_inst ();

  /* Initialize in an opaque manner from client,
   * depending on HW, one or two packet processors.
   */
  for (pp2_id = 0; pp2_id < pp2_num_inst; pp2_id++)
    {
      struct pp2_inst *inst;

      inst = pp2_inst_create (pp2_ptr, pp2_id);
      if (!inst)
	{
	  pr_err ("cannot create PP%u\n", pp2_id);
	  rc = -ENOMEM;
	  goto pp2_init_err;
	}
      /* Store the PPDK handle as parent and store
       * this instance as child handle for the PPDK
       */
      pp2_ptr->pp2_inst[pp2_id] = inst;

      pp2_inst_init (inst);

      pp2_ptr->num_pp2_inst++;
    }

  pr_debug ("PackProcs   %2u\n", pp2_num_inst);
  {
    struct pp2_ppio_params *lb_port_params;

    lb_port_params = clib_mem_alloc_or_null (sizeof (struct pp2_ppio_params));
    if (!lb_port_params)
      {
	rc = -ENOMEM;
	goto pp2_init_err;
      }

    memset (lb_port_params, 0, sizeof (*lb_port_params));
    lb_port_params->inqs_params.num_tcs = 0;
    lb_port_params->outqs_params.num_outqs = PP2_LPBK_PORT_NUM_TXQ;
    lb_port_params->outqs_params.outqs_params[0].size = PP2_LPBK_PORT_TXQ_SIZE;

    /* Initialize the loopback port */
    for (lp_pp2_id = 0; lp_pp2_id < pp2_num_inst; lp_pp2_id++)
      {
	struct pp2_port *port;

	rc = pp2_port_open (pp2_ptr, lb_port_params, lp_pp2_id, PP2_LOOPBACK_PORT, &port);
	if (rc)
	  {
	    pr_err ("[%s] ppio init failed.\n", __func__);
	    if (lb_port_params)
	      clib_mem_free (lb_port_params);
	    rc = -EFAULT;
	    /* TODO: in case of error during the loop, need to revert pp2_port_config_outq and
	     * pp2_port_start
	     */
	    goto pp2_init_err;
	  }
	pp2_port_config_outq (port);
	pp2_port_start (port, PP2_TRAFFIC_EGRESS);
      }
    if (lb_port_params)
      clib_mem_free (lb_port_params);
  }

  return 0;

pp2_init_err:
  /* Rollback creation of pp2 instances */
  for (i = 0; i < pp2_id; i++)
    pp2_destroy (pp2_ptr->pp2_inst[i]);
  if (pp2_ptr)
    clib_mem_free (pp2_ptr);
  return rc;
}

int
pp2_netdev_get_ifname (u8 pp_id, u8 ppio_id, char *ifname)
{
  int i;

  /* Retrieve netdev if information, only for first time */
  pp2_netdev_if_info_get (netdev_params);

  for (i = 0; i < PP2_MAX_NUM_PACKPROCS * PP2_NUM_ETH_PPIO; i++)
    {
      if (netdev_params[i].pp_id == pp_id && netdev_params[i].ppio_id == ppio_id)
	{
	  strcpy (ifname, netdev_params[i].if_name);
	  return 0;
	}
    }
  return -EFAULT;
}

int
pp2_ppio_available (int pp_id, int ppio_id)
{
  u32 admin_status;
  int err;

  err = pp2_netdev_if_admin_status_get (pp_id, ppio_id, &admin_status);

  if (!err && (admin_status != PP2_PORT_DISABLED))
    return true;
  return false;
}

int
pp2_hif_init (struct pp2_hif_params *params, struct pp2_hif **hif)
{
  int rc;
  u8 hif_slot = params->id, pp2_id, i;
  struct pp2_ppio_desc *descs;

  if (pp2_is_init () == false)
    {
      pr_err ("[%s] pp2 is not initialized\n", __func__);
      return (-EPERM);
    }

  if (hif_slot >= PP2_NUM_REGSPACES)
    {
      pr_err ("[%s] Invalid hif id %u!\n", __func__, hif_slot);
      return (-ENXIO);
    }
  if (pp2_ptr->init.hif_reserved_map & (1 << hif_slot))
    {
      pr_err ("[%s] hif is reserved.\n", __func__);
      return (-EFAULT);
    }
  if (pp2_ptr->pp2_common.hif_slot_map & (1 << hif_slot))
    {
      pr_err ("[%s] hif already exists.\n", __func__);
      return (-EEXIST);
    }

  descs = mem_calloc (PP2_NUM_PKT_PROC * PP2_MAX_NUM_PUT_BUFFS, sizeof (struct pp2_ppio_desc));
  if (!descs)
    return (-ENOMEM);

  /* Create AGGR_TXQ for each of the PPV2 instances. */
  for (pp2_id = 0; pp2_id < pp2_ptr->num_pp2_inst; pp2_id++)
    {
      rc = pp2_dm_if_init (params->vm, pp2_ptr, hif_slot, pp2_id, params->out_size);
      /* Rollback created instances */
      if (rc)
	{
	  for (i = 0; i < pp2_id; i++)
	    pp2_dm_if_deinit (params->vm, pp2_ptr, hif_slot, i);
	  clib_mem_free (descs);
	  return rc;
	}
    }
  pp2_hif[hif_slot].vm = params->vm;
  pp2_hif[hif_slot].regspace_slot = hif_slot;

  pp2_ptr->pp2_common.hif_slot_map |= (1 << hif_slot);
  *hif = &pp2_hif[hif_slot];
  (*hif)->rel_descs = descs;

  return 0;
}

void
pp2_hif_deinit (struct pp2_hif *hif)
{
  u8 hif_slot = hif->regspace_slot;

  for (u32 pp2_id = 0; pp2_id < pp2_ptr->num_pp2_inst; pp2_id++)
    pp2_dm_if_deinit (hif->vm, pp2_ptr, hif_slot, pp2_id);

  clib_mem_free (hif->rel_descs);
  pp2_ptr->pp2_common.hif_slot_map &= ~(1 << hif_slot);
  clib_memset (hif, 0, sizeof (*hif));
}

int
pp2_ppio_add_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int rc;

  rc = pp2_port_add_mac_addr (mp->pp_port, (const uint8_t *) addr);
  return rc;
}

void
pp2_ppio_deinit (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_port *pp_port = mp->pp_port;

  if (pp_port)
    {
      pp2_ppio_set_loopback (pp_port, false);
      pp2_ppio_set_promisc (port, false);
      pp2_ppio_flush_vlan (pp_port);

      if (pp2_cls_mng_modify_default_flows (pp_port, true))
	pr_err ("[%s] ppio deinit failed while default flows\n", __func__);

      if (pp2_cls_mng_eth_start_header_params_set (pp_port, PP2_PPIO_HDR_ETH))
	pr_err ("[%s] ppio deinit failed while initialize ethernet start header\n", __func__);

      pp2_port_close (pp_port);
      pp_port->is_open = false;
      pp_port->dev_port = NULL;
      pp_port->vpp_port = NULL;
    }
  else
    pr_err ("[%s] ppio deinit failed: port is not initialized\n", __func__);
}

int
pp2_ppio_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  pp2_port_stop (mp->pp_port);
  return 0;
}

int
pp2_ppio_enable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  pp2_port_start (mp->pp_port, PP2_TRAFFIC_INGRESS_EGRESS);
  return 0;
}

int
pp2_ppio_get_link_info (vnet_dev_port_t *port, struct pp2_ppio_link_info *link_info)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int rc;
  struct pp2_port_link_status pstatus;

  rc = pp2_port_link_info (mp->pp_port, &pstatus);
  if (rc)
    return rc;

  link_info->up = pstatus.linkup;
  link_info->speed = (enum mv_net_link_speed) pstatus.speed;
  link_info->duplex = (enum mv_net_link_duplex) pstatus.duplex;
  link_info->phy_mode = (enum mv_net_phy_mode) pstatus.phy_mode;

  return rc;
}

int
pp2_ppio_get_num_outq_done (vnet_dev_port_t *port, struct pp2_hif *hif, u8 qid, u16 *num)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_dm_if *dm_if;
  u32 outq_physid;

  dm_if = pp2_dm_if_get (mp->pp_port, hif);
  outq_physid = mp->pp_port->txqs[qid]->id;
  *num = pp2_port_outq_status (dm_if, outq_physid);

  return 0;
}

int
pp2_ppio_init (vnet_dev_port_t *port, struct pp2_ppio_params *params)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int port_id = params->id;
  int pp2_id = params->pp2_id;
  int rc;
  struct pp2_port *pp_port;

  if (pp2_is_init () == false)
    return -EPERM;

  if (port_id >= PP2_NUM_ETH_PPIO)
    {
      pr_err ("[%s] Invalid ppio.\n", __func__);
      return -ENXIO;
    }
  if (pp2_id >= pp2_ptr->num_pp2_inst)
    {
      pr_err ("[%s] Invalid pp2 instance.\n", __func__);
      return -ENXIO;
    }

  if (!pp2_ppio_available (pp2_id, port_id))
    {
      pr_err ("[%s] ppio %d:%d is not available for musdk.\n", __func__, pp2_id, port_id);
      return -EINVAL;
    }

  pp_port = pp2_ptr->pp2_inst[pp2_id]->ports[port_id];
  if (pp_port->is_open)
    {
      pr_err ("[%s] ppio already exists.\n", __func__);
      return -EEXIST;
    }

  ASSERT (mp->id == port_id);
  pp_port->dev_port = port;
  pp_port->vpp_port = mp;

  rc = pp2_port_open (pp2_ptr, params, pp2_id, port_id, &pp_port);
  if (rc)
    {
      pr_err ("[%s] ppio init failed.\n", __func__);
      pp_port->dev_port = NULL;
      pp_port->vpp_port = NULL;
      return (-EFAULT);
    }

  pp2_port_config_inq (pp_port);
  pp2_port_config_outq (pp_port);
  mp->cpu_slot = pp_port->cpu_slot;

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *mrq = vnet_dev_get_rx_queue_data (q);
      u32 log_rxq = pp_port->tc[0].first_log_rxq + q->queue_id;
      struct pp2_rx_queue *rxq = pp_port->rxqs[log_rxq];

      mrq->hw_id = rxq->id;
      mrq->desc_total = rxq->desc_total;
      mrq->desc_received = 0;
      mrq->desc_next_idx = 0;
      mrq->hw_descs = (struct pp2_ppio_desc *) rxq->desc_virt_arr;
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (q);

      mtq->log_id = pp_port->txqs[q->queue_id]->log_id;
    }

  rc = pp2_cls_mng_eth_start_header_params_set (pp_port, params->eth_start_hdr);
  if (rc)
    {
      pr_err ("[%s] ppio init failed while initialize ethernet start header\n", __func__);
      pp_port->dev_port = NULL;
      pp_port->vpp_port = NULL;
      return -EFAULT;
    }

  rc = pp2_cls_mng_modify_default_flows (pp_port, false);
  if (rc)
    {
      pr_err ("[%s] ppio init failed while modify default flows\n", __func__);
      pp_port->dev_port = NULL;
      pp_port->vpp_port = NULL;
      return -EFAULT;
    }

  pp2_ppio_set_loopback (pp_port, false);
  pp2_port_set_promisc (pp_port, false);

  pp_port->is_open = true;
  mp->pp_port = pp_port;

  return rc;
}

int
pp2_ppio_remove_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int rc;

  rc = pp2_port_remove_mac_addr (mp->pp_port, (const uint8_t *) addr);
  return rc;
}

int
pp2_ppio_set_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int rc;

  rc = pp2_port_set_mac_addr (mp->pp_port, (const uint8_t *) addr);
  return rc;
}

int
pp2_ppio_set_promisc (vnet_dev_port_t *port, int en)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int rc;

  rc = pp2_port_set_promisc (mp->pp_port, en);
  return rc;
}

static inline int
pp2_is_init (void)
{
  return (pp2_ptr) ? 1 : 0;
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
  uintptr_t addr = base + offset;

  writel (data, (void *) addr);
}

static void
mv_pp2x_cls_oversize_rxq_set (struct pp2_port *port)
{
  uintptr_t cpu_slot = port->cpu_slot;

  pp2_reg_write (cpu_slot, MVPP2_CLS_OVERSIZE_RXQ_LOW_REG (pp2_port_id (port)), port->first_rxq);
}

static void
mv_pp2x_prs_clear_active_vlans (struct pp2_port *port, uint32_t *vlans)
{
  struct pp2_inst *inst = port->parent;
  struct mv_pp2x_prs_shadow *prs_shadow = inst->cls_db->prs_db.prs_shadow;
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
mv_pp2x_prs_hw_inv (uintptr_t cpu_slot, int index)
{
  /* Write index - indirect access */
  pp2_reg_write (cpu_slot, MVPP2_PRS_TCAM_IDX_REG, index);
  pp2_reg_write (cpu_slot, MVPP2_PRS_TCAM_DATA_REG (MVPP2_PRS_TCAM_INV_WORD),
		 MVPP2_PRS_TCAM_INV_MASK);
}

static int
mv_pp2x_prs_mac_da_accept (struct pp2_port *port, const u8 *da, bool add)
{
  unsigned char mask[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  unsigned int pmap, len, ri;
  struct mv_pp2x_prs_shadow *prs_shadow = port->parent->cls_db->prs_db.prs_shadow;
  struct mv_pp2x_prs_entry pe;
  int tid;

  memset (&pe, 0, sizeof (pe));

  /* Scan TCAM and see if entry with this <MAC DA, port> already exist */
  tid = mvpp2x_prs_mac_da_range_find (port->parent, port->cpu_slot, BIT (pp2_port_id (port)), da,
				      mask, 0);

  /* No such entry */
  if (tid < 0)
    {
      if (!add)
	return 0;

      /* Create new TCAM entry */
      /* Go through the all entries from first to last */
      tid = pp2_prs_tcam_first_free (port->parent, prs_shadow->prs_mac_range_start,
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
      mv_pp2x_prs_hw_read (port->cpu_slot, &pe);
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

      mv_pp2x_prs_hw_inv (port->cpu_slot, pe.index);
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

  mv_pp2x_prs_shadow_ri_set (port->parent, pe.index, ri,
			     MVPP2_PRS_RI_L2_CAST_MASK | MVPP2_PRS_RI_MAC_ME_MASK);

  /* Shift to ethertype */
  mv_pp2x_prs_sram_shift_set (&pe, 2 * ETH_ALEN, MVPP2_PRS_SRAM_OP_SEL_SHIFT_ADD);

  /* Update shadow table and hw entry */
  mv_pp2x_prs_shadow_set (port->parent, pe.index, MVPP2_PRS_LU_MAC);
  mv_pp2x_prs_hw_write (port->cpu_slot, &pe);

  return 0;
}

static void
mv_pp2x_prs_shadow_set (struct pp2_inst *inst, int index, int lu)
{
  inst->cls_db->prs_db.prs_shadow[index].valid = true;
  inst->cls_db->prs_db.prs_shadow[index].lu = lu;
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
pp2_cls_mng_config_default_cos_queue (struct pp2_port *port)
{
  pp2_c2_config_default_queue (port, port->first_rxq);
  pp2_cls_mng_qos_tbl_dflt_set (port, port->first_rxq);
}

static void
pp2_cls_mng_rss_port_init (struct pp2_port *port)
{
  int rc, i;
  u32 num_queues = 0;

  port->rss_en = true;

  /* Check total number of TC's and number of in_queues per TC do
   * not exceed maximum number of HW queues in port
   */
  for (i = 0; i < port->num_tcs; i++)
    num_queues += port->tc[i].tc_config.num_in_qs;

  if (num_queues > PP2_PPIO_MAX_NUM_TCS)
    {
      pr_err ("not enough hw queues to allocate %d TC's and RSS. Needed %d queues, available %d\n",
	      port->num_tcs, num_queues, PP2_PPIO_MAX_NUM_TCS);
      pr_err ("RSS is set to disabled\n");
      port->rss_en = false;
    }

  if (port->hash_type == PP2_PPIO_HASH_T_NONE)
    port->rss_en = false;
  else
    {
      /* calculate the required musdk rss table map (not including the kernel rss map) */
      rc = pp2_rss_musdk_map_get (port);
      if (rc)
	{
	  pr_err ("Error in pp2_rss_musdk_map_get\n");
	  pr_err ("RSS is set to disabled\n");
	  port->rss_en = false;
	}
    }

  if (port->rss_en == true)
    {
      /* bind rxq to rss table for this port */
      if (pp22_cls_rss_rxq_set (port))
	{
	  pr_err ("cannot allocate rss table for rxq\n");
	  pr_err ("RSS is set to disabled\n");
	  port->rss_en = false;
	}

      /* Init RSS table */
      if (pp2_rss_hw_tbl_set (port))
	{
	  pr_err ("cannot init rss hw table\n");
	  pr_err ("RSS is set to disabled\n");
	  port->rss_en = false;
	}
    }

  /* Enable or disable RSS*/
  if (pp2_rss_enable (port, port->rss_en))
    {
      pr_err ("cannot enable rss\n");
      return;
    }
}

static int
pp2_get_devtree_port_data (struct netdev_if_params *netdev_params)
{
  FILE *fp;
  char cp110path[PP2_MAX_BUF_STR_LEN];
  char temppath[PP2_MAX_BUF_STR_LEN];
  char subpath[PP2_MAX_BUF_STR_LEN];
  char fullpath[PP2_MAX_BUF_STR_LEN];
  char buf[PP2_MAX_BUF_STR_LEN];
  int i, j, idx = 0, cp110_num, err;
  u8 num_inst;

  if (!netdev_params)
    return -EFAULT;

  num_inst = pp2_get_num_inst ();

  for (i = 0, cp110_num = 0; i < num_inst; i++, cp110_num++)
    {
      err = -1;
      while (cp110_num < PP2_MAX_NUM_PACKPROCS)
	{
	  sprintf (cp110path, "/proc/device-tree/cp%u/config-space@%x/ethernet@0/", cp110_num,
		   0xf2000000 + (cp110_num * 0x2000000));
	  err = access (cp110path, F_OK);
	  if (!err)
	    break;
	  cp110_num++;
	}
      if (err)
	{
	  pr_err ("error accessing file %s\n", cp110path);
	  return -EEXIST;
	}
      for (j = 0; j < PP2_NUM_ETH_PPIO; j++)
	{

	  idx = i * PP2_NUM_ETH_PPIO + j;
	  strcpy (temppath, cp110path);
	  sprintf (subpath, "eth%d", j);
	  strcat (temppath, subpath);
	  strcpy (fullpath, temppath);
	  strcat (fullpath, "/status");
	  fp = fopen (fullpath, "r");
	  if (!fp)
	    {
	      pr_err ("error opening file %s\n", fullpath);
	      return -EEXIST;
	    }

	  netdev_params[idx].ppio_id = j;
	  netdev_params[idx].pp_id = i;

	  fgets (buf, sizeof (buf), fp);
	  fclose (fp);

	  if (strcmp ("disabled", buf) == 0)
	    {
	      pr_debug ("port %d:%d is disabled\n", i, j);
	      netdev_params[idx].admin_status = PP2_PORT_DISABLED;
	    }
	  else
	    {
	      netdev_params[idx].admin_status = PP2_PORT_KERNEL;
	      pr_debug ("port %d:%d is ok\n", i, j);
	    }
	}
    }
  return 0;
}

static int
pp2_port_clear_kernel_unicast (struct pp2_port *port)
{
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

      if (strcmp (port->linux_name, name))
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
pp2_port_clear_vlan (struct pp2_port *port, u16 vlan)
{
  int rc;
  char buf[PP2_MAX_BUF_STR_LEN];

  /* build manually the system command */
  /* [TODO] check other alternatives for setting vlan id */
  sprintf (buf, "ip link delete %s.%d", port->linux_name, vlan);
  rc = system (buf);
  if (rc != 0)
    {
      pr_err ("clear vlan operation failed\n");
      return rc;
    }

  return 0;
}

static int
pp2_port_config_txsched (struct pp2_port *port)
{
  int rc, txq;
  u32 reg_val;
  u8 remapped_weights[MVPP2_MAX_TXQ];

  /* Set port MTU (which is used later in the initialization) */
  pp2_port_txsched_set_mtu (port);

  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG,
		 MVPP2_TX_PORT_NUM (pp2_port_id (port)));

  reg_val = pp2_reg_read (port->cpu_slot, MVPP2_TXP_SCHED_REFILL_REG);
  reg_val &= ~(MVPP2_TXP_REFILL_TOKENS_ALL_MASK | MVPP2_TXP_REFILL_PERIOD_ALL_MASK);
  reg_val |= MVPP2_TXP_REFILL_TOKENS_MASK (MVPP2_TXP_REFILL_TOKENS_MAX);
  reg_val |= MVPP2_TXP_REFILL_PERIOD_MASK (MVPP2_TXP_REFILL_PERIOD_MIN);
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_REFILL_REG, reg_val);
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_TOKEN_SIZE_REG,
		 MVPP2_TXP_MAX_CONFIGURABLE_BUCKET_SIZE);

  pp2_txsched_remap_weights (port, remapped_weights);

  /* Set TXQ scheduler defaults, arbitration mode and WRR weight. */
  for (txq = 0; txq < port->num_tx_queues; txq++)
    { /* This only works in logical ports post reprioritization */
      reg_val = pp2_reg_read (port->cpu_slot, MVPP2_TXQ_SCHED_REFILL_REG (txq));
      reg_val &= ~(MVPP2_TXQ_REFILL_TOKENS_ALL_MASK | MVPP2_TXQ_REFILL_PERIOD_ALL_MASK);
      reg_val |= MVPP2_TXQ_REFILL_TOKENS_MASK (MVPP2_TXQ_REFILL_TOKENS_MAX);
      reg_val |= MVPP2_TXQ_REFILL_PERIOD_MASK (MVPP2_TXQ_REFILL_PERIOD_MIN);
      pp2_reg_write (port->cpu_slot, MVPP2_TXQ_SCHED_REFILL_REG (txq), reg_val);
      pp2_reg_write (port->cpu_slot, MVPP2_TXQ_SCHED_TOKEN_SIZE_REG (txq),
		     MVPP2_TXQ_MAX_CONFIGURABLE_BUCKET_SIZE);

      if (port->num_tx_queues > 1 && NOT_LPBK_PORT (port))
	{
	  rc = pp2_txsched_queue_arbitration_set (port, txq, port->txq_config[txq].sched_mode,
						  remapped_weights[txq]);
	  if (rc)
	    return rc;
	}
    }

  return 0;
}

static int
pp2_port_set_vlan_filtering (struct pp2_port *port, int enable)
{
  const char *featstr = "rx-vlan-filter";
  int rc;

  if (!enable && port->num_vlans != 0)
    {
      pr_err ("disable vlan filtering not allowed until all the vlans removed\n");
      return -EPERM;
    }

  rc = mv_netdev_feature_set (port->linux_name, featstr, enable);
  if (rc != 0)
    {
      if (enable)
	pr_err ("failed to enable vlan filtering\n");
      else
	pr_err ("failed to disable vlan filtering\n");

      return rc;
    }

  port->vlan_enable = enable;
  return 0;
}

static int
pp2_port_uc_mac_addr_list_remove (struct pp2_port *port, const uint8_t *addr)
{
  struct port_uc_addr_node *uc_addr_node;

  LIST_FOR_EACH_OBJECT (uc_addr_node, struct port_uc_addr_node, &port->added_uc_addr, list_node)
  {
    if (mv_eaddr_identical (uc_addr_node->addr, addr))
      {
	list_del (&uc_addr_node->list_node);
	if (uc_addr_node)
	  clib_mem_free (uc_addr_node);
	pr_debug ("removed %x:%x:%x:%x:%x:%x from port_list\n", addr[0], addr[1], addr[2], addr[3],
		  addr[4], addr[5]);
	return 1;
      }
  }
  return 0;
}

static int
pp2_prs_port_update (struct pp2_port *port, u32 add, u32 tid, u32 ri, u32 ri_mask)
{
  struct mv_pp2x_prs_entry pe;
  struct pp2_inst *inst = port->parent;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  if (!inst->cls_db->prs_db.prs_shadow[tid].valid)
    {
      pr_err ("parser logical port special field DSA mode: entry not found\n");
      return -EFAULT;
    }

  pe.index = tid;
  mv_pp2x_prs_hw_read (cpu_slot, &pe);

  /* update UDF7 */
  mv_pp2x_prs_sram_ri_update (&pe, ri, ri_mask);

  /* Update port mask */
  mv_pp2x_prs_tcam_port_set (&pe, pp2_port_id (port), add);

  mv_pp2x_prs_hw_write (cpu_slot, &pe);

  return 0;
}

static void
pp2_port_defaults_set (struct pp2_port *port)
{
  u32 tx_port_num, val, queue, ptxq, lrxq;
  struct pp2_inst *inst = port->parent;
  struct pp2_hw *hw = &inst->hw;
  uintptr_t cpu_slot = port->cpu_slot;

  /* Disable Legacy WRR, Disable EJP, Release from reset */
  tx_port_num = MVPP2_MAX_TCONT + pp2_port_id (port);
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_CMD_1_REG, 0x0);

  /* Close bandwidth for all queues */
  for (queue = 0; queue < MVPP2_MAX_TXQ; queue++)
    {
      ptxq = (MVPP2_MAX_TCONT + pp2_port_id (port)) * MVPP2_MAX_TXQ + queue;
      pp2_reg_write (cpu_slot, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (ptxq), 0x0);
    }

  /* Set refill period to 1 usec, refill tokens
   * and bucket size to maximum
   */
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_PERIOD_REG, hw->tclk / 1000000); /* USEC_PER_SEC */
  val = pp2_reg_read (cpu_slot, MVPP2_TXP_SCHED_REFILL_REG);
  val &= ~MVPP2_TXP_REFILL_PERIOD_ALL_MASK;
  val |= MVPP2_TXP_REFILL_PERIOD_MASK (1);
  val |= MVPP2_TXP_REFILL_TOKENS_ALL_MASK;
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_REFILL_REG, val);
  val = MVPP2_TXP_TOKEN_SIZE_MAX;
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, val);

  /* Set MaximumLowLatencyPacketSize value to 256 */
  /* Set GemPortIdSrcSel from classifier */
  pp2_reg_write (cpu_slot, MVPP2_RX_CTRL_REG (pp2_port_id (port)),
		 MVPP2_RX_USE_PSEUDO_FOR_CSUM_MASK | MVPP2_RX_LOW_LATENCY_PKT_SIZE (256) |
		   MVPP2_RX_GEM_PORT_ID_SRC_SEL (2));

  /* Disable Rx cache snoop */
  for (lrxq = 0; lrxq < port->num_rx_queues; lrxq++)
    {
      queue = port->rxqs[lrxq]->id;
      val = pp2_reg_read (cpu_slot, MVPP2_RXQ_CONFIG_REG (queue));
      /* Coherent */
      val |= MVPP2_SNOOP_PKT_SIZE_MASK;
      val |= MVPP2_SNOOP_BUF_HDR_MASK;
      pp2_reg_write (cpu_slot, MVPP2_RXQ_CONFIG_REG (queue), val);
    }
  /* As default, mask all interrupts to all present cpus */
  pp2_port_interrupts_disable (port);
}

static void
pp2_port_deinit (struct pp2_port *port)
{
  if (NOT_LPBK_PORT (port))
    pp2_port_flush_mac_addrs (port, 1, 1);

  /* Reset/disable TXQs/RXQs from hardware */
  pp2_port_rxqs_deinit (port);
  pp2_port_txqs_deinit (port);

  /* Deallocate TXQs/RXQs for this port */
  pp2_port_txqs_destroy (port);
  pp2_port_rxqs_destroy (port);

  /* Free port TXQ slots */
  if (port->txqs)
    clib_mem_free (port->txqs);
  /* Free port RXQ slots */
  if (port->rxqs)
    clib_mem_free (port->rxqs);
}

static void
pp2_port_egress_disable (struct pp2_port *port)
{
  u32 q_mask = 0;
  uintptr_t cpu_slot = port->cpu_slot;

  q_mask = (pp2_reg_read (cpu_slot, MVPP2_TXP_SCHED_Q_CMD_REG) & MVPP2_TXP_SCHED_ENQ_MASK);
  pp2_port_egress_disable_qmask (port, q_mask);
}

static void
pp2_port_egress_enable (struct pp2_port *port)
{
  u32 q_mask = 0;

  q_mask = (1 << port->num_tx_queues) - 1;
  pp2_port_egress_enable_qmask (port, q_mask);
}

static void
pp2_port_ingress_disable (struct pp2_port *port)
{
  u32 val;
  u32 rxq, qid;
  uintptr_t cpu_slot = port->cpu_slot;

  /* RXQs disable */
  for (rxq = 0; rxq < port->num_rx_queues; rxq++)
    {
      qid = port->rxqs[rxq]->id;
      val = pp2_reg_read (cpu_slot, MVPP2_RXQ_CONFIG_REG (qid));
      val |= MVPP2_RXQ_DISABLE_MASK;
      pp2_reg_write (cpu_slot, MVPP2_RXQ_CONFIG_REG (qid), val);
    }
}

static void
pp2_port_ingress_enable (struct pp2_port *port)
{
  u32 val;
  u32 rxq, qid;
  uintptr_t cpu_slot = port->cpu_slot;

  /* RXQs enable */
  for (rxq = 0; rxq < port->num_rx_queues; rxq++)
    {
      qid = port->rxqs[rxq]->id;
      val = pp2_reg_read (cpu_slot, MVPP2_RXQ_CONFIG_REG (qid));
      val &= ~MVPP2_RXQ_DISABLE_MASK;
      pp2_reg_write (cpu_slot, MVPP2_RXQ_CONFIG_REG (qid), val);
    }
}

static void
pp2_port_mac_max_rx_size_set (struct pp2_port *port)
{
  struct gop_hw *gop = &port->parent->hw.gop;
  int mac_num = port->mac_data.gop_index;
  uint32_t pp2_version;

  /* GOP#0 and GOP#2 (In PP23/CP115) can support both XLG and GMAC;
   * MUSDK cannot know that on the fly so always configure both of them;
   * All the rest support only GMAC
   */
  pp2_version = pp2_reg_read (port->cpu_slot, MVPP2_VER_ID_REG);
  pp2_gop_gmac_max_rx_size_set (gop, mac_num, pp2_port_mru (port));
  if ((mac_num == 0) || ((mac_num == 2) && (pp2_version == MVPP2_VER_PP23)))
    pp2_gop_xlg_mac_max_rx_size_set (gop, mac_num, pp2_port_mru (port));
}

static void
pp2_port_rxqs_create (struct pp2_port *port)
{
  u32 qid, tc, id = 0;

  for (tc = 0; tc < port->num_tcs; tc++)
    {
      struct pp2_ppio_tc_config *tc_cfg = &(port->tc[tc].tc_config);

      for (qid = 0; qid < port->tc[tc].tc_config.num_in_qs; qid++)
	{
	  struct pp2_rx_queue *rxq = mem_calloc (1, sizeof (struct pp2_rx_queue));
	  u8 mem_index = port->tc[tc].rx_qs[qid].tc_pools_mem_id_index;
	  u32 tmp_bpool_id;

	  if (unlikely (!rxq))
	    {
	      pr_err ("%s out of memory rxq alloc\n", __func__);
	      return;
	    }
	  rxq->id = tc_cfg->first_rxq + qid;
	  rxq->log_id = port->tc[tc].first_log_rxq + qid;
	  rxq->desc_total = port->tc[tc].rx_qs[qid].ring_size;

	  tmp_bpool_id = tc_cfg->pools[mem_index][BM_TYPE_SHORT_BUF_POOL]->bm_pool_id;
	  rxq->bm_pool_id[BM_TYPE_SHORT_BUF_POOL] = tmp_bpool_id;

	  tmp_bpool_id = tc_cfg->pools[mem_index][BM_TYPE_LONG_BUF_POOL]->bm_pool_id;
	  rxq->bm_pool_id[BM_TYPE_LONG_BUF_POOL] = tmp_bpool_id;

	  pr_debug ("pp2_port_rxqs_create: port[%d:%d] tc%d rxq%d mem_index(%d)\n",
		    port->parent->id, pp2_port_id (port), tc, rxq->id, mem_index);

	  /* Double check of queue index */
	  if (rxq->log_id != id)
	    {
	      pr_err ("%s invalid log_id %d value (should be %d)\n", __func__, rxq->log_id, id);
	      return;
	    }
	  /*TODO: are we really serializing the queue????? */
	  port->rxqs[rxq->log_id] = rxq;
	  id++;
	}
    }
}

static void
pp2_port_rxqs_init (struct pp2_port *port)
{
  u32 qid;

  for (qid = 0; qid < port->num_rx_queues; qid++)
    {
      struct pp2_rx_queue *rxq = port->rxqs[qid];

      pp2_rxq_init (port, rxq);
    }

  pp2_port_rxqs_fc_state_reset (port);
  pp2_port_clear_fc_isr (port);
}

static int
pp2_port_set_outq_state (struct pp2_port *port, struct pp2_tx_queue *txq, int en)
{
  uintptr_t cpu_slot = port->cpu_slot;
  int tx_port_num = MVPP2_MAX_TCONT + pp2_port_id (port);
  u32 val = 0, mask;

  /* TODO: add lock to protect MVPP2_TXP_SCHED_PORT_INDEX_REG */
  /* Get active channels mask */
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  val = (pp2_reg_read (cpu_slot, MVPP2_TXP_SCHED_Q_CMD_REG) & MVPP2_TXP_SCHED_ENQ_MASK);
  mask = 1 << txq->log_id;

  if (en)
    {
      if (!(val & mask))
	{
	  /* Enable transmit packets to aggregation queue */
	  txq->disabled = 0;

	  /* Enable Tx queue */
	  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
	  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_Q_CMD_REG, mask);
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
		  pr_warn ("Port%u: TXQ=%u clean timed out\n", pp2_port_id (port), txq->log_id);
		  break;
		}
	      /* Sleep for 1 microsecond */
	      udelay (1);
	      delay++;
	      pending = pp2_txq_pend_desc_num_get (port, txq);
	      pr_debug ("pp2_txq_clean: Port%u: TXQ=%u pending: %d\n", pp2_port_id (port),
			txq->log_id, pending);
	    }
	  while (pending);

	  /* Disable Tx queue */
	  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
	  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_Q_CMD_REG, mask << MVPP2_TXP_SCHED_DISQ_OFFSET);
	}
    }

  return 0;
}

static void
pp2_port_stop_dev (struct pp2_port *port)
{
  /* Stop new packets from arriving to RXQs */
  pp2_port_ingress_disable (port);

  /* Sleep for 10 milliseconds */
  mdelay (10);

  /* Disable interrupts on all CPUs */
  pp2_port_interrupts_disable (port);
  pp2_port_egress_disable (port);
}

static void
pp2_port_txqs_create (struct pp2_port *port)
{
  u32 qid;

  for (qid = 0; qid < port->num_tx_queues; qid++)
    {
      struct pp2_tx_queue *txq = mem_calloc (1, sizeof (struct pp2_tx_queue));

      if (unlikely (!txq))
	{
	  pr_err ("%s out of memory txq alloc\n", __func__);
	  return;
	}

      txq->id = (MVPP2_MAX_TCONT + pp2_port_id (port)) * MVPP2_MAX_TXQ + qid;
      txq->log_id = qid;
      port->txqs[qid] = txq;
    }
}

static void
pp2_txq_init (struct pp2_port *port, struct pp2_tx_queue *txq)
{
  void *desc_mem;
  uintptr_t cpu_slot;
  u32 j, val, desc_per_txq, pref_buf_size, desc;
  struct pp2_hw *hw;

  hw = &port->parent->hw;
  cpu_slot = port->cpu_slot;

  if (LPBK_PORT (port))
    desc_per_txq = PP2_LOOPBACK_PORT_TXQ_PREFETCH;
  else
    desc_per_txq = PP2_ETH_PORT_TXQ_PREFETCH;

  /* FS_A8K Table 1542: The SWF ring size + a prefetch size for HWF */
  txq->desc_total = port->txq_config[txq->log_id].size;
  if (LPBK_PORT (port))
    desc_mem = vlib_physmem_alloc_aligned (
      vlib_get_main (), txq->desc_total * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN);
  else if (vnet_dev_dma_mem_alloc (vlib_get_main (), port->dev_port->dev,
				   txq->desc_total * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN,
				   &desc_mem) != VNET_DEV_OK)
    desc_mem = 0;

  if (unlikely (!desc_mem))
    {
      pr_err ("PP: cannot allocate egress descriptor array\n");
      return;
    }
  txq->desc_virt_arr = desc_mem;
  if (LPBK_PORT (port))
    txq->desc_phys_arr = vlib_physmem_get_pa (vlib_get_main (), txq->desc_virt_arr);
  else
    txq->desc_phys_arr =
      vnet_dev_get_dma_addr (vlib_get_main (), port->dev_port->dev, txq->desc_virt_arr);
  if (!IS_ALIGNED (txq->desc_phys_arr, MVPP2_DESC_Q_ALIGN))
    {
      pr_err ("PP: egress descriptor array must be %u-byte aligned\n", MVPP2_DESC_Q_ALIGN);
      if (LPBK_PORT (port))
	vlib_physmem_free (vlib_get_main (), txq->desc_virt_arr);
      else
	vnet_dev_dma_mem_free (vlib_get_main (), port->dev_port->dev, txq->desc_virt_arr);
      return;
    }

  pr_debug ("port[%d:%d] tx desc_phys_addr(0x%lx)\n", port->parent->id, pp2_port_id (port),
	    txq->desc_phys_arr);

  /* Set Tx descriptors queue starting address - indirect access */
  pp2_reg_write (cpu_slot, MVPP2_TXQ_NUM_REG, txq->id);
  pp2_reg_write (cpu_slot, MVPP2_TXQ_DESC_ADDR_LOW_REG,
		 ((uint32_t) txq->desc_phys_arr) >> MVPP2_TXQ_DESC_ADDR_LOW_SHIFT);
  pp2_reg_write (cpu_slot, MVPP22_TXQ_DESC_ADDR_HIGH_REG,
		 (txq->desc_phys_arr >> 32) & MVPP22_TXQ_DESC_ADDR_HIGH_MASK);
  pp2_reg_write (cpu_slot, MVPP2_TXQ_DESC_SIZE_REG, txq->desc_total & MVPP2_TXQ_DESC_SIZE_MASK);
  pp2_reg_write (cpu_slot, MVPP2_TXQ_INDEX_REG, 0x0);
  pp2_reg_write (cpu_slot, MVPP2_TXQ_RSVD_CLR_REG, txq->id << MVPP2_TXQ_RSVD_CLR_OFFSET);
  val = pp2_reg_read (cpu_slot, MVPP2_TXQ_PENDING_REG);
  val &= ~MVPP2_TXQ_PENDING_MASK;
  pp2_reg_write (cpu_slot, MVPP2_TXQ_PENDING_REG, val);

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
  pp2_reg_write (cpu_slot, MVPP2_TXQ_PREF_BUF_REG,
		 MVPP2_PREF_BUF_PTR (desc) | pref_buf_size |
		   MVPP2_PREF_BUF_THRESH (PP2_TXQ_PREFETCH_16 / 2));

  /* Lastly, clear all ETH_TXQS for all future DM-IFs */
  for (j = 0; j < PP2_NUM_REGSPACES; j++)
    {
      cpu_slot = hw->base[j].va;
      pp2_reg_read (cpu_slot, MVPP22_TXQ_SENT_REG (txq->id));
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
mv_netdev_feature_set (const char *netdev, const char *featstr, int val)
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
      pr_err ("can't open socket: errno %d", errno);
      return -EFAULT;
    }

  sprintf (ifr.ifr_name, "%s", netdev);

  if (mv_netdev_get_featstrs (fd, &ifr, &fs))
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
      pr_err ("failed to find feature %s\n", featstr);
      close (fd);
      mv_netdev_clean_featstrs (&fs);
      return -ENOENT;
    }

  ret = mv_netdev_set_feature_ioctl (fd, &ifr, fbit, !!val);

  close (fd);
  mv_netdev_clean_featstrs (&fs);

  if (ret)
    return -EIO;

  return 0;
}

static int
mvpp2x_prs_mac_da_range_find (struct pp2_inst *inst, uintptr_t cpu_slot, int pmap, const u8 *da,
			      const u8 *mask, int udf_type)
{
  struct mv_pp2x_prs_entry pe;
  int tid;
  struct mv_pp2x_prs_shadow *prs_shadow = inst->cls_db->prs_db.prs_shadow;

  /* Go through all entries with MVPP2_PRS_LU_MAC */
  for (tid = prs_shadow->prs_mac_range_start; tid <= prs_shadow->prs_mac_range_end; tid++)
    {
      unsigned int entry_pmap;

      if (!prs_shadow[tid].valid || prs_shadow[tid].lu != MVPP2_PRS_LU_MAC)
	continue;
      pe.index = tid;
      mv_pp2x_prs_hw_read (cpu_slot, &pe);
      entry_pmap = mv_pp2x_prs_tcam_port_map_get (&pe);

      if (mv_pp2x_prs_mac_range_equals (&pe, da, mask))
	{
	  pr_debug ("maps: %d:%d\n", entry_pmap, pmap);
	  if (entry_pmap == pmap)
	    return tid;
	}
    }

  return -ENOENT;
}

static void
mv_pp2x_prs_shadow_ri_set (struct pp2_inst *inst, int index, unsigned int ri, unsigned int ri_mask)
{
  inst->cls_db->prs_db.prs_shadow[index].ri_mask = ri_mask;
  inst->cls_db->prs_db.prs_shadow[index].ri = ri;
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
pp2_c2_config_default_queue (struct pp2_port *port, u16 queue)
{
  int index;
  int c2_status;
  int rc;
  u8 port_id, lkp_type;
  struct mv_pp2x_cls_c2_entry c2;
  struct pp2_hw *hw = &port->parent->hw;

  c2_status = pp2_reg_read (hw->base[0].va, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      pr_err ("c2 is off\n");
      return -EINVAL;
    }

  mv_pp2x_c2_sw_clear (&c2);

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mv_pp2x_cls_c2_hw_read (hw->base[0].va, index, &c2);
      port_id = pp2_cls_c2_tcam_port_get (&c2);
      lkp_type = pp2_cls_c2_tcam_lkp_type_get (&c2);

      if (c2.inv != 0 || port_id != (1 << pp2_port_id (port)))
	continue;

      if (lkp_type == MVPP2_CLS_LKP_DEFAULT)
	{
	  rc = pp2_c2_config_queue (&c2, queue, MVPP2_QOS_SRC_ACTION_TBL);
	  if (rc)
	    return -EFAULT;

	  pr_debug ("Writing index %#x, queue %d, from %d\n", index, queue,
		    MVPP2_QOS_SRC_ACTION_TBL);
	  mv_pp2x_cls_c2_hw_write (hw->base[0].va, index, &c2);
	}
      else if (lkp_type == MVPP2_CLS_LKP_DSCP_PRI || lkp_type == MVPP2_CLS_LKP_VLAN_PRI)
	{
	  rc = pp2_c2_config_queue (&c2, queue, MVPP2_QOS_SRC_DSCP_PBIT_TBL);
	  if (rc)
	    return -EFAULT;

	  pr_debug ("Writing index %#x, queue %d, from %d\n", index, queue,
		    MVPP2_QOS_SRC_DSCP_PBIT_TBL);
	  mv_pp2x_cls_c2_hw_write (hw->base[0].va, index, &c2);
	}
    }
  return 0;
}

static int
pp2_cls_mng_qos_tbl_dflt_set (struct pp2_port *port, u16 queue)
{
  int rc = 0;
  u32 i;
  u8 tc_array[MVPP2_QOS_TBL_LINE_NUM_DSCP];

  for (i = 0; i < MV_DSCP_NUM; i++)
    tc_array[i] = queue;

  rc = mv_pp2x_cls_c2_qos_tbl_fill_array (port, MVPP2_QOS_TBL_SEL_DSCP, tc_array);
  if (rc)
    {
      pr_err ("mv_pp2x_cls_c2_qos_tbl_fill_array failed\n");
      return -EINVAL;
    }

  rc = mv_pp2x_cls_c2_qos_tbl_fill_array (port, MVPP2_QOS_TBL_SEL_PRI, tc_array);
  if (rc)
    {
      pr_err ("mv_pp2x_cls_c2_qos_tbl_fill_array failed\n");
      return -EINVAL;
    }
  return 0;
}

static int
pp2_gop_gmac_max_rx_size_set (struct gop_hw *gop, int mac_num, int max_rx_size)
{
  u32 reg_val;

  reg_val = pp2_gop_gmac_read (gop, mac_num, PP2_GMAC_PORT_CTRL0_REG);
  reg_val &= ~PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_MASK;
  reg_val |= (((max_rx_size - MV_MH_SIZE) / 2) << PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_OFFS);
  pp2_gop_gmac_write (gop, mac_num, PP2_GMAC_PORT_CTRL0_REG, reg_val);

  return 0;
}

static int
pp2_gop_xlg_mac_max_rx_size_set (struct gop_hw *gop, int mac_num, int max_rx_size)
{
  u32 reg_val;

  reg_val = pp2_gop_xlg_mac_read (gop, mac_num, PP2_XLG_PORT_MAC_CTRL1_REG);
  reg_val &= ~PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_MASK;
  reg_val |= (((max_rx_size - MV_MH_SIZE) / 2) << PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_OFFS);
  pp2_gop_xlg_mac_write (gop, mac_num, PP2_XLG_PORT_MAC_CTRL1_REG, reg_val);

  return 0;
}

static void
pp2_port_clear_fc_isr (struct pp2_port *port)
{
  int cpu_slot_id;
  uintptr_t cpu_slot;

  for (cpu_slot_id = 0; cpu_slot_id < PP2_MAX_NUM_USED_INTERRUPTS; cpu_slot_id++)
    {
      /* Configure Group/Subgroup */
      port->saved_rx_isr[cpu_slot_id] = pp2_port_isr_rx_group_read (port, cpu_slot_id);
      pp2_port_isr_rx_group_write (port, cpu_slot_id, 0, 0);

      cpu_slot = port->parent->hw.base[cpu_slot_id].va;

      /* Configure RX Exceptions Interrupt Mask */
      pp2_reg_write (cpu_slot, MVPP2_RX_EX_INT_CAUSE_MASK_REG (pp2_port_id (port)), 0);
    }
}

static void
pp2_port_egress_disable_qmask (struct pp2_port *port, uint32_t q_mask)
{
  volatile u32 tmo;
  u32 val = 0;
  u32 tx_port_num = MVPP2_MAX_TCONT + pp2_port_id (port);
  uintptr_t cpu_slot = port->cpu_slot;

  /* Issue stop command for active channels only */
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  if (q_mask)
    pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_Q_CMD_REG, q_mask << MVPP2_TXP_SCHED_DISQ_OFFSET);

  /* TXQs disable. Wait for all Tx activity to terminate. */
  tmo = 0;
  do
    {
      if (tmo >= MVPP2_TX_DISABLE_TIMEOUT_MSEC)
	{
	  pr_warn ("Port: Egress disable timeout = 0x%08X\n", val);
	  break;
	}
      /* Sleep for 1 millisecond */
      usleep_range (1000, 2000);
      tmo++;
      val = pp2_reg_read (cpu_slot, MVPP2_TXP_SCHED_Q_CMD_REG);
    }
  while (val & q_mask);
}

static void
pp2_port_egress_enable_qmask (struct pp2_port *port, uint32_t q_mask)
{
  u32 tx_port_num = MVPP2_MAX_TCONT + pp2_port_id (port);
  uintptr_t cpu_slot = port->cpu_slot;

  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_Q_CMD_REG, q_mask);
  pr_debug ("Port: Egress enable tx_port_num=%u q_mask=0x%X\n", tx_port_num, q_mask);
}

static void
pp2_port_interrupts_disable (struct pp2_port *port)
{
  u32 mask = 0;
  uintptr_t cpu_slot = port->cpu_slot;

  mask = pp2_hif_map_get ();

  pp2_reg_write (cpu_slot, MVPP2_ISR_ENABLE_REG (pp2_port_id (port)),
		 MVPP2_ISR_DISABLE_INTERRUPT (mask));
}

static void
pp2_port_rxqs_deinit (struct pp2_port *port)
{
  int queue;

  if (NOT_LPBK_PORT (port))
    {
      pp2_port_restore_fc_isr (port);
      pp2_port_rxqs_fc_state_reset (port);
    }

  for (queue = 0; queue < port->num_rx_queues; queue++)
    pp2_rxq_deinit (port, port->rxqs[queue]);
}

static void
pp2_port_rxqs_destroy (struct pp2_port *port)
{
  u32 qid;

  for (qid = 0; qid < port->num_rx_queues; qid++)
    {
      struct pp2_rx_queue *rxq = port->rxqs[qid];

      vnet_dev_dma_mem_free (vlib_get_main (), port->dev_port->dev, rxq->desc_virt_arr);
      if (rxq)
	clib_mem_free (rxq);
    }
}

static void
pp2_port_rxqs_fc_state_reset (struct pp2_port *port)
{
  int cm3_state, queue;
  u32 val;
  uintptr_t base = port->parent->hw.cm3_base.va;

  /* Remove Flow control enable bit to prevent race between FW and Kernel
   * If Flow control were enabled, it would be re-enabled.
   */
  val = cm3_read (base, MSS_CP_FC_COM_REG);
  cm3_state = (val & FLOW_CONTROL_ENABLE_BIT);
  val &= ~FLOW_CONTROL_ENABLE_BIT;
  cm3_write (base, MSS_CP_FC_COM_REG, val);

  /* Set RXQs Flow control */
  for (queue = 0; queue < PP2_PPIO_MAX_NUM_INQS; queue++)
    {
      struct pp2_rx_queue *rxq = port->rxqs[queue];

      if (!(BIT (queue) & port->rxq_flow_cntrl_mask))
	continue;

      /* Clear stop and start Flow control RXQ thresholds */
      cm3_write (base, MSS_CP_CM3_RXQ_TRESH_REG (rxq->id), 0);
      cm3_write (base, MSS_CP_CM3_RXQ_ASS_REG (rxq->id), 0);
    }

  /* Notify Firmware that Flow control config space ready for update */
  val = cm3_read (base, MSS_CP_FC_COM_REG);
  val |= FLOW_CONTROL_UPD_COM_BIT;
  val |= cm3_state;
  cm3_write (base, MSS_CP_FC_COM_REG, val);
}

static void
pp2_port_txqs_deinit (struct pp2_port *port)
{
  u32 j;
  struct pp2_tx_queue *txq;
  u32 queue;
  u32 val;
  uintptr_t cpu_slot;

  cpu_slot = port->cpu_slot;

  val = pp2_reg_read (cpu_slot, MVPP2_TX_PORT_FLUSH_REG);

  /* Reset Tx ports and clear Tx queues */
  val |= MVPP2_TX_PORT_FLUSH_MASK (pp2_port_id (port));
  pp2_reg_write (cpu_slot, MVPP2_TX_PORT_FLUSH_REG, val);

  for (queue = 0; queue < port->num_tx_queues; queue++)
    {
      txq = port->txqs[queue];
      /* Disable and flush Tx queue */
      pp2_port_set_outq_state (port, txq, false);
      pp2_txq_deinit (port, txq);

      /* Lastly, clear all ETH_TXQS for all previous DM-IFs */
      for (j = 0; j < PP2_NUM_REGSPACES; j++)
	{
	  struct pp2_hw *hw = &port->parent->hw;

	  cpu_slot = hw->base[j].va;
	  pp2_reg_read (cpu_slot, MVPP22_TXQ_SENT_REG (txq->id));
	}
    }
  /* Switch to default slot */
  cpu_slot = port->cpu_slot;

  val &= ~MVPP2_TX_PORT_FLUSH_MASK (pp2_port_id (port));
  pp2_reg_write (cpu_slot, MVPP2_TX_PORT_FLUSH_REG, val);
}

static void
pp2_port_txqs_destroy (struct pp2_port *port)
{
  u32 qid;

  for (qid = 0; qid < port->num_tx_queues; qid++)
    {
      struct pp2_tx_queue *txq = port->txqs[qid];

      if (LPBK_PORT (port))
	vlib_physmem_free (vlib_get_main (), txq->desc_virt_arr);
      else
	vnet_dev_dma_mem_free (vlib_get_main (), port->dev_port->dev, txq->desc_virt_arr);
      if (txq)
	clib_mem_free (txq);
    }
}

static void
pp2_port_txsched_set_mtu (struct pp2_port *port)
{
  u32 val, mtu;
  u32 tx_port_num;
  uintptr_t cpu_slot = port->cpu_slot;

  mtu = (pp2_port_mtu (port) + ETH_HLEN) * 8;

  /* WA for wrong Token bucket update: Set MTU value = 3*real MTU value */
  mtu = 3 * mtu;

  if (mtu > MVPP2_TXP_MTU_MAX)
    mtu = MVPP2_TXP_MTU_MAX;

  /* Indirect access to registers */
  tx_port_num = MVPP2_TX_PORT_NUM (pp2_port_id (port));
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);

  /* Set MTU */
  val = pp2_reg_read (cpu_slot, MVPP2_TXP_SCHED_MTU_REG);
  val &= ~MVPP2_TXP_MTU_MAX;
  val |= mtu;
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_MTU_REG, val);
}

static int
pp2_rss_musdk_map_get (struct pp2_port *port)
{
  u16 req_tbls = 0, used_tbls, avail_tbls;
  int i, idx, req_ind[MVPP22_RSS_TBL_NUM] = { 0 };
  struct pp2_inst *inst = port->parent;
  int hw_tbl;
#ifdef DEBUG
  u16 num_in_q;
#endif

  used_tbls = pp2_cls_db_rss_kernel_rsvd_tbl_get (inst) + pp2_cls_db_rss_num_musdk_tbl_get (inst);
  avail_tbls = MVPP22_RSS_TBL_NUM - used_tbls;

  /* Calculate number of TC's which require RSS */
  for (i = 0; i < port->num_tcs; i++)
    {
      if (port->tc[i].tc_config.num_in_qs == 1)
	continue;

      hw_tbl = pp2_cls_db_rss_get_hw_tbl_from_in_q (inst, port->tc[i].tc_config.num_in_qs);
      /* New hw_tbl required for this TC */
      if (hw_tbl < 0)
	{
	  if (req_tbls >= avail_tbls)
	    {
	      pr_err ("%s:Out of RSS tables\n", __func__);
	      goto rollback;
	    }
	  /* entry in rss_tbl_map is empty. Fill dB with new values */
	  idx = pp2_cls_db_rss_tbl_map_get_next_free_idx (inst);
	  if (idx == MVPP22_RSS_TBL_NUM)
	    {
	      /* This should never happen */
	      pr_err ("%s: Unable to allocate new RSS table\n", __func__);
	      goto rollback;
	    }
	  pp2_cls_db_rss_tbl_map_set (inst, idx, pp2_cls_db_rss_kernel_rsvd_tbl_get (inst) + idx,
				      port->tc[i].tc_config.num_in_qs);
	  req_ind[req_tbls] = idx;
	  req_tbls++;
#ifdef DEBUG
	  pp2_cls_db_rss_tbl_map_get (inst, idx, &hw_tbl, &num_in_q);
	  pr_debug ("%s: rss_db_ind:%d, rss_hw_tbl_id:%d, num_in_q:%d\n", __func__, idx, hw_tbl,
		    num_in_q);
#endif
	}
    }

  pp2_cls_db_rss_num_musdk_tbl_set (inst, (used_tbls + req_tbls));

  return 0;
rollback:
  for (i = 0; i < req_tbls; i++)
    pp2_cls_db_rss_tbl_map_set (inst, req_ind[i], 0, 0);
  return -ENOSPC;
}

static void
pp2_rxq_init (struct pp2_port *port, struct pp2_rx_queue *rxq)
{
  void *desc_mem;
  u32 val;
  uintptr_t cpu_slot;
  struct pp2_tc *tc;

  cpu_slot = port->cpu_slot;

  if (vnet_dev_dma_mem_alloc (vlib_get_main (), port->dev_port->dev,
			      rxq->desc_total * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN,
			      &desc_mem) != VNET_DEV_OK)
    {
      pr_err ("PP: cannot allocate ingress descriptor array\n");
      return;
    }
  rxq->desc_virt_arr = desc_mem;
  rxq->desc_phys_arr =
    vnet_dev_get_dma_addr (vlib_get_main (), port->dev_port->dev, rxq->desc_virt_arr);
  if (!IS_ALIGNED (rxq->desc_phys_arr, MVPP2_DESC_Q_ALIGN))
    {
      pr_err ("PP: ingress descriptor array must be %u-byte aligned\n", MVPP2_DESC_Q_ALIGN);
      vnet_dev_dma_mem_free (vlib_get_main (), port->dev_port->dev, rxq->desc_virt_arr);
      return;
    }
  pr_debug ("port[%d:%d] rxq[%d], desc_phys_addr(0x%lx)\n", port->parent->id, pp2_port_id (port),
	    rxq->id, rxq->desc_phys_arr);

  /* Zero occupied and non-occupied counters - direct access */
  pp2_reg_write (cpu_slot, MVPP2_RXQ_STATUS_REG (rxq->id), 0x0);

  /* Set Rx descriptors queue starting address - indirect access */
  pp2_reg_write (cpu_slot, MVPP2_RXQ_NUM_REG, rxq->id);

  pp2_reg_write (cpu_slot, MVPP2_RXQ_DESC_ADDR_REG, (rxq->desc_phys_arr >> MVPP22_DESC_ADDR_SHIFT));
  pp2_reg_write (cpu_slot, MVPP2_RXQ_DESC_SIZE_REG, rxq->desc_total);
  pp2_reg_write (cpu_slot, MVPP2_RXQ_INDEX_REG, 0x0);

  tc = pp2_rxq_tc_get (port, rxq->id);
  if (!tc)
    {
      pr_err ("port(%d) phy_rxq(%d), not found in tc range\n", pp2_port_id (port), rxq->id);
      return;
    }
  /* Set Offset */
  pp2_rxq_offset_set (port, rxq->id, tc->tc_config.pkt_offset);

  pp2_bm_pool_assign (port, rxq->bm_pool_id[BM_TYPE_SHORT_BUF_POOL], rxq->id,
		      BM_TYPE_SHORT_BUF_POOL);
  pp2_bm_pool_assign (port, rxq->bm_pool_id[BM_TYPE_LONG_BUF_POOL], rxq->id, BM_TYPE_LONG_BUF_POOL);
  pr_debug ("port[%d:%d] rxq[%d], short_pool(%d), long_pool(%d)\n", port->parent->id,
	    pp2_port_id (port), rxq->id, rxq->bm_pool_id[BM_TYPE_SHORT_BUF_POOL],
	    rxq->bm_pool_id[BM_TYPE_LONG_BUF_POOL]);

  /* Add number of descriptors ready for receiving packets */
  val = (0 | (rxq->desc_total << MVPP2_RXQ_NUM_NEW_OFFSET));
  pp2_reg_write (cpu_slot, MVPP2_RXQ_STATUS_UPDATE_REG (rxq->id), val);
}

static uint32_t
pp2_txq_pend_desc_num_get (struct pp2_port *port, struct pp2_tx_queue *txq)
{
  u32 val;
  uintptr_t cpu_slot = port->cpu_slot;

  pp2_reg_write (cpu_slot, MVPP2_TXQ_NUM_REG, txq->id);
  val = pp2_reg_read (cpu_slot, MVPP2_TXQ_PENDING_REG);

  return val & MVPP2_TXQ_PENDING_MASK;
}

static int
pp2_txsched_queue_arbitration_set (struct pp2_port *port, u8 txq,
				   enum pp2_ppio_outq_sched_mode mode, u8 weight)
{
  if (mode == PP2_PPIO_SCHED_M_WRR)
    return pp2_txsched_queue_wrr_set (port, txq, weight);

  if (mode == PP2_PPIO_SCHED_M_SP)
    return pp2_txsched_queue_fixed_prio_set (port, txq);

  pr_err ("%s Error: Invalid egress arbitration mode on p%dq%d: %d.\n", __func__,
	  pp2_port_id (port), txq, (int) mode);

  return -EINVAL;
}

static void
pp2_txsched_remap_weights (struct pp2_port *port, u8 remapped_weights[])
{
  u32 hw_min, user_min = 0xff, user_max = 0x0;
  u8 txq;
  u32 mtu;
  int txPortNum;
  int accommodating_dynamic_range; /* Can user requested range be met after MTU restriction */

  txPortNum = MVPP2_TX_PORT_NUM (pp2_port_id (port));
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, txPortNum);

  /* Weight * 256 bytes * 8 bits must be larger then MTU [bits] */
  mtu = pp2_reg_read (port->cpu_slot, MVPP2_TXP_SCHED_MTU_REG);
  mtu /= PP2_AMPLIFY_FACTOR_MTU;
  mtu /= BITS_PER_BYTE; /* move to bytes */
  mtu = ALIGN (mtu, PP2_WRR_WEIGHT_UNIT);
  hw_min = mtu / PP2_WRR_WEIGHT_UNIT;

  for (txq = 0; txq < port->num_tx_queues; txq++)
    {

      if (port->txq_config[txq].sched_mode == PP2_PPIO_SCHED_M_WRR)
	{

	  if (port->txq_config[txq].weight == 0)
	    port->txq_config[txq].weight = 1;

	  if (port->txq_config[txq].weight > user_max)
	    user_max = port->txq_config[txq].weight;

	  if (port->txq_config[txq].weight < user_min)
	    user_min = port->txq_config[txq].weight;
	}
    }

  if (user_min > user_max) /* WRR unused */
    return;

  if ((user_max / user_min) < (MVPP2_TXQ_WRR_WEIGHT_MAX / hw_min))
    accommodating_dynamic_range = 1;
  else
    accommodating_dynamic_range = 0;

  for (txq = 0; txq < port->num_tx_queues; txq++)
    {

      if (port->txq_config[txq].sched_mode == PP2_PPIO_SCHED_M_WRR)
	{

	  if (accommodating_dynamic_range)
	    remapped_weights[txq] = port->txq_config[txq].weight * hw_min / user_min;
	  else
	    remapped_weights[txq] = pp2_txsched_rational_weight_remap (
	      port->txq_config[txq].weight, hw_min, MVPP2_TXQ_WRR_WEIGHT_MAX);
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
mv_netdev_set_feature_ioctl (int fd, struct ifreq *ifr, int bit, int val)
{
  struct
  {
    struct ethtool_sfeatures sf;
    struct ethtool_set_features_block blk[2];
  } cmd = { 0 };
  int word = bit / 32;
  int sbit = bit % 32;
  int ret;

  cmd.sf.cmd = ETHTOOL_SFEATURES;
  cmd.sf.size = 2;

  ifr->ifr_data = &cmd;

  cmd.blk[word].valid |= 1 << sbit;
  cmd.blk[word].requested = val << sbit;

  ret = ioctl (fd, SIOCETHTOOL, ifr);
  if (ret)
    {
      if (ret < 0)
	pr_err ("Error setting bit (%s)\n", strerror (errno));
      else
	pr_err ("Error setting bit (%d)\n", ret);
      return -1;
    }

  return 0;
}

static int
mv_pp2x_cls_c2_qos_tbl_fill_array (struct pp2_port *port, u8 tbl_sel, uint8_t tc_values[])
{
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
      queue = port->tc[tc_values[pri]].tc_config.first_rxq;
      color = port->tc[tc_values[pri]].tc_config.default_color;
      pr_debug ("tc_val[%d] %d, queue %d, color %d\n", pri, tc_values[pri], queue, (int) color);

      rc = mv_pp2x_cls_c2_qos_queue_set (&qos_entry, queue);
      if (rc)
	{
	  pr_err ("mv_pp2x_cls_c2_qos_queue_set failed\n");
	  return -EFAULT;
	}

      mv_pp2x_cls_c2_qos_color_set (&qos_entry, color);
      if (rc)
	{
	  pr_info ("mv_pp2x_cls_c2_qos_color_set failed\n");
	  return -EFAULT;
	}

      rc = mv_pp2x_cls_c2_qos_hw_write (&port->parent->hw, &qos_entry);
      if (rc)
	{
	  pr_err ("mv_pp2x_cls_c2_qos_hw_write failed\n");
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
pp2_cls_db_rss_get_hw_tbl_from_in_q (struct pp2_inst *inst, u8 num_in_q)
{
  int i;

  for (i = 0; i < MVPP22_RSS_TBL_NUM; i++)
    {
      pr_debug ("%d num_in_q %d, %d\n", i, inst->cls_db->rss_db.rss_tbl_map[i].num_in_q, num_in_q);
      if (inst->cls_db->rss_db.rss_tbl_map[i].num_in_q == num_in_q)
	return inst->cls_db->rss_db.rss_tbl_map[i].hw_tbl;
    }

  return -1;
}

static u16
pp2_cls_db_rss_kernel_rsvd_tbl_get (struct pp2_inst *inst)
{
  return inst->cls_db->rss_db.num_kernel_rsrvd_tbls;
}

static u16
pp2_cls_db_rss_num_musdk_tbl_get (struct pp2_inst *inst)
{
  return inst->cls_db->rss_db.num_musdk_tbls;
}

static void
pp2_cls_db_rss_num_musdk_tbl_set (struct pp2_inst *inst, u16 num_musdk_tbl)
{
  inst->cls_db->rss_db.num_musdk_tbls = num_musdk_tbl;
}

static int
pp2_cls_db_rss_tbl_map_get_next_free_idx (struct pp2_inst *inst)
{
  int i;

  for (i = 0; i < MVPP22_RSS_TBL_NUM; i++)
    {
      if (inst->cls_db->rss_db.rss_tbl_map[i].num_in_q == 0)
	return i;
    }

  return i;
}

static int
pp2_cls_db_rss_tbl_map_set (struct pp2_inst *inst, u16 idx, u16 hw_tbl, u16 num_in_q)
{
  if (idx > MVPP22_RSS_TBL_NUM)
    return -EINVAL;

  if (hw_tbl > MVPP22_RSS_TBL_NUM)
    return -EINVAL;

  inst->cls_db->rss_db.rss_tbl_map[idx].hw_tbl = hw_tbl;
  inst->cls_db->rss_db.rss_tbl_map[idx].num_in_q = num_in_q;

  return 0;
}

static inline uint32_t
pp2_gop_gmac_read (struct gop_hw *gop, int mac_num, uint32_t offset)
{
  return (pp2_gop_gen_read (gop->gmac.base.va, mac_num * gop->gmac.obj_size + offset));
}

static inline void
pp2_gop_gmac_write (struct gop_hw *gop, int mac_num, u32 offset, uint32_t data)
{
  pp2_gop_gen_write (gop->gmac.base.va, mac_num * gop->gmac.obj_size + offset, data);
}

static inline uint32_t
pp2_gop_xlg_mac_read (struct gop_hw *gop, int mac_num, uint32_t offset)
{
  return (pp2_gop_gen_read (gop->xlg_mac.base.va, mac_num * gop->xlg_mac.obj_size + offset));
}

static inline void
pp2_gop_xlg_mac_write (struct gop_hw *gop, int mac_num, u32 offset, uint32_t data)
{
  pp2_gop_gen_write (gop->xlg_mac.base.va, mac_num * gop->xlg_mac.obj_size + offset, data);
}

static inline u16
pp2_hif_map_get (void)
{
  return pp2_ptr->pp2_common.hif_slot_map;
}

static inline u32
pp2_port_isr_rx_group_read (struct pp2_port *port, int sub_group)
{
  int val;
  uintptr_t cpu_slot = port->cpu_slot;

  val = (pp2_port_id (port) << MVPP22_ISR_RXQ_GROUP_INDEX_GROUP_OFFSET) | sub_group;
  pp2_reg_write (cpu_slot, MVPP22_ISR_RXQ_GROUP_INDEX_REG, val);

  return pp2_reg_read (cpu_slot, MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG);
}

static inline void
pp2_port_isr_rx_group_write (struct pp2_port *port, int sub_group, int start_queue,
			     int num_rx_queues)
{
  int val;
  uintptr_t cpu_slot = port->cpu_slot;

  val = (pp2_port_id (port) << MVPP22_ISR_RXQ_GROUP_INDEX_GROUP_OFFSET) | sub_group;
  pp2_reg_write (cpu_slot, MVPP22_ISR_RXQ_GROUP_INDEX_REG, val);

  val = (num_rx_queues << MVPP22_ISR_RXQ_SUB_GROUP_SIZE_OFFSET) | start_queue;

  pp2_reg_write (cpu_slot, MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG, val);
}

static void
pp2_port_restore_fc_isr (struct pp2_port *port)
{
  int cpu_slot_id, start_queue, num_rx_queues;

  for (cpu_slot_id = 0; cpu_slot_id < PP2_MAX_NUM_USED_INTERRUPTS; cpu_slot_id++)
    {
      /* Configure Group/Subgroup */
      start_queue = port->saved_rx_isr[cpu_slot_id] & MVPP22_ISR_RXQ_SUB_GROUP_STARTQ_MASK;
      num_rx_queues = (port->saved_rx_isr[cpu_slot_id] & MVPP22_ISR_RXQ_SUB_GROUP_SIZE_MASK) >>
		      MVPP22_ISR_RXQ_SUB_GROUP_SIZE_OFFSET;

      pp2_port_isr_rx_group_write (port, cpu_slot_id, start_queue, num_rx_queues);
    }
}

static void
pp2_rxq_deinit (struct pp2_port *port, struct pp2_rx_queue *rxq)
{
  uintptr_t cpu_slot = port->cpu_slot;

  pp2_rxq_resid_pkts (port, rxq);

  /* Clear Rx descriptors queue starting address and size;
   * free descriptor number
   */
  pp2_reg_write (cpu_slot, MVPP2_RXQ_STATUS_REG (rxq->id), 0);
  pp2_reg_write (cpu_slot, MVPP2_RXQ_NUM_REG, rxq->id);
  pp2_reg_write (cpu_slot, MVPP2_RXQ_DESC_ADDR_REG, 0);
  pp2_reg_write (cpu_slot, MVPP2_RXQ_DESC_SIZE_REG, 0);
}

static void
pp2_rxq_offset_set (struct pp2_port *port, int prxq, int offset)
{
  u32 val;
  uintptr_t cpu_slot = port->cpu_slot;

  /* Convert offset from bytes to units of 32 bytes */
  offset = offset >> 5;

  val = pp2_reg_read (cpu_slot, MVPP2_RXQ_CONFIG_REG (prxq));
  val &= ~MVPP2_RXQ_PACKET_OFFSET_MASK;

  /* Offset is in */
  val |= ((offset << MVPP2_RXQ_PACKET_OFFSET_OFFS) & MVPP2_RXQ_PACKET_OFFSET_MASK);

  pp2_reg_write (cpu_slot, MVPP2_RXQ_CONFIG_REG (prxq), val);
}

static struct pp2_tc *
pp2_rxq_tc_get (struct pp2_port *port, uint32_t id)
{
  u8 i;

  for (i = 0; i < port->num_tcs; i++)
    {
      u8 first_rxq = port->tc[i].tc_config.first_rxq;

      if (id >= first_rxq && id < (first_rxq + port->tc[i].tc_config.num_in_qs))
	return &port->tc[i];
    }
  return NULL;
}

static void
pp2_txq_deinit (struct pp2_port *port, struct pp2_tx_queue *txq)
{
  uintptr_t cpu_slot = port->cpu_slot;

  /* Set minimum bandwidth for disabled TXQs */
  pp2_reg_write (cpu_slot, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (txq->id), 0);

  /* Set Tx descriptors queue starting address and size */
  pp2_reg_write (cpu_slot, MVPP2_TXQ_NUM_REG, txq->id);
  pp2_reg_write (cpu_slot, MVPP2_TXQ_DESC_ADDR_LOW_REG, 0);
  pp2_reg_write (cpu_slot, MVPP2_TXQ_DESC_SIZE_REG, 0);
}

static int
pp2_txsched_queue_fixed_prio_set (struct pp2_port *port, u8 txq)
{
  u32 regVal;
  int txPortNum;

  txPortNum = MVPP2_TX_PORT_NUM (pp2_port_id (port));
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, txPortNum);

  regVal = pp2_reg_read (port->cpu_slot, MVPP2_TXP_SCHED_FIXED_PRIO_REG);
  regVal |= (1 << txq);
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_FIXED_PRIO_REG, regVal);

  return 0;
}

static int
pp2_txsched_queue_wrr_set (struct pp2_port *port, u8 txq, u8 weight)
{
  u32 regVal;
  int txPortNum;

  txPortNum = MVPP2_TX_PORT_NUM (pp2_port_id (port));
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, txPortNum);

  regVal = pp2_reg_read (port->cpu_slot, MVPP2_TXQ_SCHED_WRR_REG (txq));

  regVal &= ~MVPP2_TXQ_WRR_WEIGHT_ALL_MASK;
  regVal |= MVPP2_TXQ_WRR_WEIGHT_MASK (weight);
  pp2_reg_write (port->cpu_slot, MVPP2_TXQ_SCHED_WRR_REG (txq), regVal);

  regVal = pp2_reg_read (port->cpu_slot, MVPP2_TXP_SCHED_FIXED_PRIO_REG);
  regVal &= ~(1 << txq);
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_FIXED_PRIO_REG, regVal);

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
mv_pp2x_cls_c2_qos_color_set (struct mv_pp2x_cls_c2_qos_entry *qos, int color)
{
  if (mv_pp2x_ptr_validate (qos) == MV_ERROR)
    return MV_ERROR;

  qos->data &= ~MVPP2_CLS2_QOS_TBL_COLOR_MASK;
  qos->data |= color << MVPP2_CLS2_QOS_TBL_COLOR_OFF;

  return 0;
}

static int
mv_pp2x_cls_c2_qos_hw_write (struct pp2_hw *hw, struct mv_pp2x_cls_c2_qos_entry *qos)
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
  pp2_reg_write (hw->base[0].va, MVPP2_CLS2_DSCP_PRI_INDEX_REG, reg_val);

  /* write data reg */
  pp2_reg_write (hw->base[0].va, MVPP2_CLS2_QOS_TBL_REG, qos->data);

  return 0;
}

static int
mv_pp2x_cls_c2_qos_queue_set (struct mv_pp2x_cls_c2_qos_entry *qos, uint8_t queue)
{
  if (!qos || queue >= (1 << MVPP2_CLS2_QOS_TBL_QUEUENUM_BITS))
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
  uintptr_t reg_ptr = base + offset;
  u32 val;

  val = readl ((void *) reg_ptr);
  return val;
}

static inline void
pp2_gop_gen_write (uintptr_t base, uint32_t offset, uint32_t data)
{
  uintptr_t reg_ptr = base + offset;

  writel (data, (void *) reg_ptr);
}

static void
pp2_rxq_resid_pkts (struct pp2_port *port, struct pp2_rx_queue *rxq)
{
  u32 rx_resid = pp2_rxq_received (port, rxq->id);

  if (!rx_resid)
    return;

  pr_warn ("RXQ has %u residual packets\n", rx_resid);

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
mv_pp2x_cls_c2_hw_read (uintptr_t cpu_slot, int index, struct mv_pp2x_cls_c2_entry *c2)
{
  unsigned int reg_val = 0;
  int tcm_idx;

  if (mv_pp2x_ptr_validate (c2) == MV_ERROR)
    return MV_ERROR;

  c2->index = index;

  /* write index reg */
  pp2_reg_write (cpu_slot, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* read invalid bit */
  reg_val = pp2_reg_read (cpu_slot, MVPP2_CLS2_TCAM_INV_REG);

  c2->inv = (reg_val & MVPP2_CLS2_TCAM_INV_INVALID_MASK) >> MVPP2_CLS2_TCAM_INV_INVALID_OFF;

  if (c2->inv)
    return 0;

  for (tcm_idx = 0; tcm_idx < MVPP2_CLS_C2_TCAM_WORDS; tcm_idx++)
    c2->tcam.words[tcm_idx] = pp2_reg_read (cpu_slot, MVPP2_CLS2_TCAM_DATA_REG (tcm_idx));

  c2->sram.regs.action_tbl = pp2_reg_read (cpu_slot, MVPP2_CLS2_ACT_DATA_REG);
  c2->sram.regs.actions = pp2_reg_read (cpu_slot, MVPP2_CLS2_ACT_REG);
  c2->sram.regs.qos_attr = pp2_reg_read (cpu_slot, MVPP2_CLS2_ACT_QOS_ATTR_REG);
  c2->sram.regs.hwf_attr = pp2_reg_read (cpu_slot, MVPP2_CLS2_ACT_HWF_ATTR_REG);
  c2->sram.regs.rss_attr = pp2_reg_read (cpu_slot, MVPP2_CLS2_ACT_DUP_ATTR_REG);
  c2->sram.regs.seq_attr = pp2_reg_read (cpu_slot, MVPP21_CLS2_ACT_SEQ_ATTR_REG);

  return 0;
}

u8
pp2_cls_c2_tcam_port_get (struct mv_pp2x_cls_c2_entry *c2)
{
  return ((c2->tcam.words[4] >> 8) & 0xFF);
}

int
mv_pp2x_cls_c2_hw_write (uintptr_t cpu_slot, int index, struct mv_pp2x_cls_c2_entry *c2)
{
  int tcm_idx;

  if (!c2 || index >= MVPP2_CLS_C2_TCAM_SIZE)
    return -EINVAL;

  c2->index = index;

  /* write index reg */
  pp2_reg_write (cpu_slot, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* write valid bit */
  c2->inv = 0;
  pp2_reg_write (cpu_slot, MVPP2_CLS2_TCAM_INV_REG, ((c2->inv) << MVPP2_CLS2_TCAM_INV_INVALID_OFF));

  for (tcm_idx = 0; tcm_idx < MVPP2_CLS_C2_TCAM_WORDS; tcm_idx++)
    pp2_reg_write (cpu_slot, MVPP2_CLS2_TCAM_DATA_REG (tcm_idx), c2->tcam.words[tcm_idx]);

  /* write action_tbl CLSC2_ACT_DATA */
  pp2_reg_write (cpu_slot, MVPP2_CLS2_ACT_DATA_REG, c2->sram.regs.action_tbl);

  /* write actions CLSC2_ACT */
  pp2_reg_write (cpu_slot, MVPP2_CLS2_ACT_REG, c2->sram.regs.actions);

  /* write qos_attr CLSC2_ATTR0 */
  pp2_reg_write (cpu_slot, MVPP2_CLS2_ACT_QOS_ATTR_REG, c2->sram.regs.qos_attr);

  /* write hwf_attr CLSC2_ATTR1 */
  pp2_reg_write (cpu_slot, MVPP2_CLS2_ACT_HWF_ATTR_REG, c2->sram.regs.hwf_attr);

  /* write rss_attr CLSC2_ATTR2 */
  pp2_reg_write (cpu_slot, MVPP2_CLS2_ACT_DUP_ATTR_REG, c2->sram.regs.rss_attr);

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
pp2_gop_gmac_link_status (struct gop_hw *gop, int mac_num, struct pp2_port_link_status *pstatus)
{
  u32 reg_val;

  reg_val = pp2_gop_gmac_read (gop, mac_num, PP2_GMAC_PORT_STATUS0_REG);

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
pp2_gop_xlg_mac_link_status (struct gop_hw *gop, int mac_num, struct pp2_port_link_status *pstatus)
{
  u32 reg_val;
  u32 mac_mode;
  u32 fc_en;

  reg_val = pp2_gop_xlg_mac_read (gop, mac_num, PP2_XLG_PORT_MAC_CTRL3_REG);
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
  reg_val = pp2_gop_xlg_mac_read (gop, mac_num, PP2_XLG_MAC_PORT_STATUS_REG);
  if (reg_val & PP2_XLG_MAC_PORT_STATUS_LINKSTATUS_MASK)
    pstatus->linkup = 1 /*TRUE*/;
  else
    pstatus->linkup = 0 /*FALSE*/;

  /* flow control status */
  fc_en = pp2_gop_xlg_mac_read (gop, mac_num, PP2_XLG_PORT_MAC_CTRL0_REG);
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

static int
pp2_port_remove_vlan (struct pp2_port *port, u16 vlan)
{
  int rc, vidx, vbit;
  char buf[PP2_MAX_BUF_STR_LEN];

  if (vlan >= 4095)
    {
      pr_err ("invalid vid (%d). Range: 0:4094\n", vlan);
      return -EINVAL;
    }

  if (port->num_vlans == 0)
    {
      pr_err ("no vlans configured\n");
      return -EINVAL;
    }

  /* build manually the system command */
  /* [TODO] check other alternatives for setting vlan id */
  sprintf (buf, "ip link delete %s.%d", port->linux_name, vlan);
  rc = system (buf);
  if (rc != 0)
    {
      pr_err ("remove vlan operation failed\n");
      return rc;
    }

  vidx = vlan / 64;
  vbit = vlan % 64;
  port->vlan_ids[vidx] &= ~(UINT64_C (1) << vbit);

  port->num_vlans--;
  return 0;
}

static void
pp2_port_mac_set_loopback (struct pp2_port *port, int en)
{
  struct gop_hw *gop = &port->parent->hw.gop;
  int mac_num = port->mac_data.gop_index;
  enum pp2_lb_type lb = (en) ? PP2_TX_2_RX_LB : PP2_DISABLE_LB;
  uint32_t pp2_version;

  /* GOP#0 and GOP#2 (In PP23/CP115) can support both XLG and GMAC;
   * MUSDK cannot know that on the fly so always configure both of them;
   * All the rest support only GMAC
   */
  pp2_version = pp2_reg_read (port->cpu_slot, MVPP2_VER_ID_REG);
  pp2_gop_gmac_loopback_cfg (gop, mac_num, lb);
  if ((mac_num == 0) || ((mac_num == 2) && (pp2_version == MVPP2_VER_PP23)))
    pp2_gop_xlg_mac_loopback_cfg (gop, mac_num, lb);
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
pp2_gop_gmac_loopback_cfg (struct gop_hw *gop, int mac_num, enum pp2_lb_type type)
{
  u32 reg_addr;
  u32 val;

  reg_addr = PP2_GMAC_PORT_CTRL1_REG;
  val = pp2_gop_gmac_read (gop, mac_num, reg_addr);
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
  pp2_gop_gmac_write (gop, mac_num, reg_addr, val);

  return 0;
}

int
pp2_gop_xlg_mac_loopback_cfg (struct gop_hw *gop, int mac_num, enum pp2_lb_type type)
{
  u32 reg_addr;
  u32 val;

  reg_addr = PP2_XLG_PORT_MAC_CTRL1_REG;
  val = pp2_gop_xlg_mac_read (gop, mac_num, reg_addr);
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
  pp2_gop_xlg_mac_write (gop, mac_num, reg_addr, val);
  return 0;
}
