/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Marvell.
 */

#include <stdint.h>
#include <assert.h>
#include <string.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <musdk.h>
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
#include <sys/utsname.h>
#include <sys/sysmacros.h>
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

static int sw_init_cnt_set;

#define ARP_PROTO	       0x806 /* Address Resolution packet	*/
#define CLS_MNG_RULES_SIZE_MAX 20    /* Max possible rules in CLS table */
#define MAX_OBJ_STRING	       20
#define MVPP2_CLS_DEF_RXQ      0
#define MVPP2_CLS_DEF_WAY      0
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

#define LPBK_PORT(x) ((x)->id == PP2_LOOPBACK_PORT)

#define mdelay(ms) usleep (ms * 1000)

#define MVPP2_C3_DEFAULT_SEARCH_DEPTH (3) /* default cuckoo search depth	*/

#define ACT_DUP_POLICER_MAX		  (31)
#define MVPP2_PLCR_BANK0_DEFAULT_ENTRY_ID (0)
#define MVPP2_POLICER_2_BANK(policer)	  (policer / (ACT_DUP_POLICER_MAX + 1))

#define NOT_LPBK_PORT(x) (!((x)->id == PP2_LOOPBACK_PORT))

#define PP2_BUFFER_OFFSET_GRAN (32)

#define PP2_ETHADDR_LEN (6)

#define PP2_MAX_PACKET_OFFSET (7 * 32)

#define PP2_NUM_PKT_PROC 4 /**< Maximum number of packet processors */

#define PP2_PACKET_DEF_OFFSET (L1_CACHE_LINE_BYTES)

#define PP2_PPIO_MIN_CBS 64

#define PP2_PPIO_MIN_CIR 100

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

#define MVPP2_CLS_DEF_FLOW_LEN 20

#define MVPP2_CLS_FREE_FL_LOG (0xFFFF) /* free flow rule value		*/

#define MVPP2_CLS_LOG2OFF_START (1) /* 1st entry is the free index	*/

#define MVPP2_CLS_UNDF_FL_LOG_ID (0) /* CLS undefined logical rule ID*/

#define MVPP2_PORT_BM_INV (0xFFFF) /* invalid port BM flag		*/

#define MVPP2_PORT_TYPE_INV (0xFFFF) /* invalid port type flag	*/

#define NOT_IN_USE (-1)

#define PP2_BPPE_UNIT_SIZE (8)

#define PP2_BUFFER_OFFSET (32)

#define MVPP2_CLS_FL_RND_SIZE (25) /* max rule hits per CLS round	*/

#define RND_HIT_CNT(cnt, r) (cnt[r].c2 + cnt[r].c3 + cnt[r].c4)

#define WAY_MAX (1)
#ifndef MKDEV
#define MKDEV(ma, mi) makedev ((ma), (mi))
#endif
#ifndef MAJOR
#define MAJOR(dev) major (dev)
#endif
#ifndef MINOR
#define MINOR(dev) minor (dev)
#endif

#ifdef MVCONF_PP2_LOCK
#ifdef MVCONF_PP2_LOCK_STAT
#define dm_spin_lock(dm_lock)                                                                      \
  do                                                                                               \
    {                                                                                              \
      int pre_locked = spin_trylock ((dm_lock)->lock);                                             \
      (dm_lock)->lock_fail_count += !!pre_locked;                                                  \
      (dm_lock)->lock_success_count += !pre_locked;                                                \
      if (pre_locked)                                                                              \
	spin_lock ((dm_lock)->lock);                                                               \
    }                                                                                              \
  while (0)
#else
#define dm_spin_lock(dm_lock) spin_lock ((dm_lock)->lock)
#endif /* MVCONF_PP2_LOCK_STAT */
#define dm_spin_unlock(dm_lock) spin_unlock ((dm_lock)->lock)
#else
#define dm_spin_lock(dm_lock)                                                                      \
  do                                                                                               \
    {                                                                                              \
    }                                                                                              \
  while (0)
#define dm_spin_unlock(dm_lock)                                                                    \
  do                                                                                               \
    {                                                                                              \
    }                                                                                              \
  while (0)
#endif /* #ifdef MVCONF_PP2_LOCK */

#define DM_TXD_SET_DEST_QID(desc, data)                                                            \
  ((desc)->cmds[1] = ((desc)->cmds[1] & ~TXD_DEST_QID_MASK) | (data << 8 & TXD_DEST_QID_MASK))

#define fls(n) ((sizeof (n) <= 4) ? fls_32 (n) : fls_64 (n))

#define HW_BYTE_OFFS(_offs_) (_offs_)

#define IS_ALIGNED(val, align) (((val) & ((typeof (val)) (align) - 1)) == 0)

#define likely(x) __builtin_expect (!!(x), 1)

#define IPV6_ADDR_SIZE		      (16)
#define MAC_ADDR_SIZE		      (6)
#define IPV4_ADDR_SIZE		      (4)
#define WORD_BYTES		      (4)
#define BYTE_MASK		      (0xFF)
#define MVPP2_MATCH_TTL		      0x1000000
#define MVPP2_MATCH_TCP_FLAG_RF	      0x2000000
#define MVPP2_MATCH_TCP_FLAG_S	      0x4000000
#define MVPP2_MATCH_MH		      0x8000000
#define MSS_CP_CM3_RXQ_ASS_OFFS	      4
#define MSS_CP_CM3_RXQ_ASS_PER_REG    4
#define MVPP2_C2_ENTRY_INVALID_IDX    MVPP2_C2_ENTRY_MAX
#define MVPP2_C2_LKP_TYPE_INVALID_PRI 0xFF
#define IN_USE			      (1)
#define DWORD_BITS_LEN		      (32)

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
#define MSS_CP_CM3_RXQ_TR_BASE	     0x200
#define MSS_CP_CM3_RXQ_TR_OFFS	     4
#define MVPP2_C3_INVALID_ENTRY_NUM   (0x1FFF) /* invalid C3 entry number	*/
#define MVPP2_C3_MAX_HASH_KEY_SIZE   (MVPP2_CLS_C3_EXT_HEK_WORDS * WORD_BYTES) /* max key size */
#define MVPP2_EDROP_BYPASS_THRESH_ID (0) /* "bypass" early-drop configuration */
#define MVPP2_MEMBER_NUM(array)	     ARRAY_SIZE (array)
#define MV_VLAN_PRIO_MASK	     0xe000 /* Priority Code Point */
#define MV_VLAN_PRIO_SHIFT	     13
#define MV_XT_DSCP_MAX		     0x3f /* 00111111 */

#define BITS_PER_BYTE			       (8)
#define BYTE_BITS			       (8)
#define CLS_MNG_KEY_SIZE_MAX		       37 /* Max possible size of HEK key */
#define CLS_UDF_FIELD_SIZE		       (4)
#define FEATSTRS_MAX			       64
#define GET_NUM_BYTES(field_size)	       (!!(field_size % BYTE_BITS) + field_size / BYTE_BITS)
#define in4_pton(src, srclen, dst, delim, end) inet_pton (AF_INET, src, dst)
#define in6_pton(src, srclen, dst, delim, end) inet_pton (AF_INET6, src, dst)
#define MSS_CP_CM3_RXQ_ASS_REG(queue)	       (MSS_CP_CM3_RXQ_ASS_BASE + MSS_CP_CM3_RXQ_ASS_PQ_BASE (queue))
#define MSS_CP_CM3_RXQ_TRESH_REG(queue)                                                            \
  (MSS_CP_CM3_RXQ_TR_BASE + ((queue) * MSS_CP_CM3_RXQ_TR_OFFS))
#define MV_DSCP_NUM	       (1 + MV_XT_DSCP_MAX)
#define MVPP2_CLS_DEF_SEQ_CTRL 0
#define MVPP2_MATCH_IPV4_5T                                                                        \
  (MVPP2_MATCH_IP_SRC | MVPP2_MATCH_IP_DST | MVPP2_MATCH_L4_DST | MVPP2_MATCH_L4_SRC |             \
   MVPP2_MATCH_IP_PROTO | MVPP2_MATCH_IPV4_PKT)
#define MVPP2_MATCH_IPV6_5T                                                                        \
  (MVPP2_MATCH_IP_SRC | MVPP2_MATCH_IP_DST | MVPP2_MATCH_L4_DST | MVPP2_MATCH_L4_SRC |             \
   MVPP2_MATCH_IP_PROTO | MVPP2_MATCH_IPV6_PKT)
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
#define QOS_LOG_PORT_TABLE_OFF(port_id)		(port_id + 4)
#define usleep_range(us, range)			usleep (us)

#define LIST_FOR_EACH_OBJECT(_pos, _type, _head, _member)                                          \
  for (_pos = LIST_OBJECT (LIST_FIRST (_head), _type, _member); &_pos->_member != (_head);         \
       _pos = LIST_OBJECT (LIST_FIRST (&_pos->_member), _type, _member))
#define LIST_FOR_EACH_OBJECT_REVERSE(_pos, _type, _head, _member)                                  \
  for (_pos = LIST_OBJECT (LIST_LAST (_head), _type, _member); &_pos->_member != (_head);          \
       _pos = LIST_OBJECT (LIST_LAST (&_pos->_member), _type, _member))
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

enum pp2_cls_field_match_t
{
  /* L2 */
  MVPP2_MATCH_ETH_DST = 0x000001,     /* Match Ethernet Destination Address */
  MVPP2_MATCH_ETH_SRC = 0x000002,     /* Match Ethernet Source Address */
  MVPP2_MATCH_VID_OUTER = 0x000004,   /* Match Outer VID */
  MVPP2_MATCH_PBITS_OUTER = 0x000008, /* Match Outer Pbits */
  MVPP2_MATCH_VID_INNER = 0x000010,   /* Match Inner VID */
  MVPP2_MATCH_PBITS_INNER = 0x000020, /* Match Inner Pbits */
  MVPP2_MATCH_ETH_TYPE = 0x000040,    /* Match Ethertype */

  /* PPPoE */
  MVPP2_MATCH_PPPOE_PROTO = 0x000080, /* Match PPPoE Protocol */
  MVPP2_MATCH_PPPOE_SES = 0x000100,   /* Match PPPoE SessionId */

  /* IPV4/V6 */
  MVPP2_MATCH_IPV4_PKT = 0x000200,	   /* Match IPv4 Packet, used together with other*/
					   /*  MVPP2_MATCH_IP_XX */
  MVPP2_MATCH_IPV6_PKT = 0x000400,	   /* Match IPv6 Packet, used together with other*/
					   /*  MVPP2_MATCH_IP_XX */
  MVPP2_MATCH_IP_SRC = 0x000800,	   /* Match IPV4/6 Source Address */
  MVPP2_MATCH_IP_DST = 0x001000,	   /* Match IPV4/6 Destination Address */
  MVPP2_MATCH_IP_DSCP = 0x002000,	   /* Match DSCP */
  MVPP2_MATCH_IPV6_FLBL = 0x004000,	   /* Match IPV6 Flow Label */
  MVPP2_MATCH_IP_PROTO = 0x008000,	   /* Match IPv4_Proto/IPv6_NH field */
  MVPP2_MATCH_IP_VERSION = 0x010000,	   /* Match IP version field */
  MVPP2_MATCH_L4_SRC = 0x020000,	   /* Match L4 Source Port (UDP or TCP) */
  MVPP2_MATCH_L4_DST = 0x040000,	   /* Match L4 Destination Port (UDP or TCP) */
  MVPP2_MATCH_IPV6_PREF = 0x080000,	   /* Match IPV6 address prefix */
  MVPP2_MATCH_IPV6_SUFF = 0x100000,	   /* Match IPV6 address profix */
  MVPP2_MATCH_ARP_TRGT_IP_ADDR = 0x200000, /* Match ARP TARGET IP ADDR */

  /* UDF */
  MVPP2_MATCH_UDF3 = 0x00400000, /* Match UDF3 */
  MVPP2_MATCH_UDF5 = 0x00800000, /* Match UDF5 */
  MVPP2_MATCH_UDF6 = 0x01000000, /* Match UDF6 */

  /*TPID and CFI*/
  MVPP2_MATCH_TPID_OUTER = 0x04000000, /* Match Outer TPID */
  MVPP2_MATCH_CFI_OUTER = 0x08000000,  /* Match Outer CFI */
  MVPP2_MATCH_TPID_INNER = 0x10000000, /* Match Inner TPID */
  MVPP2_MATCH_CFI_INNER = 0x20000000,  /* Match Inner CFI */

};

enum pp2_cls_cls_field_id_t
{
  MH_FIELD_ID = 0,
  GEM_PORT_ID_FIELD_ID = 1,
  MH_UNTAGGED_PRI_FIELD_ID = 2,
  MAC_DA_FIELD_ID = 3,
  MAC_SA_FIELD_ID = 4,
  OUT_VLAN_PRI_FIELD_ID = 5,
  OUT_VLAN_ID_FIELD_ID = 6,
  IN_VLAN_ID_FIELD_ID = 7,
  ETH_TYPE_FIELD_ID = 8,
  PPPOE_FIELD_ID = 9,
  IP_VER_FIELD_ID = 10,
  IPV4_DSCP_FIELD_ID = 11,
  IPV4_ECN_FIELD_ID = 12,
  IPV4_LEN_FIELD_ID = 13,
  IPV4_TTL_FIELD_ID = 14,
  IPV6_HL_FIELD_ID = 14,
  IPV4_PROTO_FIELD_ID = 15,
  IPV6_PROTO_FIELD_ID = 15,
  IPV4_SA_FIELD_ID = 16,
  IPV4_DA_FIELD_ID = 17,
  IPV6_DSCP_FIELD_ID = 18,
  IPV6_ECN_FIELD_ID = 19,
  IPV6_FLOW_LBL_FIELD_ID = 20,
  IPV6_PAYLOAD_LEN_FIELD_ID = 21,
  IPV6_NH_FIELD_ID = 22,
  IPV6_SA_FIELD_ID = 23,
  IPV6_SA_PREF_FIELD_ID = 24,
  IPV6_SA_SUFF_FIELD_ID = 25,
  IPV6_DA_FIELD_ID = 26,
  IPV6_DA_PREF_FIELD_ID = 27,
  IPV6_DA_SUFF_FIELD_ID = 28,
  L4_SRC_FIELD_ID = 29,
  L4_DST_FIELD_ID = 30,
  TCP_FLAGS_FIELD_ID = 31,
  CLS_UDF0_FIELD_ID = 32,
  CLS_UDF1_FIELD_ID = 33,
  CLS_UDF2_FIELD_ID = 34,
  CLS_UDF3_FIELD_ID = 35,
  CLS_UDF4_FIELD_ID = 36,
  CLS_UDF5_FIELD_ID = 37,
  CLS_UDF6_FIELD_ID = 38,
  CLS_UDF7_FIELD_ID = 39,
  /* not in use */
  OUT_TPID_FIELD_ID = 39,
  OUT_VLAN_CFI_FIELD_ID = 40,
  IN_TPID_FIELD_ID = 41,
  IN_VLAN_CFI_FIELD_ID = 42,
  /* end of - not in use */
  ARP_IPV4_DA_FIELD_ID = 48,
  IN_VLAN_PRI_FIELD_ID = 49,
  PPPOE_PROTO_ID = 50,
  CLS_FIELD_MAX = 51,
};

enum pp2_cls_cls_field_size_t
{ /* unit: bits */
  MH_FIELD_SIZE = 16,
  GEM_PORT_ID_FIELD_SIZE = 12,
  MH_UNTAGGED_PRI_FIELD_SIZE = 3,
  MAC_DA_FIELD_SIZE = 48,
  MAC_SA_FIELD_SIZE = 48,
  OUT_VLAN_PRI_FIELD_SIZE = 3,
  OUT_VLAN_ID_FIELD_SIZE = 12,
  IN_VLAN_ID_FIELD_SIZE = 12,
  ETH_TYPE_FIELD_SIZE = 16,
  PPPOE_FIELD_SIZE = 16,
  IP_VER_FIELD_SIZE = 4,
  IPV4_DSCP_FIELD_SIZE = 6,
  IPV4_ECN_FIELD_SIZE = 2,
  IPV4_LEN_FIELD_SIZE = 16,
  IPV4_TTL_FIELD_SIZE = 8,
  IPV4_PROTO_FIELD_SIZE = 8,
  IPV4_SA_FIELD_SIZE = 32,
  IPV4_DA_FIELD_SIZE = 32,
  IPV6_PROTO_FIELD_SIZE = 8,
  IPV6_DSCP_FIELD_SIZE = 6,
  IPV6_ECN_FIELD_SIZE = 2,
  IPV6_FLOW_LBL_FIELD_SIZE = 20,
  IPV6_PAYLOAD_LEN_FIELD_SIZE = 16,
  IPV6_NH_FIELD_SIZE = 8,
  IPV6_HL_FIELD_SIZE = 8,
  IPV6_SA_FIELD_SIZE = 128,
  IPV6_SA_PREF_FIELD_SIZE = 64,
  IPV6_SA_SUFF_FIELD_SIZE = 64,
  IPV6_DA_FIELD_SIZE = 128,
  IPV6_DA_PREF_FIELD_SIZE = 64,
  IPV6_DA_SUFF_FIELD_SIZE = 64,
  L4_SRC_FIELD_SIZE = 16,
  L4_DST_FIELD_SIZE = 16,
  TCP_FLAGS_FIELD_SIZE = 8,
  CLS_UDF0_FIELD_SIZE = CLS_UDF_FIELD_SIZE * BYTE_BITS,
  CLS_UDF1_FIELD_SIZE = CLS_UDF_FIELD_SIZE * BYTE_BITS,
  CLS_UDF2_FIELD_SIZE = CLS_UDF_FIELD_SIZE * BYTE_BITS,
  CLS_UDF3_FIELD_SIZE = CLS_UDF_FIELD_SIZE * BYTE_BITS,
  CLS_UDF4_FIELD_SIZE = CLS_UDF_FIELD_SIZE * BYTE_BITS,
  CLS_UDF5_FIELD_SIZE = CLS_UDF_FIELD_SIZE * BYTE_BITS,
  CLS_UDF6_FIELD_SIZE = CLS_UDF_FIELD_SIZE * BYTE_BITS,
  CLS_UDF7_FIELD_SIZE = CLS_UDF_FIELD_SIZE * BYTE_BITS,
  OUT_TPID_FIELD_SIZE = 16,
  OUT_VLAN_CFI_FIELD_SIZE = 1,
  IN_TPID_FIELD_SIZE = 16,
  IN_VLAN_CFI_FIELD_SIZE = 1,
  ARP_IPV4_DA_FIELD_SIZE = 32,
  IN_VLAN_PRI_FIELD_SIZE = 3,
  PPPOE_PROTO_SIZE = 16,

};

enum mv_pp2x_cls_filed_id
{
  MVPP2_CLS_FIELD_IP4SA = 0x10,
  MVPP2_CLS_FIELD_IP4DA = 0x11,
  MVPP2_CLS_FIELD_IP6SA = 0x17,
  MVPP2_CLS_FIELD_IP6DA = 0x1A,
  MVPP2_CLS_FIELD_L4SIP = 0x1D,
  MVPP2_CLS_FIELD_L4DIP = 0x1E,
};

#define LIST_FIRST_OBJECT(_lst, _type, _member) LIST_OBJECT ((_lst)->next, _type, _member)

#define LUID_IS_LSP_RESERVED(luid) (NULL)

#define mb() dsb (sy)

#define MV_ETH_ETYPE_LEN 2

#define PP2_CLS_TBL_MAX_NUM_FIELDS 5

#define PP2_MAX_BUF_STR_LEN 256

#define PP2_NUM_BPOOLS_RSRV  3
#define PP2_BPOOLS_RSRV_MASK ((1 << PP2_NUM_BPOOLS_RSRV) - 1)
#define PP2_NETDEV_PATH	     "/sys/class/net/"
#define TXD_DEST_QID_MASK    (0x0000FF00)

#define MVPP2_PLCR_MIN_ENTRY_ID		    (1)
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

#define PORT_STRING	"pp_port_%d:%d"
#define UIO_PORT_STRING "uio_" PORT_STRING

#define writel_relaxed		 mv_writel_relaxed
#define HUGE_PAGE_MAX_PAGE_COUNT 64
#define PP2_MAX_UDFS_SUPPORTED	 3

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

void log_init (int log_to_stderr);
void log_close (void);

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

#define PP2_NUM_ETH_PPIO	   3
#define PP2_NUM_PORTS		   4
#define PP2_NUM_REGSPACES	   9
#define PP2_MAX_NUM_PACKPROCS	   4
#define PP2_HW_PORT_NUM_RXQS	   32
#define PP2_LOOPBACK_PORT	   3
#define PP2_DEFAULT_REGSPACE	   0
#define MVPP2_C2_FIRST_ENTRY	   16  /* reserve 0-15 entries for kernel usage */
#define MVPP2_CLS_FREE_LOG2OFF	   (0) /* 1st entry is the free index	*/
#define MVPP2_CLS_LOG2OFF_TBL_SIZE (MVPP2_CLS_FLOWS_TBL_SIZE + MVPP2_CLS_FREE_LOG2OFF)
#define PP2_CLS_PLCR_NUM	   31
#define UIO_HDR_STR		   "uio_%s"
#define UIO_ID_FORMAT_STR	   "_%d"
#define UIO_MAX_FORMAT_SZ	   (sizeof (UIO_HDR_STR) + sizeof (UIO_ID_FORMAT_STR))
#define INT_32_MAX_DEC_STR_SZ	   10 /* max num of decimal digits in 32-bit integer */
#define OF_MAX_NODES		   64
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
#ifndef swab32
#define swab32(x)                                                                                  \
  ((u32) ((((x) & 0x000000FF) << 24) | (((x) & 0x0000FF00) << 8) | (((x) & 0x00FF0000) >> 8) |     \
	  (((x) & 0xFF000000) >> 24)))
#endif

#ifndef swab64
#define swab64(x)                                                                                  \
  ((u64) ((((x) & 0x00000000000000FFULL) << 24) | (((x) & 0x000000000000FF00ULL) << 8) |           \
	  (((x) & 0x0000000000FF0000ULL) >> 8) | (((x) & 0x00000000FF000000ULL) >> 24) |           \
	  (((x) & 0x000000FF00000000ULL) << 24) | (((x) & 0x0000FF0000000000ULL) << 8) |           \
	  (((x) & 0x00FF000000000000ULL) >> 8) | (((x) & 0xFF00000000000000ULL) >> 24)))
#endif
#define OF_DEFAULT_NA 1
#define OF_DEFAULT_NS 1

#define OF_SCRIPT_STR                                                                              \
  "#!/bin/sh\n\n"                                                                                  \
  "DT=/proc/device-tree\n\n"                                                                       \
  "# $1 - node\n"                                                                                  \
  "# $2 - property\n"                                                                              \
  "of_get_property()\n"                                                                            \
  "{\n"                                                                                            \
  "    cat $DT$1/$2\n"                                                                             \
  "}\n\n"                                                                                          \
  "# $1 - from\n"                                                                                  \
  "# $2 - compatible\n"                                                                            \
  "# $3 - node\n"                                                                                  \
  "of_find_compatible_node()\n"                                                                    \
  "{\n"                                                                                            \
  "    of_find_compatible_nodes $1 $2 | tail -n +$3 | head -1 | tr -d \\\\n\n"                     \
  "}\n\n"                                                                                          \
  "# $1 - from\n"                                                                                  \
  "# $2 - compatible\n"                                                                            \
  "of_find_compatible_nodes()\n"                                                                   \
  "{\n"                                                                                            \
  "    for c in $(fgrep -l $2 $(find $DT$1 -name compatible))\n"                                   \
  "    do\n"                                                                                       \
  "        dirname $c\n"                                                                           \
  "    done | cut -b 18-\n"                                                                        \
  "}\n\n"                                                                                          \
  "# $1 - phandle\n"                                                                               \
  "of_find_node_by_phandle()\n"                                                                    \
  "{\n"                                                                                            \
  "    dirname $(fgrep -l $1 $(find $DT -name linux,phandle)) | cut -b 18- | tr -d \\\\n\n"        \
  "}\n\n"                                                                                          \
  "exec <&-\n"                                                                                     \
  "exec 2>/dev/null\n"                                                                             \
  "$@\n"

#define OF_SH_FILENAME			  "/tmp/of.sh"
#define MV_ERROR			  (-1)
#define MVPP2_EDROP_MIN_ENTRY_ID	  (1)
#define MVPP2_TOKEN_PERIOD_400_CORE_CLOCK (400) /* 400 core clock		*/
#define MVPP2_TOKEN_PERIOD_480_CORE_CLOCK (480) /* 480 core clock		*/
#define MVPP2_TOKEN_PERIOD_600_CORE_CLOCK (600) /* 600 core clock		*/
#define MVPP2_TOKEN_PERIOD_800_CORE_CLOCK (800) /* 800 core clock		*/
#define MV_OK				  (0)
#define RETRIES_EXCEEDED		  (15000)
#define UIO_BASE_PATH			  "/sys/class/uio"
#define MAX_FILE_NAME_LEN		  64
#define UIO_PP2_STRING			  "pp"
#define MV_PP2_NUM_HIFS_RSRV		  4
#define MV_PP2_HIFS_RSRV_MASK		  ((1 << MV_PP2_NUM_HIFS_RSRV) - 1)
#define PP2_BPOOL_NUM_POOLS		  16
#define PP2_MAX_NUM_PUT_BUFFS		  8192
#define PP2_LPBK_PORT_TXQ_SIZE		  4096
#define PP2_LPBK_PORT_NUM_TXQ		  1
#define PP2_MAX_NUM_USED_INTERRUPTS	  4
#define PP2_STAT_UPDATE_THRESHOLD	  0xefffffff
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

#define PP2_RSRVD_MAP_HIF_AUTO	   0x1
#define PP2_RSRVD_MAP_BM_POOL_AUTO 0x2

#define dsb(opt)  ({ asm volatile ("dsb " #opt : : : "memory"); })
#define rmb()	  dsb (ld)
#define __iormb() rmb ()
#define wmb()	  dsb (st)
#define __iowmb() wmb ()

#define MVPP2_MEMSET_ZERO(STRUCT) memset (&(STRUCT), 0, sizeof ((STRUCT)))

#define GET_PPIO_PORT(ppio)	((struct pp2_port *) (ppio)->internal_param)
#define GET_PPIO_PORT_PTR(ppio) ((struct pp2_port **) &(ppio).internal_param)
#define GET_HW_BASE(pool)	((struct base_addr *) (pool)->internal_param)
#define SET_HW_BASE(pool, base)                                                                    \
  {                                                                                                \
    (pool)->internal_param = (base);                                                               \
  }

#define PP2_UPDATE_CNT16(counter, value)                                                           \
  {                                                                                                \
    counter = ((u32) (counter + value) > USHRT_MAX) ? USHRT_MAX : counter + value;                 \
  }
#define PP2_READ_UPDATE_CNT16(counter, cpu_slot, reg)                                              \
  {                                                                                                \
    u32 value = pp2_relaxed_reg_read (cpu_slot, reg);                                              \
    PP2_UPDATE_CNT16 (counter, value);                                                             \
  }
#define PP2_UPDATE_CNT32(counter, value)                                                           \
  {                                                                                                \
    counter = ((u64) (counter + value) > UINT_MAX) ? UINT_MAX : counter + value;                   \
  }
#define PP2_READ_UPDATE_CNT32(counter, cpu_slot, reg)                                              \
  {                                                                                                \
    u32 value = pp2_relaxed_reg_read (cpu_slot, reg);                                              \
    PP2_UPDATE_CNT32 (counter, value);                                                             \
  }
#define PP2_READ_UPDATE_CNT64(counter, cpu_slot, reg)                                              \
  {                                                                                                \
    counter += pp2_relaxed_reg_read (cpu_slot, reg);                                               \
  }

typedef struct spinlock
{
  char lock;
} spinlock_t;

#ifdef MVCONF_PP2_LOCK
static inline void
spin_lock_init (spinlock_t *spinlock)
{
  __atomic_clear (&spinlock->lock, __ATOMIC_RELAXED);
}

static spinlock_t *
spin_lock_create (void)
{
  spinlock_t *lock = clib_mem_alloc_or_null (sizeof (*lock));

  if (lock)
    spin_lock_init (lock);
  return lock;
}

static void
spin_lock_destroy (spinlock_t *lock)
{
  if (lock)
    clib_mem_free (lock);
}

static inline void
spin_lock (spinlock_t *spinlock)
{
  while (__atomic_test_and_set (&spinlock->lock, __ATOMIC_ACQUIRE))
    while (__atomic_load_n (&spinlock->lock, __ATOMIC_RELAXED))
      ;
}

static inline void
spin_unlock (spinlock_t *spinlock)
{
  __atomic_clear (&spinlock->lock, __ATOMIC_RELEASE);
}
#endif
struct sys_iomem;
enum sys_iomem_type
{
  SYS_IOMEM_T_MMAP = 0,
  SYS_IOMEM_T_UIO,
  SYS_IOMEM_T_VFIO,
  SYS_IOMEM_T_SHMEM,
};

struct sys_iomem_params
{
  enum sys_iomem_type type;
  const char *devname;
  int index;
  size_t size;
};

struct pp2_cls_db_t;
struct mv_pp2x_cls_c2_entry;
struct mv_pp2x_cls_flow_entry;
struct mv_pp2x_cls_lookup_entry;
struct pp2_inst;
struct pp2_port;
struct pp2_cls_tbl;
struct mv_pp2x_c2_add_entry;
struct pp2_cls_c3_add_entry_t;
struct pp2_cls_mng_pkt_key_t;
struct netdev_featstrs;
struct pp2_cls_c3_entry;
struct pp2_cls_c3_hash_pair;
struct mv_pp2x_cls_c2_qos_entry;
struct pp2_cls_field_match_info;
struct pp2_cls_plcr;
struct pp2_cls_early_drop;
struct mv_pp2x_prs_shadow;
struct mv_pp2x_cls_shadow;
struct mv_pp2x_c2_shadow;
struct ethtool_gstrings;
struct uio_info_t;
struct uio_mem_t;

struct base_addr
{
  uintptr_t va;
  phys_addr_t pa;
};

struct bm_pool_param
{
  u32 id;
  u32 pp2_id;
  u32 buf_num;
  u32 buf_size;
  int dummy_pool;
  struct mv_sys_dma_mem_region *likely_buffer_mem;
};

struct pp2_desc
{
  u32 cmd0;
  u32 cmd1;
  u32 cmd2;
  u32 cmd3;
  u32 cmd4;
  u32 cmd5;
  u32 cmd6;
  u32 cmd7;
};

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

struct gop_port_ctrl
{
  u32 flags;
};

struct gop_hw
{
  struct pp2_mac_unit_desc gmac;
  struct pp2_mac_unit_desc xlg_mac;
  struct base_addr mspg;
  struct gop_port_ctrl gop_port_debug[4];
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
list_add (struct list *new_lst, struct list *head)
{
  LIST_PREV (LIST_NEXT (head)) = new_lst;
  LIST_NEXT (new_lst) = LIST_NEXT (head);
  LIST_PREV (new_lst) = head;
  LIST_NEXT (head) = new_lst;
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

struct device_node
{
  char *name;
  char full_name[PATH_MAX];

  u8 _property[64];
};
static u8 current;
static struct device_node current_node[OF_MAX_NODES];
static struct device_node root = { .full_name = "/", .name = root.full_name };

#define UIO_MAX_NAME_SIZE 64
#define UIO_MAX_NUM	  255

#define UIO_INVALID_SIZE 0
#define UIO_INVALID_ADDR (~0)

enum uin_mmap_state
{
  UIO_MMAP_NOT_DONE = 0,
  UIO_MMAP_OK = 1,
  UIO_MMAP_FAILED = 2
};

#define UIO_INVALID_FD -1

#define PP2_PPIO_DESC_NUM_FRAGS 16 /* TODO: check if there is HW limitation */
#define MMAP_FILE_NAME		"/dev/mem"

/* This should be identical to the define in include/linux/uio_driver.h !!! */
#define MAX_UIO_MAPS 5

struct uio_map_t
{
  unsigned long addr;
  unsigned long size;
  char name[UIO_MAX_NAME_SIZE];
  int mmap_result;
  void *internal_addr;
};

struct uio_dev_attr_t
{
  char name[UIO_MAX_NAME_SIZE];
  char value[UIO_MAX_NAME_SIZE];
  struct uio_dev_attr_t *next;
};

struct uio_info_t
{
  int uio_num;
  struct uio_map_t maps[MAX_UIO_MAPS];
  unsigned long event_count;
  char name[UIO_MAX_NAME_SIZE];
  char version[UIO_MAX_NAME_SIZE];
  struct uio_dev_attr_t *dev_attrs;
  struct uio_info_t *next; /* for linked list */
};

struct uio_mem_t
{
  int map_num;
  int fd;
  struct uio_info_t *info;
  struct uio_mem_t *next; /* for linked list */
};

#define MAX_NAME_STRING_SIZE 64

struct mem_mmap_nd
{
  int index;
  void *va;
  phys_addr_t pa;
  uint32_t offs;
  uint64_t size;
  struct list node;
};
#define MMAP_ND_OBJ(ptr) LIST_OBJECT (ptr, struct mem_mmap_nd, node)

struct mem_mmap
{
  struct device_node *dev_node;
  struct list maps_lst;
};

struct mem_uio
{
  struct uio_info_t *info;
  struct uio_mem_t *mem;
};

struct mem_shm
{
  char dev_name[MAX_NAME_STRING_SIZE];
  void *va;
  phys_addr_t pa;
  size_t size;
};

struct sys_iomem
{
  char *name;
  uint32_t owners;
  int index;
  enum sys_iomem_type type;
  union
  {
    struct mem_uio uio;
    struct mem_mmap mmap;
    struct mem_shm shmem;
  } u;
  struct list node;
};

static struct list iomem_maps_lst = LIST_INIT (iomem_maps_lst);
static size_t pagesize = -1;
struct pp2_cls_luid_conf_t
{
  u8 luid; /* Lookup ID			*/
};
struct pp2_cls_c3_hash_index_entry_t
{
  u16 valid;	/* indicate whether this logical index is valid*/
  u16 hash_idx; /* multihash index*/
};

struct pp2_cls_c3_logic_index_entry_t
{
  u16 valid;	 /* indicate whether this hash index is valid*/
  u16 logic_idx; /* logical index*/
};

struct pp2_cls_c3_scan_config_t
{
  u8 clear_before_scan; /* clear counter before scan	*/
  u8 lkp_type_scan;	/* scan by lookup type*/
  u8 lkp_type;		/* lookup type*/
  u8 scan_mode;		/* scan mode*/
  u32 start_entry;	/* scan startted entry*/
  u32 scan_delay;	/* scan delay time*/
  u32 scan_threshold;	/* scan threshold*/
};
enum pp2_cls_plcr_token_unit
{
  PP2_CLS_PLCR_BYTES_TOKEN_UNIT = 0, /* token unit is based on number of bytes	*/
  PP2_CLS_PLCR_PACKETS_TOKEN_UNIT    /* token unit is based on number of packets	*/
};

enum pp2_cls_plcr_color_mode
{
  PP2_CLS_PLCR_COLOR_BLIND_MODE = 0, /* color blind mode	*/
  PP2_CLS_PLCR_COLOR_AWARE_MODE	     /* color aware mode	*/
};

struct pp2_cls_plcr_params
{
  /** Used for DTS access to find appropriate Policer obj;
   * E.g. "policer-0:0" means PPv2[0],policer[0]
   */
  const char *match;

  enum pp2_cls_plcr_token_unit token_unit; /* token in unit of bytes or packets	*/
  enum pp2_cls_plcr_color_mode color_mode; /* color mode, blind or aware of former color	*/
  u32 cir; /** commit information rate in unit of Kbps (data rate) or pps.
	    *  minimum value - 104Kbps or 125pps. value of '0' means maximum value.
	    *  In Byte mode, the final value is a multiple of 8.
	    */
  u32 cbs; /** commit burst size in unit of KB or number of packets;
	    *  minimum value - 64KB or 1Kpps. value of '0' means maximum value.
	    */
  u32 ebs; /** excess burst size in unit of KB or number of packets
	    *  minimum value - 64KB or 1Kpps. value of '0' means maximum value.
	    */
};

enum mv_pp2x_src_port_type
{
  MVPP2_SRC_PORT_TYPE_PHY,
  MVPP2_SRC_PORT_TYPE_UNI,
  MVPP2_SRC_PORT_TYPE_VIR,
  MVPP2_SRC_PORT_TYPE_MAX
};

enum pp2_lb_type
{
  PP2_DISABLE_LB,
  PP2_RX_2_TX_LB,
  PP2_TX_2_RX_LB,	  /* on SERDES level - analog loopback */
  PP2_TX_2_RX_DIGITAL_LB, /* on SERDES level - digital loopback */
};

struct pp2_cls_enum_str_t
{
  int enum_value;	/* the value of enum */
  const char *enum_str; /* the string name of enum	*/
};

static char g_unknown_str[] = "none";

struct mv_pp2x_src_port
{
  enum mv_pp2x_src_port_type port_type;
  u32 port_value;
  u32 port_mask;
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

struct mv_pp2x_engine_qos_info
{
  /* dscp pri table or none */
  enum mv_pp2x_qos_tbl_sel qos_tbl_type;
  /* dscp or pri table index */
  u32 qos_tbl_index;
  /* policer id, 0xffff do not assign policer */
  u16 policer_id;
  /* pri/dscp comes from qos or act tbl */
  enum mv_pp2x_qos_src_tbl pri_dscp_src;
  /* gemport comes from qos or act tbl */
  enum mv_pp2x_qos_src_tbl gemport_src;
  enum mv_pp2x_qos_src_tbl q_low_src;
  enum mv_pp2x_qos_src_tbl q_high_src;
  enum mv_pp2x_qos_src_tbl color_src;
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

enum mv_pp2x_flowid_action_type
{
  /* FlowID is disable */
  MVPP2_ACTION_FLOWID_DISABLE = 0,
  /* FlowID is enable */
  MVPP2_ACTION_FLOWID_ENABLE,
};

enum mv_pp2x_frwd_action_type
{
  /* The decision will be not updated */
  MVPP2_FRWD_ACTION_TYPE_NO_UPDT,
  /* The decision is not updated, and following no change to it */
  MVPP2_FRWD_ACTION_TYPE_NO_UPDT_LOCK,
  /* The packet to CPU (Software Forwarding) */
  MVPP2_FRWD_ACTION_TYPE_SWF,
  /* The packet to CPU, and following no change to it */
  MVPP2_FRWD_ACTION_TYPE_SWF_LOCK,
  /* The packet to one transmit port (Hardware Forwarding) */
  MVPP2_FRWD_ACTION_TYPE_HWF,
  /* The packet to one tx port, and following no change to it */
  MVPP2_FRWD_ACTION_TYPE_HWF_LOCK,
  /* The pkt to one tx port, and maybe internal packets is used */
  MVPP2_FRWD_ACTION_TYPE_HWF_LOW_LATENCY,
  /* Same to above, but following no change to it*/
  MVPP2_FRWD_ACTION_TYPE_HWF_LOW_LATENCY_LOCK,
};

struct mv_pp2x_engine_pkt_action
{
  enum mv_pp2x_color_action_type color_act;
  enum mv_pp2x_general_action_type pri_act;
  enum mv_pp2x_general_action_type dscp_act;
  enum mv_pp2x_general_action_type gemp_act;
  enum mv_pp2x_general_action_type q_low_act;
  enum mv_pp2x_general_action_type q_high_act;
  enum mv_pp2x_general_action_type policer_act;
  enum mv_pp2x_general_action_type rss_act;
  enum mv_pp2x_flowid_action_type flowid_act;
  enum mv_pp2x_frwd_action_type frwd_act;
};

struct mv_pp2x_qos_value
{
  u16 pri;
  u16 dscp;
  u16 gemp;
  u16 q_low;
  u16 q_high;
};

struct mv_pp2x_engine_pkt_mod
{
  u32 mod_cmd_idx;
  u32 mod_data_idx;
  u32 l4_chksum_update_flag;
};

struct mv_pp2x_duplicate_info
{
  /* pkt duplication flow id */
  u32 flow_id;
  /* pkt duplication count */
  u32 flow_cnt;
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

enum mv_pp2_rss_hash_select
{
  MVPP2_RSS_HASH_0_4,
  MVPP2_RSS_HASH_5_9,
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

union pp2_cls_ipvx_add
{
  u8 ipv4[4];  /* IPV4 Address */
  u8 ipv6[16]; /* IPV6 Address */
};
struct pp2_cls_pppoe_key_t
{
  u16 ppp_session; /* PPPoE session */
  u16 ppp_proto;   /* PPPoE Protocol */
};
struct pp2_cls_eth_add_key_t
{
  u8 eth_add[6];      /* Ethernet Address */
  u8 eth_add_mask[6]; /* Ethernet Address Mask*/
};

struct pp2_cls_ipvx_add_key_t
{
  union pp2_cls_ipvx_add ip_add;      /* IPV4/IPV6 Address */
  union pp2_cls_ipvx_add ip_add_mask; /* IPV4/IPV6 Address Mask*/
};

struct pp2_cls_udf_key_t
{
  u32 udf;	/* UDF */
  u32 udf_mask; /* UDF Mask*/
};

struct pp2_cls_ipvx_key_t
{
  u16 ip_ver;				/* IP version (4,6) */
  struct pp2_cls_ipvx_add_key_t ip_src; /* Maskable IPV4/IPV6 source address */
  struct pp2_cls_ipvx_add_key_t ip_dst; /* Maskable IPV4/IPV6 dest address */
  u8 dscp;				/* IPV4/IPV6 dscp */
  u8 dscp_mask;				/* IPV4/IPV6 dscp mask*/
  u8 ip_proto;				/* IP protocol */
  u32 flow_label;			/* ipv6 only */
  u32 flow_label_mask;			/* ipv6 only */
};

struct pp2_cls_pkt_key_t
{
  struct mv_pp2x_src_port port;
  u32 rule_type;     /* rules with smaller value has higher priority being matched*/
		     /* should be set together with cap/filter during MVPP2 INIT */
  u32 field_bm;	     /* Bitmap of packet fields to match (pp2_cls_field_match_t) */
  u32 field_bm_mask; /* Bitmap of packet fields to match (pp2_cls_field_match_t) */
  struct pp2_cls_eth_add_key_t eth_dst; /* Ethernet Destination address & mask */
  struct pp2_cls_eth_add_key_t eth_src; /* Ethernet Destination address & mask */
  u16 out_vid;				/* Outer Tag VID, 0x0000->untagged, 0xffff->tagged */
					/* 0x1ABC->specific Outer VID=ABC */
  u8 out_pbit;				/* Outer Tag pbits */
  u16 out_tpid;				/* Outer TPID */
  u8 out_cfi;				/* Outer Tag cfi */
  u16 inn_vid;	  /* Inner VID,0x0000->not double-tagged,0xffff-> double-tagged */
		  /* 0x1ABC->specific Inner VID=ABC */
  u8 inn_pbit;	  /* Inner Tag pbits */
  u16 inn_tpid;	  /* Inner TPID */
  u8 inn_cfi;	  /* Inner Tag cfi */
  u16 ether_type; /* Ethertype (after Vlan Tags)*/
  struct pp2_cls_pppoe_key_t ppp_info;	    /* PPPoE key (proto, ppp_session) */
  struct pp2_cls_ipvx_key_t ipvx_add;	    /*IPV4/IPV6 packet key */
  struct pp2_cls_ipvx_add_key_t arp_ip_dst; /* ARP IPV4 dest address */
  u16 l4_src;				    /*UDP/TCP source port */
  u16 l4_dst;				    /*UDP/TCP dest port */
  struct pp2_cls_udf_key_t udf3;	    /*UDF3 */
  struct pp2_cls_udf_key_t udf5;	    /*UDF5 */
  struct pp2_cls_udf_key_t udf6;	    /*UDF6 */
};

#define MVPP2_NUM_MAX_NTUPLE_FIELD_NUM (9)

enum pp2_cls_vlan_num_enum_t
{
  MVPP2_NO_VLAN,
  MVPP2_SINGLE_VLAN,
  MVPP2_DOUBLE_VLAN,
  MVPP2_TRIPLE_VLAN,
  MVPP2_NOT_DOUBLE_VLAN, /* untag or single tag */
  MVPP2_ANY_VLAN,	 /* vlan number is not relevant */
};

struct pp2_cls_ntuple_info_t
{
  u32 ntuple_field_bm;
  u32 rule_type;
  enum pp2_cls_vlan_num_enum_t tag_num;
  u32 curr_field;
  u32 field_num;
  u32 field_match_bm[MVPP2_NUM_MAX_NTUPLE_FIELD_NUM];
};

struct pp2_cls_mng_pkt_key_t
{
  struct pp2_cls_pkt_key_t *pkt_key;
  struct pp2_cls_ntuple_info_t *nt_info;
  u8 ttl;
  u8 tcp_flag;
  u8 tcp_flag_mask;
  u16 mh;
  u16 mh_mask;
};

/* The logic C2 entry, easy to understand and use */
struct mv_pp2x_c2_add_entry
{
  struct mv_pp2x_src_port port;
  u8 lkp_type;
  u8 lkp_type_mask;
  /* priority in this look_type */
  u32 priority;
  struct pp2_cls_mng_pkt_key_t *mng_pkt_key; /* pkt key value */
  /* all the qos input */
  struct mv_pp2x_engine_qos_info qos_info;
  /* update&lock info */
  struct mv_pp2x_engine_pkt_action action;
  /* pri/dscp/gemport/qLow/qHigh */
  struct mv_pp2x_qos_value qos_value;
  /* PMT cmd_idx and data_idx */
  struct mv_pp2x_engine_pkt_mod pkt_mod;
  /* RSS enable or disable */
  int rss_en;
  /* pkt duplication flow info */
  struct mv_pp2x_duplicate_info flow_info;
};

struct pp2_cls_c3_add_entry_t
{
  struct mv_pp2x_src_port port;		     /* port information	*/
  u8 lkp_type;				     /* lookup type*/
  struct pp2_cls_mng_pkt_key_t *mng_pkt_key; /* pkt key value*/
  struct mv_pp2x_engine_qos_info qos_info;   /* all the qos input	*/
  struct mv_pp2x_engine_pkt_action action;   /* update&lock info*/
  struct mv_pp2x_qos_value qos_value;	     /* pri/dscp/gemport/qLow/qHigh*/
  struct mv_pp2x_engine_pkt_mod pkt_mod;     /* PMT cmd_idx and data_idx*/
  struct mv_pp2x_duplicate_info flow_info;   /* pkt duplication flow info*/
  u8 rss_en;				     /* lookup type*/
};

struct pp2_cls_mng_pkt_key_db_t
{
  struct pp2_cls_pkt_key_t pkt_key;
  u8 ttl;
  u8 tcp_flag;
  u8 tcp_flag_mask;
  u8 dummy;
};

struct pp2_cls_field_int_value_t
{
  u32 parsed_int_val;
  u32 parsed_int_val_mask;
};

struct pp2_cls_field_mac_addr_t
{
  u8 parsed_mac_addr[MAC_ADDR_SIZE];
  u8 parsed_mac_addr_mask[MAC_ADDR_SIZE];
};

struct pp2_cls_field_ipv4_addr_t
{
  u8 parsed_ipv4_addr[IPV4_ADDR_SIZE];
  u8 parsed_ipv4_addr_mask[IPV4_ADDR_SIZE];
};

struct pp2_cls_field_ipv6_addr_t
{
  u8 parsed_ipv6_addr[IPV6_ADDR_SIZE];
  u8 parsed_ipv6_addr_mask[IPV6_ADDR_SIZE];
};

union pp2_cls_field_value_union_t
{
  struct pp2_cls_field_int_value_t int_data;
  struct pp2_cls_field_mac_addr_t mac_addr;
  struct pp2_cls_field_ipv4_addr_t ipv4_addr;
  struct pp2_cls_field_ipv6_addr_t ipv6_addr;
};

struct pp2_cls_field_match_info
{
  int valid;
  u32 field_id;
  union pp2_cls_field_value_union_t filed_value;
};

struct pp2_cls_c2_data_t
{
  u32 valid;	/* Indicate the data is a real TCAM entry or not */
  u32 priority; /* priority in this look_type */
  struct mv_pp2x_src_port port;
  u8 lkp_type;
  u8 lkp_type_mask;
  u32 field_bm;				       /* bitmap of relevant fields*/
  struct pp2_cls_mng_pkt_key_db_t mng_pkt_key; /* pkt key value */
  struct mv_pp2x_engine_qos_info qos_info;     /* all the qos input */
  struct mv_pp2x_engine_pkt_action action;     /* update&lock info */
  struct mv_pp2x_qos_value qos_value;	       /* pri/dscp/gemport/qLow/qHigh */
  struct mv_pp2x_engine_pkt_mod pkt_mod;       /* PMT cmd_idx and data_idx */
  struct mv_pp2x_duplicate_info flow_info;     /* pkt duplication flow info */
};

struct pp2_cls_c2_index_t
{
  u32 valid;		 /* Indicate the node is in list(valid), free or lookup up type list */
  u32 c2_logic_idx;	 /* logical index, unique inentifier, used for delete C2 entry */
  u32 c2_hw_idx;	 /* HW entry index in C2 engine */
  u32 c2_data_db_idx;	 /* data index in db */
  struct list list_node; /* list node */
};

/* C2 module db structure */
struct pp2_cls_db_c2_t
{
  /* info of each entry in C2 engine */
  struct pp2_cls_c2_data_t c2_data_db[MVPP2_C2_ENTRY_MAX - MVPP2_C2_FIRST_ENTRY];
  /* logic index and hw index of C2 entry */
  struct pp2_cls_c2_index_t c2_index_db[MVPP2_C2_ENTRY_MAX - MVPP2_C2_FIRST_ENTRY];
  /* header of list of the valid lookup_types */
  struct list c2_lu_type_head_db[MVPP2_C2_LKP_TYPE_MAX];
  /* header of free C2 entry list */
  struct list c2_free_head_db;
};

/* C3 module db structure */
struct pp2_cls_db_c3_t
{
  struct pp2_cls_c3_scan_config_t scan_config; /* scan config       */
  u32 max_search_depth;			       /* max search depth  */
  struct pp2_cls_c3_hash_index_entry_t
    hash_idx_tbl[MVPP2_CLS_C3_HASH_TBL_SIZE]; /* tbl for hash idx  */
  struct pp2_cls_c3_logic_index_entry_t
    logic_idx_tbl[MVPP2_CLS_C3_HASH_TBL_SIZE]; /* tbl for logic idx */
};

/* CLS module db structure */
struct pp2_db_cls_fl_ctrl_t
{
  u16 fl_max_len;  /* the max flow length		*/
  u16 lkp_dcod_en; /* swap section index		*/
  u16 f_start;	   /* free start index		*/
  u16 f_end;	   /* free end index		*/
};

struct pp2_db_cls_lkp_dcod_t
{
  bool enabled;							     /* enabled flag			*/
  u8 cpu_q;							     /* CPU queue			*/
  u8 way;							     /* entry way			*/
  u8 flow_alloc_len;						     /* flow allocation length	*/
  u8 flow_len;							     /* flow current length		*/
  u16 flow_off;							     /* flow offset			*/
  u16 luid_num;							     /* Lookup ID number		*/
  struct pp2_cls_luid_conf_t luid_list[MVPP2_CLS_LOG_FLOW_LUID_MAX]; /* Lookup ID list		*/
};

struct pp2_db_cls_fl_rule_t
{
  u16 port_type; /* port type			*/
  u16 port_bm;	 /* port bitmap			*/
  u16 lu_type;	 /* lookup type			*/
  bool enabled;	 /* enable flag			*/
  u8 prio;	 /* HW priority			*/
  u8 engine;	 /* rule engine			*/
  u8 udf7;
  u8 field_id_cnt;			   /* field ID count		*/
  u8 field_id[MVPP2_FLOW_FIELD_COUNT_MAX]; /* field IDs			*/
  u16 ref_cnt[PP2_NUM_PORTS];		   /* reference count		*/
  u16 rl_log_id;			   /* rule logical id              */
};

struct pp2_db_cls_fl_rule_list_t
{
  struct pp2_db_cls_fl_rule_t flow[MVPP2_CLS_FLOW_RULE_MAX]; /* flow rules			*/
  u16 flow_len;						     /* flow length			*/
};

struct pp2_cls_db_cls_t
{
  struct pp2_db_cls_fl_ctrl_t fl_ctrl;				/* flow control DB		*/
  struct pp2_db_cls_fl_rule_t fl_rule[MVPP2_FLOW_TBL_SIZE];	/*CLS rule DB		*/
  u16 log2off[MVPP2_CLS_LOG2OFF_TBL_SIZE];			/* logical rule ID to offset	*/
  struct pp2_db_cls_lkp_dcod_t lkp_dcod[MVPP2_MNG_FLOW_ID_MAX]; /* lookup decode DB	*/
};

struct prs_log_port_tcam_node
{
  struct list list_node;
  u32 idx;	/* TCAM matching index*/
  u32 proto;	/* TCAM matching protocol*/
  int log_port; /* Indication if TCAM index is for a logical port.*/
};

struct prs_log_port_tcam_negated_proto_node
{
  struct list list_node;
  u32 proto; /* negated protocol*/
};

struct pp2_cls_db_prs_t
{
  struct mv_pp2x_prs_shadow *prs_shadow;
  struct list tcam_match_list;	   /* List of PRS TCAM indexes matching log port rules */
  struct list tcam_neg_proto_list; /* List of logical port negated protocols */
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

enum pp2_cls_plcr_entry_state_t
{
  MVPP2_PLCR_ENTRY_INVALID_STATE = 0, /* invalid policer entry	*/
  MVPP2_PLCR_ENTRY_VALID_STATE	      /* valid policer entry		*/
};
enum pp2_cls_edrop_entry_state_t
{
  MVPP2_EDROP_ENTRY_INVALID_STATE = 0, /* invalid early-drop entry	*/
  MVPP2_EDROP_ENTRY_VALID_STATE	       /* valid early-drop entry	*/
};

enum pp2_cls_plcr_rate_state_t
{
  MVPP2_PLCR_BASE_RATE_DISABLE = 0, /* disable base rate generation	*/
  MVPP2_PLCR_BASE_RATE_ENABLE	    /* enable base rate generation	*/
};

enum pp2_cls_plcr_mode_t
{
  /* Bank#0 and Bank#1 policers are operating in serial mode (with the Bank#0 policer first)	*/
  MVPP2_PLCR_MODE_SERIAL_BANK_0_1 = 0,
  /* Bank#0 and Bank#1 policers are operating in serial mode (with the Bank#1 policer first)	*/
  MVPP2_PLCR_MODE_SERIAL_BANK_1_0,
  /* Bank#0 and Bank#1 policers are operating in parallel. The resulting color is as follows:
   * If one of the policers generates red color, then the packet color is red.
   * Else, if one of the policers generates yellow color, then the packet color is yellow.
   * Else, the packet color is green.
   */
  MVPP2_PLCR_MODE_PARALLEL,
  /* only Bank#0 is used */
  MVPP2_PLCR_MODE_ONLY_BANK_0
};
struct pp2_cls_plcr_gen_cfg_t
{
  enum pp2_cls_plcr_rate_state_t rate_state; /* enable or disable base rate generation	*/
  enum pp2_cls_plcr_mode_t mode;	     /* operation mode				*/
  u16 base_period;			     /* token update period in units of core clock	*/
  u8 min_pkt_len;			     /* minium packet length allowed by policer	*/
};
struct pp2_cls_early_drop_params
{
  /** Used for DTS access to find appropriate early-drop obj;
   * E.g. "ed-0:0" means PPv2[0],early-drop[0]
   */
  const char *match;

  u16 threshold; /** TODO */
};

struct pp2_cls_db_plcr_entry_t
{
  int valid;				 /* whether this policer entry is valid	*/
  struct pp2_cls_plcr_params plcr_entry; /* policer entry			*/
  u32 rules_ref_cnt;			 /* reference counter of CLS rules	*/
  u32 ppios_ref_cnt;			 /* reference counter of PPIOs		*/
};

struct pp2_cls_db_edrop_entry_t
{
  int valid;					/* whether this entry is valid	*/
  struct pp2_cls_early_drop_params edrop_entry; /* early-drop entry			*/
  u32 ref_cnt;					/* reference counter of queues	*/
};

/* policer module DB structure */
struct pp2_cls_db_plcr_t
{
  struct pp2_cls_plcr_gen_cfg_t gen_cfg;		   /* general configuration	*/
  struct pp2_cls_db_plcr_entry_t plcr_arr[MVPP2_PLCR_MAX]; /* policer entry array		*/
};

/* early-drop module DB structure */
struct pp2_cls_db_edrop_t
{
  struct pp2_cls_db_edrop_entry_t edrop_arr[MVPP2_EDROP_MAX]; /* early-drop entry array		*/
};

struct pp2_cls_db_t
{
  struct pp2_cls_db_c2_t c2_db;	      /* PP2_CLS module C2 db		*/
  struct pp2_cls_db_c3_t c3_db;	      /* PP2_CLS module C3 db		*/
  struct pp2_cls_db_cls_t cls_db;     /* PP2_CLS module CLS db		*/
  struct pp2_cls_db_prs_t prs_db;     /* PP2_CLS module PARSER db	*/
  struct pp2_cls_db_rss_t rss_db;     /* PP2_CLS module RSS db		*/
  struct pp2_cls_db_plcr_t plcr_db;   /* PP2 CLS module PLCR db		*/
  struct pp2_cls_db_edrop_t edrop_db; /* PP2 CLS module EDROP db		*/
};

struct pp2_cls_db_mng_t
{
  struct list pp2_cls_tbl_head;
};

static struct pp2_cls_db_mng_t *mng_db;

static struct mem_mmap_nd *mmap_find_iomap_by_index (struct mem_mmap *mmapm, int index);
static void uio_free_mem_info (struct uio_mem_t *info);
static struct uio_mem_t *uio_find_mem_byname (struct uio_info_t *info, const char *filter);
static void *uio_single_mmap (struct uio_info_t *info, int map_num, int fd);
static inline void uio_single_munmap (struct uio_info_t *info, int map_num);
static void iomem_uio_add_entry (struct uio_mem_t **headp, struct uio_mem_t *entry);
static struct uio_mem_t *iomem_uio_rm_entry (struct uio_mem_t **headp, const char *name);
static inline int pp2_is_init (void);
static u8 pp2_get_num_inst (void);

static inline bool mv_check_eaddr_mc (const u8 *eaddr);
static inline int mv_check_eaddr_valid (const u8 *addr);
static inline void mv_cp_eaddr (u8 *dest, const u8 *source);
static int mv_pp2x_cls_c2_color_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int from);
static int mv_pp2x_cls_c2_policer_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int policer_id,
				       int bank);
static u8 pp2_cls_c2_tcam_port_get (struct mv_pp2x_cls_c2_entry *c2);
static int mv_pp2x_cls_c2_hw_write (uintptr_t cpu_slot, int index, struct mv_pp2x_cls_c2_entry *c2);
static int mv_pp2x_cls_c2_hw_read (uintptr_t cpu_slot, int index, struct mv_pp2x_cls_c2_entry *c2);
static void mv_pp2x_c2_sw_clear (struct mv_pp2x_cls_c2_entry *c2);
static int mv_sys_match (const char *match, const char *obj_type, u8 hierarchy_level, u8 id[]);

static void mv_pp2x_cls_sw_flow_clear (struct mv_pp2x_cls_flow_entry *fe);
static int mv_pp2x_cls_sw_flow_engine_set (struct mv_pp2x_cls_flow_entry *fe, int engine,
					   int is_last);
static int mv_pp2x_cls_sw_flow_extra_set (struct mv_pp2x_cls_flow_entry *fe, int type, int prio);
static int mv_pp2x_cls_sw_flow_hek_num_set (struct mv_pp2x_cls_flow_entry *fe, int num_of_fields);
static int mv_pp2x_cls_sw_flow_hek_set (struct mv_pp2x_cls_flow_entry *fe, int field_index,
					int field_id);
static int mv_pp2x_cls_sw_flow_portid_select (struct mv_pp2x_cls_flow_entry *fe, int from);
static int mv_pp2x_cls_sw_flow_seq_ctrl_set (struct mv_pp2x_cls_flow_entry *fe, int mode);
static int mv_pp2x_cls_sw_flow_udf7_set (struct mv_pp2x_cls_flow_entry *fe, int mode);

static int pp2_db_cls_lkp_dcod_get (struct pp2_inst *inst, u32 fl_log_id,
				    struct pp2_db_cls_lkp_dcod_t *lkp_dcod);
static void mv_pp2x_cls_sw_lkp_clear (struct mv_pp2x_cls_lookup_entry *fe);

static int pp2_cls_db_plcr_entry_get (struct pp2_inst *inst, u8 policer_id,
				      struct pp2_cls_db_plcr_entry_t *plcr_entry);
static int pp2_gop_gmac_link_status (struct gop_hw *gop, int mac_num,
				     struct pp2_port_link_status *pstatus);
static int pp2_gop_xlg_mac_link_status (struct gop_hw *gop, int mac_num,
					struct pp2_port_link_status *pstatus);
static int pp2_port_remove_vlan (struct pp2_port *port, u16 vlan);
static void pp2_port_mac_set_loopback (struct pp2_port *port, int en);

#define BM_TYPE_SHORT_BUF_POOL (0x00)
#define BM_TYPE_LONG_BUF_POOL  (0x01)

enum mv_pp2x_cls_engine_num
{
  MVPP2_CLS_ENGINE_C2 = 1,
  MVPP2_CLS_ENGINE_C3A,
  MVPP2_CLS_ENGINE_C3B,
  MVPP2_CLS_ENGINE_C4,
  MVPP2_CLS_ENGINE_C3HA = 6,
  MVPP2_CLS_ENGINE_C3HB,
};

enum pp2_cls_params_tbl_type
{
  PP2_CLS_FLOW_TBL,
  PP2_CLS_QOS_TBL,
};

enum pp2_cls_c2_hek_offs_t
{
  MVPP2_C2_HEK_OFF_BYTE0 = 0,
  MVPP2_C2_HEK_OFF_BYTE1,
  MVPP2_C2_HEK_OFF_BYTE2,
  MVPP2_C2_HEK_OFF_BYTE3,
  MVPP2_C2_HEK_OFF_BYTE4,
  MVPP2_C2_HEK_OFF_BYTE5,
  MVPP2_C2_HEK_OFF_BYTE6,
  MVPP2_C2_HEK_OFF_BYTE7,
  MVPP2_C2_HEK_OFF_LKP_PORT_TYPE,
  MVPP2_C2_HEK_OFF_PORT_ID,
  MVPP2_C2_HEK_OFF_MAX
};

enum pp2_cls_cls_field_valid_t
{
  MVPP2_FIELD_INVALID = 0,
  MVPP2_FIELD_VALID
};

enum pp2_cls_l4_type_t
{
  MVPP2_L4_TYPE_NO_EXIST = 0, /* L4 Info no exist */
  MVPP2_L4_TYPE_TCP,	      /* TCP type */
  MVPP2_L4_TYPE_UDP,	      /* UDP type */
  MVPP2_L4_TYPE_MAX = MVPP2_L4_TYPE_UDP,
};

struct cls_field_convert_t
{
  u32 proto;
  u32 field;
  u32 field_to_config;
  u32 match_bm;
};

static struct cls_field_convert_t g_cls_field_convert[] = {
  /* ethernet, source address */
  { MV_NET_PROTO_ETH, MV_NET_ETH_F_SA, MAC_SA_FIELD_ID, MVPP2_MATCH_ETH_SRC },
  /* ethernet, destination address */
  { MV_NET_PROTO_ETH, MV_NET_ETH_F_DA, MAC_DA_FIELD_ID, MVPP2_MATCH_ETH_DST },
  /* ethernet, type */
  { MV_NET_PROTO_ETH, MV_NET_ETH_F_TYPE, ETH_TYPE_FIELD_ID, MVPP2_MATCH_ETH_TYPE },
  /* vlan, priority (outer vlan) */
  { MV_NET_PROTO_VLAN, MV_NET_VLAN_F_PRI, OUT_VLAN_PRI_FIELD_ID, MVPP2_MATCH_PBITS_OUTER },
  /* vlan, id (outer vlan) */
  { MV_NET_PROTO_VLAN, MV_NET_VLAN_F_ID, OUT_VLAN_ID_FIELD_ID, MVPP2_MATCH_VID_OUTER },
  /* vlan, tci */
  { MV_NET_PROTO_VLAN, MV_NET_VLAN_F_TCI, NOT_SUPPORTED_YET, 0 },
  /* ipv4, tos  [AW: check] */
  { MV_NET_PROTO_IP4, MV_NET_IP4_F_DSCP, IPV4_DSCP_FIELD_ID, MVPP2_MATCH_IP_DSCP },
  /* ipv4, souce address */
  { MV_NET_PROTO_IP4, MV_NET_IP4_F_SA, IPV4_SA_FIELD_ID, MVPP2_MATCH_IP_SRC },
  /* ipv4, destination address */
  { MV_NET_PROTO_IP4, MV_NET_IP4_F_DA, IPV4_DA_FIELD_ID, MVPP2_MATCH_IP_DST },
  /* ipv4, proto */
  { MV_NET_PROTO_IP4, MV_NET_IP4_F_PROTO, IPV4_PROTO_FIELD_ID, MVPP2_MATCH_IP_PROTO },
  /* ipv6, tc */
  { MV_NET_PROTO_IP6, MV_NET_IP6_F_TC, NOT_SUPPORTED_YET, 0 },
  /* ipv6, souce address */
  { MV_NET_PROTO_IP6, MV_NET_IP6_F_SA, IPV6_SA_FIELD_ID, MVPP2_MATCH_IP_SRC },
  /* ipv6, destination address */
  { MV_NET_PROTO_IP6, MV_NET_IP6_F_DA, IPV6_DA_FIELD_ID, MVPP2_MATCH_IP_DST },
  /* ipv6, flow */
  { MV_NET_PROTO_IP6, MV_NET_IP6_F_FLOW, IPV6_FLOW_LBL_FIELD_ID, MVPP2_MATCH_IPV6_FLBL },
  /* ipv6, next header */
  { MV_NET_PROTO_IP6, MV_NET_IP6_F_NEXT_HDR, IPV6_NH_FIELD_ID, MVPP2_MATCH_IP_PROTO },
  /* layer4, source port */
  { MV_NET_PROTO_L4, MV_NET_L4_F_SP, L4_SRC_FIELD_ID, MVPP2_MATCH_L4_SRC },
  /* layer4, destination port */
  { MV_NET_PROTO_L4, MV_NET_L4_F_DP, L4_DST_FIELD_ID, MVPP2_MATCH_L4_DST },
  /* tcp, source port */
  { MV_NET_PROTO_TCP, MV_NET_TCP_F_SP, L4_SRC_FIELD_ID, MVPP2_MATCH_L4_SRC },
  /* tcp, destination port */
  { MV_NET_PROTO_TCP, MV_NET_TCP_F_DP, L4_DST_FIELD_ID, MVPP2_MATCH_L4_DST },
  /* udp, source port */
  { MV_NET_PROTO_UDP, MV_NET_UDP_F_SP, L4_SRC_FIELD_ID, MVPP2_MATCH_L4_SRC },
  /* udp, destination port */
  { MV_NET_PROTO_UDP, MV_NET_UDP_F_DP, L4_DST_FIELD_ID, MVPP2_MATCH_L4_DST },
};

enum pp2_cls_c2_entry_free_t
{
  MVPP2_C2_ENTRY_FREE_TRUE = 0,
  MVPP2_C2_ENTRY_FREE_FALSE,
};

enum pp2_cls_edrop_ref_cnt_action_t
{
  MVPP2_EDROP_REF_CNT_INC = 0, /* increase reference counter by 1	*/
  MVPP2_EDROP_REF_CNT_DEC,     /* decrease reference counter by 1	*/
  MVPP2_EDROP_REF_CNT_CLEAR    /* clear reference counter to be 0	*/
};

static u32 pp2_cls_field_size_array[CLS_FIELD_MAX] = {
  MH_FIELD_SIZE,	   GEM_PORT_ID_FIELD_SIZE,   MH_UNTAGGED_PRI_FIELD_SIZE,
  MAC_DA_FIELD_SIZE,	   MAC_SA_FIELD_SIZE,	     OUT_VLAN_PRI_FIELD_SIZE,
  OUT_VLAN_ID_FIELD_SIZE,  IN_VLAN_ID_FIELD_SIZE,    ETH_TYPE_FIELD_SIZE,
  PPPOE_FIELD_SIZE,	   IP_VER_FIELD_SIZE,	     IPV4_DSCP_FIELD_SIZE,
  IPV4_ECN_FIELD_SIZE,	   IPV4_LEN_FIELD_SIZE,	     IPV4_TTL_FIELD_SIZE, /*IPV6_HL_FIELD_SIZE*/
  IPV4_PROTO_FIELD_SIZE,						  /*IPV6_PROTO_FIELD_SIZE*/
  IPV4_SA_FIELD_SIZE,	   IPV4_DA_FIELD_SIZE,	     IPV6_DSCP_FIELD_SIZE,
  IPV6_ECN_FIELD_SIZE,	   IPV6_FLOW_LBL_FIELD_SIZE, IPV6_PAYLOAD_LEN_FIELD_SIZE,
  IPV6_NH_FIELD_SIZE,	   IPV6_SA_FIELD_SIZE,	     IPV6_SA_PREF_FIELD_SIZE,
  IPV6_SA_SUFF_FIELD_SIZE, IPV6_DA_FIELD_SIZE,	     IPV6_DA_PREF_FIELD_SIZE,
  IPV6_DA_SUFF_FIELD_SIZE, L4_SRC_FIELD_SIZE,	     L4_DST_FIELD_SIZE,
  TCP_FLAGS_FIELD_SIZE,	   CLS_UDF0_FIELD_SIZE,	     CLS_UDF1_FIELD_SIZE,
  CLS_UDF2_FIELD_SIZE,	   CLS_UDF3_FIELD_SIZE,	     CLS_UDF4_FIELD_SIZE,
  CLS_UDF5_FIELD_SIZE,	   CLS_UDF6_FIELD_SIZE,	     CLS_UDF7_FIELD_SIZE,
  OUT_TPID_FIELD_SIZE,	   OUT_VLAN_CFI_FIELD_SIZE,  IN_TPID_FIELD_SIZE,
  IN_VLAN_CFI_FIELD_SIZE,  ARP_IPV4_DA_FIELD_SIZE
};

static int
pp2_cls_db_mng_init (void)
{
  if (!mng_db)
    {
      /* Allocat memory*/
      mng_db = clib_mem_alloc_or_null (sizeof (*mng_db));
      if (!mng_db)
	return -ENOMEM;

      /* Erase DB */
      MVPP2_MEMSET_ZERO (*mng_db);

      /* Init CLS Manager list head */
      INIT_LIST (&mng_db->pp2_cls_tbl_head);
    }
  return 0;
}

struct pp2_hif
{
  int regspace_slot;
  struct pp2_ppio_desc *rel_descs;
};

struct pp2_dm_if
{
  u32 id;
  u32 desc_total;
  u32 free_count;
  u32 desc_next_idx;
  uintptr_t desc_phys_arr;
  struct pp2_desc *desc_virt_arr;
  struct pp2_inst *parent;
  uintptr_t cpu_slot;
  struct mv_sys_dma_mem_region *mem;
};

struct pp2_txq_dm_if
{
  u32 desc_rsrvd;
};

struct pp2_tx_queue
{
  u32 id;
  u32 log_id;
  u32 desc_total;
  uintptr_t desc_phys_arr;
  struct pp2_desc *desc_virt_arr;
  struct pp2_txq_dm_if txq_dm_if[PP2_NUM_REGSPACES];
  struct pp2_ppio_outq_statistics stats;
  u32 threshold_tx_pkts;
  int disabled;
};

struct pp2_rx_queue
{
  u32 id;
  u32 log_id;
  u32 desc_total;
  u32 desc_received;
  u32 desc_last_idx;
  u32 desc_next_idx;
  u32 rxq_lock;
  uintptr_t desc_phys_arr;
  struct pp2_desc *desc_virt_arr;
  struct pp2_ppio_inq_statistics stats;
  u32 threshold_rx_pkts;
  struct mv_sys_dma_mem_region *mem;
  u32 bm_pool_id[PP2_PPIO_TC_CLUSTER_MAX_POOLS];
  u32 pkts_coal;
  u32 usec_coal;
  u32 fc_start_thresh;
  u32 fc_stop_thresh;
  struct pp2_cls_early_drop *edrop;
};

struct pp2_bm_pool
{
  u32 bm_pool_id;
  u32 bm_pool_buf_num;
  u32 bm_pool_buf_sz;
  u32 pp2_id;
  uintptr_t bm_pool_virt_base;
  uintptr_t bm_pool_phys_base;
  struct mv_sys_dma_mem_region *likely_buffer_mem;
  struct mv_sys_dma_mem_region *bppe_mem;
  int fc_not_supported;
  bool fc_enabled;
  u32 fc_port_mask;
  int fc_stop_threshold;
  int fc_start_threshold;
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
  struct mv_sys_dma_mem_region *mem;
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
  int rate_limit_enable;
  struct pp2_ppio_rate_limit_params rate_limit_params;
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

struct pp2_port_uio
{
  int fd;
};

struct event_intrpt
{
  uintptr_t cpu_slot;
  u32 cpu_slot_id;
  u32 qs_mask;
};

struct pp2_ppio_rxq_event_params
{
  u32 pkt_coal;
  u32 usec_coal;
  u32 tc_inqs_mask[PP2_PPIO_MAX_NUM_TCS];
};

struct rxq_event
{
  int valid;
  struct pp2_port *parent;
  struct pp2_ppio_rxq_event_params ev_params;
  u32 rxq_mask;
  struct event_intrpt rx_intrpt[PP2_MAX_NUM_USED_INTERRUPTS];
};

struct pp2_port
{
  u32 id;
  u32 flags;
  u32 num_rx_queues;
  u32 num_tx_queues;
  struct pp2_txq_config txq_config[PP2_PPIO_MAX_NUM_OUTQS];
  u32 num_tcs;
  u16 port_mru;
  u16 port_mtu;
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
  u32 rx_fifo_size;
  int maintain_stats;
  struct ethtool_gstrings *stats_name;
  struct pp2_ppio_statistics stats;
  enum pp2_ppio_type type;
  int enable_port_rate_limit;
  struct pp2_ppio_rate_limit_params rate_limit_params;
  struct pp2_cls_plcr *default_plcr;
  struct mv_sys_dma_mem_region *tx_qs_mem;
  struct pp2_port_uio uio_port;
  u32 num_rxq_events;
  struct rxq_event rx_event[PP2_PPIO_MAX_NUM_INQS];
  u32 rxq_event_mask;
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
  bool *prs_double_vlans;
  struct mv_pp2x_cls_shadow *cls_shadow;
  struct mv_pp2x_c2_shadow *c2_shadow;
  phys_addr_t phy_address_base;
};

enum mv_pp2x_queue_distribution_mode
{
  MVPP2_QDIST_SINGLE_MODE,
  MVPP2_QDIST_MULTI_MODE,
};

struct mv_pp2x_cos
{
  u8 cos_classifier;
  u8 num_cos_queues;
  u8 default_cos;
  u8 reserved;
  u32 pri_map;
};

struct mv_pp2x_rss
{
  u8 rss_mode;
  u8 dflt_cpu;
  u8 rss_en;
};

struct mv_pp2x_param_config
{
  struct mv_pp2x_cos cos_cfg;
  struct mv_pp2x_rss rss_cfg;
  u8 first_bm_pool;
  u8 first_sw_thread;
  u8 first_log_rxq;
  u8 cell_index;
  enum mv_pp2x_queue_distribution_mode queue_mode;
  u32 rx_cpu_map;
};

struct mv_pp2x_platform_data
{
  u8 pp2x_max_port_rxqs;
  u8 num_port_irq;
  bool multi_addr_space;
  bool interrupt_tx_done;
  bool multi_hw_instance;
};

struct pp2_uio
{
  struct uio_info_t *uio_info;
  struct uio_mem_t *mem;
};

struct pp2_inst
{
  u32 id;
  struct pp2_hw hw;
  struct mv_pp2x_platform_data pp2xdata;
  struct mv_pp2x_param_config pp2_cfg;
  u16 cpu_map;
  u32 num_ports;
  struct pp2_port *ports[PP2_NUM_PORTS];
  struct pp2_ppio *ppios[3];
  struct pp2_bm_pool *bm_pools[PP2_BPOOL_NUM_POOLS];
  u32 num_dm_ifs;
  struct pp2_dm_if *dm_ifs[PP2_NUM_REGSPACES];
  struct pp2_uio uio;
  struct pp2 *parent;
  struct sys_iomem *pp2_sys_iomem;
  struct pp2_cls_db_t *cls_db;
  u32 skip_hw_init;
};

struct pp2_common_cfg
{
  u16 hif_slot_map;
  u16 rss_tbl_map;
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
static struct pp2_bpool pp2_bpools[PP2_MAX_NUM_PACKPROCS][PP2_BPOOL_NUM_POOLS];

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

u32
common_mask_gen (int bit_num)
{
  u32 temp = 0x1;
  int i;

  /* para check */
  if (bit_num < 0 || bit_num > (sizeof (u32) * BYTE_BITS))
    return 0;

  if (bit_num == 0)
    return 0;

  for (i = 1; i < bit_num; i++)
    {
      temp = temp << 1;
      temp |= 0x1;
    }

  return temp;
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

static inline uintptr_t
pp2_bm_hw_buf_get (uintptr_t cpu_slot, uint32_t pool_id)
{
  uintptr_t vaddr;
#if PP2_BM_BUF_DEBUG
  u32 phys_lo;

  phys_lo = pp2_reg_read (cpu_slot, MVPP2_BM_PHY_ALLOC_REG (pool_id));
  if (unlikely (!phys_lo))
    {
      pr_err ("BM: BufGet failed! (Pool ID=%d)\n", pool_id);
      return 0;
    }
#else
  /* Trigger BM allocation by reading from BM_PHY_ALLOC and after
   * BM pops data into the lo and hi virt addr registers, construct
   * the full 40-bit virtual address
   */
  pp2_reg_read (cpu_slot, MVPP2_BM_PHY_ALLOC_REG (pool_id));
#endif

  vaddr = pp2_reg_read (cpu_slot, MVPP22_BM_PHY_VIRT_HIGH_ALLOC_REG);
  vaddr &= MVPP22_BM_VIRT_HIGH_ALLOC_MASK;
  vaddr <<= (32 - MVPP22_BM_VIRT_HIGH_ALLOC_OFFSET);
  vaddr |= pp2_reg_read (cpu_slot, MVPP2_BM_VIRT_ALLOC_REG);

#if PP2_BM_BUF_DEBUG
  pr_info ("BM: BufGet %p\n", (void *) vaddr);
#endif

  return vaddr;
}

static inline void
pp2_bm_pool_bufsize_set (uintptr_t cpu_slot, u32 pool_id, uint32_t buf_size)
{
  u32 val = ALIGN (buf_size, 1 << MVPP2_POOL_BUF_SIZE_OFFSET);

  pp2_reg_write (cpu_slot, MVPP2_POOL_BUF_SIZE_REG (pool_id), val);
}

static uint32_t
pp2_bm_pool_flush (uintptr_t cpu_slot, uint32_t pool_id)
{
  u32 j;
  u32 resid_bufs = 0;
  u32 pool_bufs;

  resid_bufs +=
    (pp2_reg_read (cpu_slot, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) & MVPP22_BM_POOL_PTRS_NUM_MASK);
  resid_bufs +=
    (pp2_reg_read (cpu_slot, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) & MVPP2_BM_BPPI_PTR_NUM_MASK);
  if (resid_bufs == 0)
    return 0;

  /* Actual number of registered buffers */
  pool_bufs = pp2_reg_read (cpu_slot, MVPP2_BM_POOL_SIZE_REG (pool_id));
  if (pool_bufs && (resid_bufs + 1) > pool_bufs)
    pr_warn ("BM: number of buffers in pool #%d (%d) is more than pool size (%d)\n", pool_id,
	     resid_bufs, pool_bufs);

  for (j = 0; j < (resid_bufs + 1); j++)
    {
      /* Clean all buffers even if return NULL pointer that can be
       * buffers remained from incorrect previous closure.
       */
      pp2_bm_hw_buf_get (cpu_slot, pool_id);
    }
  pr_debug ("pp2_bm_pool_flush: clear %d buffers from pool ID=%u\n", j, pool_id);
  resid_bufs = 0;
  resid_bufs +=
    (pp2_reg_read (cpu_slot, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) & MVPP22_BM_POOL_PTRS_NUM_MASK);
  resid_bufs +=
    (pp2_reg_read (cpu_slot, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) & MVPP2_BM_BPPI_PTR_NUM_MASK);

  return resid_bufs;
}

static void
pp2_bm_hw_pool_destroy (uintptr_t cpu_slot, uint32_t pool_id)
{
  u32 val;

  val = pp2_reg_read (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id));

  if (val & MVPP2_BM_STATE_MASK)
    {
      val |= MVPP2_BM_STOP_MASK;

      pp2_reg_write (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id), val);

      pr_debug ("BM: stopping pool %u ...\n", pool_id);
      /* Wait pool stop notification */
      do
	{
	  val = pp2_reg_read (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id));
	}
      while (val & MVPP2_BM_STATE_MASK);
      pr_debug ("BM: stopped pool %u ...\n", pool_id);
    }

  /* Mask & Clear interrupt flags */
  pp2_reg_write (cpu_slot, MVPP2_BM_INTR_MASK_REG (pool_id), 0);
  pp2_reg_write (cpu_slot, MVPP2_BM_INTR_CAUSE_REG (pool_id), 0);

  /* Clear BPPE base */
  pp2_reg_write (cpu_slot, MVPP2_BM_POOL_BASE_ADDR_REG (pool_id), 0);

  val = pp2_reg_read (cpu_slot, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG);
  val &= ~MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  pp2_reg_write (cpu_slot, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG, val);

  pp2_bm_pool_bufsize_set (cpu_slot, pool_id, 0);
#if PP2_BM_BUF_DEBUG
  pp2_bm_pool_print_regs (cpu_slot, pool_id);
#endif
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
static int
create_of_sh (void)
{
  FILE *of_sh;
  char *script_str = OF_SCRIPT_STR;
  char command[PATH_MAX];

  of_sh = fopen (OF_SH_FILENAME, "r");
  if (of_sh)
    {
      fclose (of_sh);
      return 0;
    }

  of_sh = fopen (OF_SH_FILENAME, "w");
  if (unlikely (!of_sh))
    {
      pr_err ("Couldn't create OF file!\n");
      return -EFAULT;
    }
  fputs (script_str, of_sh);
  fclose (of_sh);
  snprintf (command, sizeof (command), "sync; chmod 755 %s", OF_SH_FILENAME);
  system (command);
  return 0;
}

static char *
of_basename (const char *full_name)
{
  char *name;

  name = strrchr (full_name, '/');
  if (unlikely (name == NULL))
    return NULL;
  if (name != full_name)
    name++;
  return name;
}

static struct device_node *
mv_of_get_parent (const struct device_node *dev_node)
{
  struct device_node *_current_node;

  if (dev_node == NULL)
    dev_node = &root;

  *(_current_node = &current_node[current]) = *dev_node;
  _current_node->name = strrchr (_current_node->full_name, '/');
  if (unlikely (_current_node->name == NULL))
    return NULL;
  if (_current_node->name == _current_node->full_name)
    return &root;

  *_current_node->name = 0;
  _current_node->name = of_basename (_current_node->full_name);
  if (unlikely (_current_node->name == NULL))
    return NULL;

  current = (current + 1) % ARRAY_SIZE (current_node);
  return _current_node;
}
static void *
mv_of_get_property (struct device_node *dev_node, const char *name, size_t *lenp)
{
  int _err, __err;
  size_t len;
  char command[PATH_MAX * 2];
  FILE *of_sh;

  assert (name != NULL);

  if (dev_node == NULL)
    dev_node = &root;

  _err = create_of_sh ();
  if (_err)
    return NULL;

  snprintf (command, sizeof (command), "%s %s \"%s\" \"%s\"", OF_SH_FILENAME, "of_get_property",
	    dev_node->full_name, name);

  of_sh = popen (command, "r");
  if (unlikely (!of_sh))
    return NULL;

  len =
    fread (dev_node->_property, sizeof (*dev_node->_property), sizeof (dev_node->_property), of_sh);
  _err = len == 0 ? ferror (of_sh) : 0;
  __err = pclose (of_sh);

  if (unlikely (_err != 0 || __err != 0))
    return NULL;

  if (lenp != NULL)
    *lenp = len * sizeof (*dev_node->_property);

  return dev_node->_property;
}
static u32
mv_of_n_addr_cells (const struct device_node *dev_node)
{
  struct device_node *parent_node;
  size_t lenp;
  const u32 *na;

  if (dev_node == NULL)
    dev_node = &root;

  do
    {
      parent_node = mv_of_get_parent (dev_node);

      na = mv_of_get_property (parent_node, "#address-cells", &lenp);
      if (na != NULL)
	{
	  u32 ans;

	  assert (lenp == sizeof (u32));
	  ans = *na;
#if __BYTE_ORDER == __BIG_ENDIAN
	  /* Do nothing */
#else
	  ans = swab32 (ans);
#endif /* __BYTE_ORDER == __BIG_ENDIAN */
	  return ans;
	}
    }
  while (parent_node != &root);

  return OF_DEFAULT_NA;
}
static u32
mv_of_n_size_cells (const struct device_node *dev_node)
{
  struct device_node *parent_node;
  size_t lenp;
  const u32 *ns;

  if (dev_node == NULL)
    dev_node = &root;

  do
    {
      parent_node = mv_of_get_parent (dev_node);

      ns = mv_of_get_property (parent_node, "#size-cells", &lenp);
      if (ns != NULL)
	{
	  u32 ans;

	  assert (lenp == sizeof (u32));
	  ans = *ns;
#if __BYTE_ORDER == __BIG_ENDIAN
	  /* Do nothing */
#else
	  ans = swab32 (ans);
#endif /* __BYTE_ORDER == __BIG_ENDIAN */
	  return ans;
	}
    }
  while (parent_node != &root);

  return OF_DEFAULT_NS;
}
static void
of_bus_default_count_cells (const struct device_node *dev_node, u32 *addr, u32 *size)
{
  if (dev_node == NULL)
    dev_node = &root;

  if (addr != NULL)
    *addr = mv_of_n_addr_cells (dev_node);
  if (size != NULL)
    *size = mv_of_n_size_cells (dev_node);
}
static const u32 *
of_get_address_prop (struct device_node *dev_node, int index, u64 *size, u32 *flags,
		     const char *rprop)
{
  const u32 *uint32_prop;
#if __BYTE_ORDER != __BIG_ENDIAN
  u32 *uint32_prop_tmp;
#endif /* __BYTE_ORDER != __BIG_ENDIAN */
  size_t lenp;
  u32 na, ns;

  assert (dev_node != NULL);

  of_bus_default_count_cells (dev_node, &na, &ns);

  uint32_prop = mv_of_get_property (dev_node, rprop, &lenp);
  if (unlikely (uint32_prop == NULL))
    return NULL;

  assert ((lenp % ((na + ns) * sizeof (u32))) == 0);

  uint32_prop += (na + ns) * index;
  if (size != NULL)
    for (*size = 0; ns > 0; ns--, na++)
      *size = (*size << 32) + uint32_prop[na];

#if __BYTE_ORDER == __BIG_ENDIAN
  /* do nothing */
#else
  uint32_prop_tmp = (u32 *) uint32_prop;
  if (size != NULL)
    *size = swab64 (*size);
  *uint32_prop_tmp = swab32 (*uint32_prop_tmp);
#endif /* __BYTE_ORDER == __BIG_ENDIAN */

  return uint32_prop;
}

static struct device_node *
find_compatible_node_by_indx (const struct device_node *from, const int indx, const char *type,
			      const char *compatible)
{
  int _err, __err;
  char command[PATH_MAX * 2], *full_name;
  FILE *of_sh;
  struct device_node *dev_node;

  assert (compatible != NULL);

  if (from == NULL)
    from = &root;

  _err = create_of_sh ();
  if (_err)
    return NULL;

  snprintf (command, sizeof (command), "%s of_find_compatible_node \"%s\" \"%s\" %hhu",
	    OF_SH_FILENAME, from->full_name, compatible, indx + 1);

  of_sh = popen (command, "r");
  if (unlikely (!of_sh))
    return NULL;

  dev_node = &current_node[current];
  full_name = fgets (dev_node->full_name, sizeof (dev_node->full_name), of_sh);
  if (full_name == NULL)
    {
      _err = ferror (of_sh);
      if (_err == 0)
	{
	  _err = feof (of_sh);
	  if (_err == 0)
	    assert (0);
	}
    }
  else
    _err = 0;
  __err = pclose (of_sh);

  if (unlikely (_err != 0 || __err != 0))
    return NULL;

  dev_node->name = of_basename (dev_node->full_name);
  if (dev_node->name == NULL)
    return NULL;

  current = (current + 1) % ARRAY_SIZE (current_node);

  return dev_node;
}

static int
sort_nodes_by_addrs (struct device_node **dev_nodes, u64 *devs_pa, u8 num_nodes)
{
  u8 i, j;

  if (num_nodes < 2)
    return 0;

  for (i = 0; i < num_nodes - 1; i++)
    for (j = 0; j < num_nodes - i - 1; j++)
      if (devs_pa[j] > devs_pa[j + 1])
	{
	  struct device_node *tmp_node;
	  u64 tmp_pa;

	  tmp_pa = devs_pa[j];
	  tmp_node = dev_nodes[j];
	  devs_pa[j] = devs_pa[j + 1];
	  dev_nodes[j] = dev_nodes[j + 1];
	  devs_pa[j + 1] = tmp_pa;
	  dev_nodes[j + 1] = tmp_node;
	}

  return 0;
}
static const u32 *
mv_of_get_address (struct device_node *dev_node, int index, u64 *size, u32 *flags)
{
  return of_get_address_prop (dev_node, index, size, flags, "reg");
}

static u64
mv_of_translate_address (struct device_node *dev_node, const u32 *addr)
{
  u32 na;
  u64 phys_addr, prev_addr_offs, curr_addr_offs;
  const u32 *regs_addr;

  assert (dev_node != NULL);

  phys_addr = *addr;
  prev_addr_offs = phys_addr;
  do
    {
      dev_node = mv_of_get_parent (dev_node);
      if (unlikely (dev_node == NULL))
	{
	  /* we got to the root; let's break and return */
	  phys_addr = 0;
	  break;
	}

      /* look for field in the name 'ranges' */
      regs_addr = of_get_address_prop (dev_node, 0, NULL, NULL, "ranges");
      if (regs_addr == NULL)
	{
	  /* if 'ranges' not found, look for field 'regs' */
	  regs_addr = of_get_address_prop (dev_node, 0, NULL, NULL, "regs");
	  if (regs_addr == NULL)
	    /* in that case, there's probably no registers information in this node */
	    continue;
	}

      na = mv_of_n_addr_cells (dev_node);
      for (curr_addr_offs = 0; na > 0; na--, regs_addr += 2)
#if __BYTE_ORDER == __BIG_ENDIAN
	curr_addr_offs = (curr_addr_offs << 32) + *regs_addr;
#else
	curr_addr_offs = (curr_addr_offs << 32) + swab64 (*regs_addr);
#endif /* __BYTE_ORDER == __BIG_ENDIAN */
      /* TODO: for some reason, we may get the same offset twice;
       * Do not allow it (skip this cycle)!
       * We assume that the same offset may not be apeared twice
       * but as we go upper in the tree, the offsets must get bigger already.
       */
      if (curr_addr_offs <= prev_addr_offs)
	continue;
      phys_addr += curr_addr_offs;
      prev_addr_offs = curr_addr_offs;
    }
  while (dev_node != &root);

  return phys_addr;
}
static int
mv_of_device_is_compatible (struct device_node *dev_node, const char *compatible)
{
  size_t lenp, len;
  const char *_compatible;

  _compatible = mv_of_get_property (dev_node, "compatible", &lenp);
  if (unlikely (_compatible == NULL))
    return 0;

  while (lenp > 0)
    {
      if (strncasecmp (compatible, _compatible, strlen (compatible) + 1) == 0)
	return 1;

      len = strlen (_compatible) + 1;
      _compatible += len;
      lenp -= len;
    }

  return 0;
}

static struct device_node *
mv_of_find_compatible_node_by_indx (const struct device_node *from, const int indx,
				    const char *type, const char *compatible)
{
  struct device_node *dev_nodes[OF_MAX_NODES];
  u64 devs_pa[OF_MAX_NODES];
  u8 i, j, num_nodes, num_nodes_skipped;

  /* First, let's collect all nodes available from this compatible */
  num_nodes = 0;
  do
    {
      dev_nodes[num_nodes] = find_compatible_node_by_indx (from, num_nodes, type, compatible);
      if (!dev_nodes[num_nodes])
	break;
    }
  while (num_nodes++ < OF_MAX_NODES);

  if (!num_nodes)
    return NULL;

  /* There's a chance that we got some nodes that are not fully match; let's remove them from list
   */
  num_nodes_skipped = 0;
  for (i = 0; i < num_nodes; i++)
    if (!mv_of_device_is_compatible (dev_nodes[i], compatible))
      {
	for (j = i; j < num_nodes - 1; j++)
	  dev_nodes[j] = dev_nodes[j + 1];
	num_nodes_skipped++;
      }
  num_nodes -= num_nodes_skipped;

  if (indx >= num_nodes)
    return NULL;

  /* in case we have only 1 device found, no need to sort it */
  if (num_nodes == 1)
    return dev_nodes[0];

  /* Iterate all nodes we found and retrieve their base-address */
  for (i = 0; i < num_nodes; i++)
    {
      const uint32_t *uint32_prop;
      u64 tmp_size;

      uint32_prop = mv_of_get_address (dev_nodes[i], 0, &tmp_size, NULL);
      if (!uint32_prop)
	{
	  /* In case we don't find registers-region already in first entry,
	   * we assume all entires has no regs. in that case, return whatever we found.
	   */
	  if (i == 0)
	    return dev_nodes[indx];
	  /* if this is not the first entry, something is wrong here (since we assume all
	   * entries should look the same)
	   */
	  pr_err ("registers region (%s @ %d) not found!\n", compatible, i);
	  return NULL;
	}
      devs_pa[i] = mv_of_translate_address (dev_nodes[i], uint32_prop);
    }

  /* There's a chance that we got some nodes that are not fully match; let's remove them from list
   */
  num_nodes_skipped = 0;
  for (i = 0; i < num_nodes; i++)
    if (!devs_pa[i])
      {
	for (j = i; j < num_nodes - 1; j++)
	  {
	    dev_nodes[j] = dev_nodes[j + 1];
	    devs_pa[j] = devs_pa[j + 1];
	  }
	num_nodes_skipped++;
      }
  num_nodes -= num_nodes_skipped;

  if (indx >= num_nodes)
    return NULL;

  /* now, we sort the nodes by their addresses (since it is possible that we got the nodes
   * not-sorted) */
  sort_nodes_by_addrs (dev_nodes, devs_pa, num_nodes);

  return dev_nodes[indx];
}
static int
get_uio_num_from_filename (char *name)
{
  enum scan_states
  {
    ss_u,
    ss_i,
    ss_o,
    ss_num,
    ss_err
  };
  enum scan_states state = ss_u;
  int i = 0, num = -1;
  char ch = name[0];

  while (ch && (state != ss_err))
    {
      switch (ch)
	{
	case 'u':
	  if (state == ss_u)
	    state = ss_i;
	  else
	    state = ss_err;
	  break;
	case 'i':
	  if (state == ss_i)
	    state = ss_o;
	  else
	    state = ss_err;
	  break;
	case 'o':
	  if (state == ss_o)
	    state = ss_num;
	  else
	    state = ss_err;
	  break;
	default:
	  if ((ch >= '0') && (ch <= '9') && (state == ss_num))
	    {
	      if (num < 0)
		num = (ch - '0');
	      else
		num = (num * 10) + (ch - '0');
	    }
	  else
	    state = ss_err;
	}
      i++;
      ch = name[i];
    }
  if (state == ss_err)
    num = -1;

  return num;
}

static int
get_uio_line_from_file (char *filename, char *linebuf)
{
  char *s;
  int i;
  FILE *file = fopen (filename, "r");

  if (!file)
    return -1;

  memset (linebuf, 0, UIO_MAX_NAME_SIZE);
  s = fgets (linebuf, UIO_MAX_NAME_SIZE, file);
  if (!s)
    {
      fclose (file);
      return -2;
    }
  for (i = 0; (*s) && (i < UIO_MAX_NAME_SIZE); i++)
    {
      if (*s == '\n')
	*s = 0;
      s++;
    }
  fclose (file);

  return 0;
}

static struct uio_info_t *
get_uio_info_byname (char *name, const char *filter_name)
{
  struct uio_info_t *info;
  char linebuf[UIO_MAX_NAME_SIZE];
  char filename[255];

  snprintf (filename, sizeof (filename), "%s/%s/name", UIO_BASE_PATH, name);
  if (get_uio_line_from_file (filename, linebuf))
    return NULL;

  if (strncmp (linebuf, filter_name, strlen (filter_name)))
    return NULL;

  info = clib_mem_alloc_or_null (sizeof (struct uio_info_t));
  if (!info)
    return NULL;
  memset (info, 0, sizeof (struct uio_info_t));
  info->uio_num = get_uio_num_from_filename (name);

  return info;
}
static struct uio_info_t *
uio_find_devices_byname (const char *filter_name)
{
  struct dirent **namelist;
  struct uio_info_t *infolist = NULL, *infp, *last;
  int n;

  n = scandir (UIO_BASE_PATH, &namelist, 0, alphasort);
  if (n <= 0)
    {
      pr_err ("scandir for %s failed. errno = %d (%s)\n", UIO_BASE_PATH, errno, strerror (errno));
      return NULL;
    }
  while (n--)
    {
      infp = get_uio_info_byname (namelist[n]->d_name, filter_name);
      free (namelist[n]);
      if (!infp)
	continue;

      if (!infolist)
	infolist = infp;
      else
	last->next = infp;
      last = infp;
    }
  free (namelist);

  return infolist;
}

static int
get_uio_event_count (struct uio_info_t *info)
{
  int ret;
  char filename[MAX_FILE_NAME_LEN];
  FILE *file;

  info->event_count = 0;
  snprintf (filename, sizeof (filename), "%s/uio%d/event", UIO_BASE_PATH, info->uio_num);
  file = fopen (filename, "r");
  if (!file)
    return -1;
  ret = fscanf (file, "%d", (int *) (&info->event_count));
  fclose (file);
  if (ret < 0)
    return -2;

  return 0;
}

static int
get_uio_mem_addr (struct uio_info_t *info, int map_num)
{
  int ret;
  char filename[MAX_FILE_NAME_LEN];
  FILE *file;

  if (map_num >= MAX_UIO_MAPS)
    return -1;
  info->maps[map_num].addr = UIO_INVALID_ADDR;
  snprintf (filename, sizeof (filename), "%s/uio%d/maps/map%d/addr", UIO_BASE_PATH, info->uio_num,
	    map_num);
  file = fopen (filename, "r");
  if (!file)
    return -1;
  ret = fscanf (file, "0x%lx", &info->maps[map_num].addr);
  fclose (file);
  if (ret < 0)
    return -2;
  return 0;
}

static int
get_uio_mem_name (struct uio_info_t *info, int map_num)
{
  char filename[MAX_FILE_NAME_LEN];

  if (map_num >= MAX_UIO_MAPS)
    return -1;
  snprintf (filename, sizeof (filename), "%s/uio%d/maps/map%d/name", UIO_BASE_PATH, info->uio_num,
	    map_num);
  return get_uio_line_from_file (filename, info->maps[map_num].name);
}

static int
get_uio_mem_size (struct uio_info_t *info, int map_num)
{
  int ret;
  char filename[MAX_FILE_NAME_LEN];
  FILE *file;

  if (map_num >= MAX_UIO_MAPS)
    return -1;
  info->maps[map_num].size = UIO_INVALID_SIZE;
  snprintf (filename, sizeof (filename), "%s/uio%d/maps/map%d/size", UIO_BASE_PATH, info->uio_num,
	    map_num);
  file = fopen (filename, "r");
  if (!file)
    return -1;
  ret = fscanf (file, "0x%lx", &info->maps[map_num].size);
  fclose (file);
  if (ret < 0)
    return -2;
  return 0;
}

static int
get_uio_name (struct uio_info_t *info)
{
  char filename[MAX_FILE_NAME_LEN];

  snprintf (filename, sizeof (filename), "%s/uio%d/name", UIO_BASE_PATH, info->uio_num);
  return get_uio_line_from_file (filename, info->name);
}

static int
get_uio_version (struct uio_info_t *info)
{
  char filename[MAX_FILE_NAME_LEN];

  snprintf (filename, sizeof (filename), "%s/uio%d/version", UIO_BASE_PATH, info->uio_num);
  return get_uio_line_from_file (filename, info->version);
}

static int
uio_get_all_info (struct uio_info_t *info)
{
  int i;

  if (!info)
    return -1;
  if ((info->uio_num < 0) || (info->uio_num > UIO_MAX_NUM))
    return -1;
  for (i = 0; i < MAX_UIO_MAPS; i++)
    {
      get_uio_mem_size (info, i);
      get_uio_mem_addr (info, i);
      get_uio_mem_name (info, i);
    }
  get_uio_event_count (info);
  get_uio_name (info);
  get_uio_version (info);

  return 0;
}
static struct uio_info_t *
iomem_find_uio_device (const char *name, int index)
{
  char *tmp_name;
  char format_buf[UIO_MAX_FORMAT_SZ];
  int max_str_size = 0;
  struct uio_info_t *uio_info;

  if (name == NULL)
    return 0;

  max_str_size = strlen (UIO_HDR_STR) + strlen (name);
  max_str_size += strlen (UIO_ID_FORMAT_STR) + INT_32_MAX_DEC_STR_SZ + 1;
  tmp_name = clib_mem_alloc_or_null (max_str_size);
  if (!tmp_name)
    {
      pr_err ("no mem for IOMEM-name obj!\n");
      return NULL;
    }
  memset (tmp_name, 0, max_str_size);

  strcpy (format_buf, UIO_HDR_STR);
  if (index < 0)
    snprintf (tmp_name, max_str_size, format_buf, name);
  else
    {
      strcat (format_buf, UIO_ID_FORMAT_STR);
      snprintf (tmp_name, max_str_size, format_buf, name, index);
    }
  uio_info = uio_find_devices_byname (tmp_name);

  pr_debug ("%s: uio_name:%s found:%d\n", __func__, tmp_name, uio_info ? 1 : 0);
  clib_mem_free (tmp_name);
  return uio_info;
}

static inline uintptr_t
pp2_default_cpu_slot (struct pp2_inst *inst)
{
  return inst->hw.base[PP2_DEFAULT_REGSPACE].va;
}
static int
iomem_uio_ioinit (struct mem_uio *uiom, const char *name, int index)
{

  uiom->info = iomem_find_uio_device (name, index);
  if (!uiom->info)
    {
      pr_err ("%s: UIO device not found!\n", __func__);
      return -ENODEV;
    }

  struct uio_info_t *node;

  node = uiom->info;
  while (node)
    {
      uio_get_all_info (node);
      node = node->next;
    }

  return 0;
}
static int
iomem_mmap_ioinit (struct mem_mmap *mmapm, char *name, int index)
{
  INIT_LIST (&mmapm->maps_lst);

  mmapm->dev_node = mv_of_find_compatible_node_by_indx (NULL, index, NULL, name);

  if (pagesize == -1)
    pagesize = getpagesize ();

  return 0;
}
static int
iomem_shmem_ioinit (struct mem_shm *shm, char *name, int index, u32 size)
{
  memcpy (shm->dev_name, name, sizeof (shm->dev_name));
  if (!size)
    size = sysconf (_SC_PAGE_SIZE);
  shm->size = size;

  return 0;
}
enum pp2_cls_engine_no_t
{
  MVPP2_ENGINE_C2 = 1,
  MVPP2_ENGINE_C3_A,
  MVPP2_ENGINE_C3_B,
  MVPP2_ENGINE_C4,
  MVPP2_ENGINE_C3_HA = 6,
  MVPP2_ENGINE_C3_HB,
};
enum pp2_cls_cls_seq_ctrl_t
{
  MVPP2_CLS_SEQ_CTRL_NORMAL = 0,
  MVPP2_CLS_SEQ_CTRL_FIRST_TYPE_1,
  MVPP2_CLS_SEQ_CTRL_FIRST_TYPE_2,
  MVPP2_CLS_SEQ_CTRL_LAST,
  MVPP2_CLS_SEQ_CTRL_MIDDLE,
};
enum pp2_cls_rl_udf7_t
{
  MVPP2_CLS_KERNEL_UDF7 = 1,
  MVPP2_CLS_MUSDK_NIC_UDF7 = 1,
  MVPP2_CLS_MUSDK_LOG_UDF7 = 2,
};
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

/* Lookup ID */
static struct pp2_cls_enum_str_t g_enum_prs_lookup[] = {
  { MVPP2_PRS_LU_MH, "MVPP2_PRS_LU_MH" },	{ MVPP2_PRS_LU_MAC, "MVPP2_PRS_LU_MAC" },
  { MVPP2_PRS_LU_DSA, "MVPP2_PRS_LU_DSA" },	{ MVPP2_PRS_LU_VLAN, "MVPP2_PRS_LU_VLAN" },
  { MVPP2_PRS_LU_VID, "MVPP2_PRS_LU_VID" },	{ MVPP2_PRS_LU_L2, "MVPP2_PRS_LU_L2" },
  { MVPP2_PRS_LU_PPPOE, "MVPP2_PRS_LU_PPPOE" }, { MVPP2_PRS_LU_IP4, "MVPP2_PRS_LU_IP4" },
  { MVPP2_PRS_LU_IP6, "MVPP2_PRS_LU_IP6" },	{ MVPP2_PRS_LU_FLOWS, "MVPP2_PRS_LU_FLOWS" },
  { MVPP2_PRS_LU_LAST, "MVPP2_PRS_LU_LAST" },
};

/* Protocol number*/
static struct pp2_cls_enum_str_t g_enum_prs_proto_num[] = {
  { ETH_P_8021Q, "VLAN1" }, { ETH_P_8021AD, "VLAN2" }, { ARP_PROTO, "ARP" },
  { PPPOE_PROTO, "PPPOE" }, { ETH_P_IP, "IPv4" },      { ETH_P_IPV6, "IPv6" },
  { IPPROTO_TCP, "TCP" },   { IPPROTO_UDP, "UDP" },    { IPPROTO_ICMP, "ICMP" },
};
enum mv_pp2x_prs_flow
{
  MVPP2_PRS_FL_START = 8,
  MVPP2_PRS_FL_IP4_TCP_NF_UNTAG = MVPP2_PRS_FL_START,
  MVPP2_PRS_FL_IP4_UDP_NF_UNTAG,
  MVPP2_PRS_FL_IP4_TCP_NF_TAG,
  MVPP2_PRS_FL_IP4_UDP_NF_TAG,
  MVPP2_PRS_FL_IP6_TCP_NF_UNTAG,
  MVPP2_PRS_FL_IP6_UDP_NF_UNTAG,
  MVPP2_PRS_FL_IP6_TCP_NF_TAG,
  MVPP2_PRS_FL_IP6_UDP_NF_TAG,
  MVPP2_PRS_FL_IP4_TCP_FRAG_UNTAG,
  MVPP2_PRS_FL_IP4_UDP_FRAG_UNTAG,
  MVPP2_PRS_FL_IP4_TCP_FRAG_TAG,
  MVPP2_PRS_FL_IP4_UDP_FRAG_TAG,
  MVPP2_PRS_FL_IP6_TCP_FRAG_UNTAG,
  MVPP2_PRS_FL_IP6_UDP_FRAG_UNTAG,
  MVPP2_PRS_FL_IP6_TCP_FRAG_TAG,
  MVPP2_PRS_FL_IP6_UDP_FRAG_TAG,
  MVPP2_PRS_FL_IP4_UNTAG, /* non-TCP, non-UDP, same for below */
  MVPP2_PRS_FL_IP4_TAG,
  MVPP2_PRS_FL_IP6_UNTAG,
  MVPP2_PRS_FL_IP6_TAG,
  MVPP2_PRS_FL_NON_IP_UNTAG,
  MVPP2_PRS_FL_NON_IP_TAG,
  MVPP2_PRS_FL_LAST,
  MVPP2_PRS_FL_TCAM_NUM = 52, /* The parser TCAM lines needed to
			       *generate flow ID
			       */
};
enum mv_pp2x_cls_lkp_type
{
  MVPP2_CLS_LKP_HASH = 0,
  MVPP2_CLS_LKP_VLAN_PRI,
  MVPP2_CLS_LKP_DSCP_PRI,
  MVPP2_CLS_LKP_DEFAULT,
  MVPP2_CLS_LKP_MUSDK_LOG_HASH,
  MVPP2_CLS_LKP_MUSDK_VLAN_PRI,
  MVPP2_CLS_LKP_MUSDK_DSCP_PRI,
  MVPP2_CLS_LKP_MUSDK_LOG_PORT_DEF,
  MVPP2_CLS_LKP_MUSDK_CLS,
  MVPP2_CLS_LKP_MAX,
};
struct mv_pp2x_prs_result_info
{
  u32 ri;
  u32 ri_mask;
};

struct mv_pp2x_prs_flow_id
{
  u32 flow_id;
  struct mv_pp2x_prs_result_info prs_result;
};

enum pp2_cls_rl_prio_t
{
  MVPP2_CLS_MUSDK_CLS_PRIO = 0,
  MVPP2_CLS_MUSDK_DSCP_PRIO,
  MVPP2_CLS_MUSDK_VLAN_PRIO,
  MVPP2_CLS_MUSDK_DEF_PRIO,
  MVPP2_CLS_MUSDK_HASH_PRIO,
  MVPP2_CLS_KERNEL_DSCP_PRIO,
  MVPP2_CLS_KERNEL_VLAN_PRIO,
  MVPP2_CLS_KERNEL_DEF_PRIO,
  MVPP2_CLS_KERNEL_HASH_PRIO
};

enum pp2_cls_plcr_ref_cnt_action_t
{
  MVPP2_PLCR_REF_CNT_INC = 0, /* increase reference counter by 1	*/
  MVPP2_PLCR_REF_CNT_DEC,     /* decrease reference counter by 1	*/
  MVPP2_PLCR_REF_CNT_CLEAR    /* clear reference counter to be 0	*/
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

enum pp2_cls_tbl_action_type
{
  PP2_CLS_TBL_ACT_DROP = 0,
  PP2_CLS_TBL_ACT_DONE,
  /* TODO: PP2_CLS_TBL_ACT_LU */
};

enum pp2_cls_tbl_type
{
  PP2_CLS_TBL_EXACT_MATCH = 0,
  PP2_CLS_TBL_MASKABLE
};

#define MV_DEFAULT_MTU (1500)

/* Max-Transmit-unit (L3) to Max-Receive-Unit */
#define MV_MTU_TO_MRU(mtu) ((mtu) + MV_MH_SIZE + MV_VLAN_TAG_LEN + MV_ETH_HLEN + MV_ETH_FCS_LEN)

enum pp2_cls_cls_port_id_sel_t
{
  MVPP2_CLS_PORT_ID_FROM_TBL = 0,
  MVPP2_CLS_PORT_ID_FROM_PKT,
};

enum mv_net_eth_dsa_tag_mode_values
{
  MV_NET_TO_CPU_DSA_TAG_MODE = 0,
  MV_NET_FROM_CPU_DSA_TAG_MODE = 1,
  MV_NET_TO_SNIFFER_DSA_TAG_MODE = 2,
  MV_NET_FORWARD_DSA_TAG_MODE = 3,
};

struct pp2_cls_plcr
{
  int pp2_id; /* PP2 Instance */
  int id;     /* policer id */
};
struct pp2_cls_early_drop
{
  int pp2_id; /* PP2 Instance */
  int id;     /* early-drop id */
};
struct pp2_cls_cos_desc
{
  struct pp2_ppio *ppio;
  u8 tc;
  int override_color;		 /** 0 for default color */
  enum pp2_ppio_color pkt_color; /**< New color for given TC */
};

struct pp2_cls_tbl_action
{
  enum pp2_cls_tbl_action_type type;
  /** Valid only in case of 'MASKABLE' table.
   * This value will be reflected on the inQ descriptor in case of hit.
   * Allowed values: 0-4095. Value of '0' means 'not in use'.
   */
  u16 flow_id;
  /* TODO: struct pp2_cls_tbl		*next_tbl; */
  /** 'NULL' value means no-cos change; i.e. keep original cos */
  struct pp2_cls_cos_desc *cos;
  /** 'NULL' value means no-plcr change; i.e. keep original plcr */
  struct pp2_cls_plcr *plcr;
};

struct pp2_cls_tbl_key
{
  u8 key_size;
  u8 num_fields;
  struct pp2_proto_field proto_field[PP2_CLS_TBL_MAX_NUM_FIELDS];
};

struct pp2_cls_tbl_params
{
  enum pp2_cls_tbl_type type;
  u16 max_num_rules;
  struct pp2_cls_tbl_key key;
  /* TODO: enum pp2_cls_tbl_statistics_mode	 stats_mode; */
  /* TODO: enum pp2_cls_tbl_aging_mode	 aging_mode; */
  /* TODO: enum pp2_cls_tbl_priority_mode	 prio_mode; */
  struct pp2_cls_tbl_action default_act;
};
struct pp2_cls_rule_key_field
{
  u8 size;
  u8 *key;
  u8 *mask;
};

/*TODO : Add union to support future API's */

struct pp2_cls_tbl_rule
{
  u8 num_fields;
  struct pp2_cls_rule_key_field fields[PP2_CLS_TBL_MAX_NUM_FIELDS];
};

enum pp2_cls_qos_tbl_type
{
  PP2_CLS_QOS_TBL_NONE = 0, /**< No QoS support */
  /** QoS according to VLAN-priority (outer tag) if exists; otherwise, use default */
  PP2_CLS_QOS_TBL_VLAN_PRI,
  /** QoS according to IP-priority (i.e. DSCP) if exists;
   * otherwise, use default
   */
  PP2_CLS_QOS_TBL_IP_PRI,
  /** QoS according to VLAN-priority (outer tag) if exists; otherwise, use IP-priority (i.e. DSCP)
   * if exists; otherwise, use default
   */
  PP2_CLS_QOS_TBL_VLAN_IP_PRI,
  /** QoS according to IP-priority (i.e. DSCP) if exists; otherwise, use VLAN-priority (outer tag)
   * if exists; otherwise, use default
   */
  PP2_CLS_QOS_TBL_IP_VLAN_PRI,
  PP2_CLS_QOS_TBL_OUT_OF_RANGE /**< Invalid QoS type */
};

struct pp2_cls_qos_tbl_params
{
  enum pp2_cls_qos_tbl_type type;
  struct pp2_cls_cos_desc pcp_cos_map[MV_VLAN_PRIO_NUM];
  struct pp2_cls_cos_desc dscp_cos_map[MV_DSCP_NUM];
};

struct pp2_cls_rule_node
{
  struct pp2_cls_tbl_rule rule;
  u32 logic_index; /* Logical index in C2 or C3 database */
  struct pp2_cls_tbl_action action;
  struct list list_node;
};

struct pp2_cls_tbl
{
  enum pp2_cls_params_tbl_type type;
  struct pp2_cls_tbl_params params;
  struct pp2_cls_qos_tbl_params qos_params;
};

struct pp2_cls_tbl_node
{
  struct pp2_cls_tbl tbl;
  struct list list_node;
  struct list pp2_cls_tbl_rule_head;
};

struct pp2_ppio_sg_desc
{
  u8 num_frags;
  struct pp2_ppio_desc descs[PP2_PPIO_DESC_NUM_FRAGS];
};

struct pp2_ppio_sg_pkts
{
  u16 num;   /**< Number of scatter-gather packets */
  u8 *frags; /**< Array with size of 'num' representing
	      *   the number of fragments per packet
	      */
};
struct port_uc_addr_node
{
  struct list list_node;
  u8 addr[ETH_ALEN];
};
struct sys_hugepage
{
  u64 size;
  u64 shm_id;
  u64 huge_page_size;
  void *shm_va[HUGE_PAGE_MAX_PAGE_COUNT];
  phys_addr_t shm_pa[HUGE_PAGE_MAX_PAGE_COUNT];
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

struct mv_pp2x_cls_flow_entry
{
  u32 index;
  u32 data[MVPP2_CLS_FLOWS_TBL_DATA_WORDS];
};
struct pp2_prs_udf_map
{
  int user_udf_idx; /* pp2_parse_udf_params array index */
  u8 prs_udf_id;    /* hw udf number */
  int tid;	    /* parser tcam index for 1st entry */
  int tid2;	    /* parser tcam index for 2nd entry */
};

struct mv_pp2x_cls_lookup_entry
{
  u32 lkpid;
  u32 way;
  u32 data;
};
enum pp2_cls_c2_db_entry_valid_t
{
  MVPP2_C2_ENTRY_INVALID = 0,
  MVPP2_C2_ENTRY_VALID
};
enum pp2_cls_c3_db_entry_valid_t
{
  MVPP2_C3_ENTRY_INVALID = 0, /* invalid C3 entry	*/
  MVPP2_C3_ENTRY_VALID	      /* valid C3 entry	*/
};
enum pp2_cls_rl_mrg_state_t
{
  MVPP2_MRG_NOT_NEW = 0x0000,	/* merged rule no new		*/
  MVPP2_MRG_NEW = 0x0001,	/* merged rule new		*/
  MVPP2_MRG_NEW_EXISTS = 0x0002 /* merged rule exists		*/
};

enum pp2_cls_rl_cnt_op_t
{
  MVPP2_CNT_INC = 0x0000, /* increment engine counter	*/
  MVPP2_CNT_DEC = 0x0001  /* decrement engine counter	*/
};
struct pp2_cls_fl_eng_cnt_t
{
  u8 c2; /* C2 engine count		*/
  u8 c3; /* C3 engine count		*/
  u8 c4; /* C4 engine count		*/
};

struct pp2_cls_lkp_dcod_entry_t
{
  u8 cpu_q;							     /* CPU queue			*/
  u8 way;							     /* entry way			*/
  u8 flow_len;							     /* flow length			*/
  u16 flow_log_id;						     /* flow logical ID		*/
  u16 luid_num;							     /* Lookup ID number		*/
  struct pp2_cls_luid_conf_t luid_list[MVPP2_CLS_LOG_FLOW_LUID_MAX]; /* Lookup ID list		*/
};

struct pp2_cls_fl_rule_entry_t
{
  u16 fl_log_id; /* flow logical id              */
  u16 rl_log_id; /* rule logical id              */
  u16 port_type; /* port type			*/
  u16 port_bm;	 /* port bitmap			*/
  u16 lu_type;	 /* lookup type                  */
  u8 enabled;	 /* enable flag		*/
  u8 prio;	 /* HW priority                  */
  u8 engine;	 /* engine to use                */
  u8 udf7;
  u8 seq_ctrl;
  u8 field_id_cnt;			   /* field ID count		*/
  u8 field_id[MVPP2_FLOW_FIELD_COUNT_MAX]; /* field IDs			*/
};
struct pp2_cls_rl_entry_t
{
  u16 rl_log_id;	      /* rule logical id		*/
  u16 rl_off;		      /* rule offset			*/
  u16 ref_cnt[PP2_NUM_PORTS]; /* rule reference count         */
  u16 port_type;	      /* port type			*/
  u16 port_bm;		      /* port bitmap			*/
  u16 lu_type;		      /* lookup type                  */
  u8 prio;		      /* HW priority                  */
  u8 engine;		      /* engine to use                */
  u8 enabled;		      /* enable flag			*/
  u8 skip;		      /* skip flag			*/
  u8 udf7;
  u8 seq_ctrl;
  u8 field_id_cnt;			   /* field ID count		*/
  u8 field_id[MVPP2_FLOW_FIELD_COUNT_MAX]; /* field IDs			*/
  enum pp2_cls_rl_mrg_state_t state;	   /* rule state			*/
};

struct pp2_cls_fl_t
{
  u16 fl_log_id;					 /* flow logical id              */
  u16 fl_len;						 /* flow length			*/
  struct pp2_cls_rl_entry_t fl[MVPP2_CLS_FLOW_RULE_MAX]; /* flow rules			*/
  struct pp2_cls_fl_eng_cnt_t eng_cnt;			 /* flow rules engine count	*/
};
struct pp2_cls_c3_shadow_hash_entry
{
  /* valid if size > 0 */
  /* size include the extension*/
  int ext_ptr;
  int size;
};

struct pp2_cls_fl_rule_list_t
{
  struct pp2_cls_fl_rule_entry_t fl[MVPP2_CLS_FLOW_RULE_MAX]; /* flow rules			*/
  u16 fl_len;						      /* flow length			*/
};

enum musdk_lnx_id
{
  LNX_VER_INVALID = -1,
  LNX_4_4_x = 0,
  LNX_4_14_x = 1,
  LNX_OTHER = 2 /* Currently LNX_5_x */
};

struct pp2_lnx_format
{
  enum musdk_lnx_id ver;
  char *devtree_path;
  char *eth_format;
};

static struct pp2_lnx_format pp2_frm[] = {
  {
    .ver = LNX_4_4_x,
    .devtree_path = "/proc/device-tree/cp%u/config-space/ppv22@000000/",
    .eth_format = "eth%d@0%d0000",
  },
  {
    .ver = LNX_4_14_x,
    .devtree_path = "/proc/device-tree/cp%u/config-space/ethernet@0/",
    .eth_format = "eth%d",
  },
  {
    .ver = LNX_OTHER,
    .devtree_path = "/proc/device-tree/cp%u/config-space@%x/ethernet@0/",
    .eth_format = "eth%d",
  },
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
static struct mv_pp2x_prs_flow_id mv_pp2x_prs_flow_id_array[MVPP2_PRS_FL_TCAM_NUM] = {
  /***********#Flow ID#**************#Result Info#************/
  /* TCP over IPv4 flows, Not fragmented, no vlan tag */
  { MVPP2_PRS_FL_IP4_TCP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* TCP over IPv4 flows, Not fragmented, with vlan tag */
  { MVPP2_PRS_FL_IP4_TCP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* TCP over IPv4 flows, fragmented, no vlan tag */
  { MVPP2_PRS_FL_IP4_TCP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* TCP over IPv4 flows, fragmented, with vlan tag */
  { MVPP2_PRS_FL_IP4_TCP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* UDP over IPv4 flows, Not fragmented, no vlan tag */
  { MVPP2_PRS_FL_IP4_UDP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* UDP over IPv4 flows, Not fragmented, with vlan tag */
  { MVPP2_PRS_FL_IP4_UDP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* UDP over IPv4 flows, fragmented, no vlan tag */
  { MVPP2_PRS_FL_IP4_UDP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* UDP over IPv4 flows, fragmented, with vlan tag */
  { MVPP2_PRS_FL_IP4_UDP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* TCP over IPv6 flows, not fragmented, no vlan tag */
  { MVPP2_PRS_FL_IP6_TCP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_TCP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* TCP over IPv6 flows, not fragmented, with vlan tag */
  { MVPP2_PRS_FL_IP6_TCP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_TCP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* TCP over IPv6 flows, fragmented, no vlan tag */
  { MVPP2_PRS_FL_IP6_TCP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_TCP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* TCP over IPv6 flows, fragmented, with vlan tag */
  { MVPP2_PRS_FL_IP6_TCP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_TCP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* UDP over IPv6 flows, not fragmented, no vlan tag */
  { MVPP2_PRS_FL_IP6_UDP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_UDP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* UDP over IPv6 flows, not fragmented, with vlan tag */
  { MVPP2_PRS_FL_IP6_UDP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_UDP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* UDP over IPv6 flows, fragmented, no vlan tag */
  { MVPP2_PRS_FL_IP6_UDP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_UDP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* UDP over IPv6 flows, fragmented, with vlan tag */
  { MVPP2_PRS_FL_IP6_UDP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_UDP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  /* IPv4 flows, no vlan tag */
  { MVPP2_PRS_FL_IP4_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OPT,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OTHER,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK } },

  /* IPv4 flows, with vlan tag */
  { MVPP2_PRS_FL_IP4_TAG, { MVPP2_PRS_RI_L3_IP4, MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TAG, { MVPP2_PRS_RI_L3_IP4_OPT, MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TAG, { MVPP2_PRS_RI_L3_IP4_OTHER, MVPP2_PRS_RI_L3_PROTO_MASK } },

  /* IPv6 flows, no vlan tag */
  { MVPP2_PRS_FL_IP6_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6_EXT,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK } },

  /* IPv6 flows, with vlan tag */
  { MVPP2_PRS_FL_IP6_TAG, { MVPP2_PRS_RI_L3_IP6, MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_TAG, { MVPP2_PRS_RI_L3_IP6_EXT, MVPP2_PRS_RI_L3_PROTO_MASK } },

  /* Non IP flow, no vlan tag */
  { MVPP2_PRS_FL_NON_IP_UNTAG, { MVPP2_PRS_RI_VLAN_NONE, MVPP2_PRS_RI_VLAN_MASK } },

  /* Non IP flow, with vlan tag */
  { MVPP2_PRS_FL_NON_IP_TAG, { 0, 0 } },
};

static struct mv_pp2x_prs_flow_id mv_pp2x_prs_flow_id_array_4_4[MVPP2_PRS_FL_TCAM_NUM] = {
  /***********#Flow ID#**************#Result Info#************/
  { MVPP2_PRS_FL_IP4_TCP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP4_UDP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP4_TCP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP4_UDP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP6_TCP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_TCP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP6_UDP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_UDP_NF_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_FALSE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP6_TCP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_TCP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP6_UDP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_UDP_NF_TAG,
    { MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_FALSE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP4_TCP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP4_UDP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP4_TCP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TCP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP4_UDP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4 | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4_OPT | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UDP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP4_OTHER | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP6_TCP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_TCP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP6_UDP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_UDP_FRAG_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_TRUE |
	MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK |
	MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP6_TCP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_TCP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_TCP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP6_UDP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP6 | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_UDP_FRAG_TAG,
    { MVPP2_PRS_RI_L3_IP6_EXT | MVPP2_PRS_RI_IP_FRAG_TRUE | MVPP2_PRS_RI_L4_UDP,
      MVPP2_PRS_RI_L3_PROTO_MASK | MVPP2_PRS_RI_IP_FRAG_MASK | MVPP2_PRS_RI_L4_PROTO_MASK } },

  { MVPP2_PRS_FL_IP4_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OPT,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP4_OTHER,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK } },

  { MVPP2_PRS_FL_IP4_TAG, { MVPP2_PRS_RI_L3_IP4, MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TAG, { MVPP2_PRS_RI_L3_IP4_OPT, MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP4_TAG, { MVPP2_PRS_RI_L3_IP4_OTHER, MVPP2_PRS_RI_L3_PROTO_MASK } },

  { MVPP2_PRS_FL_IP6_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_UNTAG,
    { MVPP2_PRS_RI_VLAN_NONE | MVPP2_PRS_RI_L3_IP6_EXT,
      MVPP2_PRS_RI_VLAN_MASK | MVPP2_PRS_RI_L3_PROTO_MASK } },

  { MVPP2_PRS_FL_IP6_TAG, { MVPP2_PRS_RI_L3_IP6, MVPP2_PRS_RI_L3_PROTO_MASK } },
  { MVPP2_PRS_FL_IP6_TAG, { MVPP2_PRS_RI_L3_IP6_EXT, MVPP2_PRS_RI_L3_PROTO_MASK } },

  { MVPP2_PRS_FL_NON_IP_UNTAG, { MVPP2_PRS_RI_VLAN_NONE, MVPP2_PRS_RI_VLAN_MASK } },

  { MVPP2_PRS_FL_NON_IP_TAG, { 0, 0 } },
};

static int mv_pp2x_prs_flow_id_attr_tbl[MVPP2_PRS_FL_LAST];
static struct pp2_prs_udf_map prs_udf_map[PP2_MAX_UDFS_SUPPORTED] = {
  { -1, MVPP2_PRS_SRAM_UDF_TYPE_3, -1, -1 },
  { -1, MVPP2_PRS_SRAM_UDF_TYPE_5, -1, -1 },
  { -1, MVPP2_PRS_SRAM_UDF_TYPE_6, -1, -1 },
};

static inline u32 cm3_read (uintptr_t base, u32 offset);
static int iomem_mmap_iomap (struct mem_mmap *mmapm, const char *name, phys_addr_t *pa, void **va);
static int iomem_mmap_iounmap (struct mem_mmap *mmapm, const char *name);
static int iomem_shmem_iomap (struct mem_shm *shm, const char *name, phys_addr_t *pa, void **va);
static int iomem_shmem_iounmap (struct mem_shm *shm, const char *name);
static int iomem_uio_iomap (struct mem_uio *uiom, const char *name, phys_addr_t *pa, void **va);
static int iomem_uio_iounmap (struct mem_uio *uiom, const char *name);
static inline bool mv_check_eaddr_uc (const u8 *addr);
static int mv_netdev_ioctl (u32 ctl, struct ifreq *s);
static int mv_pp2x_cls_hw_lkp_write (uintptr_t cpu_slot, struct mv_pp2x_cls_lookup_entry *fe);
static int mv_pp2x_cls_sw_lkp_en_set (struct mv_pp2x_cls_lookup_entry *lkp, int en);
static int mv_pp2x_cls_sw_lkp_flow_set (struct mv_pp2x_cls_lookup_entry *lkp, int flow_idx);
static int mv_pp2x_cls_sw_lkp_rxq_set (struct mv_pp2x_cls_lookup_entry *lkp, int rxq);
static int parse_hex (char *str, u8 *addr, size_t size);

static int pp2_cls_db_plcr_ref_cnt_update (struct pp2_inst *inst, u8 policer_id,
					   enum pp2_cls_plcr_ref_cnt_action_t cnt_action,
					   int update_ppio);
static int pp2_prs_tag_mode_set (struct pp2_port *port, int type, int val,
				 enum pp2_ppio_cls_target target);

static int pp2_prs_proto_lookup (u16 proto, u16 lookup[], u16 proto_num[]);
static int pp2_prs_tcam_idx_list_build (struct pp2_inst *inst, u32 lookup, u16 proto, int negate,
					u32 ri);
static const char *pp2_g_enum_prs_lookup_str_get (int value);
static const char *pp2_g_enum_prs_proto_num_str_get (int value);

static void mv_pp2x_prs_sram_bits_set (struct mv_pp2x_prs_entry *pe, int bit_num, int val);
static void mv_pp2x_prs_sram_bits_clear (struct mv_pp2x_prs_entry *pe, int bit_num, int val);
static int pp2_cls_fl_rl_eng_cnt_upd (enum pp2_cls_rl_cnt_op_t op, u16 eng,
				      struct pp2_cls_fl_eng_cnt_t *eng_cnt);
static enum musdk_lnx_id lnx_id_get (void);
static int lnx_is_mainline (enum musdk_lnx_id lnx_id);

static int pp2_bm_get_8pool_mode (uintptr_t cpu_slot);
static int cmp_prio (const void *rl1, const void *rl2);
static int pp2_cls_mng_tbl_init (struct pp2_cls_tbl_params *params, struct pp2_cls_tbl **tbl,
				 int lkp_type);

static inline void cm3_write (uintptr_t base, u32 offset, u32 data);
static void dm_lock_create (struct pp2_dm_if *dm_if);
static void dm_lock_destroy (struct pp2_dm_if *dm_if);
static void iomem_mmap_iodestroy (struct mem_mmap *mmapm);
static void iomem_shmem_iodestroy (struct mem_uio *uiom);
static void iomem_uio_iodestroy (struct mem_uio *uiom);
static void mv_pp2x_cls_oversize_rxq_set (struct pp2_port *port);
static void mv_pp2x_prs_clear_active_vlans (struct pp2_port *port, uint32_t *vlans);
static void mv_pp2x_prs_hw_inv (uintptr_t cpu_slot, int index);
static int mv_pp2x_prs_mac_da_accept (struct pp2_port *port, const u8 *da, bool add);
static void mv_pp2x_prs_shadow_set (struct pp2_inst *inst, int index, int lu);
static void mv_pp2x_prs_sram_ai_update (struct mv_pp2x_prs_entry *pe, unsigned int bits,
					unsigned int mask);
static int mv_pp2x_prs_sram_bit_set (struct mv_pp2x_prs_entry *pe, int bit_num, unsigned int val);
static void mv_pp2x_prs_sram_clear (struct mv_pp2x_prs_entry *pe);
static void mv_pp2x_prs_sram_next_lu_set (struct mv_pp2x_prs_entry *pe, unsigned int lu);
static void mv_pp2x_prs_sram_offset_set (struct mv_pp2x_prs_entry *pe, unsigned int type,
					 int offset, unsigned int op);
static void mv_pp2x_prs_tcam_ai_update (struct mv_pp2x_prs_entry *pe, unsigned int bits,
					unsigned int enable);
static void mv_pp2x_prs_tcam_data_byte_set (struct mv_pp2x_prs_entry *pe, unsigned int offs,
					    unsigned char byte, unsigned char enable);
static void mv_pp2x_prs_tcam_lu_set (struct mv_pp2x_prs_entry *pe, unsigned int lu);
static void mv_pp2x_prs_tcam_port_map_set (struct mv_pp2x_prs_entry *pe, unsigned int ports);
static int pp2_cls_c3_hit_cntrs_clear_all (uintptr_t cpu_slot);
static void pp2_cls_mng_config_default_cos_queue (struct pp2_port *port);
static void pp2_cls_mng_rss_port_init (struct pp2_port *port, u16 rss_map);
static int pp2_cls_mng_rule_add (struct pp2_cls_tbl *tbl, struct pp2_cls_tbl_rule *rule,
				 struct pp2_cls_tbl_action *action, int lkp_type);
static int pp2_cls_rss_mode_flows_set (struct pp2_port *port, int rss_mode);
static int pp2_get_devtree_port_data (struct netdev_if_params *netdev_params);
static inline u32 pp2_get_mem_id (u32 pp2_id);
static int pp2_netdev_if_info_get (struct netdev_if_params *netdev_params);
static int pp2_port_clear_kernel_unicast (struct pp2_port *port);
static int pp2_port_clear_vlan (struct pp2_port *port, u16 vlan);
static int pp2_port_close_uio (struct pp2_port *port);
static int pp2_port_config_txsched (struct pp2_port *port);
static void pp2_port_defaults_set (struct pp2_port *port);
static void pp2_port_deinit (struct pp2_port *port);
static void pp2_port_egress_disable (struct pp2_port *port);
static void pp2_port_egress_enable (struct pp2_port *port);
static uint16_t pp2_port_enqueue (struct pp2_port *port, struct pp2_dm_if *dm_if, uint8_t out_qid,
				  uint16_t num_txds, struct pp2_ppio_desc desc[],
				  struct pp2_ppio_sg_pkts *pkts);
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
static int pp2_prs_create_log_port_entry (struct pp2_port *port, u32 index,
					  enum pp2_ppio_cls_target target);
static int pp2_prs_log_port_proto_update (struct pp2_port *port, enum pp2_ppio_cls_target target);
static int pp2_prs_port_update (struct pp2_port *port, u32 add, u32 tid, u32 ri, u32 ri_mask);
static inline uint32_t pp2_relaxed_reg_read (uintptr_t cpu_slot, uint32_t offset);
static inline void pp2_relaxed_reg_write (uintptr_t cpu_slot, uint32_t offset, uint32_t data);
static void pp2_txq_init (struct pp2_port *port, struct pp2_tx_queue *txq);

static int mv_netdev_feature_set (const char *netdev, const char *featstr, int val);
static int mv_pp2x_prs_flow_id_attr_get (int flow_id);
static int mvpp2x_prs_mac_da_range_find (struct pp2_inst *inst, uintptr_t cpu_slot, int pmap,
					 const u8 *da, const u8 *mask, int udf_type);
static void mv_pp2x_prs_shadow_ri_set (struct pp2_inst *inst, int index, unsigned int ri,
				       unsigned int ri_mask);
static void mv_pp2x_prs_sram_shift_set (struct mv_pp2x_prs_entry *pe, int shift, unsigned int op);
static unsigned int mv_pp2x_prs_tcam_port_map_get (struct mv_pp2x_prs_entry *pe);
static void mv_pp2x_prs_tcam_port_set (struct mv_pp2x_prs_entry *pe, unsigned int port, bool add);
static int pp2_c2_config_default_queue (struct pp2_port *port, u16 queue);
static int pp2_cls_c2_rule_add (struct pp2_inst *inst, struct mv_pp2x_c2_add_entry *c2_entry,
				u32 *c2_logic_index);
static int pp2_cls_c3_rule_add (struct pp2_inst *inst, struct pp2_cls_c3_add_entry_t *c3_entry,
				u32 *logic_idx);
static int pp2_cls_db_mng_rule_check (struct pp2_cls_tbl *tbl, struct pp2_cls_tbl_rule *rule);
static int pp2_cls_db_mng_tbl_check (struct pp2_cls_tbl *tbl);
static int pp2_cls_db_mng_tbl_rule_add (struct pp2_cls_tbl *tbl, struct pp2_cls_tbl_rule **rule,
					u32 logic_index, struct pp2_cls_tbl_action **action);
static int pp2_cls_db_prs_match_list_idx_get (struct pp2_inst *inst, u32 index,
					      struct prs_log_port_tcam_node *node);
static int pp2_cls_db_prs_match_list_num_get (struct pp2_inst *inst);
static int pp2_cls_fl_rule_enable (struct pp2_inst *inst, struct pp2_cls_fl_rule_list_t *fl_rls);
static int pp2_cls_mng_qos_tbl_dflt_set (struct pp2_port *port, u16 queue);
static int pp2_cls_mng_rule_update_db (struct pp2_cls_tbl_rule *rule,
				       struct pp2_cls_tbl_rule *rule_db,
				       struct pp2_cls_tbl_action *action,
				       struct pp2_cls_tbl_action *action_db);
static void pp2_cls_mng_set_c2_action (struct pp2_port *port,
				       struct mv_pp2x_engine_qos_info *qos_info,
				       struct mv_pp2x_qos_value *pkt_qos,
				       struct mv_pp2x_engine_pkt_action *pkt_action,
				       struct pp2_cls_tbl_action *action, int lkp_type);
static void pp2_cls_mng_set_c3_action (struct pp2_port *port,
				       struct mv_pp2x_engine_qos_info *qos_info,
				       struct mv_pp2x_qos_value *pkt_qos,
				       struct mv_pp2x_engine_pkt_action *pkt_action,
				       struct pp2_cls_tbl_action *action, int lkp_type);
static void pp2_cls_set_hash_params (struct pp2_cls_fl_rule_list_t *fl_rls, struct pp2_port *port,
				     int engine, int lkpid, int lkpid_attr, int set);
static int pp2_cls_set_rule_info (struct pp2_cls_mng_pkt_key_t *mng_pkt_key,
				  struct mv_pp2x_src_port *rule_port,
				  struct pp2_cls_tbl_params *params, struct pp2_cls_tbl_rule *rule,
				  struct pp2_port *port);
static int pp2_gop_gmac_max_rx_size_set (struct gop_hw *gop, int mac_num, int max_rx_size);
static int pp2_gop_xlg_mac_max_rx_size_set (struct gop_hw *gop, int mac_num, int max_rx_size);
static void pp2_port_clear_fc_isr (struct pp2_port *port);
static void pp2_port_deinit_txsched (struct pp2_port *port);
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
static int pp2_txsched_port_burst_set (struct pp2_port *port, int burst);
static int pp2_txsched_port_rate_set (struct pp2_port *port, int rate);
static int pp2_txsched_queue_arbitration_set (struct pp2_port *port, u8 txq,
					      enum pp2_ppio_outq_sched_mode mode, u8 weight);
static int pp2_txsched_queue_burst_set (struct pp2_port *port, int txq, int burst);
static int pp2_txsched_queue_rate_set (struct pp2_port *port, int txq, int rate);
static void pp2_txsched_remap_weights (struct pp2_port *port, u8 remapped_weights[]);
static void uio_free_info (struct uio_info_t *info);

static inline int kstrtou16 (const char *s, unsigned int base, u16 *res);
static inline int kstrtou32 (const char *s, unsigned int base, u32 *res);
static inline int kstrtou8 (const char *s, unsigned int base, u8 *res);
static int list_num_objs (struct list *lst);
static u32 lookup_field_id (struct pp2_proto_field proto_field, u32 *field_id, u32 *match_bm);
static void mv_netdev_clean_featstrs (struct netdev_featstrs *fs);
static int mv_netdev_set_feature_ioctl (int fd, struct ifreq *ifr, int bit, int val);
static int mv_pp2x_cls_c2_qos_tbl_fill_array (struct pp2_port *port, u8 tbl_sel,
					      uint8_t tc_values[]);
static int mv_pp2x_parse_mac_address (char *buf, u8 *macaddr_parts);
static void pp2_bm_pool_assign (struct pp2_port *port, uint32_t pool_id, u32 rxq_id, uint32_t type);
static int pp2_c2_config_queue (struct mv_pp2x_cls_c2_entry *c2, u16 queue, int from);
static int pp2_cls_c2_data_entry_db_add (struct pp2_inst *inst,
					 struct mv_pp2x_c2_add_entry *c2_entry, u32 *c2_db_idx);
static int pp2_cls_c2_free_list_add (struct pp2_inst *inst, u32 c2_hw_idx);
static int pp2_cls_c2_lkp_type_list_add (struct pp2_inst *inst, u8 lkp_type, u32 priority,
					 u32 c2_hw_idx, u32 c2_db_idx, u32 c2_logic_idx);
static int pp2_cls_c2_make_slot (struct pp2_inst *inst, u8 lkp_type, u32 priority, u32 *c2_hw_idx);
static int pp2_cls_c2_rule_add_check (struct mv_pp2x_c2_add_entry *c2_entry);
static u8 pp2_cls_c2_tcam_lkp_type_get (struct mv_pp2x_cls_c2_entry *c2);
static int pp2_cls_c2_tcam_set (uintptr_t cpu_slot, struct mv_pp2x_c2_add_entry *c2_entry,
				u32 c2_hw_idx);
static int pp2_cls_c3_hw_query_add (uintptr_t cpu_slot, struct pp2_cls_c3_entry *c3,
				    int max_search_depth,
				    struct pp2_cls_c3_hash_pair *hash_pair_arr);
static int pp2_cls_c3_rule_check (struct pp2_cls_c3_add_entry_t *c3_entry);
static int pp2_cls_c3_rule_convert (struct pp2_cls_c3_add_entry_t *mng_entry,
				    struct pp2_cls_c3_entry *hw_entry);
static void pp2_cls_c3_sw_clear (struct pp2_cls_c3_entry *c3);
static int pp2_cls_db_c3_entry_add (struct pp2_inst *inst, u32 logic_idx, u32 hash_idx);
static int pp2_cls_db_c3_free_logic_idx_get (struct pp2_inst *inst, u32 *logic_idx);
static int pp2_cls_db_c3_hash_idx_update (struct pp2_inst *inst,
					  struct pp2_cls_c3_hash_pair *hash_pair_arr);
static int pp2_cls_db_c3_search_depth_get (struct pp2_inst *inst, u32 *search_depth);
static int pp2_cls_db_rss_get_hw_tbl_from_in_q (struct pp2_inst *inst, u8 num_in_q);
static u16 pp2_cls_db_rss_kernel_rsvd_tbl_get (struct pp2_inst *inst);
static u16 pp2_cls_db_rss_num_musdk_tbl_get (struct pp2_inst *inst);
static void pp2_cls_db_rss_num_musdk_tbl_set (struct pp2_inst *inst, u16 num_musdk_tbl);
static int pp2_cls_db_rss_tbl_map_get_next_free_idx (struct pp2_inst *inst);
static int pp2_cls_db_rss_tbl_map_set (struct pp2_inst *inst, u16 idx, u16 hw_tbl, u16 num_in_q);
static void pp2_cls_edrop_bypass_assign_qid (struct pp2_inst *inst, u8 qid);
static int pp2_cls_fl_port_hw_read (struct pp2_inst *inst, int rl_log_id, int *port_bm);
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
static int pp2_txsched_rate_calc (u32 rate, u32 accuracy, u32 *pperiod, u32 *ptokens);
static u8 pp2_txsched_rational_weight_remap (u32 weight, u32 min, u32 max);
static void uio_free_dev_attrs (struct uio_info_t *info);
static struct pp2_tc *pp2_rxq_tc_get (struct pp2_port *port, uint32_t id);
static struct pp2_cls_c2_index_t *pp2_cls_db_c2_index_node_get (struct pp2_inst *inst,
								u32 c2_node_idx);
int pp2_cls_field_bm_to_field_info (u32 field_bm, struct pp2_cls_mng_pkt_key_t *pp2_cls_pkt_key,
				    u32 field_max, u8 l4_info,
				    struct pp2_cls_field_match_info field_info[]);
struct list *pp2_cls_db_c2_lkp_type_list_head_get (struct pp2_inst *inst, u8 lkp_type);
struct list *pp2_cls_db_c2_free_list_head_get (struct pp2_inst *inst);
int pp2_cls_db_c2_data_get (struct pp2_inst *inst, u32 c2_db_idx,
			    struct pp2_cls_c2_data_t *c2_data);
static int pp2_cls_c2_entry_is_free (struct pp2_inst *inst, u32 c2_hw_idx,
				     struct pp2_cls_c2_index_t **c2_index_node);
static int mv_netdev_get_featstrs (int fd, struct ifreq *ifr, struct netdev_featstrs *fs);
int pp2_rss_enable (struct pp2_port *port, int en);
int pp2_rss_hw_tbl_set (struct pp2_port *port);
int pp22_cls_rss_rxq_set (struct pp2_port *port);

int pp2_gop_gmac_loopback_cfg (struct gop_hw *gop, int mac_num, enum pp2_lb_type type);
int pp2_gop_xlg_mac_loopback_cfg (struct gop_hw *gop, int mac_num, enum pp2_lb_type type);
static int pp2_prs_dsa_tag_mode_set (struct pp2_port *port, u32 val, int tagged, int extend, u32 ri,
				     u32 ri_mask);
int pp2_prs_tcam_neg_proto_check (struct pp2_inst *inst, u32 proto);
int pp2_cls_db_prs_match_list_check (struct pp2_inst *inst, u32 index);
int pp2_cls_db_prs_match_list_remove_idx (struct pp2_inst *inst, u32 index);
int pp2_cls_db_prs_match_list_add (struct pp2_inst *inst, u32 idx, int log_port);
static const char *lookup_enum_str (struct pp2_cls_enum_str_t enum_str[], int enum_num,
				    int enum_value);
int pp2_cls_udf_field_add (struct pp2_inst *inst, u8 udf_num, u8 offset, u8 size);
static int pp2_cls_mng_get_lkpid_for_flow_type (u16 *select_logical_id, u32 ipv4_flag,
						u32 ipv6_flag, u32 tcp_flag, u32 udp_flag,
						u32 l4_flag);
static int pp2_cls_mng_get_lkpid_for_rss (int engine, u16 *select_logical_id, int ipv4_flag,
					  int ipv6_flag);
static int pp2_cls_mng_get_lkpid_for_lkp_type (int lkp_type, u16 *select_logical_id);
int pp2_cls_lkp_dcod_set_and_disable (struct pp2_inst *inst, u16 fl_log_id);
int pp2_cls_db_mng_tbl_add (struct pp2_cls_tbl **tbl);
static char *mv_strtok (char *src, const char *pattern);

int pp2_cls_db_prs_match_list_log_port_check (struct pp2_inst *inst);
int pp2_cls_lkp_dcod_disable (struct pp2_inst *inst, u16 fl_log_id);
static int pp2_cls_add_non_ip_logical_id (u16 *select_logical_id);
static int pp2_cls_add_ip4_logical_id (u16 *select_logical_id);
static int pp2_cls_add_ip4_tcp_logical_id (u16 *select_logical_id);
static int pp2_cls_add_ip4_udp_logical_id (u16 *select_logical_id);
static int pp2_cls_add_ip6_logical_id (u16 *select_logical_id);
static int pp2_cls_add_ip6_tcp_logical_id (u16 *select_logical_id);
static int pp2_cls_add_ip6_udp_logical_id (u16 *select_logical_id);

static int mv_pp2x_cls_c2_dscp_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int dscp, int from);
static int mv_pp2x_cls_c2_dup_set (struct mv_pp2x_cls_c2_entry *c2, int dupid, int count);
static int mv_pp2x_cls_c2_flow_id_en (struct mv_pp2x_cls_c2_entry *c2, int flow_id_en);
static int mv_pp2x_cls_c2_forward_set (struct mv_pp2x_cls_c2_entry *c2, int cmd);
static int mv_pp2x_cls_c2_gpid_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int gpid, int from);
static int mv_pp2x_cls_c2_mod_set (struct mv_pp2x_cls_c2_entry *c2, int data_ptr, int instr_offs,
				   int l4_csum);
static int mv_pp2x_cls_c2_prio_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int prio, int from);
static int mv_pp2x_cls_c2_qos_color_set (struct mv_pp2x_cls_c2_qos_entry *qos, int color);
static int mv_pp2x_cls_c2_qos_hw_write (struct pp2_hw *hw, struct mv_pp2x_cls_c2_qos_entry *qos);
static int mv_pp2x_cls_c2_qos_queue_set (struct mv_pp2x_cls_c2_qos_entry *qos, uint8_t queue);
static int mv_pp2x_cls_c2_qos_tbl_set (struct mv_pp2x_cls_c2_entry *c2, int tbl_id, int tbl_sel);
static int mv_pp2x_cls_c2_queue_high_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue,
					  int from);
static int mv_pp2x_cls_c2_queue_low_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue,
					 int from);
static int mv_pp2x_cls_c2_rss_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int rss_en);
static int mv_pp2x_cls_c2_tcam_byte_set (struct mv_pp2x_cls_c2_entry *c2, unsigned int offs,
					 unsigned char byte, unsigned char enable);
static int mv_pp2x_plcr_hw_rxq_thresh_set (uintptr_t cpu_slot, int rxq, int idx);
static int pp2_cls_c2_lkp_type_list_pri_get (struct pp2_inst *inst, u8 lkp_type, u32 *hignest_pri,
					     u32 *lowest_pri);
static int pp2_cls_c2_make_slot_high (struct pp2_inst *inst, u32 lkp_type, u32 priority,
				      u32 highest_pri, u32 lowest_pri, u32 *c2_hw_idx);
static int pp2_cls_c2_make_slot_low (struct pp2_inst *inst, u32 lkp_type, u32 priority,
				     u32 highest_pri, u32 lowest_pri, u32 *c2_hw_idx);
static int pp2_cls_c2_make_slot_middle (struct pp2_inst *inst, u32 lkp_type, u32 priority,
					u32 highest_pri, u32 lowest_pri, u32 *c2_hw_idx);
static int pp2_cls_c2_tcam_hek_get (u32 field_bm, struct mv_pp2x_c2_add_entry *c2_entry, u8 hek[],
				    u8 hek_mask[]);
static int pp2_cls_c3_color_set (struct pp2_cls_c3_entry *c3, int cmd);
static int pp2_cls_c3_dup_set (struct pp2_cls_c3_entry *c3, int dupid, int count);
static int pp2_cls_c3_flow_id_en (struct pp2_cls_c3_entry *c3, int flowid_en);
static int pp2_cls_c3_forward_set (struct pp2_cls_c3_entry *c3, int cmd);
static int pp2_cls_c3_hek_generate (struct pp2_cls_c3_add_entry_t *c3_entry, u32 *size, u8 hek[]);
static int pp2_cls_c3_hw_add (uintptr_t cpu_slot, struct pp2_cls_c3_entry *c3, int index,
			      int ext_index);
static int pp2_cls_c3_hw_query (uintptr_t cpu_slot, struct pp2_cls_c3_entry *c3, u8 *occupied_bmp,
				int index[]);
static int pp2_cls_c3_hw_query_add_relocate (uintptr_t cpu_slot, int new_idx, int max_depth,
					     int cur_depth,
					     struct pp2_cls_c3_hash_pair *hash_pair_arr);
static int pp2_cls_c3_mod_set (struct pp2_cls_c3_entry *c3, int data_ptr, int instr_offs,
			       int l4_csum);
static int pp2_cls_c3_policer_set (struct pp2_cls_c3_entry *c3, int cmd, int policer_id, int bank);
static int pp2_cls_c3_queue_high_set (struct pp2_cls_c3_entry *c3, int cmd, int queue);
static int pp2_cls_c3_queue_low_set (struct pp2_cls_c3_entry *c3, int cmd, int queue);
static int pp2_cls_c3_rss_set (struct pp2_cls_c3_entry *c3, int cmd, int rss_en);
static int pp2_cls_c3_shadow_ext_free_get (void);
static int pp2_cls_c3_sw_hek_byte_set (struct pp2_cls_c3_entry *c3, u32 offs, u8 byte);
static int pp2_cls_c3_sw_hek_size_set (struct pp2_cls_c3_entry *c3, int hek_size);
static int pp2_cls_c3_sw_l4_info_set (struct pp2_cls_c3_entry *c3, int l4info);
static int pp2_cls_c3_sw_lkp_type_set (struct pp2_cls_c3_entry *c3, int lkp_type);
static int pp2_cls_c3_sw_port_id_set (struct pp2_cls_c3_entry *c3, int type, int portid);
static int pp2_cls_db_c2_data_set (struct pp2_inst *inst, u32 c2_db_idx,
				   struct pp2_cls_c2_data_t *c2_data);
static int pp2_cls_edrop_assign_qid (struct pp2_inst *inst, u8 edrop_id, u8 qid, int assign);
static u32 pp2_cls_field_size_get (u32 field_id);
static inline uint32_t pp2_gop_gen_read (uintptr_t base, uint32_t offset);
static inline void pp2_gop_gen_write (uintptr_t base, uint32_t offset, uint32_t data);
static int pp2_prs_uid_to_prs_udf (unsigned int uid);
static void pp2_rxq_resid_pkts (struct pp2_port *port, struct pp2_rx_queue *rxq);

static u8 pp2_cls_c2_field_unmask_check (u32 field_id,
					 struct pp2_cls_field_match_info *field_unmask);
static int pp2_cls_c2_free_slot_find (struct pp2_inst *inst, u32 index1, u32 index2, u32 *free_idx);
static int pp2_cls_c2_lkp_search_down_block_get (struct pp2_inst *inst, u8 lkp_type, u32 pri_start,
						 u32 *c2_search_start, u32 *c2_search_end);
static int pp2_cls_c2_lkp_search_up_block_get (struct pp2_inst *inst, u8 lkp_type, u32 pri_start,
					       u32 *c2_search_start, u32 *c2_search_end);
static int pp2_cls_c2_lkp_type_list_neighbour_pri_get (struct pp2_inst *inst, u32 lkp_type,
						       u32 priority, u32 highest_pri,
						       u32 lowest_pri, u32 *pri_prev,
						       u32 *pri_next);
static int pp2_cls_c2_lkp_type_pri_node_info_get (struct pp2_inst *inst, u8 lkp_type, u32 priority,
						  struct pp2_cls_c2_index_t **c2_hw_first_node,
						  struct pp2_cls_c2_index_t **c2_hw_last_node,
						  u32 *node_count);
static int pp2_cls_c2_tcam_common_field_hek_get (u32 pkt_value, u32 pkt_value_mask, u32 field_bytes,
						 u32 field_size, u8 filed_unmask, u8 c2_hek[],
						 u8 c2_hek_mask[], u32 *bytes_used);
static int pp2_cls_c2_tcam_shared_field_hek_get (u32 pkt_value, u32 pkt_value_mask, u32 field_bytes,
						 u32 field_size, u8 filed_unmask, bool comb_flag,
						 u8 comb_offset, u8 c2_hek[], u8 c2_hek_mask[],
						 u32 *bytes_used);
static int pp2_cls_c3_common_field_hek_get (u32 pkt_value, u32 field_bytes, u32 field_size,
					    u8 c3_hek[], u32 *bytes_used);
static int pp2_cls_c3_hw_read (uintptr_t cpu_slot, struct pp2_cls_c3_entry *c3, int index);
static void pp2_cls_c3_shadow_set (int hek_size, int index, int ext_index);
static int pp2_cls_c3_shared_field_hek_get (u32 pkt_value, u32 field_bytes, u32 field_size,
					    u8 comb_flag, u8 comb_offset, u8 c3_hek[],
					    u32 *bytes_used);
struct list *
pp2_cls_db_c2_lkp_type_list_head_get (struct pp2_inst *inst, u8 lkp_type)
{
  return &inst->cls_db->c2_db.c2_lu_type_head_db[lkp_type];
}

struct list *
pp2_cls_db_c2_free_list_head_get (struct pp2_inst *inst)
{
  return &inst->cls_db->c2_db.c2_free_head_db;
}

int
pp2_cls_db_c2_data_get (struct pp2_inst *inst, u32 c2_db_idx, struct pp2_cls_c2_data_t *c2_data)
{
  /* Param check */
  if (c2_db_idx > MVPP2_C2_LAST_ENTRY)
    {
      pr_err ("Invalid parameter\n");
      return -EINVAL;
    }

  if (!c2_data)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  memcpy (c2_data, &inst->cls_db->c2_db.c2_data_db[c2_db_idx], sizeof (struct pp2_cls_c2_data_t));

  return 0;
}

static int
pp2_cls_c2_entry_is_free (struct pp2_inst *inst, u32 c2_hw_idx,
			  struct pp2_cls_c2_index_t **c2_index_node)
{
  struct list *list;

  if (!c2_index_node)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  /* Traverse free list */
  LIST_FOR_EACH (list, pp2_cls_db_c2_free_list_head_get (inst))
  {
    /* get list node */
    *c2_index_node = LIST_OBJECT (list, struct pp2_cls_c2_index_t, list_node);
    if ((*c2_index_node)->c2_hw_idx == c2_hw_idx)
      return MVPP2_C2_ENTRY_FREE_TRUE;
  }
  *c2_index_node = NULL;
  return MVPP2_C2_ENTRY_FREE_FALSE;
}

int
pp2_cls_field_bm_to_field_info (u32 field_bm, struct pp2_cls_mng_pkt_key_t *pp2_cls_pkt_key,
				u32 field_max, u8 l4_info,
				struct pp2_cls_field_match_info field_info[])
{
  int i = 0;
  int field_size = 0;
  u8 is_ipv4 = true;

  /* Para check */
  if (mv_pp2x_ptr_validate (pp2_cls_pkt_key) == MV_ERROR)
    return MV_ERROR;
  if (mv_pp2x_ptr_validate (field_info) == MV_ERROR)
    return MV_ERROR;

  if (field_bm & (MVPP2_MATCH_IPV6_PKT | MVPP2_MATCH_IPV6_PREF | MVPP2_MATCH_IPV6_SUFF))
    is_ipv4 = false;

  pr_debug ("field_bm 0x%x is_ipv4 %d\n", field_bm, is_ipv4);

  if (field_bm & MVPP2_MATCH_MH && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = MH_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->mh;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = pp2_cls_pkt_key->mh_mask;
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }

  if (field_bm & MVPP2_MATCH_ETH_DST && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = MAC_DA_FIELD_ID;
      memcpy (&field_info[i].filed_value.mac_addr.parsed_mac_addr[0],
	      &pp2_cls_pkt_key->pkt_key->eth_dst.eth_add[0], MAC_ADDR_SIZE);
      memcpy (&field_info[i].filed_value.mac_addr.parsed_mac_addr_mask[0],
	      &pp2_cls_pkt_key->pkt_key->eth_dst.eth_add_mask[0], MAC_ADDR_SIZE);
      i++;
    }
  if (field_bm & MVPP2_MATCH_ETH_SRC && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = MAC_SA_FIELD_ID;
      memcpy (&field_info[i].filed_value.mac_addr.parsed_mac_addr[0],
	      &pp2_cls_pkt_key->pkt_key->eth_src.eth_add[0], MAC_ADDR_SIZE);
      memcpy (&field_info[i].filed_value.mac_addr.parsed_mac_addr_mask[0],
	      &pp2_cls_pkt_key->pkt_key->eth_src.eth_add_mask[0], MAC_ADDR_SIZE);
      i++;
    }
  if (field_bm & MVPP2_MATCH_PBITS_OUTER && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = OUT_VLAN_PRI_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->out_pbit;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (field_bm & MVPP2_MATCH_VID_OUTER && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = OUT_VLAN_ID_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->out_vid;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (field_bm & MVPP2_MATCH_PBITS_INNER && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = IN_VLAN_PRI_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->inn_pbit;
      field_size = pp2_cls_field_size_get (field_info[i].field_id);
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (field_bm & MVPP2_MATCH_VID_INNER && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = IN_VLAN_ID_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->inn_vid;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }

  if (field_bm & MVPP2_MATCH_ETH_TYPE && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = ETH_TYPE_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->ether_type;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }

  if (field_bm & MVPP2_MATCH_PPPOE_SES && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = PPPOE_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val =
	pp2_cls_pkt_key->pkt_key->ppp_info.ppp_session;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }

  if (field_bm & MVPP2_MATCH_PPPOE_PROTO && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = PPPOE_PROTO_ID;
      field_info[i].filed_value.int_data.parsed_int_val =
	pp2_cls_pkt_key->pkt_key->ppp_info.ppp_proto;
      field_size = pp2_cls_field_size_get (field_info[i].field_id);
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if ((field_bm & (MVPP2_MATCH_IP_VERSION)) && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = IP_VER_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->ipvx_add.ip_ver;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (field_bm & MVPP2_MATCH_IP_DSCP && i < field_max)
    {
      if (is_ipv4)
	{
	  field_info[i].valid = MVPP2_FIELD_VALID;
	  field_info[i].field_id = IPV4_DSCP_FIELD_ID;
	  field_info[i].filed_value.int_data.parsed_int_val =
	    pp2_cls_pkt_key->pkt_key->ipvx_add.dscp;
	  field_info[i].filed_value.int_data.parsed_int_val_mask =
	    pp2_cls_pkt_key->pkt_key->ipvx_add.dscp_mask;
	}
      else
	{
	  field_info[i].valid = MVPP2_FIELD_VALID;
	  field_info[i].field_id = IPV6_DSCP_FIELD_ID;
	  field_info[i].filed_value.int_data.parsed_int_val =
	    pp2_cls_pkt_key->pkt_key->ipvx_add.dscp;
	  field_info[i].filed_value.int_data.parsed_int_val_mask =
	    pp2_cls_pkt_key->pkt_key->ipvx_add.dscp_mask;
	}
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (field_bm & MVPP2_MATCH_IPV6_FLBL && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = IPV6_FLOW_LBL_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val =
	pp2_cls_pkt_key->pkt_key->ipvx_add.flow_label;
      field_info[i].filed_value.int_data.parsed_int_val_mask =
	pp2_cls_pkt_key->pkt_key->ipvx_add.flow_label_mask;
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (field_bm & MVPP2_MATCH_TTL && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = IPV4_TTL_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->ttl;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (l4_info && field_bm & MVPP2_MATCH_IP_PROTO && i < field_max)
    {
      if (is_ipv4)
	{
	  field_info[i].valid = MVPP2_FIELD_VALID;
	  field_info[i].field_id = IPV4_PROTO_FIELD_ID;
	  field_info[i].filed_value.int_data.parsed_int_val =
	    pp2_cls_pkt_key->pkt_key->ipvx_add.ip_proto;
	  field_size = pp2_cls_field_size_array[field_info[i].field_id];
	  field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
	}
      else
	{
	  field_info[i].valid = MVPP2_FIELD_VALID;
	  field_info[i].field_id = IPV6_PROTO_FIELD_ID;
	  field_info[i].filed_value.int_data.parsed_int_val =
	    pp2_cls_pkt_key->pkt_key->ipvx_add.ip_proto;
	  field_size = pp2_cls_field_size_array[field_info[i].field_id];
	  field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
	}
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (field_bm & MVPP2_MATCH_IP_SRC && i < field_max)
    {
      if (is_ipv4)
	{
	  field_info[i].valid = MVPP2_FIELD_VALID;
	  field_info[i].field_id = IPV4_SA_FIELD_ID;
	  memcpy (&field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr[0],
		  &pp2_cls_pkt_key->pkt_key->ipvx_add.ip_src.ip_add.ipv4[0], IPV4_ADDR_SIZE);
	  memcpy (&field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr_mask[0],
		  &pp2_cls_pkt_key->pkt_key->ipvx_add.ip_src.ip_add_mask.ipv4[0], IPV4_ADDR_SIZE);
	  pr_debug ("field_info[%d] %s val %d.%d.%d.%d mask %d.%d.%d.%d\n", i,
		    pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr[0],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr[1],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr[2],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr[3],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr_mask[0],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr_mask[1],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr_mask[2],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr_mask[3]);
	  i++;
	}
      else
	{
	  if (field_bm & MVPP2_MATCH_IPV6_PREF)
	    {
	      field_info[i].field_id = IPV6_SA_PREF_FIELD_ID;
	    }
	  else if (field_bm & MVPP2_MATCH_IPV6_SUFF)
	    {
	      field_info[i].field_id = IPV6_SA_SUFF_FIELD_ID;
	    }
	  else if (field_bm & MVPP2_MATCH_IPV6_PKT)
	    {
	      field_info[i].field_id = IPV6_SA_FIELD_ID;
	    }
	  else
	    {
	      pr_debug ("field_bm %s must include %s or %s\n",
			pp2_cls_utils_field_match_str_get (MVPP2_MATCH_IPV6_PREF),
			pp2_cls_utils_field_match_str_get (MVPP2_MATCH_IP_SRC),
			pp2_cls_utils_field_match_str_get (MVPP2_MATCH_IP_DST));
	    }
	  field_info[i].valid = MVPP2_FIELD_VALID;
	  memcpy (&field_info[i].filed_value.ipv6_addr.parsed_ipv6_addr[0],
		  &pp2_cls_pkt_key->pkt_key->ipvx_add.ip_src.ip_add.ipv6[0], IPV6_ADDR_SIZE);
	  memcpy (&field_info[i].filed_value.ipv6_addr.parsed_ipv6_addr_mask[0],
		  &pp2_cls_pkt_key->pkt_key->ipvx_add.ip_src.ip_add_mask.ipv6[0], IPV6_ADDR_SIZE);
	  i++;
	}
    }
  if (field_bm & MVPP2_MATCH_IP_DST && i < field_max)
    {
      if (is_ipv4)
	{
	  field_info[i].valid = MVPP2_FIELD_VALID;
	  field_info[i].field_id = IPV4_DA_FIELD_ID;
	  memcpy (&field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr[0],
		  &pp2_cls_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add.ipv4[0], IPV4_ADDR_SIZE);
	  memcpy (&field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr_mask[0],
		  &pp2_cls_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add_mask.ipv4[0], IPV4_ADDR_SIZE);
	  pr_debug ("field_info[%d] %s val %d.%d.%d.%d mask %d.%d.%d.%d\n", i,
		    pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr[0],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr[1],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr[2],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr[3],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr_mask[0],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr_mask[1],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr_mask[2],
		    field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr_mask[3]);
	  i++;
	}
      else
	{
	  if (field_bm & MVPP2_MATCH_IPV6_PREF)
	    {
	      field_info[i].field_id = IPV6_DA_PREF_FIELD_ID;
	    }
	  else if (field_bm & MVPP2_MATCH_IPV6_SUFF)
	    {
	      field_info[i].field_id = IPV6_DA_SUFF_FIELD_ID;
	    }
	  else if (field_bm & MVPP2_MATCH_IPV6_PKT)
	    {
	      field_info[i].field_id = IPV6_DA_FIELD_ID;
	    }
	  else
	    {
	      pr_debug ("field_bm %s must include %s or %s\n",
			pp2_cls_utils_field_match_str_get (MVPP2_MATCH_IPV6_PREF),
			pp2_cls_utils_field_match_str_get (MVPP2_MATCH_IP_SRC),
			pp2_cls_utils_field_match_str_get (MVPP2_MATCH_IP_DST));
	    }
	  field_info[i].valid = MVPP2_FIELD_VALID;
	  memcpy (&field_info[i].filed_value.ipv6_addr.parsed_ipv6_addr[0],
		  &pp2_cls_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add.ipv6[0], IPV6_ADDR_SIZE);
	  memcpy (&field_info[i].filed_value.ipv6_addr.parsed_ipv6_addr_mask[0],
		  &pp2_cls_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add_mask.ipv6[0], IPV6_ADDR_SIZE);
	  i++;
	}
    }
  if (field_bm & MVPP2_MATCH_L4_SRC && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = L4_SRC_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->l4_src;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val %d mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (field_bm & MVPP2_MATCH_L4_DST && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = L4_DST_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->l4_dst;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val %d mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if ((field_bm & MVPP2_MATCH_TCP_FLAG_RF || field_bm & MVPP2_MATCH_TCP_FLAG_S) && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = TCP_FLAGS_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->tcp_flag;
      field_info[i].filed_value.int_data.parsed_int_val_mask = pp2_cls_pkt_key->tcp_flag_mask;
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }

  if (field_bm & MVPP2_MATCH_ARP_TRGT_IP_ADDR && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = ARP_IPV4_DA_FIELD_ID;
      memcpy (&field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr[0],
	      &pp2_cls_pkt_key->pkt_key->arp_ip_dst.ip_add.ipv4[0], IPV4_ADDR_SIZE);
      memcpy (&field_info[i].filed_value.ipv4_addr.parsed_ipv4_addr_mask[0],
	      &pp2_cls_pkt_key->pkt_key->arp_ip_dst.ip_add_mask.ipv4[0], IPV4_ADDR_SIZE);
      i++;
    }

  if (field_bm & MVPP2_MATCH_UDF3 && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = CLS_UDF3_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->udf3.udf;
      field_info[i].filed_value.int_data.parsed_int_val_mask =
	pp2_cls_pkt_key->pkt_key->udf3.udf_mask;
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }

  if (field_bm & MVPP2_MATCH_UDF5 && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = CLS_UDF5_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->udf5.udf;
      field_info[i].filed_value.int_data.parsed_int_val_mask =
	pp2_cls_pkt_key->pkt_key->udf5.udf_mask;
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }

  if (field_bm & MVPP2_MATCH_UDF6 && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = CLS_UDF6_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->udf6.udf;
      field_info[i].filed_value.int_data.parsed_int_val_mask =
	pp2_cls_pkt_key->pkt_key->udf6.udf_mask;
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }

  /*add other udf set fields - tpid and cfi*/
  if (field_bm & MVPP2_MATCH_TPID_OUTER && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = OUT_TPID_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->out_tpid;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (field_bm & MVPP2_MATCH_CFI_OUTER && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = OUT_VLAN_CFI_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->out_cfi;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (field_bm & MVPP2_MATCH_TPID_INNER && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = IN_TPID_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->inn_tpid;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }
  if (field_bm & MVPP2_MATCH_CFI_INNER && i < field_max)
    {
      field_info[i].valid = MVPP2_FIELD_VALID;
      field_info[i].field_id = IN_VLAN_CFI_FIELD_ID;
      field_info[i].filed_value.int_data.parsed_int_val = pp2_cls_pkt_key->pkt_key->inn_cfi;
      field_size = pp2_cls_field_size_array[field_info[i].field_id];
      field_info[i].filed_value.int_data.parsed_int_val_mask = common_mask_gen (field_size);
      pr_debug ("field_info[%d] %s val 0x%x mask 0x%x\n", i,
		pp2_cls_utils_field_id_str_get (field_info[i].field_id),
		field_info[i].filed_value.int_data.parsed_int_val,
		field_info[i].filed_value.int_data.parsed_int_val_mask);
      i++;
    }

  return 0;
}

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

      if (c2.inv == 0 && port_id == (1 << port->id))
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

int
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
int
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
int
pp2_rss_enable (struct pp2_port *port, int en)
{
  int rc;

  /* For logical port, there is no need to enable C2 since the flows are not shared with kernel */
  if (port->type == PP2_PPIO_T_LOG)
    return 0;

  rc = pp2_rss_c2_enable (port, en);
  if (rc)
    return -EINVAL;

  return 0;
}

int
pp2_bpool_get_num_buffs (struct pp2_bpool *pool, u32 *num_buffs)
{
  uintptr_t cpu_slot;
  u32 num = 0;

  cpu_slot = GET_HW_BASE (pool)[PP2_DEFAULT_REGSPACE].va;

  num =
    pp2_reg_read (cpu_slot, MVPP2_BM_POOL_PTRS_NUM_REG (pool->id)) & MVPP22_BM_POOL_PTRS_NUM_MASK;
  num +=
    pp2_reg_read (cpu_slot, MVPP2_BM_BPPI_PTRS_NUM_REG (pool->id)) & MVPP2_BM_BPPI_PTR_NUM_MASK;

  /* HW has one buffer ready and is not reflected in "external + internal" counters */
  if (num)
    num++;

  *num_buffs = num;

  return 0;
}

static int pp2_cls_db_edrop_ref_cnt_update (struct pp2_inst *inst, u8 edrop_id,
					    enum pp2_cls_edrop_ref_cnt_action_t cnt_action);

static int pp2_c2_set_default_coloring (struct pp2_port *port, int clear);
static int pp2_c2_set_default_policing (struct pp2_port *port, int clear);
static int pp2_cls_fl_rl_hw_set (uintptr_t cpu_slot, struct pp2_cls_rl_entry_t *rl, bool is_last);
static int pp2_cls_lkp_dcod_hw_set (struct pp2_inst *inst, struct pp2_cls_fl_t *fl);
static int pp2_cls_plcr_ref_cnt_get (struct pp2_inst *inst, u8 policer_id, u32 *rules_ref,
				     u32 *ppios_ref);
static int pp2_cls_plcr_ref_cnt_update (struct pp2_inst *inst, u8 policer_id,
					enum pp2_cls_plcr_ref_cnt_action_t cnt_action,
					int update_ppio);
static int pp2_db_cls_fl_ctrl_get (struct pp2_inst *inst, struct pp2_db_cls_fl_ctrl_t *fl_ctrl);
static int pp2_db_cls_fl_ctrl_set (struct pp2_inst *inst, struct pp2_db_cls_fl_ctrl_t *fl_ctrl);
static int pp2_db_cls_lkp_dcod_set (struct pp2_inst *inst, u32 fl_log_id,
				    struct pp2_db_cls_lkp_dcod_t *lkp_dcod);
static int pp2_db_cls_rl_off_free_nr (struct pp2_inst *inst, u32 *free_nr);
static struct pp2_desc *pp2_dm_if_next_desc_block_get (struct pp2_dm_if *dm_if, uint16_t num_desc,
						       uint16_t *cont_desc);
static int pp2_gop_port_link_status (struct gop_hw *gop, struct pp2_mac_data *mac,
				     struct pp2_port_link_status *pstatus);
static int pp2_port_check_mtu_valid (struct pp2_port *port, uint32_t mtu);
static int pp2_port_clear_all_vlans (struct pp2_port *port);
static inline uint32_t pp2_port_get_tx_fifo (struct pp2_port *port);
static int pp2_port_set_loopback (struct pp2_port *port, int en);
static u32 pp2_prs_eth_start_hdr_get (struct pp2_port *port);
static int pp2_prs_eth_start_hdr_set (struct pp2_port *port,
				      enum pp2_ppio_eth_start_hdr eth_start_hdr);
static int pp2_prs_log_port_field_set (struct pp2_port *port, struct pp2_proto_field proto_field,
				       int val, enum pp2_ppio_cls_target target);
static int pp2_prs_log_port_proto_set (struct pp2_port *port, enum mv_net_proto proto, int negate,
				       enum pp2_ppio_cls_target target);
static int pp2_prs_space_check (struct pp2_port *port, struct pp2_ppio_log_port_params *params);
static int pp2_prs_tcam_first_free (struct pp2_inst *inst, unsigned char start, unsigned char end);
static int pp2_prs_udf_map_allocate (unsigned int uid);

static int mv_pp2x_cls_hw_flow_read (uintptr_t cpu_slot, int index,
				     struct mv_pp2x_cls_flow_entry *fe);
static int mv_pp2x_cls_hw_flow_write (uintptr_t cpu_slot, struct mv_pp2x_cls_flow_entry *fe);
static int mv_pp2x_cls_sw_flow_engine_get (struct mv_pp2x_cls_flow_entry *fe, int *engine,
					   int *is_last);
static int mv_pp2x_cls_sw_flow_extra_get (struct mv_pp2x_cls_flow_entry *fe, int *type, int *prio);
static int mv_pp2x_cls_sw_flow_hek_get (struct mv_pp2x_cls_flow_entry *fe, int *num_of_fields,
					int field_ids[]);
static int mv_pp2x_cls_sw_flow_port_get (struct mv_pp2x_cls_flow_entry *fe, int *type, int *portid);
static int mv_pp2x_cls_sw_flow_port_set (struct mv_pp2x_cls_flow_entry *fe, int type, int portid);
static int mv_pp2x_cls_sw_flow_seq_ctrl_get (struct mv_pp2x_cls_flow_entry *fe, int *mode);
static void mv_pp2x_prs_flow_id_attr_set (int flow_id, int ri, int ri_mask);
static int mv_pp2x_prs_hw_read (uintptr_t cpu_slot, struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_hw_write (uintptr_t cpu_slot, struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_sram_ri_get (struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_sram_ri_mask_get (struct mv_pp2x_prs_entry *pe);
static void mv_pp2x_prs_sram_ri_update (struct mv_pp2x_prs_entry *pe, unsigned int bits,
					unsigned int mask);
static int mv_pp2x_prs_tcam_invalid_get (struct mv_pp2x_prs_entry *pe);
static int mv_pp2x_prs_tcam_lu_get (struct mv_pp2x_prs_entry *pe);
static int pp2_cls_db_prs_init_list (struct pp2_inst *inst);
static int pp2_cls_mng_lkp_type_to_prio (int lkp_type);
static int pp2_cls_new_fl_rl_merge (u16 new_rl_num, struct pp2_cls_fl_t *new_fl_rls,
				    struct pp2_cls_fl_t *mrg_fl_rls);
static int pp2_cls_rl_c4_validate (struct pp2_cls_rl_entry_t *rl, struct pp2_cls_fl_t *fl_rls,
				   bool *valid);
static int pp2_cls_rl_hit_cnt_upd (struct pp2_cls_rl_entry_t *rl, struct pp2_cls_fl_t *fl_rls,
				   struct pp2_cls_fl_eng_cnt_t *eng_hit_cnt);
static int pp2_cls_rl_hit_cnt_upd_reorder (struct pp2_cls_fl_t *fl_rls, u32 fl_idx,
					   struct pp2_cls_fl_eng_cnt_t *eng_hit_cnt);
static int pp2_db_cls_fl_rule_list_get (struct pp2_inst *inst, u32 off, u32 len,
					struct pp2_db_cls_fl_rule_t *fl_rl_list);
static int pp2_db_cls_fl_rule_set (struct pp2_inst *inst, u32 off,
				   struct pp2_db_cls_fl_rule_t *fl_rule);
static int pp2_db_cls_rl_off_free_set (struct pp2_inst *inst, u16 off, u16 *log);
static int pp2_db_cls_rl_off_get (struct pp2_inst *inst, u16 *off, u16 log);
static int pp2_db_cls_rl_off_set (struct pp2_inst *inst, u16 off, u16 log);

static inline u32
cm3_read (uintptr_t base, u32 offset)
{

  uintptr_t addr = base + offset;

  return readl ((void *) addr);
}

static int
iomem_mmap_iomap (struct mem_mmap *mmapm, const char *name, phys_addr_t *pa, void **va)
{
  struct mem_mmap_nd *mmap_nd;
  const uint32_t *uint32_prop;
  int dev_mem_fd, index = -1;
  uint64_t tmp_pa, tmp_size;

  if (name)
    {
      if (!mmapm->dev_node)
	{
	  pr_err ("IO device not found!\n");
	  return -EINVAL;
	}
      /* Assuming the name is actually the memory index */
      if (strlen (name) > 2)
	{
	  pr_err ("Illegal name length (%d, max is 2)!\n", (int) strlen (name));
	  return -EINVAL;
	}
      if (!((name[0] >= '0') && (name[0] <= '9')))
	{
	  pr_err ("Illegal name (%s); must be number!\n", name);
	  return -EINVAL;
	}
      if ((strlen (name) == 2) && !((name[1] >= '0') && (name[1] <= '9')))
	{
	  pr_err ("Illegal name (%s); must be number!\n", name);
	  return -EINVAL;
	}

      index = atoi (name);
      uint32_prop = mv_of_get_address (mmapm->dev_node, index, &tmp_size, NULL);
      if (!uint32_prop)
	{
	  pr_err ("mmap region (%s) not found!\n", name);
	  return -EINVAL;
	}
      tmp_pa = mv_of_translate_address (mmapm->dev_node, uint32_prop);
    }
  else
    {
      tmp_pa = *pa;
      tmp_size = pagesize;
    }

  mmap_nd = (struct mem_mmap_nd *) clib_mem_alloc_or_null (sizeof (struct mem_mmap_nd));
  if (!mmap_nd)
    {
      pr_err ("no mem for mmap mem region!\n");
      return -ENOMEM;
    }
  memset (mmap_nd, 0, sizeof (struct mem_mmap_nd));
  INIT_LIST (&mmap_nd->node);

  mmap_nd->index = index;
  /* mmap works only on page-aligned addresses;
   * let's align the address and add the offset later on.
   */
  mmap_nd->pa = tmp_pa & ~(pagesize - 1);
  mmap_nd->offs = tmp_pa & (pagesize - 1);
  mmap_nd->size = tmp_size;

  dev_mem_fd = open (MMAP_FILE_NAME, O_RDWR);
  if (dev_mem_fd < 0)
    {
      pr_err ("UIO file open (%s) = %d (%s)\n", MMAP_FILE_NAME, -errno, strerror (errno));
      return -EFAULT;
    }

  mmap_nd->va = mmap (NULL, (size_t) mmap_nd->size, PROT_READ | PROT_WRITE, MAP_SHARED, dev_mem_fd,
		      (off_t) mmap_nd->pa);
  close (dev_mem_fd);
  if (unlikely (mmap_nd->va == MAP_FAILED))
    {
      pr_err ("mmap() of 0x%016llx = %d (%s)\n", (unsigned long long int) mmap_nd->pa, -errno,
	      strerror (errno));
      return -EFAULT;
    }
  list_add_to_tail (&mmap_nd->node, &mmapm->maps_lst);

  *va = mmap_nd->va + mmap_nd->offs;
  *pa = mmap_nd->pa + mmap_nd->offs;

  pr_debug ("IO-remap: va=%p,pa=0x%016llx,sz=0x%llx\n", mmap_nd->va,
	    (unsigned long long int) mmap_nd->pa, (unsigned long long int) mmap_nd->size);

  return 0;
}

static int
iomem_mmap_iounmap (struct mem_mmap *mmapm, const char *name)
{
  struct mem_mmap_nd *mmap_nd;
  int err, dev_mem_fd, index = -1;

  if (name)
    {
      /* Assuming the name is actually the memory index */
      if (strlen (name) > 2)
	{
	  pr_err ("Illegal name length (%d, max is 2)!\n", (int) strlen (name));
	  return -EINVAL;
	}
      if (!((name[0] >= '0') && (name[0] <= '9')))
	{
	  pr_err ("Illegal name (%s); must be number!\n", name);
	  return -EINVAL;
	}
      if ((strlen (name) == 2) && !((name[1] >= '0') && (name[1] <= '9')))
	{
	  pr_err ("Illegal name (%s); must be number!\n", name);
	  return -EINVAL;
	}

      index = atoi (name);
    }

  mmap_nd = mmap_find_iomap_by_index (mmapm, index);
  if (!mmap_nd)
    {
      pr_err ("mmap mem region (%s) not found!\n", name);
      return -EINVAL;
    }

  list_del (&mmap_nd->node);

  dev_mem_fd = open (MMAP_FILE_NAME, O_RDWR);
  if (dev_mem_fd < 0)
    {
      pr_err ("UIO file open (%s) = %d (%s)\n", MMAP_FILE_NAME, -errno, strerror (errno));
      return -EFAULT;
    }

  err = munmap (mmap_nd->va, mmap_nd->size);
  close (dev_mem_fd);
  if (err)
    {
      pr_err ("munmap() of %p = %d (%s)\n", mmap_nd->va, -errno, strerror (errno));
      return -EFAULT;
    }

  clib_mem_free (mmap_nd);

  return 0;
}

static int
iomem_shmem_iomap (struct mem_shm *shm, const char *name, phys_addr_t *pa, void **va)
{
  int fd;
  void *ptr;

  if (!shm->va)
    {
      fd = open (shm->dev_name, O_RDWR);
      if (fd < 0)
	{
	  pr_err ("CMA: open() failed\n");
	  return -1;
	}

      ptr = mmap (NULL, shm->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) *pa);
      if (ptr == MAP_FAILED)
	{
	  pr_err ("mmap() of 0x%016llx = %d (%s)\n", (unsigned long long int) *pa, -errno,
		  strerror (errno));
	  return -EFAULT;
	}

      shm->pa = *pa;
      shm->va = ptr;
      pr_info ("shm->name %s, pa 0x%" PRIx64 ", va %p, size %zu\n", shm->dev_name, (u64) shm->pa,
	       shm->va, shm->size);
    }

  *va = shm->va;
  return 0;
}

static int
iomem_shmem_iounmap (struct mem_shm *shm, const char *name)
{
  int err;

  err = munmap (shm->va, shm->size);
  if (err != 0)
    {
      pr_err ("munmap failed\n");
      return -1;
    }
  return 0;
}

static int
iomem_uio_iomap (struct mem_uio *uiom, const char *name, phys_addr_t *pa, void **va)
{
  struct uio_mem_t *mem = NULL;

  mem = uio_find_mem_byname (uiom->info, name);
  if (!mem)
    {
      pr_err ("uio mem region (%s) not found!\n", name);
      return -EINVAL;
    }

  if (mem->fd < 0)
    {
      char dev_name[16];

      snprintf (dev_name, sizeof (dev_name), "/dev/uio%d", mem->info->uio_num);
      mem->fd = open (dev_name, O_RDWR);
    }

  if (mem->fd >= 0)
    {
      *va = uio_single_mmap (mem->info, mem->map_num, mem->fd);
      if (!*va)
	return -EINVAL;

      if (pa)
	*pa = (phys_addr_t) mem->info->maps[mem->map_num].addr;
      iomem_uio_add_entry (&uiom->mem, mem);
    }
  else
    uio_free_mem_info (mem);

  return 0;
}

static int
iomem_uio_iounmap (struct mem_uio *uiom, const char *name)
{
  struct uio_mem_t *mem;

  mem = iomem_uio_rm_entry (&uiom->mem, name);
  if (!mem)
    return -ENOENT;
  uio_single_munmap (mem->info, mem->map_num);
  /**
   * TODO
   * Handle device closing if no map registered as mapped. Change file
   * descriptor to -1.
   * If no memory is mapped I don't see any reason to keep the
   * device opened.
   *
   */
  uio_free_mem_info (mem);

  return 0;
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
mv_pp2x_cls_hw_lkp_write (uintptr_t cpu_slot, struct mv_pp2x_cls_lookup_entry *fe)
{
  u32 reg_val = 0;

  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (fe->way, 0, 1) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (fe->lkpid, 0, MVPP2_CLS_FLOWS_TBL_SIZE) == MV_ERROR)
    return MV_ERROR;

  /* write index reg */
  reg_val = (fe->way << MVPP2_CLS_LKP_INDEX_WAY_OFFS) | (fe->lkpid << MVPP2_CLS_LKP_INDEX_LKP_OFFS);
  pp2_reg_write (cpu_slot, MVPP2_CLS_LKP_INDEX_REG, reg_val);

  /* write flow_id reg */
  pp2_reg_write (cpu_slot, MVPP2_CLS_LKP_TBL_REG, fe->data);

  return 0;
}

static int
mv_pp2x_cls_sw_lkp_en_set (struct mv_pp2x_cls_lookup_entry *lkp, int en)
{
  if (mv_pp2x_ptr_validate (lkp) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (en, 0, 1) == MV_ERROR)
    return MV_ERROR;

  lkp->data &= ~MVPP2_FLOWID_EN_MASK;
  lkp->data |= (en << MVPP2_FLOWID_EN);

  return 0;
}

static int
mv_pp2x_cls_sw_lkp_flow_set (struct mv_pp2x_cls_lookup_entry *lkp, int flow_idx)
{
  if (mv_pp2x_ptr_validate (lkp) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (flow_idx, 0, MVPP2_CLS_FLOWS_TBL_SIZE) == MV_ERROR)
    return MV_ERROR;

  lkp->data &= ~MVPP2_FLOWID_FLOW_MASK;
  lkp->data |= (flow_idx << MVPP2_FLOWID_FLOW);

  return 0;
}

static int
mv_pp2x_cls_sw_lkp_rxq_set (struct mv_pp2x_cls_lookup_entry *lkp, int rxq)
{
  if (mv_pp2x_ptr_validate (lkp) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (rxq, 0, (1 << MVPP2_FLOWID_RXQ_BITS) - 1) == MV_ERROR)
    return MV_ERROR;

  lkp->data &= ~MVPP2_FLOWID_RXQ_MASK;
  lkp->data |= (rxq << MVPP2_FLOWID_RXQ);

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

      if (c2.inv == 0 && port_id == (1 << port->id))
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
pp2_c2_set_default_policing (struct pp2_port *port, int clear)
{
  int index, c2_status, rc, plcr_id;
  u8 port_id;
  struct mv_pp2x_cls_c2_entry c2;
  struct pp2_hw *hw = &port->parent->hw;

  c2_status = pp2_reg_read (hw->base[0].va, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      pr_err ("c2 is off\n");
      return -EINVAL;
    }

  if (clear)
    plcr_id = MVPP2_PLCR_BANK0_DEFAULT_ENTRY_ID;
  else
    plcr_id = port->default_plcr->id & MVPP2_CLS2_ACT_DUP_ATTR_PLCRID_MAX;

  mv_pp2x_c2_sw_clear (&c2);

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mv_pp2x_cls_c2_hw_read (hw->base[0].va, index, &c2);
      port_id = pp2_cls_c2_tcam_port_get (&c2);

      if (c2.inv == 0 && port_id == (1 << port->id))
	{
	  rc = mv_pp2x_cls_c2_policer_set (&c2, MVPP2_ACTION_TYPE_UPDT, plcr_id,
					   MVPP2_POLICER_2_BANK (plcr_id));
	  if (rc)
	    return rc;

	  mv_pp2x_cls_c2_hw_write (hw->base[0].va, index, &c2);
	}
    }

  return 0;
}

static int
pp2_cls_fl_rl_hw_set (uintptr_t cpu_slot, struct pp2_cls_rl_entry_t *rl, bool is_last)
{
  struct mv_pp2x_cls_flow_entry fe;
  int rc;
  u16 fid;
  /* enum pp2_init_us_2g_trunk_mode_t us_2g_trunk_support; */

  if (!rl)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  mv_pp2x_cls_sw_flow_clear (&fe);

  rc = mv_pp2x_cls_sw_flow_engine_set (&fe, rl->engine, is_last);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  /* set the port_type and port_bm according to enable configuration */
  if (rl->enabled)
    rc = mv_pp2x_cls_sw_flow_port_set (&fe, rl->port_type, rl->port_bm);
  else
    rc = mv_pp2x_cls_sw_flow_port_set (&fe, 0, 0);

  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  rc = mv_pp2x_cls_sw_flow_extra_set (&fe, rl->lu_type, rl->prio);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  rc = mv_pp2x_cls_sw_flow_hek_num_set (&fe, rl->field_id_cnt);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  /* Set Port ID Select, selects the value of the Port ID forwareded to the C2, C3 engines*/
  /* Check US 2G trunk is supported or not */
  /* rc = pp2_db_generic_param_get(MVPP2_DB_PARAM_US_2G_SUPPORT, &us_2g_trunk_support); */
  /* IF_ERROR_STR(TPM_MNG_MOD, rc, "get US 2G trunk value failed\n"); */

  /* for 2G US case, SRC port DS rules are all GMAC1 and PON
   * so in classifier and C2/3, all src port are GMAC1 and PON too,
   * and the src port value of C2/3 comes from classifier, not packet
   */
  /* if (TPM_US_2G_TRUNK_SUPPORTED == us_2g_trunk_support)
   *	rc = mv_pp2x_cls_sw_flow_portid_select(&fe, MVPP2_CLS_PORT_ID_FROM_TBL);
   * else
   *	rc = mv_pp2x_cls_sw_flow_portid_select(&fe, MVPP2_CLS_PORT_ID_FROM_PKT);
   *
   */

  rc = mv_pp2x_cls_sw_flow_portid_select (&fe, MVPP2_CLS_PORT_ID_FROM_PKT);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  rc = mv_pp2x_cls_sw_flow_seq_ctrl_set (&fe, rl->seq_ctrl);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  rc = mv_pp2x_cls_sw_flow_udf7_set (&fe, rl->udf7);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  for (fid = 0; fid < rl->field_id_cnt; fid++)
    {
      rc = mv_pp2x_cls_sw_flow_hek_set (&fe, fid, rl->field_id[fid]);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  return rc;
	}
    }
  fe.index = rl->rl_off;
  rc = mv_pp2x_cls_hw_flow_write (cpu_slot, &fe);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  return 0;
}

static int
pp2_cls_lkp_dcod_hw_set (struct pp2_inst *inst, struct pp2_cls_fl_t *fl)
{
  struct mv_pp2x_cls_lookup_entry fe;
  int rc;
  u16 luid, rl = 0;
  struct pp2_db_cls_lkp_dcod_t lkp_dcod_db;
  struct pp2_db_cls_fl_rule_list_t *fl_rl_db;
  u16 rl_off;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  if (!fl)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  /* get the lookup DB for this logical flow ID */
  rc = pp2_db_cls_lkp_dcod_get (inst, fl->fl_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("failed to get lookup decode info for fl_log_id %d\n", fl->fl_log_id);
      return rc;
    }

  if (!lkp_dcod_db.enabled)
    {
      /* entry not enabled for this log_flow id */
      return 0;
    }

  /* get the rule list for this logical flow ID */
  fl_rl_db = clib_mem_alloc_or_null (sizeof (*fl_rl_db));
  if (!fl_rl_db)
    return -ENOMEM;

  memset (fl_rl_db, 0, sizeof (struct pp2_db_cls_fl_rule_list_t));
  rc = pp2_db_cls_fl_rule_list_get (inst, lkp_dcod_db.flow_off, lkp_dcod_db.flow_len,
				    &fl_rl_db->flow[0]);
  if (rc)
    {
      pr_err ("failed to get flow rule list fl_log_id=%d flow_off=%d flow_len=%d\n", fl->fl_log_id,
	      lkp_dcod_db.flow_off, lkp_dcod_db.flow_len);
      if (fl_rl_db)
	clib_mem_free (fl_rl_db);
      return rc;
    }

  /* iterate over all LUIDs */
  for (luid = 0; luid < lkp_dcod_db.luid_num; luid++)
    {
      /* Exclude MAC default LookupID by LSP */
      if (LUID_IS_LSP_RESERVED (lkp_dcod_db.luid_list[luid].luid))
	continue;

      /* found the rule, get it`s offset */
      rc = pp2_db_cls_rl_off_get (inst, &rl_off, fl_rl_db->flow[rl].rl_log_id);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}

      /* updated the HW */
      mv_pp2x_cls_sw_lkp_clear (&fe);

      rc = mv_pp2x_cls_sw_lkp_flow_set (&fe, rl_off);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}

      rc = mv_pp2x_cls_sw_lkp_rxq_set (&fe, lkp_dcod_db.cpu_q);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}

      rc = mv_pp2x_cls_sw_lkp_en_set (&fe, lkp_dcod_db.enabled);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}

      fe.way = lkp_dcod_db.way;
      fe.lkpid = lkp_dcod_db.luid_list[luid].luid;
      rc = mv_pp2x_cls_hw_lkp_write (cpu_slot, &fe);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}

      pr_debug ("fl_log_id[%2d] lid_nr[%2d] rl_log_id[%3d] prio[%2d] rl_off[%3d] luid[%2d]\n",
		fl->fl_log_id, luid, fl_rl_db->flow[rl].rl_log_id, fl_rl_db->flow[rl].prio, rl_off,
		lkp_dcod_db.luid_list[luid].luid);
    }

  if (fl_rl_db)
    clib_mem_free (fl_rl_db);
  return 0;
}

static int
pp2_cls_plcr_ref_cnt_get (struct pp2_inst *inst, u8 policer_id, u32 *rules_ref, u32 *ppios_ref)
{
  struct pp2_cls_db_plcr_entry_t l_plcr_entry;
  int rc = 0;

  if (mv_pp2x_ptr_validate (inst))
    return -EFAULT;

  if (mv_pp2x_range_validate (policer_id, 0, MVPP2_PLCR_MAX - 1))
    {
      pr_err ("invalid policer ID %d, out of range[%d, %d]\n", policer_id, 0, MVPP2_PLCR_MAX - 1);
      return -EINVAL;
    }

  /* check police status */
  rc = pp2_cls_db_plcr_entry_get (inst, policer_id, &l_plcr_entry);
  if (rc)
    {
      pr_err ("failed to get policer entry from DB\n");
      return rc;
    }

  if (rules_ref)
    *rules_ref = l_plcr_entry.rules_ref_cnt;
  if (ppios_ref)
    *ppios_ref = l_plcr_entry.ppios_ref_cnt;

  return rc;
}

static int
pp2_cls_plcr_ref_cnt_update (struct pp2_inst *inst, u8 policer_id,
			     enum pp2_cls_plcr_ref_cnt_action_t cnt_action, int update_ppio)
{
  int rc = 0;

  if (mv_pp2x_range_validate (policer_id, MVPP2_PLCR_MIN_ENTRY_ID, MVPP2_PLCR_MAX - 1))
    {
      pr_err ("invalid policer ID %d, out of range[%d, %d]\n", policer_id, MVPP2_PLCR_MIN_ENTRY_ID,
	      MVPP2_PLCR_MAX - 1);
      return -EINVAL;
    }

  if (mv_pp2x_range_validate (cnt_action, 0, MVPP2_PLCR_REF_CNT_CLEAR))
    {
      pr_err ("invalid reference counter action %d, out of range[%d, %d]\n", cnt_action, 0,
	      MVPP2_PLCR_REF_CNT_CLEAR);
      return -EINVAL;
    }

  /* update the policer reference counter in DB */
  rc = pp2_cls_db_plcr_ref_cnt_update (inst, policer_id, cnt_action, update_ppio);
  if (rc)
    {
      pr_err ("failed to update policer reference counter\n");
      return rc;
    }

  return rc;
}

static int
pp2_db_cls_fl_ctrl_get (struct pp2_inst *inst, struct pp2_db_cls_fl_ctrl_t *fl_ctrl)
{
  if (!fl_ctrl)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  memcpy (fl_ctrl, &inst->cls_db->cls_db.fl_ctrl, sizeof (struct pp2_db_cls_fl_ctrl_t));

  return 0;
}

static int
pp2_db_cls_fl_ctrl_set (struct pp2_inst *inst, struct pp2_db_cls_fl_ctrl_t *fl_ctrl)
{
  if (!fl_ctrl)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  memcpy (&inst->cls_db->cls_db.fl_ctrl, fl_ctrl, sizeof (struct pp2_db_cls_fl_ctrl_t));

  return 0;
}

static int
pp2_db_cls_lkp_dcod_set (struct pp2_inst *inst, u32 fl_log_id,
			 struct pp2_db_cls_lkp_dcod_t *lkp_dcod)
{
  if (!lkp_dcod)
    {
      pr_err ("%s: null pointer.\n", __func__);
      return -EFAULT;
    }

  if (fl_log_id >= MVPP2_MNG_FLOW_ID_MAX)
    {
      pr_err ("Invalid parameter\n");
      return -EINVAL;
    }

  memcpy (&inst->cls_db->cls_db.lkp_dcod[fl_log_id], lkp_dcod,
	  sizeof (struct pp2_db_cls_lkp_dcod_t));

  return 0;
}

static int
pp2_db_cls_rl_off_free_nr (struct pp2_inst *inst, u32 *free_nr)
{
  if (!free_nr)
    {
      pr_err ("%s: null pointer.\n", __func__);
      return -EFAULT;
    }

  *free_nr = ((MVPP2_CLS_LOG2OFF_TBL_SIZE) -inst->cls_db->cls_db.log2off[MVPP2_CLS_FREE_LOG2OFF]);

  return 0;
}

static struct pp2_desc *
pp2_dm_if_next_desc_block_get (struct pp2_dm_if *dm_if, uint16_t num_desc, uint16_t *cont_desc)
{
  u32 tx_desc = dm_if->desc_next_idx;

  if (unlikely (num_desc >= (dm_if->desc_total - dm_if->desc_next_idx)))
    {
      *cont_desc = dm_if->desc_total - dm_if->desc_next_idx;
      dm_if->desc_next_idx = 0;
    }
  else
    {
      dm_if->desc_next_idx = tx_desc + num_desc;
      *cont_desc = num_desc;
    }

  return dm_if->desc_virt_arr + tx_desc;
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
	  pp2_reg_read (port->cpu_slot, MVPP22_TX_FIFO_SIZE_REG (port->id)));
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

  reg_val = pp2_reg_read (cpu_slot, MVPP2_MH_REG (port->id));
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

  reg_val = pp2_reg_read (cpu_slot, MVPP2_MH_REG (port->id));
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
  pp2_reg_write (cpu_slot, MVPP2_MH_REG (port->id), reg_val);

  return 0;
}

static int
pp2_prs_log_port_field_set (struct pp2_port *port, struct pp2_proto_field proto_field, int val,
			    enum pp2_ppio_cls_target target)
{
  u32 type;
  int rc;

  switch (proto_field.proto)
    {
    case MV_NET_PROTO_ETH_DSA:
      if (proto_field.field.eth_dsa != MV_NET_ETH_F_DSA_TAG_MODE)
	{
	  pr_err ("parser logical port special protocol field not supported %d\n",
		  proto_field.field.eth_dsa);
	  return -EFAULT;
	}

      if (val < MV_NET_TO_CPU_DSA_TAG_MODE || val > MV_NET_FORWARD_DSA_TAG_MODE)
	{
	  pr_err ("parser logical port special protocol field values not supported\n");
	  return -EFAULT;
	}

      /*Get MH register configured mode */
      type = pp2_prs_eth_start_hdr_get (port);

      /* Configure parser DSA entries */
      rc = pp2_prs_tag_mode_set (port, type, val, target);
      if (rc)
	return -EFAULT;
      break;
    default:
      pr_err ("parser logical port special protocol not supported %d\n", proto_field.proto);
      return -EFAULT;
    }
  return 0;
}

static int
pp2_prs_log_port_proto_set (struct pp2_port *port, enum mv_net_proto proto, int negate,
			    enum pp2_ppio_cls_target target)
{
  struct pp2_inst *inst = port->parent;
  u32 ri = 0;
  u16 lookup[MAX_LOOKUP] = { 0, 0, 0 };
  u16 proto_num[MAX_PROTO_NUM] = { 0, 0, 0 };
  int i, j, rc;

  rc = pp2_prs_proto_lookup (proto, lookup, proto_num);

  if (rc)
    return -EFAULT;

  if (target == PP2_CLS_TARGET_LOCAL_PPIO)
    ri = MVPP2_PRS_RI_UDF7_LOG_PORT;
  else
    ri = MVPP2_PRS_RI_UDF7_NIC;

  for (i = 0; i < MAX_LOOKUP; i++)
    {

      if (lookup[i] == 0)
	continue;

      for (j = 0; j < MAX_PROTO_NUM; j++)
	{

	  if (proto_num[j] == 0)
	    continue;

	  pr_info ("Logical port: Building list for lookup %s, protocol %s\n",
		   pp2_g_enum_prs_lookup_str_get (lookup[i]),
		   pp2_g_enum_prs_proto_num_str_get (proto_num[j]));
	  /* Build a list with indexes matching the specified lookup id and proto */
	  rc = pp2_prs_tcam_idx_list_build (inst, lookup[i], proto_num[j], negate, ri);
	  if (rc)
	    {
	      pr_err (
		"Logical port: no space in TCAM for adding specified rules. Operation failed\n");
	      return -EFAULT;
	    }
	}
    }

  return 0;
}

static int
pp2_prs_space_check (struct pp2_port *port, struct pp2_ppio_log_port_params *params)
{
  /* TODO */
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
pp2_prs_udf_map_allocate (unsigned int uid)
{
  int i;

  for (i = 0; i < PP2_MAX_UDFS_SUPPORTED; i++)
    {
      if (prs_udf_map[i].user_udf_idx == uid)
	return i;

      if (prs_udf_map[i].user_udf_idx == -1)
	{
	  prs_udf_map[i].user_udf_idx = uid;
	  return i;
	}
    }

  return -1;
}

static int
mv_pp2x_cls_hw_flow_read (uintptr_t cpu_slot, int index, struct mv_pp2x_cls_flow_entry *fe)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (index, 0, MVPP2_CLS_FLOWS_TBL_SIZE) == MV_ERROR)
    return MV_ERROR;

  fe->index = index;

  /*write index */
  pp2_reg_write (cpu_slot, MVPP2_CLS_FLOW_INDEX_REG, index);

  fe->data[0] = pp2_reg_read (cpu_slot, MVPP2_CLS_FLOW_TBL0_REG);
  fe->data[1] = pp2_reg_read (cpu_slot, MVPP2_CLS_FLOW_TBL1_REG);
  fe->data[2] = pp2_reg_read (cpu_slot, MVPP2_CLS_FLOW_TBL2_REG);

  return 0;
}

static int
mv_pp2x_cls_hw_flow_write (uintptr_t cpu_slot, struct mv_pp2x_cls_flow_entry *fe)
{
  if (mv_pp2x_range_validate (fe->index, 0, MVPP2_CLS_FLOWS_TBL_SIZE) == MV_ERROR)
    return -EINVAL;

  /* write index */
  pp2_reg_write (cpu_slot, MVPP2_CLS_FLOW_INDEX_REG, fe->index);

  pp2_reg_write (cpu_slot, MVPP2_CLS_FLOW_TBL0_REG, fe->data[0]);
  pp2_reg_write (cpu_slot, MVPP2_CLS_FLOW_TBL1_REG, fe->data[1]);
  pp2_reg_write (cpu_slot, MVPP2_CLS_FLOW_TBL2_REG, fe->data[2]);

  return 0;
}

static int
mv_pp2x_cls_sw_flow_engine_get (struct mv_pp2x_cls_flow_entry *fe, int *engine, int *is_last)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (engine) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (is_last) == MV_ERROR)
    return MV_ERROR;

  *engine = (fe->data[0] & MVPP2_FLOW_ENGINE_MASK) >> MVPP2_FLOW_ENGINE;
  *is_last = fe->data[0] & MVPP2_FLOW_LAST_MASK;

  return 0;
}

static int
mv_pp2x_cls_sw_flow_extra_get (struct mv_pp2x_cls_flow_entry *fe, int *type, int *prio)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (type) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (prio) == MV_ERROR)
    return MV_ERROR;

  *type = (fe->data[1] & MVPP2_FLOW_LKP_TYPE_MASK) >> MVPP2_FLOW_LKP_TYPE;
  *prio = (fe->data[1] & MVPP2_FLOW_FIELD_PRIO_MASK) >> MVPP2_FLOW_FIELD_PRIO;

  return 0;
}

static int
mv_pp2x_cls_sw_flow_hek_get (struct mv_pp2x_cls_flow_entry *fe, int *num_of_fields, int field_ids[])
{
  int index;

  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (num_of_fields) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (field_ids) == MV_ERROR)
    return MV_ERROR;

  *num_of_fields = (fe->data[1] & MVPP2_FLOW_FIELDS_NUM_MASK) >> MVPP2_FLOW_FIELDS_NUM;

  for (index = 0; index < (*num_of_fields); index++)
    field_ids[index] =
      ((fe->data[2] & MVPP2_FLOW_FIELD_MASK (index)) >> MVPP2_FLOW_FIELD_ID (index));

  return 0;
}

static int
mv_pp2x_cls_sw_flow_port_get (struct mv_pp2x_cls_flow_entry *fe, int *type, int *portid)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (type) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (portid) == MV_ERROR)
    return MV_ERROR;

  *type = (fe->data[0] & MVPP2_FLOW_PORT_TYPE_MASK) >> MVPP2_FLOW_PORT_TYPE;
  *portid = (fe->data[0] & MVPP2_FLOW_PORT_ID_MASK) >> MVPP2_FLOW_PORT_ID;

  return 0;
}

static int
mv_pp2x_cls_sw_flow_port_set (struct mv_pp2x_cls_flow_entry *fe, int type, int portid)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (type, 0, ((1 << MVPP2_FLOW_PORT_TYPE_BITS) - 1)) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (portid, 0, ((1 << MVPP2_FLOW_PORT_ID_BITS) - 1)) == MV_ERROR)
    return MV_ERROR;

  fe->data[0] &= ~MVPP2_FLOW_PORT_ID_MASK;
  fe->data[0] &= ~MVPP2_FLOW_PORT_TYPE_MASK;

  fe->data[0] |= (portid << MVPP2_FLOW_PORT_ID);
  fe->data[0] |= (type << MVPP2_FLOW_PORT_TYPE);

  return 0;
}

static int
mv_pp2x_cls_sw_flow_seq_ctrl_get (struct mv_pp2x_cls_flow_entry *fe, int *mode)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;
  if (mv_pp2x_ptr_validate (mode) == MV_ERROR)
    return MV_ERROR;

  *mode = (fe->data[1] & MVPP2_FLOW_SEQ_CTRL_MASK) >> MVPP2_FLOW_SEQ_CTRL;

  return 0;
}

static void
mv_pp2x_prs_flow_id_attr_set (int flow_id, int ri, int ri_mask)
{
  int flow_attr = 0;

  flow_attr |= MVPP2_PRS_FL_ATTR_VLAN_BIT;
  if (ri_mask & MVPP2_PRS_RI_VLAN_MASK && (ri & MVPP2_PRS_RI_VLAN_MASK) == MVPP2_PRS_RI_VLAN_NONE)
    flow_attr &= ~MVPP2_PRS_FL_ATTR_VLAN_BIT;

  if ((ri & MVPP2_PRS_RI_L3_PROTO_MASK) == MVPP2_PRS_RI_L3_IP4 ||
      (ri & MVPP2_PRS_RI_L3_PROTO_MASK) == MVPP2_PRS_RI_L3_IP4_OPT ||
      (ri & MVPP2_PRS_RI_L3_PROTO_MASK) == MVPP2_PRS_RI_L3_IP4_OTHER)
    flow_attr |= MVPP2_PRS_FL_ATTR_IP4_BIT;

  if ((ri & MVPP2_PRS_RI_L3_PROTO_MASK) == MVPP2_PRS_RI_L3_IP6 ||
      (ri & MVPP2_PRS_RI_L3_PROTO_MASK) == MVPP2_PRS_RI_L3_IP6_EXT)
    flow_attr |= MVPP2_PRS_FL_ATTR_IP6_BIT;

  if ((ri & MVPP2_PRS_RI_L3_PROTO_MASK) == MVPP2_PRS_RI_L3_ARP)
    flow_attr |= MVPP2_PRS_FL_ATTR_ARP_BIT;

  if (ri & MVPP2_PRS_RI_IP_FRAG_MASK)
    flow_attr |= MVPP2_PRS_FL_ATTR_FRAG_BIT;

  if ((ri & MVPP2_PRS_RI_L4_PROTO_MASK) == MVPP2_PRS_RI_L4_TCP)
    flow_attr |= MVPP2_PRS_FL_ATTR_TCP_BIT;

  if ((ri & MVPP2_PRS_RI_L4_PROTO_MASK) == MVPP2_PRS_RI_L4_UDP)
    flow_attr |= MVPP2_PRS_FL_ATTR_UDP_BIT;

  mv_pp2x_prs_flow_id_attr_tbl[flow_id] = flow_attr;
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
pp2_cls_db_prs_init_list (struct pp2_inst *inst)
{
  INIT_LIST (&inst->cls_db->prs_db.tcam_match_list);
  INIT_LIST (&inst->cls_db->prs_db.tcam_neg_proto_list);

  return 0;
}

static int
pp2_cls_mng_lkp_type_to_prio (int lkp_type)
{
  int prio;

  switch (lkp_type)
    {
    case MVPP2_CLS_LKP_HASH:
      prio = MVPP2_CLS_KERNEL_HASH_PRIO;
      break;
    case MVPP2_CLS_LKP_VLAN_PRI:
      prio = MVPP2_CLS_KERNEL_VLAN_PRIO;
      break;
    case MVPP2_CLS_LKP_DSCP_PRI:
      prio = MVPP2_CLS_KERNEL_DSCP_PRIO;
      break;
    case MVPP2_CLS_LKP_DEFAULT:
      prio = MVPP2_CLS_KERNEL_DEF_PRIO;
      break;
    case MVPP2_CLS_LKP_MUSDK_LOG_HASH:
      prio = MVPP2_CLS_MUSDK_HASH_PRIO;
      break;
    case MVPP2_CLS_LKP_MUSDK_VLAN_PRI:
      prio = MVPP2_CLS_MUSDK_VLAN_PRIO;
      break;
    case MVPP2_CLS_LKP_MUSDK_DSCP_PRI:
      prio = MVPP2_CLS_MUSDK_DSCP_PRIO;
      break;
    case MVPP2_CLS_LKP_MUSDK_LOG_PORT_DEF:
      prio = MVPP2_CLS_MUSDK_DEF_PRIO;
      break;
    case MVPP2_CLS_LKP_MUSDK_CLS:
      prio = MVPP2_CLS_MUSDK_CLS_PRIO;
      break;
    default:
      pr_err ("unknown lkp type = %d\n", lkp_type);
      return -EINVAL;
    }

  return prio;
}

static int
pp2_cls_new_fl_rl_merge (u16 new_rl_num, struct pp2_cls_fl_t *new_fl_rls,
			 struct pp2_cls_fl_t *mrg_fl_rls)
{
  int rc;

  if (!new_fl_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!mrg_fl_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  /* copy rule to merged flow */
  memcpy (&mrg_fl_rls->fl[mrg_fl_rls->fl_len], &new_fl_rls->fl[new_rl_num],
	  sizeof (struct pp2_cls_rl_entry_t));

  /* set the skip flag in the source */
  new_fl_rls->fl[new_rl_num].skip = 1;

  /* update merged flow length */
  mrg_fl_rls->fl_len++;

  /* update merge engine count */
  rc = pp2_cls_fl_rl_eng_cnt_upd (MVPP2_CNT_INC, new_fl_rls->fl[new_rl_num].engine,
				  &mrg_fl_rls->eng_cnt);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  /* update new engine count */
  rc = pp2_cls_fl_rl_eng_cnt_upd (MVPP2_CNT_DEC, new_fl_rls->fl[new_rl_num].engine,
				  &new_fl_rls->eng_cnt);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  return 0;
}

static int
pp2_cls_rl_c4_validate (struct pp2_cls_rl_entry_t *rl, struct pp2_cls_fl_t *fl_rls, bool *valid)
{
  u16 rl_i;

  if (!rl)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!fl_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  /* scan the flow for an identical rule */
  for (rl_i = 0; rl_i < fl_rls->fl_len; rl_i++)
    {
      if ((fl_rls->fl[rl_i].engine == MVPP2_ENGINE_C4) && (fl_rls->fl[rl_i].prio != rl->prio))
	{
	  pr_err ("add diff prio rule for C4 prohibited merged prio=%d new prio=%d fl_log_id=%d\n",
		  rl->prio, fl_rls->fl[rl_i].prio, fl_rls->fl_log_id);
	  *valid = false;
	  return 0;
	}
    }

  *valid = true;

  return 0;
}

static int
pp2_cls_rl_hit_cnt_upd (struct pp2_cls_rl_entry_t *rl, struct pp2_cls_fl_t *fl_rls,
			struct pp2_cls_fl_eng_cnt_t *eng_hit_cnt)
{
  u16 rl_i;
  int rc;

  if (!rl)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!fl_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!eng_hit_cnt)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  /* scan the flow for an identical rule */
  for (rl_i = 0; rl_i < fl_rls->fl_len; rl_i++)
    {
      if ((fl_rls->fl[rl_i].engine == rl->engine) && (fl_rls->fl[rl_i].lu_type == rl->lu_type) &&
	  (fl_rls->fl[rl_i].prio == rl->prio) && (fl_rls->fl[rl_i].udf7 == rl->udf7) &&
	  (fl_rls->fl[rl_i].field_id_cnt == rl->field_id_cnt) &&
	  (!memcmp (fl_rls->fl[rl_i].field_id, rl->field_id, sizeof (rl->field_id))))
	{
	  return 0;
	}
    }

  /*
   * did not find rule with same engine and priority
   * increment hit counter
   */
  rc = pp2_cls_fl_rl_eng_cnt_upd (MVPP2_CNT_INC, rl->engine, eng_hit_cnt);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  return 0;
}

static int
pp2_cls_rl_hit_cnt_upd_reorder (struct pp2_cls_fl_t *fl_rls, u32 fl_idx,
				struct pp2_cls_fl_eng_cnt_t *eng_hit_cnt)
{
  u16 rl_i;
  int rc;
  struct pp2_cls_rl_entry_t *rl;

  if (!fl_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!eng_hit_cnt)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (((fl_idx) > (fl_rls->fl_len - 1)) || ((fl_idx) < 0))
    {
      pr_err ("(error) %s(%d) value (%d/0x%x) is out of range[%d, %d]\n", __func__, __LINE__,
	      (fl_idx), (fl_idx), 0, (fl_rls->fl_len - 1));
      return -EINVAL;
    }

  rl = &fl_rls->fl[fl_idx];

  /* scan the flow for an identical rule */
  for (rl_i = 0; rl_i < fl_idx; rl_i++)
    {
      if ((fl_rls->fl[rl_i].engine == rl->engine) && (fl_rls->fl[rl_i].lu_type == rl->lu_type) &&
	  (fl_rls->fl[rl_i].prio == rl->prio) && (fl_rls->fl[rl_i].udf7 == rl->udf7) &&
	  (fl_rls->fl[rl_i].field_id_cnt == rl->field_id_cnt) &&
	  (fl_rls->fl[rl_i].port_type == rl->port_type) &&
	  (!memcmp (fl_rls->fl[rl_i].field_id, rl->field_id, sizeof (rl->field_id))))
	return 0;
    }

  /*
   * did not find rule with same engine and priority
   * increment hit counter
   */
  rc = pp2_cls_fl_rl_eng_cnt_upd (MVPP2_CNT_INC, rl->engine, eng_hit_cnt);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  return 0;
}

static int
pp2_db_cls_fl_rule_list_get (struct pp2_inst *inst, u32 off, u32 len,
			     struct pp2_db_cls_fl_rule_t *fl_rl_list)
{
  if (!fl_rl_list)
    {
      pr_err ("%s: null pointer.\n", __func__);
      return -EFAULT;
    }

  if (off >= MVPP2_FLOW_TBL_SIZE || off + len >= MVPP2_FLOW_TBL_SIZE)
    {
      pr_err ("requested rule list too big [offset=%d length=%d]\n", off, len);
      return -EINVAL;
    }

  memcpy (fl_rl_list, &inst->cls_db->cls_db.fl_rule[off],
	  sizeof (struct pp2_db_cls_fl_rule_t) * len);

  return 0;
}

static int
pp2_db_cls_fl_rule_set (struct pp2_inst *inst, u32 off, struct pp2_db_cls_fl_rule_t *fl_rule)
{
  if (!fl_rule)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  if (off >= MVPP2_FLOW_TBL_SIZE)
    {
      pr_err ("Invalid parameter\n");
      return -EINVAL;
    }
  memcpy (&inst->cls_db->cls_db.fl_rule[off], fl_rule, sizeof (struct pp2_db_cls_fl_rule_t));

  return 0;
}

static int
pp2_db_cls_rl_off_free_set (struct pp2_inst *inst, u16 off, u16 *log)
{
  if (!log)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  if (off >= MVPP2_FLOW_TBL_SIZE)
    {
      pr_err ("Invalid parameter\n");
      return -EINVAL;
    }

  if ((MVPP2_CLS_LOG2OFF_TBL_SIZE - inst->cls_db->cls_db.log2off[MVPP2_CLS_FREE_LOG2OFF]) == 0)
    return -EINVAL;

  *log = inst->cls_db->cls_db.log2off[MVPP2_CLS_FREE_LOG2OFF];

  inst->cls_db->cls_db.log2off[*log] = off;

  inst->cls_db->cls_db.log2off[MVPP2_CLS_FREE_LOG2OFF]++;

  return 0;
}

static int
pp2_db_cls_rl_off_get (struct pp2_inst *inst, u16 *off, u16 log)
{
  if (!off)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  if (log > MVPP2_CLS_LOG2OFF_TBL_SIZE)
    {
      pr_err ("Invalid parameter\n");
      return -EFAULT;
    }

  if (inst->cls_db->cls_db.log2off[log] == MVPP2_CLS_FREE_FL_LOG)
    return -EINVAL;

  *off = inst->cls_db->cls_db.log2off[log];

  return 0;
}

static int
pp2_db_cls_rl_off_set (struct pp2_inst *inst, u16 off, u16 log)
{
  if (log > MVPP2_CLS_LOG2OFF_TBL_SIZE)
    {
      pr_err ("Invalid parameter\n");
      return -EINVAL;
    }
  inst->cls_db->cls_db.log2off[log] = off;

  return 0;
}

static enum musdk_lnx_id lnx_id_get (void);
static int mv_kernel_ver_get (void);
static int mv_pp2x_cls_hw_lkp_read (uintptr_t cpu_slot, int lkpid, int way,
				    struct mv_pp2x_cls_lookup_entry *fe);
static int mv_pp2x_cls_sw_lkp_en_get (struct mv_pp2x_cls_lookup_entry *le, int *en);
static int mv_pp2x_cls_sw_lkp_flow_get (struct mv_pp2x_cls_lookup_entry *le, int *flow_idx);
static int mv_pp2x_cls_sw_lkp_mod_get (struct mv_pp2x_cls_lookup_entry *le, int *mod_base);
static int mv_pp2x_cls_sw_lkp_rxq_get (struct mv_pp2x_cls_lookup_entry *lkp, int *rxq);
static void mv_pp2x_prs_flow_id_attr_init (void);
static int mv_pp2x_prs_log_port_init (struct pp2_inst *inst);
static int mv_pp2x_prs_shadow_update (struct pp2_inst *inst);
static uint32_t pp2_bm_hw_pool_create (uintptr_t cpu_slot, uint32_t pool_id, u32 bppe_num,
				       uintptr_t pool_phys_addr);
static void pp2_cls_c3_shadow_init (void);
static int pp2_cls_db_rss_init (struct pp2_inst *inst);
static void pp2_cls_db_rss_kernel_rsvd_tbl_set (struct pp2_inst *inst, u16 kernel_rss_tbl);
static int pp2_cls_find_flows_per_lkp (uintptr_t cpu_slot, struct pp2_cls_fl_rule_list_t *fl_rls,
				       int flow_log_id, int flow_index);
static int pp2_cls_fl_cur_get (struct pp2_inst *inst, u16 fl_log_id, struct pp2_cls_fl_t *cur_fl);
static int pp2_cls_fl_nt_rule_reorder (struct pp2_cls_fl_t *fl_rls);
static int pp2_cls_fl_rl_db_set (struct pp2_inst *inst, struct pp2_cls_rl_entry_t *rl,
				 u16 fl_log_id);
static int pp2_cls_fl_rl_eng_cnt_upd (enum pp2_cls_rl_cnt_op_t op, u16 eng,
				      struct pp2_cls_fl_eng_cnt_t *eng_cnt);
static int pp2_cls_fl_rl_hw_ena (struct pp2_inst *inst, struct pp2_cls_fl_rule_entry_t *rl_en);
static int pp2_cls_fl_rls_log_rl_id_upd (struct pp2_cls_fl_rule_list_t *add_rls,
					 struct pp2_cls_fl_t *mrg_rls);
static int pp2_cls_fl_rls_merge (struct pp2_inst *inst, u16 fl_log_id,
				 struct pp2_cls_fl_t *cur_fl_rls, struct pp2_cls_fl_t *new_fl_rls,
				 struct pp2_cls_fl_t *mrg_fl_rls);
static int pp2_cls_fl_rls_set (struct pp2_inst *inst, struct pp2_cls_fl_t *fl_rls);
static void pp2_cls_fl_rls_sort (struct pp2_cls_rl_entry_t fls[], u16 fl_len);
static int pp2_cls_lkp_dcod_enable (struct pp2_inst *inst, u16 fl_log_id);
static int pp2_cls_lkp_dcod_set (struct pp2_inst *inst,
				 struct pp2_cls_lkp_dcod_entry_t *lkp_dcod_conf);
static int pp2_cls_mng_add_default_flow (struct pp2_ppio *ppio);
static int pp2_cls_mng_set_coloring (struct pp2_ppio *ppio, int clear);
static int pp2_cls_mng_set_policing (struct pp2_ppio *ppio, int clear);
static int pp2_db_cls_lkp_dcod_get (struct pp2_inst *inst, u32 fl_log_id,
				    struct pp2_db_cls_lkp_dcod_t *lkp_dcod);
static void pp2_dm_aggr_queue_config (struct pp2_dm_if *dm_if, uintptr_t addr, u32 size);
static int pp2_prs_eth_start_header_set (struct pp2_port *port, enum pp2_ppio_eth_start_hdr mode);
static int pp2_prs_set_log_port (struct pp2_port *port, struct pp2_ppio_log_port_params *params);
static inline u16 pp2_rss_map_get (void);

static int
mv_kernel_ver_get (void)
{
  int major, minor, parsed;
  char *kernel_version;
  struct utsname buf;
  int ret;

  ret = uname (&buf);
  if (ret < 0)
    return ret;
  kernel_version = buf.release;
  parsed = sscanf (kernel_version, "%d.%d", &major, &minor);
  if (parsed < 2)
    {
      pr_err ("%s: Failed to Parse linux_version\n", __func__);
      return 0;
    }

  pr_debug ("%s: ver:%s, major:%d, minor:%d\n", __func__, kernel_version, major, minor);

  return MKDEV (major, minor);
}

static int
mv_pp2x_cls_hw_lkp_read (uintptr_t cpu_slot, int lkpid, int way,
			 struct mv_pp2x_cls_lookup_entry *fe)
{
  unsigned int reg_val = 0;

  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (way, 0, WAY_MAX) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (lkpid, 0, MVPP2_CLS_FLOWS_TBL_SIZE) == MV_ERROR)
    return MV_ERROR;

  /* write index reg */
  reg_val = (way << MVPP2_CLS_LKP_INDEX_WAY_OFFS) | (lkpid << MVPP2_CLS_LKP_INDEX_LKP_OFFS);
  pp2_reg_write (cpu_slot, MVPP2_CLS_LKP_INDEX_REG, reg_val);

  fe->way = way;
  fe->lkpid = lkpid;

  fe->data = pp2_reg_read (cpu_slot, MVPP2_CLS_LKP_TBL_REG);

  return 0;
}

static int
mv_pp2x_cls_sw_lkp_en_get (struct mv_pp2x_cls_lookup_entry *le, int *en)
{
  if (mv_pp2x_ptr_validate (le) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (en) == MV_ERROR)
    return MV_ERROR;

  *en = (le->data & MVPP2_FLOWID_EN_MASK) >> MVPP2_FLOWID_EN;

  return 0;
}

static int
mv_pp2x_cls_sw_lkp_flow_get (struct mv_pp2x_cls_lookup_entry *le, int *flow_idx)
{
  if (mv_pp2x_ptr_validate (le) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (flow_idx) == MV_ERROR)
    return MV_ERROR;

  *flow_idx = (le->data & MVPP2_FLOWID_FLOW_MASK) >> MVPP2_FLOWID_FLOW;

  return 0;
}

static int
mv_pp2x_cls_sw_lkp_mod_get (struct mv_pp2x_cls_lookup_entry *le, int *mod_base)
{
  if (mv_pp2x_ptr_validate (le) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (mod_base) == MV_ERROR)
    return MV_ERROR;

  *mod_base = (le->data & MVPP2_FLOWID_MODE_MASK) >> MVPP2_FLOWID_MODE;

  return 0;
}

static int
mv_pp2x_cls_sw_lkp_rxq_get (struct mv_pp2x_cls_lookup_entry *lkp, int *rxq)
{
  if (mv_pp2x_ptr_validate (lkp) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_ptr_validate (rxq) == MV_ERROR)
    return MV_ERROR;

  *rxq = (lkp->data & MVPP2_FLOWID_RXQ_MASK) >> MVPP2_FLOWID_RXQ;
  return 0;
}

static void
mv_pp2x_prs_flow_id_attr_init (void)
{
  int index;
  u32 ri, ri_mask, flow_id;
  enum musdk_lnx_id lnx_id = lnx_id_get ();
  struct mv_pp2x_prs_flow_id *prs_flow_id_array;

  /* For backwards compatibility to LK 4.4 */
  if (lnx_is_mainline (lnx_id))
    prs_flow_id_array = mv_pp2x_prs_flow_id_array;
  else
    prs_flow_id_array = mv_pp2x_prs_flow_id_array_4_4;

  for (index = 0; index < MVPP2_PRS_FL_TCAM_NUM; index++)
    {
      ri = prs_flow_id_array[index].prs_result.ri;
      ri_mask = prs_flow_id_array[index].prs_result.ri_mask;
      flow_id = prs_flow_id_array[index].flow_id;

      mv_pp2x_prs_flow_id_attr_set (flow_id, ri, ri_mask);
    }
}

static int
mv_pp2x_prs_log_port_init (struct pp2_inst *inst)
{
  u32 i;
  struct mv_pp2x_prs_entry pe;
  struct mv_pp2x_prs_shadow *prs_shadow = inst->cls_db->prs_db.prs_shadow;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  if (!prs_shadow)
    {
      pr_err ("prs_shadow is null\n");
      return -EFAULT;
    }

  /* Init parser logical port lists*/
  pp2_cls_db_prs_init_list (inst);

  for (i = 0; i < MVPP2_PRS_TCAM_SRAM_SIZE; i++)
    {
      /* Clean all UDF7 bits from shadow and from HW (maybe were set in previous runs) */
      if (prs_shadow[i].valid && ((prs_shadow[i].ri & MVPP2_PRS_RI_UDF7_NIC) ||
				  (prs_shadow[i].ri & MVPP2_PRS_RI_UDF7_LOG_PORT)))
	{
	  prs_shadow[i].ri &= ~MVPP2_PRS_RI_UDF7_NIC;
	  prs_shadow[i].ri &= ~MVPP2_PRS_RI_UDF7_LOG_PORT;
	  prs_shadow[i].ri_mask &= ~MVPP2_PRS_RI_UDF7_MASK;
	  pe.index = i;
	  mv_pp2x_prs_hw_read (cpu_slot, &pe);
	  mv_pp2x_prs_sram_ri_update (&pe, MVPP2_PRS_RI_UDF7_CLEAR, MVPP2_PRS_RI_UDF7_MASK);
	  mv_pp2x_prs_hw_write (cpu_slot, &pe);
	}

      /* Set default UDF7 to all MH entries to send traffic to kernel */
      if (prs_shadow[i].valid && prs_shadow[i].lu == MVPP2_PRS_LU_MH)
	{
	  pe.index = i;
	  mv_pp2x_prs_hw_read (cpu_slot, &pe);
	  mv_pp2x_prs_sram_ri_update (&pe, MVPP2_PRS_RI_UDF7_CLEAR, MVPP2_PRS_RI_UDF7_MASK);
	  mv_pp2x_prs_sram_ri_update (&pe, MVPP2_PRS_RI_UDF7_NIC, MVPP2_PRS_RI_UDF7_MASK);
	  mv_pp2x_prs_hw_write (cpu_slot, &pe);
	}
    }
  return 0;
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

static uint32_t
pp2_bm_hw_pool_create (uintptr_t cpu_slot, uint32_t pool_id, u32 bppe_num, uintptr_t pool_phys_addr)
{
  u32 val;
  u32 phys_lo;
  u32 phys_hi;
  u32 pool_bufs;

  phys_lo = ((uint32_t) pool_phys_addr) & MVPP2_BM_POOL_BASE_ADDR_MASK;
  phys_hi = ((uint64_t) pool_phys_addr) >> 32;

  /* Check control register to see if this pool is already initialized */
  val = pp2_reg_read (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id));
  if (val & MVPP2_BM_STATE_MASK)
    {
      pr_err ("BM: pool=%u is already active\n", pool_id);
      return 1;
    }

  pp2_reg_write (cpu_slot, MVPP2_BM_POOL_BASE_ADDR_REG (pool_id), phys_lo);

  val = pp2_reg_read (cpu_slot, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG);
  val &= ~MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  val |= phys_hi & MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  pp2_reg_write (cpu_slot, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG, val);

  pool_bufs = pp2_reg_read (cpu_slot, MVPP2_BM_POOL_SIZE_REG (pool_id));

  if (!pool_bufs)
    pp2_reg_write (cpu_slot, MVPP2_BM_POOL_SIZE_REG (pool_id), bppe_num);
  else if (pool_bufs != bppe_num)
    {
      pr_err (
	"BM: pool%u: already configured pool size (%d) does not match the required value (%d)\n",
	pool_id, pool_bufs, bppe_num);
      return 1;
    }

  val = pp2_reg_read (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id));
  val |= MVPP2_BM_START_MASK;

  val &= ~MVPP2_BM_LOW_THRESH_MASK;
  val &= ~MVPP2_BM_HIGH_THRESH_MASK;

  if (pp2_bm_get_8pool_mode (cpu_slot))
    {
      val |= MVPP2_BM_LOW_THRESH_VALUE (MVPP23_BM_BPPI_8POOL_LOW_THRESH);
      val |= MVPP2_BM_HIGH_THRESH_VALUE (MVPP23_BM_BPPI_8POOL_HIGH_THRESH);
    }
  else
    {
      val |= MVPP2_BM_LOW_THRESH_VALUE (MVPP2_BM_BPPI_LOW_THRESH);
      val |= MVPP2_BM_HIGH_THRESH_VALUE (MVPP2_BM_BPPI_HIGH_THRESH);
    }

  pp2_reg_write (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id), val);

  /* Wait pool start notification */
  do
    {
      val = pp2_reg_read (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id));
    }
  while (!(val & MVPP2_BM_STATE_MASK));

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
pp2_cls_find_flows_per_lkp (uintptr_t cpu_slot, struct pp2_cls_fl_rule_list_t *fl_rls,
			    int flow_log_id, int flow_index)
{
  int rc;

  struct mv_pp2x_cls_flow_entry fe;
  int engine, is_last, num_of_fields, port_type, port_id, lkp_type, prio, seq_ctrl, tmp;
  int fields_arr[MVPP2_CLS_FLOWS_TBL_FIELDS_MAX];

  for (; flow_index < MVPP2_CLS_FLOWS_TBL_SIZE; flow_index++)
    {
      rc = mv_pp2x_cls_hw_flow_read (cpu_slot, flow_index, &fe);
      if (rc)
	{
	  pr_err ("mv_pp2x_cls_hw_flow_read fail rc = %d\n", rc);
	  return rc;
	}

      rc = mv_pp2x_cls_sw_flow_engine_get (&fe, &engine, &is_last);
      if (rc)
	{
	  pr_err ("mv_pp2x_cls_sw_flow_engine_get fail rc = %d\n", rc);
	  return rc;
	}

      if (!engine)
	{
	  pr_err ("didn't find any flows\n");
	  break;
	}

      rc = mv_pp2x_cls_sw_flow_extra_get (&fe, &lkp_type, &tmp);
      if (rc)
	{
	  pr_err ("mv_pp2x_cls_sw_flow_extra_get fail rc = %d\n", rc);
	  return rc;
	}

      /* add only kernel flows to db & hw */
      if (lkp_type > MVPP2_CLS_LKP_DEFAULT)
	{
	  if (is_last)
	    {
	      pr_debug ("found %d flows\n", fl_rls->fl_len);
	      break;
	    }
	  continue;
	}
      prio = pp2_cls_mng_lkp_type_to_prio (lkp_type);
      if (prio < 0)
	return -EINVAL;

      rc = mv_pp2x_cls_sw_flow_port_get (&fe, &port_type, &port_id);
      if (rc)
	{
	  pr_err ("mv_pp2x_cls_sw_flow_port_get fail rc = %d\n", rc);
	  return rc;
	}

      rc = mv_pp2x_cls_sw_flow_seq_ctrl_get (&fe, &seq_ctrl);
      if (rc)
	{
	  pr_err ("mv_pp2x_cls_sw_flow_seq_ctrl_get fail rc = %d\n", rc);
	  return rc;
	}

      rc = mv_pp2x_cls_sw_flow_hek_get (&fe, &num_of_fields, fields_arr);
      if (rc)
	{
	  pr_err ("mv_pp2x_cls_sw_flow_hek_get fail rc = %d\n", rc);
	  return rc;
	}

      fl_rls->fl[fl_rls->fl_len].fl_log_id = flow_log_id;
      fl_rls->fl[fl_rls->fl_len].engine = engine;
      fl_rls->fl[fl_rls->fl_len].port_type = port_type;
      fl_rls->fl[fl_rls->fl_len].port_bm = port_id;
      fl_rls->fl[fl_rls->fl_len].lu_type = lkp_type;
      fl_rls->fl[fl_rls->fl_len].enabled = true;
      fl_rls->fl[fl_rls->fl_len].prio = prio;
      fl_rls->fl[fl_rls->fl_len].udf7 = MVPP2_CLS_KERNEL_UDF7;
      fl_rls->fl[fl_rls->fl_len].seq_ctrl = seq_ctrl;
      fl_rls->fl[fl_rls->fl_len].field_id_cnt = (u8) num_of_fields;
      fl_rls->fl[fl_rls->fl_len].field_id[0] = (u8) fields_arr[0];
      fl_rls->fl[fl_rls->fl_len].field_id[1] = (u8) fields_arr[1];
      fl_rls->fl[fl_rls->fl_len].field_id[2] = (u8) fields_arr[2];
      fl_rls->fl[fl_rls->fl_len].field_id[3] = (u8) fields_arr[3];
      fl_rls->fl_len++;

      if (fl_rls->fl_len >= MVPP2_CLS_FLOW_RULE_MAX)
	{
	  pr_err ("too many flow found, fl_len = %d\n", fl_rls->fl_len);
	  return -EFAULT;
	}

      if (is_last)
	{
	  pr_debug ("found %d flows\n", fl_rls->fl_len);
	  break;
	}
    }

  return 0;
}

static int
pp2_cls_fl_cur_get (struct pp2_inst *inst, u16 fl_log_id, struct pp2_cls_fl_t *cur_fl)
{
  struct pp2_db_cls_fl_rule_list_t *fl_rl_db;
  struct pp2_db_cls_lkp_dcod_t lkp_dcod_db;
  int rc;
  u16 i;

  if (!cur_fl)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  /* get the lookup DB for this logical flow ID */
  rc = pp2_db_cls_lkp_dcod_get (inst, fl_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("failed to get lookup decode info for fl_log_id %d\n", fl_log_id);
      return rc;
    }

#ifdef MVPP2_CLS_DEBUG
  debug_dump_lkp_dcod_db ("pp2_cls_fl_cur_get", &lkp_dcod_db);
#endif

  memset (cur_fl, 0, sizeof (struct pp2_cls_fl_t));
  fl_rl_db = clib_mem_alloc_or_null (sizeof (*fl_rl_db));
  if (!fl_rl_db)
    {
      pr_err ("%s(%d) Error allocating memory!\n", __func__, __LINE__);
      return -ENOMEM;
    }
  memset (fl_rl_db, 0, sizeof (struct pp2_db_cls_fl_rule_list_t));

  /* update DB flow length */
  fl_rl_db->flow_len = lkp_dcod_db.flow_len;
  cur_fl->fl_log_id = fl_log_id;

  if (lkp_dcod_db.flow_len == 0)
    {
      if (fl_rl_db)
	clib_mem_free (fl_rl_db);
      return 0;
    }

  rc = pp2_db_cls_fl_rule_list_get (inst, lkp_dcod_db.flow_off, lkp_dcod_db.flow_len,
				    &fl_rl_db->flow[0]);

  if (rc)
    {
      pr_err ("fail to get flow rule list DB data, fl_log_id=%d, flow_off=%d, flow_len=%d\n",
	      fl_log_id, lkp_dcod_db.flow_off, lkp_dcod_db.flow_len);
      if (fl_rl_db)
	clib_mem_free (fl_rl_db);
      return rc;
    }

  /* set the current flow additional configurations */
  cur_fl->fl_len = fl_rl_db->flow_len;

  for (i = 0; i < fl_rl_db->flow_len; i++)
    {
      cur_fl->fl[i].enabled = fl_rl_db->flow[i].enabled;
      cur_fl->fl[i].engine = fl_rl_db->flow[i].engine;
      cur_fl->fl[i].field_id_cnt = fl_rl_db->flow[i].field_id_cnt;

      memcpy (cur_fl->fl[i].field_id, fl_rl_db->flow[i].field_id, sizeof (cur_fl->fl[i].field_id));

      cur_fl->fl[i].rl_off = lkp_dcod_db.flow_off + i;
      cur_fl->fl[i].lu_type = fl_rl_db->flow[i].lu_type;
      cur_fl->fl[i].port_bm = fl_rl_db->flow[i].port_bm;
      cur_fl->fl[i].port_type = fl_rl_db->flow[i].port_type;
      cur_fl->fl[i].prio = fl_rl_db->flow[i].prio;
      cur_fl->fl[i].udf7 = fl_rl_db->flow[i].udf7;
      memcpy (&cur_fl->fl[i].ref_cnt[0], &fl_rl_db->flow[i].ref_cnt[0],
	      PP2_NUM_PORTS * sizeof (u16));
      cur_fl->fl[i].rl_log_id = fl_rl_db->flow[i].rl_log_id;
      cur_fl->fl[i].state = MVPP2_MRG_NOT_NEW;
      cur_fl->fl[i].skip = 0;

      rc = pp2_cls_fl_rl_eng_cnt_upd (MVPP2_CNT_INC, fl_rl_db->flow[i].engine, &cur_fl->eng_cnt);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}
    }

  if (fl_rl_db)
    clib_mem_free (fl_rl_db);
  return 0;
}

static int
pp2_cls_fl_nt_rule_reorder (struct pp2_cls_fl_t *fl_rls)
{
  int i, j, len;
  u16 rl_off;
  struct pp2_cls_fl_eng_cnt_t eng_cnt[MVPP2_CLS_FLOW_RND_MAX]; /* two hit rounds */

  memset (&eng_cnt[0], 0, sizeof (eng_cnt));

  rl_off = fl_rls->fl[0].rl_off;

  for (i = 0; i < fl_rls->fl_len; i++)
    {
      /* Skip the normal flow rules */
      if (fl_rls->fl[i].seq_ctrl == MVPP2_CLS_SEQ_CTRL_NORMAL)
	continue;
      /* Find the first type rule */
      if (fl_rls->fl[i].seq_ctrl != MVPP2_CLS_SEQ_CTRL_FIRST_TYPE_1)
	{
	  pr_err ("n-tuple rule (%d) not start from first type 1\n", i);
	  return -EINVAL;
	}
      /* Get the n-tuple flow length */
      for (len = 1; len + i < fl_rls->fl_len; len++)
	{
	  if (fl_rls->fl[len + i].seq_ctrl != MVPP2_CLS_SEQ_CTRL_MIDDLE &&
	      fl_rls->fl[len + i].seq_ctrl != MVPP2_CLS_SEQ_CTRL_LAST)
	    {
	      pr_err ("unexpect rule (%d) sequence type (%d)\n", len + i,
		      fl_rls->fl[len + i].seq_ctrl);
	      return -EINVAL;
	    }
	  if (fl_rls->fl[len + i].seq_ctrl == MVPP2_CLS_SEQ_CTRL_LAST)
	    break;
	}
      if (len + i == fl_rls->fl_len)
	{
	  pr_err ("not found last sequence rule\n");
	  return -EINVAL;
	}
      /* Reach the end of the flow rules - out */
      if (len + i + 1 == fl_rls->fl_len)
	break;
      /* Find the higher priority rule after the n-tuple flow rules */
      for (j = len + i + 1; j < fl_rls->fl_len; j++)
	{
	  if (fl_rls->fl[j].prio < fl_rls->fl[i].prio)
	    break;
	}
      /* Skip the entire n-tuple flow if not found the higher priority rule */
      if (j == fl_rls->fl_len)
	{
	  i += len;
	  continue;
	}
      /* Reorder the rules */
      pp2_cls_fl_rls_sort (&fl_rls->fl[i], j - i + 1);
    }

  /* Reassign the rule offset */
  for (i = 0, j = 0; i < fl_rls->fl_len; i++)
    {
      fl_rls->fl[i].rl_off = rl_off + i;
      if (fl_rls->fl[i].engine == MVPP2_ENGINE_C3_A || fl_rls->fl[i].engine == MVPP2_ENGINE_C3_B ||
	  fl_rls->fl[i].engine == MVPP2_ENGINE_C3_HA || fl_rls->fl[i].engine == MVPP2_ENGINE_C3_HB)
	{
	  if (j == 0 && eng_cnt[0].c3 == MVPP2_CLS_C3_RND_MAX)
	    j = 1;
	}
      else if (fl_rls->fl[i].engine == MVPP2_ENGINE_C2)
	{
	  if (j == 0 && eng_cnt[0].c2 == MVPP2_CLS_C2_RND_MAX)
	    j = 1;
	}
      pp2_cls_rl_hit_cnt_upd_reorder (fl_rls, i, &eng_cnt[j]);
      if (j == 0 && RND_HIT_CNT (eng_cnt, 0) == MVPP2_CLS_FL_RND_SIZE)
	j = 1;
    }

  /* Verify hit count of each engine */
  if (eng_cnt[1].c2 > MVPP2_CLS_C2_RND_MAX || eng_cnt[1].c3 > MVPP2_CLS_C3_RND_MAX)
    {
      pr_err ("c2 hits (%d) or c3 hits (%d) exceed maximum number\n", eng_cnt[1].c2, eng_cnt[1].c3);
      return -EINVAL;
    }

  return 0;
}

static int
pp2_cls_fl_rl_db_set (struct pp2_inst *inst, struct pp2_cls_rl_entry_t *rl, u16 fl_log_id)
{
  struct pp2_db_cls_fl_rule_t rl_db;
  int rc;
  u16 cur_rl_off;
  int loop;

  if (!rl)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  memset (&rl_db, 0, sizeof (rl_db));

  /* different handling for rule states */
  switch (rl->state)
    {
    case MVPP2_MRG_NEW:
      /* new rule, assign logical rule id */
      rc = pp2_db_cls_rl_off_free_set (inst, rl->rl_off, &rl->rl_log_id);
      if (rc)
	{
	  pr_err ("got error for rule offset %d\n", rl->rl_off);
	  return rc;
	}

      /* save the new logical rule ID in DB */
      rl_db.rl_log_id = rl->rl_log_id;
      break;

    case MVPP2_MRG_NEW_EXISTS:
    case MVPP2_MRG_NOT_NEW:
      /* this new entry exists */
      rc = pp2_db_cls_rl_off_get (inst, &cur_rl_off, rl->rl_log_id);
      if (rc)
	{
	  pr_err ("could not get rl_log_id %d offset\n", rl->rl_log_id);
	  return rc;
	}

      /* if logical rule offset changed, update new offset */
      if (cur_rl_off != rl->rl_off)
	{
	  rc = pp2_db_cls_rl_off_set (inst, rl->rl_off, rl->rl_log_id);
	  if (rc)
	    {
	      pr_err ("could not set rule offset %d for rl_log_id %d\n", rl->rl_off, rl->rl_log_id);
	      return rc;
	    }
	}

      /* this rule is not new, use the current ref_count */
      memcpy (&rl_db.ref_cnt[0], &rl->ref_cnt[0], PP2_NUM_PORTS * sizeof (u16));
      /* same rule logical id */
      rl_db.rl_log_id = rl->rl_log_id;
      break;

    default:
      pr_err ("Invalid rule state [rl->state=%d]\n", rl->state);
      return -EINVAL;
    }

  memcpy (rl_db.field_id, rl->field_id, sizeof (rl->field_id));

  if (rl->state != MVPP2_MRG_NOT_NEW)
    {
      /* update ref_count for new entries only */
      for (loop = 0; loop < PP2_NUM_PORTS; loop++)
	{
	  if ((1 << loop) & rl->port_bm)
	    rl_db.ref_cnt[loop] = (rl->enabled) ? rl->ref_cnt[loop] + 1 : 0;
	}
    }

  rl_db.enabled = rl->enabled;
  rl_db.engine = rl->engine;
  rl_db.field_id_cnt = rl->field_id_cnt;
  rl_db.lu_type = rl->lu_type;
  rl_db.port_bm = rl->port_bm;
  rl_db.port_type = rl->port_type;
  rl_db.prio = rl->prio;
  rl_db.udf7 = rl->udf7;

  rc = pp2_db_cls_fl_rule_set (inst, rl->rl_off, &rl_db);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  return 0;
}

static int
pp2_cls_fl_rl_eng_cnt_upd (enum pp2_cls_rl_cnt_op_t op, u16 eng,
			   struct pp2_cls_fl_eng_cnt_t *eng_cnt)
{
  if (!eng_cnt)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  switch (eng)
    {
    case MVPP2_ENGINE_C2:
      (op == MVPP2_CNT_DEC) ? eng_cnt->c2-- : eng_cnt->c2++;
      break;

    case MVPP2_ENGINE_C3_A:
    case MVPP2_ENGINE_C3_B:
    case MVPP2_ENGINE_C3_HA:
    case MVPP2_ENGINE_C3_HB:
      (op == MVPP2_CNT_DEC) ? eng_cnt->c3-- : eng_cnt->c3++;
      break;

    case MVPP2_ENGINE_C4:
      (op == MVPP2_CNT_DEC) ? eng_cnt->c4-- : eng_cnt->c4++;
      break;

    default:
      pr_err ("Invalid input [engine=%d op=%d]\n", eng, op);
      return -EINVAL;
    }
  return 0;
}

static int
pp2_cls_fl_rl_hw_ena (struct pp2_inst *inst, struct pp2_cls_fl_rule_entry_t *rl_en)
{
  struct mv_pp2x_cls_flow_entry fe;
  int rc;
  u16 off;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  if (!rl_en)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  /* get the rule offset according to rule logical ID */
  rc = pp2_db_cls_rl_off_get (inst, &off, rl_en->rl_log_id);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  rc = mv_pp2x_cls_hw_flow_read (cpu_slot, off, &fe);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  /* enable the rule according to DB settings */
  rc = mv_pp2x_cls_sw_flow_port_set (&fe, rl_en->port_type, rl_en->port_bm);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  fe.index = off;
  rc = mv_pp2x_cls_hw_flow_write (cpu_slot, &fe);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  return 0;
}

static int
pp2_cls_fl_rls_log_rl_id_upd (struct pp2_cls_fl_rule_list_t *add_rls, struct pp2_cls_fl_t *mrg_rls)
{
  u16 i, j;

  if (!add_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  if (!mrg_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  for (i = 0; i < add_rls->fl_len; i++)
    {
      if (add_rls->fl[i].fl_log_id != mrg_rls->fl_log_id)
	continue;

      for (j = 0; j < mrg_rls->fl_len; j++)
	{
	  if (add_rls->fl[i].engine == mrg_rls->fl[j].engine &&
	      add_rls->fl[i].field_id_cnt == mrg_rls->fl[j].field_id_cnt &&
	      add_rls->fl[i].lu_type == mrg_rls->fl[j].lu_type &&
	      add_rls->fl[i].port_bm == mrg_rls->fl[j].port_bm &&
	      add_rls->fl[i].port_type == mrg_rls->fl[j].port_type &&
	      add_rls->fl[i].prio == mrg_rls->fl[j].prio &&
	      add_rls->fl[i].udf7 == mrg_rls->fl[j].udf7 &&
	      !memcmp (add_rls->fl[i].field_id, mrg_rls->fl[j].field_id,
		       sizeof (add_rls->fl[i].field_id)))
	    {
	      /* found the added rule, update logial rule ID */
	      add_rls->fl[i].rl_log_id = mrg_rls->fl[j].rl_log_id;
	      break;
	    }
	}
      if (j == mrg_rls->fl_len)
	{
	  pr_err ("new rule #%d not found in merged flow\n", i);
	  return -EINVAL;
	}
    }

  return 0;
}

static int
pp2_cls_fl_rls_merge (struct pp2_inst *inst, u16 fl_log_id, struct pp2_cls_fl_t *cur_fl_rls,
		      struct pp2_cls_fl_t *new_fl_rls, struct pp2_cls_fl_t *mrg_fl_rls)
{
  bool valid_c4;
  u16 rl;
  int rc;
  u16 cur_rl_cnt, new_rl_cnt;
  u16 rl_off;
  u16 rnd = 0;
  struct pp2_db_cls_lkp_dcod_t lkp_dcod_db;
  struct pp2_cls_fl_eng_cnt_t eng_hit_cnt[MVPP2_CLS_FLOW_RND_MAX]; /* two hit rounds */

  if (!cur_fl_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  if (!new_fl_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  if (!mrg_fl_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  /* get the lookup DB for this logical flow ID */
  rc = pp2_db_cls_lkp_dcod_get (inst, fl_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("failed to get lookup decode info for fl_log_id %d\n", fl_log_id);
      return rc;
    }

  rl_off = lkp_dcod_db.flow_off;

  memset (mrg_fl_rls, 0, sizeof (struct pp2_cls_fl_t));
  memset (&eng_hit_cnt[0], 0, sizeof (eng_hit_cnt));

  mrg_fl_rls->fl_log_id = fl_log_id;
  cur_rl_cnt = cur_fl_rls->fl_len;
  new_rl_cnt = new_fl_rls->fl_len;

  /* max flow length check */
  if (cur_rl_cnt + new_rl_cnt > MVPP2_CLS_FLOW_RULE_MAX)
    {
      pr_err ("cur_rl_cnt + new_rl_cnt too large [cur %d new %d]\n", cur_rl_cnt, new_rl_cnt);
      return -EPERM;
    }

  /* merge while loop */
  while (cur_rl_cnt || new_rl_cnt)
    {
      u16 cur_rl = MVPP2_CLS_FLOW_RULE_MAX;
      u16 new_rl = MVPP2_CLS_FLOW_RULE_MAX;
      bool merge_new = false;
      bool is_seq = false;

#ifdef MVPP2_CLS_DEBUG
      debug_dump_cls_fl ("curr", cur_fl_rls);
      debug_dump_cls_fl ("new", new_fl_rls);
#endif
      /* update round number */
      if (rnd == 0 && (RND_HIT_CNT (eng_hit_cnt, 0) == MVPP2_CLS_FL_RND_SIZE))
	rnd = 1;

      cur_rl = MVPP2_CLS_FLOW_RULE_MAX;
      new_rl = MVPP2_CLS_FLOW_RULE_MAX;

      /* get first C4 rule from cur and new flows  */
      if (new_fl_rls->eng_cnt.c4)
	{
	  for (rl = 0; rl < new_fl_rls->fl_len; rl++)
	    {
	      if (!new_fl_rls->fl[rl].skip && (new_fl_rls->fl[rl].engine == MVPP2_ENGINE_C4))
		{
		  break;
		}
	    }
	  if (rl == new_fl_rls->fl_len)
	    {
	      pr_err ("eng count inconsistent new_rl=%d fl_len=%d\n", rl, new_fl_rls->fl_len);
	      return -EINVAL;
	    }
	  /* found a new c4 rule, save index */
	  new_rl = rl;
	}

      if (cur_fl_rls->eng_cnt.c4)
	{
	  for (rl = 0; rl < cur_fl_rls->fl_len; rl++)
	    {
	      if (!cur_fl_rls->fl[rl].skip && (cur_fl_rls->fl[rl].engine == MVPP2_ENGINE_C4))
		{
		  break;
		}
	    }
	  if (rl == cur_fl_rls->fl_len)
	    {
	      pr_err ("eng count inconsistent new_rl=%d fl_len=%d\n", rl, cur_fl_rls->fl_len);
	      return -EINVAL;
	    }
	  /* found a current c4 rule, save index */
	  cur_rl = rl;
	}

      /* no C4 rules, proceed with C3 */
      if ((new_fl_rls->eng_cnt.c4 == 0) && (cur_fl_rls->eng_cnt.c4 == 0))
	goto c3_ins;

      /* decide which rule to merge according to rule priority */
      if (cur_rl != MVPP2_CLS_FLOW_RULE_MAX)
	merge_new = false;
      else if (new_rl != MVPP2_CLS_FLOW_RULE_MAX)
	merge_new = true;

      /* perform merge validation */

      /* max engine hits validation */
      if (RND_HIT_CNT (eng_hit_cnt, 0) ==
	  MVPP2_CLS_FL_RND_SIZE * MVPP2_CLS_FLOW_RND_MAX + RND_HIT_CNT (eng_hit_cnt, 1))
	{
	  pr_err ("max CLS entries, failed to add\n");
	  return -EPERM;
	}

      /* max allocated flow length validation */
      if (mrg_fl_rls->fl_len == lkp_dcod_db.flow_alloc_len)
	{
	  pr_err ("flow alloc length reached alloc_len=%d merge_fl_len=%d\n",
		  lkp_dcod_db.flow_alloc_len, mrg_fl_rls->fl_len);
	  return -EPERM;
	}

      /* perform single priority C4 validation */
      if (merge_new)
	rc = pp2_cls_rl_c4_validate (&new_fl_rls->fl[new_rl], mrg_fl_rls, &valid_c4);
      else
	rc = pp2_cls_rl_c4_validate (&cur_fl_rls->fl[cur_rl], mrg_fl_rls, &valid_c4);

      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  return rc;
	}

      if (!valid_c4)
	return -EPERM;

      /* validation done, update engine counters */
      if (merge_new)
	rc = pp2_cls_rl_hit_cnt_upd (&new_fl_rls->fl[new_rl], mrg_fl_rls, &eng_hit_cnt[rnd]);
      else
	rc = pp2_cls_rl_hit_cnt_upd (&cur_fl_rls->fl[cur_rl], mrg_fl_rls, &eng_hit_cnt[rnd]);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  return rc;
	}

      /* merge the new rule */
      if (merge_new)
	{
	  new_fl_rls->fl[new_rl].rl_off = rl_off;
	  rc = pp2_cls_new_fl_rl_merge (new_rl, new_fl_rls, mrg_fl_rls);
	  if (rc)
	    {
	      pr_err ("failed to merge new C4 rule offset=%d fl_log_id=%d\n", rl_off,
		      new_fl_rls->fl_log_id);
	      return rc;
	    }

	  /* update new rule count */
	  new_rl_cnt--;
	}
      else
	{
	  cur_fl_rls->fl[cur_rl].rl_off = rl_off;
	  rc = pp2_cls_new_fl_rl_merge (cur_rl, cur_fl_rls, mrg_fl_rls);

	  if (rc)
	    {
	      pr_err ("failed to merge cur C4 rule offset=%d fl_log_id=%d\n", rl_off,
		      cur_fl_rls->fl_log_id);
	      return rc;
	    }

	  /* update current rule count */
	  cur_rl_cnt--;
	}

      rl_off++;
      continue;

    c3_ins:
      /* get first C3 rule */

      /* no C3 rules, proceed with C2 */
      if (new_fl_rls->eng_cnt.c3 == 0 && cur_fl_rls->eng_cnt.c3 == 0)
	goto c2_ins;

      cur_rl = MVPP2_CLS_FLOW_RULE_MAX;
      new_rl = MVPP2_CLS_FLOW_RULE_MAX;

      /* get first C3 rule from cur and new flows  */
      if (new_fl_rls->eng_cnt.c3)
	{
	  for (rl = 0; rl < new_fl_rls->fl_len; rl++)
	    {
	      if (!new_fl_rls->fl[rl].skip && (new_fl_rls->fl[rl].engine == MVPP2_ENGINE_C3_A ||
					       new_fl_rls->fl[rl].engine == MVPP2_ENGINE_C3_B ||
					       new_fl_rls->fl[rl].engine == MVPP2_ENGINE_C3_HA ||
					       new_fl_rls->fl[rl].engine == MVPP2_ENGINE_C3_HB))
		{
		  break;
		}
	    }
	  if (rl == new_fl_rls->fl_len)
	    {
	      pr_err ("eng count inconsistent new_rl=%d fl_len=%d\n", rl, new_fl_rls->fl_len);
	      return -EINVAL;
	    }
	  /* found a new c3 rule, save index */
	  new_rl = rl;
	}

      /* get first C3 rule */
      if (cur_fl_rls->eng_cnt.c3)
	{
	  for (rl = 0; rl < cur_fl_rls->fl_len; rl++)
	    {
	      if (!cur_fl_rls->fl[rl].skip && (cur_fl_rls->fl[rl].engine == MVPP2_ENGINE_C3_A ||
					       cur_fl_rls->fl[rl].engine == MVPP2_ENGINE_C3_B ||
					       cur_fl_rls->fl[rl].engine == MVPP2_ENGINE_C3_HA ||
					       cur_fl_rls->fl[rl].engine == MVPP2_ENGINE_C3_HB))
		{
		  break;
		}
	    }
	  if (rl == cur_fl_rls->fl_len)
	    {
	      pr_err ("eng count inconsistent new_rl=%d fl_len=%d\n", rl, cur_fl_rls->fl_len);
	      return -EINVAL;
	    }
	  /* found a current c3 rule, save index */
	  cur_rl = rl;
	}

      /* no C3 rules, skip to C2 section */
      if (cur_rl == MVPP2_CLS_FLOW_RULE_MAX && new_rl == MVPP2_CLS_FLOW_RULE_MAX)
	goto c2_ins;

    c3_seq_ins:
      /* decide which rule to merge according to rule priority */
      if (cur_rl != MVPP2_CLS_FLOW_RULE_MAX && new_rl != MVPP2_CLS_FLOW_RULE_MAX)
	{
	  if (cur_fl_rls->fl[cur_rl].prio > new_fl_rls->fl[new_rl].prio)
	    merge_new = true;
	  else
	    merge_new = false;
#if SAME_PRIO_ENABLED
	  else if (cur_fl_rls->fl[cur_rl].prio < new_fl_rls->fl[new_rl].prio) merge_new = false;
	  else
	  {
	    pr_err ("add same prio rule prio=%d fl_log_id=%d rule #=%d\n",
		    cur_fl_rls->fl[cur_rl].prio, cur_fl_rls->fl[cur_rl].rl_log_id, cur_rl);
	    return -EINVAL;
	  }
#endif
	}
      else if (cur_rl != MVPP2_CLS_FLOW_RULE_MAX)
	{
	  merge_new = false;
	}
      else if (new_rl != MVPP2_CLS_FLOW_RULE_MAX)
	{
	  merge_new = true;
	}

      /* perform merge validation */

      /* round 0 full of C2 and there are some C2 to merge */
      if (rnd == 0 && MVPP2_CLS_C3_RND_MAX == eng_hit_cnt[0].c3)
	{
	  if (!is_seq && (new_fl_rls->eng_cnt.c2 || cur_fl_rls->eng_cnt.c2))
	    goto c2_ins;
	  rnd = 1;
	}
      else if (rnd == 1 && MVPP2_CLS_C3_RND_MAX == eng_hit_cnt[1].c3)
	{
	  pr_err ("max C3 entries (last round), failed to add\n");
	  return -EPERM;
	}

      /* max C3 hits validation */
      if (MVPP2_CLS_C3_RND_MAX * MVPP2_CLS_FLOW_RND_MAX < (eng_hit_cnt[0].c3 + eng_hit_cnt[1].c3))
	{
	  pr_err ("max C3 entries, failed to add\n");
	  return -EPERM;
	}

      /* max engine hits validation */
      if (MVPP2_CLS_FL_RND_SIZE * MVPP2_CLS_FLOW_RND_MAX <
	  (RND_HIT_CNT (eng_hit_cnt, 0) + RND_HIT_CNT (eng_hit_cnt, 1)))
	{
	  pr_err ("max CLS entries, failed to add\n");
	  return -EPERM;
	}

      /* max allocated flow length validation */
      if (mrg_fl_rls->fl_len == lkp_dcod_db.flow_alloc_len)
	{
	  pr_err ("flow alloc length reached alloc_len=%d merge_fl_len=%d\n",
		  lkp_dcod_db.flow_alloc_len, mrg_fl_rls->fl_len);
	  return -EPERM;
	}

      /* validation done, update engine counters */
      if (merge_new)
	{
	  rc = pp2_cls_rl_hit_cnt_upd (&new_fl_rls->fl[new_rl], mrg_fl_rls, &eng_hit_cnt[rnd]);
	  if (rc)
	    {
	      pr_err ("recvd ret_code(%d)\n", rc);
	      return rc;
	    }
	}
      else
	{
	  rc = pp2_cls_rl_hit_cnt_upd (&cur_fl_rls->fl[cur_rl], mrg_fl_rls, &eng_hit_cnt[rnd]);
	  if (rc)
	    {
	      pr_err ("recvd ret_code(%d)\n", rc);
	      return rc;
	    }
	}

      /* merge the new rule */
      if (merge_new)
	{
	  new_fl_rls->fl[new_rl].rl_off = rl_off;
	  rc = pp2_cls_new_fl_rl_merge (new_rl, new_fl_rls, mrg_fl_rls);

	  if (rc)
	    {
	      pr_err ("failed to merge new C3 rule offset=%d fl_log_id=%d\n", rl_off,
		      new_fl_rls->fl_log_id);
	      return rc;
	    }

	  /* update new rule count */
	  new_rl_cnt--;
	}
      else
	{
	  cur_fl_rls->fl[cur_rl].rl_off = rl_off;
	  rc = pp2_cls_new_fl_rl_merge (cur_rl, cur_fl_rls, mrg_fl_rls);

	  if (rc)
	    {
	      pr_err ("failed to merge cur C3 rule offset=%d fl_log_id=%d\n", rl_off,
		      cur_fl_rls->fl_log_id);
	      return rc;
	    }

	  /* update current rule count */
	  cur_rl_cnt--;
	}

      rl_off++;

      if (merge_new)
	{
	  if (!is_seq)
	    {
	      if (new_fl_rls->fl[new_rl].seq_ctrl != MVPP2_CLS_SEQ_CTRL_NORMAL)
		{
		  if (new_fl_rls->fl[new_rl].seq_ctrl != MVPP2_CLS_SEQ_CTRL_FIRST_TYPE_1)
		    {
		      pr_err ("seqence control rule not start from first type (new_rl %d)\n",
			      new_rl);
		      return -EINVAL;
		    }
		  is_seq = true;
		  cur_rl = MVPP2_CLS_FLOW_RULE_MAX;
		}
	    }
	  else
	    {
	      if (new_fl_rls->fl[new_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_LAST)
		is_seq = false;
	    }
	  if (is_seq)
	    {
	      new_rl++;
	      if (new_fl_rls->fl[new_rl].skip ||
		  new_fl_rls->fl[new_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_NORMAL ||
		  new_fl_rls->fl[new_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_FIRST_TYPE_1)
		{
		  pr_err ("seqence control rule is not continuous (new_rl %d)\n", new_rl);
		  return -EINVAL;
		}
	      if (new_fl_rls->fl[new_rl].engine == MVPP2_ENGINE_C3_A ||
		  new_fl_rls->fl[new_rl].engine == MVPP2_ENGINE_C3_B ||
		  new_fl_rls->fl[new_rl].engine == MVPP2_ENGINE_C3_HA ||
		  new_fl_rls->fl[new_rl].engine == MVPP2_ENGINE_C3_HB)
		{
		  goto c3_seq_ins;
		}
	      else if (new_fl_rls->fl[new_rl].engine == MVPP2_ENGINE_C2)
		{
		  goto c2_seq_ins;
		}
	      else
		{
		  pr_err ("seqence control not support c4 rule\n");
		  return -EINVAL;
		}
	    }
	}
      else
	{
	  if (!is_seq)
	    {
	      if (cur_fl_rls->fl[cur_rl].seq_ctrl != MVPP2_CLS_SEQ_CTRL_NORMAL)
		{
		  if (new_fl_rls->fl[new_rl].seq_ctrl != MVPP2_CLS_SEQ_CTRL_FIRST_TYPE_1)
		    {
		      pr_err ("seqence control rule not start from first type (new_rl %d)\n",
			      new_rl);
		      return -EINVAL;
		    }
		  is_seq = true;
		  new_rl = MVPP2_CLS_FLOW_RULE_MAX;
		}
	    }
	  else
	    {
	      if (cur_fl_rls->fl[cur_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_LAST)
		is_seq = false;
	    }
	  if (is_seq)
	    {
	      cur_rl++;
	      if (cur_fl_rls->fl[cur_rl].skip ||
		  cur_fl_rls->fl[cur_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_NORMAL ||
		  cur_fl_rls->fl[cur_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_FIRST_TYPE_1)
		{
		  pr_err ("seqence control rule is not continuous (cur_rl %d)\n", cur_rl);
		  return -EINVAL;
		}
	      if (cur_fl_rls->fl[cur_rl].engine == MVPP2_ENGINE_C3_A ||
		  cur_fl_rls->fl[cur_rl].engine == MVPP2_ENGINE_C3_B ||
		  cur_fl_rls->fl[cur_rl].engine == MVPP2_ENGINE_C3_HA ||
		  cur_fl_rls->fl[cur_rl].engine == MVPP2_ENGINE_C3_HB)
		{
		  goto c3_seq_ins;
		}
	      else if (cur_fl_rls->fl[cur_rl].engine == MVPP2_ENGINE_C2)
		{
		  goto c2_seq_ins;
		}
	      else
		{
		  pr_err ("seqence control not support c4 rule\n");
		  return -EINVAL;
		}
	    }
	}
      continue;

    c2_ins:
      /* no C2 in both flow list, skip */
      if (new_fl_rls->eng_cnt.c2 == 0 && cur_fl_rls->eng_cnt.c2 == 0)
	continue;

      cur_rl = MVPP2_CLS_FLOW_RULE_MAX;
      new_rl = MVPP2_CLS_FLOW_RULE_MAX;

      /* get first C2 rule from cur and new flows  */
      if (new_fl_rls->eng_cnt.c2)
	{
	  for (rl = 0; rl < new_fl_rls->fl_len; rl++)
	    {
	      if (!new_fl_rls->fl[rl].skip && new_fl_rls->fl[rl].engine == MVPP2_ENGINE_C2)
		{
		  break;
		}
	    }
	  if (rl == new_fl_rls->fl_len)
	    {
	      pr_err ("eng count inconsistent new_rl=%d fl_len=%d\n", rl, new_fl_rls->fl_len);
	      return -EINVAL;
	    }
	  /* found a new c2 rule, save index */
	  new_rl = rl;
	}

      /* get first C2 rule */
      if (cur_fl_rls->eng_cnt.c2)
	{
	  for (rl = 0; rl < cur_fl_rls->fl_len; rl++)
	    {
	      if (!cur_fl_rls->fl[rl].skip && (cur_fl_rls->fl[rl].engine == MVPP2_ENGINE_C2))
		{
		  break;
		}
	    }
	  if (rl == cur_fl_rls->fl_len)
	    {
	      pr_err ("eng count inconsistent new_rl=%d fl_len=%d\n", rl, cur_fl_rls->fl_len);
	      return -EINVAL;
	    }
	  /* found a current c2 rule, save index */
	  cur_rl = rl;
	}

      if (cur_rl == MVPP2_CLS_FLOW_RULE_MAX && new_rl == MVPP2_CLS_FLOW_RULE_MAX)
	continue;

    c2_seq_ins:

      /* decide which rule to merge according to rule priority */
      if (cur_rl != MVPP2_CLS_FLOW_RULE_MAX && new_rl != MVPP2_CLS_FLOW_RULE_MAX)
	{
	  if (cur_fl_rls->fl[cur_rl].prio > new_fl_rls->fl[new_rl].prio)
	    merge_new = true;
	  else
	    merge_new = false;
#if SAME_PRIO_ENABLED
	  else if (cur_fl_rls->fl[cur_rl].prio < new_fl_rls->fl[new_rl].prio) merge_new = false;
	  else
	  {
	    pr_err ("add same prio rule prio=%d fl_log_id=%d rule #=%d\n",
		    cur_fl_rls->fl[cur_rl].prio, cur_fl_rls->fl[cur_rl].rl_log_id, cur_rl);
	    return -EINVAL;
	  }
#endif
	}
      else if (cur_rl != MVPP2_CLS_FLOW_RULE_MAX)
	{
	  merge_new = false;
	}
      else if (new_rl != MVPP2_CLS_FLOW_RULE_MAX)
	{
	  merge_new = true;
	}

      /* perform merge validation */

      /* running out of C3 rules, but next highest priority C2 rule is part of N-tuple - update
       * round */
      if (merge_new)
	{
	  if (!is_seq && new_fl_rls->fl[new_rl].seq_ctrl != MVPP2_CLS_SEQ_CTRL_NORMAL)
	    {
	      rnd = 1;
	      continue;
	    }
	}
      else
	{
	  if (!is_seq && cur_fl_rls->fl[cur_rl].seq_ctrl != MVPP2_CLS_SEQ_CTRL_NORMAL)
	    {
	      rnd = 1;
	      continue;
	    }
	}

      /* update round number */
      if (rnd == 0 && MVPP2_CLS_C2_RND_MAX == eng_hit_cnt[0].c2)
	{
	  rnd = 1;
	}
      else if (rnd == 1 && MVPP2_CLS_C2_RND_MAX == eng_hit_cnt[1].c2)
	{
	  pr_err ("max C2 entries (last round), failed to add\n");
	  return -EPERM;
	}

      /* max C2 hits validation */
      if (MVPP2_CLS_C2_RND_MAX * MVPP2_CLS_FLOW_RND_MAX < (eng_hit_cnt[0].c2 + eng_hit_cnt[1].c2))
	{
	  pr_err ("max C2 entries, failed to add\n");
	  return -EPERM;
	}

      /* max engine hits validation */
      if (MVPP2_CLS_FL_RND_SIZE * MVPP2_CLS_FLOW_RND_MAX <
	  (RND_HIT_CNT (eng_hit_cnt, 0) + RND_HIT_CNT (eng_hit_cnt, 1)))
	{
	  pr_err ("max CLS entries, failed to add\n");
	  return -EPERM;
	}

      /* max allocated flow length validation */
      if (mrg_fl_rls->fl_len == lkp_dcod_db.flow_alloc_len)
	{
	  pr_err ("flow alloc length reached alloc_len=%d merge_fl_len=%d\n",
		  lkp_dcod_db.flow_alloc_len, mrg_fl_rls->fl_len);
	  return -EPERM;
	}

      /* validation done, update engine counters */
      if (merge_new)
	{
	  rc = pp2_cls_rl_hit_cnt_upd (&new_fl_rls->fl[new_rl], mrg_fl_rls, &eng_hit_cnt[rnd]);
	  if (rc)
	    {
	      pr_err ("recvd ret_code(%d)\n", rc);
	      return rc;
	    }
	}
      else
	{
	  rc = pp2_cls_rl_hit_cnt_upd (&cur_fl_rls->fl[cur_rl], mrg_fl_rls, &eng_hit_cnt[rnd]);
	  if (rc)
	    {
	      pr_err ("recvd ret_code(%d)\n", rc);
	      return rc;
	    }
	}

      /* merge the new rule */
      if (merge_new)
	{
	  new_fl_rls->fl[new_rl].rl_off = rl_off;
	  rc = pp2_cls_new_fl_rl_merge (new_rl, new_fl_rls, mrg_fl_rls);

	  if (rc)
	    {
	      pr_err ("failed to merge new C2 rule offset=%d fl_log_id=%d\n", rl_off,
		      new_fl_rls->fl_log_id);
	      return rc;
	    }

	  /* update new rule count */
	  new_rl_cnt--;
	}
      else
	{
	  cur_fl_rls->fl[cur_rl].rl_off = rl_off;
	  rc = pp2_cls_new_fl_rl_merge (cur_rl, cur_fl_rls, mrg_fl_rls);

	  if (rc)
	    {
	      pr_err ("failed to merge cur C2 rule offset=%d fl_log_id=%d\n", rl_off,
		      cur_fl_rls->fl_log_id);
	      return rc;
	    }

	  /* update current rule count */
	  cur_rl_cnt--;
	}
      rl_off++;

      if (merge_new)
	{
	  if (!is_seq)
	    {
	      if (new_fl_rls->fl[new_rl].seq_ctrl != MVPP2_CLS_SEQ_CTRL_NORMAL)
		{
		  if (new_fl_rls->fl[new_rl].seq_ctrl != MVPP2_CLS_SEQ_CTRL_FIRST_TYPE_1)
		    {
		      pr_err ("seqence control rule not start from first type (new_rl %d)\n",
			      new_rl);
		      return -EINVAL;
		    }
		  is_seq = true;
		  cur_rl = MVPP2_CLS_FLOW_RULE_MAX;
		}
	    }
	  else
	    {
	      if (new_fl_rls->fl[new_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_LAST)
		is_seq = false;
	    }
	  if (is_seq)
	    {
	      new_rl++;
	      if (new_fl_rls->fl[new_rl].skip ||
		  new_fl_rls->fl[new_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_NORMAL ||
		  new_fl_rls->fl[new_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_FIRST_TYPE_1)
		{
		  pr_err ("seqence control rule is not continuous (new_rl %d)\n", new_rl);
		  return -EINVAL;
		}
	      if (new_fl_rls->fl[new_rl].engine == MVPP2_ENGINE_C3_A ||
		  new_fl_rls->fl[new_rl].engine == MVPP2_ENGINE_C3_B ||
		  new_fl_rls->fl[new_rl].engine == MVPP2_ENGINE_C3_HA ||
		  new_fl_rls->fl[new_rl].engine == MVPP2_ENGINE_C3_HB)
		{
		  goto c3_seq_ins;
		}
	      else if (new_fl_rls->fl[new_rl].engine == MVPP2_ENGINE_C2)
		{
		  goto c2_seq_ins;
		}
	      else
		{
		  pr_err ("seqence control not support c4 rule\n");
		  return -EINVAL;
		}
	    }
	}
      else
	{
	  if (!is_seq)
	    {
	      if (cur_fl_rls->fl[cur_rl].seq_ctrl != MVPP2_CLS_SEQ_CTRL_NORMAL)
		{
		  if (new_fl_rls->fl[new_rl].seq_ctrl != MVPP2_CLS_SEQ_CTRL_FIRST_TYPE_1)
		    {
		      pr_err ("seqence control rule not start from first type (new_rl %d)\n",
			      new_rl);
		      return -EINVAL;
		    }
		  is_seq = true;
		  new_rl = MVPP2_CLS_FLOW_RULE_MAX;
		}
	    }
	  else
	    {
	      if (cur_fl_rls->fl[cur_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_LAST)
		is_seq = false;
	    }
	  if (is_seq)
	    {
	      cur_rl++;
	      if (cur_fl_rls->fl[cur_rl].skip ||
		  cur_fl_rls->fl[cur_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_NORMAL ||
		  cur_fl_rls->fl[cur_rl].seq_ctrl == MVPP2_CLS_SEQ_CTRL_FIRST_TYPE_1)
		{
		  pr_err ("seqence control rule is not continuous (cur_rl %d)\n", cur_rl);
		  return -EINVAL;
		}
	      if (cur_fl_rls->fl[cur_rl].engine == MVPP2_ENGINE_C3_A ||
		  cur_fl_rls->fl[cur_rl].engine == MVPP2_ENGINE_C3_B ||
		  cur_fl_rls->fl[cur_rl].engine == MVPP2_ENGINE_C3_HA ||
		  cur_fl_rls->fl[cur_rl].engine == MVPP2_ENGINE_C3_HB)
		{
		  goto c3_seq_ins;
		}
	      else if (cur_fl_rls->fl[cur_rl].engine == MVPP2_ENGINE_C2)
		{
		  goto c2_seq_ins;
		}
	      else
		{
		  pr_err ("seqence control not support c4 rule\n");
		  return -EINVAL;
		}
	    }
	}
    }

  return 0;
}

static int
pp2_cls_fl_rls_set (struct pp2_inst *inst, struct pp2_cls_fl_t *fl_rls)
{
  struct pp2_db_cls_lkp_dcod_t lkp_dcod_db;
  int rc;
  u32 free_db_cnt;
  u16 rl_idx;
  bool is_last;
  u16 new_rl_cnt = 0;
  struct pp2_cls_rl_entry_t *rl;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  if (!fl_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  /* get the lookup DB for this logical flow ID */
  rc = pp2_db_cls_lkp_dcod_get (inst, fl_rls->fl_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("failed to get lookup decode info for fl_log_id %d\n", fl_rls->fl_log_id);
      return rc;
    }

  /* count all new rules */
  for (rl_idx = 0; rl_idx < fl_rls->fl_len; rl_idx++)
    {
      rl = &fl_rls->fl[rl_idx];
      if (rl->rl_log_id == MVPP2_CLS_UNDF_FL_LOG_ID)
	new_rl_cnt++;
    }

  /* validate enough DB entries for new rules */
  if (new_rl_cnt)
    {
      rc = pp2_db_cls_rl_off_free_nr (inst, &free_db_cnt);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  return rc;
	}

      if (free_db_cnt < new_rl_cnt)
	{
	  pr_err ("not enough free rule DB[free_db_cnt=%d new_rl_cnt=%d]\n", free_db_cnt,
		  new_rl_cnt);
	  return -EPERM;
	}
    }

  /* set the flow rules */
  for (rl_idx = 0; rl_idx < fl_rls->fl_len; rl_idx++)
    {
      rl = &fl_rls->fl[rl_idx];
      is_last = (rl_idx == fl_rls->fl_len - 1) ? true : false;

      /* write rule to HW */
      rc = pp2_cls_fl_rl_hw_set (cpu_slot, rl, is_last);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  return rc;
	}
    }

  /* set the lookup decode table */
  rc = pp2_cls_lkp_dcod_hw_set (inst, fl_rls);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  /* update DB for rules and lookup decode */
  for (rl_idx = 0; rl_idx < fl_rls->fl_len; rl_idx++)
    {
      rl = &fl_rls->fl[rl_idx];

      /* write rule to DB */
      rc = pp2_cls_fl_rl_db_set (inst, rl, fl_rls->fl_log_id);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  return rc;
	}
    }

  /* update flow actual length */
  lkp_dcod_db.flow_len = fl_rls->fl_len;
  rc = pp2_db_cls_lkp_dcod_set (inst, fl_rls->fl_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("failed to set lookup decode info for fl_log_id %d\n", fl_rls->fl_log_id);
      return rc;
    }

  return 0;
}

static void
pp2_cls_fl_rls_sort (struct pp2_cls_rl_entry_t fls[], u16 fl_len)
{
  struct pp2_cls_rl_entry_t temp;
  int i, j;

  for (i = 0; i < fl_len; i++)
    {
      for (j = 0; j < fl_len - i - 1; j++)
	{
	  if (cmp_prio (&fls[j], &fls[j + 1]) == 1)
	    {
	      temp = fls[j];
	      fls[j] = fls[j + 1];
	      fls[j + 1] = temp;
	    }
	}
    }
}

static int
pp2_cls_lkp_dcod_enable (struct pp2_inst *inst, u16 fl_log_id)
{
  struct mv_pp2x_cls_lookup_entry fe;
  int rc;
  u16 luid, rl = 0;
  struct pp2_db_cls_lkp_dcod_t lkp_dcod_db;
  struct pp2_db_cls_fl_rule_list_t *fl_rl_db;
  u16 rl_off;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  /* get the lookup DB for this logical flow ID */
  rc = pp2_db_cls_lkp_dcod_get (inst, fl_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("failed to get lookup decode info for fl_log_id %d\n", fl_log_id);
      return rc;
    }

  if (lkp_dcod_db.enabled)
    {
      /* entry enabled for this log_flow id */
      pr_warn ("skipping enable of fl_log_id=%d, already enabled\n", fl_log_id);
      return 0;
    }

  if (!lkp_dcod_db.flow_len)
    {
      /* there are no flow rules */
      pr_warn ("skipping enable of fl_log_id=%d, no rules in flow\n", fl_log_id);
      return 0;
    }

  /* get the rule list for this logical flow ID */
  fl_rl_db = clib_mem_alloc_or_null (sizeof (*fl_rl_db));
  if (!fl_rl_db)
    return -ENOMEM;

  memset (fl_rl_db, 0, sizeof (struct pp2_db_cls_fl_rule_list_t));
  rc = pp2_db_cls_fl_rule_list_get (inst, lkp_dcod_db.flow_off, lkp_dcod_db.flow_len,
				    &fl_rl_db->flow[0]);
  if (rc)
    {
      pr_err ("failed to get flow rule list fl_log_id=%d flow_off=%d flow_len=%d\n", fl_log_id,
	      lkp_dcod_db.flow_off, lkp_dcod_db.flow_len);
      if (fl_rl_db)
	clib_mem_free (fl_rl_db);
      return rc;
    }

  fl_rl_db->flow_len = lkp_dcod_db.flow_len;

  /* iterate over all LUIDs */
  for (luid = 0; luid < lkp_dcod_db.luid_num; luid++)
    {
      /* Exclude MAC default LookupID by LSP */
      if (LUID_IS_LSP_RESERVED (lkp_dcod_db.luid_list[luid].luid))
	continue;

      /* found the rule, get it`s offset */
      rc = pp2_db_cls_rl_off_get (inst, &rl_off, fl_rl_db->flow[rl].rl_log_id);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}

      /* updated the HW */
      mv_pp2x_cls_sw_lkp_clear (&fe);

      rc = mv_pp2x_cls_sw_lkp_flow_set (&fe, rl_off);

      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}

      rc = mv_pp2x_cls_sw_lkp_rxq_set (&fe, lkp_dcod_db.cpu_q);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}

      rc = mv_pp2x_cls_sw_lkp_en_set (&fe, 1);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}

      fe.way = lkp_dcod_db.way;
      fe.lkpid = lkp_dcod_db.luid_list[luid].luid;
      rc = mv_pp2x_cls_hw_lkp_write (cpu_slot, &fe);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}

      pr_debug ("fl_log_id[%2d] luid_nr[%2d] rl_log_id[%3d] prio[%2d] rl_off[%3d] luid[%2d]\n",
		fl_log_id, luid, fl_rl_db->flow[rl].rl_log_id, fl_rl_db->flow[rl].prio, rl_off,
		lkp_dcod_db.luid_list[luid].luid);
    }

  /* update lkp_dcod DB */
  lkp_dcod_db.enabled = true;
  rc = pp2_db_cls_lkp_dcod_set (inst, fl_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      if (fl_rl_db)
	clib_mem_free (fl_rl_db);
      return rc;
    }

  if (fl_rl_db)
    clib_mem_free (fl_rl_db);
  return 0;
}

static int
pp2_cls_lkp_dcod_set (struct pp2_inst *inst, struct pp2_cls_lkp_dcod_entry_t *lkp_dcod_conf)
{
  struct pp2_db_cls_lkp_dcod_t lkp_dcod_db;
  struct pp2_db_cls_fl_ctrl_t fl_ctrl;
  int rc;

  if (!lkp_dcod_conf)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  if (lkp_dcod_conf->flow_log_id >= MVPP2_MNG_FLOW_ID_MAX)
    {
      pr_err ("Invalid input (flow_log_id = %d)\n", lkp_dcod_conf->flow_log_id);
      return -EINVAL;
    }

  if (lkp_dcod_conf->luid_num >= MVPP2_CLS_LOG_FLOW_LUID_MAX)
    {
      pr_err ("Invalid input (luid_num = %d)\n", lkp_dcod_conf->luid_num);
      return -EINVAL;
    }

  if (lkp_dcod_conf->flow_len <= 0)
    {
      pr_err ("Invalid input (flow_alloc_len = %d)\n", lkp_dcod_conf->flow_len);
      return -EINVAL;
    }

  /* get the DB entry for log flow ID */
  rc = pp2_db_cls_lkp_dcod_get (inst, lkp_dcod_conf->flow_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("failed to get lookup decode info for fl_log_id %d\n", lkp_dcod_conf->flow_log_id);
      return rc;
    }

  if (lkp_dcod_db.enabled)
    {
      pr_err ("log flowid %d already configured\n", lkp_dcod_conf->flow_log_id);
      return -EFAULT;
    }

  if (lkp_dcod_db.flow_alloc_len)
    {
      pr_err ("lkp for flow_log_id = %d already set\n", lkp_dcod_conf->flow_log_id);
      return 0;
    }

  rc = pp2_db_cls_fl_ctrl_get (inst, &fl_ctrl);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  /* check that we have enough free space for flow */
  if (fl_ctrl.f_end - fl_ctrl.f_start <= lkp_dcod_conf->flow_len)
    {
      pr_err ("not enough space for flow, request: %d, free:%d\n", lkp_dcod_conf->flow_len,
	      fl_ctrl.f_end - fl_ctrl.f_start);
      return -EPERM;
    }

  lkp_dcod_db.flow_off = fl_ctrl.f_start;
  lkp_dcod_db.flow_alloc_len = lkp_dcod_conf->flow_len;
  lkp_dcod_db.flow_len = 0;
  lkp_dcod_db.luid_num = lkp_dcod_conf->luid_num;
  memcpy (lkp_dcod_db.luid_list, lkp_dcod_conf->luid_list,
	  sizeof (struct pp2_cls_luid_conf_t) * lkp_dcod_conf->luid_num);
  lkp_dcod_db.way = 0; /* currently, always setting way to '0' */
  lkp_dcod_db.cpu_q = lkp_dcod_conf->cpu_q;
  lkp_dcod_db.enabled = false;

  rc = pp2_db_cls_lkp_dcod_set (inst, lkp_dcod_conf->flow_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  /* update the max flow length */
  if (lkp_dcod_conf->flow_len > fl_ctrl.fl_max_len)
    fl_ctrl.fl_max_len = lkp_dcod_conf->flow_len;

  /* update the control start index */
  fl_ctrl.f_start += lkp_dcod_conf->flow_len;

  rc = pp2_db_cls_fl_ctrl_set (inst, &fl_ctrl);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  return 0;
}

static int
pp2_cls_mng_add_default_flow (struct pp2_ppio *ppio)
{
  struct pp2_cls_tbl_params tbl_params;
  struct pp2_cls_tbl_rule rule;
  struct pp2_cls_tbl *tbl;
  struct pp2_cls_tbl *tbl_hash;
  struct pp2_port *port = GET_PPIO_PORT (ppio);

  /* add default flow for all lkpid */
  tbl_params.type = PP2_CLS_TBL_MASKABLE;
  tbl_params.max_num_rules = 1;
  tbl_params.key.key_size = 0;
  tbl_params.key.num_fields = 0;

  tbl_params.default_act.cos = clib_mem_alloc_or_null ((sizeof (*tbl_params.default_act.cos)));
  if (!tbl_params.default_act.cos)
    return -ENOMEM;

  tbl_params.default_act.type = PP2_CLS_TBL_ACT_DONE;
  tbl_params.default_act.cos->ppio = ppio;
  tbl_params.default_act.cos->tc = 0;
  tbl_params.default_act.plcr = NULL;

  pp2_cls_mng_tbl_init (&tbl_params, &tbl, MVPP2_CLS_LKP_MUSDK_VLAN_PRI);
  pp2_cls_mng_tbl_init (&tbl_params, &tbl, MVPP2_CLS_LKP_MUSDK_DSCP_PRI);
  pp2_cls_mng_tbl_init (&tbl_params, &tbl, MVPP2_CLS_LKP_MUSDK_LOG_PORT_DEF);

  /* add 2 tuple hash rule fo ipv4 */
  tbl_params.type = PP2_CLS_TBL_EXACT_MATCH;
  tbl_params.max_num_rules = 1;
  tbl_params.key.num_fields = 2;
  tbl_params.key.key_size = 8;
  tbl_params.key.proto_field[0].proto = MV_NET_PROTO_IP4;
  tbl_params.key.proto_field[0].field.eth = MV_NET_IP4_F_SA;
  tbl_params.key.proto_field[1].proto = MV_NET_PROTO_IP4;
  tbl_params.key.proto_field[1].field.eth = MV_NET_IP4_F_DA;
  pp2_cls_mng_tbl_init (&tbl_params, &tbl_hash, MVPP2_CLS_LKP_MUSDK_LOG_HASH);

  /* add 2 tuple hash rule fo ipv6 */
  tbl_params.type = PP2_CLS_TBL_EXACT_MATCH;
  tbl_params.max_num_rules = 1;
  tbl_params.key.num_fields = 2;
  tbl_params.key.key_size = 8;
  tbl_params.key.proto_field[0].proto = MV_NET_PROTO_IP6;
  tbl_params.key.proto_field[0].field.eth = MV_NET_IP6_F_SA;
  tbl_params.key.proto_field[1].proto = MV_NET_PROTO_IP6;
  tbl_params.key.proto_field[1].field.eth = MV_NET_IP6_F_DA;
  pp2_cls_mng_tbl_init (&tbl_params, &tbl_hash, MVPP2_CLS_LKP_MUSDK_LOG_HASH);

  /* add 5 tuple hash rule ipv4 */
  tbl_params.type = PP2_CLS_TBL_EXACT_MATCH;
  tbl_params.max_num_rules = 1;
  tbl_params.key.num_fields = PP2_CLS_TBL_MAX_NUM_FIELDS;
  tbl_params.key.key_size = 13;
  tbl_params.key.proto_field[0].proto = MV_NET_PROTO_IP4;
  tbl_params.key.proto_field[0].field.eth = MV_NET_IP4_F_SA;
  tbl_params.key.proto_field[1].proto = MV_NET_PROTO_IP4;
  tbl_params.key.proto_field[1].field.eth = MV_NET_IP4_F_DA;
  tbl_params.key.proto_field[2].proto = MV_NET_PROTO_L4;
  tbl_params.key.proto_field[2].field.eth = MV_NET_L4_F_SP;
  tbl_params.key.proto_field[3].proto = MV_NET_PROTO_L4;
  tbl_params.key.proto_field[3].field.eth = MV_NET_L4_F_DP;
  tbl_params.key.proto_field[4].proto = MV_NET_PROTO_IP4;
  tbl_params.key.proto_field[4].field.eth = MV_NET_IP4_F_PROTO;
  pp2_cls_mng_tbl_init (&tbl_params, &tbl_hash, MVPP2_CLS_LKP_MUSDK_LOG_HASH);

  /* add 5 tuple hash rule ipv6 */
  tbl_params.type = PP2_CLS_TBL_EXACT_MATCH;
  tbl_params.max_num_rules = 1;
  tbl_params.key.num_fields = PP2_CLS_TBL_MAX_NUM_FIELDS;
  tbl_params.key.key_size = 36;
  tbl_params.key.proto_field[0].proto = MV_NET_PROTO_IP6;
  tbl_params.key.proto_field[0].field.eth = MV_NET_IP6_F_SA;
  tbl_params.key.proto_field[1].proto = MV_NET_PROTO_IP6;
  tbl_params.key.proto_field[1].field.eth = MV_NET_IP6_F_DA;
  tbl_params.key.proto_field[2].proto = MV_NET_PROTO_L4;
  tbl_params.key.proto_field[2].field.eth = MV_NET_L4_F_SP;
  tbl_params.key.proto_field[3].proto = MV_NET_PROTO_L4;
  tbl_params.key.proto_field[3].field.eth = MV_NET_L4_F_DP;
  tbl_params.key.proto_field[4].proto = MV_NET_PROTO_IP6;
  tbl_params.key.proto_field[4].field.eth = MV_NET_IP6_F_NEXT_HDR;
  pp2_cls_mng_tbl_init (&tbl_params, &tbl_hash, MVPP2_CLS_LKP_MUSDK_LOG_HASH);

  /* add default c2 rule */
  rule.num_fields = 0;
  pp2_cls_mng_rule_add (tbl, &rule, &tbl_params.default_act, MVPP2_CLS_LKP_MUSDK_VLAN_PRI);
  pp2_cls_mng_rule_add (tbl, &rule, &tbl_params.default_act, MVPP2_CLS_LKP_MUSDK_DSCP_PRI);
  pp2_cls_mng_rule_add (tbl, &rule, &tbl_params.default_act, MVPP2_CLS_LKP_MUSDK_LOG_PORT_DEF);

  /* set rss mode */
  pp2_cls_rss_mode_flows_set (port, port->hash_type);

  if (tbl_params.default_act.cos)
    clib_mem_free (tbl_params.default_act.cos);
  return 0;
}

static int
pp2_cls_mng_set_coloring (struct pp2_ppio *ppio, int clear)
{
  struct pp2_port *port = GET_PPIO_PORT (ppio);
  int rc;

  rc = pp2_c2_set_default_coloring (port, clear);
  if (rc)
    {
      pr_err ("%s(%d) pp2_c2_set_default_coloring fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  return 0;
}

static int
pp2_cls_mng_set_policing (struct pp2_ppio *ppio, int clear)
{
  struct pp2_port *port = GET_PPIO_PORT (ppio);
  u32 ref_cnt;
  int rc;

  if (!port->default_plcr)
    return 0;

  if (!clear)
    {
      rc = pp2_cls_plcr_ref_cnt_get (pp2_ptr->pp2_inst[ppio->pp2_id], port->default_plcr->id, NULL,
				     &ref_cnt);
      if (rc || ref_cnt)
	{
	  pr_err ("[%s] policer already in use by other ppio\n", __func__);
	  return -EFAULT;
	}
    }

  rc = pp2_c2_set_default_policing (port, clear);
  if (rc)
    {
      pr_err ("%s(%d) pp2_cls_mng_set_policing fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  rc =
    pp2_cls_plcr_ref_cnt_update (pp2_ptr->pp2_inst[ppio->pp2_id], port->default_plcr->id,
				 (clear) ? MVPP2_PLCR_REF_CNT_DEC : MVPP2_PLCR_REF_CNT_INC, true);
  if (rc)
    {
      pr_err ("%s(%d) pp2_cls_plcr_ref_cnt_update fail\n", __func__, __LINE__);
      return -EFAULT;
    }

  return 0;
}

static int
pp2_db_cls_lkp_dcod_get (struct pp2_inst *inst, u32 fl_log_id,
			 struct pp2_db_cls_lkp_dcod_t *lkp_dcod)
{
  if (!lkp_dcod)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  if (fl_log_id >= MVPP2_MNG_FLOW_ID_MAX)
    {
      pr_err ("Invalid parameter\n");
      return -EINVAL;
    }
  memcpy (lkp_dcod, &inst->cls_db->cls_db.lkp_dcod[fl_log_id],
	  sizeof (struct pp2_db_cls_lkp_dcod_t));

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
pp2_prs_set_log_port (struct pp2_port *port, struct pp2_ppio_log_port_params *params)
{
  int rc, i, j;

  /* Check parameters validity*/
  if (mv_pp2x_ptr_validate (port))
    return -EINVAL;

  if (mv_pp2x_ptr_validate (params))
    return -EINVAL;

  /* Calculate required space in parser */
  rc = pp2_prs_space_check (port, params);
  if (rc)
    {
      pr_err ("Unable to configure parser logical port: not enough space\n");
      return -EFAULT;
    }

  /* TODO - remove limitation */
  if (params->proto_based_target.num_proto_rule_sets > 1)
    {
      pr_err ("only one rule set is supported\n");
      return -EFAULT;
    }

  /* Initialize logical port according to target:
   * PP2_CLS_TARGET_LOCAL_PPIO	-> default traffic going to kernel and logical port to MUSDK
   * PP2_CLS_TARGET_OTHER		-> default traffic going to MUSDK and logical port to kernel
   * By default parser is initialized with PP2_CLS_TARGET_LOCAL_PPIO, so only need to change
   * if target is PP2_CLS_TARGET_OTHER
   */
  if (params->proto_based_target.target == PP2_CLS_TARGET_OTHER)
    pp2_prs_create_log_port_entry (port, MVPP2_PE_MH_DEFAULT, PP2_CLS_TARGET_LOCAL_PPIO);

  /* Go over all requested protocols and protocol fields*/
  for (i = 0; i < params->proto_based_target.num_proto_rule_sets; i++)
    {
      for (j = 0; j < params->proto_based_target.rule_sets[i].num_rules; j++)
	{
	  struct pp2_ppio_log_port_rule_params *rule_params =
	    &params->proto_based_target.rule_sets[i].rules[j];

	  pr_debug ("%d:%d %d\n", i, j, rule_params->rule_type);
	  if (rule_params->rule_type == PP2_RULE_TYPE_PROTO)
	    {
	      /* Create a list of protocols according to imputs. This list will then be
	       * written to parser once completed
	       */
	      rc = pp2_prs_log_port_proto_set (port, rule_params->u.proto_params.proto,
					       rule_params->u.proto_params.val,
					       params->proto_based_target.target);
	      if (rc)
		return -EFAULT;
	    }
	  else if (rule_params->rule_type == PP2_RULE_TYPE_PROTO_FIELD)
	    {
	      /* Create a list of protocol fields according to imputs. This list will then be
	       * written to parser once completed
	       */
	      rc = pp2_prs_log_port_field_set (port, rule_params->u.proto_field_params.proto_field,
					       rule_params->u.proto_field_params.val,
					       params->proto_based_target.target);
	      if (rc)
		return -EFAULT;
	    }
	  else
	    {
	      pr_err ("Invalid rule_proto_field %d\n", rule_params->rule_type);
	      return -EFAULT;
	    }
	}
    }

  /* List of protocols and protool fields was build, now need to create the new entries in parser */
  pp2_prs_log_port_proto_update (port, params->proto_based_target.target);

  return 0;
}

static inline u16
pp2_rss_map_get (void)
{
  return pp2_ptr->pp2_common.rss_tbl_map;
}

static int
iomem_uio_io_exists (const char *name, int index)
{
  struct uio_info_t *uio_info;

  uio_info = iomem_find_uio_device (name, index);
  return (uio_info != NULL);
}

static enum musdk_lnx_id
lnx_id_get (void)
{
  int lk_ver;
  static enum musdk_lnx_id lnx_id = LNX_VER_INVALID;

  if (lnx_id != LNX_VER_INVALID)
    return lnx_id;

  lk_ver = mv_kernel_ver_get ();

  if ((MAJOR (lk_ver) == 4) && (MINOR (lk_ver) == 4))
    lnx_id = LNX_4_4_x;
  else if ((MAJOR (lk_ver) == 4) && (MINOR (lk_ver) == 14))
    lnx_id = LNX_4_14_x;
  else
    lnx_id = LNX_OTHER;

  return lnx_id;
}

static int
lnx_is_mainline (enum musdk_lnx_id lnx_id)
{
  return (lnx_id > LNX_4_4_x);
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
mv_pp2x_plcr_hw_base_rate_gen_enable (uintptr_t cpu_slot, int enable)
{
  u32 regVal;

  regVal = pp2_reg_read (cpu_slot, MVPP2_PLCR_BASE_PERIOD_REG);
  if (enable)
    regVal |= MVPP2_PLCR_ADD_TOKENS_EN_MASK;
  else
    regVal &= ~MVPP2_PLCR_ADD_TOKENS_EN_MASK;

  pp2_reg_write (cpu_slot, MVPP2_PLCR_BASE_PERIOD_REG, regVal);

  return MV_OK;
}

static int
mv_pp2x_plcr_hw_min_pkt_len (uintptr_t cpu_slot, int bytes)
{
  u32 regVal;

  regVal = pp2_reg_read (cpu_slot, MVPP2_PLCR_MIN_PKT_LEN_REG);
  regVal &= ~MVPP2_PLCR_MIN_PKT_LEN_ALL_MASK;
  regVal |= MVPP2_PLCR_MIN_PKT_LEN_MASK (bytes);
  pp2_reg_write (cpu_slot, MVPP2_PLCR_MIN_PKT_LEN_REG, regVal);

  return MV_OK;
}

static int
mv_pp2x_plcr_hw_mode (uintptr_t cpu_slot, int mode)
{
  pp2_reg_write (cpu_slot, MVPP2_PLCR_MODE_REG, mode);
  return MV_OK;
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
pp2_bm_pool_create (struct pp2 *pp2, struct bm_pool_param *param)
{
  struct pp2_inst *pp2_inst;
  uintptr_t cpu_slot;
  u32 bppe_num;
  u32 bppe_size;
  u32 bppe_region_size;
  struct pp2_bm_pool *bm_pool;
  u32 mem_id;

  /* FS_A8K Table 1558: Provided buffer numbers divisible by
   * PP2_BPPE_UNIT_SIZE in order to avoid incomplete BPPEs
   */
  if (param->buf_num % PP2_BPPE_UNIT_SIZE)
    {
      pr_err ("BM: pool buffer number param must be a multiple of %u\n", PP2_BPPE_UNIT_SIZE);
      return -EACCES;
    }
  /* FS_A8K Table 1713: Buffer 32-byte aligned and greater
   * than packet offset configured in RXSWQCFG register
   */
  if ((param->buf_size < PP2_BUFFER_OFFSET) || (param->buf_size % PP2_BUFFER_OFFSET_GRAN))
    {
      pr_err ("BM: pool buffer size must be %u-byte aligned and greater or equal %u-bytes\n",
	      PP2_BUFFER_OFFSET_GRAN, PP2_BUFFER_OFFSET);
      return -EACCES;
    }
  /* Allocate space for pool handler */
  bm_pool = mem_calloc (1, sizeof (struct pp2_bm_pool));
  if (unlikely (!bm_pool))
    {
      pr_err ("BM: cannot allocate memory for a BM pool\n");
      return -ENOMEM;
    }

  /* Offset pool hardware ID depending on configured pool offset */
  bm_pool->bm_pool_id = param->id;
  bm_pool->bm_pool_buf_sz = param->buf_size;

  /* Store packet processor parent ID */
  bm_pool->pp2_id = param->pp2_id;

  /* Number of buffers */
  bm_pool->bm_pool_buf_num = param->buf_num;

  /* FC shouldn't be configured for dummy pool */
  bm_pool->fc_not_supported = param->dummy_pool ? 1 : 0;

  /* FS_A8K Table 1558: A BPPE holds 8 x BPs (buffers), and for each
   * buffer, 2 x pointer sizes must be allocated. The BPPE region size
   * is computed by adding up all BPPEs.
   *
   * Always aligned to PP2_BPPE_UNIT_SIZE
   */
  bppe_num = bm_pool->bm_pool_buf_num;
  bppe_size = (2 * sizeof (uint64_t));
  bppe_region_size = (bppe_num * bppe_size);

  pr_debug ("BM: pool=%u buf_num %u bppe_num %u bppe_region_size %u\n", bm_pool->bm_pool_id,
	    bm_pool->bm_pool_buf_num, bppe_num, bppe_region_size);

  mem_id = pp2_get_mem_id (bm_pool->pp2_id);

  bm_pool->bppe_mem = mv_sys_dma_mem_region_get (mem_id);
  pr_debug ("(%s)Got pointer %p for mem_id(%d)\n", __func__, bm_pool->bppe_mem, mem_id);

  bm_pool->bm_pool_virt_base = (uintptr_t) mv_sys_dma_mem_region_alloc (
    bm_pool->bppe_mem, bppe_region_size, MVPP2_BM_POOL_PTR_ALIGN);
  if (unlikely (!bm_pool->bm_pool_virt_base))
    {
      pr_err ("BM: cannot allocate region for pool BPPEs\n");
      if (bm_pool)
	clib_mem_free (bm_pool);
      return -ENOMEM;
    }

  bm_pool->bm_pool_phys_base = (uintptr_t) mv_sys_dma_mem_region_virt2phys (
    bm_pool->bppe_mem, (void *) bm_pool->bm_pool_virt_base);

  if (!IS_ALIGNED (bm_pool->bm_pool_phys_base, MVPP2_BM_POOL_PTR_ALIGN))
    {
      pr_err ("BM: pool=%u is not %u bytes aligned", param->id, MVPP2_BM_POOL_PTR_ALIGN);
      mv_sys_dma_mem_region_free (bm_pool->bppe_mem, (void *) bm_pool->bm_pool_virt_base);
      if (bm_pool)
	clib_mem_free (bm_pool);
      return -EIO;
    }

  pr_debug ("BM: pp2_id=%u pool=%u BPPEs phys_base 0x%lX virt_base 0x%lX\n", bm_pool->pp2_id,
	    bm_pool->bm_pool_id, bm_pool->bm_pool_phys_base, bm_pool->bm_pool_virt_base);

  pp2_inst = pp2->pp2_inst[param->pp2_id];
  cpu_slot = pp2_inst->hw.base[PP2_DEFAULT_REGSPACE].va;

  /*TODO YUVAL: Add lock here, to protect simultaneous creation of bm_pools */
  if (pp2_bm_hw_pool_create (cpu_slot, bm_pool->bm_pool_id, bppe_num, bm_pool->bm_pool_phys_base))
    {
      pr_err ("BM: could not initialize hardware pool%u\n", bm_pool->bm_pool_id);
      mv_sys_dma_mem_region_free (bm_pool->bppe_mem, (void *) bm_pool->bm_pool_virt_base);
      if (bm_pool)
	clib_mem_free (bm_pool);
      return -EIO;
    }

  pp2_bm_pool_bufsize_set (cpu_slot, bm_pool->bm_pool_id, bm_pool->bm_pool_buf_sz);

#if PP2_BM_BUF_DEBUG
  pp2_bm_pool_print_regs (cpu_slot, bm_pool->bm_pool_id);
#endif
  pp2->pp2_inst[param->pp2_id]->bm_pools[bm_pool->bm_pool_id] = bm_pool;

  return 0;
}

static int
pp2_bm_pool_destroy (uintptr_t cpu_slot, struct pp2_bm_pool *bm_pool)
{
  u32 pool_id;
  u32 resid_bufs = 0;

  pool_id = bm_pool->bm_pool_id;

  pr_debug ("BM: destroying pool ID=%u\n", pool_id);

  /* If client did not clean up explicitly before
   * destroying this pool, then implictly clear up the
   * BM stack of virtual addresses by allocating
   * every available buffer from this pool
   */
  resid_bufs = pp2_bm_pool_flush (cpu_slot, pool_id);
  if (resid_bufs)
    {
      pr_debug ("BM: could not clear all buffers from pool ID=%u\n", pool_id);
      pr_debug ("BM: total bufs    : %u\n", bm_pool->bm_pool_buf_num);
      pr_debug ("BM: residual bufs : %u\n", resid_bufs);
    }

  pp2_bm_hw_pool_destroy (cpu_slot, pool_id);

  mv_sys_dma_mem_region_free (bm_pool->bppe_mem, (void *) bm_pool->bm_pool_virt_base);

  if (bm_pool)
    clib_mem_free (bm_pool);
  return 0;
}

static struct pp2_bm_pool *
pp2_bm_pool_get_pool_by_id (struct pp2_inst *pp2_inst, uint32_t pool_id)
{
  return pp2_inst->bm_pools[pool_id];
}

static void
pp2_bm_pool_reset_fc (uintptr_t base, struct pp2_bm_pool *pool)
{
  int cm3_state;
  u32 val;

  /* Remove Flow control enable bit to prevent race between FW and Kernel
   * If Flow control were enabled, it would be re-enabled.
   */
  val = cm3_read (base, MSS_CP_FC_COM_REG);
  cm3_state = (val & FLOW_CONTROL_ENABLE_BIT);
  val &= ~FLOW_CONTROL_ENABLE_BIT;
  cm3_write (base, MSS_CP_FC_COM_REG, val);

  cm3_write (base, MSS_CP_CM3_BUF_POOL_BASE + pool->bm_pool_id * MSS_CP_CM3_BUF_POOL_OFFS, 0);

  /* Notify Firmware that Flow control config space ready for update */
  val = cm3_read (base, MSS_CP_FC_COM_REG);
  val |= FLOW_CONTROL_UPD_COM_BIT;
  val |= cm3_state;
  cm3_write (base, MSS_CP_FC_COM_REG, val);
}

static inline void
pp2_bpool_put_buffs_core (int pp2_id, int num_buffs, int dm_if_index,
			  struct pp2_ppio_desc pp2_descs[])
{
  u16 sent_pkts = 0;
  struct pp2_port *lb_port;

  lb_port = pp2_ptr->pp2_inst[pp2_id]->ports[PP2_LOOPBACK_PORT];
  do
    {
      sent_pkts += pp2_port_enqueue (lb_port, lb_port->parent->dm_ifs[dm_if_index], 0,
				     (num_buffs - sent_pkts), &pp2_descs[sent_pkts], NULL);
    }
  while (sent_pkts != num_buffs);
}

static int
pp2_cls_add_lkpid_and_flows_to_db (struct pp2_inst *inst, struct pp2_cls_fl_rule_list_t *fl_rls)
{
  struct pp2_cls_lkp_dcod_entry_t *dcod_entry;
  struct mv_pp2x_cls_lookup_entry le;
  int lkp_index, rxq, en, flow_index, mod;
  int rc = 0;
  int way = 0; /* currently, always setting way to '0' */
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  dcod_entry = clib_mem_alloc_or_null (sizeof (*dcod_entry));
  if (!dcod_entry)
    return -ENOMEM;

  pr_debug ("\n");
  pr_debug ("ID :	RXQ	EN	FLOW	MODE_BASE\n");
  for (lkp_index = 0; lkp_index < MVPP2_CLS_LKP_TBL_SIZE; lkp_index++)
    {
      rc = mv_pp2x_cls_hw_lkp_read (cpu_slot, lkp_index, way, &le);
      if (rc)
	goto end;
      rc = mv_pp2x_cls_sw_lkp_rxq_get (&le, &rxq);
      if (rc)
	goto end;
      rc = mv_pp2x_cls_sw_lkp_en_get (&le, &en);
      if (rc)
	goto end;
      rc = mv_pp2x_cls_sw_lkp_flow_get (&le, &flow_index);
      if (rc)
	goto end;
      rc = mv_pp2x_cls_sw_lkp_mod_get (&le, &mod);
      if (rc)
	goto end;
      if (en)
	{
	  pr_debug (" 0x%2.2x\t 0x%2.2x\t %1.1d\t 0x%3.3x\t 0x%2.2x\n", le.lkpid, rxq, en,
		    flow_index, mod);
	  memset (dcod_entry, 0, sizeof (struct pp2_cls_lkp_dcod_entry_t));
	  dcod_entry->cpu_q = rxq;
	  dcod_entry->way = way;
	  dcod_entry->flow_len = MVPP2_CLS_DEF_FLOW_LEN;
	  dcod_entry->flow_log_id = le.lkpid;
	  dcod_entry->luid_num = 1;
	  dcod_entry->luid_list[0].luid = le.lkpid;

	  rc = pp2_cls_find_flows_per_lkp (cpu_slot, fl_rls, dcod_entry->flow_log_id, flow_index);
	  if (rc)
	    goto end;
	  pp2_cls_lkp_dcod_set (inst, dcod_entry);
	}
    }

end:
  if (dcod_entry)
    clib_mem_free (dcod_entry);
  return rc;
}

static u32
pp2_cls_c2_new_logic_idx_allocate (bool reset)
{
  /* Base logical index for C2 entry, every time a new index is allocated, perform
   * pp2_cls_c2_logic_base_idx++ */
  static u32 pp2_cls_c2_logic_base_idx = MVPP2_C2_LOGIC_IDX_BASE;

  pp2_cls_c2_logic_base_idx++;
  /* if c2_reset, restore pp2_cls_c2_logic_base_idx to original value */
  if (reset)
    pp2_cls_c2_logic_base_idx = MVPP2_C2_LOGIC_IDX_BASE;

  return pp2_cls_c2_logic_base_idx;
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
pp2_cls_db_c2_init (struct pp2_inst *inst)
{
  int i;

  /* Clear C2 db */
  memset (&inst->cls_db->c2_db, 0, sizeof (struct pp2_cls_db_c2_t));

  /* Init c2_hw_idx to C2 corresponding c2 hw index in c2 data db and index db */
  for (i = 0; i < MVPP2_C2_ENTRY_MAX - MVPP2_C2_FIRST_ENTRY; i++)
    {
      inst->cls_db->c2_db.c2_data_db[i].valid = MVPP2_C2_ENTRY_INVALID;
      inst->cls_db->c2_db.c2_index_db[i].valid = MVPP2_C2_ENTRY_INVALID;
      inst->cls_db->c2_db.c2_index_db[i].c2_hw_idx = i + MVPP2_C2_FIRST_ENTRY;
    }

  /* Init C2 list head */
  INIT_LIST (&inst->cls_db->c2_db.c2_free_head_db);
  for (i = 0; i < MVPP2_C2_LKP_TYPE_MAX; i++)
    INIT_LIST (&inst->cls_db->c2_db.c2_lu_type_head_db[i]);

  /* Init free list, last entry is used for default entry, always not available */
  for (i = MVPP2_C2_LAST_ENTRY - MVPP2_C2_FIRST_ENTRY - 1; i >= 0; i--)
    {
      list_add (&inst->cls_db->c2_db.c2_index_db[i].list_node,
		&inst->cls_db->c2_db.c2_free_head_db);
      /* Change index node valid status after adding to free list */
      inst->cls_db->c2_db.c2_index_db[i].valid = MVPP2_C2_ENTRY_VALID;
    }
  /* Reserve the last one for default miss entry */
  inst->cls_db->c2_db.c2_index_db[MVPP2_C2_LAST_ENTRY - MVPP2_C2_FIRST_ENTRY].valid =
    MVPP2_C2_ENTRY_VALID;
  inst->cls_db->c2_db.c2_data_db[MVPP2_C2_LAST_ENTRY - MVPP2_C2_FIRST_ENTRY].valid =
    MVPP2_C2_ENTRY_VALID;

  return 0;
}

static int
pp2_cls_db_c3_init (struct pp2_inst *inst)
{
  int idx;

  if (!inst->cls_db)
    return -EINVAL;

  /* Clear C3 db */
  memset (&inst->cls_db->c3_db, 0, sizeof (struct pp2_cls_db_c3_t));

  /* Init C3 multihash index table and logical index table */
  for (idx = 0; idx < MVPP2_CLS_C3_HASH_TBL_SIZE; idx++)
    {
      inst->cls_db->c3_db.hash_idx_tbl[idx].valid = MVPP2_C3_ENTRY_INVALID;
      inst->cls_db->c3_db.logic_idx_tbl[idx].valid = MVPP2_C3_ENTRY_INVALID;
    }

  return 0;
}

static int
pp2_cls_db_c3_search_depth_set (struct pp2_inst *inst, u32 search_depth)
{
  inst->cls_db->c3_db.max_search_depth = search_depth;
  return 0;
}

static int
pp2_cls_db_plcr_gen_cfg_set (struct pp2_inst *inst, struct pp2_cls_plcr_gen_cfg_t *gen_cfg)
{
  if (mv_pp2x_ptr_validate (gen_cfg))
    return -EINVAL;

  memcpy (&inst->cls_db->plcr_db.gen_cfg, gen_cfg, sizeof (struct pp2_cls_plcr_gen_cfg_t));
  return 0;
}

static int
pp2_cls_fl_rule_add (struct pp2_inst *inst, struct pp2_cls_fl_rule_list_t *fl_rls)
{
  struct pp2_cls_fl_t *new_fl;
  struct pp2_cls_fl_t *merge_fl;
  struct pp2_cls_fl_t *cur_fl;
  struct pp2_cls_fl_rule_entry_t *fl_rl;
  struct pp2_cls_rl_entry_t *fl;
  struct pp2_db_cls_lkp_dcod_t lkp_dcod_db;
  int rc;
  u16 i, j, fl_log_id;
  bool rule_found;

  if (!fl_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  new_fl = clib_mem_alloc_or_null (sizeof (*new_fl));
  if (!new_fl)
    return -ENOMEM;

  merge_fl = clib_mem_alloc_or_null (sizeof (*merge_fl));
  if (!merge_fl)
    {
      rc = -ENOMEM;
      goto err1;
    }

  cur_fl = clib_mem_alloc_or_null (sizeof (*cur_fl));
  if (!cur_fl)
    {
      rc = -ENOMEM;
      goto err2;
    }

  /* populate all current flows from DB for flow_log_id */
  for (fl_log_id = 0; fl_log_id < MVPP2_MNG_FLOW_ID_MAX; fl_log_id++)
    {
      memset (cur_fl, 0, sizeof (struct pp2_cls_fl_t));

      /* get current flow_log_id rules */
      rc = pp2_cls_fl_cur_get (inst, fl_log_id, cur_fl);
      if (rc != 0)
	{
	  pr_err ("pp2_db_cls_lkp_dcod_get returned error\n");
	  rc = -EFAULT;
	  goto err3;
	}

      memset (new_fl, 0, sizeof (struct pp2_cls_fl_t));

      new_fl->fl_log_id = fl_log_id;
      new_fl->fl_len = 0;

      /* inset all new flow rules to logical flow based table */
      for (i = 0; i < fl_rls->fl_len; i++)
	{
	  rule_found = false;
	  fl_rl = &fl_rls->fl[i];

	  /* handle only the current logical flow ID */
	  if (fl_log_id != fl_rl->fl_log_id)
	    continue;

	  /* get the lookup DB for this logical flow ID */
	  rc = pp2_db_cls_lkp_dcod_get (inst, fl_log_id, &lkp_dcod_db);
	  if (rc)
	    {
	      pr_err ("failed to get lookup decode info for fl_log_id %d\n", fl_log_id);
	      goto err3;
	    }

	  /* logical flow not initialized */
	  if (lkp_dcod_db.flow_alloc_len == 0)
	    {
	      pr_err ("fl_log_id %d new rule #%d was not initialized\n", fl_log_id, i);
	      rc = -EFAULT;
	      goto err3;
	    }

	  fl = &new_fl->fl[new_fl->fl_len];

	  if (!fl_rl->enabled)
	    {
	      fl_rl->port_type = MVPP2_PORT_TYPE_INV;
	      fl_rl->port_bm = MVPP2_PORT_BM_INV;
	    }

	  /* copy the data to new entry */
	  fl->enabled = fl_rl->enabled;
	  fl->engine = fl_rl->engine;
	  fl->field_id_cnt = fl_rl->field_id_cnt;
	  fl->lu_type = fl_rl->lu_type;
	  fl->port_bm = fl_rl->port_bm;
	  fl->port_type = fl_rl->port_type;
	  fl->prio = fl_rl->prio;
	  fl->udf7 = fl_rl->udf7;
	  MVPP2_MEMSET_ZERO (fl->ref_cnt);
	  fl->rl_log_id = MVPP2_CLS_UNDF_FL_LOG_ID;
	  fl->rl_off = lkp_dcod_db.flow_off + i;
	  fl->skip = 0;
	  fl->seq_ctrl = fl_rl->seq_ctrl;
	  fl->state = MVPP2_MRG_NEW;
	  memcpy (fl->field_id, fl_rl->field_id, sizeof (fl_rl->field_id));
	  /*
	   * code snippet is disabled since currently rules addition does
	   * not include valid port_type and port_bm and there is no
	   * way to differentiate two rules with same priority
	   */

	  /* search for the rule within the current flow rules */
	  for (j = 0; j < cur_fl->fl_len; j++)
	    {
	      if (cur_fl->fl[j].engine == fl_rl->engine &&
		  cur_fl->fl[j].field_id_cnt == fl_rl->field_id_cnt &&
		  cur_fl->fl[j].lu_type == fl_rl->lu_type && cur_fl->fl[j].prio == fl_rl->prio &&
		  cur_fl->fl[j].udf7 == fl_rl->udf7 &&
		  !memcmp (cur_fl->fl[j].field_id, fl_rl->field_id, sizeof (fl_rl->field_id)))
		{
		  /* identical rule found */
		  rule_found = true;

		  /* update the logical rule id */
		  fl_rl->rl_log_id = cur_fl->fl[j].rl_log_id;

		  cur_fl->fl[j].state = MVPP2_MRG_NEW_EXISTS;

		  if (cur_fl->fl[j].enabled == 1)
		    break;

		  /* enable the found rule if it's disabled */
		  fl_rl->enabled = 1;
		  cur_fl->fl[j].enabled = 1;
		  cur_fl->fl[j].port_type = fl_rl->port_type;
		  cur_fl->fl[j].port_bm = fl_rl->port_bm;

		  rc = pp2_cls_fl_rl_hw_ena (inst, fl_rl);
		  if (rc)
		    {
		      pr_err ("pp2_cls_fl_rl_hw_ena ret_code(%d)\n", rc);
		      goto err3;
		    }

		  rc = pp2_cls_fl_rl_db_set (inst, &cur_fl->fl[j], cur_fl->fl_log_id);
		  if (rc)
		    {
		      pr_err ("pp2_cls_fl_rl_db_set ret_code(%d)\n", rc);
		      goto err3;
		    }
		  break;
		}
	    }

	  /* rule already exist in the current flow */
	  if (rule_found)
	    continue;
	  /* increment the engine count per flow log id */
	  rc = pp2_cls_fl_rl_eng_cnt_upd (MVPP2_CNT_INC, fl_rl->engine, &new_fl->eng_cnt);
	  if (rc)
	    {
	      pr_err ("recvd ret_code(%d)\n", rc);
	      goto err3;
	    }

	  new_fl->fl_len++;
	}

      /* did we find new rules for the logical flow ID? */
      if (new_fl->fl_len == 0)
	continue;

      /* merge the current and new flow rules together */

      /* sort the new flow according to prio */
      if (new_fl->fl_len > 1)
	pp2_cls_fl_rls_sort (new_fl->fl, new_fl->fl_len);

      /* merge the two flows (new & curr) */
      rc = pp2_cls_fl_rls_merge (inst, fl_log_id, cur_fl, new_fl, merge_fl);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  goto err3;
	}

      /* reorder the n-tuple flows by priority */
      rc = pp2_cls_fl_nt_rule_reorder (merge_fl);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  goto err3;
	}

      /* set the rules in DB and HW */
      rc = pp2_cls_fl_rls_set (inst, merge_fl);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  goto err3;
	}

      /* update logical rule ID in caller structure */
      rc = pp2_cls_fl_rls_log_rl_id_upd (fl_rls, merge_fl);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  goto err3;
	}
    }

  if (cur_fl)
    clib_mem_free (cur_fl);
  if (merge_fl)
    clib_mem_free (merge_fl);
  if (new_fl)
    clib_mem_free (new_fl);
  return 0;
err3:
  if (cur_fl)
    clib_mem_free (cur_fl);
err2:
  if (merge_fl)
    clib_mem_free (merge_fl);
err1:
  if (new_fl)
    clib_mem_free (new_fl);
  return rc;
}

static int
pp2_cls_lkp_dcod_enable_all (struct pp2_inst *inst)
{
  struct pp2_db_cls_lkp_dcod_t lkp_dcod_db;
  int fl_log_id;
  int rc;

  for (fl_log_id = 0; fl_log_id < MVPP2_MNG_FLOW_ID_MAX; fl_log_id++)
    {
      /* get the lookup DB for this logical flow ID */
      rc = pp2_db_cls_lkp_dcod_get (inst, fl_log_id, &lkp_dcod_db);
      if (rc)
	pr_err ("failed to get lookup decode info for fl_log_id %d\n", fl_log_id);

      if ((!lkp_dcod_db.enabled) && (lkp_dcod_db.flow_alloc_len > 0))
	{
	  rc = pp2_cls_lkp_dcod_enable (inst, fl_log_id);
	  if (rc)
	    pr_err ("fail fl_log_id %d\n", fl_log_id);
	}
    }

  return 0;
}

static int
pp2_cls_mng_eth_start_header_params_set (struct pp2_ppio *ppio,
					 enum pp2_ppio_eth_start_hdr eth_start_hdr)
{
  struct pp2_port *port = GET_PPIO_PORT (ppio);
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
pp2_cls_mng_modify_default_flows (struct pp2_ppio *ppio, int clear)
{
  int rc;

  rc = pp2_cls_mng_set_coloring (ppio, clear);
  if (rc)
    {
      pr_err ("%s(%d) pp2_cls_mng_set_coloring fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  rc = pp2_cls_mng_set_policing (ppio, clear);
  if (rc)
    {
      pr_err ("%s(%d) pp2_cls_mng_set_policing fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  return 0;
}

static int
pp2_cls_mng_set_logical_port_params (struct pp2_ppio *ppio, struct pp2_ppio_params *params)
{
  struct pp2_port *port = GET_PPIO_PORT (ppio);
  int rc;

  rc = pp2_cls_mng_add_default_flow (ppio);
  if (rc)
    {
      pr_err ("%s(%d) pp2_cls_mng_add_default_flow_for_log fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  rc = pp2_prs_set_log_port (port, &params->specific_type_params.log_port_params);
  if (rc)
    {
      pr_err ("%s(%d) pp2_prs_set_log_port fail\n", __func__, __LINE__);
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

  /* Initialize parser for logical port support */
  rc = mv_pp2x_prs_log_port_init (inst);
  if (rc)
    return -EINVAL;

  /* MUSDK local parser flow id attribute tbl init (used in classifier)
   * TODO  this table needs to be synchronized with kernel
   * TODO  this table will be dynamic once struct pp2_parse_params is implemented
   */
  mv_pp2x_prs_flow_id_attr_init ();

  return 0;
}

static int
pp2_cls_rss_init (struct pp2_inst *inst)
{
  int rc, i;
  u16 rss_k_map;
  u16 rss_k_tbls = 0;

  rc = pp2_cls_db_rss_init (inst);
  if (rc)
    return rc;

  rss_k_map = pp2_rss_map_get ();
  /* Check RSS tables can fit number of TC's configured */
  for (i = 0; i < MVPP22_RSS_TBL_NUM; i++)
    rss_k_tbls += (rss_k_map >> i) & 0x1;

  if (rss_k_tbls >= MVPP22_RSS_TBL_NUM)
    {
      pr_err ("Kernel is using all RSS tables\n");
      return -EFAULT;
    }

  pp2_cls_db_rss_kernel_rsvd_tbl_set (inst, rss_k_tbls);

  return 0;
}

static void
pp2_db_cls_init (struct pp2_inst *inst)
{
  int i;

  /* set the CLS control to default values */
  memset (&inst->cls_db->cls_db, 0, sizeof (inst->cls_db->cls_db));

  /* f_start = 1 for kernel alignment */
  inst->cls_db->cls_db.fl_ctrl.f_start = 1;
  inst->cls_db->cls_db.fl_ctrl.f_end = MVPP2_FLOW_TBL_SIZE - 1;

  for (i = MVPP2_CLS_LOG2OFF_START; i < MVPP2_CLS_LOG2OFF_TBL_SIZE; i++)
    inst->cls_db->cls_db.log2off[i] = MVPP2_CLS_FREE_FL_LOG;

  inst->cls_db->cls_db.log2off[MVPP2_CLS_FREE_LOG2OFF] = MVPP2_CLS_LOG2OFF_START;
}

static void
pp2_dm_if_deinit (struct pp2 *pp2, uint32_t dm_id, uint32_t pp2_id)
{
  struct pp2_dm_if *dm_if;
  struct pp2_inst *inst;

  inst = pp2->pp2_inst[pp2_id];
  dm_if = inst->dm_ifs[dm_id];

  if (!dm_if)
    return;

  /* Reset the aggregation queue under this DM object */
  pp2_dm_aggr_queue_config (dm_if, 0, 0);
  dm_lock_destroy (dm_if);

  pr_debug ("DM: (AQ%u)(PP%u) destroyed\n", dm_if->id, inst->id);
  mv_sys_dma_mem_region_free (dm_if->mem, dm_if->desc_virt_arr);
  if (dm_if)
    clib_mem_free (dm_if);
  inst->num_dm_ifs--;
  inst->dm_ifs[dm_id] = NULL;
}

static inline struct pp2_dm_if *
pp2_dm_if_get (struct pp2_ppio *ppio, struct pp2_hif *hif)
{
  return GET_PPIO_PORT (ppio)->parent->dm_ifs[hif->regspace_slot];
}

static int
pp2_dm_if_init (struct pp2 *pp2, uint32_t dm_id, uint32_t pp2_id, uint32_t num_desc,
		struct mv_sys_dma_mem_region *mem)
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
  dm_if->mem = mem;

  /* Allocate a region via CMA for TXDs and setup their addresses */
  dm_if->desc_virt_arr =
    mv_sys_dma_mem_region_alloc (mem, (num_desc * MVPP2_DESC_ALIGNED_SIZE), MVPP2_DESC_Q_ALIGN);
  if (unlikely (!dm_if->desc_virt_arr))
    {
      pr_err ("DM: cannot allocate DM region\n");
      if (dm_if)
	clib_mem_free (dm_if);
      return -ENOMEM;
    }
  dm_if->desc_phys_arr = (uintptr_t) mv_sys_dma_mem_region_virt2phys (mem, dm_if->desc_virt_arr);
  if (!IS_ALIGNED (dm_if->desc_phys_arr, MVPP2_DESC_Q_ALIGN))
    {
      pr_err ("DM: Descriptor array must be %u-byte aligned\n", MVPP2_DESC_Q_ALIGN);
      mv_sys_dma_mem_region_free (mem, dm_if->desc_virt_arr);
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

  /* Create dm_lock for aggregation_queue locking */
  dm_lock_create (dm_if);
  pr_debug ("DM:(AQ%u)(PP%u) created\n", dm_id, pp2_id);

  return 0;
}

static inline u32
pp2_get_mem_id (u32 pp2_id)
{
  /* TODO: Temporary code to for testing, mechanism required to find this pp2's mem_id.
   *       Currently assume two mem_ids, and set mem_id=1, if pp2_id is in second half of
   * pp2_instances.
   */
  if ((pp2_get_num_inst () > 1) && (pp2_id >= (pp2_get_num_inst () >> 1)))
    return 1;

  return 0;
}

static u16
pp2_get_used_bm_pool_map (void)
{
  u32 bm_pool_map;

  /* TODO : Replace with pp2_reg_read that will read actual bm_map,
   *        after supported in kernel is added
   */
  bm_pool_map = PP2_BPOOLS_RSRV_MASK;

  pr_info ("%s: bm_pool_map(0x%x)\n", __func__, bm_pool_map);
  return bm_pool_map;
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

static uint16_t
pp2_port_enqueue (struct pp2_port *port, struct pp2_dm_if *dm_if, uint8_t out_qid,
		  uint16_t num_txds, struct pp2_ppio_desc desc[], struct pp2_ppio_sg_pkts *pkts)
{
  uintptr_t cpu_slot;
  struct pp2_tx_queue *txq;
  struct pp2_txq_dm_if *txq_dm_if;
  struct pp2_desc *tx_desc;
  u16 block_size, to_send = num_txds;
  int i;

  txq = port->txqs[out_qid];
  cpu_slot = dm_if->cpu_slot;

  if (unlikely (txq->disabled))
    goto error;

#ifdef DEBUG
  if ((port->flags & PP2_PORT_FLAGS_L4_CHKSUM) == 0)
    {
      for (i = 0; i < num_txds; i++)
	{
	  if (DM_TXD_GET_GEN_L4_CHK ((desc + i)) == TXD_L4_CHK_ENABLE)
	    {
	      pr_err ("[%s] port(%d) l4_checksum flag disabled.\n", __func__, port->id);
	      goto error;
	    }
	}
    }
#endif
  dm_spin_lock (&dm_if->dm_lock);
  if (unlikely (dm_if->free_count < num_txds))
    {
      u32 occ_desc;
      /* Update AGGR_Q status, just once */
      occ_desc = pp2_relaxed_reg_read (dm_if->cpu_slot, MVPP2_AGGR_TXQ_STATUS_REG (dm_if->id)) &
		 MVPP2_AGGR_TXQ_PENDING_MASK;
      dm_if->free_count = dm_if->desc_total - occ_desc;

      if (unlikely (dm_if->free_count < num_txds))
	{
	  pr_debug ("%s num_txds(%d), free_count(%d) occ_desc(%d)\n", __func__, num_txds,
		    dm_if->free_count, occ_desc);
	  num_txds = dm_if->free_count;
	}
    }
  txq_dm_if = &txq->txq_dm_if[dm_if->id];
  if (unlikely (txq_dm_if->desc_rsrvd < num_txds))
    {
      u32 req_val, result_val, res_req;

      res_req =
	max ((uint32_t) (num_txds - txq_dm_if->desc_rsrvd), (uint32_t) MVPP2_CPU_DESC_CHUNK);

      req_val = ((txq->id << MVPP2_TXQ_RSVD_REQ_Q_OFFSET) | res_req);
      pp2_relaxed_reg_write (cpu_slot, MVPP2_TXQ_RSVD_REQ_REG, req_val);
      mb ();
      result_val =
	pp2_relaxed_reg_read (cpu_slot, MVPP2_TXQ_RSVD_RSLT_REG) & MVPP2_TXQ_RSVD_RSLT_MASK;

      txq_dm_if->desc_rsrvd += result_val;

      if (unlikely (txq_dm_if->desc_rsrvd < num_txds))
	{
	  pr_debug ("%s prev_desc_rsrvd(%d) desc_rsrvd(%d) res_request(%d) num_txds(%d)\n",
		    __func__, (txq_dm_if->desc_rsrvd - result_val), txq_dm_if->desc_rsrvd, res_req,
		    num_txds);
	  num_txds = txq_dm_if->desc_rsrvd;
	}
    }

  if (pkts && to_send > num_txds)
    {
      u16 curr_txds = 0;

      for (i = 0; i < pkts->num; i++)
	{
	  if (curr_txds + pkts->frags[i] > num_txds)
	    break;
	  curr_txds += pkts->frags[i];
	}

      pr_debug ("[%s:%s] Sending %u descs(%u <- %u) and %u packets (%u)\n", __func__,
		port->linux_name, curr_txds, num_txds, to_send, i, pkts->num);

      num_txds = curr_txds;
      pkts->num = i;
    }

  if (!num_txds)
    {
      pr_debug ("[%s] num_txds is zero\n", __func__);
      dm_spin_unlock (&dm_if->dm_lock);
      goto error;
    }

  tx_desc = pp2_dm_if_next_desc_block_get (dm_if, num_txds, &block_size);

  for (i = 0; i < block_size; i++)
    {
      /* Destination physical queue ID */
      DM_TXD_SET_DEST_QID (&desc[i], txq->id);
#if __BYTE_ORDER == __BIG_ENDIAN
      pp2_port_tx_desc_swap_ncopy (&tx_desc[i], &desc[i]);
#else
      __builtin_memcpy (&tx_desc[i], &desc[i], sizeof (*tx_desc));
#endif
    }

  if (block_size < num_txds)
    {
      u16 index = block_size;
      u16 txds_remaining = num_txds - block_size;

      tx_desc = pp2_dm_if_next_desc_block_get (dm_if, txds_remaining, &block_size);
      if (unlikely ((index + block_size) != num_txds))
	{
	  if (likely (num_txds > txq->desc_total))
	    {
	      pr_debug ("[%s] More tx_descs(%u) than txq_len(%u)\n", __func__, num_txds,
			txq->desc_total);
	    }
	  else
	    {
	      pr_debug ("[%s] failed copying tx_descs(%u),in block#1(%u),block#2(%u) txq_len(%u)\n",
			__func__, num_txds, i, block_size, txq->desc_total);
	    }
	  num_txds = index + block_size;
	}

      for (i = 0; i < block_size; i++)
	{
	  /* Destination physical queue ID */
	  DM_TXD_SET_DEST_QID (&desc[index + i], txq->id);
#if __BYTE_ORDER == __BIG_ENDIAN
	  pp2_port_tx_desc_swap_ncopy (&tx_desc[i], &desc[index + i]);
#else
	  __builtin_memcpy (&tx_desc[i], &desc[index + i], sizeof (*tx_desc));
#endif
	}
    }

  /* Trigger TX */
  pp2_reg_write (cpu_slot, MVPP2_AGGR_TXQ_UPDATE_REG, num_txds);

  /* Sync reserve count with the AGGR_Q and the Physical TXQ */
  dm_if->free_count -= num_txds;
  txq_dm_if->desc_rsrvd -= num_txds;

  dm_spin_unlock (&dm_if->dm_lock);
  return num_txds;

error:
  if (pkts)
    pkts->num = 0;
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
pp2_port_get_statistics (struct pp2_port *port, struct pp2_ppio_statistics *stats)
{
  struct ifreq ifr;
  struct ethtool_stats *estats;
  u32 i;
  int rc;
  enum musdk_lnx_id lnx_id = lnx_id_get ();

  if (!port->stats_name)
    return -1;

  estats =
    mem_calloc (1, port->stats_name->len * sizeof (uint64_t) + sizeof (struct ethtool_stats));
  if (!estats)
    {
      pr_err ("PORT: alloc failed\n");
      return -1;
    }

  strcpy (ifr.ifr_name, port->linux_name);

  estats->cmd = ETHTOOL_GSTATS;
  estats->n_stats = port->stats_name->len;
  ifr.ifr_data = estats;
  rc = mv_netdev_ioctl (SIOCETHTOOL, &ifr);
  if (rc)
    {
      pr_err ("PORT: unable to get statistics\n");
      clib_mem_free (estats);
      return rc;
    }

  for (i = 0; i < port->stats_name->len; i++)
    {
      char *cnt = (char *) &port->stats_name->data[i * ETH_GSTRING_LEN];
      uint64_t val = estats->data[i];

      if (lnx_is_mainline (lnx_id))
	{
	  if (!strcmp (cnt, "good_octets_received"))
	    stats->rx_bytes = val;
	  else if (!strcmp (cnt, "unicast_frames_received"))
	    {
	      stats->rx_unicast_packets = val;
	      stats->rx_packets += val;
	    }
	  else if (!strcmp (cnt, "broadcast_frames_received"))
	    stats->rx_packets += val;
	  else if (!strcmp (cnt, "multicast_frames_received"))
	    stats->rx_packets += val;
	  else if (!strcmp (cnt, "rx_fifo_overrun"))
	    stats->rx_errors += val;
	  else if (!strcmp (cnt, "undersize_received"))
	    stats->rx_errors += val;
	  else if (!strcmp (cnt, "fragments_err_received"))
	    stats->rx_errors += val;
	  else if (!strcmp (cnt, "oversize_received"))
	    stats->rx_errors += val;
	  else if (!strcmp (cnt, "jabber_received"))
	    stats->rx_errors += val;
	  else if (!strcmp (cnt, "mac_receive_error"))
	    stats->rx_errors += val;
	  else if (!strcmp (cnt, "bad_crc_event"))
	    stats->rx_errors += val;
	  else if (!strcmp (cnt, "rx_ppv2_overrun"))
	    stats->rx_fifo_dropped = val;
	  else if (!strcmp (cnt, "rx_cls_drop"))
	    stats->rx_cls_dropped = val;
	  else if (!strcmp (cnt, "good_octets_sent"))
	    stats->tx_bytes = val;
	  else if (!strcmp (cnt, "unicast_frames_sent"))
	    {
	      stats->tx_unicast_packets = val;
	      stats->tx_packets += val;
	    }
	  else if (!strcmp (cnt, "multicast_frames_sent"))
	    stats->tx_packets += val;
	  else if (!strcmp (cnt, "broadcast_frames_sent"))
	    stats->tx_packets += val;
	  else if (!strcmp (cnt, "collision"))
	    stats->tx_errors += val;
	  else if (!strcmp (cnt, "late_collision"))
	    stats->tx_errors += val;
	  else if (!strcmp (cnt, "crc_errors_sent"))
	    stats->tx_errors += val;
	}
      else
	{
	  if (!strcmp (cnt, "rx_bytes"))
	    stats->rx_bytes = val;
	  else if (!strcmp (cnt, "rx_frames"))
	    stats->rx_packets = val;
	  else if (!strcmp (cnt, "rx_unicast"))
	    stats->rx_unicast_packets = val;
	  else if (!strcmp (cnt, "rx_ppv2_overrun"))
	    stats->rx_fifo_dropped = val;
	  else if (!strcmp (cnt, "rx_cls_drop"))
	    stats->rx_cls_dropped = val;
	  else if (!strcmp (cnt, "rx_total_err"))
	    stats->rx_errors = val;
	  else if (!strcmp (cnt, "tx_bytes"))
	    stats->tx_bytes = val;
	  else if (!strcmp (cnt, "tx_frames"))
	    stats->tx_packets = val;
	  else if (!strcmp (cnt, "tx_unicast"))
	    stats->tx_unicast_packets = val;
	  else if (!strcmp (cnt, "collision"))
	    stats->tx_errors += val;
	  else if (!strcmp (cnt, "late_collision"))
	    stats->tx_errors += val;
	  else if (!strcmp (cnt, "tx_crc_sent"))
	    stats->tx_errors += val;
	}
    }

  clib_mem_free (estats);

  return 0;
}

static int
pp2_port_initialize_statistics (struct pp2_port *port)
{
  struct
  {
    struct ethtool_sset_info hdr;
    uint32_t buf[1];
  } sset_info;
  uint32_t len = 0;
  struct ifreq ifr;
  int rc;

  strcpy (ifr.ifr_name, port->linux_name);

  sset_info.hdr.cmd = ETHTOOL_GSSET_INFO;
  sset_info.hdr.reserved = 0;
  sset_info.hdr.sset_mask = 1ULL << ETH_SS_STATS;
  ifr.ifr_data = &sset_info;
  rc = mv_netdev_ioctl (SIOCETHTOOL, &ifr);
  if (rc)
    {
      pr_err ("PORT: unable to get stringset length\n");
      return -1;
    }
  if (sset_info.hdr.sset_mask)
    memcpy (&len, sset_info.hdr.data, sizeof (uint32_t));

  if (!len)
    {
      pr_err ("PORT: stringset length is zero\n");
      return -1;
    }

  port->stats_name = mem_calloc (1, sizeof (struct ethtool_gstrings) + len * ETH_GSTRING_LEN);
  if (!port->stats_name)
    {
      pr_err ("PORT: alloc failed\n");
      return -1;
    }

  port->stats_name->cmd = ETHTOOL_GSTRINGS;
  port->stats_name->string_set = ETH_SS_STATS;
  port->stats_name->len = len;
  ifr.ifr_data = port->stats_name;
  rc = mv_netdev_ioctl (SIOCETHTOOL, &ifr);
  if (rc)
    {
      clib_mem_free (port->stats_name);
      port->stats_name = NULL;
      pr_err ("PORT: unable to get stringset\n");
      return -1;
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
pp2_port_open_uio (struct pp2_port *port)
{
  char *tmp_name;
  char dev_name[16];
  struct uio_info_t *uio_info;
  int fd;
  int max_uio_port_str_size = sizeof (UIO_PORT_STRING) + 8;

  tmp_name = clib_mem_alloc_or_null (max_uio_port_str_size);
  snprintf (tmp_name, max_uio_port_str_size, UIO_PORT_STRING, port->parent->id, port->id);
  uio_info = uio_find_devices_byname (tmp_name);
  if (!uio_info)
    {
      pr_err ("UIO device (%s) not found!\n", tmp_name);
      if (tmp_name)
	clib_mem_free (tmp_name);
      return -ENODEV;
    }
  if (tmp_name)
    clib_mem_free (tmp_name);
  snprintf (dev_name, sizeof (dev_name), "/dev/uio%d", uio_info->uio_num);
  fd = open (dev_name, O_RDWR);
  if (fd < 0)
    {
      pr_err ("Could not open file (%s)\n", dev_name);
      return errno;
    }
  port->uio_port.fd = fd;
  return 0;
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
  pr_debug ("pp2_port_set_enable : port->id %d, port->linux_name: %s, enable(%d)\n", port->id,
	    port->linux_name, en);
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
pp2_ppio_flush_vlan (struct pp2_ppio *ppio)
{
  int rc;

  rc = pp2_port_clear_all_vlans (GET_PPIO_PORT (ppio));
  return rc;
}

static inline void
pp2_ppio_outq_desc_set_cookie (struct pp2_ppio_desc *desc, u64 cookie)
{
  desc->cmds[6] = (u32) cookie;
  desc->cmds[7] = (desc->cmds[7] & ~TXD_BUF_VIRT_HI_MASK) | (cookie >> 32 & TXD_BUF_VIRT_HI_MASK);
}

static void
pp2_ppio_outq_desc_set_pool (struct pp2_ppio_desc *desc, struct pp2_bpool *pool)
{
  desc->cmds[0] = (desc->cmds[0] & ~(TXD_POOL_ID_MASK | TXD_BUFMODE_MASK)) |
		  (pool->id << 16 & TXD_POOL_ID_MASK) | (1 << 7 & TXD_BUFMODE_MASK);
}

static int
pp2_ppio_set_loopback (struct pp2_ppio *ppio, int en)
{
  int rc;

  rc = pp2_port_set_loopback (GET_PPIO_PORT (ppio), en);
  return rc;
}

static int
pp2_prs_check_udf_params (struct pp2_parse_udfs *parse_udfs)
{
  int i;
  int proto;

  if (parse_udfs->num_udfs > PP2_MAX_UDFS_SUPPORTED)
    {
      pr_err ("%s: invalid num of UDFs %d\n", __func__, parse_udfs->num_udfs);
      return -EINVAL;
    }

  for (i = 0; i < parse_udfs->num_udfs; i++)
    {
      proto = parse_udfs->udfs[i].match_proto;
      if (!((proto == MV_NET_PROTO_ETH) || (proto == MV_NET_PROTO_ETH_DSA) ||
	    (proto == MV_NET_PROTO_VLAN) || (proto == MV_NET_PROTO_IP4) ||
	    (proto == MV_NET_PROTO_IP6) || (proto == MV_NET_PROTO_UDP) ||
	    (proto == MV_NET_PROTO_TCP)))
	{
	  pr_err ("%s: not supported protocol %d\n", __func__, proto);
	  return -ENOTSUP;
	}

      if (!parse_udfs->udfs[i].match_key)
	{
	  pr_err ("%s: UDF[%d] key is NULL\n", __func__, i);
	  return -EINVAL;
	}

      if (!parse_udfs->udfs[i].match_mask)
	{
	  pr_err ("%s: UDF[%d] mask is NULL\n", __func__, i);
	  return -EINVAL;
	}
    }

  return 0;
}

static int
pp2_prs_create_udf_entry (struct pp2_inst *inst, struct pp2_parse_udf_params *udf_params,
			  int user_uid)
{
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);
  struct mv_pp2x_prs_entry pe;
  int tid, tid2;
  int idx;
  int len;

  memset (&pe, 0, sizeof (struct mv_pp2x_prs_entry));

  /* Find first empty slot in TCAM */
  tid = pp2_prs_tcam_first_free (inst, MVPP2_PE_FIRST_FREE_TID, MVPP2_PE_LAST_FREE_TID);
  if (tid < 0)
    {
      pr_err ("%s(%d): failed to find empty Parser entry\n", __func__, __LINE__);
      return tid;
    }

  pe.index = tid;

  switch (udf_params->match_proto)
    {
    case MV_NET_PROTO_ETH:
      if (udf_params->match_field.eth == MV_NET_ETH_F_TYPE)
	{
	  mv_pp2x_prs_tcam_lu_set (&pe, MVPP2_PRS_LU_L2);
	  /* Mask all ports */
	  mv_pp2x_prs_tcam_port_map_set (&pe, 0xFF);

	  len = MV_ETH_ETYPE_LEN;
	  while (len--)
	    mv_pp2x_prs_tcam_data_byte_set (&pe, len, udf_params->match_key[len],
					    udf_params->match_mask[len]);

	  /* turn on the mask for UDF_AI bit */
	  mv_pp2x_prs_tcam_ai_update (&pe, 0, MVPP2_PRS_L2_UDF_AI_BIT);

	  /* allocate available UDF id */
	  idx = pp2_prs_udf_map_allocate (user_uid);
	  if (idx < 0)
	    {
	      pr_err ("%s: failed to allocate UDF number\n", __func__);
	      return -EINVAL;
	    }
	  /* store the entry index */
	  prs_udf_map[idx].tid = tid;

	  /* set UDF for CLS and UDF offset */
	  mv_pp2x_prs_sram_offset_set (&pe, prs_udf_map[idx].prs_udf_id, udf_params->offset,
				       MVPP2_PRS_SRAM_OP_SEL_UDF_ADD);

	  /* HW doesn't support udf offset generation in the same iteration when SRAM_LU_GEN_BIT set
	   */
	  /* create two L2_FLOW entries: 1st one - UDF offset generation, 2nd - continue to LU_FLOWS
	   */
	  mv_pp2x_prs_sram_ai_update (&pe, MVPP2_PRS_L2_UDF_AI_BIT, MVPP2_PRS_SRAM_AI_MASK);

	  /* set UDF Result Info, required by CLS in order to identify UDF offset*/
	  if (prs_udf_map[idx].prs_udf_id == MVPP2_PRS_SRAM_UDF_TYPE_3)
	    mv_pp2x_prs_sram_ri_update (&pe, MVPP2_PRS_RI_UDF3_MASK, MVPP2_PRS_RI_UDF3_MASK);
	  else if (prs_udf_map[idx].prs_udf_id == MVPP2_PRS_SRAM_UDF_TYPE_5)
	    mv_pp2x_prs_sram_ri_update (&pe, MVPP2_PRS_RI_UDF5_MASK, MVPP2_PRS_RI_UDF5_MASK);
	  else if (prs_udf_map[idx].prs_udf_id == MVPP2_PRS_SRAM_UDF_TYPE_6)
	    mv_pp2x_prs_sram_ri_update (&pe, MVPP2_PRS_RI_UDF6_MASK, MVPP2_PRS_RI_UDF6_MASK);

	  /* the second entry has the same type LU_L2 */
	  mv_pp2x_prs_sram_next_lu_set (&pe, MVPP2_PRS_LU_L2);

	  /* Update shadow table and hw entry for new entry*/
	  mv_pp2x_prs_shadow_set (inst, pe.index, mv_pp2x_prs_tcam_lu_get (&pe));
	  mv_pp2x_prs_hw_write (cpu_slot, &pe);

	  /* start building the second entry */
	  /* Find empty slot in TCAM */
	  tid2 = pp2_prs_tcam_first_free (inst, MVPP2_PE_FIRST_FREE_TID, MVPP2_PE_LAST_FREE_TID);
	  if (tid2 < 0)
	    {
	      mv_pp2x_prs_hw_inv (cpu_slot, tid);
	      pr_err ("%s(%d): failed to find empty Parser entry\n", __func__, __LINE__);
	      return tid;
	    }

	  pe.index = tid2;
	  /* use the same TCAM key, only update AI */
	  mv_pp2x_prs_tcam_ai_update (&pe, MVPP2_PRS_L2_UDF_AI_BIT, MVPP2_PRS_L2_UDF_AI_BIT);
	  /* store the second entry index */
	  prs_udf_map[idx].tid2 = tid2;

	  mv_pp2x_prs_sram_clear (&pe);
	  mv_pp2x_prs_sram_next_lu_set (&pe, MVPP2_PRS_LU_FLOWS);
	  mv_pp2x_prs_sram_bit_set (&pe, MVPP2_PRS_SRAM_LU_GEN_BIT, 1);

	  /* Update shadow table and hw entry for new entry*/
	  mv_pp2x_prs_shadow_set (inst, pe.index, mv_pp2x_prs_tcam_lu_get (&pe));
	  mv_pp2x_prs_hw_write (cpu_slot, &pe);
	}
      else
	{
	  pr_err ("%s: PROTO_ETH - not supported field\n", __func__);
	  return -ENOTSUP;
	}
      break;
    default:
      pr_err ("%s: not supported protocol\n", __func__);
      return -ENOTSUP;
    }

  return 0;
}

static inline uint32_t
pp2_relaxed_reg_read (uintptr_t cpu_slot, uint32_t offset)
{
  uintptr_t addr = cpu_slot + offset;

  return readl_relaxed ((void *) addr);
}

static inline void
pp2_relaxed_reg_write (uintptr_t cpu_slot, uint32_t offset, uint32_t data)
{
  uintptr_t addr = cpu_slot + offset;

  writel_relaxed (data, (void *) addr);
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

  if (iomem->type == SYS_IOMEM_T_UIO)
    iomem_uio_iodestroy (&iomem->u.uio);
  else if (iomem->type == SYS_IOMEM_T_MMAP)
    iomem_mmap_iodestroy (&iomem->u.mmap);
  else if (iomem->type == SYS_IOMEM_T_SHMEM)
    iomem_shmem_iodestroy (&iomem->u.uio);
  else
    {
      pr_warn ("IOtype not supported yet!\n");
      return;
    }
  clib_mem_free (iomem->name);
  clib_mem_free (iomem);
}

static int
sys_iomem_map (struct sys_iomem *iomem, const char *name, phys_addr_t *pa, void **va)
{
  if (iomem->type == SYS_IOMEM_T_MMAP)
    return iomem_mmap_iomap (&iomem->u.mmap, name, pa, va);
  if (iomem->type == SYS_IOMEM_T_UIO)
    return iomem_uio_iomap (&iomem->u.uio, name, pa, va);
  if (iomem->type == SYS_IOMEM_T_SHMEM)
    return iomem_shmem_iomap (&iomem->u.shmem, name, pa, va);
  pr_err ("IOtype not supported yet!\n");
  return -ENOTSUP;
}

static int
sys_iomem_unmap (struct sys_iomem *iomem, const char *name)
{
  if (iomem->type == SYS_IOMEM_T_MMAP)
    return iomem_mmap_iounmap (&iomem->u.mmap, name);
  if (iomem->type == SYS_IOMEM_T_UIO)
    return iomem_uio_iounmap (&iomem->u.uio, name);
  if (iomem->type == SYS_IOMEM_T_SHMEM)
    return iomem_shmem_iounmap (&iomem->u.shmem, name);
  pr_err ("IOtype not supported yet!\n");
  return -ENOTSUP;
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
  enum musdk_lnx_id lnx_id = lnx_id_get ();

  if (!port)
    return;

  inst = port->parent;
  pp2_port_deinit (port);
  inst->num_ports--;

  /* Close uio_device file, returns ownership to Linux */
  if (NOT_LPBK_PORT (port) && port->type == PP2_PPIO_T_NIC)
    {
      if (lnx_is_mainline (lnx_id))
	pp2_port_set_priv_flags (port, 0);
      else
	pp2_port_close_uio (port);
    }
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
  port->port_mtu = MV_DEFAULT_MTU;

  /* Get tx_fifo_size from hw_register, value was configured by Linux */
  port->tx_fifo_size = pp2_port_get_tx_fifo (port);

  err = pp2_port_check_mtu_valid (port, port->port_mtu);
  if (unlikely (err))
    {
      pr_err ("%s MTU error\n", __func__);
      return;
    }

  /* Provide an initial MRU */
  port->port_mru = MV_MTU_TO_MRU (port->port_mtu);

  /* TODO: Below fn_call is incorrect.
   * Should mask Interrupts:
   *  - For MUSDK_NIC ports for all cpu_slots, including kernel
   *  - For other ports, only for MUSDK cpu_slots (hif_map)
   */
#if 0
	pp2_port_interrupts_mask(port);
#endif

  port->maintain_stats = 0;
  memset (&port->stats, 0, sizeof (port->stats));

  /* Initialize RSS */
  pp2_cls_mng_rss_port_init (port, pp2_rss_map_get ());

  /* Set initial cos value */
  pp2_cls_mng_config_default_cos_queue (port);
}

static void
pp2_port_inq_update (struct pp2_port *port, uint32_t in_qid, u32 used_count, uint32_t free_count)
{
  /* Decrement the number of used descriptors and increment the
   * number of free descriptors
   */
  u32 id = port->rxqs[in_qid]->id;
  u32 val = used_count | (free_count << MVPP2_RXQ_NUM_NEW_OFFSET);
  uintptr_t cpu_slot = port->cpu_slot;

  /* pp2_rxq_update_next_desc_idx(port->rxqs[in_qid], used_count); */

  pp2_reg_write (cpu_slot, MVPP2_RXQ_STATUS_UPDATE_REG (id), val);
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

  pr_debug ("start_dev: tx_port_num %d, traffic mode %s%s\n", MVPP2_MAX_TCONT + port->id,
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

static struct pp2_desc *
pp2_rxq_get_desc (struct pp2_rx_queue *rxq, u32 *num_recv, struct pp2_desc **extra_desc,
		  uint32_t *extra_num)
{
  u32 rx_idx;

  rx_idx = rxq->desc_next_idx;
  *extra_num = 0;
  *extra_desc = NULL;

  /*
   * It looks that the continues memory allocated for rx desc
   * is treated by the HW as an circular queue.
   * When the rx desc index is very close to the end of the rx desc array
   * the next descriptors are be stored to the end of the array AND
   * from the beginning of the rx desc array. In this case the return from
   * this function will be 2 arrays of desc:
   * 1 - at the end of the array
   * 2 - starting from the beginning(extra)
   */

  if (unlikely ((rx_idx + *num_recv) > rxq->desc_total))
    {
      *extra_desc = rxq->desc_virt_arr;
      /* extra_num is relative to start of desc array */
      *extra_num = rx_idx + *num_recv - rxq->desc_total;
      /* num_recv is relative to end of desc array */
      *num_recv = rxq->desc_total - rx_idx;
      rxq->desc_next_idx = *extra_num;
    }
  else
    {
      rxq->desc_next_idx = (((rx_idx + *num_recv) == rxq->desc_total) ? 0 : (rx_idx + *num_recv));
    }

  /*
   *	pr_debug("%s\tdesc array: cur_idx=%d\tlast_idx=%d\n",__func__, rx_idx, rxq->desc_last_idx);
   *	pr_debug("%s\tdesc array: num_recv=%d\textra_num=%d\n",__func__,*num_recv, *extra_num);
   */

  return (rxq->desc_virt_arr + rx_idx);
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
mv_pp2x_plcr_hw_base_period_set (uintptr_t cpu_slot, int period)
{
  u32 regVal;

  regVal = pp2_reg_read (cpu_slot, MVPP2_PLCR_BASE_PERIOD_REG);
  regVal &= ~MVPP2_PLCR_BASE_PERIOD_ALL_MASK;
  regVal |= MVPP2_PLCR_BASE_PERIOD_MASK (period);
  pp2_reg_write (cpu_slot, MVPP2_PLCR_BASE_PERIOD_REG, regVal);

  return MV_OK;
}
static int
mv_pp2x_plcr_hw_cpu_thresh_set (uintptr_t cpu_slot, int idx, int threshold)
{
  pp2_reg_write (cpu_slot, MVPP2_PLCR_EDROP_CPU_TR_REG (idx), threshold);

  return MV_OK;
}

static int
mv_pp2x_plcr_hw_enable (uintptr_t cpu_slot, int plcr, int enable)
{
  u32 regVal;

  pp2_reg_write (cpu_slot, MVPP2_PLCR_TABLE_INDEX_REG, plcr);

  regVal = pp2_reg_read (cpu_slot, MVPP2_PLCR_TOKEN_CFG_REG);
  if (enable)
    regVal |= MVPP2_PLCR_ENABLE_MASK;
  else
    regVal &= ~MVPP2_PLCR_ENABLE_MASK;

  pp2_reg_write (cpu_slot, MVPP2_PLCR_TOKEN_CFG_REG, regVal);

  return MV_OK;
}
static int
mv_pp2x_plcr_hw_early_drop_set (uintptr_t cpu_slot, int enable)
{
  u32 regVal;

  regVal = pp2_reg_read (cpu_slot, MVPP2_PLCR_EDROP_EN_REG);
  if (enable)
    regVal |= MVPP2_PLCR_EDROP_EN_MASK;
  else
    regVal &= ~MVPP2_PLCR_EDROP_EN_MASK;

  pp2_reg_write (cpu_slot, MVPP2_PLCR_EDROP_EN_REG, regVal);

  return MV_OK;
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
pp2_cls_db_plcr_init (struct pp2_inst *inst)
{
  u32 idx = 0;

  /* clear policer DB */
  memset (&inst->cls_db->plcr_db, 0, sizeof (struct pp2_cls_db_plcr_t));

  /* set policer entry to invalid state */
  for (idx = 0; idx < MVPP2_PLCR_MAX; idx++)
    inst->cls_db->plcr_db.plcr_arr[idx].valid = MVPP2_PLCR_ENTRY_INVALID_STATE;

  return 0;
}
static int
pp2_cls_db_edrop_init (struct pp2_inst *inst)
{
  u32 idx = 0;

  /* clear early-drop DB */
  memset (&inst->cls_db->edrop_db, 0, sizeof (struct pp2_cls_db_edrop_t));

  /* set early-drop entry to invalid state */
  for (idx = 0; idx < MVPP2_EDROP_MAX; idx++)
    inst->cls_db->edrop_db.edrop_arr[idx].valid = MVPP2_EDROP_ENTRY_INVALID_STATE;

  return 0;
}
static int
pp2_cls_edrop_hw_entry_del (struct pp2_inst *inst, u8 edrop_id)
{
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);
  int rc = 0;

  if (mv_pp2x_range_validate (edrop_id, 0, MVPP2_EDROP_MAX - 1))
    {
      pr_err ("invalid early-drop ID %d, out of range[%d, %d]\n", edrop_id, 0, MVPP2_EDROP_MAX - 1);
      return -EINVAL;
    }

  /* disable this early-drop */
  rc = mv_pp2x_plcr_hw_cpu_thresh_set (cpu_slot, edrop_id, MVPP2_EDROP_MAX_THESH);
  if (rc)
    {
      pr_err ("failed to set CPU threshold to HW\n");
      return rc;
    }

  return rc;
}
static int
pp2_cls_plcr_gen_cfg_set (struct pp2_inst *inst, struct pp2_cls_plcr_gen_cfg_t *gen_cfg)
{
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);
  int rc;

  /* parameter verification */
  if (mv_pp2x_ptr_validate (gen_cfg))
    return -EFAULT;

  if ((gen_cfg->rate_state != MVPP2_PLCR_BASE_RATE_ENABLE) &&
      (gen_cfg->rate_state != MVPP2_PLCR_BASE_RATE_DISABLE))
    {
      pr_err ("invalid base rate state (%d)\n", gen_cfg->rate_state);
      return -EINVAL;
    }

  if ((gen_cfg->base_period != MVPP2_TOKEN_PERIOD_400_CORE_CLOCK) &&
      (gen_cfg->base_period != MVPP2_TOKEN_PERIOD_480_CORE_CLOCK) &&
      (gen_cfg->base_period != MVPP2_TOKEN_PERIOD_600_CORE_CLOCK) &&
      (gen_cfg->base_period != MVPP2_TOKEN_PERIOD_800_CORE_CLOCK))
    {
      pr_err ("invalid token base period(%d)\n", gen_cfg->base_period);
      return -EINVAL;
    }

  if ((gen_cfg->mode != MVPP2_PLCR_MODE_SERIAL_BANK_0_1) &&
      (gen_cfg->mode != MVPP2_PLCR_MODE_SERIAL_BANK_1_0) &&
      (gen_cfg->mode != MVPP2_PLCR_MODE_PARALLEL) && (gen_cfg->mode != MVPP2_PLCR_MODE_ONLY_BANK_0))
    {
      pr_err ("invalid mode(%d)\n", gen_cfg->mode);
      return -EINVAL;
    }

  /* set token base period */
  rc = mv_pp2x_plcr_hw_base_period_set (cpu_slot, gen_cfg->base_period);
  if (rc)
    {
      pr_err ("failed to set token base period to HW\n");
      return rc;
    }

  /* set base rate generation state */
  rc = mv_pp2x_plcr_hw_base_rate_gen_enable (cpu_slot, gen_cfg->rate_state);
  if (rc)
    {
      pr_err ("failed to set token base rate generation to HW\n");
      return rc;
    }

  /* set min packet length */
  rc = mv_pp2x_plcr_hw_min_pkt_len (cpu_slot, gen_cfg->min_pkt_len);
  if (rc)
    {
      pr_err ("failed to set min packet length to HW\n");
      return rc;
    }

  /* set operation mode */
  rc = mv_pp2x_plcr_hw_mode (cpu_slot, gen_cfg->mode);
  if (rc)
    {
      pr_err ("failed to set mode to HW\n");
      return rc;
    }

  /* save the general configuration to DB */
  rc = pp2_cls_db_plcr_gen_cfg_set (inst, gen_cfg);
  if (rc)
    {
      pr_err ("failed to set policer general configuration to DBr\n");
      return rc;
    }

  return 0;
}

static int
pp2_cls_plcr_hw_entry_del (struct pp2_inst *inst, u8 policer_id)
{
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);
  int rc = 0;

  if (mv_pp2x_range_validate (policer_id, 0, MVPP2_PLCR_MAX - 1))
    {
      pr_err ("invalid policer ID %d, out of range[%d, %d]\n", policer_id, 0, MVPP2_PLCR_MAX - 1);
      return -EINVAL;
    }

  /* disable this policer */
  rc = mv_pp2x_plcr_hw_enable (cpu_slot, policer_id, MVPP2_PLCR_ENTRY_INVALID_STATE);
  if (rc)
    {
      pr_err ("failed to disable policer to HW\\n");
      return rc;
    }

  return rc;
}
static int
pp2_cls_plcr_reset (struct pp2_inst *inst)
{
  struct pp2_cls_plcr_gen_cfg_t gen_cfg;
  int rc = 0;

  /* init policer DB */
  rc = pp2_cls_db_plcr_init (inst);
  if (rc)
    {
      pr_err ("fail to init policer DB\n");
      return rc;
    }

  /* set policer default general configuration */
  MVPP2_MEMSET_ZERO (gen_cfg);
  gen_cfg.rate_state = MVPP2_PLCR_BASE_RATE_ENABLE;
  gen_cfg.mode = MVPP2_PLCR_MODE_ONLY_BANK_0;
  gen_cfg.base_period = MVPP2_TOKEN_PERIOD_800_CORE_CLOCK;
  gen_cfg.min_pkt_len = MVPP2_PLCR_MIN_PKT_LEN;
  rc = pp2_cls_plcr_gen_cfg_set (inst, &gen_cfg);
  if (rc)
    {
      pr_err ("fail to set policer default general configuration\n");
      return rc;
    }

  return rc;
}
static int
pp2_cls_edrop_reset (struct pp2_inst *inst)
{
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);
  int i, rc = 0;

  /* init early drop DB */
  rc = pp2_cls_db_edrop_init (inst);
  if (rc)
    {
      pr_err ("fail to init policer DB\n");
      return rc;
    }

  /* Set CPU threshold #0 and "non-reserved-entries" to maximum value
   * to simulate "disable" mode
   */
  pp2_cls_edrop_hw_entry_del (inst, 0);

  for (i = 0; i < MVPP2_EDROP_MAX - 1; i++)
    {
      if (!(pp2_ptr->init.early_drop_reserved_map & (1 << i)))
	pp2_cls_edrop_hw_entry_del (inst, (MVPP2_EDROP_MIN_ENTRY_ID + i));
    }

  /* enable early drop */
  rc = mv_pp2x_plcr_hw_early_drop_set (cpu_slot, true);
  if (rc)
    {
      pr_err ("failed to set early drop to HW\n");
      return rc;
    }

  return rc;
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

  /* init PP2_CLS C3 DB */
  rc = pp2_cls_db_c3_init (inst);
  if (rc)
    {
      pr_err ("fail to init PP2_CLS C3 DB\n");
      return rc;
    }
  pr_debug ("PP2_CLS C3 DB initialized\n");

  /* init PP2_CLS C3 HAL */
  rc = pp2_cls_c3_init (cpu_slot);
  if (rc)
    {
      pr_err ("fail to init PP2_CLS C3 DB\n");
      return rc;
    }
  pr_debug ("PP2_CLS C3 DB initialized\n");

  /* set PP2_CLS C3 maximum search depth */
  rc = pp2_cls_db_c3_search_depth_set (inst, MVPP2_C3_DEFAULT_SEARCH_DEPTH);
  if (rc)
    {
      pr_err ("fail to set PP2_CLS C3 max search depth\n");
      return rc;
    }
  pr_debug ("PP2_CLS C3 max depth set to %d\n", MVPP2_C3_DEFAULT_SEARCH_DEPTH);

  return 0;
}
static int
pp2_cls_c2_reset (struct pp2_inst *inst)
{
  int ret_code;
  int index;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  /* Clear all TCAM entry, except last one added by LSP */
  for (index = MVPP2_C2_FIRST_ENTRY; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    mv_pp2x_cls_c2_hw_inv (cpu_slot, index);

  /* Clear MVPP2 C2 DB */
  ret_code = pp2_cls_db_c2_init (inst);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Reset logic index */
  pp2_cls_c2_new_logic_idx_allocate (true);

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

  pp2_cls_db_mng_init ();
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

  liomem->type = params->type;
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

  if (liomem->type == SYS_IOMEM_T_UIO)
    {
      err = iomem_uio_ioinit (&liomem->u.uio, liomem->name, liomem->index);
      if (err)
	{
	  clib_mem_free (liomem->name);
	  clib_mem_free (liomem);
	  return err;
	}
    }
  else if (liomem->type == SYS_IOMEM_T_MMAP)
    {
      err = iomem_mmap_ioinit (&liomem->u.mmap, liomem->name, liomem->index);
      if (err)
	{
	  clib_mem_free (liomem->name);
	  clib_mem_free (liomem);
	  return err;
	}
    }
  else if (liomem->type == SYS_IOMEM_T_SHMEM)
    {
      err = iomem_shmem_ioinit (&liomem->u.shmem, liomem->name, liomem->index, params->size);
      if (err)
	{
	  clib_mem_free (liomem->name);
	  clib_mem_free (liomem);
	  return err;
	}
    }
  else
    {
      pr_err ("IOtype not supported yet!\n");
      return -ENOTSUP;
    }

  /* add to list: name & index */
  list_add_to_tail (&liomem->node, &iomem_maps_lst);

  *iomem = liomem;
  return 0;
}

static int
pp2_cls_edrop_start (struct pp2_inst *inst)
{
  if (pp2_cls_edrop_reset (inst) != 0)
    {
      pr_err ("MVPP2 early-drop start failed\n");
      return -EINVAL;
    }

  return 0;
}

static int
pp2_cls_plcr_start (struct pp2_inst *inst)
{
  int i;

  if (pp2_cls_plcr_reset (inst) != 0)
    {
      pr_err ("MVPP2 policer start failed\n");
      return -EINVAL;
    }

  /* Make sure policers are disabled */
  for (i = 0; i < PP2_CLS_PLCR_NUM; i++)
    {
      if (!(pp2_ptr->init.policers_reserved_map & (1 << i)))
	pp2_cls_plcr_hw_entry_del (inst, (i + 1));
    }

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
  int rc = 0;
  struct pp2_cls_fl_rule_list_t *fl_rls;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  rc = mv_pp2x_cls_hw_cls_enable (cpu_slot, true);
  if (rc)
    {
      pr_err ("failed to enable clasifier\n");
      return rc;
    }

  pp2_db_cls_init (inst);

  fl_rls = clib_mem_alloc_or_null (sizeof (*fl_rls));
  if (!fl_rls)
    return -ENOMEM;
  memset (fl_rls, 0, sizeof (struct pp2_cls_fl_rule_list_t));

  /* add flow rules to DB */
  rc = pp2_cls_add_lkpid_and_flows_to_db (inst, fl_rls);
  if (rc)
    {
      pr_err ("pp2_cls_adding_db_current_flows fail rc = %d\n", rc);
      goto end;
    }

  if (fl_rls->fl_len)
    pp2_cls_fl_rule_add (inst, fl_rls);

  /* Enable lookup decoder */
  pp2_cls_lkp_dcod_enable_all (inst);

end:
  if (fl_rls)
    clib_mem_free (fl_rls);
  return rc;
}

static void
pp2_bm_flush_pools (uintptr_t cpu_slot, uint16_t bm_pool_reserved_map)
{
  u32 pool_id;
  u32 resid_bufs = 0;

  /* Iterate through all the pools. Clean and reset registers */
  for (pool_id = 0; pool_id < PP2_BPOOL_NUM_POOLS; pool_id++)
    {
      if (bm_pool_reserved_map & (1 << pool_id))
	continue;
      /* Discard residual buffers */
      resid_bufs = pp2_bm_pool_flush (cpu_slot, pool_id);
      if (resid_bufs)
	{
	  pr_warn ("BM: could not clear all buffers from pool ID=%u\n", pool_id);
	  pr_warn ("BM: residual bufs : %u\n", resid_bufs);
	}
      /* Stop and clear pool internals */
      pp2_bm_hw_pool_destroy (cpu_slot, pool_id);
      /* Mask BM all interrupts */
      pp2_reg_write (cpu_slot, MVPP2_BM_INTR_MASK_REG (pool_id), 0x00);
      /* Clear BM cause register */
      pp2_reg_write (cpu_slot, MVPP2_BM_INTR_CAUSE_REG (pool_id), 0x00);
    }
  /* Disable the priority algorithm for buffer alloc/release */
  pp2_reg_write (cpu_slot, MVPP2_BM_PRIO_CTRL_REG, 0x00);

  pp2_reg_write (cpu_slot, MVPP22_BM_PHY_VIRT_HIGH_RLS_REG, 0x00);
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
  pp2_cls_plcr_start (inst);
  pp2_cls_edrop_start (inst);
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
  iomem_params.type = SYS_IOMEM_T_UIO;
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
      u32 id = port->id + (inst->id * PP2_NUM_ETH_PPIO);

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
  if (params->type == SYS_IOMEM_T_UIO)
    return iomem_uio_io_exists (params->devname, params->index);
  pr_err ("IOtype not supported yet!\n");
  return -ENOTSUP;
}

static u16
pp2_get_used_hif_map (void)
{
  uintptr_t cpu_slot;
  u32 hif_map;
  struct pp2_inst *pp2_first_inst = pp2_ptr->pp2_inst[0];

  cpu_slot = pp2_first_inst->hw.base[PP2_DEFAULT_REGSPACE].va;
  hif_map = pp2_reg_read (cpu_slot, MVPP22_HIF_ALLOCATION_REG);
  hif_map = (hif_map) ? hif_map : MV_PP2_HIFS_RSRV_MASK;

  pr_info ("%s: hif_map(0x%x)\n", __func__, hif_map);
  return hif_map;
}

static int
pp2_prs_udf_init (struct pp2_inst *inst, struct pp2_parse_udfs *prs_udfs)
{
  int rc;

  rc = pp2_prs_check_udf_params (prs_udfs);
  if (rc)
    return rc;

  for (int i = 0; i < prs_udfs->num_udfs; i++)
    {
      rc = pp2_prs_create_udf_entry (inst, &prs_udfs->udfs[i], i);
      if (rc)
	return rc;
    }

  return 0;
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
  enum musdk_lnx_id lnx_id = lnx_id_get ();

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

  first_rxq = port->id * PP2_HW_PORT_NUM_RXQS;
  if (param->type == PP2_PPIO_T_LOG)
    first_rxq += param->specific_type_params.log_port_params.first_inq;

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
	  rx_q->mem = inqs_params->mem;
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
      port->txq_config[i].rate_limit_enable =
	param->outqs_params.outqs_params[i].rate_limit.rate_limit_enable;
      if (param->outqs_params.outqs_params[i].rate_limit.rate_limit_enable &&
	  param->outqs_params.outqs_params[i].rate_limit.rate_limit_params.cbs < PP2_PPIO_MIN_CBS)
	{
	  pr_err ("port %s: CBS for egress queue %u has to be at least %ukB.\n", port->linux_name,
		  i, PP2_PPIO_MIN_CBS);
	  return -EINVAL;
	}
      if (param->outqs_params.outqs_params[i].rate_limit.rate_limit_enable &&
	  param->outqs_params.outqs_params[i].rate_limit.rate_limit_params.cir < PP2_PPIO_MIN_CIR)
	{
	  pr_err ("port %s: CIR for egress queue %u has to be at least %ukbps.\n", port->linux_name,
		  i, PP2_PPIO_MIN_CIR);
	  return -EINVAL;
	}
      port->txq_config[i].rate_limit_params.cbs =
	param->outqs_params.outqs_params[i].rate_limit.rate_limit_params.cbs;
      port->txq_config[i].rate_limit_params.cir =
	param->outqs_params.outqs_params[i].rate_limit.rate_limit_params.cir;
    }

  port->enable_port_rate_limit = param->rate_limit.rate_limit_enable;
  if (param->rate_limit.rate_limit_enable &&
      param->rate_limit.rate_limit_params.cbs < PP2_PPIO_MIN_CBS)
    {
      pr_err ("port %s: CBS has to be at least %ukB.\n", port->linux_name, PP2_PPIO_MIN_CBS);
      return -EINVAL;
    }
  if (param->rate_limit.rate_limit_enable &&
      param->rate_limit.rate_limit_params.cir < PP2_PPIO_MIN_CIR)
    {
      pr_err ("port %s: CIR has to be at least %ukbps.\n", port->linux_name, PP2_PPIO_MIN_CIR);
      return -EINVAL;
    }
  port->rate_limit_params.cbs = param->rate_limit.rate_limit_params.cbs;
  port->rate_limit_params.cir = param->rate_limit.rate_limit_params.cir;

  port->hash_type = param->inqs_params.hash_type;
  port->default_plcr = param->inqs_params.plcr;

  if (LPBK_PORT (port))
    port->use_mac_lb = true;
  else
    port->use_mac_lb = false;

  pr_debug ("PORT: ID %u (on PP%u):\n", port->id, pp2_id);
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

  if (param->type != PP2_PPIO_T_NIC && param->type != PP2_PPIO_T_LOG)
    return -EINVAL;

  port->type = param->type;
  port->num_vlans = 0;
  port->vlan_enable = 0;

  /* For MUSDK Ethernet ports, call uio_open to request port ownership from Linux */
  if (NOT_LPBK_PORT (port) && port->type == PP2_PPIO_T_NIC)
    {
      if (lnx_is_mainline (lnx_id))
	rc = pp2_port_set_priv_flags (port, MVPP22_F_IF_MUSDK_PRIV);
      else
	rc = pp2_port_open_uio (port);
      if (rc)
	return rc;
    }
  /* Assign and initialize port private data and hardware */
  pp2_port_init (port);

  port->maintain_stats = param->maintain_stats;
  inst->num_ports++;

  /* At this point, the port is default allocated and configured */
  *port_hdl = port;

  if (!(NOT_LPBK_PORT (port) && (param->type == PP2_PPIO_T_NIC)))
    return 0;

  pp2_port_initialize_statistics (port);
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

  /* TODO: Temporary code to for testing, mechanism required to find this pp2's mem_id */
  u32 mem_id = pp2_get_mem_id (port->parent->id);

  port->tx_qs_mem = mv_sys_dma_mem_region_get (mem_id);
  pr_debug ("(%s)Got pointer %p for mem_id(%d)\n", __func__, port->tx_qs_mem, mem_id);
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

  if (!inst->skip_hw_init)
    {
      /* Clear BM */
      pp2_bm_flush_pools (cpu_slot, inst->parent->init.bm_pool_reserved_map);

      pp2_cls_mng_init (inst);
    }

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
      /* Static ID assignment */
      port->id = i;
      inst->ports[i] = port;
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

  iomem_params.type = SYS_IOMEM_T_UIO;
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
  pp2_ptr->pp2_common.rss_tbl_map = params->rss_tbl_reserved_map;
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

      /* Initialize this packet processor */
      inst->skip_hw_init = params->skip_hw_init;

      /* Retrieve reserved_maps for auto_detect requests, only required to perform once.
       * bm_pool_map must be valid before call to pp2_inst_init().
       */
      if (pp2_id == 0)
	{
	  if (pp2_ptr->init.res_maps_auto_detect_map & PP2_RSRVD_MAP_HIF_AUTO)
	    {
	      pp2_ptr->init.hif_reserved_map = pp2_get_used_hif_map ();
	      params->hif_reserved_map = pp2_ptr->init.hif_reserved_map;
	    }
	  if (pp2_ptr->init.res_maps_auto_detect_map & PP2_RSRVD_MAP_BM_POOL_AUTO)
	    {
	      pp2_ptr->init.bm_pool_reserved_map = pp2_get_used_bm_pool_map ();
	      params->bm_pool_reserved_map = pp2_ptr->init.bm_pool_reserved_map;
	    }
	}

      pp2_inst_init (inst);

      if (params->prs_udfs.num_udfs > 0)
	{
	  rc = pp2_prs_udf_init (inst, &params->prs_udfs);
	  if (rc)
	    {
	      pr_err ("[%s] failed to init parser udfs.\n", __func__);
	      rc = -EFAULT;
	      goto pp2_init_err;
	    }
	}

      pp2_ptr->num_pp2_inst++;
    }

  pr_debug ("PackProcs   %2u\n", pp2_num_inst);
  if (!params->skip_hw_init)
    {
      struct pp2_ppio_params *lb_port_params;

      lb_port_params = clib_mem_alloc_or_null (sizeof (struct pp2_ppio_params));
      if (!lb_port_params)
	{
	  rc = -ENOMEM;
	  goto pp2_init_err;
	}

      memset (lb_port_params, 0, sizeof (*lb_port_params));
      lb_port_params->type = PP2_PPIO_T_NIC;
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
  u8 hif_slot, pp2_id, i;
  struct pp2_ppio_desc *descs;

  if (mv_sys_match (params->match, "hif", 1, &hif_slot))
    {
      pr_err ("[%s] Invalid match string (%s)!\n", __func__, params->match);
      return (-ENXIO);
    }
  if (pp2_is_init () == false)
    {
      pr_err ("[%s] pp2 is not initialized\n", __func__);
      return (-EPERM);
    }

  if (hif_slot >= PP2_NUM_REGSPACES)
    {
      pr_err ("[%s] Invalid match string!\n", __func__);
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
      rc = pp2_dm_if_init (pp2_ptr, hif_slot, pp2_id, params->out_size, params->mem);
      /* Rollback created instances */
      if (rc)
	{
	  for (i = 0; i < pp2_id; i++)
	    pp2_dm_if_deinit (pp2_ptr, hif_slot, i);
	  return rc;
	}
    }
  pp2_hif[hif_slot].regspace_slot = hif_slot;

  pp2_ptr->pp2_common.hif_slot_map |= (1 << hif_slot);
  *hif = &pp2_hif[hif_slot];
  (*hif)->rel_descs = descs;

  return 0;
}

void
pp2_bpool_deinit (struct pp2_bpool *pool)
{
  uintptr_t cpu_slot;
  int pool_id;
  u32 buf_num;
  struct pp2_bm_pool *bm_pool;

  cpu_slot = GET_HW_BASE (pool)[PP2_DEFAULT_REGSPACE].va;
  pool_id = pool->id;

  /* Check buffer counters after free */
  pp2_bpool_get_num_buffs (pool, &buf_num);
  if (buf_num)
    {
      pr_warn ("cannot free all buffers in pool %d, buf_num left %d\n", pool_id, buf_num);
    }

  bm_pool = pp2_bm_pool_get_pool_by_id (pp2_ptr->pp2_inst[pool->pp2_id], pool_id);

  /* reset cm3 bm pool flow control */
  if (bm_pool)
    pp2_bm_pool_reset_fc (pp2_ptr->pp2_inst[pool->pp2_id]->hw.cm3_base.va, bm_pool);

  if (bm_pool && !pp2_bm_pool_destroy (cpu_slot, bm_pool))
    pp2_ptr->pp2_inst[pool->pp2_id]->bm_pools[pool_id] = NULL;
  else
    pr_err ("[%s] Can not destroy pool_id-%d:%d !\n", __func__, pool->pp2_id, pool_id);
}

int
pp2_bpool_get_buff (struct pp2_hif *hif, struct pp2_bpool *pool, struct pp2_buff_inf *buff)
{
  uintptr_t cpu_slot;
  dma_addr_t paddr;
  int pool_id;
  u64 vaddr, high_addr_reg;

  cpu_slot = GET_HW_BASE (pool)[hif->regspace_slot].va;
  pool_id = pool->id;

  paddr = pp2_reg_read (cpu_slot, MVPP2_BM_PHY_ALLOC_REG (pool_id));
  if (unlikely (!paddr))
    return -ENOBUFS;

  vaddr = pp2_reg_read (cpu_slot, MVPP2_BM_VIRT_ALLOC_REG);

  high_addr_reg = pp2_reg_read (cpu_slot, MVPP22_BM_PHY_VIRT_HIGH_ALLOC_REG);
  vaddr |=
    ((high_addr_reg & MVPP22_BM_VIRT_HIGH_ALLOC_MASK) << (32 - MVPP22_BM_VIRT_HIGH_ALLOC_OFFSET));

#if (MVCONF_DMA_PHYS_ADDR_T_SIZE == 64)
  paddr |=
    ((high_addr_reg & MVPP22_BM_PHY_HIGH_ALLOC_MASK) << (32 - MVPP22_BM_PHY_HIGH_ALLOC_OFFSET));
#endif
  buff->addr = paddr;

  buff->cookie = vaddr;
  return 0;
}

int
pp2_bpool_init (struct pp2_bpool_params *params, struct pp2_bpool **bpool)
{
  u8 match[2];
  struct bm_pool_param param;
  int pool_id, pp2_id, rc;

  if (mv_sys_match (params->match, "pool", 2, match))
    return (-ENXIO);

  if (pp2_is_init () == false)
    return (-EPERM);

  pp2_id = match[0];
  pool_id = match[1];

  if (pool_id < 0 || pool_id >= PP2_BPOOL_NUM_POOLS)
    {
      pr_err ("[%s] Invalid match string!\n", __func__);
      return (-ENXIO);
    }
  if (pp2_id < 0 || pp2_id >= pp2_ptr->num_pp2_inst)
    {
      pr_err ("[%s] Invalid match string!\n", __func__);
      return (-ENXIO);
    }
  if (pp2_ptr->init.bm_pool_reserved_map & (1 << pool_id))
    {
      pr_err ("[%s] bm_pool is reserved.\n", __func__);
      return (-EFAULT);
    }
  if (pp2_ptr->pp2_inst[pp2_id]->bm_pools[pool_id])
    {
      pr_err ("[%s] bm_pool already exists.\n", __func__);
      return (-EEXIST);
    }
  pr_debug ("[%s] pp2_id(%d) pool_id(%d)\n", __func__, pp2_id, pool_id);
  param.dummy_pool = params->dummy_short_pool;
  param.buf_num = MVPP2_BM_POOL_SIZE_MAX;
  param.buf_size = param.dummy_pool ? PP2_DUMMY_POOL_BUF_SIZE : params->buff_len;
  param.id = pool_id;
  param.pp2_id = pp2_id;
  param.likely_buffer_mem = params->likely_buffer_mem;
  rc = pp2_bm_pool_create (pp2_ptr, &param);
  if (!rc)
    {
      pp2_bpools[pp2_id][pool_id].id = pool_id;
      pp2_bpools[pp2_id][pool_id].pp2_id = pp2_id;
      SET_HW_BASE (&pp2_bpools[pp2_id][pool_id], &pp2_ptr->pp2_inst[pp2_id]->hw.base[0]);
      *bpool = &pp2_bpools[pp2_id][pool_id];
      pp2_bm_pool_reset_fc (pp2_ptr->pp2_inst[pp2_id]->hw.cm3_base.va,
			    pp2_ptr->pp2_inst[pp2_id]->bm_pools[pool_id]);
    }
  return rc;
}

int
pp2_bpool_put_buffs (struct pp2_hif *hif, struct buff_release_entry buff_entry[], u16 *num)
{
  struct pp2_ppio_desc *cur_desc;
  int i, pp2_id;
  int pp_ind[PP2_NUM_PKT_PROC] = { 0 };

  if (unlikely (*num > PP2_MAX_NUM_PUT_BUFFS))
    {
      pr_err ("(%s):Received too many buffers:%d > MAX:%d\n", __func__, *num,
	      PP2_MAX_NUM_PUT_BUFFS);
    }
  for (i = 0; i < (*num); i++)
    {
      /* TODO: Before version release, skip buffer instead of crashing */
      if (unlikely (!(buff_entry + i)))
	{
	  pr_err ("(%s):buf_entry %d out of %d = NULL\n", __func__, i, *num);
	  mdelay (100);
	}
      if (unlikely (!(buff_entry[i].bpool)))
	{
	  pr_err ("(%s):buf_entry[%d].bpool out of %d = NULL\n", __func__, i, *num);
	  mdelay (100);
	}
      pp2_id = buff_entry[i].bpool->pp2_id;
      cur_desc = hif->rel_descs + PP2_MAX_NUM_PUT_BUFFS * pp2_id + pp_ind[pp2_id];
      pp2_ppio_outq_desc_reset (cur_desc);
      pp2_ppio_outq_desc_set_phys_addr (cur_desc, buff_entry[i].buff.addr);
      /* TODO: ASAP, check if setting to 0 creates issues. */
      pp2_ppio_outq_desc_set_pkt_offset (cur_desc, DUMMY_PKT_EFEC_OFFS);
      pp2_ppio_outq_desc_set_pkt_len (cur_desc, 0);
      pp2_ppio_outq_desc_set_cookie (cur_desc, buff_entry[i].buff.cookie);
      pp2_ppio_outq_desc_set_pool (cur_desc, buff_entry[i].bpool);
      cur_desc->cmds[3] = TXD_ERR_SUM_MASK;
      pp_ind[pp2_id]++;
#ifdef DEBUG
      do
	{
	  int pool_id;
	  struct mv_sys_dma_mem_region *likely_mem;
	  dma_addr_t buf_addr = buff_entry[i].buff.addr;

	  pool_id = buff_entry[i].bpool->id;
	  likely_mem = pp2_ptr->pp2_inst[pp2_id]->bm_pools[pool_id]->likely_buffer_mem;

	  if (likely_mem)
	    if ((buf_addr < likely_mem->dma_phys_base) ||
		(buf_addr > (likely_mem->dma_phys_base + likely_mem->size)))
	      pr_debug ("(%s): buf_addr 0x%" PRIdma ", not in likely_mem range mem_id(%d)\n",
			__func__, buf_addr, likely_mem->mem_id);
	}
      while (0);
#endif
    }
  for (i = 0; i < PP2_NUM_PKT_PROC; i++)
    {
      if (pp_ind[i])
	pp2_bpool_put_buffs_core (i, pp_ind[i], hif->regspace_slot,
				  hif->rel_descs + PP2_MAX_NUM_PUT_BUFFS * i);
    }

  return 0;
}

int
pp2_ppio_add_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio *ppio = mp->ppio;
  int rc;

  rc = pp2_port_add_mac_addr (GET_PPIO_PORT (ppio), (const uint8_t *) addr);
  return rc;
}

void
pp2_ppio_deinit (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio *ppio = mp->ppio;
  struct pp2_port **port_ptr = NULL;

  port_ptr = GET_PPIO_PORT_PTR (*ppio);

  if (*port_ptr)
    {
      pp2_ppio_set_loopback (ppio, false);
      pp2_ppio_set_promisc (port, false);
      pp2_ppio_flush_vlan (ppio);

      if (pp2_cls_mng_modify_default_flows (ppio, true))
	pr_err ("[%s] ppio deinit failed while default flows\n", __func__);

      if (pp2_cls_mng_eth_start_header_params_set (ppio, PP2_PPIO_HDR_ETH))
	pr_err ("[%s] ppio deinit failed while initialize ethernet start header\n", __func__);

      pp2_port_close (*port_ptr);
      *port_ptr = NULL;
      pp2_ptr->pp2_inst[ppio->pp2_id]->ppios[ppio->port_id] = NULL;
      if (ppio)
	clib_mem_free (ppio);
    }
  else
    pr_err ("[%s] ppio deinit failed close port %d:%d\n", __func__, ppio->pp2_id, ppio->port_id);
}

int
pp2_ppio_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio *ppio = mp->ppio;

  pp2_port_stop (GET_PPIO_PORT (ppio));
  return 0;
}

int
pp2_ppio_enable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio *ppio = mp->ppio;

  pp2_port_start (GET_PPIO_PORT (ppio), PP2_TRAFFIC_INGRESS_EGRESS);
  return 0;
}

int
pp2_ppio_get_link_info (vnet_dev_port_t *port, struct pp2_ppio_link_info *link_info)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio *ppio = mp->ppio;
  int rc;
  struct pp2_port_link_status pstatus;

  rc = pp2_port_link_info (GET_PPIO_PORT (ppio), &pstatus);
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
  struct pp2_ppio *ppio = mp->ppio;
  struct pp2_dm_if *dm_if;
  u32 outq_physid;

  dm_if = pp2_dm_if_get (ppio, hif);
  outq_physid = GET_PPIO_PORT (ppio)->txqs[qid]->id;
  *num = pp2_port_outq_status (dm_if, outq_physid);

  return 0;
}

static int pp2_ppio_inq_get_statistics_internal (struct pp2_ppio *ppio, u8 tc, u8 qid,
						 struct pp2_ppio_inq_statistics *stats, int reset);
static int pp2_ppio_outq_get_statistics_internal (struct pp2_ppio *ppio, u8 qid,
						  struct pp2_ppio_outq_statistics *stats,
						  int reset);

static int
pp2_ppio_get_statistics_internal (struct pp2_ppio *ppio, struct pp2_ppio_statistics *stats,
				  int reset)
{
  struct pp2_ppio_statistics cur_stats;
  struct pp2_port *port = GET_PPIO_PORT (ppio);
  int qid, tc;

  memset (&cur_stats, 0, sizeof (struct pp2_ppio_statistics));
  pp2_port_get_statistics (port, &cur_stats);

  /* Get rx and tx packets counters from queues and not from GOP */
  cur_stats.rx_packets = 0;
  cur_stats.tx_packets = 0;

  /* Update Rx Qs Statistics */
  for (tc = 0; tc < port->num_tcs; tc++)
    {
      for (qid = 0; qid < port->tc[tc].tc_config.num_in_qs; qid++)
	{
	  struct pp2_ppio_inq_statistics rx_stats;

	  pp2_ppio_inq_get_statistics_internal (ppio, tc, qid, &rx_stats, reset);
	  cur_stats.rx_packets += rx_stats.enq_desc;
	  cur_stats.rx_fullq_dropped += rx_stats.drop_fullq;
	  cur_stats.rx_bm_dropped += rx_stats.drop_bm;
	  cur_stats.rx_early_dropped += rx_stats.drop_early;
	}
    }

  /* Update Tx Qs Statistics */
  for (qid = 0; qid < port->num_tx_queues; qid++)
    {
      struct pp2_ppio_outq_statistics tx_stats;

      pp2_ppio_outq_get_statistics_internal (ppio, qid, &tx_stats, reset);
      cur_stats.tx_packets += tx_stats.deq_desc;
    }

  if (stats)
    {
      stats->rx_packets = cur_stats.rx_packets;
      stats->rx_fullq_dropped = cur_stats.rx_fullq_dropped;
      stats->rx_bm_dropped = cur_stats.rx_bm_dropped;
      stats->rx_early_dropped = cur_stats.rx_early_dropped;
      stats->tx_packets = cur_stats.tx_packets;
      /* From KS */
      stats->rx_bytes = cur_stats.rx_bytes - port->stats.rx_bytes;
      stats->rx_unicast_packets = cur_stats.rx_unicast_packets - port->stats.rx_unicast_packets;
      stats->rx_errors = cur_stats.rx_errors - port->stats.rx_errors;
      stats->rx_fifo_dropped = cur_stats.rx_fifo_dropped - port->stats.rx_fifo_dropped;
      stats->rx_cls_dropped = cur_stats.rx_cls_dropped - port->stats.rx_cls_dropped;
      stats->tx_bytes = cur_stats.tx_bytes - port->stats.tx_bytes;
      stats->tx_unicast_packets = cur_stats.tx_unicast_packets - port->stats.tx_unicast_packets;
      stats->tx_errors = cur_stats.tx_errors - port->stats.tx_errors;
    }

  if (reset)
    memcpy (&port->stats, &cur_stats, sizeof (struct pp2_ppio_statistics));

  return 0;
}

int
pp2_ppio_get_statistics (vnet_dev_port_t *port, struct pp2_ppio_statistics *stats, int reset)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  return pp2_ppio_get_statistics_internal (mp->ppio, stats, reset);
}

int
pp2_ppio_init (struct pp2_ppio_params *params, struct pp2_ppio **ppio)
{
  u8 match[2];
  int port_id, pp2_id, rc;
  struct pp2_port **port;

  if (mv_sys_match (params->match, "ppio", 2, match))
    {
      pr_err ("[%s] Invalid match string!\n", __func__);
      return -ENXIO;
    }

  if (pp2_is_init () == false)
    return -EPERM;

  pp2_id = match[0];
  port_id = match[1];

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
      pr_err ("[%s] %s is not available for musdk.\n", __func__, params->match);
      return -EINVAL;
    }

  if (pp2_ptr->pp2_inst[pp2_id]->ppios[port_id])
    {
      pr_err ("[%s] ppio already exists.\n", __func__);
      return -EEXIST;
    }

  *ppio = mem_calloc (1, sizeof (struct pp2_ppio));
  if (!*ppio)
    {
      pr_err ("%s out of memory ppio alloc\n", __func__);
      return -ENOMEM;
    }

  port = GET_PPIO_PORT_PTR (**ppio);

  rc = pp2_port_open (pp2_ptr, params, pp2_id, port_id, port);
  if (rc)
    {
      pr_err ("[%s] ppio init failed.\n", __func__);
      if (*ppio)
	clib_mem_free (*ppio);
      return (-EFAULT);
    }

  pp2_port_config_inq (*port);
  pp2_port_config_outq (*port);
  (*ppio)->pp2_id = pp2_id;
  (*ppio)->port_id = port_id;

  rc = pp2_cls_mng_eth_start_header_params_set (*ppio, params->eth_start_hdr);
  if (rc)
    {
      pr_err ("[%s] ppio init failed while initialize ethernet start header\n", __func__);
      return -EFAULT;
    }

  if (params->type == PP2_PPIO_T_LOG)
    {
      rc = pp2_cls_mng_set_logical_port_params (*ppio, params);
      if (rc)
	{
	  pr_err ("[%s] ppio init failed while initialize logical port\n", __func__);
	  return -EFAULT;
	}
    }

  rc = pp2_cls_mng_modify_default_flows (*ppio, false);
  if (rc)
    {
      pr_err ("[%s] ppio init failed while modify default flows\n", __func__);
      return -EFAULT;
    }

  pp2_ppio_get_statistics_internal (*ppio, NULL, true);
  pp2_ppio_set_loopback (*ppio, false);
  pp2_port_set_promisc (GET_PPIO_PORT (*ppio), false);

  pp2_ptr->pp2_inst[pp2_id]->ppios[port_id] = *ppio;

  return rc;
}

static int
pp2_ppio_inq_get_statistics_internal (struct pp2_ppio *ppio, u8 tc, u8 qid,
				      struct pp2_ppio_inq_statistics *stats, int reset)
{
  struct pp2_port *port = GET_PPIO_PORT (ppio);
  uintptr_t cpu_slot = port->cpu_slot;
  struct pp2_rx_queue *rxq;
  int log_rxq;

  if (unlikely (qid >= port->tc[tc].tc_config.num_in_qs))
    {
      pr_err ("[%s] invalid queue id (%d)!\n", __func__, qid);
      return -EINVAL;
    }

  log_rxq = port->tc[tc].first_log_rxq + qid;
  rxq = port->rxqs[log_rxq];

  pp2_relaxed_reg_write (cpu_slot, MVPP2_CNT_IDX_REG, rxq->id);
  PP2_READ_UPDATE_CNT64 (rxq->stats.enq_desc, cpu_slot, MVPP2_RX_DESC_ENQ_REG);
  PP2_READ_UPDATE_CNT32 (rxq->stats.drop_fullq, cpu_slot, MVPP2_RX_PKT_FULLQ_DROP_REG);
  PP2_READ_UPDATE_CNT16 (rxq->stats.drop_early, cpu_slot, MVPP2_RX_PKT_EARLY_DROP_REG);
  PP2_READ_UPDATE_CNT16 (rxq->stats.drop_bm, cpu_slot, MVPP2_RX_PKT_BM_DROP_REG);

  if (stats)
    memcpy (stats, &rxq->stats, sizeof (rxq->stats));

  if (reset)
    memset (&rxq->stats, 0, sizeof (rxq->stats));

  return 0;
}

int
pp2_ppio_inq_get_statistics (vnet_dev_port_t *port, u8 tc, u8 qid,
			     struct pp2_ppio_inq_statistics *stats, int reset)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  return pp2_ppio_inq_get_statistics_internal (mp->ppio, tc, qid, stats, reset);
}

static int
pp2_ppio_outq_get_statistics_internal (struct pp2_ppio *ppio, u8 qid,
				       struct pp2_ppio_outq_statistics *stats, int reset)
{
  struct pp2_port *port = GET_PPIO_PORT (ppio);
  uintptr_t cpu_slot = port->cpu_slot;
  struct pp2_tx_queue *txq;

  if (unlikely (qid >= port->num_tx_queues))
    {
      pr_err ("[%s] invalid queue id (%d)!\n", __func__, qid);
      return -EINVAL;
    }
  txq = port->txqs[qid];

  pp2_relaxed_reg_write (cpu_slot, MVPP2_CNT_IDX_REG, MVPP2_CNT_IDX_TX (port->id, txq->log_id));
  PP2_READ_UPDATE_CNT64 (txq->stats.enq_desc, cpu_slot, MVPP2_TX_DESC_ENQ_REG);
  PP2_READ_UPDATE_CNT64 (txq->stats.enq_dec_to_ddr, cpu_slot, MVPP2_TX_DESC_ENQ_TO_DRAM_REG);
  PP2_READ_UPDATE_CNT64 (txq->stats.enq_buf_to_ddr, cpu_slot, MVPP2_TX_BUF_ENQ_TO_DRAM_REG);
  PP2_READ_UPDATE_CNT64 (txq->stats.deq_desc, cpu_slot, MVPP2_TX_PKT_DQ_REG);

  if (stats)
    memcpy (stats, &txq->stats, sizeof (txq->stats));

  if (reset)
    memset (&txq->stats, 0, sizeof (txq->stats));

  return 0;
}

int
pp2_ppio_outq_get_statistics (vnet_dev_port_t *port, u8 qid, struct pp2_ppio_outq_statistics *stats,
			      int reset)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  return pp2_ppio_outq_get_statistics_internal (mp->ppio, qid, stats, reset);
}

int
pp2_ppio_recv (vnet_dev_port_t *port, u8 tc, u8 qid, struct pp2_ppio_desc *descs, u16 *num)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio *ppio = mp->ppio;
  struct pp2_port *pp_port = GET_PPIO_PORT (ppio);
  struct pp2_desc *rx_desc, *extra_rx_desc;
  struct pp2_rx_queue *rxq;
  u32 recv_req = *num, extra_num = 0;
  int log_rxq;
#if __BYTE_ORDER == __BIG_ENDIAN
  int i;
#endif

  /* TODO: After validation, delete recv_req variable */
  log_rxq = pp_port->tc[tc].first_log_rxq + qid;
  rxq = pp_port->rxqs[log_rxq];

  if (recv_req > rxq->desc_received)
    {
      rxq->desc_received = pp2_rxq_received (pp_port, rxq->id);
      if (unlikely (recv_req > rxq->desc_received))
	{
	  recv_req = rxq->desc_received;
	  *num = recv_req;
	}
    }

  /* TODO : Make pp2_rxq_get_desc inline */
  rx_desc = pp2_rxq_get_desc (rxq, &recv_req, &extra_rx_desc, &extra_num);
#if __BYTE_ORDER == __BIG_ENDIAN
  for (i = 0; i < recv_req; i++)
    pp2_ppio_desc_swap_ncopy (&descs[i], &rx_desc[i]);
#else
  __builtin_memcpy (descs, rx_desc, recv_req * sizeof (*descs));
#endif
  if (extra_num)
    {
#if __BYTE_ORDER == __BIG_ENDIAN
      for (i = 0; i < extra_num; i++)
	pp2_ppio_desc_swap_ncopy (&descs[recv_req + i], &extra_rx_desc[i]);
#else
      __builtin_memcpy (&descs[recv_req], extra_rx_desc, extra_num * sizeof (*descs));
#endif
      recv_req += extra_num; /* Put the split numbers back together */
    }
  /*  Update HW */
  pp2_port_inq_update (pp_port, log_rxq, recv_req, recv_req);
  rxq->desc_received -= recv_req;

  if (pp_port->maintain_stats)
    {
      rxq->threshold_rx_pkts += recv_req;
      if (unlikely (rxq->threshold_rx_pkts > PP2_STAT_UPDATE_THRESHOLD))
	{
	  pp2_ppio_inq_get_statistics (port, tc, qid, NULL, 0);
	  rxq->threshold_rx_pkts = 0;
	}
    }
  return 0;
}

int
pp2_ppio_remove_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio *ppio = mp->ppio;
  int rc;

  rc = pp2_port_remove_mac_addr (GET_PPIO_PORT (ppio), (const uint8_t *) addr);
  return rc;
}

int
pp2_ppio_send (vnet_dev_port_t *port, struct pp2_hif *hif, u8 qid, struct pp2_ppio_desc *descs,
	       u16 *num)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio *ppio = mp->ppio;
  struct pp2_dm_if *dm_if;
  u16 desc_sent, desc_req = *num;
  struct pp2_port *pp_port = GET_PPIO_PORT (ppio);

  dm_if = pp2_dm_if_get (ppio, hif);

  desc_sent = pp2_port_enqueue (pp_port, dm_if, qid, desc_req, descs, NULL);
  if (unlikely (desc_sent < desc_req))
    {
      pr_debug ("[%s] pp2_id %u Port %u qid %u, send_request %u sent %u!\n", __func__, ppio->pp2_id,
		ppio->port_id, qid, *num, desc_sent);
      *num = desc_sent;
    }

  if (pp_port->maintain_stats)
    {
      struct pp2_tx_queue *txq;

      txq = pp_port->txqs[qid];
      txq->threshold_tx_pkts += desc_sent;
      if (unlikely (txq->threshold_tx_pkts > PP2_STAT_UPDATE_THRESHOLD))
	{
	  pp2_ppio_outq_get_statistics (port, qid, NULL, 0);
	  txq->threshold_tx_pkts = 0;
	}
    }
  return 0;
}

int
pp2_ppio_set_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio *ppio = mp->ppio;
  int rc;

  rc = pp2_port_set_mac_addr (GET_PPIO_PORT (ppio), (const uint8_t *) addr);
  return rc;
}

int
pp2_ppio_set_promisc (vnet_dev_port_t *port, int en)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio *ppio = mp->ppio;
  int rc;

  rc = pp2_port_set_promisc (GET_PPIO_PORT (ppio), en);
  return rc;
}

static inline void
uio_single_munmap (struct uio_info_t *info, int map_num)
{
  munmap (info->maps[map_num].internal_addr, info->maps[map_num].size);
  info->maps[map_num].mmap_result = UIO_MMAP_NOT_DONE;
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
#ifdef __BIG_ENDIAN
  return 0x01 & e_16;
#else
  return 0x01 & (e_16 >> ((sizeof (e_16) * 8) - 8));
#endif
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
dm_lock_create (struct pp2_dm_if *dm_if)
{
#ifdef MVCONF_PP2_LOCK
  dm_if->dm_lock.lock = spin_lock_create ();
#endif
}

static void
dm_lock_destroy (struct pp2_dm_if *dm_if)
{
#ifdef MVCONF_PP2_LOCK
  spin_lock_destroy (dm_if->dm_lock.lock);
#endif
}

static void
iomem_mmap_iodestroy (struct mem_mmap *mmapm)
{
  /* TODO: free all objs */
}

static void
iomem_shmem_iodestroy (struct mem_uio *uiom)
{
  /* Nothing to do */
}

static void
iomem_uio_iodestroy (struct mem_uio *uiom)
{
  uio_free_info (uiom->info);
}

static void
mv_pp2x_cls_oversize_rxq_set (struct pp2_port *port)
{
  uintptr_t cpu_slot = port->cpu_slot;

  pp2_reg_write (cpu_slot, MVPP2_CLS_OVERSIZE_RXQ_LOW_REG (port->id), port->first_rxq);
}

static void
mv_pp2x_prs_clear_active_vlans (struct pp2_port *port, uint32_t *vlans)
{
  struct pp2_inst *inst = port->parent;
  struct mv_pp2x_prs_shadow *prs_shadow = inst->cls_db->prs_db.prs_shadow;
  int index = 0;
  int tid;

  for (tid = MVPP2_PRS_VID_PORT_FIRST (port->id); tid <= MVPP2_PRS_VID_PORT_LAST (port->id); tid++)
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
  tid = mvpp2x_prs_mac_da_range_find (port->parent, port->cpu_slot, BIT (port->id), da, mask, 0);

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
  mv_pp2x_prs_tcam_port_set (&pe, port->id, add);

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
mv_pp2x_prs_sram_ai_update (struct mv_pp2x_prs_entry *pe, unsigned int bits, unsigned int mask)
{
  unsigned int i;
  int ai_off = MVPP2_PRS_SRAM_AI_OFFS;

  for (i = 0; i < MVPP2_PRS_SRAM_AI_CTRL_BITS; i++)
    {
      if (!(mask & BIT (i)))
	continue;

      if (bits & BIT (i))
	mv_pp2x_prs_sram_bits_set (pe, ai_off + i, 1);
      else
	mv_pp2x_prs_sram_bits_clear (pe, ai_off + i, 1);

      mv_pp2x_prs_sram_bits_set (pe, MVPP2_PRS_SRAM_AI_CTRL_OFFS + i, 1);
    }
}

static int
mv_pp2x_prs_sram_bit_set (struct mv_pp2x_prs_entry *pe, int bit_num, unsigned int val)
{
  if (mv_pp2x_ptr_validate (pe))
    return -1;

  pe->sram.word[SRAM_BIT_TO_WORD (bit_num)] |= (val << (SRAM_BIT_IN_WORD (bit_num)));

  return 0;
}

static void
mv_pp2x_prs_sram_clear (struct mv_pp2x_prs_entry *pe)
{
  memset (&pe->sram, 0, sizeof (pe->sram));
}

static void
mv_pp2x_prs_sram_next_lu_set (struct mv_pp2x_prs_entry *pe, unsigned int lu)
{
  int sram_next_off = MVPP2_PRS_SRAM_NEXT_LU_OFFS;

  mv_pp2x_prs_sram_bits_clear (pe, sram_next_off, MVPP2_PRS_SRAM_NEXT_LU_MASK);
  mv_pp2x_prs_sram_bits_set (pe, sram_next_off, lu);
}

static void
mv_pp2x_prs_sram_offset_set (struct mv_pp2x_prs_entry *pe, unsigned int type, int offset,
			     unsigned int op)
{
  /* Set sign */
  if (offset < 0)
    {
      mv_pp2x_prs_sram_bits_set (pe, MVPP2_PRS_SRAM_UDF_SIGN_BIT, 1);
      offset = 0 - offset;
    }
  else
    {
      mv_pp2x_prs_sram_bits_clear (pe, MVPP2_PRS_SRAM_UDF_SIGN_BIT, 1);
    }

  /* Set value */
  mv_pp2x_prs_sram_bits_clear (pe, MVPP2_PRS_SRAM_UDF_OFFS, MVPP2_PRS_SRAM_UDF_MASK);
  mv_pp2x_prs_sram_bits_set (pe, MVPP2_PRS_SRAM_UDF_OFFS, offset);
  pe->sram.byte[SRAM_BIT_TO_BYTE (MVPP2_PRS_SRAM_UDF_OFFS + MVPP2_PRS_SRAM_UDF_BITS)] &=
    ~(MVPP2_PRS_SRAM_UDF_MASK >> (8 - (MVPP2_PRS_SRAM_UDF_OFFS % 8)));
  pe->sram.byte[SRAM_BIT_TO_BYTE (MVPP2_PRS_SRAM_UDF_OFFS + MVPP2_PRS_SRAM_UDF_BITS)] |=
    (offset >> (8 - (MVPP2_PRS_SRAM_UDF_OFFS % 8)));

  /* Set offset type */
  mv_pp2x_prs_sram_bits_clear (pe, MVPP2_PRS_SRAM_UDF_TYPE_OFFS, MVPP2_PRS_SRAM_UDF_TYPE_MASK);
  mv_pp2x_prs_sram_bits_set (pe, MVPP2_PRS_SRAM_UDF_TYPE_OFFS, type);

  /* Set offset operation */
  mv_pp2x_prs_sram_bits_clear (pe, MVPP2_PRS_SRAM_OP_SEL_UDF_OFFS, MVPP2_PRS_SRAM_OP_SEL_UDF_MASK);
  mv_pp2x_prs_sram_bits_set (pe, MVPP2_PRS_SRAM_OP_SEL_UDF_OFFS, op);

  pe->sram
    .byte[SRAM_BIT_TO_BYTE (MVPP2_PRS_SRAM_OP_SEL_UDF_OFFS + MVPP2_PRS_SRAM_OP_SEL_UDF_BITS)] &=
    ~(MVPP2_PRS_SRAM_OP_SEL_UDF_MASK >> (8 - (MVPP2_PRS_SRAM_OP_SEL_UDF_OFFS % 8)));

  pe->sram
    .byte[SRAM_BIT_TO_BYTE (MVPP2_PRS_SRAM_OP_SEL_UDF_OFFS + MVPP2_PRS_SRAM_OP_SEL_UDF_BITS)] |=
    (op >> (8 - (MVPP2_PRS_SRAM_OP_SEL_UDF_OFFS % 8)));

  /* Set base offset as current */
  mv_pp2x_prs_sram_bits_clear (pe, MVPP2_PRS_SRAM_OP_SEL_BASE_OFFS, 1);
}

static void
mv_pp2x_prs_tcam_ai_update (struct mv_pp2x_prs_entry *pe, unsigned int bits, unsigned int enable)
{
  int i, ai_idx = MVPP2_PRS_TCAM_AI_BYTE;

  for (i = 0; i < MVPP2_PRS_AI_BITS; i++)
    {
      if (!(enable & BIT (i)))
	continue;

      if (bits & BIT (i))
	pe->tcam.byte[HW_BYTE_OFFS (ai_idx)] |= 1 << i;
      else
	pe->tcam.byte[HW_BYTE_OFFS (ai_idx)] &= ~(1 << i);
    }

  pe->tcam.byte[HW_BYTE_OFFS (MVPP2_PRS_TCAM_EN_OFFS (ai_idx))] |= enable;
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
  if (port->type == PP2_PPIO_T_NIC)
    {
      pp2_c2_config_default_queue (port, port->first_rxq);
      pp2_cls_mng_qos_tbl_dflt_set (port, port->first_rxq);
    }
}

static void
pp2_cls_mng_rss_port_init (struct pp2_port *port, u16 rss_map)
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

      /* Configure hash type only for MUSDK port at this point (flows for logical port are not
       * defined yet at this point, so hash type is configured later for logical ports
       */
      if (port->type == PP2_PPIO_T_NIC)
	{
	  rc = pp2_cls_rss_mode_flows_set (port, port->hash_type);
	  if (rc)
	    {
	      pr_err ("cannot set hash type in flows\n");
	      pr_err ("RSS is set to disabled\n");
	      port->rss_en = false;
	    }
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
pp2_cls_mng_rule_add (struct pp2_cls_tbl *tbl, struct pp2_cls_tbl_rule *rule,
		      struct pp2_cls_tbl_action *action, int lkp_type)
{
  struct pp2_cls_pkt_key_t pkt_key;
  struct pp2_cls_mng_pkt_key_t mng_pkt_key;
  struct mv_pp2x_src_port rule_port;
  struct pp2_port *port;
  struct pp2_inst *inst;
  u32 rc = 0, logic_idx;
  struct pp2_cls_tbl_params *params = &tbl->params;
  struct pp2_cls_tbl_rule *rule_db;
  struct pp2_cls_tbl_action *action_db;

  /* check table type */
  if (tbl->type != PP2_CLS_FLOW_TBL)
    {
      pr_err ("%s(%d) wrong table type inserted\n", __func__, __LINE__);
      return -EFAULT;
    }

  /* check if table exists in DB */
  rc = pp2_cls_db_mng_tbl_check (tbl);
  if (rc)
    {
      pr_err ("table not found in db\n");
      return -EIO;
    }

  /* check rule is not duplicated */
  rc = pp2_cls_db_mng_rule_check (tbl, rule);
  if (rc)
    {
      pr_warn ("duplicated rule, ignoring request\n");
      return -EEXIST;
    }

  /* init value */
  MVPP2_MEMSET_ZERO (pkt_key);
  MVPP2_MEMSET_ZERO (mng_pkt_key);
  mng_pkt_key.pkt_key = &pkt_key;

  port = GET_PPIO_PORT (params->default_act.cos->ppio);
  inst = port->parent;

  if (mv_pp2x_range_validate (rule->num_fields, 0, PP2_CLS_TBL_MAX_NUM_FIELDS))
    {
      pr_err ("%s(%d) fail, num_fields = %d is out of range\n", __func__, __LINE__,
	      rule->num_fields);
      return -EINVAL;
    }

  if (action->cos && mv_pp2x_range_validate (action->cos->tc, 0, port->num_tcs))
    {
      pr_err ("%s(%d) fail, tc = %d is out of range\n", __func__, __LINE__, action->cos->tc);
      return -EINVAL;
    }

  if ((action->type != PP2_CLS_TBL_ACT_DROP) && (action->type != PP2_CLS_TBL_ACT_DONE))
    {
      pr_err ("%s(%d) fail, action type = %d is out of range\n", __func__, __LINE__, action->type);
      return -EINVAL;
    }

  rc = pp2_cls_set_rule_info (&mng_pkt_key, &rule_port, params, rule, port);
  if (rc)
    {
      pr_err ("%s(%d) pp2_cls_set_rule_info failed\n", __func__, __LINE__);
      return rc;
    }

  if (params->type == PP2_CLS_TBL_MASKABLE)
    {
      struct mv_pp2x_c2_add_entry c2_entry;

      MVPP2_MEMSET_ZERO (c2_entry);
      c2_entry.mng_pkt_key = &mng_pkt_key;
      c2_entry.mng_pkt_key->pkt_key = &pkt_key;
      c2_entry.lkp_type = lkp_type;
      c2_entry.lkp_type_mask = MVPP2_C2_HEK_LKP_TYPE_MASK >> MVPP2_C2_HEK_LKP_TYPE_OFFS;
      c2_entry.rss_en = port->rss_en;
      pp2_cls_mng_set_c2_action (port, &c2_entry.qos_info, &c2_entry.qos_value, &c2_entry.action,
				 action, lkp_type);

      memcpy (&c2_entry.port, &rule_port, sizeof (rule_port));

      /* add rule */
      rc = pp2_cls_c2_rule_add (inst, &c2_entry, &logic_idx);
      if (rc)
	{
	  pr_err ("fail to add C2 rule\n");
	  return rc;
	}
      pr_debug ("Rule added in C2: logic_idx: %d\n", logic_idx);
    }
  else if (params->type == PP2_CLS_TBL_EXACT_MATCH)
    {
      struct pp2_cls_c3_add_entry_t c3_entry;

      if (action->flow_id != 0)
	{
	  pr_err ("Exact-match engine does not support flow_id action. Ignoring request\n");
	  return -EINVAL;
	}

      MVPP2_MEMSET_ZERO (c3_entry);
      c3_entry.mng_pkt_key = &mng_pkt_key;
      c3_entry.mng_pkt_key->pkt_key = &pkt_key;
      c3_entry.lkp_type = lkp_type;
      c3_entry.rss_en = port->rss_en;
      pp2_cls_mng_set_c3_action (port, &c3_entry.qos_info, &c3_entry.qos_value, &c3_entry.action,
				 action, lkp_type);

      memcpy (&c3_entry.port, &rule_port, sizeof (rule_port));

      /* add rule */
      rc = pp2_cls_c3_rule_add (inst, &c3_entry, &logic_idx);
      if (rc)
	{
	  pr_err ("fail to add C3 rule\n");
	  return rc;
	}
      pr_debug ("Rule added in C3: logic_idx: %d\n", logic_idx);
    }
  else
    {
      pr_err ("%s(%d) unknown engine type!\n", __func__, __LINE__);
      return -EINVAL;
    }
  /* Update database */
  rc = pp2_cls_db_mng_tbl_rule_add (tbl, &rule_db, logic_idx, &action_db);
  if (rc)
    return -EFAULT;

  rc = pp2_cls_mng_rule_update_db (rule, rule_db, action, action_db);
  if (rc)
    return -EFAULT;

  if (action->plcr)
    {
      rc = pp2_cls_plcr_ref_cnt_update (inst, action->plcr->id, MVPP2_PLCR_REF_CNT_INC, false);
      if (rc)
	return -EFAULT;
    }

  return 0;
}

static int
pp2_cls_rss_mode_flows_set (struct pp2_port *port, int rss_mode)
{
  int lkpid, lkpid_attr;
  struct pp2_inst *inst = port->parent;
  struct pp2_cls_fl_rule_list_t *fl_rls_hash;
  enum musdk_lnx_id lnx_id = lnx_id_get ();

  if (rss_mode == PP2_PPIO_HASH_T_NONE)
    return 0;

  fl_rls_hash = clib_mem_alloc_or_null ((sizeof (*fl_rls_hash)));
  if (!fl_rls_hash)
    return -ENOMEM;

  int lkp_type = (port->type == PP2_PPIO_T_LOG) ? MVPP2_CLS_LKP_MUSDK_LOG_HASH : MVPP2_CLS_LKP_HASH;

  for (lkpid = MVPP2_PRS_FL_START; lkpid < MVPP2_PRS_FL_LAST; lkpid++)
    {
      /* Get lookup id attribute */
      lkpid_attr = mv_pp2x_prs_flow_id_attr_get (lkpid);
      if ((lkpid_attr & (MVPP2_PRS_FL_ATTR_TCP_BIT | MVPP2_PRS_FL_ATTR_UDP_BIT)) &&
	  !(lkpid_attr & MVPP2_PRS_FL_ATTR_FRAG_BIT))
	{
	  if (rss_mode == PP2_PPIO_HASH_T_2_TUPLE)
	    {
	      /* For backwards compatibility to LK 4.4 */
	      if (!(lnx_is_mainline (lnx_id) && (lkp_type == MVPP2_CLS_LKP_HASH)))
		{
		  pp2_cls_set_hash_params (fl_rls_hash, port, MVPP2_CLS_ENGINE_C3HA, lkpid,
					   lkpid_attr, true);
		  pp2_cls_fl_rule_enable (inst, fl_rls_hash);
		  pp2_cls_set_hash_params (fl_rls_hash, port, MVPP2_CLS_ENGINE_C3HB, lkpid,
					   lkpid_attr, false);
		  pp2_cls_fl_rule_enable (inst, fl_rls_hash);
		}
	    }
	  else if (rss_mode == PP2_PPIO_HASH_T_5_TUPLE)
	    {
	      /* For backwards compatibility to LK 4.4 */
	      if (!(lnx_is_mainline (lnx_id) && (lkp_type == MVPP2_CLS_LKP_HASH)))
		{
		  pp2_cls_set_hash_params (fl_rls_hash, port, MVPP2_CLS_ENGINE_C3HA, lkpid,
					   lkpid_attr, false);
		  pp2_cls_fl_rule_enable (inst, fl_rls_hash);
		  pp2_cls_set_hash_params (fl_rls_hash, port, MVPP2_CLS_ENGINE_C3HB, lkpid,
					   lkpid_attr, true);
		  pp2_cls_fl_rule_enable (inst, fl_rls_hash);
		}
	    }
	  else
	    {
	      pr_err ("%s(%d), unknown rss mode\n", __func__, __LINE__);
	      if (fl_rls_hash)
		clib_mem_free (fl_rls_hash);
	      return -EINVAL;
	    }
	}
      else if (lkpid_attr & (MVPP2_PRS_FL_ATTR_IP4_BIT | MVPP2_PRS_FL_ATTR_IP6_BIT))
	{
	  /* For backwards compatibility to LK 4.4 */
	  if (!(lnx_is_mainline (lnx_id) && (lkp_type == MVPP2_CLS_LKP_HASH)))
	    {
	      pp2_cls_set_hash_params (fl_rls_hash, port, MVPP2_CLS_ENGINE_C3HA, lkpid, lkpid_attr,
				       true);
	      pp2_cls_fl_rule_enable (inst, fl_rls_hash);
	    }
	}
    }

  if (fl_rls_hash)
    clib_mem_free (fl_rls_hash);
  return 0;
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
  enum musdk_lnx_id lnx_id = lnx_id_get ();

  if (!netdev_params)
    return -EFAULT;

  num_inst = pp2_get_num_inst ();

  for (i = 0, cp110_num = 0; i < num_inst; i++, cp110_num++)
    {
      err = -1;
      while (cp110_num < PP2_MAX_NUM_PACKPROCS)
	{
	  if (lnx_id == LNX_4_4_x || lnx_id == LNX_4_14_x)
	    sprintf (cp110path, pp2_frm[lnx_id].devtree_path, cp110_num);
	  else
	    sprintf (cp110path, pp2_frm[lnx_id].devtree_path, cp110_num,
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
	  if (lnx_id == LNX_4_4_x)
	    sprintf (subpath, pp2_frm[lnx_id].eth_format, j, j + 1);
	  else
	    sprintf (subpath, pp2_frm[lnx_id].eth_format, j);
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
pp2_port_close_uio (struct pp2_port *port)
{
  int err;

  err = close (port->uio_port.fd);
  if (err < 0)
    pr_err (" Could not close file (%s)\n", strerror (errno));
  port->uio_port.fd = -1;
  return err;
}

static int
pp2_port_config_txsched (struct pp2_port *port)
{
  int rc, txq;
  u8 remapped_weights[MVPP2_MAX_TXQ];

  /* Store hardware state */

  /* Set port MTU (which is used later in the initialization) */
  pp2_port_txsched_set_mtu (port);

  /* Set port rate limit and burst size */
  rc = pp2_txsched_port_rate_set (port, port->rate_limit_params.cir);
  if (rc)
    return rc;

  rc = pp2_txsched_port_burst_set (port, port->rate_limit_params.cbs * 1024);
  if (rc)
    return rc;

  pp2_txsched_remap_weights (port, remapped_weights);

  /* Set txq rate limits, burst sizes, arbitration mode and WRR weight */
  for (txq = 0; txq < port->num_tx_queues; txq++)
    { /* This only works in logical ports post reprioritization */

      rc = pp2_txsched_queue_rate_set (port, txq, port->txq_config[txq].rate_limit_params.cir);
      if (rc)
	return rc;

      rc =
	pp2_txsched_queue_burst_set (port, txq, port->txq_config[txq].rate_limit_params.cbs * 1024);
      if (rc)
	return rc;

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
pp2_prs_create_log_port_entry (struct pp2_port *port, u32 index, enum pp2_ppio_cls_target target)
{
  struct pp2_inst *inst = port->parent;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);
  u32 ri = 0;
  struct mv_pp2x_prs_entry pe_orig, pe_log_port;
  int tid;

  /* create a new MH entry for the specified port and set UDF7 to log_port */
  memset (&pe_orig, 0, sizeof (struct mv_pp2x_prs_entry));
  memset (&pe_log_port, 0, sizeof (struct mv_pp2x_prs_entry));

  /* Read pe from HW */
  pe_orig.index = index;
  mv_pp2x_prs_hw_read (cpu_slot, &pe_orig);

  memcpy (&pe_log_port, &pe_orig, sizeof (struct mv_pp2x_prs_entry));

  /* Find first empty slot in TCAM */
  tid = pp2_prs_tcam_first_free (inst, MVPP2_PE_FIRST_FREE_TID, MVPP2_PE_LAST_FREE_TID);
  if (tid < 0)
    return tid;

  /* Update ri and ri_mask */
  pe_log_port.index = tid;

  if (target == PP2_CLS_TARGET_LOCAL_PPIO)
    ri = MVPP2_PRS_RI_UDF7_LOG_PORT;
  else
    ri = MVPP2_PRS_RI_UDF7_NIC;

  mv_pp2x_prs_sram_ri_update (&pe_log_port, ri, MVPP2_PRS_RI_UDF7_MASK);

  /* Mask all ports */
  mv_pp2x_prs_tcam_port_map_set (&pe_log_port, 0);

  /* Update port mask */
  mv_pp2x_prs_tcam_port_set (&pe_log_port, port->id, true);

  pr_debug ("target %d, ri %x\n", target, ri);

  /* Update shadow table and hw entry for new entry*/
  mv_pp2x_prs_shadow_set (inst, pe_log_port.index, mv_pp2x_prs_tcam_lu_get (&pe_log_port));
  mv_pp2x_prs_shadow_ri_set (inst, pe_log_port.index, ri, MVPP2_PRS_RI_UDF7_MASK);
  mv_pp2x_prs_hw_write (cpu_slot, &pe_log_port);

  /* update port mask of existing non-logical entry */
  mv_pp2x_prs_tcam_port_set (&pe_orig, port->id, false);

  /* write entry to HW */
  mv_pp2x_prs_hw_write (cpu_slot, &pe_orig);

  return 0;
}

static int
pp2_prs_log_port_proto_update (struct pp2_port *port, enum pp2_ppio_cls_target target)
{
  int i;
  struct pp2_inst *inst = port->parent;
  struct prs_log_port_tcam_node tcam_match_node;

  for (i = 0; i < pp2_cls_db_prs_match_list_num_get (inst); i++)
    {
      pp2_cls_db_prs_match_list_idx_get (inst, i, &tcam_match_node);

      if (tcam_match_node.log_port == 0)
	pp2_prs_create_log_port_entry (port, tcam_match_node.idx, target);
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
  mv_pp2x_prs_tcam_port_set (&pe, port->id, add);

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
  tx_port_num = MVPP2_MAX_TCONT + port->id;
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  pp2_reg_write (cpu_slot, MVPP2_TXP_SCHED_CMD_1_REG, 0x0);

  /* Close bandwidth for all queues */
  for (queue = 0; queue < MVPP2_MAX_TXQ; queue++)
    {
      ptxq = (MVPP2_MAX_TCONT + port->id) * MVPP2_MAX_TXQ + queue;
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
  pp2_reg_write (cpu_slot, MVPP2_RX_CTRL_REG (port->id),
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
  if (port->stats_name)
    clib_mem_free (port->stats_name);
  /* Restore rate limits and arbitration to original state */
  pp2_port_deinit_txsched (port);

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
  pp2_gop_gmac_max_rx_size_set (gop, mac_num, port->port_mru);
  if ((mac_num == 0) || ((mac_num == 2) && (pp2_version == MVPP2_VER_PP23)))
    pp2_gop_xlg_mac_max_rx_size_set (gop, mac_num, port->port_mru);
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
	  rxq->mem = port->tc[tc].rx_qs[qid].mem;

	  tmp_bpool_id = tc_cfg->pools[mem_index][BM_TYPE_SHORT_BUF_POOL]->bm_pool_id;
	  rxq->bm_pool_id[BM_TYPE_SHORT_BUF_POOL] = tmp_bpool_id;

	  tmp_bpool_id = tc_cfg->pools[mem_index][BM_TYPE_LONG_BUF_POOL]->bm_pool_id;
	  rxq->bm_pool_id[BM_TYPE_LONG_BUF_POOL] = tmp_bpool_id;

	  pr_debug ("pp2_port_rxqs_create: port[%d:%d] tc%d rxq%d mem_index(%d)\n",
		    port->parent->id, port->id, tc, rxq->id, mem_index);

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
  int tx_port_num = MVPP2_MAX_TCONT + port->id;
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
		  pr_warn ("Port%u: TXQ=%u clean timed out\n", port->id, txq->log_id);
		  break;
		}
	      /* Sleep for 1 microsecond */
	      udelay (1);
	      delay++;
	      pending = pp2_txq_pend_desc_num_get (port, txq);
	      pr_debug ("pp2_txq_clean: Port%u: TXQ=%u pending: %d\n", port->id, txq->log_id,
			pending);
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

      txq->id = (MVPP2_MAX_TCONT + port->id) * MVPP2_MAX_TXQ + qid;
      txq->log_id = qid;
      port->txqs[qid] = txq;
    }
}

static void
pp2_txq_init (struct pp2_port *port, struct pp2_tx_queue *txq)
{
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
  txq->desc_virt_arr = mv_sys_dma_mem_region_alloc (
    port->tx_qs_mem, (txq->desc_total * MVPP2_DESC_ALIGNED_SIZE), MVPP2_DESC_Q_ALIGN);
  if (unlikely (!txq->desc_virt_arr))
    {
      pr_err ("PP: cannot allocate egress descriptor array\n");
      return;
    }
  txq->desc_phys_arr =
    (uintptr_t) mv_sys_dma_mem_region_virt2phys (port->tx_qs_mem, txq->desc_virt_arr);
  if (!IS_ALIGNED (txq->desc_phys_arr, MVPP2_DESC_Q_ALIGN))
    {
      pr_err ("PP: egress descriptor array must be %u-byte aligned\n", MVPP2_DESC_Q_ALIGN);
      mv_sys_dma_mem_region_free (port->tx_qs_mem, txq->desc_virt_arr);
      return;
    }

  pr_debug ("port[%d:%d] tx desc_phys_addr(0x%lx)\n", port->parent->id, port->id,
	    txq->desc_phys_arr);

  /* Set Tx descriptors queue starting address - indirect access */
  pp2_reg_write (cpu_slot, MVPP2_TXQ_NUM_REG, txq->id);
  pp2_reg_write (cpu_slot, MVPP2_TXQ_DESC_ADDR_LOW_REG,
		 ((uint32_t) txq->desc_phys_arr) >> MVPP2_TXQ_DESC_ADDR_LOW_SHIFT);
  pp2_reg_write (cpu_slot, MVPP22_TXQ_DESC_ADDR_HIGH_REG, 0x00 & MVPP22_TXQ_DESC_ADDR_HIGH_MASK);
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
  desc = (port->id * MVPP2_MAX_TXQ * PP2_ETH_PORT_TXQ_PREFETCH) + (txq->log_id * desc_per_txq);

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

  memset (&txq->stats, 0, sizeof (txq->stats));
  txq->threshold_tx_pkts = 0;
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
mv_pp2x_prs_flow_id_attr_get (int flow_id)
{
  return mv_pp2x_prs_flow_id_attr_tbl[flow_id];
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

      if (c2.inv != 0 || port_id != (1 << port->id))
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
pp2_cls_c2_rule_add (struct pp2_inst *inst, struct mv_pp2x_c2_add_entry *c2_entry,
		     u32 *c2_logic_index)
{
  int ret_code;
  u32 c2_db_idx, c2_logic_idx, c2_hw_idx = 0;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  /* Parameter check */
  ret_code = pp2_cls_c2_rule_add_check (c2_entry);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }
  if (!c2_logic_index)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  /* Make C2 slot */
  ret_code = pp2_cls_c2_make_slot (inst, c2_entry->lkp_type, c2_entry->priority, &c2_hw_idx);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Write TCAM */
  ret_code = pp2_cls_c2_tcam_set (cpu_slot, c2_entry, c2_hw_idx);
  if (ret_code != 0)
    {
      /* Return slot to free list */
      pp2_cls_c2_free_list_add (inst, c2_hw_idx);
      pr_err ("C2 TCAM(%d) set failed\n", c2_hw_idx);
      return ret_code;
    }

  /* Update MVPP2 DB */
  ret_code = pp2_cls_c2_data_entry_db_add (inst, c2_entry, &c2_db_idx);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Allocate logical index for delete */
  c2_logic_idx = pp2_cls_c2_new_logic_idx_allocate (false);

  /* Update corresponding lookup type list */
  ret_code = pp2_cls_c2_lkp_type_list_add (inst, c2_entry->lkp_type, c2_entry->priority, c2_hw_idx,
					   c2_db_idx, c2_logic_idx);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Return logic index */
  *c2_logic_index = c2_logic_idx;

  return 0;
}

static int
pp2_cls_c3_rule_add (struct pp2_inst *inst, struct pp2_cls_c3_add_entry_t *c3_entry, u32 *logic_idx)
{
  u32 l_logic_idx;
  u32 hash_idx;
  struct pp2_cls_c3_entry c3;
  u32 max_search_depth;
  struct pp2_cls_c3_hash_pair hash_pair_arr;
  int rc = 0;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);
#ifdef PP2_CLS_C3_DEBUG
  int idx;
#endif

  pr_debug ("reached\n");

  /* validation */
  if (mv_pp2x_ptr_validate (c3_entry))
    return -EINVAL;

  if (mv_pp2x_ptr_validate (logic_idx))
    return -EINVAL;

  /* check C3 rule */
  rc = pp2_cls_c3_rule_check (c3_entry);
  if (rc)
    {
      pr_err ("failed to check C3 entry\n");
      return rc;
    }

  /* convert the C3 mng entry to LSP entry */
  pp2_cls_c3_sw_clear (&c3);
  rc = pp2_cls_c3_rule_convert (c3_entry, &c3);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_rule_convert\n");
      return rc;
    }

#ifdef PP2_CLS_C3_DEBUG
  pp2_cls_c3_sw_dump (&c3);
#endif

  /* get free logical index, also check whether there is an available entry */
  rc = pp2_cls_db_c3_free_logic_idx_get (inst, &l_logic_idx);
  if (rc)
    {
      pr_err ("failed to get free logical index\n");
      return rc;
    }

  *logic_idx = l_logic_idx;

  /* add C3 entry */
  rc = pp2_cls_db_c3_search_depth_get (inst, &max_search_depth);
  if (rc)
    {
      pr_err ("fail to get PP2_CLS C3 max search depth\n");
      return rc;
    }
  MVPP2_MEMSET_ZERO (hash_pair_arr);

#ifdef PP2_CLS_C3_DEBUG
  pr_debug ("C3 HEK %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n", c3.key.hek.bytes[35],
	    c3.key.hek.bytes[34], c3.key.hek.bytes[33], c3.key.hek.bytes[32], c3.key.hek.bytes[31],
	    c3.key.hek.bytes[30], c3.key.hek.bytes[29], c3.key.hek.bytes[28]);
#endif
  rc = pp2_cls_c3_hw_query_add (cpu_slot, &c3, max_search_depth, &hash_pair_arr);
  /* do not need to release logic index since it is still not occuppied */
  if (rc)
    {
      pr_err ("failed to add C3 entry to HW\n");
      return rc;
    }
  hash_idx = c3.index;

  /* update C3 DB multihash index */
#ifdef PP2_CLS_C3_DEBUG
  if (hash_pair_arr.pair_num)
    {
      pr_debug ("hash pair number=%d\n", hash_pair_arr.pair_num);
      for (idx = 0; idx < hash_pair_arr.pair_num; idx++)
	pr_debug ("hash pair(%d) %x-->%x\n", idx, hash_pair_arr.old_idx[idx],
		  hash_pair_arr.new_idx[idx]);
    }
#endif
  rc = pp2_cls_db_c3_hash_idx_update (inst, &hash_pair_arr);
  if (rc)
    {
      pr_err ("failed to update C3 multihash index\n");
      return rc;
    }

  /* save to DB */
  rc = pp2_cls_db_c3_entry_add (inst, l_logic_idx, hash_idx);
  if (rc)
    {
      pr_err ("failed to add C3 entry to DB\n");
      return rc;
    }

  return 0;
}

static int
pp2_cls_db_mng_rule_check (struct pp2_cls_tbl *tbl, struct pp2_cls_tbl_rule *rule)
{
  struct pp2_cls_tbl_node *tbl_node;
  struct pp2_cls_rule_node *rule_node;
  u32 i;
  int duplicated;

  LIST_FOR_EACH_OBJECT (tbl_node, struct pp2_cls_tbl_node, &mng_db->pp2_cls_tbl_head, list_node)
  {
    if (&tbl_node->tbl == tbl)
      {
	LIST_FOR_EACH_OBJECT (rule_node, struct pp2_cls_rule_node, &tbl_node->pp2_cls_tbl_rule_head,
			      list_node)
	{
	  pr_debug ("num_fields %d %d\n", rule_node->rule.num_fields, rule->num_fields);
	  if (rule_node->rule.num_fields != rule->num_fields)
	    continue;

	  duplicated = 1;
	  for (i = 0; i < rule_node->rule.num_fields; i++)
	    {
	      pr_debug ("size %d key %s, mask %s\n", rule_node->rule.fields[i].size,
			rule_node->rule.fields[i].key, rule_node->rule.fields[i].mask);
	      pr_debug ("size %d key %s, mask %s\n", rule->fields[i].size, rule->fields[i].key,
			rule->fields[i].mask);
	      if ((rule_node->rule.fields[i].size != rule->fields[i].size) ||
		  (strcmp ((char *) rule_node->rule.fields[i].key, (char *) rule->fields[i].key) !=
		   0) ||
		  (strcmp ((char *) rule_node->rule.fields[i].mask,
			   (char *) rule->fields[i].mask) != 0))
		{
		  duplicated = 0;
		  break;
		}
	    }
	  if (duplicated == 1)
	    return 1;
	}
      }
  }
  return 0;
}

static int
pp2_cls_db_mng_tbl_check (struct pp2_cls_tbl *tbl)
{
  struct pp2_cls_tbl_node *tbl_node;

  LIST_FOR_EACH_OBJECT (tbl_node, struct pp2_cls_tbl_node, &mng_db->pp2_cls_tbl_head, list_node)
  {
    if (&tbl_node->tbl == tbl)
      return 0;
  }
  return -EFAULT;
}

static int
pp2_cls_db_mng_tbl_rule_add (struct pp2_cls_tbl *tbl, struct pp2_cls_tbl_rule **rule,
			     u32 logic_index, struct pp2_cls_tbl_action **action)
{
  struct pp2_cls_tbl_node *tbl_node;
  struct pp2_cls_rule_node *rule_node;

  LIST_FOR_EACH_OBJECT (tbl_node, struct pp2_cls_tbl_node, &mng_db->pp2_cls_tbl_head, list_node)
  {
    if (&tbl_node->tbl == tbl)
      {
	rule_node = clib_mem_alloc_or_null (sizeof (*rule_node));
	if (!rule_node)
	  {
	    pr_err ("%s: null pointer\n", __func__);
	    return -ENOMEM;
	  }
	*rule = &rule_node->rule;
	*action = &rule_node->action;
	rule_node->logic_index = logic_index;
	list_add_to_tail (&rule_node->list_node, &tbl_node->pp2_cls_tbl_rule_head);
	return 0;
      }
  }
  return -EFAULT;
}

static int
pp2_cls_db_prs_match_list_idx_get (struct pp2_inst *inst, u32 index,
				   struct prs_log_port_tcam_node *node)
{
  int i = 0;
  struct prs_log_port_tcam_node *tcam_match_node;

  LIST_FOR_EACH_OBJECT (tcam_match_node, struct prs_log_port_tcam_node,
			&inst->cls_db->prs_db.tcam_match_list, list_node)
  {
    if (i == index)
      {
	node->idx = tcam_match_node->idx;
	node->log_port = tcam_match_node->log_port;
	pr_debug ("%d, index %d, log_port %d\n", i, node->idx, node->log_port);
	return 1;
      }
    i++;
  }

  return 0;
}

static int
pp2_cls_db_prs_match_list_num_get (struct pp2_inst *inst)
{
  return list_num_objs (&inst->cls_db->prs_db.tcam_match_list);
}

static int
pp2_cls_fl_rule_enable (struct pp2_inst *inst, struct pp2_cls_fl_rule_list_t *fl_rls)
{
  u16 rl_off, i;
  struct pp2_db_cls_lkp_dcod_t lkp_dcod_db;
  struct pp2_db_cls_fl_rule_list_t *fl_rl_db; /*use heap to reduce stack size*/
  struct pp2_cls_fl_rule_entry_t *rl_en;
  struct pp2_db_cls_fl_rule_t *rl_db = NULL;
  int rc;
  int loop;
  u16 port_bm = 0;
  u16 fl_rls_port_bm;

  if (!fl_rls)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  fl_rl_db = clib_mem_alloc_or_null (sizeof (*fl_rl_db));
  if (!fl_rl_db)
    return -ENOMEM;

  /* iterate over all rule list */
  for (i = 0; i < fl_rls->fl_len; i++)
    {
      /* get the lookup DB for this logical flow ID */
      rc = pp2_db_cls_lkp_dcod_get (inst, fl_rls->fl[i].fl_log_id, &lkp_dcod_db);
      if (rc)
	{
	  pr_err ("failed to get lookup decode DB data for fl_log_id %d\n",
		  fl_rls->fl[i].fl_log_id);
	  return rc;
	}

      /* get all rules for this logical flow ID */
      memset (fl_rl_db, 0, sizeof (struct pp2_db_cls_fl_rule_list_t));
      rc = pp2_db_cls_fl_rule_list_get (inst, lkp_dcod_db.flow_off, lkp_dcod_db.flow_len,
					&fl_rl_db->flow[0]);
      if (rc)
	{
	  pr_err ("failed to get flow rule list, fl_log_id=%d flow_off=%d flow_len=%d\n",
		  fl_rls->fl[i].fl_log_id, lkp_dcod_db.flow_off, lkp_dcod_db.flow_len);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}

      /* set the flow length in the DB entry */
      fl_rl_db->flow_len = lkp_dcod_db.flow_len;

      rl_en = &fl_rls->fl[i];

      /* search for enabled rule (valid port_type and port_bm) to enable */
      for (rl_off = 0; rl_off < fl_rl_db->flow_len; rl_off++)
	{
	  rl_db = &fl_rl_db->flow[rl_off];
	  if (rl_en->engine == rl_db->engine && rl_en->field_id_cnt == rl_db->field_id_cnt &&
	      rl_en->lu_type == rl_db->lu_type && rl_en->port_type == rl_db->port_type &&
	      rl_en->prio == rl_db->prio && rl_en->udf7 == rl_db->udf7 &&
	      !memcmp (rl_en->field_id, rl_db->field_id,
		       rl_en->field_id_cnt * sizeof (rl_en->field_id[0])))
	    {
	      /* for virt port, port_id does not matter */
	      if (rl_en->port_type != MVPP2_SRC_PORT_TYPE_VIR)
		{
		  int read_port_bm;

		  rc = pp2_cls_fl_port_hw_read (inst, rl_db->rl_log_id, &read_port_bm);
		  if (rc)
		    {
		      pr_err ("recvd ret_code(%d)\n", rc);
		      if (fl_rl_db)
			clib_mem_free (fl_rl_db);
		      return rc;
		    }
		  if (rl_en->enabled)
		    rl_db->port_bm = read_port_bm | rl_en->port_bm;
		  else
		    rl_db->port_bm = read_port_bm & (~rl_en->port_bm);
		  port_bm = rl_db->port_bm;

		  if (!rl_db->enabled)
		    {
		      MVPP2_MEMSET_ZERO (rl_db->ref_cnt);
		      rl_db->enabled = true;
		    }
		  fl_rls_port_bm = rl_en->port_bm;

		  rl_en->port_bm = rl_db->port_bm;
		  /* Update Port BM */
		  rl_en->rl_log_id = rl_db->rl_log_id;
		  rc = pp2_cls_fl_rl_hw_ena (inst, rl_en);
		  if (rc)
		    {
		      pr_err ("recvd ret_code(%d)\n", rc);
		      if (fl_rl_db)
			clib_mem_free (fl_rl_db);
		      return rc;
		    }
		  /* restore rl_en value */
		  rl_en->port_bm = fl_rls_port_bm;
		  /* update the logical rule id */
		  rl_en->rl_log_id = rl_db->rl_log_id;
		}
	      break;
	    }
	}

      /* verify that we found a rule */
      if (rl_off == fl_rl_db->flow_len)
	{
	  pr_err ("failed to find flow rule #%d to enable\n", i);
	  pr_err ("fl_id(%d),port_type(%d),port_bm(%d),", fl_rls->fl[i].fl_log_id,
		  fl_rls->fl[i].port_type, fl_rls->fl[i].port_bm);
	  pr_err ("prio(%d),lu_type(%d),engine(%d),udf7(%d),field_id_cnt(%d)", fl_rls->fl[i].prio,
		  fl_rls->fl[i].lu_type, fl_rls->fl[i].engine, fl_rls->fl[i].udf7,
		  fl_rls->fl[i].field_id_cnt);
	  pr_err ("field_id_0(%x), field_id_1(%x),field_id_2(%x),field_id_3(%x)\n",
		  fl_rls->fl[i].field_id[0], fl_rls->fl[i].field_id[1], fl_rls->fl[i].field_id[2],
		  fl_rls->fl[i].field_id[3]);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return -EFAULT;
	}

      /* update the logical rule id */
      rl_en->rl_log_id = rl_db->rl_log_id;

      /* found the rule we searched for */
      if (!rl_db->enabled)
	{
	  u16 fl_rls_port_bm = rl_en->port_bm;
	  u16 fl_rls_log_id = rl_en->rl_log_id;

	  MVPP2_MEMSET_ZERO (rl_db->ref_cnt);
	  rl_db->enabled = true;
	  if (rl_en->enabled)
	    rl_db->port_bm |= rl_en->port_bm;
	  else
	    rl_db->port_bm &= ~rl_en->port_bm;
	  rl_en->port_bm = rl_db->port_bm;
	  rl_en->rl_log_id = rl_db->rl_log_id;
	  /* rule disabled, enable the HW */
	  rc = pp2_cls_fl_rl_hw_ena (inst, rl_en);
	  if (rc)
	    {
	      pr_err ("recvd ret_code(%d)\n", rc);
	      if (fl_rl_db)
		clib_mem_free (fl_rl_db);
	      return rc;
	    }
	  /* restore rl_en value */
	  rl_en->port_bm = fl_rls_port_bm;
	  rl_en->rl_log_id = fl_rls_log_id;
	}

      /* increment the reference counter */
      for (loop = 0; loop < PP2_NUM_PORTS; loop++)
	{
	  if (1 << loop & port_bm)
	    rl_db->ref_cnt[loop]++;
	}

      pr_debug ("enable: fl_log_id[%d] rl_log_id[%d] rl_off[%d] port_type[%d] port_bm[%d]",
		fl_rls->fl[i].fl_log_id, rl_en->rl_log_id, rl_off, fl_rls->fl[i].port_type,
		fl_rls->fl[i].port_bm);
      pr_debug ("prio[%d] lu_type[%d] engine[%d] udf7[%d] field_id_cnt[%d]\n", fl_rls->fl[i].prio,
		fl_rls->fl[i].lu_type, fl_rls->fl[i].engine, fl_rls->fl[i].udf7,
		fl_rls->fl[i].field_id_cnt);

      /* update the DB */
      rc = pp2_db_cls_fl_rule_set (inst, lkp_dcod_db.flow_off + rl_off, rl_db);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  if (fl_rl_db)
	    clib_mem_free (fl_rl_db);
	  return rc;
	}
    }

  if (fl_rl_db)
    clib_mem_free (fl_rl_db);
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
pp2_cls_mng_rule_update_db (struct pp2_cls_tbl_rule *rule, struct pp2_cls_tbl_rule *rule_db,
			    struct pp2_cls_tbl_action *action, struct pp2_cls_tbl_action *action_db)
{
  u8 *key, *mask;
  u32 i;

  rule_db->num_fields = rule->num_fields;

  for (i = 0; i < rule->num_fields; i++)
    {
      rule_db->fields[i].size = rule->fields[i].size;
      key = clib_mem_alloc_or_null (CLS_MNG_KEY_SIZE_MAX);
      if (!key)
	{
	  pr_err ("no mem for HEK in DB!\n");
	  return -ENOMEM;
	}
      memcpy (key, rule->fields[i].key, CLS_MNG_KEY_SIZE_MAX);
      rule_db->fields[i].key = key;

      mask = clib_mem_alloc_or_null (CLS_MNG_KEY_SIZE_MAX);
      if (!mask)
	{
	  if (key)
	    clib_mem_free (key);
	  pr_err ("no mem for HEK in DB!\n");
	  return -ENOMEM;
	}
      memcpy (mask, rule->fields[i].mask, CLS_MNG_KEY_SIZE_MAX);
      rule_db->fields[i].mask = mask;
    }
  action_db->plcr = action->plcr;
  action_db->cos = NULL;
  if (action->cos)
    {
      action_db->cos = clib_mem_alloc_or_null (sizeof (*action_db->cos));
      if (!action_db->cos)
	return -ENOMEM;
      action_db->cos->tc = action->cos->tc;
      action_db->cos->override_color = action->cos->override_color;
      action_db->cos->pkt_color = action->cos->pkt_color;
    }

  action_db->type = action->type;
  return 0;
}

static void
pp2_cls_mng_set_c2_action (struct pp2_port *port, struct mv_pp2x_engine_qos_info *qos_info,
			   struct mv_pp2x_qos_value *pkt_qos,
			   struct mv_pp2x_engine_pkt_action *pkt_action,
			   struct pp2_cls_tbl_action *action, int lkp_type)
{
  u8 queue;
  u8 tc_array[MVPP2_QOS_TBL_LINE_NUM_DSCP] = { 0 };

  if (action->type == PP2_CLS_TBL_ACT_DROP)
    pkt_action->color_act = MVPP2_COLOR_ACTION_TYPE_RED_LOCK;
  else if (action->cos)
    {
      int pkt_action_color;

      if (action->cos->override_color)
	pkt_action_color = action->cos->pkt_color;
      else
	pkt_action_color = port->tc[action->cos->tc].tc_config.default_color;

      switch (pkt_action_color)
	{
	case PP2_PPIO_COLOR_GREEN:
	  pkt_action->color_act = MVPP2_COLOR_ACTION_TYPE_GREEN_LOCK;
	  break;
	case PP2_PPIO_COLOR_YELLOW:
	  pkt_action->color_act = MVPP2_COLOR_ACTION_TYPE_YELLOW_LOCK;
	  break;
	case PP2_PPIO_COLOR_RED:
	  pkt_action->color_act = MVPP2_COLOR_ACTION_TYPE_RED_LOCK;
	  break;
	}
    }
  else
    {
      pkt_action->color_act = MVPP2_COLOR_ACTION_TYPE_NO_UPDT;
    }
  pkt_action->policer_act = MVPP2_ACTION_TYPE_NO_UPDT;
  pkt_action->flowid_act = MVPP2_ACTION_FLOWID_DISABLE;
  pkt_action->frwd_act = MVPP2_ACTION_TYPE_NO_UPDT;
  pkt_action->rss_act = MVPP2_ACTION_TYPE_UPDT_LOCK;
  pkt_action->gemp_act = MVPP2_ACTION_TYPE_UPDT_LOCK;

  if (action->plcr)
    {
      pkt_action->policer_act = MVPP2_ACTION_TYPE_UPDT_LOCK;
      qos_info->policer_id = action->plcr->id;
    }

  /* for qos rules (only activated when logical port is initialized) */
  if (lkp_type == MVPP2_CLS_LKP_MUSDK_DSCP_PRI || lkp_type == MVPP2_CLS_LKP_MUSDK_VLAN_PRI)
    {
      u8 tbl_sel;

      if (lkp_type == MVPP2_CLS_LKP_MUSDK_VLAN_PRI)
	tbl_sel = MVPP2_QOS_TBL_SEL_PRI;
      else if (lkp_type == MVPP2_CLS_LKP_MUSDK_DSCP_PRI)
	tbl_sel = MVPP2_QOS_TBL_SEL_DSCP;

      qos_info->qos_tbl_index = QOS_LOG_PORT_TABLE_OFF (port->id);
      qos_info->q_low_src = MVPP2_QOS_SRC_DSCP_PBIT_TBL;
      qos_info->q_high_src = MVPP2_QOS_SRC_DSCP_PBIT_TBL;
      qos_info->color_src = MVPP2_QOS_SRC_DSCP_PBIT_TBL;
      qos_info->qos_tbl_type = tbl_sel;
      pkt_action->q_low_act = MVPP2_ACTION_TYPE_UPDT_LOCK;
      pkt_action->q_high_act = MVPP2_ACTION_TYPE_UPDT_LOCK;

      mv_pp2x_cls_c2_qos_tbl_fill_array (port, tbl_sel, tc_array);
    }
  else
    {
      /* for classifier and default rules */
      pkt_qos->gemp = action->flow_id;
      qos_info->gemport_src = MVPP2_QOS_SRC_ACTION_TBL;
      if (action->cos)
	{
	  pkt_action->q_low_act = MVPP2_ACTION_TYPE_UPDT_LOCK;
	  pkt_action->q_high_act = MVPP2_ACTION_TYPE_UPDT_LOCK;
	  queue = port->tc[action->cos->tc].tc_config.first_rxq;
	  pkt_qos->q_high = ((u16) queue) >> MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS;
	  pkt_qos->q_low = ((u16) queue) & ((1 << MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS) - 1);
	  qos_info->q_low_src = MVPP2_QOS_SRC_ACTION_TBL;
	  qos_info->q_high_src = MVPP2_QOS_SRC_ACTION_TBL;
	  pr_debug ("q_low %d, q_high %d, queue %d, tc %d\n", pkt_qos->q_low, pkt_qos->q_high,
		    queue, action->cos->tc);
	}
      else
	{
	  pkt_action->q_low_act = MVPP2_ACTION_TYPE_NO_UPDT;
	  pkt_action->q_high_act = MVPP2_ACTION_TYPE_NO_UPDT;
	}
    }
}

static void
pp2_cls_mng_set_c3_action (struct pp2_port *port, struct mv_pp2x_engine_qos_info *qos_info,
			   struct mv_pp2x_qos_value *pkt_qos,
			   struct mv_pp2x_engine_pkt_action *pkt_action,
			   struct pp2_cls_tbl_action *action, int lkp_type)
{
  u8 queue;

  if (action->type == PP2_CLS_TBL_ACT_DROP)
    pkt_action->color_act = MVPP2_COLOR_ACTION_TYPE_RED_LOCK;
  else if (action->cos)
    {
      int pkt_action_color;

      if (action->cos->override_color)
	pkt_action_color = action->cos->pkt_color;
      else
	pkt_action_color = port->tc[action->cos->tc].tc_config.default_color;

      switch (pkt_action_color)
	{
	case PP2_PPIO_COLOR_GREEN:
	  pkt_action->color_act = MVPP2_COLOR_ACTION_TYPE_GREEN_LOCK;
	  break;
	case PP2_PPIO_COLOR_YELLOW:
	  pkt_action->color_act = MVPP2_COLOR_ACTION_TYPE_YELLOW_LOCK;
	  break;
	case PP2_PPIO_COLOR_RED:
	  pkt_action->color_act = MVPP2_COLOR_ACTION_TYPE_RED_LOCK;
	  break;
	}
    }
  else
    {
      pkt_action->color_act = MVPP2_COLOR_ACTION_TYPE_NO_UPDT;
    }

  pkt_action->policer_act = MVPP2_ACTION_TYPE_NO_UPDT;
  pkt_action->flowid_act = MVPP2_ACTION_FLOWID_DISABLE;
  pkt_action->frwd_act = MVPP2_ACTION_TYPE_NO_UPDT;
  pkt_action->rss_act = MVPP2_ACTION_TYPE_UPDT_LOCK;

  if (action->plcr)
    {
      pkt_action->policer_act = MVPP2_ACTION_TYPE_UPDT_LOCK;
      qos_info->policer_id = action->plcr->id;
    }

  if (action->cos)
    {
      pkt_action->q_low_act = MVPP2_ACTION_TYPE_UPDT_LOCK;
      pkt_action->q_high_act = MVPP2_ACTION_TYPE_UPDT_LOCK;
      queue = port->tc[action->cos->tc].tc_config.first_rxq;
      pkt_qos->q_high = ((u16) queue) >> MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS;
      pkt_qos->q_low = ((u16) queue) & ((1 << MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS) - 1);
      pr_debug ("q_low %d, q_high %d, queue %d, tc %d\n", pkt_qos->q_low, pkt_qos->q_high, queue,
		action->cos->tc);
    }
  else
    {
      pkt_action->q_low_act = MVPP2_ACTION_TYPE_NO_UPDT;
      pkt_action->q_high_act = MVPP2_ACTION_TYPE_NO_UPDT;
    }
}

static void
pp2_cls_set_hash_params (struct pp2_cls_fl_rule_list_t *fl_rls, struct pp2_port *port, int engine,
			 int lkpid, int lkpid_attr, int set)
{
  int lkp_type = (port->type == PP2_PPIO_T_LOG) ? MVPP2_CLS_LKP_MUSDK_LOG_HASH : MVPP2_CLS_LKP_HASH;

  fl_rls->fl_len = 1;
  fl_rls->fl->enabled = set;
  fl_rls->fl->fl_log_id = lkpid;
  fl_rls->fl->port_type = MVPP2_SRC_PORT_TYPE_PHY;
  fl_rls->fl->port_bm = (1 << port->id);
  fl_rls->fl->lu_type = lkp_type;
  fl_rls->fl->prio = pp2_cls_mng_lkp_type_to_prio (lkp_type);
  fl_rls->fl->engine = engine;
  fl_rls->fl->udf7 =
    (port->type == PP2_PPIO_T_LOG) ? MVPP2_CLS_MUSDK_LOG_UDF7 : MVPP2_CLS_MUSDK_NIC_UDF7;
  fl_rls->fl->seq_ctrl = MVPP2_CLS_DEF_SEQ_CTRL;

  if (engine == MVPP2_CLS_ENGINE_C3HA)
    fl_rls->fl->field_id_cnt = 2;
  else
    fl_rls->fl->field_id_cnt = 4;

  if (lkpid_attr & MVPP2_PRS_FL_ATTR_IP4_BIT)
    {
      fl_rls->fl->field_id[0] = MVPP2_CLS_FIELD_IP4SA;
      fl_rls->fl->field_id[1] = MVPP2_CLS_FIELD_IP4DA;
    }
  else if (lkpid_attr & MVPP2_PRS_FL_ATTR_IP6_BIT)
    {
      fl_rls->fl->field_id[0] = MVPP2_CLS_FIELD_IP6SA;
      fl_rls->fl->field_id[1] = MVPP2_CLS_FIELD_IP6DA;
    }
  fl_rls->fl->field_id[2] = MVPP2_CLS_FIELD_L4SIP;
  fl_rls->fl->field_id[3] = MVPP2_CLS_FIELD_L4DIP;
}

static int
pp2_cls_set_rule_info (struct pp2_cls_mng_pkt_key_t *mng_pkt_key,
		       struct mv_pp2x_src_port *rule_port, struct pp2_cls_tbl_params *params,
		       struct pp2_cls_tbl_rule *rule, struct pp2_port *port)
{
  char *mask_ptr;
  char mask_arr[3];
  int rc = 0, i;
  u32 proto_flag = 0;
  u32 ipv4_flag = 0;
  u32 ipv6_flag = 0;
  u32 field;
  u16 ipproto;
  u32 idx1, idx2;
  u32 field_bm = 0, bm = 0;
  u32 src, dst;

  rule_port->port_type = MVPP2_SRC_PORT_TYPE_PHY;
  rule_port->port_value = (1 << port->id);
  rule_port->port_mask = 0xff;

  if (rule->num_fields == 0)
    {
      pr_err ("[%s] Error: num of fields in rule is 0. Nothing to be done\n", __func__);
      return -EINVAL;
    }

  /* parse the protocol and protocol fields */
  for (idx1 = 0; idx1 < params->key.num_fields; idx1++)
    {
      rc = lookup_field_id (params->key.proto_field[idx1], &field, &bm);
      if (rc)
	{
	  pr_err ("%s(%d) lookup id error!\n", __func__, __LINE__);
	  return -EINVAL;
	}

      if (field == NOT_SUPPORTED_YET)
	{
	  pr_err ("%s(%d) protocol_field not supported yet - skipping!\n", __func__, __LINE__);
	  continue;
	}

      if (params->key.proto_field[idx1].proto == MV_NET_PROTO_IP4)
	{
	  ipv4_flag = 1;
	  field_bm |= MVPP2_MATCH_IPV4_PKT;
	}
      if (params->key.proto_field[idx1].proto == MV_NET_PROTO_IP6)
	{
	  ipv6_flag = 1;
	  field_bm |= MVPP2_MATCH_IPV6_PKT;
	}
      field_bm |= bm;

      switch (field)
	{
	case MAC_SA_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (MAC_DA_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }
	  rc = mv_pp2x_parse_mac_address ((char *) rule->fields[idx1].key,
					  &mng_pkt_key->pkt_key->eth_src.eth_add[0]);
	  if (rc < 0)
	    {
	      pr_err ("Unable to parse MAC SA\n");
	      return -EINVAL;
	    }
	  pr_debug (
	    "MAC SA: %02x:%02x:%02x:%02x:%02x:%02x\n", mng_pkt_key->pkt_key->eth_src.eth_add[0],
	    mng_pkt_key->pkt_key->eth_src.eth_add[1], mng_pkt_key->pkt_key->eth_src.eth_add[2],
	    mng_pkt_key->pkt_key->eth_src.eth_add[3], mng_pkt_key->pkt_key->eth_src.eth_add[4],
	    mng_pkt_key->pkt_key->eth_src.eth_add[5]);
	  rc = mv_pp2x_parse_mac_address ((char *) rule->fields[idx1].mask,
					  &mng_pkt_key->pkt_key->eth_src.eth_add_mask[0]);
	  if (rc < 0)
	    {
	      pr_err ("Unable to parse MAC SA mask\n");
	      return -EINVAL;
	    }
	  pr_debug ("MAC SA MASK: %02x:%02x:%02x:%02x:%02x:%02x\n",
		    mng_pkt_key->pkt_key->eth_src.eth_add_mask[0],
		    mng_pkt_key->pkt_key->eth_src.eth_add_mask[1],
		    mng_pkt_key->pkt_key->eth_src.eth_add_mask[2],
		    mng_pkt_key->pkt_key->eth_src.eth_add_mask[3],
		    mng_pkt_key->pkt_key->eth_src.eth_add_mask[4],
		    mng_pkt_key->pkt_key->eth_src.eth_add_mask[5]);
	  break;
	case MAC_DA_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (MAC_SA_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }
	  rc = mv_pp2x_parse_mac_address ((char *) rule->fields[idx1].key,
					  &mng_pkt_key->pkt_key->eth_dst.eth_add[0]);
	  if (rc < 0)
	    {
	      pr_err ("Unable to parse MAC DA\n");
	      return -EINVAL;
	    }
	  pr_debug (
	    "MAC DA: %02x:%02x:%02x:%02x:%02x:%02x\n", mng_pkt_key->pkt_key->eth_dst.eth_add[0],
	    mng_pkt_key->pkt_key->eth_dst.eth_add[1], mng_pkt_key->pkt_key->eth_dst.eth_add[2],
	    mng_pkt_key->pkt_key->eth_dst.eth_add[3], mng_pkt_key->pkt_key->eth_dst.eth_add[4],
	    mng_pkt_key->pkt_key->eth_dst.eth_add[5]);
	  rc = mv_pp2x_parse_mac_address ((char *) rule->fields[idx1].mask,
					  &mng_pkt_key->pkt_key->eth_dst.eth_add_mask[0]);
	  if (rc < 0)
	    {
	      pr_err ("Unable to parse MAC DA mask\n");
	      return -EINVAL;
	    }
	  pr_debug ("MAC DA MASK: %02x:%02x:%02x:%02x:%02x:%02x\n",
		    mng_pkt_key->pkt_key->eth_dst.eth_add_mask[0],
		    mng_pkt_key->pkt_key->eth_dst.eth_add_mask[1],
		    mng_pkt_key->pkt_key->eth_dst.eth_add_mask[2],
		    mng_pkt_key->pkt_key->eth_dst.eth_add_mask[3],
		    mng_pkt_key->pkt_key->eth_dst.eth_add_mask[4],
		    mng_pkt_key->pkt_key->eth_dst.eth_add_mask[5]);
	  break;
	case ETH_TYPE_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (ETH_TYPE_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }
	  rc = kstrtou16 ((char *) (rule->fields[idx1].key), 0, &mng_pkt_key->pkt_key->ether_type);
	  if (rc)
	    {
	      pr_err ("Failed to parse eth_type header.\n");
	      return rc;
	    }
	  if (mng_pkt_key->pkt_key->ether_type > ((1 << ETH_TYPE_FIELD_SIZE) - 1))
	    {
	      pr_err ("eth_type exceeds max val!.\n");
	      return rc;
	    }
	  pr_debug ("ETH_TYPE_FIELD_ID = %d\n", mng_pkt_key->pkt_key->ether_type);
	  break;
	case OUT_VLAN_PRI_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (OUT_VLAN_PRI_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }
	  rc = kstrtou8 ((char *) (rule->fields[idx1].key), 0, &mng_pkt_key->pkt_key->out_pbit);
	  if (rc)
	    {
	      pr_err ("Failed to parse PCP bits in VLAN header.\n");
	      return rc;
	    }
	  if (mng_pkt_key->pkt_key->out_pbit >= MV_VLAN_PRIO_NUM)
	    {
	      pr_err ("Key exceeds max val! %d\n", MV_VLAN_PRIO_NUM - 1);
	      return -EINVAL;
	    }
	  pr_debug ("OUT_VLAN_PRI_FIELD_ID = %d\n", mng_pkt_key->pkt_key->out_pbit);
	  break;
	case OUT_VLAN_ID_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (OUT_VLAN_ID_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }
	  rc = kstrtou16 ((char *) (rule->fields[idx1].key), 0, &mng_pkt_key->pkt_key->out_vid);
	  if (rc)
	    {
	      pr_err ("Failed to parse VID in VLAN header.\n");
	      return rc;
	    }
	  if (mng_pkt_key->pkt_key->out_vid > ((1 << OUT_VLAN_ID_FIELD_SIZE) - 1))
	    {
	      pr_err ("vlan_id exceeds max val!.\n");
	      return rc;
	    }
	  pr_debug ("OUT_VLAN_ID_FIELD_ID = %d\n", mng_pkt_key->pkt_key->out_vid);
	  break;
	case IPV4_DSCP_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (IPV4_DSCP_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }
	  rc =
	    kstrtou8 ((char *) (rule->fields[idx1].key), 0, &mng_pkt_key->pkt_key->ipvx_add.dscp);
	  if (rc)
	    {
	      pr_err ("Failed to parse DSCP field.\n");
	      return rc;
	    }
	  if (mng_pkt_key->pkt_key->ipvx_add.dscp >= MV_DSCP_NUM)
	    {
	      pr_err ("Key exceeds max val! %d\n", MV_DSCP_NUM - 1);
	      return -EINVAL;
	    }
	  pr_debug ("OUT_VLAN_ID_FIELD_ID = %d\n", mng_pkt_key->pkt_key->ipvx_add.dscp);
	  rc = kstrtou8 ((char *) (rule->fields[idx1].mask), 0,
			 &mng_pkt_key->pkt_key->ipvx_add.dscp_mask);
	  if (rc)
	    {
	      pr_err ("Failed to parse DSCP mask.\n");
	      return rc;
	    }
	  pr_debug ("OUT_VLAN_ID_FIELD_ID mask = %d\n", mng_pkt_key->pkt_key->ipvx_add.dscp_mask);
	  break;
	case IPV4_SA_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (IPV4_SA_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }
	  rc = in4_pton ((char *) rule->fields[idx1].key, strlen ((char *) rule->fields[idx1].key),
			 &mng_pkt_key->pkt_key->ipvx_add.ip_src.ip_add.ipv4[0], '.', NULL);
	  if (!rc)
	    {
	      pr_err ("Unable to parse IPv4 SA\n");
	      return -EINVAL;
	    }
	  /* convert mask */
	  if (strncmp ((char *) rule->fields[idx1].mask, "0x", 2) == 0)
	    mask_ptr = (char *) ((char *) rule->fields[idx1].mask + 2);
	  else
	    return -EINVAL;
	  for (i = 0; i < 4; i++)
	    {
	      strncpy (mask_arr, mask_ptr, 2);
	      mask_arr[2] = '\0';
	      rc =
		kstrtou8 (mask_arr, 16, &mng_pkt_key->pkt_key->ipvx_add.ip_src.ip_add_mask.ipv4[i]);
	      if (rc)
		{
		  pr_err ("Unable to parse IPv4 SA mask\n");
		  return rc;
		}
	      mask_ptr += 2;
	    }
	  pr_debug ("IPv4 SA: %d.%d.%d.%d\n", mng_pkt_key->pkt_key->ipvx_add.ip_src.ip_add.ipv4[0],
		    mng_pkt_key->pkt_key->ipvx_add.ip_src.ip_add.ipv4[1],
		    mng_pkt_key->pkt_key->ipvx_add.ip_src.ip_add.ipv4[2],
		    mng_pkt_key->pkt_key->ipvx_add.ip_src.ip_add.ipv4[3]);
	  break;
	case IPV4_DA_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (IPV4_DA_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }
	  rc = in4_pton ((char *) rule->fields[idx1].key, strlen ((char *) rule->fields[idx1].key),
			 &mng_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add.ipv4[0], '.', NULL);
	  if (!rc)
	    {
	      pr_err ("Unable to parse IPv4 DA\n");
	      return -EINVAL;
	    }
	  /* convert mask */
	  if (strncmp ((char *) rule->fields[idx1].mask, "0x", 2) == 0)
	    mask_ptr = (char *) ((char *) rule->fields[idx1].mask + 2);
	  else
	    return -EINVAL;
	  for (i = 0; i < 4; i++)
	    {
	      strncpy (mask_arr, mask_ptr, 2);
	      mask_arr[2] = '\0';
	      rc =
		kstrtou8 (mask_arr, 16, &mng_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add_mask.ipv4[i]);
	      if (rc)
		{
		  pr_err ("Unable to parse IPv4 DA mask\n");
		  return rc;
		}
	      mask_ptr += 2;
	    }

	  pr_debug ("IPv4 DA: %d.%d.%d.%d\n", mng_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add.ipv4[0],
		    mng_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add.ipv4[1],
		    mng_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add.ipv4[2],
		    mng_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add.ipv4[3]);
	  break;
	case IPV4_PROTO_FIELD_ID:
	case IPV6_NH_FIELD_ID:
	  rc = kstrtou16 ((char *) (rule->fields[idx1].key), 0, &ipproto);
	  if (rc)
	    {
	      pr_err ("Unable to parse Ipv6 protocol");
	      return rc;
	    }
	  mng_pkt_key->pkt_key->ipvx_add.ip_proto = ipproto;
	  if ((ipproto == IPPROTO_UDP) || (ipproto == IPPROTO_TCP))
	    /* Turn on flag indicating tcp/udp, used for detecting 5 tuple configuration */
	    proto_flag = 1;
	  pr_debug ("protocol: %d\n", ipproto);
	  break;
	case IPV6_SA_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (IPV6_SA_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }

	  rc = in6_pton ((char *) rule->fields[idx1].key, strlen ((char *) rule->fields[idx1].key),
			 &mng_pkt_key->pkt_key->ipvx_add.ip_src.ip_add.ipv6[0], ':', NULL);
	  if (!rc)
	    {
	      pr_err ("Unable to parse IPv6 SA\n");
	      return -EINVAL;
	    }
	  pr_debug ("IPv6 SA: ");
	  for (idx2 = 0; idx2 < 16; idx2 += 2)
	    {
	      pr_info ("%x%x", mng_pkt_key->pkt_key->ipvx_add.ip_src.ip_add.ipv6[idx2],
		       mng_pkt_key->pkt_key->ipvx_add.ip_src.ip_add.ipv6[idx2 + 1]);
	      if (idx2 < 14)
		pr_info (":");
	      else
		pr_info ("\n");
	    }
	  break;
	case IPV6_DA_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (IPV6_DA_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }

	  rc = in6_pton ((char *) rule->fields[idx1].key, strlen ((char *) rule->fields[idx1].key),
			 &mng_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add.ipv6[0], ':', NULL);
	  if (!rc)
	    {
	      pr_err ("Unable to parse IPv6 DA\n");
	      return -EINVAL;
	    }
	  pr_debug ("IPv6 DA: ");
	  for (idx2 = 0; idx2 < 16; idx2 += 2)
	    {
	      pr_info ("%x%x", mng_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add.ipv6[idx2],
		       mng_pkt_key->pkt_key->ipvx_add.ip_dst.ip_add.ipv6[idx2 + 1]);
	      if (idx2 < 14)
		pr_info (":");
	      else
		pr_info ("\n");
	    }
	  break;
	case IPV6_FLOW_LBL_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (IPV6_FLOW_LBL_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }

	  rc = kstrtou32 ((char *) (rule->fields[idx1].key), 0,
			  &mng_pkt_key->pkt_key->ipvx_add.flow_label);
	  if (rc)
	    {
	      pr_err ("%s(%d)) Falied to parse IPv6 flow label.", __func__, __LINE__);
	      return rc;
	    }
	  pr_debug ("IPV6_FLOW_LBL_FIELD_ID = %x\n", mng_pkt_key->pkt_key->ipvx_add.flow_label);

	  if (mng_pkt_key->pkt_key->ipvx_add.flow_label > (1 << IPV6_FLOW_LBL_FIELD_SIZE) - 1)
	    {
	      pr_err ("%s(%d)) IPv6 flow label.value too big. Max value %x", __func__, __LINE__,
		      ((1 << IPV6_FLOW_LBL_FIELD_SIZE) - 1));
	      return -EFAULT;
	    }

	  rc = kstrtou32 ((char *) (rule->fields[idx1].mask), 0,
			  &mng_pkt_key->pkt_key->ipvx_add.flow_label_mask);
	  if (rc)
	    {
	      pr_err ("Failed to parse IPv6 flow label mask.\n");
	      return rc;
	    }
	  pr_debug ("IPV6_FLOW_LBL_FIELD_ID mask = %x\n",
		    mng_pkt_key->pkt_key->ipvx_add.flow_label_mask);

	  if (mng_pkt_key->pkt_key->ipvx_add.flow_label_mask > (1 << IPV6_FLOW_LBL_FIELD_SIZE) - 1)
	    {
	      pr_err ("%s(%d)) IPv6 flow label.mask value too big. Max value %x", __func__,
		      __LINE__, ((1 << IPV6_FLOW_LBL_FIELD_SIZE) - 1));
	      return -EFAULT;
	    }
	  break;
	case L4_SRC_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (L4_SRC_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }
	  rc = kstrtou32 ((char *) (rule->fields[idx1].key), 0, &src);
	  if (rc)
	    {
	      pr_err ("%s(%d)) Falied to parse L4 source port.\n", __func__, __LINE__);
	      return rc;
	    }

	  if (src > ((1 << L4_SRC_FIELD_SIZE) - 1))
	    {
	      pr_err ("%s(%d)) L4 src port value too big. Max value %x\n", __func__, __LINE__,
		      ((1 << L4_SRC_FIELD_SIZE) - 1));
	      return -EFAULT;
	    }

	  mng_pkt_key->pkt_key->l4_src = src;

	  pr_debug ("L4_SRC_FIELD_ID = %d\n", mng_pkt_key->pkt_key->l4_src);
	  break;
	case L4_DST_FIELD_ID:
	  if (rule->fields[idx1].size != (GET_NUM_BYTES (L4_DST_FIELD_SIZE)))
	    {
	      pr_err ("%s(%d) field size does not match! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }
	  rc = kstrtou32 ((char *) (rule->fields[idx1].key), 0, &dst);
	  if (rc)
	    {
	      pr_err ("%s(%d)) Falied to parse L4 destination port.\n", __func__, __LINE__);
	      return rc;
	    }

	  if (dst > ((1 << L4_DST_FIELD_SIZE) - 1))
	    {
	      pr_err ("%s(%d)) L4 dst port value too big. Max value %x\n", __func__, __LINE__,
		      ((1 << L4_DST_FIELD_SIZE) - 1));
	      return -EFAULT;
	    }

	  mng_pkt_key->pkt_key->l4_dst = dst;

	  pr_debug ("L4_DST_FIELD_ID = %d\n", mng_pkt_key->pkt_key->l4_dst);
	  break;
	case CLS_UDF3_FIELD_ID:
	  if ((rule->fields[idx1].size > CLS_UDF_FIELD_SIZE) || (rule->fields[idx1].size == 0))
	    {
	      pr_err ("%s(%d) invalid field size value! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }

	  memset (&mng_pkt_key->pkt_key->udf3.udf, 0, CLS_UDF_FIELD_SIZE);
	  memcpy (&mng_pkt_key->pkt_key->udf3.udf, rule->fields[idx1].key, rule->fields[idx1].size);
	  /* the value is shifted to the high bits of u32, since driver uses constant field size */
	  /* Example: user passes 2 bytes: 0xABCD, driver will receive: 0xABCD0000 */
	  mng_pkt_key->pkt_key->udf3.udf <<=
	    (CLS_UDF_FIELD_SIZE - rule->fields[idx1].size) * BYTE_BITS;
	  pr_debug ("UDF3 = 0x%x\n", mng_pkt_key->pkt_key->udf3.udf);

	  memset (&mng_pkt_key->pkt_key->udf3.udf_mask, 0, CLS_UDF_FIELD_SIZE);
	  memcpy (&mng_pkt_key->pkt_key->udf3.udf_mask, rule->fields[idx1].mask,
		  rule->fields[idx1].size);
	  mng_pkt_key->pkt_key->udf3.udf_mask <<=
	    (CLS_UDF_FIELD_SIZE - rule->fields[idx1].size) * BYTE_BITS;
	  pr_debug ("UDF3 mask = 0x%x\n", mng_pkt_key->pkt_key->udf3.udf_mask);
	  break;
	case CLS_UDF5_FIELD_ID:
	  if ((rule->fields[idx1].size > CLS_UDF_FIELD_SIZE) || (rule->fields[idx1].size == 0))
	    {
	      pr_err ("%s(%d) invalid field size value! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }

	  memset (&mng_pkt_key->pkt_key->udf5.udf, 0, CLS_UDF_FIELD_SIZE);
	  memcpy (&mng_pkt_key->pkt_key->udf5.udf, rule->fields[idx1].key, rule->fields[idx1].size);
	  /* the value is shifted to the high bits of u32, since driver uses constant field size */
	  /* Example: user passes 2 bytes: 0xABCD, driver will receive: 0xABCD0000 */
	  mng_pkt_key->pkt_key->udf5.udf <<=
	    (CLS_UDF_FIELD_SIZE - rule->fields[idx1].size) * BYTE_BITS;
	  pr_debug ("UDF5 = 0x%x\n", mng_pkt_key->pkt_key->udf5.udf);

	  memset (&mng_pkt_key->pkt_key->udf5.udf_mask, 0, CLS_UDF_FIELD_SIZE);
	  memcpy (&mng_pkt_key->pkt_key->udf5.udf_mask, rule->fields[idx1].mask,
		  rule->fields[idx1].size);
	  mng_pkt_key->pkt_key->udf5.udf_mask <<=
	    (CLS_UDF_FIELD_SIZE - rule->fields[idx1].size) * BYTE_BITS;
	  pr_debug ("UDF5 mask = 0x%x\n", mng_pkt_key->pkt_key->udf5.udf_mask);
	  break;
	case CLS_UDF6_FIELD_ID:
	  if ((rule->fields[idx1].size > CLS_UDF_FIELD_SIZE) || (rule->fields[idx1].size == 0))
	    {
	      pr_err ("%s(%d) invalid field size value! %d\n", __func__, __LINE__,
		      rule->fields[idx1].size);
	      return -EINVAL;
	    }

	  memset (&mng_pkt_key->pkt_key->udf6.udf, 0, CLS_UDF_FIELD_SIZE);
	  memcpy (&mng_pkt_key->pkt_key->udf6.udf, rule->fields[idx1].key, rule->fields[idx1].size);
	  /* the value is shifted to the high bits of u32, since driver uses constant field size */
	  /* Example: user passes 2 bytes: 0xABCD, driver will receive: 0xABCD0000 */
	  mng_pkt_key->pkt_key->udf6.udf <<=
	    (CLS_UDF_FIELD_SIZE - rule->fields[idx1].size) * BYTE_BITS;
	  pr_debug ("UDF6 = 0x%x\n", mng_pkt_key->pkt_key->udf6.udf);

	  memset (&mng_pkt_key->pkt_key->udf6.udf_mask, 0, CLS_UDF_FIELD_SIZE);
	  memcpy (&mng_pkt_key->pkt_key->udf6.udf_mask, rule->fields[idx1].mask,
		  rule->fields[idx1].size);
	  mng_pkt_key->pkt_key->udf6.udf_mask <<=
	    (CLS_UDF_FIELD_SIZE - rule->fields[idx1].size) * BYTE_BITS;
	  pr_debug ("UDF6 mask = 0x%x\n", mng_pkt_key->pkt_key->udf6.udf_mask);
	  break;
	default:
	  pr_err ("%s(%d) protocol_field not supported yet!\n", __func__, __LINE__);
	  return -EINVAL;
	}
    }

  if ((field_bm == (MVPP2_MATCH_IP_SRC | MVPP2_MATCH_IP_DST | MVPP2_MATCH_L4_SRC |
		    MVPP2_MATCH_L4_DST | MVPP2_MATCH_IPV4_PKT)) &&
      (proto_flag))
    mng_pkt_key->pkt_key->field_bm = MVPP2_MATCH_IPV4_5T;
  else if ((field_bm == (IPV6_SA_FIELD_ID | IPV6_DA_FIELD_ID | L4_SRC_FIELD_ID | L4_DST_FIELD_ID |
			 MVPP2_MATCH_IPV6_PKT)) &&
	   (proto_flag))
    mng_pkt_key->pkt_key->field_bm = MVPP2_MATCH_IPV6_5T;
  else
    mng_pkt_key->pkt_key->field_bm = field_bm;

  mng_pkt_key->pkt_key->field_bm_mask = mng_pkt_key->pkt_key->field_bm;

  pr_debug ("field_bm: %x\n", mng_pkt_key->pkt_key->field_bm);

  if (ipv4_flag)
    mng_pkt_key->pkt_key->ipvx_add.ip_ver = 4;
  else if (ipv6_flag)
    mng_pkt_key->pkt_key->ipvx_add.ip_ver = 6;

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
      pp2_reg_write (cpu_slot, MVPP2_RX_EX_INT_CAUSE_MASK_REG (port->id), 0);
    }
}

static void
pp2_port_deinit_txsched (struct pp2_port *port)
{
}

static void
pp2_port_egress_disable_qmask (struct pp2_port *port, uint32_t q_mask)
{
  volatile u32 tmo;
  u32 val = 0;
  u32 tx_port_num = MVPP2_MAX_TCONT + port->id;
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
  u32 tx_port_num = MVPP2_MAX_TCONT + port->id;
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

  pp2_reg_write (cpu_slot, MVPP2_ISR_ENABLE_REG (port->id), MVPP2_ISR_DISABLE_INTERRUPT (mask));
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

      mv_sys_dma_mem_region_free (rxq->mem, rxq->desc_virt_arr);
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
  val |= MVPP2_TX_PORT_FLUSH_MASK (port->id);
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

  val &= ~MVPP2_TX_PORT_FLUSH_MASK (port->id);
  pp2_reg_write (cpu_slot, MVPP2_TX_PORT_FLUSH_REG, val);
}

static void
pp2_port_txqs_destroy (struct pp2_port *port)
{
  u32 qid;

  for (qid = 0; qid < port->num_tx_queues; qid++)
    {
      struct pp2_tx_queue *txq = port->txqs[qid];

      mv_sys_dma_mem_region_free (port->tx_qs_mem, txq->desc_virt_arr);
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

  mtu = (port->port_mtu + ETH_HLEN) * 8;

  /* WA for wrong Token bucket update: Set MTU value = 3*real MTU value */
  mtu = 3 * mtu;

  if (mtu > MVPP2_TXP_MTU_MAX)
    mtu = MVPP2_TXP_MTU_MAX;

  /* Indirect access to registers */
  tx_port_num = MVPP2_TX_PORT_NUM (port->id);
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
  u32 val;
  uintptr_t cpu_slot;
  struct pp2_tc *tc;

  cpu_slot = port->cpu_slot;

  rxq->desc_virt_arr = mv_sys_dma_mem_region_alloc (
    rxq->mem, (rxq->desc_total * MVPP2_DESC_ALIGNED_SIZE), MVPP2_DESC_Q_ALIGN);
  if (unlikely (!rxq->desc_virt_arr))
    {
      pr_err ("PP: cannot allocate ingress descriptor array\n");
      return;
    }
  rxq->desc_phys_arr = (uintptr_t) mv_sys_dma_mem_region_virt2phys (rxq->mem, rxq->desc_virt_arr);
  if (!IS_ALIGNED (rxq->desc_phys_arr, MVPP2_DESC_Q_ALIGN))
    {
      pr_err ("PP: ingress descriptor array must be %u-byte aligned\n", MVPP2_DESC_Q_ALIGN);
      mv_sys_dma_mem_region_free (rxq->mem, rxq->desc_virt_arr);
      return;
    }
  pr_debug ("port[%d:%d] rxq[%d], desc_phys_addr(0x%lx)\n", port->parent->id, port->id, rxq->id,
	    rxq->desc_phys_arr);
  rxq->desc_last_idx = rxq->desc_total - 1;

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
      pr_err ("port(%d) phy_rxq(%d), not found in tc range\n", port->id, rxq->id);
      return;
    }
  /* Set Offset */
  pp2_rxq_offset_set (port, rxq->id, tc->tc_config.pkt_offset);

  pp2_bm_pool_assign (port, rxq->bm_pool_id[BM_TYPE_SHORT_BUF_POOL], rxq->id,
		      BM_TYPE_SHORT_BUF_POOL);
  pp2_bm_pool_assign (port, rxq->bm_pool_id[BM_TYPE_LONG_BUF_POOL], rxq->id, BM_TYPE_LONG_BUF_POOL);
  pr_debug ("port[%d:%d] rxq[%d], short_pool(%d), long_pool(%d)\n", port->parent->id, port->id,
	    rxq->id, rxq->bm_pool_id[BM_TYPE_SHORT_BUF_POOL],
	    rxq->bm_pool_id[BM_TYPE_LONG_BUF_POOL]);

  /* Add number of descriptors ready for receiving packets */
  val = (0 | (rxq->desc_total << MVPP2_RXQ_NUM_NEW_OFFSET));
  pp2_reg_write (cpu_slot, MVPP2_RXQ_STATUS_UPDATE_REG (rxq->id), val);

  memset (&rxq->stats, 0, sizeof (rxq->stats));
  rxq->threshold_rx_pkts = 0;

  pp2_cls_edrop_bypass_assign_qid (port->parent, rxq->id);
  rxq->edrop = NULL;
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
pp2_txsched_port_burst_set (struct pp2_port *port, int burst)
{
  u32 size, mtu;
  u32 txPortNum;

  if (!port->enable_port_rate_limit)
    burst = MVPP2_TXP_MAX_CONFIGURABLE_BUCKET_SIZE / 8;

  txPortNum = MVPP2_TX_PORT_NUM (port->id);
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, txPortNum);

  /* Caclulate Token Bucket Size */
  size = 8 * burst;

  if (size > MVPP2_TXP_TOKEN_SIZE_MAX)
    size = MVPP2_TXP_TOKEN_SIZE_MAX;

  /* Token bucket size must be larger then MTU. We set it to max. */
  mtu = MVPP2_TX_MTU_MAX;
  if (mtu > size)
    {
      pr_err ("%s Error: Bucket size (%d bytes) < MTU (%d bytes)\n", __func__, (size / 8),
	      (mtu / 8));
      return -EINVAL;
    }
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, size);

  return 0;
}

static int
pp2_txsched_port_rate_set (struct pp2_port *port, int rate)
{
  int rc;
  u32 regVal;
  u32 tokens, period, txPortNum, accuracy = 0;

  txPortNum = MVPP2_TX_PORT_NUM (port->id);
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, txPortNum);

  if (port->enable_port_rate_limit)
    {

      rc = pp2_txsched_rate_calc (rate, accuracy, &period, &tokens);
      if (rc)
	{
	  pr_err ("%s: Can't provide rate of %d [Kbps] with accuracy of %d [%%]\n", __func__, rate,
		  accuracy);
	  return rc;
	}

      if (tokens > MVPP2_TXP_REFILL_TOKENS_MAX)
	tokens = MVPP2_TXP_REFILL_TOKENS_MAX;
      if (period > MVPP2_TXP_REFILL_PERIOD_MAX)
	period = MVPP2_TXP_REFILL_PERIOD_MAX;
    }
  else
    {
      period = MVPP2_TXP_REFILL_PERIOD_MIN;
      tokens = MVPP2_TXP_REFILL_TOKENS_MAX;
    }

  regVal = pp2_reg_read (port->cpu_slot, MVPP2_TXP_SCHED_REFILL_REG);

  regVal &= ~MVPP2_TXP_REFILL_TOKENS_ALL_MASK;
  regVal |= MVPP2_TXP_REFILL_TOKENS_MASK (tokens);

  regVal &= ~MVPP2_TXP_REFILL_PERIOD_ALL_MASK;
  regVal |= MVPP2_TXP_REFILL_PERIOD_MASK (period);

  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_REFILL_REG, regVal);

  return 0;
}

static int
pp2_txsched_queue_arbitration_set (struct pp2_port *port, u8 txq,
				   enum pp2_ppio_outq_sched_mode mode, u8 weight)
{
  if (mode == PP2_PPIO_SCHED_M_WRR)
    return pp2_txsched_queue_wrr_set (port, txq, weight);

  if (mode == PP2_PPIO_SCHED_M_SP)
    return pp2_txsched_queue_fixed_prio_set (port, txq);

  pr_err ("%s Error: Invalid egress arbitration mode on p%dq%d: %d.\n", __func__, port->id, txq,
	  (int) mode);

  return -EINVAL;
}

static int
pp2_txsched_queue_burst_set (struct pp2_port *port, int txq, int burst)
{
  u32 size, mtu;
  int txPortNum;

  if (!port->txq_config[txq].rate_limit_enable)
    burst = MVPP2_TXQ_MAX_CONFIGURABLE_BUCKET_SIZE / 8;

  txPortNum = MVPP2_TX_PORT_NUM (port->id);
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, txPortNum);

  /* Calculate Tocket Bucket Size */
  size = 8 * burst;

  if (size > MVPP2_TXQ_TOKEN_SIZE_MAX)
    size = MVPP2_TXQ_TOKEN_SIZE_MAX;

  /* Token bucket size must be larger then MTU. We set it to max. */
  mtu = MVPP2_TX_MTU_MAX;
  if (mtu > size)
    {
      pr_err ("%s Error: Bucket size (%d bytes) < MTU (%d bytes)\n", __func__, (size / 8),
	      (mtu / 8));
      return -EINVAL;
    }

  pp2_reg_write (port->cpu_slot, MVPP2_TXQ_SCHED_TOKEN_SIZE_REG (txq), size);

  return 0;
}

static int
pp2_txsched_queue_rate_set (struct pp2_port *port, int txq, int rate)
{
  u32 regVal;
  u32 txPortNum, period, tokens, accuracy = 0;
  int rc;

  txPortNum = MVPP2_TX_PORT_NUM (port->id);
  pp2_reg_write (port->cpu_slot, MVPP2_TXP_SCHED_PORT_INDEX_REG, txPortNum);

  if (port->txq_config[txq].rate_limit_enable)
    {

      rc = pp2_txsched_rate_calc (rate, accuracy, &period, &tokens);
      if (rc)
	{
	  pr_err ("%s: Can't provide rate of %d [Kbps] with accuracy of %d [%%]\n", __func__, rate,
		  accuracy);
	  return rc;
	}

      if (tokens > MVPP2_TXQ_REFILL_TOKENS_MAX)
	tokens = MVPP2_TXQ_REFILL_TOKENS_MAX;

      if (period > MVPP2_TXQ_REFILL_PERIOD_MAX)
	period = MVPP2_TXQ_REFILL_PERIOD_MAX;
    }
  else
    {
      tokens = MVPP2_TXQ_REFILL_TOKENS_MAX;
      period = MVPP2_TXQ_REFILL_PERIOD_MIN;
    }

  regVal = pp2_reg_read (port->cpu_slot, MVPP2_TXQ_SCHED_REFILL_REG (txq));

  regVal &= ~MVPP2_TXQ_REFILL_TOKENS_ALL_MASK;
  regVal |= MVPP2_TXQ_REFILL_TOKENS_MASK (tokens);

  regVal &= ~MVPP2_TXQ_REFILL_PERIOD_ALL_MASK;
  regVal |= MVPP2_TXQ_REFILL_PERIOD_MASK (period);

  pp2_reg_write (port->cpu_slot, MVPP2_TXQ_SCHED_REFILL_REG (txq), regVal);

  return 0;
}

static void
pp2_txsched_remap_weights (struct pp2_port *port, u8 remapped_weights[])
{
  u32 hw_min, user_min = 0xff, user_max = 0x0;
  u8 txq;
  u32 mtu;
  int txPortNum;
  int accommodating_dynamic_range; /* Can user requested range be met after MTU restriction */

  txPortNum = MVPP2_TX_PORT_NUM (port->id);
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
uio_free_info (struct uio_info_t *info)
{
  struct uio_info_t *p1, *p2;

  p1 = info;
  while (p1)
    {
      uio_free_dev_attrs (p1);
      p2 = p1->next;
      if (p1)
	clib_mem_free (p1);
      p1 = p2;
    }
}

static inline int
kstrtou16 (const char *s, unsigned int base, u16 *res)
{
  char *endptr;
  unsigned long ores = strtoul (s, &endptr, base);

  if (endptr == s)
    return -EINVAL;
  *res = (u16) ores;
  return 0;
}

static inline int
kstrtou32 (const char *s, unsigned int base, u32 *res)
{
  char *endptr;
  unsigned long ores = strtoul (s, &endptr, base);

  if (endptr == s)
    return -EINVAL;
  *res = (u32) ores;
  return 0;
}

static inline int
kstrtou8 (const char *s, unsigned int base, u8 *res)
{
  char *endptr;
  unsigned long ores = strtoul (s, &endptr, base);

  if (endptr == s)
    return -EINVAL;
  *res = (u8) ores;
  return 0;
}

static int
list_num_objs (struct list *lst)
{
  struct list *tmp;
  int num_objs = 0;

  if (!list_is_empty (lst))
    LIST_FOR_EACH (tmp, lst)
  num_objs++;

  return num_objs;
}

static u32
lookup_field_id (struct pp2_proto_field proto_field, u32 *field_id, u32 *match_bm)
{
  u32 idx;
  int udf_id;

  if (proto_field.proto == MV_NET_UDF)
    {
      udf_id = pp2_prs_uid_to_prs_udf (proto_field.field.udf.id);
      if (udf_id <= 0)
	{
	  pr_err ("%s(%d) invalid udf number\n", __func__, __LINE__);
	  return -EINVAL;
	}

      switch (udf_id)
	{
	case MVPP2_PRS_SRAM_UDF_TYPE_3:
	  *field_id = CLS_UDF3_FIELD_ID;
	  *match_bm = MVPP2_MATCH_UDF3;
	  break;
	case MVPP2_PRS_SRAM_UDF_TYPE_5:
	  *field_id = CLS_UDF5_FIELD_ID;
	  *match_bm = MVPP2_MATCH_UDF5;
	  break;
	case MVPP2_PRS_SRAM_UDF_TYPE_6:
	  *field_id = CLS_UDF6_FIELD_ID;
	  *match_bm = MVPP2_MATCH_UDF6;
	  break;
	default:
	  pr_err ("%s(%d) reserved udf number\n", __func__, __LINE__);
	  return -EINVAL;
	}
      return 0;
    }

  for (idx = 0; idx < MVPP2_MEMBER_NUM (g_cls_field_convert); idx++)
    {
      if ((proto_field.proto == g_cls_field_convert[idx].proto) &&
	  (proto_field.field.eth == g_cls_field_convert[idx].field))
	{
	  *field_id = g_cls_field_convert[idx].field_to_config;
	  *match_bm = g_cls_field_convert[idx].match_bm;
	  return 0;
	}
    }
  return -ENOENT;
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
  if (port->type == PP2_PPIO_T_LOG)
    qos_entry.tbl_id = QOS_LOG_PORT_TABLE_OFF (port->id);
  else
    qos_entry.tbl_id = port->id;
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
mv_pp2x_parse_mac_address (char *buf, u8 *macaddr_parts)
{
  if (sscanf (buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &macaddr_parts[0], &macaddr_parts[1],
	      &macaddr_parts[2], &macaddr_parts[3], &macaddr_parts[4],
	      &macaddr_parts[5]) == ETH_ALEN)
    return 0;
  else
    return -EFAULT;
}

static void
pp2_bm_pool_assign (struct pp2_port *port, uint32_t pool_id, u32 rxq_id, uint32_t type)
{
  u32 val;
  u32 mask = 0;
  u32 offset = 0;

  if (type == BM_TYPE_LONG_BUF_POOL)
    {
      mask = MVPP22_RXQ_POOL_LONG_MASK;
      offset = MVPP22_RXQ_POOL_LONG_OFFS;
    }
  else if (type == BM_TYPE_SHORT_BUF_POOL)
    {
      mask = MVPP22_RXQ_POOL_SHORT_MASK;
      offset = MVPP22_RXQ_POOL_SHORT_OFFS;
    }

  val = pp2_reg_read (port->cpu_slot, MVPP2_RXQ_CONFIG_REG (rxq_id));
  val &= ~mask;
  val |= ((pool_id << offset) & mask);
  pp2_reg_write (port->cpu_slot, MVPP2_RXQ_CONFIG_REG (rxq_id), val);
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

static int
pp2_cls_c2_data_entry_db_add (struct pp2_inst *inst, struct mv_pp2x_c2_add_entry *c2_entry,
			      u32 *c2_db_idx)
{
  int ret_code;
  struct pp2_cls_c2_data_t *c2_entry_db; /*use heap to reduce stack size*/
  u32 index;

  if (!c2_entry)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!c2_db_idx)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  c2_entry_db = clib_mem_alloc_or_null (sizeof (*c2_entry_db));
  if (!c2_entry_db)
    return -ENOMEM;

  memset (c2_entry_db, 0, sizeof (struct pp2_cls_c2_data_t));

  /* Get available db entry for c2 entry */
  for (index = 0; index < MVPP2_C2_ENTRY_MAX; index++)
    {
      ret_code = pp2_cls_db_c2_data_get (inst, index, c2_entry_db);
      if (ret_code)
	{
	  pr_err ("recvd ret_code(%d)\n", ret_code);
	  if (c2_entry_db)
	    clib_mem_free (c2_entry_db);
	  return ret_code;
	}
      if (c2_entry_db->valid == MVPP2_C2_ENTRY_INVALID)
	break;
    }
  if (index == MVPP2_C2_ENTRY_MAX)
    {
      pr_err ("No free space in DB for C2 entry\n");
      if (c2_entry_db)
	clib_mem_free (c2_entry_db);
      return -EINVAL;
    }

  /* record c2 entry to DB */
  memcpy (&c2_entry_db->port, &c2_entry->port, sizeof (struct mv_pp2x_src_port));
  c2_entry_db->lkp_type = c2_entry->lkp_type;
  c2_entry_db->lkp_type_mask = c2_entry->lkp_type_mask;
  c2_entry_db->priority = c2_entry->priority;
  c2_entry_db->field_bm = c2_entry->mng_pkt_key->pkt_key->field_bm;
  /* pkt Key */
  c2_entry_db->mng_pkt_key.ttl = c2_entry->mng_pkt_key->ttl;
  c2_entry_db->mng_pkt_key.tcp_flag = c2_entry->mng_pkt_key->tcp_flag;
  c2_entry_db->mng_pkt_key.tcp_flag_mask = c2_entry->mng_pkt_key->tcp_flag_mask;
  memcpy (&c2_entry_db->mng_pkt_key.pkt_key, c2_entry->mng_pkt_key->pkt_key,
	  sizeof (struct pp2_cls_pkt_key_t));
  /* Qos */
  memcpy (&c2_entry_db->qos_info, &c2_entry->qos_info, sizeof (struct mv_pp2x_engine_qos_info));
  memcpy (&c2_entry_db->action, &c2_entry->action, sizeof (struct mv_pp2x_engine_pkt_action));
  memcpy (&c2_entry_db->qos_value, &c2_entry->qos_value, sizeof (struct mv_pp2x_qos_value));
  memcpy (&c2_entry_db->pkt_mod, &c2_entry->pkt_mod, sizeof (struct mv_pp2x_engine_pkt_mod));
  memcpy (&c2_entry_db->flow_info, &c2_entry->flow_info, sizeof (struct mv_pp2x_duplicate_info));
  c2_entry_db->valid = MVPP2_C2_ENTRY_VALID;

  /* Write to db */
  ret_code = pp2_cls_db_c2_data_set (inst, index, c2_entry_db);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      if (c2_entry_db)
	clib_mem_free (c2_entry_db);
      return ret_code;
    }

  /* Return db index */
  *c2_db_idx = index;

  if (c2_entry_db)
    clib_mem_free (c2_entry_db);
  return 0;
}

static int
pp2_cls_c2_free_list_add (struct pp2_inst *inst, u32 c2_hw_idx)
{
  struct list *free_list_head;
  struct pp2_cls_c2_index_t *c2_index_node, *temp_node;
  u32 index;
  bool bigger_found = false;

  /* Get list head */
  free_list_head = pp2_cls_db_c2_free_list_head_get (inst);

  /* Check hw index already exist or not */
  LIST_FOR_EACH_OBJECT (temp_node, struct pp2_cls_c2_index_t, free_list_head, list_node)
  {
    if (temp_node->c2_hw_idx == c2_hw_idx)
      return 0;
  }

  /* Get the invalid index node */
  for (index = 0; index < MVPP2_C2_ENTRY_MAX; index++)
    {
      c2_index_node = pp2_cls_db_c2_index_node_get (inst, index);
      if (!c2_index_node)
	return -ENXIO;
      if (c2_index_node->valid == MVPP2_C2_ENTRY_INVALID)
	break;
    }
  if (index == MVPP2_C2_ENTRY_MAX)
    return -ENXIO;

  c2_index_node->c2_hw_idx = c2_hw_idx;

  /* Check free list empty */
  if (list_is_empty (free_list_head))
    {
      list_add (&c2_index_node->list_node, free_list_head);
    }
  else
    {
      /* Add to free list */
      LIST_FOR_EACH_OBJECT (temp_node, struct pp2_cls_c2_index_t, free_list_head, list_node)
      {
	if (temp_node->c2_hw_idx > c2_hw_idx)
	  {
	    bigger_found = true;
	    list_add_to_tail (&c2_index_node->list_node, &temp_node->list_node);
	    break;
	  }
      }
      if (!bigger_found)
	list_add_to_tail (&c2_index_node->list_node, free_list_head);
    }

  /* Change Valid status to valid */
  c2_index_node->valid = MVPP2_C2_ENTRY_VALID;

  return 0;
}

static int
pp2_cls_c2_lkp_type_list_add (struct pp2_inst *inst, u8 lkp_type, u32 priority, u32 c2_hw_idx,
			      u32 c2_db_idx, u32 c2_logic_idx)
{
  int ret_code;
  struct list *lkp_type_list_head;
  struct pp2_cls_c2_index_t *c2_index_node, *temp_node;
  struct pp2_cls_c2_data_t *c2_entry_data; /*use heap to reduce stack size*/
  u32 highest_pri, lowest_pri;
  u32 index;

  /* Get list head */
  lkp_type_list_head = pp2_cls_db_c2_lkp_type_list_head_get (inst, lkp_type);

  /* Get the invalid index node */
  for (index = 0; index < MVPP2_C2_ENTRY_MAX; index++)
    {
      c2_index_node = pp2_cls_db_c2_index_node_get (inst, index);
      if (!c2_index_node)
	return -ENXIO;
      if (c2_index_node->valid == MVPP2_C2_ENTRY_INVALID)
	break;
    }
  if (index == MVPP2_C2_ENTRY_MAX)
    return -ENXIO;

  c2_index_node->c2_hw_idx = c2_hw_idx;
  c2_index_node->c2_data_db_idx = c2_db_idx;
  c2_index_node->c2_logic_idx = c2_logic_idx;

  /* Check lkp list is empty or not */
  if (list_is_empty (lkp_type_list_head))
    {
      /* Just add the new node */
      list_add (&c2_index_node->list_node, lkp_type_list_head);
      /* Change Valid status to valid */
      c2_index_node->valid = MVPP2_C2_ENTRY_VALID;
      return 0;
    }

  ret_code = pp2_cls_c2_lkp_type_list_pri_get (inst, lkp_type, &highest_pri, &lowest_pri);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* New node with highest priority */
  if (highest_pri >= priority)
    {
      /* Just add the new node to first */
      list_add (&c2_index_node->list_node, lkp_type_list_head);
      /* Change Valid status to valid */
      c2_index_node->valid = MVPP2_C2_ENTRY_VALID;
      return 0;
    }

  /* New node with lowest priority */
  if (highest_pri <= priority)
    {
      /* Just add the new node to end */
      list_add_to_tail (&c2_index_node->list_node, lkp_type_list_head);
      /* Change Valid status to valid */
      c2_index_node->valid = MVPP2_C2_ENTRY_VALID;
      return 0;
    }

  c2_entry_data = clib_mem_alloc_or_null (sizeof (*c2_entry_data));
  if (!c2_entry_data)
    return -ENOMEM;

  memset (c2_entry_data, 0, sizeof (struct pp2_cls_c2_data_t));

  /* New node not the highest and lowest, add it after first node with priority lower than new
   * priority */
  /* Traverse lookup type list */
  LIST_FOR_EACH_OBJECT (temp_node, struct pp2_cls_c2_index_t, lkp_type_list_head, list_node)
  {
    /* get C2 db entry data */
    if (pp2_cls_db_c2_data_get (inst, c2_index_node->c2_data_db_idx, c2_entry_data))
      {
	if (c2_entry_data)
	  clib_mem_free (c2_entry_data);
	return -EINVAL;
      }
    if (c2_entry_data->priority > priority)
      {
	list_add_to_tail (&c2_index_node->list_node, &temp_node->list_node);
	/* Change Valid status to valid */
	c2_index_node->valid = MVPP2_C2_ENTRY_VALID;
      }
  }

  if (c2_entry_data)
    clib_mem_free (c2_entry_data);
  return 0;
}

static int
pp2_cls_c2_make_slot (struct pp2_inst *inst, u8 lkp_type, u32 priority, u32 *c2_hw_idx)
{
  int ret_code = 0;
  struct pp2_cls_c2_index_t *c2_index_node = NULL;
  u32 highest_pri = 0, lowest_pri = 0;

  /* Patameter check */
  if (!c2_hw_idx)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  /* check free list empty or not */
  if (list_is_empty (pp2_cls_db_c2_free_list_head_get (inst)))
    {
      pr_err ("No free C2 entry for lookup typs %d, priority %d\n", lkp_type, priority);
      return -EINVAL;
    }

  /* lkp type list empty, find any available slot */
  if (list_is_empty (pp2_cls_db_c2_lkp_type_list_head_get (inst, lkp_type)))
    {
      c2_index_node = LIST_FIRST_OBJECT (pp2_cls_db_c2_free_list_head_get (inst),
					 struct pp2_cls_c2_index_t, list_node);
      /* delete it from free list */
      list_del (&c2_index_node->list_node);
      /* Change to node valid status to invalid */
      c2_index_node->valid = MVPP2_C2_ENTRY_INVALID;
      /* return c2 hw index */
      *c2_hw_idx = c2_index_node->c2_hw_idx;
      return 0;
    }

  /* Get the highest priority and lowest priority */
  ret_code = pp2_cls_c2_lkp_type_list_pri_get (inst, lkp_type, &highest_pri, &lowest_pri);
  if (ret_code != 0)
    {
      pr_err ("Lookup type list(%d) priority get failed\n", lkp_type);
      return -EINVAL;
    }

  /* According to priority and current priority in list, search available slot */
  if (priority <= highest_pri)
    ret_code =
      pp2_cls_c2_make_slot_high (inst, lkp_type, priority, highest_pri, lowest_pri, c2_hw_idx);
  else if (priority >= lowest_pri)
    ret_code =
      pp2_cls_c2_make_slot_low (inst, lkp_type, priority, highest_pri, lowest_pri, c2_hw_idx);
  else
    ret_code =
      pp2_cls_c2_make_slot_middle (inst, lkp_type, priority, highest_pri, lowest_pri, c2_hw_idx);

  return ret_code;
}

static int
pp2_cls_c2_rule_add_check (struct mv_pp2x_c2_add_entry *c2_entry)
{
  struct pp2_cls_field_match_info field_info[MVPP2_FLOW_FIELD_COUNT_MAX + 1];
  int i;
  u32 bits_cnt = 0;

  /* check c2_entry NULL */
  if (!c2_entry)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  /* Port check */
  if (c2_entry->port.port_type > MVPP2_SRC_PORT_TYPE_VIR ||
      c2_entry->port.port_type < MVPP2_SRC_PORT_TYPE_PHY)
    {
      pr_err ("Invalid port type(%d)\n", c2_entry->port.port_type);
      return -EFAULT;
    }
  if (c2_entry->port.port_type == MVPP2_SRC_PORT_TYPE_VIR)
    {
      if (c2_entry->port.port_value > MVPP2_VIRT_PORT_ID_MAX)
	{
	  pr_err ("Invalid Virt port ID(%d)\n", c2_entry->port.port_value);
	  return -EFAULT;
	}
    }

  /* Lookup type check */
  if (c2_entry->lkp_type >= MVPP2_C2_LKP_TYPE_MAX)
    {
      pr_err ("Invalid lookup type(%d)\n", c2_entry->lkp_type);
      return -EFAULT;
    }

  /* Packet key check  */
  if (!c2_entry->mng_pkt_key)
    {
      pr_err ("Input NULL pointer\n");
      return -EFAULT;
    }
  /* Get field info */
  memset (field_info, 0,
	  sizeof (struct pp2_cls_field_match_info) * (MVPP2_FLOW_FIELD_COUNT_MAX + 1));
  if (pp2_cls_field_bm_to_field_info (c2_entry->mng_pkt_key->pkt_key->field_bm,
				      c2_entry->mng_pkt_key, MVPP2_FLOW_FIELD_COUNT_MAX + 1, true,
				      field_info))
    {
      pr_err ("Field info get failed\n");
      return -EFAULT;
    }
  /* Check field number, if greater than 4, invalid */
  if (field_info[MVPP2_FLOW_FIELD_COUNT_MAX].valid == MVPP2_FIELD_VALID)
    {
      pr_err ("At most 4 fileds are supported\n");
      return -EFAULT;
    }
  /*
   * Raw check field length(detail check will be done in pp2_cls_c2_tcam_hek_get),
   * total can not more than 8 bytes
   */
  for (i = 0; i < MVPP2_FLOW_FIELD_COUNT_MAX; i++)
    {
      if (field_info[i].valid == MVPP2_FIELD_VALID)
	bits_cnt += pp2_cls_field_size_get (field_info[i].field_id);
    }
  if (bits_cnt > MVPP2_C2_TCAM_KEY_LEN_MAX * BYTE_BITS)
    {
      pr_err ("Packet key length(%d bits) beyond C2 capability\n", bits_cnt);
      return -EFAULT;
    }

  /* QOS check, TBD */

  /* Action check, TBD */

  /* Mod info check */
  if (c2_entry->pkt_mod.mod_cmd_idx > MVPP2_HWF_MOD_IPTR_MAX)
    {
      pr_err ("Invalid modification cmd index(%d)\n", c2_entry->pkt_mod.mod_cmd_idx);
      return -EFAULT;
    }
  if (c2_entry->pkt_mod.mod_data_idx > MVPP2_HW_MOD_DPTR_MAX)
    {
      pr_err ("Invalid data index(%d)\n", c2_entry->pkt_mod.mod_data_idx);
      return -EFAULT;
    }

  /* Duplication flow info check */

  return 0;
}

static u8
pp2_cls_c2_tcam_lkp_type_get (struct mv_pp2x_cls_c2_entry *c2)
{
  return (c2->tcam.words[4] & MVPP2_CLS_C2_HEK_LKP_TYPE_MASK);
}

static int
pp2_cls_c2_tcam_set (uintptr_t cpu_slot, struct mv_pp2x_c2_add_entry *c2_entry, u32 c2_hw_idx)
{
  int ret_code;
  struct mv_pp2x_cls_c2_entry pp2_cls_c2_entry;
  int hek_offs;
  u8 hek_byte[MVPP2_C2_HEK_OFF_MAX], hek_byte_mask[MVPP2_C2_HEK_OFF_MAX];

  if (!c2_entry)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  /* Clear C2 sw data */
  memset (&pp2_cls_c2_entry, 0, sizeof (struct mv_pp2x_cls_c2_entry));

  /* Set QOS table, selection and ID */
  ret_code = mv_pp2x_cls_c2_qos_tbl_set (&pp2_cls_c2_entry, c2_entry->qos_info.qos_tbl_index,
					 c2_entry->qos_info.qos_tbl_type);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set color, cmd and source */
  ret_code = mv_pp2x_cls_c2_color_set (&pp2_cls_c2_entry, c2_entry->action.color_act,
				       c2_entry->qos_info.color_src);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set priority(pbit), cmd, value(not from qos table) and source */
  ret_code = mv_pp2x_cls_c2_prio_set (&pp2_cls_c2_entry, c2_entry->action.pri_act,
				      c2_entry->qos_value.pri, c2_entry->qos_info.pri_dscp_src);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set DSCP, cmd, value(not from qos table) and source */
  ret_code = mv_pp2x_cls_c2_dscp_set (&pp2_cls_c2_entry, c2_entry->action.dscp_act,
				      c2_entry->qos_value.dscp, c2_entry->qos_info.pri_dscp_src);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set gemport ID, cmd, value, and source */
  ret_code = mv_pp2x_cls_c2_gpid_set (&pp2_cls_c2_entry, c2_entry->action.gemp_act,
				      c2_entry->qos_value.gemp, c2_entry->qos_info.gemport_src);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set queue low, cmd, value, and source */
  ret_code = mv_pp2x_cls_c2_queue_low_set (&pp2_cls_c2_entry, c2_entry->action.q_low_act,
					   c2_entry->qos_value.q_low, c2_entry->qos_info.q_low_src);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set queue high, cmd, value and source */
  ret_code =
    mv_pp2x_cls_c2_queue_high_set (&pp2_cls_c2_entry, c2_entry->action.q_high_act,
				   c2_entry->qos_value.q_high, c2_entry->qos_info.q_high_src);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set forward */
  ret_code = mv_pp2x_cls_c2_forward_set (&pp2_cls_c2_entry, c2_entry->action.frwd_act);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set RSS */
  ret_code = mv_pp2x_cls_c2_rss_set (&pp2_cls_c2_entry, c2_entry->action.rss_act, c2_entry->rss_en);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set policer */
  ret_code =
    mv_pp2x_cls_c2_policer_set (&pp2_cls_c2_entry, c2_entry->action.policer_act,
				c2_entry->qos_info.policer_id & MVPP2_CLS2_ACT_DUP_ATTR_PLCRID_MAX,
				MVPP2_POLICER_2_BANK (c2_entry->qos_info.policer_id));
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set flowID(not for multicast) */
  ret_code = mv_pp2x_cls_c2_flow_id_en (&pp2_cls_c2_entry, c2_entry->action.flowid_act);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set modification info */
  ret_code =
    mv_pp2x_cls_c2_mod_set (&pp2_cls_c2_entry, c2_entry->pkt_mod.mod_data_idx,
			    c2_entry->pkt_mod.mod_cmd_idx, c2_entry->pkt_mod.l4_chksum_update_flag);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  /* Set duplication */
  ret_code = mv_pp2x_cls_c2_dup_set (&pp2_cls_c2_entry, c2_entry->flow_info.flow_id,
				     c2_entry->flow_info.flow_cnt);
  if (ret_code)
    {
      pr_err ("failed to call mv_pp2x_cls_c2_dup_set\n");
      return ret_code;
    }

  /* Set C2 HEK */
  memset (hek_byte, 0, MVPP2_C2_HEK_OFF_MAX);
  memset (hek_byte_mask, 0, MVPP2_C2_HEK_OFF_MAX);
  ret_code = pp2_cls_c2_tcam_hek_get (c2_entry->mng_pkt_key->pkt_key->field_bm, c2_entry, hek_byte,
				      hek_byte_mask);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  for (hek_offs = MVPP2_C2_HEK_OFF_PORT_ID; hek_offs >= MVPP2_C2_HEK_OFF_BYTE0; hek_offs--)
    {
      ret_code = mv_pp2x_cls_c2_tcam_byte_set (&pp2_cls_c2_entry, hek_offs, hek_byte[hek_offs],
					       hek_byte_mask[hek_offs]);
      if (ret_code)
	{
	  pr_err ("recvd ret_code(%d)\n", ret_code);
	  return ret_code;
	}
    }

  /* Write C2 entry data to HW */
  ret_code = mv_pp2x_cls_c2_hw_write (cpu_slot, c2_hw_idx, &pp2_cls_c2_entry);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      return ret_code;
    }

  return 0;
}

static int
pp2_cls_c3_hw_query_add (uintptr_t cpu_slot, struct pp2_cls_c3_entry *c3, int max_search_depth,
			 struct pp2_cls_c3_hash_pair *hash_pair_arr)
{
  int used_index[MVPP2_CLS3_HASH_BANKS_NUM] = { 0 };
  u8 occupied_bmp;
  int idx, index_free, hek_size, ret_val, ext_index = 0;

  ret_val = pp2_cls_c3_hw_query (cpu_slot, c3, &occupied_bmp, used_index);
  if (ret_val != 0)
    {
      pr_err ("%s:Error - pp2_cls_c3_hw_query failed\n", __func__);
      return ret_val;
    }

  /* Select available entry index */
  for (idx = 0; idx < MVPP2_CLS3_HASH_BANKS_NUM; idx++)
    {
      if (!(occupied_bmp & (1 << idx)))
	break;
    }

  /* Available index did not found, try to relocate another key */
  if (idx == MVPP2_CLS3_HASH_BANKS_NUM)
    {
      for (idx = 0; idx < MVPP2_CLS3_HASH_BANKS_NUM; idx++)
	{
	  if (pp2_cls_c3_hw_query_add_relocate (cpu_slot, used_index[idx], max_search_depth,
						0 /*curren depth*/, hash_pair_arr) == 0)
	    break;
	}

      if (idx == MVPP2_CLS3_HASH_BANKS_NUM)
	{
	  /* Available index did not found*/
	  pr_err ("%s:Error - HASH table is full.\n", __func__);
	  return -EIO;
	}
    }

  index_free = used_index[idx];

  hek_size = ((c3->key.key_ctrl & KEY_CTRL_HEK_SIZE_MASK) >> KEY_CTRL_HEK_SIZE);

  if (hek_size > MVPP2_CLS_C3_HEK_BYTES)
    {
      /* Get Free Extension Index */
      ext_index = pp2_cls_c3_shadow_ext_free_get ();

      if (ext_index == MVPP2_CLS_C3_EXT_TBL_SIZE)
	{
	  pr_err ("%s:Error - Extension table is full.\n", __func__);
	  return -EIO;
	}
    }

  ret_val = pp2_cls_c3_hw_add (cpu_slot, c3, index_free, ext_index);
  if (ret_val != 0)
    {
      pr_err ("%s:Error - pp2_cls_c3_hw_add failed\n", __func__);
      return ret_val;
    }

  if (hek_size > MVPP2_CLS_C3_HEK_BYTES)
    pr_info ("Added C3 entry @ index=0x%.3x ext=0x%.3x\n", index_free, ext_index);
  else
    pr_info ("Added C3 entry @ index=0x%.3x\n", index_free);

  return 0;
}

static int
pp2_cls_c3_rule_check (struct pp2_cls_c3_add_entry_t *c3_entry)
{
  struct pp2_cls_field_match_info field_info[MVPP2_FLOW_FIELD_COUNT_MAX + 1];
  int idx;
  struct pp2_cls_c3_entry c3;
  u32 bits_cnt = 0;
  int rc = 0;

  pr_debug ("reached\n");

  /* NULL validation */
  if (mv_pp2x_ptr_validate (c3_entry))
    return -EINVAL;

  /* port check */
  if (mv_pp2x_range_validate (c3_entry->port.port_type, 0, MVPP2_SRC_PORT_TYPE_VIR))
    return -EINVAL;

  if (c3_entry->port.port_type == MVPP2_SRC_PORT_TYPE_VIR)
    {
      if (c3_entry->port.port_value > MVPP2_VIRT_PORT_ID_MAX)
	{
	  pr_err ("Invalid Virt port ID(%d)\n", c3_entry->port.port_value);
	  return -EIO;
	}
    }

  /* lookup type check */
  if (mv_pp2x_range_validate (c3_entry->lkp_type, 0, KEY_CTRL_LKP_TYPE_MAX))
    return -EINVAL;

  /* packet key check  */
  if (mv_pp2x_ptr_validate (c3_entry->mng_pkt_key) == MV_ERROR)
    return -EINVAL;

  /* get field info */
  memset (field_info, 0,
	  sizeof (struct pp2_cls_field_match_info) * (MVPP2_FLOW_FIELD_COUNT_MAX + 1));
  if (pp2_cls_field_bm_to_field_info (c3_entry->mng_pkt_key->pkt_key->field_bm,
				      c3_entry->mng_pkt_key, MVPP2_FLOW_FIELD_COUNT_MAX + 1, false,
				      field_info))
    {
      pr_err ("Field info get failed\n");
      return -EIO;
    }

  /* if not 5T, check field number -> if greater than 4 is invalid */
  if ((c3_entry->mng_pkt_key->pkt_key->field_bm != MVPP2_MATCH_IPV4_5T) &&
      (c3_entry->mng_pkt_key->pkt_key->field_bm != MVPP2_MATCH_IPV6_5T) &&
      (field_info[MVPP2_FLOW_FIELD_COUNT_MAX].valid == MVPP2_FIELD_VALID))
    {
      pr_err ("At most 4 fileds are supported\n");
      return -EIO;
    }
  /* raw check field length, total can not more than 36 bytes */
  for (idx = 0; idx < MVPP2_FLOW_FIELD_COUNT_MAX; idx++)
    {
      if (field_info[idx].valid == MVPP2_FIELD_VALID)
	bits_cnt += pp2_cls_field_size_get (field_info[idx].field_id);
    }
  if (bits_cnt > MVPP2_C3_MAX_HASH_KEY_SIZE * BYTE_BITS)
    {
      pr_err ("Packet key length(%d bits) beyond C3 capability\n", bits_cnt);
      return -EIO;
    }

  /* QOS check, TBD */

  /* Action check, TBD */

  /* Mod info check */
  if (c3_entry->pkt_mod.mod_cmd_idx > MVPP2_HWF_MOD_IPTR_MAX)
    {
      pr_err ("Invalid modification cmd index(%d)\n", c3_entry->pkt_mod.mod_cmd_idx);
      return -EIO;
    }
  if (c3_entry->pkt_mod.mod_data_idx > MVPP2_HW_MOD_DPTR_MAX)
    {
      pr_err ("Invalid data index(%d)\n", c3_entry->pkt_mod.mod_data_idx);
      return -EIO;
    }

  /* Duplication flow info check */
  rc = pp2_cls_c3_rule_convert (c3_entry, &c3);
  if (rc)
    {
      pr_err ("failed to convert C3 key\n");
      return rc;
    }

  /* To be implemented later: for rule update, maybe 2 rules have the same key may co-exist for a
   * short time, so the repeat check will blcok rule update, remove it temporary, and in future
   * commit maybe a new method found to implement it.
   */

  return 0;
}

static int
pp2_cls_c3_rule_convert (struct pp2_cls_c3_add_entry_t *mng_entry,
			 struct pp2_cls_c3_entry *hw_entry)
{
  enum pp2_cls_l4_type_t l4_type;
  u32 hek_bytes;
  int hek_offs;
  u8 hek[MVPP2_C3_MAX_HASH_KEY_SIZE];
  int rc = 0;

  pr_debug ("reached\n");

  /* NULL validation */
  if (mv_pp2x_ptr_validate (mng_entry))
    return -EINVAL;

  if (mv_pp2x_ptr_validate (hw_entry))
    return -EINVAL;

  /* init c3 entry */
  pp2_cls_c3_sw_clear (hw_entry);

  /* set L4 info  for NAPT 5-tupple */
  if (mng_entry->mng_pkt_key->pkt_key->field_bm == MVPP2_MATCH_IPV4_5T ||
      mng_entry->mng_pkt_key->pkt_key->field_bm == MVPP2_MATCH_IPV6_5T)
    {
      if (mng_entry->mng_pkt_key->pkt_key->ipvx_add.ip_proto == IPPROTO_TCP)
	l4_type = MVPP2_L4_TYPE_TCP;
      else if (mng_entry->mng_pkt_key->pkt_key->ipvx_add.ip_proto == IPPROTO_UDP)
	l4_type = MVPP2_L4_TYPE_UDP;
      else
	l4_type = MVPP2_L4_TYPE_TCP; /* default one */

      rc = pp2_cls_c3_sw_l4_info_set (hw_entry, l4_type);
      if (rc)
	{
	  pr_err ("failed to call pp2_cls_c3_sw_l4_info_set\n");
	  return rc;
	}
    }

  /* set lookup type */
  rc = pp2_cls_c3_sw_lkp_type_set (hw_entry, mng_entry->lkp_type);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_sw_lkp_type_set\n");
      return rc;
    }

  /* set port ID */
  rc = pp2_cls_c3_sw_port_id_set (hw_entry, mng_entry->port.port_type, mng_entry->port.port_value);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_sw_port_id_set\n");
      return rc;
    }

  /* set HEK */
  rc = pp2_cls_c3_hek_generate (mng_entry, &hek_bytes, hek);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_hek_generate\n");
      return rc;
    }

  for (hek_offs = MVPP2_C3_MAX_HASH_KEY_SIZE - 1; hek_offs >= 0; hek_offs--)
    {
      if (pp2_cls_c3_sw_hek_byte_set (hw_entry, hek_offs, hek[hek_offs]) != MV_OK)
	return MV_ERROR;
    }

  rc = pp2_cls_c3_sw_hek_size_set (hw_entry, hek_bytes);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_sw_hek_size_set\n");
      return rc;
    }

  /* set color */
  rc = pp2_cls_c3_color_set (hw_entry, mng_entry->action.color_act);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_color_set\n");
      return rc;
    }

  /* set queue high */
  rc =
    pp2_cls_c3_queue_high_set (hw_entry, mng_entry->action.q_high_act, mng_entry->qos_value.q_high);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_queue_high_set\n");
      return rc;
    }

  /* set queue low */
  rc = pp2_cls_c3_queue_low_set (hw_entry, mng_entry->action.q_low_act, mng_entry->qos_value.q_low);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_queue_low_set\n");
      return rc;
    }

  /* set forward */
  rc = pp2_cls_c3_forward_set (hw_entry, mng_entry->action.frwd_act);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_forward_set\n");
      return rc;
    }

  /* set rss */
  rc = pp2_cls_c3_rss_set (hw_entry, mng_entry->action.rss_act, mng_entry->rss_en);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_rss_set\n");
      return rc;
    }

  /* Set policer */
  rc = pp2_cls_c3_policer_set (hw_entry, mng_entry->action.policer_act,
			       mng_entry->qos_info.policer_id & MVPP2_CLS3_ACT_DUP_POLICER_MAX,
			       MVPP2_POLICER_2_BANK (mng_entry->qos_info.policer_id));
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_policer_set\n");
      return rc;
    }

  /* set flow ID */
  rc = pp2_cls_c3_flow_id_en (hw_entry, mng_entry->action.flowid_act);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_flow_id_en\n");
      return rc;
    }

  /* set mod */
  rc =
    pp2_cls_c3_mod_set (hw_entry, mng_entry->pkt_mod.mod_data_idx, mng_entry->pkt_mod.mod_cmd_idx,
			mng_entry->pkt_mod.l4_chksum_update_flag);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_mod_set\n");
      return rc;
    }

  /* set duplication */
  rc = pp2_cls_c3_dup_set (hw_entry, mng_entry->flow_info.flow_id, mng_entry->flow_info.flow_cnt);
  if (rc)
    {
      pr_err ("failed to call pp2_cls_c3_dup_set\n");
      return rc;
    }

  return rc;
}

static void
pp2_cls_c3_sw_clear (struct pp2_cls_c3_entry *c3)
{
  memset (c3, 0, sizeof (struct pp2_cls_c3_entry));
}

static int
pp2_cls_db_c3_entry_add (struct pp2_inst *inst, u32 logic_idx, u32 hash_idx)
{
  if (mv_pp2x_range_validate (logic_idx, 0, MVPP2_CLS_C3_HASH_TBL_SIZE - 1))
    return -EINVAL;

  if (mv_pp2x_range_validate (hash_idx, 0, MVPP2_CLS_C3_HASH_TBL_SIZE - 1))
    return -EINVAL;

  /* add or update hash index table */
  inst->cls_db->c3_db.hash_idx_tbl[logic_idx].valid = MVPP2_C3_ENTRY_VALID;
  inst->cls_db->c3_db.hash_idx_tbl[logic_idx].hash_idx = hash_idx;

  /* add or update logical index table */
  inst->cls_db->c3_db.logic_idx_tbl[hash_idx].valid = MVPP2_C3_ENTRY_VALID;
  inst->cls_db->c3_db.logic_idx_tbl[hash_idx].logic_idx = logic_idx;

  return 0;
}

static int
pp2_cls_db_c3_free_logic_idx_get (struct pp2_inst *inst, u32 *logic_idx)
{
  int idx;

  if (mv_pp2x_ptr_validate (logic_idx))
    return -EINVAL;

  /* search for valid C3 logical index */
  for (idx = 0; idx < MVPP2_CLS_C3_HASH_TBL_SIZE; idx++)
    {
      if (inst->cls_db->c3_db.hash_idx_tbl[idx].valid == MVPP2_C3_ENTRY_INVALID)
	break;
    }

  if (idx >= MVPP2_CLS_C3_HASH_TBL_SIZE)
    {
      *logic_idx = 0;
      return -EIO;
    }

  *logic_idx = idx;

  return 0;
}

static int
pp2_cls_db_c3_hash_idx_update (struct pp2_inst *inst, struct pp2_cls_c3_hash_pair *hash_pair_arr)
{
  int idx;
  u32 old_idx;
  u32 new_idx;
  u32 logic_idx;
  struct pp2_cls_c3_hash_index_entry_t *p_hash_entry = NULL;
  struct pp2_cls_c3_logic_index_entry_t *p_logic_entry = NULL;

  if (mv_pp2x_ptr_validate (hash_pair_arr))
    return -EINVAL;

  /* update the multihash mapping in loop */
  for (idx = 0; idx < hash_pair_arr->pair_num; idx++)
    {
      old_idx = hash_pair_arr->old_idx[idx];
      new_idx = hash_pair_arr->new_idx[idx];

      if (mv_pp2x_range_validate (old_idx, 0, MVPP2_CLS_C3_HASH_TBL_SIZE - 1))
	return -EINVAL;

      if (mv_pp2x_range_validate (new_idx, 0, MVPP2_CLS_C3_HASH_TBL_SIZE - 1))
	return -EINVAL;

      p_logic_entry = &inst->cls_db->c3_db.logic_idx_tbl[old_idx];
      if (p_logic_entry->valid == MVPP2_C3_ENTRY_INVALID)
	{
	  pr_err ("hash entry is invalid w/ index(%d)\n", old_idx);
	  return MV_ERROR;
	}

      logic_idx = p_logic_entry->logic_idx;

      if (mv_pp2x_range_validate (logic_idx, 0, MVPP2_CLS_C3_HASH_TBL_SIZE - 1))
	return -EINVAL;

      /* update logical index table */
      p_logic_entry->valid = MVPP2_C3_ENTRY_INVALID;
      p_logic_entry->logic_idx = MVPP2_C3_INVALID_ENTRY_NUM;
      p_logic_entry = &inst->cls_db->c3_db.logic_idx_tbl[new_idx];
      p_logic_entry->valid = MVPP2_C3_ENTRY_VALID;
      p_logic_entry->logic_idx = logic_idx;

      /* update hash index table */
      p_hash_entry = &inst->cls_db->c3_db.hash_idx_tbl[logic_idx];
      p_hash_entry->valid = MVPP2_C3_ENTRY_VALID;
      p_hash_entry->hash_idx = new_idx;
    }

  return 0;
}

static int
pp2_cls_db_c3_search_depth_get (struct pp2_inst *inst, u32 *search_depth)
{
  if (mv_pp2x_ptr_validate (search_depth))
    return -EINVAL;

  *search_depth = inst->cls_db->c3_db.max_search_depth;

  return 0;
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

static void
pp2_cls_edrop_bypass_assign_qid (struct pp2_inst *inst, u8 qid)
{
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  mv_pp2x_plcr_hw_rxq_thresh_set (cpu_slot, qid, MVPP2_EDROP_BYPASS_THRESH_ID);
}

static int
pp2_cls_fl_port_hw_read (struct pp2_inst *inst, int rl_log_id, int *port_bm)
{
  struct mv_pp2x_cls_flow_entry fe;
  int port_type;
  int rc;
  u16 off;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  /* get the rule offset according to rule logical ID */
  rc = pp2_db_cls_rl_off_get (inst, &off, rl_log_id);
  if (rc)
    {
      pr_err ("%s(%d): recvd ret_code(%d)\n", __func__, __LINE__, rc);
      return rc;
    }

  rc = mv_pp2x_cls_hw_flow_read (cpu_slot, off, &fe);
  if (rc)
    {
      pr_err ("%s(%d): recvd ret_code(%d)\n", __func__, __LINE__, rc);
      return rc;
    }

  rc = mv_pp2x_cls_sw_flow_port_get (&fe, &port_type, port_bm);
  if (rc)
    {
      pr_err ("%s(%d): recvd ret_code(%d)\n", __func__, __LINE__, rc);
      return rc;
    }

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

  val = (port->id << MVPP22_ISR_RXQ_GROUP_INDEX_GROUP_OFFSET) | sub_group;
  pp2_reg_write (cpu_slot, MVPP22_ISR_RXQ_GROUP_INDEX_REG, val);

  return pp2_reg_read (cpu_slot, MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG);
}

static inline void
pp2_port_isr_rx_group_write (struct pp2_port *port, int sub_group, int start_queue,
			     int num_rx_queues)
{
  int val;
  uintptr_t cpu_slot = port->cpu_slot;

  val = (port->id << MVPP22_ISR_RXQ_GROUP_INDEX_GROUP_OFFSET) | sub_group;
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

  if (rxq->edrop)
    {
      pp2_cls_edrop_assign_qid (port->parent, rxq->edrop->id, rxq->id, false);
      rxq->edrop = NULL;
    }

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

  txPortNum = MVPP2_TX_PORT_NUM (port->id);
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

  txPortNum = MVPP2_TX_PORT_NUM (port->id);
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

static int
pp2_txsched_rate_calc (u32 rate, u32 accuracy, u32 *pperiod, u32 *ptokens)
{
  /* Calculate refill tokens and period - rate [kbps] = tokens [bits] * 1000 / period [usec] */
  /* Assume:  Tclock [MHz] / BasicRefillNoOfClocks = 1 */
  u32 period, tokens, calc;
  s32 var;

  if (rate == 0)
    {
      /* Disable traffic from the port: tokens = 0 */
      if (pperiod != NULL)
	*pperiod = 1000;

      if (ptokens != NULL)
	*ptokens = 0;

      return 0;
    }

  /* Find values of "period" and "tokens" match "rate" and "accuracy" when period is minimal */
  for (period = 1; period <= 1000; period++)
    {
      tokens = 1;
      while (true)
	{
	  calc = (tokens * 1000) / period;
	  var = ((calc - rate) * 100) / 100;
	  var = (var > 0) ? var : -var;
	  if (var <= accuracy)
	    {
	      if (pperiod != NULL)
		*pperiod = period;
	      if (ptokens != NULL)
		*ptokens = tokens;

	      return 0;
	    }
	  if (calc > rate)
	    break;

	  tokens++;
	}
    }
  return -EDOM;
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

static void
uio_free_dev_attrs (struct uio_info_t *info)
{
  struct uio_dev_attr_t *p1, *p2;

  p1 = info->dev_attrs;
  while (p1)
    {
      p2 = p1->next;
      if (p1)
	clib_mem_free (p1);
      p1 = p2;
    }
  info->dev_attrs = NULL;
}

static int
mv_pp2x_cls_c2_dscp_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int dscp, int from)
{
  if (!c2 || cmd > MVPP2_ACTION_TYPE_UPDT_LOCK || dscp >= MVPP2_QOS_TBL_LINE_NUM_DSCP)
    return -EINVAL;

  /*set command */
  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_DSCP_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_DSCP_OFF);

  /*set modify DSCP value */
  c2->sram.regs.qos_attr &= ~MVPP2_CLS2_ACT_QOS_ATTR_DSCP_MASK;
  c2->sram.regs.qos_attr |=
    ((dscp << MVPP2_CLS2_ACT_QOS_ATTR_DSCP_OFF) & MVPP2_CLS2_ACT_QOS_ATTR_DSCP_MASK);

  if (from == 1)
    c2->sram.regs.action_tbl |= (1 << MVPP2_CLS2_ACT_DATA_TBL_PRI_DSCP_OFF);
  else
    c2->sram.regs.action_tbl &= ~(1 << MVPP2_CLS2_ACT_DATA_TBL_PRI_DSCP_OFF);

  return 0;
}

static int
mv_pp2x_cls_c2_dup_set (struct mv_pp2x_cls_c2_entry *c2, int dupid, int count)
{
  if (mv_pp2x_ptr_validate (c2) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (count, 0, MVPP2_CLS2_ACT_DUP_ATTR_DUPCNT_MAX) == MV_ERROR)
    return MV_ERROR;
  if (mv_pp2x_range_validate (dupid, 0, MVPP2_CLS2_ACT_DUP_ATTR_DUPID_MAX) == MV_ERROR)
    return MV_ERROR;

  /*set flowid and count*/
  c2->sram.regs.rss_attr &=
    ~(MVPP2_CLS2_ACT_DUP_ATTR_DUPID_MASK | MVPP2_CLS2_ACT_DUP_ATTR_DUPCNT_MASK);
  c2->sram.regs.rss_attr |= (dupid << MVPP2_CLS2_ACT_DUP_ATTR_DUPID_OFF);
  c2->sram.regs.rss_attr |= (count << MVPP2_CLS2_ACT_DUP_ATTR_DUPCNT_OFF);

  return 0;
}

static int
mv_pp2x_cls_c2_flow_id_en (struct mv_pp2x_cls_c2_entry *c2, int flow_id_en)
{
  if (!c2)
    return -EINVAL;

  /*set Flow ID enable or disable */
  if (flow_id_en)
    c2->sram.regs.actions |= (1 << MVPP2_CLS2_ACT_FLD_EN_OFF);
  else
    c2->sram.regs.actions &= ~(1 << MVPP2_CLS2_ACT_FLD_EN_OFF);

  return 0;
}

static int
mv_pp2x_cls_c2_forward_set (struct mv_pp2x_cls_c2_entry *c2, int cmd)
{
  if (!c2 || cmd > MVPP2_ACTION_TYPE_UPDT_LOCK)
    return -EINVAL;

  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_FRWD_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_FRWD_OFF);

  return 0;
}

static int
mv_pp2x_cls_c2_gpid_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int gpid, int from)
{
  if (mv_pp2x_ptr_validate (c2) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (cmd, 0, MVPP2_ACTION_TYPE_UPDT_LOCK) == MV_ERROR)
    return MV_ERROR;
  if (mv_pp2x_range_validate (gpid, 0, MVPP2_CLS2_ACT_QOS_ATTR_GEM_MAX) == MV_ERROR)
    return MV_ERROR;
  /*set command*/
  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_GEM_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_GEM_OFF);

  /*set modify DSCP value*/
  c2->sram.regs.qos_attr &= ~MVPP2_CLS2_ACT_QOS_ATTR_GEM_MASK;
  c2->sram.regs.qos_attr |= (gpid << MVPP2_CLS2_ACT_QOS_ATTR_GEM_OFF);

  if (from == 1)
    c2->sram.regs.action_tbl |= (1 << MVPP2_CLS2_ACT_DATA_TBL_GEM_ID_OFF);
  else
    c2->sram.regs.action_tbl &= ~(1 << MVPP2_CLS2_ACT_DATA_TBL_GEM_ID_OFF);

  return 0;
}

static int
mv_pp2x_cls_c2_mod_set (struct mv_pp2x_cls_c2_entry *c2, int data_ptr, int instr_offs, int l4_csum)
{
  if (mv_pp2x_ptr_validate (c2) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (data_ptr, 0, MVPP2_CLS2_ACT_HWF_ATTR_DPTR_MAX) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (instr_offs, 0, MVPP2_CLS2_ACT_HWF_ATTR_IPTR_MAX) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (l4_csum, 0, 1) == MV_ERROR)
    return MV_ERROR;

  c2->sram.regs.hwf_attr &= ~MVPP2_CLS2_ACT_HWF_ATTR_DPTR_MASK;
  c2->sram.regs.hwf_attr &= ~MVPP2_CLS2_ACT_HWF_ATTR_IPTR_MASK;
  c2->sram.regs.hwf_attr &= ~MVPP2_CLS2_ACT_HWF_ATTR_L4CHK_MASK;

  c2->sram.regs.hwf_attr |= (data_ptr << MVPP2_CLS2_ACT_HWF_ATTR_DPTR_OFF);
  c2->sram.regs.hwf_attr |= (instr_offs << MVPP2_CLS2_ACT_HWF_ATTR_IPTR_OFF);
  c2->sram.regs.hwf_attr |= (l4_csum << MVPP2_CLS2_ACT_HWF_ATTR_L4CHK_OFF);

  return 0;
}

static int
mv_pp2x_cls_c2_prio_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int prio, int from)
{
  if (!c2 || cmd > MVPP2_ACTION_TYPE_UPDT_LOCK || prio >= MVPP2_QOS_TBL_LINE_NUM_PRI)
    return -EINVAL;

  /*set command */
  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_PRI_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_PRI_OFF);

  /*set modify priority value */
  c2->sram.regs.qos_attr &= ~MVPP2_CLS2_ACT_QOS_ATTR_PRI_MASK;
  c2->sram.regs.qos_attr |=
    ((prio << MVPP2_CLS2_ACT_QOS_ATTR_PRI_OFF) & MVPP2_CLS2_ACT_QOS_ATTR_PRI_MASK);

  if (from == 1)
    c2->sram.regs.action_tbl |= (1 << MVPP2_CLS2_ACT_DATA_TBL_PRI_DSCP_OFF);
  else
    c2->sram.regs.action_tbl &= ~(1 << MVPP2_CLS2_ACT_DATA_TBL_PRI_DSCP_OFF);

  return 0;
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
mv_pp2x_cls_c2_qos_tbl_set (struct mv_pp2x_cls_c2_entry *c2, int tbl_id, int tbl_sel)
{
  if (!c2 || tbl_sel > 1)
    return -EINVAL;

  if (tbl_sel == 1)
    {
      /*dscp */
      if (tbl_id >= MVPP2_QOS_TBL_NUM_DSCP)
	return -EINVAL;
    }
  else
    {
      /*pri */
      if (tbl_id >= MVPP2_QOS_TBL_NUM_PRI)
	return -EINVAL;
    }
  c2->sram.regs.action_tbl =
    (tbl_id << MVPP2_CLS2_ACT_DATA_TBL_ID_OFF) | (tbl_sel << MVPP2_CLS2_ACT_DATA_TBL_SEL_OFF);

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

static int
mv_pp2x_cls_c2_tcam_byte_set (struct mv_pp2x_cls_c2_entry *c2, unsigned int offs,
			      unsigned char byte, unsigned char enable)
{
  if (!c2 || offs >= MVPP2_CLS_C2_TCAM_DATA_BYTES)
    return -EINVAL;

  c2->tcam.bytes[TCAM_DATA_BYTE (offs)] = byte;
  c2->tcam.bytes[TCAM_DATA_MASK (offs)] = enable;

  return 0;
}

static int
mv_pp2x_plcr_hw_rxq_thresh_set (uintptr_t cpu_slot, int rxq, int idx)
{
  pp2_reg_write (cpu_slot, MVPP2_PLCR_EDROP_RXQ_REG, rxq);
  pp2_reg_write (cpu_slot, MVPP2_PLCR_EDROP_RXQ_TR_REG, idx);

  return MV_OK;
}

static int
pp2_cls_c2_lkp_type_list_pri_get (struct pp2_inst *inst, u8 lkp_type, u32 *hignest_pri,
				  u32 *lowest_pri)
{
  struct list *lkp_type_list_head;
  struct pp2_cls_c2_index_t *c2_index_node;
  struct pp2_cls_c2_data_t *c2_entry_data; /*use heap to reduce stack size*/

  /* param check */
  if (!hignest_pri)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!lowest_pri)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  /* Get list head */
  lkp_type_list_head = pp2_cls_db_c2_lkp_type_list_head_get (inst, lkp_type);

  if (list_is_empty (lkp_type_list_head))
    {
      pr_err ("C2 engine lookup type list (%d) is empty\n", lkp_type);
      return -EFAULT;
    }

  /* Get first priority */
  c2_index_node = LIST_FIRST_OBJECT (lkp_type_list_head, struct pp2_cls_c2_index_t, list_node);

  c2_entry_data = clib_mem_alloc_or_null (sizeof (*c2_entry_data));
  if (!c2_entry_data)
    return -ENOMEM;

  memset (c2_entry_data, 0, sizeof (struct pp2_cls_c2_data_t));

  /* get C2 db entry data */
  if (pp2_cls_db_c2_data_get (inst, c2_index_node->c2_data_db_idx, c2_entry_data))
    {
      if (c2_entry_data)
	clib_mem_free (c2_entry_data);
      return -EINVAL;
    }
  *hignest_pri = c2_entry_data->priority;
  *lowest_pri = c2_entry_data->priority;

  /* Search the list */
  LIST_FOR_EACH_OBJECT (c2_index_node, struct pp2_cls_c2_index_t, lkp_type_list_head, list_node)
  {
    if (pp2_cls_db_c2_data_get (inst, c2_index_node->c2_data_db_idx, c2_entry_data))
      {
	if (c2_entry_data)
	  clib_mem_free (c2_entry_data);
	return -EINVAL;
      }
    if ((*hignest_pri) > c2_entry_data->priority)
      *hignest_pri = c2_entry_data->priority;
    if ((*lowest_pri) < c2_entry_data->priority)
      *lowest_pri = c2_entry_data->priority;
  }

  if (c2_entry_data)
    clib_mem_free (c2_entry_data);
  return 0;
}

static int
pp2_cls_c2_make_slot_high (struct pp2_inst *inst, u32 lkp_type, u32 priority, u32 highest_pri,
			   u32 lowest_pri, u32 *c2_hw_idx)
{
  int ret_code;
  struct pp2_cls_c2_index_t *c2_index_node = NULL, *c2_first_node = NULL, *c2_last_node = NULL;
  u32 free_idx, pp2_cls_idx, node_count;
  u32 c2_search_start, c2_search_end;
  int pri_tmp, i;
  struct mv_pp2x_cls_c2_entry c2_entry;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  /* No need to agjust C2 way */
  if (pp2_cls_c2_entry_is_free (inst, MVPP2_C2_FIRST_ENTRY, &c2_index_node) ==
      MVPP2_C2_ENTRY_FREE_TRUE)
    {
      /* delete it from free list */
      list_del (&c2_index_node->list_node);
      /* Change to node valid status to invalid */
      c2_index_node->valid = MVPP2_C2_ENTRY_INVALID;
      /* return c2 hw index */
      *c2_hw_idx = MVPP2_C2_FIRST_ENTRY;
      return 0;
    }

  ret_code = pp2_cls_c2_lkp_type_pri_node_info_get (inst, lkp_type, highest_pri, &c2_first_node,
						    &c2_last_node, &node_count);
  if (ret_code)
    {
      pr_err ("C2 lookup type list(%d) priority (%d) node info get failed\n", lkp_type,
	      highest_pri);
      return -EINVAL;
    }
  if (c2_first_node && c2_first_node->c2_hw_idx > MVPP2_C2_FIRST_ENTRY)
    {
      /* Find the available slot */
      ret_code =
	pp2_cls_c2_free_slot_find (inst, MVPP2_C2_FIRST_ENTRY, c2_first_node->c2_hw_idx, &free_idx);
      if (ret_code)
	{
	  pr_err ("No found free slot between entry(%d) and entry(%d)\n", MVPP2_C2_FIRST_ENTRY,
		  c2_first_node->c2_hw_idx);
	  return -EINVAL;
	}
      if (free_idx != MVPP2_C2_ENTRY_INVALID_IDX)
	{
	  /* return c2 hw index */
	  *c2_hw_idx = free_idx;
	  return 0;
	}
    }

  /* Search down and adjust C2 original entries */
  for (pri_tmp = highest_pri; pri_tmp <= lowest_pri; pri_tmp++)
    {
      /* Get search block */
      ret_code = pp2_cls_c2_lkp_search_down_block_get (inst, lkp_type, pri_tmp, &c2_search_start,
						       &c2_search_end);
      if (ret_code)
	{
	  pr_err ("Search blcok get failed\n");
	  return -EINVAL;
	}
      if (c2_search_start != MVPP2_C2_ENTRY_INVALID_IDX)
	{
	  ret_code = pp2_cls_c2_free_slot_find (inst, c2_search_start, c2_search_end, &free_idx);
	  if (ret_code)
	    {
	      pr_err ("No found free slot between (%d) and (%d)\n", c2_search_start, c2_search_end);
	      return -EINVAL;
	    }
	  if (free_idx != MVPP2_C2_ENTRY_INVALID_IDX)
	    {
	      /* Find free entry, adjust C2 table */
	      for (i = pri_tmp; i >= (int) highest_pri; i--)
		{
		  pp2_cls_idx = free_idx;
		  /* Find the first entry with priority found free slot */
		  ret_code = pp2_cls_c2_lkp_type_pri_node_info_get (
		    inst, lkp_type, i, &c2_first_node, &c2_last_node, &node_count);
		  if (ret_code)
		    return -EINVAL;
		  if (c2_first_node)
		    {
		      mv_pp2x_c2_sw_clear (&c2_entry);
		      mv_pp2x_cls_c2_hw_read (cpu_slot, c2_first_node->c2_hw_idx, &c2_entry);
		      mv_pp2x_cls_c2_hw_write (cpu_slot, free_idx, &c2_entry);
		      /* Continue next move */
		      free_idx = c2_first_node->c2_hw_idx;
		      /* Update C2 index node of the lookup type */
		      c2_first_node->c2_hw_idx = pp2_cls_idx;
		    }
		}
	      *c2_hw_idx = free_idx;
	      return 0;
	    }
	}
    }

  return -EINVAL;
}

static int
pp2_cls_c2_make_slot_low (struct pp2_inst *inst, u32 lkp_type, u32 priority, u32 highest_pri,
			  u32 lowest_pri, u32 *c2_hw_idx)
{
  int ret_code;
  struct pp2_cls_c2_index_t *c2_index_node = NULL, *c2_first_node = NULL, *c2_last_node = NULL;
  u32 free_idx, pp2_cls_idx, node_count;
  u32 c2_search_start, c2_search_end;
  int pri_tmp, i;
  struct mv_pp2x_cls_c2_entry c2_entry;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  /* No need adjust other C2 entry way */
  /* get last node with lowest priority */
  ret_code = pp2_cls_c2_lkp_type_pri_node_info_get (inst, lkp_type, lowest_pri, &c2_first_node,
						    &c2_last_node, &node_count);
  if (ret_code)
    {
      pr_err ("Lookup type list(%d) priority (%d) node info get failed\n", lkp_type, lowest_pri);
      return -EINVAL;
    }
  /* try to find the slot after last node with lowest_pri */
  if (c2_last_node)
    {
      /* Find the available slot */
      ret_code =
	pp2_cls_c2_free_slot_find (inst, c2_last_node->c2_hw_idx, MVPP2_C2_LAST_ENTRY, &free_idx);
      if (ret_code)
	{
	  pr_err ("Free slot between (%d) and (%d) failed\n", c2_last_node->c2_hw_idx,
		  MVPP2_C2_LAST_ENTRY);
	  return -EINVAL;
	}
      if (free_idx != MVPP2_C2_ENTRY_INVALID_IDX)
	{
	  /* return c2 hw index */
	  *c2_hw_idx = free_idx;

	  return 0;
	}
    }
  /* find available slot above node with current lowest priority */
  /* Search up and adjust C2 original entries */
  for (pri_tmp = lowest_pri; pri_tmp >= (int) highest_pri; pri_tmp--)
    {
      /* Get search block */
      ret_code = pp2_cls_c2_lkp_search_up_block_get (inst, lkp_type, pri_tmp, &c2_search_start,
						     &c2_search_end);
      if (c2_search_end != MVPP2_C2_ENTRY_INVALID_IDX)
	{
	  /* Special handle entry 0 */
	  if (c2_search_start == MVPP2_C2_FIRST_ENTRY &&
	      pp2_cls_c2_entry_is_free (inst, c2_search_start, &c2_index_node) ==
		MVPP2_C2_ENTRY_FREE_TRUE)
	    {
	      /* delete it from free list */
	      list_del (&c2_index_node->list_node);
	      /* Change to node valid status to invalid */
	      c2_index_node->valid = MVPP2_C2_ENTRY_INVALID;
	      free_idx = c2_search_start;
	    }
	  else
	    {
	      ret_code =
		pp2_cls_c2_free_slot_find (inst, c2_search_start, c2_search_end, &free_idx);
	      if (ret_code)
		{
		  pr_err ("Free slot between (%d) and (%d) failed\n", c2_search_start,
			  c2_search_end);
		  return -EINVAL;
		}
	    }
	  if (free_idx != MVPP2_C2_ENTRY_INVALID_IDX)
	    {
	      /* Find free entry, adjust C2 table */
	      for (i = pri_tmp; i <= (int) lowest_pri; i++)
		{
		  pp2_cls_idx = free_idx;
		  /* Find the first entry with priority found free slot */
		  ret_code = pp2_cls_c2_lkp_type_pri_node_info_get (
		    inst, lkp_type, i, &c2_first_node, &c2_last_node, &node_count);
		  if (ret_code)
		    return -EINVAL;
		  if (c2_last_node)
		    {
		      mv_pp2x_c2_sw_clear (&c2_entry);
		      mv_pp2x_cls_c2_hw_read (cpu_slot, c2_last_node->c2_hw_idx, &c2_entry);
		      mv_pp2x_cls_c2_hw_write (cpu_slot, free_idx, &c2_entry);
		      /* Continue next move */
		      free_idx = c2_last_node->c2_hw_idx;
		      /* Update C2 index node of the lookup type */
		      c2_last_node->c2_hw_idx = pp2_cls_idx;
		    }
		}
	      *c2_hw_idx = free_idx;
	      return 0;
	    }
	}
    }

  return -EINVAL;
}

static int
pp2_cls_c2_make_slot_middle (struct pp2_inst *inst, u32 lkp_type, u32 priority, u32 highest_pri,
			     u32 lowest_pri, u32 *c2_hw_idx)
{
  int ret_code;
  struct pp2_cls_c2_index_t *c2_index_node = NULL, *c2_first_node = NULL, *c2_last_node = NULL;
  u32 free_idx, pp2_cls_idx, node_count;
  u32 c2_search_start, c2_search_end, pri_prev, pri_next;
  int pri_tmp, i;
  struct mv_pp2x_cls_c2_entry c2_entry;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  /* No need adjust other C2 entry way */
  ret_code = pp2_cls_c2_lkp_type_list_neighbour_pri_get (inst, lkp_type, priority, highest_pri,
							 lowest_pri, &pri_prev, &pri_next);
  if (ret_code)
    return -EINVAL;
  /* Get node info with priority */
  if (pri_prev != MVPP2_C2_LKP_TYPE_INVALID_PRI)
    {
      ret_code = pp2_cls_c2_lkp_type_pri_node_info_get (inst, lkp_type, pri_prev, &c2_first_node,
							&c2_last_node, &node_count);
      if (ret_code)
	return -EINVAL;
      if (c2_last_node)
	c2_search_start = c2_last_node->c2_hw_idx;
    }
  if (pri_next != MVPP2_C2_LKP_TYPE_INVALID_PRI)
    {
      ret_code = pp2_cls_c2_lkp_type_pri_node_info_get (inst, lkp_type, pri_next, &c2_first_node,
							&c2_last_node, &node_count);
      if (ret_code)
	return -EINVAL;
      if (c2_first_node)
	c2_search_end = c2_first_node->c2_hw_idx;
    }
  /* Find the available before first node */
  ret_code = pp2_cls_c2_free_slot_find (inst, c2_search_start, c2_search_end, &free_idx);
  if (ret_code)
    {
      pr_err ("No found free slot between (%d) and (%d) on C2 engine\n", c2_search_start,
	      c2_search_end);
      return -EINVAL;
    }
  if (free_idx != MVPP2_C2_ENTRY_INVALID_IDX)
    {
      /* return c2 hw index */
      *c2_hw_idx = free_idx;

      return 0;
    }

  /* Search up and adjust C2 original entries */
  for (pri_tmp = pri_prev; pri_tmp >= (int) highest_pri; pri_tmp--)
    {
      /* Get search block */
      ret_code = pp2_cls_c2_lkp_search_up_block_get (inst, lkp_type, pri_tmp, &c2_search_start,
						     &c2_search_end);
      if (c2_search_end != MVPP2_C2_ENTRY_INVALID_IDX)
	{
	  /* Special handle entry 0 */
	  if (c2_search_start == MVPP2_C2_FIRST_ENTRY &&
	      pp2_cls_c2_entry_is_free (inst, c2_search_start, &c2_index_node) ==
		MVPP2_C2_ENTRY_FREE_TRUE)
	    {
	      /* delete it from free list */
	      list_del (&c2_index_node->list_node);
	      /* Change to node valid status to invalid */
	      c2_index_node->valid = MVPP2_C2_ENTRY_INVALID;
	      free_idx = c2_search_start;
	    }
	  else
	    {
	      ret_code =
		pp2_cls_c2_free_slot_find (inst, c2_search_start, c2_search_end, &free_idx);
	      if (ret_code)
		{
		  pr_err ("No found free slot between (%d) and (%d) failed\n", c2_search_start,
			  c2_search_end);
		  return -EINVAL;
		}
	    }
	  if (free_idx != MVPP2_C2_ENTRY_INVALID_IDX)
	    {
	      /* Find free entry, adjust C2 table */
	      for (i = pri_tmp; i <= pri_prev; i++)
		{
		  pp2_cls_idx = free_idx;
		  /* Find the first entry with priority found free slot */
		  ret_code = pp2_cls_c2_lkp_type_pri_node_info_get (
		    inst, lkp_type, i, &c2_first_node, &c2_last_node, &node_count);
		  if (ret_code)
		    return -EINVAL;
		  if (c2_last_node)
		    {
		      mv_pp2x_c2_sw_clear (&c2_entry);
		      mv_pp2x_cls_c2_hw_read (cpu_slot, c2_last_node->c2_hw_idx, &c2_entry);
		      mv_pp2x_cls_c2_hw_write (cpu_slot, free_idx, &c2_entry);
		      /* Continue next move */
		      free_idx = c2_last_node->c2_hw_idx;
		      /* Update C2 index node of the lookup type */
		      c2_last_node->c2_hw_idx = pp2_cls_idx;
		    }
		}
	      *c2_hw_idx = free_idx;
	      return 0;
	    }
	}
    }

  /* Search down and adjust C2 original entries */
  for (pri_tmp = pri_next; pri_tmp <= (int) lowest_pri; pri_tmp++)
    {
      /* Get search block */
      ret_code = pp2_cls_c2_lkp_search_down_block_get (inst, lkp_type, pri_tmp, &c2_search_start,
						       &c2_search_end);
      if (c2_search_start != MVPP2_C2_ENTRY_INVALID_IDX)
	{
	  ret_code = pp2_cls_c2_free_slot_find (inst, c2_search_start, c2_search_end, &free_idx);
	  if (ret_code)
	    {
	      pr_err ("No found free slot between (%d) and (%d) failed\n", c2_search_start,
		      c2_search_end);
	      return -EINVAL;
	    }
	  if (free_idx != MVPP2_C2_ENTRY_INVALID_IDX)
	    {
	      /* Find free entry, adjust C2 table */
	      for (i = pri_tmp; i >= pri_next; i--)
		{
		  pp2_cls_idx = free_idx;
		  /* Find the first entry with priority found free slot */
		  ret_code = pp2_cls_c2_lkp_type_pri_node_info_get (
		    inst, lkp_type, i, &c2_first_node, &c2_last_node, &node_count);
		  if (ret_code)
		    return -EINVAL;
		  if (c2_last_node)
		    {
		      mv_pp2x_c2_sw_clear (&c2_entry);
		      mv_pp2x_cls_c2_hw_read (cpu_slot, c2_first_node->c2_hw_idx, &c2_entry);
		      mv_pp2x_cls_c2_hw_write (cpu_slot, free_idx, &c2_entry);
		      /* Continue next move */
		      free_idx = c2_first_node->c2_hw_idx;
		      /* Update C2 index node of the lookup type */
		      c2_first_node->c2_hw_idx = pp2_cls_idx;
		    }
		}
	      *c2_hw_idx = free_idx;
	      return 0;
	    }
	}
    }

  return -EINVAL;
}

static int
pp2_cls_c2_tcam_hek_get (u32 field_bm, struct mv_pp2x_c2_add_entry *c2_entry, u8 hek[],
			 u8 hek_mask[])
{
  int ret_code = 0;
  struct pp2_cls_field_match_info *field_info, *field_unmask; /*use heap to reduce stack size*/
  u8 c2_hek[MVPP2_C2_HEK_OFF_MAX];
  u8 c2_hek_mask[MVPP2_C2_HEK_OFF_MAX];
  u32 field_bytes, field_id, field_size, pkt_value, pkt_value_mask;
  u32 c2_hek_bytes_used = 0; /* used to recoed current bytes filled in HEK */
  int field_num, i;
  u32 pre_field_id = 0;
  bool comb_flag = false;
  u8 comb_offset = 0;

  if (!c2_entry)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!hek)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!hek_mask)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  field_info = mem_calloc (MVPP2_FLOW_FIELD_COUNT_MAX, sizeof (struct pp2_cls_field_match_info));
  if (!field_info)
    return -ENOMEM;

  memset (field_info, 0, MVPP2_FLOW_FIELD_COUNT_MAX * sizeof (struct pp2_cls_field_match_info));

  field_unmask = mem_calloc (MVPP2_FLOW_FIELD_COUNT_MAX, sizeof (struct pp2_cls_field_match_info));
  if (!field_unmask)
    {
      if (field_info)
	clib_mem_free (field_info);
      return -ENOMEM;
    }
  memset (field_unmask, 0, MVPP2_FLOW_FIELD_COUNT_MAX * sizeof (struct pp2_cls_field_match_info));

  /* clear related structure */
  memset (&field_info[0], 0, sizeof (struct pp2_cls_field_match_info) * MVPP2_FLOW_FIELD_COUNT_MAX);
  memset (c2_hek, 0, MVPP2_C2_HEK_OFF_MAX);
  memset (c2_hek_mask, 0, MVPP2_C2_HEK_OFF_MAX);
  /* get field info */
  ret_code = pp2_cls_field_bm_to_field_info (field_bm, c2_entry->mng_pkt_key,
					     MVPP2_FLOW_FIELD_COUNT_MAX, true, field_info);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      if (field_info)
	clib_mem_free (field_info);
      if (field_unmask)
	clib_mem_free (field_unmask);
      return ret_code;
    }

  /* Get filed need to unmask */
  ret_code = pp2_cls_field_bm_to_field_info (
    field_bm & ((~(c2_entry->mng_pkt_key->pkt_key->field_bm_mask)) | MVPP2_MATCH_IPV6_PKT |
		MVPP2_MATCH_IPV4_PKT),
    c2_entry->mng_pkt_key, MVPP2_FLOW_FIELD_COUNT_MAX, true, field_unmask);
  if (ret_code)
    {
      pr_err ("recvd ret_code(%d)\n", ret_code);
      if (field_info)
	clib_mem_free (field_info);
      if (field_unmask)
	clib_mem_free (field_unmask);
      return ret_code;
    }
  /* Set C2 TCAM HEK */
  field_num = 0;
  while (field_num < MVPP2_FLOW_FIELD_COUNT_MAX && field_info[field_num].valid == MVPP2_FIELD_VALID)
    {
      field_id = field_info[field_num].field_id;
      field_size = pp2_cls_field_size_get (field_id);
      if (field_size % BYTE_BITS)
	field_bytes = (field_size / BYTE_BITS) + 1;
      else
	field_bytes = field_size / BYTE_BITS;

      /* Organize pkt key according to field size and order */
      switch (field_id)
	{
	case MH_FIELD_ID:
	case MH_UNTAGGED_PRI_FIELD_ID:
	case OUT_VLAN_PRI_FIELD_ID:
	case ETH_TYPE_FIELD_ID:
	case PPPOE_FIELD_ID:
	case IP_VER_FIELD_ID:
	case IPV4_DSCP_FIELD_ID:
	case IPV4_LEN_FIELD_ID:
	case IPV4_TTL_FIELD_ID:
	case IPV4_PROTO_FIELD_ID:
	case IPV6_PAYLOAD_LEN_FIELD_ID:
	case IPV6_NH_FIELD_ID:
	case L4_SRC_FIELD_ID:
	case L4_DST_FIELD_ID:
	case TCP_FLAGS_FIELD_ID:
	case CLS_UDF3_FIELD_ID:
	case CLS_UDF5_FIELD_ID:
	case CLS_UDF6_FIELD_ID:
	case IN_VLAN_PRI_FIELD_ID:
	case PPPOE_PROTO_ID:
	case OUT_TPID_FIELD_ID:
	case IN_TPID_FIELD_ID:
	  /* Get HEK data */
	  pkt_value = field_info[field_num].filed_value.int_data.parsed_int_val;
	  pkt_value_mask = field_info[field_num].filed_value.int_data.parsed_int_val_mask;
	  /* Store HEK in c2_hek, each filed byte boutary */
	  ret_code = pp2_cls_c2_tcam_common_field_hek_get (
	    pkt_value, pkt_value_mask, field_bytes, field_size,
	    pp2_cls_c2_field_unmask_check (field_id, field_unmask), c2_hek, c2_hek_mask,
	    &c2_hek_bytes_used);
	  if (ret_code)
	    {
	      pr_err ("recvd ret_code(%d)\n", ret_code);
	      if (field_info)
		clib_mem_free (field_info);
	      if (field_unmask)
		clib_mem_free (field_unmask);
	      return ret_code;
	    }
	  /* Check HEK bytes number */
	  if (c2_hek_bytes_used > MVPP2_C2_HEK_OFF_LKP_PORT_TYPE)
	    {
	      pr_info ("HEK bytes (%d) beyond C2 capcity\n", c2_hek_bytes_used);
	      if (field_info)
		clib_mem_free (field_info);
	      if (field_unmask)
		clib_mem_free (field_unmask);
	      return -EFAULT;
	    }
	  break;
	case OUT_VLAN_CFI_FIELD_ID:
	case IN_VLAN_CFI_FIELD_ID:
	  /* Get HEK data */
	  pkt_value = field_info[field_num].filed_value.int_data.parsed_int_val;
	  pkt_value_mask = field_info[field_num].filed_value.int_data.parsed_int_val_mask;
	  c2_hek_bytes_used++;
	  if (c2_hek_bytes_used > MVPP2_C2_HEK_OFF_LKP_PORT_TYPE)
	    {
	      pr_info ("HEK bytes (%d) is beyond C2 capcity\n", c2_hek_bytes_used);
	      if (field_info)
		clib_mem_free (field_info);
	      if (field_unmask)
		clib_mem_free (field_unmask);
	      return -EFAULT;
	    }
	  c2_hek[c2_hek_bytes_used - 1] =
	    (pkt_value << (BYTE_BITS - 1 - (MVPP2_CFI_OFFSET_BITS % BYTE_BITS)));
	  c2_hek_mask[c2_hek_bytes_used - 1] =
	    (pkt_value_mask << (BYTE_BITS - 1 - (MVPP2_CFI_OFFSET_BITS % BYTE_BITS)));
	  break;
	/* Share bits combination */
	case GEM_PORT_ID_FIELD_ID:
	case IN_VLAN_ID_FIELD_ID:
	case OUT_VLAN_ID_FIELD_ID:
	case IPV4_ECN_FIELD_ID:
	case IPV6_DSCP_FIELD_ID:
	case IPV6_ECN_FIELD_ID:
	case IPV6_FLOW_LBL_FIELD_ID:
	  if (pre_field_id == OUT_VLAN_PRI_FIELD_ID && field_id == OUT_VLAN_ID_FIELD_ID)
	    {
	      comb_flag = true;
	      comb_offset = 4;
	    }
	  if (pre_field_id == IN_VLAN_PRI_FIELD_ID && field_id == IN_VLAN_ID_FIELD_ID)
	    {
	      comb_flag = true;
	      comb_offset = 4;
	    }
	  if (pre_field_id == IPV4_DSCP_FIELD_ID && field_id == IPV4_ECN_FIELD_ID)
	    {
	      comb_flag = true;
	      comb_offset = 2;
	    }
	  if (pre_field_id == IP_VER_FIELD_ID || field_id == IPV6_DSCP_FIELD_ID)
	    {
	      comb_flag = true;
	      comb_offset = 4;
	      if (pre_field_id != IP_VER_FIELD_ID)
		c2_hek_bytes_used++;
	    }
	  if (pre_field_id == IPV6_DSCP_FIELD_ID && field_id == IPV6_ECN_FIELD_ID)
	    {
	      comb_flag = true;
	      comb_offset = 2;
	    }
	  if (field_id == IPV6_FLOW_LBL_FIELD_ID &&
	      (pre_field_id == IPV6_DSCP_FIELD_ID || pre_field_id == IPV6_ECN_FIELD_ID))
	    {
	      comb_flag = true;
	      comb_offset = 4;
	    }

	  /* Get HEK data */
	  pkt_value = field_info[field_num].filed_value.int_data.parsed_int_val;
	  pkt_value_mask = field_info[field_num].filed_value.int_data.parsed_int_val_mask;
	  /* Check Combination */
	  if (comb_flag && (field_size < BYTE_BITS) && ((field_size + comb_offset) > BYTE_BITS))
	    field_bytes++;

	  ret_code = pp2_cls_c2_tcam_shared_field_hek_get (
	    pkt_value, pkt_value_mask, field_bytes, field_size,
	    pp2_cls_c2_field_unmask_check (field_id, field_unmask), comb_flag, comb_offset, c2_hek,
	    c2_hek_mask, &c2_hek_bytes_used);
	  if (ret_code)
	    {
	      pr_err ("recvd ret_code(%d)\n", ret_code);
	      if (field_info)
		clib_mem_free (field_info);
	      if (field_unmask)
		clib_mem_free (field_unmask);
	      return ret_code;
	    }
	  /* Check HEK bytes number */
	  if (c2_hek_bytes_used > MVPP2_C2_HEK_OFF_LKP_PORT_TYPE)
	    {
	      pr_info ("HEK bytes (%d) beyond C2 capcity\n", c2_hek_bytes_used);
	      if (field_info)
		clib_mem_free (field_info);
	      if (field_unmask)
		clib_mem_free (field_unmask);
	      return -EFAULT;
	    }
	  break;

	case MAC_DA_FIELD_ID:
	case MAC_SA_FIELD_ID:
	case IPV4_SA_FIELD_ID:
	case IPV4_DA_FIELD_ID:
	case ARP_IPV4_DA_FIELD_ID:
	  for (i = 0; i < field_bytes; i++)
	    {
	      if (field_id == MAC_DA_FIELD_ID || field_id == MAC_SA_FIELD_ID)
		{
		  /* HEK Value */
		  c2_hek[c2_hek_bytes_used] =
		    field_info[field_num].filed_value.mac_addr.parsed_mac_addr[i];
		  /* HEK Mask */
		  if (!pp2_cls_c2_field_unmask_check (field_id, field_unmask))
		    c2_hek_mask[c2_hek_bytes_used] =
		      field_info[field_num].filed_value.mac_addr.parsed_mac_addr_mask[i];
		}
	      else
		{
		  /* HEK Value */
		  c2_hek[c2_hek_bytes_used] =
		    field_info[field_num].filed_value.ipv4_addr.parsed_ipv4_addr[i];
		  /* HEK Mask */
		  if (!pp2_cls_c2_field_unmask_check (field_id, field_unmask))
		    c2_hek_mask[c2_hek_bytes_used] =
		      field_info[field_num].filed_value.ipv4_addr.parsed_ipv4_addr_mask[i];
		}
	      c2_hek_bytes_used++;
	    }
	  /* Check HEK bytes number */
	  if (c2_hek_bytes_used > MVPP2_C2_HEK_OFF_LKP_PORT_TYPE)
	    {
	      pr_info ("HEK bytes (%d) beyond C2 capcity\n", c2_hek_bytes_used);
	      if (field_info)
		clib_mem_free (field_info);
	      if (field_unmask)
		clib_mem_free (field_unmask);
	      return -EFAULT;
	    }
	  break;

	case IPV6_SA_PREF_FIELD_ID:
	case IPV6_DA_PREF_FIELD_ID:
	  for (i = 0; i < field_bytes; i++)
	    {
	      /* HEK Value */
	      c2_hek[c2_hek_bytes_used] =
		field_info[field_num].filed_value.ipv6_addr.parsed_ipv6_addr[i];
	      /* HEK Mask */
	      if (!pp2_cls_c2_field_unmask_check (field_id, field_unmask))
		c2_hek_mask[c2_hek_bytes_used] =
		  field_info[field_num].filed_value.ipv6_addr.parsed_ipv6_addr_mask[i];
	      c2_hek_bytes_used++;
	    }
	  /* Check HEK bytes number */
	  if (c2_hek_bytes_used > MVPP2_C2_HEK_OFF_LKP_PORT_TYPE)
	    {
	      pr_info ("HEK bytes (%d) beyond C2 capcity\n", c2_hek_bytes_used);
	      if (field_info)
		clib_mem_free (field_info);
	      if (field_unmask)
		clib_mem_free (field_unmask);
	      return -EFAULT;
	    }
	  break;

	case IPV6_SA_SUFF_FIELD_ID:
	case IPV6_DA_SUFF_FIELD_ID:
	  /* IPv6 suffix needs to be moved to MSB bytes for SRAM */
	  for (i = field_bytes; i < IPV6_ADDR_SIZE; i++)
	    {
	      /* HEK Value */
	      c2_hek[c2_hek_bytes_used] =
		field_info[field_num].filed_value.ipv6_addr.parsed_ipv6_addr[i];
	      /* HEK Mask */
	      if (!pp2_cls_c2_field_unmask_check (field_id, field_unmask))
		c2_hek_mask[c2_hek_bytes_used] =
		  field_info[field_num].filed_value.ipv6_addr.parsed_ipv6_addr_mask[i];
	      c2_hek_bytes_used++;
	    }
	  /* Check HEK bytes number */
	  if (c2_hek_bytes_used > MVPP2_C2_HEK_OFF_LKP_PORT_TYPE)
	    {
	      pr_info ("HEK bytes (%d) beyond C2 capcity\n", c2_hek_bytes_used);
	      if (field_info)
		clib_mem_free (field_info);
	      if (field_unmask)
		clib_mem_free (field_unmask);
	      return -EFAULT;
	    }
	  break;

	case IPV6_SA_FIELD_ID:
	case IPV6_DA_FIELD_ID:
	  /* IPv6 SIP and DIP cant not fit into C2 SRAM */
	  if (field_info)
	    clib_mem_free (field_info);
	  if (field_unmask)
	    clib_mem_free (field_unmask);
	  return -EFAULT;

	default:
	  pr_err ("Invalid field ID (%d) on C2 engine\n", field_id);
	  if (field_info)
	    clib_mem_free (field_info);
	  if (field_unmask)
	    clib_mem_free (field_unmask);
	  return -EFAULT;
	}
      /* record previous id */
      pre_field_id = field_id;

      /* Increase filed number */
      field_num++;

      /* Clear combine flag */
      comb_flag = false;
    }
  /* Return hek and hek_mask */
  for (i = 0; i < c2_hek_bytes_used; i++)
    {
      hek[MVPP2_C2_HEK_OFF_BYTE7 - i] = c2_hek[i];
      hek_mask[MVPP2_C2_HEK_OFF_BYTE7 - i] = c2_hek_mask[i];
    }
  /* HEK offs 8, lookup type, port type */
  hek[MVPP2_C2_HEK_OFF_LKP_PORT_TYPE] = (c2_entry->port.port_type << MVPP2_C2_HEK_PORT_TYPE_OFFS) |
					(c2_entry->lkp_type << MVPP2_C2_HEK_LKP_TYPE_OFFS);
  hek_mask[MVPP2_C2_HEK_OFF_LKP_PORT_TYPE] =
    MVPP2_C2_HEK_PORT_TYPE_MASK |
    ((c2_entry->lkp_type_mask << MVPP2_C2_HEK_LKP_TYPE_OFFS) & MVPP2_C2_HEK_LKP_TYPE_MASK);
  /* HEK offs 9, port ID */
  hek[MVPP2_C2_HEK_OFF_PORT_ID] = c2_entry->port.port_value;
  hek_mask[MVPP2_C2_HEK_OFF_PORT_ID] = c2_entry->port.port_mask;

  if (field_info)
    clib_mem_free (field_info);
  if (field_unmask)
    clib_mem_free (field_unmask);
  return 0;
}

static int
pp2_cls_c3_color_set (struct pp2_cls_c3_entry *c3, int cmd)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (cmd, 0, MVPP2_COLOR_ACTION_TYPE_RED_LOCK))
    return -EINVAL;

  c3->sram.regs.actions &= ~MVPP2_CLS3_ACT_COLOR_MASK;
  c3->sram.regs.actions |= (cmd << MVPP2_CLS3_ACT_COLOR);

  return 0;
}

static int
pp2_cls_c3_dup_set (struct pp2_cls_c3_entry *c3, int dupid, int count)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (count, 0, MVPP2_CLS3_ACT_DUP_COUNT_MAX))
    return -EINVAL;

  if (mv_pp2x_range_validate (dupid, 0, MVPP2_CLS3_ACT_DUP_FID_MAX))
    return -EINVAL;

  /*set flowid and count*/
  c3->sram.regs.dup_attr &= ~(MVPP2_CLS3_ACT_DUP_FID_MASK | MVPP2_CLS3_ACT_DUP_COUNT_MASK);
  c3->sram.regs.dup_attr |= (dupid << MVPP2_CLS3_ACT_DUP_FID);
  c3->sram.regs.dup_attr |= (count << MVPP2_CLS3_ACT_DUP_COUNT);

  return 0;
}

static int
pp2_cls_c3_flow_id_en (struct pp2_cls_c3_entry *c3, int flowid_en)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  /*set Flow ID enable or disable*/
  if (flowid_en)
    c3->sram.regs.actions |= (1 << MVPP2_CLS3_ACT_FLOW_ID_EN);
  else
    c3->sram.regs.actions &= ~(1 << MVPP2_CLS3_ACT_FLOW_ID_EN);

  return 0;
}

static int
pp2_cls_c3_forward_set (struct pp2_cls_c3_entry *c3, int cmd)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (cmd, 0, MVPP2_FRWD_ACTION_TYPE_HWF_LOW_LATENCY_LOCK))
    return -EINVAL;

  c3->sram.regs.actions &= ~MVPP2_CLS3_ACT_FWD_MASK;
  c3->sram.regs.actions |= (cmd << MVPP2_CLS3_ACT_FWD);
  return 0;
}

static int
pp2_cls_c3_hek_generate (struct pp2_cls_c3_add_entry_t *c3_entry, u32 *size, u8 hek[])
{
  struct pp2_cls_field_match_info field_info[MVPP2_FLOW_FIELD_COUNT_MAX];
  u8 c3_hek[MVPP2_C3_MAX_HASH_KEY_SIZE];
  u32 field_bytes;
  u32 field_id;
  u32 field_size;
  u32 pkt_value = 0;
  u32 c3_hek_bytes_used = 0; /* used to recoed current bytes filled in HEK */
  int field_num;
  int idx;
  u32 pre_field_id = 0;
  u8 comb_flag = false;
  u8 comb_offset = 0;
  int rc = MV_OK;
  u8 l4_info;

  pr_debug ("reached\n");

  if (mv_pp2x_ptr_validate (c3_entry))
    return -EINVAL;

  if (mv_pp2x_ptr_validate (size))
    return -EINVAL;

  if (mv_pp2x_ptr_validate (hek))
    return -EINVAL;

  /* clear related structure */
  memset (&field_info[0], 0, sizeof (struct pp2_cls_field_match_info) * MVPP2_FLOW_FIELD_COUNT_MAX);
  memset (c3_hek, 0, MVPP2_C3_MAX_HASH_KEY_SIZE);

  if (c3_entry->mng_pkt_key->pkt_key->field_bm == MVPP2_MATCH_IPV4_5T ||
      c3_entry->mng_pkt_key->pkt_key->field_bm == MVPP2_MATCH_IPV6_5T)
    l4_info = false;
  else
    l4_info = true;

  /* get field info */
  rc =
    pp2_cls_field_bm_to_field_info (c3_entry->mng_pkt_key->pkt_key->field_bm, c3_entry->mng_pkt_key,
				    MVPP2_FLOW_FIELD_COUNT_MAX, l4_info, field_info);

  if (rc)
    {
      pr_err ("failed to get field information\n");
      return rc;
    }

  /* Set C3 TCAM HEK */
  field_num = 0;
  while (field_num < MVPP2_FLOW_FIELD_COUNT_MAX && field_info[field_num].valid == MVPP2_FIELD_VALID)
    {
      field_id = field_info[field_num].field_id;
      field_size = pp2_cls_field_size_get (field_id);
      if (field_size % BYTE_BITS)
	field_bytes = (field_size / BYTE_BITS) + 1;
      else
	field_bytes = field_size / BYTE_BITS;
      /* Check HEK bytes number */
      if (c3_hek_bytes_used >= MVPP2_C3_MAX_HASH_KEY_SIZE ||
	  (field_bytes > (MVPP2_C3_MAX_HASH_KEY_SIZE - c3_hek_bytes_used)))
	{
	  pr_err ("HEK bytes (%d) beyond C3 capcity\n", (c3_hek_bytes_used + field_bytes));
	  return -EINVAL;
	}
      /* Organize pkt key according to field size and order */
      switch (field_id)
	{
	case MH_FIELD_ID:
	case MH_UNTAGGED_PRI_FIELD_ID:
	case OUT_VLAN_PRI_FIELD_ID:
	case ETH_TYPE_FIELD_ID:
	case PPPOE_FIELD_ID:
	case IP_VER_FIELD_ID:
	case IPV4_DSCP_FIELD_ID:
	case IPV4_LEN_FIELD_ID:
	case IPV4_TTL_FIELD_ID:
	case IPV4_PROTO_FIELD_ID:
	case IPV6_PAYLOAD_LEN_FIELD_ID:
	case IPV6_NH_FIELD_ID:
	case L4_SRC_FIELD_ID:
	case L4_DST_FIELD_ID:
	case TCP_FLAGS_FIELD_ID:
	case IN_VLAN_PRI_FIELD_ID:
	case PPPOE_PROTO_ID:
	case OUT_TPID_FIELD_ID:
	case IN_TPID_FIELD_ID:
	  /* Get HEK data */
	  pkt_value = field_info[field_num].filed_value.int_data.parsed_int_val;
	  /* Store HEK in c3_hek, each filed byte boutary */
	  rc = pp2_cls_c3_common_field_hek_get (pkt_value, field_bytes, field_size, c3_hek,
						&c3_hek_bytes_used);
	  if (rc)
	    {
	      pr_err ("failed to get HEK\n");
	      return rc;
	    }

	  break;
	case OUT_VLAN_CFI_FIELD_ID:
	case IN_VLAN_CFI_FIELD_ID:
	  c3_hek_bytes_used++;
	  if (c3_hek_bytes_used > MVPP2_C3_MAX_HASH_KEY_SIZE)
	    {
	      pr_err ("HEK bytes (%d) out C3 capcity\n", c3_hek_bytes_used);
	      /*mvOsFree(field_info);*/ /* [AW] TBD */
	      return -EINVAL;
	    }
	  c3_hek[c3_hek_bytes_used - 1] =
	    (pkt_value << (BYTE_BITS - 1 - (MVPP2_CFI_OFFSET_BITS % BYTE_BITS)));
	  break;
	/* Share bits combination */
	case GEM_PORT_ID_FIELD_ID:
	case IN_VLAN_ID_FIELD_ID:
	case OUT_VLAN_ID_FIELD_ID:
	  if (pre_field_id == OUT_VLAN_PRI_FIELD_ID && field_id == OUT_VLAN_ID_FIELD_ID)
	    {
	      comb_flag = true;
	      comb_offset = 4;
	    }
	  if (pre_field_id == IN_VLAN_PRI_FIELD_ID && field_id == IN_VLAN_ID_FIELD_ID)
	    {
	      comb_flag = true;
	      comb_offset = 4;
	    }
	/* fallthru */
	case IPV4_ECN_FIELD_ID:
	  if (pre_field_id == IPV4_DSCP_FIELD_ID && field_id == IPV4_ECN_FIELD_ID)
	    {
	      comb_flag = true;
	      comb_offset = 2;
	    }
	/* fallthru */
	case IPV6_DSCP_FIELD_ID:
	  if (pre_field_id == IP_VER_FIELD_ID || field_id == IPV6_DSCP_FIELD_ID)
	    {
	      comb_flag = true;
	      comb_offset = 4;
	      if (pre_field_id != IP_VER_FIELD_ID)
		c3_hek_bytes_used++;
	    }
	/* fallthru */
	case IPV6_ECN_FIELD_ID:
	  if (pre_field_id == IPV6_DSCP_FIELD_ID && field_id == IPV6_ECN_FIELD_ID)
	    {
	      comb_flag = true;
	      comb_offset = 2;
	    }
	/* fallthru */
	case IPV6_FLOW_LBL_FIELD_ID:
	  if (field_id == IPV6_FLOW_LBL_FIELD_ID &&
	      (pre_field_id == IPV6_DSCP_FIELD_ID || pre_field_id == IPV6_ECN_FIELD_ID))
	    {
	      comb_flag = true;
	      comb_offset = 4;
	    }

	  /* Get HEK data */
	  pkt_value = field_info[field_num].filed_value.int_data.parsed_int_val;
	  /* Check Combination */
	  if (comb_flag && (field_size < BYTE_BITS) && ((field_size + comb_offset) > BYTE_BITS))
	    field_bytes++;

	  if (c3_hek_bytes_used >= MVPP2_C3_MAX_HASH_KEY_SIZE ||
	      (field_bytes > (MVPP2_C3_MAX_HASH_KEY_SIZE - c3_hek_bytes_used)))
	    {
	      pr_err ("HEK bytes (%d) beyond C3 capcity\n", (c3_hek_bytes_used + field_bytes));
	      return -EINVAL;
	    }

	  rc = pp2_cls_c3_shared_field_hek_get (pkt_value, field_bytes, field_size, comb_flag,
						comb_offset, c3_hek, &c3_hek_bytes_used);
	  if (rc)
	    {
	      pr_err ("failed to get HEK\n");
	      return rc;
	    }
	  break;

	case MAC_DA_FIELD_ID:
	case MAC_SA_FIELD_ID:
	case IPV4_SA_FIELD_ID:
	case IPV4_DA_FIELD_ID:
	case ARP_IPV4_DA_FIELD_ID:
	  for (idx = 0; idx < field_bytes; idx++)
	    {
	      if (field_id == MAC_DA_FIELD_ID || field_id == MAC_SA_FIELD_ID)
		{
		  /* HEK value */
		  c3_hek[c3_hek_bytes_used] =
		    field_info[field_num].filed_value.mac_addr.parsed_mac_addr[idx];
		}
	      else
		{
		  /* HEK value */
		  c3_hek[c3_hek_bytes_used] =
		    field_info[field_num].filed_value.ipv4_addr.parsed_ipv4_addr[idx];
		}
	      c3_hek_bytes_used++;
	    }
	  break;

	case IPV6_SA_FIELD_ID:
	case IPV6_DA_FIELD_ID:
	case IPV6_SA_PREF_FIELD_ID:
	case IPV6_DA_PREF_FIELD_ID:
	  for (idx = 0; idx < field_bytes; idx++)
	    {
	      /* HEK value */
	      c3_hek[c3_hek_bytes_used] =
		field_info[field_num].filed_value.ipv6_addr.parsed_ipv6_addr[idx];
	      c3_hek_bytes_used++;
	    }
	  break;

	case IPV6_SA_SUFF_FIELD_ID:
	case IPV6_DA_SUFF_FIELD_ID:
	  /* IPv6 suffix needs to be moved to MSB bytes for SRAM */
	  for (idx = field_bytes; idx < IPV6_ADDR_SIZE; idx++)
	    {
	      /* HEK value */
	      c3_hek[c3_hek_bytes_used] =
		field_info[field_num].filed_value.ipv6_addr.parsed_ipv6_addr[idx];
	      c3_hek_bytes_used++;
	    }
	  break;
	default:
	  pr_err ("Invalid field ID (%d) on C3 engine\n", field_id);
	  return MV_ERROR;
	}
      /* record previous id */
      pre_field_id = field_id;

      /* increase field number */
      field_num++;

      /* Clear combine flag */
      comb_flag = false;
    }

  /* save HEK */
  *size = c3_hek_bytes_used;
  for (idx = 0; idx < c3_hek_bytes_used; idx++)
    hek[MVPP2_C3_MAX_HASH_KEY_SIZE - 1 - idx] = c3_hek[idx];

  return 0;
}

static int
pp2_cls_c3_hw_add (uintptr_t cpu_slot, struct pp2_cls_c3_entry *c3, int index, int ext_index)
{
  int reg_start_ind, hek_size, iter = 0;
  u32 reg_val = 0;

  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (index, 0, MVPP2_CLS3_HASH_OP_TBL_ADDR_MAX))
    return -EINVAL;

  c3->index = index;

  /* write key control */
  pp2_reg_write (cpu_slot, MVPP2_CLS3_KEY_CTRL_REG, c3->key.key_ctrl);

  hek_size = ((c3->key.key_ctrl & KEY_CTRL_HEK_SIZE_MASK) >> KEY_CTRL_HEK_SIZE);

  if (hek_size > MVPP2_CLS_C3_HEK_BYTES)
    {
      /* Extension */

      if (mv_pp2x_range_validate (ext_index, 0, MVPP2_CLS3_HASH_OP_EXT_TBL_ADDR_MAX))
	return -EINVAL;

      c3->ext_index = ext_index;
      reg_val |= (ext_index << MVPP2_CLS3_HASH_OP_EXT_TBL_ADDR);

      /* write 9 hek registers */
      reg_start_ind = 0;
    }
  else
    /* write 3 hek registers */
    reg_start_ind = 6;

  for (; reg_start_ind < MVPP2_CLS_C3_EXT_HEK_WORDS; reg_start_ind++)
    pp2_reg_write (cpu_slot, MVPP2_CLS3_KEY_HEK_REG (reg_start_ind),
		   c3->key.hek.words[reg_start_ind]);

  reg_val |= (index << MVPP2_CLS3_HASH_OP_TBL_ADDR);
  reg_val &= ~MVPP2_CLS3_MISS_PTR_MASK; /*set miss bit to 0*/
  reg_val |= (1 << MVPP2_CLS3_HASH_OP_ADD);

  /* set hit counter init value */
  pp2_reg_write (cpu_slot, MVPP2_CLS3_INIT_HIT_CNT_REG,
		 sw_init_cnt_set << MVPP2_CLS3_INIT_HIT_CNT_OFFS),
    /*trigger ADD operation*/
    pp2_reg_write (cpu_slot, MVPP2_CLS3_HASH_OP_REG, reg_val);

  /* wait to cpu access done bit */
  while (!pp2_cls_c3_cpu_done (cpu_slot))
    if (++iter >= RETRIES_EXCEEDED)
      {
	pr_err ("%s:Error - retries exceeded.\n", __func__);
	return -EBUSY;
      }

  /* write action table registers */
  pp2_reg_write (cpu_slot, MVPP2_CLS3_ACT_REG, c3->sram.regs.actions);
  pp2_reg_write (cpu_slot, MVPP2_CLS3_ACT_QOS_ATTR_REG, c3->sram.regs.qos_attr);
  pp2_reg_write (cpu_slot, MVPP2_CLS3_ACT_HWF_ATTR_REG, c3->sram.regs.hwf_attr);
  pp2_reg_write (cpu_slot, MVPP2_CLS3_ACT_DUP_ATTR_REG, c3->sram.regs.dup_attr);
  pp2_reg_write (cpu_slot, MVPP2_CLS3_ACT_SEQ_L_ATTR_REG, c3->sram.regs.seq_l_attr);
  pp2_reg_write (cpu_slot, MVPP2_CLS3_ACT_SEQ_H_ATTR_REG, c3->sram.regs.seq_h_attr);
  /* set entry as valid, extesion pointer in use only if size > 12*/
  pp2_cls_c3_shadow_set (hek_size, index, ext_index);

  return 0;
}

static int
pp2_cls_c3_hw_query (uintptr_t cpu_slot, struct pp2_cls_c3_entry *c3, u8 *occupied_bmp, int index[])
{
  int idx = 0;
  u32 reg_val = 0;

  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  /* write key control */
  pp2_reg_write (cpu_slot, MVPP2_CLS3_KEY_CTRL_REG, c3->key.key_ctrl);

  /* write hek */
  for (idx = 0; idx < MVPP2_CLS_C3_EXT_HEK_WORDS; idx++)
    pp2_reg_write (cpu_slot, MVPP2_CLS3_KEY_HEK_REG (idx), c3->key.hek.words[idx]);

  /*trigger query operation*/
  pp2_reg_write (cpu_slot, MVPP2_CLS3_QRY_ACT_REG, (1 << MVPP2_CLS3_QRY_ACT));

  idx = 0;
  while (!pp2_cls_c3_cpu_done (cpu_slot))
    if (++idx >= RETRIES_EXCEEDED)
      {
	pr_err ("%s:Error - retries exceeded.\n", __func__);
	return -EBUSY;
      }

  reg_val = pp2_reg_read (cpu_slot, MVPP2_CLS3_STATE_REG) & MVPP2_CLS3_STATE_OCCIPIED_MASK;
  reg_val = reg_val >> MVPP2_CLS3_STATE_OCCIPIED;

  if ((!occupied_bmp) || (!index))
    {
      /* print to screen - call from sysfs*/
      for (idx = 0; idx < MVPP2_CLS3_HASH_BANKS_NUM; idx++)
	pr_info ("0x%8.8x	%s\n", pp2_reg_read (cpu_slot, MVPP2_CLS3_QRY_RES_HASH_REG (idx)),
		 (reg_val & (1 << idx)) ? "OCCUPIED" : "FREE");
      return 0;
    }

  *occupied_bmp = reg_val;
  for (idx = 0; idx < MVPP2_CLS3_HASH_BANKS_NUM; idx++)
    index[idx] = pp2_reg_read (cpu_slot, MVPP2_CLS3_QRY_RES_HASH_REG (idx));

  return 0;
}

static int
pp2_cls_c3_hw_query_add_relocate (uintptr_t cpu_slot, int new_idx, int max_depth, int cur_depth,
				  struct pp2_cls_c3_hash_pair *hash_pair_arr)
{
  int ret_val = 0, index_free, idx = 0;
  u8 occupied_bmp;
  struct pp2_cls_c3_entry local_c3;
  int used_index[MVPP2_CLS3_HASH_BANKS_NUM] = { 0 };

  if (cur_depth >= max_depth)
    return -EINVAL;

  pp2_cls_c3_sw_clear (&local_c3);

  ret_val = pp2_cls_c3_hw_read (cpu_slot, &local_c3, new_idx);
  if (ret_val)
    {
      pr_err ("%s could not get key for index [0x%x]\n", __func__, new_idx);
      return ret_val;
    }

  ret_val = pp2_cls_c3_hw_query (cpu_slot, &local_c3, &occupied_bmp, used_index);
  if (ret_val)
    {
      pr_err ("%s: pp2_cls_c3_hw_query failed, depth = %d\n", __func__, cur_depth);
      return ret_val;
    }

  /* fill in indices for this key */
  for (idx = 0; idx < MVPP2_CLS3_HASH_BANKS_NUM; idx++)
    {
      /* if new index is in the bank index, skip it */
      if (new_idx == used_index[idx])
	{
	  used_index[idx] = 0;
	  continue;
	}

      /* found a vacant index */
      if (!(occupied_bmp & (1 << idx)))
	{
	  index_free = used_index[idx];
	  break;
	}
    }

  /* no free index, recurse and relocate another key */
  if (idx == MVPP2_CLS3_HASH_BANKS_NUM)
    {
#ifdef MV_DEBUG
      pr_debug ("new[0x%.3x]:%.1d ", new_idx, cur_depth);
      for (idx = 0; idx < MVPP2_CLS3_HASH_BANKS_NUM; idx++)
	pr_debug ("0x%.3x ", used_index[idx]);
      pr_debug ("\n");
#endif

      /* recurse over all valid indices */
      for (idx = 0; idx < MVPP2_CLS3_HASH_BANKS_NUM; idx++)
	{
	  if (used_index[idx] == 0)
	    continue;

	  if (pp2_cls_c3_hw_query_add_relocate (cpu_slot, used_index[idx], max_depth, cur_depth + 1,
						hash_pair_arr) == 0)
	    break;
	}

      /* tried relocate, no valid entries found */
      if (idx == MVPP2_CLS3_HASH_BANKS_NUM)
	return -EIO;
    }

  /* if we reached here, we found a valid free index */
  index_free = used_index[idx];

  /* new_idx del is not necessary */

  /*We do not chage extension tabe*/
  ret_val = pp2_cls_c3_hw_add (cpu_slot, &local_c3, index_free, local_c3.ext_index);

  /* update the hash pair */
  if (!hash_pair_arr)
    {
      hash_pair_arr->old_idx[hash_pair_arr->pair_num] = new_idx;
      hash_pair_arr->new_idx[hash_pair_arr->pair_num] = index_free;
      hash_pair_arr->pair_num++;
    }

  if (ret_val != 0)
    {
      pr_err ("%s:Error - pp2_cls_c3_hw_add failed, depth = %d\\n", __func__, cur_depth);
      return ret_val;
    }

  pr_info ("key relocated  0x%.3x->0x%.3x\n", new_idx, index_free);

  return 0;
}

static int
pp2_cls_c3_mod_set (struct pp2_cls_c3_entry *c3, int data_ptr, int instr_offs, int l4_csum)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (data_ptr, 0, MVPP2_CLS3_ACT_HWF_ATTR_DPTR_MAX))
    return -EINVAL;

  if (mv_pp2x_range_validate (instr_offs, 0, MVPP2_CLS3_ACT_HWF_ATTR_IPTR_MAX))
    return -EINVAL;

  if (mv_pp2x_range_validate (l4_csum, 0, 1))
    return -EINVAL;

  c3->sram.regs.hwf_attr &= ~MVPP2_CLS3_ACT_HWF_ATTR_DPTR_MASK;
  c3->sram.regs.hwf_attr &= ~MVPP2_CLS3_ACT_HWF_ATTR_IPTR_MASK;
  c3->sram.regs.hwf_attr &= ~MVPP2_CLS3_ACT_HWF_ATTR_CHKSM_EN_MASK;

  c3->sram.regs.hwf_attr |= (data_ptr << MVPP2_CLS3_ACT_HWF_ATTR_DPTR);
  c3->sram.regs.hwf_attr |= (instr_offs << MVPP2_CLS3_ACT_HWF_ATTR_IPTR);
  c3->sram.regs.hwf_attr |= (l4_csum << MVPP2_CLS3_ACT_HWF_ATTR_CHKSM_EN);

  return 0;
}

static int
pp2_cls_c3_policer_set (struct pp2_cls_c3_entry *c3, int cmd, int policer_id, int bank)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (cmd, 0, MVPP2_ACTION_TYPE_UPDT_LOCK))
    return -EINVAL;

  if (mv_pp2x_range_validate (policer_id, 0, MVPP2_CLS3_ACT_DUP_POLICER_MAX))
    return -EINVAL;

  if (mv_pp2x_range_validate (bank, 0, 1))
    return -EINVAL;

  c3->sram.regs.actions &= ~MVPP2_CLS3_ACT_POLICER_SELECT_MASK;
  c3->sram.regs.actions |= (cmd << MVPP2_CLS3_ACT_POLICER_SELECT);

  c3->sram.regs.dup_attr &= ~MVPP2_CLS3_ACT_DUP_POLICER_MASK;
  c3->sram.regs.dup_attr |= (policer_id << MVPP2_CLS3_ACT_DUP_POLICER_ID);

  if (bank)
    c3->sram.regs.dup_attr |= MVPP2_CLS3_ACT_DUP_POLICER_BANK_MASK;
  else
    c3->sram.regs.dup_attr &= ~MVPP2_CLS3_ACT_DUP_POLICER_BANK_MASK;

  return 0;
}

static int
pp2_cls_c3_queue_high_set (struct pp2_cls_c3_entry *c3, int cmd, int queue)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (cmd, 0, MVPP2_ACTION_TYPE_UPDT_LOCK))
    return -EINVAL;

  if (mv_pp2x_range_validate (queue, 0, MVPP2_CLS3_ACT_QOS_ATTR_HIGH_Q_MAX))
    return -EINVAL;

  /*set command*/
  c3->sram.regs.actions &= ~MVPP2_CLS3_ACT_HIGH_Q_MASK;
  c3->sram.regs.actions |= (cmd << MVPP2_CLS3_ACT_HIGH_Q);

  /*set modify High queue value*/
  c3->sram.regs.qos_attr &= ~MVPP2_CLS3_ACT_QOS_ATTR_HIGH_Q_MASK;
  c3->sram.regs.qos_attr |= (queue << MVPP2_CLS3_ACT_QOS_ATTR_HIGH_Q);

  return 0;
}

static int
pp2_cls_c3_queue_low_set (struct pp2_cls_c3_entry *c3, int cmd, int queue)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (cmd, 0, MVPP2_ACTION_TYPE_UPDT_LOCK))
    return -EINVAL;

  if (mv_pp2x_range_validate (queue, 0, MVPP2_CLS3_ACT_QOS_ATTR_LOW_Q_MAX))
    return -EINVAL;

  /*set command*/
  c3->sram.regs.actions &= ~MVPP2_CLS3_ACT_LOW_Q_MASK;
  c3->sram.regs.actions |= (cmd << MVPP2_CLS3_ACT_LOW_Q);

  /*set modify High queue value*/
  c3->sram.regs.qos_attr &= ~MVPP2_CLS3_ACT_QOS_ATTR_LOW_Q_MASK;
  c3->sram.regs.qos_attr |= (queue << MVPP2_CLS3_ACT_QOS_ATTR_LOW_Q);

  return 0;
}

static int
pp2_cls_c3_rss_set (struct pp2_cls_c3_entry *c3, int cmd, int rss_en)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (cmd, 0, MVPP2_ACTION_TYPE_UPDT_LOCK))
    return -EINVAL;

  if (mv_pp2x_range_validate (rss_en, 0, 1))
    return -EINVAL;

  c3->sram.regs.actions &= ~MVPP2_CLS3_ACT_RSS_EN_MASK;
  c3->sram.regs.actions |= (cmd << MVPP2_CLS3_ACT_RSS_EN);

  c3->sram.regs.dup_attr &= ~MVPP2_CLS3_ACT_DUP_RSS_EN_MASK;
  c3->sram.regs.dup_attr |= (rss_en << MVPP2_CLS3_ACT_DUP_RSS_EN_BIT);

  return 0;
}

static int
pp2_cls_c3_shadow_ext_free_get (void)
{
  int index;

  /* Go through the all entires from first to last */
  for (index = 0; index < MVPP2_CLS_C3_EXT_TBL_SIZE; index++)
    {
      if (pp2_cls_c3_shadow_ext_tbl[index] == NOT_IN_USE)
	break;
    }
  return index;
}

static int
pp2_cls_c3_sw_hek_byte_set (struct pp2_cls_c3_entry *c3, u32 offs, u8 byte)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (offs, 0, ((MVPP2_CLS_C3_EXT_HEK_WORDS * 4) - 1)))
    return -EINVAL;

  c3->key.hek.bytes[HW_BYTE_OFFS (offs)] = byte;

  return 0;
}

static int
pp2_cls_c3_sw_hek_size_set (struct pp2_cls_c3_entry *c3, int hek_size)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (hek_size, 0, KEY_CTRL_HEK_SIZE_MAX))
    return -EINVAL;

  c3->key.key_ctrl &= ~KEY_CTRL_HEK_SIZE_MASK;
  c3->key.key_ctrl |= (hek_size << KEY_CTRL_HEK_SIZE);
  return 0;
}

static int
pp2_cls_c3_sw_l4_info_set (struct pp2_cls_c3_entry *c3, int l4info)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (l4info, 0, KEY_CTRL_L4_MAX))
    return -EINVAL;

  c3->key.key_ctrl &= ~KEY_CTRL_L4_MASK;
  c3->key.key_ctrl |= (l4info << KEY_CTRL_L4);
  return 0;
}

static int
pp2_cls_c3_sw_lkp_type_set (struct pp2_cls_c3_entry *c3, int lkp_type)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (lkp_type, 0, KEY_CTRL_LKP_TYPE_MAX))
    return -EINVAL;

  c3->key.key_ctrl &= ~KEY_CTRL_LKP_TYPE_MASK;
  c3->key.key_ctrl |= (lkp_type << KEY_CTRL_LKP_TYPE);
  return 0;
}

static int
pp2_cls_c3_sw_port_id_set (struct pp2_cls_c3_entry *c3, int type, int portid)
{
  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (portid, 0, KEY_CTRL_PRT_ID_MAX))
    return -EINVAL;

  if (mv_pp2x_range_validate (type, 0, KEY_CTRL_PRT_ID_TYPE_MAX))
    return -EINVAL;

  c3->key.key_ctrl &= ~(KEY_CTRL_PRT_ID_MASK | KEY_CTRL_PRT_ID_TYPE_MASK);
  c3->key.key_ctrl |= ((portid << KEY_CTRL_PRT_ID) | (type << KEY_CTRL_PRT_ID_TYPE));

  return 0;
}

static int
pp2_cls_db_c2_data_set (struct pp2_inst *inst, u32 c2_db_idx, struct pp2_cls_c2_data_t *c2_data)
{
  /* Param check */
  if (c2_db_idx > MVPP2_C2_LAST_ENTRY)
    {
      pr_err ("Invalid parameter\n");
      return -EINVAL;
    }

  if (!c2_data)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  memcpy (&inst->cls_db->c2_db.c2_data_db[c2_db_idx], c2_data, sizeof (struct pp2_cls_c2_data_t));

  return 0;
}

static struct pp2_cls_c2_index_t *
pp2_cls_db_c2_index_node_get (struct pp2_inst *inst, u32 c2_node_idx)
{
  /* Para check */
  if (c2_node_idx >= MVPP2_C2_ENTRY_MAX)
    {
      pr_err ("Invalid parameter\n");
      return NULL;
    }
  return &inst->cls_db->c2_db.c2_index_db[c2_node_idx];
}

static int
pp2_cls_edrop_assign_qid (struct pp2_inst *inst, u8 edrop_id, u8 qid, int assign)
{
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);
  enum pp2_cls_edrop_ref_cnt_action_t cnt_action;
  int rc;

  if (mv_pp2x_range_validate (edrop_id, MVPP2_EDROP_MIN_ENTRY_ID, MVPP2_EDROP_MAX - 1))
    {
      pr_err ("invalid early-drop ID %d, out of range[%d, %d]\n", edrop_id,
	      MVPP2_EDROP_MIN_ENTRY_ID, MVPP2_EDROP_MAX - 1);
      return -EINVAL;
    }

  if (assign)
    {
      cnt_action = MVPP2_EDROP_REF_CNT_INC;
      mv_pp2x_plcr_hw_rxq_thresh_set (cpu_slot, qid, edrop_id);
    }
  else
    {
      cnt_action = MVPP2_EDROP_REF_CNT_DEC;
      pp2_cls_edrop_bypass_assign_qid (inst, qid);
    }

  rc = pp2_cls_db_edrop_ref_cnt_update (inst, edrop_id, cnt_action);
  if (rc)
    {
      pr_err ("failed to update early-drop ref count\n");
      return rc;
    }

  return rc;
}

static u32
pp2_cls_field_size_get (u32 field_id)
{
  if (field_id == ARP_IPV4_DA_FIELD_ID)
    return ARP_IPV4_DA_FIELD_SIZE;

  if (field_id == IN_VLAN_PRI_FIELD_ID)
    return IN_VLAN_PRI_FIELD_SIZE;

  if (field_id == PPPOE_PROTO_ID)
    return PPPOE_PROTO_SIZE;

  if (field_id >= CLS_FIELD_MAX)
    return 0;

  return pp2_cls_field_size_array[field_id];
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

static int
pp2_prs_uid_to_prs_udf (unsigned int uid)
{
  int i;

  for (i = 0; i < PP2_MAX_UDFS_SUPPORTED; i++)
    if (prs_udf_map[i].user_udf_idx == uid)
      return prs_udf_map[i].prs_udf_id;

  return -1;
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

static u8
pp2_cls_c2_field_unmask_check (u32 field_id, struct pp2_cls_field_match_info *field_unmask)
{
  u8 unmask = 0;
  u32 idx;

  if (!field_unmask)
    return unmask;

  for (idx = 0; idx < MVPP2_FLOW_FIELD_COUNT_MAX; idx++)
    {
      if (field_unmask[idx].valid == MVPP2_FIELD_VALID && field_unmask[idx].field_id == field_id)
	{
	  unmask = 1;
	  break;
	}
    }

  return unmask;
}

static int
pp2_cls_c2_free_slot_find (struct pp2_inst *inst, u32 index1, u32 index2, u32 *free_idx)
{
  struct pp2_cls_c2_index_t *c2_index_node;
  int found = 0;

  if (!free_idx)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (index1 >= index2)
    {
      *free_idx = MVPP2_C2_ENTRY_INVALID_IDX;
      return 0;
    }
  /* Traverse free list */
  LIST_FOR_EACH_OBJECT (c2_index_node, struct pp2_cls_c2_index_t,
			pp2_cls_db_c2_free_list_head_get (inst), list_node)
  {
    if ((c2_index_node->c2_hw_idx > index1) && (c2_index_node->c2_hw_idx < index2))
      {
	found++;
	/* delete it from free list */
	list_del (&c2_index_node->list_node);
	/* Change to node valid status to invalid */
	c2_index_node->valid = MVPP2_C2_ENTRY_INVALID;
	*free_idx = c2_index_node->c2_hw_idx;
	break;
      }
  }
  if (found == 0)
    *free_idx = MVPP2_C2_ENTRY_INVALID_IDX;

  return 0;
}

static int
pp2_cls_c2_lkp_search_down_block_get (struct pp2_inst *inst, u8 lkp_type, u32 pri_start,
				      u32 *c2_search_start, u32 *c2_search_end)
{
  struct pp2_cls_c2_index_t *c2_index_node;
  struct pp2_cls_c2_data_t *c2_entry_data; /*use heap to reduce stack size*/
  u32 first_pri_find, next_pri_find;
  u32 next_pri;

  /* Para check */
  if (!c2_search_start)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!c2_search_end)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  c2_entry_data = clib_mem_alloc_or_null (sizeof (*c2_entry_data));
  if (!c2_entry_data)
    return -ENOMEM;

  memset (c2_entry_data, 0, sizeof (struct pp2_cls_c2_data_t));

  first_pri_find = 0;
  next_pri_find = 0;
  next_pri = 0;
  /* Traverse lookup type list */
  LIST_FOR_EACH_OBJECT (c2_index_node, struct pp2_cls_c2_index_t,
			pp2_cls_db_c2_lkp_type_list_head_get (inst, lkp_type), list_node)
  {
    /* get C2 db entry data */
    if (pp2_cls_db_c2_data_get (inst, c2_index_node->c2_data_db_idx, c2_entry_data))
      {
	if (c2_entry_data)
	  clib_mem_free (c2_entry_data);
	return -EINVAL;
      }
    if (c2_entry_data->priority == pri_start)
      {
	if (first_pri_find == 0)
	  {
	    *c2_search_start = c2_index_node->c2_hw_idx;
	  }
	else
	  {
	    /* Find the first C2 HW entry in HW table */
	    if (*c2_search_start > c2_index_node->c2_hw_idx)
	      *c2_search_start = c2_index_node->c2_hw_idx;
	  }
	first_pri_find++;
      }
    /* Find the next priority */
    if (first_pri_find != 0 && c2_entry_data->priority > pri_start)
      {
	if (next_pri_find == 0)
	  {
	    next_pri = c2_entry_data->priority;
	    *c2_search_end = c2_index_node->c2_hw_idx;
	  }
	else
	  {
	    /* Find the first C2 HW entry in HW table */
	    if (*c2_search_end > c2_index_node->c2_hw_idx)
	      *c2_search_end = c2_index_node->c2_hw_idx;
	  }
	next_pri_find++;
      }
    /* Stop search */
    if (next_pri_find != 0 && c2_entry_data->priority > next_pri)
      break;
  }
  /* if no node with pri, return invalid index */
  if (first_pri_find == 0)
    *c2_search_start = MVPP2_C2_ENTRY_INVALID_IDX;
  if (next_pri_find == 0)
    {
      if (first_pri_find == 0)
	*c2_search_end = MVPP2_C2_ENTRY_INVALID_IDX;
      else
	*c2_search_end = MVPP2_C2_LAST_ENTRY;
    }

  if (c2_entry_data)
    clib_mem_free (c2_entry_data);
  return 0;
}

static int
pp2_cls_c2_lkp_search_up_block_get (struct pp2_inst *inst, u8 lkp_type, u32 pri_start,
				    u32 *c2_search_start, u32 *c2_search_end)
{
  struct pp2_cls_c2_index_t *c2_index_node;
  struct pp2_cls_c2_data_t *c2_entry_data; /*use heap to reduce stack size*/
  u32 first_pri_find, prev_pri_find;
  u32 next_pri;

  /* Para check */
  if (!c2_search_start)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!c2_search_end)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  c2_entry_data = clib_mem_alloc_or_null (sizeof (*c2_entry_data));
  if (!c2_entry_data)
    return -ENOMEM;

  memset (c2_entry_data, 0, sizeof (struct pp2_cls_c2_data_t));

  first_pri_find = 0;
  prev_pri_find = 0;
  next_pri = 0;
  /* Traverse lookup type list */
  LIST_FOR_EACH_OBJECT_REVERSE (c2_index_node, struct pp2_cls_c2_index_t,
				pp2_cls_db_c2_lkp_type_list_head_get (inst, lkp_type), list_node)
  {
    /* get C2 db entry data */
    if (pp2_cls_db_c2_data_get (inst, c2_index_node->c2_data_db_idx, c2_entry_data))
      {
	if (c2_entry_data)
	  clib_mem_free (c2_entry_data);
	return -EINVAL;
      }
    if (c2_entry_data->priority == pri_start)
      {
	if (!first_pri_find)
	  {
	    *c2_search_end = c2_index_node->c2_hw_idx;
	  }
	else
	  {
	    /* Find the last C2 HW entry in HW table */
	    if (*c2_search_end < c2_index_node->c2_hw_idx)
	      *c2_search_end = c2_index_node->c2_hw_idx;
	  }
	first_pri_find++;
      }
    /* Find the next priority */
    if (first_pri_find != 0 && c2_entry_data->priority != pri_start)
      {
	if (prev_pri_find == 0)
	  {
	    next_pri = c2_entry_data->priority;
	    *c2_search_start = c2_index_node->c2_hw_idx;
	  }
	else
	  {
	    /* Find the last C2 HW entry in HW table */
	    if (*c2_search_start < c2_index_node->c2_hw_idx)
	      *c2_search_start = c2_index_node->c2_hw_idx;
	  }
	prev_pri_find++;
      }
    /* Stop search */
    if (prev_pri_find != 0 && c2_entry_data->priority != next_pri)
      break;
  }
  /* if no node with pri, return invalid index */
  if (first_pri_find == 0)
    *c2_search_end = MVPP2_C2_ENTRY_INVALID_IDX;
  if (prev_pri_find == 0)
    {
      if (first_pri_find == 0)
	*c2_search_start = MVPP2_C2_ENTRY_INVALID_IDX;
      else
	*c2_search_start = MVPP2_C2_FIRST_ENTRY;
    }

  if (c2_entry_data)
    clib_mem_free (c2_entry_data);
  return 0;
}

static int
pp2_cls_c2_lkp_type_list_neighbour_pri_get (struct pp2_inst *inst, u32 lkp_type, u32 priority,
					    u32 highest_pri, u32 lowest_pri, u32 *pri_prev,
					    u32 *pri_next)
{
  struct pp2_cls_c2_index_t *c2_index_node;
  struct pp2_cls_c2_data_t *c2_entry_data; /*use heap to reduce stack size*/
  u32 pri_temp_h = 0, pri_temp_l = 0;

  /* para check */
  if (!pri_prev)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!pri_next)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (priority < highest_pri || priority > lowest_pri)
    {
      pr_err ("Invalid C2 internal priority %d\n", priority);
      return -EFAULT;
    }

  if (highest_pri == lowest_pri)
    {
      *pri_prev = MVPP2_C2_LKP_TYPE_INVALID_PRI;
      *pri_next = MVPP2_C2_LKP_TYPE_INVALID_PRI;
      return 0;
    }

  c2_entry_data = clib_mem_alloc_or_null (sizeof (*c2_entry_data));
  if (!c2_entry_data)
    return -ENOMEM;

  memset (c2_entry_data, 0, sizeof (struct pp2_cls_c2_data_t));

  /* Traverse lookup type list */
  LIST_FOR_EACH_OBJECT (c2_index_node, struct pp2_cls_c2_index_t,
			pp2_cls_db_c2_lkp_type_list_head_get (inst, lkp_type), list_node)
  {
    /* get C2 db entry data */
    if (pp2_cls_db_c2_data_get (inst, c2_index_node->c2_data_db_idx, c2_entry_data))
      {
	if (c2_entry_data)
	  clib_mem_free (c2_entry_data);
	return -EINVAL;
      }
    if (priority > c2_entry_data->priority)
      pri_temp_h = c2_entry_data->priority;
    if (priority < c2_entry_data->priority && pri_temp_l == 0)
      pri_temp_l = c2_entry_data->priority;
  }

  *pri_prev = pri_temp_h;
  *pri_next = pri_temp_l;

  if (c2_entry_data)
    clib_mem_free (c2_entry_data);
  return 0;
}

static int
pp2_cls_c2_lkp_type_pri_node_info_get (struct pp2_inst *inst, u8 lkp_type, u32 priority,
				       struct pp2_cls_c2_index_t **c2_hw_first_node,
				       struct pp2_cls_c2_index_t **c2_hw_last_node, u32 *node_count)
{
  struct pp2_cls_c2_index_t *c2_index_node;
  struct pp2_cls_c2_data_t *c2_entry_data; /*use heap to reduce stack size*/
  int i;

  /* param check */
  if (!c2_hw_first_node)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!c2_hw_last_node)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!node_count)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  c2_entry_data = clib_mem_alloc_or_null (sizeof (*c2_entry_data));
  if (!c2_entry_data)
    return -ENOMEM;

  memset (c2_entry_data, 0, sizeof (struct pp2_cls_c2_data_t));

  i = 0;
  /* Traverse lookup type list */
  LIST_FOR_EACH_OBJECT (c2_index_node, struct pp2_cls_c2_index_t,
			pp2_cls_db_c2_lkp_type_list_head_get (inst, lkp_type), list_node)
  {
    /* get C2 db entry data */
    if (pp2_cls_db_c2_data_get (inst, c2_index_node->c2_data_db_idx, c2_entry_data))
      {
	if (c2_entry_data)
	  clib_mem_free (c2_entry_data);
	return -EINVAL;
      }
    if (c2_entry_data->priority == priority)
      {
	if (i == 0)
	  {
	    *c2_hw_first_node = c2_index_node;
	    *c2_hw_last_node = c2_index_node;
	  }
	else
	  {
	    /* Find the first C2 HW entry in HW table */
	    if ((*c2_hw_first_node)->c2_hw_idx > c2_index_node->c2_hw_idx)
	      *c2_hw_first_node = c2_index_node;
	    /* Find the last C2 HW entry in HW table */
	    if ((*c2_hw_last_node)->c2_hw_idx < c2_index_node->c2_hw_idx)
	      *c2_hw_last_node = c2_index_node;
	  }
	i++;
      }
  }

  /* if no node with pri, return invalid index */
  if (i == 0)
    {
      *c2_hw_first_node = NULL;
      *c2_hw_last_node = NULL;
    }
  *node_count = i;

  if (c2_entry_data)
    clib_mem_free (c2_entry_data);
  return 0;
}

static int
pp2_cls_c2_tcam_common_field_hek_get (u32 pkt_value, u32 pkt_value_mask, u32 field_bytes,
				      u32 field_size, u8 filed_unmask, u8 c2_hek[],
				      u8 c2_hek_mask[], u32 *bytes_used)
{
  int i;
  u32 c2_hek_bytes_used;

  /* Para check */
  if (!c2_hek)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!c2_hek_mask)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!bytes_used)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  if (field_size == 0 || field_bytes == 0)
    return -EFAULT;

  /* Parse packet key */
  c2_hek_bytes_used = *bytes_used;
  for (i = 0; i < field_bytes; i++)
    {
      if (field_size % BYTE_BITS)
	{
	  if (i < (field_bytes - 1))
	    {
	      /* HEK Value */
	      c2_hek[c2_hek_bytes_used] =
		(((pkt_value & common_mask_gen (field_size)) >>
		  (BYTE_BITS * (field_bytes - 2 - i) + field_size % BYTE_BITS)) &
		 BYTE_MASK);
	      /* HEK Mask */
	      c2_hek_mask[c2_hek_bytes_used] =
		(((pkt_value_mask & common_mask_gen (field_size) &
		   (filed_unmask ? (~(common_mask_gen (field_size))) :
				   (common_mask_gen (field_size)))) >>
		  (BYTE_BITS * (field_bytes - 2 - i) + field_size % BYTE_BITS)) &
		 BYTE_MASK);
	    }
	  else
	    {
	      /* HEK Value */
	      c2_hek[c2_hek_bytes_used] =
		((pkt_value << (BYTE_BITS - field_size % BYTE_BITS)) & BYTE_MASK);
	      /* HEK Mask */
	      if (!filed_unmask)
		c2_hek_mask[c2_hek_bytes_used] =
		  ((pkt_value_mask << (BYTE_BITS - field_size % BYTE_BITS)) & BYTE_MASK);
	    }
	}
      else
	{
	  /* HEK Value */
	  c2_hek[c2_hek_bytes_used] =
	    (((pkt_value & common_mask_gen (field_size)) >> (BYTE_BITS * (field_bytes - 1 - i))) &
	     BYTE_MASK);
	  /* HEK Mask */
	  c2_hek_mask[c2_hek_bytes_used] = (((pkt_value_mask & common_mask_gen (field_size) &
					      (filed_unmask ? (~(common_mask_gen (field_size))) :
							      (common_mask_gen (field_size)))) >>
					     (BYTE_BITS * (field_bytes - 1 - i))) &
					    BYTE_MASK);
	}
      /* Increase HEK byte count */
      c2_hek_bytes_used++;
    }
  /* Update bytes_used */
  *bytes_used = c2_hek_bytes_used;

  return 0;
}

static int
pp2_cls_c2_tcam_shared_field_hek_get (u32 pkt_value, u32 pkt_value_mask, u32 field_bytes,
				      u32 field_size, u8 filed_unmask, bool comb_flag,
				      u8 comb_offset, u8 c2_hek[], u8 c2_hek_mask[],
				      u32 *bytes_used)
{
  int i;
  u32 left_bits, c2_hek_bytes_used;
  bool comb_flag1, comb_flag2;

  /* Para check */
  if (!c2_hek)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!c2_hek_mask)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }
  if (!bytes_used)
    {
      pr_err ("%s: null pointer\n", __func__);
      return -EFAULT;
    }

  if (field_size == 0 || field_bytes == 0)
    return -EFAULT;

  left_bits = field_size;
  c2_hek_bytes_used = *bytes_used;
  comb_flag1 = comb_flag;
  comb_flag2 = comb_flag;
  for (i = 0; i < field_bytes; i++)
    {
      if (comb_flag2 && comb_flag1)
	{
	  c2_hek_bytes_used--;
	  /* HEK Value */
	  c2_hek[c2_hek_bytes_used] |=
	    (((pkt_value >> (field_size - comb_offset)) & common_mask_gen (comb_offset)) &
	     BYTE_MASK);
	  /* HEK Mask */
	  c2_hek_mask[c2_hek_bytes_used] |=
	    (((pkt_value_mask >> (field_size - comb_offset)) & common_mask_gen (comb_offset) &
	      (filed_unmask ? (~(common_mask_gen (comb_offset))) : common_mask_gen (comb_offset))) &
	     BYTE_MASK);
	  if (((field_size % BYTE_BITS) + comb_offset) > BYTE_BITS || (field_size > BYTE_BITS))
	    {
	      pkt_value &= common_mask_gen (field_size - comb_offset);
	      pkt_value_mask &= common_mask_gen (field_size - comb_offset);
	    }
	  c2_hek_bytes_used++;
	  left_bits = field_size - comb_offset;
	  comb_flag1 = false;
	}
      else if (comb_flag2)
	{
	  if (left_bits % BYTE_BITS)
	    {
	      if (i < (field_bytes - 1))
		{
		  /* HEK Value */
		  c2_hek[c2_hek_bytes_used] =
		    ((pkt_value & common_mask_gen (field_size)) >>
		     (BYTE_BITS * (field_bytes - 2 - i) + left_bits % BYTE_BITS)) &
		    BYTE_MASK;
		  /* HEK Mask */
		  c2_hek_mask[c2_hek_bytes_used] =
		    ((pkt_value_mask & common_mask_gen (field_size) &
		      (filed_unmask ? (~(common_mask_gen (field_size))) :
				      common_mask_gen (field_size))) >>
		     (BYTE_BITS * (field_bytes - 2 - i) + left_bits % BYTE_BITS)) &
		    BYTE_MASK;
		}
	      else
		{
		  /* HEK Value */
		  c2_hek[c2_hek_bytes_used] =
		    (pkt_value << (BYTE_BITS - left_bits % BYTE_BITS)) & BYTE_MASK;
		  /* HEK Mask */
		  if (!filed_unmask)
		    c2_hek_mask[c2_hek_bytes_used] =
		      (pkt_value_mask << (BYTE_BITS - left_bits % BYTE_BITS)) & BYTE_MASK;
		}
	    }
	  else
	    {
	      /* HEK Value */
	      c2_hek[c2_hek_bytes_used] = ((pkt_value & common_mask_gen (field_size)) >>
					   (BYTE_BITS * (field_bytes - 1 - i))) &
					  BYTE_MASK;
	      /* HEK Mask */
	      if (!filed_unmask)
		c2_hek_mask[c2_hek_bytes_used] = ((pkt_value_mask & common_mask_gen (field_size)) >>
						  (BYTE_BITS * (field_bytes - 1 - i))) &
						 BYTE_MASK;
	    }
	  c2_hek_bytes_used++;
	  comb_flag2 = false;
	}
      else
	{
	  /* HEK Value */
	  c2_hek[c2_hek_bytes_used] =
	    ((pkt_value & common_mask_gen (field_size)) >> (BYTE_BITS * (field_bytes - 1 - i))) &
	    BYTE_MASK;
	  /* HEK Mask */
	  c2_hek_mask[c2_hek_bytes_used] =
	    ((pkt_value_mask & common_mask_gen (field_size) &
	      (filed_unmask ? (~(common_mask_gen (field_size))) : common_mask_gen (field_size))) >>
	     (BYTE_BITS * (field_bytes - 1 - i))) &
	    BYTE_MASK;
	  c2_hek_bytes_used++;
	}
    }
  *bytes_used = c2_hek_bytes_used;

  return 0;
}

static int
pp2_cls_c3_common_field_hek_get (u32 pkt_value, u32 field_bytes, u32 field_size, u8 c3_hek[],
				 u32 *bytes_used)
{
  int idx;
  u32 c3_hek_bytes_used;

  pr_debug ("reached\n");

  /* NULL validation */
  if (mv_pp2x_ptr_validate (c3_hek))
    return -EINVAL;

  if (mv_pp2x_ptr_validate (bytes_used))
    return -EINVAL;

  if (field_size == 0 || field_bytes == 0)
    return -EINVAL;

  /* parse packet key */
  c3_hek_bytes_used = *bytes_used;
  for (idx = 0; idx < field_bytes; idx++)
    {
      if (field_size % BYTE_BITS)
	{
	  if (idx < (field_bytes - 1))
	    {
	      /* HEK value */
	      c3_hek[c3_hek_bytes_used] =
		((pkt_value >> (BYTE_BITS * (field_bytes - 2 - idx) + field_size % BYTE_BITS)) &
		 BYTE_MASK);
	    }
	  else
	    {
	      /* HEK value */
	      c3_hek[c3_hek_bytes_used] =
		((pkt_value << (BYTE_BITS - field_size % BYTE_BITS)) & BYTE_MASK);
	    }
	}
      else
	{
	  /* HEK value */
	  c3_hek[c3_hek_bytes_used] =
	    ((pkt_value >> (BYTE_BITS * (field_bytes - 1 - idx))) & BYTE_MASK);
	}
      /* increase HEK byte count */
      c3_hek_bytes_used++;
    }
  /* update bytes_used */
  *bytes_used = c3_hek_bytes_used;

  return 0;
}

static int
pp2_cls_c3_hw_read (uintptr_t cpu_slot, struct pp2_cls_c3_entry *c3, int index)
{
  int i, is_ext;
  int reg_val = 0;
  u32 hash_data[MVPP2_CLS3_HASH_DATA_REG_NUM];
  u32 hash_ext_data[MVPP2_CLS3_HASH_EXT_DATA_REG_NUM];

  if (mv_pp2x_ptr_validate (c3))
    return -EINVAL;

  if (mv_pp2x_range_validate (index, 0, MVPP2_CLS3_HASH_OP_TBL_ADDR_MAX))
    return -EINVAL;

  pp2_cls_c3_sw_clear (c3);

  c3->index = index;
  c3->ext_index = NOT_IN_USE;

  /* write index */
  pp2_reg_write (cpu_slot, MVPP2_CLS3_DB_INDEX_REG, index);

  reg_val |= (index << MVPP2_CLS3_HASH_OP_TBL_ADDR);
  pp2_reg_write (cpu_slot, MVPP2_CLS3_HASH_OP_REG, reg_val);

  /* read action table */
  c3->sram.regs.actions = pp2_reg_read (cpu_slot, MVPP2_CLS3_ACT_REG);
  c3->sram.regs.qos_attr = pp2_reg_read (cpu_slot, MVPP2_CLS3_ACT_QOS_ATTR_REG);
  c3->sram.regs.hwf_attr = pp2_reg_read (cpu_slot, MVPP2_CLS3_ACT_HWF_ATTR_REG);
  c3->sram.regs.dup_attr = pp2_reg_read (cpu_slot, MVPP2_CLS3_ACT_DUP_ATTR_REG);

  c3->sram.regs.seq_l_attr = pp2_reg_read (cpu_slot, MVPP2_CLS3_ACT_SEQ_L_ATTR_REG);
  c3->sram.regs.seq_h_attr = pp2_reg_read (cpu_slot, MVPP2_CLS3_ACT_SEQ_H_ATTR_REG);

  /* read hash data*/
  for (i = 0; i < MVPP2_CLS3_HASH_DATA_REG_NUM; i++)
    hash_data[i] = pp2_reg_read (cpu_slot, MVPP2_CLS3_HASH_DATA_REG (i));

  if (pp2_cls_c3_shadow_tbl[index].size == 0)
    /* entry not in use */
    return 0;

  c3->key.key_ctrl = 0;

  if (pp2_cls_c3_shadow_tbl[index].ext_ptr == NOT_IN_USE)
    {
      is_ext = 0;
      /* TODO REMOVE NEXT LINES- ONLY FOR INTERNAL VALIDATION */
      if ((pp2_cls_c3_shadow_tbl[index].size == 0) ||
	  (pp2_cls_c3_shadow_tbl[index].ext_ptr != NOT_IN_USE))
	{
	  pr_err ("%s: SW internal error.\n", __func__);
	  return -EIO;
	}

      /*read Multihash entry data*/
      c3->key.hek.words[6] = hash_data[0]; /* hek 0*/
      c3->key.hek.words[7] = hash_data[1]; /* hek 1*/
      c3->key.hek.words[8] = hash_data[2]; /* hek 2*/

      /* write key control data to SW */
      c3->key.key_ctrl |=
	(((hash_data[3] & KEY_PRT_ID_MASK (is_ext)) >> (KEY_PRT_ID (is_ext) % DWORD_BITS_LEN))
	 << KEY_CTRL_PRT_ID);

      c3->key.key_ctrl |= (((hash_data[3] & KEY_PRT_ID_TYPE_MASK (is_ext)) >>
			    (KEY_PRT_ID_TYPE (is_ext) % DWORD_BITS_LEN))
			   << KEY_CTRL_PRT_ID_TYPE);

      c3->key.key_ctrl |=
	(((hash_data[3] & KEY_LKP_TYPE_MASK (is_ext)) >> (KEY_LKP_TYPE (is_ext) % DWORD_BITS_LEN))
	 << KEY_CTRL_LKP_TYPE);

      c3->key.key_ctrl |=
	(((hash_data[3] & KEY_L4_INFO_MASK (is_ext)) >> (KEY_L4_INFO (is_ext) % DWORD_BITS_LEN))
	 << KEY_CTRL_L4);
    }
  else
    {
      is_ext = 1;
      /* TODO REMOVE NEXT LINES- ONLY FOR INTERNAL VALIDATION */
      if ((pp2_cls_c3_shadow_tbl[index].size == 0) ||
	  (pp2_cls_c3_shadow_tbl[index].ext_ptr == NOT_IN_USE))
	{
	  pr_err ("%s: SW internal error.\n", __func__);
	  return -EIO;
	}
      c3->ext_index = pp2_cls_c3_shadow_tbl[index].ext_ptr;

      /* write extension index */
      pp2_reg_write (cpu_slot, MVPP2_CLS3_DB_INDEX_REG, pp2_cls_c3_shadow_tbl[index].ext_ptr);

      /* read hash extesion data*/
      for (i = 0; i < MVPP2_CLS3_HASH_EXT_DATA_REG_NUM; i++)
	hash_ext_data[i] = pp2_reg_read (cpu_slot, MVPP2_CLS3_HASH_EXT_DATA_REG (i));

      /* heks bytes 35 - 32 */
      c3->key.hek.words[8] =
	((hash_data[2] & 0x00FFFFFF) << 8) | ((hash_data[1] & 0xFF000000) >> 24);

      /* heks bytes 31 - 28 */
      c3->key.hek.words[7] =
	((hash_data[1] & 0x00FFFFFF) << 8) | ((hash_data[0] & 0xFF000000) >> 24);

      /* heks bytes 27 - 24 */
      c3->key.hek.words[6] = ((hash_data[0] & 0x00FFFFFF) << 8) | (hash_ext_data[6] & 0x000000FF);

      c3->key.hek.words[5] = hash_ext_data[5]; /* heks bytes 23 - 20 */
      c3->key.hek.words[4] = hash_ext_data[4]; /* heks bytes 19 - 16 */
      c3->key.hek.words[3] = hash_ext_data[3]; /* heks bytes 15 - 12 */
      c3->key.hek.words[2] = hash_ext_data[2]; /* heks bytes 11 - 8  */
      c3->key.hek.words[1] = hash_ext_data[1]; /* heks bytes 7 - 4   */
      c3->key.hek.words[0] = hash_ext_data[0]; /* heks bytes 3 - 0   */

      /* write key control data to SW*/

      c3->key.key_ctrl |=
	(((hash_data[3] & KEY_PRT_ID_MASK (is_ext)) >> (KEY_PRT_ID (is_ext) % DWORD_BITS_LEN))
	 << KEY_CTRL_PRT_ID);

      /* PPv2.1 (feature MAS 3.16) LKP_TYPE size and offset changed */

      c3->key.key_ctrl |= (((hash_data[3] & KEY_PRT_ID_TYPE_MASK (is_ext)) >>
			    (KEY_PRT_ID_TYPE (is_ext) % DWORD_BITS_LEN))
			   << KEY_CTRL_PRT_ID_TYPE);

      c3->key.key_ctrl |=
	((((hash_data[2] & 0xf8000000) >> 27) | ((hash_data[3] & 0x1) << 5)) << KEY_CTRL_LKP_TYPE);

      c3->key.key_ctrl |=
	(((hash_data[2] & KEY_L4_INFO_MASK (is_ext)) >> (KEY_L4_INFO (is_ext) % DWORD_BITS_LEN))
	 << KEY_CTRL_L4);
    }

  /* update hek size */
  c3->key.key_ctrl |=
    ((pp2_cls_c3_shadow_tbl[index].size << KEY_CTRL_HEK_SIZE) & KEY_CTRL_HEK_SIZE_MASK);

  return 0;
}

static void
pp2_cls_c3_shadow_set (int hek_size, int index, int ext_index)
{
  pp2_cls_c3_shadow_tbl[index].size = hek_size;

  if (hek_size > MVPP2_CLS_C3_HEK_BYTES)
    {
      pp2_cls_c3_shadow_tbl[index].ext_ptr = ext_index;
      pp2_cls_c3_shadow_ext_tbl[ext_index] = IN_USE;
    }
  else
    {
      pp2_cls_c3_shadow_tbl[index].ext_ptr = NOT_IN_USE;
    }
}

static int
pp2_cls_c3_shared_field_hek_get (u32 pkt_value, u32 field_bytes, u32 field_size, u8 comb_flag,
				 u8 comb_offset, u8 c3_hek[], u32 *bytes_used)
{
  int idx;
  u32 left_bits;
  u32 c3_hek_bytes_used;
  u8 comb_flag1;
  u8 comb_flag2;

  pr_debug ("reached\n");

  /* Para check */
  if (mv_pp2x_ptr_validate (c3_hek))
    return -EINVAL;

  if (mv_pp2x_ptr_validate (bytes_used))
    return -EINVAL;

  if (field_size == 0 || field_bytes == 0)
    return MV_ERROR;

  left_bits = field_size;
  c3_hek_bytes_used = *bytes_used;
  comb_flag1 = comb_flag;
  comb_flag2 = comb_flag;
  for (idx = 0; idx < field_bytes; idx++)
    {
      if (comb_flag2)
	{
	  if (comb_flag1)
	    {
	      c3_hek_bytes_used--;
	      /* HEK value */
	      c3_hek[c3_hek_bytes_used] |= ((pkt_value >> (field_size - comb_offset)) & BYTE_MASK);
	      if (((field_size % BYTE_BITS) + comb_offset) > BYTE_BITS || (field_size > BYTE_BITS))
		{
		  pkt_value &= common_mask_gen (field_size - comb_offset);
		}
	      c3_hek_bytes_used++;
	      left_bits = field_size - comb_offset;
	      comb_flag1 = false;
	    }
	  else
	    {
	      if (left_bits % BYTE_BITS)
		{
		  if (idx < (field_bytes - 1))
		    {
		      /* HEK value */
		      c3_hek[c3_hek_bytes_used] =
			(pkt_value >>
			 (BYTE_BITS * (field_bytes - 2 - idx) + left_bits % BYTE_BITS)) &
			BYTE_MASK;
		    }
		  else
		    {
		      /* HEK value */
		      c3_hek[c3_hek_bytes_used] =
			(pkt_value << (BYTE_BITS - left_bits % BYTE_BITS)) & BYTE_MASK;
		    }
		}
	      else
		{
		  /* HEK value */
		  c3_hek[c3_hek_bytes_used] =
		    (pkt_value >> (BYTE_BITS * (field_bytes - 1 - idx))) & BYTE_MASK;
		}
	      c3_hek_bytes_used++;
	      comb_flag2 = false;
	    }
	}
      else
	{
	  /* HEK Value */
	  c3_hek[c3_hek_bytes_used] =
	    (pkt_value >> (BYTE_BITS * (field_bytes - 1 - idx))) & BYTE_MASK;
	  c3_hek_bytes_used++;
	}
    }
  *bytes_used = c3_hek_bytes_used;

  return 0;
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
mv_pp2x_cls_c2_policer_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int policer_id, int bank)
{
  if (mv_pp2x_ptr_validate (c2) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (cmd, 0, MVPP2_ACTION_TYPE_UPDT_LOCK) == MV_ERROR)
    return MV_ERROR;
  if (mv_pp2x_range_validate (policer_id, 0, MVPP2_CLS2_ACT_DUP_ATTR_PLCRID_MAX) == MV_ERROR)
    return MV_ERROR;
  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_PLCR_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_PLCR_OFF);

  c2->sram.regs.rss_attr &= ~MVPP2_CLS2_ACT_DUP_ATTR_PLCRID_MASK;
  c2->sram.regs.rss_attr |= (policer_id << MVPP2_CLS2_ACT_DUP_ATTR_PLCRID_OFF);

  if (bank)
    c2->sram.regs.rss_attr |= MVPP2_CLS2_ACT_DUP_ATTR_PLCRBK_MASK;
  else
    c2->sram.regs.rss_attr &= ~MVPP2_CLS2_ACT_DUP_ATTR_PLCRBK_MASK;

  return 0;
}

void
mv_pp2x_cls_sw_flow_clear (struct mv_pp2x_cls_flow_entry *fe)
{
  memset (fe, 0, sizeof (struct mv_pp2x_cls_flow_entry));
}

int
mv_pp2x_cls_sw_flow_engine_set (struct mv_pp2x_cls_flow_entry *fe, int engine, int is_last)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (is_last, 0, 1) == MV_ERROR)
    return MV_ERROR;

  fe->data[0] &= ~MVPP2_FLOW_LAST_MASK;
  fe->data[0] &= ~MVPP2_FLOW_ENGINE_MASK;

  fe->data[0] |= is_last;
  fe->data[0] |= (engine << MVPP2_FLOW_ENGINE);

  return 0;
}

int
mv_pp2x_cls_sw_flow_extra_set (struct mv_pp2x_cls_flow_entry *fe, int type, int prio)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (type, 0, MVPP2_FLOW_PORT_ID_MAX) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (prio, 0, ((1 << MVPP2_FLOW_FIELD_ID_BITS) - 1)) == MV_ERROR)
    return MV_ERROR;

  fe->data[1] &= ~MVPP2_FLOW_LKP_TYPE_MASK;
  fe->data[1] |= (type << MVPP2_FLOW_LKP_TYPE);

  fe->data[1] &= ~MVPP2_FLOW_FIELD_PRIO_MASK;
  fe->data[1] |= (prio << MVPP2_FLOW_FIELD_PRIO);

  return 0;
}

int
mv_pp2x_cls_sw_flow_hek_num_set (struct mv_pp2x_cls_flow_entry *fe, int num_of_fields)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (num_of_fields, 0, MVPP2_CLS_FLOWS_TBL_FIELDS_MAX) == MV_ERROR)
    return MV_ERROR;

  fe->data[1] &= ~MVPP2_FLOW_FIELDS_NUM_MASK;
  fe->data[1] |= (num_of_fields << MVPP2_FLOW_FIELDS_NUM);

  return 0;
}

int
mv_pp2x_cls_sw_flow_portid_select (struct mv_pp2x_cls_flow_entry *fe, int from)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (from, 0, 1) == MV_ERROR)
    return MV_ERROR;

  if (from)
    fe->data[0] |= MVPP2_FLOW_PORT_ID_SEL_MASK;
  else
    fe->data[0] &= ~MVPP2_FLOW_PORT_ID_SEL_MASK;

  return 0;
}

int
mv_pp2x_cls_sw_flow_seq_ctrl_set (struct mv_pp2x_cls_flow_entry *fe, int mode)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (mode, 0, MVPP2_FLOW_ENGINE_MAX) == MV_ERROR)
    return MV_ERROR;

  fe->data[1] &= ~MVPP2_FLOW_SEQ_CTRL_MASK;
  fe->data[1] |= (mode << MVPP2_FLOW_SEQ_CTRL);

  return 0;
}

int
mv_pp2x_cls_sw_flow_udf7_set (struct mv_pp2x_cls_flow_entry *fe, int mode)
{
  if (mv_pp2x_ptr_validate (fe) == MV_ERROR)
    return MV_ERROR;

  if (mv_pp2x_range_validate (mode, 0, MVPP2_FLOW_UDF7_MAX) == MV_ERROR)
    return MV_ERROR;

  fe->data[0] &= ~MVPP2_FLOW_UDF7_MASK;
  fe->data[0] |= (mode << MVPP2_FLOW_UDF7);
  return 0;
}

int
mv_pp2x_cls_sw_flow_hek_set (struct mv_pp2x_cls_flow_entry *fe, int field_index, int field_id)
{
  int num_of_fields;

  /* get current num_of_fields */
  num_of_fields = ((fe->data[1] & MVPP2_FLOW_FIELDS_NUM_MASK) >> MVPP2_FLOW_FIELDS_NUM);

  if (num_of_fields < (field_index + 1))
    {
      pr_debug ("%s:num of heks=%d ,idx(%d) out of range\n", __func__, num_of_fields, field_index);
      return -1;
    }

  fe->data[2] &= ~MVPP2_FLOW_FIELD_MASK (field_index);
  fe->data[2] |= (field_id << MVPP2_FLOW_FIELD_ID (field_index));

  return 0;
}

void
mv_pp2x_cls_sw_lkp_clear (struct mv_pp2x_cls_lookup_entry *fe)
{
  memset (fe, 0, sizeof (struct mv_pp2x_cls_lookup_entry));
}

static struct mem_mmap_nd *
mmap_find_iomap_by_index (struct mem_mmap *mmapm, int index)
{
  struct mem_mmap_nd *mmap_nd;
  struct list *pos;

  if (!mmapm->maps_lst.next || !mmapm->maps_lst.prev)
    return NULL;

  LIST_FOR_EACH (pos, &mmapm->maps_lst)
  {
    mmap_nd = MMAP_ND_OBJ (pos);
    if (mmap_nd->index == index)
      return mmap_nd;
  }

  return NULL;
}

static void
iomem_uio_add_entry (struct uio_mem_t **headp, struct uio_mem_t *entry)
{
  entry->next = *headp;
  *headp = entry;
}

static struct uio_mem_t *
iomem_uio_rm_entry (struct uio_mem_t **headp, const char *name)
{
  struct uio_mem_t *entry = *headp;
  struct uio_mem_t *node = NULL;

  while (entry)
    {
      if (!strncmp (entry->info->maps[entry->map_num].name, name, UIO_MAX_NAME_SIZE))
	{
	  *headp = entry->next;
	  headp = &*headp;
	  node = entry;
	  return node;
	}

      headp = &entry->next;
      entry = entry->next;
    }
  return node;
}

struct uio_mem_t *
uio_find_mem_byname (struct uio_info_t *info, const char *filter)
{
  struct uio_info_t *infp = info;
  struct uio_mem_t *uiofdp = NULL;

  if (!infp || !filter)
    return NULL;

  while (infp)
    {
      int i;

      for (i = 0; i < MAX_UIO_MAPS; i++)
	{
	  if (strncmp (infp->maps[i].name, filter, UIO_MAX_NAME_SIZE))
	    {
	      continue;
	    }
	  else
	    {
	      uiofdp = mem_calloc (1, sizeof (struct uio_info_t));
	      uiofdp->map_num = i;
	      uiofdp->fd = UIO_INVALID_FD;
	      uiofdp->info = infp;
	      return uiofdp;
	    }
	}
      infp = infp->next;
    }

  return uiofdp;
}

void *
uio_single_mmap (struct uio_info_t *info, int map_num, int fd)
{
  if (!fd)
    return NULL;
  info->maps[map_num].mmap_result = UIO_MMAP_NOT_DONE;
  if (info->maps[map_num].size == UIO_INVALID_SIZE)
    return NULL;
  info->maps[map_num].mmap_result = UIO_MMAP_FAILED;
  info->maps[map_num].internal_addr = mmap (NULL, info->maps[map_num].size, PROT_READ | PROT_WRITE,
					    MAP_SHARED, fd, map_num * getpagesize ());

  if (info->maps[map_num].internal_addr != MAP_FAILED)
    {
      info->maps[map_num].mmap_result = UIO_MMAP_OK;
      return info->maps[map_num].internal_addr;
    }

  return NULL;
}

void
uio_free_mem_info (struct uio_mem_t *info)
{
  if (info)
    clib_mem_free (info);
  info = NULL;
}

int
pp2_cls_db_plcr_entry_get (struct pp2_inst *inst, u8 policer_id,
			   struct pp2_cls_db_plcr_entry_t *plcr_entry)
{
  if (mv_pp2x_range_validate (policer_id, MVPP2_PLCR_MIN_ENTRY_ID, MVPP2_PLCR_MAX - 1))
    {
      pr_err ("invalid policer ID %d, out of range[%d, %d]\n", policer_id, MVPP2_PLCR_MIN_ENTRY_ID,
	      MVPP2_PLCR_MAX - 1);
      return -EINVAL;
    }

  if (mv_pp2x_ptr_validate (plcr_entry))
    return -EINVAL;

  memcpy (plcr_entry, &inst->cls_db->plcr_db.plcr_arr[policer_id],
	  sizeof (struct pp2_cls_db_plcr_entry_t));
  return 0;
}

int
pp2_cls_db_plcr_ref_cnt_update (struct pp2_inst *inst, u8 policer_id,
				enum pp2_cls_plcr_ref_cnt_action_t cnt_action, int update_ppio)
{
  struct pp2_cls_db_plcr_entry_t *plcr_arr = NULL;
  u32 *ref_cnt;

  if (mv_pp2x_range_validate (policer_id, MVPP2_PLCR_MIN_ENTRY_ID, MVPP2_PLCR_MAX - 1))
    {
      pr_err ("invalid policer ID %d, out of range[%d, %d]\n", policer_id, MVPP2_PLCR_MIN_ENTRY_ID,
	      MVPP2_PLCR_MAX - 1);
      return -EINVAL;
    }

  if (mv_pp2x_range_validate (cnt_action, 0, MVPP2_PLCR_REF_CNT_CLEAR))
    {
      pr_err ("invalid reference counter action %d, out of range[%d, %d]\n", cnt_action, 0,
	      MVPP2_PLCR_REF_CNT_CLEAR);
      return -EINVAL;
    }

  /* check the policer ID */
  plcr_arr = &inst->cls_db->plcr_db.plcr_arr[policer_id];
  if (((cnt_action == MVPP2_PLCR_REF_CNT_INC) || (cnt_action == MVPP2_PLCR_REF_CNT_DEC) ||
       (cnt_action == MVPP2_PLCR_REF_CNT_CLEAR)) &&
      (plcr_arr->valid == MVPP2_PLCR_ENTRY_INVALID_STATE))
    {
      pr_err ("policer ID(%d) is invalid\n", policer_id);
      return -EINVAL;
    }

  /* action to reference counter */
  if (update_ppio)
    ref_cnt = &plcr_arr->ppios_ref_cnt;
  else
    ref_cnt = &plcr_arr->rules_ref_cnt;

  switch (cnt_action)
    {
    case MVPP2_PLCR_REF_CNT_INC:
      (*ref_cnt)++;
      break;
    case MVPP2_PLCR_REF_CNT_DEC:
      (*ref_cnt)--;
      break;
    case MVPP2_PLCR_REF_CNT_CLEAR:
      (*ref_cnt) = 0;
      break;
    default:
      break;
    }

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

int
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

static int
pp2_prs_tag_mode_set (struct pp2_port *port, int type, int val, enum pp2_ppio_cls_target target)
{
  u32 ri = 0, nri = 0;
  u32 ri_mask = 0;

  if (target == PP2_CLS_TARGET_LOCAL_PPIO)
    {
      ri = MVPP2_PRS_RI_UDF7_LOG_PORT;
      nri = MVPP2_PRS_RI_UDF7_NIC;
    }
  else
    {
      ri = MVPP2_PRS_RI_UDF7_NIC;
      nri = MVPP2_PRS_RI_UDF7_LOG_PORT;
    }

  ri_mask = MVPP2_PRS_RI_UDF7_MASK;

  pr_debug ("%s target %d, ri %x, nri %x, mask %x\n", __func__, target, ri, nri, ri_mask);

  switch (type)
    {
    case MVPP2_TAG_TYPE_EDSA:
      /* create new entries for DSA mode*/
      pp2_prs_dsa_tag_mode_set (port, val, MVPP2_PRS_TAGGED, MVPP2_PRS_EDSA, ri, ri_mask);
      pp2_prs_dsa_tag_mode_set (port, val, MVPP2_PRS_UNTAGGED, MVPP2_PRS_EDSA, ri, ri_mask);
      break;
    case MVPP2_TAG_TYPE_DSA:
      /* create new entries for DSA mode*/
      pp2_prs_dsa_tag_mode_set (port, val, MVPP2_PRS_TAGGED, MVPP2_PRS_DSA, ri, ri_mask);
      pp2_prs_dsa_tag_mode_set (port, val, MVPP2_PRS_UNTAGGED, MVPP2_PRS_DSA, ri, ri_mask);
      break;
    case MVPP2_TAG_TYPE_MH:
    case MVPP2_TAG_TYPE_NONE:
      /* Remove port form EDSA and DSA entries */
      pp2_prs_port_update (port, false, MVPP2_PE_DSA_TAGGED, nri, ri_mask);
      pp2_prs_port_update (port, false, MVPP2_PE_DSA_UNTAGGED, nri, ri_mask);
      pp2_prs_port_update (port, false, MVPP2_PE_EDSA_TAGGED, nri, ri_mask);
      pp2_prs_port_update (port, false, MVPP2_PE_EDSA_UNTAGGED, nri, ri_mask);
      break;
    default:
      if ((type < 0) || (type > MVPP2_TAG_TYPE_EDSA))
	return -EINVAL;
    }

  return 0;
}

static int
pp2_prs_proto_lookup (u16 proto, u16 lookup[], u16 proto_num[])
{
  switch (proto)
    {
    case MV_NET_PROTO_VLAN:
      proto_num[0] = ETH_P_8021Q;
      proto_num[1] = ETH_P_8021AD;
      lookup[0] = MVPP2_PRS_LU_VLAN;
      break;
    case MV_NET_PROTO_ARP:
      proto_num[0] = ARP_PROTO;
      lookup[0] = MVPP2_PRS_LU_L2;
      break;
    case MV_NET_PROTO_PPPOE:
      proto_num[0] = PPPOE_PROTO;
      lookup[0] = MVPP2_PRS_LU_L2;
      break;
    case MV_NET_PROTO_IP:
      proto_num[0] = ETH_P_IP;
      proto_num[1] = ETH_P_IPV6;
      lookup[0] = MVPP2_PRS_LU_L2;
      break;
    case MV_NET_PROTO_IP4:
      proto_num[0] = ETH_P_IP;
      lookup[0] = MVPP2_PRS_LU_L2;
      break;
    case MV_NET_PROTO_IP6:
      proto_num[0] = ETH_P_IPV6;
      lookup[0] = MVPP2_PRS_LU_L2;
      break;
      break;
    case MV_NET_PROTO_TCP:
      proto_num[0] = IPPROTO_TCP;
      lookup[0] = MVPP2_PRS_LU_IP4;
      lookup[1] = MVPP2_PRS_LU_IP6;
      break;
    case MV_NET_PROTO_UDP:
      proto_num[0] = IPPROTO_UDP;
      lookup[0] = MVPP2_PRS_LU_IP4;
      lookup[1] = MVPP2_PRS_LU_IP6;
      break;
    case MV_NET_PROTO_ICMP:
      proto_num[0] = IPPROTO_ICMP;
      lookup[0] = MVPP2_PRS_LU_IP4;
      lookup[1] = MVPP2_PRS_LU_IP6;
      break;
    default:
      return -EINVAL;
    }

  return 0;
}

static int
pp2_prs_tcam_idx_list_build (struct pp2_inst *inst, u32 lookup, u16 proto, int negate, u32 ri)
{
  int tid, i = 0;
  u8 byte;
  u16 word;
  u8 tcam_ai;
  int update = false;
  int found = 0;
  struct mv_pp2x_prs_shadow *prs_shadow = inst->cls_db->prs_db.prs_shadow;
  struct prs_log_port_tcam_negated_proto_node *neg_proto_node;
  int rc;

  for (tid = MVPP2_PE_FIRST_FREE_TID; tid <= MVPP2_PRS_TCAM_SRAM_SIZE; tid++)
    {

      update = false;

      if (i >= MVPP2_PE_TID_SIZE)
	return -EFAULT;

      if (tid == MVPP2_PE_LAST_FREE_TID)
	/* Skip parser filtering area and increment to start of default area */
	tid = MVPP2_PE_LAST_FREE_TID + MVPP2_PRS_MAC_RANGE_SIZE + MVPP2_PRS_VLAN_FILT_RANGE_SIZE;

      if (!prs_shadow[tid].valid)
	continue;

      if (prs_shadow[tid].lu != lookup)
	continue;

      if (negate)
	{
	  /* Add protocol to negated list */
	  rc = pp2_prs_tcam_neg_proto_check (inst, proto);
	  if (!rc)
	    {
	      neg_proto_node = clib_mem_alloc_or_null (sizeof (*neg_proto_node));
	      if (!neg_proto_node)
		return -ENOMEM;

	      neg_proto_node->proto = proto;
	      list_add_to_tail (&neg_proto_node->list_node,
				&inst->cls_db->prs_db.tcam_neg_proto_list);
	    }
	}

      switch (proto)
	{
	case ARP_PROTO:
	case PPPOE_PROTO:
	case ETH_P_IP:
	case ETH_P_IPV6:
	case ETH_P_8021Q:
	case ETH_P_8021AD:
	  /* For L2, need to match type in TCAM words 0 and 1 */
	  word = (prs_shadow[tid].tcam.byte[TCAM_DATA_BYTE (0)] << 8) +
		 prs_shadow[tid].tcam.byte[TCAM_DATA_BYTE (1)];
	  if ((word == proto && negate == 0) || (word != proto && negate == 1))
	    {
	      /* Check if protocol was already negated before. In this case, skip adding it */
	      found = pp2_prs_tcam_neg_proto_check (inst, word);
	      if (found)
		continue;

	      update = true;
	    }
	  else if (word == proto && negate == 1)
	    {
	      /* If negated, need to check if the protocol was already added to
	       * the match list (maybe in another rule). In this case, remove from the list
	       */
	      found = pp2_cls_db_prs_match_list_check (inst, tid);
	      if (found)
		pp2_cls_db_prs_match_list_remove_idx (inst, tid);
	    }
	  break;
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
	  if (lookup == MVPP2_PRS_LU_IP4)
	    {
	      /* For L3, need to match the protocol in TCAM byte 5 */
	      byte = prs_shadow[tid].tcam.byte[TCAM_DATA_BYTE (5)];
	      if ((byte == proto && negate == 0) || (byte != proto && negate == 1))
		{
		  /*
		   * In IPv4 parser entries, there are 2 rounds performed:
		   * the first round is to match the protocol, while the second round
		   * is to set the cast flag. The entries needed are those that match
		   * the protocol and not the ones that set the cast flag
		   */
		  tcam_ai = prs_shadow[tid].tcam.byte[HW_BYTE_OFFS (MVPP2_PRS_TCAM_AI_BYTE)];
		  if (tcam_ai != 0x0)
		    continue;

		  /* Check if protocol was already negated before. In this case, skip adding it */
		  found = pp2_prs_tcam_neg_proto_check (inst, byte);
		  if (found)
		    continue;

		  update = true;
		}
	      else if (byte == proto && negate == 1)
		{
		  /* If negated, need to check if the protocol was already added to
		   * the match list (maybe in another rule). In this case, remove from the list
		   */
		  found = pp2_cls_db_prs_match_list_check (inst, tid);
		  if (found)
		    pp2_cls_db_prs_match_list_remove_idx (inst, tid);
		}
	    }
	  else if (lookup == MVPP2_PRS_LU_IP6)
	    {
	      /* For IPv6, need to match the protocol in TCAM byte 0 */
	      byte = prs_shadow[tid].tcam.byte[TCAM_DATA_BYTE (0)];
	      if ((byte == proto && negate == 0) || (byte != proto && negate == 1))
		{
		  /*
		   * In IPv6 parser entries, there are 2 rounds performed:
		   * the first round is to match the cast flag, while the second round
		   * is to set the protocol. The entries needed are those that match
		   * the protocol and not the ones that set the cast flag
		   */
		  tcam_ai = prs_shadow[tid].tcam.byte[HW_BYTE_OFFS (MVPP2_PRS_TCAM_AI_BYTE)];
		  if (tcam_ai != 0x1)
		    continue;

		  /* Check if protocol was already negated before. In this case, skip adding it */
		  found = pp2_prs_tcam_neg_proto_check (inst, byte);
		  if (found)
		    continue;

		  update = true;
		}
	      else if (byte == proto && negate == 1)
		{
		  /* If negated, need to check if the protocol was already added to
		   * the match list (maybe in another rule). In this case, remove from the list
		   */
		  found = pp2_cls_db_prs_match_list_check (inst, tid);
		  if (found)
		    pp2_cls_db_prs_match_list_remove_idx (inst, tid);
		}
	    }
	  break;
	case 0:
	  /* DSA will enter here */
	  update = true;
	default:
	  pr_err ("No matching protocol found for proto: %x , lookup %d\n", proto, lookup);
	}

      if (update)
	{
	  /* add match to db */
	  found = pp2_cls_db_prs_match_list_check (inst, tid);
	  if (!found)
	    {
	      if (prs_shadow[tid].ri & ri)
		pp2_cls_db_prs_match_list_add (inst, tid, 1);
	      else
		pp2_cls_db_prs_match_list_add (inst, tid, 0);
	      i++;
	    }
	}
    }

  return 0;
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

const char *
pp2_g_enum_prs_lookup_str_get (int value)
{
  return lookup_enum_str (g_enum_prs_lookup, MVPP2_MEMBER_NUM (g_enum_prs_lookup), value);
}

const char *
pp2_g_enum_prs_proto_num_str_get (int value)
{
  return lookup_enum_str (g_enum_prs_proto_num, MVPP2_MEMBER_NUM (g_enum_prs_proto_num), value);
}

static int
pp2_bm_get_8pool_mode (uintptr_t cpu_slot)
{
  int val;

  val = pp2_reg_read (cpu_slot, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG);
  pr_debug ("8pool_mode is:%s\n", (val & MVPP23_BM_8POOL_MODE) ? "enabled" : "disabled");
  return (val & MVPP23_BM_8POOL_MODE);
}

static int
cmp_prio (const void *rl1, const void *rl2)
{
  if (((const struct pp2_cls_rl_entry_t *) rl1)->prio <
      ((const struct pp2_cls_rl_entry_t *) rl2)->prio)
    return -1;
  else if (((const struct pp2_cls_rl_entry_t *) rl1)->prio >
	   ((const struct pp2_cls_rl_entry_t *) rl2)->prio)
    return 1;
  else
    return 0;
}

int
pp2_cls_mng_tbl_init (struct pp2_cls_tbl_params *params, struct pp2_cls_tbl **tbl, int lkp_type)
{
  struct pp2_cls_fl_rule_list_t *fl_rls;
  struct pp2_ppio *ppio;
  struct pp2_port *port;
  struct pp2_inst *inst;
  struct pp2_cls_tbl *tbl_node = NULL;
  struct pp2_cls_cos_desc *cos;

  u32 idx;
  u32 field, match_bm;
  u32 rc = 0;
  u32 i, num_lkpid = 0, field_index;
  int udf_id;
  u32 five_tuple = 0;
  u32 ipv4_flag = 0;
  u32 ipv6_flag = 0;
  u32 tcp_flag = 0;
  u32 udp_flag = 0;
  u32 l4_flag = 0;
  u16 select_logical_id[30];

  if (mv_pp2x_ptr_validate (params))
    {
      pr_err ("%s(%d) fail, param = NULL\n", __func__, __LINE__);
      return -EINVAL;
    }

  /* get packet processor instance */
  ppio = params->default_act.cos->ppio;
  port = GET_PPIO_PORT (ppio);
  inst = port->parent;

  if ((params->type != PP2_CLS_TBL_EXACT_MATCH) && (params->type != PP2_CLS_TBL_MASKABLE))
    {
      pr_err ("%s(%d) fail, engine type = %d is out of range\n", __func__, __LINE__, params->type);
      return -EINVAL;
    }

  if (mv_pp2x_range_validate (params->max_num_rules, 0, CLS_MNG_RULES_SIZE_MAX))
    {
      pr_err ("%s(%d) fail, max_num_rules = %d is out of range\n", __func__, __LINE__,
	      params->max_num_rules);
      return -EINVAL;
    }

  if (mv_pp2x_range_validate (params->default_act.cos->tc, 0, port->num_tcs))
    {
      pr_err ("%s(%d) fail, tc = %d is out of range\n", __func__, __LINE__,
	      params->default_act.cos->tc);
      return -EINVAL;
    }

  if (mv_pp2x_range_validate (params->key.key_size, 1, CLS_MNG_KEY_SIZE_MAX))
    {
      pr_err ("%s(%d) fail, key_size = %d is out of range\n", __func__, __LINE__,
	      params->key.key_size);
      return -EINVAL;
    }

  if (mv_pp2x_range_validate (params->key.num_fields, 1, PP2_CLS_TBL_MAX_NUM_FIELDS))
    {
      pr_err ("%s(%d) fail, num_fields = %d is out of range\n", __func__, __LINE__,
	      params->key.num_fields);
      return -EINVAL;
    }

  for (i = 0; i < params->key.num_fields; i++)
    {
      if (mv_pp2x_range_validate (params->key.proto_field[i].proto, MV_NET_PROTO_NONE + 1,
				  MV_NET_PROTO_LAST - 1))
	{
	  pr_err ("%s(%d) fail, protocol = %d is out of range\n", __func__, __LINE__,
		  params->key.proto_field[i].proto);
	  return -EINVAL;
	}
    }

  if ((params->default_act.type != PP2_CLS_TBL_ACT_DROP) &&
      (params->default_act.type != PP2_CLS_TBL_ACT_DONE))
    {
      pr_err ("%s(%d) fail, action type = %d is out of range\n", __func__, __LINE__,
	      params->default_act.type);
      return -EINVAL;
    }

  fl_rls = clib_mem_alloc_or_null (sizeof (*fl_rls));
  if (!fl_rls)
    return -ENOMEM;

  fl_rls->fl_len = 1;
  field_index = 0;

  /* parse the protocol and protocol fields */
  for (idx = 0; idx < params->key.num_fields; idx++)
    {
      rc = lookup_field_id (params->key.proto_field[idx], &field, &match_bm);
      if (rc)
	{
	  pr_err ("%s(%d) lookup id error!\n", __func__, __LINE__);
	  goto end;
	}

      if (field == NOT_SUPPORTED_YET)
	{
	  pr_err ("key not supported (proto:field %d:%d) - table not created.\n",
		  params->key.proto_field[idx].proto, params->key.proto_field[idx].field.eth);
	  rc = -EINVAL;
	  goto end;
	}

      if (params->key.proto_field[idx].proto == MV_NET_PROTO_IP4)
	{
	  ipv4_flag = 1;
	  if ((params->key.proto_field[idx].field.ipv4 == MV_NET_IP4_F_PROTO) &&
	      (params->key.num_fields == PP2_CLS_TBL_MAX_NUM_FIELDS))
	    five_tuple = 1;
	}
      else if (params->key.proto_field[idx].proto == MV_NET_PROTO_IP6)
	{
	  ipv6_flag = 1;
	  if ((params->key.proto_field[idx].field.ipv6 == MV_NET_IP6_F_NEXT_HDR) &&
	      (params->key.num_fields == PP2_CLS_TBL_MAX_NUM_FIELDS))
	    five_tuple = 1;
	}
      if (params->key.proto_field[idx].proto == MV_NET_PROTO_TCP)
	tcp_flag = 1;
      else if (params->key.proto_field[idx].proto == MV_NET_PROTO_UDP)
	udp_flag = 1;
      else if (params->key.proto_field[idx].proto == MV_NET_PROTO_L4)
	l4_flag = 1;
      else if (params->key.proto_field[idx].proto == MV_NET_UDF)
	{
	  udf_id = pp2_prs_uid_to_prs_udf (params->key.proto_field[idx].field.udf.id);
	  if (udf_id <= 0)
	    {
	      pr_err ("%s(%d) invalid udf number\n", __func__, __LINE__);
	      return -EINVAL;
	    }
	  /* Add UDF field */
	  pp2_cls_udf_field_add (inst, udf_id, 0, params->key.proto_field[idx].field.udf.size);
	}

      fl_rls->fl[0].field_id[field_index++] = field;
    }

  /* engine selection */
  if (params->type == PP2_CLS_TBL_MASKABLE)
    {
      if (five_tuple)
	{
	  pr_err ("%s(%d) maskable engine doesn't support 5 tuples!\n", __func__, __LINE__);
	  return -EINVAL;
	}
      fl_rls->fl[0].engine = MVPP2_CLS_ENGINE_C2;
    }
  else if (params->type == PP2_CLS_TBL_EXACT_MATCH)
    {
      if (five_tuple)
	fl_rls->fl[0].engine =
	  (lkp_type == MVPP2_CLS_LKP_MUSDK_LOG_HASH) ? MVPP2_CLS_ENGINE_C3HB : MVPP2_CLS_ENGINE_C3B;
      else
	fl_rls->fl[0].engine =
	  (lkp_type == MVPP2_CLS_LKP_MUSDK_LOG_HASH) ? MVPP2_CLS_ENGINE_C3HA : MVPP2_CLS_ENGINE_C3A;
    }
  else
    {
      pr_err ("%s(%d) unknown engine type!\n", __func__, __LINE__);
      return -EINVAL;
    }

  /* port type - TODO fixed to PHY for now */
  fl_rls->fl[0].port_type = MVPP2_SRC_PORT_TYPE_PHY;

  /* port ID - TODO set it fixed to 1. this value is used only if
   * PortIdSelect bit in CLS_FLOW_TBL1 register is set to 0
   */

  fl_rls->fl[0].port_bm = (1 << port->id);

  /* lookup_type */
  fl_rls->fl[0].lu_type = lkp_type;
  /* as default DSCP flows should be disabled */
  fl_rls->fl[0].enabled = (lkp_type != MVPP2_CLS_LKP_MUSDK_DSCP_PRI) ? true : false;

  fl_rls->fl[0].prio = pp2_cls_mng_lkp_type_to_prio (lkp_type);
  if (fl_rls->fl[0].prio < 0)
    return -EINVAL;

  fl_rls->fl[0].udf7 =
    (port->type == PP2_PPIO_T_LOG) ? MVPP2_CLS_MUSDK_LOG_UDF7 : MVPP2_CLS_MUSDK_NIC_UDF7;
  fl_rls->fl[0].seq_ctrl = MVPP2_CLS_DEF_SEQ_CTRL;
  fl_rls->fl[0].field_id_cnt = params->key.num_fields - five_tuple;

  pr_debug ("ipv4_flag = %d\n", ipv4_flag);
  pr_debug ("ipv6_flag = %d\n", ipv6_flag);
  pr_debug ("l4_flag = %d\n", l4_flag);
  pr_debug ("udp_flag = %d\n", udp_flag);
  pr_debug ("tcp_flag = %d\n", tcp_flag);

  if (lkp_type == MVPP2_CLS_LKP_MUSDK_CLS)
    {
      num_lkpid = pp2_cls_mng_get_lkpid_for_flow_type (&select_logical_id[0], ipv4_flag, ipv6_flag,
						       tcp_flag, udp_flag, l4_flag);
    }
  else if (lkp_type == MVPP2_CLS_LKP_MUSDK_LOG_HASH)
    {
      num_lkpid = pp2_cls_mng_get_lkpid_for_rss (fl_rls->fl[0].engine, &select_logical_id[0],
						 ipv4_flag, ipv6_flag);
    }
  else
    {
      num_lkpid = pp2_cls_mng_get_lkpid_for_lkp_type (lkp_type, &select_logical_id[0]);
    }

  /* add current rule for all selected logical flow id */
  for (i = 0; i < num_lkpid; i++)
    {
      pr_debug ("select_logical_id = %d\n", select_logical_id[i]);
      fl_rls->fl[0].fl_log_id = select_logical_id[i];

      /* Add flow rule */
      pp2_cls_lkp_dcod_set_and_disable (inst, select_logical_id[i]);
      rc = pp2_cls_fl_rule_add (inst, fl_rls);
      if (rc)
	{
	  pr_err ("failed to add cls flow rule\n");
	  goto end;
	}
      pp2_cls_lkp_dcod_enable (inst, select_logical_id[i]);
    }

  /* add flow to list db */
  rc = pp2_cls_db_mng_tbl_add (&tbl_node);
  tbl_node->params.max_num_rules = params->max_num_rules;
  tbl_node->params.type = params->type;
  tbl_node->type = PP2_CLS_FLOW_TBL;
  tbl_node->params.default_act.type = params->default_act.type;
  cos = clib_mem_alloc_or_null (sizeof (*cos));
  if (!cos)
    {
      pr_err ("%s(%d) no mem for pp2_cls_cos_desc!\n", __func__, __LINE__);
      return -ENOMEM;
    }
  tbl_node->params.default_act.cos = cos;
  tbl_node->params.default_act.cos->ppio = params->default_act.cos->ppio;
  tbl_node->params.default_act.cos->tc = params->default_act.cos->tc;

  tbl_node->params.key.key_size = params->key.key_size;
  tbl_node->params.key.num_fields = params->key.num_fields;
  for (i = 0; i < params->key.num_fields; i++)
    {
      tbl_node->params.key.proto_field[i].proto = params->key.proto_field[i].proto;
      tbl_node->params.key.proto_field[i].field = params->key.proto_field[i].field;
    }
  *tbl = tbl_node;

end:
  if (fl_rls)
    clib_mem_free (fl_rls);
  return rc;
}

int
mv_sys_match (const char *match, const char *obj_type, u8 hierarchy_level, u8 id[])
{
  char tmp_str[MAX_OBJ_STRING];
  char *tok;
  int rc;

  if (hierarchy_level > 2)
    {
      pr_err ("Maximum 3 levels of hierarchy supported (given %d)!\n", hierarchy_level);
      return (-1);
    }

  memcpy (tmp_str, match, strlen (match));
  tmp_str[strlen (match)] = '\0';
  tok = mv_strtok (tmp_str, "-");
  if (!tok)
    {
      pr_err ("Illegal match str!\n");
      return -1;
    }

  if (strcmp (obj_type, tok))
    {
      pr_err ("String {%s} does not match obj_type {%s}\n", tok, obj_type);
      return (-1);
    }

  if (hierarchy_level == 1)
    {
      tok = mv_strtok (NULL, "");
      if (!tok)
	{
	  pr_err ("Illegal match str!\n");
	  return -1;
	}
      rc = kstrtou8 (tok, 10, &id[0]);
      if (rc)
	{
	  pr_err ("String \"%s\" is not a number.\n", tok);
	  return rc;
	}
    }
  else if (hierarchy_level == 2)
    {
      tok = mv_strtok (NULL, ":");
      if (!tok)
	{
	  pr_err ("Illegal match str!\n");
	  return -1;
	}
      rc = kstrtou8 (tok, 10, &id[0]);
      if (rc)
	{
	  pr_err ("String \"%s\" is not a number.\n", tok);
	  return rc;
	}
      tok = mv_strtok (NULL, "");
      if (!tok)
	{
	  pr_err ("Illegal match str!\n");
	  return -1;
	}
      rc = kstrtou8 (tok, 10, &id[1]);
      if (rc)
	{
	  pr_err ("String \"%s\" is not a number.\n", tok);
	  return rc;
	}
    }

  return 0;
}

int
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

static int
pp2_prs_dsa_tag_mode_set (struct pp2_port *port, u32 val, int tagged, int extend, u32 ri,
			  u32 ri_mask)
{
  struct mv_pp2x_prs_entry pe;
  int tid, shift;
  struct pp2_inst *inst = port->parent;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  if (extend)
    {
      tid = tagged ? MVPP2_PE_ETYPE_EDSA_TAGGED : MVPP2_PE_ETYPE_EDSA_UNTAGGED;
      shift = 8;
    }
  else
    {
      tid = tagged ? MVPP2_PE_ETYPE_DSA_TAGGED : MVPP2_PE_ETYPE_DSA_UNTAGGED;
      shift = 4;
    }

  /* Build a list with indexes matching the specified lookup id and proto */
  pp2_prs_tcam_idx_list_build (inst, MVPP2_PRS_LU_DSA, 0, 0, ri);

  if (!pp2_cls_db_prs_match_list_log_port_check (inst))
    {
      /* Create new parser entries for the specified logical port */
      /* step 1: Not fragmented packet */
      tid = pp2_prs_tcam_first_free (inst, MVPP2_PE_FIRST_FREE_TID, MVPP2_PE_LAST_FREE_TID);
      if (tid < 0)
	return tid;

      memset (&pe, 0, sizeof (struct mv_pp2x_prs_entry));
      mv_pp2x_prs_tcam_lu_set (&pe, MVPP2_PRS_LU_DSA);
      pe.index = tid;

      /* Shift 4 bytes if DSA tag or 8 bytes in case of EDSA tag*/
      mv_pp2x_prs_sram_shift_set (&pe, shift, MVPP2_PRS_SRAM_OP_SEL_SHIFT_ADD);

      /* Update shadow table */
      mv_pp2x_prs_shadow_set (inst, pe.index, MVPP2_PRS_LU_DSA);

      if (tagged)
	{
	  /* Set tagged bit in DSA tag */
	  mv_pp2x_prs_tcam_data_byte_set (&pe, 0, MVPP2_PRS_TCAM_DSA_TAGGED_BIT,
					  MVPP2_PRS_TCAM_DSA_TAGGED_BIT);
	  /* Clear all ai bits for next iteration */
	  mv_pp2x_prs_sram_ai_update (&pe, 0, MVPP2_PRS_SRAM_AI_MASK);
	  /* If packet is tagged continue check vlans */
	  mv_pp2x_prs_sram_next_lu_set (&pe, MVPP2_PRS_LU_VLAN);
	}
      else
	{
	  /* Set result info bits to 'no vlans' */
	  mv_pp2x_prs_sram_ri_update (&pe, MVPP2_PRS_RI_VLAN_NONE, MVPP2_PRS_RI_VLAN_MASK);
	  mv_pp2x_prs_sram_next_lu_set (&pe, MVPP2_PRS_LU_L2);
	}

      /* update TCAM */
      switch (val)
	{
	case MV_NET_TO_CPU_DSA_TAG_MODE:
	  mv_pp2x_prs_tcam_data_byte_set (&pe, 0, MVPP2_PRS_TCAM_DSA_TO_CPU_MODE,
					  MVPP2_PRS_TCAM_DSA_MODE_MASK);
	  break;
	case MV_NET_FROM_CPU_DSA_TAG_MODE:
	  mv_pp2x_prs_tcam_data_byte_set (&pe, 0, MVPP2_PRS_TCAM_DSA_FROM_CPU_MODE,
					  MVPP2_PRS_TCAM_DSA_MODE_MASK);
	  break;
	case MV_NET_TO_SNIFFER_DSA_TAG_MODE:
	  mv_pp2x_prs_tcam_data_byte_set (&pe, 0, MVPP2_PRS_TCAM_DSA_TO_SNIFFER_MODE,
					  MVPP2_PRS_TCAM_DSA_MODE_MASK);
	  break;
	case MV_NET_FORWARD_DSA_TAG_MODE:
	  mv_pp2x_prs_tcam_data_byte_set (&pe, 0, MVPP2_PRS_TCAM_DSA_FORWARD_MODE,
					  MVPP2_PRS_TCAM_DSA_MODE_MASK);
	  break;
	default:
	  pr_err ("parser logical port special field DSA mode: invalid tcam value\n");
	  return -EFAULT;
	}

      /* update UDF7 */
      mv_pp2x_prs_sram_ri_update (&pe, ri, ri_mask);

      /* Mask all ports */
      mv_pp2x_prs_tcam_port_map_set (&pe, 0);

      /* Update port mask */
      mv_pp2x_prs_tcam_port_set (&pe, port->id, true);

      /* Update shadow table and hw entry */
      mv_pp2x_prs_shadow_set (inst, pe.index, MVPP2_PRS_LU_DSA);
      mv_pp2x_prs_hw_write (cpu_slot, &pe);
    }

  return 0;
}

int
pp2_prs_tcam_neg_proto_check (struct pp2_inst *inst, u32 proto)
{
  struct prs_log_port_tcam_negated_proto_node *neg_proto_node;

  LIST_FOR_EACH_OBJECT (neg_proto_node, struct prs_log_port_tcam_negated_proto_node,
			&inst->cls_db->prs_db.tcam_neg_proto_list, list_node)
  {
    if (neg_proto_node->proto == proto)
      return 1;
  }
  return 0;
}

int
pp2_cls_db_prs_match_list_check (struct pp2_inst *inst, u32 index)
{
  struct prs_log_port_tcam_node *tcam_match_node;

  LIST_FOR_EACH_OBJECT (tcam_match_node, struct prs_log_port_tcam_node,
			&inst->cls_db->prs_db.tcam_match_list, list_node)
  {
    if (tcam_match_node->idx == index)
      return 1;
  }

  return 0;
}

int
pp2_cls_db_prs_match_list_remove_idx (struct pp2_inst *inst, u32 index)
{
  struct prs_log_port_tcam_node *tcam_match_node;

  LIST_FOR_EACH_OBJECT (tcam_match_node, struct prs_log_port_tcam_node,
			&inst->cls_db->prs_db.tcam_match_list, list_node)
  {
    if (tcam_match_node->idx == index)
      {
	list_del (&tcam_match_node->list_node);
	if (tcam_match_node)
	  clib_mem_free (tcam_match_node);
	pr_debug ("removed %d from table\n", index);
	return 1;
      }
  }
  return 0;
}

int
pp2_cls_db_prs_match_list_add (struct pp2_inst *inst, u32 idx, int log_port)
{
  struct prs_log_port_tcam_node *match_node;

  match_node = clib_mem_alloc_or_null (sizeof (*match_node));
  if (!match_node)
    return -ENOMEM;

  match_node->idx = idx;
  match_node->log_port = log_port;

  /* add table to db */
  list_add_to_tail (&match_node->list_node, &inst->cls_db->prs_db.tcam_match_list);

  return 0;
}

int
pp2_cls_db_mng_tbl_add (struct pp2_cls_tbl **tbl)
{
  struct pp2_cls_tbl_node *tbl_node;

  tbl_node = clib_mem_alloc_or_null (sizeof (*tbl_node));
  if (!tbl_node)
    return -ENOMEM;

  /* Initialize table's rules db */
  INIT_LIST (&tbl_node->pp2_cls_tbl_rule_head);

  /* add table to db */
  list_add_to_tail (&tbl_node->list_node, &mng_db->pp2_cls_tbl_head);

  *tbl = &tbl_node->tbl;
  return 0;
}

static const char *
lookup_enum_str (struct pp2_cls_enum_str_t enum_str[], int enum_num, int enum_value)
{
  int idx;

  for (idx = 0; idx < enum_num; idx++)
    {
      if (enum_value == enum_str[idx].enum_value)
	return enum_str[idx].enum_str;
    }
  return g_unknown_str;
}

int
pp2_cls_udf_field_add (struct pp2_inst *inst, u8 udf_num, u8 offset, u8 size)
{
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);
  u32 reg, val;
  u32 size_bits, offset_bits;

  /* relative offset and field size resolution is in bits */
  size_bits = size * 8;
  offset_bits = offset * 8;

  /* Parameters check */
  if (mv_pp2x_range_validate (offset_bits, 0, MVPP2_CLS_UDF_REL_OFFSET_MAX))
    return -EINVAL;

  if (mv_pp2x_range_validate (size_bits, 1, MVPP2_CLS_UDF_SIZE_MAX))
    return -EINVAL;

  /* Check for available UDF numbers */
  if (!(udf_num == MVPP2_CLS_UDF_OFFSET_3 || udf_num == MVPP2_CLS_UDF_OFFSET_5 ||
	udf_num == MVPP2_CLS_UDF_OFFSET_6))
    return -EINVAL;

  reg = MVPP2_CLS_UDF_REG (udf_num);
  val = ((udf_num << MVPP2_CLS_UDF_OFFSET_ID_OFFS) & MVPP2_CLS_UDF_OFFSET_ID_MASK) |
	((offset_bits << MVPP2_CLS_UDF_REL_OFFSET_OFFS) & MVPP2_CLS_UDF_REL_OFFSET_MASK) |
	((size_bits << MVPP2_CLS_UDF_SIZE_OFFS) & MVPP2_CLS_UDF_SIZE_MASK);

  pp2_reg_write (cpu_slot, reg, val);

  return 0;
}

int
pp2_cls_lkp_dcod_set_and_disable (struct pp2_inst *inst, u16 fl_log_id)
{
  struct pp2_cls_lkp_dcod_entry_t dcod;
  struct pp2_db_cls_lkp_dcod_t lkp_dcod_db;
  int rc;

  rc = pp2_db_cls_lkp_dcod_get (inst, fl_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("failed to get lookup decode info for fl_log_id %d\n", fl_log_id);
      return rc;
    }
  if (lkp_dcod_db.enabled)
    {
      pp2_cls_lkp_dcod_disable (inst, fl_log_id);
      /* if it isn't enabled it means that we should init decoder setting */
    }
  else
    {
      /* way - always 0*/
      dcod.way = MVPP2_CLS_DEF_WAY;

      /* currently every lkp id have specific log id */
      dcod.luid_num = 1;

      /* Flow log ID - Set to be the same as luid_list[0] TODO Ehud*/
      dcod.flow_log_id = fl_log_id;
      dcod.luid_list[0].luid = fl_log_id;

      dcod.flow_len = MVPP2_CLS_DEF_FLOW_LEN;

      /* Default queue - TODO not implemented yet in API */
      dcod.cpu_q = MVPP2_CLS_DEF_RXQ;

      /* Configure decoder table*/
      rc = pp2_cls_lkp_dcod_set (inst, &dcod);
      if (rc)
	{
	  pr_err ("failed to add in decoder table\n");
	  return rc;
	}
    }

  return 0;
}

static int
pp2_cls_mng_get_lkpid_for_flow_type (u16 *select_logical_id, u32 ipv4_flag, u32 ipv6_flag,
				     u32 tcp_flag, u32 udp_flag, u32 l4_flag)
{
  int num_lkpid = 0;

  /* find relevant lkpid for this flow */
  if (!ipv4_flag && !ipv6_flag && !l4_flag && !tcp_flag && !udp_flag)
    {
      num_lkpid += pp2_cls_add_non_ip_logical_id (&select_logical_id[num_lkpid]);
      num_lkpid += pp2_cls_add_ip4_logical_id (&select_logical_id[num_lkpid]);
      num_lkpid += pp2_cls_add_ip4_tcp_logical_id (&select_logical_id[num_lkpid]);
      num_lkpid += pp2_cls_add_ip4_udp_logical_id (&select_logical_id[num_lkpid]);
      num_lkpid += pp2_cls_add_ip6_logical_id (&select_logical_id[num_lkpid]);
      num_lkpid += pp2_cls_add_ip6_tcp_logical_id (&select_logical_id[num_lkpid]);
      num_lkpid += pp2_cls_add_ip6_udp_logical_id (&select_logical_id[num_lkpid]);
    }
  else if (ipv4_flag)
    {
      if (!tcp_flag && !udp_flag && !l4_flag)
	{
	  num_lkpid += pp2_cls_add_ip4_logical_id (&select_logical_id[num_lkpid]);
	  num_lkpid += pp2_cls_add_ip4_tcp_logical_id (&select_logical_id[num_lkpid]);
	  num_lkpid += pp2_cls_add_ip4_udp_logical_id (&select_logical_id[num_lkpid]);
	}
      else if (l4_flag && !tcp_flag && !udp_flag)
	{
	  num_lkpid += pp2_cls_add_ip4_tcp_logical_id (&select_logical_id[num_lkpid]);
	  num_lkpid += pp2_cls_add_ip4_udp_logical_id (&select_logical_id[num_lkpid]);
	}
      else if (tcp_flag)
	{
	  num_lkpid += pp2_cls_add_ip4_tcp_logical_id (&select_logical_id[num_lkpid]);
	}
      else if (udp_flag)
	{
	  num_lkpid += pp2_cls_add_ip4_udp_logical_id (&select_logical_id[num_lkpid]);
	}
      else
	{
	  pr_err ("%s(%d), failed to calculate lkpid\n", __func__, __LINE__);
	  return -EINVAL;
	}
    }
  else if (ipv6_flag)
    {
      if (!tcp_flag && !udp_flag && !l4_flag)
	{
	  num_lkpid += pp2_cls_add_ip6_logical_id (&select_logical_id[num_lkpid]);
	  num_lkpid += pp2_cls_add_ip6_tcp_logical_id (&select_logical_id[num_lkpid]);
	  num_lkpid += pp2_cls_add_ip6_udp_logical_id (&select_logical_id[num_lkpid]);
	}
      else if (l4_flag && !tcp_flag && !udp_flag)
	{
	  num_lkpid += pp2_cls_add_ip6_tcp_logical_id (&select_logical_id[num_lkpid]);
	  num_lkpid += pp2_cls_add_ip6_udp_logical_id (&select_logical_id[num_lkpid]);
	}
      else if (tcp_flag)
	{
	  num_lkpid += pp2_cls_add_ip6_tcp_logical_id (&select_logical_id[num_lkpid]);
	}
      else if (udp_flag)
	{
	  num_lkpid += pp2_cls_add_ip6_udp_logical_id (&select_logical_id[num_lkpid]);
	}
      else
	{
	  pr_err ("%s(%d), failed to calculate lkpid\n", __func__, __LINE__);
	  return -EINVAL;
	}
    }
  else if (l4_flag)
    {
      num_lkpid += pp2_cls_add_ip4_tcp_logical_id (&select_logical_id[num_lkpid]);
      num_lkpid += pp2_cls_add_ip4_udp_logical_id (&select_logical_id[num_lkpid]);
      num_lkpid += pp2_cls_add_ip6_tcp_logical_id (&select_logical_id[num_lkpid]);
      num_lkpid += pp2_cls_add_ip6_udp_logical_id (&select_logical_id[num_lkpid]);
    }
  else if (tcp_flag)
    {
      num_lkpid += pp2_cls_add_ip4_tcp_logical_id (&select_logical_id[num_lkpid]);
      num_lkpid += pp2_cls_add_ip6_tcp_logical_id (&select_logical_id[num_lkpid]);
    }
  else if (udp_flag)
    {
      num_lkpid += pp2_cls_add_ip4_udp_logical_id (&select_logical_id[num_lkpid]);
      num_lkpid += pp2_cls_add_ip6_udp_logical_id (&select_logical_id[num_lkpid]);
    }
  else
    {
      pr_err ("%s(%d), failed to calculate lkpid\n", __func__, __LINE__);
      return -EINVAL;
    }

  return num_lkpid;
}

static int
pp2_cls_mng_get_lkpid_for_rss (int engine, u16 *select_logical_id, int ipv4_flag, int ipv6_flag)
{
  int lkpid, lkpid_attr;
  int num_lkpid = 0;

  for (lkpid = MVPP2_PRS_FL_START; lkpid < MVPP2_PRS_FL_LAST; lkpid++)
    {
      /* Get lookup id attribute */
      lkpid_attr = mv_pp2x_prs_flow_id_attr_get (lkpid);

      if (!((lkpid_attr & MVPP2_PRS_FL_ATTR_IP4_BIT && ipv4_flag) ||
	    (lkpid_attr & MVPP2_PRS_FL_ATTR_IP6_BIT && ipv6_flag)))
	continue;

      /* For frag packets or non-TCP & UDP, rss must be based on 2T */
      if ((engine == MVPP2_CLS_ENGINE_C3HA) &&
	  ((lkpid_attr & MVPP2_PRS_FL_ATTR_FRAG_BIT) ||
	   !(lkpid_attr & (MVPP2_PRS_FL_ATTR_TCP_BIT | MVPP2_PRS_FL_ATTR_UDP_BIT))))
	{
	  select_logical_id[num_lkpid++] = lkpid;
	  continue;
	}

      if (!(lkpid_attr & MVPP2_PRS_FL_ATTR_FRAG_BIT))
	{
	  if (lkpid_attr & (MVPP2_PRS_FL_ATTR_TCP_BIT | MVPP2_PRS_FL_ATTR_UDP_BIT))
	    {
	      select_logical_id[num_lkpid++] = lkpid;
	      continue;
	    }
	  else if ((engine == MVPP2_CLS_ENGINE_C3HB) && (lkpid_attr & MVPP2_PRS_FL_ATTR_TCP_BIT))
	    {
	      select_logical_id[num_lkpid++] = lkpid;
	      continue;
	    }
	}
    }

  return num_lkpid;
}

static int
pp2_cls_mng_get_lkpid_for_lkp_type (int lkp_type, u16 *select_logical_id)
{
  int lkpid, lkpid_attr;
  int num_lkpid = 0;

  for (lkpid = MVPP2_PRS_FL_START; lkpid < MVPP2_PRS_FL_LAST; lkpid++)
    {
      /* Get lookup id attribute */
      lkpid_attr = mv_pp2x_prs_flow_id_attr_get (lkpid);
      /* For untagged IP packets, only need default
       * rule and dscp rule
       */
      if ((lkpid_attr & (MVPP2_PRS_FL_ATTR_IP4_BIT | MVPP2_PRS_FL_ATTR_IP6_BIT)) &&
	  (!(lkpid_attr & MVPP2_PRS_FL_ATTR_VLAN_BIT)))
	{
	  if (lkp_type == MVPP2_CLS_LKP_DEFAULT || lkp_type == MVPP2_CLS_LKP_DSCP_PRI ||
	      lkp_type == MVPP2_CLS_LKP_MUSDK_LOG_PORT_DEF ||
	      lkp_type == MVPP2_CLS_LKP_MUSDK_DSCP_PRI)
	    {
	      select_logical_id[num_lkpid++] = lkpid;
	      continue;
	    }
	}

      /* For tagged IP packets, only need vlan rule and dscp rule */
      if ((lkpid_attr & (MVPP2_PRS_FL_ATTR_IP4_BIT | MVPP2_PRS_FL_ATTR_IP6_BIT)) &&
	  (lkpid_attr & MVPP2_PRS_FL_ATTR_VLAN_BIT))
	{
	  if (lkp_type == MVPP2_CLS_LKP_VLAN_PRI || lkp_type == MVPP2_CLS_LKP_DSCP_PRI ||
	      lkp_type == MVPP2_CLS_LKP_MUSDK_VLAN_PRI || lkp_type == MVPP2_CLS_LKP_MUSDK_DSCP_PRI)
	    {
	      select_logical_id[num_lkpid++] = lkpid;
	      continue;
	    }
	}

      /* For non-IP packets, only need default rule if untagged,
       * vlan rule also needed if tagged
       */
      if (!(lkpid_attr & (MVPP2_PRS_FL_ATTR_IP4_BIT | MVPP2_PRS_FL_ATTR_IP6_BIT)))
	{
	  /* Default rule */
	  if (lkp_type == MVPP2_CLS_LKP_DEFAULT || lkp_type == MVPP2_CLS_LKP_MUSDK_LOG_PORT_DEF)
	    {
	      select_logical_id[num_lkpid++] = lkpid;
	      continue;
	    }
	  /* VLAN rule if tagged */
	  if (lkpid_attr & MVPP2_PRS_FL_ATTR_VLAN_BIT)
	    {
	      if (lkp_type == MVPP2_CLS_LKP_VLAN_PRI || lkp_type == MVPP2_CLS_LKP_MUSDK_VLAN_PRI)
		{
		  select_logical_id[num_lkpid++] = lkpid;
		  continue;
		}
	    }
	}
    }

  return num_lkpid;
}

static char *
mv_strtok (char *src, const char *pattern)
{
  static char *nxt_tok;
  char *ret_val = NULL;

  if (!src)
    src = nxt_tok;

  while (*src)
    {
      const char *pp = pattern;

      while (*pp)
	{
	  if (*pp == *src)
	    break;

	  pp++;
	}
      if (!*pp)
	{
	  if (!ret_val)
	    ret_val = src;
	  else if (!src[-1])
	    break;
	}
      else
	*src = '\0';
      src++;
    }

  nxt_tok = src;

  return ret_val;
}

int
pp2_cls_db_prs_match_list_log_port_check (struct pp2_inst *inst)
{
  struct prs_log_port_tcam_node *tcam_match_node;

  LIST_FOR_EACH_OBJECT (tcam_match_node, struct prs_log_port_tcam_node,
			&inst->cls_db->prs_db.tcam_match_list, list_node)
  {
    if (tcam_match_node->log_port == 1)
      return 1;
  }

  return 0;
}

int
pp2_cls_lkp_dcod_disable (struct pp2_inst *inst, u16 fl_log_id)
{
  struct mv_pp2x_cls_lookup_entry le;
  int rc;
  u16 luid;
  int way = 0; /* currently, always setting way to '0' */
  struct pp2_db_cls_lkp_dcod_t lkp_dcod_db;
  uintptr_t cpu_slot = pp2_default_cpu_slot (inst);

  /* get the lookup DB for this logical flow ID */
  rc = pp2_db_cls_lkp_dcod_get (inst, fl_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("failed to get lookup decode info for fl_log_id %d\n", fl_log_id);
      return rc;
    }

  if (!lkp_dcod_db.enabled)
    {
      /* entry disabled for this log_flow id */
      pr_warn ("skipping disable of fl_log_id=%d, already disabled\n", fl_log_id);
      return 0;
    }

  /* iterate over all LUIDs */
  for (luid = 0; luid < lkp_dcod_db.luid_num; luid++)
    {
      /* Exclude MAC default LookupID by LSP */
      if (LUID_IS_LSP_RESERVED (lkp_dcod_db.luid_list[luid].luid))
	continue;

      /* updated the HW */
      mv_pp2x_cls_sw_lkp_clear (&le);

      rc = mv_pp2x_cls_hw_lkp_read (cpu_slot, luid, way, &le);
      if (rc)
	return rc;

      rc = mv_pp2x_cls_sw_lkp_en_set (&le, 0);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  return rc;
	}

      le.way = lkp_dcod_db.way;
      le.lkpid = lkp_dcod_db.luid_list[luid].luid;
      rc = mv_pp2x_cls_hw_lkp_write (cpu_slot, &le);
      if (rc)
	{
	  pr_err ("recvd ret_code(%d)\n", rc);
	  return rc;
	}

      pr_debug ("fl_log_id[%2d] luid_nr[%2d] luid[%2d]\n", fl_log_id, luid,
		lkp_dcod_db.luid_list[luid].luid);
    }

  /* update lkp_dcod DB */
  lkp_dcod_db.enabled = false;
  rc = pp2_db_cls_lkp_dcod_set (inst, fl_log_id, &lkp_dcod_db);
  if (rc)
    {
      pr_err ("recvd ret_code(%d)\n", rc);
      return rc;
    }

  return 0;
}

static int
pp2_cls_add_non_ip_logical_id (u16 *select_logical_id)
{
  int i = 0;

  select_logical_id[i++] = MVPP2_PRS_FL_NON_IP_UNTAG;
  select_logical_id[i++] = MVPP2_PRS_FL_NON_IP_TAG;

  return i;
}

static int
pp2_cls_add_ip4_logical_id (u16 *select_logical_id)
{
  int i = 0;

  select_logical_id[i++] = MVPP2_PRS_FL_IP4_UNTAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP4_TAG;

  return i;
}

static int
pp2_cls_add_ip4_tcp_logical_id (u16 *select_logical_id)
{
  int i = 0;

  select_logical_id[i++] = MVPP2_PRS_FL_IP4_TCP_NF_UNTAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP4_TCP_NF_TAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP4_TCP_FRAG_UNTAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP4_TCP_FRAG_TAG;

  return i;
}

static int
pp2_cls_add_ip4_udp_logical_id (u16 *select_logical_id)
{
  int i = 0;

  select_logical_id[i++] = MVPP2_PRS_FL_IP4_UDP_NF_TAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP4_UDP_NF_UNTAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP4_UDP_FRAG_UNTAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP4_UDP_FRAG_TAG;

  return i;
}

static int
pp2_cls_add_ip6_logical_id (u16 *select_logical_id)
{
  int i = 0;

  select_logical_id[i++] = MVPP2_PRS_FL_IP6_UNTAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP6_TAG;

  return i;
}

static int
pp2_cls_add_ip6_tcp_logical_id (u16 *select_logical_id)
{
  int i = 0;

  select_logical_id[i++] = MVPP2_PRS_FL_IP6_TCP_NF_UNTAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP6_TCP_NF_TAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP6_TCP_FRAG_UNTAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP6_TCP_FRAG_TAG;

  return i;
}

static int
pp2_cls_add_ip6_udp_logical_id (u16 *select_logical_id)
{
  int i = 0;

  select_logical_id[i++] = MVPP2_PRS_FL_IP6_UDP_NF_UNTAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP6_UDP_NF_TAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP6_UDP_FRAG_UNTAG;
  select_logical_id[i++] = MVPP2_PRS_FL_IP6_UDP_FRAG_TAG;

  return i;
}

static int
pp2_cls_db_edrop_ref_cnt_update (struct pp2_inst *inst, u8 edrop_id,
				 enum pp2_cls_edrop_ref_cnt_action_t cnt_action)
{
  struct pp2_cls_db_edrop_entry_t *edrop_entry = NULL;

  if (mv_pp2x_range_validate (edrop_id, 0, MVPP2_EDROP_MAX - 1))
    {
      pr_err ("invalid early-drop ID %d, out of range[%d, %d]\n", edrop_id, 0, MVPP2_EDROP_MAX - 1);
      return -EINVAL;
    }

  if (mv_pp2x_range_validate (cnt_action, 0, MVPP2_EDROP_REF_CNT_CLEAR))
    {
      pr_err ("invalid reference counter action %d, out of range[%d, %d]\n", cnt_action, 0,
	      MVPP2_EDROP_REF_CNT_CLEAR);
      return -EINVAL;
    }

  /* check the early-drop state */
  edrop_entry = &inst->cls_db->edrop_db.edrop_arr[edrop_id];
  if (((cnt_action == MVPP2_EDROP_REF_CNT_INC) || (cnt_action == MVPP2_EDROP_REF_CNT_DEC) ||
       (cnt_action == MVPP2_EDROP_REF_CNT_CLEAR)) &&
      (edrop_entry->valid == MVPP2_EDROP_ENTRY_INVALID_STATE))
    {
      pr_err ("early-drop ID(%d) is invalid\n", edrop_id);
      return -EINVAL;
    }

  /* action to reference counter */
  switch (cnt_action)
    {
    case MVPP2_PLCR_REF_CNT_INC:
      edrop_entry->ref_cnt++;
      break;
    case MVPP2_PLCR_REF_CNT_DEC:
      edrop_entry->ref_cnt--;
      break;
    case MVPP2_PLCR_REF_CNT_CLEAR:
      edrop_entry->ref_cnt = 0;
      break;
    default:
      break;
    }

  return 0;
}
