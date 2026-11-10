/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

/* VF BAR 0: ring bundles (banks), config and base registers at a per generation offset */
#define QAT_RING_CSR_HEAD(r)	    (0x0c0 + (r) * 4)
#define QAT_RING_CSR_TAIL(r)	    (0x100 + (r) * 4)
#define QAT_RING_CSR_SRV_ARB_EN	    0x19c
#define QAT_RING_CSR_CONFIG(r)	    (0x000 + (r) * 4)
#define QAT_RING_CSR_BASE_LO(r)	    (0x040 + (r) * 4)
#define QAT_RING_CSR_BASE_HI(r)	    (0x080 + (r) * 4)
#define QAT_RING_EMPTY_SIG	    0x7f7f7f7f
#define QAT_RING_EMPTY_SIG_BYTE	    0x7f
#define QAT_RING_MIN_SIZE_BYTES	    128
#define QAT_RING_MAX_SIZE_BYTES	    (4 << 20)
#define QAT_RING_NEAR_WATERMARK_512 8

/* gen4: a bank per ring pair */
#define QAT_GEN4_VF_N_BANKS 4
#define QAT_GEN4_RING_TX    0
#define QAT_GEN4_RING_RX    1

/* gen2: one bank of 16 rings, response ring is request ring + 8 */
#define QAT_GEN2_RX_RING_OFFSET 8
#define QAT_GEN2_SYM_TX_RING0	2
#define QAT_GEN2_N_SYM_RINGS	2

/* VF BAR 2: PF/VF mailbox */
#define QAT_GEN4_VF_PF2VM 0x1008
#define QAT_GEN4_VF_VM2PF 0x100c

/* gen2 PF->VF message in bits 0-15, VF->PF in bits 16-31 of one register; the sender marks the
 * other half in use */
#define QAT_GEN2_VF_PFVF	      0x200
#define QAT_GEN2_PFVF_VF2PF_SHIFT     16
#define QAT_GEN2_PFVF_IN_USE	      0x6ac2
#define QAT_GEN2_PFVF_IN_USE_MASK     0xfffe
#define QAT_GEN2_PFVF_COMPAT_FAST_ACK 3

#define QAT_SVC_UNUSED	    0
#define QAT_SVC_CRYPTO	    1
#define QAT_SVC_COMPRESSION 2
#define QAT_SVC_SYM	    3
#define QAT_SVC_ASYM	    4

typedef union
{
  struct
  {
    u16 bank0 : 3;
    u16 bank1 : 3;
    u16 bank2 : 3;
    u16 bank3 : 3;
    u16 _reserved_12_15 : 4;
  };
  u16 as_u16;
} qat_ring_to_svc_map_t;

static_always_inline u8
qat_ring_to_svc_map_get (qat_ring_to_svc_map_t m, u8 bank)
{
  switch (bank)
    {
    case 0:
      return m.bank0;
    case 1:
      return m.bank1;
    case 2:
      return m.bank2;
    case 3:
      return m.bank3;
    }
  return QAT_SVC_UNUSED;
}

#define QAT_TX_MSG_SIZE 128
#define QAT_RX_MSG_SIZE 32

typedef union
{
  struct
  {
    u32 ring_size : 5;
    u32 near_empty_wm : 5;
    u32 near_full_wm : 5;
    u32 _reserved_15_31 : 17;
  };
  u32 as_u32;
} qat_ring_config_t;

/* PF/VF messages */
#define QAT_PFVF_COMPAT_VERSION 4

#define foreach_qat_pf2vf_msgtype                                                                  \
  _ (0x01, RESTARTING, "restarting")                                                               \
  _ (0x02, VERSION_RESP, "version-resp")                                                           \
  _ (0x03, BLKMSG_RESP, "blkmsg-resp")                                                             \
  _ (0x04, FATAL_ERROR, "fatal-error")                                                             \
  _ (0x10, RP_RESET_RESP, "rp-reset-resp")

typedef enum
{
#define _(v, n, s) QAT_PF2VF_MSGTYPE_##n = v,
  foreach_qat_pf2vf_msgtype
#undef _
} qat_pf2vf_msgtype_t;

#define foreach_qat_vf2pf_msgtype                                                                  \
  _ (0x03, INIT, "init")                                                                           \
  _ (0x04, SHUTDOWN, "shutdown")                                                                   \
  _ (0x05, VERSION_REQ, "version-req")                                                             \
  _ (0x06, COMPAT_VER_REQ, "compat-version-req")                                                   \
  _ (0x07, LARGE_BLOCK_REQ, "large-block-req")                                                     \
  _ (0x08, MEDIUM_BLOCK_REQ, "medium-block-req")                                                   \
  _ (0x09, SMALL_BLOCK_REQ, "small-block-req")                                                     \
  _ (0x10, RP_RESET, "rp-reset")

typedef enum
{
#define _(v, n, s) QAT_VF2PF_MSGTYPE_##n = v,
  foreach_qat_vf2pf_msgtype
#undef _
} qat_vf2pf_msgtype_t;

#define foreach_qat_pf2vf_compat                                                                   \
  _ (1, COMPATIBLE, "compatible")                                                                  \
  _ (2, INCOMPATIBLE, "incompatible")                                                              \
  _ (3, COMPAT_UNKNOWN, "unknown")

typedef enum
{
#define _(v, n, s) QAT_PF2VF_VF_##n = v,
  foreach_qat_pf2vf_compat
#undef _
} qat_pf2vf_compat_t;

typedef enum
{
  QAT_PF2VF_BLKMSG_RESP_TYPE_DATA = 0,
  QAT_PF2VF_BLKMSG_RESP_TYPE_CRC = 1,
  QAT_PF2VF_BLKMSG_RESP_TYPE_ERROR = 2,
} qat_pf2vf_blkmsg_resp_type_t;

#define foreach_qat_blkmsg_type                                                                    \
  _ (2, CAP_SUMMARY, "capabilities")                                                               \
  _ (3, RING_SVC_MAP, "ring-to-service-map")

typedef enum
{
#define _(v, n, s) QAT_BLKMSG_REQ_##n = v,
  foreach_qat_blkmsg_type
#undef _
} qat_blkmsg_type_t;
#define QAT_BLKMSG_HDR_SIZE	  2
#define QAT_BLKMSG_SMALL_MAX_BYTE 31
#define QAT_BLKMSG_CRC8_POLY	  0x97

#define QAT_BLKMSG_CAPS_V2_LEN 8
#define QAT_BLKMSG_CAPS_V3_LEN 12

typedef struct
{
  u8 version;
  u8 len;
  u32 ext_dc_caps;
  u32 capabilities;
  u32 frequency;
} __clib_packed qat_blkmsg_caps_t;

#define foreach_qat_capability                                                                     \
  _ (0, SYM, "sym")                                                                                \
  _ (1, ASYM, "asym")                                                                              \
  _ (2, CIPHER, "cipher")                                                                          \
  _ (3, AUTH, "auth")                                                                              \
  _ (5, COMPRESSION, "compression")                                                                \
  _ (7, RAND, "rand")                                                                              \
  _ (8, ZUC, "zuc")                                                                                \
  _ (9, SHA3, "sha3")                                                                              \
  _ (10, KPT, "kpt")                                                                               \
  _ (11, RL, "rate-limit")                                                                         \
  _ (12, HKDF, "hkdf")                                                                             \
  _ (13, ECEDMONT, "ecedmont")                                                                     \
  _ (14, EXT_ALGCHAIN, "ext-algchain")                                                             \
  _ (15, SHA3_EXT, "sha3-ext")                                                                     \
  _ (16, AESGCM_SPC, "aes-gcm-spc")                                                                \
  _ (17, CHACHA_POLY, "chacha-poly")                                                               \
  _ (18, SM2, "sm2")                                                                               \
  _ (19, SM3, "sm3")                                                                               \
  _ (20, SM4, "sm4")                                                                               \
  _ (21, INLINE, "inline")                                                                         \
  _ (22, CNV_INTEGRITY, "cnv-integrity")                                                           \
  _ (23, CNV_INTEGRITY64, "cnv-integrity64")                                                       \
  _ (24, LZ4, "lz4")                                                                               \
  _ (25, LZ4S, "lz4s")                                                                             \
  _ (26, AES_V2, "aes-v2")                                                                         \
  _ (27, KPT2, "kpt2")

typedef enum
{
#define _(b, n, s) QAT_CAP_##n = 1 << (b),
  foreach_qat_capability
#undef _
} qat_capability_t;

typedef union
{
  struct
  {
    u32 irq : 1;
    u32 origin_system : 1;
    u32 type : 6;
    u32 data : 24;
  };
  u32 as_u32;
} qat_pfvf_msg_t;

typedef union
{
  struct
  {
    u16 irq : 1;
    u16 origin_system : 1;
    u16 type : 4;
    u16 data : 10;
  };
  u16 as_u16;
} qat_gen2_pfvf_msg_t;

typedef union
{
  struct
  {
    u32 type : 4;
    u32 byte : 5;
    u32 is_crc : 1;
    u32 _reserved_10_23 : 14;
  };
  u32 as_u32;
} qat_vf2pf_small_blkmsg_req_t;

typedef union
{
  struct
  {
    u32 type : 2;
    u32 data : 8;
    u32 _reserved_10_23 : 14;
  };
  u32 as_u32;
} qat_pf2vf_blkmsg_resp_t;

typedef union
{
  struct
  {
    u32 version : 8;
    u32 result : 2;
    u32 _reserved_10_23 : 14;
  };
  u32 as_u32;
} qat_pf2vf_version_resp_t;

/* firmware request */
#define QAT_FW_COMN_REQ_NULL	  0
#define QAT_FW_COMN_REQ_CPM_FW_LA 4
#define QAT_FW_NULL_REQ_SERV_ID	  1
#define QAT_FW_HDR_FLAG_VALID	  1

typedef enum
{
  QAT_FW_LA_CMD_CIPHER = 0,
  QAT_FW_LA_CMD_AUTH = 1,
  QAT_FW_LA_CMD_CIPHER_HASH = 2,
  QAT_FW_LA_CMD_HASH_CIPHER = 3,
} qat_fw_la_cmd_t;

typedef enum
{
  QAT_FW_SLICE_NULL = 0,
  QAT_FW_SLICE_CIPHER = 1,
  QAT_FW_SLICE_AUTH = 2,
  QAT_FW_SLICE_DRAM_RD = 3,
  QAT_FW_SLICE_DRAM_WR = 4,
} qat_fw_slice_t;

#define QAT_FW_LA_SLICE_TYPE_LEGACY 0
#define QAT_FW_LA_SLICE_TYPE_UCS    1

typedef union
{
  struct
  {
    u16 partial : 2;
    u16 ciph_iv_16byte_data : 1;
    u16 ciph_auth_cfg_offset : 1;
    u16 update_state : 1;
    u16 ret_auth_res : 1;
    u16 cmp_auth_res : 1;
    u16 proto : 3;
    u16 digest_in_buffer : 1;
    u16 gcm_iv_len_12_octets : 1;
    u16 zuc_proto : 1;
    u16 single_pass : 1;
    u16 slice_type : 2;
  };
  u16 as_u16;
} qat_fw_la_flags_t;

typedef struct
{
  u8 _reserved0;
  u8 service_cmd_id;
  u8 service_type;
  u8 _reserved_flags : 7;
  u8 valid : 1;
  qat_fw_la_flags_t la_flags;
  u8 ptr_type_sgl : 1;
  u8 cd_fld_type_16byte_data : 1;
  u8 _reserved_req_flags : 6;
  u8 ext_flags;
} qat_fw_req_hdr_t;

STATIC_ASSERT_SIZEOF (qat_fw_req_hdr_t, 8);

typedef struct
{
  u64 content_desc_addr;
  u16 _reserved0;
  u8 content_desc_params_sz;
  u8 _reserved1;
  u32 _reserved2;
} qat_fw_req_cd_pars_t;

typedef struct
{
  u64 opaque;
  u64 src_data_addr;
  u64 dst_data_addr;
  u32 src_length;
  u32 dst_length;
} qat_fw_req_mid_t;

typedef struct
{
  u32 cipher_offset;
  u32 cipher_length;
  u8 cipher_iv[16];
  u32 auth_off;
  u32 auth_len;
  u64 auth_prefix_addr;
  u64 auth_res_addr;
  u8 inner_prefix_sz;
  u8 _reserved0;
  u8 hash_state_sz;
  u8 auth_res_sz;
} __clib_packed qat_fw_la_cipher_auth_params_t;

/* single pass AEAD on the UCS slice */
typedef struct
{
  u32 cipher_offset;
  u32 cipher_length;
  u8 cipher_iv[16];
  u32 spc_aad_offset;
  u32 spc_aad_sz;
  u64 spc_aad_addr;
  u64 spc_auth_res_addr;
  u8 _reserved0[3];
  u8 spc_auth_res_sz;
} __clib_packed qat_fw_la_ucs_params_t;

STATIC_ASSERT_SIZEOF (qat_fw_la_cipher_auth_params_t, 52);
STATIC_ASSERT_SIZEOF (qat_fw_la_ucs_params_t, 52);

typedef struct
{
  u8 cipher_state_sz;
  u8 cipher_key_sz;
  u8 cipher_cfg_offset;
  u8 cipher_curr_id : 4;
  u8 cipher_next_id : 4;
  u8 cipher_padding_sz;
  u8 hash_flags;
  u8 hash_cfg_offset;
  u8 auth_curr_id : 4;
  u8 auth_next_id : 4;
  u8 _reserved0;
  u8 outer_prefix_sz;
  u8 final_sz;
  u8 inner_res_sz;
  u8 _reserved1;
  u8 inner_state1_sz;
  u8 inner_state2_offset;
  u8 inner_state2_sz;
  u8 outer_config_offset;
  u8 outer_state1_sz;
  u8 outer_res_sz;
  u8 outer_prefix_offset;
} qat_fw_cd_ctrl_t;

STATIC_ASSERT_SIZEOF (qat_fw_cd_ctrl_t, 20);

typedef struct
{
  qat_fw_req_hdr_t hdr;
  qat_fw_req_cd_pars_t cd_pars;
  qat_fw_req_mid_t mid;
  union
  {
    qat_fw_la_cipher_auth_params_t cipher_auth;
    qat_fw_la_ucs_params_t ucs;
  };
  qat_fw_cd_ctrl_t cd_ctrl;
} qat_fw_la_req_t;

STATIC_ASSERT_SIZEOF (qat_fw_la_req_t, QAT_TX_MSG_SIZE);

typedef union
{
  struct
  {
    u8 xlt_wa_applied : 1;
    u8 invalid_param : 1;
    u8 unsupported_request : 1;
    u8 cmp_end_of_last_blk : 1;
    u8 xlat_error : 1;
    u8 cmp_error : 1;
    u8 pke_error : 1;
    u8 crypto_error : 1;
  };
  u8 as_u8;
} qat_fw_resp_status_t;

typedef struct
{
  u8 _reserved0;
  u8 service_id;
  u8 response_type;
  u8 hdr_flags;
  u8 xlat_err_code;
  u8 cmp_err_code;
  qat_fw_resp_status_t status;
  u8 cmd_id;
  u64 opaque;
  u32 _reserved1[4];
} qat_fw_resp_t;

STATIC_ASSERT_SIZEOF (qat_fw_resp_t, QAT_RX_MSG_SIZE);

typedef struct
{
  u32 len;
  u32 _reserved;
  u64 addr;
} qat_flat_buf_t;

#define QAT_SGL_MAX_BUFS 16

typedef struct
{
  u64 _reserved;
  u32 num_bufs;
  u32 num_mapped_bufs;
  qat_flat_buf_t bufs[QAT_SGL_MAX_BUFS];
} qat_sgl_t;

/* content descriptor: hardware slice configuration */
typedef enum
{
  QAT_HW_CIPHER_ALGO_NULL = 0,
  QAT_HW_CIPHER_ALGO_DES = 1,
  QAT_HW_CIPHER_ALGO_3DES = 2,
  QAT_HW_CIPHER_ALGO_AES128 = 3,
  QAT_HW_CIPHER_ALGO_AES192 = 4,
  QAT_HW_CIPHER_ALGO_AES256 = 5,
  QAT_HW_CIPHER_ALGO_CHACHA20_POLY1305 = 11,
} __clib_packed qat_hw_cipher_algo_t;

typedef enum
{
  QAT_HW_CIPHER_ECB_MODE = 0,
  QAT_HW_CIPHER_CBC_MODE = 1,
  QAT_HW_CIPHER_CTR_MODE = 2,
  QAT_HW_CIPHER_AEAD_MODE = 4,
} __clib_packed qat_hw_cipher_mode_t;

typedef enum
{
  QAT_HW_AUTH_ALGO_NULL = 0,
  QAT_HW_AUTH_ALGO_SHA1 = 1,
  QAT_HW_AUTH_ALGO_MD5 = 2,
  QAT_HW_AUTH_ALGO_SHA224 = 3,
  QAT_HW_AUTH_ALGO_SHA256 = 4,
  QAT_HW_AUTH_ALGO_SHA384 = 5,
  QAT_HW_AUTH_ALGO_SHA512 = 6,
} __clib_packed qat_hw_auth_algo_t;

#define QAT_HW_AUTH_MODE1 1

typedef union
{
  struct
  {
    u32 algo : 4;
    u32 mode : 4;
    u32 decrypt : 1;
    u32 key_convert : 1;
    u32 aead_hash_cmp_len : 5;
    u32 _reserved_15_31 : 17;
  };
  u32 as_u32;
} qat_hw_cipher_config_t;

/* second config word of the UCS slice */
typedef union
{
  struct
  {
    u32 _reserved_0_15 : 16;
    u32 aad_size_upper : 6;
    u32 _reserved_22_23 : 2;
    u32 aad_size_lower : 8;
  };
  u32 as_u32;
} qat_hw_ucs_cipher_config_upper_t;

typedef struct
{
  qat_hw_cipher_config_t config;
  u32 _reserved;
  u8 key[];
} qat_hw_cipher_blk_t;

typedef struct
{
  qat_hw_cipher_config_t config;
  qat_hw_ucs_cipher_config_upper_t config_upper;
  u32 _reserved[2];
  u8 key[];
} qat_hw_ucs_cipher_blk_t;

typedef union
{
  struct
  {
    u32 algo : 4;
    u32 mode : 4;
    u32 cmp_len : 7;
    u32 _reserved_15_31 : 17;
  };
  u32 as_u32;
} qat_hw_auth_config_t;

typedef struct
{
  qat_hw_auth_config_t config;
  u32 _reserved0;
  u32 counter_be;
  u32 _reserved1;
  u8 state[];
} qat_hw_auth_blk_t;
