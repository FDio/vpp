/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_ikev2_priv_h__
#define __included_ikev2_priv_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <plugins/ikev2/ikev2.h>

#include <vppinfra/hash.h>
#include <vppinfra/elog.h>
#include <vppinfra/error.h>

#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define foreach_ikev2_log_level \
  _(0x00, LOG_NONE)             \
  _(0x01, LOG_ERROR)            \
  _(0x02, LOG_WARNING)          \
  _(0x03, LOG_INFO)             \
  _(0x04, LOG_DEBUG)            \
  _(0x05, LOG_DETAIL)           \


typedef enum ikev2_log_level_t_
{
#define _(n,f) IKEV2_##f = n,
  foreach_ikev2_log_level
#undef _
  IKEV2_LOG_MAX
} ikev2_log_level_t;

/* dataplane logging */
#define _ikev2_elog(_level, _msg)                                             \
do {                                                                          \
  ikev2_main_t *km = &ikev2_main;                                             \
  if (PREDICT_FALSE (km->log_level >= _level))                                \
    {                                                                         \
      ELOG_TYPE_DECLARE (e) =                                                 \
        {                                                                     \
          .format = "ikev2 " _msg,                                            \
          .format_args = "",                                                  \
        };                                                                    \
      ELOG_DATA (&vlib_global_main.elog_main, e);                             \
    }                                                                         \
} while (0)

#define ikev2_elog_sa_state(_format, _ispi)                                   \
do {                                                                          \
  ikev2_main_t *km = &ikev2_main;                                             \
  if (PREDICT_FALSE (km->log_level >= IKEV2_LOG_DEBUG))                       \
    {                                                                         \
      ELOG_TYPE_DECLARE (e) =                                                 \
        {                                                                     \
          .format = "ikev2: " _format,                                        \
          .format_args = "i8",                                                \
        };                                                                    \
      CLIB_PACKED(struct                                                      \
        {                                                                     \
          u64 ispi;                                                           \
        }) *ed;                                                               \
      ed = ELOG_DATA (&vlib_global_main.elog_main, e);                        \
      ed->ispi = _ispi;                                                       \
    }                                                                         \
} while (0)                                                                   \

#define ikev2_elog_exchange_internal(_format, _ispi, _rspi, _addr)            \
do {                                                                          \
  ikev2_main_t *km = &ikev2_main;                                             \
  if (PREDICT_FALSE (km->log_level >= IKEV2_LOG_DEBUG))                       \
    {                                                                         \
      ELOG_TYPE_DECLARE (e) =                                                 \
        {                                                                     \
          .format = "ikev2: " _format,                                        \
          .format_args = "i8i8i1i1i1i1",                                      \
        };                                                                    \
      CLIB_PACKED(struct                                                      \
        {                                                                     \
          u64 ispi;                                                           \
          u64 rspi;                                                           \
          u8 oct1;                                                            \
          u8 oct2;                                                            \
          u8 oct3;                                                            \
          u8 oct4;                                                            \
        }) *ed;                                                               \
      ed = ELOG_DATA (&vlib_global_main.elog_main, e);                        \
      ed->ispi = _ispi;                                                       \
      ed->rspi = _rspi;                                                       \
      ed->oct4 = (_addr) >> 24;                                               \
      ed->oct3 = (_addr) >> 16;                                               \
      ed->oct2 = (_addr) >> 8;                                                \
      ed->oct1 = (_addr);                                                     \
    }                                                                         \
} while (0)                                                                   \

#define IKE_ELOG_IP4_FMT "%d.%d.%d.%d"
#define IKE_ELOG_IP6_FMT "[v6]:%x%x:%x%x"

#define ikev2_elog_exchange(_fmt, _ispi, _rspi, _addr, _v4)                   \
do {                                                                          \
  if (_v4)                                                                    \
    ikev2_elog_exchange_internal (_fmt IKE_ELOG_IP4_FMT, _ispi, _rspi, _addr);\
  else                                                                        \
    ikev2_elog_exchange_internal (_fmt IKE_ELOG_IP6_FMT, _ispi, _rspi, _addr);\
} while (0)

#define ikev2_elog_uint(_level, _format, _val)                                \
do {                                                                          \
  ikev2_main_t *km = &ikev2_main;                                             \
  if (PREDICT_FALSE (km->log_level >= _level))                                \
    {                                                                         \
      ELOG_TYPE_DECLARE (e) =                                                 \
        {                                                                     \
          .format = "ikev2: " _format,                                        \
          .format_args = "i8",                                                \
        };                                                                    \
      CLIB_PACKED(struct                                                      \
        {                                                                     \
          u64 val;                                                            \
        }) *ed;                                                               \
      ed = ELOG_DATA (&vlib_global_main.elog_main, e);                        \
      ed->val = _val;                                                         \
    }                                                                         \
} while (0)

#define ikev2_elog_uint_peers(_level, _format, _val, _ip1, _ip2)              \
do {                                                                          \
  ikev2_main_t *km = &ikev2_main;                                             \
  if (PREDICT_FALSE (km->log_level >= _level))                                \
    {                                                                         \
      ELOG_TYPE_DECLARE (e) =                                                 \
        {                                                                     \
          .format = "ikev2: " _format,                                        \
          .format_args = "i8i1i1i1i1i1i1i1i1",                                \
        };                                                                    \
      CLIB_PACKED(struct {                                                    \
        u64 val;                                                              \
        u8 i11; u8 i12; u8 i13; u8 i14;                                       \
        u8 i21; u8 i22; u8 i23; u8 i24; }) *ed;                               \
      ed = ELOG_DATA (&vlib_global_main.elog_main, e);                        \
      ed->val = _val;                                                         \
      ed->i14 = (_ip1) >> 24;                                                 \
      ed->i13 = (_ip1) >> 16;                                                 \
      ed->i12 = (_ip1) >> 8;                                                  \
      ed->i11 = (_ip1);                                                       \
      ed->i24 = (_ip2) >> 24;                                                 \
      ed->i23 = (_ip2) >> 16;                                                 \
      ed->i22 = (_ip2) >> 8;                                                  \
      ed->i21 = (_ip2);                                                       \
    }                                                                         \
} while (0)

#define ikev2_elog_error(_msg) \
  _ikev2_elog(IKEV2_LOG_ERROR, "[error] " _msg)
#define ikev2_elog_warning(_msg) \
  _ikev2_elog(IKEV2_LOG_WARNING, "[warning] " _msg)
#define ikev2_elog_debug(_msg) \
  _ikev2_elog(IKEV2_LOG_DEBUG, "[debug] " _msg)
#define ikev2_elog_detail(_msg) \
  _ikev2_elog(IKEV2_LOG_DETAIL, "[detail] " _msg)

/* logging for main thread */
#define ikev2_log_error(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, ikev2_main.log_class, __VA_ARGS__)
#define ikev2_log_warning(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, ikev2_main.log_class, __VA_ARGS__)
#define ikev2_log_debug(...) \
  vlib_log(VLIB_LOG_LEVEL_DEBUG, ikev2_main.log_class, __VA_ARGS__)

typedef enum
{
  IKEV2_STATE_UNKNOWN,
  IKEV2_STATE_SA_INIT,
  IKEV2_STATE_DELETED,
  IKEV2_STATE_AUTH_FAILED,
  IKEV2_STATE_AUTHENTICATED,
  IKEV2_STATE_NOTIFY_AND_DELETE,
  IKEV2_STATE_TS_UNACCEPTABLE,
  IKEV2_STATE_NO_PROPOSAL_CHOSEN,
} ikev2_state_t;

typedef struct
{
  ikev2_auth_method_t method:8;
  u8 *data;
  u8 hex;			/* hex encoding of the shared secret */
  EVP_PKEY *key;
} ikev2_auth_t;

typedef enum
{
  IKEV2_DH_GROUP_MODP = 0,
  IKEV2_DH_GROUP_ECP = 1,
} ikev2_dh_group_t;

typedef struct
{
  ikev2_transform_type_t type;
  union
  {
    u16 transform_id;
    ikev2_transform_encr_type_t encr_type:16;
    ikev2_transform_prf_type_t prf_type:16;
    ikev2_transform_integ_type_t integ_type:16;
    ikev2_transform_dh_type_t dh_type:16;
    ikev2_transform_esn_type_t esn_type:16;
  };
  u8 *attrs;
  u16 key_len;
  u16 key_trunc;
  u16 block_size;
  u8 dh_group;
  int nid;
  const char *dh_p;
  const char *dh_g;
  const void *md;
  const void *cipher;
} ikev2_sa_transform_t;

typedef struct
{
  u8 proposal_num;
  ikev2_protocol_id_t protocol_id:8;
  u32 spi;
  ikev2_sa_transform_t *transforms;
} ikev2_sa_proposal_t;

typedef struct
{
  ikev2_traffic_selector_type_t ts_type;
  u8 protocol_id;
  u16 selector_len;
  u16 start_port;
  u16 end_port;
  ip_address_t start_addr;
  ip_address_t end_addr;
} ikev2_ts_t;

typedef struct
{
  u32 sw_if_index;
  ip_address_t addr;
} ikev2_responder_t;

typedef struct
{
  ikev2_transform_encr_type_t crypto_alg;
  ikev2_transform_integ_type_t integ_alg;
  ikev2_transform_dh_type_t dh_type;
  u32 crypto_key_size;
} ikev2_transforms_set;


typedef struct
{
  ikev2_id_type_t type:8;
  u8 *data;
} ikev2_id_t;

typedef struct
{
  /* sa proposals vectors */
  ikev2_sa_proposal_t *i_proposals;
  ikev2_sa_proposal_t *r_proposals;

  /* Traffic Selectors */
  ikev2_ts_t *tsi;
  ikev2_ts_t *tsr;

  /* keys */
  u8 *sk_ai;
  u8 *sk_ar;
  u8 *sk_ei;
  u8 *sk_er;
  u32 salt_ei;
  u32 salt_er;

  /* installed data */
  u32 local_sa_id;
  u32 remote_sa_id;

  /* lifetime data */
  f64 time_to_expiration;
  u8 is_expired;
  i8 rekey_retries;
} ikev2_child_sa_t;

typedef struct
{
  u8 protocol_id;
  u32 spi;			/*for ESP and AH SPI size is 4, for IKE size is 0 */
} ikev2_delete_t;

typedef struct
{
  u8 protocol_id;
  u32 spi;
  u32 ispi;
  ikev2_sa_proposal_t *i_proposal;
  ikev2_sa_proposal_t *r_proposal;
  ikev2_ts_t *tsi;
  ikev2_ts_t *tsr;
} ikev2_rekey_t;

typedef struct
{
  u16 msg_type;
  u8 protocol_id;
  u32 spi;
  u8 *data;
} ikev2_notify_t;

typedef struct
{
  u8 *name;

  ikev2_auth_t auth;
  ikev2_id_t loc_id;
  ikev2_id_t rem_id;
  ikev2_ts_t loc_ts;
  ikev2_ts_t rem_ts;
  ikev2_responder_t responder;
  ikev2_transforms_set ike_ts;
  ikev2_transforms_set esp_ts;
  u64 lifetime;
  u64 lifetime_maxdata;
  u32 lifetime_jitter;
  u32 handover;
  u16 ipsec_over_udp_port;

  u32 tun_itf;
  u8 udp_encap;
} ikev2_profile_t;

typedef struct
{
  ikev2_state_t state;
  u8 unsupported_cp;
  u8 initial_contact;
  ip_address_t iaddr;
  ip_address_t raddr;
  u64 ispi;
  u64 rspi;
  u8 *i_nonce;
  u8 *r_nonce;

  /* DH data */
  u16 dh_group;
  u8 *dh_shared_key;
  u8 *dh_private_key;
  u8 *i_dh_data;
  u8 *r_dh_data;

  /* sa proposals vectors */
  ikev2_sa_proposal_t *i_proposals;
  ikev2_sa_proposal_t *r_proposals;

  /* keys */
  u8 *sk_d;
  u8 *sk_ai;
  u8 *sk_ar;
  u8 *sk_ei;
  u8 *sk_er;
  u8 *sk_pi;
  u8 *sk_pr;

  /* auth */
  ikev2_auth_t i_auth;
  ikev2_auth_t r_auth;

  /* ID */
  ikev2_id_t i_id;
  ikev2_id_t r_id;

  /* pending deletes */
  ikev2_delete_t *del;

  /* pending rekeyings */
  ikev2_rekey_t *rekey;

  /* packet data */
  u8 *last_sa_init_req_packet_data;
  u8 *last_sa_init_res_packet_data;

  /* retransmit */
  u32 last_msg_id;
  u8 *last_res_packet_data;

  u8 is_initiator;
  u32 last_init_msg_id;
  u32 profile_index;
  u8 is_tun_itf_set;
  u32 tun_itf;
  u8 udp_encap;
  u16 ipsec_over_udp_port;

  f64 old_id_expiration;
  u32 current_remote_id_mask;
  u32 old_remote_id;
  u8 old_remote_id_present;
  u8 init_response_received;

  ikev2_child_sa_t *childs;

  u8 liveness_retries;
  f64 liveness_period_check;

  u16 dst_port;
  u32 sw_if_index;

  /* is NAT traversal mode */
  u8 natt;
  u8 keys_generated;
} ikev2_sa_t;


typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* pool of IKEv2 Security Associations */
  ikev2_sa_t *sas;

  /* hash */
  uword *sa_by_rspi;

  EVP_CIPHER_CTX *evp_ctx;
  HMAC_CTX *hmac_ctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  HMAC_CTX _hmac_ctx;
  EVP_CIPHER_CTX _evp_ctx;
#endif
} ikev2_main_per_thread_data_t;

typedef struct
{
  /* pool of IKEv2 profiles */
  ikev2_profile_t *profiles;

  /* vector of supported transform types */
  ikev2_sa_transform_t *supported_transforms;

  /* hash */
  mhash_t profile_index_by_name;

  /* local private key */
  EVP_PKEY *pkey;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* pool of IKEv2 Security Associations created in initiator mode */
  ikev2_sa_t *sais;
  /* hash */
  uword *sa_by_ispi;

  ikev2_main_per_thread_data_t *per_thread_data;

  /* interface indices managed by IKE */
  uword *sw_if_indices;

  /* API message ID base */
  u16 msg_id_base;

  /* log class used for main thread */
  vlib_log_class_t log_class;

  /* logging level */
  ikev2_log_level_t log_level;

  /* custom ipsec-over-udp ports managed by ike */
  uword *udp_ports;

  /* how often a liveness check will be performed */
  u32 liveness_period;

  /* max number of retries before considering peer dead */
  u32 liveness_max_retries;
} ikev2_main_t;

extern ikev2_main_t ikev2_main;

void ikev2_sa_free_proposal_vector (ikev2_sa_proposal_t ** v);
ikev2_sa_transform_t *ikev2_sa_get_td_for_type (ikev2_sa_proposal_t * p,
						ikev2_transform_type_t type);

/* ikev2_crypto.c */
v8 *ikev2_calc_prf (ikev2_sa_transform_t * tr, v8 * key, v8 * data);
u8 *ikev2_calc_prfplus (ikev2_sa_transform_t * tr, u8 * key, u8 * seed,
			int len);
v8 *ikev2_calc_integr (ikev2_sa_transform_t * tr, v8 * key, u8 * data,
		       int len);
int ikev2_decrypt_data (ikev2_main_per_thread_data_t * ptd, ikev2_sa_t * sa,
			ikev2_sa_transform_t * tr_encr, u8 * data, int len,
			u32 * out_len);
int ikev2_encrypt_data (ikev2_main_per_thread_data_t * ptd, ikev2_sa_t * sa,
			ikev2_sa_transform_t * tr_encr, v8 * src, u8 * dst);
int ikev2_encrypt_aead_data (ikev2_main_per_thread_data_t * ptd,
			     ikev2_sa_t * sa, ikev2_sa_transform_t * tr_encr,
			     v8 * src, u8 * dst, u8 * aad,
			     u32 aad_len, u8 * tag);
int ikev2_decrypt_aead_data (ikev2_main_per_thread_data_t * ptd,
			     ikev2_sa_t * sa, ikev2_sa_transform_t * tr_encr,
			     u8 * data, int data_len, u8 * aad, u32 aad_len,
			     u8 * tag, u32 * out_len);
void ikev2_generate_dh (ikev2_sa_t * sa, ikev2_sa_transform_t * t);
void ikev2_complete_dh (ikev2_sa_t * sa, ikev2_sa_transform_t * t);
int ikev2_verify_sign (EVP_PKEY * pkey, u8 * sigbuf, u8 * data);
u8 *ikev2_calc_sign (EVP_PKEY * pkey, u8 * data);
EVP_PKEY *ikev2_load_cert_file (u8 * file);
EVP_PKEY *ikev2_load_key_file (u8 * file);
void ikev2_crypto_init (ikev2_main_t * km);

/* ikev2_payload.c */
typedef struct
{
  u8 first_payload_type;
  u16 last_hdr_off;
  u8 *data;
} ikev2_payload_chain_t;

#define ikev2_payload_new_chain(V) vec_validate (V, 0)
#define ikev2_payload_destroy_chain(V) do { \
  vec_free((V)->data);                 \
  vec_free(V);                         \
} while (0)

void ikev2_payload_add_notify (ikev2_payload_chain_t * c, u16 msg_type,
			       u8 * data);
void ikev2_payload_add_notify_2 (ikev2_payload_chain_t * c, u16 msg_type,
				 u8 * data, ikev2_notify_t * notify);
void ikev2_payload_add_sa (ikev2_payload_chain_t * c,
			   ikev2_sa_proposal_t * proposals);
void ikev2_payload_add_ke (ikev2_payload_chain_t * c, u16 dh_group,
			   u8 * dh_data);
void ikev2_payload_add_nonce (ikev2_payload_chain_t * c, u8 * nonce);
void ikev2_payload_add_id (ikev2_payload_chain_t * c, ikev2_id_t * id,
			   u8 type);
void ikev2_payload_add_auth (ikev2_payload_chain_t * c, ikev2_auth_t * auth);
void ikev2_payload_add_ts (ikev2_payload_chain_t * c, ikev2_ts_t * ts,
			   u8 type);
void ikev2_payload_add_delete (ikev2_payload_chain_t * c, ikev2_delete_t * d);
void ikev2_payload_chain_add_padding (ikev2_payload_chain_t * c, int bs);
void ikev2_parse_vendor_payload (ike_payload_header_t * ikep);
ikev2_sa_proposal_t *ikev2_parse_sa_payload (ike_payload_header_t * ikep,
					     u32 rlen);
ikev2_ts_t *ikev2_parse_ts_payload (ike_payload_header_t * ikep, u32 rlen);
ikev2_delete_t *ikev2_parse_delete_payload (ike_payload_header_t * ikep,
					    u32 rlen);
ikev2_notify_t *ikev2_parse_notify_payload (ike_payload_header_t * ikep,
					    u32 rlen);
int ikev2_set_log_level (ikev2_log_level_t log_level);
u8 *ikev2_find_ike_notify_payload (ike_header_t * ike, u32 msg_type);

static_always_inline ikev2_main_per_thread_data_t *
ikev2_get_per_thread_data ()
{
  u32 thread_index = vlib_get_thread_index ();
  return vec_elt_at_index (ikev2_main.per_thread_data, thread_index);
}
#endif /* __included_ikev2_priv_h__ */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
